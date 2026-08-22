// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::sync::mpsc;
use anyhow::Result;
use std::fs;

use crate::state::app_state;
use crate::types::{Request, InternalEvent, PolicyDecision, PendingEntry, KernelEventLog, TicketPayload, EntityId, ApprovedTicket};
use crate::types::{next_audit_ticket_id, ACTIVE_TICKETS};
use crate::bundle::bundle;
use crate::decide::request_to_ctx;
use crate::evidence::EvidenceManager;
use crate::evidence::schema::LogType;
use crate::netlink::{self, TealNetlinkMessage, TealReq, TealInfo};

use teal_policy_engine::types::{Effect, RuleType};
use teal_policy_engine::ir::Decision;
use teal_policy_engine::util::{uid_to_name, ktime_prefix};
use teal_policy_engine::eval::evaluate;
use teal_policy_engine::raw::{TEAL_TICKET_FLG_SILENT_IO, TEAL_TICKET_FLG_INHERIT};

// =========================================================================
// ワーカーのメインループ (AUDITレーン)
// =========================================================================

pub async fn audit_worker_loop(
    mut rx_audit: mpsc::Receiver<TealNetlinkMessage>, 
    mut internal_rx: mpsc::Receiver<InternalEvent>,
    nl_tx: netlink::NlWriter
) {
    loop {
        tokio::select! {
            // --------------------------------------------------------
            // A) カーネルから直接飛んできた AUDIT要求 や INFOログ
            // --------------------------------------------------------
            Some(msg) = rx_audit.recv() => {
                match msg {
                    TealNetlinkMessage::Req(nl_req) => {
                        // AUDITモード時のアクセスリクエスト（判定不要、ログのみ）
                        let tx_clone = nl_tx.clone();
                        tokio::spawn(async move {
                            handle_audit_req(nl_req, tx_clone).await;
                        });
                    }
                    TealNetlinkMessage::Info(nl_info) => {
                        // キャッシュヒット（CONSUMED）や期限切れ（EXPIRED）などの事実報告
                        tokio::spawn(async move {
                            if let Err(e) = handle_kernel_info(nl_info).await {
                                eprintln!("[ERROR] Info processing failed: {}", e);
                            }
                        });
                    }
                }
            }

            // --------------------------------------------------------
            // B) Decision/Admin Worker で発生した「事後報告イベント」
            // --------------------------------------------------------
            Some(event) = internal_rx.recv() => {
                tokio::spawn(async move {
                    handle_internal_event(event).await;
                });
            }
        }
    }
}

// =========================================================================
// イベントとREQのハンドラ
// =========================================================================

pub async fn handle_internal_event(event: InternalEvent) {
    match event {
        InternalEvent::Resolved { req_line: _, parsed_req, decision, rule_id, ticket_id } => {
            if let Err(e) = process_resolved_event(parsed_req, decision, rule_id, ticket_id).await {
                eprintln!("[ERROR] Resolved log failed: {}", e);
            }
        }
        InternalEvent::MpaApproved { draft, ticket } => {
            EvidenceManager::log_ticket_add_static(LogType::TicketIssued, Effect::Allow, &draft, &ticket).await;
        }
        InternalEvent::EntryApproved { entry, cacheable, ticket_id } => {
            EvidenceManager::log_slow_path_static(LogType::InteractiveDecision, Effect::Allow, cacheable, &ticket_id, &entry).await;
        }
        InternalEvent::DraftDenied { draft, ticket, denier_uid: _ } => {
            EvidenceManager::log_ticket_add_static(LogType::InteractiveDecision, Effect::Deny, &draft, &ticket).await;
        }
        InternalEvent::EntryDenied { entry, denier_uid: _ } => {
            EvidenceManager::log_slow_path_static(LogType::InteractiveDecision, Effect::Deny, false, "", &entry).await;
        }

        // ==============================================================
        // ライフサイクル管理 (Start/Stop/Reload/Flush) 用のパス
        // ==============================================================
        InternalEvent::CtlApproved { pending_ctl } => {
            EvidenceManager::log_mgmt_ctl_static(LogType::InteractiveDecision, Effect::Allow, &pending_ctl).await;
        }
        InternalEvent::CtlDenied { pending_ctl, denier_uid: _ } => {
            EvidenceManager::log_mgmt_ctl_static(LogType::AccessDenied, Effect::Deny, &pending_ctl).await;
        }
    }
}

/// AUDITレーンから流れてきた REQ メッセージを処理し、ログを出力する
pub async fn handle_audit_req(nl_req: TealReq, nl_tx: netlink::NlWriter) {
    // 1. 変換: Netlinkリクエストを内部の Request 型にマッピング
    let req = Request::from_audit_teal_req(nl_req);

    // 2. 評価: ポリシーの評価と、必要なチケット（キャッシュ）の準備
    let eval_result = evaluate_audit_request(&req).await;

    // 3. 送信: チケットのカーネルへの送信（必要な場合のみ）
    let is_cache_issued = eval_result.ticket_to_send.is_some();
    if let Some(payload) = eval_result.ticket_to_send {
        let _ = nl_tx.send_ticket_add(payload).await;
    }

    // 4. 記録: 証跡ログの非同期エンリッチメントとディスクへの書き込み
    process_audit_log(
        &req,
        eval_result.rule_id,
        eval_result.effect,
        eval_result.issued_ticket_id,
        is_cache_issued,
    ).await;
}

pub struct AuditEvalResult {
    pub effect: Effect,
    pub rule_id: Option<String>,
    pub ticket_to_send: Option<TicketPayload>,
    pub issued_ticket_id: String,
}

/// ポリシーを評価し、発行すべきチケットがあれば生成する
async fn evaluate_audit_request(req: &Request) -> AuditEvalResult {
    let mut ticket_to_send: Option<TicketPayload> = None;
    let mut issued_ticket_id = "0".to_string();

    let compiled = bundle();

    // 1. AppStateのロックを取得する *前* に、重い名前解決を非同期 (spawn_blocking) で済ませる
    let target_uid = req.uid; 

    let request_user = tokio::task::spawn_blocking(move || {
        uid_to_name(target_uid).ok() 
    })
    .await
    .unwrap_or(None); // 万が一タスクがパニックしても None として安全に扱う

    // 2. ロックを取得し、瞬時に判定を行う
    let state = app_state().lock().await;
    let session_info = state.check_registered_session(&req.session_tty, req.uid, request_user.as_deref());
    drop(state); 
    
    let ctx = request_to_ctx(req, &compiled.roles, session_info);

    let (effect, rule_id) = match evaluate(&compiled.policy, &ctx) {
        Decision::Pass => {
            let payload = create_not_managed_ticket(req);
            issued_ticket_id = payload.ticket_id.clone();
            ticket_to_send = Some(payload);
            (Effect::Allow, None)
        },
        Decision::NoMatchManaged => (Effect::Deny, None),
        Decision::Matched(r) => {
            let eff = match r.effect.as_str() {
                "allow" => Effect::Allow,
                "deny" => Effect::Deny,
                "need_approval" => Effect::NeedApproval,
                "audit_only" => Effect::AuditOnly,
                _ => Effect::Deny,
            };

            if (eff == Effect::Allow || eff == Effect::AuditOnly) 
                && r.ticket_profile.flags != 0 
                && r.pre_approval.ttl_sec > 0 
            {
                let ticket_id = next_audit_ticket_id();
                issued_ticket_id = ticket_id.clone();

                let (target_dev, target_ino) = if r.rule_type == RuleType::SubjectOnly {
                    (0, 0)
                } else {
                    (req.target_dev, req.target_ino)
                };

                let (new_target_dev, new_target_ino) = if r.rule_type == RuleType::SubjectOnly {
                    (0, 0)
                } else {
                    (req.new_target_dev, req.new_target_ino)
                };

                let mut safe_flags = r.ticket_profile.flags;
                if (safe_flags & TEAL_TICKET_FLG_INHERIT) != 0 && (safe_flags & TEAL_TICKET_FLG_SILENT_IO) == 0 {
                    eprintln!("{}[WARN] Rule '{}' specifies INHERIT without SILENT_IO. Auto-appending SILENT_IO to prevent Netlink log storm.", ktime_prefix(), r.id);
                    safe_flags |= TEAL_TICKET_FLG_SILENT_IO;
                }

                ticket_to_send = Some(TicketPayload {
                    ticket_id: ticket_id.clone(),
                    uid: req.uid,
                    op: r.action_match.to_u32(),
                    prog_dev: req.prog_dev,
                    prog_ino: req.prog_ino,
                    script_dev: req.script_dev,
                    script_ino: req.script_ino,
                    applet_hash: 0,
                    target_dev,
                    target_ino,
                    new_target_dev,
                    new_target_ino,
                    expires_in_sec: r.pre_approval.ttl_sec,
                    flags: safe_flags,
                    uses_left: r.max_uses,
                    epoch: 0,
                    audit_flags: r.audit_level.to_u32(),
                });

                let origin_script_id = if req.script_dev != 0 || req.script_ino != 0 {
                    Some(EntityId::new((req.script_dev, req.script_ino)))
                } else {
                    None
                };

                let approved_ticket = ApprovedTicket {
                    ticket_id: ticket_id.clone(),
                    rule_id: r.id.clone(),
                    origin_program: req.raw_program.clone(),
                    origin_script: req.raw_script.clone(),
                    object: req.raw_target.clone(),
                    new_object: req.raw_new_target.clone(),
                    uid: req.uid,
                    origin_program_id: EntityId::new((req.prog_dev, req.prog_ino)),
                    origin_script_id,
                    origin_applet: req.raw_applet.clone(),
                    object_id: EntityId::new((req.target_dev, req.target_ino)),
                    new_object_id: if req.new_target_dev != 0 || req.new_target_ino != 0 {
                        Some(EntityId::new((req.new_target_dev, req.new_target_ino)))
                    } else {
                        None
                    },
                    op_mask: r.action_match.to_u32(),
                    ttl_sec: r.pre_approval.ttl_sec,
                    max_uses: r.max_uses,
                };

                ACTIVE_TICKETS.insert(ticket_id, approved_ticket);
            }

            (eff, Some(r.id.clone()))
        }
    };

    AuditEvalResult {
        effect,
        rule_id,
        ticket_to_send,
        issued_ticket_id,
    }
}

/// ペンディングエントリを作成・エンリッチし、ディスクにログを記録する
async fn process_audit_log(
    req: &Request,
    rule_id: Option<String>,
    effect: Effect,
    issued_ticket_id: String,
    is_cache_issued: bool,
) {
    let mut pending = PendingEntry::from_audit(req, rule_id, effect.clone());

    // エンリッチメント処理 (CPUバウンド/同期I/Oの可能性があるため spawn_blocking を使用)
    let pending = tokio::task::spawn_blocking(move || {
        enrich_pending_entry(&mut pending);
        pending
    })
    .await
    .expect("Audit enrichment task panicked");

    // ログの保存
    EvidenceManager::log_slow_path_static(
        LogType::AccessAllowed, // システムAUDITモードでは実際にはアクセスは通ったので ALLOW
        effect,                 // 本来のポリシー判定結果
        is_cache_issued,
        &issued_ticket_id,
        &pending
    ).await;
}

/// 管理対象外パス用の T-000000000 チケットを生成する
fn create_not_managed_ticket(req: &Request) -> TicketPayload {
    TicketPayload {
        ticket_id: "T-000000000".to_string(),
        uid: req.uid,
        op: 0xFFFFFFFF, // 全操作許可
        prog_dev: req.prog_dev,
        prog_ino: req.prog_ino,
        script_dev: req.script_dev,
        script_ino: req.script_ino,
        applet_hash: 0,
        target_dev: req.target_dev,
        target_ino: req.target_ino,
        new_target_dev: req.new_target_dev,     // --- 移動先情報を渡す ---
        new_target_ino: req.new_target_ino,
        expires_in_sec: u64::MAX, // 無期限
        flags: 0,                 // パス単位のパス（T-000000000）には主体特権は不要
        uses_left: 1,
        epoch: 0,
        audit_flags: TEAL_TICKET_FLG_SILENT_IO,
    }
}

/// Fast Path（カーネルキャッシュ）で消費・期限切れになったチケットの情報を処理する
pub async fn handle_kernel_info(info: TealInfo) -> Result<()> {
    let ticket_id = format!("T-{:09}", info.ticket_id);
    let event_name = if info.is_expired { "EXPIRED" } else { "CONSUMED" };

    // 1. チケットをクローンし、必要なら即座に削除（超高速・ブロックなし）
    let target_ticket = {
        if let Some(ticket) = ACTIVE_TICKETS.get(&ticket_id) {
            let t_clone = ticket.clone(); 
            
            // 削除条件の判定: 期限切れ、または使用回数が0になったら削除
            let should_remove = match event_name {
                "EXPIRED" => true,
                "CONSUMED" => info.uses_left == 0,
                _ => false,
            };
            if should_remove {
                ACTIVE_TICKETS.remove(&ticket_id);
            }
            
            Some(t_clone)
        } else {
            None
        }
    };

    // 2. ロックを持たない安全な状態で、重い非同期ログ出力を実行
    if let Some(ticket) = target_ticket {
        // EvidenceManager に渡すための互換構造体 (KernelEventLog) に詰め替える
        let event_log = KernelEventLog {
            ticket_id: info.ticket_id,
            uid: info.uid,
            uses_left: info.uses_left,
            obj_dev: info.target_dev as u64,
            obj_ino: info.target_ino,
            new_obj_dev: if info.new_target_dev != 0 { Some(info.new_target_dev as u64) } else { None },
            new_obj_ino: if info.new_target_ino != 0 { Some(info.new_target_ino) } else { None },
        };

        match event_name {
            "EXPIRED" => {
                EvidenceManager::log_fast_path_static(LogType::TicketExpired, &event_log, &ticket).await;
            }
            "CONSUMED" => {
                EvidenceManager::log_fast_path_static(LogType::TicketConsumed, &event_log, &ticket).await;
            }
            _ => {}
        }
    } else {
        eprintln!("{}[WARN] Received kernel event for unknown ticket id: {}", ktime_prefix(), ticket_id);
    }

    Ok(())
}

async fn process_resolved_event(
    req: Request,
    decision: PolicyDecision,
    rule_id: Option<String>,
    ticket_id: Option<String>,
) -> Result<()> {
    let (effect, log_type) = match decision {
        PolicyDecision::Allow => (Effect::Allow, LogType::AccessAllowed),
        PolicyDecision::NotManaged => (Effect::Allow, LogType::AccessAllowed),
        PolicyDecision::AuditOnly => (Effect::AuditOnly, LogType::AccessAllowed),
        PolicyDecision::Deny => (Effect::Deny, LogType::AccessDenied),
        PolicyDecision::NoRuleMatched => (Effect::Deny, LogType::AccessDenied),
        PolicyDecision::NeedApproval | PolicyDecision::Approved(_) => {
            return Ok(());
        }
    };

    let mut pending = PendingEntry::from_audit(&req, rule_id, effect.clone());
    enrich_pending_entry(&mut pending);

    let is_cache = ticket_id.is_some();
    let final_ticket_id = ticket_id.unwrap_or_else(|| "0".to_string());

    EvidenceManager::log_slow_path_static(
        log_type, effect, is_cache, &final_ticket_id, &pending
    ).await;

    Ok(())
}

// =========================================================================
// ヘルパー関数
// =========================================================================

pub fn enrich_pending_entry(entry: &mut PendingEntry) {
    let mut current_pid = entry.subject.pid;
    
    for _ in 0..10 {
        if current_pid == 0 || current_pid == 1 {
            break;
        }
        
        let environ_path = format!("/proc/{}/environ", current_pid);
        if let Ok(env_data) = fs::read(&environ_path) {
            let env_str = String::from_utf8_lossy(&env_data);
            for kv in env_str.split('\0') {
                if kv.starts_with("SSH_CLIENT=") || kv.starts_with("SSH_CONNECTION=") {
                    if let Some((_, val)) = kv.split_once('=') {
                        if entry.subject.client_ip.is_none() {
                            let ip = val.split_whitespace().next().unwrap_or(val).to_string();
                            entry.subject.client_ip = Some(ip);
                        }
                    }
                } else if kv.starts_with("SSH_USER_AUTH=") {
                    if let Some((_, val)) = kv.split_once('=') {
                        if entry.subject.auth_method.is_none() {
                            entry.subject.auth_method = Some(val.to_string());
                        }
                    }
                }
            }
        }
        
        if entry.subject.client_ip.is_some() && entry.subject.auth_method.is_some() {
            break;
        }
        
        if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", current_pid)) {
            let parts: Vec<&str> = stat.split_whitespace().collect();
            if parts.len() > 3 {
                if let Ok(ppid) = parts[3].parse::<u32>() {
                    if ppid == current_pid { break; } 
                    current_pid = ppid;
                    continue;
                }
            }
        }
        break;
    }
    
    if entry.subject.auth_method.is_none() {
        entry.subject.auth_method = Some("unknown".to_string());
    }
}
