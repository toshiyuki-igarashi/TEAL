// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::sync::mpsc;
use anyhow::Result;
use std::fs;

use crate::app_state;
use crate::types::{Request, InternalEvent, PolicyDecision, PendingEntry, KernelEventLog, TicketPayload, EntityId, ApprovedTicket};
use crate::bundle::bundle;
use crate::decide::request_to_ctx;
use crate::evidence::EvidenceManager;
use crate::evidence::schema::LogType;
use crate::netlink::{self, TealNetlinkMessage, TealReq, TealInfo};

use teal_policy_engine::types::Effect;
use teal_policy_engine::ir::{Decision, RuleType};
use teal_policy_engine::util::ktime_prefix;
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
    // ※ 内部イベント処理は元のコードと「全く同じ」です
    match event {
        InternalEvent::Resolved { req_line: _, parsed_req, decision, rule_id, ticket_id } => {
            if let Err(e) = process_resolved_event(parsed_req, decision, rule_id, ticket_id).await {
                eprintln!("[ERROR] Resolved log failed: {}", e);
            }
        }
        InternalEvent::MpaApproved { draft, ticket } => {
            EvidenceManager::log_ticket_add_static(LogType::TicketIssued, Effect::Allow, &draft, &ticket).await;
        }
        InternalEvent::StartApproved { pending_start } => {
            EvidenceManager::log_enforce_start_static(LogType::InteractiveDecision, Effect::Allow, &pending_start).await;
        }
        InternalEvent::EntryApproved { entry, cacheable, ticket_id } => {
            EvidenceManager::log_slow_path_static(LogType::InteractiveDecision, Effect::Allow, cacheable, &ticket_id, &entry).await;
        }
        InternalEvent::StartDenied { pending_start, denier_uid: _ } => {
            EvidenceManager::log_enforce_start_static(LogType::AccessDenied, Effect::Deny, &pending_start).await;
        }
        InternalEvent::DraftDenied { draft, ticket, denier_uid: _ } => {
            EvidenceManager::log_ticket_add_static(LogType::InteractiveDecision, Effect::Deny, &draft, &ticket).await;
        }
        InternalEvent::EntryDenied { entry, denier_uid: _ } => {
            EvidenceManager::log_slow_path_static(LogType::InteractiveDecision, Effect::Deny, false, "", &entry).await;
        }
        InternalEvent::StopApproved { pending_stop } => {
            EvidenceManager::log_enforce_stop_static(LogType::InteractiveDecision, Effect::Allow, &pending_stop).await;
        }
        InternalEvent::StopDenied { pending_stop, denier_uid: _ } => {
            EvidenceManager::log_enforce_stop_static(LogType::AccessDenied, Effect::Deny, &pending_stop).await;
        }
    }
}

/// AUDITレーンから流れてきた REQ メッセージを処理し、ログを出力する
pub async fn handle_audit_req(nl_req: TealReq, nl_tx: netlink::NlWriter) {
    // 1. Netlinkの TealReq を内部処理用の Request 構造体に変換
    let req = Request {
        id: nl_req.trans_id,
        pid: nl_req.pid,
        ppid: nl_req.ppid,
        session_id: nl_req.session_id,
        uid: nl_req.uid,
        gid: nl_req.gid,
        prog_dev: nl_req.prog_dev as u64,
        prog_ino: nl_req.prog_ino,
        raw_program: nl_req.program.clone(),
        raw_action: nl_req.action.clone(),
        target_dev: nl_req.target_dev as u64,
        target_ino: nl_req.target_ino,
        raw_target: nl_req.target.clone(),
        script_dev: nl_req.script_dev as u64,
        script_ino: nl_req.script_ino,
        raw_script: normalize_opt_field(&nl_req.script),
        raw_applet: normalize_opt_field(&nl_req.applet),
        lsm_label_hex: nl_req.lsm_label.clone(),
        args_head: normalize_opt_field(&nl_req.args_head),
        flag: nl_req.flags,
        is_audit: true, // AUDITレーンに流れてきたので true 確定
    };

    // 2. ポリシー評価とチケット生成の準備
    let mut ticket_to_send: Option<TicketPayload> = None;
    let mut issued_ticket_id = "0".to_string();
    let mut is_cache_issued = false;

    let (effect, rule_id) = {
        let compiled = bundle();
        let ctx = request_to_ctx(&req, &compiled.roles);

        match evaluate(&compiled.policy, &ctx) {
            Decision::Pass => {
                // 管理対象外パスへの連続REQを止めるため、T-000000000を発行
                // NotManagedパスへのログストーム抑制
                let payload = create_not_managed_ticket(&req);
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

                // =========================================================================
                // AUDITモードでも silent_io や inherit などがあればチケットを発行
                // Allow または AuditOnly の場合「のみ」チケットを発行する
                // =========================================================================
                if eff == Effect::Allow || eff == Effect::AuditOnly {
                    if (r.ticket_profile.flags != 0) && r.ttl_sec > 0 {
                        let ticket_id = generate_audit_ticket_id().await;   // ログ追跡用のID生成
                        issued_ticket_id = ticket_id.clone();

                        let (target_dev, target_ino) = if r.rule_type == RuleType::SubjectOnly {
                            (0, 0)
                        } else {
                            (req.target_dev, req.target_ino)
                        };

                        // --- INHERIT の場合の SILENT_IO 自動補完 ---
                        let mut safe_flags = r.ticket_profile.flags;
                        
                        if (safe_flags & TEAL_TICKET_FLG_INHERIT) != 0 
                        && (safe_flags & TEAL_TICKET_FLG_SILENT_IO) == 0 {
                            // ログストーム防止のためのフェイルセーフ発動
                            eprintln!("{}[WARN] Rule '{}' specifies INHERIT without SILENT_IO. Auto-appending SILENT_IO to prevent Netlink log storm.", ktime_prefix(), r.id);
                            safe_flags |= TEAL_TICKET_FLG_SILENT_IO;
                        }
                        // -----------------------------------------------------

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
                            expires_in_sec: r.ttl_sec,
                            flags: safe_flags,    // 補完済みの安全なフラグをセット
                            uses_left: r.max_uses,
                            epoch: 0,             // AUDIT時は0固定など
                            audit_flags: r.audit_level.to_u32(),
                        });

                        // 発行したチケットを FastState.tickets に保存する
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
                            uid: req.uid,
                            origin_program_id: EntityId::new((req.prog_dev, req.prog_ino)),
                            origin_script_id,
                            origin_applet: req.raw_applet.clone(),
                            object_id: EntityId::new((req.target_dev, req.target_ino)),
                            op_mask: r.action_match.to_u32(),
                            ttl_sec: r.ttl_sec,
                            max_uses: r.max_uses,
                        };

                        let mut state = crate::app_state().lock().await;
                        state.fast.tickets.insert(ticket_id, approved_ticket);
                    }
                }
                // =========================================================================

                (eff, Some(r.id.clone()))
            }
        }
    };

    // 2.1 カーネルへチケットを送信（非同期）
    if let Some(payload) = ticket_to_send {
        let _ = nl_tx.send_ticket_add(payload).await;
        is_cache_issued = true;
    }

    // 3. ログ出力（issued_ticket_id を渡すことで、どのチケットで抑制が始まったか記録する）
    let mut pending = PendingEntry::from_audit(&req, rule_id, effect.clone());

    let pending = tokio::task::spawn_blocking(move || {
        enrich_pending_entry(&mut pending);     // 解析を実行、解析が終わるまでこのタスクは中断(yield)し、他を邪魔しない
        pending
    })
    .await
    .expect("Audit enrichment task panicked");  // ここで Result をほどく

    EvidenceManager::log_slow_path_static(
        LogType::AccessAllowed, // システムAUDITモードでは実際にはアクセスは通ったので ALLOW
        effect,                 // 本来のポリシー判定結果 (DenyやNeedApproval等)
        is_cache_issued,        // チケット発行の有無を渡す
        &issued_ticket_id,      // 生成した変数の参照を渡す
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
        expires_in_sec: u64::MAX, // 無期限
        flags: 0,                 // パス単位のパス（T-000000000）には主体特権は不要
        uses_left: 1,
        epoch: 0,
        audit_flags: TEAL_TICKET_FLG_SILENT_IO,
    }
}

/// AUDITモード用の新規チケットIDを生成する
async fn generate_audit_ticket_id() -> String {
    let mut state = crate::app_state().lock().await;
    let seq = state.generate_next_ticket_seq();
    format!("T-{:09}", seq)
}

/// Fast Path（カーネルキャッシュ）で消費・期限切れになったチケットの情報を処理する
pub async fn handle_kernel_info(info: TealInfo) -> Result<()> {
    let ticket_id = format!("T-{:09}", info.ticket_id);
    let event_name = if info.is_expired { "EXPIRED" } else { "CONSUMED" };

    // 1. ロックを取ってチケットをクローンし、必要なら即座に削除（超高速・ブロックなし）
    let target_ticket = {
        let mut lock = app_state().lock().await;
        if let Some(ticket) = lock.fast.tickets.get(&ticket_id) {
            let t_clone = ticket.clone(); 
            
            // 削除条件の判定: 期限切れ、または使用回数が0になったら削除
            let should_remove = match event_name {
                "EXPIRED" => true,
                "CONSUMED" => info.uses_left == 0,
                _ => false,
            };
            if should_remove {
                lock.fast.tickets.remove(&ticket_id);
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
//            event: event_name.to_string(),
            ticket_id: info.ticket_id,
            uid: info.uid,
            uses_left: info.uses_left,
//            res: "ALLOW".to_string(),
//            org_dev: info.prog_dev as u64,
//            org_ino: info.prog_ino,
//            obj_dev: info.target_dev as u64,
            obj_ino: info.target_ino,
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

fn normalize_opt_field(s: &str) -> Option<String> {
    if s == "-" || s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

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
