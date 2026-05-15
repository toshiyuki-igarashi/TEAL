// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::sync::mpsc;
use anyhow::Result;

// プロジェクト内の必要なモジュールをインポート
use crate::app_state;
use crate::types::{
    AppState, Request, InternalEvent, PolicyDecision, EntityId, PendingEntry,
    ApprovedTicket, PolicyResult, TicketPayload
};
use crate::bundle::bundle;
use crate::decide::request_to_ctx;
use crate::netlink::{TealNetlinkMessage, NlWriter};

use teal_policy_engine::ir::{Decision, Action};
use teal_policy_engine::util::ktime_prefix;
use teal_policy_engine::eval::evaluate;
use teal_policy_engine::types::AuditLevel;

// =========================================================================
// ワーカーのメインループ
// =========================================================================

/// 特急レーン（ENFORCEモード）専用のワーカー
pub async fn decision_worker_loop(
    mut rx_decision: mpsc::Receiver<TealNetlinkMessage>, 
    internal_tx: mpsc::Sender<InternalEvent>,
    nl_tx: NlWriter,
) {
    loop {
        // 1. Netlinkモジュールから安全にパース済みのメッセージを受け取る
        let Some(msg) = rx_decision.recv().await else {
            eprintln!("{}[INFO] Decision Channel closed, exiting worker.", ktime_prefix());
            break;
        };

        let nl_req = match msg {
            TealNetlinkMessage::Req(r) => r,
            _ => continue, // Decisionレーンには Req (ENFORCE) しか来ない想定
        };

        // 2. Netlinkの TealReq を内部処理用の Request 構造体に変換
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
            is_audit: false, // ルーティング時点で ENFORCE であることが確定している
        };

        let mut state = app_state().lock().await;

        // 3. ポリシー判定の実行
        let mut policy_result = evaluate_policy(&req, &mut state);
        drop(state); 

        // 4. カーネルへの即時応答（Netlink経由で TICKET_ADD または APPROVE/DENY を送信）
        if let Err(e) = reply_to_kernel(&nl_tx, &req, &mut policy_result).await {
            eprintln!("{}[ERROR] Failed to reply to kernel for REQ {}: {}", ktime_prefix(), req.id, e);
            // 送信失敗時のフェイルセーフ: 確実にプロセスを解放するために再度DENYを試みる
            let _ = nl_tx.send_deny(req.id).await;
        }

        // 5. ログ記録を Audit Worker へ委譲
        let event = InternalEvent::Resolved {
            req_line: format!("NETLINK_REQ: {:?}", nl_req), // 互換性のため文字列化
            parsed_req: req,
            decision: policy_result.decision.clone(), 
            rule_id: policy_result.rule_id.clone(),
            ticket_id: policy_result.ticket.as_ref().map(|t| t.ticket_id.clone()),
        };

        if let Err(e) = internal_tx.send(event).await {
            eprintln!("{}[ERROR] Failed to delegate log to Audit Lane: {}", ktime_prefix(), e);
        }
    }
}

pub fn evaluate_policy(req: &Request, state: &mut AppState) -> PolicyResult {
    let compiled = bundle();
    let ctx = request_to_ctx(&req, &compiled.roles);

    match evaluate(&compiled.policy, &ctx) {
        // ---------------------------------------------------------
        // 1. NotManaged: 対象外パス (Silent & Unlimited Mode のキャッシュ)
        // ---------------------------------------------------------
        Decision::Pass => {
            let payload = TicketPayload {
                ticket_id: "T-000000000".to_string(),  // 予約値0
                uid: req.uid,
                op: 0xFFFFFFFF,             // Alpha版: 対象外は全操作許可マスク
                prog_dev: req.prog_dev,
                prog_ino: req.prog_ino,
                script_dev: req.script_dev,
                script_ino: req.script_ino,
                applet_hash: 0,             // Alphaフェーズ固定
                target_dev: req.target_dev,
                target_ino: req.target_ino,
                expires_in_sec: u64::MAX,   // Epochが変わるまで無限
                flags: 0,
                uses_left: 1,               // 予約値0でもプロトコル要件として1以上
                epoch: state.current_epoch, // グローバルEpochと紐付け
                audit_flags: AuditLevel::Silent.to_u32(),
            };
            
            PolicyResult {
                decision: PolicyDecision::NotManaged,
                rule_id: None,
                ticket: Some(payload),
            }
        }

        // ---------------------------------------------------------
        // 2. NoRuleMatched: デフォルト拒否 (キャッシュ不可)
        // ---------------------------------------------------------
        Decision::NoMatchManaged => {
            // 仕様書においてキャッシュ(AllowList)は許可操作用のため、
            // デフォルト拒否の場合はチケットを作成せず、都度 DENY を返す
            PolicyResult {
                decision: PolicyDecision::NoRuleMatched,
                rule_id: None,
                ticket: None,
            }
        }

        // ---------------------------------------------------------
        // 3. Matched: ルールに基づくチケット生成 / 状態の更新
        // ---------------------------------------------------------
        Decision::Matched(r) => {
            let decision_kind = match r.effect.as_str() {
                "allow" => PolicyDecision::Allow,
                "deny" => PolicyDecision::Deny,
                "audit_only" => PolicyDecision::AuditOnly,
                "need_approval" => PolicyDecision::NeedApproval,
                _ => PolicyDecision::Deny,
            };

            let mut ticket_payload = None;

            if decision_kind == PolicyDecision::Allow && r.ttl_sec > 0 {
                // 仕様書 5.1.2 準拠: T-XXXXXX 形式のID生成
                let ticket_seq = state.generate_next_ticket_seq(); // (内部カウンターで生成)
                let formatted_id = format!("T-{:09}", ticket_seq);

                let payload = TicketPayload {
                    ticket_id: formatted_id.clone(),
                    uid: req.uid,
                    op: r.action_match.to_u32(), // ルールの操作マスク
                    prog_dev: req.prog_dev,
                    prog_ino: req.prog_ino,
                    script_dev: req.script_dev,
                    script_ino: req.script_ino,
                    applet_hash: 0,
                    target_dev: req.target_dev,
                    target_ino: req.target_ino,
                    expires_in_sec: r.ttl_sec,
                    flags: r.ticket_profile.flags,
                    uses_left: r.max_uses,
                    epoch: state.current_epoch,
                    audit_flags: r.audit_level.to_u32(),
                };
                
                ticket_payload = Some(payload);
            } else if decision_kind == PolicyDecision::NeedApproval {
                // 1. HashMapのvaluesから、ルールIDが一致したチケットを1つ探す
                let target_ticket_id = state.fast.approved.values()
                    .find(|t| t.rule_id == r.id)
                    .map(|t| t.ticket_id.clone());

                // 2. 該当するIDが見つかった場合のみ、approvedからticketsへticketを移す
                if let Some(ticket_id) = target_ticket_id {
                    if let Some(approved) = state.fast.approved.remove(&ticket_id) {
                        state.fast.tickets.insert(approved.ticket_id.clone(), approved.clone());

                        let payload = TicketPayload {
                            ticket_id: approved.ticket_id.clone(),
                            uid: req.uid,
                            op: approved.op_mask,
                            prog_dev: req.prog_dev,
                            prog_ino: req.prog_ino,
                            script_dev: req.script_dev,
                            script_ino: req.script_ino,
                            applet_hash: 0,
                            target_dev: req.target_dev,
                            target_ino: req.target_ino,
                            expires_in_sec: approved.ttl_sec,
                            flags: r.ticket_profile.flags,
                            uses_left: approved.max_uses,
                            epoch: state.current_epoch,
                            audit_flags: r.audit_level.to_u32(),
                        };
                        
                        return PolicyResult {
                            decision: PolicyDecision::Approved(approved),
                            rule_id: Some(r.id.clone()),
                            ticket: Some(payload),
                        };
                    }
                }

                // 3. 見つからなかった場合は通常の承認待ち (PendingEntry) を作成
                // 3-1. PendingEntry (リッチなコンテキスト) を生成
                let pending_entry = PendingEntry::from_rule(&r, req);

                // 3-2. Slow Lane (承認待ちリスト) へ登録
                state.slow.pending_requests.insert(req.id, pending_entry);
            }

            PolicyResult {
                decision: decision_kind,
                rule_id: Some(r.id.clone()),
                ticket: ticket_payload, // NeedApproval時は None になるためカーネルへは返さない
            }
        }
    }
}

// --- カーネルへの応答 ---
async fn reply_to_kernel(nl_tx: &NlWriter, req: &Request, policy_result: &mut PolicyResult) -> Result<()> {
    match &mut policy_result.decision {
        PolicyDecision::NotManaged => {
            if let Some(ticket) = policy_result.ticket.take() {
                let _ = nl_tx.send_approve(req.id).await;
                nl_tx.send_ticket_add(ticket).await
            } else {
                nl_tx.send_approve(req.id).await
            }
        }
        PolicyDecision::Allow => {
            if let Some(ticket) = policy_result.ticket.take() {
                let _ = nl_tx.send_approve(req.id).await;
                nl_tx.send_ticket_add(ticket).await?;

                if let Some(approved) = ApprovedTicket::from_result(policy_result) {
                    let mut lock = app_state().lock().await;
                    lock.fast.tickets.insert(approved.ticket_id.clone(), approved);
                }
                Ok(())
            } else {
                nl_tx.send_approve(req.id).await
            }
        }
        PolicyDecision::Approved(approved) => {
            // メタデータの補完
            approved.origin_program = req.raw_program.clone();
            approved.origin_script = req.raw_script.clone();
            approved.object = req.raw_target.clone();
            approved.uid = req.uid;
            approved.origin_program_id = EntityId::new((req.prog_dev, req.prog_ino));
            approved.origin_script_id = Some(EntityId::new((req.script_dev, req.script_ino)));
            approved.origin_applet = req.raw_applet.clone();
            approved.object_id = EntityId::new((req.target_dev, req.target_ino));
            approved.op_mask = Action::parse(&req.raw_action).unwrap_or(Action::Unknown).to_mask();

            {
                let mut state = app_state().lock().await;
                state.fast.tickets.insert(approved.ticket_id.clone(), approved.clone());
            }

            if let Some(ticket) = policy_result.ticket.take() {
                let _ = nl_tx.send_approve(req.id).await;
                nl_tx.send_ticket_add(ticket).await
            } else {
                nl_tx.send_approve(req.id).await
            }
        }
        PolicyDecision::AuditOnly => nl_tx.send_approve(req.id).await,
        PolicyDecision::NeedApproval => Ok(()), // 承認待ちのためカーネルへは無応答（タイムアウトまで待機させる）
        PolicyDecision::Deny | PolicyDecision::NoRuleMatched => nl_tx.send_deny(req.id).await,
    }
}

// --- ヘルパー関数 ---
fn normalize_opt_field(s: &str) -> Option<String> {
    if s == "-" || s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}
