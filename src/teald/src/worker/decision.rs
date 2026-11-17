// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::Result;
use std::fs;
use std::os::unix::fs::MetadataExt;
use tokio::sync::mpsc;

// プロジェクト内の必要なモジュールをインポート
use crate::bundle::policy_snapshot;
use crate::decide::request_to_ctx;
use crate::evidence::{ensure_program_hash, invalidate_hash_cache_for_request};
use crate::netlink::{NlWriter, TealNetlinkMessage};
use crate::state::app_state;
use crate::types::{next_audit_ticket_id, to_kernel_dev, ACTIVE_TICKETS};
use crate::types::{
    ApprovedTicket, EntityId, InternalEvent, PolicyDecision, PolicyResult, Request, TicketPayload,
};

use teal_policy_engine::eval::evaluate;
use teal_policy_engine::ir::PathMatcher;
use teal_policy_engine::ir::{CompiledRule, Decision};
use teal_policy_engine::raw::{TEAL_TICKET_FLG_PARENT_MATCH, TEAL_TICKET_FLG_SILENT_IO};

// NAMELESS_IPC and SILENT_IO are intentionally session-independent.
const TEAL_TICKET_FLG_NAMELESS_IPC: u32 = 1 << 2;
use teal_policy_engine::types::Action;
use teal_policy_engine::types::AuditLevel;
use teal_policy_engine::util::ktime_prefix;

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
            eprintln!(
                "{}[INFO] Decision Channel closed, exiting worker.",
                ktime_prefix()
            );
            break;
        };

        let nl_req = match msg {
            TealNetlinkMessage::Req(r) => *r,
            _ => continue, // Decisionレーンには Req (ENFORCE) しか来ない想定
        };

        // nl_req がムーブ（消費）される前に、互換性用の文字列を作っておく
        let req_line = format!("NETLINK_REQ: {:?}", nl_req);

        // 2. ENFORCEモード用として Request 構造体に変換 (is_audit = false)
        // ここで nl_req の所有権が移動（消費）される
        let mut req = Request::from_enforce_teal_req(nl_req);
        invalidate_hash_cache_for_request(&req);

        // 3. ポリシー判定の実行
        let mut policy_result = process_policy_decision(&mut req).await;

        // reply_to_kernel で take() されて消失する前に、チケットIDを退避しておく
        let proposed_ticket_id = policy_result.ticket.as_ref().map(|t| t.ticket_id.clone());

        // 4. Respond to the request and optionally enqueue TICKET_ADD.
        // Cache-disabled operations must not be logged as issuing a ticket.
        let ticket_queued = match reply_to_kernel(&nl_tx, &req, &mut policy_result).await {
            Ok(queued) => queued,
            Err(e) => {
                eprintln!(
                    "{}[ERROR] Failed to reply to kernel for REQ {}: {}",
                    ktime_prefix(),
                    req.id,
                    e
                );
                let _ = nl_tx.send_deny(req.id).await;
                false
            }
        };
        let issued_ticket_id = if ticket_queued {
            proposed_ticket_id
        } else {
            None
        };

        // 5. ログ記録を Audit Worker へ委譲
        let event = InternalEvent::Resolved {
            req_line,
            parsed_req: req,
            decision: policy_result.decision.clone(),
            rule_id: policy_result.rule_id.clone(),
            ticket_id: issued_ticket_id,
            epoch: policy_result.current_epoch,
        };

        if let Err(e) = internal_tx.send(event).await {
            eprintln!(
                "{}[ERROR] Failed to delegate log to Audit Lane: {}",
                ktime_prefix(),
                e
            );
        }
    }
}

// ============================================================================
// 1. メイン関数（非同期化し、ロック期間を最小化）
// ============================================================================
pub async fn process_policy_decision(req: &mut Request) -> PolicyResult {
    let current = policy_snapshot();
    let compiled = &current.bundle;
    let current_epoch = current.epoch;

    let session_info = {
        let state = app_state().lock().await;

        state.check_registered_session(req.audit_session_id, req.loginuid)
    };

    let ctx = request_to_ctx(req, &compiled.roles, session_info);

    let decision = evaluate(&compiled, &ctx);

    match decision {
        Decision::Pass => build_not_managed_result(req, current_epoch),
        Decision::NoMatchManaged => {
            ensure_program_hash(req).await;
            build_no_match_result(current_epoch)
        }
        Decision::Matched(rule) => {
            if !rule.ticket_profile.is_silent_io() {
                ensure_program_hash(req).await;
            }
            apply_matched_rule(rule, req, current_epoch).await
        }
    }
}

// ============================================================================
// 2. 対象外パス (NotManaged) 用の処理
// ============================================================================
fn build_not_managed_result(req: &Request, current_epoch: u32) -> PolicyResult {
    let payload = TicketPayload {
        ticket_id: "T-000000000".to_string(), // 予約値0
        uid: req.uid,
        op: 0xFFFFFFFF, // Alpha版: 対象外は全操作許可マスク
        prog_dev: req.prog_dev,
        prog_ino: req.prog_ino,
        script_dev: req.script_dev,
        script_ino: req.script_ino,
        applet_hash: 0, // Alphaフェーズ固定
        target_dev: req.target_dev,
        target_ino: req.target_ino,
        new_target_dev: req.new_target_dev,
        new_target_ino: req.new_target_ino,
        expires_in_sec: u64::MAX, // Epochが変わるまで無限
        flags: 0,
        uses_left: 1,         // 予約値0でもプロトコル要件として1以上
        epoch: current_epoch, // グローバルEpochと紐付け
        audit_flags: AuditLevel::Silent.to_u32(),
    };

    PolicyResult {
        decision: PolicyDecision::NotManaged,
        rule_id: None,
        ticket: Some(payload),
        current_epoch,
    }
}

// ============================================================================
// 3. デフォルト拒否 (NoMatchManaged) 用の処理
// ============================================================================
fn build_no_match_result(current_epoch: u32) -> PolicyResult {
    PolicyResult {
        decision: PolicyDecision::NoRuleMatched,
        rule_id: None,
        ticket: None,
        current_epoch,
    }
}

// ============================================================================
// 4. ルールマッチ時の処理（状態変更が必要な場合のみ再度ロック）
// ============================================================================
async fn apply_matched_rule(r: &CompiledRule, req: &Request, current_epoch: u32) -> PolicyResult {
    let decision_kind = match r.effect.as_str() {
        "allow" => PolicyDecision::Allow,
        "deny" => PolicyDecision::Deny,
        "audit_only" => PolicyDecision::AuditOnly,
        "need_approval" => PolicyDecision::NeedApproval,
        _ => PolicyDecision::Deny,
    };

    match decision_kind {
        PolicyDecision::Allow if r.pre_approval.ttl_sec > 0 => {
            // チケット発行に必要な「次のシーケンス番号」だけを、一瞬のロックで取得
            let ticket_id = next_audit_ticket_id();

            // AppStateへの参照を渡さず、値だけを渡して純粋な関数として処理
            let ticket = generate_allow_ticket(r, req, ticket_id, current_epoch);

            PolicyResult {
                decision: decision_kind,
                rule_id: Some(r.id.clone()),
                ticket: Some(ticket),
                current_epoch,
            }
        }
        PolicyDecision::NeedApproval => {
            // キューの操作を伴うため、内部でロックを取って安全に処理
            process_need_approval(r, req, current_epoch).await
        }
        _ => PolicyResult {
            decision: decision_kind,
            rule_id: Some(r.id.clone()),
            ticket: None,
            current_epoch,
        },
    }
}

// ============================================================================
// 5. 許可(ALLOW)チケットの生成ロジック（純粋な関数になり、ロック非依存に）
// ============================================================================
fn generate_allow_ticket(
    r: &CompiledRule,
    req: &Request,
    ticket_seq: String,
    current_epoch: u32,
) -> TicketPayload {
    let mut flags = r.ticket_profile.flags;
    let mut target_dev = req.target_dev;
    let mut target_ino = req.target_ino;
    let mut uses_left = r.max_uses;
    let mut expires_in_sec = r.pre_approval.ttl_sec;

    let is_silent = (flags & TEAL_TICKET_FLG_SILENT_IO) != 0;

    // ★ ログストーム対策: silent_io かつ prefix ルールの場合、包括チケット化する
    if is_silent {
        if let Some(ref obj) = r.object {
            if let Some(PathMatcher::Prefix(ref prefix_path)) = obj.path {
                // ルール指定の prefix ディレクトリが存在すれば、その Dev/Inode に差し替える
                if let Ok(meta) = fs::metadata(prefix_path) {
                    if meta.is_dir() {
                        target_dev = to_kernel_dev(meta.dev()) as u64;
                        target_ino = meta.ino();

                        // 包括フラグを追加
                        flags |= TEAL_TICKET_FLG_PARENT_MATCH;

                        // ログストームを確実に止めるため、無制限・長寿命化
                        uses_left = u32::MAX;
                        if expires_in_sec == 0 {
                            expires_in_sec = 86400; // デフォルト1日など
                        }
                    }
                }
            }
        }
    }

    TicketPayload {
        ticket_id: ticket_seq,
        uid: req.uid,
        op: r.action_match.to_u32(),
        prog_dev: req.prog_dev,
        prog_ino: req.prog_ino,
        script_dev: req.script_dev,
        script_ino: req.script_ino,
        applet_hash: 0,
        target_dev,
        target_ino,
        new_target_dev: req.new_target_dev,
        new_target_ino: req.new_target_ino,
        expires_in_sec,
        flags,
        uses_left,
        epoch: current_epoch,
        audit_flags: r.audit_level.to_u32(),
    }
}

// ============================================================================
// 6. NeedApproval 特有の処理 (究極までロックを最小化したJIT Hydration)
// ============================================================================
async fn process_need_approval(
    r: &CompiledRule,
    req: &Request,
    current_epoch: u32,
) -> PolicyResult {
    // Pre-approval is explicit (teal-cli ticket + MPA). A first access
    // without an approved draft must be DENIED immediately; never put the
    // already-denied kernel request into slow.pending_requests for later approval.
    // Approved drafts still follow JIT Hydration on their first matching REQ.
    let approved_ticket_opt = {
        let mut state = app_state().lock().await;
        let target_ticket_id = state
            .fast
            .approved
            .values()
            .find(|t| t.rule_id == r.id)
            .map(|t| t.ticket_id.clone());

        if let Some(ticket_id) = target_ticket_id {
            if let Some(approved) = state.fast.approved.remove(&ticket_id) {
                ACTIVE_TICKETS.insert(approved.ticket_id.clone(), approved.clone());
                Some(approved)
            } else {
                None
            }
        } else {
            None
        }
    };

    // 【フェーズ3: 結果の構築】
    // ロック解放後に、取得できたチケット情報を使ってペイロードを組み立てる
    if let Some(approved) = approved_ticket_opt {
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
            new_target_dev: req.new_target_dev,
            new_target_ino: req.new_target_ino,
            expires_in_sec: approved.ttl_sec,
            flags: r.ticket_profile.flags,
            uses_left: approved.max_uses,
            epoch: current_epoch,
            audit_flags: r.audit_level.to_u32(),
        };

        PolicyResult {
            decision: PolicyDecision::Approved(Box::new(approved)),
            rule_id: Some(r.id.clone()),
            ticket: Some(payload),
            current_epoch,
        }
    } else {
        PolicyResult {
            decision: PolicyDecision::NeedApproval,
            rule_id: Some(r.id.clone()),
            ticket: None,
            current_epoch,
        }
    }
}

// ============================================================================
// Issuance-time PAM gate. Cached tickets are session-independent.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TicketCacheChoice {
    // Special tickets for processes without a Linux Audit login session.
    Unbound,
    // PAM verified when the ticket is ISSUED. No binding is sent to kernel.
    VerifiedLogin,
    // A request with incomplete or unverified login context may be allowed
    // by Slow Path policy, but must not create a reusable unbound ticket.
    NoCache,
}

fn classify_session_cache(
    sid: Option<u32>,
    loginuid: Option<u32>,
    registered: bool,
) -> TicketCacheChoice {
    match (sid, loginuid) {
        (Some(u32::MAX), Some(u32::MAX)) => TicketCacheChoice::Unbound,
        (Some(sid), Some(loginuid)) if sid != u32::MAX && loginuid != u32::MAX => {
            if registered {
                TicketCacheChoice::VerifiedLogin
            } else {
                TicketCacheChoice::NoCache
            }
        }
        // Missing/partial attributes do not silently downgrade to Unbound.
        // The current kernel always sends both fields (u32::MAX when unset).
        _ => TicketCacheChoice::NoCache,
    }
}

// For immediate Decision/Audit tickets, check PAM registration before issuing
// a cache ticket. Delayed MPA entries retain proof from the original request.
async fn choose_ticket_cache_for_ids(
    audit_session_id: Option<u32>,
    loginuid: Option<u32>,
    flags: u32,
) -> TicketCacheChoice {
    // Log-storm suppression privileges remain intentionally session-independent.
    if flags & (TEAL_TICKET_FLG_SILENT_IO | TEAL_TICKET_FLG_NAMELESS_IPC) != 0 {
        return TicketCacheChoice::Unbound;
    }

    let registered = match (audit_session_id, loginuid) {
        (Some(sid), Some(loginuid)) if sid != u32::MAX && loginuid != u32::MAX => {
            let st = app_state().lock().await;
            st.check_registered_session(Some(sid), Some(loginuid))
                .is_some()
        }
        _ => false,
    };

    classify_session_cache(audit_session_id, loginuid, registered)
}

async fn choose_ticket_cache(req: &Request, flags: u32) -> TicketCacheChoice {
    choose_ticket_cache_for_ids(req.audit_session_id, req.loginuid, flags).await
}

async fn queue_ticket(
    nl_tx: &NlWriter,
    ticket: TicketPayload,
    choice: TicketCacheChoice,
) -> Result<bool> {
    match choice {
        TicketCacheChoice::Unbound => {
            nl_tx.send_ticket_add(ticket).await?;
            Ok(true)
        }
        TicketCacheChoice::VerifiedLogin => {
            // PAM was verified before issuance, but the cached ticket has
            // no session flags and is usable without later PAM checks.
            nl_tx.send_ticket_add(ticket).await?;
            Ok(true)
        }
        TicketCacheChoice::NoCache => Ok(false),
    }
}

/// Queue a cache ticket from an Audit or MPA/PendingEntry context.
/// `Ok(true)` means queued, not acknowledged by the kernel.
/// `Ok(false)` means login context was incomplete or not PAM-registered.
/// No Audit SID, Login UID or PAM status is encoded in issued tickets.
pub(crate) async fn queue_ticket_for_login_context(
    nl_tx: &NlWriter,
    ticket: TicketPayload,
    audit_session_id: Option<u32>,
    loginuid: Option<u32>,
) -> Result<bool> {
    let choice = choose_ticket_cache_for_ids(audit_session_id, loginuid, ticket.flags).await;
    queue_ticket(nl_tx, ticket, choice).await
}

/// MPA PendingEntry: the original request was PAM-attested when queued.
/// On later approval, do NOT depend on the original SID still being active.
/// No live PAM session is required when the cached ticket is USED.
fn classify_mpa_ticket_cache(
    sid: Option<u32>,
    loginuid: Option<u32>,
    verified_loginuid_at_request: Option<u32>,
) -> TicketCacheChoice {
    match (sid, loginuid, verified_loginuid_at_request) {
        (Some(u32::MAX), Some(u32::MAX), None) => TicketCacheChoice::Unbound,
        (Some(sid), Some(auid), Some(verified))
            if sid != u32::MAX && auid != u32::MAX && auid == verified =>
        {
            TicketCacheChoice::VerifiedLogin
        }
        _ => TicketCacheChoice::NoCache,
    }
}

pub(crate) async fn queue_ticket_for_mpa_entry(
    nl_tx: &NlWriter,
    ticket: TicketPayload,
    sid: Option<u32>,
    loginuid: Option<u32>,
    verified_loginuid_at_request: Option<u32>,
) -> Result<bool> {
    if ticket.flags & (TEAL_TICKET_FLG_SILENT_IO | TEAL_TICKET_FLG_NAMELESS_IPC) != 0 {
        return queue_ticket(nl_tx, ticket, TicketCacheChoice::Unbound).await;
    }
    let choice = classify_mpa_ticket_cache(sid, loginuid, verified_loginuid_at_request);
    queue_ticket(nl_tx, ticket, choice).await
}

// --- カーネルへの応答 ---
/// Return true only when TICKET_ADD was successfully queued for sending.
/// This is not a kernel ACK; the existing Netlink writer is asynchronous.
async fn reply_to_kernel(
    nl_tx: &NlWriter,
    req: &Request,
    policy_result: &mut PolicyResult,
) -> Result<bool> {
    match &mut policy_result.decision {
        PolicyDecision::NotManaged => {
            // NotManaged is outside the TEAL policy domain. Preserve its
            // existing unbound, ticket_id=0 behaviour.
            if let Some(ticket) = policy_result.ticket.take() {
                nl_tx.send_approve(req.id).await?;
                queue_ticket(nl_tx, ticket, TicketCacheChoice::Unbound).await
            } else {
                nl_tx.send_approve(req.id).await?;
                Ok(false)
            }
        }
        PolicyDecision::Allow => {
            if let Some(ticket) = policy_result.ticket.take() {
                let choice = choose_ticket_cache(req, ticket.flags).await;
                if choice == TicketCacheChoice::NoCache {
                    // Policy allows the operation; only the reusable cache
                    // ticket is suppressed when login context is unverified.
                    eprintln!(
                        "{}[WARN] TICKET_ADD skipped (unverified login context): pid={} uid={} audit_sid={:?} loginuid={:?}",
                        ktime_prefix(), req.pid, req.uid,
                        req.audit_session_id, req.loginuid
                    );
                    nl_tx.send_approve(req.id).await?;
                    return Ok(false);
                }

                let approved = ApprovedTicket::from_result_with_req(policy_result, &ticket, req)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Failed to create ApprovedTicket: rule_id={:?}, ticket_epoch={}",
                            policy_result.rule_id,
                            ticket.epoch
                        )
                    })?;

                // Preserve the existing low-latency reply ordering.
                nl_tx.send_approve(req.id).await?;
                let queued = queue_ticket(nl_tx, ticket, choice).await?;
                if queued {
                    ACTIVE_TICKETS.insert(approved.ticket_id.clone(), approved);
                }
                Ok(queued)
            } else {
                nl_tx.send_approve(req.id).await?;
                Ok(false)
            }
        }
        PolicyDecision::Approved(approved) => {
            // Hydrate the approved MPA ticket from the actual kernel REQ.
            approved.origin_program = req.raw_program.clone();
            approved.origin_program_sha256 = req.prog_sha256.clone();
            approved.origin_script = req.raw_script.clone();
            approved.object = req.raw_target.clone();
            approved.new_object = req.raw_new_target.clone();
            approved.uid = req.uid;
            approved.origin_program_id = EntityId::new((req.prog_dev, req.prog_ino));
            approved.origin_script_id = Some(EntityId::new((req.script_dev, req.script_ino)));
            approved.origin_applet = req.raw_applet.clone();
            approved.object_id = EntityId::new((req.target_dev, req.target_ino));
            approved.new_object_id = if req.new_target_dev != 0 || req.new_target_ino != 0 {
                Some(EntityId::new((req.new_target_dev, req.new_target_ino)))
            } else {
                None
            };
            approved.op_mask = Action::parse(&req.raw_action)
                .unwrap_or(Action::Unknown)
                .to_mask();

            if let Some(ticket) = policy_result.ticket.take() {
                let choice = choose_ticket_cache(req, ticket.flags).await;
                if choice == TicketCacheChoice::NoCache {
                    // The MPA-approved operation can proceed once, but no
                    // cross-session reusable kernel ticket is installed.
                    // Remove the entry inserted by process_need_approval.
                    ACTIVE_TICKETS.remove(&approved.ticket_id);
                    eprintln!(
                        "{}[WARN] MPA TICKET_ADD skipped (unverified login context): pid={} uid={} audit_sid={:?} loginuid={:?}",
                        ktime_prefix(), req.pid, req.uid,
                        req.audit_session_id, req.loginuid
                    );
                    nl_tx.send_approve(req.id).await?;
                    return Ok(false);
                }

                // Preserve the existing ordering and activity tracking.
                ACTIVE_TICKETS.insert(approved.ticket_id.clone(), (**approved).clone());
                nl_tx.send_approve(req.id).await?;
                queue_ticket(nl_tx, ticket, choice).await
            } else {
                nl_tx.send_approve(req.id).await?;
                Ok(false)
            }
        }
        PolicyDecision::AuditOnly => {
            nl_tx.send_approve(req.id).await?;
            Ok(false)
        }
        // No pre-approved MPA ticket: reject this syscall now, rather than
        // leaving the kernel waiting for its 3-second fail-open timeout.
        PolicyDecision::NeedApproval | PolicyDecision::Deny | PolicyDecision::NoRuleMatched => {
            nl_tx.send_deny(req.id).await?;
            Ok(false)
        }
    }
}

#[cfg(test)]
mod fastpath_session_cache_tests {
    use super::*;
    #[test]
    fn verified_login_allows_session_independent_ticket() {
        assert_eq!(
            classify_session_cache(Some(77), Some(1000), true),
            TicketCacheChoice::VerifiedLogin
        );
        assert_eq!(
            classify_session_cache(Some(88), Some(1000), true),
            TicketCacheChoice::VerifiedLogin
        );
    }
    #[test]
    fn unknown_login_does_not_downgrade() {
        assert_eq!(
            classify_session_cache(Some(77), Some(1000), false),
            TicketCacheChoice::NoCache
        );
        assert_eq!(
            classify_session_cache(Some(77), None, false),
            TicketCacheChoice::NoCache
        );
        assert_eq!(
            classify_session_cache(None, None, false),
            TicketCacheChoice::NoCache
        );
    }
    #[test]
    fn delayed_mpa_approval_after_logout_keeps_login_principal() {
        // The original PAM-attested SID=77 has already logged out. Ticket
        // issuance is allowed and kernel use requires no active session.
        assert_eq!(
            classify_mpa_ticket_cache(Some(77), Some(1000), Some(1000)),
            TicketCacheChoice::VerifiedLogin
        );
        assert_eq!(
            classify_mpa_ticket_cache(Some(77), Some(1000), None),
            TicketCacheChoice::NoCache
        );
        assert_eq!(
            classify_mpa_ticket_cache(Some(77), Some(1001), Some(1000)),
            TicketCacheChoice::NoCache
        );
    }
    #[test]
    fn mpa_for_daemon_without_login_remains_unbound() {
        assert_eq!(
            classify_mpa_ticket_cache(Some(u32::MAX), Some(u32::MAX), None),
            TicketCacheChoice::Unbound
        );
    }
    #[test]
    fn service_process_remains_unbound() {
        assert_eq!(
            classify_session_cache(Some(u32::MAX), Some(u32::MAX), false),
            TicketCacheChoice::Unbound
        );
    }
}
