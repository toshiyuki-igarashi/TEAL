// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::path::PathBuf;
use uuid::Uuid;
use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use once_cell::sync::Lazy;

use crate::state::app_state;
use crate::bundle::{compute_directory_hash, DEFAULT_TEAL_DIR, STAGE_TEAL_DIR};
use crate::bundle::{policy_snapshot, load_bundle_from_dir, update_bundle, advance_epoch};
use crate::management::{management, prepare_management, commit_management};
use crate::common::{DecisionKind, TealStatus, NetlinkStatus, QueueStatus, is_mgmt_id, find_rule};
use crate::types::{InternalEvent, MgmtPendingCtl, MgmtCtlKind, MpaState, AppState, SignedCmdArgs, ApprovedTicket};
use crate::types::{ACTIVE_TICKETS, DaemonMode, set_daemon_mode, is_enforce};
use crate::ticket::{is_ticketable, draft_from_rule, preload_silent_directory_tickets};
use crate::netlink::NlWriter;
use crate::netlink::get_netlink_socket_metrics;

use teal_policy_engine::util::{uid_to_name, ktime_prefix};
use teal_policy_engine::management::{CompiledManagement, CompiledMgmtMpa, CompiledMgmtMpaEnabled};
use teal_policy_engine::ir::CompiledRule;
use teal_policy_engine::ir::CompiledBundle;

// --- ループとルーティング ---
/// Admin Socket Worker (管理ソケット) のメインループ
pub async fn admin_socket_loop(listener: UnixListener, admin_tx: mpsc::Sender<InternalEvent>, nl_tx: NlWriter) {
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let tx_clone = admin_tx.clone();
            let nl_tx_clone = nl_tx.clone();
            
            tokio::spawn(async move {
                if let Some(event) = handle_admin_connection(stream, &nl_tx_clone).await {
                    if let Err(e) = tx_clone.send(event).await {
                        eprintln!("{}[ERROR] Failed to send event to Audit Worker: {}", ktime_prefix(), e);
                    }
                }
            });
        }
    }
}

async fn handle_admin_connection(mut stream: tokio::net::UnixStream, nl_tx: &NlWriter) -> Option<InternalEvent> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let uid = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        Err(_) => {
            let _ = stream.write_all(b"ERR cannot get peer credential\n").await;
            return None; 
        }
    };

    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return None, 
    };
    if n == 0 {
        return None;
    }

    let cmd = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    let cmd_name = cmd.split_whitespace().next().unwrap_or_else(|| "");

    // 管理設定(CompiledManagement)の参照を取得
    let mgmt = management();

    // Netlinkの送信が必要なコマンドには nl_tx を渡す
    let (response, event) = match cmd_name {
        "STATUS"        => handle_status().await,
        "NETLINK_STATUS" => (handle_netlink_status(), None),
        "LIST"          => handle_list(&cmd, uid).await,
        "REGISTER"      => handle_register(&cmd, uid).await,
        "TICKET"        => handle_ticket(&cmd, uid, nl_tx).await,
        "APPROVE"       => handle_approve(&cmd, uid, nl_tx).await,
        "DENY"          => handle_deny(&cmd, uid, nl_tx).await,

        // 【署名が必要なライフサイクル操作】
        "START"         => handle_mgmt(&cmd, MgmtCtlKind::Start, DecisionKind::Start, uid, nl_tx).await,
        "STOP"          => handle_mgmt(&cmd, MgmtCtlKind::Stop, DecisionKind::Stop, uid, nl_tx).await,
        
        // 【署名なしの管理・特権操作（直接チェック＆実行へ流す）】
        "POLICY_UPDATE" => handle_mgmt(&cmd, MgmtCtlKind::PolicyUpdate, DecisionKind::PolicyUpdate, uid, nl_tx).await,
        "FLUSH"         => check_initiator_and_handle(MgmtCtlKind::Flush, &mgmt, uid, "", nl_tx).await,

        _ => ("ERR unknown cmd\n".to_string(), None),
    };

    let _ = stream.write_all(response.as_bytes()).await;
    event
}

// --- 各コマンドの入り口 ---

/// ログストーム（バッファ高負荷）と判定する Netlink 受信バッファ使用率のしきい値 (%)
const LOG_STORM_BUFFER_USAGE_THRESHOLD_PCT: f64 = 50.0;

/// 前回の測定時の累積ドロップ数を保持する静的変数
static PREV_DROPS: AtomicU64 = AtomicU64::new(0);

/// ドロップ数の差分（増加量）を計算し、静的変数を最新値に更新する
fn record_drops_and_calc_delta(current_drops: u64) -> u64 {
    let prev = PREV_DROPS.swap(current_drops, Ordering::Relaxed);
    current_drops.saturating_sub(prev)
}

async fn handle_status() -> (String, Option<InternalEvent>) {
    let (is_flushed, pending_len) = {
        let st = app_state().lock().await;
        (
            st.is_flushed,
            st.slow.pending_requests.len(),
        )
    };

    let (buffer_usage_pct, drops) = get_netlink_socket_metrics();

    // ★ ドロップ差分の計算（NETLINK_STATUS 側で更新済みなら 0 になる）
    let drops_delta = record_drops_and_calc_delta(drops);

    // バッファ使用率超過、または直近サンプリング以降に新規ドロップがあればストームと判定
    let is_storming = buffer_usage_pct > LOG_STORM_BUFFER_USAGE_THRESHOLD_PCT || drops_delta > 0;

    let status_obj = TealStatus {
        status: "ok".to_string(),
        is_enforce: is_enforce(),
        is_flushed,
        current_epoch: policy_snapshot().epoch,
        netlink: NetlinkStatus {
            buffer_usage_pct,
            drops,
            recv_rate_per_sec: 0,
        },
        queues: QueueStatus {
            decision_channel_len: 0,
            audit_channel_len: 0,
            pending_requests_len: pending_len,
        },
        is_storming,
    };

    match serde_json::to_string_pretty(&status_obj) {
        Ok(json) => (format!("{}\n", json), None),
        Err(e) => (format!("ERR failed to serialize status: {}\n", e), None),
    }
}

/// ログストーム時でも app_state() のロックを取得せずに即座に Netlink の健康状態を返す
fn handle_netlink_status() -> String {
    let (buffer_usage_pct, drops) = get_netlink_socket_metrics();

    // ★ ポーリング中にも PREV_DROPS を最新値へ進める
    let _drops_delta = record_drops_and_calc_delta(drops);

    let netlink_obj = NetlinkStatus {
        buffer_usage_pct,
        drops,
        recv_rate_per_sec: 0,
    };

    match serde_json::to_string(&netlink_obj) {
        Ok(json) => format!("{}\n", json),
        Err(e) => format!("ERR failed to serialize netlink status: {}\n", e),
    }
}

async fn handle_list(_cmd: &str, _uid: u32) -> (String, Option<InternalEvent>) {
    // 1. ロックを取得し、必要なデータだけを「スナップショット」として手元にコピーする
    let (drafts, pending_ctl, pending_requests) = {
        let lock = app_state().lock().await; // ロック取得

        // 空判定（早期リターン）
        if lock.fast.drafts.is_empty() 
            && lock.slow.pending_requests.is_empty() 
            && lock.slow.pending_ctl.is_none() 
        {
            return ("No pending requests.\n".to_string(), None); // ここでロック自動解除
        }

        // 必要なデータをクローン
        (
            lock.fast.drafts.clone(),
            lock.slow.pending_ctl.clone(),
            lock.slow.pending_requests.clone(),
        )
    }; // スコープを抜けてここで即座にロック解除！

    // -------------------------------------------------------------
    // これ以降はロックを持っていないため、どれだけ時間がかかっても安全！
    // -------------------------------------------------------------

    let mut s = String::new();

    // クローンしたデータを使って、安全に文字列を生成する
    for (id, draft) in &drafts {
        s.push_str(&format!("DRAFT ID: {} | Rule-ID: {} | Status: {} | MPA: {}/{} | Roles: {:?} | timeout_minutes: {} | max_uses = {}\n",         
            id, draft.rule_id, draft.mpa_state.is_fulfilled(), draft.mpa_state.approvals.len(), draft.mpa_state.threshold, draft.mpa_state.required_roles, draft.ttl_sec, draft.max_uses,
        ));
    }

    // 集約された pending_ctl のハンドリング (kindに応じて表示ラベルを切り替え)
    if let Some(ctl) = &pending_ctl {
        let label = match ctl.kind {
            MgmtCtlKind::Start        => "START",
            MgmtCtlKind::Stop         => "STOP",
            MgmtCtlKind::PolicyUpdate => "POLICY_UPDATE",
            MgmtCtlKind::Flush        => "FLUSH",
        };

        s.push_str(&format!(
            "ID: {} | audit_id: {} | UID: {} | Status: {} | MPA: {}/{} | Roles: {:?} | timeout_minutes: {}\n",
            label,
            ctl.audit_id,
            ctl.initiator_uid,
            ctl.mpa_state.is_fulfilled(),
            ctl.mpa_state.approvals.len(),
            ctl.mpa_state.threshold,
            ctl.mpa_state.required_roles,
            ctl.timeout_minutes,
        ));
    }

    for (id, entry) in &pending_requests {
        s.push_str(&format!("ID: {} | PID: {} | Target: {} | Status: {} | Reason: {} | MPA: {}/{} | Roles: {:?}\n",
            id, entry.subject.pid, entry.object.path, entry.mpa_state.is_fulfilled(), entry.reason, entry.mpa_state.approvals.len(), entry.mpa_state.threshold, entry.mpa_state.required_roles,
        ));
    }

    (s, None)
}

async fn handle_register(cmd: &str, uid: u32) -> (String, Option<InternalEvent>) {
    let mut it = cmd.split_whitespace();
    let head = it.next().unwrap_or_else(|| "");
    if head != "REGISTER" { return ("ERR bad cmd head (expected REGISTER)\n".to_string(), None); }

    let hex = it.next();
    if hex.is_none() || it.next().is_some() { return ("Usage: REGISTER <hex_pubkey>\n".to_string(), None); }

    let hex = hex.unwrap().trim().to_string();
    let is_hex = !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    if !is_hex { return ("Invalid pubkey (expected hex)\n".to_string(), None); }

    {
        let mut lock = app_state().lock().await;
        lock.slow.registered_keys.insert(uid, hex.clone());
    }
    eprintln!("{}[INFO] Admin REGISTER uid={} pubkey={}", ktime_prefix(), uid, hex);
    ("OK\n".to_string(), None)
}

async fn handle_ticket(cmd: &str, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    if nl_tx.ticket_transition_active() {
        return ("ERR policy epoch transition in progress\n".to_string(), None);
    }
    handle_signed_decision(cmd, DecisionKind::Ticket, uid, Some(nl_tx)).await
}

async fn handle_approve(cmd: &str, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    handle_signed_decision(cmd, DecisionKind::Approve, uid, Some(nl_tx)).await
}

async fn handle_deny(cmd: &str, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    handle_signed_decision(cmd, DecisionKind::Deny, uid, Some(nl_tx)).await
}

/// 管理操作コマンド（START/STOP等）の受付共通ハンドラ
async fn handle_mgmt(
    cmd: &str,
    ctl_kind: MgmtCtlKind,
    decision_kind: DecisionKind,
    uid: u32,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    eprintln!(
        "{}[INFO] {}: user={}",
        ktime_prefix(),
        ctl_kind.as_str(),
        resolve_account(uid).await
    );
    handle_signed_decision(cmd, decision_kind, uid, Some(nl_tx)).await
}

// --- 署名検証とメイン制御 ---
async fn handle_signed_decision(
    cmd: &str,
    kind: DecisionKind,
    uid: u32,
    nl_tx: Option<&NlWriter>
) -> (String, Option<InternalEvent>) {
    let mut args = match parse_args(cmd, kind, uid) {
        Ok(a) => a,
        Err(err_msg) => return (err_msg, None),
    };

    if let Err(err_msg) = fetch_pubkey_and_verify(uid, kind, &args).await {
        return (err_msg, None);
    }

    args.account = resolve_account(uid).await;

    apply_decision(kind, args, nl_tx).await
}

fn parse_args(
    cmd: &str,
    kind: DecisionKind,
    uid: u32,
) -> Result<SignedCmdArgs, String> {
    let mut it = cmd.split_whitespace();

    let head = it.next().unwrap_or("");
    if head != kind.as_str() {
        return Err(format!(
            "ERR bad cmd head (expected {})\n", kind.as_str()
        ));
    }

    let id = match kind {
        DecisionKind::Approve
        | DecisionKind::Deny
        | DecisionKind::Ticket
        | DecisionKind::PolicyUpdate => {
            it.next().ok_or("ERR missing id\n")?.to_string()
        }
        _ => String::new(),
    };

    let is_mgmt_decision =
        matches!(kind, DecisionKind::Approve | DecisionKind::Deny)
        && is_mgmt_id(&id);

    let audit_id = if is_mgmt_decision {
        Some(it.next().ok_or("ERR missing audit_id\n")?.to_string())
    } else {
        None
    };

    let sig_hex = it.next()
        .ok_or("ERR missing signature\n")?
        .to_string();

    if it.next().is_some() {
        return Err("ERR too many args\n".to_string());
    }

    Ok(SignedCmdArgs {
        id,
        uid,
        account: String::new(),
        sig_hex,
        audit_id,
    })
}

async fn fetch_public_key(uid: u32, kind: DecisionKind) -> Result<String, String> {
    // 1. まず一瞬だけロックを取り、鍵があるかどうかだけを確認（クローン）する
    let key_opt = {
        let st = app_state().lock().await;
        st.slow.registered_keys.get(&uid).cloned()
    }; // スコープを抜けて確実にロック解除！

    // 2. ロックを持たない安全な状態で分岐処理
    match key_opt {
        Some(k) => Ok(k),
        None => {
            // エラー時：ロックを持っていないので、どれだけ時間がかかってもデーモンは止まらない
            
            // 非同期でユーザー名を安全に解決
            let username = resolve_account(uid).await;

            // ロックなしで安全にログ出力
            eprintln!("{}[WARN] {} user={} not registered", ktime_prefix(), kind.as_str(), username);
            
            Err("ERR user not registered\n".to_string())
        }
    }
}

fn decision_message(
    kind: DecisionKind,
    args: &SignedCmdArgs,
) -> Result<String, String> {
    if matches!(kind, DecisionKind::Approve | DecisionKind::Deny)
        && is_mgmt_id(&args.id)
    {
        let audit_id = args.audit_id.as_deref()
            .ok_or("Missing audit_id")?;

        Ok(format!(
            "{}:{}:{}",
            kind.as_str(),
            args.id,
            audit_id
        ))
    } else {
        Ok(format!("{}:{}", kind.as_str(), args.id))
    }
}

fn verify_request(
    pubkey_hex: &str,
    kind: DecisionKind,
    args: &SignedCmdArgs,
) -> Result<(), String> {
    let message = decision_message(kind, args)?;

    verify_signature_message(
        pubkey_hex,
        message.as_bytes(),
        &args.sig_hex,
    ).map_err(|e| {
        eprintln!(
            "{}[WARN] {} verify failed: ID={} uid={} err={}",
            ktime_prefix(), kind.as_str(), args.id, args.uid, e
        );
        "ERR invalid signature\n".to_string()
    })?;

    Ok(())
}

fn verify_signature_message(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), String> {
    let pub_bytes = hex::decode(pubkey_hex).map_err(|_| "Invalid public key hex format".to_string())?;
    let pubkey = PublicKey::from_bytes(&pub_bytes).map_err(|e| format!("Invalid public key bytes: {:?}", e))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|_| "Invalid signature hex format".to_string())?;
    let signature = Signature::from_bytes(&sig_bytes).map_err(|e| format!("Invalid signature bytes: {:?}", e))?;

    match signature.verify(true, msg, TEAL_DST, &[], &pubkey, true) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err("Invalid BLS signature verification failed".to_string()),
    }
}

async fn fetch_pubkey_and_verify(uid: u32, kind: DecisionKind, args: &SignedCmdArgs) -> Result<(), String> {
    let pubkey_hex = fetch_public_key(uid, kind).await?;
    verify_request(&pubkey_hex, kind, args)?;
    Ok(())
}

const TEAL_DST: &[u8] = b"TEAL_SYSTEM_V1_MPA_SIG";

// --- 分岐と適用 ---
async fn apply_decision(
    kind: DecisionKind,
    args: SignedCmdArgs,
    nl_tx: Option<&NlWriter>
) -> (String, Option<InternalEvent>) {
    match kind {
        DecisionKind::Approve => process_approval(args, nl_tx.unwrap()).await,
        DecisionKind::Deny    => process_deny(args, nl_tx.unwrap()).await,
        DecisionKind::Ticket  => process_ticket(&args.id, args.uid, nl_tx.unwrap()).await,
        
        DecisionKind::Start => {
            let mgmt = management();
            check_initiator_and_handle(MgmtCtlKind::Start, &mgmt, args.uid, "", nl_tx.unwrap()).await
        }
        DecisionKind::Stop => {
            let mgmt = management();
            check_initiator_and_handle(MgmtCtlKind::Stop, &mgmt, args.uid, "", nl_tx.unwrap()).await
        }
        DecisionKind::PolicyUpdate => {
            let mgmt = management();
            check_initiator_and_handle(MgmtCtlKind::PolicyUpdate, &mgmt, args.uid, &args.id, nl_tx.unwrap()).await
        }
    }
}

enum ApprovalResult {
    Pending,
    CtlReady(MgmtPendingCtl),
    DraftReady,
    EntryReady,
}

async fn process_approval(
    args: SignedCmdArgs,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    let result = match record_approval(&args).await {
        Ok(result) => result,
        Err(e) => return (format!("ERR {}\n", e), None),
    };

    let event = match result {
        ApprovalResult::Pending => {
            return ("PENDING\n".to_string(), None);
        }

        ApprovalResult::CtlReady(pending_ctl) => {
            finalize_ctl_approval(pending_ctl, nl_tx)
                .await
                .map(Some)
        }

        ApprovalResult::DraftReady => {
            Ok(finalize_draft_approval(&args.id).await)
        }

        ApprovalResult::EntryReady => {
            Ok(finalize_entry_approval(&args, nl_tx).await)
        }
    };

    match event {
        Ok(Some(event)) => ("OK\n".to_string(), Some(event)),
        Ok(None) => (
            "ERR approval finalization failed\n".to_string(),
            None,
        ),
        Err(e) => (format!("ERR {}\n", e), None),
    }
}

async fn process_approve_entry(
    args: &SignedCmdArgs,
) -> Result<bool, String> {
    let id_num = args.id.parse::<u64>()
        .map_err(|_| "ERR invalid pending id".to_string())?;

    let mut st = app_state().lock().await;

    let pending = st.slow.pending_requests.get_mut(&id_num)
        .ok_or_else(|| "ERR no such pending id".to_string())?;

    check_fully_approved(
        args,
        &mut pending.mpa_state,
        pending.policy_epoch,
    )
}

async fn process_approve_draft(
    args: &SignedCmdArgs,
) -> Result<bool, String> {
    let mut st = app_state().lock().await;

    let pending = st.fast.drafts.get_mut(&args.id)
        .ok_or("ERR no such pending ticket")?;

    let expected_epoch = pending.epoch;

    if policy_snapshot().epoch != expected_epoch {
        return Err("Policy epoch changed".to_string());
    }

    check_fully_approved(
        args,
        &mut pending.mpa_state,
        expected_epoch,
    )
}

async fn process_approve_ctl(
    args: &SignedCmdArgs,
) -> Result<Option<MgmtPendingCtl>, String> {
    let mut st = app_state().lock().await;

    let pending = st.slow.pending_ctl.as_mut()
        .ok_or("ERR no pending management command")?;

    if !args.id.eq_ignore_ascii_case(pending.kind.as_str()) {
        return Err("Management command mismatch".to_string());
    }

    if args.audit_id.as_deref() != Some(pending.audit_id.as_str()) {
        return Err("Management audit_id mismatch".to_string());
    }

    let fulfilled = check_fully_approved(
        args,
        &mut pending.mpa_state,
        pending.epoch,
    )?;

    if !fulfilled {
        return Ok(None);
    }

    // MPA成立とPendingの取得を同一Mutex内で実行
    Ok(st.slow.pending_ctl.take())
}

/// 管理コマンドの最終決裁共通関数
async fn finalize_ctl_approval(
    mut pending_ctl: MgmtPendingCtl,
    nl_tx: &NlWriter,
) -> Result<InternalEvent, String> {
    // epoch整合性
    if pending_ctl.epoch != policy_snapshot().epoch {
        return Err("Policy epoch changed".to_string());
    }

    // MPA成立確認
    if !pending_ctl.mpa_state.is_fulfilled() {
        return Err("MPA requirements are not fulfilled".to_string());
    }

    // BLS署名集約（AppState Mutex外）
    pending_ctl = tokio::task::spawn_blocking(move || {
        pending_ctl.mpa_state.try_aggregate()?;
        Ok::<_, String>(pending_ctl)
    })
    .await
    .map_err(|e| format!("Aggregation task failed: {}", e))??;

    // 管理コマンド実行
    // epochはexecute_mgmt_ctl_core()でロック取得後に再確認
    execute_mgmt_ctl_core(
        pending_ctl.kind.clone(),
        &pending_ctl.target_hash,
        pending_ctl.epoch,
        nl_tx,
    )
    .await?;

    Ok(InternalEvent::CtlApproved { pending_ctl })
}

async fn finalize_draft_approval(id: &str) -> Option<InternalEvent> {
    // 1. Draftを取得し、Mutexを即座に解放
    let mut draft = {
        let mut st = app_state().lock().await;
        st.fast.drafts.remove(id)?
    };

    // 2. ENFORCEモード以外では終了
    if !is_enforce() {
        return None;
    }

    // 3. BLS署名の集約（Mutex外）
    if let Err(e) = draft.mpa_state.try_aggregate() {
        eprintln!(
            "{}[ERROR] Draft {}: signature aggregation failed: {}",
            ktime_prefix(), id, e
        );
        return None;
    }

    // 4. Ticketを生成（Mutex外）
    let ticket = match ApprovedTicket::from_draft(&draft) {
        Some(ticket) => ticket,
        None => {
            eprintln!(
                "{}[ERROR] can't generate ticket for draft={}",
                ktime_prefix(), draft.draft_id
            );
            return None;
        }
    };

    // 5. 承認済みTicketを登録（Mutex内）
    {
        let mut st = app_state().lock().await;
        st.fast.approved.insert(
            draft.draft_id.clone(),
            ticket.clone(),
        );
    }

    eprintln!(
        "{}[INFO] Draft {} approved (Lazy Binding).",
        ktime_prefix(), id
    );

    Some(InternalEvent::MpaApproved { draft, ticket })
}

async fn finalize_entry_approval(args: &SignedCmdArgs, nl_tx: &NlWriter) -> Option<InternalEvent> {
    let id_num = args.id.parse().unwrap_or(0);
    let mut event = None; 

    let entry = {
        let mut lock = app_state().lock().await;
        lock.slow.pending_requests.remove(&id_num)
    };

    let (cacheable, ticket_payload) = match entry {
        Some(mut removed_request) => {
            let rule_id = removed_request.rule_id.clone().unwrap_or_else(|| "".to_string());
            let (cacheable, ticket_payload, ticket_id) = match find_rule(Some(&rule_id)) {
                Ok((Some(rule), epoch)) => {
                    match removed_request.is_cacheable(&rule, epoch).await {
                        Ok(t) => t,
                        Err(msg) => {
                            eprintln!("{}[ERROR]{}", ktime_prefix(), msg);
                            (false, None, "".to_string())
                        }
                    }
                }
                Ok((None, epoch)) => {
                    eprintln!(
                        "{}[WARN] Cannot create cache: Rule is None, request_id={}, epoch={}",
                        ktime_prefix(),
                        id_num,
                        epoch
                    );
                    (false, None, "".to_string())
                }
                Err(msg) => {
                    eprintln!("{}[ERROR]{}", ktime_prefix(), msg);
                    (false, None, "".to_string())
                }
            };

            let _ = removed_request.mpa_state.try_aggregate();
            
            event = Some(InternalEvent::EntryApproved {
                entry: removed_request,
                cacheable,
                ticket_id,
            });
            
            (cacheable, ticket_payload)
        }
        None => (false, None)
    };

    if is_enforce() {
        let _ = nl_tx.send_approve(id_num).await;
        if cacheable {
            if let Some(ticket) = ticket_payload {
                let _ = nl_tx.send_ticket_add(ticket).await;
            }
        }
    }
    
    event
}

async fn record_approval(
    args: &SignedCmdArgs,
) -> Result<ApprovalResult, String> {
    if is_mgmt_id(&args.id) {
        return match process_approve_ctl(args).await? {
            Some(pending_ctl) => Ok(ApprovalResult::CtlReady(pending_ctl)),
            None => Ok(ApprovalResult::Pending),
        };
    }

    if is_draft_id(&args.id) {
        return if process_approve_draft(args).await? {
            Ok(ApprovalResult::DraftReady)
        } else {
            Ok(ApprovalResult::Pending)
        };
    }

    if process_approve_entry(args).await? {
        Ok(ApprovalResult::EntryReady)
    } else {
        Ok(ApprovalResult::Pending)
    }
}

fn check_fully_approved(
    args: &SignedCmdArgs,
    mpa_state: &mut MpaState,
    expected_epoch: u32,
) -> Result<bool, String> {
    mpa_state.insert_approver(args, expected_epoch)?;

    Ok(mpa_state.is_fulfilled())
}

async fn process_deny(
    args: SignedCmdArgs,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    if is_mgmt_id(&args.id) {
        process_deny_ctl(&args).await
    } else if is_draft_id(&args.id) {
        process_deny_draft(&args.id, args.uid).await
    } else {
        process_deny_entry(&args, nl_tx).await
    }
}

/// 保留中の管理コマンド要求を拒否する
async fn process_deny_ctl(
    args: &SignedCmdArgs,
) -> (String, Option<InternalEvent>) {
    let mut st = app_state().lock().await;

    // 1. Pending管理コマンドを取得
    let pending = match st.slow.pending_ctl.as_ref() {
        Some(p) => p,
        None => {
            return (
                "ERR no pending management command\n".to_string(),
                None,
            );
        }
    };

    // 2. コマンド種別の照合
    if !args.id.eq_ignore_ascii_case(pending.kind.as_str()) {
        return (
            format!(
                "ERR pending command is {}, not {}\n",
                pending.kind.as_str(),
                args.id,
            ),
            None,
        );
    }

    // 3. audit_idの照合
    if args.audit_id.as_deref() != Some(pending.audit_id.as_str()) {
        return (
            "ERR management audit_id mismatch\n".to_string(),
            None,
        );
    }

    // 4. 拒否権限の確認
    let (has_permission, _) = match check_permission(
        args.uid,
        &pending.mpa_state.required_roles,
        pending.epoch,
    ) {
        Ok(result) => result,
        Err(e) => return (format!("ERR {}\n", e), None),
    };

    if !has_permission {
        return (
            "ERR user is not allowed to deny\n".to_string(),
            None,
        );
    }

    // 5. 権限確認済みのPendingを取り出す
    let pending_ctl = st.slow.pending_ctl.take()
        .expect("pending_ctl was checked above");

    // Mutexはここで明示的に解放
    drop(st);

    let kind = pending_ctl.kind.clone();

    let event = Some(InternalEvent::CtlDenied {
        pending_ctl,
        denier_uid: args.uid,
    });

    (format!("OK {} denied\n", kind.as_str()), event)
}

async fn process_deny_draft(id: &str, uid: u32) -> (String, Option<InternalEvent>) {
    let (required_roles, expected_epoch) = {
        let lock = app_state().lock().await;

        match lock.fast.drafts.get(id) {
            Some(p) => (
                p.mpa_state.required_roles.clone(),
                p.epoch,
            ),
            None => {
                return ("ERR no such pending ticket\n".to_string(), None);
            }
        }
    };

    let (has_permission, _uid_roles) =
        match check_permission(uid, &required_roles, expected_epoch) {
            Ok(result) => result,
            Err(err) => return (format!("ERR {}\n", err), None),
        };

    if !has_permission {
        return ("ERR user are not allowed to deny\n".to_string(), None);
    }

    let mut event = None;
    let existed = {
        let mut lock = app_state().lock().await;

        // draft が存在していれば削除し、紐づく ticket も削除する
        if let Some(draft) = lock.fast.drafts.remove(id) {
            let ticket = ACTIVE_TICKETS.remove(id).map(|(_, ticket)| ticket).unwrap_or_default();
            event = Some(InternalEvent::DraftDenied { draft, ticket, denier_uid: uid });
            true
        } else {
            false // チェック直後に他の人が処理済みだった場合
        }
    };

    if !existed { 
        return ("ERR no such pending ticket\n".to_string(), None); 
    }

    ("DENIED\n".to_string(), event)
}

async fn process_deny_entry(args: &SignedCmdArgs, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    let id = args.id.parse().unwrap_or(0);
    
    let (required_roles, expected_epoch) = {
        let lock = app_state().lock().await;

        match lock.slow.pending_requests.get(&id) {
            Some(p) => (
                p.mpa_state.required_roles.clone(),
                p.policy_epoch,
            ),
            None => {
                return ("ERR no such pending ticket\n".to_string(), None);
            }
        }
    };

    let (has_permission, _uid_roles) =
        match check_permission(args.uid, &required_roles, expected_epoch) {
            Ok(result) => result,
            Err(err) => return (format!("ERR {}\n", err), None),
        };

    if !has_permission {
        return ("ERR user are not allowed to deny\n".to_string(), None);
    }

    let removed_request_opt = {
        let mut lock = app_state().lock().await;
        lock.slow.pending_requests.remove(&id)
    };

    let Some(removed_request) = removed_request_opt else {
        return ("ERR no such pending id\n".to_string(), None);
    };

    let event = Some(InternalEvent::EntryDenied { 
        entry: removed_request, 
        denier_uid: args.uid 
    });

    if is_enforce() {
        let _ = nl_tx.send_deny(id).await;
    }
    
    ("DENIED\n".to_string(), event)
}

async fn process_ticket(id: &str, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    if nl_tx.ticket_transition_active() {
        return ("ERR policy epoch transition in progress\n".to_string(), None);
    }
    let (rule, epoch) = match find_rule(Some(id)) {
        Ok((Some(rule), epoch)) => (rule, epoch),
        Ok((None, epoch)) => return (format!("ERR Rule id={} is None in policy epoch={}\n", id, epoch), None),
        Err(err) => return (format!("ERR {}\n", err), None),
    };

    if let Err(err) = is_ticketable(&rule) { return (format!("ERR {}\n", err), None); }
    let draft = match draft_from_rule(&rule, uid, epoch).await { Ok(d) => d, Err(err) => return (format!("ERR {}\n", err), None) };
    match is_allowed_user(uid, &rule, epoch) {
        Ok(true) => {}
        Ok(false) => {
            return ("ERR user is not allowed to ticket this rule\n".to_string(), None);
        }
        Err(err) => {
            return (format!("ERR {}\n", err), None);
        }
    }

    {
        let mut state = app_state().lock().await;
        if state.fast.has_draft_for_rule(&rule.id) { return ("ERR ticket is already in waiting list for approval\n".to_string(), None); }
        if policy_snapshot().epoch != epoch || nl_tx.ticket_transition_active() {
            return ("ERR policy epoch transition in progress\n".to_string(), None);
        }
        state.fast.drafts.insert(draft.draft_id.clone(), draft);
    }
    ("OK\n".to_string(), None)
}

/// 管理コマンド実行者の権限チェックとハンドラ呼び出しの共通関数
async fn check_initiator_and_handle(
    kind: MgmtCtlKind,
    mgmt: &CompiledManagement,
    uid: u32,
    target_hash: &str,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    // 1. kind に応じて該当操作の control (Option) を取得
    let control_opt = match kind {
        MgmtCtlKind::Start        => Some(&mgmt.controls.start),
        MgmtCtlKind::Stop         => Some(&mgmt.controls.stop),
        MgmtCtlKind::PolicyUpdate => mgmt.controls.policy_update.as_ref(),
        MgmtCtlKind::Flush        => mgmt.controls.flush.as_ref(),
    };

    // 2. コントロール自体がポリシーに定義されていない（None）場合は、
    //    「その操作は許可されていない（Fail-Safe）」として安全に拒否する
    let Some(control) = control_opt else {
        return (format!("ERR {} control is not configured in policy\n", kind.as_str()), None);
    };

    // 3. initiator 権限チェック
    if !control.initiator_uids.contains(&uid) {
        return (format!("ERR not permitted to {}\n", kind.as_str()), None);
    }

    // 4. 権限OKなら、handle_mgmt_cmd へ委約
    handle_mgmt_cmd(kind, mgmt, uid, target_hash, nl_tx).await
}

/// 管理コマンドの受付共通処理 (Start/Stop/PolicyUpdate/Flush)
async fn handle_mgmt_cmd(
    kind: MgmtCtlKind,
    mgmt: &CompiledManagement,
    uid: u32,
    target_hash: &str,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    // 1. kind に応じて該当操作の Control (Option含む) を取得
    let control_opt = match kind {
        MgmtCtlKind::Start        => Some(&mgmt.controls.start),
        MgmtCtlKind::Stop         => Some(&mgmt.controls.stop),
        MgmtCtlKind::PolicyUpdate => mgmt.controls.policy_update.as_ref(),
        MgmtCtlKind::Flush        => mgmt.controls.flush.as_ref(),
    };

    // 2. コントロールが存在し、かつ MPA が Enabled になっているか判定
    let mpa_config = control_opt
        .map(|ctrl| &ctrl.mpa)
        .unwrap_or(&CompiledMgmtMpa::Disabled); // コントロール未定義なら MPA 不要 (Disabled) 扱い

    // 3. MPAの有効/無効に応じて処理を分岐
    match mpa_config {
        CompiledMgmtMpa::Disabled => {
            // MPA不要: 即時実行
            execute_mgmt_ctl(kind, uid, target_hash, nl_tx).await
        }
        CompiledMgmtMpa::Enabled(mpa) => {
            // MPA必要: 承認待ち状態を作成
            create_mgmt_pending(kind, uid, target_hash, mpa).await
        }
    }
}

/// ライフサイクル管理コマンドの承認待ち(Pending)状態を作成する
async fn create_mgmt_pending(
    kind: MgmtCtlKind,
    uid: u32,
    target_hash: &str,
    mpa: &CompiledMgmtMpaEnabled
) -> (String, Option<InternalEvent>) {
    // 1. 事前準備：重い処理（名前解決とUUID生成）をロックの外で完全に終わらせる
    let initiator_user = resolve_account(uid).await;

    let audit_id = Uuid::new_v4().to_string();

    // 2. 具材が揃ったら、一瞬だけロックを取って状態を更新する
    {
        let mut st = app_state().lock().await; // ロック取得
        
        // 既に何らかの管理コマンドがPending中ならエラーにする（排他制御）
        if let Some(existing) = &st.slow.pending_ctl { 
            return (format!("ERR {} is already pending\n", existing.kind.as_str()), None); 
        }
        let epoch = policy_snapshot().epoch;
        st.slow.pending_ctl = Some(
            MgmtPendingCtl {
                kind: kind.clone(),
                initiator_uid: uid,
                initiator_user,
                audit_id,
                target_hash: target_hash.to_string(),
                epoch,
                mpa_state: MpaState {
                    threshold: mpa.threshold,
                    required_roles: mpa.approver_roles.clone(),
                    approvals: HashMap::new(),
                    aggregated_signature: None,
                },
                timeout_minutes: mpa.timeout_minutes,
            }
        );
    } // ここで即座にロック解放！

    ("PENDING\n".to_string(), None)
}

/// 管理コマンドの即時実行、またはMPA承認完了後の状態変更とカーネル通知を行う

static MGMT_EXEC_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

type MgmtResult<T> = Result<T, String>;

/// Kernel Epoch の成否が判定不能になった場合、通常処理を即時停止する。
/// panic! では管理タスクだけが終了してワーカーが動き続けるため使用しない。
/// プロセスのFDはOSにより閉じられ、Netlink切断通知から再登録が可能になる。
/// 注意: 現行カーネルの切断時Fail-Open動作までは変更しない。
fn terminate_on_epoch_uncertainty(operation: &str, old_epoch: u32, new_epoch: u32, cause: &str) -> ! {
    eprintln!(
        concat!(
            "{}[CRITICAL] {}: kernel epoch result UNKNOWN ({} -> {}): {}. ",
            "Stopping teald; policy files will NOT be rolled back. ",
            "Recovery requires REGISTER and a fresh Epoch synchronization."
        ),
        ktime_prefix(), operation, old_epoch, new_epoch, cause
    );
    std::process::exit(1);
}

struct MgmtOutcome {
    epoch: u32,
    // The caller may retain the original MPA-approved MgmtPendingCtl for audit.
}

struct PreparedPolicyUpdate {
    old_epoch: u32,
    new_epoch: u32,
    new_bundle: CompiledBundle,
    new_management: CompiledManagement,
    backup_dir: PathBuf,
}

async fn execute_mgmt_ctl(
    kind: MgmtCtlKind,
    uid: u32,
    target_hash: &str,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    // Serialize lifecycle operations. Other policy decision/ticket paths must
    // independently enforce epoch and transition safety.
    let request_epoch = policy_snapshot().epoch;

    let result = execute_mgmt_ctl_core(
        kind.clone(),
        target_hash,
        request_epoch,
        nl_tx,
    ).await;

    match result {
        Ok(outcome) => {
            let pending_ctl = MgmtPendingCtl {
                kind: kind.clone(),
                initiator_uid: uid,
                initiator_user: resolve_account(uid).await,
                audit_id: Uuid::new_v4().to_string(),
                target_hash: target_hash.to_string(),
                epoch: request_epoch,
                mpa_state: MpaState::default(),
                timeout_minutes: 0,
            };
            (
                format!("OK {} executed (Epoch: {})\n", kind.as_str(), outcome.epoch),
                Some(InternalEvent::CtlApproved { pending_ctl }),
            )
        }
        Err(e) => (format!("ERR {}: {}\n", kind.as_str(), e), None),
    }
}

async fn execute_mgmt_ctl_core(
    kind: MgmtCtlKind,
    target_hash: &str,
    expected_epoch: u32,
    nl_tx: &NlWriter,
) -> MgmtResult<MgmtOutcome> {
    let _guard = MGMT_EXEC_LOCK.lock().await;

    // 管理コマンドの実行直前にepoch確認
    let current_epoch = policy_snapshot().epoch;

    if current_epoch != expected_epoch {
        return Err(format!(
            "Policy epoch changed before management execution: expected={}, current={}",
            expected_epoch,
            current_epoch
        ));
    }

    match kind {
        MgmtCtlKind::Start => execute_start(nl_tx).await,
        MgmtCtlKind::Stop => execute_stop(nl_tx).await,
        MgmtCtlKind::PolicyUpdate => {
            execute_policy_update(target_hash, nl_tx).await
        }
        MgmtCtlKind::Flush => execute_flush(nl_tx).await,
    }
}

async fn execute_start(nl_tx: &NlWriter) -> MgmtResult<MgmtOutcome> {
    // Switch the kernel first. A send success may not imply kernel ACK.
    nl_tx.send_mode_switch(1).await.map_err(|e| e.to_string())?;

    let ids = {
        let mut state = app_state().lock().await;
        let ids = state.slow.pending_requests.keys().copied().collect::<Vec<_>>();
        clear_ephemeral_state_for_enforce(&mut state);
        state.is_flushed = false;
        set_daemon_mode(DaemonMode::Enforce);
        ids
    };
    for id in ids {
        if let Err(e) = nl_tx.send_deny(id).await {
            eprintln!("{}[WARN] failed to deny pending request {}: {}", ktime_prefix(), id, e);
        }
    }
    if let Err(e) = preload_silent_directory_tickets(nl_tx).await {
        eprintln!("{}[WARN] START succeeded, but preloading tickets failed: {}", ktime_prefix(), e);
    }
    Ok(MgmtOutcome { epoch: policy_snapshot().epoch })
}

async fn execute_stop(nl_tx: &NlWriter) -> MgmtResult<MgmtOutcome> {
    nl_tx.send_mode_switch(0).await.map_err(|e| e.to_string())?;
    {
        let mut state = app_state().lock().await;
        clear_ephemeral_state_for_enforce(&mut state);
        set_daemon_mode(DaemonMode::Audit);
    }
    Ok(MgmtOutcome { epoch: policy_snapshot().epoch })
}

async fn execute_policy_update(
    target_hash: &str,
    nl_tx: &NlWriter,
) -> MgmtResult<MgmtOutcome> {
    // Stop new ticket dispatch before validation / directory switching.
    // The guard is released on all ordinary returns; fatal paths exit teald.
    let ticket_guard = nl_tx.begin_ticket_transition().map_err(|e| e.to_string())?;
    let prepared = prepare_policy_update(target_hash).await?;
    let old_epoch = prepared.old_epoch;

    // The caller must ensure other kernel ticket-producing paths cannot race
    // through this transition; see integration notes.
    switch_policy_directory(&prepared).await?;

    if let Err(e) = synchronize_kernel_epoch(nl_tx, prepared.new_epoch).await {
        // ACKが欠落していても、kernelでは更新が完了している可能性がある。
        // /etc/teal.dを旧版に戻さず、処理を停止してREGISTER同期から復旧する。
        terminate_on_epoch_uncertainty(
            "POLICY_UPDATE", old_epoch, prepared.new_epoch, &e
        );
    }

    // ACK成功後にユーザー空間のSnapshot確定に失敗した場合も同期不整合。
    let new_epoch = match commit_policy_snapshot(
        prepared.new_bundle, old_epoch, prepared.new_epoch
    ) {
        Ok(epoch) => epoch,
        Err(e) => terminate_on_epoch_uncertainty(
            "POLICY_UPDATE snapshot commit", old_epoch, prepared.new_epoch, &e
        ),
    };

    // Prepared together with the staged bundle. Publication is infallible.
    // Both snapshots are switched while the ticket transition gate is held.
    commit_management(prepared.new_management);

    invalidate_old_approvals().await;
    drop(ticket_guard);
    if let Err(e) = preload_silent_directory_tickets(nl_tx).await {
        // Policy is committed. Never claim that the update was rolled back.
        eprintln!("{}[WARN] policy updated, but preloading tickets failed: {}", ktime_prefix(), e);
    }
    Ok(MgmtOutcome { epoch: new_epoch })
}

async fn prepare_policy_update(target_hash: &str) -> MgmtResult<PreparedPolicyUpdate> {
    let old_epoch = policy_snapshot().epoch;
    let new_epoch = old_epoch.checked_add(1).ok_or("epoch overflow")?;
    let target_hash = target_hash.to_owned();

    tokio::task::spawn_blocking(move || {
        validate_staged_policy(&target_hash)?;
        let new_bundle = compile_staged_bundle()?;
        let staged_management_path = std::path::Path::new(STAGE_TEAL_DIR)
            .join("management.json");
        let new_management = prepare_management(
            &staged_management_path, &new_bundle.roles
        ).map_err(|e| format!("staged management validation failed: {:#}", e))?;
        // Unique suffix prevents backup-directory collisions.
        let backup_dir = PathBuf::from(format!(
            "/var/lib/teal/epochs/epoch_{}_{}_{}",
            old_epoch,
            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            Uuid::new_v4()
        ));
        Ok(PreparedPolicyUpdate { old_epoch, new_epoch, new_bundle, new_management, backup_dir })
    })
    .await
    .map_err(|e| format!("policy preparation task failed: {}", e))?
}

fn validate_staged_policy(expected_hash: &str) -> MgmtResult<()> {
    let actual = compute_directory_hash(STAGE_TEAL_DIR)
        .map_err(|e| format!("staged policy hash failed: {}", e))?;
    if actual != expected_hash {
        return Err("TOCTOU validation failed: hash mismatch".into());
    }
    Ok(())
}

fn compile_staged_bundle() -> MgmtResult<CompiledBundle> {
    load_bundle_from_dir(STAGE_TEAL_DIR)
        .map_err(|e| format!("staged bundle compilation failed: {:#}", e))
}

async fn switch_policy_directory(update: &PreparedPolicyUpdate) -> MgmtResult<()> {
    let backup = update.backup_dir.clone();
    tokio::task::spawn_blocking(move || {
        let base = std::path::Path::new(DEFAULT_TEAL_DIR);
        let stage_child = backup.join("new");
        std::fs::create_dir_all("/var/lib/teal/epochs")
            .map_err(|e| format!("create backup parent: {}", e))?;
        // /etc/teal.d/new travels to backup/new with its parent.
        std::fs::rename(base, &backup)
            .map_err(|e| format!("backup current policy: {}", e))?;
        if let Err(e) = std::fs::rename(&stage_child, base) {
            std::fs::rename(&backup, base)
                .map_err(|rollback| format!("FATAL: apply failed ({e}), rollback failed ({rollback})"))?;
            return Err(format!("apply staged policy: {}", e));
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("directory switch task failed: {}", e))?
}

async fn synchronize_kernel_epoch(nl_tx: &NlWriter, epoch: u32) -> MgmtResult<()> {
    // send_sync_epoch() waits for the kernel NLMSG_ERROR(success ACK).
    nl_tx.send_sync_epoch(epoch).await.map_err(|e| format!("send epoch {}: {}", epoch, e))?;
    Ok(())
}

fn commit_policy_snapshot(
    new_bundle: CompiledBundle,
    expected_old_epoch: u32,
    expected_new_epoch: u32,
) -> MgmtResult<u32> {
    if policy_snapshot().epoch != expected_old_epoch {
        return Err("policy epoch changed during update".into());
    }
    let actual = update_bundle(new_bundle, expected_old_epoch)
        .map_err(|e| e.to_string())?;
    if actual != expected_new_epoch {
        return Err(format!("unexpected committed epoch {} != {}", actual, expected_new_epoch));
    }
    Ok(actual)
}

async fn invalidate_old_approvals() {
    let mut state = app_state().lock().await;
    state.fast.drafts.clear();
    state.fast.approved.clear();
    state.slow.pending_requests.clear();
    state.slow.pending_ctl = None;
    ACTIVE_TICKETS.clear();
}

async fn execute_flush(nl_tx: &NlWriter) -> MgmtResult<MgmtOutcome> {
    let ticket_guard = nl_tx.begin_ticket_transition().map_err(|e| e.to_string())?;
    let old_epoch = policy_snapshot().epoch;
    let new_epoch = old_epoch.checked_add(1).ok_or("epoch overflow")?;
    if let Err(e) = synchronize_kernel_epoch(nl_tx, new_epoch).await {
        terminate_on_epoch_uncertainty("FLUSH", old_epoch, new_epoch, &e);
    }
    let actual_epoch = match advance_epoch(old_epoch) {
        Ok(epoch) if epoch == new_epoch => epoch,
        Ok(epoch) => terminate_on_epoch_uncertainty(
            "FLUSH snapshot commit", old_epoch, new_epoch,
            &format!("committed unexpected epoch {}", epoch)
        ),
        Err(e) => terminate_on_epoch_uncertainty(
            "FLUSH snapshot commit", old_epoch, new_epoch, &e.to_string()
        ),
    };
    {
        let mut state = app_state().lock().await;
        state.is_flushed = true;
        clear_ephemeral_state_for_enforce(&mut state);
        state.fast.approved.clear();
    }
    drop(ticket_guard);
    Ok(MgmtOutcome { epoch: actual_epoch })
}

fn clear_ephemeral_state_for_enforce(state: &mut AppState) {
    state.fast.drafts.clear();
    ACTIVE_TICKETS.clear();
    state.slow.pending_requests.clear();
    state.slow.pending_ctl = None;
}

// --- ヘルパー関数 ---
fn check_permission(
    uid: u32,
    required_roles: &HashSet<String>,
    expected_epoch: u32,
) -> Result<(bool, HashSet<String>), String> {
    let snapshot = policy_snapshot();

    if snapshot.epoch != expected_epoch {
        return Err(format!(
            "Policy epoch changed: expected={}, current={}",
            expected_epoch,
            snapshot.epoch
        ));
    }

    let user_roles = snapshot.bundle.roles
        .assignments
        .uid_roles
        .get(&uid)
        .cloned()
        .unwrap_or_default();

    let has_permission = !user_roles.is_disjoint(required_roles);

    Ok((has_permission, user_roles))
}

fn is_draft_id(id: &str) -> bool { id.starts_with("T-") }

pub fn is_allowed_user(
    uid: u32,
    rule: &CompiledRule,
    expected_epoch: u32,
) -> Result<bool, String> {
    let snapshot = policy_snapshot();

    if snapshot.epoch != expected_epoch {
        return Err(format!(
            "Policy epoch changed: expected={}, current={}",
            expected_epoch,
            snapshot.epoch
        ));
    }

    let m = &rule.subject;
    let uid_roles = &snapshot.bundle.roles.assignments.uid_roles;
    let subject_roles = uid_roles.get(&uid).cloned().unwrap_or_default();

    if let Some(rule_uid) = m.uid {
        if uid != rule_uid {
            return Ok(false);
        }
    }

    if !m.required_roles.is_empty() {
        return Ok(
            m.required_roles.iter()
                .any(|r| subject_roles.contains(r))
        );
    }

    Ok(true)
}

static ACCOUNT_CACHE: Lazy<dashmap::DashMap<u32, String>> =
    Lazy::new(dashmap::DashMap::new);

async fn resolve_account(uid: u32) -> String {
    if let Some(name) = ACCOUNT_CACHE.get(&uid) {
        return name.value().clone();
    }

    let account = tokio::task::spawn_blocking(move || {
        uid_to_name(uid).unwrap_or_else(|_| uid.to_string())
    })
    .await
    .unwrap_or_else(|_| uid.to_string());

    ACCOUNT_CACHE.insert(uid, account.clone());
    account
}
