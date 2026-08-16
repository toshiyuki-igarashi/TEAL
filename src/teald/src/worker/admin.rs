// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;

use crate::state::app_state;
use crate::bundle::bundle;
use crate::management::management;
use crate::common::DecisionKind;
use crate::types::{InternalEvent, MgmtPendingCtl, MgmtCtlKind, MpaState, AppState, SignedCmdArgs, ApprovedTicket};
use crate::types::ACTIVE_TICKETS;
use crate::ticket::{is_ticketable, draft_from_rule};
use crate::netlink::NlWriter;

use teal_policy_engine::util::{uid_to_name, ktime_prefix};
use teal_policy_engine::management::{CompiledManagement, CompiledMgmtMpa, CompiledMgmtMpaEnabled};
use teal_policy_engine::ir::CompiledRule;

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
        "LIST"          => handle_list(&cmd, uid).await,
        "REGISTER"      => handle_register(&cmd, uid).await,
        "TICKET"        => handle_ticket(&cmd, uid).await,
        "APPROVE"       => handle_approve(&cmd, uid, nl_tx).await,
        "DENY"          => handle_deny(&cmd, uid, nl_tx).await,

        // 【署名が必要なライフサイクル操作】
        "START"         => handle_mgmt(&cmd, MgmtCtlKind::Start, DecisionKind::Start, uid, nl_tx).await,
        "STOP"          => handle_mgmt(&cmd, MgmtCtlKind::Stop, DecisionKind::Stop, uid, nl_tx).await,
        
        // 【署名なしの管理・特権操作（直接チェック＆実行へ流す）】
        "POLICY_UPDATE" => check_initiator_and_handle(MgmtCtlKind::PolicyUpdate, &mgmt, uid, nl_tx).await,
        "FLUSH"         => check_initiator_and_handle(MgmtCtlKind::Flush, &mgmt, uid, nl_tx).await,

        _ => ("ERR unknown cmd\n".to_string(), None),
    };

    let _ = stream.write_all(response.as_bytes()).await;
    event
}

// --- 各コマンドの入り口 ---
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

        s.push_str(&format!("ID: {} | UID: {} | Status: {} | MPA: {}/{} | Roles: {:?} | timeout_minutes: {}\n",
            label, 
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

async fn handle_ticket(cmd: &str, uid: u32) -> (String, Option<InternalEvent>) {
    handle_signed_decision(cmd, DecisionKind::Ticket, uid, None).await
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
        uid_to_name(uid).unwrap_or_else(|_| "".to_string())
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
    let args = match parse_args(cmd, kind, uid) {
        Ok(a) => a,
        Err(err_msg) => return (err_msg, None),
    };

    if let Err(err_msg) = fetch_pubkey_and_verify(uid, kind, &args).await {
        return (err_msg, None);
    }

    apply_decision(kind, args, nl_tx).await
}

fn parse_args(cmd: &str, kind: DecisionKind, uid: u32) -> Result<SignedCmdArgs, String> {
    let mut it = cmd.split_whitespace();
    let head = it.next().unwrap_or_else(|| "");
    if head != kind.as_str() { return Err(format!("ERR bad cmd head (expected {})\n", kind.as_str())); }

    let id: String = match kind {
        DecisionKind::Approve | DecisionKind::Deny | DecisionKind::Ticket => {
            it.next().ok_or("ERR missing/invalid id\n")?.to_string()
        }
        _ => "".to_string(),
    };

    let sig_hex = it.next().ok_or_else(|| "ERR missing signature\n".to_string())?.to_string();
    if it.next().is_some() { return Err("ERR too many args\n".to_string()); }

    Ok(SignedCmdArgs { id, uid, sig_hex })
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
            let username = tokio::task::spawn_blocking(move || {
                uid_to_name(uid).unwrap_or_else(|_| "".to_string())
            })
            .await
            .unwrap_or_default();

            // ロックなしで安全にログ出力
            eprintln!("{}[WARN] {} user={} not registered", ktime_prefix(), kind.as_str(), username);
            
            Err("ERR user not registered\n".to_string())
        }
    }
}

fn verify_request(pubkey_hex: &str, kind: DecisionKind, args: &SignedCmdArgs) -> Result<(), String> {
    if let Err(e) = verify_decision_signature(pubkey_hex, kind.as_str(), &args.id, &args.sig_hex) {
        eprintln!("{}[WARN] {} verify failed: ID={} user={} err={}", ktime_prefix(), kind.as_str(), args.id, uid_to_name(args.uid).unwrap_or_else(|_| "".to_string()), e);
        return Err("ERR invalid signature\n".to_string());
    }
    eprintln!("{}[INFO] {} verified: ID={} user={}", ktime_prefix(), kind.as_str(), args.id, uid_to_name(args.uid).unwrap_or_else(|_| "".to_string()));
    Ok(())
}

fn verify_decision_signature(pubkey_hex: &str, kind: &str, id: &str, sig_hex: &str) -> Result<(), String> {
    let msg_str = format!("{}:{}", kind, id);
    verify_signature_message(pubkey_hex, msg_str.as_bytes(), sig_hex)
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
        DecisionKind::Ticket  => process_ticket(&args.id, args.uid).await,
        
        DecisionKind::Start => {
            let mgmt = management();
            check_initiator_and_handle(MgmtCtlKind::Start, &mgmt, args.uid, nl_tx.unwrap()).await
        }
        DecisionKind::Stop => {
            let mgmt = management();
            check_initiator_and_handle(MgmtCtlKind::Stop, &mgmt, args.uid, nl_tx.unwrap()).await
        }
    }
}

async fn process_approval(args: SignedCmdArgs, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    match record_approval(&args).await {
        Ok(true) => {
            eprintln!("{}[INFO] APPROVE record finalized: ID={} user={}",
                ktime_prefix(), args.id, uid_to_name(args.uid).unwrap_or_else(|_| "".to_string())
            );
            let event = finalize_approval(&args, nl_tx).await;
            ("OK\n".to_string(), event)
        }
        Ok(false) => {
            eprintln!("{}[INFO] APPROVE record pending: ID={} user={}",
                ktime_prefix(), args.id, uid_to_name(args.uid).unwrap_or_else(|_| "".to_string())
            );
            ("PENDING\n".to_string(), None)
        }
        Err(e) => {
            eprintln!("{}[INFO] APPROVE record failed: ID={} user={} err={}",
                ktime_prefix(), args.id, uid_to_name(args.uid).unwrap_or_else(|_| "".to_string()), e
            );
            (format!("ERR {}\n", e), None)
        }
    }
}

fn is_mgmt_id(id: &str) -> bool {
    let id_upper = id.to_uppercase();
    matches!(id_upper.as_str(), "START" | "STOP" | "RELOAD" | "POLICY_UPDATE" | "FLUSH")
}

async fn finalize_approval(args: &SignedCmdArgs, nl_tx: &NlWriter) -> Option<InternalEvent> {
    if is_mgmt_id(&args.id) {
        finalize_ctl_approval(nl_tx).await
    } else if is_draft_id(&args.id) {
        finalize_draft_approval(&args.id).await
    } else {
        finalize_entry_approval(args, nl_tx).await
    }
}

async fn process_approve_entry(args: &SignedCmdArgs) -> Result<bool, String> {
    let id_num = args.id.parse().unwrap_or(0);

    // 1. 必要なデータ（MpaState）だけをクローンして取り出し、即座にロックを解除する
    let mut current_mpa_state = {
        let lock = app_state().lock().await;
        let pending = lock.slow.pending_requests.get(&id_num)
            .ok_or_else(|| "no such pending id".to_string())?;
        pending.mpa_state.clone() // 状態のコピーをもらう
    }; // ここでスコープを抜け、ロック解除！

    // 2. ロックを持たない安全な状態で、CPU計算（ロールチェックや要素の削除）を行う
    let is_fulfilled = check_fully_approved(args, &mut current_mpa_state)?;

    // 3. 計算結果（更新されたMpaState）を、もう一度一瞬だけロックを取って書き戻す
    {
        let mut lock = app_state().lock().await;
        if let Some(pending) = lock.slow.pending_requests.get_mut(&id_num) {
            pending.mpa_state = current_mpa_state; // 結果を反映
        }
    } // 即解除

    Ok(is_fulfilled)
}

async fn process_approve_draft(args: &SignedCmdArgs) -> Result<bool, String> {
    // 1. 必要なデータ（MpaState）だけをクローンして取り出し、即座にロックを解除する
    let mut current_mpa_state = {
        let lock = app_state().lock().await; // ロック取得
        let pending = lock.fast.drafts.get(&args.id)
            .ok_or_else(|| "no such pending ticket".to_string())?;
        pending.mpa_state.clone() // 状態のコピーをもらう
    }; // ここでスコープを抜け、即座にロック解除！

    // 2. ロックを持たない安全な状態で、CPU計算（ロールチェックや要素の削除）を行う
    let is_fulfilled = check_fully_approved(args, &mut current_mpa_state)?;

    // 3. 計算結果（更新されたMpaState）を、もう一度一瞬だけロックを取って書き戻す
    {
        let mut lock = app_state().lock().await; // ロック再取得
        // ※書き戻す前に、対象がまだ存在するか確認する（競合対策）
        if let Some(pending) = lock.fast.drafts.get_mut(&args.id) {
            pending.mpa_state = current_mpa_state; // 結果を反映
        }
    } // 即解除

    Ok(is_fulfilled)
}

async fn process_approve_ctl(args: &SignedCmdArgs) -> Result<bool, String> {
    // 1. 必要なデータ（MpaState）だけをクローンして取り出し、即座にロックを解除
    let mut current_mpa_state = {
        let st = app_state().lock().await;
        match &st.slow.pending_ctl {
            Some(p) => p.mpa_state.clone(),
            None => return Err("ERR no pending management command\n".to_string()),
        }
    }; // ここでスコープを抜け、確実にロック解放！

    // 2. ロックを持たない安全な状態で、CPU計算（ロールチェックや要素の追加）を行う
    let is_fulfilled = check_fully_approved(args, &mut current_mpa_state)?;

    // 3. 計算結果を、もう一度一瞬だけロックを取って書き戻す
    {
        let mut st = app_state().lock().await;
        if let Some(pending) = st.slow.pending_ctl.as_mut() {
            pending.mpa_state = current_mpa_state; // 署名追加・状態更新結果を反映
        }
    } // 即解放

    Ok(is_fulfilled)
}

/// 管理コマンドの最終決裁共通関数
async fn finalize_ctl_approval(
    nl_tx: &NlWriter,
) -> Option<InternalEvent> {
    // 1. まず所有権を取り出す (try_aggregate で内部状態を変更するため mut を付与)
    let mut pending_ctl = {
        let mut st = app_state().lock().await;
        st.slow.pending_ctl.take()?
    };

    let kind = pending_ctl.kind.clone();
    let uid = pending_ctl.initiator_uid;

    // 2. 暗号計算 (BLS集約) はロック外で実行
    // (受け取る側はその後可変操作を行わないため mut は不要)
    let pending_ctl = tokio::task::spawn_blocking(move || {
        let _ = pending_ctl.mpa_state.try_aggregate();
        pending_ctl
    })
    .await
    .ok()?;

    // 3. kind に応じた実行ロジックへ委約
    execute_mgmt_ctl(kind, uid, nl_tx).await;

    // 4. 承認イベントを返す
    Some(InternalEvent::CtlApproved { pending_ctl })
}

async fn finalize_draft_approval(id: &str) -> Option<InternalEvent> {
    let mut event = None;
    let is_enforce;
    let mut draft;

    {
        let mut lock = app_state().lock().await;
        draft = lock.fast.drafts.remove(id)?;
        is_enforce = lock.is_enforce;
    }

    if is_enforce {
        let _ = draft.mpa_state.try_aggregate();

        if let Some(ticket) = ApprovedTicket::from_draft(&draft) {
            event = Some(InternalEvent::MpaApproved { draft: draft.clone(), ticket: ticket.clone() });
            let mut lock = app_state().lock().await;
            lock.fast.approved.insert(draft.draft_id.clone(), ticket);
        } else {
            eprintln!("{}[ERROR] can't generate ticket for draft={}", ktime_prefix(), draft.draft_id);
            return None;
        }
        eprintln!("{}[INFO] Draft {} approved. Ticket cached to kernel (Lazy Binding).", ktime_prefix(), id);
    }
    event
}

async fn finalize_entry_approval(args: &SignedCmdArgs, nl_tx: &NlWriter) -> Option<InternalEvent> {
    let id_num = args.id.parse().unwrap_or(0);
    let mut event = None; 

    let (is_enforce, entry) = {
        let mut lock = app_state().lock().await;
        let entry_opt = lock.slow.pending_requests.remove(&id_num);
        (lock.is_enforce, entry_opt)
    };

    let (cacheable, ticket_payload) = match entry {
        Some(mut removed_request) => {
            let rule_id = removed_request.rule_id.clone().unwrap_or_else(|| "".to_string());
            let (cacheable, ticket_payload, ticket_id) = match find_rule(&rule_id) {
                Ok(rule) => {
                    match removed_request.is_cacheable(&rule).await {
                        Ok(t) => t,
                        Err(msg) => {
                            eprintln!("{}[ERROR]{}", ktime_prefix(), msg);
                            (false, None, "".to_string())
                        }
                    }
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

    if is_enforce {
        let _ = nl_tx.send_approve(id_num).await;
        if cacheable {
            if let Some(ticket) = ticket_payload {
                let _ = nl_tx.send_ticket_add(ticket).await;
            }
        }
    }
    
    event
}

async fn record_approval(args: &SignedCmdArgs) -> Result<bool, String> {
    if is_mgmt_id(&args.id) {
        process_approve_ctl(args).await
    } else if is_draft_id(&args.id) {
        process_approve_draft(args).await
    } else {
        process_approve_entry(args).await
    }
}

fn check_fully_approved(args: &SignedCmdArgs, mpa_state: &mut MpaState) -> Result<bool, String> {
    let (has_permission, uid_roles) = check_permission(args.uid, &mpa_state.approver_roles);
    if has_permission { 
        for r in uid_roles { mpa_state.required_roles.retain(|role| role != &r); } 
    } else { return Err("user are not allowed to approve\n".to_string()); } 
    mpa_state.insert_approver(args);
    Ok(mpa_state.is_fulfilled())
}

async fn process_deny(args: SignedCmdArgs, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    if is_mgmt_id(&args.id) { 
        process_deny_ctl(&args.id, args.uid).await 
    }
    else if is_draft_id(&args.id) { process_deny_draft(&args.id, args.uid).await }
    else { process_deny_entry(&args, nl_tx).await }
}

/// 保留中の管理コマンド要求を拒否する
async fn process_deny_ctl(cmd_id: &str, uid: u32) -> (String, Option<InternalEvent>) {
    // 1. 引数(cmd_id)から、ユーザーが何を拒否しようとしているか推測する
    let expected_kind = match cmd_id {
        "start" => MgmtCtlKind::Start,
        "stop" => MgmtCtlKind::Stop,
        "policy_update" | "reload" => MgmtCtlKind::PolicyUpdate,
        "flush" => MgmtCtlKind::Flush,
        _ => return (format!("ERR unknown management command {}\n", cmd_id), None),
    };

    // 2. 必要なデータ（検証用のロール）を一瞬でコピーしてロック解放
    let (approver_roles, kind) = {
        let st = app_state().lock().await;
        match st.slow.pending_ctl.as_ref() {
            Some(p) if p.kind == expected_kind => {
                // 要求されたコマンドと、実際に保留中のコマンドが完全に一致！
                (p.mpa_state.approver_roles.clone(), p.kind.clone())
            },
            Some(p) => {
                // 誤爆防止: 要求と実際の保留状態が食い違っている
                return (format!("ERR pending command is {}, not {}\n", p.kind.as_str(), expected_kind.as_str()), None);
            },
            None => {
                return (format!("ERR no pending {} command\n", expected_kind.as_str()), None);
            }
        }
    }; // 即解放

    // 3. ロックを持たない安全な状態で権限チェック
    let has_permission = check_permission(uid, &approver_roles).0;

    // 4. 権限があれば再度ロックを取って対象を取り除く (take)
    if has_permission {
        let pending = {
            let mut st = app_state().lock().await;
            // 競合状態を防ぐため、取り出す直前に再度 kind の一致を確認して take()
            if st.slow.pending_ctl.as_ref().map(|p| &p.kind) == Some(&kind) {
                st.slow.pending_ctl.take()
            } else {
                None
            }
        }; // 即解放

        if let Some(pending_ctl) = pending {
            let event = Some(InternalEvent::CtlDenied {
                pending_ctl,
                denier_uid: uid,
            });
            (format!("OK {} denied\n", kind.as_str()), event)
        } else {
            ("ERR pending command was already processed\n".to_string(), None)
        }
    } else {
        ("ERR user is not allowed to deny\n".to_string(), None)
    }
}

async fn process_deny_draft(id: &str, uid: u32) -> (String, Option<InternalEvent>) {
    // 1. まず一瞬だけロックを取り、判定に必要な「ロール」だけをコピーする
    let approver_roles = {
        let lock = app_state().lock().await;
        match lock.fast.drafts.get(id) {
            Some(p) => p.mpa_state.approver_roles.clone(),
            None => return ("ERR no such pending ticket\n".to_string(), None),
        }
    }; // ここで即座にロック解放！

    // 2. ロックを持たない安全な状態で、1回だけ権限チェックを行う
    let (has_permission, _uid_roles) = check_permission(uid, &approver_roles);

    if !has_permission {
        return ("ERR user are not allowed to deny\n".to_string(), None);
    }

    // 3. 権限がある場合のみ、再度一瞬だけロックを取って「削除 (remove)」する
    let mut event = None;
    let existed = {
        let mut lock = app_state().lock().await; // ロック再取得
        
        // draft が存在していれば削除し、紐づく ticket も削除する
        if let Some(draft) = lock.fast.drafts.remove(id) {
            let ticket = ACTIVE_TICKETS.remove(id).map(|(_, ticket)| ticket).unwrap_or_default();
            event = Some(InternalEvent::DraftDenied { draft, ticket, denier_uid: uid });
            true
        } else {
            false // チェック直後に他の人が処理済みだった場合
        }
    }; // 即解放！

    if !existed { 
        return ("ERR no such pending ticket\n".to_string(), None); 
    }
    
    ("DENIED\n".to_string(), event)
}

async fn process_deny_entry(args: &SignedCmdArgs, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    let id = args.id.parse().unwrap_or(0);
    
    // 1. まず一瞬だけロックを取り、判定に必要な「ロール」と「ENFORCE状態」だけをコピーする
    let (is_enforce, approver_roles) = {
        let lock = app_state().lock().await;
        let entry = match lock.slow.pending_requests.get(&id) {
            Some(p) => p,
            None => return ("ERR no such pending id\n".to_string(), None),
        };
        (lock.is_enforce, entry.mpa_state.approver_roles.clone())
    }; // ここで即座にロック解放！

    // 2. ロックを持たない安全な状態で、1回だけ権限チェックを行う
    let (has_permission, uid_roles) = check_permission(args.uid, &approver_roles);

    if !has_permission {
        return ("ERR user are not allowed to deny\n".to_string(), None);
    }

    // 3. 権限がある場合のみ、再度一瞬だけロックを取って「削除 (remove)」する
    let removed_request_opt = {
        let mut lock = app_state().lock().await;
        lock.slow.pending_requests.remove(&id)
    }; // 即解放！

    // 4. 削除できた要素に対して、ロックなしで変更（履歴の追加）を加え、イベントを生成
    let Some(mut removed_request) = removed_request_opt else {
        // チェック直後に他の人が処理済みだった場合
        return ("ERR no such pending id\n".to_string(), None);
    };

    // ここまで到達したということは削除成功 (removed_request) が確定している
    for r in uid_roles { 
        removed_request.mpa_state.required_roles.retain(|role| role != &r); 
    } 
    removed_request.mpa_state.insert_approver(args);
    
    let event = Some(InternalEvent::EntryDenied { 
        entry: removed_request, 
        denier_uid: args.uid 
    });

    // 5. I/O処理（カーネルへの通知）
    if is_enforce {
        let _ = nl_tx.send_deny(id).await;
    }
    
    ("DENIED\n".to_string(), event)
}

async fn process_ticket(id: &str, uid: u32) -> (String, Option<InternalEvent>) {
    let rule = match find_rule(id) { Ok(r) => r, Err(err) => return (format!("ERR {}\n", err), None) };
    if let Err(err) = is_ticketable(&rule) { return (format!("ERR {}\n", err), None); }
    let draft = match draft_from_rule(&rule, uid).await { Ok(d) => d, Err(err) => return (format!("ERR {}\n", err), None) };
    if !is_allowed_user(uid, &rule) { return ("ERR user is not allowed to ticket this rule\n".to_string(), None); }
    
    {
        let mut state = app_state().lock().await;
        if state.fast.has_draft_for_rule(&rule.id) { return ("ERR ticket is already in waiting list for approval\n".to_string(), None); }
        state.fast.drafts.insert(draft.draft_id.clone(), draft);
    }
    ("OK\n".to_string(), None)
}

/// 管理コマンド実行者の権限チェックとハンドラ呼び出しの共通関数
async fn check_initiator_and_handle(
    kind: MgmtCtlKind,
    mgmt: &CompiledManagement,
    uid: u32,
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
    handle_mgmt_cmd(kind, mgmt, uid, nl_tx).await
}

/// 管理コマンドの受付共通処理 (Start/Stop/PolicyUpdate/Flush)
async fn handle_mgmt_cmd(
    kind: MgmtCtlKind,
    mgmt: &CompiledManagement,
    uid: u32,
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
            execute_mgmt_ctl(kind, uid, nl_tx).await
        }
        CompiledMgmtMpa::Enabled(mpa) => {
            // MPA必要: 承認待ち状態を作成
            create_mgmt_pending(kind, uid, mpa).await
        }
    }
}

/// ライフサイクル管理コマンドの承認待ち(Pending)状態を作成する
async fn create_mgmt_pending(
    kind: MgmtCtlKind,
    uid: u32,
    mpa: &CompiledMgmtMpaEnabled
) -> (String, Option<InternalEvent>) {
    // 1. 事前準備：重い処理（名前解決とUUID生成）をロックの外で完全に終わらせる
    let initiator_user = tokio::task::spawn_blocking(move || {
        uid_to_name(uid).unwrap_or_else(|_| "".to_string())
    })
    .await
    .unwrap_or_default();
    
    let audit_id = Uuid::new_v4().to_string();

    // 2. 具材が揃ったら、一瞬だけロックを取って状態を更新する
    {
        let mut st = app_state().lock().await; // ロック取得
        
        // 既に何らかの管理コマンドがPending中ならエラーにする（排他制御）
        if let Some(existing) = &st.slow.pending_ctl { 
            return (format!("ERR {} is already pending\n", existing.kind.as_str()), None); 
        }
        
        st.slow.pending_ctl = Some(
            MgmtPendingCtl {
                kind: kind.clone(),
                initiator_uid: uid,
                initiator_user,
                audit_id,
                mpa_state: MpaState {
                    threshold: mpa.threshold,
                    approver_roles: mpa.approver_roles.clone(),
                    required_roles: mpa.approver_roles.clone(),
                    approvals: HashMap::new(),
                    aggregated_signature: None
                },
                timeout_minutes: mpa.timeout_minutes
            }
        );
    } // ここで即座にロック解放！
    
    ("PENDING\n".to_string(), None)
}

/// 管理コマンドの即時実行、またはMPA承認完了後の状態変更とカーネル通知を行う
async fn execute_mgmt_ctl(
    kind: MgmtCtlKind,
    uid: u32,
    nl_tx: &NlWriter,
) -> (String, Option<InternalEvent>) {
    // 1. ロック前に重い処理（名前解決・UUID生成）を実行
    let initiator_user_str = tokio::task::spawn_blocking(move || {
        uid_to_name(uid).unwrap_or_else(|_| "".to_string())
    })
    .await
    .unwrap_or_default();

    let generated_audit_id = Uuid::new_v4().to_string();

    // 即時実行用の監査イベント生成 (承認情報はデフォルトで空)
    let pending_ctl = MgmtPendingCtl {
        kind: kind.clone(),
        initiator_uid: uid,
        initiator_user: initiator_user_str,
        audit_id: generated_audit_id,
        mpa_state: MpaState::default(), // MpaState::default() を使用
        timeout_minutes: 0,
    };
    let event = Some(InternalEvent::CtlApproved {
        pending_ctl: pending_ctl.clone(),
    });

    let mut pending_deny_ids = Vec::new();
    let current_epoch: u32;

    // 2. ロックを取得してインメモリ状態を更新 (フェーズ1)
    {
        let mut st = app_state().lock().await;

        match kind {
            MgmtCtlKind::Start => {
                if st.is_flushed {
                    st.is_flushed = false; // ネットワーク復旧
                }
                if !st.slow.pending_requests.is_empty() {
                    pending_deny_ids = st.slow.pending_requests.keys().cloned().collect();
                    eprintln!(
                        "{}[WARN] Auto-denying {} pending requests before ENFORCE start.",
                        ktime_prefix(),
                        pending_deny_ids.len()
                    );
                }
                clear_ephemeral_state_for_enforce(&mut st);
                st.is_enforce = true;
            }
            MgmtCtlKind::Stop => {
                st.is_enforce = false;
                clear_ephemeral_state_for_enforce(&mut st);
            }
            MgmtCtlKind::PolicyUpdate => {
                // TODO: 今後の本実装で、新 bundle.json の検証・コンパイル・アトミック差し替えを行う。
                // 現在はEpochの更新とキャッシュクリアのみを行うスタブ（骨組み）として動作。
                st.current_epoch = st.current_epoch.wrapping_add(1);
                st.fast.drafts.clear();
                st.fast.approved.clear();
                ACTIVE_TICKETS.clear();
            }
            MgmtCtlKind::Flush => {
                st.is_flushed = true;
                st.current_epoch = st.current_epoch.wrapping_add(1);
                clear_ephemeral_state_for_enforce(&mut st);
            }
        }

        current_epoch = st.current_epoch;
        st.slow.pending_ctl = None; // 管理コマンドの承認待ち状態を解除
    } // ロック解放

    // 3. ロック外で安全に外部I/O（Netlink送信など）を実行 (フェーズ2)
    match kind {
        MgmtCtlKind::Start => {
            for id in pending_deny_ids {
                let _ = nl_tx.send_deny(id).await;
            }
            let _ = nl_tx.send_mode_switch(1).await;
        }
        MgmtCtlKind::Stop => {
            let _ = nl_tx.send_mode_switch(0).await;
        }
        MgmtCtlKind::PolicyUpdate => {
            // TODO: カーネルへ Epoch 更新メッセージを送る本実装時に有効化
            // let _ = nl_tx.send_sync_epoch(current_epoch).await;
        }
        MgmtCtlKind::Flush => {
            // TODO: カーネルへ Epoch 更新メッセージを送る本実装時に有効化
            // let _ = nl_tx.send_sync_epoch(current_epoch).await;
        }
    }

    (
        format!("OK {} executed (Epoch: {})\n", kind.as_str(), current_epoch),
        event,
    )
}

fn clear_ephemeral_state_for_enforce(state: &mut AppState) {
    state.fast.drafts.clear();
    ACTIVE_TICKETS.clear();
    state.slow.pending_requests.clear();
    state.slow.pending_ctl = None;
}

// --- ヘルパー関数 ---
fn check_permission(uid: u32, approver_roles: &HashSet<String>) -> (bool, HashSet<String>) {
    let b = bundle();
    let user_roles = b.roles.assignments.uid_roles.get(&uid).cloned().unwrap_or_default();
    let has_permission = !user_roles.is_disjoint(approver_roles);
    (has_permission, user_roles)
}

fn is_draft_id(id: &str) -> bool { id.starts_with("T-") }

pub fn find_rule(id: &str) -> Result<CompiledRule, String> {
    let b = bundle();
    for rule in &b.policy.rules { if rule.id == id { return Ok(rule.clone()); } }
    Err(format!("Rule id={} is not found", id))
}

pub fn is_allowed_user(uid: u32, rule: &CompiledRule) -> bool {
    let m = &rule.subject;
    let uid_roles = &bundle().roles.assignments.uid_roles;
    let subject_roles = uid_roles.get(&uid).cloned().unwrap_or_default();

    if let Some(rule_uid) = m.uid { if uid != rule_uid { return false; } }
    if !m.required_roles.is_empty() {
        if m.required_roles.iter().any(|r| subject_roles.contains(r)) { return true; } 
        else { return false; }
    }
    true
}
