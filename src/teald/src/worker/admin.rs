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

use crate::app_state;
use crate::bundle::bundle;
use crate::management::management;
use crate::common::DecisionKind;
use crate::types::{InternalEvent, MgmtPendingStart, MgmtPendingStop, MpaState, AppState, SignedCmdArgs, ApprovedTicket};
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

    // Netlinkの送信が必要なコマンドには nl_tx を渡す
    let (response, event) = match cmd_name {
        "LIST"     => handle_list(&cmd, uid).await,
        "REGISTER" => handle_register(&cmd, uid).await,
        "TICKET"   => handle_ticket(&cmd, uid).await,
        "APPROVE"  => handle_approve(&cmd, uid, nl_tx).await,
        "DENY"     => handle_deny(&cmd, uid, nl_tx).await,
        "START"    => handle_start(&cmd, uid, nl_tx).await,
        "STOP"     => handle_stop(&cmd, uid, nl_tx).await,
        _ => ("ERR unknown cmd\n".to_string(), None),
    };

    let _ = stream.write_all(response.as_bytes()).await;
    event
}

// --- 各コマンドの入り口 ---
async fn handle_list(_cmd: &str, _uid: u32) -> (String, Option<InternalEvent>) {
    let lock = app_state().lock().await;

    if lock.fast.drafts.is_empty() 
        && lock.slow.pending_requests.is_empty() 
        && lock.slow.pending_start.is_none()
        && lock.slow.pending_stop.is_none() 
    {
        return ("No pending requests.\n".to_string(), None);
    }

    let mut s = String::new();

    for (id, draft) in &lock.fast.drafts {
        s.push_str(&format!("DRAFT ID: {} | Rule-ID: {} | Status: {} | MPA: {}/{} | Roles: {:?} | timeout_minutes: {} | max_uses = {}\n",            
            id, draft.rule_id, draft.mpa_state.is_fulfilled(), draft.mpa_state.approvals.len(), draft.mpa_state.threshold, draft.mpa_state.required_roles, draft.ttl_sec, draft.max_uses,
        ));
    }

    if let Some(start) = &lock.slow.pending_start {
        s.push_str(&format!("ID: START | UID: {} | Status: {} | MPA: {}/{} | Roles: {:?} | timeout_minutes: {}\n",
            start.initiator_uid, start.mpa_state.is_fulfilled(), start.mpa_state.approvals.len(), start.mpa_state.threshold, start.mpa_state.required_roles, start.timeout_minutes,
        ));
    }

    if let Some(stop) = &lock.slow.pending_stop {
        s.push_str(&format!("ID: STOP | UID: {} | Status: {} | MPA: {}/{} | Roles: {:?} | timeout_minutes: {}\n",
            stop.initiator_uid, stop.mpa_state.is_fulfilled(), stop.mpa_state.approvals.len(), stop.mpa_state.threshold, stop.mpa_state.required_roles, stop.timeout_minutes,
        ));
    }

    for (id, entry) in &lock.slow.pending_requests {
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

async fn handle_start(cmd: &str, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    eprintln!("{}[INFO] START: user={}", ktime_prefix(), uid_to_name(uid).unwrap_or_else(|_| "".to_string()));
    handle_signed_decision(cmd, DecisionKind::Start, uid, Some(nl_tx)).await
}

async fn handle_stop(cmd: &str, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    eprintln!("{}[INFO] STOP: user={}", ktime_prefix(), uid_to_name(uid).unwrap_or_else(|_| "".to_string()));
    handle_signed_decision(cmd, DecisionKind::Stop, uid, Some(nl_tx)).await
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
    let st = app_state().lock().await;
    match st.slow.registered_keys.get(&uid) {
        Some(k) => Ok(k.clone()),
        None => {
            eprintln!("{}[WARN] {} user={} not registered", ktime_prefix(), kind.as_str(), uid_to_name(uid).unwrap_or_else(|_| "".to_string()));
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
async fn apply_decision(kind: DecisionKind, args: SignedCmdArgs, nl_tx: Option<&NlWriter>) -> (String, Option<InternalEvent>) {
    match kind {
        DecisionKind::Approve => process_approval(args, nl_tx.unwrap()).await,
        DecisionKind::Deny => process_deny(args, nl_tx.unwrap()).await,
        DecisionKind::Start => {
            let mgmt = management();
            check_start_initiator_and_handle(&mgmt, args.uid, nl_tx.unwrap()).await
        }
        DecisionKind::Stop => {
            let mgmt = management();
            check_stop_initiator_and_handle(&mgmt, args.uid, nl_tx.unwrap()).await
        }
        DecisionKind::Ticket => process_ticket(&args.id, args.uid).await,
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

async fn finalize_approval(args: &SignedCmdArgs, nl_tx: &NlWriter) -> Option<InternalEvent> {
    if args.id == "start" {
        finalize_start_approval(nl_tx).await
    } else if args.id == "stop" {
        finalize_stop_approval(nl_tx).await
    } else if is_draft_id(&args.id) {
        finalize_draft_approval(&args.id).await
    } else {
        finalize_entry_approval(args, nl_tx).await
    }
}

async fn process_approve_entry(args: &SignedCmdArgs) -> Result<bool, String> {
    let mut lock = app_state().lock().await;
    let pending = lock.slow.pending_requests.get_mut(&args.id.parse().unwrap_or(0)).ok_or_else(|| "no such pending id".to_string())?;
    check_fully_approved(args, &mut pending.mpa_state)
}

async fn process_approve_draft(args: &SignedCmdArgs) -> Result<bool, String> {
    let mut lock = app_state().lock().await;
    let pending = lock.fast.drafts.get_mut(&args.id).ok_or_else(|| "no such pending ticket".to_string())?;
    check_fully_approved(args, &mut pending.mpa_state)
}

async fn process_approve_start(args: &SignedCmdArgs) -> Result<bool, String> {
    let mut st = app_state().lock().await;
    let pending = match st.slow.pending_start.as_mut() {
        Some(p) => p,
        None => return Err("ERR no pending start\n".to_string()),
    };
    check_fully_approved(args, &mut pending.mpa_state)
}

async fn process_approve_stop(args: &SignedCmdArgs) -> Result<bool, String> {
    let mut st = app_state().lock().await;
    let pending = match st.slow.pending_stop.as_mut() {
        Some(p) => p,
        None => return Err("ERR no pending stop\n".to_string()),
    };
    check_fully_approved(args, &mut pending.mpa_state)
}

/// 最終決裁 (START)
async fn finalize_start_approval(nl_tx: &NlWriter) -> Option<InternalEvent> {
    let mut event = None;
    let mut pending_ids = Vec::new();

    {
        let mut st = app_state().lock().await;
        if let Some(mut pending_start) = st.slow.pending_start.take() {
            let _ = pending_start.mpa_state.try_aggregate();
            event = Some(InternalEvent::StartApproved { pending_start });
        }

        if !st.slow.pending_requests.is_empty() {
            pending_ids = st.slow.pending_requests.keys().cloned().collect();
            eprintln!("{}[WARN] Flushing {} pending requests before ENFORCE start.", ktime_prefix(), pending_ids.len());
        }

        clear_ephemeral_state_for_enforce(&mut st);
        st.is_enforce = true;
    } // ★ ロック解放

    // Netlinkでの送信（ロックなしで安全に実行）
    for id in pending_ids {
        let _ = nl_tx.send_deny(id).await;
    }
    let _ = nl_tx.send_mode_switch(1).await;

    event
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

async fn finalize_stop_approval(nl_tx: &NlWriter) -> Option<InternalEvent> {
    let mut event = None;

    {
        let mut st = app_state().lock().await;
        if let Some(mut pending_stop) = st.slow.pending_stop.take() {
            let _ = pending_stop.mpa_state.try_aggregate();
            event = Some(InternalEvent::StopApproved { pending_stop });
        }
        st.is_enforce = false;
        st.slow.pending_requests.clear();
        st.fast.drafts.clear();
        st.slow.pending_start = None;
        st.slow.pending_stop = None;
    } // ★ ロック解放

    let _ = nl_tx.send_mode_switch(0).await;

    event
}

async fn record_approval(args: &SignedCmdArgs) -> Result<bool, String> {
    if args.id == "start" { process_approve_start(args).await }
    else if args.id == "stop" { process_approve_stop(args).await }
    else if is_draft_id(&args.id) { process_approve_draft(args).await }
    else { process_approve_entry(args).await }
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
    if args.id == "start" { process_deny_start(args.uid).await }
    else if args.id == "stop" { process_deny_stop(args.uid).await }
    else if is_draft_id(&args.id) { process_deny_draft(&args.id, args.uid).await }
    else { process_deny_entry(&args, nl_tx).await }
}

async fn process_deny_start(uid: u32) -> (String, Option<InternalEvent>) {
    let mut st = app_state().lock().await;
    let has_permission = {
        let pending = match st.slow.pending_start.as_ref() {
            Some(p) => p,
            None => return ("ERR no pending start\n".to_string(), None),
        };
        check_permission(uid, &pending.mpa_state.approver_roles).0
    };

    if has_permission { 
        let pending = st.slow.pending_start.take().unwrap(); 
        let event = Some(InternalEvent::StartDenied { pending_start: pending, denier_uid: uid });
        ("OK denied\n".to_string(), event)
    } else { 
        ("ERR user are not allowed to deny\n".to_string(), None)
    } 
}

async fn process_deny_draft(id: &str, uid: u32) -> (String, Option<InternalEvent>) {
    let mut event = None;
    let existed = {
        let mut lock = app_state().lock().await;
        let has_permission = match lock.fast.drafts.get(id) {
            Some(p) => check_permission(uid, &p.mpa_state.approver_roles).0,
            None => return ("ERR no such pending ticket\n".to_string(), None),
        };

        if has_permission {
            let ticket = lock.fast.tickets.remove(id).unwrap_or_default();
            if let Some(draft) = lock.fast.drafts.remove(id) {
                event = Some(InternalEvent::DraftDenied { draft, ticket, denier_uid: uid });
                true
            } else { false }
        } else {
            return ("ERR user are not allowed to deny\n".to_string(), None);
        }
    }; 
    if !existed { return ("ERR no such pending ticket\n".to_string(), None); }
    ("DENIED\n".to_string(), event)
}

async fn process_deny_entry(args: &SignedCmdArgs, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    let id = args.id.parse().unwrap_or(0);
    let mut event = None;

    let (is_enforce, existed) = {
        let mut lock = app_state().lock().await;
        let check_result = match lock.slow.pending_requests.get_mut(&id) {
            Some(p) => Some((check_permission(args.uid, &p.mpa_state.approver_roles).0, check_permission(args.uid, &p.mpa_state.approver_roles).1)),
            None => None,
        };

        match check_result {
            Some((true, uid_roles)) => {
                if let Some(pending) = lock.slow.pending_requests.get_mut(&id) {
                    for r in uid_roles { pending.mpa_state.required_roles.retain(|role| role != &r); } 
                    pending.mpa_state.insert_approver(args);
                }
                if let Some(removed_request) = lock.slow.pending_requests.remove(&id) {
                    event = Some(InternalEvent::EntryDenied { entry: removed_request, denier_uid: args.uid });
                    (lock.is_enforce, true) 
                } else { (lock.is_enforce, false) }
            }
            Some((false, _)) => return ("ERR user are not allowed to deny\n".to_string(), None),
            None => return ("ERR no such pending id\n".to_string(), None),
        }
    }; // ★ ロック解放

    if !existed { return ("ERR no such pending id\n".to_string(), None); }

    if is_enforce {
        let _ = nl_tx.send_deny(id).await;
    }
    ("DENIED\n".to_string(), event)
}

async fn process_deny_stop(uid: u32) -> (String, Option<InternalEvent>) {
    let mut st = app_state().lock().await;
    let has_permission = {
        let pending = match st.slow.pending_stop.as_ref() {
            Some(p) => p,
            None => return ("ERR no pending stop\n".to_string(), None),
        };
        check_permission(uid, &pending.mpa_state.approver_roles).0
    };

    if has_permission { 
        let pending = st.slow.pending_stop.take().unwrap(); 
        let event = Some(InternalEvent::StopDenied { pending_stop: pending, denier_uid: uid });
        ("OK denied\n".to_string(), event)
    } else { 
        ("ERR user are not allowed to deny\n".to_string(), None)
    } 
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

async fn check_start_initiator_and_handle(mgmt: &CompiledManagement, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    if !mgmt.controls.start.initiator_uids.contains(&uid) { return ("ERR not permitted to START\n".to_string(), None); }
    handle_start_cmd(mgmt, uid, nl_tx).await
}

async fn handle_start_cmd(mgmt: &CompiledManagement, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    match &mgmt.controls.start.mpa {
        CompiledMgmtMpa::Disabled => handle_enforce_start(mgmt, uid, nl_tx).await,
        CompiledMgmtMpa::Enabled(mpa) => create_start_pending(uid, mpa).await,
    }
}

async fn create_start_pending(uid: u32, mpa: &CompiledMgmtMpaEnabled) -> (String, Option<InternalEvent>) {
    {
        let mut st = app_state().lock().await;
        if st.slow.pending_start.is_some() { return ("ERR start already pending\n".to_string(), None); }
        st.slow.pending_start = Some(
            MgmtPendingStart { 
                initiator_uid: uid,
                initiator_user: uid_to_name(uid).unwrap_or_else(|_| "".to_string()),
                audit_id: Uuid::new_v4().to_string(),
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
    }
    ("PENDING\n".to_string(), None)
}

async fn handle_enforce_start(mgmt: &CompiledManagement, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    let event: Option<InternalEvent>;   
    let mut pending_ids = Vec::new();

    {
        let mut st = app_state().lock().await;
        if !st.slow.pending_requests.is_empty() {
            pending_ids = st.slow.pending_requests.keys().cloned().collect();
            eprintln!("{}[WARN] handle_enforce_start: Auto-denying {} pending requests to prevent hang.", ktime_prefix(), pending_ids.len());
        }

        let timeout_minutes = match &mgmt.controls.start.mpa {
            CompiledMgmtMpa::Enabled(enabled) => enabled.timeout_minutes,
            _ => 0
        };
        let mgmt_start = MgmtPendingStart {
            initiator_uid: uid,
            initiator_user: uid_to_name(uid).unwrap_or_else(|_| "".to_string()),
            audit_id: Uuid::new_v4().to_string(),
            mpa_state: MpaState {
                threshold: 1,
                approver_roles: HashSet::new(),
                required_roles: HashSet::new(),
                approvals: HashMap::new(),
                aggregated_signature: None
            },
            timeout_minutes
        };

        event = Some(InternalEvent::StartApproved { pending_start: mgmt_start });
        clear_ephemeral_state_for_enforce(&mut st);
        st.is_enforce = true;
    } // ★ ロック解放

    for id in pending_ids {
        let _ = nl_tx.send_deny(id).await;
    }
    let _ = nl_tx.send_mode_switch(1).await;
    
    ("OK started\n".to_string(), event)
}

fn clear_ephemeral_state_for_enforce(state: &mut AppState) {
    state.fast.drafts.clear();
    state.fast.tickets.clear();
    state.slow.pending_requests.clear();
    state.slow.pending_start = None;
}

async fn check_stop_initiator_and_handle(mgmt: &CompiledManagement, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    if !mgmt.controls.stop.initiator_uids.contains(&uid) { return ("ERR not permitted to STOP\n".to_string(), None); }
    handle_stop_cmd(mgmt, uid, nl_tx).await
}

async fn handle_stop_cmd(mgmt: &CompiledManagement, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    match &mgmt.controls.stop.mpa {
        CompiledMgmtMpa::Disabled => handle_enforce_stop(mgmt, uid, nl_tx).await,
        CompiledMgmtMpa::Enabled(mpa) => create_stop_pending(uid, mpa).await,
    }
}

async fn handle_enforce_stop(mgmt: &CompiledManagement, uid: u32, nl_tx: &NlWriter) -> (String, Option<InternalEvent>) {
    let event: Option<InternalEvent>;   

    {
        let mut st = app_state().lock().await;
        let timeout_minutes = match &mgmt.controls.stop.mpa {
            CompiledMgmtMpa::Enabled(enabled) => enabled.timeout_minutes,
            _ => 0
        };
        let mgmt_stop = MgmtPendingStop {
            initiator_uid: uid,
            initiator_user: uid_to_name(uid).unwrap_or_else(|_| "".to_string()),
            audit_id: Uuid::new_v4().to_string(),
            mpa_state: MpaState {
                threshold: 1,
                approver_roles: HashSet::new(),
                required_roles: HashSet::new(),
                approvals: HashMap::new(),
                aggregated_signature: None
            },
            timeout_minutes
        };

        event = Some(InternalEvent::StopApproved { pending_stop: mgmt_stop });
        st.is_enforce = false;
        st.slow.pending_requests.clear();
        st.fast.drafts.clear();
        st.fast.tickets.clear();
        st.slow.pending_start = None;
        st.slow.pending_stop = None;
    } // ★ ロック解放

    let _ = nl_tx.send_mode_switch(0).await;
    
    ("OK stopped\n".to_string(), event)
}

async fn create_stop_pending(uid: u32, mpa: &CompiledMgmtMpaEnabled) -> (String, Option<InternalEvent>) {
    {
        let mut st = app_state().lock().await;
        if st.slow.pending_stop.is_some() { return ("ERR stop already pending\n".to_string(), None); }
        st.slow.pending_stop = Some(
            MgmtPendingStop {
                initiator_uid: uid,
                initiator_user: uid_to_name(uid).unwrap_or_else(|_| "".to_string()),
                audit_id: Uuid::new_v4().to_string(),
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
    }
    ("PENDING\n".to_string(), None)
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
