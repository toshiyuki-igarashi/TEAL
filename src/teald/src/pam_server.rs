// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
// teald/src/pam_server.rs

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use teal_common::{PamLoginNotification, PAM_SOCKET_PATH, TEAL_SOCKET_ROOT};
use teal_policy_engine::ir::RegisteredSession;

use crate::netlink::pam_netlink_writer;
use crate::state::app_state;

const MAX_PAM_EVENT_BYTES: usize = 8 * 1024;
const PAM_READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_PAM_CONNECTIONS: usize = 64;

// Serialize LOGIN/LOGOUT including kernel ACK to prevent reorder in teald.
static PAM_EVENT_LOCK: Mutex<()> = Mutex::const_new(());

/// PAM ソケットの配置先が安全であることを確認する。
/// /run/teal は他の TEAL ソケットとも共有するため 0700 を要求しない。
fn verify_socket_directory() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "teald PAM listener must run as root",
        ));
    }

    fs::create_dir_all(TEAL_SOCKET_ROOT)?;
    let meta = fs::symlink_metadata(TEAL_SOCKET_ROOT)?;

    if !meta.is_dir() || meta.uid() != 0 || (meta.mode() & 0o022) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "unsafe PAM socket directory: {} (uid={}, mode={:o})",
                TEAL_SOCKET_ROOT,
                meta.uid(),
                meta.mode() & 0o7777
            ),
        ));
    }

    Ok(())
}

/// root 所有の残存ソケットに限り削除する。
/// 動作中の別リスナー、symlink、通常ファイル等は削除せず起動を拒否する。
fn remove_stale_pam_socket(path: &str) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    if meta.uid() != 0 || !meta.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to remove non-root or non-socket path: {path}"),
        ));
    }

    match StdUnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("PAM socket already has an active listener: {path}"),
        )),
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path),
        Err(err) => Err(io::Error::new(
            err.kind(),
            format!("cannot establish that PAM socket is stale ({path}): {err}"),
        )),
    }
}

fn is_authorized_pam_peer(uid: u32) -> bool {
    uid == 0
}

/// PAM イベントの受信を開始する。失敗した場合は受信を開始しない。
/// 既存の呼び出し側との互換性のため、戻り値は () のままとする。
pub async fn start_pam_listener() {
    let socket_path = PAM_SOCKET_PATH;

    if let Err(err) = verify_socket_directory() {
        eprintln!("[ERROR] teald-PAM: socket directory verification failed: {err}");
        return;
    }

    if let Err(err) = remove_stale_pam_socket(socket_path) {
        eprintln!("[ERROR] teald-PAM: cannot prepare socket: {err}");
        return;
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("[ERROR] teald-PAM: socket bind failed: {err}");
            return;
        }
    };

    // 受信前に root 専用権限へ変更する。権限設定失敗時には受信しない。
    if let Err(err) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)) {
        eprintln!("[ERROR] teald-PAM: cannot secure socket permissions: {err}");
        drop(listener);
        let _ = fs::remove_file(socket_path);
        return;
    }

    let meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) => {
            eprintln!("[ERROR] teald-PAM: cannot inspect socket: {err}");
            drop(listener);
            let _ = fs::remove_file(socket_path);
            return;
        }
    };

    if meta.uid() != 0 || !meta.file_type().is_socket() || (meta.mode() & 0o777) != 0o600 {
        eprintln!(
            "[ERROR] teald-PAM: unsafe socket ownership/mode: uid={} mode={:o}",
            meta.uid(),
            meta.mode() & 0o777
        );
        drop(listener);
        let _ = fs::remove_file(socket_path);
        return;
    }

    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_PAM_CONNECTIONS));

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let permit = match Arc::clone(&limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!("[WARN] teald-PAM: concurrent connection limit reached");
                        continue;
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit;
                    handle_pam_connection(stream).await;
                });
            }
            Err(err) => {
                eprintln!("[ERROR] teald-PAM: socket accept failed: {err}");
            }
        }
    }
}

/// 8 KiB を超える入力や、2 秒以内に完了しない入力を拒否する。
/// pam_teal.so は JSON と LF を送信後、接続を閉じる。
async fn read_pam_payload(stream: UnixStream) -> io::Result<Vec<u8>> {
    let mut limited = stream.take((MAX_PAM_EVENT_BYTES + 1) as u64);
    let mut bytes = Vec::with_capacity(256);

    match timeout(PAM_READ_TIMEOUT, limited.read_to_end(&mut bytes)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PAM notification read timed out",
            ));
        }
    }

    if bytes.len() > MAX_PAM_EVENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PAM notification exceeds 8 KiB",
        ));
    }
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty PAM notification",
        ));
    }

    Ok(bytes)
}

async fn handle_pam_connection(stream: UnixStream) {
    let cred = match stream.peer_cred() {
        Ok(cred) => cred,
        Err(err) => {
            eprintln!("[WARN] teald-PAM: SO_PEERCRED failed: {err}");
            return;
        }
    };

    if !is_authorized_pam_peer(cred.uid()) {
        eprintln!(
            "[SECURITY] teald-PAM: unauthorized peer uid={} pid={:?}",
            cred.uid(),
            cred.pid()
        );
        return;
    }

    let bytes = match read_pam_payload(stream).await {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("[WARN] teald-PAM: invalid notification stream: {err}");
            return;
        }
    };

    match serde_json::from_slice::<PamLoginNotification>(&bytes) {
        Ok(event) => process_pam_event(event).await,
        Err(err) => {
            // 受信した本文そのものはログへ出さない。
            eprintln!(
                "[WARN] teald-PAM: invalid notification JSON ({} bytes): {err}",
                bytes.len()
            );
        }
    }
}

/// Synchronize the kernel's PAM session table BEFORE publishing to teald's
/// policy state. SESSION_LOGOUT removes the *session*, not any issued tickets.
async fn process_pam_event(event: PamLoginNotification) {
    let _guard = PAM_EVENT_LOCK.lock().await;

    let Some(sid) = event.audit_session_id.filter(|&v| v != u32::MAX) else {
        eprintln!("[WARN] teald-PAM: invalid audit session ID");
        return;
    };
    let Some(loginuid) = event.loginuid.filter(|&v| v != u32::MAX) else {
        eprintln!("[WARN] teald-PAM: invalid loginuid sid={sid}");
        return;
    };
    if event.uid != loginuid {
        eprintln!(
            "[SECURITY] teald-PAM: uid/loginuid mismatch sid={sid} uid={} auid={loginuid}",
            event.uid
        );
        return;
    }
    let add = match event.action.as_str() {
        "login" => true,
        "logout" => false,
        _ => {
            eprintln!("[WARN] teald-PAM: unknown notification action");
            return;
        }
    };

    let Some(writer) = pam_netlink_writer() else {
        eprintln!(
            "[ERROR] teald-PAM: Netlink TX writer is not initialized; refusing to publish session"
        );
        return;
    };
    // Logout must not leave a stale authenticated SID in the kernel. Retry
    // an uncertain Netlink ACK up to three times. The kernel DEL is idempotent.
    let mut last_error = None;
    for _ in 0..(if add { 1 } else { 3 }) {
        match writer.send_pam_session_update(sid, loginuid, add).await {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(err) => last_error = Some(err),
        }
    }
    if let Some(err) = last_error {
        eprintln!(
            "[CRITICAL] teald-PAM: kernel PAM session {} failed: sid={} loginuid={} error={}. Kernel and user login state may differ; inspect kernel logs.",
            if add { "registration" } else { "unregistration" }, sid, loginuid, err,
        );
        // Never claim the local PAM session is authenticated when kernel ACK
        // has not confirmed a successful update. Keep existing tickets intact.
        // On logout failure, also drop local policy authentication.
        if !add {
            let mut state = app_state().lock().await;
            if state
                .slow
                .active_login_sessions
                .get(&sid)
                .is_some_and(|session| session.uid == loginuid)
            {
                state.slow.active_login_sessions.remove(&sid);
            }
        }
        return;
    }

    apply_pam_event_local(event).await;
}

/// Local policy state only; call after the kernel has accepted PAM update.
async fn apply_pam_event_local(event: PamLoginNotification) {
    let Some(sid) = event.audit_session_id.filter(|&v| v != u32::MAX) else {
        return;
    };
    let Some(loginuid) = event.loginuid.filter(|&v| v != u32::MAX) else {
        return;
    };
    if event.uid != loginuid {
        return;
    }
    match event.action.as_str() {
        "login" => {
            let session = RegisteredSession {
                uid: loginuid,
                source_ip: event.source_ip,
                auth_method: event.auth_method,
            };
            let audit_entry =
                format!(
                "[TEAL-AUDIT] SESSION_LOGIN sid={} uid={} tty={:?} source_ip={:?} auth_method={:?}",
                sid, loginuid, event.session_tty,
                session.source_ip.as_deref(), session.auth_method.as_deref(),
            );
            let mut state = app_state().lock().await;
            state.slow.active_login_sessions.insert(sid, session);
            eprintln!("{audit_entry}");
        }
        "logout" => {
            let mut state = app_state().lock().await;
            if state
                .slow
                .active_login_sessions
                .get(&sid)
                .is_some_and(|session| session.uid == loginuid)
            {
                state.slow.active_login_sessions.remove(&sid);
                eprintln!(
                    "[TEAL-AUDIT] SESSION_LOGOUT sid={} uid={} tty={:?}",
                    sid, loginuid, event.session_tty
                );
            } else {
                eprintln!(
                    "[WARN] teald-PAM: local logout sid={} loginuid={} not registered",
                    sid, loginuid
                );
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{init_state, APP_STATE};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn pam_peer_uid_policy() {
        assert!(is_authorized_pam_peer(0));
        assert!(!is_authorized_pam_peer(1000));
        assert!(!is_authorized_pam_peer(u32::MAX));
    }

    #[tokio::test]
    async fn payload_rejects_oversize() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let writer = tokio::spawn(async move {
            client
                .write_all(&vec![b'x'; MAX_PAM_EVENT_BYTES + 1])
                .await
                .unwrap();
        });

        let err = read_pam_payload(server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn payload_accepts_valid_size() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let writer = tokio::spawn(async move {
            client.write_all(b"{}\n").await.unwrap();
        });

        let bytes = read_pam_payload(server).await.unwrap();
        assert_eq!(bytes, b"{}\n");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn process_pam_login_logout() {
        if APP_STATE.get().is_none() {
            init_state().await;
        }

        let login = PamLoginNotification {
            action: "login".into(),
            uid: 1000,
            session_tty: "ssh".into(),
            audit_session_id: Some(451239),
            loginuid: Some(1000),
            source_ip: Some("192.0.2.10".into()),
            auth_method: Some("publickey".into()),
        };
        apply_pam_event_local(login).await;

        {
            let state = app_state().lock().await;
            let session = state.slow.active_login_sessions.get(&451239).unwrap();
            assert_eq!(session.uid, 1000);
            assert_eq!(session.source_ip.as_deref(), Some("192.0.2.10"));
        }

        let logout = PamLoginNotification {
            action: "logout".into(),
            uid: 1000,
            session_tty: "ssh".into(),
            audit_session_id: Some(451239),
            loginuid: Some(1000),
            source_ip: None,
            auth_method: None,
        };
        apply_pam_event_local(logout).await;

        let state = app_state().lock().await;
        assert!(!state.slow.active_login_sessions.contains_key(&451239));
    }
}
