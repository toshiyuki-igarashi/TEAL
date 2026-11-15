// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
// teald/src/pam_server.rs

use std::fs;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};

use teal_common::{PamLoginNotification, PAM_SOCKET_PATH, TEAL_SOCKET_ROOT};
use teal_policy_engine::ir::RegisteredSession;

use crate::state::app_state; // AppStateへのアクセス用（※プロジェクトの構造に合わせてパスは調整してください）

/// PAMからのイベントを待ち受ける UNIX ドメインソケットリスナーを起動する
pub async fn start_pam_listener() {
    let socket_path = PAM_SOCKET_PATH;

    // ★ 保険: 親ディレクトリ (/run/teal) が存在しない場合は作成
    let _ = tokio::fs::create_dir_all(TEAL_SOCKET_ROOT).await;

    // 1. ソケットファイルの初期化
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[ERROR] teald-PAM: Failed to bind PAM socket at {}: {}",
                socket_path, e
            );
            return;
        }
    };

    // 2. クライアント（pam_teal.so）が書き込めるように権限を設定
    if let Err(e) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)) {
        eprintln!("[ERROR] teald-PAM: Failed to secure PAM socket: {}", e);
        drop(listener);
        let _ = fs::remove_file(socket_path);
        return;
    }

    println!("[INFO] teald: Listening for PAM events on {}", socket_path);

    // 3. 接続受け入れの無限ループ（軽量に保つ）
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // 1接続ごとの重い処理は別関数へ移譲し、Tokioタスクで並列実行
                tokio::spawn(handle_pam_connection(stream));
            }
            Err(e) => {
                eprintln!("[ERROR] teald-PAM: PAM socket accept failed: {}", e);
            }
        }
    }
}

/// 1つのPAM接続ストリームからデータを読み込み、パースを試みる
async fn handle_pam_connection(mut stream: UnixStream) {
    let mut buffer = String::new();

    // ストリームから終端（EOF）まで生文字列を非同期で読み込む
    if stream.read_to_string(&mut buffer).await.is_err() {
        eprintln!("[WARN] teald-PAM: Failed to read from PAM stream.");
        return;
    }

    // JSONのデシライズ処理
    match serde_json::from_str::<PamLoginNotification>(&buffer) {
        Ok(event) => {
            // パースに成功したら、実際の状態更新ロジックへ引き渡す
            process_pam_event(event).await;
        }
        Err(e) => {
            eprintln!(
                "[WARN] teald-PAM: Failed to parse JSON from PAM: {}. Received: {}",
                e, buffer
            );
        }
    }
}

/// パース済みのPAMイベントを評価し、AppStateのアクティブセッション台帳を更新する
async fn process_pam_event(event: PamLoginNotification) {
    // Audit情報が無効な場合、セッション台帳を変更しない
    let Some(sid) = event.audit_session_id.filter(|&v| v != u32::MAX) else {
        eprintln!(
            "[WARN] teald-PAM: Invalid Audit Session ID: \
             action={} uid={} loginuid={:?} audit_sid={:?} tty={}",
            event.action, event.uid, event.loginuid, event.audit_session_id, event.session_tty,
        );
        return;
    };

    let Some(loginuid) = event.loginuid.filter(|&v| v != u32::MAX) else {
        eprintln!("[WARN] teald-PAM: Invalid Login UID, sid={}", sid);
        return;
    };

    if loginuid != event.uid {
        eprintln!(
            "[SECURITY ALERT] PAM UID mismatch: \
             uid={} loginuid={} sid={}",
            event.uid, loginuid, sid
        );
        return;
    }

    match event.action.as_str() {
        "login" => {
            let session = RegisteredSession {
                uid: loginuid,
                source_ip: event.source_ip.clone(),
                auth_method: event.auth_method.clone(),
            };

            let mut st = app_state().lock().await;

            st.slow.active_login_sessions.insert(sid, session);

            println!(
                "[teald-PAM] Registered: sid={} loginuid={} \
                 tty={} source={}",
                sid,
                loginuid,
                event.session_tty,
                event.source_ip.as_deref().unwrap_or("-")
            );
        }

        "logout" => {
            let mut st = app_state().lock().await;

            let valid = st
                .slow
                .active_login_sessions
                .get(&sid)
                .is_some_and(|session| session.uid == loginuid);

            if valid {
                st.slow.active_login_sessions.remove(&sid);

                println!(
                    "[teald-PAM] Removed session: sid={} loginuid={}",
                    sid, loginuid
                );
            } else {
                eprintln!(
                    "[WARN] teald-PAM: Logout ignored: \
                     sid={} loginuid={}",
                    sid, loginuid
                );
            }
        }

        _ => {
            eprintln!("[WARN] teald-PAM: Unknown action '{}'", event.action);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{init_state, APP_STATE};

    #[tokio::test]
    async fn test_process_pam_login_logout() {
        if APP_STATE.get().is_none() {
            init_state().await;
        }

        let login_event = PamLoginNotification {
            action: "login".to_string(),
            uid: 1000,
            session_tty: "ssh".to_string(),
            audit_session_id: Some(45),
            loginuid: Some(1000),
            source_ip: Some("192.168.1.50".to_string()),
            auth_method: Some("publickey".to_string()),
        };

        process_pam_event(login_event).await;

        {
            let st = app_state().lock().await;
            let session = st.slow.active_login_sessions.get(&45).unwrap();

            assert_eq!(session.uid, 1000);
            assert_eq!(session.source_ip.as_deref(), Some("192.168.1.50"));
        }

        let logout_event = PamLoginNotification {
            action: "logout".to_string(),
            uid: 1000,
            session_tty: "pts/9".to_string(),
            audit_session_id: Some(45),
            loginuid: Some(1000),
            source_ip: None,
            auth_method: None,
        };

        process_pam_event(logout_event).await;

        {
            let st = app_state().lock().await;
            assert!(!st.slow.active_login_sessions.contains_key(&45));
        }
    }
}
