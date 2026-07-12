// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
// teald/src/pam_server.rs

use tokio::net::UnixListener;
use tokio::io::AsyncReadExt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use serde::Deserialize;

use teal_policy_engine::util::normalize_tty_name;

use crate::state::app_state; // AppStateへのアクセス用（※プロジェクトの構造に合わせてパスは調整してください）

// 受信する JSON の構造体を定義
#[derive(Debug, Deserialize)]
struct PamEvent {
    action: String,
    user: String,
    tty: String,
}

pub async fn start_pam_listener() {
    let socket_path = "/tmp/teal_pam.sock";

    // 1. 古いソケットファイルが残っていれば削除
    let _ = fs::remove_file(socket_path);

    // 2. UNIXドメインソケットをバインド
    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[ERROR] teald-PAM: Failed to bind PAM socket at {}: {}", socket_path, e);
            return;
        }
    };

    // 3. pam_teal.so (クライアント) が書き込めるようにパーミッションを 777 に設定
    if let Err(e) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o777)) {
        eprintln!("[WARN] teald-PAM: Failed to set permissions on PAM socket: {}", e);
    }

    println!("[INFO] teald: Listening for PAM events on {}", socket_path);

    // 4. クライアントからの接続を無限ループで待ち受ける
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                // 接続が来たら別タスクで処理（メインループを止めない）
                tokio::spawn(async move {
                    let mut buffer = String::new();
                    // データを読み取る
                    if stream.read_to_string(&mut buffer).await.is_ok() {
                        // 5. JSONをパースする
                        match serde_json::from_str::<PamEvent>(&buffer) {
                            Ok(event) => {
                                let mut st = app_state().lock().await;

                                // アクションによる分岐（ログインとログアウト）
                                match event.action.as_str() {
                                    "login" => {
                                        // PAMから来た形式 (例: "/dev/pts/1") を "pts1" に正規化して格納
                                        let normalized_key = normalize_tty_name(&event.tty);
                                        st.slow.active_tty_sessions.insert(normalized_key, event.user.clone());
                                        println!("[teald-PAM] Registered session: user={} at {} (normalized)", event.user, event.tty);
                                    }
                                    "logout" => {
                                        let normalized_key = normalize_tty_name(&event.tty);
                                        st.slow.active_tty_sessions.remove(&normalized_key);
                                        println!("[teald-PAM] Removed session for TTY {} (normalized)", event.tty);
                                    }
                                    _ => {
                                        eprintln!("[WARN] teald-PAM: Unknown action '{}'", event.action);
                                    }
                                }

                            }
                            Err(e) => {
                                eprintln!("[WARN] teald-PAM: Failed to parse JSON from PAM: {}. Received: {}", e, buffer);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("[ERROR] teald-PAM: PAM socket accept failed: {}", e);
            }
        }
    }
}