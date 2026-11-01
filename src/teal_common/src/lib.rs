// SPDX-License-Identifier: MIT
/*
 * TEAL Common Types and Constants (teal_common)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use const_format::concatcp;
use serde::{Deserialize, Serialize};

// =========================================================================
// システム共通パス定義
// =========================================================================

/// teal のソケットファイルのルートディレクトリ
pub const TEAL_SOCKET_ROOT: &str = "/run/teal";

/// pam_teal から teald へのセッション通知用 UNIX ドメインソケット
pub const PAM_SOCKET_PATH: &str = concatcp!(TEAL_SOCKET_ROOT, "/teal_pam.sock");

/// teal-cli から teald への管理コマンド用 UNIX ドメインソケット
pub const TEALD_ADMIN_SOCKET_PATH: &str = concatcp!(TEAL_SOCKET_ROOT, "/teald.sock");

// =========================================================================
// PAMセッション通知プロトコル
// =========================================================================

/// pam_teal から teald へ送信されるログイン/ログアウトイベント通知
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PamLoginNotification {
    pub action: String,      // "login" または "logout"
    pub uid: u32,            // user id
    pub session_tty: String, // "pts4", "tty1" など

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
}
