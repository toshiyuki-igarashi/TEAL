// SPDX-License-Identifier: MIT
//
// TEAL PAM module (pam_teal)
//
// Copyright (c) 2026 Toshiyuki Igarashi
use std::os::unix::net::UnixStream;
use std::io::Write;

// FFI用のC言語互換型や c_int は標準ライブラリから取得
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use pam_sys::types::{PamHandle, PamItemType, PamReturnCode};
use pam_sys::raw::{pam_get_item, pam_getenv, pam_get_user};

use serde::Serialize;

// --- PAMの定数定義 ---
const PAM_SUCCESS: c_int = 0;
//const PAM_USER_UNKNOWN: c_int = 13;
const PAM_TTY: c_int = 3;

// --- PAMの不透明(Opaque)構造体 ---
#[repr(C)]
pub struct pam_handle_t {
    _data: [u8; 0],
}

#[derive(Serialize)]
struct PamLoginNotification {
    action: String,       // "login"
    user: String,         // "toshiyuki"
    session_tty: String,  // "pts1"
    
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_method: Option<String>,
}


// =========================================================================
// ヘルパー関数
// =========================================================================

/// teald に UNIX Domain Socket 経由でイベント（JSON文字列）を送信する
pub fn notify_teald(
    action: &str, 
    user: &str, 
    tty: &str, 
    source_ip: Option<String>,
    auth_method: Option<String>,
) {
    let socket_path = "/tmp/teal_pam.sock";
    
    // 1. 構造体にデータをマッピング
    let notification = PamLoginNotification {
        action: action.to_string(),
        user: user.to_string(),
        session_tty: tty.to_string(),
        source_ip,
        auth_method,
    };

    // 2. serde_json で安全にシリアライズ（インジェクション脆弱性を100%排除）
    let msg = match serde_json::to_string(&notification) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("[TEAL PAM] Failed to serialize notification: {}", e);
            return;
        }
    };
    
    // 3. tealdへの接続と書き込みを試みる
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        // デーモン側が1行ずつ読み込めるように、末尾に改行コード '\n' を付与しておくと受信論理が綺麗になります
        let mut payload = msg.into_bytes();
        payload.push(b'\n');
        
        let _ = stream.write_all(&payload);
    }
    // tealdが停止中の場合でも、PAMのログイン処理自体は止めないようにエラーは握りつぶす(Fail-Safe)
}

/// pam_handle_t からユーザー名とTTYを安全に取り出す
unsafe fn get_session_info(pamh: *mut PamHandle) -> (String, String) {
    // 1. ユーザー名の取得
    let mut user_ptr: *const c_char = std::ptr::null();
    let user = if pam_get_user(pamh, &mut user_ptr, std::ptr::null()) == PAM_SUCCESS && !user_ptr.is_null() {
        CStr::from_ptr(user_ptr).to_string_lossy().into_owned()
    } else {
        "unknown".to_string()
    };

    // 2. TTYの取得
    let mut tty_ptr: *const c_void = std::ptr::null();
    let tty = if pam_get_item(pamh, PAM_TTY, &mut tty_ptr) == PAM_SUCCESS && !tty_ptr.is_null() {
        CStr::from_ptr(tty_ptr as *const c_char).to_string_lossy().into_owned()
    } else {
        "unknown".to_string()
    };

    (user, tty)
}

// =========================================================================
// PAMモジュールのエントリポイント (C言語互換)
// =========================================================================

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let (user, tty) = unsafe { get_session_info(pamh) };

    // 接続元IPと認証方式を安全に取得
    let source_ip = unsafe { get_pam_rhost(pamh) };
    let auth_method = unsafe { get_pam_env(pamh, "SSH_USER_AUTH") };

    // ログ用の表示文字列を生成（所有権は奪わない）
    let log_ip = source_ip.as_deref().unwrap_or("127.0.0.1");
    let log_auth = auth_method.as_deref().unwrap_or("local/unknown");

    println!(
        "[TEAL PAM] User '{}' logged in on TTY '{}' from IP '{}' via '{}'", 
        user, tty, log_ip, log_auth
    );

    // teald へログインコンテキストを通知
    notify_teald("login", &user, &tty, source_ip, auth_method);

    // ★ Enumバリアントを c_int にキャストしてC言語のPAMスタックへ返す
    PamReturnCode::SUCCESS as c_int
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let (user, tty) = unsafe { get_session_info(pamh) };

    notify_teald("logout", &user, &tty, None, None);

    println!("[TEAL PAM] User '{}' logged out from TTY '{}'", user, tty);

    PamReturnCode::SUCCESS as c_int
}

// ===== 安全なコンテキスト抽出ヘルパー =====

unsafe fn get_pam_rhost(pamh: *mut PamHandle) -> Option<String> {
    let mut ptr: *const c_void = std::ptr::null();
    
    // ★ PamItemType::PAM_RHOST という厳密なEnumを指定
    let rc = pam_get_item(pamh as *const _, PamItemType::RHOST as c_int, &mut ptr);
    
    if rc == PamReturnCode::SUCCESS as c_int && !ptr.is_null() {
        let c_str = CStr::from_ptr(ptr as *const c_char);
        let s = c_str.to_string_lossy().trim().to_string();
        if !s.is_empty() { Some(s) } else { None }
    } else {
        None
    }
}

unsafe fn get_pam_env(pamh: *mut PamHandle, key: &str) -> Option<String> {
    let c_key = CString::new(key).ok()?;
    
    // ★ rawモジュールの pam_getenv を使用
    let ptr = pam_getenv(pamh, c_key.as_ptr());
    
    if !ptr.is_null() {
        let c_str = CStr::from_ptr(ptr);
        Some(c_str.to_string_lossy().trim().to_string())
    } else {
        None
    }
}

