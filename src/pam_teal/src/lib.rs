// SPDX-License-Identifier: MIT
//
// TEAL PAM module (pam_teal)
//
// Copyright (c) 2026 Toshiyuki Igarashi
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::net::UnixStream;
use std::io::Write;

// --- PAMの定数定義 ---
const PAM_SUCCESS: c_int = 0;
//const PAM_USER_UNKNOWN: c_int = 13;
const PAM_TTY: c_int = 3;

// --- PAMの不透明(Opaque)構造体 ---
#[repr(C)]
pub struct pam_handle_t {
    _data: [u8; 0],
}

// --- PAMのC言語APIのリンク ---
#[link(name = "pam")]
extern "C" {
    fn pam_get_user(
        pamh: *const pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;
}

// =========================================================================
// ヘルパー関数
// =========================================================================

/// teald に UNIX Domain Socket 経由でイベント（JSON文字列）を送信する
fn notify_teald(action: &str, user: &str, tty: &str) {
    let socket_path = "/tmp/teal_pam.sock";
    
    // tealdへの接続を試みる
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        // serdeを使わずに標準機能で軽量なJSONを組み立て
        let msg = format!(r#"{{"action":"{}", "user":"{}", "tty":"{}"}}"#, action, user, tty);
        let _ = stream.write_all(msg.as_bytes());
    }
    // tealdが停止中の場合でも、PAMのログイン処理自体は止めないようにエラーは握りつぶす(フェイルセーフ)
}

/// pam_handle_t からユーザー名とTTYを安全に取り出す
unsafe fn get_session_info(pamh: *const pam_handle_t) -> (String, String) {
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
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // ヘルパーを使って情報を取得
    let (user, tty) = unsafe { get_session_info(pamh) };

    // teald へログインを通知
    notify_teald("login", &user, &tty);
    println!("[TEAL PAM] User '{}' logged in on TTY '{}'", user, tty);

    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // ヘルパーを使って情報を取得
    let (user, tty) = unsafe { get_session_info(pamh) };

    // teald へログアウトを通知
    notify_teald("logout", &user, &tty);
    println!("[TEAL PAM] User '{}' logged out from TTY '{}'", user, tty);

    PAM_SUCCESS
}