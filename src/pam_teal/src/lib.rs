// SPDX-License-Identifier: MIT
//
// TEAL PAM module (pam_teal)
//
// Copyright (c) 2026 Toshiyuki Igarashi
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

// --- PAMの定数定義 ---
const PAM_SUCCESS: c_int = 0;
const PAM_USER_UNKNOWN: c_int = 13;
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
// PAMモジュールのエントリポイント (C言語互換)
// =========================================================================

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // 1. ユーザー名の取得
    let mut user_ptr: *const c_char = std::ptr::null();
    let ret = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if ret != PAM_SUCCESS || user_ptr.is_null() {
        return PAM_USER_UNKNOWN;
    }
    let user = unsafe { CStr::from_ptr(user_ptr) }.to_string_lossy().into_owned();

    // 2. TTYの取得
    let mut tty_ptr: *const c_void = std::ptr::null();
    let ret = unsafe { pam_get_item(pamh, PAM_TTY, &mut tty_ptr) };
    let tty = if ret == PAM_SUCCESS && !tty_ptr.is_null() {
        unsafe { CStr::from_ptr(tty_ptr as *const c_char) }.to_string_lossy().into_owned()
    } else {
        "unknown".to_string()
    };

    // TODO: ここで teald (Unix Domain Socket) に繋いで、user と tty を送信する
    println!("[TEAL PAM] User '{}' logged in on TTY '{}'", user, tty);

    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // TODO: teald にログアウトしたことを通知し、台帳からTTYを削除させる
    PAM_SUCCESS
}
