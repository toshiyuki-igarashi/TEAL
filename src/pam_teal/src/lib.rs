// SPDX-License-Identifier: MIT
//
// TEAL PAM module (pam_teal)
//
// Copyright (c) 2026 Toshiyuki Igarashi
use std::os::unix::net::UnixStream;
use std::io::Write;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// pam_sys から公式の型、Enum、生C関数インポート
use pam_sys::types::{PamHandle, PamItemType, PamReturnCode};
use pam_sys::raw::{pam_set_data, pam_get_data, pam_get_item, pam_get_user};

use serde::Serialize;

// TEAL内部で認証状態を引き回すための一意のメモリキー名
const TEAL_AUTH_METHOD_KEY: &[u8] = b"teal_auth_method\0";

#[derive(Serialize)]
struct PamLoginNotification {
    action: String,       // "login" または "logout"
    user: String,         // "toshiyuki"
    session_tty: String,  // "pts4" など
    
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_method: Option<String>,
}

// =========================================================================
// ヘルパー関数 / コールバック
// =========================================================================

/// pam_set_dataが確保したメモリを、PAMハンドル解放時に安全に破棄するためのコールバック
extern "C" fn cleanup_string(_pamh: *mut PamHandle, data: *mut c_void, _pam_status: c_int) {
    if !data.is_null() {
        unsafe {
            // RawポインタからCStringに戻すことで、Rustのメモリ管理下に引き戻して自動解放(Drop)させる
            let _ = CString::from_raw(data as *mut c_char);
        }
    }
}

/// teald に UNIX Domain Socket 経由でイベント（JSON文字列）を送信する
pub fn notify_teald(
    action: &str, 
    user: &str, 
    tty: &str, 
    source_ip: Option<String>,
    auth_method: Option<String>,
) {
    let socket_path = "/tmp/teal_pam.sock";
    
    let notification = PamLoginNotification {
        action: action.to_string(),
        user: user.to_string(),
        session_tty: tty.to_string(),
        source_ip,
        auth_method,
    };

    let msg = match serde_json::to_string(&notification) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("[TEAL PAM] Failed to serialize notification: {}", e);
            return;
        }
    };
    
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        let mut payload = msg.into_bytes();
        payload.push(b'\n'); // デーモン側が1行バッファで読めるように改行を付与
        let _ = stream.write_all(&payload);
    }
}

/// PamHandle からユーザー名とTTY、接続元IPを安全に一括取得する
unsafe fn get_session_info(pamh: *mut PamHandle) -> (String, String, Option<String>) {
    // 1. ユーザー名の取得 (pam_sys::raw::pam_get_user を使用)
    let mut user_ptr: *const c_char = std::ptr::null();
    let user = if pam_get_user(pamh, &mut user_ptr, std::ptr::null()) == (PamReturnCode::SUCCESS as c_int) && !user_ptr.is_null() {
        CStr::from_ptr(user_ptr).to_string_lossy().into_owned()
    } else {
        "unknown".to_string()
    };

    // 2. TTYの取得 (PamItemType::TTY を使用)
    let mut tty_ptr: *const c_void = std::ptr::null();
    let tty = if pam_get_item(pamh, PamItemType::TTY as c_int, &mut tty_ptr) == (PamReturnCode::SUCCESS as c_int) && !tty_ptr.is_null() {
        CStr::from_ptr(tty_ptr as *const c_char).to_string_lossy().into_owned()
    } else {
        "unknown".to_string()
    };

    // 3. 接続元IP (RHOST) の取得
    let mut rhost_ptr: *const c_void = std::ptr::null();
    let source_ip = if pam_get_item(pamh, PamItemType::RHOST as c_int, &mut rhost_ptr) == (PamReturnCode::SUCCESS as c_int) && !rhost_ptr.is_null() {
        let s = CStr::from_ptr(rhost_ptr as *const c_char).to_string_lossy().trim().to_string();
        if !s.is_empty() { Some(s) } else { None }
    } else {
        None
    };

    (user, tty, source_ip)
}

// =========================================================================
// PAMモジュールのエントリポイント (C言語互換)
// =========================================================================

/// --- 1. 認証フェーズのフック (パスワード等の認証時にsshdからlibpam経由で呼ばれる) ---
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // このフックが呼ばれたということは、パスワード認証系（またはKbdInteractive）が走っている
    let method = CString::new("password").unwrap();
    let raw_ptr = method.into_raw(); // 所有権を放棄して生ポインタ化

    // メモリスタックに "password" ファクトを保存
    pam_set_data(
        pamh,
        TEAL_AUTH_METHOD_KEY.as_ptr() as *const c_char,
        raw_ptr as *mut c_void,
        Some(cleanup_string),
    );

    // 認証自体はsshd側の pam_unix 等に任せるため、IGNOREを返してスタックを邪魔しない
    PamReturnCode::IGNORE as c_int
}

/// --- 2. セッション開始フェーズのフック ---
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // ユーザー名、TTY、接続元IPを取得
    let (user, tty, source_ip) = get_session_info(pamh);
    
    let mut auth_method: Option<String> = None;

    // ステップA: pam_get_data で auth フックが残したデータを検索
    let mut data_ptr: *const c_void = std::ptr::null();
    let res = pam_get_data(pamh, TEAL_AUTH_METHOD_KEY.as_ptr() as *const c_char, &mut data_ptr);
    
    if res == (PamReturnCode::SUCCESS as c_int) && !data_ptr.is_null() {
        let c_str = CStr::from_ptr(data_ptr as *const c_char);
        auth_method = Some(c_str.to_string_lossy().into_owned());
    } else {
        // ステップB: データがない場合、かつリモートからの接続IPが存在すれば「公開鍵認証」と判定
        if let Some(ref ip) = source_ip {
            if !ip.is_empty() {
                auth_method = Some("publickey".to_string());
            }
        }
    }

    // ログ表示（表示用には unwrap_or を使用して綺麗に整形）
    let log_ip = source_ip.as_deref().unwrap_or("127.0.0.1");
    let log_auth = auth_method.as_deref().unwrap_or("local/unspecified");
    println!(
        "[TEAL PAM] User '{}' logged in on TTY '{}' from IP '{}' via '{}'", 
        user, tty, log_ip, log_auth
    );

    notify_teald("login", &user, &tty, source_ip, auth_method);
    
    PamReturnCode::SUCCESS as c_int
}

/// --- 3. セッション終了フェーズのフック（ログアウト通知） ---
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let (user, tty, _source_ip) = get_session_info(pamh);

    // デーモンにログアウトを通知
    notify_teald("logout", &user, &tty, None, None);

    println!("[TEAL PAM] User '{}' logged out from TTY '{}'", user, tty);

    PamReturnCode::SUCCESS as c_int
}

// 共有ライブラリの要件を満たすためのその他ダミーフック群
#[no_mangle] pub unsafe extern "C" fn pam_sm_setcred(_pamh: *mut PamHandle, _f: c_int, _ac: c_int, _av: *const *const c_char) -> c_int { PamReturnCode::SUCCESS as c_int }
#[no_mangle] pub unsafe extern "C" fn pam_sm_acct_mgmt(_pamh: *mut PamHandle, _f: c_int, _ac: c_int, _av: *const *const c_char) -> c_int { PamReturnCode::SUCCESS as c_int }