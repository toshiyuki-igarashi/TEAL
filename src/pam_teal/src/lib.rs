// SPDX-License-Identifier: MIT
//
// TEAL PAM module (pam_teal)
//
// Copyright (c) 2026 Toshiyuki Igarashi
use nix::unistd::User;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::net::UnixStream;

// pam_sys から公式の型、Enum、生C関数インポート
use pam_sys::raw::{pam_get_data, pam_get_item, pam_get_user, pam_set_data};
use pam_sys::types::{PamHandle, PamItemType, PamReturnCode};

use teal_common::{PamLoginNotification, PAM_SOCKET_PATH};

// TEAL内部で認証状態を引き回すための一意のメモリキー名
const TEAL_AUTH_METHOD_KEY: &[u8] = b"teal_auth_method\0";
const TEAL_SESSION_UID_KEY: &[u8] = b"teal_session_uid\0";

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

extern "C" fn cleanup_uid(_pamh: *mut PamHandle, data: *mut c_void, _pam_status: c_int) {
    if !data.is_null() {
        unsafe {
            drop(Box::from_raw(data as *mut u32));
        }
    }
}

/// teald に UNIX Domain Socket 経由でイベント（JSON文字列）を送信する
fn notify_teald(
    action: &str,
    uid: u32,
    tty: &str,
    source_ip: Option<String>,
    auth_method: Option<String>,
) {
    let socket_path = PAM_SOCKET_PATH;

    let notification = PamLoginNotification {
        action: action.to_string(),
        uid,
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

/// PamHandle からTTYを安全に一括取得する
unsafe fn get_session_tty(pamh: *mut PamHandle) -> String {
    let mut tty_ptr: *const c_void = std::ptr::null();

    if pam_get_item(pamh, PamItemType::TTY as c_int, &mut tty_ptr)
        == PamReturnCode::SUCCESS as c_int
        && !tty_ptr.is_null()
    {
        CStr::from_ptr(tty_ptr as *const c_char)
            .to_string_lossy()
            .into_owned()
    } else {
        "unknown".to_string()
    }
}

/// PamHandle からユーザー名とTTY、接続元IPを安全に一括取得する
unsafe fn get_session_info(pamh: *mut PamHandle) -> (Option<u32>, String, String, Option<String>) {
    // 1. ユーザー名の取得 (pam_sys::raw::pam_get_user を使用)
    let mut user_ptr: *const c_char = std::ptr::null();
    let get_result = pam_get_user(pamh, &mut user_ptr, std::ptr::null());
    let (uid, user) = if get_result == (PamReturnCode::SUCCESS as c_int) && !user_ptr.is_null() {
        let user = CStr::from_ptr(user_ptr).to_string_lossy().into_owned();
        // PAM環境下でUIDを解決
        (
            User::from_name(&user)
                .ok()
                .flatten()
                .map(|u| u.uid.as_raw()),
            user,
        )
    } else {
        (None, "unknown".to_string())
    };

    // 2. TTYの取得 (PamItemType::TTY を使用)
    let tty = get_session_tty(pamh);

    // 3. 接続元IP (RHOST) の取得
    let mut rhost_ptr: *const c_void = std::ptr::null();
    let source_ip = if pam_get_item(pamh, PamItemType::RHOST as c_int, &mut rhost_ptr)
        == (PamReturnCode::SUCCESS as c_int)
        && !rhost_ptr.is_null()
    {
        let s = CStr::from_ptr(rhost_ptr as *const c_char)
            .to_string_lossy()
            .trim()
            .to_string();
        if !s.is_empty() {
            Some(s)
        } else {
            None
        }
    } else {
        None
    };

    let source_ip = source_ip.and_then(|s| match s.parse::<IpAddr>() {
        Ok(ip) => Some(ip.to_string()),
        Err(_) => {
            eprintln!("[TEAL PAM] Invalid source IP from PAM_RHOST: '{}'", s);
            None
        }
    });

    (uid, user, tty, source_ip)
}

// =========================================================================
// PAMモジュールのエントリポイント (C言語互換)
// =========================================================================

/// --- 1. 認証フェーズのフック (パスワード等の認証時にsshdからlibpam経由で呼ばれる) ---
/// 認証フェーズのフック (パスワード等の認証時にsshdからlibpam経由で呼ばれる)
///
/// # Safety
///
/// この関数は Linux-PAM フレームワーク（C-ABI）から直接呼び出されることを前提としています。
/// 呼び出し元は、`pamh` が有効な PAM ハンドルを指す有効なポインタであること、
/// および `_argv`（引数がある場合）が `_argc` 個の NULL 終端 C 文字列配列を指していることを保証する必要があります。
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
    let result = pam_set_data(
        pamh,
        TEAL_AUTH_METHOD_KEY.as_ptr() as *const c_char,
        raw_ptr as *mut c_void,
        Some(cleanup_string),
    );

    if result != PamReturnCode::SUCCESS as c_int {
        let _ = CString::from_raw(raw_ptr);
    }

    // 認証自体はsshd側の pam_unix 等に任せるため、IGNOREを返してスタックを邪魔しない
    PamReturnCode::IGNORE as c_int
}

/// --- 2. セッション開始フェーズのフック ---
/// セッション開始フェーズのフック
///
/// # Safety
///
/// この関数は Linux-PAM フレームワーク（C-ABI）から直接呼び出されることを前提としています。
/// `pamh` は有効かつ初期化済みの PAM ハンドルポインタである必要があります。
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // ユーザー名、TTY、接続元IPを取得
    let (uid_opt, user, tty, source_ip) = get_session_info(pamh);

    let uid = match uid_opt {
        Some(u) => u,
        None => {
            eprintln!("[TEAL PAM] Failed to resolve UID for login session");
            return PamReturnCode::SESSION_ERR as c_int;
        }
    };

    // UIDをヒープに確保
    let uid_ptr = Box::into_raw(Box::new(uid));

    // PAMハンドルに保存
    let result = pam_set_data(
        pamh,
        TEAL_SESSION_UID_KEY.as_ptr() as *const c_char,
        uid_ptr as *mut c_void,
        Some(cleanup_uid),
    );

    if result != PamReturnCode::SUCCESS as c_int {
        // 保存に失敗した場合は自分で解放
        drop(Box::from_raw(uid_ptr));

        eprintln!("[TEAL PAM] Failed to save session UID");
        return PamReturnCode::SESSION_ERR as c_int;
    }

    let mut auth_method: Option<String> = None;

    // ステップA: pam_get_data で auth フックが残したデータを検索
    let mut data_ptr: *const c_void = std::ptr::null();
    let res = pam_get_data(
        pamh,
        TEAL_AUTH_METHOD_KEY.as_ptr() as *const c_char,
        &mut data_ptr,
    );

    if res == (PamReturnCode::SUCCESS as c_int) && !data_ptr.is_null() {
        let c_str = CStr::from_ptr(data_ptr as *const c_char);
        auth_method = Some(c_str.to_string_lossy().into_owned());
    }

    // ログ表示（表示用には unwrap_or を使用して綺麗に整形）
    let log_ip = source_ip.as_deref().unwrap_or("<unknown>");
    let log_auth = auth_method.as_deref().unwrap_or("local/unspecified");
    println!(
        "[TEAL PAM] User '{}' UID '{}' logged in on TTY '{}' from IP '{}' via '{}'",
        user, uid, tty, log_ip, log_auth
    );

    notify_teald("login", uid, &tty, source_ip, auth_method);

    PamReturnCode::SUCCESS as c_int
}

/// --- 3. セッション終了フェーズのフック（ログアウト通知） ---
/// セッション終了フェーズのフック（ログアウト通知）
///
/// # Safety
///
/// この関数は Linux-PAM フレームワーク（C-ABI）から直接呼び出されることを前提としています。
/// `pamh` は有効かつ初期化済みの PAM ハンドルポインタである必要があります。
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let tty = get_session_tty(pamh);

    let mut data_ptr: *const c_void = std::ptr::null();

    let result = pam_get_data(
        pamh,
        TEAL_SESSION_UID_KEY.as_ptr() as *const c_char,
        &mut data_ptr,
    );

    let uid = if result == PamReturnCode::SUCCESS as c_int && !data_ptr.is_null() {
        *(data_ptr as *const u32)
    } else {
        eprintln!("[TEAL PAM] Failed to retrieve session UID");
        return PamReturnCode::SESSION_ERR as c_int;
    };

    // デーモンにログアウトを通知
    notify_teald("logout", uid, &tty, None, None);

    println!("[TEAL PAM] UID '{}' logged out from TTY '{}'", uid, tty);

    PamReturnCode::SUCCESS as c_int
}

// 共有ライブラリの要件を満たすためのその他ダミーフック群

/// PAM setcred フック（未使用のスタブ）
///
/// # Safety
///
/// Linux-PAM から呼び出される前提の C-ABI インターフェースです。
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _f: c_int,
    _ac: c_int,
    _av: *const *const c_char,
) -> c_int {
    PamReturnCode::SUCCESS as c_int
}

/// PAM acct_mgmt フック（未使用のスタブ）
///
/// # Safety
///
/// Linux-PAM から呼び出される前提の C-ABI インターフェースです。
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _f: c_int,
    _ac: c_int,
    _av: *const *const c_char,
) -> c_int {
    PamReturnCode::SUCCESS as c_int
}
