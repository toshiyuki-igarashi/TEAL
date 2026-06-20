// SPDX-License-Identifier: GPL-2.0-only
/*
 * TEAL (Trusted Execution Analysis Layer) LSM
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
//! TEAL Integrated Kernel Module
//! Role: Decision Maker Logic Only (Infrastructure is handled by C-LSM)

use kernel::prelude::*;
use kernel::str::{CStr, CString};

use core::ffi::{c_void, c_char};
use core::str;
use core::sync::atomic::{AtomicBool, Ordering};
use core::ptr::{addr_of, read_unaligned};

// --- v6.8 以降用（#ifdef is_v6_8 に相当） ---
#[cfg(is_v6_8)]
module! {
    type: TealModule,
    name: "teal_module",
    author: "Kernel-MPA Dev",      // ←単数形
    description: "TEAL Decision Maker",
    license: "GPL",
}

// --- v6.8 より古いバージョン用（#ifndef is_v6_8 に相当） ---
#[cfg(not(is_v6_8))]
module! {
    type: TealModule,
    name: "teal_module",
    authors: ["Kernel-MPA Dev"],   // ←複数形
    description: "TEAL Decision Maker",
    license: "GPL",
}

extern "C" {
    /// C側の承認待ち関数（teal_wait_for_approval）を呼び出します。
    pub fn teal_wait_for_approval(
        action: *const core::ffi::c_char,
        target_name: *const core::ffi::c_char,
        target_dev: u64,
        target_ino: u64,
        new_target: *const core::ffi::c_char,
        new_target_dev: u64,
        new_target_ino: u64,
        teal_mode: u8,
        exec_path: *const core::ffi::c_char,
        script_path: *const core::ffi::c_char,
        applet: *const core::ffi::c_char,
    ) -> i32;

    /// 決定ロジックのコールバックをC言語側のLSMに登録します。
    pub fn teal_register_decision_maker(
        callback: core::option::Option<unsafe extern "C" fn(i32, *mut core::ffi::c_void) -> i32>,
    );

    /// 決定ロジックのコールバックの登録を解除します。
    pub fn teal_unregister_decision_maker();

    /// コンフィグ更新のコールバックをC言語側のLSMに登録します。
    pub fn teal_register_configurator(
        callback: core::option::Option<unsafe extern "C" fn(i32)>,
    );

    /// 現在のプロセスのコマンド名（comm）を取得します。
    pub fn teal_get_current_comm(buf: *mut core::ffi::c_char, len: usize);

    /// 現在のプロセスのスレッドID（pid）を取得します。
    pub fn teal_get_current_pid() -> i32;

    /// 現在のプロセスのスレッドグループID（tgid）を取得します。
    pub fn teal_get_current_tgid() -> i32;
}


/// Context structure passed from the C LSM layer to the Rust decision logic.
///
/// This structure is created on the C side (`teal_lsm.c`) and passed to Rust
/// via the `teal_decision_maker` callback. All fields are raw C string pointers
/// (`const char *`) and **must be treated as borrowed data**.
///
/// # Safety
///
/// - All pointers may be NULL.
/// - Each pointer, if non-NULL, must point to a valid NUL-terminated C string.
/// - The lifetime of the pointed-to memory is limited to the duration of the
///   callback invocation; the Rust side must not store these pointers or derived
///   references beyond that scope.
///
/// # ABI
///
/// This struct is marked with `#[repr(C)]` to ensure ABI compatibility with
/// the corresponding C definition:
///
/// ```c
///struct teal_rs_ctx {
///    const char *target;
///    const char *program;
///    const char *script;
///    dev_t target_dev;
///    unsigned long target_ino;
///};
/// ```
#[repr(C)]
pub struct teal_rs_ctx {
    /// Target path or object associated with the security event.
    pub target: *const core::ffi::c_char,

    /// Executing program path (e.g. executable path or interpreter).
    pub program: *const core::ffi::c_char,

    /// Script path, if applicable (may be NULL).
    pub script: *const core::ffi::c_char,

    /// Target device ID (major/minor combined).
    pub target_dev: u64,

    /// Target inode number.
    pub target_ino: u64,
}

#[repr(C)]
struct teal_rs_rename_ctx {
    program: *const c_char,
    script: *const c_char,
    old_target: *const c_char,
    old_target_dev: u64,
    old_target_ino: u64,
    new_target: *const c_char,
    new_target_dev: u64,
    new_target_ino: u64,
}

static ENFORCING_MODE: AtomicBool = AtomicBool::new(false);

struct TealModule;

// --- コンフィグ更新コールバック ---
#[no_mangle]
unsafe extern "C" fn teal_update_config(mode: i32) {
    pr_info!("TEAL-RS: teal_update_config called: mode={}\n", mode);
    if mode == 1 {
        ENFORCING_MODE.store(true, Ordering::Relaxed);
        pr_info!("TEAL-RS: Switched to ENFORCING mode.\n");
    } else {
        ENFORCING_MODE.store(false, Ordering::Relaxed);
        pr_info!("TEAL-RS: Switched to AUDIT mode.\n");
    }
}

// --- 承認要求ヘルパー ---
fn to_kcstring_or_empty(s: &str) -> Result<CString, kernel::error::Error> {
    match CString::try_from_fmt(format_args!("{}", s)) {
        Ok(cs) => Ok(cs),
        Err(_) => {
            // NUL 混入などで失敗したら空文字を試す
            CString::try_from_fmt(format_args!(""))
        }
    }
}

fn request_approval_ex(
    action: &str, 
    target: &str, 
    target_dev: u64, 
    target_ino: u64, 
    new_target: &str,
    new_target_dev: u64,
    new_target_ino: u64,
    program: &str, 
    script: &str, 
    applet: &str
) -> i32 {
    let teal_mode: u8 = (!ENFORCING_MODE.load(Ordering::Relaxed)) as u8;

    // =========================================================
    // 変換失敗時（ENOMEM等）に早期リターンするマクロを定義
    // =========================================================
    macro_rules! try_cstring {
        ($val:expr) => {
            match to_kcstring_or_empty($val) {
                Ok(v) => v,
                Err(e) => return e.to_errno(),
            }
        };
    }

    // マクロを使って一気にパース（万が一どれか失敗したらその時点で return される）
    let action_c     = try_cstring!(action);
    let target_c     = try_cstring!(target);
    let new_target_c = try_cstring!(new_target);
    let program_c    = try_cstring!(program);
    let script_c     = try_cstring!(script);
    let applet_c     = try_cstring!(applet);

    unsafe {
        // C側のカーネル関数を呼び出す
        teal_wait_for_approval(
            action_c.as_ptr()     as *const core::ffi::c_char,
            target_c.as_ptr()     as *const core::ffi::c_char,
            target_dev            as _,         
            target_ino            as _,         
            new_target_c.as_ptr() as *const core::ffi::c_char,
            new_target_dev        as _,
            new_target_ino        as _,
            teal_mode,               
            program_c.as_ptr()    as *const core::ffi::c_char, 
            script_c.as_ptr()     as *const core::ffi::c_char,  
            applet_c.as_ptr()     as *const core::ffi::c_char,  
        )
    }
}

// --- LSM 決定ロジック ---
const TASK_COMM_LEN: usize = 16;

#[inline]
fn current_comm_str() -> [u8; TASK_COMM_LEN] {
    let mut comm = [0u8; TASK_COMM_LEN];
    unsafe {
        teal_get_current_comm(
            comm.as_mut_ptr() as *mut c_char,
            comm.len(),
        );
    }
    comm
}

#[inline]
fn comm_bytes_to_str(comm: &[u8; TASK_COMM_LEN]) -> &str {
    // 末尾の \0 を落としてから UTF-8 解釈
    let s = match comm.iter().position(|&b| b == 0) {
        Some(n) => &comm[..n],
        None => &comm[..],
    };
   str::from_utf8(s).unwrap_or("")
}

#[inline]
fn cstr_to_str_lossy<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }

    // unsafe を最小範囲に閉じ込める
    // --- v6.8 以降用（i8 を要求） ---
    #[cfg(is_v6_8)]
    let cs: &CStr = unsafe { CStr::from_char_ptr(p as *const i8) };

    // --- v6.8 より古いバージョン用（u8 を許容） ---
    #[cfg(not(is_v6_8))]
    let cs: &CStr = unsafe { CStr::from_char_ptr(p as *const u8) };

    cs.to_str().unwrap_or("")
}


const EVENT_READ: i32    = 1;
const EVENT_WRITE: i32   = 2;
const EVENT_EXECUTE: i32 = 4;
const EVENT_DELETE: i32  = 8;
const EVENT_UNLINK: i32  = 16;
const EVENT_RENAME: i32  = 32;
const EVENT_CHMOD: i32   = 64;
const EVENT_CHOWN: i32   = 128;
const EVENT_CONNECT: i32 = 256;

#[inline]
fn action_name_for_event(event_type: i32) -> Option<&'static str> {
    match event_type {
        EVENT_READ    => Some("READ"),
        EVENT_WRITE   => Some("WRITE"),
        EVENT_EXECUTE => Some("EXECUTE"),
        EVENT_DELETE  => Some("DELETE"),    // rmdir用
        EVENT_UNLINK  => Some("DELETE"),    // unlink用
        EVENT_RENAME  => Some("RENAME"),
        EVENT_CHMOD   => Some("CHMOD"),
        EVENT_CHOWN   => Some("CHOWN"),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct TealContext<'a> {
    target: &'a str,
    program: &'a str,
    script: &'a str,
    target_dev: u64,
    target_ino: u64,
}

unsafe fn parse_teal_ctx<'a>(ctx: *mut c_void) -> Option<TealContext<'a>> {
    if ctx.is_null() {
        return None;
    }
    let p = ctx as *const teal_rs_ctx;

    let t  = unsafe { read_unaligned(addr_of!((*p).target)) };
    let pr = unsafe { read_unaligned(addr_of!((*p).program)) };
    let sc = unsafe { read_unaligned(addr_of!((*p).script)) };
    let target_dev = unsafe { read_unaligned(addr_of!((*p).target_dev)) };
    let target_ino = unsafe { read_unaligned(addr_of!((*p).target_ino)) };

    let target  = cstr_to_str_lossy::<'a>(t);
    let program = cstr_to_str_lossy::<'a>(pr);
    let script  = cstr_to_str_lossy::<'a>(sc);

    Some(TealContext { 
        target, 
        program, 
        script, 
        target_dev, 
        target_ino 
    })
}

unsafe fn handle_file_event(event_type: i32, ctx: *mut c_void) -> i32 {
    let action = match action_name_for_event(event_type) {
        Some(a) => a,
        None => return 0,
    };

    let tctx = match unsafe { parse_teal_ctx(ctx) } {
        Some(v) => v,
        None => return 0,
    };

    let comm = current_comm_str();
    let comm_str = comm_bytes_to_str(&comm);

    request_approval_ex(
        action, 
        tctx.target, 
        tctx.target_dev, 
        tctx.target_ino, 
        "",
        0,
        0,
        tctx.program, 
        tctx.script, 
        comm_str
    )
}

unsafe fn handle_dentry_event(event_type: i32, ctx: *mut c_void) -> i32 {
    // 共通関数を使ってアクション名を取得（失敗時は0を返して保護）
    let action = match action_name_for_event(event_type) {
        Some(a) => a,
        None => return 0,
    };

    // C側で既に解決済みの ctx を使うだけ！
    let tctx = match unsafe { parse_teal_ctx(ctx) } {
        Some(v) => v,
        None => return 0,
    };

    let comm = current_comm_str();
    let comm_str = comm_bytes_to_str(&comm);

    request_approval_ex(
        action, 
        tctx.target, 
        tctx.target_dev, 
        tctx.target_ino, 
        "",
        0,
        0,
        tctx.program, 
        tctx.script, 
        comm_str
    )
}

unsafe fn handle_connect_event(ctx: *mut c_void) -> i32 {
    let tctx = match unsafe { parse_teal_ctx(ctx) } {
        Some(v) => v,
        None => return 0,
    };

    let comm = current_comm_str();
    let comm_str = comm_bytes_to_str(&comm);

    // program と script が空文字 "" の場合に確実に "-" に変換する
    let prog = if tctx.program.is_empty() { "-" } else { tctx.program };
    let scpt = if tctx.script.is_empty() { "-" } else { tctx.script };

    request_approval_ex(
        "CONNECT", 
        tctx.target, 
        tctx.target_dev, // ネットワークでは通常 0
        tctx.target_ino, // ネットワークでは通常 0
        "",
        0,
        0,
        prog,            // 確実に "-" 以上を渡す
        scpt,            // 確実に "-" 以上を渡す
        comm_str
    )
}

#[derive(Clone, Copy)]
struct TealRenameContext<'a> {
    program: &'a str,
    script: &'a str,
    old_target: &'a str,
    old_target_dev: u64,
    old_target_ino: u64,
    new_target: &'a str,
    new_target_dev: u64,
    new_target_ino: u64,
}

unsafe fn parse_teal_rename_ctx<'a>(ctx: *mut c_void) -> Option<TealRenameContext<'a>> {
    if ctx.is_null() { return None; }
    let p = ctx as *const teal_rs_rename_ctx;

    // 非アライメントリードでCの構造体から安全に値を引き出す
    let pr = unsafe { read_unaligned(addr_of!((*p).program)) };
    let sc = unsafe { read_unaligned(addr_of!((*p).script)) };
    let ot = unsafe { read_unaligned(addr_of!((*p).old_target)) };
    let old_target_dev = unsafe { read_unaligned(addr_of!((*p).old_target_dev)) };
    let old_target_ino = unsafe { read_unaligned(addr_of!((*p).old_target_ino)) };
    let nt = unsafe { read_unaligned(addr_of!((*p).new_target)) };
    let new_target_dev = unsafe { read_unaligned(addr_of!((*p).new_target_dev)) };
    let new_target_ino = unsafe { read_unaligned(addr_of!((*p).new_target_ino)) };

    Some(TealRenameContext {
        program: cstr_to_str_lossy::<'a>(pr),
        script: cstr_to_str_lossy::<'a>(sc),
        old_target: cstr_to_str_lossy::<'a>(ot),
        old_target_dev,
        old_target_ino,
        new_target: cstr_to_str_lossy::<'a>(nt),
        new_target_dev,
        new_target_ino,
    })
}

unsafe fn handle_rename_event(ctx: *mut c_void) -> i32 {
    let action = "RENAME"; // リネーム固定

    let tctx = match unsafe { parse_teal_rename_ctx(ctx) } { // 専用パース関数
        Some(v) => v,
        None => return 0,
    };

    let comm = current_comm_str();
    let comm_str = comm_bytes_to_str(&comm);

    request_approval_ex(
        action, 
        tctx.old_target, // 移動元パス
        tctx.old_target_dev, 
        tctx.old_target_ino, 
        tctx.new_target, // 移動先パス
        tctx.new_target_dev, // 移動先dev
        tctx.new_target_ino, // 移動先ino
        tctx.program, 
        tctx.script, 
        comm_str
    )
}

#[inline(never)]
fn always_false_but_opaque() -> bool {
    let x: u8 = 0;
    unsafe { core::ptr::read_volatile(&x) != 0 }
}

#[cold]
#[inline(never)]
fn unreachable_tail() -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
unsafe extern "C" fn teal_decision_logic(event_type: i32, ctx: *mut c_void) -> i32 {
    // LSMフックの規約に従い、デフォルトは 0 (ALLOW)
    let final_result = 0; 

    // 評価対象の全イベントビット
    let events = [
        EVENT_READ, EVENT_WRITE, EVENT_EXECUTE, 
        EVENT_DELETE, EVENT_UNLINK, EVENT_RENAME, 
        EVENT_CHMOD, EVENT_CHOWN, EVENT_CONNECT
    ];

    for &event in &events {
        // ビットが立っているかチェック
        if (event_type & event) != 0 {
            // 個別の評価を実行
            let res = match event {
                EVENT_READ | EVENT_EXECUTE | EVENT_WRITE | EVENT_CHMOD | EVENT_CHOWN => {
                    unsafe { handle_file_event(event, ctx) }
                },
                EVENT_UNLINK | EVENT_DELETE => unsafe { handle_dentry_event(event, ctx) },
                EVENT_RENAME => unsafe { handle_rename_event(ctx) },
                EVENT_CONNECT => unsafe { handle_connect_event(ctx) },
                _ => 0, // 未知のイベントは透過許可
            };

            if res != 0 {
                return res; 
            }
        }
    }

    // =========================================================================
    // 最適化避けハック (末尾呼び出し最適化およびデッドコード削除を抑制)
    // =========================================================================
    if always_false_but_opaque() {
        unreachable_tail();
    }

    final_result
}

impl kernel::Module for TealModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("TEAL-RS: Module Loaded (Decision Maker Only).\n");
        unsafe {
            teal_register_decision_maker(Some(teal_decision_logic));
            teal_register_configurator(Some(teal_update_config));
        }
        Ok(TealModule)
    }
}

impl Drop for TealModule {
    fn drop(&mut self) {
        unsafe { 
            teal_unregister_decision_maker();
        }
        pr_info!("TEAL-RS: Unloaded.\n");
    }
}
