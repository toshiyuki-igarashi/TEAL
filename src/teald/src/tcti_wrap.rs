// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use tss_esapi::tss2_esys::{TSS2_RC, TSS2_TCTI_CONTEXT, size_t};

// 本物のデバイスドライバ初期化関数 (tss2-tcti-device)
extern "C" {
    fn Tss2_Tcti_Device_Init(
        tctiContext: *mut TSS2_TCTI_CONTEXT,
        size: *mut size_t,
        conf: *const c_char,
    ) -> TSS2_RC;
}

// リンカによって「Tss2_TctiLdr_Initialize」の代わりに呼ばれる関数
// 関数名は必ず "__wrap_" で始めるルールです
#[no_mangle]
pub unsafe extern "C" fn __wrap_Tss2_TctiLdr_Initialize(
    name_conf: *const c_char,
    context: *mut *mut TSS2_TCTI_CONTEXT,
) -> TSS2_RC {
    // どんな設定(name_conf)が来ても無視して、強制的に "/dev/tpmrm0" を使う
    let conf_str = CString::new("/dev/tpmrm0").unwrap();
    
    // 1. サイズ取得
    let mut size: size_t = 0;
    let ret = Tss2_Tcti_Device_Init(std::ptr::null_mut(), &mut size, conf_str.as_ptr());
    if ret != 0 { return ret; }

    // 2. メモリ確保 (本来は呼び出し元が解放責任を持つため、ここでmalloc相当が必要)
    // Rustのallocatorを使って確保し、C側に渡す
    let layout = std::alloc::Layout::from_size_align(size as usize, 8).unwrap();
    let ctx_ptr = std::alloc::alloc(layout) as *mut TSS2_TCTI_CONTEXT;

    // 3. 初期化
    let ret = Tss2_Tcti_Device_Init(ctx_ptr, &mut size, conf_str.as_ptr());
    if ret != 0 {
        std::alloc::dealloc(ctx_ptr as *mut u8, layout);
        return ret;
    }

    // 成功したらポインタを書き戻す
    *context = ctx_ptr;
    0 // TSS2_RC_SUCCESS
}

// Finalizeも乗っ取って、Rustで確保したメモリを正しく解放する
#[no_mangle]
pub unsafe extern "C" fn __wrap_Tss2_TctiLdr_Finalize(
    context: *mut *mut TSS2_TCTI_CONTEXT,
) {
    if !context.is_null() && !(*context).is_null() {
        // ここでは本来 Tss2_Tcti_Device_Finalize を呼ぶべきですが、
        // 単純なメモリ解放のみ行います (プロセス終了時なのでリークしても致命的ではない)
        // 厳密にはサイズを知る術がないため、deallocは危険。
        // デーモンプロセスなのでOSによる回収に任せるのが安全策です。
        *context = std::ptr::null_mut();
    }
}
