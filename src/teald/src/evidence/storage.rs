// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::fs::{File, OpenOptions};
use std::io::{self, Write, BufWriter};
use std::sync::{RwLock, OnceLock, RwLockWriteGuard};
use super::schema::AuditLogEntry;

/// グローバルなログライター保持。
/// OnceLock で場所を固定し、RwLock で中身（BufWriter）の交換を許可する。
static LOG_WRITER: OnceLock<RwLock<BufWriter<File>>> = OnceLock::new();
const LOG_PATH: &str = "/var/log/teal/audit.jsonl";

/// 内部ヘルパー：書き込み用ガードを安全に取得する（遅延初期化付き）
fn get_writer_mut() -> io::Result<RwLockWriteGuard<'static, BufWriter<File>>> {
    // すでに初期化済みなら、ロックを取得して返す (毎回実行されるが高速)
    if let Some(rwlock) = LOG_WRITER.get() {
        return rwlock.write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Audit log lock poisoned"));
    }

    // --- 初回アクセス時のみ実行される初期化ロジック ---
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_PATH)?;

    let writer = RwLock::new(BufWriter::new(file));

    // OnceLockにセット (他スレッドとの競合時はセットせず既存の物を使う)
    let _ = LOG_WRITER.set(writer);

    // セットされた箱から改めてロックを取得して返す
    LOG_WRITER.get()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Logger initialization race condition"))?
        .write()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Audit log lock poisoned after init"))
}

/// ログ書き込み (通常はメモリバッファに入るだけなので高速)
pub fn write_log(entry: &AuditLogEntry) -> io::Result<()> {
    // 1. 書き込みロックを取得
    let mut guard = get_writer_mut()?;

    // 2. JSONシリアライズ、&mut *guard で内部の BufWriter<File> への可変参照を渡す
    serde_json::to_writer(&mut *guard, entry)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JSON serialisation error: {}", e)))?;
    
    // 3. 改行を付与
    writeln!(&mut *guard)?;

    Ok(())
}

/// 定期的な強制フラッシュ (sync_all)
/// ※ これを別スレッドから 1秒〜数秒おきに呼ぶ
pub fn force_flush() -> io::Result<()> {
    // 1. 書き込みロックを取得
    let mut writer = get_writer_mut()?;

    // 2. まず BufWriter のメモリバッファを OS のページキャッシュへ送る
    writer.flush()?;

    // 3. get_ref() で内部の File にアクセスし、
    //    OS のページキャッシュから物理ディスクへの同期（fsync）を強制する
    writer.get_ref().sync_all()?;

    Ok(())
}

/// ログファイルを閉じて、新しいファイルで開き直す（ローテーション）
pub fn reopen_log() -> io::Result<()> {
    // 1. 書込ロックを取得。この間、他のスレッドによる log_event は待機状態になる
    let mut writer_guard = get_writer_mut()?;

    // 2. 既存のバッファを強制フラッシュしてディスクに確実に書き出す
    writer_guard.flush()?;

    // 3. 新しいファイルを開く (logrotateによって古いファイルはリネーム済みの想定)
    let new_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_PATH)?;

    // 4. 中身を入れ替える！ (古い BufWriter はここでドロップされる)
    *writer_guard = BufWriter::new(new_file);

    Ok(())
}


