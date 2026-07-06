// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use nix::unistd::{Uid, User};
use anyhow::{Context, Result};
use std::borrow::Cow;
use serde::{Deserialize, Deserializer};

use crate::types::Action;

/// u32でエンコードされたActionを文字列へ変換
pub fn u32_to_str(op: u32) -> String {
    let mut s = Vec::new();
    if Action::Read.to_mask() & op != 0 { s.push("READ"); };
    if Action::Write.to_mask() & op != 0 { s.push("WRITE"); };
    if Action::Execute.to_mask() & op != 0 { s.push("EXECUTE"); };
    if Action::FileDelete.to_mask() & op != 0 { s.push("DELETE"); };
    if Action::FileUnlink.to_mask() & op != 0 { s.push("UNLINK"); };
    if Action::FileRename.to_mask() & op != 0 { s.push("RENAME"); };
    if Action::FileChmod.to_mask() & op != 0 { s.push("CHMOD"); };
    if Action::FileChown.to_mask() & op != 0 { s.push("CHOWN"); };
    if Action::NetConnect.to_mask() & op != 0 { s.push("CONNECT"); };
    if Action::Unknown.to_mask() & op != 0 { s.push("UNKNOWN"); };

    s.join(",")
}

/// ユーザー名から UID を取得する (REGISTER コマンド等で使用)
///
/// # Errors
/// ユーザーが見つからない場合は ERR_RESOLVE_FAILED 相当のエラーを返す
pub fn name_to_uid(name: &str) -> Result<u32> {
    User::from_name(name)
        .with_context(|| format!("Failed to call getpwnam for {}", name))?
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| anyhow::anyhow!("User not found: {}", name))
}

/// UID からユーザー名を取得する (LIST/SHOW/監査ログ等で使用)
///
/// # Errors
/// システムに存在しない UID の場合はエラーを返す
pub fn uid_to_name(uid: u32) -> Result<String> {
    User::from_uid(Uid::from_raw(uid))
        .with_context(|| format!("Failed to call getpwuid for UID {}", uid))?
        .map(|u| u.name)
        .ok_or_else(|| anyhow::anyhow!("UID not found: {}", uid))
}

/// カーネルの起動後の時間を文字列に変換
pub fn ktime_prefix() -> String {
    // dmesg と合わせるなら MONOTONIC（起動後秒）
    // サスペンド時間も含めたいなら CLOCK_BOOTTIME に変える
    let mut ts: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    format!("[{:>6}.{:06}] ", ts.tv_sec, (ts.tv_nsec / 1_000) as i64)
}

/// &strの文字列を小文字に変換し&strを返す
pub fn lower<'a>(s: &'a str) -> Cow<'a, str> {
    if s.chars().all(|c| !c.is_uppercase()) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.to_lowercase())
    }
}

/// 文字列が空の場合に None を返し、値がある場合は Some(String) を返す
pub fn normalize_opt_field(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// ヘルパー関数: 小文字の文字列配列を大文字に変換して Enum の Vec にする
pub fn deserialize_ops_uppercase<'de, D>(deserializer: D) -> Result<Vec<Action>, D::Error>
where
    D: Deserializer<'de>,
{
    // 1. 一度 JSON から通常の String の配列として読み込む
    let raw_strings = Vec::<String>::deserialize(deserializer)?;
    
    // 2. 各文字列を大文字に変換し、Action Enum にパースし直す
    let actions = raw_strings
        .into_iter()
        .map(|s| {
            let uppercase_str = s.to_uppercase();
            // serde_json の仕組みを利用して、大文字にした文字列から Action Enum を生成
            serde_json::from_value::<Action>(serde_json::Value::String(uppercase_str))
                .unwrap_or(Action::Unknown) // 変換に失敗したら Unknown に倒す
        })
        .collect();

    Ok(actions)
}


