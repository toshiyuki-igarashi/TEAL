// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * 
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;

use teald::bundle::load_bundle_from_dir;
use teald::bundle::{
    compute_directory_hash, STAGE_TEAL_DIR, STAGE_LOCK_PATH,
};
use crate::run_signed_decision;

// teald クレートから共通型をインポート
use teald::common::DecisionKind;

/// ポリシー更新コマンドのエントリポイント
pub fn run() -> Result<()> {
    println!("=> ポリシー更新要求の準備を開始します...");

    // 1. ステージング領域の存在確認
    if !Path::new(STAGE_TEAL_DIR).exists() {
        anyhow::bail!(
            "ステージングディレクトリ '{}' が見つかりません。適用するポリシーファイルを配置してください。",
            STAGE_TEAL_DIR
        );
    }

    // 2. ロック取得 (LOCK_SH: 共有ロック)
    // ハッシュ計算および検証中のファイル書き換えを抑止
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(STAGE_LOCK_PATH)
        .context("Failed to open staging lock file")?;

    #[cfg(unix)]
    lock_file
        .lock_shared()
        .context("Failed to acquire shared lock (LOCK_SH) on staging area")?;

    // 3. バンドル構文チェック & バリデーション
    println!("  -> ステージングポリシー ({}) の妥当性を検証中...", STAGE_TEAL_DIR);
    let _stage_bundle = load_bundle_from_dir(STAGE_TEAL_DIR)
        .context("Failed to load/validate staged policy bundle")?;

    // 4. 決定論的結合ハッシュの計算 (diff と共通ロジック)
    let stage_hash = compute_directory_hash(STAGE_TEAL_DIR)
        .context("Failed to compute staged policy hash")?;
    println!("  -> ステージングポリシー結合ハッシュ: {}", stage_hash);

    // ロックの明示的解放（送信前に解放、またはスコープ終端で自動解放）
    #[cfg(unix)]
    let _ = lock_file.unlock();

    // 5. BLS署名を生成し、teald へ更新要求を送信 (Format: POLICY_UPDATE <hash> <sig>)
    println!("  -> 更新要求に署名し、teald デーモンへ送信中...");
    run_signed_decision(DecisionKind::PolicyUpdate, &stage_hash)?;

    println!("✅ ポリシー更新要求を送信しました (Staged Hash: {})", stage_hash);
    println!("   ※ 管理者の承認完了後、teald によりアトミックに本番適用されます。");

    Ok(())
}

