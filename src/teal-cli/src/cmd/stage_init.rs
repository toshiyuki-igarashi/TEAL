// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * 
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::{self, File};
use std::path::Path;

use teald::bundle::{DEFAULT_TEAL_DIR, STAGE_LOCK_PATH, STAGE_TEAL_DIR};

/// `teal-cli stage-init` のエントリポイント
pub fn run(force: bool) -> Result<()> {
    println!("=> ステージング領域の初期化を開始します...");

    let current_dir = Path::new(DEFAULT_TEAL_DIR);
    let stage_dir = Path::new(STAGE_TEAL_DIR);

    // 1. 現行ポリシーディレクトリの存在確認
    if !current_dir.exists() {
        anyhow::bail!(
            "現行ポリシーディレクトリ '{}' が存在しません。",
            current_dir.display()
        );
    }

    // 2. 排他ロック (LOCK_EX) の取得
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(STAGE_LOCK_PATH)
        .context("Failed to open staging lock file")?;

    #[cfg(unix)]
    lock_file
        .lock_exclusive()
        .context("Failed to acquire exclusive lock (LOCK_EX) on staging area")?;

    // 3. 既存のステージングディレクトリの確認
    if stage_dir.exists() {
        let is_empty = fs::read_dir(stage_dir)
            .map(|mut i| i.next().is_none())
            .unwrap_or(false);

        if !is_empty && !force {
            anyhow::bail!(
                "ステージングディレクトリ '{}' は既に存在し、ファイルが含まれています。\n上書きする場合は `--force` (-f) オプションを指定してください。",
                stage_dir.display()
            );
        }

        if force {
            fs::remove_dir_all(stage_dir)
                .with_context(|| format!("Failed to clear existing staging directory: {}", stage_dir.display()))?;
        }
    }

    fs::create_dir_all(stage_dir)
        .with_context(|| format!("Failed to create staging directory: {}", stage_dir.display()))?;

    // 4. 現行ポリシー・ロールを階層構造ごと再帰コピー
    let copied_count = copy_dir_recursive(current_dir, stage_dir, true)?;

    #[cfg(unix)]
    let _ = lock_file.unlock();

    println!("  -> {} 個のポリシー定義ファイルを '{}' へコピーしました", copied_count, stage_dir.display());
    println!("✅ ステージング環境の準備が完了しました。ファイルを編集後に `teal-cli diff` を実行してください。");

    Ok(())
}

/// ディレクトリ構造を保ったままファイルを再帰的にコピーするヘルパー
fn copy_dir_recursive(src: &Path, dst: &Path, is_root: bool) -> Result<usize> {
    let mut count = 0;

    for entry in fs::read_dir(src).with_context(|| format!("Failed to read directory: {}", src.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // 隠しファイル（.stage.lock 等）は常に除外
        if name_str.starts_with('.') {
            continue;
        }

        // ルート直下の場合は、ステージング先ディレクトリ自身（"new"）を除外
        if is_root && name_str == "new" {
            continue;
        }

        let dest_path = dst.join(&file_name);

        if path.is_dir() {
            fs::create_dir_all(&dest_path)
                .with_context(|| format!("Failed to create directory: {}", dest_path.display()))?;
            count += copy_dir_recursive(&path, &dest_path, false)?;
        } else if path.is_file() {
            fs::copy(&path, &dest_path)
                .with_context(|| format!("Failed to copy '{}' to '{}'", path.display(), dest_path.display()))?;
            count += 1;
        }
    }

    Ok(count)
}