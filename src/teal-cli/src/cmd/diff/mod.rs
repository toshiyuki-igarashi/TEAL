// SPDX-License-Identifier: MIT
/*
 * TEAL Policy Engine (teal_policy_engine)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */


pub mod rule_diff;
pub mod html;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use colored::Colorize;

#[cfg(unix)]
use fs2::FileExt; // flock用

use teald::bundle::load_bundle_from_dir;
use self::rule_diff::compare_policies;
use self::html::generate_html_report;


const CURRENT_DIR: &str = "/etc/teal.d";
const STAGE_DIR: &str = "/etc/teal.d/new";
const LOCK_FILE_PATH: &str = "/etc/teal.d/.stage.lock";

/// `teal-cli diff` コマンドの実体ハンドラ
pub fn run(html: Option<PathBuf>) -> Result<()> {
    // -------------------------------------------------------------
    // 1. ロック取得 (LOCK_SH: 共有ロック)
    // -------------------------------------------------------------
    // ディレクトリが存在しない場合は自動作成
    if !Path::new(STAGE_DIR).exists() {
        anyhow::bail!("Staging directory '{}' does not exist.", STAGE_DIR);
    }

    // ロックファイルを開いて共有ロックを取得（スコープを抜けると自動解放）
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(LOCK_FILE_PATH)
        .context("Failed to open staging lock file")?;

    #[cfg(unix)]
    lock_file.lock_shared().context("Failed to acquire shared lock (LOCK_SH)")?;

    // -------------------------------------------------------------
    // 2. ディレクトリ内のファイルをソート順に一括ロード & ハッシュ計算
    // -------------------------------------------------------------
    let current_hash = compute_directory_hash(CURRENT_DIR)?;
    let new_hash = compute_directory_hash(STAGE_DIR)?;

    println!("{}", "🔍 Comparing TEAL Security Policies...".cyan().bold());
    println!("  • Current Policy Hash : {}", current_hash.yellow());
    println!("  • Staged Policy Hash  : {}\n", new_hash.green());

    // -------------------------------------------------------------
    // 3. 差分エンジンの呼び出し & 出力 (teal_policy_engine::diff)
    // -------------------------------------------------------------
    // teal_policy_engine 側で構文検証・差分抽出・セキュリティ強度判定を実行
    execute_diff(
        CURRENT_DIR,
        STAGE_DIR,
        &current_hash,
        &new_hash,
        html.as_deref(), // None なら標準出力、Some(path) なら HTML 書き出し
    )?;

    #[cfg(unix)]
    let _ = lock_file.unlock();

    Ok(())
}

/// 指定ディレクトリ配下のポリシー定義ファイル群をソート順に連結して SHA-256 を計算
fn compute_directory_hash<P: AsRef<Path>>(dir: P) -> Result<String> {
    let mut files = Vec::new();
    collect_policy_files(dir.as_ref(), &mut files)?;

    // 決定性を担保するためファイルパス（相対パス）でソート
    files.sort();

    let mut hasher = Sha256::new();
    for path in files {
        let content = fs::read(&path)
            .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
        hasher.update(&content);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// 再帰的に JSON ファイルを収集
fn collect_policy_files(dir: &Path, file_list: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // "new" ディレクトリ自身を再帰処理しないように除外
            if path.file_name().and_then(|s| s.to_str()) != Some("new") {
                collect_policy_files(&path, file_list)?;
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            file_list.push(path);
        }
    }
    Ok(())
}

/// セキュリティ影響度
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityImpact {
    Hardened, // 🟢 強化 (制限追加・権限縮小)
    Relaxed,  // 🔴 弱化 (制限解除・権限拡張)
    Neutral,  // ⚪ ニュートラル
}

/// 差分項目
#[derive(Debug, Clone)]
pub struct RuleDiffItem {
    pub rule_id: String,
    pub change_kind: String, // "ADDED", "REMOVED", "MODIFIED", "UNCHANGED"
    pub impact: SecurityImpact,
    pub details: Vec<String>,
}

/// 差分レポート全体の構造体
#[derive(Debug, Clone)]
pub struct PolicyDiffReport {
    pub current_hash: String,
    pub new_hash: String,
    pub items: Vec<RuleDiffItem>,
}

impl PolicyDiffReport {
    /// ターミナルへ ANSI カラー付きで出力
    pub fn render_terminal(&self) {
        println!("{}", "================ Policy Diff Summary ================".bold());
        for item in &self.items {
            let tag = match item.impact {
                SecurityImpact::Relaxed => "🔴 RELAXED".red().bold(),
                SecurityImpact::Hardened => "🟢 HARDENED".green().bold(),
                SecurityImpact::Neutral => "⚪ NEUTRAL".white(),
            };
            println!("  [{}] {} ({})", tag, item.rule_id.cyan(), item.change_kind);
            for d in &item.details {
                println!("      {}", d);
            }
        }
        println!("{}", "=====================================================".bold());
    }
}

pub fn execute_diff<P: AsRef<Path>>(
    current_dir: P,
    stage_dir: P,
    current_hash: &str,
    new_hash: &str,
    html_path: Option<&Path>,
) -> Result<()> {
    let current_bundle = teald::bundle::load_bundle_from_dir("/etc/teal.d")
        .context("Failed to load current policy bundle")?;

    let stage_bundle = load_bundle_from_dir("/etc/teal.d/new")
        .context("Failed to load staged policy bundle")?;

    let diff_report = compare_policies(
        &current_bundle,
        &stage_bundle,
        current_hash,
        new_hash,
    )?;

    if let Some(path) = html_path {
        generate_html_report(&diff_report, path)?;
        println!("  • Diff HTML Report written to: {}", path.display());
    } else {
        diff_report.render_terminal();
    }

    Ok(())
}
