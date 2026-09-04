// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

pub mod bundle_diff;
pub mod rule_diff;
pub mod html;

use anyhow::{Context, Result};
use std::fs::File;
use std::path::{Path, PathBuf};
use colored::Colorize;

use teald::bundle::load_bundle_from_dir;
use teald::bundle::{
    compute_directory_hash, DEFAULT_TEAL_DIR, STAGE_TEAL_DIR, STAGE_LOCK_PATH,
};
use teal_policy_engine::ir::CompiledRule;

use self::bundle_diff::{compare_full_config, FullConfigDiff};
use self::rule_diff::compare_policies;
use self::html::generate_html_report;

/// `teal-cli diff` コマンドの実体ハンドラ
pub fn run(html: Option<PathBuf>) -> Result<()> {
    // -------------------------------------------------------------
    // 1. ロック取得 (LOCK_SH: 共有ロック)
    // -------------------------------------------------------------
    // ディレクトリが存在しない場合は自動作成
    if !Path::new(STAGE_TEAL_DIR).exists() {
        anyhow::bail!("Staging directory '{}' does not exist.", STAGE_TEAL_DIR);
    }

    // ロックファイルを開いて共有ロックを取得（スコープを抜けると自動解放）
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(STAGE_LOCK_PATH)
        .context("Failed to open staging lock file")?;

    #[cfg(unix)]
    lock_file.lock_shared().context("Failed to acquire shared lock (LOCK_SH)")?;

    // -------------------------------------------------------------
    // 2. ディレクトリ内のファイルをソート順に一括ロード & ハッシュ計算
    // -------------------------------------------------------------
    let current_hash = compute_directory_hash(DEFAULT_TEAL_DIR)?;
    let new_hash = compute_directory_hash(STAGE_TEAL_DIR)?;

    println!("{}", "🔍 Comparing TEAL Security Policies...".cyan().bold());
    println!("  • Current Policy Hash : {}", current_hash.yellow());
    println!("  • Staged Policy Hash  : {}\n", new_hash.green());

    // -------------------------------------------------------------
    // 3. 差分エンジンの呼び出し & 出力 (teal_policy_engine::diff)
    // -------------------------------------------------------------
    // teal_policy_engine 側で構文検証・差分抽出・セキュリティ強度判定を実行
    execute_diff(
        &current_hash,
        &new_hash,
        html.as_deref(), // None なら標準出力、Some(path) なら HTML 書き出し
    )?;

    #[cfg(unix)]
    let _ = lock_file.unlock();

    Ok(())
}

/// セキュリティ影響度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityImpact {
    Hardened, // 🟢 強化 (制限追加・権限縮小)
    Relaxed,  // 🔴 弱化 (制限解除・権限拡張)
    Neutral,  // ⚪ ニュートラル
}

/// 個別ルールの差分項目
#[derive(Debug, Clone)]
pub enum RuleDiffItem {
    Unchanged {
        id: String,
        source_file: String,
    },
    Added {
        rule: CompiledRule,
        impact: SecurityImpact,
    },
    Removed {
        rule: CompiledRule,
        impact: SecurityImpact,
    },
    Modified {
        id: String,
        impact: SecurityImpact,
        details: Vec<String>,
        source_file: String,
        // old_rule: Option<CompiledRule>, // 必要に応じて旧定義の全文プレビュー用
        // new_rule: Option<CompiledRule>, // 必要に応じて新定義の全文プレビュー用
    },
}

impl RuleDiffItem {
    pub fn source_file(&self) -> &str {
        match self {
            RuleDiffItem::Unchanged { source_file, .. } => source_file.as_str(),
            RuleDiffItem::Added { rule, .. } => rule.source_file.as_deref().unwrap_or("unknown.json"),
            RuleDiffItem::Removed { rule, .. } => rule.source_file.as_deref().unwrap_or("unknown.json"),
            RuleDiffItem::Modified { source_file, .. } => source_file.as_str(),
        }
    }

    pub fn rule_id(&self) -> &str {
        match self {
            RuleDiffItem::Unchanged { id, .. } => id,
            RuleDiffItem::Added { rule, .. } => &rule.id,
            RuleDiffItem::Removed { rule, .. } => &rule.id,
            RuleDiffItem::Modified { id, .. } => id,
        }
    }

    pub fn change_kind(&self) -> &'static str {
        match self {
            RuleDiffItem::Unchanged { .. } => "UNCHANGED",
            RuleDiffItem::Added { .. } => "ADDED",
            RuleDiffItem::Removed { .. } => "REMOVED",
            RuleDiffItem::Modified { .. } => "MODIFIED",
        }
    }

    pub fn impact(&self) -> SecurityImpact {
        match self {
            RuleDiffItem::Unchanged { .. } => SecurityImpact::Neutral,
            RuleDiffItem::Added { impact, .. } => *impact,
            RuleDiffItem::Removed { impact, .. } => *impact,
            RuleDiffItem::Modified { impact, .. } => *impact,
        }
    }

    pub fn details(&self) -> &[String] {
        match self {
            RuleDiffItem::Modified { details, .. } => details.as_slice(),
            _ => &[],
        }
    }
}

/// グローバル設定（ポリシーメタデータ）の個別差分
#[derive(Debug, Clone)]
pub struct GlobalDiffItem {
    pub key: String,            // 例: "system_type", "default_effect", "pre_approval_defaults.ttl_sec_default"
    pub old_value: String,      // 例: "Server", "Deny", "600s"
    pub new_value: String,      // 例: "Workstation", "Allow", "1200s"
    pub impact: SecurityImpact, // Relaxed / Hardened / Neutral
    pub description: String,    // 承認者向けの説明メッセージ
}

/// バンドル総合差分レポート
#[derive(Debug, Clone)]
pub struct BundleDiffReport {
    pub current_hash: String,
    pub new_hash: String,
    /// bundle.json, roles.json, management.json の構造化差分
    pub config_diff: Option<FullConfigDiff>,
    /// 従来のグローバル設定差分（エンジン全体の共通パラメータ等）
    pub global_diffs: Vec<GlobalDiffItem>,
    /// 個別ルールの差分リスト
    pub rule_diffs: Vec<RuleDiffItem>,
}

impl BundleDiffReport {
    pub fn render_terminal(&self) {
        println!("{}", "================ Policy Diff Summary ================".bold());
        println!("  • Current Hash : {}", self.current_hash.yellow());
        println!("  • Staged Hash  : {}", self.new_hash.green());
        println!();

        // -------------------------------------------------------------
        // 1. Bundle & Configuration Diffs (management, roles, bundle)
        // -------------------------------------------------------------
        if let Some(ref config) = self.config_diff {
            // (1) Management Policy (MPA / Governance) - 最重要
            if let Some(ref mgmt) = config.mgmt_diff {
                println!("{}", "─── Management Governance ──────────────────────────".bright_black());

                // A. 管理ロールの UID 変更
                for r in &mgmt.role_changes {
                    println!("  • Management Role '{}':", r.role_name.cyan().bold());
                    if !r.added_uids.is_empty() {
                        println!("      + Added UIDs: {}", format!("{:?}", r.added_uids).green());
                    }
                    if !r.removed_uids.is_empty() {
                        println!("      - Removed UIDs: {}", format!("{:?}", r.removed_uids).red());
                    }
                }

                // B. コマンド制御・MPA の変更
                for c in &mgmt.control_changes {
                    let impact_badge = match c.impact {
                        crate::cmd::diff::bundle_diff::SecurityImpact::Critical => "🚨 CRITICAL".red().bold(),
                        crate::cmd::diff::bundle_diff::SecurityImpact::Warning  => "⚠️  WARNING".yellow().bold(),
                        crate::cmd::diff::bundle_diff::SecurityImpact::Stricter => "🛡️  STRICTER".green().bold(),
                        crate::cmd::diff::bundle_diff::SecurityImpact::Neutral  => "⚪ NEUTRAL".white(),
                    };
                    println!("  [{}] Command '{}':", impact_badge, c.command.cyan().bold());
                    if let Some((old_t, new_t)) = c.threshold_change {
                        println!("      MPA Threshold: {} ➔ {}", old_t.to_string().yellow(), new_t.to_string().green());
                    }
                    if let Some((old_e, new_e)) = c.mpa_enabled_change {
                        println!("      MPA Enabled: {} ➔ {}", old_e.to_string().yellow(), new_e.to_string().green());
                    }
                    // 起案可能ロール (initiator)
                    if !c.added_initiator_roles.is_empty() {
                        println!("      Added Initiator Roles: {}", format!("{:?}", c.added_initiator_roles).green());
                    }
                    if !c.removed_initiator_roles.is_empty() {
                        println!("      Removed Initiator Roles: {}", format!("{:?}", c.removed_initiator_roles).red());
                    }
                    // 承認可能ロール (approver)
                    if !c.added_approver_roles.is_empty() {
                        println!("      Added Approver Roles: {}", format!("{:?}", c.added_approver_roles).green());
                    }
                    if !c.removed_approver_roles.is_empty() {
                        println!("      Removed Approver Roles: {}", format!("{:?}", c.removed_approver_roles).red());
                    }
                }
                println!();
            }

            // (2) Roles & Assignments
            if let Some(ref roles) = config.roles_diff {
                println!("{}", "─── Role Definitions & Assignments ──────────────────".bright_black());

                // ロール定義そのものの変更
                if !roles.added_roles.is_empty() {
                    println!("  + Added Roles    : {}", format!("{:?}", roles.added_roles).green().bold());
                }
                if !roles.removed_roles.is_empty() {
                    println!("  - Removed Roles  : {}", format!("{:?}", roles.removed_roles).red().bold());
                }

                // UID / GID へのロール付与・剥奪
                for a in &roles.assignment_changes {
                    println!("  • {}:", a.target.cyan().bold());
                    if !a.added.is_empty() {
                        println!("      + Granted Roles: {}", format!("{:?}", a.added).green());
                    }
                    if !a.removed.is_empty() {
                        println!("      - Revoked Roles: {}", format!("{:?}", a.removed).red());
                    }
                }

                // 未知ユーザー用デフォルトロールの変更
                if let Some((old_d, new_d)) = &roles.default_roles_changed {
                    println!("  • Unknown User Defaults: {:?} ➔ {:?}", old_d, new_d);
                }
                println!();
            }

            // (3) Bundle Files
            if let Some(ref bundle) = config.bundle_diff {
                println!("{}", "─── Bundle Composition ──────────────────────────────".bright_black());
                for f in &bundle.added_policies {
                    println!("  + Included Policy File: {}", f.green());
                }
                for f in &bundle.removed_policies {
                    println!("  - Removed Policy File : {}", f.red());
                }
                println!();
            }
        }

        // -------------------------------------------------------------
        // 2. Global Configurations Diff (ルール前提設定)
        // -------------------------------------------------------------
        if !self.global_diffs.is_empty() {
            println!("{}", "─── Global Configurations ───────────────────────────".bright_black());
            for g in &self.global_diffs {
                let tag = match g.impact {
                    SecurityImpact::Relaxed => "🔴 RELAXED".red().bold(),
                    SecurityImpact::Hardened => "🟢 HARDENED".green().bold(),
                    SecurityImpact::Neutral => "⚪ NEUTRAL".white(),
                };
                println!("  [{}] {}: {} ➔ {}", tag, g.key.cyan().bold(), g.old_value.yellow(), g.new_value.green());
                if !g.description.is_empty() {
                    println!("      {}", g.description.dimmed());
                }
            }
            println!();
        }

        // -------------------------------------------------------------
        // 3. Rule Diffs (個別ルール)
        // -------------------------------------------------------------
        println!("{}", "─── Rule Changes ────────────────────────────────────".bright_black());
        if self.rule_diffs.is_empty() {
            println!("  {}", "No rule changes.".dimmed());
        } else {
            for item in &self.rule_diffs {
                let tag = match item.impact() {
                    SecurityImpact::Relaxed => "🔴 RELAXED".red().bold(),
                    SecurityImpact::Hardened => "🟢 HARDENED".green().bold(),
                    SecurityImpact::Neutral => "⚪ NEUTRAL".white(),
                };
                println!("  [{}] {} ({})", tag, item.rule_id().cyan(), item.change_kind());
                for d in item.details() {
                    println!("      {}", d);
                }
            }
        }
        println!("{}", "=====================================================".bold());
    }
}

pub fn execute_diff(
    current_hash: &str,
    new_hash: &str,
    html_path: Option<&Path>,
) -> Result<()> {
    let curr_path = Path::new(DEFAULT_TEAL_DIR);
    let stage_path = Path::new(STAGE_TEAL_DIR);

    // 1. 各設定ファイル (bundle/roles/management) の意味的差分を抽出
    let config_diff = compare_full_config(curr_path, stage_path)
        .context("Failed to compare bundle configurations")?;

    // 2. policies/*.json 配下の個別ルール差分を抽出
    let current_bundle = load_bundle_from_dir(curr_path)
        .context("Failed to load current policy bundle")?;
    let stage_bundle = load_bundle_from_dir(stage_path)
        .context("Failed to load staged policy bundle")?;

    let mut diff_report = compare_policies(
        &current_bundle,
        &stage_bundle,
        current_hash,
        new_hash,
    )?;

    // 3. レポート構造体に config_diff を結合 (または個別に描画)
    diff_report.config_diff = Some(config_diff);

    // 4. 出力切り替え (HTML または ターミナル)
    if let Some(path) = html_path {
        generate_html_report(&diff_report, path)?;
        println!("  • Diff HTML Report written to: {}", path.display());
    } else {
        diff_report.render_terminal();
    }

    Ok(())
}
