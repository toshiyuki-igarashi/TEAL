// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::fs;
use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::roles::load_roles;
use crate::policy::load_policies_listed_in_bundle;

use teal_policy_engine::load::load_json_file;
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::raw::RawBundleV1;
use teal_policy_engine::ir::CompiledBundle;
use teal_policy_engine::util::ktime_prefix;

// --- ディレクトリ・ファイルパス定数の共通定義 ---
pub const DEFAULT_TEAL_DIR: &str = "/etc/teal.d";
pub const STAGE_TEAL_DIR: &str   = "/etc/teal.d/new";
pub const STAGE_LOCK_PATH: &str  = "/etc/teal.d/.stage.lock";
const BUNDLE_SCHEMA_JSON: &str = include_str!("../../schema/bundle_v1_0.schema.json");

static SCHEMA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();

fn bundle_schema_value() -> &'static Value {
    SCHEMA.get_or_init(|| {
        serde_json::from_str::<Value>(BUNDLE_SCHEMA_JSON)
            .expect("parse embedded bundle schema JSON")
    })
}

pub static BUNDLE: ArcSwapOption<CompiledBundle> = ArcSwapOption::const_empty();

/// バンドルの初期化およびアトミック更新
pub fn init_bundle(bundle: CompiledBundle) -> Result<()> {
    BUNDLE.store(Some(Arc::new(bundle)));
    Ok(())
}

/// 現在有効なポリシーバンドルを取得 (Wait-Free)
pub fn bundle() -> Arc<CompiledBundle> {
    BUNDLE
        .load_full()
        .expect("BUNDLE not initialized")
}

/// 指定したディレクトリ配下から bundle.json / roles / policies をロードして CompiledBundle を構築
pub fn load_bundle_from_dir<P: AsRef<Path>>(dir: P) -> Result<CompiledBundle> {
    let base = dir.as_ref();
    let bundle_path = base.join("bundle.json");
    let roles_path = base.join("roles.json");
    let policies_dir = base.join("policies");

    // 1) bundle.json -> Value
    let v = load_json_file(&bundle_path)
        .with_context(|| format!("load bundle json: {}", bundle_path.display()))?;

    // 2) schema validate
    validate_against_schema(&v, bundle_schema_value())
        .with_context(|| format!("bundle schema validation failed: {}", bundle_path.display()))?;

    // 3) Value -> RawBundleV1
    let raw_bundle: RawBundleV1 = serde_json::from_value(v)
        .with_context(|| format!("deserialize bundle raw struct failed: {}", bundle_path.display()))?;

    // 4) roles
    let (roles, mut warnings) = load_roles(&roles_path)
        .with_context(|| format!("load_roles failed: {}", roles_path.display()))?;

    // 5) policies (bundle順に compile & merge)
    let (policy, w2) = load_policies_listed_in_bundle(&raw_bundle, &roles, &policies_dir)
        .context("load policies from bundle")?;
    warnings.extend(w2);

    for w in &warnings.warnings {
        eprintln!("{}[WARN] {}", ktime_prefix(), w);
    }

    Ok(CompiledBundle {
        policy,
        roles: roles.core,
        warnings,
    })
}

/// デーモン起動時のデフォルトディレクトリ (/etc/teal.d) からロードして BUNDLE に格納
pub fn load_from_bundle() -> Result<()> {
    let compiled = load_bundle_from_dir(DEFAULT_TEAL_DIR)?;
    init_bundle(compiled)?;
    Ok(())
}

/// 指定ディレクトリ配下のポリシー定義ファイル群をソート順に連結して SHA-256 を計算
pub fn compute_directory_hash<P: AsRef<Path>>(dir: P) -> Result<String> {
    let mut files = Vec::new();
    collect_policy_files(dir.as_ref(), &mut files)?;

    // 決定性を担保するためファイルパスでソート
    files.sort();

    let mut hasher = Sha256::new();
    for path in files {
        let content = fs::read(&path)
            .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
        hasher.update(&content);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// ポリシーファイル (.json 等) の再帰/階層探索
pub fn collect_policy_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read dir: {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        
        // 隠しファイル（.stage.lock 等）を除外
        if path.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.starts_with('.')) {
            continue;
        }

        if path.is_file() {
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                files.push(path);
            }
        } else if path.is_dir() {
            collect_policy_files(&path, files)?;
        }
    }
    Ok(())
}

