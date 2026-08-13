// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::sync::{Arc, OnceLock};
use anyhow::{Context, Result};
use serde_json::Value;
use arc_swap::ArcSwapOption;

use crate::roles::load_roles;
use crate::policy::load_policies_listed_in_bundle;

use teal_policy_engine::load::load_json_file;
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::raw::RawBundleV1;
use teal_policy_engine::ir::CompiledBundle;
use teal_policy_engine::util::ktime_prefix;

pub const BUNDLE_PATH: &str = "/etc/teal.d/bundle.json";
pub const ROLES_PATH: &str = "/etc/teal.d/roles/roles.json";
pub const POLICIES_DIR: &str = "/etc/teal.d/policies";

const BUNDLE_SCHEMA_JSON: &str =
    include_str!("../../schema/bundle_v1_0.schema.json");

static SCHEMA: OnceLock<Value> = OnceLock::new();

fn bundle_schema_value() -> &'static Value {
    SCHEMA.get_or_init(|| {
        serde_json::from_str::<Value>(BUNDLE_SCHEMA_JSON)
            .expect("parse embedded bundle schema JSON")
    })
}

// teald 側（バイナリクレート）例

pub static BUNDLE: ArcSwapOption<CompiledBundle> = ArcSwapOption::const_empty();

/// バンドルの初期化および更新（POLICY_UPDATE等から何度でも安全に呼び出し可能）
pub fn init_bundle(bundle: CompiledBundle) -> Result<()> {
    BUNDLE.store(Some(Arc::new(bundle)));
    Ok(())
}

/// 現在有効なポリシーバンドルを取得 (Wait-Freeで参照を取得)
pub fn bundle() -> Arc<CompiledBundle> {
    BUNDLE
        .load_full()
        .expect("BUNDLE not initialized")
}

pub fn load_from_bundle() -> Result<()> {
    // 1) file -> Value
    let v = load_json_file(BUNDLE_PATH)
        .with_context(|| format!("load bundle json: {}", BUNDLE_PATH))?;

    // 2) schema validate（構文）
    validate_against_schema(&v, bundle_schema_value())
        .with_context(|| format!("bundle schema validation failed: {}", BUNDLE_PATH))?;

    // 3) Value -> Raw（構造体）
    let bundle: RawBundleV1 = serde_json::from_value(v)
        .with_context(|| format!("deserialize bundle raw struct failed: {}", BUNDLE_PATH))?;

    // 4) roles（固定）
    let (roles, mut warnings) = load_roles(ROLES_PATH)
        .with_context(|| format!("load_roles failed: {}", ROLES_PATH))?;

    // 5) policies（bundle順に compile & merge）
    let (policy, w2) = load_policies_listed_in_bundle(&bundle, &roles)
        .context("load policies from bundle")?;
    warnings.extend(w2);

    for w in &warnings.warnings {
        eprintln!("{}[WARN] {}", ktime_prefix(), w);
    }

    let compiled = CompiledBundle {
        policy,
        roles: roles.core,
        warnings,
    };

    // 起動時・リロード時ともに、アトミックに差し替え実行
    init_bundle(compiled)?;

    Ok(())
}

