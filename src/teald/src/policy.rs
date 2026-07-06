// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use anyhow::{Context, Result, anyhow};
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;
use serde_json::Value;

use crate::bundle::POLICIES_DIR;

use teal_policy_engine::errors::CompileWarnings;
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::raw::{RawPolicyV14, RawBundleV1};
use teal_policy_engine::compile::compile_policy_v13;
use teal_policy_engine::ir::{CompiledRoles, CompiledPolicy};

const POLICY_SCHEMA_JSON: &str =
    include_str!("../../schema/policy_v1_4.schema.json");

static SCHEMA: OnceLock<Value> = OnceLock::new();

fn policy_schema_value() -> &'static Value {
    SCHEMA.get_or_init(|| {
        serde_json::from_str::<Value>(POLICY_SCHEMA_JSON)
            .expect("parse embedded policy schema JSON")
    })
}

pub fn load_policy(
    path: &str,
    roles: &CompiledRoles,
) -> Result<(CompiledPolicy, CompileWarnings)> {
    // 1) file -> Value
    let mut v = load_json_file(path)
        .with_context(|| format!("load policy json: {}", path))?;

    // スキーマ検証の前に、Value内の ops 配列にある文字列をすべて大文字に変換
    uppercase_ops_in_value(&mut v);

    // 2) schema validate（構文検証）
    validate_against_schema(&v, policy_schema_value())
        .with_context(|| format!("policy schema validation failed: {}", path))?;

    // 3) Value -> Raw（構造体化）
    let raw: RawPolicyV14 = serde_json::from_value(v)
        .with_context(|| format!("deserialize policy raw struct failed: {}", path))?;

    // 4) compile（意味解釈 + 正規化）
    let (compiled, warnings) = compile_policy_v13(raw, roles)
        .with_context(|| format!("compile policy failed: {}", path))?;

    Ok((compiled, warnings))
}

/// JSON Value内を再帰的に探索し、"ops" キー配下にある文字列をすべて大文字に変換するヘルパー
fn uppercase_ops_in_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if key == "ops" {
                    // ops が配列（Vec）であれば、その中の文字列要素を大文字に変換
                    if let serde_json::Value::Array(arr) = val {
                        for item in arr.iter_mut() {
                            if let serde_json::Value::String(s) = item {
                                *s = s.to_uppercase();
                            }
                        }
                    }
                } else {
                    // それ以外のキーならさらに深く探索（再帰呼び出し）
                    uppercase_ops_in_value(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                uppercase_ops_in_value(item);
            }
        }
        _ => {}
    }
}

fn merge_compiled_policies(
    mut base: CompiledPolicy,
    next: CompiledPolicy,
    warnings: &mut CompileWarnings,
) -> Result<CompiledPolicy> {
    // 1) version は一致必須
    if base.version != next.version {
        return Err(anyhow!(
            "policy version mismatch: base={:?} next={:?}",
            base.version, next.version
        ));
    }

    // 2) defaults は base を採用し、next が違うなら運用事故なので警告（厳格運用なら Err にしても良い）
    if base.default_action != next.default_action {
        warnings.warn(format!(
            "default_action differs across policy files: base='{}' next='{}' (keeping base)",
            base.default_action, next.default_action
        ));
    }
    if base.default_reason != next.default_reason {
        warnings.warn(format!(
            "default_reason differs across policy files: base='{}' next='{}' (keeping base)",
            base.default_reason, next.default_reason
        ));
    }

    // 3) scope は union（ManagedScopeIndex に union API がある想定）
    base.scope = base.scope.union(&next.scope);

    // 4) rules は結合。ただし rule id 重複はエラー
    let mut seen: HashSet<String> = base.rules.iter().map(|r| r.id.clone()).collect();
    for r in next.rules {
        if !seen.insert(r.id.clone()) {
            return Err(anyhow!("duplicate rule id while merging: {}", r.id));
        }
        base.rules.push(r);
    }

    Ok(base)
}

pub fn load_policies_listed_in_bundle(
    bundle: &RawBundleV1,
    roles: &CompiledRoles,
) -> Result<(CompiledPolicy, CompileWarnings)> {
    let mut warnings = CompileWarnings::default();

    let mut merged: Option<CompiledPolicy> = None;

    for name in &bundle.policy_files {
        // basename-only: "/" を含んだら拒否（相対パス禁止と同等以上に強い）
        if name.contains('/') || name == "." || name == ".." || name.is_empty() {
            anyhow::bail!("invalid policy name in bundle: {}", name);
        }

        let path = Path::new(POLICIES_DIR).join(name);
        let path_s = path.to_string_lossy().to_string();

        let (cp, w) = load_policy(&path_s, roles)
            .with_context(|| format!("load_policy failed: {}", path_s))?;
        warnings.extend(w);

        merged = Some(match merged {
            None => cp,
            Some(acc) => merge_compiled_policies(acc, cp, &mut warnings)
                .with_context(|| format!("merge policies failed at: {}", path_s))?,
        });
    }

    let policy = merged.ok_or_else(|| anyhow::anyhow!("bundle.policies is empty"))?;

    // 必要なら最終整合チェック（compile中に unknown-role を落としてるなら省略可）
    // check_roles_consistency(&policy, roles);

    Ok((policy, warnings))
}
