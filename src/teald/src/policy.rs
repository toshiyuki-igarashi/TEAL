// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::OnceLock;
use serde_json::Value;

use teal_policy_engine::errors::CompileWarnings;
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::raw::{RawPolicyV14, RawBundleV1};
use teal_policy_engine::compile::compile_policy_v14;
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

pub fn load_policy<P: AsRef<Path>>(
    path: P,
    roles: &CompiledRoles,
) -> Result<(CompiledPolicy, CompileWarnings)> {
    let p = path.as_ref();

    // 1) file -> Value (後で書き換えるため mut が必須)
    let mut v = load_json_file(p)
        .with_context(|| format!("load policy json: {}", p.display()))?;

    // スキーマ検証の前に、Value内の ops 配列にある文字列をすべて大文字に変換
    uppercase_ops_in_value(&mut v);

    // 2) schema validate（構文検証）
    validate_against_schema(&v, policy_schema_value())
        .with_context(|| format!("policy schema validation failed: {}", p.display()))?;

    // 3) Value -> Raw（構造体化）
    let raw: RawPolicyV14 = serde_json::from_value(v)
        .with_context(|| format!("deserialize policy raw struct failed: {}", p.display()))?;

    // 4) compile（意味解釈 + 正規化）
    let (compiled, warnings) = compile_policy_v14(raw, roles)
        .with_context(|| format!("compile policy failed: {}", p.display()))?;

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


pub fn load_policies_listed_in_bundle(
    bundle: &RawBundleV1,
    roles: &CompiledRoles,
    policies_dir: &Path,
) -> Result<(CompiledPolicy, CompileWarnings)> {
    let mut warnings = CompileWarnings::default();
    let mut merged: Option<CompiledPolicy> = None;

    for name in &bundle.policy_files {
        if name.contains('/') || name == "." || name == ".." || name.is_empty() {
            anyhow::bail!("invalid policy name in bundle: {}", name);
        }

        let path = policies_dir.join(name);
        let path_s = path.to_string_lossy().to_string();

        let (cp, w) = load_policy(&path_s, roles)
            .with_context(|| format!("load_policy failed: {}", path_s))?;
        warnings.extend(w);

        merged = Some(match merged {
            None => cp,
            Some(mut acc) => {
                acc.merge(cp, &mut warnings)
                    .with_context(|| format!("merge policies failed at: {}", path_s))?;
                acc
            }
        });
    }

    let policy = merged.ok_or_else(|| anyhow::anyhow!("bundle.policies is empty"))?;
    Ok((policy, warnings))
}
