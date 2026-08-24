// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde_json::Value;

use teal_policy_engine::errors::CompileWarnings;
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::raw::RawRolesV1;
use teal_policy_engine::compile::compile_roles_v1;
use teal_policy_engine::ir::CompiledRoles;

const ROLES_SCHEMA_JSON: &str =
    include_str!("../../schema/roles_v1_0.schema.json");

static SCHEMA: OnceLock<Value> = OnceLock::new();

fn roles_schema_value() -> &'static Value {
    SCHEMA.get_or_init(|| {
        serde_json::from_str::<Value>(ROLES_SCHEMA_JSON)
            .expect("embedded ROLES_SCHEMA_JSON must be valid JSON")
    })
}

/// roles.json を読み込み、schema validate → RawRolesV1 deserialize → compile を行い
/// (CompiledRoles, CompileWarnings) を返す。
pub fn load_roles<P: AsRef<Path>>(path: P) -> Result<(CompiledRoles, CompileWarnings)> {
    let p = path.as_ref();
    
    // 1) file -> Value
    let v = load_json_file(p)
        .with_context(|| format!("load roles json: {}", p.display()))?;

    // 2) schema validate
    validate_against_schema(&v, roles_schema_value())
        .with_context(|| format!("roles schema validation failed: {}", p.display()))?;

    // 3) Value -> RawRolesV1
    let raw: RawRolesV1 = serde_json::from_value(v)
        .with_context(|| format!("deserialize roles raw struct failed: {}", p.display()))?;

    // 4) compile
    let (core, warnings) = compile_roles_v1(raw)
        .with_context(|| format!("compile roles failed: {}", p.display()))?;

    let compiled = CompiledRoles {
        roles_file: p.to_path_buf(),
        deny_if_role_unknown: true,
        known_roles: core.roles.known_roles.clone(), // ★ core.roles.known_roles を参照
        core,
    };

    Ok((compiled, warnings))
}
