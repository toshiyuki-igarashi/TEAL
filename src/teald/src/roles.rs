use std::path::PathBuf;
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
pub fn load_roles(path: &str) -> Result<(CompiledRoles, CompileWarnings)> {
    // 1) file -> Value
    let v = load_json_file(path).with_context(|| format!("load roles json: {}", path))?;

    // 2) schema validate（構文）
    validate_against_schema(&v, roles_schema_value())
        .with_context(|| format!("roles schema validation failed: {}", path))?;

    // 3) Value -> Raw（構造体）
    let raw: RawRolesV1 = serde_json::from_value(v)
        .with_context(|| format!("deserialize roles raw struct failed: {}", path))?;

    // 4) compile（意味解釈 + 正規化）
    let (core, warnings) = compile_roles_v1(raw)
        .with_context(|| format!("compile roles failed: {}", path))?;

    let compiled = CompiledRoles {
        roles_file: PathBuf::from(path),
        deny_if_role_unknown: core.defaults.deny_if_role_unknown, // または raw.defaults から
        known_roles: core.roles.known_roles.clone(),              // または core が持っている
        core,
    };

    Ok((compiled, warnings))
}
