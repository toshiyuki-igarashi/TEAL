// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::sync::{Arc, OnceLock};
use anyhow::{Context, Result};
use serde_json::Value;


use teal_policy_engine::util::ktime_prefix;
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::management::{RawManagement, CompiledManagement, compile_management};
use teal_policy_engine::ir::CompiledRolesCore;

pub const MANAGEMENT_PATH: &str = "/etc/teal.d/management.json";

const MANAGEMENT_SCHEMA_JSON: &str =
    include_str!("../../schema/management_v1_0.schema.json");

static SCHEMA: OnceLock<Value> = OnceLock::new();

fn management_schema_value() -> &'static Value {
    SCHEMA.get_or_init(|| {
        serde_json::from_str::<Value>(MANAGEMENT_SCHEMA_JSON)
            .expect("parse embedded management schema JSON")
    })
}

static MANAGEMENT: OnceLock<Arc<CompiledManagement>> = OnceLock::new();

pub fn init_management(management: CompiledManagement) -> Result<(), &'static str> {
    MANAGEMENT
        .set(Arc::new(management))
        .map_err(|_| "MANAGEMENT already initialized")
}

pub fn management() -> Arc<CompiledManagement> {
    MANAGEMENT.get().expect("MANAGEMENT not initialized").clone()
}

pub fn load_from_management(roles: &CompiledRolesCore) -> Result<()> {
    // 1) file -> Value
    let v = load_json_file(MANAGEMENT_PATH)
        .with_context(|| format!("load management json: {}", MANAGEMENT_PATH))?;

    // 2) schema validate（構文）
    validate_against_schema(&v, management_schema_value())
        .with_context(|| format!("management schema validation failed: {}", MANAGEMENT_PATH))?;

    // 3) Value -> Raw（構造体）
    let management: RawManagement = serde_json::from_value(v)
        .with_context(|| format!("deserialize management raw struct failed: {}", MANAGEMENT_PATH))?;

    // 4) compile（意味解釈 + 正規化）
    let (compiled, warnings) = compile_management(management, roles)
        .with_context(|| format!("compile management failed: {}", MANAGEMENT_PATH))?;

    for w in &warnings.warnings {
        eprintln!("{}[WARN] {}", ktime_prefix(), w);
    }

    init_management(compiled).map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}

