// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use teal_policy_engine::ir::CompiledRolesCore;
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::management::{compile_management, CompiledManagement, RawManagement};
use teal_policy_engine::schema::validate_against_schema;
use teal_policy_engine::util::ktime_prefix;

pub const MANAGEMENT_PATH: &str = "/etc/teal.d/management.json";

const MANAGEMENT_SCHEMA_JSON: &str = include_str!("../../schema/management_v1_0.schema.json");

static SCHEMA: OnceLock<Value> = OnceLock::new();

fn management_schema_value() -> &'static Value {
    SCHEMA.get_or_init(|| {
        serde_json::from_str::<Value>(MANAGEMENT_SCHEMA_JSON)
            .expect("parse embedded management schema JSON")
    })
}

// Management is read via an atomic snapshot, and updated only after the
// corresponding policy bundle has been committed.
static MANAGEMENT: ArcSwapOption<CompiledManagement> = ArcSwapOption::const_empty();

pub fn init_management(management: CompiledManagement) -> Result<(), &'static str> {
    let value = Arc::new(management);
    let previous = MANAGEMENT.compare_and_swap(&None::<Arc<CompiledManagement>>, Some(value));
    if previous.is_some() {
        return Err("MANAGEMENT already initialized");
    }
    Ok(())
}

pub fn management() -> Arc<CompiledManagement> {
    MANAGEMENT.load_full().expect("MANAGEMENT not initialized")
}

/// Validate and compile a candidate configuration without publishing it.
/// The caller must provide the Roles compiled from the SAME staged bundle.
pub fn prepare_management<P: AsRef<Path>>(
    path: P,
    roles: &CompiledRolesCore,
) -> Result<CompiledManagement> {
    let path = path.as_ref();
    let v = load_json_file(path)
        .with_context(|| format!("load management json: {}", path.display()))?;
    validate_against_schema(&v, management_schema_value())
        .with_context(|| format!("management schema validation failed: {}", path.display()))?;
    let raw: RawManagement = serde_json::from_value(v).with_context(|| {
        format!(
            "deserialize management raw struct failed: {}",
            path.display()
        )
    })?;
    let (compiled, warnings) = compile_management(raw, roles)
        .with_context(|| format!("compile management failed: {}", path.display()))?;
    for w in &warnings.warnings {
        eprintln!("{}[WARN] {}", ktime_prefix(), w);
    }
    Ok(compiled)
}

/// Publish an already compiled configuration. Call under MGMT_EXEC_LOCK,
/// after the corresponding bundle has been committed.
pub fn commit_management(compiled: CompiledManagement) {
    MANAGEMENT.store(Some(Arc::new(compiled)));
}

/// Initial loading (once). For policy updates use prepare + commit instead.
pub fn load_from_management(roles: &CompiledRolesCore) -> Result<()> {
    let compiled = prepare_management(MANAGEMENT_PATH, roles)?;
    init_management(compiled).map_err(|e| anyhow::anyhow!(e))
}
