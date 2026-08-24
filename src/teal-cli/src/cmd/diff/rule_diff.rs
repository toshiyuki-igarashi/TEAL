// SPDX-License-Identifier: MIT
/*
 * TEAL Policy Engine (teal_policy_engine)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use teal_policy_engine::ir::CompiledBundle;
use super::{PolicyDiffReport, RuleDiffItem, SecurityImpact};
use anyhow::Result;

/// 2つの CompiledBundle を比較して PolicyDiffReport を構築
pub fn compare_policies(
    current: &CompiledBundle,
    stage: &CompiledBundle,
    current_hash: &str,
    new_hash: &str,
) -> Result<PolicyDiffReport> {
    let mut items = Vec::new();

    // 1. rule_id をキーにして Added / Removed / Modified / Unchanged を分類
    // 2. Modified の各フィールドを精査し、SecurityImpact を判定
    
    Ok(PolicyDiffReport {
        current_hash: current_hash.to_string(),
        new_hash: new_hash.to_string(),
        items,
    })
}
