// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use anyhow::{Context, Result};
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::raw::{RawBundleV1, RawRolesV1};
use teal_policy_engine::management::{RawManagement, RawMgmtControl};

#[derive(Debug, Default, Clone)]
pub struct FullConfigDiff {
    pub bundle_diff: Option<BundleDiff>,
    pub roles_diff: Option<RolesDiff>,
    pub mgmt_diff: Option<ManagementDiff>,
}

/// bundle.json, roles.json, management.json の差分を一括抽出
pub fn compare_full_config(curr_dir: &Path, stage_dir: &Path) -> Result<FullConfigDiff> {
    // 1. bundle.json の比較
    let curr_bundle_val = load_json_file(curr_dir.join("bundle.json"))
        .context("Failed to load current bundle.json")?;
    let stage_bundle_val = load_json_file(stage_dir.join("bundle.json"))
        .context("Failed to load staged bundle.json")?;
    let curr_bundle: RawBundleV1 = serde_json::from_value(curr_bundle_val)?;
    let stage_bundle: RawBundleV1 = serde_json::from_value(stage_bundle_val)?;
    let bundle_diff = compare_bundle(&curr_bundle, &stage_bundle);

    // 2. roles.json の比較
    let curr_roles_val = load_json_file(curr_dir.join("roles.json"))
        .context("Failed to load current roles.json")?;
    let stage_roles_val = load_json_file(stage_dir.join("roles.json"))
        .context("Failed to load staged roles.json")?;
    let curr_roles: RawRolesV1 = serde_json::from_value(curr_roles_val)?;
    let stage_roles: RawRolesV1 = serde_json::from_value(stage_roles_val)?;
    let roles_diff = compare_roles(&curr_roles, &stage_roles);

    // 3. management.json の比較 (存在する場合のみ検証)
    let curr_mgmt_path = curr_dir.join("management.json");
    let stage_mgmt_path = stage_dir.join("management.json");
    let mgmt_diff = if curr_mgmt_path.exists() && stage_mgmt_path.exists() {
        let curr_mgmt_val = load_json_file(&curr_mgmt_path)
            .context("Failed to load current management.json")?;
        let stage_mgmt_val = load_json_file(&stage_mgmt_path)
            .context("Failed to load staged management.json")?;
        let curr_mgmt: RawManagement = serde_json::from_value(curr_mgmt_val)?;
        let stage_mgmt: RawManagement = serde_json::from_value(stage_mgmt_val)?;
        compare_management(&curr_mgmt, &stage_mgmt)
    } else {
        None
    };

    Ok(FullConfigDiff {
        bundle_diff,
        roles_diff,
        mgmt_diff,
    })
}

#[derive(Debug, Clone)]
pub struct BundleDiff {
    pub added_policies: Vec<String>,
    pub removed_policies: Vec<String>,
}

pub fn compare_bundle(curr: &RawBundleV1, stage: &RawBundleV1) -> Option<BundleDiff> {
    let curr_set: BTreeSet<_> = curr.policy_files.iter().collect();
    let stage_set: BTreeSet<_> = stage.policy_files.iter().collect();

    let added: Vec<String> = stage_set.difference(&curr_set).map(|s| (*s).clone()).collect();
    let removed: Vec<String> = curr_set.difference(&stage_set).map(|s| (*s).clone()).collect();

    if added.is_empty() && removed.is_empty() {
        None
    } else {
        Some(BundleDiff {
            added_policies: added,
            removed_policies: removed,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RolesDiff {
    pub added_roles: Vec<String>,
    pub removed_roles: Vec<String>,
    pub assignment_changes: Vec<AssignmentChange>,
    pub default_roles_changed: Option<(Vec<String>, Vec<String>)>, // (旧, 新)
}

#[derive(Debug, Clone)]
pub struct AssignmentChange {
    pub target: String, // "UID 1000" や "GID 10"
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

pub fn compare_roles(curr: &RawRolesV1, stage: &RawRolesV1) -> Option<RolesDiff> {
    let mut diff = RolesDiff::default();

    // 1. ロール自体の追加・削除
    let curr_roles: BTreeSet<_> = curr.roles.iter().map(|r| &r.name).collect();
    let stage_roles: BTreeSet<_> = stage.roles.iter().map(|r| &r.name).collect();
    diff.added_roles = stage_roles.difference(&curr_roles).map(|s| (*s).clone()).collect();
    diff.removed_roles = curr_roles.difference(&stage_roles).map(|s| (*s).clone()).collect();

    // 2. UID 割り当ての比較
    let to_map = |assignments: &[teal_policy_engine::raw::RawAssignment]| {
        let mut map: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
        for a in assignments {
            if let Some(uid) = a.uid {
                map.entry(uid).or_default().extend(a.roles.iter().cloned());
            }
        }
        map
    };

    let curr_map = to_map(&curr.assignments);
    let stage_map = to_map(&stage.assignments);

    let all_uids: BTreeSet<_> = curr_map.keys().chain(stage_map.keys()).copied().collect();
    for uid in all_uids {
        let empty = BTreeSet::new();
        let curr_assigned = curr_map.get(&uid).unwrap_or(&empty);
        let stage_assigned = stage_map.get(&uid).unwrap_or(&empty);

        let added: Vec<_> = stage_assigned.difference(curr_assigned).cloned().collect();
        let removed: Vec<_> = curr_assigned.difference(stage_assigned).cloned().collect();

        if !added.is_empty() || !removed.is_empty() {
            diff.assignment_changes.push(AssignmentChange {
                target: format!("UID {}", uid),
                added,
                removed,
            });
        }
    }

    // 3. デフォルトロールの変更検知
    if curr.defaults.roles_for_unknown_user != stage.defaults.roles_for_unknown_user {
        diff.default_roles_changed = Some((
            curr.defaults.roles_for_unknown_user.clone(),
            stage.defaults.roles_for_unknown_user.clone(),
        ));
    }

    let is_empty = diff.added_roles.is_empty()
        && diff.removed_roles.is_empty()
        && diff.assignment_changes.is_empty()
        && diff.default_roles_changed.is_none();

    if is_empty { None } else { Some(diff) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityImpact {
    Critical, // MPA無効化、閾値の低下など
    Warning,  // 承認ロール・起案ロールの変更
    Stricter, // MPA有効化、閾値の引き上げ
    Neutral,  // 変更なし
}

#[derive(Debug, Default, Clone)]
pub struct ManagementDiff {
    pub role_changes: Vec<MgmtRoleChange>,
    pub control_changes: Vec<ControlChange>,
}

#[derive(Debug, Clone)]
pub struct MgmtRoleChange {
    pub role_name: String,
    pub added_uids: Vec<u32>,
    pub removed_uids: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct ControlChange {
    pub command: String,
    pub mpa_enabled_change: Option<(bool, bool)>, // (旧, 新)
    pub threshold_change: Option<(u32, u32)>,     // (旧, 新)
    pub added_approver_roles: Vec<String>,
    pub removed_approver_roles: Vec<String>,
    pub added_initiator_roles: Vec<String>,
    pub removed_initiator_roles: Vec<String>,
    pub impact: SecurityImpact,
}

pub fn compare_management(curr: &RawManagement, stage: &RawManagement) -> Option<ManagementDiff> {
    let mut diff = ManagementDiff::default();

    // 1. 管理ロール (roles) の UID 割り当て差分
    let curr_roles: BTreeMap<_, _> = curr.roles.iter().map(|r| (&r.name, &r.uids)).collect();
    let stage_roles: BTreeMap<_, _> = stage.roles.iter().map(|r| (&r.name, &r.uids)).collect();

    for (role, stage_uids) in &stage_roles {
        let empty = Vec::new();
        let curr_uids = curr_roles.get(role).copied().unwrap_or(&empty);

        let curr_set: BTreeSet<_> = curr_uids.iter().copied().collect();
        let stage_set: BTreeSet<_> = stage_uids.iter().copied().collect();

        let added: Vec<_> = stage_set.difference(&curr_set).copied().collect();
        let removed: Vec<_> = curr_set.difference(&stage_set).copied().collect();

        if !added.is_empty() || !removed.is_empty() {
            diff.role_changes.push(MgmtRoleChange {
                role_name: (*role).clone(),
                added_uids: added,
                removed_uids: removed,
            });
        }
    }

    // 2. コマンド制御 (controls) の比較
    // 非Option型 (start, stop) と Option型 (policy_update, flush) を Option<&RawMgmtControl> に揃える
    let commands: [(&str, Option<&RawMgmtControl>, Option<&RawMgmtControl>); 4] = [
        ("start", Some(&curr.controls.start), Some(&stage.controls.start)),
        ("stop", Some(&curr.controls.stop), Some(&stage.controls.stop)),
        ("policy_update", curr.controls.policy_update.as_ref(), stage.controls.policy_update.as_ref()),
        ("flush", curr.controls.flush.as_ref(), stage.controls.flush.as_ref()),
    ];

    for (cmd_name, curr_ctrl, stage_ctrl) in commands {
        if let Some(change) = compare_single_control(cmd_name, curr_ctrl, stage_ctrl) {
            diff.control_changes.push(change);
        }
    }

    if diff.role_changes.is_empty() && diff.control_changes.is_empty() {
        None
    } else {
        Some(diff)
    }
}

fn compare_single_control(
    cmd: &str,
    curr: Option<&RawMgmtControl>,
    stage: Option<&RawMgmtControl>,
) -> Option<ControlChange> {
    match (curr, stage) {
        (Some(c), Some(s)) => {
            // 起案可能ロール (initiator_roles) の比較
            let curr_init: BTreeSet<_> = c.initiator_roles.iter().cloned().collect();
            let stage_init: BTreeSet<_> = s.initiator_roles.iter().cloned().collect();
            let added_init: Vec<_> = stage_init.difference(&curr_init).cloned().collect();
            let removed_init: Vec<_> = curr_init.difference(&stage_init).cloned().collect();

            // MPA有効化フラグ (mpa.enabled) の比較
            let enabled_change = if c.mpa.enabled != s.mpa.enabled {
                Some((c.mpa.enabled, s.mpa.enabled))
            } else {
                None
            };

            // 閾値 (mpa.threshold) の比較
            let old_t = c.mpa.threshold.unwrap_or(0);
            let new_t = s.mpa.threshold.unwrap_or(0);
            let threshold_change = if old_t != new_t {
                Some((old_t, new_t))
            } else {
                None
            };

            // 承認ロール (mpa.approver_roles) の比較
            let empty_roles = Vec::new();
            let curr_app: BTreeSet<_> = c.mpa.approver_roles.as_ref().unwrap_or(&empty_roles).iter().cloned().collect();
            let stage_app: BTreeSet<_> = s.mpa.approver_roles.as_ref().unwrap_or(&empty_roles).iter().cloned().collect();
            let added_app: Vec<_> = stage_app.difference(&curr_app).cloned().collect();
            let removed_app: Vec<_> = curr_app.difference(&stage_app).cloned().collect();

            // 差分が存在しない場合は None
            if enabled_change.is_none()
                && threshold_change.is_none()
                && added_init.is_empty()
                && removed_init.is_empty()
                && added_app.is_empty()
                && removed_app.is_empty()
            {
                return None;
            }

            // セキュリティ影響度の判定
            let impact = if let Some((true, false)) = enabled_change {
                SecurityImpact::Critical // MPAが無効化された
            } else if let Some((old_val, new_val)) = threshold_change {
                if new_val < old_val {
                    SecurityImpact::Critical // 閾値の緩和
                } else {
                    SecurityImpact::Stricter
                }
            } else if let Some((false, true)) = enabled_change {
                SecurityImpact::Stricter // MPAが有効化された
            } else if !removed_app.is_empty() || !added_init.is_empty() {
                SecurityImpact::Warning
            } else {
                SecurityImpact::Neutral
            };

            Some(ControlChange {
                command: cmd.to_string(),
                mpa_enabled_change: enabled_change,
                threshold_change,
                added_approver_roles: added_app,
                removed_approver_roles: removed_app,
                added_initiator_roles: added_init,
                removed_initiator_roles: removed_init,
                impact,
            })
        }
        (None, Some(s)) => Some(ControlChange {
            command: cmd.to_string(),
            mpa_enabled_change: Some((false, s.mpa.enabled)),
            threshold_change: s.mpa.threshold.map(|t| (0, t)),
            added_approver_roles: s.mpa.approver_roles.clone().unwrap_or_default(),
            removed_approver_roles: Vec::new(),
            added_initiator_roles: s.initiator_roles.clone(),
            removed_initiator_roles: Vec::new(),
            impact: SecurityImpact::Stricter,
        }),
        (Some(c), None) => Some(ControlChange {
            command: cmd.to_string(),
            mpa_enabled_change: Some((c.mpa.enabled, false)),
            threshold_change: c.mpa.threshold.map(|t| (t, 0)),
            added_approver_roles: Vec::new(),
            removed_approver_roles: c.mpa.approver_roles.clone().unwrap_or_default(),
            added_initiator_roles: Vec::new(),
            removed_initiator_roles: c.initiator_roles.clone(),
            impact: SecurityImpact::Critical,
        }),
        (None, None) => None,
    }
}