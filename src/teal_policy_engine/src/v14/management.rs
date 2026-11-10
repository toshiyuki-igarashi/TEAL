// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::errors::{CompileError, CompileWarnings};
use crate::ir::CompiledRolesCore;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawManagement {
    pub controls: RawMgmtControls,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawMgmtControls {
    pub start: RawMgmtControl,
    pub stop: RawMgmtControl,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_update: Option<RawMgmtControl>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush: Option<RawMgmtControl>,

    /// 未配送通知管理。省略時は管理操作を許可しない (fail-closed)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<RawMgmtControl>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawMgmtControl {
    #[serde(default)]
    pub description: Option<String>,

    /// 起案可能ロール名一覧（スキーマ: initiator_roles）
    pub initiator_roles: Vec<String>,

    pub mpa: RawMgmtMpa,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawMgmtMpa {
    pub enabled: bool,

    /// enabled=true の場合に必須（compile時に検査）
    #[serde(default)]
    pub threshold: Option<u32>,

    /// enabled=true の場合に必須（compile時に検査）
    #[serde(default)]
    pub approver_roles: Option<Vec<String>>,

    /// enabled=true の場合に必須（compile時に検査）
    #[serde(default)]
    pub timeout_minutes: Option<u32>,
}

/// ===== Compiled =====
/// 目的:
/// - role名 -> UID集合 へ解決して高速化
/// - start/stop の設定を正規化（enabled=false でも扱いやすく）
/// - semantic validation を compile 時に集約

#[derive(Debug, Clone)]
pub struct CompiledManagement {
    pub controls: CompiledMgmtControls,
}

#[derive(Debug, Clone)]
pub struct CompiledMgmtControls {
    pub start: CompiledMgmtControl,
    pub stop: CompiledMgmtControl,
    pub policy_update: Option<CompiledMgmtControl>,
    pub flush: Option<CompiledMgmtControl>,
    /// None は notify 管理操作を許可しないことを表す。
    pub notify: Option<CompiledMgmtControl>,
}

#[derive(Debug, Clone)]
pub struct CompiledMgmtControl {
    pub description: Option<String>,

    /// 起案可能UID集合（initiator_roles を roles 展開した結果）
    pub initiator_uids: HashSet<u32>,

    pub mpa: CompiledMgmtMpa,
}

#[derive(Debug, Clone)]
pub enum CompiledMgmtMpa {
    Disabled,
    Enabled(CompiledMgmtMpaEnabled),
}

#[derive(Debug, Clone)]
pub struct CompiledMgmtMpaEnabled {
    /// 必要承認数
    pub threshold: u32,

    /// 承認に必要な管理ロール集合
    pub approver_roles: HashSet<String>,

    /// Pending の有効期限（分）
    pub timeout_minutes: u32,
}

/// START / STOP を指す管理アクション（teald 側のコマンドと1対1）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtAction {
    Start,
    Stop,
}

type RoleUidResolver<'a> = dyn FnMut(&str, &str) -> Result<HashSet<u32>, CompileError> + 'a;

// role参照の解決：management.roles を優先、無ければ CompiledRoles にフォールバック
fn lookup_uids_in_compiled_roles(roles: &CompiledRolesCore, role_name: &str) -> HashSet<u32> {
    let mut uids = HashSet::new();

    // uid -> roles(HashSet<String>) を全走査して逆引き
    for (uid, role_set) in roles.assignments.uid_roles.iter() {
        if role_set.contains(role_name) {
            uids.insert(*uid);
        }
    }

    uids
}

pub fn compile_management(
    raw: RawManagement,
    roles: &CompiledRolesCore,
) -> Result<(CompiledManagement, CompileWarnings), CompileError> {
    let mut warnings = CompileWarnings::default();

    // ---- helpers ----

    fn validate_role_name(name: &str) -> Result<(), String> {
        // ^[a-zA-Z][a-zA-Z0-9_:\-\.]{0,63}$
        if name.is_empty() {
            return Err("empty".into());
        }
        if name.len() > 64 {
            return Err(format!("too long (len={})", name.len()));
        }
        let bytes = name.as_bytes();
        if !bytes[0].is_ascii_alphabetic() {
            return Err("first char must be ASCII alphabetic".into());
        }
        for &b in bytes.iter() {
            let ok = (b as char).is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.');
            if !ok {
                return Err(format!("invalid char: 0x{:02x}", b));
            }
        }
        Ok(())
    }

    let mut resolve_role_uids =
        |role_name: &str, context: &str| -> Result<HashSet<u32>, CompileError> {
            // CompiledRoles から逆引き
            let uids = lookup_uids_in_compiled_roles(roles, role_name);
            if !uids.is_empty() {
                return Ok(uids);
            }

            // どこにも存在しない
            Err(CompileError::UnknownRoleReferenced {
                role: role_name.to_string(),
                context: context.to_string(),
            })
        };

    // ---- control(start/stop/policy_update/flush/notify) をコンパイル ----

    fn compile_control(
        which: &str,
        c: RawMgmtControl,
        warnings: &mut CompileWarnings,
        resolve_role_uids: &mut RoleUidResolver<'_>,
    ) -> Result<CompiledMgmtControl, CompileError> {
        let ctx_base = format!("management.controls.{}", which);

        // initiator_roles
        if c.initiator_roles.is_empty() {
            return Err(CompileError::InvalidField(
                "management.controls.*.initiator_roles",
                "initiator_roles must be non-empty".into(),
            ));
        }

        let mut initiator_uids = HashSet::<u32>::new();
        let mut seen_roles = HashSet::<String>::new();

        for role_name in c.initiator_roles.iter() {
            if let Err(reason) = validate_role_name(role_name) {
                return Err(CompileError::InvalidRoleName {
                    name: role_name.clone(),
                    reason: format!("invalid initiator_roles ref: {}", reason),
                });
            }
            if !seen_roles.insert(role_name.clone()) {
                warnings.warn(format!(
                    "{}.initiator_roles: duplicate role '{}' removed",
                    ctx_base, role_name
                ));
                continue;
            }
            initiator_uids.extend(resolve_role_uids(
                role_name,
                &format!("{}.initiator_roles", ctx_base),
            )?);
        }

        if initiator_uids.is_empty() {
            return Err(CompileError::InvalidValue(format!(
                "{}.initiator_roles resolved to empty uid set",
                ctx_base
            )));
        }

        // mpa
        let mpa = compile_mpa(which, &ctx_base, c.mpa, warnings, resolve_role_uids)?;

        Ok(CompiledMgmtControl {
            description: c.description,
            initiator_uids,
            mpa,
        })
    }

    fn compile_mpa(
        which: &str,
        ctx_base: &str,
        mpa: RawMgmtMpa,
        warnings: &mut CompileWarnings,
        resolve_role_uids: &mut RoleUidResolver<'_>,
    ) -> Result<CompiledMgmtMpa, CompileError> {
        let _ = which; // 将来 start/stop で追加制約を入れる場合に使う

        if !mpa.enabled {
            return Ok(CompiledMgmtMpa::Disabled);
        }

        // enabled=true のとき必須
        let threshold = mpa.threshold.ok_or(CompileError::MissingField(
            "management.controls.*.mpa.threshold",
        ))?;

        let approver_roles = mpa
            .approver_roles
            .as_ref()
            .ok_or(CompileError::MissingField(
                "management.controls.*.mpa.approver_roles",
            ))?;

        let timeout_minutes = mpa.timeout_minutes.ok_or(CompileError::MissingField(
            "management.controls.*.mpa.timeout_minutes",
        ))?;

        // 範囲チェック（スキーマに合わせる）
        if !(1..=32).contains(&threshold) {
            return Err(CompileError::InvalidValue(format!(
                "{}.mpa.threshold out of range (1..=32): {}",
                ctx_base, threshold
            )));
        }

        if !(1..=1440).contains(&timeout_minutes) {
            return Err(CompileError::InvalidValue(format!(
                "{}.mpa.timeout_minutes out of range (1..=1440): {}",
                ctx_base, timeout_minutes
            )));
        }

        if approver_roles.is_empty() {
            return Err(CompileError::InvalidField(
                "management.controls.*.mpa.approver_roles",
                "approver_roles must be non-empty when enabled=true".into(),
            ));
        }

        // approver_roles -> approver_uids
        let mut approver_uids = HashSet::<u32>::new();
        let mut seen = HashSet::<String>::new();

        for role_name in approver_roles.iter() {
            if let Err(reason) = validate_role_name(role_name) {
                return Err(CompileError::InvalidRoleName {
                    name: role_name.clone(),
                    reason: format!("invalid approver_roles ref: {}", reason),
                });
            }
            if !seen.insert(role_name.clone()) {
                warnings.warn(format!(
                    "{}.mpa.approver_roles: duplicate role '{}' removed",
                    ctx_base, role_name
                ));
                continue;
            }

            approver_uids.extend(resolve_role_uids(
                role_name,
                &format!("{}.mpa.approver_roles", ctx_base),
            )?);
        }

        if approver_uids.is_empty() {
            return Err(CompileError::InvalidValue(format!(
                "{}.mpa.approver_roles resolved to empty uid set",
                ctx_base
            )));
        }

        // セマンティクス：threshold が満たせない設定はエラー（運用事故防止）
        if threshold as usize > approver_uids.len() {
            return Err(CompileError::InvalidValue(format!(
                "{}.mpa.threshold={} is greater than distinct approver uids={}",
                ctx_base,
                threshold,
                approver_uids.len()
            )));
        }

        let approver_roles: HashSet<String> = mpa
            .approver_roles
            .as_ref()
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        Ok(CompiledMgmtMpa::Enabled(CompiledMgmtMpaEnabled {
            threshold,
            approver_roles,
            timeout_minutes,
        }))
    }

    // 1. 必須項目 (start / stop)
    let start = compile_control(
        "start",
        raw.controls.start,
        &mut warnings,
        &mut resolve_role_uids,
    )?;
    let stop = compile_control(
        "stop",
        raw.controls.stop,
        &mut warnings,
        &mut resolve_role_uids,
    )?;

    // 2. 任意項目 (policy_update)
    let policy_update = match raw.controls.policy_update {
        Some(c) => Some(compile_control(
            "policy_update",
            c,
            &mut warnings,
            &mut resolve_role_uids,
        )?),
        None => None,
    };

    // 3. 任意項目 (flush)
    let flush = match raw.controls.flush {
        Some(c) => Some(compile_control(
            "flush",
            c,
            &mut warnings,
            &mut resolve_role_uids,
        )?),
        None => None,
    };

    // 4. 任意項目 (notify)。従来の管理操作と同じロール解決・MPA 検証を適用。
    let notify = match raw.controls.notify {
        Some(c) => Some(compile_control(
            "notify",
            c,
            &mut warnings,
            &mut resolve_role_uids,
        )?),
        None => None,
    };

    let compiled = CompiledManagement {
        controls: CompiledMgmtControls {
            start,
            stop,
            policy_update,
            flush,
            notify,
        },
    };

    Ok((compiled, warnings))
}

#[cfg(test)]
mod notify_tests {
    use super::*;
    use crate::ir::{CompiledDefaults, GroupRoleIndex, RoleCatalog, SubjectRoleIndex};
    use serde_json::{json, Value};
    use std::collections::HashMap;

    fn roles() -> CompiledRolesCore {
        let mut assignments = SubjectRoleIndex::default();
        assignments
            .uid_roles
            .insert(1001, HashSet::from(["ops".into()]));
        assignments
            .uid_roles
            .insert(1002, HashSet::from(["security".into()]));
        CompiledRolesCore {
            roles: RoleCatalog {
                known_roles: HashSet::from(["ops".into(), "security".into()]),
                meta: HashMap::new(),
            },
            assignments,
            group_assignments: GroupRoleIndex::default(),
            defaults: CompiledDefaults {
                roles_for_unknown_user: HashSet::new(),
                deny_if_role_unknown: true,
            },
            allowed_ssh_networks: HashMap::new(),
        }
    }

    fn management_json(notify: Option<Value>) -> Value {
        let mut data = json!({
            "controls": {
                "start": {"initiator_roles": ["ops"], "mpa": {"enabled": false}},
                "stop":  {"initiator_roles": ["ops"], "mpa": {"enabled": false}}
            }
        });
        if let Some(notify) = notify {
            data["controls"]["notify"] = notify;
        }
        data
    }

    #[test]
    fn old_management_without_notify_remains_valid_and_denies_notify() {
        let raw: RawManagement = serde_json::from_value(management_json(None)).unwrap();
        assert!(raw.controls.notify.is_none());
        let encoded = serde_json::to_value(&raw).unwrap();
        assert!(encoded["controls"].get("notify").is_none());

        let (compiled, _) = compile_management(raw, &roles()).unwrap();
        assert!(compiled.controls.notify.is_none());
    }

    #[test]
    fn notify_resolves_its_own_initiator_roles_not_start_roles() {
        let raw: RawManagement = serde_json::from_value(management_json(Some(json!({
            "description": "Manage undelivered notifications",
            "initiator_roles": ["security"],
            "mpa": {"enabled": false}
        }))))
        .unwrap();
        let (compiled, _) = compile_management(raw, &roles()).unwrap();
        let notify = compiled.controls.notify.unwrap();
        assert_eq!(notify.initiator_uids, HashSet::from([1002]));
        assert!(!notify.initiator_uids.contains(&1001));
        assert!(matches!(notify.mpa, CompiledMgmtMpa::Disabled));
    }

    #[test]
    fn notify_mpa_enabled_compiles_with_existing_control_validation() {
        let raw: RawManagement = serde_json::from_value(management_json(Some(json!({
            "initiator_roles": ["ops"],
            "mpa": {
                "enabled": true,
                "threshold": 1,
                "approver_roles": ["security"],
                "timeout_minutes": 30
            }
        }))))
        .unwrap();
        let (compiled, _) = compile_management(raw, &roles()).unwrap();
        let notify = compiled.controls.notify.unwrap();
        match notify.mpa {
            CompiledMgmtMpa::Enabled(mpa) => {
                assert_eq!(mpa.threshold, 1);
                assert_eq!(mpa.timeout_minutes, 30);
                assert_eq!(mpa.approver_roles, HashSet::from(["security".into()]));
            }
            CompiledMgmtMpa::Disabled => panic!("notify MPA was unexpectedly disabled"),
        }
    }

    #[test]
    fn unknown_notify_initiator_role_fails_compilation() {
        let raw: RawManagement = serde_json::from_value(management_json(Some(json!({
            "initiator_roles": ["nonexistent_role"],
            "mpa": {"enabled": false}
        }))))
        .unwrap();
        assert!(matches!(
            compile_management(raw, &roles()),
            Err(CompileError::UnknownRoleReferenced { .. })
        ));
    }

    #[test]
    fn notify_mpa_threshold_exceeding_available_approvers_is_rejected() {
        let raw: RawManagement = serde_json::from_value(management_json(Some(json!({
            "initiator_roles": ["ops"],
            "mpa": {
                "enabled": true,
                "threshold": 2,
                "approver_roles": ["security"],
                "timeout_minutes": 30
            }
        }))))
        .unwrap();
        assert!(compile_management(raw, &roles()).is_err());
    }

    #[test]
    fn unknown_management_control_remains_rejected() {
        let mut value = management_json(None);
        value["controls"]["unexpected_action"] = json!({
            "initiator_roles": ["ops"],
            "mpa": {"enabled": false}
        });
        assert!(serde_json::from_value::<RawManagement>(value).is_err());
    }
}
