// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::errors::{CompileError, CompileWarnings};
use crate::ir::CompiledRolesCore;

///   pub management: Option<RawManagement>
///   pub management: Option<CompiledManagement>

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawManagement {
    pub roles: Vec<RawMgmtRole>,
    pub controls: RawMgmtControls,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawMgmtRole {
    pub name: String,
    pub uids: Vec<u32>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawMgmtControls {
    pub start: RawMgmtControl,
    pub stop: RawMgmtControl,
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
    /// role_name -> uids
    pub roles: HashMap<String, HashSet<u32>>,
    pub controls: CompiledMgmtControls,
}

#[derive(Debug, Clone)]
pub struct CompiledMgmtControls {
    pub start: CompiledMgmtControl,
    pub stop: CompiledMgmtControl,
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


fn role_to_uids_from_compiled_roles(
    roles: &CompiledRolesCore,
    role_name: &str,
) -> HashSet<u32> {
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
            let ok = (b as char).is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-' | b'.');
            if !ok {
                return Err(format!("invalid char: 0x{:02x}", b));
            }
        }
        Ok(())
    }

    // role参照の解決：management.roles を優先、無ければ CompiledRoles にフォールバック
    fn lookup_uids_in_compiled_roles(
        roles: &CompiledRolesCore,
        role_name: &str,
    ) -> HashSet<u32> {
        role_to_uids_from_compiled_roles(roles, role_name)
    }

    // ---- 1) management.roles を role_name -> uid set に ----
    let mut mgmt_roles: HashMap<String, HashSet<u32>> = HashMap::new();

    for r in raw.roles.into_iter() {
        if let Err(reason) = validate_role_name(&r.name) {
            return Err(CompileError::InvalidRoleName {
                name: r.name,
                reason,
            });
        }

        if r.uids.is_empty() {
            return Err(CompileError::InvalidField(
                "management.roles[].uids",
                "uids must be non-empty".into(),
            ));
        }

        if mgmt_roles.contains_key(&r.name) {
            return Err(CompileError::DuplicateRoleName(r.name));
        }

        let mut set = HashSet::<u32>::new();
        for uid in r.uids {
            if !set.insert(uid) {
                warnings.warn(format!(
                    "management.roles[name={}]: duplicate uid {} removed",
                    r.name, uid
                ));
            }
        }

        mgmt_roles.insert(r.name, set);
    }

    let mut resolve_role_uids =
        |role_name: &str, context: &str| -> Result<HashSet<u32>, CompileError> {
    
            // 1) management.roles を優先
            if let Some(s) = mgmt_roles.get(role_name) {
                return Ok(s.clone());
            }
    
            // 2) CompiledRoles から逆引き
            let uids = lookup_uids_in_compiled_roles(roles, role_name);
            if !uids.is_empty() {
                return Ok(uids);
            }
    
            // 3) どこにも存在しない
            Err(CompileError::UnknownRoleReferenced {
                role: role_name.to_string(),
                context: context.to_string(),
            })
        };


    // ---- 2) control(start/stop) をコンパイル ----

    fn compile_control(
        which: &str,
        c: RawMgmtControl,
        warnings: &mut CompileWarnings,
        resolve_role_uids: &mut dyn FnMut(&str, &str) -> Result<HashSet<u32>, CompileError>,
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
        resolve_role_uids: &mut dyn FnMut(&str, &str) -> Result<HashSet<u32>, CompileError>,
    ) -> Result<CompiledMgmtMpa, CompileError> {
        let _ = which; // 将来 start/stop で追加制約を入れる場合に使う

        if !mpa.enabled {
            return Ok(CompiledMgmtMpa::Disabled);
        }

        // enabled=true のとき必須
        let threshold = mpa.threshold.ok_or(CompileError::MissingField(
            "management.controls.*.mpa.threshold",
        ))?;

        let approver_roles = mpa.approver_roles
            .as_ref()
            .ok_or(CompileError::MissingField(
                "management.controls.*.mpa.approver_roles",
            ))?;

        let timeout_minutes = mpa.timeout_minutes.ok_or(CompileError::MissingField(
            "management.controls.*.mpa.timeout_minutes",
        ))?;

        // 範囲チェック（スキーマに合わせる）
        if threshold < 1 || threshold > 32 {
            return Err(CompileError::InvalidValue(format!(
                "{}.mpa.threshold out of range (1..=32): {}",
                ctx_base, threshold
            )));
        }

        if timeout_minutes < 1 || timeout_minutes > 1440 {
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
            .unwrap_or_else(HashSet::new);

        Ok(CompiledMgmtMpa::Enabled(CompiledMgmtMpaEnabled {
            threshold,
            approver_roles,
            timeout_minutes,
        }))
    }

    let start = compile_control("start", raw.controls.start, &mut warnings, &mut resolve_role_uids)?;
    let stop  = compile_control("stop",  raw.controls.stop,  &mut warnings, &mut resolve_role_uids)?;

    let compiled = CompiledManagement {
        roles: mgmt_roles,
        controls: CompiledMgmtControls { start, stop },
    };

    Ok((compiled, warnings))
}
