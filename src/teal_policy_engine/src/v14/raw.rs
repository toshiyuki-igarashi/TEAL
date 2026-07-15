// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use serde::{Deserialize, Serialize};

use crate::util::deserialize_ops_uppercase;
use crate::types::{SystemType, RuleType, Effect, AuditLevel, Action};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBundleV1 {
    pub schema_version: String, // must be "1.0"
    #[serde(default)]
    pub name: Option<String>,
    pub policy_files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicyV14 {
    /// const "1.4"
    pub version: String,

    // デフォルトで Server が適用されるよう設定
    #[serde(default)]
    pub system_type: SystemType,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_effect: Option<Effect>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_reason: Option<String>,

    pub ttl_minutes: u64,
    pub sweep_minutes: u64,
    pub pre_approval_defaults: RawPreApprovalDefaults,
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPreApprovalDefaults {
    pub ttl_sec_default: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_sec_max: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default)]
    pub rule_type: RuleType,

    pub subject: RawSubject,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_constraints: Vec<RawTimeConstraint>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<RawObject>,
    pub action: RawAction,
    pub effect: Effect,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mpa: Option<RawMpa>,

    #[serde(default = "default_audit_level")]
    pub audit_level: AuditLevel,

    #[serde(default = "default_max_uses")]
    pub max_uses: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_approval: Option<RawPreApproval>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    #[serde(default)]
    pub ticket_profile: RawTicketProfile,
}

/// Serde 用のデフォルト値返却関数
fn default_audit_level() -> AuditLevel {
    AuditLevel::Standard
}

fn default_max_uses() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSubject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_program: Option<String>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_script: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_applet: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_context: Option<RawLoginContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RawLoginContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_interactive_tty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_registered_session: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTimeConstraint {
    pub days: Vec<String>,
    pub window: RawTimeWindow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTimeWindow {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawObject {
    pub path: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAction {
    #[serde(default, deserialize_with = "deserialize_ops_uppercase", skip_serializing_if = "Vec::is_empty")]
    pub ops: Vec<Action>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMpa {
    pub threshold: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approver_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPreApproval {
    /// Whether pre-approval (JIT_ALLOW) is enabled for this rule.
    pub enabled: bool,

    /// Per-rule TTL override in seconds for JIT_ALLOW.
    /// If None, the policy-level default (or engine default) is used.
    #[serde(default)]
    pub ttl_sec: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RawTicketProfile {
    #[serde(default)] pub silent_io: bool,
    #[serde(default)] pub inherit: bool,
    #[serde(default)] pub allow_nameless_ipc: bool,
}

pub const TEAL_TICKET_FLG_SILENT_IO: u32 = 0x01;
pub const TEAL_TICKET_FLG_INHERIT:   u32 = 0x02;
pub const TEAL_TICKET_FLG_NAMELESS_IPC:   u32 = 0x04;

impl RawTicketProfile {
    pub fn to_u32(&self) -> u32 {
        let mut flags = 0u32;
        if self.silent_io { flags |= TEAL_TICKET_FLG_SILENT_IO; }
        if self.inherit   { flags |= TEAL_TICKET_FLG_INHERIT;   }
        if self.allow_nameless_ipc   { flags |= TEAL_TICKET_FLG_NAMELESS_IPC;   }
        flags
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRolesV1 {
    pub schema_version: String, // must be "1.0" (validate phase)

    pub roles: Vec<RawRoleDef>,

    #[serde(default)]
    pub assignments: Vec<RawAssignment>,

    #[serde(default)]
    pub group_assignments: Vec<RawGroupAssignment>,

    pub defaults: RawDefaults,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRoleDef {
    pub name: String,                // roleName (pattern は validate)
    #[serde(default)]
    pub description: Option<String>,

    /// tags are informational labels for classification / audit / UI.
    /// They MUST NOT affect policy evaluation semantics.
    #[serde(default)]
    pub tags: Vec<String>,

    /// permissions declare abstract capabilities of the role.
    /// They are NOT used in policy evaluation in v1.x.
    /// Intended for future capability / lint / audit use.
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAssignment {
    #[serde(default)]
    pub uid: Option<u32>,

    #[serde(default)]
    pub user: Option<String>,

    pub roles: Vec<String>, // roleList (minItems=1 は validate)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGroupAssignment {
    #[serde(default)]
    pub gid: Option<u32>,

    #[serde(default)]
    pub group: Option<String>,

    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    /// Roles assigned to subjects that have no explicit assignment.
    /// These roles are applied as a set (AND), not OR.
    #[serde(default)]
    pub roles_for_unknown_user: Vec<String>,

    pub deny_if_role_unknown: bool,
}

