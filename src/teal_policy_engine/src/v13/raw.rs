// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use serde::{Serialize, Deserialize};

use crate::util::deserialize_ops_uppercase;
use crate::types::{Effect, AuditLevel, Action};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBundleV1 {
    pub schema_version: String, // must be "1.0"
    #[serde(default)]
    pub name: Option<String>,
    pub policy_files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawPolicyV13 {
    /// const "1.3"
    pub version: String,

    #[serde(default)]
    pub default_effect: Option<Effect>,

    #[serde(default)]
    pub default_reason: Option<String>,

    /// TTL (time to live) for pending approvals, in minutes.
    /// expires_at = created_at + ttl_minutes
    /// In ENFORCE mode, expiration results in DENY.
    pub ttl_minutes: u64,

    /// Expire sweep period, in minutes.
    /// Periodically sweeps pending approvals and expires them.
    pub sweep_minutes: u64,

    /// Defaults and hard limits for Pre-Approval / JIT_ALLOW TTL handling.
    /// Corresponds to schema object: pre_approval_defaults
    pub pre_approval_defaults: RawPreApprovalDefaults,

    pub rules: Vec<RawRule>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawPreApprovalDefaults {
    /// Default TTL (seconds) for JIT_ALLOW when rule.pre_approval.ttl_sec is not specified.
    /// Schema: minimum = 1
    pub ttl_sec_default: u64,

    /// Hard upper bound (seconds) for any JIT TTL.
    /// If a rule's chosen TTL exceeds this value, policy compilation MUST fail.
    /// Schema: minimum = 1
    #[serde(default)]
    pub ttl_sec_max: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,

    #[serde(default = "default_rule_type")]
    pub rule_type: String, 

    pub subject: RawSubject,

    pub object: Option<RawObject>, 

    pub action: RawAction,

    pub effect: Effect,

    #[serde(default = "default_audit_level")]
    pub audit_level: AuditLevel,

    #[serde(default)]
    pub ttl_sec: u64,

    #[serde(default = "default_max_uses")]
    pub max_uses: u32,

    #[serde(default)]
    pub required_roles: Option<Vec<String>>,

    #[serde(default)]
    pub threshold: Option<u32>,

    /// Pre-approval (JIT_ALLOW) configuration for this rule.
    #[serde(default)]
    pub pre_approval: Option<RawPreApproval>,

    #[serde(default)]
    pub reason: Option<String>,

    #[serde(default)]
    pub ticket_profile: RawTicketProfile,
}


fn default_rule_type() -> String {
    "standard".to_string()
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
    #[serde(default)]
    pub user: Option<String>,

    #[serde(default)]
    pub uid: Option<u32>,

    #[serde(default)]
    pub roles: Vec<String>,
    
    #[serde(default)]
    pub origin_program: Option<String>,
    
    #[serde(default)]
    pub origin_script: Option<String>,

    #[serde(default)]
    pub origin_applet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawObject {
    pub path: String,
    
    // RENAME 操作の移動先パス。RENAME 以外では None になる。
    #[serde(default)]
    pub new_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAction {
    #[serde(default, deserialize_with = "deserialize_ops_uppercase")]
    pub ops: Vec<Action>,
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

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

