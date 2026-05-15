// types.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
    NeedApproval,
    AuditOnly,
}
// "allow" | "deny" | "need_approval" | "audit_only" に対応

impl Effect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Effect::NeedApproval => "need_approval",
            Effect::Allow => "allow",
            Effect::AuditOnly => "audit_only",
            Effect::Deny => "deny",
        }
    }

    pub fn from(s: &str) -> Self {
        match s {
            "need_approval" => Effect::NeedApproval,
            "allow" => Effect::Allow,
            "audit_only" => Effect::AuditOnly,
            _ => Effect::Deny,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    Standard,
    Silent,
    Strict,
}

impl AuditLevel {
    pub fn to_u32(&self) -> u32 {
        match self {
            AuditLevel::Standard => 0,
            AuditLevel::Silent => 1,
            AuditLevel::Strict => 2,
        }
    }
}
