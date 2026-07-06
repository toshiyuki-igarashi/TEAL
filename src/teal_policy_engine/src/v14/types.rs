// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use serde::{Deserialize, Serialize};

use crate::errors::CompileError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Standard,
    SubjectOnly,
}

impl Default for RuleType {
    fn default() -> Self {
        RuleType::Standard
    }
}

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
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditLevel::Standard => "standard",
            AuditLevel::Silent => "silent",
            AuditLevel::Strict => "strict",
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            AuditLevel::Standard => 0,
            AuditLevel::Silent => 1,
            AuditLevel::Strict => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Read,
    Write,
    Execute,
    FileDelete,
    FileUnlink,
    FileRename,
    FileChmod,
    FileChown,
    NetConnect,

    #[serde(other)]
    #[default]
    Unknown,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "FILE_READ",
            Action::Write => "FILE_WRITE",
            Action::Execute => "FILE_EXECUTE",
            Action::FileDelete => "FILE_DELETE",
            Action::FileUnlink => "FILE_UNLINK",
            Action::FileRename => "FILE_RENAME",
            Action::FileChmod => "FILE_CHMOD",
            Action::FileChown => "FILE_CHOWN",
            Action::NetConnect => "NET_CONNECT",
            Action::Unknown => "UNKNOWN_ACTION",
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Action::Read => String::from("Read"),
            Action::Write => String::from("Write"),
            Action::Execute => String::from("Execute"),
            Action::FileDelete => String::from("Delete"),
            Action::FileUnlink => String::from("Unlink"),
            Action::FileRename => String::from("Rename"),
            Action::FileChmod => String::from("Chmod"),
            Action::FileChown => String::from("Chown"),
            Action::NetConnect => String::from("Connect"),
            Action::Unknown => String::from("Unknown"),
        }
    }

    pub fn parse(s: &str) -> Result<Self, CompileError> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "read"  => Ok(Action::Read),
            "write" => Ok(Action::Write),
            "execute"  => Ok(Action::Execute),
            "delete" => Ok(Action::FileDelete),
            "unlink" => Ok(Action::FileUnlink),
            "rename" => Ok(Action::FileRename),
            "chmod" => Ok(Action::FileChmod),
            "chown" => Ok(Action::FileChown),
            "connect" => Ok(Action::NetConnect),
            "unknown" => Ok(Action::Unknown),
            _ => Err(CompileError::UnknownAction(s.to_string())),
        }
    }

    pub fn to_mask(&self) -> u32 {
        match self {
            Action::Read => 1,
            Action::Write => 2,
            Action::Execute => 4,
            Action::FileDelete => 8,
            Action::FileUnlink => 16,
            Action::FileRename => 32,
            Action::FileChmod => 64,
            Action::FileChown => 128,
            Action::NetConnect => 256,
            Action::Unknown => 512,
        }
    }
}

