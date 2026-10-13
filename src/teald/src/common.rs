// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use serde::{Deserialize, Serialize};
use teal_policy_engine::ir::CompiledRule;

use crate::bundle::policy_snapshot;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TealStatus {
    pub status: String,
    pub is_enforce: bool,
    pub is_flushed: bool,
    pub current_epoch: u32,
    pub netlink: NetlinkStatus,
    pub queues: QueueStatus,
    pub is_storming: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetlinkStatus {
    pub buffer_usage_pct: f64,
    pub drops: u64,
    pub recv_rate_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatus {
    pub decision_channel_len: usize,
    pub audit_channel_len: usize,
    pub pending_requests_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Approve,
    Deny,
    Ticket,
    Start,
    Stop,
    PolicyUpdate,
}

impl DecisionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionKind::Approve => "APPROVE",
            DecisionKind::Deny => "DENY",
            DecisionKind::Ticket => "TICKET",
            DecisionKind::Start => "START",
            DecisionKind::Stop => "STOP",
            DecisionKind::PolicyUpdate => "POLICY_UPDATE",
        }
    }
}

pub fn is_mgmt_id(id: &str) -> bool {
    let id_upper = id.to_uppercase();
    matches!(id_upper.as_str(), "START" | "STOP" | "POLICY_UPDATE" | "FLUSH")
}

pub fn find_rule(
    id: Option<&str>,
) -> Result<(Option<CompiledRule>, u32), String> {
    let snapshot = policy_snapshot();

    match id {
        Some(id) => {
            for rule in &snapshot.bundle.policy.rules {
                if rule.id == id {
                    return Ok((Some(rule.clone()), snapshot.epoch));
                }
            }
            Err(format!("Rule id={} is not found", id))
        }
        None => Ok((None, snapshot.epoch)),
    }
}
