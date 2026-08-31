// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
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

