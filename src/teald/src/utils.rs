// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use teal_policy_engine::ir::Action;

pub fn u32_to_str(op: u32) -> String {
    let mut s = Vec::new();
    if Action::Read.to_mask() & op != 0 { s.push("READ"); };
    if Action::Write.to_mask() & op != 0 { s.push("WRITE"); };
    if Action::Execute.to_mask() & op != 0 { s.push("EXECUTE"); };
    if Action::Delete.to_mask() & op != 0 { s.push("DELETE"); };
    if Action::Unlink.to_mask() & op != 0 { s.push("UNLINK"); };
    if Action::Rename.to_mask() & op != 0 { s.push("RENAME"); };
    if Action::Chmod.to_mask() & op != 0 { s.push("CHMOD"); };
    if Action::Chown.to_mask() & op != 0 { s.push("CHOWN"); };
    if Action::Connect.to_mask() & op != 0 { s.push("CONNECT"); };
    if Action::Unknown.to_mask() & op != 0 { s.push("UNKNOWN"); };

    s.join(",")
}
