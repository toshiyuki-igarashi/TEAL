// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::path::PathBuf;

use crate::types::Request;

use teal_policy_engine::types::Action;
use teal_policy_engine::ir::{CompiledRolesCore, AccessContext, RegisteredSession};

fn origin_program_from_req(req: &Request) -> Option<PathBuf> {
    let s = req.raw_program.trim();
    if s.is_empty() {
        return None;
    }
    Some(PathBuf::from(s))
}

fn origin_script_from_req(req: &Request) -> Option<PathBuf> {
    let s = req.raw_script.as_ref()?.trim();
    if s.is_empty() {
        return None;
    }
    Some(PathBuf::from(s))
}

fn origin_applet_from_req(req: &Request) -> Option<String> {
    let s = req.raw_applet.as_ref()?.trim();
    if s.is_empty() || s == "-" {
        return None;
    }
    Some(s.to_string())
}

pub fn request_to_ctx(
    req: &Request, 
    roles: &CompiledRolesCore,
    registered_session: Option<RegisteredSession>
) -> AccessContext {
    let subject_roles = roles.assignments.uid_roles.get(&req.uid).cloned().unwrap_or_default();
    AccessContext {
        uid: req.uid,                   // ★ kernel truth
        subject_roles,

        // exec path (ELF or interpreter)
        origin_program: origin_program_from_req(req),

        // shebang script (if available)
        origin_script: origin_script_from_req(req),

        // 実行時の「呼び出し名」（argv[0] / task comm 相当）
        origin_applet: origin_applet_from_req(req),

        // subject_rolesをコピー

        action: Action::parse(&req.raw_action).unwrap_or(Action::Unknown),
        object_path: PathBuf::from(&req.raw_target),
        object_new_path: req.raw_new_target.as_ref().map(PathBuf::from),
        object_kind: None,

        session_tty: req.session_tty.clone(),
        registered_session,
    }
}

