// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use crate::matchers::rule_matches;
use crate::ir::{CompiledPolicy, AccessContext, Decision};

pub fn evaluate<'a>(policy: &'a CompiledPolicy, ctx: &AccessContext) -> Decision<'a> {
    if !policy.scope.is_request_managed(ctx) {
        return Decision::Pass;
    }

    for r in &policy.rules {
        if rule_matches(r, ctx) {
            return Decision::Matched(r);
        }
    }

    Decision::NoMatchManaged
}

