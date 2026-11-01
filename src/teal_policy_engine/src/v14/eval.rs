// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use crate::ir::{AccessContext, CompiledBundle, Decision};
use crate::matchers::rule_matches;

pub fn evaluate<'a>(bundle: &'a CompiledBundle, ctx: &AccessContext) -> Decision<'a> {
    if !bundle.policy.scope.is_request_managed(ctx) {
        return Decision::Pass;
    }

    let allowed_ssh_networks = &bundle.roles.allowed_ssh_networks;
    for r in &bundle.policy.rules {
        if rule_matches(r, allowed_ssh_networks, ctx, bundle.policy.system_type) {
            return Decision::Matched(r);
        }
    }

    Decision::NoMatchManaged
}
