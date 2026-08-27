// SPDX-License-Identifier: MIT
/*
 * TEAL Policy Engine (teal_policy_engine)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::collections::HashMap;
use std::collections::HashSet;
use anyhow::Result;

use teal_policy_engine::ir::{CompiledBundle, CompiledPolicy, CompiledRule, ActionMatcher};
use teal_policy_engine::types::{Action, AuditLevel, Effect, SystemType};
use super::{PolicyDiffReport, RuleDiffItem, GlobalDiffItem, SecurityImpact};

/// 2つの CompiledBundle を比較して PolicyDiffReport を構築
pub fn compare_policies(
    current: &CompiledBundle,
    stage: &CompiledBundle,
    current_hash: &str,
    new_hash: &str,
) -> Result<PolicyDiffReport> {
    // 1. グローバル設定 / メタデータの差分抽出
    let global_diffs = compare_global_configs(&current.policy, &stage.policy);

    // 2. ルール群の差分抽出 (Added / Removed / Modified / Unchanged)
    let rule_diffs = diff_rules(&current.policy.rules, &stage.policy.rules);

    // 3. (必要に応じて) ロール定義・割り当ての差分抽出
    // let role_diffs = diff_roles(&current.roles, &stage.roles);

    Ok(PolicyDiffReport {
        current_hash: current_hash.to_string(),
        new_hash: new_hash.to_string(),
        global_diffs,
        rule_diffs,
    })
}

/// グローバル設定差分の分類と構築
pub fn compare_global_configs(
    current: &CompiledPolicy,
    stage: &CompiledPolicy,
) -> Vec<GlobalDiffItem> {
    let mut diffs = Vec::new();

    // 1. system_type
    if current.system_type != stage.system_type {
        let impact = match (current.system_type, stage.system_type) {
            (SystemType::Server, SystemType::Workstation) => SecurityImpact::Relaxed, // 物理端末/SSH限定からGUI許可へ緩和
            (SystemType::Workstation, SystemType::Server) => SecurityImpact::Hardened,
            _ => SecurityImpact::Neutral,
        };
        diffs.push(GlobalDiffItem {
            key: "system_type".to_string(),
            old_value: format!("{:?}", current.system_type),
            new_value: format!("{:?}", stage.system_type),
            impact,
            description: match impact {
                SecurityImpact::Relaxed => "Workstation mode permits non-standard interactive TTY (e.g. GUI sessions).".to_string(),
                SecurityImpact::Hardened => "Server mode restricts interactive TTY to pure CUI (pts/tty).".to_string(),
                _ => String::new(),
            },
        });
    }

    // 2. default_effect (マッチしなかった場合のフォールバック)
    if current.default_effect != stage.default_effect {
        let impact = match (current.default_effect, stage.default_effect) {
            (Effect::Deny, Effect::Allow) | (Effect::Deny, Effect::AuditOnly) | (Effect::NeedApproval, Effect::Allow) => {
                SecurityImpact::Relaxed // 全体拒否から全体許可への重大な緩和
            }
            (Effect::Allow, Effect::Deny) | (Effect::AuditOnly, Effect::Deny) | (Effect::Allow, Effect::NeedApproval) => {
                SecurityImpact::Hardened // 全体許可から全体遮断への強化
            }
            _ => SecurityImpact::Neutral,
        };
        diffs.push(GlobalDiffItem {
            key: "default_effect".to_string(),
            old_value: format!("{:?}", current.default_effect),
            new_value: format!("{:?}", stage.default_effect),
            impact,
            description: format!("Fallback effect changed from {:?} to {:?}", current.default_effect, stage.default_effect),
        });
    }

    // 3. pre_approval_defaults (ttl_sec_default, ttl_sec_max)
    let curr_pad = &current.pre_approval_defaults;
    let stage_pad = &stage.pre_approval_defaults;
    if curr_pad.ttl_sec_default != stage_pad.ttl_sec_default {
        let impact = if stage_pad.ttl_sec_default > curr_pad.ttl_sec_default {
            SecurityImpact::Relaxed // TTL延長は緩和
        } else {
            SecurityImpact::Hardened
        };
        diffs.push(GlobalDiffItem {
            key: "pre_approval_defaults.ttl_sec_default".to_string(),
            old_value: format!("{}s", curr_pad.ttl_sec_default),
            new_value: format!("{}s", stage_pad.ttl_sec_default),
            impact,
            description: "Default TTL for JIT pre-approvals changed.".to_string(),
        });
    }

    if curr_pad.ttl_sec_max != stage_pad.ttl_sec_max {
        let impact = match (curr_pad.ttl_sec_max, stage_pad.ttl_sec_max) {
            (Some(_), None) => SecurityImpact::Relaxed, // 上限撤廃は緩和
            (None, Some(_)) => SecurityImpact::Hardened, // 上限新設は強化
            (Some(c), Some(s)) if s > c => SecurityImpact::Relaxed,
            (Some(c), Some(s)) if s < c => SecurityImpact::Hardened,
            _ => SecurityImpact::Neutral,
        };
        diffs.push(GlobalDiffItem {
            key: "pre_approval_defaults.ttl_sec_max".to_string(),
            old_value: curr_pad.ttl_sec_max.map_or("None (unlimited)".to_string(), |v| format!("{}s", v)),
            new_value: stage_pad.ttl_sec_max.map_or("None (unlimited)".to_string(), |v| format!("{}s", v)),
            impact,
            description: "Hard limit cap for JIT pre-approval TTL changed.".to_string(),
        });
    }

    // 4. ttl_minutes (MPA pending チケット有効期限)
    if current.ttl_minutes != stage.ttl_minutes {
        let impact = if stage.ttl_minutes > current.ttl_minutes {
            SecurityImpact::Relaxed // 承認待ち放置可能時間の延長
        } else {
            SecurityImpact::Hardened
        };
        diffs.push(GlobalDiffItem {
            key: "ttl_minutes".to_string(),
            old_value: format!("{}m", current.ttl_minutes),
            new_value: format!("{}m", stage.ttl_minutes),
            impact,
            description: "MPA pending approval expiration window changed.".to_string(),
        });
    }

    // 5. sweep_minutes
    if current.sweep_minutes != stage.sweep_minutes {
        let impact = if stage.sweep_minutes > current.sweep_minutes {
            SecurityImpact::Relaxed // クリーンアップ頻度の低下
        } else {
            SecurityImpact::Hardened
        };
        diffs.push(GlobalDiffItem {
            key: "sweep_minutes".to_string(),
            old_value: format!("{}m", current.sweep_minutes),
            new_value: format!("{}m", stage.sweep_minutes),
            impact,
            description: "Pending approvals sweep/cleanup interval changed.".to_string(),
        });
    }

    // 6. version (メタ情報として記録)
    if current.version != stage.version {
        diffs.push(GlobalDiffItem {
            key: "version".to_string(),
            old_value: format!("{:?}", current.version),
            new_value: format!("{:?}", stage.version),
            impact: SecurityImpact::Neutral,
            description: "Policy schema version changed.".to_string(),
        });
    }

    diffs
}

/// ルール差分の分類と構築
fn diff_rules(
    current_rules: &[CompiledRule],
    stage_rules: &[CompiledRule],
) -> Vec<RuleDiffItem> {
    let mut items = Vec::new();

    // 1. current のルールを ID をキーにした HashMap に詰める
    let mut current_map: HashMap<&str, &CompiledRule> = current_rules
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();

    // 2. stage 側を走査（Added / Modified / Unchanged の判定）
    for stage_rule in stage_rules {
        if let Some(curr_rule) = current_map.remove(stage_rule.id.as_str()) {
            // current にも存在していた場合 -> 内容の比較
            if is_rule_equal(curr_rule, stage_rule) {
                items.push(RuleDiffItem::Unchanged {
                    id: stage_rule.id.clone(),
                });
            } else {
                let (impact, details) = inspect_rule_modification(curr_rule, stage_rule);
                items.push(RuleDiffItem::Modified {
                    id: stage_rule.id.clone(),
                    impact,
                    details,
                });
            }
        } else {
            // current に存在しない場合 -> Added
            items.push(RuleDiffItem::Added {
                rule: stage_rule.clone(),
                impact: evaluate_added_rule_impact(stage_rule),
            });
        }
    }

    // 3. current_map に残っている要素 -> stage で消去されたもの（Removed）
    for (_, removed_rule) in current_map {
        items.push(RuleDiffItem::Removed {
            rule: removed_rule.clone(),
            impact: evaluate_removed_rule_impact(removed_rule),
        });
    }

    items
}

/// 1. 2つのルールが完全一致しているか判定
pub fn is_rule_equal(curr: &CompiledRule, stage: &CompiledRule) -> bool {
    // 主要なフィールドが一致しているか判定
    curr.id == stage.id
        && curr.description == stage.description
        && curr.rule_type == stage.rule_type
        && curr.effect == stage.effect
        && curr.max_uses == stage.max_uses
        && curr.audit_level == stage.audit_level
        && curr.out_reason == stage.out_reason
        && curr.ticket_profile.flags == stage.ticket_profile.flags
        && is_action_equal(&curr.action_match, &stage.action_match)
        && is_mpa_equal(&curr.mpa, &stage.mpa)
        && is_pre_approval_equal(&curr.pre_approval, &stage.pre_approval)
        && is_subject_equal(&curr.subject, &stage.subject)
        && is_object_equal(&curr.object, &stage.object)
        && is_time_constraints_equal(&curr.time_constraints, &stage.time_constraints)
}

/// 2. 新規追加されたルールのセキュリティ影響判定
pub fn evaluate_added_rule_impact(rule: &CompiledRule) -> SecurityImpact {
    match rule.effect {
        // 許可ルールの新設はアクセス権の拡張 (🔴 緩和)
        Effect::Allow => SecurityImpact::Relaxed,
        // 承認付き許可の新設も新たなアクセス経路の開通 (🔴 緩和)
        Effect::NeedApproval => SecurityImpact::Relaxed,
        // 遮断ルールの新設はアクセス制限の強化 (🟢 強化)
        Effect::Deny => SecurityImpact::Hardened,
        // 監査のみのルールはアクセス判定そのものに影響しない
        Effect::AuditOnly => SecurityImpact::Neutral,
    }
}

/// 3. 削除されたルールのセキュリティ影響判定
pub fn evaluate_removed_rule_impact(rule: &CompiledRule) -> SecurityImpact {
    match rule.effect {
        // 許可ルール・承認ルールの削除はアクセス経路の閉鎖 (🟢 強化)
        Effect::Allow | Effect::NeedApproval => SecurityImpact::Hardened,
        // 拒否ルールの削除は既存の遮断防御の喪失 (🔴 緩和)
        Effect::Deny => SecurityImpact::Relaxed,
        Effect::AuditOnly => SecurityImpact::Neutral,
    }
}

/// 4. 変更されたルールのフィールド精査とセキュリティ影響判定
pub fn inspect_rule_modification(
    curr: &CompiledRule,
    stage: &CompiledRule,
) -> (SecurityImpact, Vec<String>) {
    let mut details = Vec::new();
    let mut impacts = Vec::new();

    // 1) Effect の変更
    if curr.effect != stage.effect {
        let impact = match (curr.effect, stage.effect) {
            (Effect::Deny, Effect::Allow)
            | (Effect::Deny, Effect::NeedApproval)
            | (Effect::NeedApproval, Effect::Allow)
            | (Effect::Deny, Effect::AuditOnly) => SecurityImpact::Relaxed,
            (Effect::Allow, Effect::Deny)
            | (Effect::NeedApproval, Effect::Deny)
            | (Effect::Allow, Effect::NeedApproval) => SecurityImpact::Hardened,
            _ => SecurityImpact::Neutral,
        };
        details.push(format!(
            "effect changed: {:?} ➔ {:?}",
            curr.effect, stage.effect
        ));
        impacts.push(impact);
    }

    // 2) ActionMatcher の変更
    match (&curr.action_match, &stage.action_match) {
        (ActionMatcher::OneOf(curr_set), ActionMatcher::OneOf(stage_set)) => {
            let added_ops: HashSet<_> = stage_set.difference(curr_set).collect();
            let removed_ops: HashSet<_> = curr_set.difference(stage_set).collect();

            if !added_ops.is_empty() {
                details.push(format!("action added: {:?}", added_ops));
                impacts.push(SecurityImpact::Relaxed);
            }
            if !removed_ops.is_empty() {
                details.push(format!("action removed: {:?}", removed_ops));
                impacts.push(SecurityImpact::Hardened);
            }
        }
        (ActionMatcher::OneOf(_), ActionMatcher::Any) => {
            details.push("action expanded to ANY".to_string());
            impacts.push(SecurityImpact::Relaxed);
        }
        (ActionMatcher::Any, ActionMatcher::OneOf(set)) => {
            details.push(format!("action restricted from ANY to {:?}", set));
            impacts.push(SecurityImpact::Hardened);
        }
        _ => {}
    }

    // 3) MPA (マルチパーティー承認) 条件の変更
    match (&curr.mpa, &stage.mpa) {
        (Some(c_mpa), Some(s_mpa)) => {
            if s_mpa.threshold < c_mpa.threshold {
                details.push(format!(
                    "mpa.threshold decreased: {} ➔ {}",
                    c_mpa.threshold, s_mpa.threshold
                ));
                impacts.push(SecurityImpact::Relaxed);
            } else if s_mpa.threshold > c_mpa.threshold {
                details.push(format!(
                    "mpa.threshold increased: {} ➔ {}",
                    c_mpa.threshold, s_mpa.threshold
                ));
                impacts.push(SecurityImpact::Hardened);
            }

            let dropped_roles: HashSet<_> = c_mpa.approver_roles.difference(&s_mpa.approver_roles).collect();
            let added_roles: HashSet<_> = s_mpa.approver_roles.difference(&c_mpa.approver_roles).collect();
            if !dropped_roles.is_empty() {
                details.push(format!("mpa approver_roles removed: {:?}", dropped_roles));
                impacts.push(SecurityImpact::Relaxed);
            }
            if !added_roles.is_empty() {
                details.push(format!("mpa approver_roles added: {:?}", added_roles));
                impacts.push(SecurityImpact::Hardened);
            }
        }
        (Some(_), None) => {
            details.push("mpa requirement removed".to_string());
            impacts.push(SecurityImpact::Relaxed);
        }
        (None, Some(_)) => {
            details.push("mpa requirement newly attached".to_string());
            impacts.push(SecurityImpact::Hardened);
        }
        (None, None) => {}
    }

    // 4) Pre-Approval (JIT TTL) の変更
    if curr.pre_approval.enabled != stage.pre_approval.enabled {
        if stage.pre_approval.enabled {
            details.push(format!(
                "pre_approval enabled (ttl: {}s)",
                stage.pre_approval.ttl_sec
            ));
            impacts.push(SecurityImpact::Relaxed);
        } else {
            details.push("pre_approval disabled".to_string());
            impacts.push(SecurityImpact::Hardened);
        }
    } else if stage.pre_approval.enabled && curr.pre_approval.ttl_sec != stage.pre_approval.ttl_sec {
        if stage.pre_approval.ttl_sec > curr.pre_approval.ttl_sec {
            details.push(format!(
                "pre_approval ttl extended: {}s ➔ {}s",
                curr.pre_approval.ttl_sec, stage.pre_approval.ttl_sec
            ));
            impacts.push(SecurityImpact::Relaxed);
        } else {
            details.push(format!(
                "pre_approval ttl shortened: {}s ➔ {}s",
                curr.pre_approval.ttl_sec, stage.pre_approval.ttl_sec
            ));
            impacts.push(SecurityImpact::Hardened);
        }
    }

    // 5) LoginContext (端末制約・IP等) の変更
    if let (Some(c_ctx), Some(s_ctx)) = (&curr.subject.login_context, &stage.subject.login_context) {
        if c_ctx.require_interactive_tty && !s_ctx.require_interactive_tty {
            details.push("login_context: require_interactive_tty relaxed to false".to_string());
            impacts.push(SecurityImpact::Relaxed);
        } else if !c_ctx.require_interactive_tty && s_ctx.require_interactive_tty {
            details.push("login_context: require_interactive_tty enforced to true".to_string());
            impacts.push(SecurityImpact::Hardened);
        }
    }

    // 6) AuditLevel の変更 (ログ抑制はセキュリティ上の追跡性を弱めるため Relaxed 扱い)
    if curr.audit_level != stage.audit_level {
        match (curr.audit_level, stage.audit_level) {
            (AuditLevel::Strict, AuditLevel::Standard)
            | (AuditLevel::Standard, AuditLevel::Silent)
            | (AuditLevel::Strict, AuditLevel::Silent) => {
                details.push(format!("audit_level degraded: {:?} ➔ {:?}", curr.audit_level, stage.audit_level));
                impacts.push(SecurityImpact::Relaxed);
            }
            (AuditLevel::Silent, AuditLevel::Standard)
            | (AuditLevel::Standard, AuditLevel::Strict)
            | (AuditLevel::Silent, AuditLevel::Strict) => {
                details.push(format!("audit_level strengthened: {:?} ➔ {:?}", curr.audit_level, stage.audit_level));
                impacts.push(SecurityImpact::Hardened);
            }
            _ => {}
        }
    }

    // 7) メタデータ・その他の変更 (Info / Neutral)
    if curr.description != stage.description {
        details.push("description updated".to_string());
    }
    if curr.out_reason != stage.out_reason {
        details.push(format!("out_reason changed: \"{}\" ➔ \"{}\"", curr.out_reason, stage.out_reason));
    }

    // 総合的な SecurityImpact の判定: 1つでも Relaxed があれば最悪ケースとして Relaxed
    let overall_impact = if impacts.contains(&SecurityImpact::Relaxed) {
        SecurityImpact::Relaxed
    } else if impacts.contains(&SecurityImpact::Hardened) {
        SecurityImpact::Hardened
    } else {
        SecurityImpact::Neutral
    };

    (overall_impact, details)
}

// --- 内部フィールド比較ヘルパー ---

fn is_action_equal(a: &ActionMatcher, b: &ActionMatcher) -> bool {
    match (a, b) {
        (ActionMatcher::Any, ActionMatcher::Any) => true,
        (ActionMatcher::OneOf(set_a), ActionMatcher::OneOf(set_b)) => set_a == set_b,
        _ => false,
    }
}

fn is_mpa_equal(a: &Option<teal_policy_engine::ir::MpaMatcher>, b: &Option<teal_policy_engine::ir::MpaMatcher>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(ma), Some(mb)) => ma.threshold == mb.threshold && ma.approver_roles == mb.approver_roles,
        _ => false,
    }
}

fn is_pre_approval_equal(a: &teal_policy_engine::ir::CompiledPreApproval, b: &teal_policy_engine::ir::CompiledPreApproval) -> bool {
    a.enabled == b.enabled && a.ttl_sec == b.ttl_sec
}

fn is_subject_equal(a: &teal_policy_engine::ir::SubjectMatcher, b: &teal_policy_engine::ir::SubjectMatcher) -> bool {
    a.uid == b.uid
        && a.required_roles == b.required_roles
        && a.origin_applet == b.origin_applet
        && a.origin_program == b.origin_program
        && a.origin_script == b.origin_script
        && is_login_ctx_equal(&a.login_context, &b.login_context)
}

fn is_login_ctx_equal(a: &Option<teal_policy_engine::ir::LoginContextMatcher>, b: &Option<teal_policy_engine::ir::LoginContextMatcher>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(ca), Some(cb)) => {
            ca.source_ip_network == cb.source_ip_network
                && ca.auth_method == cb.auth_method
                && ca.require_interactive_tty == cb.require_interactive_tty
                && ca.bind_registered_session == cb.bind_registered_session
        }
        _ => false,
    }
}

fn is_object_equal(a: &Option<teal_policy_engine::ir::ObjectMatcher>, b: &Option<teal_policy_engine::ir::ObjectMatcher>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(oa), Some(ob)) => oa.kind == ob.kind && oa.path == ob.path && oa.new_path == ob.new_path,
        _ => false,
    }
}

fn is_time_constraints_equal(a: &[teal_policy_engine::ir::TimeConstraintMatcher], b: &[teal_policy_engine::ir::TimeConstraintMatcher]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(ta, tb)| {
        ta.allowed_days == tb.allowed_days
            && ta.start_minutes_from_midnight == tb.start_minutes_from_midnight
            && ta.end_minutes_from_midnight == tb.end_minutes_from_midnight
    })
}

