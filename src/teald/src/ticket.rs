// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
//! TEAL Admin/MPA/Ticket 発行（そのまま貼れる最小実装）
//!
//! 前提：
//! - Admin/Approver → teald は Unix Domain Socket（tokio::net::UnixStream）
//! - peercred(uid) で approver を確定（コマンド内の approver 自己申告は使わない）
//! - `TICKET <policy_rule_id>` を受けたら、teald が Dev+Inode を確定して Draft を作る
//! - APPROVE/DENY で MPA を集約し、成立したら `/dev/teal` に `TICKET_ADD ...\n` を書く
//! - Fast Path の照合キーは Dev+Inode のみ（Hash は使わない）
//!
//! 依存：tokio（fs, io, net, sync）, std
//!   Cargo.toml 例：
//!   tokio = { version = "1", features = ["full"] }

use std::collections::HashMap;
use anyhow::Result;
use uuid::Uuid;

use crate::app_state;
use crate::types::{PreApprovalDraft, PendingEntry, EntityId, ApprovedTicket, MpaState};

use teal_policy_engine::ir::{CompiledRule, ActionMatcher, RuleType};

// ==================================
//  Ticketable 判定と Draft 生成
// ==================================

pub fn is_ticketable(rule: &CompiledRule) -> Result<(), String> {
    // 1. TTLチェック (最優先)
    if rule.ttl_sec == 0 {
        return Err("ttl_sec > 0 is required for TICKET".to_string());
    }

    // 2. object path 必須（Exact相当）
    // 名無しルール (SubjectOnly または allow_nameless_ipc) の場合はチェックをスキップ
    if rule.rule_type != RuleType::SubjectOnly {
        // Standardルールの場合: object が存在し、かつ path が Exact であることを要求
        let is_obj_exact = rule.object.as_ref()
            .and_then(|obj| obj.path.as_ref())
            .map_or(false, |path| path.is_exact());

        if !is_obj_exact {
            return Err("object.path (exact) is required for standard TICKET".to_string());
        }
    }

    // 3. action(op) 単一必須
    match &rule.action_match {
        ActionMatcher::OneOf(s) if s.len() == 1 => Ok(()),
        ActionMatcher::Any => Err("ActionMatcher::Any is too broad for TICKET".to_string()),
        _ => Err("single action op is required for TICKET".to_string()),
    }?;

    // 4. origin_program は必須かつ Exact であること
    let is_origin_exact = rule.subject.origin_program.as_ref().map_or(false, |p| p.is_exact());
    if !is_origin_exact {
        return Err("subject.origin_program (exact) is required for TICKET".to_string());
    }

    // 5. スクリプト指定がある場合も Exact が必要
    if let Some(script) = &rule.subject.origin_script {
        if !script.is_exact() {
             return Err("subject.origin_script (exact) is required if specified".to_string());
        }
    }

    Ok(())
}

pub async fn make_draft_id() -> String {
    let state = app_state();

    let seq = {
        let mut guard = state.lock().await;
        guard.fast.next_draft_seq += 1;
        guard.fast.next_draft_seq
    }; 

    format!("T-{:09}", seq)
}

/// rule_id を起点に Draft を作る。inodeの事前取得は行わない (Lazy Binding)
pub async fn draft_from_rule(rule: &CompiledRule, uid: u32) -> Result<PreApprovalDraft> {
    let op_mask = rule.action_match.to_u32();

    let origin_program_id = EntityId::new((0, 0));
    let object_id = EntityId::new((0, 0));
    let origin_script_id = if rule.subject.origin_script.is_some() {
        Some(EntityId::new((0, 0)))
    } else {
        None
    };

    let draft_id = make_draft_id().await;

    Ok(
        PreApprovalDraft {
            draft_id,
            audit_id: Uuid::new_v4().to_string(),
            rule_id: rule.id.clone(),

            uid,
            origin_program_id,
            origin_script_id,
            origin_applet: rule.subject.origin_applet.clone(),
            object_id,
            op_mask,

            mpa_state: MpaState {
                threshold: rule.threshold(),
                approver_roles: rule.required_roles().clone(),
                required_roles: rule.required_roles().clone(),
                approvals: HashMap::new(),
                aggregated_signature: None,
            },

            ttl_sec: rule.ttl_sec,
            max_uses: rule.max_uses,
        }
    )
}

/// PendingEntry を起点に Draft を作る。
pub async fn ticket_from_entry(rule: &CompiledRule, entry: &PendingEntry) -> ApprovedTicket {
    let op_mask = rule.action_match.to_u32();

    let origin_program = entry.subject.program_path.clone();
    let object = entry.object.path.clone();

    // ファイルシステムへの事前アクセスを行わず、すべて 0:0 でプレースホルダーを作成する
    let origin_program_id = EntityId::new((entry.subject.prog_dev, entry.subject.prog_ino));
    let object_id = EntityId::new((entry.object.device_id, entry.object.inode));
    let origin_script_id = if entry.subject.script_path.is_some() {
        Some(EntityId::new((entry.subject.script_dev, entry.subject.script_ino)))
    } else {
        None
    };

    let draft_id = make_draft_id().await;

    ApprovedTicket {
        ticket_id: draft_id,
        rule_id: rule.id.clone(),
        origin_program,
        origin_script: entry.subject.script_path.clone(),
        object,

        uid: entry.subject.uid,
        origin_program_id,
        origin_script_id,
        origin_applet: rule.subject.origin_applet.clone(),
        object_id,
        op_mask,

        ttl_sec: rule.ttl_sec,
        max_uses: rule.max_uses
    }
}

