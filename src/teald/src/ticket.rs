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

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::collections::HashMap;
use anyhow::Result;
use uuid::Uuid;

use teal_policy_engine::types::RuleType;
use teal_policy_engine::types::Action;
use teal_policy_engine::raw::{TEAL_TICKET_FLG_SILENT_IO, TEAL_TICKET_FLG_PARENT_MATCH};
use teal_policy_engine::util::ktime_prefix;
use teal_policy_engine::ir::{CompiledRule, ActionMatcher, PathMatcher};

use crate::bundle::bundle;
use crate::netlink::NlWriter;
use crate::types::{PreApprovalDraft, PendingEntry, EntityId, ApprovedTicket, MpaState};
use crate::types::TicketPayload;
use crate::types::next_audit_ticket_id;


// ==================================
//  Ticketable 判定と Draft 生成
// ==================================

pub fn is_ticketable(rule: &CompiledRule) -> Result<(), String> {
    // 1. TTLチェック (最優先)
    if rule.pre_approval.ttl_sec == 0 {
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

    let draft_id = next_audit_ticket_id();

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
            new_object_id: None, 
            
            op_mask,

            mpa_state: MpaState {
                threshold: rule.threshold(),
                approver_roles: rule.approver_roles(),
                required_roles: rule.approver_roles(),
                approvals: HashMap::new(),
                aggregated_signature: None,
            },

            ttl_sec: rule.pre_approval.ttl_sec,
            max_uses: rule.max_uses,
        }
    )
}


/// PendingEntry を起点に Draft を作る。
pub async fn ticket_from_entry(rule: &CompiledRule, entry: &PendingEntry) -> ApprovedTicket {
    let op_mask = rule.action_match.to_u32();

    let origin_program = entry.subject.program_path.clone();
    let object = entry.object.path.clone();
    let new_object = entry.object.new_path.clone(); // ★追加

    // 既存のID構築
    let origin_program_id = EntityId::new((entry.subject.prog_dev, entry.subject.prog_ino));
    let object_id = EntityId::new((entry.object.device_id, entry.object.inode));
    
    // 移動先IDの構築 (両方の値が存在する場合のみ EntityId を生成)
    let new_object_id = if let (Some(dev), Some(ino)) = (entry.object.new_device_id, entry.object.new_inode) {
        Some(EntityId::new((dev, ino)))
    } else {
        None
    };

    let origin_script_id = if entry.subject.script_path.is_some() {
        Some(EntityId::new((entry.subject.script_dev, entry.subject.script_ino)))
    } else {
        None
    };

    let draft_id = next_audit_ticket_id();

    ApprovedTicket {
        ticket_id: draft_id,
        rule_id: rule.id.clone(),
        origin_program,
        origin_script: entry.subject.script_path.clone(),
        object,
        new_object,

        uid: entry.subject.uid,
        origin_program_id,
        origin_script_id,
        origin_applet: rule.subject.origin_applet.clone(),
        object_id,
        new_object_id,
        op_mask,

        ttl_sec: rule.pre_approval.ttl_sec,
        max_uses: rule.max_uses,
    }
}

/// 起動時およびポリシー更新時に、silent_io な prefix ディレクトリの包括チケットを一括投入する
pub async fn preload_silent_directory_tickets(nl_tx: &NlWriter) -> Result<()> {
    let compiled = bundle();
    let mut loaded_count = 0;

    for rule in &compiled.policy.rules {
        // 1. allow ルールかつ silent_io: true であること
        if rule.effect.as_str() != "allow" || !rule.ticket_profile.is_silent_io() {
            continue;
        }

        // 2. 対象アクションにファイル操作が含まれていること
        let op_mask = rule.action_match.to_u32();
        if (op_mask & Action::file_ops_mask()) == 0 {
            continue;
        }

        // 3. object.path が存在し、Prefix バリアントであること
        let Some(ref obj) = rule.object else { continue; };
        let Some(PathMatcher::Prefix(ref prefix_path)) = obj.path else { continue; };

        // 4. ディレクトリが存在し、ディレクトリであることを確認して Dev/Inode を取得
        let Ok(meta) = fs::metadata(prefix_path) else {
            continue;
        };

        if !meta.is_dir() {
            continue;
        }

        let target_dev = meta.dev() as u32;
        let target_ino = meta.ino();

        // 5. Subject（実行元）の Dev/Inode を取得
        let (prog_dev, prog_ino) = if rule.rule_type == RuleType::SubjectOnly {
            (0, 0)
        } else if let Some(ref prog_matcher) = rule.subject.origin_program {
            let prog_path = match prog_matcher {
                PathMatcher::Exact(p) | PathMatcher::Prefix(p) => Some(p.as_path()),
                PathMatcher::Glob { .. } => None,
            };

            if let Some(path) = prog_path {
                if let Ok(pmeta) = fs::metadata(path) {
                    (pmeta.dev() as u32, pmeta.ino())
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        // 6. 包括チケットの組み立て (無制限・サイレント・包括フラグ付き)
        let payload = TicketPayload {
            ticket_id: "T-000000000".to_string(), // ID: 0 (Fast Path 恒久許可)
            uid: rule.subject.uid.unwrap_or(0),
            op: op_mask,
            prog_dev: prog_dev.into(),
            prog_ino,
            script_dev: 0,
            script_ino: 0,
            applet_hash: 0,
            target_dev: target_dev.into(),
            target_ino,
            new_target_dev: 0,
            new_target_ino: 0,
            expires_in_sec: u64::MAX, // 無期限
            flags: TEAL_TICKET_FLG_PARENT_MATCH | TEAL_TICKET_FLG_SILENT_IO,
            uses_left: u32::MAX,
            epoch: 0,
            audit_flags: 1, // Silent
        };

        if let Err(e) = nl_tx.send_ticket_add(payload).await {
            eprintln!(
                "{}[WARN] Failed to preload directory ticket for {}: {}",
                ktime_prefix(), prefix_path.display(), e
            );
        } else {
            loaded_count += 1;
            eprintln!(
                "{}[INFO] teald: Preloaded parent wildcard ticket: rule='{}', path='{}' (dev={}, ino={})",
                ktime_prefix(), rule.id, prefix_path.display(), target_dev, target_ino
            );
        }
    }

    eprintln!(
        "{}[INFO] teald: Successfully preloaded {} silent directory tickets into Kernel.",
        ktime_prefix(),
        loaded_count
    );

    Ok(())
}
