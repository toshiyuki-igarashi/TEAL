// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::sync::mpsc;
use anyhow::Result;

// プロジェクト内の必要なモジュールをインポート
use crate::state::app_state;
use crate::types::{
    Request, InternalEvent, PolicyDecision, EntityId, PendingEntry,
    ApprovedTicket, PolicyResult, TicketPayload
};
use crate::bundle::bundle;
use crate::decide::request_to_ctx;
use crate::netlink::{TealNetlinkMessage, NlWriter};

use teal_policy_engine::types::Action;
use teal_policy_engine::ir::{CompiledRule, Decision};
use teal_policy_engine::util::{uid_to_name, ktime_prefix};
use teal_policy_engine::eval::evaluate;
use teal_policy_engine::types::AuditLevel;

// =========================================================================
// ワーカーのメインループ
// =========================================================================

/// 特急レーン（ENFORCEモード）専用のワーカー
pub async fn decision_worker_loop(
    mut rx_decision: mpsc::Receiver<TealNetlinkMessage>, 
    internal_tx: mpsc::Sender<InternalEvent>,
    nl_tx: NlWriter,
) {
    loop {
        // 1. Netlinkモジュールから安全にパース済みのメッセージを受け取る
        let Some(msg) = rx_decision.recv().await else {
            eprintln!("{}[INFO] Decision Channel closed, exiting worker.", ktime_prefix());
            break;
        };

        let nl_req = match msg {
            TealNetlinkMessage::Req(r) => r,
            _ => continue, // Decisionレーンには Req (ENFORCE) しか来ない想定
        };

        // nl_req がムーブ（消費）される前に、互換性用の文字列を作っておく
        let req_line = format!("NETLINK_REQ: {:?}", nl_req);

        // 2. ENFORCEモード用として Request 構造体に変換 (is_audit = false)
        // ここで nl_req の所有権が移動（消費）される
        let req = Request::from_enforce_teal_req(nl_req);

        // 3. ポリシー判定の実行
        let mut policy_result = process_policy_decision(&req).await;

        // 4. カーネルへの即時応答（Netlink経由で TICKET_ADD または APPROVE/DENY を送信）
        if let Err(e) = reply_to_kernel(&nl_tx, &req, &mut policy_result).await {
            eprintln!("{}[ERROR] Failed to reply to kernel for REQ {}: {}", ktime_prefix(), req.id, e);
            // 送信失敗時のフェイルセーフ: 確実にプロセスを解放するために再度DENYを試みる
            let _ = nl_tx.send_deny(req.id).await;
        }

        // 5. ログ記録を Audit Worker へ委譲
        let event = InternalEvent::Resolved {
            req_line,       // 事前に作っておいた文字列を渡す
            parsed_req: req,
            decision: policy_result.decision.clone(), 
            rule_id: policy_result.rule_id.clone(),
            ticket_id: policy_result.ticket.as_ref().map(|t| t.ticket_id.clone()),
        };

        if let Err(e) = internal_tx.send(event).await {
            eprintln!("{}[ERROR] Failed to delegate log to Audit Lane: {}", ktime_prefix(), e);
        }
    }
}

// ============================================================================
// 1. メイン関数（非同期化し、ロック期間を最小化）
// ============================================================================
pub async fn process_policy_decision(req: &Request) -> PolicyResult {
    let compiled = bundle();

    // 1. AppStateのロックを取得する *前* に、重い名前解決を非同期 (spawn_blocking) で済ませる
    let target_uid = req.uid; 

    let request_user = tokio::task::spawn_blocking(move || {
        uid_to_name(target_uid).ok() // 戻り値は Option<String> と推測される
    })
    .await
    .unwrap_or(None); // 万が一タスクがパニックしても None として安全に扱う

    // 【フェーズ1】一瞬だけロックを取り、判定に必要な事実（ファクト）だけをコピー
    let (session_info, current_epoch) = {
        let state = app_state().lock().await;
        (
            state.check_registered_session(&req.session_tty, req.uid, request_user.as_deref()),
            state.current_epoch
        )
    }; // 即座にロック解放！

    // 【フェーズ2】ロックを持たない状態で、重いポリシー評価を並行実行
    let ctx = request_to_ctx(req, &compiled.roles, session_info);
    let decision = evaluate(&compiled.policy, &ctx);

    // 【フェーズ3】評価結果に応じた処理へルーティング
    match decision {
        Decision::Pass => build_not_managed_result(req, current_epoch),
        Decision::NoMatchManaged => build_no_match_result(),
        Decision::Matched(rule) => apply_matched_rule(rule, req, current_epoch).await,
    }
}

// ============================================================================
// 2. 対象外パス (NotManaged) 用の処理
// ============================================================================
fn build_not_managed_result(req: &Request, current_epoch: u32) -> PolicyResult {
    let payload = TicketPayload {
        ticket_id: "T-000000000".to_string(), // 予約値0
        uid: req.uid,
        op: 0xFFFFFFFF,             // Alpha版: 対象外は全操作許可マスク
        prog_dev: req.prog_dev,
        prog_ino: req.prog_ino,
        script_dev: req.script_dev,
        script_ino: req.script_ino,
        applet_hash: 0,             // Alphaフェーズ固定
        target_dev: req.target_dev,
        target_ino: req.target_ino,
        new_target_dev: req.new_target_dev,
        new_target_ino: req.new_target_ino,
        expires_in_sec: u64::MAX,   // Epochが変わるまで無限
        flags: 0,
        uses_left: 1,               // 予約値0でもプロトコル要件として1以上
        epoch: current_epoch,       // グローバルEpochと紐付け
        audit_flags: AuditLevel::Silent.to_u32(),
    };
    
    PolicyResult {
        decision: PolicyDecision::NotManaged,
        rule_id: None,
        ticket: Some(payload),
    }
}

// ============================================================================
// 3. デフォルト拒否 (NoMatchManaged) 用の処理
// ============================================================================
fn build_no_match_result() -> PolicyResult {
    PolicyResult {
        decision: PolicyDecision::NoRuleMatched,
        rule_id: None,
        ticket: None,
    }
}

// ============================================================================
// 4. ルールマッチ時の処理（状態変更が必要な場合のみ再度ロック）
// ============================================================================
async fn apply_matched_rule(r: &CompiledRule, req: &Request, current_epoch: u32) -> PolicyResult {
    let decision_kind = match r.effect.as_str() {
        "allow" => PolicyDecision::Allow,
        "deny" => PolicyDecision::Deny,
        "audit_only" => PolicyDecision::AuditOnly,
        "need_approval" => PolicyDecision::NeedApproval,
        _ => PolicyDecision::Deny,
    };

    match decision_kind {
        PolicyDecision::Allow if r.pre_approval.ttl_sec > 0 => {
            // チケット発行に必要な「次のシーケンス番号」だけを、一瞬のロックで取得
            let ticket_seq = {
                let mut state = app_state().lock().await;
                state.generate_next_ticket_seq()
            }; // ロックを即解放

            // AppStateへの参照を渡さず、値だけを渡して純粋な関数として処理
            let ticket = generate_allow_ticket(r, req, ticket_seq, current_epoch);

            PolicyResult {
                decision: decision_kind,
                rule_id: Some(r.id.clone()),
                ticket: Some(ticket),
            }
        },
        PolicyDecision::NeedApproval => {
            // キューの操作を伴うため、内部でロックを取って安全に処理
            process_need_approval(r, req, current_epoch).await
        },
        _ => {
            PolicyResult {
                decision: decision_kind,
                rule_id: Some(r.id.clone()),
                ticket: None,
            }
        }
    }
}

// ============================================================================
// 5. 許可(ALLOW)チケットの生成ロジック（純粋な関数になり、ロック非依存に）
// ============================================================================
fn generate_allow_ticket(
    r: &CompiledRule, 
    req: &Request, 
    ticket_seq: u64, 
    current_epoch: u32
) -> TicketPayload {
    let formatted_id = format!("T-{:09}", ticket_seq);

    TicketPayload {
        ticket_id: formatted_id,
        uid: req.uid,
        op: r.action_match.to_u32(),
        prog_dev: req.prog_dev,
        prog_ino: req.prog_ino,
        script_dev: req.script_dev,
        script_ino: req.script_ino,
        applet_hash: 0,
        target_dev: req.target_dev,
        target_ino: req.target_ino,
        new_target_dev: req.new_target_dev,
        new_target_ino: req.new_target_ino,
        expires_in_sec: r.pre_approval.ttl_sec,
        flags: r.ticket_profile.flags,
        uses_left: r.max_uses,
        epoch: current_epoch, // フェーズ1で取得したコピーを使用
        audit_flags: r.audit_level.to_u32(),
    }
}

// ============================================================================
// 6. NeedApproval 特有の処理 (究極までロックを最小化したJIT Hydration)
// ============================================================================
async fn process_need_approval(r: &CompiledRule, req: &Request, current_epoch: u32) -> PolicyResult {
    // 【フェーズ1: 準備】
    // Uuid生成やメモリ確保を伴う重い処理は、ロックを取る「前」に済ませておく
    let pending_entry = PendingEntry::from_rule(r, req);

    // 【フェーズ2: 状態変更 (一瞬だけロック)】
    let approved_ticket_opt = {
        let mut state = app_state().lock().await;

        // 1. HashMapから該当ルールのチケットを探す
        let target_ticket_id = state.fast.approved.values()
            .find(|t| t.rule_id == r.id)
            .map(|t| t.ticket_id.clone());

        if let Some(ticket_id) = target_ticket_id {
            // 2. 見つかった場合: JIT Hydration (approved から tickets へ移動)
            if let Some(approved) = state.fast.approved.remove(&ticket_id) {
                state.fast.tickets.insert(approved.ticket_id.clone(), approved.clone());
                Some(approved) // 成功したチケット情報をコピーして返す
            } else {
                None
            }
        } else {
            // 3. 見つからなかった場合: 承認待ちキューへ登録
            // (事前のフェーズ1で作っておいた pending_entry を挿入するだけ)
            state.slow.pending_requests.insert(req.id, pending_entry);
            None
        }
    }; // 即座にロック解放！

    // 【フェーズ3: 結果の構築】
    // ロック解放後に、取得できたチケット情報を使ってペイロードを組み立てる
    if let Some(approved) = approved_ticket_opt {
        let payload = TicketPayload {
            ticket_id: approved.ticket_id.clone(),
            uid: req.uid,
            op: approved.op_mask,
            prog_dev: req.prog_dev,
            prog_ino: req.prog_ino,
            script_dev: req.script_dev,
            script_ino: req.script_ino,
            applet_hash: 0,
            target_dev: req.target_dev,
            target_ino: req.target_ino,
            new_target_dev: req.new_target_dev,
            new_target_ino: req.new_target_ino,
            expires_in_sec: approved.ttl_sec,
            flags: r.ticket_profile.flags,
            uses_left: approved.max_uses,
            epoch: current_epoch,
            audit_flags: r.audit_level.to_u32(),
        };
        
        PolicyResult {
            decision: PolicyDecision::Approved(approved),
            rule_id: Some(r.id.clone()),
            ticket: Some(payload),
        }
    } else {
        PolicyResult {
            decision: PolicyDecision::NeedApproval,
            rule_id: Some(r.id.clone()),
            ticket: None,
        }
    }
}

// --- カーネルへの応答 ---
async fn reply_to_kernel(nl_tx: &NlWriter, req: &Request, policy_result: &mut PolicyResult) -> Result<()> {
    match &mut policy_result.decision {
        PolicyDecision::NotManaged => {
            if let Some(ticket) = policy_result.ticket.take() {
                let _ = nl_tx.send_approve(req.id).await;
                nl_tx.send_ticket_add(ticket).await
            } else {
                nl_tx.send_approve(req.id).await
            }
        }
        PolicyDecision::Allow => {
            if let Some(ticket) = policy_result.ticket.take() {
                let _ = nl_tx.send_approve(req.id).await;
                nl_tx.send_ticket_add(ticket).await?;

                if let Some(approved) = ApprovedTicket::from_result(policy_result) {
                    let mut lock = app_state().lock().await;
                    lock.fast.tickets.insert(approved.ticket_id.clone(), approved);
                }
                Ok(())
            } else {
                nl_tx.send_approve(req.id).await
            }
        }
        PolicyDecision::Approved(approved) => {
            // メタデータの補完
            approved.origin_program = req.raw_program.clone();
            approved.origin_script = req.raw_script.clone();

            // --- パスの補完 ---
            approved.object = req.raw_target.clone();
            approved.new_object = req.raw_new_target.clone();

            // --- EntityID (inode/dev) の補完 ---
            approved.uid = req.uid;
            approved.origin_program_id = EntityId::new((req.prog_dev, req.prog_ino));
            approved.origin_script_id = Some(EntityId::new((req.script_dev, req.script_ino)));
            approved.origin_applet = req.raw_applet.clone();

            approved.object_id = EntityId::new((req.target_dev, req.target_ino));
            
            // new_object_id がある場合のみセット
            if req.new_target_dev != 0 || req.new_target_ino != 0 {
                approved.new_object_id = Some(EntityId::new((req.new_target_dev, req.new_target_ino)));
            } else {
                approved.new_object_id = None;
            }

            approved.op_mask = Action::parse(&req.raw_action).unwrap_or(Action::Unknown).to_mask();

            {
                let mut state = app_state().lock().await;
                state.fast.tickets.insert(approved.ticket_id.clone(), approved.clone());
            }

            if let Some(ticket) = policy_result.ticket.take() {
                let _ = nl_tx.send_approve(req.id).await;
                nl_tx.send_ticket_add(ticket).await
            } else {
                nl_tx.send_approve(req.id).await
            }
        }
        PolicyDecision::AuditOnly => nl_tx.send_approve(req.id).await,
        PolicyDecision::NeedApproval => Ok(()), // 承認待ちのためカーネルへは無応答（タイムアウトまで待機させる）
        PolicyDecision::Deny | PolicyDecision::NoRuleMatched => nl_tx.send_deny(req.id).await,
    }
}

