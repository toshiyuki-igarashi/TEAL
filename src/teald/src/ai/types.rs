// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::evidence::schema::{AuditLogEntry, AuthInfo, LogType};

use crate::ai::aggregator::AiAggregatedEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEvent {
    /// 元のTEAL監査ログID（根拠特定用）
    pub event_id: String,

    /// 発生日時
    pub timestamp: DateTime<Utc>,

    /// ログ種別
    pub log_type: LogType,

    /// ポリシー世代
    pub epoch: u32,

    /// 操作ユーザー
    pub user: String,

    /// プロセスID
    pub pid: u32,

    /// アクション
    pub action: String,

    /// 実行バイナリ
    pub binary: String,

    /// スクリプトパス
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_path: Option<String>,

    /// Multi-call Binary のアプレット名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applet: Option<String>,

    /// 実行時引数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,

    /// 操作対象パス
    pub target_path: String,

    /// 操作対象種別
    pub target_kind: String,

    /// リネーム先パス
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,

    /// SSH接続元
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_client: Option<String>,

    /// 適用ポリシールールID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,

    /// チケットID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
}

impl From<&AuditLogEntry> for AiEvent {
    fn from(log: &AuditLogEntry) -> Self {
        let ctx = &log.syscall_context;

        let (rule, ticket_id) = match &log.auth_info {
            AuthInfo::SlowPath { policy_eval, .. } => (
                Some(policy_eval.rule_id.clone()),
                policy_eval
                    .issued_ticket
                    .as_ref()
                    .map(|t| t.ticket_id.clone()),
            ),

            AuthInfo::FastPath { ticket_context } => (
                Some(ticket_context.policy_rule.clone()),
                Some(ticket_context.ticket_id.clone()),
            ),
        };

        Self {
            event_id: log.id.clone(),
            timestamp: log.ts,
            log_type: log.log_type.clone(),
            epoch: log.epoch,

            user: ctx.user.clone(),
            pid: ctx.pid,
            action: ctx.action.clone(),

            binary: ctx.subject.path.clone(),
            script_path: ctx.subject.script_path.clone(),
            applet: ctx.subject.applet.clone(),
            args: ctx.subject.args.clone(),

            target_path: ctx.object.path.clone(),
            target_kind: ctx.object.kind.clone(),
            new_path: ctx.object.new_path.clone(),

            remote_client: log
                .environment_context
                .as_ref()
                .and_then(|e| e.ssh_client.clone()),

            rule,
            ticket_id,
        }
    }
}

/// 運用ルール・ホスト前提条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiOperationalContext {
    pub description: String,
}

/// TEALから発行される分析要求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisRequest {
    /// TEAL側の分析タスク一意ID
    pub analysis_id: String,

    /// 分析対象のホスト識別子
    pub host: String,

    /// 監査ウィンドウの開始日時
    pub time_window_start: DateTime<Utc>,

    /// 監査ウィンドウの終了日時
    pub time_window_end: DateTime<Utc>,

    /// 分析対象の監査イベント一覧
    pub events: Vec<AiEvent>,
}

/// 検出した異常の重要度
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// 検出した異常
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnomaly {
    /// 重要度
    pub severity: Severity,

    /// 推定攻撃種別
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_type: Option<String>,

    /// 要約
    pub summary: String,

    /// 詳細説明・推論根拠
    pub explanation: String,

    /// 根拠となったイベントID一覧
    pub evidence_event_ids: Vec<String>,

    /// 確信度 (0.0 - 1.0)
    pub confidence_score: f32,
}

/// Requestに対する結果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisResult {
    /// 対応するTEAL側の分析ID
    pub analysis_id: String,

    /// 検出された異常の一覧
    pub anomalies: Vec<AiAnomaly>,
}

/// AIプロバイダーへ渡す分析要求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderRequest {
    /// TEAL側の分析タスク一意ID
    pub analysis_id: String,

    /// 分析対象のホスト識別子
    pub host: String,

    /// 監査ウィンドウの開始日時
    pub time_window_start: DateTime<Utc>,

    /// 監査ウィンドウの終了日時
    pub time_window_end: DateTime<Utc>,

    /// 分析対象の集約済み監査イベント
    pub events: Vec<AiAggregatedEvent>,
}
