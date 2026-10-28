// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Instant};
use uuid::Uuid;

use crate::ai::engine::AiAnalysisEngine;
use crate::ai::results::{append_result, AiStoredAnalysis};
use crate::ai::types::AiAnalysisRequest;
use crate::ai::types::AiEvent;
use crate::evidence::schema::{AuditLogEntry, AuthInfo};
use teal_policy_engine::types::Effect;

static AI_ANALYSIS_BATCHES_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Collectorの設定
#[derive(Debug, Clone)]
pub struct AiCollectorConfig {
    pub window: Duration,
    pub max_events: usize,
}

impl Default for AiCollectorConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            max_events: 4096,
        }
    }
}

/// AI監査イベント収集器
pub struct AiCollector {
    host: String,
    config: AiCollectorConfig,
    events: Vec<AiEvent>,
    window_start: DateTime<Utc>,
}

impl AiCollector {
    pub fn new(host: String, config: AiCollectorConfig) -> Self {
        assert!(config.window > Duration::ZERO);
        assert!(config.max_events > 0);

        Self {
            host,
            config,
            events: Vec::new(),
            window_start: Utc::now(),
        }
    }

    /// 現在蓄積しているイベントから分析要求を生成
    fn flush(&mut self, end_time: DateTime<Utc>) -> Option<AiAnalysisRequest> {
        let events = std::mem::take(&mut self.events);
        let start_time = self.window_start;

        self.window_start = end_time;

        if events.is_empty() {
            return None;
        }

        Some(AiAnalysisRequest {
            analysis_id: Uuid::new_v4().to_string(),
            host: self.host.clone(),
            time_window_start: start_time,
            time_window_end: end_time,
            events,
        })
    }

    /// AI分析要求をキューへ送る
    fn submit(request: AiAnalysisRequest, tx: &mpsc::Sender<AiAnalysisRequest>) {
        match tx.try_send(request) {
            Ok(()) => {}

            Err(mpsc::error::TrySendError::Full(_)) => {
                eprintln!("[WARN] AI analysis queue full; analysis batch dropped");
                AI_ANALYSIS_BATCHES_DROPPED.fetch_add(1, Ordering::Relaxed);
            }

            Err(mpsc::error::TrySendError::Closed(_)) => {
                eprintln!("[WARN] AI analysis receiver closed");
            }
        }
    }

    /// EvidenceManagerからのイベントを継続収集する
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<AiEvent>,
        analysis_tx: mpsc::Sender<AiAnalysisRequest>,
    ) {
        let window = self.config.window;

        let mut interval = time::interval_at(Instant::now() + window, window);

        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(event) => {
                            self.events.push(event);

                            if self.events.len() >= self.config.max_events {
                                if let Some(request) = self.flush(Utc::now()) {
                                    Self::submit(request, &analysis_tx);
                                }
                            }
                        }

                        None => {
                            // チャネル終了時に残りを処理
                            if let Some(request) = self.flush(Utc::now()) {
                                Self::submit(request, &analysis_tx);
                            }
                            break;
                        }
                    }
                }

                _ = interval.tick() => {
                    if let Some(request) = self.flush(Utc::now()) {
                        Self::submit(request, &analysis_tx);
                    }
                }
            }
        }
    }
}

/// 管理対象外パスへのアクションを示す特殊チケットID
pub const NOT_MANAGED_TICKET_ID: &str = "T-000000000";

/// 監査ログエントリが AI 分析の対象かどうかを客観的に判定
pub fn is_target_for_ai(log: &AuditLogEntry) -> bool {
    // 管理操作はAI分析対象外
    if matches!(
        log.syscall_context.action.as_str(),
        "enable enforce mode"
            | "disable enforce mode"
            | "update policies"
            | "flush caches and lockdown"
    ) {
        return false;
    }

    match &log.auth_info {
        // Fast Pathは対象外
        AuthInfo::FastPath { .. } => false,

        AuthInfo::SlowPath { policy_eval, .. } => {
            // 管理対象外は除外
            if policy_eval
                .issued_ticket
                .as_ref()
                .is_some_and(|ticket| ticket.ticket_id == NOT_MANAGED_TICKET_ID)
            {
                return false;
            }

            // Allow / AuditOnlyのみ対象
            matches!(policy_eval.decision, Effect::Allow | Effect::AuditOnly)
        }
    }
}

/// 監査ログエントリを評価し、AI 分析対象であれば AiEvent に変換して返す
pub fn collect_ai_event(log: &AuditLogEntry) -> Option<AiEvent> {
    if is_target_for_ai(log) {
        Some(AiEvent::from(log))
    } else {
        None
    }
}

/// AI分析要求を順次処理するワーカー
pub async fn run_ai_analysis_worker(
    engine: Arc<AiAnalysisEngine>,
    mut rx: mpsc::Receiver<AiAnalysisRequest>,
) {
    while let Some(request) = rx.recv().await {
        match engine.analyze_with_provenance(&request).await {
            Ok(outcome) => {
                let record =
                    AiStoredAnalysis::from_outcome(&request, engine.provider_name(), outcome);
                let id = record.result.analysis_id.clone();
                let anomaly_count = record.result.anomalies.len();
                // ファイルI/OがTokioワーカーをブロックしないよう分離する。
                match tokio::task::spawn_blocking(move || append_result(&record)).await {
                    Ok(Ok(())) => eprintln!(
                        "[INFO] AI analysis saved: id={}, anomalies={}",
                        id, anomaly_count
                    ),
                    Ok(Err(e)) => {
                        eprintln!("[ERROR] AI analysis save failed: id={}, error={}", id, e)
                    }
                    Err(e) => eprintln!(
                        "[ERROR] AI analysis storage task failed: id={}, error={}",
                        id, e
                    ),
                }
            }

            Err(e) => {
                eprintln!(
                    "[WARN] AI analysis failed: id={}, error={}",
                    request.analysis_id, e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::schema::{
        AuditLogEntry, AuthInfo, IssuedTicketInfo, LogType, ObjectInfo, PolicyEvalResult,
        SubjectInfo, SyscallContext,
    };
    use chrono::Utc;

    fn make_test_audit_entry(ticket_id: Option<&str>, effect: Effect) -> AuditLogEntry {
        AuditLogEntry {
            ver: "1.5".to_string(),
            id: "evt-001".to_string(),
            ts: Utc::now(),
            host: "test-host".to_string(),
            epoch: 1,
            log_type: LogType::AccessAllowed, // 判定には使用されない
            syscall_context: SyscallContext {
                uid: 0,
                user: "root".to_string(),
                pid: 1000,
                action: "OPEN".to_string(),
                subject: SubjectInfo {
                    path: "/bin/ls".to_string(),
                    hash: "".to_string(),
                    script_path: None,
                    applet: None,
                    args: None,
                    session_tty: None,
                },
                object: ObjectInfo {
                    path: "/data/file.txt".to_string(),
                    inode: 0,
                    device_id: 0,
                    kind: "file".to_string(),
                    new_path: None,
                    new_inode: None,
                    new_device_id: None,
                },
            },
            auth_info: AuthInfo::SlowPath {
                policy_eval: PolicyEvalResult {
                    rule_id: "rule_1".to_string(),
                    matched_file: "".to_string(),
                    mpa_level_required: 0,
                    decision: effect,
                    issued_ticket: ticket_id.map(|id| IssuedTicketInfo {
                        ticket_id: id.to_string(),
                        ttl_sec: 0,
                    }),
                },
                mpa_proof: Default::default(),
            },
            environment_context: None,
        }
    }

    #[test]
    fn test_filter_not_managed() {
        // T-000000000 の場合は除外されること
        let entry = make_test_audit_entry(Some(NOT_MANAGED_TICKET_ID), Effect::Allow);
        assert!(!is_target_for_ai(&entry));
        assert!(collect_ai_event(&entry).is_none());
    }

    #[test]
    fn test_filter_effects() {
        // Allow: 対象
        let allow_entry = make_test_audit_entry(Some("T-000000001"), Effect::Allow);
        assert!(is_target_for_ai(&allow_entry));
        assert!(collect_ai_event(&allow_entry).is_some());

        // AuditOnly: 対象
        let audit_entry = make_test_audit_entry(Some("T-000000002"), Effect::AuditOnly);
        assert!(is_target_for_ai(&audit_entry));
        assert!(collect_ai_event(&audit_entry).is_some());

        // NeedApproval: 対象外
        let na_entry = make_test_audit_entry(None, Effect::NeedApproval);
        assert!(!is_target_for_ai(&na_entry));
        assert!(collect_ai_event(&na_entry).is_none());

        // Deny: 対象外
        let deny_entry = make_test_audit_entry(None, Effect::Deny);
        assert!(!is_target_for_ai(&deny_entry));
        assert!(collect_ai_event(&deny_entry).is_none());
    }

    #[test]
    fn test_filter_management_actions() {
        let actions = [
            "enable enforce mode",
            "disable enforce mode",
            "update policies",
            "flush caches and lockdown",
        ];

        for action in actions {
            let mut entry = make_test_audit_entry(None, Effect::Allow);

            entry.syscall_context.action = action.to_string();

            assert!(
                !is_target_for_ai(&entry),
                "Management action should be excluded: {}",
                action
            );

            assert!(collect_ai_event(&entry).is_none());
        }
    }

    #[tokio::test]
    async fn test_collector_pipeline_batch_and_submit() {
        let host = "test-host".to_string();
        let config = AiCollectorConfig {
            window: Duration::from_secs(60),
            max_events: 5, // 5件で即時フラッシュ
        };

        let (ai_tx, ai_rx) = mpsc::channel(16);
        let (analysis_tx, mut analysis_rx) = mpsc::channel(4);

        let collector = AiCollector::new(host, config);

        // Collectorをバックグラウンド実行
        tokio::spawn(collector.run(ai_rx, analysis_tx));

        // 1. イベントを5件投入（max_events到達による即時フラッシュを検証）
        for i in 0..5 {
            let entry = make_test_audit_entry(Some("T-000000001"), Effect::Allow);
            let mut event = collect_ai_event(&entry).unwrap();
            event.event_id = format!("evt-{:03}", i);
            ai_tx.send(event).await.unwrap();
        }

        // 2. 分析要求がキューに届いたことを確認
        let req = tokio::time::timeout(Duration::from_millis(500), analysis_rx.recv())
            .await
            .expect("Timeout waiting for analysis request")
            .expect("Channel closed unexpectedly");

        assert_eq!(req.events.len(), 5);
        assert_eq!(req.events[0].event_id, "evt-000");
        assert_eq!(req.events[4].event_id, "evt-004");
        assert_eq!(req.host, "test-host");
    }
}
