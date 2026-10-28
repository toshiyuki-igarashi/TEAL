// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::ai::aggregator::aggregate_events;
use crate::ai::error::{AiError, ValidationCode, ValidationFailure};
use crate::ai::provider::AiProvider;
use crate::ai::types::{
    AiAnalysisRequest, AiAnalysisResult, AiOperationalContext, AiProviderRequest,
};
use crate::ai::AggregatorConfig;

/// Providerが実際に評価した集約と、その全元イベントの対応関係を保持する。
pub struct AiAnalysisOutcome {
    pub result: AiAnalysisResult,
    pub source_event_ids: HashMap<String, Vec<String>>,
    pub aggregated_event_count: usize,
}

/// AI分析の実行および結果検証を担当するエンジン
pub struct AiAnalysisEngine {
    provider: Arc<dyn AiProvider>,
    config: AggregatorConfig,
}

impl AiAnalysisEngine {
    /// AIプロバイダーを指定してエンジンを生成
    pub fn new(provider: Arc<dyn AiProvider>, config: AggregatorConfig) -> Self {
        Self { provider, config }
    }

    /// 使用中のプロバイダー名
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// 運用コンテキストを設定
    pub async fn set_operational_context(
        &self,
        context: &AiOperationalContext,
    ) -> Result<(), AiError> {
        self.provider.set_operational_context(context).await
    }

    /// 監査イベントをAIで分析
    pub async fn analyze(&self, request: &AiAnalysisRequest) -> Result<AiAnalysisResult, AiError> {
        Ok(self.analyze_with_provenance(request).await?.result)
    }

    /// 分析結果と、実際にProviderへ渡した集約の元イベントID対応を返す。
    pub async fn analyze_with_provenance(
        &self,
        request: &AiAnalysisRequest,
    ) -> Result<AiAnalysisOutcome, AiError> {
        // 分析要求を検証
        Self::validate_request(request)?;

        // イベントを時刻順にソート
        let mut sorted_request = request.clone();

        sorted_request.events.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        // 集約
        let aggregation = aggregate_events(
            &sorted_request.analysis_id,
            &sorted_request.events,
            &self.config,
        );

        // Provider向けの要求を生成
        let provider_request = AiProviderRequest {
            analysis_id: sorted_request.analysis_id.clone(),
            host: sorted_request.host.clone(),
            time_window_start: sorted_request.time_window_start,
            time_window_end: sorted_request.time_window_end,
            events: aggregation.events,
        };

        // AIプロバイダーによる分析
        let result = self.provider.analyze(&provider_request).await?;

        // 分析結果を検証
        Self::validate_result(&sorted_request, &provider_request, &result)?;

        Ok(AiAnalysisOutcome {
            result,
            source_event_ids: aggregation.source_event_ids,
            aggregated_event_count: provider_request.events.len(),
        })
    }

    /// 分析要求の基本的な整合性検証
    fn validate_request(request: &AiAnalysisRequest) -> Result<(), AiError> {
        if request.analysis_id.trim().is_empty() {
            return Err(AiError::InvalidRequest("analysis_id is empty".to_string()));
        }

        if request.host.trim().is_empty() {
            return Err(AiError::InvalidRequest("host is empty".to_string()));
        }

        if request.time_window_start > request.time_window_end {
            return Err(AiError::InvalidRequest(
                "Invalid analysis time window".to_string(),
            ));
        }

        // 同じ分析要求内でのイベントID重複を禁止
        let mut ids = HashSet::new();

        for event in &request.events {
            if event.event_id.trim().is_empty() {
                return Err(AiError::InvalidRequest("event_id is empty".to_string()));
            }

            if !ids.insert(event.event_id.as_str()) {
                return Err(AiError::InvalidRequest(format!(
                    "Duplicate event_id: {}",
                    event.event_id
                )));
            }
        }

        Ok(())
    }

    /// AI分析結果の整合性検証。AI生成の値をエラーには記録しない。
    fn validate_result(
        request: &AiAnalysisRequest,
        provider_request: &AiProviderRequest,
        result: &AiAnalysisResult,
    ) -> Result<(), AiError> {
        fn invalid(code: ValidationCode, field: &'static str, index: Option<usize>) -> AiError {
            AiError::Validation(ValidationFailure::new(code, Some(field), index))
        }
        if result.analysis_id != request.analysis_id {
            return Err(invalid(
                ValidationCode::AnalysisIdMismatch,
                "analysis_id",
                None,
            ));
        }
        let event_ids: HashSet<&str> = provider_request
            .events
            .iter()
            .flat_map(|event| event.evidence_event_ids.iter())
            .map(String::as_str)
            .collect();
        for (index, anomaly) in result.anomalies.iter().enumerate() {
            if !anomaly.confidence_score.is_finite()
                || !(0.0..=1.0).contains(&anomaly.confidence_score)
            {
                return Err(invalid(
                    ValidationCode::InvalidConfidence,
                    "confidence_score",
                    Some(index),
                ));
            }
            if anomaly.evidence_event_ids.is_empty() {
                return Err(invalid(
                    ValidationCode::MissingEvidence,
                    "evidence_event_ids",
                    Some(index),
                ));
            }
            if anomaly.evidence_event_ids.len() > 3 {
                return Err(invalid(
                    ValidationCode::InvalidEvidenceCount,
                    "evidence_event_ids",
                    Some(index),
                ));
            }
            for id in &anomaly.evidence_event_ids {
                if !event_ids.contains(id.as_str()) {
                    return Err(invalid(
                        ValidationCode::UnknownEvidenceId,
                        "evidence_event_ids",
                        Some(index),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::adapters::common::build_system_prompt;
    use crate::ai::PromptConfig;
    use chrono::Utc;

    use crate::ai::adapters::mock::{MockAdapter, MockResponse};
    use crate::ai::types::{AiAnomaly, AiEvent, Severity};
    use crate::evidence::schema::LogType;

    fn test_request() -> AiAnalysisRequest {
        let now = Utc::now();

        AiAnalysisRequest {
            analysis_id: "A-001".to_string(),
            host: "test-host".to_string(),
            time_window_start: now,
            time_window_end: now,
            events: Vec::new(),
        }
    }

    fn test_event(id: &str) -> AiEvent {
        AiEvent {
            event_id: id.to_string(),
            timestamp: Utc::now(),
            log_type: LogType::AccessAllowed,
            epoch: 1,
            user: "root".to_string(),
            pid: 1234,
            action: "RENAME".to_string(),
            binary: "/usr/bin/mv".to_string(),
            script_path: None,
            applet: None,
            args: None,
            target_path: "/data/file".to_string(),
            target_kind: "file".to_string(),
            new_path: Some("/data/file.enc".to_string()),
            remote_client: None,
            rule: None,
            ticket_id: None,
        }
    }

    fn test_anomaly() -> AiAnomaly {
        AiAnomaly {
            severity: Severity::High,
            attack_type: Some("ransomware".to_string()),
            summary: "Mass file rename detected".to_string(),
            explanation: "Suspicious rename activity".to_string(),
            evidence_event_ids: vec!["evt-001".to_string(), "evt-002".to_string()],
            confidence_score: 0.95,
        }
    }

    #[tokio::test]
    async fn test_no_anomaly() {
        let provider = Arc::new(MockAdapter::new());
        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        let result = engine.analyze(&test_request()).await.unwrap();

        assert_eq!(engine.provider_name(), "mock");
        assert_eq!(result.analysis_id, "A-001");
        assert!(result.anomalies.is_empty());
    }

    #[tokio::test]
    async fn test_with_anomaly() {
        let provider = Arc::new(MockAdapter::new());

        provider.set_response(MockResponse::Success(vec![test_anomaly()]));

        // providerをcloneしてEngineに渡す
        let engine = AiAnalysisEngine::new(provider.clone(), AggregatorConfig::default());

        let mut request = test_request();
        request.events = vec![test_event("evt-001"), test_event("evt-002")];

        let result = engine.analyze(&request).await.unwrap();

        // AI分析結果の検証
        assert_eq!(result.anomalies.len(), 1);
        assert_eq!(result.analysis_id, request.analysis_id);

        // Providerに渡された集約イベントの検証
        let provider_request = provider.last_request().unwrap();

        assert_eq!(provider_request.events.len(), 1);
        assert_eq!(provider_request.events[0].event_count, 2);
    }

    #[tokio::test]
    async fn test_invalid_evidence() {
        let provider = Arc::new(MockAdapter::new());

        provider.set_response(MockResponse::Success(vec![test_anomaly()]));

        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        // 根拠イベントを含まない要求
        let request = test_request();

        let result = engine.analyze(&request).await;

        assert!(matches!(result, Err(AiError::Validation(_))));
    }

    #[tokio::test]
    async fn test_invalid_confidence() {
        let provider = Arc::new(MockAdapter::new());

        let mut anomaly = test_anomaly();
        anomaly.confidence_score = 1.5;

        provider.set_response(MockResponse::Success(vec![anomaly]));

        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        let mut request = test_request();
        request.events = vec![test_event("evt-001"), test_event("evt-002")];

        let result = engine.analyze(&request).await;

        assert!(matches!(result, Err(AiError::Validation(_))));
    }

    #[tokio::test]
    async fn test_provider_timeout() {
        let provider = Arc::new(MockAdapter::new());
        provider.set_response(MockResponse::Timeout);

        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        let result = engine.analyze(&test_request()).await;

        assert!(matches!(result, Err(AiError::Timeout)));
    }

    #[tokio::test]
    async fn test_invalid_request() {
        let provider = Arc::new(MockAdapter::new());
        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        let mut request = test_request();
        request.analysis_id.clear();

        let result = engine.analyze(&request).await;

        assert!(matches!(result, Err(AiError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn test_operational_context() {
        let provider = Arc::new(MockAdapter::new());
        let engine = AiAnalysisEngine::new(provider.clone(), AggregatorConfig::default());

        let context = AiOperationalContext {
            description: "Monthly database backup".to_string(),
        };

        engine.set_operational_context(&context).await.unwrap();

        let saved = provider.operational_context().unwrap();

        assert_eq!(saved.description, context.description);
    }

    #[tokio::test]
    async fn test_event_sorting() {
        use chrono::Duration;

        let provider = Arc::new(MockAdapter::new());
        let engine = AiAnalysisEngine::new(provider.clone(), AggregatorConfig::default());

        let now = Utc::now();
        let mut request = test_request();

        let mut later = test_event("evt-later");
        later.timestamp = now;

        let mut earlier = test_event("evt-earlier");
        earlier.timestamp = now - Duration::seconds(10);

        // 集約されないよう、操作を変える
        earlier.action = "UNLINK".to_string();

        request.events = vec![later, earlier];

        engine.analyze(&request).await.unwrap();

        let provider_request = provider.last_request().unwrap();

        assert_eq!(provider_request.events.len(), 2);
        assert_eq!(
            provider_request.events[0].evidence_event_ids[0],
            "evt-earlier"
        );
        assert_eq!(
            provider_request.events[1].evidence_event_ids[0],
            "evt-later"
        );
    }

    #[tokio::test]
    async fn test_engine_aggregation() {
        let provider = Arc::new(MockAdapter::new());
        let engine = AiAnalysisEngine::new(provider.clone(), AggregatorConfig::default());

        let mut request = test_request();

        request.events = (0..20)
            .map(|i| {
                let mut event = test_event(&format!("evt-{i:03}"));
                event.target_path = format!("/data/file_{i:03}");
                event
            })
            .collect();

        engine.analyze(&request).await.unwrap();

        let provider_request = provider.last_request().unwrap();

        assert_eq!(provider_request.events.len(), 1);
        assert_eq!(provider_request.events[0].event_count, 20);
        assert_eq!(provider_request.events[0].unique_target_count, 20);
    }

    #[tokio::test]
    async fn test_invalid_non_representative_evidence() {
        let provider = Arc::new(MockAdapter::new());

        let mut anomaly = test_anomaly();
        anomaly.evidence_event_ids = vec!["evt-010".to_string()];

        provider.set_response(MockResponse::Success(vec![anomaly]));

        let engine = AiAnalysisEngine::new(provider.clone(), AggregatorConfig::default());

        let mut request = test_request();

        request.events = (0..20)
            .map(|i| {
                let mut event = test_event(&format!("evt-{i:03}"));
                event.target_path = format!("/data/file_{i:03}");
                event
            })
            .collect();

        let result = engine.analyze(&request).await;

        // evt-010 は元イベントに存在するが、
        // AIに提示した代表イベントIDには含まれない
        assert!(matches!(result, Err(AiError::Validation(_))));

        let provider_request = provider.last_request().unwrap();

        assert_eq!(provider_request.events.len(), 1);

        assert!(!provider_request.events[0]
            .evidence_event_ids
            .contains(&"evt-010".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires local Ollama server and qwen3:1.7b"]
    async fn test_ollama_integration() {
        use crate::ai::adapters::ollama::OllamaAdapter;
        use std::time::Duration;

        let provider = Arc::new(
            OllamaAdapter::new(
                "http://127.0.0.1:11434",
                "qwen3:1.7b",
                Duration::from_secs(120),
                build_system_prompt(&PromptConfig::default()),
                None,
            )
            .unwrap(),
        );

        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        let mut request = test_request();
        request.events = vec![test_event("evt-001"), test_event("evt-002")];

        let result = engine.analyze(&request).await.unwrap();

        println!("{}", serde_json::to_string_pretty(&result).unwrap());

        assert_eq!(result.analysis_id, request.analysis_id);
    }

    #[tokio::test]
    #[ignore = "requires local Ollama server and qwen3:1.7b"]
    async fn test_ollama_mass_rename() {
        use crate::ai::adapters::ollama::OllamaAdapter;
        use chrono::Duration as ChronoDuration;
        use std::time::Duration as StdDuration;

        const EVENTS_NUM: i64 = 20;

        let provider = Arc::new(
            OllamaAdapter::new(
                "http://127.0.0.1:11434",
                "qwen3:1.7b",
                StdDuration::from_secs(180),
                build_system_prompt(&PromptConfig::default()),
                None,
            )
            .unwrap(),
        );

        let engine = AiAnalysisEngine::new(provider, AggregatorConfig::default());

        let mut request = test_request();
        let start = Utc::now();

        request.time_window_start = start;
        request.time_window_end = start + ChronoDuration::seconds(60);

        request.events = (0..EVENTS_NUM)
            .map(|i| {
                let mut event = test_event(&format!("evt-{i:03}"));

                event.timestamp = start + ChronoDuration::milliseconds(i * 500);

                event.target_path = format!("/data/documents/file_{i:03}.txt");

                event.new_path = Some(format!("/data/documents/file_{i:03}.enc"));

                event
            })
            .collect();

        let result = engine.analyze(&request).await.unwrap();

        println!("{}", serde_json::to_string_pretty(&result).unwrap());

        assert_eq!(result.analysis_id, request.analysis_id);
    }
}
