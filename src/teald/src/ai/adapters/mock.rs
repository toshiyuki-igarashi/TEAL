// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::sync::RwLock;

use async_trait::async_trait;

use crate::ai::error::AiError;
use crate::ai::provider::AiProvider;
use crate::ai::types::{
    AiAnalysisRequest,
    AiAnalysisResult,
    AiAnomaly,
    AiOperationalContext,
};

/// MockAdapter の応答モード
#[derive(Debug, Clone)]
pub enum MockResponse {
    /// 指定された異常一覧を返す
    Success(Vec<AiAnomaly>),

    /// APIタイムアウトを模擬
    Timeout,

    /// API利用制限超過を模擬
    RateLimited,

    /// プロバイダー利用不能を模擬
    Unavailable,
}

/// テスト用 AI プロバイダー
pub struct MockAdapter {
    /// AI分析の応答モード
    response: RwLock<MockResponse>,

    /// 運用ルール
    operational_context: RwLock<Option<AiOperationalContext>>,
}

impl MockAdapter {
    pub fn new() -> Self {
        Self {
            response: RwLock::new(
                MockResponse::Success(Vec::new())
            ),
            operational_context: RwLock::new(None),
        }
    }

    /// Mock の応答モードを設定
    pub fn set_response(&self, response: MockResponse) {
        *self.response.write().unwrap() = response;
    }

    /// 設定済み運用コンテキストを取得
    pub fn operational_context(
        &self,
    ) -> Option<AiOperationalContext> {
        self.operational_context
            .read()
            .unwrap()
            .clone()
    }
}

impl Default for MockAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AiProvider for MockAdapter {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn set_operational_context(
        &self,
        context: &AiOperationalContext,
    ) -> Result<(), AiError> {
        *self.operational_context
            .write()
            .unwrap() = Some(context.clone());

        Ok(())
    }

    async fn analyze(
        &self,
        request: &AiAnalysisRequest,
    ) -> Result<AiAnalysisResult, AiError> {
        // ロック保持中に await しないよう、応答モードをコピーする
        let response = self.response
            .read()
            .unwrap()
            .clone();

        match response {
            MockResponse::Success(anomalies) => {
                Ok(AiAnalysisResult {
                    analysis_id: request.analysis_id.clone(),
                    anomalies,
                })
            }

            MockResponse::Timeout => Err(AiError::Timeout),

            MockResponse::RateLimited => {
                Err(AiError::RateLimited {
                    retry_after: None,
                })
            }

            MockResponse::Unavailable => {
                Err(AiError::Unavailable(
                    "Mock provider unavailable".to_string()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

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

    #[tokio::test]
    async fn test_no_anomaly() {
        let mock = MockAdapter::new();
        let request = test_request();

        let result = mock.analyze(&request).await.unwrap();

        assert_eq!(mock.name(), "mock");
        assert_eq!(result.analysis_id, "A-001");
        assert!(result.anomalies.is_empty());
    }

    #[tokio::test]
    async fn test_timeout() {
        let mock = MockAdapter::new();
        mock.set_response(MockResponse::Timeout);

        let result = mock.analyze(&test_request()).await;

        assert!(matches!(result, Err(AiError::Timeout)));
    }

    #[tokio::test]
    async fn test_operational_context() {
        let mock = MockAdapter::new();

        let context = AiOperationalContext {
            description: "Monthly database backup".to_string(),
        };

        mock.set_operational_context(&context)
            .await
            .unwrap();

        let saved = mock.operational_context().unwrap();

        assert_eq!(
            saved.description,
            "Monthly database backup"
        );
    }

    #[tokio::test]
    async fn test_with_anomalies() {
        let mock = MockAdapter::new();
        let anomalies = vec![AiAnomaly {
            severity: crate::ai::types::Severity::High,
            attack_type: Some("ransomware".to_string()),
            summary: "Mass file rename detected".to_string(),
            explanation: "Multiple .enc files created within 1 minute".to_string(),
            evidence_event_ids: vec!["evt-001".to_string(), "evt-002".to_string()],
            confidence_score: 0.95,
        }];

        mock.set_response(MockResponse::Success(anomalies));

        let request = test_request();
        let result = mock.analyze(&request).await.unwrap();

        assert_eq!(result.anomalies.len(), 1);
        assert_eq!(result.anomalies[0].attack_type.as_deref(), Some("ransomware"));
        assert_eq!(result.anomalies[0].evidence_event_ids.len(), 2);
        assert_eq!(result.analysis_id, request.analysis_id);

        assert!(matches!(
            result.anomalies[0].severity,
            crate::ai::types::Severity::High
        ));

        assert_eq!(
            result.anomalies[0].evidence_event_ids,
            vec!["evt-001", "evt-002"]
        );

        assert_eq!(
            result.anomalies[0].confidence_score,
            0.95
        );
    }

    #[tokio::test]
    async fn test_rate_limited() {
        let mock = MockAdapter::new();
        mock.set_response(MockResponse::RateLimited);

        let result = mock.analyze(&test_request()).await;

        assert!(matches!(
            result,
            Err(AiError::RateLimited { retry_after: None })
        ));
    }

    #[tokio::test]
    async fn test_unavailable() {
        let mock = MockAdapter::new();
        mock.set_response(MockResponse::Unavailable);

        let result = mock.analyze(&test_request()).await;

        assert!(matches!(
            result,
            Err(AiError::Unavailable(_))
        ));
    }
}
