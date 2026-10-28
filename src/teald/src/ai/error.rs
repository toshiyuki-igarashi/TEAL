// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    /// プロバイダーに接続できない、または利用不能
    #[error("AI provider is unavailable: {0}")]
    Unavailable(String),

    /// API応答がタイムアウト
    #[error("AI request timed out")]
    Timeout,

    /// API利用制限超過
    #[error("AI rate limit exceeded{}", .retry_after.map(|d| format!(" (retry after {d:?})")).unwrap_or_default())]
    RateLimited { retry_after: Option<Duration> },

    /// AI応答の形式・内容が不正
    #[error("Invalid AI response: {0}")]
    InvalidResponse(String),

    /// 構造化されたAI回答検証エラー（回答本文・監査データは含めない）
    #[error("AI response validation failed: {0}")]
    Validation(ValidationFailure),

    /// TEALからの分析要求が不正
    #[error("Invalid AI request: {0}")]
    InvalidRequest(String),

    /// API認証エラー
    #[error("AI provider authentication failed: {0}")]
    Authentication(String),

    /// 構造化されたProvider障害
    #[error("AI provider failed: {0}")]
    ProviderFailure(ProviderFailure),

    /// その他のプロバイダー固有エラー
    #[error("AI provider error: {0}")]
    Provider(String),
}

/// ログ・評価レポートに安全に記録できる回答検証失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    InvalidJson,
    MissingField,
    InvalidFieldType,
    InvalidFieldValue,
    InvalidConfidence,
    MissingEvidence,
    InvalidEvidenceCount,
    UnknownEvidenceId,
    AnalysisIdMismatch,
}

impl ValidationCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::MissingField => "missing_field",
            Self::InvalidFieldType => "invalid_field_type",
            Self::InvalidFieldValue => "invalid_field_value",
            Self::InvalidConfidence => "invalid_confidence",
            Self::MissingEvidence => "missing_evidence",
            Self::InvalidEvidenceCount => "invalid_evidence_count",
            Self::UnknownEvidenceId => "unknown_evidence_id",
            Self::AnalysisIdMismatch => "analysis_id_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidationFailure {
    pub code: ValidationCode,
    /// 定義済みフィールド名のみ。AIが生成した値やパスは保持しない。
    pub field: Option<String>,
    pub anomaly_index: Option<usize>,
}

impl ValidationFailure {
    pub fn new(
        code: ValidationCode,
        field: Option<&'static str>,
        anomaly_index: Option<usize>,
    ) -> Self {
        Self {
            code,
            field: field.map(str::to_owned),
            anomaly_index,
        }
    }
}

impl std::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.code)?;
        if let Some(field) = &self.field {
            write!(f, " field={field}")?;
        }
        if let Some(index) = self.anomaly_index {
            write!(f, " anomaly_index={index}")?;
        }
        Ok(())
    }
}

/// AI Provider障害の分類。機密情報を含まない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorCode {
    Timeout,
    RateLimited,
    ServerError,
    NetworkError,
    InvalidResponse,
    AuthenticationError,
    Other,
}

impl ProviderErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
            Self::NetworkError => "network_error",
            Self::InvalidResponse => "invalid_response",
            Self::AuthenticationError => "authentication_error",
            Self::Other => "other",
        }
    }
}

/// ログ・評価レポートに安全に記録できるProvider障害情報。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderFailure {
    pub code: ProviderErrorCode,
    pub http_status: Option<u16>,
}

impl std::fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.code)?;

        if let Some(status) = self.http_status {
            write!(f, " http_status={status}")?;
        }

        Ok(())
    }
}
