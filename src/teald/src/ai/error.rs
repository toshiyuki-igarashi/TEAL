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
    #[error(
        "AI rate limit exceeded{}",
        .retry_after
            .map(|d| format!(" (retry after {d:?})"))
            .unwrap_or_default()
    )]
    RateLimited {
        retry_after: Option<Duration>,
    },

    /// AI応答の形式・内容が不正
    #[error("Invalid AI response: {0}")]
    InvalidResponse(String),

    /// TEALからの分析要求が不正
    #[error("Invalid AI request: {0}")]
    InvalidRequest(String),

    /// API認証エラー
    #[error("AI provider authentication failed: {0}")]
    Authentication(String),

    /// その他のプロバイダー固有エラー
    #[error("AI provider error: {0}")]
    Provider(String),
}
