// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use async_trait::async_trait;

use crate::ai::types::{AiAnalysisRequest, AiAnalysisResult, AiOperationalContext};
use crate::ai::error::AiError;

#[async_trait]
pub trait AiProvider: Send + Sync {
    /// プロバイダー名（"mock", "ollama", "groq", "gemini" など）
    fn name(&self) -> &'static str;

    /// 運用ルールやホストプロファイル等の前提コンテキストを設定
    async fn set_operational_context(
        &self,
        context: &AiOperationalContext,
    ) -> Result<(), AiError>;

    /// イベント履歴の異常検出を実行
    async fn analyze(
        &self,
        request: &AiAnalysisRequest,
    ) -> Result<AiAnalysisResult, AiError>;
}
