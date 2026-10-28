// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::ai::engine::AiAnalysisOutcome;
use crate::ai::types::{AiAnalysisRequest, AiAnalysisResult};

/// TEAL監査ログ本体とは別の、AI分析結果用JSON Linesファイル。
/// 配置先ディレクトリは事前に適切な権限で作成すること。
pub const AI_RESULTS_PATH: &str = "/var/log/teal/ai-results.jsonl";

#[derive(Debug, Serialize)]
pub struct AiStoredAnalysis {
    pub version: &'static str,
    pub recorded_at: DateTime<Utc>,
    pub provider: String,
    pub host: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub input_event_count: usize,
    pub aggregated_event_count: usize,
    pub result: AiAnalysisResult,
    /// aggregation_id -> 集約元イベントIDの全件
    pub source_event_ids: HashMap<String, Vec<String>>,
}

impl AiStoredAnalysis {
    pub fn from_outcome(
        request: &AiAnalysisRequest,
        provider_name: &str,
        outcome: AiAnalysisOutcome,
    ) -> Self {
        Self {
            version: "1.0",
            recorded_at: Utc::now(),
            provider: provider_name.to_string(),
            host: request.host.clone(),
            time_window_start: request.time_window_start,
            time_window_end: request.time_window_end,
            input_event_count: request.events.len(),
            aggregated_event_count: outcome.aggregated_event_count,
            result: outcome.result,
            source_event_ids: outcome.source_event_ids,
        }
    }
}

pub fn append_result(record: &AiStoredAnalysis) -> io::Result<()> {
    append_result_to(Path::new(AI_RESULTS_PATH), record)
}

fn append_result_to(path: &Path, record: &AiStoredAnalysis) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_data()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::AiAnalysisResult;

    #[test]
    fn write_record_and_provenance() {
        let path =
            std::env::temp_dir().join(format!("teal-ai-result-{}.jsonl", uuid::Uuid::new_v4()));
        let now = Utc::now();
        let record = AiStoredAnalysis {
            version: "1.0",
            recorded_at: now,
            provider: "mock".into(),
            host: "test-host".into(),
            time_window_start: now,
            time_window_end: now,
            input_event_count: 2,
            aggregated_event_count: 1,
            result: AiAnalysisResult {
                analysis_id: "test-1".into(),
                anomalies: vec![],
            },
            source_event_ids: HashMap::from([(
                "test-1-agg-1".into(),
                vec!["e1".into(), "e2".into()],
            )]),
        };
        append_result_to(&path, &record).unwrap();
        let line = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(json["result"]["analysis_id"], "test-1");
        assert_eq!(json["source_event_ids"]["test-1-agg-1"][1], "e2");
        std::fs::remove_file(path).unwrap();
    }
}
