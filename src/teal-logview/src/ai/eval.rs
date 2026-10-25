// SPDX-License-Identifier: MIT
/*
 * TEAL logview (teal-logview)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use teald::ai::adapters::gemini::GeminiAdapter;
use teald::ai::adapters::groq::GroqAdapter;
use teald::ai::adapters::ollama::OllamaAdapter;
use teald::ai::adapters::common;
use teald::ai::engine::AiAnalysisEngine;
use teald::ai::provider::AiProvider;
use teald::ai::types::{AiAnalysisRequest, AiAnalysisResult, AiEvent};
use teald::ai::error::AiError;
use teald::ai::AiConfig;

#[derive(Args, Debug)]
pub struct EvalArgs {
    /// Path to the test dataset (JSONL of AiEvent)
    #[arg(long)]
    pub dataset: PathBuf,

    /// Path to the AI config file (e.g. /etc/teal.d/ai.json)
    #[arg(long)]
    pub config: PathBuf,

    /// Output path for evaluation report (JSON format); fails if exists
    #[arg(long = "out", alias = "out-result")]
    pub out: PathBuf,

    /// Target host identifier in analysis request
    #[arg(long, default_value = "eval-host")]
    pub host: String,
}

/// One analysis result per collector-sized replay batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvalBatchReport {
    pub batch_index: usize,
    pub analysis_id: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub input_event_count: usize,
    pub aggregated_event_count: Option<usize>,
    pub target_event_ids: Vec<String>,
    pub elapsed_ms: u64,

    pub result: Option<AiAnalysisResult>,

    #[serde(default)]
    pub error: Option<EvalBatchError>,

    pub source_event_ids: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvalBatchError {
    pub error_type: String,
    pub code: Option<String>,
    pub field: Option<String>,
    pub anomaly_index: Option<usize>,
    #[serde(default)]
    pub http_status: Option<u16>,
}

/// Offline evaluation report with per-batch provenance.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvalReport {
    pub report_version: String,
    pub evaluated_at: DateTime<Utc>,
    pub provider_name: String,
    pub model_name: String,
    pub config_sha256: String,
    pub prompt_sha256: String,
    pub dataset_path: String,
    pub input_event_count: usize,
    pub aggregated_event_count: usize,
    pub batch_count: usize,
    pub elapsed_ms: u64,
    pub batches: Vec<EvalBatchReport>,
}

fn calculate_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("sha256:{:x}", hasher.finalize())
}

/// Event-time replay. The window origin is the earliest event, NOT wall clock.
/// A batch is flushed on max_events or when the next event falls outside its
/// fixed-width window. Clock gaps do not create empty batches.
fn split_batches(events: Vec<AiEvent>, window_seconds: u64, max_events: usize) -> Result<Vec<Vec<AiEvent>>> {
    if window_seconds == 0 || max_events == 0 {
        bail!("collector.window_seconds and collector.max_events must be greater than zero");
    }
    let window = chrono::Duration::from_std(Duration::from_secs(window_seconds))
        .context("Invalid collector.window_seconds")?;
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut window_start = None;

    for event in events {
        if let Some(start) = window_start {
            if event.timestamp >= start + window || current.len() >= max_events {
                if !current.is_empty() {
                    batches.push(std::mem::take(&mut current));
                }
                // Reset the window on a flush (deterministic approximation of
                // collector's runtime interval and max_events behavior).
                window_start = Some(event.timestamp);
            }
        } else {
            window_start = Some(event.timestamp);
        }
        current.push(event);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    Ok(batches)
}

pub fn run(args: EvalArgs) -> Result<()> {
    let config_raw = fs::read(&args.config)
        .with_context(|| format!("Cannot read config file: {}", args.config.display()))?;
    let config_sha256 = calculate_sha256(&config_raw);
    let config: AiConfig = serde_json::from_slice(&config_raw)
        .with_context(|| format!("Invalid AI config: {}", args.config.display()))?;
    if config.aggregator.max_group_events == 0 {
        bail!("AI aggregator.max_group_events must be greater than zero");
    }

    let dataset_file = fs::File::open(&args.dataset)
        .with_context(|| format!("Cannot open dataset: {}", args.dataset.display()))?;
    let mut events = Vec::new();
    for (idx, line) in BufReader::new(dataset_file).lines().enumerate() {
        let line = line.with_context(|| format!("Cannot read dataset line {}", idx + 1))?;
        if line.trim().is_empty() { continue; }
        let event: AiEvent = serde_json::from_str(&line)
            .with_context(|| format!("Invalid AiEvent at line {}", idx + 1))?;
        events.push(event);
    }
    if events.is_empty() {
        bail!("Dataset contains no events: {}", args.dataset.display());
    }
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.event_id.cmp(&b.event_id)));
    let input_event_count = events.len();
    let batches = split_batches(events, config.collector.window_seconds, config.collector.max_events)?;
    let system_prompt = common::build_system_prompt(&config.prompt);
    let prompt_sha256 = calculate_sha256(system_prompt.as_bytes());

    let (provider, model_name): (Arc<dyn AiProvider>, String) = match config.provider.as_str() {
        "gemini" => {
            let g = config.gemini.context("Missing gemini config in ai.json")?;
            let model = g.model;
            (Arc::new(GeminiAdapter::new(&model, Duration::from_secs(g.timeout_seconds), system_prompt, g.temperature)?), model)
        }
        "groq" => {
            let g = config.groq.context("Missing groq config in ai.json")?;
            let model = g.model;
            (Arc::new(GroqAdapter::new(&model, Duration::from_secs(g.timeout_seconds), system_prompt, g.temperature)?), model)
        }
        "ollama" => {
            let o = config.ollama.context("Missing ollama config in ai.json")?;
            let model = o.model;
            (Arc::new(OllamaAdapter::new(&o.endpoint, &model, Duration::from_secs(o.timeout_seconds), system_prompt, o.temperature)?), model)
        }
        other => bail!("Unsupported provider in evaluation: {}", other),
    };
    let engine = AiAnalysisEngine::new(provider, config.aggregator);
    let provider_name = engine.provider_name().to_string();
    let runtime = tokio::runtime::Runtime::new().context("Cannot create Tokio runtime")?;
    let overall_start = Instant::now();
    let total_batches = batches.len();
    let mut batch_reports = Vec::with_capacity(total_batches);
    let mut aggregated_event_count = 0usize;

    eprintln!("[INFO] AI evaluation: provider={}, model={}, batches={}", provider_name, model_name, batches.len());
    for (index, batch_events) in batches.into_iter().enumerate() {
        let time_window_start = batch_events.first().expect("nonempty batch").timestamp;
        let time_window_end = batch_events.last().expect("nonempty batch").timestamp;
        let target_event_ids = batch_events.iter().map(|e| e.event_id.clone()).collect();
        let request = AiAnalysisRequest {
            analysis_id: format!("eval-{}", Uuid::new_v4()),
            host: args.host.clone(),
            time_window_start,
            time_window_end,
            events: batch_events,
        };

        let started = Instant::now();

        let outcome = runtime.block_on(
            engine.analyze_with_provenance(&request)
        );

        let elapsed_ms = started.elapsed().as_millis() as u64;

        match outcome {
            Ok(outcome) => {
                aggregated_event_count += outcome.aggregated_event_count;

                eprintln!(
                    "[INFO] Batch {}/{}: events={}, anomalies={}, elapsed={}ms",
                    index + 1,
                    total_batches,
                    request.events.len(),
                    outcome.result.anomalies.len(),
                    elapsed_ms
                );

                batch_reports.push(EvalBatchReport {
                    batch_index: index + 1,
                    analysis_id: request.analysis_id,
                    time_window_start,
                    time_window_end,
                    input_event_count: request.events.len(),
                    aggregated_event_count: Some(outcome.aggregated_event_count),
                    target_event_ids,
                    elapsed_ms,
                    result: Some(outcome.result),
                    error: None,
                    source_event_ids: outcome.source_event_ids,
                });
            }

            Err(error) => {
                let batch_error = match &error {
                    AiError::Validation(failure) => EvalBatchError {
                        error_type: "validation_failed".into(),
                        code: Some(failure.code.as_str().to_owned()),
                        field: failure.field.clone(),
                        anomaly_index: failure.anomaly_index,
                        http_status: None,
                    },
                    AiError::ProviderFailure(failure) => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some(failure.code.as_str().to_owned()),
                        field: None,
                        anomaly_index: None,
                        http_status: failure.http_status,
                    },
                    AiError::Timeout => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some("timeout".into()),
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                    AiError::RateLimited { .. } => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some("rate_limited".into()),
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                    AiError::Authentication(_) => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some("authentication_error".into()),
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                    AiError::InvalidResponse(_) => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some("invalid_response".into()),
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                    AiError::InvalidRequest(_) => EvalBatchError {
                        error_type: "invalid_request".into(),
                        code: None,
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                    AiError::Unavailable(_) => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some("other".into()),
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                    AiError::Provider(_) => EvalBatchError {
                        error_type: "provider_failed".into(),
                        code: Some("other".into()),
                        field: None,
                        anomaly_index: None,
                        http_status: None,
                    },
                };

                eprintln!(
                    "[WARN] Batch {}/{} failed: type={}, code={:?}, http_status={:?}, field={:?}",
                    index + 1,
                    total_batches,
                    batch_error.error_type,
                    batch_error.code,
                    batch_error.http_status,
                    batch_error.field,
                );

                batch_reports.push(EvalBatchReport {
                    batch_index: index + 1,
                    analysis_id: request.analysis_id,
                    time_window_start,
                    time_window_end,
                    input_event_count: request.events.len(),
                    aggregated_event_count: None,
                    target_event_ids,
                    elapsed_ms,
                    result: None,
                    error: Some(batch_error),
                    source_event_ids: HashMap::new(),
                });
            }
        }
    }

    let report = EvalReport {
        report_version: "1.2".to_owned(),
        evaluated_at: Utc::now(),
        provider_name,
        model_name,
        config_sha256,
        prompt_sha256,
        dataset_path: args.dataset.display().to_string(),
        input_event_count,
        aggregated_event_count,
        batch_count: batch_reports.len(),
        elapsed_ms: overall_start.elapsed().as_millis() as u64,
        batches: batch_reports,
    };

    let output = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&args.out)
        .with_context(|| format!("Cannot create eval output file (must not exist): {}", args.out.display()))?;
    let result = (|| -> Result<()> {
        let mut writer = BufWriter::new(output);
        serde_json::to_writer_pretty(&mut writer, &report)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&args.out);
        return Err(error);
    }
    eprintln!("[INFO] AI evaluation saved: {}, batches={}, events={}",
        args.out.display(), report.batch_count, report.input_event_count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use teald::evidence::schema::LogType;

    fn event(second: u32, id: &str) -> AiEvent {
        AiEvent {
            event_id: id.into(),
            timestamp: DateTime::parse_from_rfc3339(&format!("2026-10-21T00:00:{second:02}Z"))
                .unwrap().with_timezone(&Utc),
            log_type: LogType::AccessAllowed,
            epoch: 1,
            user: "root".into(),
            pid: 1,
            action: "READ".into(),
            binary: "/bin/cat".into(),
            script_path: None,
            applet: None,
            args: None,
            target_path: "/etc/passwd".into(),
            target_kind: "file".into(),
            new_path: None,
            remote_client: None,
            rule: None,
            ticket_id: None,
        }
    }

    #[test]
    fn batches_split_by_time_and_count() {
        let batches = split_batches(vec![
            event(0, "a"), event(1, "b"), event(2, "c"), event(12, "d"),
        ], 10, 2).unwrap();
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 1);
        assert_eq!(batches[2].len(), 1);
    }

    #[test]
    fn invalid_collector_limits_rejected() {
        assert!(split_batches(vec![event(0, "a")], 0, 2).is_err());
        assert!(split_batches(vec![event(0, "a")], 10, 0).is_err());
    }
}
