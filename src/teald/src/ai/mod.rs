// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

pub mod adapters;
pub mod aggregator;
pub mod collector;
pub mod engine;
pub mod error;
pub mod provider;
pub mod results;
pub mod types;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use self::adapters::gemini::GeminiAdapter;
use self::adapters::groq::GroqAdapter;
use self::adapters::ollama::OllamaAdapter;
use self::collector::AiCollectorConfig;
use self::engine::AiAnalysisEngine;
use self::provider::AiProvider;

pub const AI_CONFIG_PATH: &str = "/etc/teal.d/ai.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiConfig {
    pub version: String,
    pub enabled: bool,
    pub provider: String,
    pub ollama: Option<OllamaConfig>,
    pub groq: Option<CloudConfig>,
    pub gemini: Option<CloudConfig>,
    pub collector: CollectorConfig,
    #[serde(default)]
    pub prompt: PromptConfig,
    #[serde(default)]
    pub aggregator: AggregatorConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OllamaConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub temperature: Option<f32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudConfig {
    pub model: String,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub temperature: Option<f32>,
}

pub fn default_temperature() -> f32 {
    0.1
}

pub fn validate_temperature(value: Option<f32>) -> Result<(), String> {
    if let Some(t) = value {
        if !t.is_finite() || !(0.0..=1.0).contains(&t) {
            return Err("AI temperature must be between 0.0 and 1.0".into());
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub window_seconds: u64,
    pub max_events: usize,
    pub event_queue_capacity: usize,
    pub analysis_queue_capacity: usize,
}

/// Curated few-shot input/output example. Not an AI-generated instruction.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptExample {
    pub description: String,
    pub input: serde_json::Value,
    pub expected: serde_json::Value,
}

/// Reject malformed or excessively large examples at configuration load time.
fn deserialize_examples<'de, D>(deserializer: D) -> Result<Vec<PromptExample>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let examples = Vec::<PromptExample>::deserialize(deserializer)?;
    if examples.len() > 8 {
        return Err(D::Error::custom("prompt.examples exceeds 8 entries"));
    }
    for example in &examples {
        if example.description.trim().is_empty() || example.description.len() > 256 {
            return Err(D::Error::custom("prompt example description is invalid"));
        }
        if !example.input.is_object() || !example.expected.is_object() {
            return Err(D::Error::custom(
                "prompt example input/expected must be objects",
            ));
        }
        let input = serde_json::to_string(&example.input).map_err(D::Error::custom)?;
        let expected = serde_json::to_string(&example.expected).map_err(D::Error::custom)?;
        if input.len() + expected.len() > 16 * 1024 {
            return Err(D::Error::custom("prompt example exceeds 16 KiB"));
        }
        // Reuse the same structural validation as the actual model output.
        if crate::ai::adapters::common::parse_output("example", &expected).is_err() {
            return Err(D::Error::custom(
                "prompt example expected output does not match AI output schema",
            ));
        }
    }
    Ok(examples)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptConfig {
    #[serde(default)]
    pub system_role: String,

    #[serde(default)]
    pub custom_rules: Vec<String>,

    #[serde(default, deserialize_with = "deserialize_examples")]
    pub examples: Vec<PromptExample>,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatorConfig {
    pub max_gap_ms: u64,
    pub max_group_events: u32,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            max_gap_ms: u64::MAX,
            max_group_events: u32::MAX,
        }
    }
}

pub struct AiRuntime {
    pub engine: Arc<AiAnalysisEngine>,
    pub collector: AiCollectorConfig,
    pub event_queue_capacity: usize,
    pub analysis_queue_capacity: usize,
}

pub fn init_ai() -> Result<Option<AiRuntime>, String> {
    init_ai_from_path(Path::new(AI_CONFIG_PATH))
}

pub fn init_ai_from_path(path: &Path) -> Result<Option<AiRuntime>, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot read AI config {}: {e}", path.display())),
    };
    let config: AiConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid AI config {}: {e}", path.display()))?;
    build_ai_runtime(config)
}

fn build_ai_runtime(config: AiConfig) -> Result<Option<AiRuntime>, String> {
    if config.version != "1.0" {
        return Err(format!("Unsupported AI config version: {}", config.version));
    }
    if !config.enabled {
        return Ok(None);
    }
    let c = config.collector;
    if c.window_seconds == 0
        || c.max_events == 0
        || c.event_queue_capacity == 0
        || c.analysis_queue_capacity == 0
    {
        return Err("AI collector settings must be greater than zero".into());
    }
    if config.aggregator.max_group_events == 0 {
        return Err("AI aggregator.max_group_events must be greater than zero".into());
    }
    let system_prompt = adapters::common::build_system_prompt(&config.prompt);

    let provider: Arc<dyn AiProvider> = match config.provider.as_str() {
        "ollama" => {
            let o = config.ollama.ok_or("Missing ollama configuration")?;
            if o.endpoint.trim().is_empty() || o.model.trim().is_empty() || o.timeout_seconds == 0 {
                return Err("Invalid Ollama endpoint, model or timeout_seconds".into());
            }
            let adapter = OllamaAdapter::new(
                &o.endpoint,
                &o.model,
                Duration::from_secs(o.timeout_seconds),
                system_prompt,
                o.temperature,
            )
            .map_err(|e| format!("Ollama provider initialization failed: {e}"))?;
            Arc::new(adapter)
        }
        "groq" => {
            let c = config.groq.ok_or("Missing groq configuration")?;

            Arc::new(
                GroqAdapter::new(
                    &c.model,
                    Duration::from_secs(c.timeout_seconds),
                    system_prompt,
                    c.temperature,
                )
                .map_err(|e| format!("Groq provider initialization failed: {e}"))?,
            )
        }
        "gemini" => {
            let c = config.gemini.ok_or("Missing gemini configuration")?;
            Arc::new(
                GeminiAdapter::new(
                    &c.model,
                    Duration::from_secs(c.timeout_seconds),
                    system_prompt,
                    c.temperature,
                )
                .map_err(|e| format!("Gemini provider initialization failed: {e}"))?,
            )
        }
        other => return Err(format!("Unsupported AI provider: {other}")),
    };

    Ok(Some(AiRuntime {
        engine: Arc::new(AiAnalysisEngine::new(provider, config.aggregator)),
        collector: AiCollectorConfig {
            window: Duration::from_secs(c.window_seconds),
            max_events: c.max_events,
        },
        event_queue_capacity: c.event_queue_capacity,
        analysis_queue_capacity: c.analysis_queue_capacity,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(enabled: bool) -> AiConfig {
        AiConfig {
            version: "1.0".into(),
            enabled,
            provider: "ollama".into(),
            groq: None,
            gemini: None,
            ollama: Some(OllamaConfig {
                endpoint: "http://127.0.0.1:11434".into(),
                model: "qwen3:1.7b".into(),
                timeout_seconds: 120,
                temperature: None,
            }),
            collector: CollectorConfig {
                window_seconds: 60,
                max_events: 4096,
                event_queue_capacity: 8192,
                analysis_queue_capacity: 2,
            },
            prompt: PromptConfig::default(),
            aggregator: AggregatorConfig::default(),
        }
    }

    #[test]
    fn disabled_returns_none() {
        assert!(build_ai_runtime(config(false)).unwrap().is_none());
    }

    #[test]
    fn enabled_builds_runtime() {
        let runtime = build_ai_runtime(config(true)).unwrap().unwrap();
        assert_eq!(runtime.engine.provider_name(), "ollama");
        assert_eq!(runtime.event_queue_capacity, 8192);
        assert_eq!(runtime.analysis_queue_capacity, 2);
    }

    #[test]
    fn invalid_capacity_is_rejected() {
        let mut cfg = config(true);
        cfg.collector.event_queue_capacity = 0;
        assert!(build_ai_runtime(cfg).is_err());
    }

    #[test]
    fn unsupported_provider_is_rejected() {
        let mut cfg = config(true);
        cfg.provider = "unknown".into();
        assert!(build_ai_runtime(cfg).is_err());
    }
}
