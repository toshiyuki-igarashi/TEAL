// SPDX-License-Identifier: MIT
/*
 * TEAL logview (teal-logview)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use super::eval::EvalReport;
use teald::ai::types::AiAnomaly;

#[derive(Args, Debug)]
pub struct CompareArgs {
    /// Baseline evaluation report file (JSON)
    pub baseline: PathBuf,

    /// Candidate evaluation report file to compare (JSON)
    pub candidate: PathBuf,
}

/// Resolve each AI evidence ID to the original audit events represented by its
/// aggregation block. Evidence can be either an aggregation ID or a representative
/// original event ID contained in source_event_ids values.
fn original_evidence_key(
    evidence_ids: &[String],
    source_event_ids: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>> {
    if evidence_ids.is_empty() {
        bail!("Anomaly has no evidence event IDs");
    }

    let mut originals = Vec::new();
    for id in evidence_ids {
        // Prefer direct aggregation ID lookup when available.
        let sources = if let Some(sources) = source_event_ids.get(id) {
            sources
        } else {
            // The model may have returned a representative original event ID.
            // Resolve it to the containing aggregation block.
            let mut matches = source_event_ids.values()
                .filter(|sources| sources.iter().any(|source| source == id));
            let first = matches.next()
                .with_context(|| format!("No aggregation block contains evidence ID {id}"))?;
            if matches.next().is_some() {
                bail!("Evidence ID {id} belongs to multiple aggregation blocks");
            }
            first
        };
        if sources.is_empty() {
            bail!("Empty source_event_ids mapping for evidence ID {id}");
        }
        originals.extend(sources.iter().cloned());
    }
    originals.sort_unstable();
    originals.dedup();
    Ok(originals)
}

/// Collect anomaly/key pairs while keeping the batch-specific provenance.
fn collect_detections<'a>(report: &'a EvalReport) -> Result<Vec<(&'a AiAnomaly, Vec<String>)>> {
    let mut detections = Vec::new();
    for batch in &report.batches {
        for anomaly in &batch.result.anomalies {
            let key = original_evidence_key(
                &anomaly.evidence_event_ids,
                &batch.source_event_ids,
            ).with_context(|| format!(
                "Cannot resolve evidence in batch {} of report {}",
                batch.batch_index, report.dataset_path
            ))?;
            detections.push((anomaly, key));
        }
    }
    Ok(detections)
}

pub fn run(args: CompareArgs) -> Result<()> {
    let base_raw = fs::read_to_string(&args.baseline)
        .with_context(|| format!("Failed to read baseline report: {}", args.baseline.display()))?;
    let cand_raw = fs::read_to_string(&args.candidate)
        .with_context(|| format!("Failed to read candidate report: {}", args.candidate.display()))?;

    let base: EvalReport = serde_json::from_str(&base_raw)
        .with_context(|| "Failed to parse baseline JSON report")?;
    let cand: EvalReport = serde_json::from_str(&cand_raw)
        .with_context(|| "Failed to parse candidate JSON report")?;

    // Keep each anomaly associated with its own batch's provenance map.
    let base_detections = collect_detections(&base)?;
    let cand_detections = collect_detections(&cand)?;

    println!("================================================================================");
    println!(" TEAL AI Evaluation Comparison Report (v1.1 Multi-Batch)");
    println!("================================================================================");
    println!("Metric / Field          | Baseline                      | Candidate");
    println!("------------------------+-------------------------------+-------------------------------");
    println!("Provider                | {:<29} | {:<29}", base.provider_name, cand.provider_name);
    println!("Model                   | {:<29} | {:<29}", base.model_name, cand.model_name);
    println!("Total Elapsed Time      | {:<26} ms | {:<26} ms", base.elapsed_ms, cand.elapsed_ms);
    println!("Batch Count             | {:<29} | {:<29}", base.batch_count, cand.batch_count);
    println!("Input Events            | {:<29} | {:<29}", base.input_event_count, cand.input_event_count);
    println!("Aggregated Events       | {:<29} | {:<29}", base.aggregated_event_count, cand.aggregated_event_count);
    println!("Total Anomalies         | {:<29} | {:<29}", base_detections.len(), cand_detections.len());
    println!("Config SHA256           | {:<29} | {:<29}", &base.config_sha256[..16.min(base.config_sha256.len())], &cand.config_sha256[..16.min(cand.config_sha256.len())]);
    println!("Prompt SHA256           | {:<29} | {:<29}", &base.prompt_sha256[..16.min(base.prompt_sha256.len())], &cand.prompt_sha256[..16.min(cand.prompt_sha256.len())]);
    println!("================================================================================");

    // Compare original audit event sets, not aggregation IDs.
    let base_keys: HashSet<Vec<String>> = base_detections.iter()
        .map(|(_, key)| key.clone()).collect();
    let cand_keys: HashSet<Vec<String>> = cand_detections.iter()
        .map(|(_, key)| key.clone()).collect();

    let common_count = base_keys.intersection(&cand_keys).count();
    let dropped_count = base_keys.difference(&cand_keys).count();
    let new_count = cand_keys.difference(&base_keys).count();

    println!("\n[Detection Discrepancies]");
    println!("  * Common Detections  : {}", common_count);
    println!("  * Resolved / Dropped : {} (Possible false positives fixed OR missed detections)", dropped_count);
    println!("  * Newly Detected     : {} (Newly captured threats OR new false positives)", new_count);

    if dropped_count > 0 {
        println!("\n--- [Dropped in Candidate] ---");
        for (a, key) in &base_detections {
            if !cand_keys.contains(key) {
                println!("  - [{:?}] {} (Original evidence: {:?}, Score: {:.2})", a.severity, a.summary, key, a.confidence_score);
            }
        }
    }

    if new_count > 0 {
        println!("\n+++ [Newly Detected in Candidate] +++");
        for (a, key) in &cand_detections {
            if !base_keys.contains(key) {
                println!("  + [{:?}] {} (Original evidence: {:?}, Score: {:.2})", a.severity, a.summary, key, a.confidence_score);
            }
        }
    }

    println!("\n================================================================================");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_aggregate_ids_with_same_sources_match() {
        let baseline = HashMap::from([("agg-a".to_owned(), vec!["evt-2".into(), "evt-1".into()])]);
        let candidate = HashMap::from([("agg-b".to_owned(), vec!["evt-1".into(), "evt-2".into()])]);
        let left = original_evidence_key(&["agg-a".into()], &baseline).unwrap();
        let right = original_evidence_key(&["agg-b".into()], &candidate).unwrap();
        assert_eq!(left, right);
        assert_eq!(left, vec!["evt-1", "evt-2"]);
    }

    #[test]
    fn overlapping_sources_are_deduplicated() {
        let mapping = HashMap::from([
            ("agg-a".to_owned(), vec!["evt-1".into(), "evt-2".into()]),
            ("agg-b".to_owned(), vec!["evt-2".into(), "evt-3".into()]),
        ]);
        let key = original_evidence_key(&["agg-b".into(), "agg-a".into()], &mapping).unwrap();
        assert_eq!(key, vec!["evt-1", "evt-2", "evt-3"]);
    }

    #[test]
    fn representative_raw_event_id_expands_to_its_block() {
        let mapping = HashMap::from([("agg-a".to_owned(), vec!["evt-1".into(), "evt-2".into()])]);
        let key = original_evidence_key(&["evt-2".into()], &mapping).unwrap();
        assert_eq!(key, vec!["evt-1", "evt-2"]);
    }

    #[test]
    fn representative_and_aggregate_ids_are_equivalent() {
        let mapping = HashMap::from([("agg-a".to_owned(), vec!["evt-1".into(), "evt-2".into()])]);
        assert_eq!(
            original_evidence_key(&["agg-a".into()], &mapping).unwrap(),
            original_evidence_key(&["evt-1".into()], &mapping).unwrap(),
        );
    }

    #[test]
    fn ambiguous_representative_is_rejected() {
        let mapping = HashMap::from([
            ("agg-a".to_owned(), vec!["evt-1".into()]),
            ("agg-b".to_owned(), vec!["evt-1".into(), "evt-2".into()]),
        ]);
        assert!(original_evidence_key(&["evt-1".into()], &mapping).is_err());
    }

    #[test]
    fn unknown_mapping_is_rejected() {
        assert!(original_evidence_key(&["agg-missing".into()], &HashMap::new()).is_err());
    }
}
