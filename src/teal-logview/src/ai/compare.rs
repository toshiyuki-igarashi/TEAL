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

use super::eval::{EvalBatchReport, EvalReport};
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

/// Canonical identity of a replay batch, independent of event order.
fn batch_key(batch: &EvalBatchReport) -> Result<Vec<String>> {
    if batch.target_event_ids.is_empty() {
        bail!("Batch {} has no input event IDs", batch.batch_index);
    }
    let mut key = batch.target_event_ids.clone();
    key.sort_unstable();
    if key.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("Duplicate input event ID in batch {}", batch.batch_index);
    }
    Ok(key)
}

/// Build unique mappings from exact input-event sets to batches.
/// Reject overlapping event IDs across batches to avoid ambiguous comparisons.
fn batch_index<'a>(report: &'a EvalReport) -> Result<HashMap<Vec<String>, &'a EvalBatchReport>> {
    let mut index = HashMap::new();
    let mut seen_events = HashSet::new();
    for batch in &report.batches {
        let key = batch_key(batch)?;
        for id in &key {
            if !seen_events.insert(id.clone()) {
                bail!("Overlapping input events across batches in report {}", report.dataset_path);
            }
        }
        if index.insert(key, batch).is_some() {
            bail!("Repeated input-event set in report {}", report.dataset_path);
        }
    }
    Ok(index)
}

struct Comparable<'a> {
    pairs: Vec<(&'a EvalBatchReport, &'a EvalBatchReport)>,
    excluded_failed: usize,
    excluded_unmatched_base: usize,
    excluded_unmatched_cand: usize,
}

/// Only exact same input events and successful analyses are comparable.
fn comparable_batches<'a>(base: &'a EvalReport, cand: &'a EvalReport) -> Result<Comparable<'a>> {
    let base_index = batch_index(base)?;
    let cand_index = batch_index(cand)?;
    let mut pairs = Vec::new();
    let mut excluded_failed = 0;
    let mut excluded_unmatched_base = 0;
    let mut excluded_unmatched_cand = 0;
    for (key, left) in &base_index {
        match cand_index.get(key) {
            Some(right) if left.result.is_some() && right.result.is_some() => {
                pairs.push((*left, *right));
            }
            Some(_) => excluded_failed += 1,
            None => excluded_unmatched_base += 1,
        }
    }
    for key in cand_index.keys() {
        if !base_index.contains_key(key) {
            excluded_unmatched_cand += 1;
        }
    }
    pairs.sort_by_key(|(left, _)| left.batch_index);
    Ok(Comparable { pairs, excluded_failed, excluded_unmatched_base, excluded_unmatched_cand })
}

/// Collect only anomalies from batches selected for a fair comparison.
fn collect_detections<'a>(
    batches: impl IntoIterator<Item = &'a EvalBatchReport>,
) -> Result<Vec<(&'a AiAnomaly, Vec<String>)>> {
    let mut detections = Vec::new();
    for batch in batches {
        let Some(result) = batch.result.as_ref() else { continue };
        for anomaly in &result.anomalies {
            let key = original_evidence_key(&anomaly.evidence_event_ids, &batch.source_event_ids)
                .with_context(|| format!("Cannot resolve evidence in batch {}", batch.batch_index))?;
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

    // Compare only matching input-event sets that succeeded on both sides.
    let comparable = comparable_batches(&base, &cand)?;
    let base_detections = collect_detections(comparable.pairs.iter().map(|(b, _)| *b))?;
    let cand_detections = collect_detections(comparable.pairs.iter().map(|(_, c)| *c))?;

    let base_success = base.batches.iter()
        .filter(|b| b.result.is_some())
        .count();

    let cand_success = cand.batches.iter()
        .filter(|b| b.result.is_some())
        .count();

    let base_failed = base.batches.iter()
        .filter(|b| b.error.is_some())
        .count();

    let cand_failed = cand.batches.iter()
        .filter(|b| b.error.is_some())
        .count();

    println!("================================================================================");
    println!(" TEAL AI Evaluation Comparison Report (Comparable Batches)");
    println!("================================================================================");
    println!("Metric / Field          | Baseline                      | Candidate");
    println!("------------------------+-------------------------------+-------------------------------");
    println!("Provider                | {:<29} | {:<29}", base.provider_name, cand.provider_name);
    println!("Model                   | {:<29} | {:<29}", base.model_name, cand.model_name);
    println!("Total Elapsed Time      | {:<26} ms | {:<26} ms", base.elapsed_ms, cand.elapsed_ms);
    println!("Batch Count             | {:<29} | {:<29}", base.batch_count, cand.batch_count);
    println!("Input Events            | {:<29} | {:<29}", base.input_event_count, cand.input_event_count);
    println!("Successful Aggregates   | {:<29} | {:<29}", base.aggregated_event_count, cand.aggregated_event_count);
    println!("Comparable Anomalies    | {:<29} | {:<29}", base_detections.len(), cand_detections.len());
    println!("Config SHA256           | {:<29} | {:<29}", &base.config_sha256[..16.min(base.config_sha256.len())], &cand.config_sha256[..16.min(cand.config_sha256.len())]);
    println!("Prompt SHA256           | {:<29} | {:<29}", &base.prompt_sha256[..16.min(base.prompt_sha256.len())], &cand.prompt_sha256[..16.min(cand.prompt_sha256.len())]);
    println!("Successful Batches      | {:<29} | {:<29}", base_success, cand_success);
    println!("Failed Batches          | {:<29} | {:<29}", base_failed, cand_failed);
    println!("Comparable Batches      | {}", comparable.pairs.len());
    println!("Excluded Failed Pairs   | {}", comparable.excluded_failed);
    println!("Unmatched Base Batches  | {}", comparable.excluded_unmatched_base);
    println!("Unmatched Cand Batches  | {}", comparable.excluded_unmatched_cand);
    for (label, report) in [("Baseline", &base), ("Candidate", &cand)] {
        for batch in &report.batches {
            if let Some(error) = &batch.error {
                println!(
                    "[{}] Batch {} failed: type={}, code={:?}, field={:?}",
                    label,
                    batch.batch_index,
                    error.error_type,
                    error.code,
                    error.field,
                );
            }
        }
    }
    println!("================================================================================");

    println!("\n[Detection Discrepancies]");
    if comparable.pairs.is_empty() {
        println!("  * Common Detections  : N/A");
        println!("  * Resolved / Dropped : N/A");
        println!("  * Newly Detected     : N/A");
        println!("[WARN] No comparable batches. Detection quality cannot be compared.");
    } else {
        // Compare original audit-event sets, not aggregation IDs.
        let base_keys: HashSet<Vec<String>> = base_detections.iter()
            .map(|(_, key)| key.clone()).collect();
        let cand_keys: HashSet<Vec<String>> = cand_detections.iter()
            .map(|(_, key)| key.clone()).collect();
        let common_count = base_keys.intersection(&cand_keys).count();
        let dropped_count = base_keys.difference(&cand_keys).count();
        let new_count = cand_keys.difference(&base_keys).count();
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
        if comparable.excluded_failed > 0 || comparable.excluded_unmatched_base > 0 || comparable.excluded_unmatched_cand > 0 {
            println!("\n[WARN] Detection counts cover comparable batches only; excluded batches are not scored.");
        }
    }
    println!("\n================================================================================");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_report(batches: Vec<EvalBatchReport>) -> EvalReport {
        EvalReport {
            report_version: "1.2".into(), evaluated_at: chrono::Utc::now(),
            provider_name: "mock".into(), model_name: "mock".into(),
            config_sha256: "hash".into(), prompt_sha256: "hash".into(),
            dataset_path: "test.jsonl".into(), input_event_count: 0,
            aggregated_event_count: 0, batch_count: batches.len(), elapsed_ms: 0, batches,
        }
    }

    fn mock_batch(index: usize, ids: &[&str], success: bool) -> EvalBatchReport {
        use teald::ai::types::AiAnalysisResult;
        let now = chrono::Utc::now();
        EvalBatchReport {
            batch_index: index, analysis_id: format!("test-{index}"),
            time_window_start: now, time_window_end: now,
            input_event_count: ids.len(), aggregated_event_count: None,
            target_event_ids: ids.iter().map(|s| (*s).into()).collect(),
            elapsed_ms: 0,
            result: success.then(|| AiAnalysisResult {
                analysis_id: format!("test-{index}"), anomalies: vec![],
            }),
            error: None, source_event_ids: HashMap::new(),
        }
    }

    #[test]
    fn failed_matching_batch_is_not_comparable() {
        let base = mock_report(vec![mock_batch(1, &["a", "b"], false)]);
        let cand = mock_report(vec![mock_batch(1, &["b", "a"], true)]);
        let comparison = comparable_batches(&base, &cand).unwrap();
        assert!(comparison.pairs.is_empty());
        assert_eq!(comparison.excluded_failed, 1);
    }

    #[test]
    fn matches_by_event_set_not_batch_index() {
        let base = mock_report(vec![mock_batch(1, &["a", "b"], true), mock_batch(2, &["c"], true)]);
        let cand = mock_report(vec![mock_batch(1, &["c"], true), mock_batch(2, &["b", "a"], true)]);
        let comparison = comparable_batches(&base, &cand).unwrap();
        assert_eq!(comparison.pairs.len(), 2);
        assert_eq!(comparison.pairs[0].1.batch_index, 2);
        assert_eq!(comparison.pairs[1].1.batch_index, 1);
    }

    #[test]
    fn mismatched_batches_are_excluded() {
        let base = mock_report(vec![mock_batch(1, &["a", "b"], true)]);
        let cand = mock_report(vec![mock_batch(1, &["a"], true), mock_batch(2, &["b"], true)]);
        let comparison = comparable_batches(&base, &cand).unwrap();
        assert!(comparison.pairs.is_empty());
        assert_eq!(comparison.excluded_unmatched_base, 1);
        assert_eq!(comparison.excluded_unmatched_cand, 2);
    }

    #[test]
    fn overlapping_batches_are_rejected() {
        let base = mock_report(vec![mock_batch(1, &["a"], true), mock_batch(2, &["a"], true)]);
        let cand = mock_report(vec![mock_batch(1, &["a"], true)]);
        assert!(comparable_batches(&base, &cand).is_err());
    }

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
