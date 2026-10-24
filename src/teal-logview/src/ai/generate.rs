// SPDX-License-Identifier: MIT
/*
 * TEAL logview (teal-logview)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
//! Deterministic synthetic AiEvent datasets for offline AI evaluation.
//! This module does not perform any filesystem operations described by events.

use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::{Args, ValueEnum};
use teald::ai::types::AiEvent;
use teald::evidence::schema::LogType;

const DEFAULT_START: &str = "2026-10-23T00:00:00Z";
const MAX_EVENTS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum Scenario {
    NormalRename,
    MassRename,
    MassDelete,
}

impl Scenario {
    fn label(self) -> &'static str {
        match self {
            Self::NormalRename => "normal-rename",
            Self::MassRename => "mass-rename",
            Self::MassDelete => "mass-delete",
        }
    }

    fn default_events(self) -> usize {
        match self {
            Self::NormalRename => 5,
            Self::MassRename | Self::MassDelete => 100,
        }
    }

    fn default_interval_ms(self) -> i64 {
        match self {
            Self::NormalRename => 10_000,
            Self::MassRename | Self::MassDelete => 100,
        }
    }
}

#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Synthetic activity pattern
    #[arg(long, value_enum)]
    pub scenario: Scenario,

    /// Number of events (defaults to 5 for normal-rename, 100 otherwise)
    #[arg(long)]
    pub events: Option<usize>,

    /// Milliseconds between successive events (scenario-specific default)
    #[arg(long)]
    pub interval_ms: Option<i64>,

    /// Start timestamp in RFC3339 (UTC recommended)
    #[arg(long, default_value = DEFAULT_START)]
    pub start: String,

    /// Output JSONL file; refuses to overwrite an existing file
    #[arg(long)]
    pub out: PathBuf,
}

fn generate_events(
    scenario: Scenario,
    count: usize,
    start: DateTime<Utc>,
    interval_ms: i64,
) -> Result<Vec<AiEvent>> {
    if count == 0 || count > MAX_EVENTS {
        bail!("--events must be between 1 and {MAX_EVENTS}");
    }
    if interval_ms <= 0 {
        bail!("--interval-ms must be positive");
    }

    let mut events = Vec::with_capacity(count);
    for i in 0..count {
        let offset_ms = i64::try_from(i)
            .ok()
            .and_then(|n| n.checked_mul(interval_ms))
            .context("Timestamp offset overflow")?;
        let timestamp = start.checked_add_signed(Duration::milliseconds(offset_ms))
            .context("Timestamp overflow")?;

        let (action, target_path, new_path) = match scenario {
            Scenario::NormalRename => (
                "RENAME",
                format!("/home/testuser/documents/draft_{i:06}.txt"),
                Some(format!("/home/testuser/documents/final_{i:06}.txt")),
            ),
            Scenario::MassRename => (
                "RENAME",
                format!("/data/documents/file_{i:06}.txt"),
                Some(format!("/data/documents/file_{i:06}.enc")),
            ),
            Scenario::MassDelete => (
                "UNLINK",
                format!("/data/documents/file_{i:06}.txt"),
                None,
            ),
        };
        let (user, pid, binary) = match scenario {
            Scenario::NormalRename => ("testuser", 2100, "/usr/bin/mv"),
            Scenario::MassRename => ("root", 4321, "/usr/bin/mv"),
            Scenario::MassDelete => ("root", 4322, "/usr/bin/rm"),
        };
        events.push(AiEvent {
            event_id: format!("synthetic-{}-{i:06}", scenario.label()),
            timestamp,
            log_type: LogType::AccessAllowed,
            epoch: 1,
            user: user.into(),
            pid,
            action: action.into(),
            binary: binary.into(),
            script_path: None,
            applet: None,
            args: None,
            target_path,
            target_kind: "file".into(),
            new_path,
            remote_client: None,
            rule: None,
            ticket_id: None,
        });
    }
    Ok(events)
}

pub fn run(args: GenerateArgs) -> Result<()> {
    let start = DateTime::parse_from_rfc3339(&args.start)
        .with_context(|| format!("Invalid --start RFC3339 timestamp: {}", args.start))?
        .with_timezone(&Utc);
    let count = args.events.unwrap_or_else(|| args.scenario.default_events());
    let interval_ms = args.interval_ms.unwrap_or_else(|| args.scenario.default_interval_ms());
    let events = generate_events(args.scenario, count, start, interval_ms)?;

    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.out)
        .with_context(|| format!("Cannot create dataset (must not exist): {}", args.out.display()))?;

    let result = (|| -> Result<()> {
        let mut writer = BufWriter::new(output);
        for event in &events {
            serde_json::to_writer(&mut writer, event)?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&args.out);
        return Err(error);
    }
    eprintln!(
        "[INFO] Synthetic dataset saved: scenario={}, events={}, interval_ms={}, out={}",
        args.scenario.label(), events.len(), interval_ms, args.out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(DEFAULT_START).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn normal_rename_has_non_suspicious_targets_and_slow_cadence() {
        let events = generate_events(Scenario::NormalRename, 5, start(), 10_000).unwrap();
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|e| e.action == "RENAME" && e.new_path.as_deref().unwrap().ends_with(".txt")));
        assert_eq!((events[1].timestamp - events[0].timestamp).num_seconds(), 10);
    }

    #[test]
    fn mass_rename_is_reproducible_and_aggregatable() {
        let a = generate_events(Scenario::MassRename, 100, start(), 100).unwrap();
        let b = generate_events(Scenario::MassRename, 100, start(), 100).unwrap();
        assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&b).unwrap());
        assert_eq!(a.len(), 100);
        assert!(a.iter().all(|e| e.action == "RENAME" && e.new_path.as_deref().unwrap().ends_with(".enc")));
        assert_eq!((a[99].timestamp - a[0].timestamp).num_milliseconds(), 9900);
    }

    #[test]
    fn mass_delete_uses_unlink_without_destination() {
        let events = generate_events(Scenario::MassDelete, 100, start(), 100).unwrap();
        assert!(events.iter().all(|e| e.action == "UNLINK" && e.new_path.is_none()));
        assert_eq!(events[0].event_id, "synthetic-mass-delete-000000");
    }

    #[test]
    fn invalid_counts_and_intervals_are_rejected() {
        assert!(generate_events(Scenario::MassDelete, 0, start(), 100).is_err());
        assert!(generate_events(Scenario::MassDelete, MAX_EVENTS + 1, start(), 100).is_err());
        assert!(generate_events(Scenario::MassDelete, 1, start(), 0).is_err());
        assert!(generate_events(Scenario::MassDelete, 1, start(), -1).is_err());
    }
}
