// SPDX-License-Identifier: MIT
//! Offline AI evaluation datasets created from TEAL audit JSONL logs.
/*
 * TEAL logview (teal-logview)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Args;

use teald::ai::collector::collect_ai_event;
use teald::ai::types::AiEvent;
use teald::evidence::schema::AuditLogEntry;

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Include events at or after this RFC3339 time (inclusive)
    #[arg(long = "from", value_parser = crate::parse_time)]
    from: Option<DateTime<Utc>>,

    /// Include events before this RFC3339 time (exclusive)
    #[arg(long = "to", value_parser = crate::parse_time)]
    to: Option<DateTime<Utc>>,

    /// Include only this action (e.g., RENAME); case-insensitive exact match
    #[arg(long)]
    action: Option<String>,

    /// Include only events from this executable path (exact match)
    #[arg(long)]
    binary: Option<String>,

    /// New dataset file path; fails if the file already exists
    #[arg(long)]
    out: PathBuf,
}

fn matches_filters(event: &AiEvent, args: &CreateArgs) -> bool {
    if args.from.is_some_and(|from| event.timestamp < from) {
        return false;
    }
    if args.to.is_some_and(|to| event.timestamp >= to) {
        return false;
    }
    if args
        .action
        .as_deref()
        .is_some_and(|a| !event.action.eq_ignore_ascii_case(a))
    {
        return false;
    }
    if args.binary.as_deref().is_some_and(|b| event.binary != b) {
        return false;
    }
    true
}

pub fn create(audit_file: &Path, args: CreateArgs) -> Result<()> {
    if let (Some(from), Some(to)) = (args.from, args.to) {
        if from >= to {
            bail!("--from must be earlier than --to");
        }
    }

    let input = fs::File::open(audit_file)
        .with_context(|| format!("Cannot open audit log: {}", audit_file.display()))?;

    // Never overwrite existing datasets or original audit logs.
    // 0600 because audit paths/arguments may contain sensitive information.
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.out)
        .with_context(|| {
            format!(
                "Cannot create dataset (must not exist): {}",
                args.out.display()
            )
        })?;

    let result = (|| -> Result<(usize, usize, usize)> {
        let mut writer = BufWriter::new(output);
        let mut count = 0usize;
        let mut examined = 0usize;
        let mut skipped = 0usize;

        for (index, line) in BufReader::new(input).lines().enumerate() {
            let line = line.with_context(|| format!("Read error at input line {}", index + 1))?;

            if line.trim().is_empty() {
                continue;
            }

            examined += 1;

            let entry: AuditLogEntry = match serde_json::from_str(&line) {
                Ok(entry) => entry,
                Err(e) => {
                    skipped += 1;
                    eprintln!(
                        "[WARN] Skipping invalid audit JSON at line {}: {}",
                        index + 1,
                        e
                    );
                    continue;
                }
            };

            if let Some(event) = collect_ai_event(&entry) {
                if matches_filters(&event, &args) {
                    serde_json::to_writer(&mut writer, &event).with_context(|| {
                        format!("Failed to serialize event at line {}", index + 1)
                    })?;
                    writer.write_all(b"\n")?;
                    count += 1;
                }
            }
        }

        writer.flush()?;
        Ok((examined, count, skipped))
    })();

    match result {
        Ok((examined, count, skipped)) => {
            eprintln!(
                "[INFO] AI dataset created: path={}, audit_entries={}, ai_events={}, invalid_lines={}",
                args.out.display(),
                examined,
                count,
                skipped
            );
            Ok(())
        }

        Err(err) => {
            if let Err(clean_err) = fs::remove_file(&args.out) {
                eprintln!("[WARN] Failed to remove incomplete dataset: {clean_err}");
            }
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_event() -> AiEvent {
        AiEvent {
            event_id: "evt-001".into(),
            timestamp: DateTime::parse_from_rfc3339("2026-10-20T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            log_type: teald::evidence::schema::LogType::AccessAllowed,
            epoch: 1,
            user: "root".into(),
            pid: 100,
            action: "RENAME".into(),
            binary: "/usr/bin/mv".into(),
            script_path: None,
            applet: None,
            args: None,
            target_path: "/data/a".into(),
            target_kind: "file".into(),
            new_path: Some("/data/b".into()),
            remote_client: None,
            rule: None,
            ticket_id: None,
        }
    }

    #[test]
    fn filter_time_and_action_and_binary() {
        let event = example_event();
        let args = CreateArgs {
            from: Some(event.timestamp),
            to: Some(event.timestamp + chrono::Duration::seconds(1)),
            action: Some("rename".into()),
            binary: Some("/usr/bin/mv".into()),
            out: PathBuf::from("unused.jsonl"),
        };
        assert!(matches_filters(&event, &args));
        let end_exclusive = CreateArgs {
            to: Some(event.timestamp),
            ..args
        };
        assert!(!matches_filters(&event, &end_exclusive));
    }

    #[test]
    fn invalid_time_window_is_rejected() {
        let t = DateTime::parse_from_rfc3339("2026-10-20T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let args = CreateArgs {
            from: Some(t),
            to: Some(t),
            action: None,
            binary: None,
            out: PathBuf::from("unused.jsonl"),
        };
        assert!(create(Path::new("unused-audit.jsonl"), args).is_err());
    }
}
