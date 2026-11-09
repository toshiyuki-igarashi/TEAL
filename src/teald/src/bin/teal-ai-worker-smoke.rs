// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Explicitly opted-in, separate-process Phase 4 Step 2 SMTP smoke test.
//! Uses the real AI collector and analysis worker, with a MockAdapter.
//! No kernel access, authorization state, or production teald main loop is touched.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use teal_policy_engine::types::Effect;
use teald::ai::adapters::mock::{MockAdapter, MockResponse};
use teald::ai::collector::{
    collect_ai_event, run_ai_analysis_worker, AiCollector, AiCollectorConfig,
};
use teald::ai::engine::AiAnalysisEngine;
use teald::ai::types::{AiAnomaly, Severity};
use teald::ai::AggregatorConfig;
use teald::evidence::schema::{
    AuditLogEntry, AuthInfo, IssuedTicketInfo, LogType, ObjectInfo, PolicyEvalResult, SubjectInfo,
    SyscallContext,
};
use teald::notification::{self, NotificationTransportConfig};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Create an audit record in the same shape that the AI collector consumes.
/// It is simulated test data, *not* a real kernel-generated access event.
fn audit_entry(id: String, effect: Effect, log_type: LogType) -> AuditLogEntry {
    let denied = matches!(&effect, Effect::Deny);
    AuditLogEntry {
        ver: "1.5".into(),
        id,
        ts: Utc::now(),
        host: hostname::get()
            .map(|host| host.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "localhost".into()),
        epoch: 1,
        log_type,
        syscall_context: SyscallContext {
            uid: 0,
            user: "root".into(),
            pid: std::process::id(),
            action: "READ".into(),
            subject: SubjectInfo {
                path: "/usr/bin/cat".into(),
                hash: String::new(),
                script_path: None,
                applet: None,
                args: None,
                session_tty: None,
            },
            object: ObjectInfo {
                path: "/var/tmp/teal-ai-worker-smoke.txt".into(),
                inode: 0,
                device_id: 0,
                kind: "file".into(),
                new_path: None,
                new_inode: None,
                new_device_id: None,
            },
        },
        auth_info: AuthInfo::SlowPath {
            policy_eval: PolicyEvalResult {
                rule_id: "phase4-worker-smoke".into(),
                matched_file: String::new(),
                mpa_level_required: 0,
                decision: effect,
                issued_ticket: if denied {
                    None
                } else {
                    Some(IssuedTicketInfo {
                        ticket_id: "T-PHASE4-SMOKE".into(),
                        ttl_sec: 0,
                    })
                },
            },
            mpa_proof: Default::default(),
        },
        environment_context: None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("TEAL_AI_WORKER_SMOKE").ok().as_deref() != Some("1") {
        bail!("Refusing to send test email: set TEAL_AI_WORKER_SMOKE=1 explicitly");
    }

    // This binary runs alone (not inside the production teald process), so
    // registration of the process-global notifier cannot affect teald.service.
    let runtime = notification::start(NotificationTransportConfig::default())
        .map_err(|e| anyhow::anyhow!("Cannot start notification transport: {e}"))?;
    notification::install_global(runtime.handle())
        .map_err(|_| anyhow::anyhow!("Notifier already installed in smoke process"))?;

    let audit_id = Uuid::new_v4().to_string();
    let denied_id = Uuid::new_v4().to_string();
    let analysis_id_prefix = "generated-by-collector";

    // A real denied audit record must be filtered at the collector's input,
    // not passed to the analysis channel.
    let denied = audit_entry(denied_id.clone(), Effect::Deny, LogType::AccessDenied);
    if collect_ai_event(&denied).is_some() {
        bail!("DENY was incorrectly accepted as an AI input");
    }

    let allowed = audit_entry(audit_id.clone(), Effect::Allow, LogType::AccessAllowed);
    let allowed_event =
        collect_ai_event(&allowed).context("ALLOW audit event unexpectedly excluded")?;
    if allowed_event.event_id != audit_id {
        bail!("Collector changed Audit Event ID");
    }

    // Simulate exactly one validated high-confidence anomaly. Evidence must
    // name the original audit event ID; provider response validation enforces
    // that the ID was in the actual provider request.
    let mock = Arc::new(MockAdapter::new());
    mock.set_response(MockResponse::Success(vec![AiAnomaly {
        severity: Severity::High,
        attack_type: Some("phase4_smoke_test".into()),
        summary: "Phase 4 Step 2 test: allowed activity flagged by MockAdapter".into(),
        explanation: "Only an isolated simulated audit record; no real attack".into(),
        evidence_event_ids: vec![audit_id.clone()],
        confidence_score: 0.98,
    }]));

    let engine = Arc::new(AiAnalysisEngine::new(
        mock.clone(),
        AggregatorConfig::default(),
    ));
    let (analysis_tx, analysis_rx) = mpsc::channel(4);
    let analysis_task = tokio::spawn(run_ai_analysis_worker(engine, analysis_rx));

    let (ai_tx, ai_rx) = mpsc::channel(4);
    let collector = AiCollector::new(
        allowed.host.clone(),
        AiCollectorConfig {
            window: Duration::from_secs(60),
            max_events: 1,
        },
    );
    let collector_task = tokio::spawn(collector.run(ai_rx, analysis_tx));

    // One ALLOW record immediately flushes the batch to the real worker.
    ai_tx
        .send(allowed_event)
        .await
        .context("AI collector channel closed")?;
    drop(ai_tx);

    println!("[SMOKE] original ALLOW Audit ID: {audit_id}");
    println!("[SMOKE] DENY Audit ID filtered (not sent): {denied_id}");
    println!("[SMOKE] analysis ID: {analysis_id_prefix} (collector will generate a UUID)");

    // Do not claim success just because the mock provider returned an anomaly.
    // Ensure that the real analysis worker called the notification bridge and
    // the bridge enqueued a valid notification.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let stats = runtime.handle().stats();
            if stats.ai_enqueued >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("No AI notification was enqueued (check worker stderr)")?;

    let provider_request = mock
        .last_request()
        .context("MockAdapter did not receive the analysis request")?;
    let provider_ids: Vec<&str> = provider_request
        .events
        .iter()
        .flat_map(|e| e.evidence_event_ids.iter().map(String::as_str))
        .collect();
    if !provider_ids.contains(&audit_id.as_str()) || provider_ids.contains(&denied_id.as_str()) {
        bail!("Provider evidence IDs were incorrect: {provider_ids:?}");
    }

    println!("[SMOKE][PASS] MockAdapter received ALLOW Audit ID; DENY not analyzed");
    println!("[SMOKE][PASS] Actual run_ai_analysis_worker enqueued one AI alert");
    println!(
        "[SMOKE] Checking real teal-mailer response; expected: [TEAL][notify][Ai] accepted by SMTP"
    );

    // Give the *real* notification sender time for IPC/SMTP. The acceptance
    // log is emitted by run_sender, not this test harness.  Manual inbox
    // receipt is the final end-to-end assertion.
    tokio::time::sleep(Duration::from_secs(25)).await;
    collector_task.await.context("Collector task panicked")?;
    analysis_task.await.context("Analysis task panicked")?;
    println!("[SMOKE] Check accepted-by-SMTP log and mailbox. Enqueue != mail delivery.");
    Ok(())
}
