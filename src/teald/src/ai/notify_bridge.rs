// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Phase 4 Step 2: advisory AI results -> non-blocking mail notifications.
//!
//! Only ALLOW/AuditOnly evidence reaches this adapter.  The collector is the
//! first filter; this module independently rejects DENY evidence to prevent
//! a future pipeline change from silently turning DENY into AI input.

use crate::ai::engine::AiAnalysisOutcome;
use crate::ai::types::{AiAnalysisRequest, AiAnomaly};
use crate::evidence::schema::LogType;
use crate::notification::ai_event::{submit, AiAttackEvent, AiSubmitError};

#[derive(Debug)]
struct PreparedNotice {
    analysis_id: String,
    hostname: String,
    confidence: f64,
    reason: String,
    related_event_ids: Vec<String>,
    program: String,
    action: String,
    target: String,
}

// Mail notifications cannot contain literal newlines or other control chars.
// 4096 Unicode scalar values occupy at most 16 KiB in UTF-8.
fn single_line_reason(s: &str) -> String {
    s.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .take(4096)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Build an immutable, audit-provenance-backed notice for one anomaly.
/// Fail closed if an anomaly references any missing or DENY audit event.
fn prepare_one(
    request: &AiAnalysisRequest,
    anomaly: &AiAnomaly,
    index: usize,
) -> Result<PreparedNotice, &'static str> {
    if anomaly.evidence_event_ids.is_empty() {
        return Err("missing evidence IDs");
    }

    let mut representative = None;
    for id in &anomaly.evidence_event_ids {
        let event = request
            .events
            .iter()
            .find(|event| event.event_id == *id)
            .ok_or("evidence ID not found in analysis request")?;

        if matches!(&event.log_type, LogType::AccessDenied) {
            return Err("DENY evidence is excluded from AI notifications");
        }
        if representative.is_none() {
            representative = Some(event);
        }
    }

    let event = representative.ok_or("no representative event")?;
    Ok(PreparedNotice {
        // notification::ai_event adds the "AI-" prefix. A suffix ensures
        // that multiple anomalies in one analysis do not share an ID.
        analysis_id: format!("{}-A{}", request.analysis_id, index + 1),
        hostname: request.host.clone(),
        confidence: anomaly.confidence_score as f64,
        reason: single_line_reason(&anomaly.summary),
        related_event_ids: anomaly.evidence_event_ids.clone(),
        // The values below are copied from audit events, never AI-generated.
        program: event.binary.clone(),
        action: event.action.clone(),
        target: event.target_path.clone(),
    })
}

/// Called after AI result validation, before the outcome is moved into storage.
/// Notification failures never change the AI result or authorization decision.
pub(super) fn emit_notifications(request: &AiAnalysisRequest, outcome: &AiAnalysisOutcome) {
    for (index, anomaly) in outcome.result.anomalies.iter().enumerate() {
        let notice = match prepare_one(request, anomaly, index) {
            Ok(notice) => notice,
            Err(error) => {
                eprintln!(
                    "[TEAL][AI][notify][WARN] skipped: analysis_id={}, anomaly={}, reason={}",
                    request.analysis_id,
                    index + 1,
                    error,
                );
                continue;
            }
        };

        // Borrow the String vector for the duration of submit(); the sender
        // queue receives its own owned notification request.
        let related_refs: Vec<&str> = notice
            .related_event_ids
            .iter()
            .map(String::as_str)
            .collect();
        let event = AiAttackEvent {
            analysis_id: &notice.analysis_id,
            hostname: &notice.hostname,
            confidence: notice.confidence,
            reason: &notice.reason,
            related_event_ids: &related_refs,
            program: &notice.program,
            action: &notice.action,
            target: &notice.target,
        };
        match submit(event, &[]) {
            Ok(()) => eprintln!(
                "[TEAL][AI][notify][INFO] enqueued: notification_id=AI-{}, confidence={:.4}, related_audit_events={}",
                notice.analysis_id, notice.confidence, notice.related_event_ids.len(),
            ),
            Err(AiSubmitError::LowConfidence { .. }) => { /* expected filtering */ }
            Err(error) => eprintln!(
                "[TEAL][AI][notify][WARN] enqueue failed: analysis_id={}, anomaly={}, error={:?}",
                request.analysis_id, index + 1, error,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::{AiEvent, Severity};
    use crate::notification::ai_event::build_request;
    use chrono::Utc;
    use teal_notify_protocol::NotificationPayload;

    fn event(id: &str, denied: bool) -> AiEvent {
        AiEvent {
            event_id: id.to_string(),
            timestamp: Utc::now(),
            log_type: if denied {
                LogType::AccessDenied
            } else {
                LogType::AccessAllowed
            },
            epoch: 1,
            user: "root".into(),
            pid: 1234,
            action: "RENAME".into(),
            binary: "/usr/bin/mv".into(),
            script_path: None,
            applet: None,
            args: None,
            target_path: "/data/file".into(),
            target_kind: "file".into(),
            new_path: Some("/data/file.enc".into()),
            remote_client: None,
            rule: None,
            ticket_id: None,
        }
    }

    fn request(events: Vec<AiEvent>) -> AiAnalysisRequest {
        let now = Utc::now();
        AiAnalysisRequest {
            analysis_id: "A-001".into(),
            host: "host-test".into(),
            time_window_start: now,
            time_window_end: now,
            events,
        }
    }

    fn anomaly(ids: Vec<&str>) -> AiAnomaly {
        AiAnomaly {
            severity: Severity::High,
            attack_type: Some("ransomware".into()),
            summary: "Mass rename\npossible attack".into(),
            explanation: "Suspicious actions".into(),
            evidence_event_ids: ids.into_iter().map(str::to_owned).collect(),
            confidence_score: 0.98,
        }
    }

    #[test]
    fn allowed_audit_ids_are_preserved_in_mail_payload() {
        let req = request(vec![event("AUDIT-1", false), event("AUDIT-2", false)]);
        let notice = prepare_one(&req, &anomaly(vec!["AUDIT-1", "AUDIT-2"]), 0).unwrap();
        assert_eq!(notice.analysis_id, "A-001-A1");
        assert_eq!(notice.related_event_ids, vec!["AUDIT-1", "AUDIT-2"]);
        assert_eq!(notice.reason, "Mass rename possible attack");
        let ids: Vec<&str> = notice
            .related_event_ids
            .iter()
            .map(String::as_str)
            .collect();
        let event = AiAttackEvent {
            analysis_id: &notice.analysis_id,
            hostname: &notice.hostname,
            confidence: notice.confidence,
            reason: &notice.reason,
            related_event_ids: &ids,
            program: &notice.program,
            action: &notice.action,
            target: &notice.target,
        };
        let mail = build_request(event, 0.95, &[]).unwrap();
        assert_eq!(mail.notification_id, "AI-A-001-A1");
        match mail.payload {
            NotificationPayload::Ai(payload) => {
                assert_eq!(payload.related_event_ids, vec!["AUDIT-1", "AUDIT-2"]);
                assert_eq!(payload.program, "/usr/bin/mv");
            }
            _ => panic!("expected AI payload"),
        }
    }

    #[test]
    fn deny_and_unknown_evidence_are_rejected() {
        let req = request(vec![event("AUDIT-1", false), event("DENY-1", true)]);
        assert!(prepare_one(&req, &anomaly(vec!["AUDIT-1", "DENY-1"]), 0).is_err());
        assert!(prepare_one(&req, &anomaly(vec!["MISSING"]), 0).is_err());
        assert!(prepare_one(&req, &anomaly(vec!["DENY-1"]), 0).is_err());
    }

    #[test]
    fn anomaly_index_makes_notification_ids_unique() {
        let req = request(vec![event("AUDIT-1", false)]);
        let anomaly = anomaly(vec!["AUDIT-1"]);
        let first = prepare_one(&req, &anomaly, 0).unwrap();
        let second = prepare_one(&req, &anomaly, 1).unwrap();
        assert_ne!(first.analysis_id, second.analysis_id);
    }
}
