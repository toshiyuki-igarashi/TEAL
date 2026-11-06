// SPDX-License-Identifier: MIT
//! Convert a confirmed ENFORCE ACCESS_DENIED audit event into a mail notification.
//!
//! Only call this after the audit event has been recorded and after a kernel
//! DENY decision has been confirmed. Time-window aggregation is handled by
//! aggregation.rs; role-to-Bcc resolution remains a separate step.

use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

use teal_notify_protocol::{
    DenyNotification, NotificationPayload, NotificationRequest, MAX_RECIPIENTS, PROTOCOL_VERSION,
};

use super::{
    aggregation::{AggregationConfig, AggregationDispatcher},
    global_handle, EnqueueError, NotificationHandle,
};

const MAX_ID_BYTES: usize = 128;
const MAX_HOST_BYTES: usize = 255;
const MAX_PROGRAM_BYTES: usize = 4096;
const MAX_ACTION_BYTES: usize = 64;
const MAX_TARGET_BYTES: usize = 4096;
const MAX_RULE_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_EMAIL_BYTES: usize = 320;

static GLOBAL_AGGREGATOR: OnceLock<Arc<AggregationDispatcher>> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub struct ConfirmedDenyEvent<'a> {
    /// This is the audit log ID (not the kernel transport ID).
    pub audit_id: &'a str,
    pub hostname: &'a str,
    pub uid: u32,
    pub pid: Option<u32>,
    pub program: &'a str,
    pub action: &'a str,
    pub rule_id: Option<&'a str>,
    pub policy_epoch: u32,
    pub target: &'a str,
    /// RFC3339 timestamp from the persisted audit record.
    pub timestamp: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenySubmitError {
    Uninitialized,
    InvalidData(&'static str),
    Enqueue(EnqueueError),
}

/// Route eligibility: a policy's hypothetical DENY in AUDIT mode is not
/// a real access denial. Caller also checks the final PolicyDecision.
pub fn should_notify(is_audit_request: bool, final_access_denied: bool) -> bool {
    !is_audit_request && final_access_denied
}

fn nonempty_bounded(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

/// A cached hostname; avoid reading procfs for every audited DENY.
/// Call this once during notification startup if first-event I/O is unwanted.
pub fn cached_hostname() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| nonempty_bounded(s, MAX_HOST_BYTES))
            .unwrap_or_else(|| "unknown-host".to_owned())
    })
}

/// Parent directory for absolute filesystem paths. Non-file targets such as
/// CONNECT destinations are kept verbatim until operation-specific grouping
/// normalization is introduced with the aggregation stage.
fn target_group(target: &str) -> String {
    if target.starts_with('/') {
        Path::new(target)
            .parent()
            .and_then(|p| p.to_str())
            .filter(|p| !p.is_empty())
            .unwrap_or("/")
            .to_owned()
    } else {
        target.to_owned()
    }
}

/// Pure conversion, usable in unit tests without a running teald or mailer.
/// `bcc_recipients` are informational; the mandatory To is in mailer.json.
pub fn build_request(
    event: ConfirmedDenyEvent<'_>,
    bcc_recipients: &[String],
) -> Result<NotificationRequest, DenySubmitError> {
    if !nonempty_bounded(event.audit_id, MAX_ID_BYTES - "DENY-".len()) {
        return Err(DenySubmitError::InvalidData("invalid audit ID"));
    }
    if !nonempty_bounded(event.hostname, MAX_HOST_BYTES) {
        return Err(DenySubmitError::InvalidData("invalid hostname"));
    }
    if !nonempty_bounded(event.program, MAX_PROGRAM_BYTES) {
        return Err(DenySubmitError::InvalidData("invalid program"));
    }
    if !nonempty_bounded(event.action, MAX_ACTION_BYTES) {
        return Err(DenySubmitError::InvalidData("invalid action"));
    }
    if !nonempty_bounded(event.target, MAX_TARGET_BYTES) {
        return Err(DenySubmitError::InvalidData("invalid target"));
    }
    if !nonempty_bounded(event.timestamp, MAX_TIMESTAMP_BYTES) {
        return Err(DenySubmitError::InvalidData("invalid timestamp"));
    }
    if event
        .rule_id
        .is_some_and(|id| !nonempty_bounded(id, MAX_RULE_BYTES))
    {
        return Err(DenySubmitError::InvalidData("invalid rule ID"));
    }
    if bcc_recipients.len() > MAX_RECIPIENTS
        || bcc_recipients
            .iter()
            .any(|s| !nonempty_bounded(s, MAX_EMAIL_BYTES))
    {
        return Err(DenySubmitError::InvalidData("invalid Bcc recipients"));
    }

    let request = NotificationRequest {
        version: PROTOCOL_VERSION,
        notification_id: format!("DENY-{}", event.audit_id),
        recipients: bcc_recipients.to_vec(),
        payload: NotificationPayload::Deny(DenyNotification {
            hostname: event.hostname.to_owned(),
            uid: event.uid,
            pid: event.pid,
            program: event.program.to_owned(),
            action: event.action.to_owned(),
            rule_id: event.rule_id.map(str::to_owned),
            policy_epoch: event.policy_epoch,
            target_parent: target_group(event.target),
            target_samples: vec![event.target.to_owned()],
            count: 1,
            first_seen: event.timestamp.to_owned(),
            last_seen: event.timestamp.to_owned(),
            representative_event_id: event.audit_id.to_owned(),
            early_flush: false,
        }),
    };
    request.validate().map_err(DenySubmitError::InvalidData)?;
    Ok(request)
}

/// Enqueue without awaiting IPC, SMTP, filesystem or a channel permit.
/// Never call from the kernel reply critical path; call from the audit worker.
pub fn submit(
    event: ConfirmedDenyEvent<'_>,
    bcc_recipients: &[String],
) -> Result<(), DenySubmitError> {
    let handle = global_handle().ok_or(DenySubmitError::Uninitialized)?;
    let request = build_request(event, bcc_recipients)?;
    let dispatcher = GLOBAL_AGGREGATOR.get_or_init(|| {
        let dispatcher = Arc::new(AggregationDispatcher::new(
            handle.clone(),
            AggregationConfig::default(),
        ));
        tokio::spawn(Arc::clone(&dispatcher).run_sweeper());
        dispatcher
    });
    dispatcher.submit(request);
    Ok(())
}

/// Direct, non-aggregated enqueue for isolated transport tests only.
/// Production DENY events go through submit() and the aggregation manager.
pub fn enqueue_to(
    handle: &NotificationHandle,
    event: ConfirmedDenyEvent<'_>,
    bcc_recipients: &[String],
) -> Result<(), DenySubmitError> {
    let request = build_request(event, bcc_recipients)?;
    handle
        .try_enqueue_deny(request)
        .map_err(DenySubmitError::Enqueue)
}

#[cfg(test)]
mod tests {
    use super::super::queue::{NotificationCounters, NotificationHandle};
    use super::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn event() -> ConfirmedDenyEvent<'static> {
        ConfirmedDenyEvent {
            audit_id: "7d7aca13-8a7a-4d8e-af4d-8e8768e980ff",
            hostname: "server01",
            uid: 1000,
            pid: Some(42),
            program: "/usr/bin/rm",
            action: "UNLINK",
            rule_id: Some("protect-backups"),
            policy_epoch: 17,
            target: "/var/backups/db.sql",
            timestamp: "2026-11-05T11:00:00+09:00",
        }
    }

    #[test]
    fn notifies_only_actual_enforce_denials() {
        assert!(should_notify(false, true));
        assert!(!should_notify(true, true));
        assert!(!should_notify(false, false));
        assert!(!should_notify(true, false));
    }

    #[test]
    fn maps_confirmed_deny_to_protocol() {
        let request = build_request(event(), &[]).unwrap();
        assert_eq!(
            request.notification_id,
            format!("DENY-{}", event().audit_id)
        );
        assert!(request.recipients.is_empty());
        assert!(request.validate().is_ok());
        let NotificationPayload::Deny(deny) = request.payload else {
            panic!("not DENY")
        };
        assert_eq!(deny.target_parent, "/var/backups");
        assert_eq!(deny.target_samples, vec!["/var/backups/db.sql"]);
        assert_eq!(deny.count, 1);
        assert_eq!(deny.first_seen, deny.last_seen);
        assert_eq!(deny.policy_epoch, 17);
        assert_eq!(deny.representative_event_id, event().audit_id);
        assert!(!deny.early_flush);
    }

    #[test]
    fn supports_connect_and_no_rule() {
        let mut e = event();
        e.target = "203.0.113.5:443";
        e.action = "CONNECT";
        e.rule_id = None;
        let request = build_request(e, &[]).unwrap();
        let NotificationPayload::Deny(deny) = request.payload else {
            panic!("not DENY")
        };
        assert_eq!(deny.target_parent, "203.0.113.5:443");
        assert_eq!(deny.rule_id, None);
    }

    #[test]
    fn pushes_deny_into_bounded_queue() {
        let (ai_tx, _ai_rx) = mpsc::channel(1);
        let (deny_tx, mut deny_rx) = mpsc::channel(1);
        let handle =
            NotificationHandle::new(ai_tx, deny_tx, Arc::new(NotificationCounters::default()));
        enqueue_to(&handle, event(), &[]).unwrap();
        assert_eq!(handle.stats().deny_enqueued, 1);
        // A full notification channel must never block the audit worker.
        assert_eq!(
            enqueue_to(&handle, event(), &[]),
            Err(DenySubmitError::Enqueue(EnqueueError::QueueFull))
        );
        assert_eq!(handle.stats().deny_queue_full, 1);
        let received = deny_rx.try_recv().unwrap();
        assert_eq!(
            received.notification_id,
            format!("DENY-{}", event().audit_id)
        );
    }

    #[test]
    fn rejects_invalid_fields_before_enqueue() {
        let mut e = event();
        e.audit_id = "bad\nlog";
        assert_eq!(
            build_request(e, &[]).unwrap_err(),
            DenySubmitError::InvalidData("invalid audit ID")
        );
        let mut e = event();
        e.target = "";
        assert!(build_request(e, &[]).is_err());
        let bcc = vec!["x@example.com".to_owned(); MAX_RECIPIENTS + 1];
        assert!(build_request(event(), &bcc).is_err());
    }
}
