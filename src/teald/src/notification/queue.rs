// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Bounded, non-blocking AI and DENY submission to independent IPC workers.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use teal_notify_protocol::{NotificationPayload, NotificationRequest};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationKind {
    Ai,
    Deny,
}

impl NotificationKind {
    pub fn from_request(request: &NotificationRequest) -> Self {
        match &request.payload {
            NotificationPayload::Ai(_) => Self::Ai,
            NotificationPayload::Deny(_) => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueError {
    InvalidRequest(&'static str),
    WrongKind,
    QueueFull,
    QueueClosed,
}

#[derive(Debug, Default)]
pub struct NotificationCounters {
    pub ai_enqueued: AtomicU64,
    pub deny_enqueued: AtomicU64,
    pub ai_queue_full: AtomicU64,
    pub deny_queue_full: AtomicU64,
    pub ai_accepted: AtomicU64,
    pub deny_accepted: AtomicU64,
    pub ai_permanent_failure: AtomicU64,
    pub deny_permanent_failure: AtomicU64,
    pub ai_retries: AtomicU64,
    pub deny_retries: AtomicU64,
    pub ai_emergency_queued: AtomicU64,
    pub ai_spool_failed: AtomicU64,
    pub ai_save_failed: AtomicU64,
    pub deny_save_failed: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotificationStats {
    pub ai_enqueued: u64,
    pub deny_enqueued: u64,
    pub ai_queue_full: u64,
    pub deny_queue_full: u64,
    pub ai_accepted: u64,
    pub deny_accepted: u64,
    pub ai_permanent_failure: u64,
    pub deny_permanent_failure: u64,
    pub ai_retries: u64,
    pub deny_retries: u64,
    pub ai_emergency_queued: u64,
    pub ai_spool_failed: u64,
    pub ai_save_failed: u64,
    pub deny_save_failed: u64,
}

impl NotificationCounters {
    pub fn snapshot(&self) -> NotificationStats {
        let load = |n: &AtomicU64| n.load(Ordering::Relaxed);
        NotificationStats {
            ai_enqueued: load(&self.ai_enqueued),
            deny_enqueued: load(&self.deny_enqueued),
            ai_queue_full: load(&self.ai_queue_full),
            deny_queue_full: load(&self.deny_queue_full),
            ai_accepted: load(&self.ai_accepted),
            deny_accepted: load(&self.deny_accepted),
            ai_permanent_failure: load(&self.ai_permanent_failure),
            deny_permanent_failure: load(&self.deny_permanent_failure),
            ai_retries: load(&self.ai_retries),
            deny_retries: load(&self.deny_retries),
            ai_emergency_queued: load(&self.ai_emergency_queued),
            ai_spool_failed: load(&self.ai_spool_failed),
            ai_save_failed: load(&self.ai_save_failed),
            deny_save_failed: load(&self.deny_save_failed),
        }
    }

    pub(crate) fn increment_accepted(&self, kind: NotificationKind) {
        match kind {
            NotificationKind::Ai => &self.ai_accepted,
            NotificationKind::Deny => &self.deny_accepted,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_retry(&self, kind: NotificationKind) {
        match kind {
            NotificationKind::Ai => &self.ai_retries,
            NotificationKind::Deny => &self.deny_retries,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_save_failed(&self, kind: NotificationKind) {
        match kind {
            NotificationKind::Ai => &self.ai_save_failed,
            NotificationKind::Deny => &self.deny_save_failed,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn increment_permanent_failure(&self, kind: NotificationKind) {
        match kind {
            NotificationKind::Ai => &self.ai_permanent_failure,
            NotificationKind::Deny => &self.deny_permanent_failure,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct NotificationHandle {
    ai_tx: mpsc::Sender<NotificationRequest>,
    deny_tx: mpsc::Sender<NotificationRequest>,
    pub(crate) counters: Arc<NotificationCounters>,
    emergency_tx: Option<mpsc::Sender<NotificationRequest>>,
    accepting: Arc<AtomicBool>,
}

impl NotificationHandle {
    pub(crate) fn new(
        ai_tx: mpsc::Sender<NotificationRequest>,
        deny_tx: mpsc::Sender<NotificationRequest>,
        counters: Arc<NotificationCounters>,
    ) -> Self {
        Self {
            ai_tx,
            deny_tx,
            counters,
            emergency_tx: None,
            accepting: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(crate) fn with_emergency(
        mut self,
        emergency_tx: mpsc::Sender<NotificationRequest>,
    ) -> Self {
        self.emergency_tx = Some(emergency_tx);
        self
    }
    pub(crate) fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    /// Safe for use in the decision/AI event processing path: never awaits IPC.
    /// The caller owns generation of a unique notification_id and role resolution.
    pub fn try_enqueue_ai(&self, request: NotificationRequest) -> Result<(), EnqueueError> {
        self.try_enqueue(NotificationKind::Ai, request)
    }

    pub fn try_enqueue_deny(&self, request: NotificationRequest) -> Result<(), EnqueueError> {
        self.try_enqueue(NotificationKind::Deny, request)
    }

    fn try_enqueue(
        &self,
        kind: NotificationKind,
        request: NotificationRequest,
    ) -> Result<(), EnqueueError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(EnqueueError::QueueClosed);
        }
        if NotificationKind::from_request(&request) != kind {
            return Err(EnqueueError::WrongKind);
        }
        request.validate().map_err(EnqueueError::InvalidRequest)?;
        let (tx, enqueued, full) = match kind {
            NotificationKind::Ai => (
                &self.ai_tx,
                &self.counters.ai_enqueued,
                &self.counters.ai_queue_full,
            ),
            NotificationKind::Deny => (
                &self.deny_tx,
                &self.counters.deny_enqueued,
                &self.counters.deny_queue_full,
            ),
        };
        match tx.try_send(request) {
            Ok(()) => {
                enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(request)) => {
                full.fetch_add(1, Ordering::Relaxed);
                if kind == NotificationKind::Ai {
                    if let Some(emergency) = &self.emergency_tx {
                        if emergency.try_send(request).is_ok() {
                            self.counters
                                .ai_emergency_queued
                                .fetch_add(1, Ordering::Relaxed);
                            return Ok(());
                        }
                        self.counters
                            .ai_spool_failed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(EnqueueError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(EnqueueError::QueueClosed),
        }
    }

    pub fn stats(&self) -> NotificationStats {
        self.counters.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use teal_notify_protocol::{AiNotification, DenyNotification, PROTOCOL_VERSION};

    fn ai_request() -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "Q-AI".into(),
            recipients: vec![],
            payload: NotificationPayload::Ai(AiNotification {
                hostname: "host".into(),
                confidence: 0.96,
                reason: "test".into(),
                related_event_ids: vec![],
                program: "/bin/true".into(),
                action: "EXEC".into(),
                target: "/bin/true".into(),
            }),
        }
    }

    fn deny_request() -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "Q-DENY".into(),
            recipients: vec![],
            payload: NotificationPayload::Deny(DenyNotification {
                hostname: "host".into(),
                uid: 0,
                pid: None,
                program: "/bin/true".into(),
                action: "EXEC".into(),
                rule_id: None,
                policy_epoch: 1,
                target_parent: "/bin".into(),
                target_samples: vec![],
                count: 1,
                first_seen: "2026-11-05T00:00:00Z".into(),
                last_seen: "2026-11-05T00:00:00Z".into(),
                representative_event_id: "E-1".into(),
                early_flush: false,
            }),
        }
    }

    #[test]
    fn full_queue_fails_without_waiting_and_is_counted() {
        let (ai_tx, _ai_rx) = mpsc::channel(1);
        let (deny_tx, _deny_rx) = mpsc::channel(1);
        let handle =
            NotificationHandle::new(ai_tx, deny_tx, Arc::new(NotificationCounters::default()));
        handle.try_enqueue_ai(ai_request()).unwrap();
        assert_eq!(
            handle.try_enqueue_ai(ai_request()),
            Err(EnqueueError::QueueFull)
        );
        handle.try_enqueue_deny(deny_request()).unwrap();
        assert_eq!(handle.stats().ai_queue_full, 1);
        assert_eq!(handle.stats().ai_enqueued, 1);
        assert_eq!(handle.stats().deny_enqueued, 1);
    }

    #[test]
    fn mismatched_payload_is_rejected() {
        let (ai_tx, _ai_rx) = mpsc::channel(1);
        let (deny_tx, _deny_rx) = mpsc::channel(1);
        let handle =
            NotificationHandle::new(ai_tx, deny_tx, Arc::new(NotificationCounters::default()));
        assert_eq!(
            handle.try_enqueue_deny(ai_request()),
            Err(EnqueueError::WrongKind)
        );
        assert_eq!(handle.stats().deny_enqueued, 0);
    }
}
