// SPDX-License-Identifier: MIT
//! Fixed-window aggregation of actual ENFORCE DENY notifications.
//!
//! Aggregation is independent of SMTP, IPC, and the audit log. Time windows
//! use a monotonic clock, while first_seen/last_seen retain audit timestamps.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use teal_notify_protocol::{NotificationPayload, NotificationRequest, MAX_TARGET_SAMPLES};
use tokio::time::MissedTickBehavior;

use super::{EnqueueError, NotificationHandle};

pub const DENY_WINDOW: Duration = Duration::from_secs(300);
pub const DENY_MAX_GROUPS: usize = 1000;
pub const DENY_TARGET_SAMPLE_LIMIT: usize = MAX_TARGET_SAMPLES;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggregationKey {
    hostname: String,
    uid: u32,
    program: String,
    action: String,
    rule_id: Option<String>,
    target_parent: String,
    policy_epoch: u32,
}

impl AggregationKey {
    fn from_request(req: &NotificationRequest) -> Option<Self> {
        let NotificationPayload::Deny(deny) = &req.payload else {
            return None;
        };
        Some(Self {
            hostname: deny.hostname.clone(),
            uid: deny.uid,
            program: deny.program.clone(),
            action: deny.action.clone(),
            rule_id: deny.rule_id.clone(),
            target_parent: deny.target_parent.clone(),
            policy_epoch: deny.policy_epoch,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AggregationConfig {
    pub window: Duration,
    pub max_groups: usize,
    pub sample_limit: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            window: DENY_WINDOW,
            max_groups: DENY_MAX_GROUPS,
            sample_limit: DENY_TARGET_SAMPLE_LIMIT,
        }
    }
}

#[derive(Debug)]
struct Group {
    created: Instant,
    deadline: Instant,
    /// Events after the immediate notification, or a notification that
    /// could not enter the bounded delivery queue.
    pending: Option<NotificationRequest>,
    /// Retry time for a notification rejected by the bounded queue; this is
    /// separate from the original fixed aggregation deadline.
    retry_at: Option<Instant>,
}

/// Pure state machine; all mutations are performed in a short mutex section
/// by AggregationDispatcher, never across an await.
#[derive(Debug)]
pub struct DenyAggregator {
    groups: HashMap<AggregationKey, Group>,
    config: AggregationConfig,
}

impl DenyAggregator {
    pub fn new(config: AggregationConfig) -> Self {
        assert!(config.window > Duration::ZERO);
        assert!(config.max_groups > 0);
        assert!((1..=MAX_TARGET_SAMPLES).contains(&config.sample_limit));
        Self {
            groups: HashMap::new(),
            config,
        }
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// The caller has already validated that this is one real DENY event.
    /// Returns notifications to enqueue without waiting; the first event for
    /// a new key is returned immediately, and is not double-counted.
    pub fn add_event(
        &mut self,
        request: NotificationRequest,
        now: Instant,
    ) -> Vec<NotificationRequest> {
        let key = AggregationKey::from_request(&request)
            .expect("DenyAggregator accepts only DENY requests");
        let mut outgoing = Vec::with_capacity(2);

        // Handle a window that expired before the periodic sweeper ran.
        let mut remove = false;
        if let Some(group) = self.groups.get_mut(&key) {
            if now >= group.deadline {
                let had_pending = group.pending.is_some();
                if let Some(summary) = group.pending.take() {
                    outgoing.push(summary);
                }
                // Do not extend a window from the last event. A long idle
                // interval starts a fresh group (and an immediate alert).
                if !had_pending
                    || now.saturating_duration_since(group.deadline) >= self.config.window
                {
                    remove = true;
                } else {
                    group.deadline += self.config.window;
                    group.retry_at = None;
                }
            }
        }
        if remove {
            self.groups.remove(&key);
        }

        if let Some(group) = self.groups.get_mut(&key) {
            match &mut group.pending {
                Some(existing) => merge(existing, &request, self.config.sample_limit),
                None => group.pending = Some(as_summary(request)),
            }
        } else {
            if self.groups.len() == self.config.max_groups {
                if let Some(oldest) = self
                    .groups
                    .iter()
                    .min_by_key(|(_, group)| group.created)
                    .map(|(key, _)| key.clone())
                {
                    if let Some(mut displaced) =
                        self.groups.remove(&oldest).and_then(|group| group.pending)
                    {
                        if let NotificationPayload::Deny(deny) = &mut displaced.payload {
                            deny.early_flush = true;
                        }
                        outgoing.push(displaced);
                    }
                }
            }
            self.groups.insert(
                key,
                Group {
                    created: now,
                    deadline: now + self.config.window,
                    pending: None,
                    retry_at: None,
                },
            );
            outgoing.push(request);
        }
        outgoing
    }

    /// Called periodically. Send only when at least one event was aggregated;
    /// a quiet window generates no follow-up email.
    pub fn flush_expired(&mut self, now: Instant) -> Vec<NotificationRequest> {
        let mut outgoing = Vec::new();
        let window = self.config.window;
        self.groups.retain(|_, group| {
            if now < group.deadline {
                if group.retry_at.is_some_and(|retry| now >= retry) {
                    if let Some(summary) = group.pending.take() {
                        outgoing.push(summary);
                    }
                    group.retry_at = None;
                }
                return true;
            }
            group.retry_at = None;
            match group.pending.take() {
                Some(summary) => {
                    outgoing.push(summary);
                    // Keep one more anchored window for continuous activity.
                    // If the timer was late by a full extra window, expire it.
                    if now.saturating_duration_since(group.deadline) >= window {
                        false
                    } else {
                        group.deadline += window;
                        true
                    }
                }
                None => false,
            }
        });
        outgoing
    }

    /// Preserve a failed enqueue within its existing aggregation group, so
    /// transient queue pressure does not immediately lose the event count.
    /// Returns false if the group was already evicted or expired.
    pub fn requeue_failed(&mut self, request: NotificationRequest, now: Instant) -> bool {
        let Some(key) = AggregationKey::from_request(&request) else {
            return false;
        };
        let Some(group) = self.groups.get_mut(&key) else {
            return false;
        };
        if let Some(pending) = &mut group.pending {
            // An older failed notification must remain the representative.
            let mut original = request;
            merge(&mut original, pending, self.config.sample_limit);
            group.pending = Some(original);
        } else {
            group.pending = Some(request);
        }
        // Retry on the next 1s sweeper tick. Do not move the fixed 300s
        // boundary just because the delivery queue is under pressure.
        group.retry_at = Some(now + Duration::from_secs(1));
        true
    }
}

fn as_summary(mut request: NotificationRequest) -> NotificationRequest {
    // Original audit IDs are bounded by deny_event::build_request. A distinct
    // prefix makes the aggregate notification ID unique and retry-stable.
    let original = request
        .notification_id
        .strip_prefix("DENY-")
        .unwrap_or(&request.notification_id);
    request.notification_id = format!("DAG-{original}");
    request
}

fn merge(existing: &mut NotificationRequest, next: &NotificationRequest, sample_limit: usize) {
    let (NotificationPayload::Deny(a), NotificationPayload::Deny(b)) =
        (&mut existing.payload, &next.payload)
    else {
        unreachable!()
    };
    a.count = a.count.saturating_add(b.count);
    if b.first_seen < a.first_seen {
        a.first_seen.clone_from(&b.first_seen);
    }
    if b.last_seen > a.last_seen {
        a.last_seen.clone_from(&b.last_seen);
    }
    for sample in &b.target_samples {
        if a.target_samples.len() >= sample_limit {
            break;
        }
        if !a.target_samples.contains(sample) {
            a.target_samples.push(sample.clone());
        }
    }
    a.early_flush |= b.early_flush;
}

/// Owns aggregate state; event producers never perform socket I/O or await.
/// Queue-full summaries are kept in their group when possible; unrecoverable
/// losses are counted and periodically reported (not silently discarded).
#[derive(Debug)]
pub struct AggregationDispatcher {
    state: Mutex<DenyAggregator>,
    handle: NotificationHandle,
    overflow_attempts: AtomicU64,
    unrecoverable_events: AtomicU64,
}

impl AggregationDispatcher {
    pub fn new(handle: NotificationHandle, config: AggregationConfig) -> Self {
        Self {
            state: Mutex::new(DenyAggregator::new(config)),
            handle,
            overflow_attempts: AtomicU64::new(0),
            unrecoverable_events: AtomicU64::new(0),
        }
    }

    pub fn submit(&self, request: NotificationRequest) {
        let now = Instant::now();
        let outgoing = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add_event(request, now);
        self.dispatch(outgoing, now);
    }

    pub fn tick(&self) {
        let now = Instant::now();
        let outgoing = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .flush_expired(now);
        self.dispatch(outgoing, now);
    }

    fn dispatch(&self, outgoing: Vec<NotificationRequest>, now: Instant) {
        for request in outgoing {
            // This work is non-blocking: mpsc::Sender::try_send only.
            match self.handle.try_enqueue_deny(request.clone()) {
                Ok(()) => {}
                Err(EnqueueError::QueueFull) => {
                    self.overflow_attempts.fetch_add(1, Ordering::Relaxed);
                    if !self
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .requeue_failed(request.clone(), now)
                    {
                        self.count_unrecoverable(&request);
                    }
                }
                Err(err) => {
                    eprintln!("[TEAL][notify][Deny][ERROR] cannot enqueue aggregate: {err:?}");
                    self.count_unrecoverable(&request);
                }
            }
        }
    }

    fn count_unrecoverable(&self, request: &NotificationRequest) {
        if let NotificationPayload::Deny(deny) = &request.payload {
            self.unrecoverable_events
                .fetch_add(deny.count, Ordering::Relaxed);
        }
    }

    pub fn overflow_stats(&self) -> (u64, u64) {
        (
            self.overflow_attempts.load(Ordering::Relaxed),
            self.unrecoverable_events.load(Ordering::Relaxed),
        )
    }

    pub async fn run_sweeper(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_report = Instant::now();
        loop {
            interval.tick().await;
            self.tick();
            if last_report.elapsed() >= Duration::from_secs(60) {
                let (overflows, losses) = self.overflow_stats();
                if overflows > 0 || losses > 0 {
                    eprintln!(
                        "[TEAL][notify][Deny][WARN] cumulative queue-full attempts={overflows}, unrecoverable DENY events={losses}"
                    );
                }
                last_report = Instant::now();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::queue::{NotificationCounters, NotificationHandle};
    use super::*;
    use std::sync::Arc;
    use teal_notify_protocol::{DenyNotification, PROTOCOL_VERSION};
    use tokio::sync::mpsc;

    fn request(id: &str, path: &str, epoch: u32) -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: format!("DENY-{id}"),
            recipients: vec![],
            payload: NotificationPayload::Deny(DenyNotification {
                hostname: "host".into(),
                uid: 1000,
                pid: Some(42),
                program: "/usr/bin/cat".into(),
                action: "READ".into(),
                rule_id: Some("deny-test".into()),
                policy_epoch: epoch,
                target_parent: "/var/backups".into(),
                target_samples: vec![path.into()],
                count: 1,
                first_seen: format!("2026-11-05T12:00:{id}Z"),
                last_seen: format!("2026-11-05T12:00:{id}Z"),
                representative_event_id: id.into(),
                early_flush: false,
            }),
        }
    }

    fn count(request: &NotificationRequest) -> u64 {
        let NotificationPayload::Deny(d) = &request.payload else {
            unreachable!()
        };
        d.count
    }

    #[test]
    fn first_immediate_followups_aggregated_fixed_window() {
        let mut a = DenyAggregator::new(AggregationConfig::default());
        let t = Instant::now();
        assert_eq!(a.add_event(request("01", "/var/backups/a", 1), t).len(), 1);
        assert!(a
            .add_event(
                request("02", "/var/backups/b", 1),
                t + Duration::from_secs(5)
            )
            .is_empty());
        assert!(a
            .add_event(
                request("03", "/var/backups/a", 1),
                t + Duration::from_secs(250)
            )
            .is_empty());
        assert!(a.flush_expired(t + Duration::from_secs(299)).is_empty());
        let notices = a.flush_expired(t + Duration::from_secs(300));
        assert_eq!(notices.len(), 1);
        assert_eq!(count(&notices[0]), 2);
        let NotificationPayload::Deny(d) = &notices[0].payload else {
            unreachable!()
        };
        assert_eq!(d.target_samples, vec!["/var/backups/b", "/var/backups/a"]);
        assert!(!d.early_flush);
        assert_eq!(notices[0].notification_id, "DAG-02");
        assert!(a.flush_expired(t + Duration::from_secs(600)).is_empty());
        assert_eq!(a.group_count(), 0);
    }

    #[test]
    fn continuous_denials_use_second_fixed_window() {
        let mut a = DenyAggregator::new(AggregationConfig::default());
        let t = Instant::now();
        assert_eq!(a.add_event(request("01", "a", 1), t).len(), 1);
        assert!(a
            .add_event(request("02", "b", 1), t + Duration::from_secs(40))
            .is_empty());
        assert_eq!(count(&a.flush_expired(t + Duration::from_secs(300))[0]), 1);
        assert!(a
            .add_event(request("03", "c", 1), t + Duration::from_secs(320))
            .is_empty());
        assert_eq!(count(&a.flush_expired(t + Duration::from_secs(600))[0]), 1);
    }

    #[test]
    fn epoch_change_creates_independent_group_and_immediate_notice() {
        let mut a = DenyAggregator::new(AggregationConfig::default());
        let now = Instant::now();
        assert_eq!(a.add_event(request("01", "a", 17), now).len(), 1);
        assert_eq!(a.add_event(request("02", "b", 18), now).len(), 1);
        assert_eq!(a.group_count(), 2);
    }

    #[test]
    fn sample_limit_and_group_eviction() {
        let mut config = AggregationConfig::default();
        config.sample_limit = 2;
        config.max_groups = 1;
        let mut a = DenyAggregator::new(config);
        let t = Instant::now();
        a.add_event(request("01", "a", 1), t);
        a.add_event(request("02", "b", 1), t);
        a.add_event(request("03", "c", 1), t);
        let notices = a.add_event(request("04", "d", 2), t);
        assert_eq!(notices.len(), 2);
        let NotificationPayload::Deny(summary) = &notices[0].payload else {
            unreachable!()
        };
        assert_eq!(summary.target_samples, vec!["b", "c"]);
        assert!(summary.early_flush);
        assert_eq!(summary.count, 2);
        assert_eq!(a.group_count(), 1);
    }

    #[test]
    fn failed_enqueue_can_be_retried_without_losing_count() {
        let (ai_tx, _ai_rx) = mpsc::channel(1);
        let (deny_tx, mut deny_rx) = mpsc::channel(1);
        let handle =
            NotificationHandle::new(ai_tx, deny_tx, Arc::new(NotificationCounters::default()));
        let d = AggregationDispatcher::new(handle, AggregationConfig::default());
        d.submit(request("01", "a", 1));
        d.submit(request("02", "b", 1));
        assert_eq!(deny_rx.try_recv().unwrap().notification_id, "DENY-01");
        // Wait until the real monotonic 300s window expires is impractical;
        // exercise the no-blocking queue-full restoration directly.
        let another = request("03", "c", 2);
        d.handle.try_enqueue_deny(another).unwrap();
        d.submit(request("04", "d", 3));
        assert_eq!(d.overflow_stats().0, 1);
        assert_eq!(d.overflow_stats().1, 0);
    }
}
