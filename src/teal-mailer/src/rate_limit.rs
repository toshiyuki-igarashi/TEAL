// SPDX-License-Identifier: MIT
/*
 * TEAL mailer for Notification (teal-mailer)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Independent strict sliding 60-second SMTP attempt budgets for AI and DENY.
//!
//! The mailer never buffers or retries an over-limit request. It returns
//! RetryableError/RATE_LIMIT and leaves the same-ID retry to teald.

use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};
use teal_notify_protocol::NotificationPayload;

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct SlidingWindow {
    limit: usize,
    used: VecDeque<Instant>,
}

impl SlidingWindow {
    fn new(limit: u32) -> Self {
        Self {
            limit: limit as usize,
            used: VecDeque::new(),
        }
    }

    fn allow_at(&mut self, now: Instant) -> bool {
        while self
            .used
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= WINDOW)
        {
            self.used.pop_front();
        }
        if self.used.len() >= self.limit {
            return false;
        }
        // Reserve BEFORE SMTP to bound concurrent sends. Failed sends also
        // consume an attempt, preventing an SMTP failure storm.
        self.used.push_back(now);
        true
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    ai: Mutex<SlidingWindow>,
    deny: Mutex<SlidingWindow>,
}

impl RateLimiter {
    pub fn new(ai_per_minute: u32, deny_per_minute: u32) -> Self {
        assert!(ai_per_minute > 0 && deny_per_minute > 0);
        Self {
            ai: Mutex::new(SlidingWindow::new(ai_per_minute)),
            deny: Mutex::new(SlidingWindow::new(deny_per_minute)),
        }
    }

    pub fn allow(&self, payload: &NotificationPayload) -> bool {
        let lock = match payload {
            NotificationPayload::Ai(_) => &self.ai,
            NotificationPayload::Deny(_) => &self.deny,
        };
        lock.lock()
            .unwrap_or_else(|err| err.into_inner())
            .allow_at(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictly_limits_each_rolling_minute() {
        let mut budget = SlidingWindow::new(5);
        let start = Instant::now();
        for _ in 0..5 {
            assert!(budget.allow_at(start));
        }
        assert!(!budget.allow_at(start));
        assert!(!budget.allow_at(start + Duration::from_secs(59)));
        assert!(budget.allow_at(start + Duration::from_secs(60)));
    }

    #[test]
    fn successive_calls_do_not_reset_window() {
        let mut budget = SlidingWindow::new(2);
        let start = Instant::now();
        assert!(budget.allow_at(start));
        assert!(budget.allow_at(start + Duration::from_secs(30)));
        assert!(!budget.allow_at(start + Duration::from_secs(31)));
        assert!(budget.allow_at(start + Duration::from_secs(60)));
        assert!(!budget.allow_at(start + Duration::from_secs(61)));
        assert!(budget.allow_at(start + Duration::from_secs(90)));
    }

    #[test]
    fn ai_and_deny_have_independent_budgets() {
        let mut ai = SlidingWindow::new(1);
        let mut deny = SlidingWindow::new(2);
        let start = Instant::now();
        assert!(ai.allow_at(start));
        assert!(!ai.allow_at(start));
        assert!(deny.allow_at(start));
        assert!(deny.allow_at(start));
        assert!(!deny.allow_at(start));
    }
}

// Standalone concurrency tests. Appended to src/rate_limit.rs by apply.py.
#[cfg(test)]
mod phase4_parallel_rate_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };
    use std::thread;
    use teal_notify_protocol::{AiNotification, DenyNotification};

    fn ai() -> NotificationPayload {
        NotificationPayload::Ai(AiNotification {
            hostname: "unit-test".into(),
            confidence: 0.98,
            reason: "load test".into(),
            related_event_ids: vec!["TEST-ALLOW".into()],
            program: "/usr/bin/true".into(),
            action: "READ".into(),
            target: "/var/tmp/test".into(),
        })
    }

    fn deny() -> NotificationPayload {
        NotificationPayload::Deny(DenyNotification {
            hostname: "unit-test".into(),
            uid: 1000,
            pid: None,
            program: "/usr/bin/true".into(),
            action: "READ".into(),
            rule_id: None,
            policy_epoch: 1,
            target_parent: "/var/tmp".into(),
            target_samples: vec!["/var/tmp/test".into()],
            count: 1,
            first_seen: "2026-11-10T00:00:00Z".into(),
            last_seen: "2026-11-10T00:00:00Z".into(),
            representative_event_id: "TEST-DENY".into(),
            early_flush: false,
        })
    }

    #[test]
    fn concurrent_mixed_flood_respects_10_ai_and_5_deny_budgets() {
        let limiter = Arc::new(RateLimiter::new(10, 5));
        let ai_payload = Arc::new(ai());
        let deny_payload = Arc::new(deny());
        let started = Arc::new(Barrier::new(20));
        let ai_allowed = Arc::new(AtomicUsize::new(0));
        let deny_allowed = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();

        for index in 0..20 {
            let limiter = Arc::clone(&limiter);
            let a = Arc::clone(&ai_payload);
            let d = Arc::clone(&deny_payload);
            let start = Arc::clone(&started);
            let ai_count = Arc::clone(&ai_allowed);
            let deny_count = Arc::clone(&deny_allowed);
            threads.push(thread::spawn(move || {
                start.wait();
                for _ in 0..50 {
                    if index % 2 == 0 {
                        if limiter.allow(&a) {
                            ai_count.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if limiter.allow(&d) {
                        deny_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for worker in threads {
            worker.join().unwrap();
        }
        assert_eq!(ai_allowed.load(Ordering::Relaxed), 10);
        assert_eq!(deny_allowed.load(Ordering::Relaxed), 5);
        // 1,000 attempted notifications; only 15 SMTP slots reserved.
    }

    #[test]
    fn exhausting_one_kind_does_not_exhaust_the_other() {
        let limiter = RateLimiter::new(2, 1);
        assert!(limiter.allow(&ai()));
        assert!(limiter.allow(&ai()));
        assert!(!limiter.allow(&ai()));
        assert!(limiter.allow(&deny()));
        assert!(!limiter.allow(&deny()));
    }
}
