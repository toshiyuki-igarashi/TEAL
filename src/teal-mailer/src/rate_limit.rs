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
