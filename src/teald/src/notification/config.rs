// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Initial, in-process configuration for the teald notification transport.
//! JSON configuration and role resolution are integrated in a later step.

use std::{path::PathBuf, time::Duration};
use teal_common::TEAL_NOTIFY_SOCKET_PATH;

pub const AI_QUEUE_CAPACITY: usize = 128;
pub const DENY_QUEUE_CAPACITY: usize = 896;

#[derive(Debug, Clone)]
pub struct NotificationTransportConfig {
    pub socket_path: PathBuf,
    pub ai_queue_capacity: usize,
    pub deny_queue_capacity: usize,
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    /// Must exceed teal-mailer's 40-second SMTP timeout, with startup margin.
    pub response_timeout: Duration,
    pub retry_initial_delay: Duration,
    pub retry_max_delay: Duration,
    pub retry_max_attempts: u32,
    pub retry_max_elapsed: Duration,
    pub rate_limit_wait: Duration,
    pub recovery_path: PathBuf,
    pub recovery_max_total_bytes: u64,
    pub recovery_max_undelivered_records: usize,
    pub ai_emergency_spool_capacity: usize,
    pub shutdown_grace: Duration,
    pub shutdown_save_max_attempts: u32,
    pub shutdown_save_retry_delay: Duration,
}

impl Default for NotificationTransportConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(TEAL_NOTIFY_SOCKET_PATH),
            ai_queue_capacity: AI_QUEUE_CAPACITY,
            deny_queue_capacity: DENY_QUEUE_CAPACITY,
            connect_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(90),
            retry_initial_delay: Duration::from_secs(10),
            retry_max_delay: Duration::from_secs(120),
            retry_max_attempts: 5,
            retry_max_elapsed: Duration::from_secs(600),
            rate_limit_wait: Duration::from_secs(60),
            recovery_path: PathBuf::from("/var/lib/teal/notifications"),
            recovery_max_total_bytes: 256 * 1024 * 1024,
            recovery_max_undelivered_records: 4096,
            ai_emergency_spool_capacity: 64,
            shutdown_grace: Duration::from_secs(15),
            shutdown_save_max_attempts: 3,
            shutdown_save_retry_delay: Duration::from_millis(100),
        }
    }
}

impl NotificationTransportConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.socket_path.is_absolute() {
            return Err("notification socket_path must be absolute");
        }
        if self.ai_queue_capacity == 0 || self.deny_queue_capacity == 0 {
            return Err("notification queue capacity must be positive");
        }
        if self
            .ai_queue_capacity
            .checked_add(self.deny_queue_capacity)
            .is_none()
        {
            return Err("notification queue capacity overflow");
        }
        if self.connect_timeout.is_zero()
            || self.write_timeout.is_zero()
            || self.response_timeout.is_zero()
        {
            return Err("notification IPC timeouts must be positive");
        }
        if self.retry_initial_delay.is_zero()
            || self.retry_max_delay.is_zero()
            || self.retry_initial_delay > self.retry_max_delay
        {
            return Err("notification retry interval is invalid");
        }
        if self.retry_max_attempts == 0
            || self.retry_max_elapsed.is_zero()
            || self.rate_limit_wait.is_zero()
        {
            return Err("notification retry maximums must be positive");
        }
        if !self.recovery_path.is_absolute()
            || self.recovery_max_total_bytes == 0
            || self.recovery_max_undelivered_records == 0
            || self.ai_emergency_spool_capacity == 0
        {
            return Err("notification recovery limits/path invalid");
        }
        if self.shutdown_grace.is_zero()
            || self.shutdown_save_max_attempts == 0
            || self.shutdown_save_retry_delay.is_zero()
        {
            return Err("notification graceful shutdown limits invalid");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_matches_phase2_spec() {
        let c = NotificationTransportConfig::default();
        assert_eq!(c.ai_queue_capacity, 128);
        assert_eq!(c.deny_queue_capacity, 896);
        assert_eq!(c.ai_queue_capacity + c.deny_queue_capacity, 1024);
        assert_eq!(c.socket_path.to_str(), Some("/run/teal/teal-notify.sock"));
        c.validate().unwrap();
    }
}
