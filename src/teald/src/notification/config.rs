// SPDX-License-Identifier: MIT
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
            retry_initial_delay: Duration::from_secs(2),
            retry_max_delay: Duration::from_secs(60),
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
        if self.ai_queue_capacity.checked_add(self.deny_queue_capacity).is_none() {
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
