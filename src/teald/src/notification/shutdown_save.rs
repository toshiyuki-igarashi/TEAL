// SPDX-License-Identifier: MIT
//! Phase 5 Step 3: the entire normal-shutdown snapshot retry sequence shares
//! one deadline.  A failed save is attempted no more than the configured limit.

use std::{future::Future, io};
use tokio::time::{sleep, timeout_at, Instant};

use super::config::NotificationTransportConfig;

fn deadline_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "notification shutdown snapshot save deadline exceeded",
    )
}

pub(super) async fn persist_with_retry<F, Fut>(
    config: &NotificationTransportConfig,
    mut save: F,
) -> io::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    // One budget across ALL save attempts and inter-attempt sleeps.
    // This does not reset for the second or third attempt.
    let deadline = Instant::now() + config.shutdown_grace;
    let mut last_error = io::Error::other("notification snapshot save was not attempted");
    for attempt in 0..config.shutdown_save_max_attempts {
        match timeout_at(deadline, save()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => last_error = error,
            Err(_) => return Err(deadline_error()),
        }
        if attempt + 1 < config.shutdown_save_max_attempts {
            timeout_at(deadline, sleep(config.shutdown_save_retry_delay))
                .await
                .map_err(|_| deadline_error())?;
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn three_failures_mean_exactly_three_attempts() {
        let mut config = NotificationTransportConfig::default();
        assert_eq!(config.shutdown_save_max_attempts, 3);
        assert_eq!(config.shutdown_grace, Duration::from_secs(15));
        config.shutdown_save_retry_delay = Duration::from_millis(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let outcome = persist_with_retry(&config, move || {
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "injected disk full",
                ))
            }
        })
        .await;
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn third_attempt_can_succeed() {
        let mut config = NotificationTransportConfig::default();
        config.shutdown_save_retry_delay = Duration::from_millis(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        persist_with_retry(&config, move || {
            let count = Arc::clone(&count);
            async move {
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err(io::Error::other("temporary disk error"))
                } else {
                    Ok(())
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn one_hanging_save_cannot_consume_three_independent_deadlines() {
        // Scale the real 15-second production budget to 90ms for a fast test.
        let mut config = NotificationTransportConfig::default();
        config.shutdown_grace = Duration::from_millis(90);
        config.shutdown_save_retry_delay = Duration::from_millis(2);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            persist_with_retry(&config, move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    sleep(Duration::from_secs(1)).await;
                    Ok(())
                }
            }),
        )
        .await
        .expect("the shutdown saver must terminate promptly");
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_millis(750));
    }

    #[tokio::test]
    async fn failures_plus_delays_share_one_deadline() {
        // The third call may start, but cannot run to completion after 110ms.
        let mut config = NotificationTransportConfig::default();
        config.shutdown_grace = Duration::from_millis(110);
        config.shutdown_save_max_attempts = 10;
        config.shutdown_save_retry_delay = Duration::from_millis(10);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            persist_with_retry(&config, move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    sleep(Duration::from_millis(45)).await;
                    Err(io::Error::other("injected transient write failure"))
                }
            }),
        )
        .await
        .expect("the shutdown saver must terminate promptly");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(calls.load(Ordering::SeqCst) < 10);
        assert!(started.elapsed() < Duration::from_millis(750));
    }
}
