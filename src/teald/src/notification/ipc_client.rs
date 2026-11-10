// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! teald -> teal-mailer: one length-prefixed JSON request per Unix connection.
//! Retries belong exclusively to teald, never to teal-mailer.

use std::io;
use std::time::Duration;

use teal_notify_protocol::{
    DeliveryResponse, DeliveryStatus, NotificationRequest, MAX_FRAME_LENGTH,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::mpsc,
    time::{sleep, timeout},
};

use super::{
    config::NotificationTransportConfig,
    queue::{NotificationCounters, NotificationKind},
};
use std::sync::Arc;

#[derive(Debug)]
pub enum IpcError {
    /// The mailer may already have accepted the notification. Retrying might duplicate it.
    Retryable(io::Error),
    /// Incompatible response, invalid ID, or a locally invalid request.
    Permanent(&'static str),
}

fn io_error(error: io::Error) -> IpcError {
    IpcError::Retryable(error)
}

fn timed_out(what: &'static str) -> IpcError {
    IpcError::Retryable(io::Error::new(io::ErrorKind::TimedOut, what))
}

/// A single attempt, without retry. The caller retains ownership of request.
/// The response timeout is deliberately longer than teal-mailer's SMTP timeout.
pub async fn send_notification(
    config: &NotificationTransportConfig,
    request: &NotificationRequest,
) -> Result<DeliveryResponse, IpcError> {
    request.validate().map_err(IpcError::Permanent)?;
    let body = serde_json::to_vec(request)
        .map_err(|_| IpcError::Permanent("cannot serialize notification request"))?;
    if body.is_empty() || body.len() > MAX_FRAME_LENGTH {
        return Err(IpcError::Permanent(
            "notification request exceeds IPC frame limit",
        ));
    }

    let mut stream = timeout(
        config.connect_timeout,
        UnixStream::connect(&config.socket_path),
    )
    .await
    .map_err(|_| timed_out("teal-mailer connect timeout"))?
    .map_err(io_error)?;

    let frame_len = (body.len() as u32).to_be_bytes();
    timeout(config.write_timeout, async {
        stream.write_all(&frame_len).await?;
        stream.write_all(&body).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| timed_out("teal-mailer write timeout"))?
    .map_err(io_error)?;

    let response = timeout(config.response_timeout, async {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_FRAME_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response frame length",
            ));
        }
        let mut response_bytes = vec![0_u8; len];
        stream.read_exact(&mut response_bytes).await?;
        Ok::<_, io::Error>(response_bytes)
    })
    .await
    .map_err(|_| timed_out("teal-mailer response timeout"))?
    .map_err(|e| {
        if e.kind() == io::ErrorKind::InvalidData {
            IpcError::Permanent("invalid response frame length")
        } else {
            io_error(e)
        }
    })?;

    let result: DeliveryResponse = serde_json::from_slice(&response)
        .map_err(|_| IpcError::Permanent("invalid delivery response JSON"))?;
    if result.notification_id != request.notification_id {
        return Err(IpcError::Permanent(
            "delivery response notification_id mismatch",
        ));
    }
    Ok(result)
}

/// Legacy test entry point: no storage and no lifecycle signal. Production uses
/// `run_sender_managed` with the same bounded retry policy and durable storage.
#[cfg(test)]
pub(crate) async fn run_sender(
    kind: NotificationKind,
    rx: mpsc::Receiver<NotificationRequest>,
    config: NotificationTransportConfig,
    counters: Arc<NotificationCounters>,
) {
    let _ = run_sender_managed(kind, rx, config, counters, None, None, Vec::new()).await;
}

async fn stopping(signal: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match signal {
        Some(rx) => {
            if !*rx.borrow() {
                let _ = rx.changed().await;
            }
        }
        None => std::future::pending::<()>().await,
    }
}

/// A managed sender returns ALL in-memory work that still requires delivery when
/// normal shutdown is requested. It does not perform filesystem I/O in teald's
/// audit/decision workers. A deadline or exhausted budget becomes UNDELIVERED.
pub async fn run_sender_managed(
    kind: NotificationKind,
    mut rx: mpsc::Receiver<NotificationRequest>,
    config: NotificationTransportConfig,
    counters: Arc<NotificationCounters>,
    storage: Option<Arc<super::recovery::RecoveryStore>>,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    restored: Vec<super::recovery::PendingNotification>,
) -> Vec<super::recovery::PendingNotification> {
    use super::recovery::{now_ms, PendingNotification};
    use std::collections::VecDeque;
    let mut initial: VecDeque<_> = restored.into();
    let mut leftover = Vec::new();
    let mut stopped = false;

    loop {
        if shutdown.as_ref().is_some_and(|r| *r.borrow()) {
            stopped = true;
        }
        if stopped {
            break;
        }
        let mut job = if let Some(saved) = initial.pop_front() {
            saved
        } else {
            tokio::select! {
                _ = stopping(&mut shutdown) => { break; }
                msg = rx.recv() => match msg {
                    Some(request) => PendingNotification::fresh(request),
                    None => break,
                }
            }
        };
        let mut delay = config.retry_initial_delay;
        loop {
            if shutdown.as_ref().is_some_and(|r| *r.borrow()) {
                stopped = true;
                leftover.push(job);
                break;
            }
            if job.expired(&config) {
                let reason = if job.attempts >= config.retry_max_attempts {
                    "RETRY_EXHAUSTED"
                } else {
                    "RETRY_DEADLINE"
                };
                fail_to_undelivered(kind, &job, reason, &storage, &counters, &config).await;
                break;
            }
            let start_ms = *job.first_attempt_ms.get_or_insert_with(now_ms);
            let elapsed_ms = now_ms().saturating_sub(start_ms);
            let remaining_ms =
                (config.retry_max_elapsed.as_millis() as u64).saturating_sub(elapsed_ms);
            if remaining_ms == 0 {
                fail_to_undelivered(kind, &job, "RETRY_DEADLINE", &storage, &counters, &config)
                    .await;
                break;
            }
            enum Outcome {
                Accepted,
                RateLimit,
                Retry(String, bool),
                Failed(String),
            }
            let result = tokio::select! {
                _ = stopping(&mut shutdown) => None,
                value = tokio::time::timeout(Duration::from_millis(remaining_ms), send_notification(&config, &job.request)) => Some(value),
            };
            // The send future is dropped before we move `job` into the snapshot.
            let Some(result) = result else {
                stopped = true;
                leftover.push(job);
                break;
            };
            let outcome = match result {
                Ok(Ok(reply)) => match reply.status {
                    DeliveryStatus::AcceptedBySmtp => Outcome::Accepted,
                    DeliveryStatus::RetryableError
                        if reply.error_code.as_deref() == Some("RATE_LIMIT") =>
                    {
                        Outcome::RateLimit
                    }
                    DeliveryStatus::RetryableError => Outcome::Retry(
                        reply.error_code.unwrap_or_else(|| "SMTP_TEMP".into()),
                        false,
                    ),
                    DeliveryStatus::PermanentError => {
                        Outcome::Failed(reply.error_code.unwrap_or_else(|| "SMTP_PERMANENT".into()))
                    }
                },
                Ok(Err(IpcError::Retryable(e))) => Outcome::Retry(e.to_string(), true),
                Ok(Err(IpcError::Permanent(reason))) => Outcome::Failed(reason.into()),
                Err(_) => Outcome::Retry("RETRY_DEADLINE".into(), true),
            };
            match outcome {
                Outcome::Accepted => {
                    counters.increment_accepted(kind);
                    eprintln!(
                        "[TEAL][notify][{:?}] accepted by SMTP: id={:?}",
                        kind, job.request.notification_id
                    );
                    break;
                }
                Outcome::Failed(reason) => {
                    job.attempts = job.attempts.saturating_add(1);
                    job.last_attempt_ms = Some(now_ms());
                    job.last_error = Some(reason.clone());
                    counters.increment_permanent_failure(kind);
                    fail_to_undelivered(kind, &job, &reason, &storage, &counters, &config).await;
                    break;
                }
                Outcome::Retry(reason, uncertain) => {
                    job.attempts = job.attempts.saturating_add(1);
                    job.last_attempt_ms = Some(now_ms());
                    job.last_error = Some(reason.clone());
                    job.delivery_uncertain |= uncertain;
                    if job.expired(&config) {
                        let reason = if job.attempts >= config.retry_max_attempts {
                            "RETRY_EXHAUSTED"
                        } else {
                            "RETRY_DEADLINE"
                        };
                        fail_to_undelivered(kind, &job, reason, &storage, &counters, &config).await;
                        break;
                    }
                    counters.increment_retry(kind);
                    eprintln!(
                        "[TEAL][notify][{:?}][WARN] retry in {:?}: id={:?} reason={:?}",
                        kind, delay, job.request.notification_id, reason
                    );
                }
                Outcome::RateLimit => {
                    job.last_error = Some("RATE_LIMIT".into());
                    // Production: avoid re-polling a rolling 60-second limiter.
                    // Legacy test entry point uses the configured test delay.
                    if storage.is_some() {
                        delay = delay.max(config.rate_limit_wait);
                    }
                }
            }
            let remaining = config
                .retry_max_elapsed
                .saturating_sub(Duration::from_millis(now_ms().saturating_sub(start_ms)));
            if remaining.is_zero() {
                fail_to_undelivered(kind, &job, "RETRY_DEADLINE", &storage, &counters, &config)
                    .await;
                break;
            }
            tokio::select! {
                _ = stopping(&mut shutdown) => { stopped = true; leftover.push(job); break; }
                _ = sleep(delay.min(remaining)) => {}
            }
            delay = delay.saturating_mul(2).min(config.retry_max_delay);
        }
        if stopped {
            break;
        }
    }
    leftover.extend(initial);
    while let Ok(msg) = rx.try_recv() {
        leftover.push(super::recovery::PendingNotification::fresh(msg));
    }
    leftover
}

async fn fail_to_undelivered(
    kind: NotificationKind,
    job: &super::recovery::PendingNotification,
    reason: &str,
    storage: &Option<Arc<super::recovery::RecoveryStore>>,
    counters: &Arc<NotificationCounters>,
    config: &NotificationTransportConfig,
) {
    if let Some(store) = storage {
        let saved = tokio::time::timeout(
            config.shutdown_grace,
            store.store_undelivered_async(job.clone(), reason.to_owned()),
        )
        .await;
        match saved {
            Ok(Ok(())) => eprintln!(
                "[TEAL][notify][{:?}] undelivered saved: id={:?} attempts={}",
                kind, job.request.notification_id, job.attempts
            ),
            other => {
                counters.increment_save_failed(kind);
                eprintln!(
                    "[TEAL][notify][{:?}][ERROR] SAVE_FAILED: id={:?} result={:?}",
                    kind, job.request.notification_id, other
                );
            }
        }
    } else {
        eprintln!(
            "[TEAL][notify][{:?}][WARN] no recovery store: id={:?} reason={reason}",
            kind, job.request.notification_id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use teal_notify_protocol::{AiNotification, NotificationPayload, PROTOCOL_VERSION};
    use tokio::{net::UnixListener, time::Instant};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestSocket(PathBuf);

    impl TestSocket {
        fn new() -> Self {
            let n = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let base =
                std::env::temp_dir().join(format!("teal-notify-{}-{n}.sock", std::process::id()));
            let _ = std::fs::remove_file(&base);
            Self(base)
        }
    }
    impl Drop for TestSocket {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn sample() -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "IPC-TEST-001".into(),
            recipients: vec![],
            payload: NotificationPayload::Ai(AiNotification {
                hostname: "test-host".into(),
                confidence: 0.99,
                reason: "test".into(),
                related_event_ids: vec![],
                program: "/usr/bin/true".into(),
                action: "EXEC".into(),
                target: "/usr/bin/true".into(),
            }),
        }
    }

    async fn answer_one(listener: &UnixListener, status: DeliveryStatus) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len_bytes = [0_u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let len = u32::from_be_bytes(len_bytes) as usize;
        assert!(len > 0 && len <= MAX_FRAME_LENGTH);
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await.unwrap();
        let request: NotificationRequest = serde_json::from_slice(&data).unwrap();
        assert_eq!(request.notification_id, "IPC-TEST-001");
        let reply = DeliveryResponse {
            notification_id: request.notification_id,
            status,
            error_code: None,
        };
        let bytes = serde_json::to_vec(&reply).unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();
    }

    #[tokio::test]
    async fn ipc_round_trip_validates_id_and_status() {
        let socket = TestSocket::new();
        let listener = UnixListener::bind(&socket.0).unwrap();
        let mut config = NotificationTransportConfig::default();
        config.socket_path = socket.0.clone();
        let server = tokio::spawn(async move {
            answer_one(&listener, DeliveryStatus::AcceptedBySmtp).await;
        });
        let response = send_notification(&config, &sample()).await.unwrap();
        assert_eq!(response.status, DeliveryStatus::AcceptedBySmtp);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn retries_temporary_failure_with_same_notification_id() {
        let socket = TestSocket::new();
        let listener = UnixListener::bind(&socket.0).unwrap();
        let mut config = NotificationTransportConfig::default();
        config.socket_path = socket.0.clone();
        config.retry_initial_delay = Duration::from_millis(10);
        config.retry_max_delay = Duration::from_millis(25);
        let server = tokio::spawn(async move {
            answer_one(&listener, DeliveryStatus::RetryableError).await;
            answer_one(&listener, DeliveryStatus::AcceptedBySmtp).await;
        });
        let (tx, rx) = mpsc::channel(2);
        let counters = Arc::new(NotificationCounters::default());
        let worker = tokio::spawn(run_sender(
            NotificationKind::Ai,
            rx,
            config,
            counters.clone(),
        ));
        tx.send(sample()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while counters.snapshot().ai_accepted == 0 && Instant::now() < deadline {
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(counters.snapshot().ai_retries, 1);
        assert_eq!(counters.snapshot().ai_accepted, 1);
        server.await.unwrap();
        drop(tx);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn connect_failure_is_retryable() {
        let socket = TestSocket::new();
        let mut config = NotificationTransportConfig::default();
        config.socket_path = socket.0.clone();
        config.connect_timeout = Duration::from_millis(100);
        let err = send_notification(&config, &sample()).await.unwrap_err();
        assert!(matches!(err, IpcError::Retryable(_)));
    }
}
