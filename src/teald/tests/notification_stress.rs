// SPDX-License-Identifier: MIT
//! Phase 4 isolation tests: real teald queue/sender tasks, fake local IPC mailer.
//! No SMTP, real mailer, systemd, kernel policy or production socket is touched.

use std::{
    collections::HashMap,
    io,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use teal_notify_protocol::{
    AiNotification, DeliveryResponse, DeliveryStatus, DenyNotification, NotificationPayload,
    NotificationRequest, MAX_FRAME_LENGTH, PROTOCOL_VERSION,
};
use teald::notification::{
    self, NotificationHandle, NotificationStats, NotificationTransportConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    time::{sleep, timeout},
};

fn ai(id: &str) -> NotificationRequest {
    NotificationRequest {
        version: PROTOCOL_VERSION,
        notification_id: id.into(),
        recipients: Vec::new(), // smtp.to_address is configured on the real mailer
        payload: NotificationPayload::Ai(AiNotification {
            hostname: "test-only".into(),
            confidence: 0.99,
            reason: "simulated load test, not an incident".into(),
            related_event_ids: vec!["TEST-ALLOW-001".into()],
            program: "/usr/bin/true".into(),
            action: "EXEC".into(),
            target: "/usr/bin/true".into(),
        }),
    }
}

fn deny(id: &str) -> NotificationRequest {
    NotificationRequest {
        version: PROTOCOL_VERSION,
        notification_id: id.into(),
        recipients: Vec::new(),
        payload: NotificationPayload::Deny(DenyNotification {
            hostname: "test-only".into(),
            uid: 1000,
            pid: Some(4242),
            program: "/usr/bin/true".into(),
            action: "READ".into(),
            rule_id: Some("test-deny".into()),
            policy_epoch: 1,
            target_parent: "/var/tmp".into(),
            target_samples: vec!["/var/tmp/test-only".into()],
            count: 1,
            first_seen: "2026-11-10T00:00:00Z".into(),
            last_seen: "2026-11-10T00:00:00Z".into(),
            representative_event_id: "TEST-DENY-001".into(),
            early_flush: false,
        }),
    }
}

fn config(path: &Path) -> NotificationTransportConfig {
    let mut cfg = NotificationTransportConfig::default();
    cfg.socket_path = path.to_path_buf();
    cfg.ai_queue_capacity = 16;
    cfg.deny_queue_capacity = 16;
    cfg.connect_timeout = Duration::from_millis(100);
    cfg.write_timeout = Duration::from_millis(200);
    cfg.response_timeout = Duration::from_secs(3);
    cfg.retry_initial_delay = Duration::from_millis(30);
    cfg.retry_max_delay = Duration::from_millis(100);
    cfg
}

async fn read_request(stream: &mut UnixStream) -> io::Result<NotificationRequest> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let size = u32::from_be_bytes(len) as usize;
    if !(1..=MAX_FRAME_LENGTH).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request length",
        ));
    }
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn reply(
    stream: &mut UnixStream,
    id: &str,
    status: DeliveryStatus,
    code: Option<&str>,
) -> io::Result<()> {
    let response = DeliveryResponse {
        notification_id: id.into(),
        status,
        error_code: code.map(str::to_owned),
    };
    let bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

async fn wait_stats(
    handle: &NotificationHandle,
    condition: impl Fn(NotificationStats) -> bool,
) -> NotificationStats {
    timeout(Duration::from_secs(5), async {
        loop {
            let stats = handle.stats();
            if condition(stats) {
                return stats;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for notification counters")
}

#[tokio::test]
async fn blocked_ai_smtp_does_not_block_deny_sender() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("mock-mailer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    let (ai_received_tx, ai_received_rx) = oneshot::channel::<()>();
    let (unblock_tx, unblock_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut ai_stream, _) = listener.accept().await.unwrap();
        let req = read_request(&mut ai_stream).await.unwrap();
        assert!(matches!(req.payload, NotificationPayload::Ai(_)));
        ai_received_tx.send(()).unwrap();
        let ai_response = tokio::spawn(async move {
            unblock_rx.await.unwrap();
            reply(
                &mut ai_stream,
                &req.notification_id,
                DeliveryStatus::AcceptedBySmtp,
                None,
            )
            .await
            .unwrap();
        });
        let (mut deny_stream, _) = listener.accept().await.unwrap();
        let req = read_request(&mut deny_stream).await.unwrap();
        assert!(matches!(req.payload, NotificationPayload::Deny(_)));
        reply(
            &mut deny_stream,
            &req.notification_id,
            DeliveryStatus::AcceptedBySmtp,
            None,
        )
        .await
        .unwrap();
        ai_response.await.unwrap();
    });

    handle.try_enqueue_ai(ai("AI-BLOCKED")).unwrap();
    timeout(Duration::from_secs(2), ai_received_rx)
        .await
        .unwrap()
        .unwrap();
    handle.try_enqueue_deny(deny("DENY-INDEPENDENT")).unwrap();
    let s = wait_stats(&handle, |s| s.deny_accepted == 1).await;
    assert_eq!(s.ai_accepted, 0, "AI response is deliberately withheld");
    unblock_tx.send(()).unwrap();
    wait_stats(&handle, |s| s.ai_accepted == 1).await;
    server.await.unwrap();
}

#[tokio::test]
async fn ai_rate_limit_response_retries_same_id_without_delaying_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("mock-mailer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let seen_server = Arc::clone(&seen);
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = read_request(&mut stream).await.unwrap();
            let nth = {
                let mut map = seen_server.lock().unwrap();
                let nth = map.entry(req.notification_id.clone()).or_default();
                *nth += 1;
                *nth
            };
            if req.notification_id == "AI-RETRY" && nth == 1 {
                reply(
                    &mut stream,
                    &req.notification_id,
                    DeliveryStatus::RetryableError,
                    Some("RATE_LIMIT"),
                )
                .await
                .unwrap();
            } else {
                reply(
                    &mut stream,
                    &req.notification_id,
                    DeliveryStatus::AcceptedBySmtp,
                    None,
                )
                .await
                .unwrap();
            }
        }
    });
    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    handle.try_enqueue_ai(ai("AI-RETRY")).unwrap();
    handle.try_enqueue_deny(deny("DENY-ALLOWED")).unwrap();
    let s = wait_stats(&handle, |s| s.ai_accepted == 1 && s.deny_accepted == 1).await;
    assert_eq!((s.ai_retries, s.deny_retries), (1, 0));
    server.await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.get("AI-RETRY"), Some(&2));
    assert_eq!(seen.get("DENY-ALLOWED"), Some(&1));
}

#[tokio::test]
async fn permanent_deny_failure_does_not_block_ai() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("mock-mailer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = read_request(&mut stream).await.unwrap();
            let (status, reason) = if matches!(req.payload, NotificationPayload::Deny(_)) {
                (DeliveryStatus::PermanentError, Some("SMTP_PERMANENT"))
            } else {
                (DeliveryStatus::AcceptedBySmtp, None)
            };
            reply(&mut stream, &req.notification_id, status, reason)
                .await
                .unwrap();
        }
    });
    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    handle.try_enqueue_deny(deny("DENY-PERMANENT")).unwrap();
    handle.try_enqueue_ai(ai("AI-AFTER-ERROR")).unwrap();
    let s = wait_stats(&handle, |s| {
        s.deny_permanent_failure == 1 && s.ai_accepted == 1
    })
    .await;
    assert_eq!(s.deny_retries, 0);
    server.await.unwrap();
}

#[tokio::test]
async fn socket_outage_recovers_both_kinds_without_changing_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("mock-mailer.sock");
    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    handle.try_enqueue_ai(ai("AI-OUTAGE-SAME-ID")).unwrap();
    handle
        .try_enqueue_deny(deny("DENY-OUTAGE-SAME-ID"))
        .unwrap();
    wait_stats(&handle, |s| s.ai_retries > 0 && s.deny_retries > 0).await;

    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = read_request(&mut stream).await.unwrap();
            ids.push(req.notification_id.clone());
            reply(
                &mut stream,
                &req.notification_id,
                DeliveryStatus::AcceptedBySmtp,
                None,
            )
            .await
            .unwrap();
        }
        ids
    });
    wait_stats(&handle, |s| s.ai_accepted == 1 && s.deny_accepted == 1).await;
    let ids = server.await.unwrap();
    assert!(ids.iter().any(|id| id == "AI-OUTAGE-SAME-ID"));
    assert!(ids.iter().any(|id| id == "DENY-OUTAGE-SAME-ID"));
}

#[tokio::test]
async fn queue_overflow_is_nonblocking_and_counted_per_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("mock-mailer.sock");
    // No accepts: force worker congestion. Never connect to the actual mailer.
    let _listener = UnixListener::bind(&socket).unwrap();
    let mut cfg = config(&socket);
    cfg.ai_queue_capacity = 2;
    cfg.deny_queue_capacity = 2;
    let runtime = notification::start(cfg).unwrap();
    let handle = runtime.handle();
    let begun = std::time::Instant::now();
    let count = 400;
    for n in 0..count {
        let _ = handle.try_enqueue_ai(ai(&format!("AI-FLOOD-{n}")));
        let _ = handle.try_enqueue_deny(deny(&format!("DENY-FLOOD-{n}")));
    }
    let elapsed = begun.elapsed();
    let stats = handle.stats();
    assert!(stats.ai_queue_full > 0, "AI queue must bound overload");
    assert!(stats.deny_queue_full > 0, "DENY queue must bound overload");
    assert_eq!(stats.ai_enqueued + stats.ai_queue_full, count);
    assert_eq!(stats.deny_enqueued + stats.deny_queue_full, count);
    assert!(
        elapsed < Duration::from_secs(2),
        "submission must remain nonblocking"
    );
}
