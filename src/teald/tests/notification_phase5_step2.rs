// SPDX-License-Identifier: MIT
//! Phase 5 Step 2: real teald IPC senders, isolated fake Unix mailer.
//! SMTP failure responses are simulated; no production service is touched.

use std::{io, path::Path, time::Duration};
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
    time::{sleep, timeout},
};

fn config(socket_path: &Path) -> NotificationTransportConfig {
    let mut cfg = NotificationTransportConfig::default();
    cfg.socket_path = socket_path.to_owned();
    cfg.recovery_path = socket_path.parent().unwrap().join("phase5-step2-recovery");
    cfg.ai_queue_capacity = 8;
    cfg.deny_queue_capacity = 8;
    cfg.connect_timeout = Duration::from_millis(150);
    cfg.write_timeout = Duration::from_millis(200);
    cfg.response_timeout = Duration::from_secs(1);
    cfg.retry_initial_delay = Duration::from_millis(30);
    cfg.retry_max_delay = Duration::from_millis(80);
    cfg
}

fn request(id: &str, is_ai: bool) -> NotificationRequest {
    let payload = if is_ai {
        NotificationPayload::Ai(AiNotification {
            hostname: "phase5-test".into(),
            confidence: 0.99,
            reason: "Phase 5 synthetic test; not a real security incident".into(),
            related_event_ids: vec!["TEST-ALLOW-1".into()],
            program: "/usr/bin/true".into(),
            action: "EXEC".into(),
            target: "/usr/bin/true".into(),
        })
    } else {
        NotificationPayload::Deny(DenyNotification {
            hostname: "phase5-test".into(),
            uid: 0,
            pid: Some(1),
            program: "/usr/bin/true".into(),
            action: "READ".into(),
            rule_id: Some("phase5-test".into()),
            policy_epoch: 1,
            target_parent: "/tmp".into(),
            target_samples: vec!["/tmp/phase5-test".into()],
            count: 1,
            first_seen: "2026-11-10T00:00:00Z".into(),
            last_seen: "2026-11-10T00:00:00Z".into(),
            representative_event_id: "TEST-DENY-1".into(),
            early_flush: false,
        })
    };
    NotificationRequest {
        version: PROTOCOL_VERSION,
        notification_id: id.to_owned(),
        recipients: vec![], // In production smtp.to_address is configured at the mailer.
        payload,
    }
}

async fn read_request(stream: &mut UnixStream) -> io::Result<NotificationRequest> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad length"));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

async fn respond(
    stream: &mut UnixStream,
    id: &str,
    status: DeliveryStatus,
    error_code: Option<&str>,
) -> io::Result<()> {
    let body = serde_json::to_vec(&DeliveryResponse {
        notification_id: id.to_owned(),
        status,
        error_code: error_code.map(str::to_owned),
    })?;
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
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
    .expect("notification Sender made no progress")
}

#[tokio::test]
async fn smtp_transient_errors_then_recovery_resend_same_ai_id() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("isolated-mailer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let mut ids = Vec::new();
        for attempt in 0..3 {
            let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let req = read_request(&mut stream).await.unwrap();
            ids.push(req.notification_id.clone());
            assert!(matches!(req.payload, NotificationPayload::Ai(_)));
            if attempt < 2 {
                respond(
                    &mut stream,
                    &req.notification_id,
                    DeliveryStatus::RetryableError,
                    Some("SMTP_TRANSPORT"),
                )
                .await
                .unwrap();
            } else {
                respond(
                    &mut stream,
                    &req.notification_id,
                    DeliveryStatus::AcceptedBySmtp,
                    None,
                )
                .await
                .unwrap();
            }
        }
        ids
    });

    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    handle
        .try_enqueue_ai(request("AI-PHASE5-RETRY-001", true))
        .unwrap();
    let stats = wait_stats(&handle, |s| s.ai_accepted == 1).await;
    assert_eq!(stats.ai_retries, 2);
    let ids = server.await.unwrap();
    assert_eq!(ids, vec!["AI-PHASE5-RETRY-001".to_owned(); 3]);
}

#[tokio::test]
async fn unavailable_mailer_start_then_recovery_preserves_deny_id() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("missing-then-available.sock");
    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    handle
        .try_enqueue_deny(request("DENY-PHASE5-BOOT-001", false))
        .unwrap();

    // Simulate mailer.service startup/decryption failure: socket has no server.
    wait_stats(&handle, |s| s.deny_retries >= 1).await;

    // Simulate successful systemd mailer restart with the same socket path.
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let req = read_request(&mut stream).await.unwrap();
        let id = req.notification_id.clone();
        assert!(matches!(req.payload, NotificationPayload::Deny(_)));
        respond(&mut stream, &id, DeliveryStatus::AcceptedBySmtp, None)
            .await
            .unwrap();
        id
    });
    wait_stats(&handle, |s| s.deny_accepted == 1).await;
    assert_eq!(server.await.unwrap(), "DENY-PHASE5-BOOT-001");
}

#[tokio::test]
async fn smtp_permanent_failure_does_not_retry() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("smtp-permanent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let req = read_request(&mut stream).await.unwrap();
        assert_eq!(req.notification_id, "DENY-PHASE5-PERM-001");
        respond(
            &mut stream,
            &req.notification_id,
            DeliveryStatus::PermanentError,
            Some("SMTP_PERMANENT"),
        )
        .await
        .unwrap();
        // Sender must not create a second attempt for a permanent response.
        assert!(timeout(Duration::from_millis(220), listener.accept())
            .await
            .is_err());
    });

    let runtime = notification::start(config(&socket)).unwrap();
    let handle = runtime.handle();
    handle
        .try_enqueue_deny(request("DENY-PHASE5-PERM-001", false))
        .unwrap();
    let stats = wait_stats(&handle, |s| s.deny_permanent_failure == 1).await;
    assert_eq!(stats.deny_retries, 0);
    server.await.unwrap();
}
