// SPDX-License-Identifier: MIT
//! Phase 5 Step 3 boundaries: 600,000 ms exactness, RATE_LIMIT deadline,
//! restoration at expiry and bounded shutdown when storage is full.
//! No real SMTP service, systemd unit or /var/lib/teal is touched.

use std::{sync::Arc, time::Duration};
use teal_notify_protocol::{
    AiNotification, DeliveryResponse, DeliveryStatus, NotificationPayload, NotificationRequest,
    MAX_FRAME_LENGTH, PROTOCOL_VERSION,
};
use teald::notification::{
    config::NotificationTransportConfig,
    queue::{NotificationCounters, NotificationKind},
    recovery::{PendingNotification, RecoveryStore},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::mpsc,
    time::{timeout, Instant},
};

fn make_request(id: &str) -> NotificationRequest {
    NotificationRequest {
        version: PROTOCOL_VERSION,
        notification_id: id.to_owned(),
        recipients: vec![],
        payload: NotificationPayload::Ai(AiNotification {
            hostname: "phase5-boundary-test".into(),
            confidence: 0.98,
            reason: "boundary test".into(),
            related_event_ids: vec!["ALLOW-BOUNDARY".into()],
            program: "/bin/true".into(),
            action: "READ".into(),
            target: "/tmp/teal-boundary".into(),
        }),
    }
}

fn test_config(path: &std::path::Path) -> NotificationTransportConfig {
    let mut cfg = NotificationTransportConfig::default();
    cfg.socket_path = path.join("smtp-mock.sock");
    cfg.recovery_path = path.join("recovery");
    cfg.connect_timeout = Duration::from_millis(50);
    cfg.write_timeout = Duration::from_millis(50);
    cfg.response_timeout = Duration::from_millis(80);
    cfg.retry_initial_delay = Duration::from_millis(10);
    cfg.retry_max_delay = Duration::from_millis(20);
    cfg.rate_limit_wait = Duration::from_millis(200);
    cfg.shutdown_grace = Duration::from_millis(120);
    cfg.shutdown_save_retry_delay = Duration::from_millis(5);
    cfg
}

#[test]
fn exactly_600_seconds_is_expired_not_one_millisecond_before() {
    let cfg = NotificationTransportConfig::default();
    assert_eq!(cfg.retry_max_elapsed, Duration::from_secs(600));
    assert_eq!(cfg.retry_max_attempts, 5);
    let mut job = PendingNotification::fresh(make_request("BOUNDARY-600-EXACT"));
    job.first_attempt_ms = Some(1_000_000);
    job.attempts = 2;
    assert!(
        !job.expired_at(&cfg, 1_599_999),
        "599,999ms must remain eligible"
    );
    assert!(job.expired_at(&cfg, 1_600_000), "600,000ms must expire");
    assert!(job.expired_at(&cfg, 1_600_001));
    job.attempts = 5;
    assert!(
        job.expired_at(&cfg, 1_000_001),
        "five attempts override the time window"
    );
    job.attempts = 0;
    job.first_attempt_ms = None;
    assert!(
        !job.expired_at(&cfg, 9_999_999),
        "a never-attempted job has no elapsed send deadline"
    );
}

#[tokio::test]
async fn restored_job_past_600s_is_undelivered_without_another_send() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let store = RecoveryStore::open(&cfg).unwrap();
    let mut job = PendingNotification::fresh(make_request("BOUNDARY-RESTORED-EXPIRED"));
    job.first_attempt_ms = Some(teald::notification::recovery::now_ms().saturating_sub(600_001));
    job.attempts = 2;
    store.save_pending(&[job]).unwrap();
    let restored = store.restore_pending().unwrap();
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let counters = Arc::new(NotificationCounters::default());
    let result = timeout(
        Duration::from_secs(2),
        teald::notification::ipc_client::run_sender_managed(
            NotificationKind::Ai,
            rx,
            cfg,
            Arc::clone(&counters),
            Some(Arc::clone(&store)),
            None,
            restored,
        ),
    )
    .await
    .expect("expiry must not cause repeated network attempts");
    assert!(result.is_empty());
    let saved = store.list_undelivered().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(
        saved[0].job.attempts, 2,
        "no new send attempt after restart"
    );
    assert_eq!(saved[0].reason, "RETRY_DEADLINE");
    assert_eq!(
        saved[0].job.request.notification_id,
        "BOUNDARY-RESTORED-EXPIRED"
    );
    assert_eq!(counters.snapshot().ai_retries, 0);
    assert!(store.restore_pending().unwrap().is_empty());
}

#[tokio::test]
async fn rate_limit_does_not_bypass_elapsed_deadline() {
    // Scale down the same deadline behavior to 100ms: RATE_LIMIT is free
    // in attempt count, but is not allowed to extend the elapsed-time budget.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    cfg.retry_max_elapsed = Duration::from_millis(100);
    let listener = UnixListener::bind(&cfg.socket_path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes(header) as usize;
        assert!((1..=MAX_FRAME_LENGTH).contains(&len));
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await.unwrap();
        let req: NotificationRequest = serde_json::from_slice(&data).unwrap();
        let response = DeliveryResponse {
            notification_id: req.notification_id.clone(),
            status: DeliveryStatus::RetryableError,
            error_code: Some("RATE_LIMIT".into()),
        };
        let encoded = serde_json::to_vec(&response).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
        req.notification_id
    });
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(make_request("BOUNDARY-RATE-LIMIT")).unwrap();
    drop(tx);
    let store = RecoveryStore::open(&cfg).unwrap();
    let counters = Arc::new(NotificationCounters::default());
    let started = Instant::now();
    timeout(
        Duration::from_secs(2),
        teald::notification::ipc_client::run_sender_managed(
            NotificationKind::Ai,
            rx,
            cfg,
            Arc::clone(&counters),
            Some(Arc::clone(&store)),
            None,
            vec![],
        ),
    )
    .await
    .expect("RATE_LIMIT cannot keep sender alive indefinitely");
    assert_eq!(
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap(),
        "BOUNDARY-RATE-LIMIT"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let saved = store.list_undelivered().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].reason, "RETRY_DEADLINE");
    assert_eq!(
        saved[0].job.attempts, 0,
        "RATE_LIMIT must not consume attempts"
    );
    assert_eq!(counters.snapshot().ai_retries, 0);
}

#[tokio::test]
async fn real_storage_quota_failure_still_terminates_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    cfg.recovery_max_total_bytes = 32; // too small to hold even one snapshot
    let runtime = teald::notification::start(cfg.clone()).unwrap();
    runtime
        .handle()
        .try_enqueue_ai(make_request("BOUNDARY-SAVE-FULL"))
        .unwrap();
    let started = Instant::now();
    let result = timeout(Duration::from_secs(2), runtime.shutdown())
        .await
        .expect("shutdown must not block indefinitely");
    assert!(
        result.is_err(),
        "save must report the quota failure, not silently succeed"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let store = RecoveryStore::open(&cfg).unwrap();
    assert!(
        store.restore_pending().unwrap().is_empty(),
        "failed snapshot must not be accepted"
    );
}
