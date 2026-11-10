// SPDX-License-Identifier: MIT
//! Phase 5 Step 3: bounded retries, pending restore and dead-letter durability.
use std::{sync::Arc, time::Duration};
use teal_notify_protocol::{
    AiNotification, DeliveryResponse, DeliveryStatus, NotificationPayload, NotificationRequest,
    MAX_FRAME_LENGTH, PROTOCOL_VERSION,
};
use teald::notification::{
    config::NotificationTransportConfig,
    queue::{NotificationCounters, NotificationKind},
    recovery::{now_ms, PendingNotification, RecoveryStore},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::mpsc,
    time::timeout,
};

fn request(id: &str) -> NotificationRequest {
    NotificationRequest {
        version: PROTOCOL_VERSION,
        notification_id: id.to_owned(),
        recipients: vec![],
        payload: NotificationPayload::Ai(AiNotification {
            hostname: "phase5".into(),
            confidence: 0.99,
            reason: "synthetic test".into(),
            related_event_ids: vec!["AUDIT-ALLOW-1".into()],
            program: "/usr/bin/cat".into(),
            action: "READ".into(),
            target: "/var/tmp/phase5-test".into(),
        }),
    }
}
fn config(base: &std::path::Path) -> NotificationTransportConfig {
    let mut c = NotificationTransportConfig::default();
    c.socket_path = base.join("mailer.sock");
    c.recovery_path = base.join("recovery");
    c.connect_timeout = Duration::from_millis(50);
    c.write_timeout = Duration::from_millis(50);
    c.response_timeout = Duration::from_millis(80);
    c.retry_initial_delay = Duration::from_millis(10);
    c.retry_max_delay = Duration::from_millis(30);
    c.retry_max_elapsed = Duration::from_secs(2);
    c.rate_limit_wait = Duration::from_millis(10);
    c.shutdown_grace = Duration::from_secs(2);
    c
}
async fn reply(listener: &UnixListener, status: DeliveryStatus, err: Option<&str>) -> String {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut size = [0u8; 4];
    stream.read_exact(&mut size).await.unwrap();
    let n = u32::from_be_bytes(size) as usize;
    assert!((1..=MAX_FRAME_LENGTH).contains(&n));
    let mut data = vec![0u8; n];
    stream.read_exact(&mut data).await.unwrap();
    let request: NotificationRequest = serde_json::from_slice(&data).unwrap();
    let id = request.notification_id;
    let response = DeliveryResponse {
        notification_id: id.clone(),
        status,
        error_code: err.map(str::to_owned),
    };
    let wire = serde_json::to_vec(&response).unwrap();
    stream
        .write_all(&(wire.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&wire).await.unwrap();
    id
}

#[tokio::test]
async fn five_retryable_attempts_store_one_undelivered_record() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let listener = UnixListener::bind(&c.socket_path).unwrap();
    let store = RecoveryStore::open(&c).unwrap();
    let srv = tokio::spawn(async move {
        for _ in 0..5 {
            let id = reply(
                &listener,
                DeliveryStatus::RetryableError,
                Some("SMTP_TRANSPORT"),
            )
            .await;
            assert_eq!(id, "TEST-MAX-FIVE");
        }
    });
    let (tx, rx) = mpsc::channel(2);
    let counters = Arc::new(NotificationCounters::default());
    let task = tokio::spawn(teald::notification::ipc_client::run_sender_managed(
        NotificationKind::Ai,
        rx,
        c.clone(),
        Arc::clone(&counters),
        Some(Arc::clone(&store)),
        None,
        vec![],
    ));
    tx.try_send(request("TEST-MAX-FIVE")).unwrap();
    drop(tx);
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    srv.await.unwrap();
    let undelivered = store.list_undelivered().unwrap();
    assert_eq!(undelivered.len(), 1);
    assert_eq!(undelivered[0].job.attempts, 5);
    assert_eq!(undelivered[0].job.request.notification_id, "TEST-MAX-FIVE");
    assert_eq!(counters.snapshot().ai_retries, 4);
    assert!(
        store.restore_pending().unwrap().is_empty(),
        "UNDELIVERED must not auto-requeue"
    );
}

#[tokio::test]
async fn rate_limit_does_not_consume_attempt_budget() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let listener = UnixListener::bind(&c.socket_path).unwrap();
    let srv = tokio::spawn(async move {
        for _ in 0..2 {
            assert_eq!(
                reply(
                    &listener,
                    DeliveryStatus::RetryableError,
                    Some("RATE_LIMIT")
                )
                .await,
                "RATE-ID"
            );
        }
        assert_eq!(
            reply(&listener, DeliveryStatus::AcceptedBySmtp, None).await,
            "RATE-ID"
        );
    });
    let (tx, rx) = mpsc::channel(1);
    let counters = Arc::new(NotificationCounters::default());
    let store = RecoveryStore::open(&c).unwrap();
    let task = tokio::spawn(teald::notification::ipc_client::run_sender_managed(
        NotificationKind::Ai,
        rx,
        c,
        counters.clone(),
        Some(Arc::clone(&store)),
        None,
        vec![],
    ));
    tx.try_send(request("RATE-ID")).unwrap();
    drop(tx);
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    srv.await.unwrap();
    assert_eq!(counters.snapshot().ai_accepted, 1);
    assert_eq!(counters.snapshot().ai_retries, 0);
    assert!(store.list_undelivered().unwrap().is_empty());
}

#[tokio::test]
async fn restart_preserves_four_attempts_and_last_attempt_becomes_undelivered() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let store = RecoveryStore::open(&c).unwrap();
    let mut job = PendingNotification::fresh(request("RESTART-REMAINING-ONE"));
    job.attempts = 4;
    job.first_attempt_ms = Some(now_ms());
    store.save_pending(&[job]).unwrap();
    let restored = store.restore_pending().unwrap();
    assert_eq!(restored[0].attempts, 4);
    let listener = UnixListener::bind(&c.socket_path).unwrap();
    let srv = tokio::spawn(async move {
        reply(
            &listener,
            DeliveryStatus::RetryableError,
            Some("SMTP_TIMEOUT"),
        )
        .await
    });
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let counters = Arc::new(NotificationCounters::default());
    let task = tokio::spawn(teald::notification::ipc_client::run_sender_managed(
        NotificationKind::Ai,
        rx,
        c,
        counters,
        Some(Arc::clone(&store)),
        None,
        restored,
    ));
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(srv.await.unwrap(), "RESTART-REMAINING-ONE");
    assert_eq!(store.list_undelivered().unwrap()[0].job.attempts, 5);
}

#[tokio::test]
async fn runtime_shutdown_snapshots_pending_and_restart_restores() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let runtime = teald::notification::start(c.clone()).unwrap();
    let handle = runtime.handle();
    handle.try_enqueue_ai(request("PENDING-AI-1")).unwrap();
    handle.try_enqueue_ai(request("PENDING-AI-2")).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    runtime.shutdown().await.unwrap();
    assert!(handle.try_enqueue_ai(request("NO-LATE-JOBS")).is_err());
    let store = RecoveryStore::open(&c).unwrap();
    let restored = store.restore_pending().unwrap();
    let ids: std::collections::HashSet<_> = restored
        .iter()
        .map(|j| j.request.notification_id.as_str())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains("PENDING-AI-1") && ids.contains("PENDING-AI-2"));
}

#[test]
fn quota_rejects_new_records_preserving_existing_dead_letter() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    c.recovery_max_undelivered_records = 1;
    let store = RecoveryStore::open(&c).unwrap();
    store
        .store_undelivered(
            PendingNotification::fresh(request("KEEP")),
            "PERMANENT".into(),
        )
        .unwrap();
    let e = store
        .store_undelivered(
            PendingNotification::fresh(request("REJECT")),
            "PERMANENT".into(),
        )
        .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::StorageFull);
    assert_eq!(
        store.list_undelivered().unwrap()[0]
            .job
            .request
            .notification_id,
        "KEEP"
    );
}

#[tokio::test]
async fn recovered_pending_job_is_delivered_after_restart_with_same_id() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let first = teald::notification::start(c.clone()).unwrap();
    first
        .handle()
        .try_enqueue_ai(request("PERSIST-THROUGH-RESTART"))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(15)).await;
    first.shutdown().await.unwrap();

    // Start a test-only Mailer AFTER the first process has stopped.
    let listener = UnixListener::bind(&c.socket_path).unwrap();
    let server =
        tokio::spawn(async move { reply(&listener, DeliveryStatus::AcceptedBySmtp, None).await });
    let second = teald::notification::start(c.clone()).unwrap();
    let delivered = timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered, "PERSIST-THROUGH-RESTART");
    second.shutdown().await.unwrap();
    let store = RecoveryStore::open(&c).unwrap();
    assert!(store.restore_pending().unwrap().is_empty());
}

#[test]
fn on_disk_byte_limit_rejects_new_notification() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    c.recovery_max_total_bytes = 32;
    let store = RecoveryStore::open(&c).unwrap();
    let err = store
        .store_undelivered(
            PendingNotification::fresh(request("TOO-BIG")),
            "TEST".into(),
        )
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
    assert!(store.list_undelivered().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn recovery_root_symlink_is_rejected() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("real");
    std::fs::create_dir(&destination).unwrap();
    let link = dir.path().join("link");
    symlink(&destination, &link).unwrap();
    let mut c = config(dir.path());
    c.recovery_path = link;
    assert!(RecoveryStore::open(&c).is_err());
}
