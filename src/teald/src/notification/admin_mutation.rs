// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Authorized, explicit retry through teald's existing managed IPC sender.
//! It uses exactly the same bounded backoff, RATE_LIMIT and SMTP semantics as
//! automatic delivery. The original UNDELIVERED record is claimed on disk.

use std::{io, sync::Arc};
use tokio::sync::mpsc;

use super::{
    config::NotificationTransportConfig,
    ipc_client::run_sender_managed,
    queue::{NotificationCounters, NotificationKind},
    recovery::RecoveryStore,
};

#[derive(Debug)]
pub struct ManualRetryResult {
    pub accepted: bool,
    pub attempts: u32,
    pub delivery_uncertain: bool,
    pub reason: String,
}

pub async fn retry(
    store: Arc<RecoveryStore>,
    config: NotificationTransportConfig,
    id: String,
    operator_uid: u32,
) -> io::Result<ManualRetryResult> {
    let store_for_claim = Arc::clone(&store);
    let id_for_claim = id.clone();
    let job = tokio::task::spawn_blocking(move || {
        store_for_claim.begin_manual_retry(&id_for_claim, operator_uid)
    })
    .await
    .map_err(io::Error::other)??;

    eprintln!(
        "[TEAL][notify][AUDIT] manual RETRY started uid={} id={:?} previous_delivery_uncertain={}",
        operator_uid, id, job.delivery_uncertain
    );

    // A closed inbound queue and a single restored manual job let us reuse the
    // production sender, without accidentally activating normal queue traffic.
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let kind = NotificationKind::from_request(&job.request);
    let counters = Arc::new(NotificationCounters::default());
    let leftover = run_sender_managed(
        kind,
        rx,
        config,
        counters,
        Some(Arc::clone(&store)),
        None,
        vec![job],
    )
    .await;
    if !leftover.is_empty() {
        return Err(io::Error::other(
            "manual sender ended with unprocessed notification",
        ));
    }

    let store_for_result = Arc::clone(&store);
    tokio::task::spawn_blocking(move || {
        if let Some(sent) = store_for_result.manual_sent_result(&id)? {
            if sent.retried_by_uid != operator_uid {
                return Err(io::Error::other("manual retry actor mismatch"));
            }
            return Ok(ManualRetryResult {
                accepted: true,
                attempts: sent.completed_job.attempts,
                delivery_uncertain: sent.completed_job.delivery_uncertain,
                reason: "ACCEPTED_BY_SMTP".into(),
            });
        }
        if let Some(failed) = store_for_result.get_undelivered(&id)? {
            if failed.job.manual_initiator_uid == Some(operator_uid) {
                return Ok(ManualRetryResult {
                    accepted: false,
                    attempts: failed.job.attempts,
                    delivery_uncertain: failed.job.delivery_uncertain,
                    reason: failed.reason,
                });
            }
        }
        // A persistence failure leaves manual_inflight safely claimed rather
        // than permitting a duplicate retry. It is reconciled at next startup.
        Err(io::Error::other(
            "manual retry outcome not persisted; inspect journal and do not retry blindly",
        ))
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::super::recovery::PendingNotification;
    use super::*;
    use teal_notify_protocol::{
        AiNotification, DeliveryResponse, DeliveryStatus, NotificationPayload, NotificationRequest,
        PROTOCOL_VERSION,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    fn request(id: &str) -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: id.into(),
            recipients: vec![],
            payload: NotificationPayload::Ai(AiNotification {
                hostname: "host".into(),
                confidence: 0.99,
                reason: "test".into(),
                related_event_ids: vec![],
                program: "/bin/true".into(),
                action: "EXEC".into(),
                target: "/tmp/test".into(),
            }),
        }
    }

    async fn respond(listener: &UnixListener, status: DeliveryStatus, id: &str) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0_u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        let mut body = vec![0_u8; u32::from_be_bytes(head) as usize];
        stream.read_exact(&mut body).await.unwrap();
        let parsed: NotificationRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.notification_id, id);
        let reply = DeliveryResponse {
            notification_id: id.into(),
            status,
            error_code: Some("SMTP_TEMPORARY".into()),
        };
        let encoded = serde_json::to_vec(&reply).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
    }

    #[tokio::test]
    async fn retry_uses_existing_sender_and_preserves_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NotificationTransportConfig::default();
        config.recovery_path = dir.path().join("recovery");
        config.socket_path = dir.path().join("mailer.sock");
        config.retry_initial_delay = std::time::Duration::from_millis(10);
        config.retry_max_delay = std::time::Duration::from_millis(20);
        let store = RecoveryStore::open(&config).unwrap();
        store
            .store_undelivered(
                PendingNotification::fresh(request("MANUAL-1")),
                "SMTP_TEMP".into(),
            )
            .unwrap();
        let listener = UnixListener::bind(&config.socket_path).unwrap();
        let server = tokio::spawn(async move {
            respond(&listener, DeliveryStatus::RetryableError, "MANUAL-1").await;
            respond(&listener, DeliveryStatus::AcceptedBySmtp, "MANUAL-1").await;
        });
        let result = retry(store.clone(), config, "MANUAL-1".into(), 1001)
            .await
            .unwrap();
        assert!(result.accepted);
        assert_eq!(result.attempts, 2);
        assert!(store.get_undelivered("MANUAL-1").unwrap().is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn permanent_error_keeps_failed_job_and_prior_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NotificationTransportConfig::default();
        config.recovery_path = dir.path().join("recovery");
        config.socket_path = dir.path().join("mailer.sock");
        let store = RecoveryStore::open(&config).unwrap();
        let mut prior = PendingNotification::fresh(request("MANUAL-2"));
        prior.attempts = 5;
        store
            .store_undelivered(prior, "RETRY_EXHAUSTED".into())
            .unwrap();
        let listener = UnixListener::bind(&config.socket_path).unwrap();
        let server = tokio::spawn(async move {
            respond(&listener, DeliveryStatus::PermanentError, "MANUAL-2").await;
        });
        let result = retry(store.clone(), config, "MANUAL-2".into(), 1001)
            .await
            .unwrap();
        assert!(!result.accepted);
        assert_eq!(result.attempts, 1);
        let failed = store.get_undelivered("MANUAL-2").unwrap().unwrap();
        assert_eq!(failed.history[0].previous_job.attempts, 5);
        assert_eq!(failed.history[0].operator_uid, 1001);
        server.await.unwrap();
    }
}
