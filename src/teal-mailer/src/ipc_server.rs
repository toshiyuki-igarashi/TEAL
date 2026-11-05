// SPDX-License-Identifier: MIT
/*
 * TEAL mailer for Notification (teal-mailer)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! Notification IPC server for Phase 1.
//!
//! - The listening socket is inherited from teal-mailer.socket (systemd).
//! - One connection contains exactly one length-prefixed JSON request/reply.
//! - Only root-owned clients are accepted (the current teald service UID).
//! - The request is acknowledged only *after* the SMTP attempt finishes.
//!
//! Phase 4 will move body formatting and per-kind rate limits into
//! ai_worker.rs and deny_worker.rs. This module intentionally has no SMTP
//! retry: only the future teald IPC sender will own retry decisions.

use std::{
    env,
    fmt::Write as _,
    io,
    os::{fd::FromRawFd, unix::net::UnixListener as StdUnixListener},
    process,
    sync::Arc,
    time::Duration,
};

use teal_notify_protocol::{
    DeliveryResponse, DeliveryStatus, NotificationPayload, NotificationRequest, MAX_FRAME_LENGTH,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

use crate::smtp::SmtpMailer;

const SYSTEMD_FIRST_FD: i32 = 3;
const TEALD_UID: u32 = 0;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
// Per-field caps prevent a syntactically valid 64 KiB JSON frame from
// containing unreasonably long strings or excessive event references.
const MAX_NOTIFICATION_ID_BYTES: usize = 128;
const MAX_ADDRESS_BYTES: usize = 320;
const MAX_HOSTNAME_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 4096;
const MAX_ACTION_BYTES: usize = 64;
const MAX_RULE_ID_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 16 * 1024;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_RELATED_EVENT_IDS: usize = 128;
const IPC_READ_TIMEOUT: Duration = Duration::from_secs(10);
const IPC_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(45);

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn other(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// The fd is owned by systemd until the service starts. The service expects
/// exactly one listening fd, fd 3, and does not call `bind()` or `unlink()`.
///
/// Must be called from within the Tokio runtime (UnixListener::from_std).
/// In regular execution this function is called once, during startup.
pub fn take_systemd_listener() -> io::Result<UnixListener> {
    let pid_var = env::var("LISTEN_PID").ok();
    let fds_var = env::var("LISTEN_FDS").ok();
    validate_activation_env(pid_var.as_deref(), fds_var.as_deref(), process::id())?;

    // SAFETY: systemd's socket activation contract guarantees that fd 3 is
    // an open, *owned* listening fd when LISTEN_PID/FDS match this process.
    // from_raw_fd takes ownership, so it will be closed on drop exactly once.
    let listener = unsafe { StdUnixListener::from_raw_fd(SYSTEMD_FIRST_FD) };
    listener.set_nonblocking(true)?;

    // Reject unexpected fd types rather than exposing a service on an
    // unintended socket. UnixListener::from_std also requires nonblocking.
    let addr = listener.local_addr()?;
    if addr.as_pathname().is_none() {
        return Err(invalid_input(
            "systemd listener must be a pathname Unix socket",
        ));
    }
    UnixListener::from_std(listener)
}

fn validate_activation_env(
    pid_var: Option<&str>,
    fds_var: Option<&str>,
    own_pid: u32,
) -> io::Result<()> {
    if pid_var.and_then(|s| s.parse::<u32>().ok()) != Some(own_pid) {
        return Err(invalid_input("missing or mismatched systemd LISTEN_PID"));
    }
    if fds_var.and_then(|s| s.parse::<u32>().ok()) != Some(1) {
        return Err(invalid_input("expected exactly one systemd LISTEN_FDS"));
    }
    Ok(())
}

/// Run until SIGTERM or SIGINT. The listener itself remains owned by systemd;
/// in-flight sends are given limited time to complete on graceful shutdown.
pub async fn run(listener: UnixListener, smtp: SmtpMailer) -> io::Result<()> {
    let smtp = Arc::new(smtp);
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut tasks = JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    loop {
        // Reserve capacity before accepting, so malicious/slow clients cannot
        // cause an unbounded number of spawned connection tasks.
        let permit = tokio::select! {
            biased;
            _ = term.recv() => break,
            _ = interrupt.recv() => break,
            task = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(err)) = task {
                    eprintln!("teal-mailer: IPC task failed: {err}");
                }
                continue;
            }
            acquired = permits.clone().acquire_owned() => {
                acquired.map_err(|_| other("IPC semaphore closed"))?
            }
        };

        let accepted = tokio::select! {
            biased;
            _ = term.recv() => break,
            _ = interrupt.recv() => break,
            result = listener.accept() => result,
        };

        match accepted {
            Ok((stream, _)) => {
                let smtp = Arc::clone(&smtp);
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve_connection(stream, &smtp).await {
                        // Do not log message contents or SMTP credentials.
                        eprintln!("teal-mailer: IPC request failed: {err}");
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }

    // SMTP is bounded by the transport timeout (40s); drain for 45s.
    // On timeout delivery is ambiguous and the future teald sender may retry.
    if timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            if let Err(err) = result {
                eprintln!("teal-mailer: IPC task failed during shutdown: {err}");
            }
        }
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        eprintln!("teal-mailer: IPC shutdown drain timed out (delivery may be uncertain)");
    }
    Ok(())
}

async fn serve_connection(mut stream: UnixStream, smtp: &SmtpMailer) -> io::Result<()> {
    let peer_uid = stream.peer_cred()?.uid();
    if !is_authorized_uid(peer_uid) {
        // No response to an unauthorized client.
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unauthorized IPC peer",
        ));
    }

    let frame = read_frame(&mut stream).await?;
    let request = decode_request(&frame)?;

    let validation = request
        .validate()
        .map_err(|e| format!("protocol: {e}"))
        .and_then(|()| validate_request_fields(&request).map_err(|e| format!("fields: {e}")));

    let response = match validation {
        Ok(()) => {
            let (subject, body) = format_mail(&request);

            smtp.send_once(&request.recipients, subject, &body)
                .await
                .into_response(request.notification_id)
        }

        Err(reason) => {
            eprintln!(
                "[TEAL][mailer][WARN] Invalid notification request: {}",
                reason
            );

            DeliveryResponse {
                notification_id: request.notification_id,
                status: DeliveryStatus::PermanentError,
                error_code: Some("INVALID_REQUEST".to_owned()),
            }
        }
    };
    write_response(&mut stream, &response).await
}

fn is_authorized_uid(uid: u32) -> bool {
    uid == TEALD_UID
}

fn decode_request(frame: &[u8]) -> io::Result<NotificationRequest> {
    serde_json::from_slice(frame).map_err(|_| invalid_data("invalid notification JSON"))
}

fn has_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes
}

/// Defense-in-depth until these constraints are moved into the shared
/// teal-notify-protocol validation code.
fn validate_request_fields(request: &NotificationRequest) -> io::Result<()> {
    if !has_text(&request.notification_id, MAX_NOTIFICATION_ID_BYTES)
        || request.notification_id.chars().any(char::is_control)
        || request.recipients.iter().any(|recipient| {
            !has_text(recipient, MAX_ADDRESS_BYTES) || recipient.chars().any(char::is_control)
        })
    {
        return Err(invalid_data(
            "invalid notification identifiers or recipients",
        ));
    }

    match &request.payload {
        NotificationPayload::Ai(ai) => {
            if !ai.confidence.is_finite()
                || !(0.0..=1.0).contains(&ai.confidence)
                || !has_text(&ai.hostname, MAX_HOSTNAME_BYTES)
                || !has_text(&ai.program, MAX_PATH_BYTES)
                || !has_text(&ai.action, MAX_ACTION_BYTES)
                || !has_text(&ai.target, MAX_PATH_BYTES)
                || !has_text(&ai.reason, MAX_REASON_BYTES)
                || ai.related_event_ids.len() > MAX_RELATED_EVENT_IDS
                || ai
                    .related_event_ids
                    .iter()
                    .any(|s| !has_text(s, MAX_NOTIFICATION_ID_BYTES))
            {
                return Err(invalid_data("invalid AI notification fields"));
            }
        }
        NotificationPayload::Deny(deny) => {
            if !has_text(&deny.hostname, MAX_HOSTNAME_BYTES)
                || !has_text(&deny.program, MAX_PATH_BYTES)
                || !has_text(&deny.action, MAX_ACTION_BYTES)
                || !has_text(&deny.target_parent, MAX_PATH_BYTES)
                || !has_text(&deny.first_seen, MAX_TIMESTAMP_BYTES)
                || !has_text(&deny.last_seen, MAX_TIMESTAMP_BYTES)
                || !has_text(&deny.representative_event_id, MAX_NOTIFICATION_ID_BYTES)
                || deny
                    .rule_id
                    .as_ref()
                    .is_some_and(|s| !has_text(s, MAX_RULE_ID_BYTES))
                || deny
                    .target_samples
                    .iter()
                    .any(|s| !has_text(s, MAX_PATH_BYTES))
                || deny.count == 0
            {
                return Err(invalid_data("invalid DENY notification fields"));
            }
        }
    }
    Ok(())
}

/// Wire format: u32 big-endian length, followed by exactly that many JSON
/// bytes. Length excludes the four-byte header. Zero and >64 KiB are invalid.
async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    timeout(IPC_READ_TIMEOUT, async {
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_FRAME_LENGTH {
            return Err(invalid_data("IPC frame length out of range"));
        }
        let mut frame = vec![0_u8; length];
        stream.read_exact(&mut frame).await?;
        Ok(frame)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "IPC read timeout"))?
}

async fn write_response(stream: &mut UnixStream, response: &DeliveryResponse) -> io::Result<()> {
    let frame =
        serde_json::to_vec(response).map_err(|_| invalid_data("cannot serialize IPC response"))?;
    if frame.is_empty() || frame.len() > MAX_FRAME_LENGTH {
        return Err(invalid_data("IPC response exceeds maximum frame length"));
    }
    let header = (frame.len() as u32).to_be_bytes();
    timeout(IPC_WRITE_TIMEOUT, async {
        stream.write_all(&header).await?;
        stream.write_all(&frame).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "IPC write timeout"))?
}

/// Temporary Phase 1 formatting; split into AI/DENY workers in Phase 4.
/// Security-relevant claims are different for the two event classes.
///
/// Notification values are escaped with Debug formatting, so embedded CR/LF
/// or terminal control bytes cannot forge a new metadata line.
fn format_mail(request: &NotificationRequest) -> (&'static str, String) {
    let mut body = String::with_capacity(1024);
    writeln!(
        &mut body,
        "TEAL Notification ID: {:?}",
        request.notification_id
    )
    .unwrap();
    match &request.payload {
        NotificationPayload::Ai(ai) => {
            writeln!(&mut body, "Type: AI analysis alert").unwrap();
            writeln!(
                &mut body,
                "Assessment: Suspected attack (not a confirmed incident)"
            )
            .unwrap();
            writeln!(&mut body, "Hostname: {:?}", ai.hostname).unwrap();
            writeln!(&mut body, "Confidence: {:.4}", ai.confidence).unwrap();
            writeln!(&mut body, "Reason: {:?}", ai.reason).unwrap();
            writeln!(&mut body, "Program: {:?}", ai.program).unwrap();
            writeln!(&mut body, "Action: {:?}", ai.action).unwrap();
            writeln!(&mut body, "Target: {:?}", ai.target).unwrap();
            writeln!(
                &mut body,
                "Related Audit Event IDs: {:?}",
                ai.related_event_ids
            )
            .unwrap();
            ("TEAL: Suspected Attack Detected", body)
        }
        NotificationPayload::Deny(deny) => {
            writeln!(&mut body, "Type: Access denied").unwrap();
            writeln!(
                &mut body,
                "Assessment: The action was denied. Cause is not determined."
            )
            .unwrap();
            writeln!(&mut body, "Hostname: {:?}", deny.hostname).unwrap();
            writeln!(&mut body, "UID: {}", deny.uid).unwrap();
            writeln!(&mut body, "PID: {:?}", deny.pid).unwrap();
            writeln!(&mut body, "Program: {:?}", deny.program).unwrap();
            writeln!(&mut body, "Action: {:?}", deny.action).unwrap();
            writeln!(&mut body, "Rule ID: {:?}", deny.rule_id).unwrap();
            writeln!(&mut body, "Policy Epoch: {}", deny.policy_epoch).unwrap();
            writeln!(&mut body, "Target parent: {:?}", deny.target_parent).unwrap();
            writeln!(&mut body, "Target samples: {:?}", deny.target_samples).unwrap();
            writeln!(&mut body, "Occurrences: {}", deny.count).unwrap();
            writeln!(&mut body, "First seen: {:?}", deny.first_seen).unwrap();
            writeln!(&mut body, "Last seen: {:?}", deny.last_seen).unwrap();
            writeln!(
                &mut body,
                "Representative Audit Event ID: {:?}",
                deny.representative_event_id
            )
            .unwrap();
            writeln!(&mut body, "Early aggregation flush: {}", deny.early_flush).unwrap();
            ("TEAL: Action Denied", body)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use teal_notify_protocol::{AiNotification, DenyNotification, PROTOCOL_VERSION};

    fn sample_ai() -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "N-AI-001".into(),
            recipients: vec!["security@example.com".into()],
            payload: NotificationPayload::Ai(AiNotification {
                hostname: "db01".into(),
                confidence: 0.97,
                reason: "backup deletion attempt".into(),
                related_event_ids: vec!["EVT-101".into()],
                program: "/usr/bin/sh".into(),
                action: "UNLINK".into(),
                target: "/var/backups/x.sql".into(),
            }),
        }
    }

    fn sample_deny() -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "N-DENY-001".into(),
            recipients: vec!["security@example.com".into()],
            payload: NotificationPayload::Deny(DenyNotification {
                hostname: "db01".into(),
                uid: 1000,
                pid: Some(1234),
                program: "/usr/bin/sh".into(),
                action: "UNLINK".into(),
                rule_id: Some("backup-protection".into()),
                policy_epoch: 42,
                target_parent: "/var/backups".into(),
                target_samples: vec!["/var/backups/x.sql".into()],
                count: 1,
                first_seen: "2026-11-04T09:00:00+09:00".into(),
                last_seen: "2026-11-04T09:00:00+09:00".into(),
                representative_event_id: "EVT-222".into(),
                early_flush: false,
            }),
        }
    }

    #[test]
    fn validates_systemd_activation_vars() {
        assert!(validate_activation_env(Some("222"), Some("1"), 222).is_ok());
        assert!(validate_activation_env(None, Some("1"), 222).is_err());
        assert!(validate_activation_env(Some("222"), Some("2"), 222).is_err());
        assert!(validate_activation_env(Some("999"), Some("1"), 222).is_err());
    }

    #[test]
    fn only_teald_root_is_accepted() {
        assert!(is_authorized_uid(0));
        assert!(!is_authorized_uid(1000));
    }

    #[test]
    fn parses_ai_and_deny_request() {
        for request in [sample_ai(), sample_deny()] {
            let encoded = serde_json::to_vec(&request).unwrap();
            assert_eq!(decode_request(&encoded).unwrap(), request);
        }
        assert!(decode_request(b"{").is_err());
    }

    #[test]
    fn enforces_notification_field_limits() {
        assert!(validate_request_fields(&sample_ai()).is_ok());
        assert!(validate_request_fields(&sample_deny()).is_ok());
        let mut request = sample_ai();
        request.notification_id = "x".repeat(MAX_NOTIFICATION_ID_BYTES + 1);
        assert!(validate_request_fields(&request).is_err());
        let mut request = sample_ai();
        if let NotificationPayload::Ai(ref mut ai) = request.payload {
            ai.related_event_ids = vec!["E".into(); MAX_RELATED_EVENT_IDS + 1];
        }
        assert!(validate_request_fields(&request).is_err());
        let mut request = sample_deny();
        if let NotificationPayload::Deny(ref mut deny) = request.payload {
            deny.count = 0;
        }
        assert!(validate_request_fields(&request).is_err());
    }

    #[test]
    fn sends_deny_as_fact_not_attack_accusation() {
        let (subject, body) = format_mail(&sample_deny());
        assert_eq!(subject, "TEAL: Action Denied");
        assert!(body.contains("Cause is not determined"));
        assert!(body.contains("Policy Epoch: 42"));
        assert!(body.contains("EVT-222"));
        assert!(!body.contains("Suspected Attack"));
    }

    #[test]
    fn formats_ai_evidence() {
        let (subject, body) = format_mail(&sample_ai());
        assert_eq!(subject, "TEAL: Suspected Attack Detected");
        assert!(body.contains("Confidence: 0.9700"));
        assert!(body.contains("EVT-101"));
    }

    #[test]
    fn escapes_untrusted_fields() {
        let mut request = sample_ai();
        if let NotificationPayload::Ai(ref mut ai) = request.payload {
            ai.hostname = "good\nFake-Header: attack".to_owned();
        }
        let (_, body) = format_mail(&request);
        assert!(body.contains("good\\nFake-Header: attack"));
        assert!(!body.contains("good\nFake-Header: attack"));
    }

    #[tokio::test]
    async fn framed_response_round_trip() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let response = DeliveryResponse {
            notification_id: "N-1".into(),
            status: DeliveryStatus::AcceptedBySmtp,
            error_code: None,
        };
        let task = tokio::spawn(async move { write_response(&mut server, &response).await });
        let received = read_frame(&mut client).await.unwrap();
        task.await.unwrap().unwrap();
        let decoded: DeliveryResponse = serde_json::from_slice(&received).unwrap();
        assert_eq!(decoded.notification_id, "N-1");
        assert_eq!(decoded.status, DeliveryStatus::AcceptedBySmtp);
    }

    #[tokio::test]
    async fn rejects_oversized_length_before_allocating_payload() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client
            .write_all(&((MAX_FRAME_LENGTH + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        let err = read_frame(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_zero_length_frame() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&0_u32.to_be_bytes()).await.unwrap();
        let err = read_frame(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
