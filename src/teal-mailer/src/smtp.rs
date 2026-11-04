// SPDX-License-Identifier: MIT
/*
 * TEAL mailer for Notification (teal-mailer)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! One-shot SMTP delivery for the notification mailer.
//!
//! This module is transport only: AI/DENY formatting, queuing, rate limits,
//! retry policy and IPC response handling are the responsibilities of other
//! modules. An SMTP 2xx acceptance does not guarantee mailbox delivery.

use std::{error::Error, fmt, time::Duration};

use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{authentication::Credentials, Error as LettreSmtpError},
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use teal_notify_protocol::{DeliveryResponse, DeliveryStatus, MAX_FRAME_LENGTH, MAX_RECIPIENTS};

use crate::{
    config::{ConfigError, MailerConfig},
    credentials::SmtpCredentials,
};

const SMTP_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const SMTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_SUBJECT_BYTES: usize = 512;

/// Values reported to IPC are deliberately limited to fixed, safe error codes.
/// Do not forward raw SMTP responses: servers can include input or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtpOutcome {
    pub status: DeliveryStatus,
    pub error_code: Option<&'static str>,
}

impl SmtpOutcome {
    fn accepted() -> Self {
        Self { status: DeliveryStatus::AcceptedBySmtp, error_code: None }
    }

    fn retryable(code: &'static str) -> Self {
        Self { status: DeliveryStatus::RetryableError, error_code: Some(code) }
    }

    fn permanent(code: &'static str) -> Self {
        Self { status: DeliveryStatus::PermanentError, error_code: Some(code) }
    }

    /// Convert to the shared IPC reply. The caller supplies the request ID.
    pub fn into_response(self, notification_id: String) -> DeliveryResponse {
        DeliveryResponse {
            notification_id,
            status: self.status,
            error_code: self.error_code.map(str::to_owned),
        }
    }
}

#[derive(Debug)]
pub enum SmtpInitError {
    Config(ConfigError),
    InvalidFromAddress,
    InvalidToAddress,
    TransportConfiguration,
}

impl fmt::Display for SmtpInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "invalid mailer config: {err}"),
            Self::InvalidFromAddress => f.write_str("smtp.from is not a valid mailbox address"),
            Self::InvalidToAddress => f.write_str("smtp.to_address is not a valid mailbox address"),
            Self::TransportConfiguration => f.write_str("cannot configure secure SMTP transport"),
        }
    }
}

impl Error for SmtpInitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageError {
    TooManyRecipients,
    InvalidRecipient,
    InvalidSubject,
    BodyTooLarge,
    BuildFailure,
}

/// Reusable, authenticated SMTP client. Construct once at startup, not once
/// per notification. `Debug` is intentionally not implemented to avoid
/// inadvertently printing internals that may retain authentication data.
pub struct SmtpMailer {
    from: Mailbox,
    common_to: Mailbox,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpMailer {
    pub fn new(config: &MailerConfig, secrets: &SmtpCredentials) -> Result<Self, SmtpInitError> {
        config.validate().map_err(SmtpInitError::Config)?;

        let from_address: Address = config
            .smtp
            .from_address
            .parse()
            .map_err(|_| SmtpInitError::InvalidFromAddress)?;
        let from = Mailbox::new(None, from_address);
        let to_address: Address = config
            .smtp
            .to_address
            .parse()
            .map_err(|_| SmtpInitError::InvalidToAddress)?;
        let common_to = Mailbox::new(None, to_address);

        // Port 465 uses implicit TLS (SMTPS). Other ports (typically 587)
        // require STARTTLS, not opportunistic encryption. Both constructors
        // validate the server certificate and host name.
        let builder = if config.smtp.port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp.host)
        }
        .map_err(|_| SmtpInitError::TransportConfiguration)?;

        // lettre owns the copied credentials for its lifetime. Never log,
        // format or serialize `transport`; do not create SMTP URLs with secrets.
        let auth = Credentials::new(
            secrets.username.expose().to_owned(),
            secrets.password.expose().to_owned(),
        );
        let transport = builder
            .port(config.smtp.port)
            .credentials(auth)
            .timeout(Some(SMTP_COMMAND_TIMEOUT))
            .build();

        Ok(Self { from, common_to, transport })
    }

    /// Perform exactly one attempt for one email message; no internal retry.
    /// A future IPC sender/queue is responsible for deciding about retries.
    pub async fn send_once(
        &self,
        recipients: &[String],
        subject: &str,
        body: &str,
    ) -> SmtpOutcome {
        let message = match build_message(&self.from, &self.common_to, recipients, subject, body) {
            Ok(message) => message,
            Err(_) => return SmtpOutcome::permanent("INVALID_MESSAGE"),
        };

        match tokio::time::timeout(SMTP_TOTAL_TIMEOUT, self.transport.send(message)).await {
            Ok(Ok(_smtp_reply)) => SmtpOutcome::accepted(),
            Ok(Err(err)) => classify_smtp_error(&err),
            Err(_) => SmtpOutcome::retryable("SMTP_TIMEOUT"),
        }
    }
}

fn build_message(
    from: &Mailbox,
    common_to: &Mailbox,
    recipients: &[String],
    subject: &str,
    body: &str,
) -> Result<Message, MessageError> {
    // The configured To mailbox is mandatory; IPC recipients are optional Bcc.
    if recipients.len() > MAX_RECIPIENTS {
        return Err(MessageError::TooManyRecipients);
    }
    if subject.trim().is_empty()
        || subject.len() > MAX_SUBJECT_BYTES
        || subject.chars().any(char::is_control)
    {
        return Err(MessageError::InvalidSubject);
    }
    if body.len() > MAX_FRAME_LENGTH {
        return Err(MessageError::BodyTooLarge);
    }

    let mut builder = Message::builder()
        .from(from.clone())
        .to(common_to.clone())
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);

    // To is the accountable incident-response mailbox, configured locally.
    // IPC recipients are informational Bcc destinations only.
    // lettre derives SMTP RCPT TO from To and Bcc, and removes Bcc from MIME headers.
    for recipient in recipients {
        if recipient.trim() != recipient || recipient.is_empty() {
            return Err(MessageError::InvalidRecipient);
        }
        let address: Address = recipient
            .parse()
            .map_err(|_| MessageError::InvalidRecipient)?;
        builder = builder.bcc(Mailbox::new(None, address));
    }

    builder.body(body.to_owned()).map_err(|_| MessageError::BuildFailure)
}

fn classify_smtp_error(err: &LettreSmtpError) -> SmtpOutcome {
    if err.is_permanent() {
        // SMTP 5xx. Includes invalid credentials / rejected recipients.
        SmtpOutcome::permanent("SMTP_PERMANENT")
    } else if err.is_transient() {
        // SMTP 4xx: try again later in the teald IPC sender.
        SmtpOutcome::retryable("SMTP_TEMPORARY")
    } else if err.is_tls() {
        // Often a certificate / TLS configuration problem requiring action.
        SmtpOutcome::permanent("SMTP_TLS")
    } else if err.is_timeout() {
        SmtpOutcome::retryable("SMTP_TIMEOUT")
    } else {
        // Network failure, dropped connection, unexpected SMTP response.
        // A timeout after DATA may still have been accepted by the server.
        SmtpOutcome::retryable("SMTP_TRANSPORT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Mailbox {
        Mailbox::new(None, "teal@example.com".parse().unwrap())
    }

    fn common_to() -> Mailbox {
        Mailbox::new(None, "security-team@example.com".parse().unwrap())
    }

    fn recipients() -> Vec<String> {
        vec!["sec1@example.com".to_owned(), "sec2@example.com".to_owned()]
    }

    #[test]
    fn builds_utf8_plaintext_mail_with_private_recipients() {
        let mail = build_message(&sender(), &common_to(), &recipients(), "TEAL 通知", "拒否された操作\n日本語").unwrap();
        let formatted = String::from_utf8(mail.formatted()).unwrap();
        assert!(formatted.contains("Content-Type: text/plain"));
        assert!(formatted.contains("To: security-team@example.com"));
        assert!(!formatted.contains("Bcc:"));
        assert!(!formatted.contains("sec1@example.com"));
        assert!(!formatted.contains("sec2@example.com"));
        assert_eq!(mail.envelope().to().len(), 3); // To + two Bcc recipients
    }

    #[test]
    fn supports_to_only_and_rejects_excessive_bcc_recipients() {
        let mail = build_message(&sender(), &common_to(), &[], "Test", "body").unwrap();
        assert_eq!(mail.envelope().to().len(), 1); // To is always an envelope recipient
        let formatted = String::from_utf8(mail.formatted()).unwrap();
        assert!(formatted.contains("To: security-team@example.com"));

        let too_many = vec!["a@example.com".to_owned(); MAX_RECIPIENTS + 1];
        assert_eq!(build_message(&sender(), &common_to(), &too_many, "Test", "body").unwrap_err(), MessageError::TooManyRecipients);
    }

    #[test]
    fn rejects_non_mailbox_recipients() {
        for address in ["", "test@example.com\r\nBcc: other@example.com", "Name <test@example.com>", "test@example.com "] {
            let result = build_message(&sender(), &common_to(), &[address.to_owned()], "Test", "body");
            assert!(matches!(result, Err(MessageError::InvalidRecipient)));
        }
    }

    #[test]
    fn rejects_subject_injection_or_empty_subject() {
        for subject in ["", "  ", "Hello\r\nBcc: injected@example.com"] {
            assert_eq!(build_message(&sender(), &common_to(), &recipients(), subject, "body").unwrap_err(), MessageError::InvalidSubject);
        }
    }

    #[test]
    fn rejects_oversized_body() {
        let oversized = "x".repeat(MAX_FRAME_LENGTH + 1);
        assert_eq!(build_message(&sender(), &common_to(), &recipients(), "Test", &oversized).unwrap_err(), MessageError::BodyTooLarge);
    }

    #[test]
    fn converts_outcome_to_shared_response() {
        let reply = SmtpOutcome::accepted().into_response("N-123".to_owned());
        assert_eq!(reply.notification_id, "N-123");
        assert_eq!(reply.status, DeliveryStatus::AcceptedBySmtp);
        assert_eq!(reply.error_code, None);

        let reply = SmtpOutcome::retryable("SMTP_TIMEOUT").into_response("N-456".to_owned());
        assert_eq!(reply.status, DeliveryStatus::RetryableError);
        assert_eq!(reply.error_code.as_deref(), Some("SMTP_TIMEOUT"));
    }
}
