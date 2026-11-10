// SPDX-License-Identifier: MIT
/*
 * TEAL Common Types for Notification (teal-notify-protocol)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use serde::{Deserialize, Serialize};

/// プロトコルバージョン
pub const PROTOCOL_VERSION: u16 = 1;

/// Length-delimited フレーミングの最大長（64 KiB）
pub const MAX_FRAME_LENGTH: usize = 64 * 1024;

/// Target サンプルの最大保持数
pub const MAX_TARGET_SAMPLES: usize = 10;

/// 宛先メールアドレスの最大件数
pub const MAX_RECIPIENTS: usize = 50;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum NotificationPayload {
    Ai(AiNotification),
    Deny(DenyNotification),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationRequest {
    pub version: u16,
    pub notification_id: String,
    /// Informational Bcc addresses; the mandatory To address is configured in mailer.json.
    /// May be empty: the configured To mailbox still receives the notification.
    pub recipients: Vec<String>,
    pub payload: NotificationPayload,
}

impl NotificationRequest {
    /// メッセージの整合性と上限を検証
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if self.notification_id.is_empty() {
            return Err("notification_id is required");
        }
        if self.recipients.len() > MAX_RECIPIENTS {
            return Err("exceeded maximum recipients limit");
        }

        match &self.payload {
            NotificationPayload::Ai(ai) => {
                if ai.confidence < 0.0 || ai.confidence > 1.0 {
                    return Err("confidence must be between 0.0 and 1.0");
                }
            }
            NotificationPayload::Deny(deny) => {
                if deny.target_samples.len() > MAX_TARGET_SAMPLES {
                    return Err("target_samples exceeds MAX_TARGET_SAMPLES");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    AcceptedBySmtp,
    RetryableError,
    PermanentError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryResponse {
    pub notification_id: String,
    pub status: DeliveryStatus,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiNotification {
    pub hostname: String,
    pub confidence: f64,
    pub reason: String,
    pub related_event_ids: Vec<String>,
    pub program: String,
    pub action: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyNotification {
    pub hostname: String,
    pub uid: u32,
    pub pid: Option<u32>,
    pub program: String,
    pub action: String,
    pub rule_id: Option<String>,
    pub policy_epoch: u32,

    pub target_parent: String,
    pub target_samples: Vec<String>,

    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,

    pub representative_event_id: String,
    pub early_flush: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn ai_request() -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "N-AI-001".to_owned(),
            recipients: vec!["sec@example.com".to_owned()],
            payload: NotificationPayload::Ai(AiNotification {
                hostname: "server01".to_owned(),
                confidence: 0.97,
                reason: "不審な操作\nbackup deletion".to_owned(),
                related_event_ids: vec!["EVT-101".to_owned(), "EVT-102".to_owned()],
                program: "/usr/bin/bash".to_owned(),
                action: "UNLINK".to_owned(),
                target: "/var/backups/db.sql".to_owned(),
            }),
        }
    }

    fn deny_request(count: u64, early_flush: bool) -> NotificationRequest {
        NotificationRequest {
            version: PROTOCOL_VERSION,
            notification_id: "N-DENY-001".to_owned(),
            recipients: vec!["admin@example.com".to_owned()],
            payload: NotificationPayload::Deny(DenyNotification {
                hostname: "server01".to_owned(),
                uid: 1000,
                pid: None,
                program: "/usr/bin/bash".to_owned(),
                action: "UNLINK".to_owned(),
                rule_id: Some("protect-backups".to_owned()),
                policy_epoch: 42,
                target_parent: "/var/backups".to_owned(),
                target_samples: vec![
                    "/var/backups/a.sql".to_owned(),
                    "/var/backups/b.sql".to_owned(),
                ],
                count,
                first_seen: "2026-11-03T10:00:00+09:00".to_owned(),
                last_seen: "2026-11-03T10:04:59+09:00".to_owned(),
                representative_event_id: "EVT-201".to_owned(),
                early_flush,
            }),
        }
    }

    #[test]
    fn ai_notification_json_round_trip() {
        let original = ai_request();
        let encoded = serde_json::to_string(&original).unwrap();
        let wire: Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(wire["version"], json!(PROTOCOL_VERSION));
        assert_eq!(wire["notification_id"], "N-AI-001");
        assert_eq!(wire["payload"]["kind"], "ai");
        assert_eq!(
            wire["payload"]["data"]["related_event_ids"],
            json!(["EVT-101", "EVT-102"])
        );

        let restored: NotificationRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(restored.recipients, vec!["sec@example.com"]);
        match &restored.payload {
            NotificationPayload::Ai(ai) => {
                assert_eq!(ai.hostname, "server01");
                assert_eq!(ai.confidence, 0.97);
                assert_eq!(ai.reason, "不審な操作\nbackup deletion");
                assert_eq!(ai.related_event_ids.len(), 2);
            }
            NotificationPayload::Deny(_) => panic!("expected AI notification"),
        }
        assert_eq!(serde_json::to_value(&restored).unwrap(), wire);
    }

    #[test]
    fn single_deny_notification_json_round_trip() {
        let original = deny_request(1, false);
        let wire = serde_json::to_value(&original).unwrap();

        assert_eq!(wire["payload"]["kind"], "deny");
        assert_eq!(wire["payload"]["data"]["pid"], Value::Null);
        assert_eq!(wire["payload"]["data"]["policy_epoch"], 42);

        let restored: NotificationRequest = serde_json::from_value(wire.clone()).unwrap();
        match &restored.payload {
            NotificationPayload::Deny(deny) => {
                assert_eq!(deny.count, 1);
                assert!(!deny.early_flush);
                assert_eq!(deny.pid, None);
                assert_eq!(deny.rule_id.as_deref(), Some("protect-backups"));
                assert_eq!(deny.target_samples.len(), 2);
            }
            NotificationPayload::Ai(_) => panic!("expected DENY notification"),
        }
        assert_eq!(serde_json::to_value(restored).unwrap(), wire);
    }

    #[test]
    fn aggregated_deny_notification_json_round_trip() {
        let original = deny_request(120, true);
        let wire = serde_json::to_value(&original).unwrap();
        let restored: NotificationRequest = serde_json::from_value(wire.clone()).unwrap();

        match restored.payload {
            NotificationPayload::Deny(deny) => {
                assert_eq!(deny.count, 120);
                assert!(deny.early_flush);
                assert_eq!(deny.first_seen, "2026-11-03T10:00:00+09:00");
                assert_eq!(deny.last_seen, "2026-11-03T10:04:59+09:00");
                assert_eq!(deny.target_parent, "/var/backups");
            }
            NotificationPayload::Ai(_) => panic!("expected DENY notification"),
        }
    }

    #[test]
    fn delivery_response_json_round_trip_for_all_statuses() {
        let examples = [
            (DeliveryStatus::AcceptedBySmtp, "AcceptedBySmtp", None),
            (
                DeliveryStatus::RetryableError,
                "RetryableError",
                Some("SMTP_TEMP"),
            ),
            (
                DeliveryStatus::PermanentError,
                "PermanentError",
                Some("SMTP_AUTH"),
            ),
        ];
        for (status, status_on_wire, error_code) in examples {
            let original = DeliveryResponse {
                notification_id: "N-001".to_owned(),
                status,
                error_code: error_code.map(str::to_owned),
            };
            let wire = serde_json::to_value(&original).unwrap();
            assert_eq!(wire["status"], status_on_wire);
            let restored: DeliveryResponse = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(restored.notification_id, "N-001");
            assert_eq!(restored.error_code.as_deref(), error_code);
            assert_eq!(serde_json::to_value(restored).unwrap(), wire);
        }
    }

    #[test]
    fn bcc_recipients_are_optional_but_bounded() {
        let mut request = ai_request();
        request.recipients.clear();
        assert!(request.validate().is_ok()); // mandatory To comes from local config
        request.recipients = vec!["x@example.com".to_owned(); MAX_RECIPIENTS + 1];
        assert!(request.validate().is_err());
    }

    #[test]
    fn invalid_payload_kind_is_rejected() {
        let mut wire = serde_json::to_value(ai_request()).unwrap();
        wire["payload"]["kind"] = json!("other");
        assert!(serde_json::from_value::<NotificationRequest>(wire).is_err());
    }

    #[test]
    fn missing_required_field_is_rejected() {
        let mut wire = serde_json::to_value(ai_request()).unwrap();
        wire.as_object_mut().unwrap().remove("notification_id");
        assert!(serde_json::from_value::<NotificationRequest>(wire).is_err());
    }
}
