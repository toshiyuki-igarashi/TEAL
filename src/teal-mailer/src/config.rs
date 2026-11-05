// SPDX-License-Identifier: MIT
/*
 * TEAL mailer for Notification (teal-mailer)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use serde::Deserialize;
use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

/// Default configuration path. This matches teal-mailer.service.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/teal.d/mailer.json";
const CONFIG_VERSION: &str = "1.0";
const MAX_CREDENTIAL_NAME_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailerConfig {
    pub version: String,
    pub smtp: SmtpConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    #[serde(rename = "from")]
    pub from_address: String,
    /// Mandatory shared mailbox responsible for acting on the notification.
    pub to_address: String,
    pub tls: TlsMode,
    pub credentials: CredentialConfig,
}

/// v1.0 accepts only a TLS-required transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Required,
}

/// v1.0 accepts only systemd Credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialProvider {
    Systemd,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    pub provider: CredentialProvider,
    /// Credential *identifier*, not the SMTP username value.
    pub user: String,
    /// Credential *identifier*, not the SMTP password value.
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub ai_per_minute: u32,
    pub deny_per_minute: u32,
}

#[derive(Debug)]
pub enum ConfigError {
    Io { path: PathBuf, source: io::Error },
    Json(serde_json::Error),
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "failed to read mailer config {}: {source}",
                    path.display()
                )
            }
            Self::Json(source) => write!(f, "invalid mailer JSON: {source}"),
            Self::Invalid(reason) => write!(f, "invalid mailer config: {reason}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(source) => Some(source),
            Self::Invalid(_) => None,
        }
    }
}

impl MailerConfig {
    /// Read a JSON config file and validate its semantics.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&contents)
    }

    /// Parse and validate JSON without filesystem I/O (also used by unit tests).
    pub fn from_json(contents: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(contents).map_err(ConfigError::Json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::Invalid("unsupported configuration version"));
        }

        let host = self.smtp.host.as_str();
        if host.is_empty()
            || host.trim() != host
            || host.chars().any(|c| c.is_control() || c.is_whitespace())
            || host.contains('/')
            || host.contains('@')
        {
            return Err(ConfigError::Invalid(
                "smtp.host must be a host name or IP address, not a URL",
            ));
        }
        if self.smtp.port == 0 {
            return Err(ConfigError::Invalid(
                "smtp.port must be in the range 1..=65535",
            ));
        }

        // v1.0 config uses plain mailbox addresses without display names.
        // The SMTP/MIME layer additionally validates full RFC syntax.
        if !is_plain_mailbox_address(&self.smtp.from_address) {
            return Err(ConfigError::Invalid(
                "smtp.from must be a plain mailbox address",
            ));
        }
        if !is_plain_mailbox_address(&self.smtp.to_address) {
            return Err(ConfigError::Invalid(
                "smtp.to_address must be a plain mailbox address",
            ));
        }

        let credentials = &self.smtp.credentials;
        if !is_valid_credential_name(&credentials.user)
            || !is_valid_credential_name(&credentials.password)
        {
            return Err(ConfigError::Invalid(
                "credential identifiers contain invalid characters",
            ));
        }
        if credentials.user == credentials.password {
            return Err(ConfigError::Invalid(
                "SMTP username and password credential identifiers must differ",
            ));
        }
        if self.rate_limit.ai_per_minute == 0 || self.rate_limit.deny_per_minute == 0 {
            return Err(ConfigError::Invalid(
                "rate limits must be greater than zero",
            ));
        }
        Ok(())
    }
}

fn is_plain_mailbox_address(address: &str) -> bool {
    let parts_nonempty = match address.split_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty(),
        None => false,
    };
    parts_nonempty
        && address.matches('@').count() == 1
        && !address
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';'))
}

pub(crate) fn is_valid_credential_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CREDENTIAL_NAME_LEN
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn valid_json() -> Value {
        json!({
            "version": "1.0",
            "smtp": {
                "host": "smtp.example.com",
                "port": 587,
                "from": "teal@example.com",
                "to_address": "security-team@example.com",
                "tls": "required",
                "credentials": {
                    "provider": "systemd",
                    "user": "smtp_user",
                    "password": "smtp_password"
                }
            },
            "rate_limit": { "ai_per_minute": 10, "deny_per_minute": 5 }
        })
    }

    fn parse(value: Value) -> Result<MailerConfig, ConfigError> {
        MailerConfig::from_json(&value.to_string())
    }

    #[test]
    fn accepts_spec_example() {
        let config = parse(valid_json()).unwrap();
        assert_eq!(config.smtp.host, "smtp.example.com");
        assert_eq!(config.smtp.from_address, "teal@example.com");
        assert_eq!(config.smtp.to_address, "security-team@example.com");
        assert_eq!(config.smtp.credentials.user, "smtp_user");
        assert_eq!(config.rate_limit.ai_per_minute, 10);
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut value = valid_json();
        value["smtp"]["password"] = json!("do-not-store-secrets-here");
        assert!(parse(value).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut value = valid_json();
        value["version"] = json!("2.0");
        assert!(parse(value).is_err());
    }

    #[test]
    fn requires_tls_and_systemd_credentials() {
        let mut value = valid_json();
        value["smtp"]["tls"] = json!("none");
        assert!(parse(value).is_err());
        let mut value = valid_json();
        value["smtp"]["credentials"]["provider"] = json!("env");
        assert!(parse(value).is_err());
    }

    #[test]
    fn rejects_invalid_host_port_or_sender() {
        let mut value = valid_json();
        value["smtp"]["host"] = json!("https://smtp.example.com");
        assert!(parse(value).is_err());
        let mut value = valid_json();
        value["smtp"]["port"] = json!(0);
        assert!(parse(value).is_err());
        let mut value = valid_json();
        value["smtp"]["from"] = json!("teal@example.com\r\nBcc: x@example.com");
        assert!(parse(value).is_err());
    }

    #[test]
    fn requires_valid_common_to_address() {
        let mut value = valid_json();
        value["smtp"].as_object_mut().unwrap().remove("to_address");
        assert!(parse(value).is_err());

        for address in [
            "",
            "security-team",
            "Name <team@example.com>",
            "team@example.com\r\nBcc: leak@example.com",
            "team@example.com ",
        ] {
            let mut value = valid_json();
            value["smtp"]["to_address"] = json!(address);
            assert!(parse(value).is_err(), "accepted invalid To: {address:?}");
        }
    }

    #[test]
    fn rejects_unsafe_or_duplicate_credential_names() {
        let mut value = valid_json();
        value["smtp"]["credentials"]["password"] = json!("../etc/passwd");
        assert!(parse(value).is_err());
        let mut value = valid_json();
        value["smtp"]["credentials"]["password"] = json!("smtp_user");
        assert!(parse(value).is_err());
    }

    #[test]
    fn rejects_zero_rate_limits() {
        let mut value = valid_json();
        value["rate_limit"]["ai_per_minute"] = json!(0);
        assert!(parse(value).is_err());
        let mut value = valid_json();
        value["rate_limit"]["deny_per_minute"] = json!(0);
        assert!(parse(value).is_err());
    }

    #[test]
    fn rejects_missing_required_fields_and_bad_json() {
        let mut value = valid_json();
        value["rate_limit"]
            .as_object_mut()
            .unwrap()
            .remove("deny_per_minute");
        assert!(parse(value).is_err());
        assert!(MailerConfig::from_json("{broken json").is_err());
    }
}
