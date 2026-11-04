// SPDX-License-Identifier: MIT
/*
 * TEAL mailer for Notification (teal-mailer)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use crate::config::{is_valid_credential_name, ConfigError, CredentialConfig, MailerConfig};
use std::{env, error::Error, fmt, fs::File, io::{self, Read}, path::Path};
use zeroize::Zeroizing;

/// Maximum size of an individual SMTP credential, in bytes.
/// Bound memory use even if a credential file is unexpectedly large.
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

/// Sensitive UTF-8 value: no Clone, no plaintext Debug/Display output,
/// and its live allocation is zeroized on drop.
pub struct Secret {
    value: Zeroizing<String>,
}

impl Secret {
    /// Explicit access for the SMTP authentication layer only.
    pub fn expose(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// SMTP authentication data loaded from systemd's per-service credential files.
/// Keep this value inside teal-mailer; never log or serialize it.
pub struct SmtpCredentials {
    pub username: Secret,
    pub password: Secret,
}

impl fmt::Debug for SmtpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpCredentials")
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

#[derive(Debug)]
pub enum CredentialsError {
    InvalidConfiguration(ConfigError),
    MissingDirectory,
    InvalidDirectory,
    InvalidCredentialNames,
    Read { kind: &'static str, source: io::Error },
    TooLarge { kind: &'static str },
    Empty { kind: &'static str },
    InvalidCharacters { kind: &'static str },
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(source) => write!(f, "invalid mailer config: {source}"),
            Self::MissingDirectory => f.write_str("CREDENTIALS_DIRECTORY is not set (start via systemd)"),
            Self::InvalidDirectory => f.write_str("CREDENTIALS_DIRECTORY must be an absolute directory path"),
            Self::InvalidCredentialNames => f.write_str("unsafe SMTP credential identifiers"),
            Self::Read { kind, source } => write!(f, "failed to read SMTP {kind} credential: {source}"),
            Self::TooLarge { kind } => write!(f, "SMTP {kind} credential exceeds size limit"),
            Self::Empty { kind } => write!(f, "SMTP {kind} credential is empty"),
            Self::InvalidCharacters { kind } => {
                write!(f, "SMTP {kind} credential contains NUL or newline")
            }
        }
    }
}

impl Error for CredentialsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidConfiguration(source) => Some(source),
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl SmtpCredentials {
    /// Production entry point. systemd decrypts LoadCredentialEncrypted
    /// before starting this process, and exports CREDENTIALS_DIRECTORY.
    pub fn load(config: &MailerConfig) -> Result<Self, CredentialsError> {
        config.validate().map_err(CredentialsError::InvalidConfiguration)?;
        let directory = env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or(CredentialsError::MissingDirectory)?;
        Self::load_from_directory(&config.smtp.credentials, Path::new(&directory))
    }

    /// The directory is passed explicitly to make unit testing independent
    /// of process-wide environment variables.
    fn load_from_directory(
        config: &CredentialConfig,
        directory: &Path,
    ) -> Result<Self, CredentialsError> {
        // Defense in depth: a CredentialConfig may have been constructed directly.
        if !is_valid_credential_name(&config.user)
            || !is_valid_credential_name(&config.password)
            || config.user == config.password
        {
            return Err(CredentialsError::InvalidCredentialNames);
        }
        if !directory.is_absolute() || !directory.is_dir() {
            return Err(CredentialsError::InvalidDirectory);
        }

        let username = read_secret(directory, &config.user, "username")?;
        let password = read_secret(directory, &config.password, "password")?;
        Ok(Self { username, password })
    }
}

fn read_secret(
    directory: &Path,
    name: &str,
    kind: &'static str,
) -> Result<Secret, CredentialsError> {
    let file = File::open(directory.join(name))
        .map_err(|source| CredentialsError::Read { kind, source })?;

    // Read at most MAX_CREDENTIAL_BYTES + 1 bytes to detect overflow.
    // Partial data is still zeroized when an error is returned.
    let mut text = Zeroizing::new(String::new());
    file.take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_string(&mut *text)
        .map_err(|source| CredentialsError::Read { kind, source })?;

    if text.len() > MAX_CREDENTIAL_BYTES {
        return Err(CredentialsError::TooLarge { kind });
    }
    if text.is_empty() {
        return Err(CredentialsError::Empty { kind });
    }
    // Avoid silently trimming: a trailing newline from `echo` is likely a
    // provisioning mistake; spaces can be meaningful in SMTP passwords.
    if text.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')) {
        return Err(CredentialsError::InvalidCharacters { kind });
    }

    Ok(Secret { value: text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CredentialProvider;
    use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let n = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "teal-mailer-credentials-test-{}-{n}", std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            fs::write(self.0.join(name), bytes).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn ids() -> CredentialConfig {
        CredentialConfig {
            provider: CredentialProvider::Systemd,
            user: "smtp_user".into(),
            password: "smtp_password".into(),
        }
    }

    #[test]
    fn reads_username_and_password_without_modification() {
        let dir = TestDir::new();
        dir.write("smtp_user", b"mailer@example.com");
        dir.write("smtp_password", b"leading and trailing spaces ");
        let credentials = SmtpCredentials::load_from_directory(&ids(), &dir.0).unwrap();
        assert_eq!(credentials.username.expose(), "mailer@example.com");
        assert_eq!(credentials.password.expose(), "leading and trailing spaces ");
    }

    #[test]
    fn debug_redacts_both_secrets() {
        let dir = TestDir::new();
        dir.write("smtp_user", b"private-user@example.com");
        dir.write("smtp_password", b"top-secret-password");
        let credentials = SmtpCredentials::load_from_directory(&ids(), &dir.0).unwrap();
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("private-user@example.com"));
        assert!(!debug.contains("top-secret-password"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn missing_password_is_an_error() {
        let dir = TestDir::new();
        dir.write("smtp_user", b"mailer@example.com");
        let err = SmtpCredentials::load_from_directory(&ids(), &dir.0).unwrap_err();
        assert!(matches!(err, CredentialsError::Read { kind: "password", .. }));
    }

    #[test]
    fn empty_or_newline_credentials_are_rejected() {
        let dir = TestDir::new();
        dir.write("smtp_user", b"");
        dir.write("smtp_password", b"password");
        assert!(matches!(
            SmtpCredentials::load_from_directory(&ids(), &dir.0),
            Err(CredentialsError::Empty { kind: "username" })
        ));

        dir.write("smtp_user", b"mailer@example.com");
        dir.write("smtp_password", b"password\n");
        assert!(matches!(
            SmtpCredentials::load_from_directory(&ids(), &dir.0),
            Err(CredentialsError::InvalidCharacters { kind: "password" })
        ));
    }

    #[test]
    fn oversized_credential_is_rejected() {
        let dir = TestDir::new();
        dir.write("smtp_user", b"mailer@example.com");
        dir.write("smtp_password", &vec![b'x'; MAX_CREDENTIAL_BYTES + 1]);
        assert!(matches!(
            SmtpCredentials::load_from_directory(&ids(), &dir.0),
            Err(CredentialsError::TooLarge { kind: "password" })
        ));
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        let dir = TestDir::new();
        dir.write("smtp_user", b"mailer@example.com");
        dir.write("smtp_password", &[0xff]);
        assert!(matches!(
            SmtpCredentials::load_from_directory(&ids(), &dir.0),
            Err(CredentialsError::Read { kind: "password", .. })
        ));
    }

    #[test]
    fn unsafe_names_cannot_escape_credential_directory() {
        let dir = TestDir::new();
        let mut names = ids();
        names.password = "../etc/shadow".to_string();
        assert!(matches!(
            SmtpCredentials::load_from_directory(&names, &dir.0),
            Err(CredentialsError::InvalidCredentialNames)
        ));
    }

    #[test]
    fn requires_an_absolute_existing_directory() {
        let err = SmtpCredentials::load_from_directory(&ids(), Path::new("relative/path"))
            .unwrap_err();
        assert!(matches!(err, CredentialsError::InvalidDirectory));
    }
}
