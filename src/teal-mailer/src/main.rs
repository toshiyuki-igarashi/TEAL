// SPDX-License-Identifier: MIT
/*
 * TEAL mailer for Notification (teal-mailer)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

mod config;
mod credentials;
mod ipc_server;
mod smtp;

use std::error::Error;
use teal_notify_protocol::DeliveryStatus;

// Normal start (`--config PATH`, as used by teal-mailer.service):
// load config+credentials+SMTP and serve systemd's inherited Unix listener.
// Diagnostics: --check-config, --check-credentials, and --send-test.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (path, check_config_only, check_credentials_only, test_recipient):
        (&str, bool, bool, Option<&str>) = match args.as_slice() {
            [] => (config::DEFAULT_CONFIG_PATH, false, false, None),
            [option, path] if option == "--config" => (path, false, false, None),
            [option, path] if option == "--check-config" => (path, true, false, None),
            [option, path] if option == "--check-credentials" => (path, false, true, None),
            [option, recipient] if option == "--send-test" => {
                (config::DEFAULT_CONFIG_PATH, false, false, Some(recipient))
            }
            [option, recipient, config_option, path]
                if option == "--send-test" && config_option == "--config" => {
                (path, false, false, Some(recipient))
            }
            _ => {
                eprintln!("Usage: teal-mailer [--config PATH | --check-config PATH | --check-credentials PATH | --send-test ADDRESS [--config PATH]]");
                std::process::exit(2);
            }
        };

    let cfg = config::MailerConfig::load_from_path(path)?;
    if check_config_only {
        println!("teal-mailer: configuration validated (credentials not read)");
        return Ok(());
    }

    let secrets = credentials::SmtpCredentials::load(&cfg)?;
    if check_credentials_only {
        println!("teal-mailer: configuration and credentials verified (values hidden)");
        return Ok(());
    }
    let sender = smtp::SmtpMailer::new(&cfg, &secrets)?;

    if let Some(recipient) = test_recipient {
        let outcome = sender.send_once(
            &[recipient.to_owned()],
            "TEAL mailer Phase 1 SMTP test",
            "This is a test notification from the TEAL mailer.\n",
        ).await;
        if outcome.status != DeliveryStatus::AcceptedBySmtp {
            eprintln!("teal-mailer: SMTP test failed ({})", outcome.error_code.unwrap_or("UNKNOWN"));
            return Err(std::io::Error::other("SMTP test failed").into());
        }
        println!("teal-mailer: SMTP server accepted test message (mailbox delivery not guaranteed)");
        return Ok(());
    }

    // The socket is created by systemd; do not bind /run/teal here.
    let listener = ipc_server::take_systemd_listener()?;
    println!("teal-mailer: IPC listener inherited from systemd");
    ipc_server::run(listener, sender).await?;
    Ok(())
}
