# TEAL mailer Phase 1: systemd Credentials reader

This package continues the previously generated config.rs implementation.

## Copy into the TEAL workspace
- teal-mailer/src/credentials.rs (new)
- teal-mailer/src/main.rs (replace temporary Phase 1 main)
- teal-mailer/src/config.rs (one change: make is_valid_credential_name pub(crate))
- teal-mailer/Cargo.toml (add zeroize dependency)
- mailer.example.json (unchanged reference)

## Tests

```bash
cargo test -p teal-mailer
```

## CLI verification

```bash
cargo run -p teal-mailer -- --check-config /etc/teal.d/mailer.json
```

This checks JSON only, and can run outside systemd.

```bash
cargo run -p teal-mailer -- --check-credentials /etc/teal.d/mailer.json
```

This requires CREDENTIALS_DIRECTORY to be provided, normally by systemd to
teal-mailer.service. The service invocation is `--config /etc/teal.d/mailer.json`.

CREDENTIALS_DIRECTORY points to plaintext files already decrypted by systemd;
this module does not decrypt the .cred files itself. Secret values are never
printed by this module. Credentials remain sensitive in process memory while
used; Zeroizing<String> is best-effort memory cleanup, not a complete guarantee
against copies, swap, core dumps or privileged inspection.

`teal-mailer.service` MUST NOT be deployed with this temporary main: it exits
after validation and does not yet accept IPC / send SMTP messages.

---

# TEAL mailer Phase 1 — lettre SMTP single-send implementation

Includes `teal-mailer/src/smtp.rs` and updates `teal-mailer/src/main.rs` and
`Cargo.toml`, based on the prior config.rs and credentials.rs implementation.
This ZIP assumes your TEAL Rust workspace **already includes**
`teal-notify-protocol` as a sibling crate. Its source is not overwritten.

## Features

- Authenticated async SMTP using lettre 0.11.23 + Tokio 1
- Port 465: implicit TLS; all other ports: **required STARTTLS**
- TLS server certificate and host-name verification; `rustls` TLS backend
- Login information read from the earlier systemd Credentials module
- Message body: UTF-8 text/plain; recipient addresses sent as Bcc (not disclosed)
- One SMTP attempt only, 20 s command timeout and 40 s overall timeout
- Error classification: SMTP 4xx → RetryableError; SMTP 5xx → PermanentError;
  TLS verification/config errors → PermanentError; network/timeout → RetryableError
- Fixed IPC-safe error codes, no raw SMTP responses and no logging of secrets
- Six offline unit tests of message building and IPC result mapping

## Integration

Place the crate files into `teal-mailer/`, keeping the pre-existing
`teal-notify-protocol/` crate. Ensure the workspace registers both packages.

```bash
cargo test -p teal-mailer
cargo run -p teal-mailer -- --check-config /etc/teal.d/mailer.json
```

For an actual test email, start the binary **under systemd** so that
`CREDENTIALS_DIRECTORY` and the two encrypted Credentials are available.
An opt-in command is provided:

```bash
# Once the new binary is installed at /usr/local/sbin/teal-mailer:
sudo systemd-run --unit=teal-mailer-smtp-test --wait --collect \
  -p User=teal-mailer -p Group=teal-mailer \
  -p LoadCredentialEncrypted=smtp_user:/etc/credstore.encrypted/teal.smtp_user \
  -p LoadCredentialEncrypted=smtp_password:/etc/credstore.encrypted/teal.smtp_password \
  /usr/local/sbin/teal-mailer --send-test receiver@example.com
sudo journalctl -u teal-mailer-smtp-test --no-pager -n 40
```

Replace `receiver@example.com` with your test mailbox. The command performs
an actual send. Test only against an SMTP server you control or are permitted
to use. The `mailer.json` SMTP host/port/from must also be configured.

## Scope / remaining work

- `teal-mailer.socket` / `teal-mailer.service` socket activation is **not yet
  operational**. `--config` currently validates the configuration/credentials
  and exits; the IPC server will be added in the next step.
- AI/DENY formatting, separate worker rate limits, queueing, retries, and
  recovery are future steps. The SMTP module must not retry on its own.
- SMTP acceptance is *not* inbox delivery. If a response is lost after SMTP
  acceptance, upstream retries can cause duplicates; Notification ID is for
  correlation, not exactly-once delivery.
- Secure credential handling is best-effort: `lettre::Credentials` owns copies
  of secrets that cannot be guaranteed to be zeroized on drop.
- Full Rust compilation and live SMTP delivery were **not tested in this
  environment**. Run cargo tests locally and verify with a real SMTP server.
- `lettre` 0.11.23 requires Rust 1.85 or later.

---

# TEAL Mailer Phase 1: Unix IPC / Socket Activation

## Purpose

`teal-mailer/src/ipc_server.rs` adds the systemd socket-activated Unix IPC
server to the previously delivered config/credentials/SMTP modules.

**Normal operation** now serves IPC. The default and `--config PATH` modes
no longer exit after credential verification, unlike the earlier placeholder.

The two included crates form an **independently testable mini-workspace**.
In your existing TEAL workspace, copy only the files relevant to your project
and keep your real workspace's `Cargo.toml`. The included protocol code is
an exact copy of the last user-supplied `lib.rs` (not a new version).

## Files

- `teal-mailer/src/ipc_server.rs` — new
- `teal-mailer/src/main.rs` — updated for socket activation
- `teal-mailer/Cargo.toml` — adds Tokio `net`, `io-util`, `sync`, `signal`
- `teal-mailer/src/config.rs`, `credentials.rs`, `smtp.rs` — previous versions unchanged
- `teal-notify-protocol` — reference copy for standalone tests
- `tools/send_ipc_test.py` — one-shot Unix client using the same wire format
- `systemd/*` — reference copies from user uploads; unchanged

## Wire protocol

One connection / one request / one response, then close.

```
request:  [u32 BE JSON byte length][JSON NotificationRequest]
response: [u32 BE JSON byte length][JSON DeliveryResponse]
```

Frame length is payload bytes, excluding the 4-byte header; 1..=65536.
The server reads the header before allocating its buffer.
The receiver checks `NotificationRequest::validate()` before sending mail.
A parseable, invalid request receives `PermanentError/INVALID_REQUEST` with
its `notification_id`; broken JSON or an invalid frame closes the connection.
An unauthorized client receives no response.

Only peer uid 0 is accepted (`SO_PEERCRED`), reflecting the current root-run
`teald` design. When `teald` moves to a dedicated UID, revisit this policy and
socket ownership (`SocketMode=0600` currently permits only root to connect).
`SO_PEERCRED` by itself **does not** distinguish teald from other root processes.

## One-message SMTP semantics

- `AcceptedBySmtp`: SMTP server accepted the message, not guaranteed mailbox delivery.
- `RetryableError`: SMTP error code indicates retry might succeed.
- `PermanentError`: invalid request/message or permanent SMTP error.
- There is **no retry inside the mailer**. The future teald IPC Sender owns retries.
- SMTP acceptance followed by IPC interruption has ambiguous delivery status;
  an external retry may send duplicate emails. The Notification ID is included
  in the message body to help trace duplicates.
- Before Phase 4 there is **no AI/DENY rate limiter**. Do not expose this
  implementation to bulk production notification traffic yet.

## Build and tests

From your TEAL workspace root:

```sh
cargo check -p teal-mailer
cargo test -p teal-mailer
cargo test -p teal-notify-protocol
```

This artifact was not compiled in the creation environment (no Rust toolchain
available). Validate with your `rustc 1.97.1` installation.

## Deployment

The existing service already contains:

```ini
ExecStart=/usr/local/sbin/teal-mailer --config /etc/teal.d/mailer.json
LoadCredentialEncrypted=smtp_user:/etc/credstore.encrypted/teal.smtp_user
LoadCredentialEncrypted=smtp_password:/etc/credstore.encrypted/teal.smtp_password
```

The existing socket contains:

```ini
ListenStream=/run/teal/teal-notify.sock
SocketMode=0600
Accept=no
```

No unit-file changes are required specifically for this code (assuming a
root-run `teald` client). The `/run/teal` directory's lifecycle across
teald/mailer restarts still needs to be checked separately.

Install after successfully compiling and checking the intended binary:

```sh
cargo build --release -p teal-mailer
sudo install -m 0755 target/release/teal-mailer /usr/local/sbin/teal-mailer
sudo systemctl daemon-reload
sudo systemctl enable --now teal-mailer.socket
systemctl status teal-mailer.socket
```

Trigger exactly one **real test email** through IPC, specifying only a test
mailbox:

```sh
sudo python3 tools/send_ipc_test.py --recipient test@example.com --kind deny
```

Expected response if the SMTP server accepts the message:

```json
{"notification_id":"PHASE1-...","status":"AcceptedBySmtp","error_code":null}
```

`teal-mailer.service` should start on demand. Check:

```sh
systemctl status teal-mailer.service
journalctl -u teal-mailer.service -n 50 --no-pager
```

### Important service isolation caveat

The SMTP/IPC implementation is independent from the teald process, but TEAL's
kernel/LSM policy and TEAL-NET controls still need a static allow rule for
mailer startup, credential access (via systemd), Unix IPC and SMTP outbound.
Otherwise TEAL's own enforcement may deadlock the notification path.

## Phase boundaries

- Phase 1: transport + one-shot SMTP + basic per-connection validation.
- Phase 2: teald's notification producers, bounded queues and IPC sender.
- Phase 4: AI/DENY dedicated workers, independently bounded rate limiting,
  and refined fair scheduling.
- Phase 5: failure/recovery and extended integration testing.

---

# TEAL Mailer Phase 1: Shared To + Informational Bcc (2026-11-04)

## Notification policy

- Mandatory `smtp.to_address` is the **accountable response mailbox**.
  A human on-call owner (and backup) is responsible for review, acknowledgement,
  assignment, and escalation; this is an organizational process, NOT software
  proof of message delivery or human acknowledgement.
- `NotificationRequest.recipients` are **informational Bcc mailboxes**.
  They are not shown in recipient headers. Empty Bcc is allowed; the common
  To mailbox is still an SMTP recipient.
- From, To and SMTP server are set only in trusted `mailer.json`.
  IPC callers cannot override them.
- A single SMTP transaction includes the common To and all Bcc recipients.
  SMTP failures, partial recipient acceptance, asynchronous bounces and
  timeouts can create ambiguous delivery outcomes. `AcceptedBySmtp` means
  SMTP relay acceptance only, **not** delivery to common To nor acknowledgement.
  Do not claim separate Bcc delivery guarantees.
- An informational Bcc rejecting during a shared SMTP transaction can affect
  the overall send result. If strong independent guarantees for the To mailbox
  are later required, use separate SMTP envelopes/transactions for primary
  To versus informational Bcc (with dedicated outcome semantics).

## Incompatible configuration change

`smtp.to_address` is now **required**. Before restarting teal-mailer, set it in
`/etc/teal.d/mailer.json` with a real monitored shared mailbox. For a Gmail
experiment, the Gmail sender may also be used as the shared To mailbox:

```json
"smtp": {
  "host": "smtp.gmail.com",
  "port": 465,
  "from": "your-account@gmail.com",
  "to_address": "your-account@gmail.com",
  "tls": "required",
  "credentials": {
    "provider": "systemd",
    "user": "smtp_user",
    "password": "smtp_password"
  }
}
```

The snippet is only the `smtp` portion; retain `version` and `rate_limit`
in the existing config. Do not put Gmail app passwords in JSON. Continue to
use systemd encrypted Credentials. No change to socket or service units.

## Changed source files

- `teal-mailer/src/config.rs`: required validated `smtp.to_address`.
- `teal-mailer/src/smtp.rs`: configured To header + informative Bcc; envelope
  contains To and Bcc. Updated tests, including empty Bcc.
- `teal-notify-protocol/src/lib.rs`: Bcc list may be empty. JSON frame and
  structs **unchanged**; only semantics of `recipients` and validation changed.
- `mailer.example.json`: common To example.

## Build / test / install in user's existing TEAL workspace

Copy modified sources to their corresponding workspace paths, keeping local
changes. Run `cargo test -p teal-mailer` and
`cargo test -p teal-notify-protocol`; then `cargo build --release -p teal-mailer`.
After editing `/etc/teal.d/mailer.json` to add `to_address`, run:

```sh
sudo /usr/local/sbin/teal-mailer --check-config /etc/teal.d/mailer.json
# After installing the new executable, stop the old on-demand service.
# The active .socket stays listening and activates the new executable on next IPC.
sudo systemctl stop teal-mailer.service
sudo python3 tools/send_ipc_test.py --recipient yahoo-test@example.com --kind deny
journalctl -u teal-mailer.service -n 50 --no-pager
```

Note: `--check-config` in the example must be run **after** installing the
new binary, because the old executable does not recognize `to_address`.
Confirm that the common To mailbox actually receives the mail and that Bcc
received it, rather than relying on `AcceptedBySmtp` alone.

---

# TEAL Mailer Phase 1: Unix IPC / Socket Activation

## Purpose

`teal-mailer/src/ipc_server.rs` adds the systemd socket-activated Unix IPC
server to the previously delivered config/credentials/SMTP modules.

**Normal operation** now serves IPC. The default and `--config PATH` modes
no longer exit after credential verification, unlike the earlier placeholder.

The two included crates form an **independently testable mini-workspace**.
In your existing TEAL workspace, copy only the files relevant to your project
and keep your real workspace's `Cargo.toml`. The included protocol code is
an exact copy of the last user-supplied `lib.rs` (not a new version).

## Files

- `teal-mailer/src/ipc_server.rs` — new
- `teal-mailer/src/main.rs` — updated for socket activation
- `teal-mailer/Cargo.toml` — adds Tokio `net`, `io-util`, `sync`, `signal`
- `teal-mailer/src/config.rs`, `credentials.rs`, `smtp.rs` — previous versions unchanged
- `teal-notify-protocol` — reference copy for standalone tests
- `tools/send_ipc_test.py` — one-shot Unix client using the same wire format
- `systemd/*` — reference copies from user uploads; unchanged

## Wire protocol

One connection / one request / one response, then close.

```
request:  [u32 BE JSON byte length][JSON NotificationRequest]
response: [u32 BE JSON byte length][JSON DeliveryResponse]
```

Frame length is payload bytes, excluding the 4-byte header; 1..=65536.
The server reads the header before allocating its buffer.
The receiver checks `NotificationRequest::validate()` before sending mail.
A parseable, invalid request receives `PermanentError/INVALID_REQUEST` with
its `notification_id`; broken JSON or an invalid frame closes the connection.
An unauthorized client receives no response.

Only peer uid 0 is accepted (`SO_PEERCRED`), reflecting the current root-run
`teald` design. When `teald` moves to a dedicated UID, revisit this policy and
socket ownership (`SocketMode=0600` currently permits only root to connect).
`SO_PEERCRED` by itself **does not** distinguish teald from other root processes.

## One-message SMTP semantics

- `AcceptedBySmtp`: SMTP server accepted the message, not guaranteed mailbox delivery.
- `RetryableError`: SMTP error code indicates retry might succeed.
- `PermanentError`: invalid request/message or permanent SMTP error.
- There is **no retry inside the mailer**. The future teald IPC Sender owns retries.
- SMTP acceptance followed by IPC interruption has ambiguous delivery status;
  an external retry may send duplicate emails. The Notification ID is included
  in the message body to help trace duplicates.
- Before Phase 4 there is **no AI/DENY rate limiter**. Do not expose this
  implementation to bulk production notification traffic yet.

## Build and tests

From your TEAL workspace root:

```sh
cargo check -p teal-mailer
cargo test -p teal-mailer
cargo test -p teal-notify-protocol
```

This artifact was not compiled in the creation environment (no Rust toolchain
available). Validate with your `rustc 1.97.1` installation.

## Deployment

The existing service already contains:

```ini
ExecStart=/usr/local/sbin/teal-mailer --config /etc/teal.d/mailer.json
LoadCredentialEncrypted=smtp_user:/etc/credstore.encrypted/teal.smtp_user
LoadCredentialEncrypted=smtp_password:/etc/credstore.encrypted/teal.smtp_password
```

The existing socket contains:

```ini
ListenStream=/run/teal/teal-notify.sock
SocketMode=0600
Accept=no
```

No unit-file changes are required specifically for this code (assuming a
root-run `teald` client). The `/run/teal` directory's lifecycle across
teald/mailer restarts still needs to be checked separately.

Install after successfully compiling and checking the intended binary:

```sh
cargo build --release -p teal-mailer
sudo install -m 0755 target/release/teal-mailer /usr/local/sbin/teal-mailer
sudo systemctl daemon-reload
sudo systemctl enable --now teal-mailer.socket
systemctl status teal-mailer.socket
```

Trigger exactly one **real test email** through IPC, specifying only a test
mailbox:

```sh
sudo python3 tools/send_ipc_test.py --recipient test@example.com --kind deny
```

Expected response if the SMTP server accepts the message:

```json
{"notification_id":"PHASE1-...","status":"AcceptedBySmtp","error_code":null}
```

`teal-mailer.service` should start on demand. Check:

```sh
systemctl status teal-mailer.service
journalctl -u teal-mailer.service -n 50 --no-pager
```

### Important service isolation caveat

The SMTP/IPC implementation is independent from the teald process, but TEAL's
kernel/LSM policy and TEAL-NET controls still need a static allow rule for
mailer startup, credential access (via systemd), Unix IPC and SMTP outbound.
Otherwise TEAL's own enforcement may deadlock the notification path.

## Phase boundaries

- Phase 1: transport + one-shot SMTP + basic per-connection validation.
- Phase 2: teald's notification producers, bounded queues and IPC sender.
- Phase 4: AI/DENY dedicated workers, independently bounded rate limiting,
  and refined fair scheduling.
- Phase 5: failure/recovery and extended integration testing.

