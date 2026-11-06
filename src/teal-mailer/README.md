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

---

# TEAL Phase 2 / Step 1 — teald 非同期通知キュー + IPC Sender

2026-11-05。Phase 1 の「共通 To + 参考通知先 Bcc」方式を継承する。
この成果物は `teald` 本体の**一部追加ソース**と、独立したテスト用 Cargo ワークスペース。
`teald` の既存ワークスペース全体を受領していないため、既存 `teald/src/lib.rs` と
`teald/Cargo.toml` は上書きしない。統合作業は以下の手順で行う。

## 実装済み

- `notification/config.rs`: 固定初期値、IPC 接続・応答タイムアウト、指数バックオフ。デフォルトのソケットは既存定数 `/run/teal/teal-notify.sock`。
- `notification/queue.rs`: AI 128件、DENY 896件の独立した有界 Tokio mpsc。送信元は `try_enqueue_ai/deny()` による **非同期待機なし** の投入。満杯時はエラー返却と件数計測。
- `notification/ipc_client.rs`: 4バイト big-endian + JSON の通信、フレーム最大64KiB、socket 接続・書込み・応答待ちタイムアウト、応答 ID 対応、ステータス評価、再接続・指数バックオフ。
- `notification/mod.rs`: 2本の独立 IPC Sender、再利用可能な `NotificationHandle`、将来のイベント元用の `global_handle()`。
- 単体テスト: キュー満杯、種別不一致、設定、IPC フレーム送受信、RetryableError → AcceptedBySmtp、接続失敗。
- 独立テストワークスペース `test-harness/`：提供された Phase 1 と同じ protocol v1.0 を収録。Rust が使える PC で Cargo テスト可能。`test-harness` のコードは、本体と同じ notification モジュールを参照する。

**既存のメールアドレス設定は変更不要。** `mailer.json` の `smtp.to_address` は mailer 側のまま。`NotificationRequest.recipients` は Bcc の参考通知先。空配列も許容。

## このステップではまだ実装しない

- `ACCESS_DENIED` からの自動生成・ENFORCE 確認・AI 検出連携・ロール→Bcc 解決
- DENY の5分窓集約、レート制限（mailer の独立 Worker は後続段階）
- 通知内容の規格化／byte 数上限の生成時強制（IPC Sender では64KiB超過を恒久エラー扱い）
- AI 満杯時の永続退避、DENY 溢れの集約と損失情報保持
- 正常終了時の待機キュー保存／再起動時の復元、デッドレターの永続記録
- 共通 To のメール到着・人による受領確認（`AcceptedBySmtp` は SMTP サーバー受理のみ）

失敗時の挙動：同種別で一度に送信するのは1件（in-flight）だけ。
一時障害ではその通知を保持し、2秒→4秒→8秒…最大60秒のバックオフで再送する。
無限再送の間は同じキューの後続通知は待機する。別種別のキューは独立稼働する。
恒久失敗はログ・件数計測後に処理を終了し、現段階では永続保存しない。
IPC 応答不明で再送すると、SMTP 受理済みメールが重複する可能性がある。

## A. まず単体テスト（本体の teald を変更しない）

```bash
unzip teald-notification-phase2-step1.zip -d /tmp/teald-phase2
cd /tmp/teald-phase2/test-harness
cargo test --workspace
```

ここでは本番 SMTP に接続しない。仮の Unix Domain Socket をテスト内部で作成する。

## B. 既存 TEAL ワークスペースへ統合

以下は既存ルートが `~/TEAL/src` という前提。**既存 `teald/src` 全体は上書きしないこと。**

```bash
cd ~/TEAL/src
cp -r /tmp/teald-phase2/teald/src/notification teald/src/
```

`teald/src/lib.rs`（**teal_common の lib.rs ではない**）に追記：

```rust
pub mod notification;
```

`teald/Cargo.toml` の `[dependencies]` に未登録なら追記：

```toml
teal-notify-protocol = { path = "../teal-notify-protocol" }
serde_json = "1"
```

既存の `tokio` に必要な features: `net`, `io-util`, `time`, `sync`, `rt`（または `full`）。
`teal_common::TEAL_NOTIFY_SOCKET_PATH` は現在の共通クレートですでに定義済み。

ユーザーから提供された2026-11-04版 `teald/src/main.rs` を基準にしたパッチ：

```bash
cd ~/TEAL/src
patch --dry-run -p1 < /tmp/teald-phase2/integration/teald-main.patch
patch -p1 < /tmp/teald-phase2/integration/teald-main.patch
```

`EvidenceManager::init(1024, ai_runtime);` の直後に、通知サブシステムの起動と `install_global()` が追加される。
エラーが起きても認可デーモンは終了しない。`main.rs` の内容が違えば、
`integration/main.rs.after` を参考に該当ブロックのみ手作業で追加。

```bash
cargo check -p teald
cargo test -p teald
cargo build --release -p teald
```

`teald` の実運用インストール・再起動は他の開発変更を十分確認してから行うこと。
今回は自動イベント通知の呼び出し元が未接続なので、実際の DENY 発生によるメール送信はまだ起きない。

## C. 既存 mailer を使う実 SMTP スモークテスト（実メールを送信）

本体の `teald` 変更と独立して、IPC Sender が **本当にメールを送れる** ことを確認する。
ビルドは一般ユーザーで行い、socket mode `0600` のため**実行バイナリのみ root で起動**する。

```bash
cd /tmp/teald-phase2/test-harness
cargo build -p teald-notification-smoke --bin send_test
sudo ./target/debug/send_test --send-real-mail
# 参考 Bcc もテストするときだけ：
sudo ./target/debug/send_test --send-real-mail test-recipient@example.com
```

共通 To は既存 `/etc/teal.d/mailer.json` で設定済みのアドレスに送信される。
`--send-real-mail` を指定しない限り、テストプログラムは実メールを送らない。
送信テストは合成 DENY 通知であり、実際の攻撃検出や実アクセス拒否を示さない。
結果表示 `AcceptedBySmtp` の後、共通 To のメールボックスで受信確認する。

## 将来のイベント処理との API 接続例

```rust
// event を NotificationRequest に整形し、ロールで Bcc を解決したあと：
if let Some(handle) = teald::notification::global_handle() {
    match handle.try_enqueue_deny(request) {
        Ok(()) => {}
        Err(teald::notification::EnqueueError::QueueFull) => {
            // 次の段階: bounded 集約超過情報に計上する
        }
        Err(other) => {
            // 次の段階: 失敗種別に応じて診断記録を追加する
            eprintln!("notification enqueue error: {other:?}");
        }
    }
}
```

`NotificationRequest` の `notification_id` は呼び出し側で一意に発行し、
**再送では同じ ID を使用**する。AI と DENY の生成者は SMTP を待機しない。

## 変更を既存 TEAL に組み込むときの注意

- 実際の `teald/src/lib.rs` / `teald/Cargo.toml` 未受領につき、統合作業と cargo コンパイルはユーザー環境で要検証。
- 作業環境に `cargo` / `rustc` がないため、コードのコンパイルと実 SMTP テストは **未実施**。ここに含まれるテストはユーザー環境で実行する。
- 送信 worker を `tokio::spawn` しており `teald` の既存アクセス判定処理は IPC を待たない。
- いまは再送数の上限がない。長時間の mailer 停止中はキューが満杯になり得る。次の復旧・退避実装が不可欠。
- 実際のセキュリティ運用では共通 To の監視当番、代理人への連絡、エスカレーションを組織側で定める。


---

# TEAL Phase 2 — Step 2: ENFORCE DENY → 非同期通知キュー

2026-11-05。Phase 2 Step 1 (`notification::start`, `global_handle`, `try_enqueue_deny`) の導入が前提です。

## 実装範囲

1. `teald/src/notification/deny_event.rs` を追加。監査ログの `audit_id`, timestamp, subject, action, object, epoch から `NotificationRequest::Deny` を生成。
2. `teald/src/worker/audit.rs` の `process_resolved_event()` にフックを追加。`PolicyDecision::Deny | NoRuleMatched` かつ **ENFORCEレーン** のみ対象。
3. `EvidenceManager::log_slow_path_static()` の後で `submit()` → `NotificationHandle::try_enqueue_deny()`。**IPC/SMTP の await なし**、キュー満杯時は戻り値と既存カウンタで把握。
4. 通知 ID は `DENY-{audit_id}`。監査ログとメールの関連を保ち、同一通知の IPC 再送でも ID を固定する。
5. キュー利用可能性・宛先なし・長さ検証を実施。共通Toは `mailer.json` 側、Bccは今回空配列（Phase 2 Step3 で roles.json と連動）。
6. `target_parent` は**絶対ファイルパスなら親ディレクトリ**、非ファイル系ターゲットは当面元の識別子を使用。`target_samples` に元パス1件、`count=1`、`first_seen=last_seen`。

## 組み込み手順（既存ソースを上書きしない）

```sh
unzip teal-phase2-deny-enqueue.zip -d /tmp/teal-phase2-deny
cd ~/TEAL/src

# 追加モジュールのみコピー。すでに変更した ipc_client.rs / queue.rs などは上書きしません。
cp /tmp/teal-phase2-deny/teald/src/notification/deny_event.rs teald/src/notification/

patch --dry-run -p1 < /tmp/teal-phase2-deny/integration/teald-notification-mod.patch
patch --dry-run -p1 < /tmp/teal-phase2-deny/integration/teald-audit-deny.patch

patch -p1 < /tmp/teal-phase2-deny/integration/teald-notification-mod.patch
patch -p1 < /tmp/teal-phase2-deny/integration/teald-audit-deny.patch

cargo fmt -p teald
cargo check -p teald
cargo test -p teald
```

**重要：** `teald-audit-deny.patch` は前回共有された `audit(1).rs`（2026-10-19アップロード版）を基準に作成しました。その後に `audit.rs` に変更があれば `--dry-run` が失敗する場合があります。`integration/teald-audit-deny.patch` の追加ブロックを **現在の** `process_resolved_event()` に移植してください。構造を丸ごと置換しないでください。

### 単独テスト（本体のコードを変更せず実施）

```sh
cd /tmp/teal-phase2-deny/test-harness
cargo test --workspace
```

特に `notification::deny_event::tests` に、ENFORCE条件、通知の組み立て、Bcc空、通知ID、キュー投入と満杯条件のテストがあります。`test-harness` は単体で SMTP へメールを送信しません。

### 運用試験

1. `teal-mailer.socket` が active (listening)、`teald` 本体の通知キュー初期化が成功していることを確認。
2. `teald` の AUDIT モードでは、ポリシー評価結果が DENY でもメールが発生しないことを確認。
3. ENFORCE に切り替え、検証専用の安全な操作で `ACCESS_DENIED` を1件発生させる。監査ログの audit_id に対応するメールが共通Toに届き、ログに `AcceptedBySmtp` が出ることを確認。
4. `journalctl -u teald.service`、`journalctl -u teal-mailer.service` でエラーを確認。

**本番ENFORCEでの運用はまだ行わないでください。** 今回は1 DENYにつき1通知です。規定の5分・7属性集約、最大1000グループ・10サンプル・queue-overflow、宛先ロール解決、SMTP側レート制限が未完成で、DENYが大量発生するとメール洪水になり得ます。

## 設計上の境界

- ENFORCEの実際の `ACCESS_DENIED` だけを対象とします。`handle_audit_req` 内の shadow deny、MPA中の `EntryDenied`、管理操作の `CtlDenied` はこの段階で対象にしません。
- 現行の `process_resolved_event()` は、ルールの解決や epoch 整合性確認でエラーになると監査ログ出力前に戻ります。今回はその処理を変更していません。したがって、監査ログが生成されなかった事象のメールも生成されません。
- 通知キューが満杯・未初期化・終了した場合は既存の監査処理を止めず、警告を記録します。失われる通知の永続退避は未実装です。
- JSON/IPC フレーム上限64KiBと`teal-mailer`側の厳しいフィールド長制約に準拠するよう入力を検証します。
- `AcceptedBySmtp` は SMTP リレー受理の確認であり、受信箱到達・担当者の確認を保証しません。

## Commit message

```text
feat(teald): enqueue confirmed ENFORCE denials for asynchronous notification
```

---

# TEAL DENY 5-minute aggregation + independent mailer SMTP rate limits

## What this changes

- `teald/src/notification/aggregation.rs` (new): 7-field aggregation key (hostname, UID, program, action, rule ID, target parent, epoch); 300s fixed window anchored at initial DENY, maximum 1,000 groups, maximum 10 distinct Target samples, initial notification immediately enqueued, follow-up summary on expiry only if later DENYs occurred. When full, evicts the oldest group and enqueues its pending summary with `early_flush=true`.
- `teald/src/notification/deny_event.rs`: `submit()` now sends DENYs through a global aggregator created on first submit, with a 1s periodic sweeper. `enqueue_to()` is retained as a direct-enqueue test helper.
- `teald/src/notification/mod.rs`: registers the aggregation module.
- `teal-mailer/src/rate_limit.rs` (new): independent strict 60s rolling attempt budgets, default from `mailer.json` (typically AI=10/minute, DENY=5/minute). The budget is shared across concurrent IPC connections; unsuccessful SMTP attempts also consume a slot.
- `teal-mailer/src/ipc_server.rs`: checks the configured per-kind limit *after input validation and before SMTP*; on limit hit returns `RetryableError` with `RATE_LIMIT`, without trying SMTP.
- `teal-mailer/src/main.rs`: wires `rate_limit` and passes `cfg.rate_limit` to the IPC server.

Important: the `teal-mailer/src/ipc_server.rs` patch is based on the user's `ipc_server(1).rs` snapshot that ALREADY includes permanent validation diagnostics. It preserves these diagnostics. The `teald` patch is based on the November 5 Phase 2 DENY enqueue implementation, not an earlier audit.rs; **no edits to audit.rs** are required because it already calls `deny_event::submit`.

## Apply from `~/TEAL/src`

1. Commit or back up local edits first; check `git status --short`.
2. Extract this ZIP (example `unzip teal-deny-aggregation-rate-limit.zip -d /tmp/teal-deny-agg`).
3. `cd ~/TEAL/src`
4. Check exact source compatibility:
   ```bash
   patch --dry-run --fuzz=0 -p1 < /tmp/teal-deny-agg/integration/teald-deny-aggregation.patch
   patch --dry-run --fuzz=0 -p1 < /tmp/teal-deny-agg/integration/teal-mailer-rate-limit.patch
   ```
5. If both checks pass, apply the same commands without `--dry-run`.
6. `cargo fmt -p teald -p teal-mailer`
7. `cargo test -p teald --lib && cargo test -p teal-mailer`
8. `cargo check -p teald && cargo check -p teal-mailer`

If patch hunks fail, compare supplied full files with your current modified files instead of forcing fuzzy application. **Do not overwrite newer local changes.**

## Deployment and tests

Build/install only in a dedicated safe test environment:

```bash
cargo build --release -p teald -p teal-mailer
# First verify teald update is safe in your TEAL fail-safe operational procedure.
sudo systemctl stop teal-mailer.service
sudo install -m 0755 target/release/teal-mailer /usr/local/sbin/teal-mailer
sudo /usr/local/sbin/teal-mailer --check-config /etc/teal.d/mailer.json
sudo systemctl reset-failed teal-mailer.service teal-mailer.socket
sudo systemctl start teal-mailer.socket
# Install/restart teald ONLY during a TEAL-safe maintenance/test window.
```

For a controlled DENY rule (already integration-tested in Phase 2):
- First denied operation → one immediate notification (`DENY-<audit_id>`).
- 2nd/3rd denied operation for the same 7-field key within 300s → no immediate new message.
- At the fixed 300s boundary → one summary (`DAG-<representative_audit_id>`) with `count = number of subsequent DENYs`, not including the already-sent initial DENY. If zero subsequent DENYs, no summary is sent.
- If the sequence continues into the next 300s interval → the next interval generates its own summary, without an extra immediate message.
- Under the mailer's DENY limit, the 6th SMTP attempt in any rolling 60s window receives `RetryableError/RATE_LIMIT`; teald's sender holds the same request ID and retries with backoff. Expect delayed emails, not disappearance.

### Standalone module tests

The included `test-harness` points at the bundled `teald` module tree and exercises the same aggregation unit tests without your full kernel build:

```bash
cd /tmp/teal-deny-agg/test-harness
cargo test --workspace
```

The actual `teald` and `teal-mailer` workspaces should be used for the definitive Rust tests.

## Important current limitations / scope

- `notifications.json` loading and role-derived Bcc were not implemented in the earlier Phase 2 step; this patch keeps the same in-process default aggregation parameters and Bcc logic.
- Aggregation state is in memory only. A `teald` restart loses current windows and pending aggregated notifications; crash-safe checkpointing remains a separate phase.
- Queue saturation keeps rejected notifications in their existing aggregation group for subsequent non-blocking retry when possible. When a group has already been evicted/removed, the failed enqueue cannot be restored in this bounded structure. A cumulative *unrecoverable DENY event count* is logged once per minute, not injected into a synthetic email. Full specification-level overflow summary delivery remains separate work.
- The 60-second SMTP attempt limits reset when `teal-mailer` restarts. Each failed SMTP attempt consumes its budget slot; manual `--send-test` mode is outside the IPC limiter.
- `CONNECT` targets remain grouped by their full target string, consistent with existing `deny_event::target_group()`. Operation-specific network endpoint normalization is later work.
- `AcceptedBySmtp` confirms relay acceptance, **not delivery to the inbox**. Retry after an ambiguous IPC result can duplicate a mail.
- There is intentionally NO notification path in the kernel reply-critical section, and no extra audit log changes. Every denied action is still logged individually.
- No Rust toolchain was available in the artifact-authoring environment; patch application was verified against the specified source snapshots, but the user should run `cargo test` / `cargo check` before deployment.


---
