# TEAL Phase 1 — Gmail SMTP / systemd Socket Activation 実験環境設定

作成日：2026-11-04

## 目的と注意

`teal-mailer.socket` が管理する `/run/teal/teal-notify.sock` へ、独立したテスト IPC クライアントから `NotificationRequest` を送信し、`teal-mailer.service` による SMTP 認証・送信と `DeliveryResponse` の返却を検証する。Phase 1 では `teald` の通知機能への組み込みを必要としない。

**重要：現時点の `smtp.rs` は Bcc 方式で、先の議論で選んだ案 A（受信者ごとに `To:` を設定する個別送信）は未実装。** 今回のテストで Gmail の SMTP 経路と IPC は確認できるが、案 A の表示動作までは検証できない。また `rate_limit` は設定読み込みのみで、送信レート制御は未実装。

## 1. 必要条件

- Ubuntu / systemd、Rust 1.97.1、Cargo、Python 3、`openssl`。
- Google アカウントの2段階認証を有効化し、実験用の16文字のアプリパスワードを取得済み。
- SMTP 接続先 `smtp.gmail.com:465`（TLS 直接接続）。DNS、外向き TCP 465 と、TEAL/TEAL-NET 側の静的許可が必要。
- `teal-mailer` の現在の Cargo ワークスペース・ソースコードと `tools/send_ipc_test.py`。
- 既存の `teal-mailer.socket` と `teal-mailer.service` が `/etc/systemd/system/` に配置済み。

バージョン確認：

```bash
rustc --version
cargo --version
systemctl --version
python3 --version
```

## 2. 配置ファイル

| ファイル | 役割 |
| --- | --- |
| `/etc/teal.d/mailer.json` | Gmail 接続設定（秘密情報は含めない） |
| `/etc/credstore.encrypted/teal.smtp_user` | 暗号化した Gmail アドレス |
| `/etc/credstore.encrypted/teal.smtp_password` | 暗号化したアプリパスワード |
| `/etc/systemd/system/teal-mailer.socket` | systemd の待ち受けソケット定義 |
| `/etc/systemd/system/teal-mailer.service` | 非 root メール送信サービス定義 |
| `/usr/local/sbin/teal-mailer` | 実行バイナリ |
| `/run/teal/teal-notify.sock` | systemd が生成する Unix ソケット |

## 3. mailer.json

`/etc/teal.d/mailer.json` を作成し、`xxxx@gmail.com` を実際の送信アカウントへ置換する。

```json
{
  "version": "1.0",
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 465,
    "from": "xxxx@gmail.com",
    "tls": "required",
    "credentials": {
      "provider": "systemd",
      "user": "smtp_user",
      "password": "smtp_password"
    }
  },
  "rate_limit": {
    "ai_per_minute": 10,
    "deny_per_minute": 5
  }
}
```

`user` / `password` は **Credential の ID** であり、Gmail アドレスやパスワードそのものではない。`from` は実際に SMTP 認証する Gmail アカウントと同じにする。`mailer.json` は `teal-mailer` ユーザーが読めることを確認：

```bash
sudo -u teal-mailer test -r /etc/teal.d/mailer.json && echo 'mailer.json readable'
```

読めない場合は既存の `/etc/teal.d` のセキュリティ設定を確認し、このファイルへの読み取り・ディレクトリ通過権限を **最小限** 付与する（既存の TEAL ポリシー全体を一括して公開しない）。

## 4. 非特権ユーザー

作成済みなら再作成不要。

```bash
getent passwd teal-mailer >/dev/null || \
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin teal-mailer
id teal-mailer
```

## 5. systemd Credentials の登録（未登録の場合）

- `smtp_user` は `xxxx@gmail.com` **全体**。
- `smtp_password` は Google が4文字ごとに表示する空白を除いた **16文字**。通常の Google ログインパスワードを使わない。

```bash
sudo install -d -m 700 /etc/credstore.encrypted
sudo -v

read -r -p 'Gmail address: ' smtp_user
printf '%s' "$smtp_user" | \
  sudo systemd-creds encrypt --name=smtp_user - /etc/credstore.encrypted/teal.smtp_user
unset smtp_user

read -r -s -p 'Gmail app password: ' smtp_password
printf '\n'
smtp_password=${smtp_password// /}
if [[ ${#smtp_password} -ne 16 ]]; then
  echo 'ERROR: app password must contain 16 characters after removing spaces' >&2
else
  printf '%s' "$smtp_password" | \
    sudo systemd-creds encrypt --name=smtp_password - /etc/credstore.encrypted/teal.smtp_password
fi
unset smtp_password

sudo chmod 600 /etc/credstore.encrypted/teal.smtp_*
```

既に正しく暗号化してある場合、この登録を繰り返す必要はない。パスワードをコマンドライン引数、JSON、ログ、チャット等に書かない。`printf '%s'` により末尾改行が付かない（`credentials.rs` は改行をエラーとする）。

**復号可能性の確認（値を表示しない）：**

```bash
sudo systemd-creds decrypt --name=smtp_user \
  /etc/credstore.encrypted/teal.smtp_user - >/dev/null && echo 'smtp_user: OK'
sudo systemd-creds decrypt --name=smtp_password \
  /etc/credstore.encrypted/teal.smtp_password - >/dev/null && echo 'smtp_password: OK'
```

TPM2が使われる場合の暗号鍵バインディング等は systemd の動作環境による。暗号化 Credential は root 侵害からの完全防御を意味しない。

## 6. systemd Unit ファイルの確認

`/etc/systemd/system/teal-mailer.socket`:

```ini
[Unit]
Description=TEAL Notification Mailer Socket

[Socket]
ListenStream=/run/teal/teal-notify.sock
SocketMode=0600
DirectoryMode=0755
Accept=no

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/teal-mailer.service`:

```ini
[Unit]
Description=TEAL Mailer Service

[Service]
Type=simple
User=teal-mailer
Group=teal-mailer
ExecStart=/usr/local/sbin/teal-mailer --config /etc/teal.d/mailer.json
LoadCredentialEncrypted=smtp_user:/etc/credstore.encrypted/teal.smtp_user
LoadCredentialEncrypted=smtp_password:/etc/credstore.encrypted/teal.smtp_password
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Restart=on-failure
```

`teal-mailer.service` は通常 `enable` しない。ソケットへの接続で systemd が起動する。`SocketMode=0600` なので IPC のテストクライアントは root で実行し、サービス自体は非 root の `teal-mailer` で実行する。サーバー側 `SO_PEERCRED` は UID 0 のみ許可（root 間の個別識別まではしない）。

## 7. ビルド・インストール

TEAL Cargo ワークスペースルートで：

```bash
cargo check -p teal-notify-protocol
cargo test -p teal-notify-protocol
cargo check -p teal-mailer
cargo test -p teal-mailer
cargo build --release -p teal-mailer
sudo install -o root -g root -m 0755 \
  target/release/teal-mailer /usr/local/sbin/teal-mailer
```

`--check-config` はシェルから直接実行可能。`--send-test` / `--check-credentials` は通常のシェルから起動すると `$CREDENTIALS_DIRECTORY` がなく失敗するので、**実メール送信はソケット経由のテスト**にする。

```bash
sudo /usr/local/sbin/teal-mailer --check-config /etc/teal.d/mailer.json
```

## 8. サービス起動

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/teal-mailer.socket \
  /etc/systemd/system/teal-mailer.service
sudo systemctl daemon-reload
sudo systemctl enable --now teal-mailer.socket
systemctl status teal-mailer.socket
sudo ls -l /run/teal/teal-notify.sock
```

期待する状態は `teal-mailer.socket` の `active (listening)`。`teal-mailer.service` は IPC 接続まで inactive でも正常。

`/run/teal` を `teald.service` の `RuntimeDirectory=teal` 等でも管理する場合は、teald 停止時に通知ソケットまで消えないかを別途確認する。

## 9. 外向きネットワーク確認

```bash
getent ahosts smtp.gmail.com
openssl s_client -brief -connect smtp.gmail.com:465 \
  -servername smtp.gmail.com </dev/null
```

`openssl s_client` が成功しても SMTP 認証成功ではない。ファイアウォール、TEAL-NET、LSM ポリシー等で `teal-mailer` の DNS と TCP 465、必要な設定・Credential 読み込み、Unix IPC が静的に許可されている必要がある。無制限なプロセス除外は避ける。

## 10. IPC → Gmail 実送信テスト

同梱の `tools/send_ipc_test.py` があるディレクトリで、テスト用受信先を指定して **1通だけ**送る。

```bash
sudo python3 tools/send_ipc_test.py \
  --recipient test-recipient@example.net --kind deny
```

受理された場合の例：

```json
{
  "notification_id": "PHASE1-...",
  "status": "AcceptedBySmtp",
  "error_code": null
}
```

`AcceptedBySmtp` は Gmail の SMTP サーバーが受理したという意味であり、受信箱への配達保証ではない。受信箱・迷惑メールフォルダー・ヘッダー認証の結果も確認する。受信者の Gmail では「メッセージのソースを表示」などから SPF / DKIM / DMARC を確認できる。

## 11. 障害時確認

```bash
systemctl status teal-mailer.socket teal-mailer.service
journalctl -u teal-mailer.service -n 100 --no-pager
journalctl -u teal-mailer.socket -n 50 --no-pager
systemctl cat teal-mailer.service teal-mailer.socket
```

| 症状 | 重点確認 |
| --- | --- |
| ソケットがない | `teal-mailer.socket` の有効化と `/run/teal` のライフサイクル |
| `Permission denied` | ソケット0600、テストクライアント root、`SO_PEERCRED` |
| Credential 読み込みエラー | 2ファイルの存在、`--name`、復号可能性、`LoadCredentialEncrypted=` |
| JSON 読み込み失敗 | `/etc/teal.d/mailer.json` と非 root ユーザーの読取権限 |
| SMTP 認証エラー | Gmail アドレス全体、16文字のアプリパスワード、`smtp.from` |
| SMTP 接続失敗 | DNS、TCP 465、TLS 証明書、ファイアウォール、TEAL/TEAL-NET |
| メール不達 | `AcceptedBySmtp` と最終配達の差、受信側スパムフォルダー |
| `To:` が空 | 現行 `smtp.rs` が Bcc 専用（案Aは未反映） |

## 12. Phase 1 完了基準

- `cargo check` と `cargo test` が成功
- `.socket` が `active (listening)`
- IPC 接続で `.service` が自動起動
- systemd Credentials を非 root mailer が読み取り可能
- Gmail で SMTP 認証が成功
- `AcceptedBySmtp` の IPC 応答を受信
- 実験メールが受信でき、認証ヘッダーを確認可能

個別 To 方式（案A）を正式な受信表示として確認するには、後続の `smtp.rs` 改修が必要。複数受信者への個別送信と部分失敗の追跡はさらに設計が必要。

### 参考（公式資料）

- Google アプリ パスワード: https://support.google.com/accounts/answer/185833?hl=ja
- Gmail メール送信者のガイドライン: https://support.google.com/mail/answer/81126?hl=ja
- systemd Credentials: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- systemd-creds: https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html
- systemd Socket: https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html

