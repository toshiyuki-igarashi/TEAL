# TEAL Security Alert Notification 機能仕様案

## 1. 目的

TEAL に、ENFORCE モードで発生した DENY イベント、および AI が高い確度で攻撃を検出した場合に、指定されたロールの担当者へメールで通知する機能を追加する。

この機能の目的は、アクセス制御の結果や AI による分析結果を管理者へ伝え、必要な調査・対応を開始する契機を提供することである。

## 2. 通知の種類

通知は以下の2種類に分ける。

| 項目    | DENY 通知                     | AI 攻撃検出通知                 |
| ----- | --------------------------- | ------------------------- |
| 通知条件  | ENFORCE モードでアクションが DENY された | AI が高確度で攻撃と判定した           |
| 件名    | Action Denied               | Suspected Attack Detected |
| 目的    | 原因調査の開始                     | 攻撃への対応判断                  |
| 攻撃の判断 | 行わない                        | AI による判断                  |
| 通知先   | 指定されたロール                    | 指定されたロール                  |

### 2.1 DENY 通知

DENY イベントは、必ずしも攻撃を意味しない。

主な原因として次の3つが考えられる。

1. 人為的な操作ミス
2. ポリシールールの不具合
3. 攻撃による不正操作

DENY 通知では攻撃であるという判断を行わず、拒否された事実と調査の必要性を伝える。

### 2.2 AI 攻撃検出通知

既存の AI 解析機能によって、設定された閾値以上の確度で攻撃の疑いが検出された場合に通知する。

通知には、攻撃と判断した根拠、関連イベント、対象ホスト、操作内容などを含める。

AI 判定は DENY の有無とは独立しており、DENY されていない操作についても通知できる。

## 3. 通知アーキテクチャ（サービス分離）

```text
             TEAL Kernel / LSM
                  │
                  ▼
       teald.service（既存）
       ├─ DENY Event / AI Analysis
       ├─ Notification Manager
       │   ├─ 条件判定・DENY 集約
       │   └─ roles.json から宛先解決
       ├─ AI Queue   （128件）── IPC Sender (AI) ───┐
       └─ DENY Queue （896件）── IPC Sender (DENY) ─┤
                                                   │
            Unix Domain Socket（リクエスト/応答）     │
                                                   ▼
       teal-mailer.socket（systemd 管理）
                  │  Socket Activation
                  ▼
       teal-mailer.service（新規、非特権ユーザー）
       ├─ IPC Server
       ├─ AI Mail Worker   （独立レート制限）
       ├─ DENY Mail Worker （独立レート制限）
       ├─ systemd Credentials から SMTP 認証情報取得
       └─ SMTP Server → 指定ロールの担当者
```

- **teald は通知イベントの検出・評価・集約・宛先解決・送信待ちキューを担当する。SMTP パスワードにはアクセスしない。**
- **teal-mailer はメール整形・SMTP 送信と、AI/DENY 別の送信レート制限を担当する。** アクセス制御・ポリシー評価は実装しない。
- 既存仕様の通知待ちチャネル容量は **合計1024件（AI 128 / DENY 896）を teald 側に保持**する。teal-mailer に重複する大容量の待機キューは設けない。IPC 送信中の少数の案件は別途管理する。
- IPC にはローカル Unix Domain Socket を使用する。teald は送信結果の応答を受け取るまで、担当する送信中の通知を保持する。SMTP 側の「受理」と受信者への最終配送は異なる。
- teald.service から teal-mailer.service へ `Requires=` / `BindsTo=` を設定しない。サービス間の障害伝播を防ぐ。メール送信が失敗しても teald のアクセス制御は継続する。
- systemd Socket Activation を採用する場合、socket unit がリスニングソケットを確保し、接続時に mailer service を起動する。サービス側にはソケット引き継ぎ処理を実装する。
- IPC の接続、送信、応答待機は通知の独立タスクだけで行う。アクセス制御・監査ログ生成経路は待機しない。

## 4. DENY 通知の集約

大量の DENY が発生した場合、メールが大量に送信されることを防ぐため、通知を集約する。DENY の原因は人為的ミス、ルールの不具合、攻撃などがあり、集約自体は原因を判定しない。

### 4.1 基本方式

**初回の DENY は即時に通知キューへ投入し、以後の同種 DENY は5分（300秒）単位で集約する。** 「即時」は SMTP による即時配送を保証する意味ではなく、送信待ちキューへ速やかに投入することを意味する。

| 時刻 | 発生内容 | 通知処理 |
| --- | --- | --- |
| 10:00:00 | 最初の DENY | 即時キュー投入 |
| 10:00:05 | 同種 DENY | 集約 |
| 10:00:10 | 同種 DENY | 集約 |
| 10:01:00 | 別種 DENY | 即時キュー投入 |
| 10:05:00 | 同種 DENY が計120回 | 集約通知をキュー投入 |
| 10:10:00 | さらに300回発生 | 集約通知をキュー投入 |

集約期間中に新たな DENY がなければ、不要な定期通知は送らない。集約期間は最終イベント発生時刻で延長せず、最初の通知からの固定期間で管理する。

### 4.2 同種イベントの判定

集約キーは次の **7属性** とする。

1. Hostname
2. UID
3. Program
4. Action
5. Rule ID
6. **Target の親ディレクトリパス**（個別ファイル名はキーに含めない）
7. **Policy Epoch**（ポリシー変更前後を混在させない）

同一親ディレクトリ配下で多数のファイルが操作されても同一グループとしてまとめる。元の個別 Target パスは、**集約構造体内に最大10件のサンプル**を保持する。集約回数、最初／最後の発生時刻、代表 Event ID なども保持する。

ファイルパスでない Target（例：接続先）の正規化方法は、操作種別に応じて実装時に規定する。

### 4.3 集約グループ数の上限

- 同時に保持できる集約グループの上限は **1000件** とする。
- 上限を超えて新たなグループを追加する場合は、最古のグループを **teald 側の DENY 通知キューへ即時投入**し、そのグループを集約領域から除去する。
- キューが満杯で投入できない場合は処理元を待機させず、超過情報の集約・計数など9章の過負荷処理へ移す。通知データの保全方法と、集約領域の上限維持を両立させる。
- 1000グループの大量入れ替わりによるメール洪水を抑えるため、**DENY 側の送信レート上限**を適用する。

### 4.4 監査ログとの関係

TEAL では、すでに **ALLOW / DENY のすべての結果が監査ログに記録される**。今回の機能では監査ログを追加・変更しない。

通知の集約はメール送信量を制御する仕組みであり、個々のアクセス制御結果を記録する既存監査ログには影響させない。

## 5. 通知メールの内容

### 5.1 DENY 通知

件名：`[TEAL][DENY] Action Denied on server01`

```text
TEAL Security Notification

An action was denied by TEAL in ENFORCE mode.

Host: server01
Time: 2026-11-03 09:15:00 JST
Mode: ENFORCE
Event: ACCESS_DENIED

UID: 1000
PID: 12345
Program: /usr/bin/bash
Action: UNLINK
Target: /var/backups/database.sql

Rule ID: protect-backups
Policy Epoch: 42
Event ID: EVT-123456

Investigation Required

This notification does not indicate that
an attack has been detected.

The action may have been denied due to:
- An operational or human error.
- An incorrect policy rule.
- Potentially malicious activity.

Please review the associated audit logs.
```

### 5.2 集約 DENY 通知

件名：`[TEAL][DENY] Repeated Denied Actions on server01`

本文には以下を含める。

- 最初と最後の DENY 発生時刻、集約期間、DENY 発生回数
- Hostname、UID、Program、Action、Rule ID、**Policy Epoch、親ディレクトリパス**
- 個別 Target のサンプル（最大10件）
- 関連する監査ログを調査するための代表 Event ID など
- 集約グループ上限超過による早期通知である場合は、その旨

### 5.3 AI 攻撃検出通知

件名：`[TEAL][CRITICAL] Suspected Attack Detected on server01`

既存の `run_ai_analysis_worker()` から、**確度（`f64`）、判定根拠テキスト、関連 Event ID のリスト、対象ホスト、操作内容**を含む解析結果を受け取る。確度が設定した閾値以上の場合のみ通知する（初期仮値 `0.95`）。この確度は事前に検証・校正する必要がある。

AI による判定であり、攻撃が確定したという意味ではないことを明示する。該当する DENY があれば、**その Event ID を AI 通知本文にも列挙して関連付ける**。DENY 通知は取り消さず、両方の通知を送る。

## 6. 設定ファイル（責務ごとに分割）

他の TEAL 設定と同様に JSON を用いる。**通知生成に関する `notifications.json` は teald、SMTP の接続・送信に関する `mailer.json` は teal-mailer が読む。** 認証値そのものはどちらにも書かない。

### 6.1 `/etc/teal.d/notifications.json`（teald 用）

```json
{
  "version": "1.0",
  "enabled": true,
  "mode": "enforce",
  "deny": {
    "enabled": true,
    "recipient_roles": ["security_admin"],
    "aggregation": {
      "enabled": true,
      "window_sec": 300,
      "notify_immediately": true,
      "max_groups": 1000,
      "target_sample_limit": 10,
      "group_by": [
        "hostname", "uid", "program", "action", "rule_id",
        "target_parent_directory", "policy_epoch"
      ],
      "on_group_overflow": "enqueue_oldest"
    }
  },
  "ai": {
    "enabled": true,
    "min_confidence": 0.95,
    "recipient_roles": ["security_admin", "system_admin"]
  },
  "delivery": {
    "transport": "unix_socket",
    "socket_path": "/run/teal/teal-notify.sock",
    "queue": {
      "ai_capacity": 128,
      "deny_capacity": 896,
      "on_ai_full": "async_emergency_spool",
      "on_deny_full": "aggregate_overflow"
    },
    "ipc_timeout_sec": 30,
    "retry": {
      "max_attempts": 5,
      "initial_delay_sec": 10
    }
  }
}
```

### 6.2 `/etc/teal.d/mailer.json`（teal-mailer 用）

```json
{
  "version": "1.0",
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "from": "teal@example.com",
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

初期値として AI 10通/分、DENY 5通/分を例示する。実際の値は検証で調整する。構造・範囲・ロール参照・キュー合計・ソケットパスを検証する。SMTP 設定を変更した場合は mailer のみを再起動できるようにする。

### 6.3 SMTP 認証情報

- `smtp_user` および `smtp_password` は **systemd Encrypted Credentials** を標準とする。
- 暗号化ファイルは例として `/etc/credstore.encrypted/teal.smtp_user`、`/etc/credstore.encrypted/teal.smtp_password` に格納する。
- **LoadCredentialEncrypted は teal-mailer.service のみに指定する。teald.service には指定しない。**
- teal-mailer は `$CREDENTIALS_DIRECTORY/smtp_user` と `$CREDENTIALS_DIRECTORY/smtp_password` を取得する。いずれもログ出力しない。
- 復号失敗・認証情報欠落時は teal-mailer の起動が失敗することがあるが、teald は独立稼働する。通知停止を検知可能にし、保留・再送処理を実施する。
- systemd Credentials は保存中の保護とサービスへの受け渡しを提供するが、root 侵害に対する絶対的な秘匿性を保証しない。

## 7. ロール管理

既存の TEAL Roles v1.0 を利用して通知先を指定する。**MPA の承認権限と通知受信権限は分離する。**

`roles.json` の各ロール定義に通知先メールアドレスのリストを追加する。例（ロール定義の断片であり、実際の形式は既存スキーマに合わせる）：

```json
{
  "id": "security_admin",
  "notification_emails": [
    "admin1@example.com",
    "admin2@example.com"
  ]
}
```

`notifications.json` の `recipient_roles` はロール名を指定し、**TEAL の設定ロード／ポリシーコンパイル時に**ロール所属先のメールアドレスを解決する（Rust のビルド時ではない）。同じメールアドレスが複数ロールに重複する場合は重複送信を避ける。

ロール定義が更新された場合は、通知先のスナップショットも整合性を保って切り替える。

## 8. Rust 実装方針

実行バイナリを `teald` と **`teal-mailer`** に分離し、IPC メッセージの型だけを共有する小さなライブラリを設ける。

```text
teald/src/notification/
    mod.rs
    config.rs
    event.rs
    manager.rs
    aggregation.rs
    queue.rs
    ipc_client.rs
    recovery.rs

teal-mailer/src/
    main.rs
    config.rs
    credentials.rs
    ipc_server.rs
    ai_worker.rs
    deny_worker.rs
    smtp.rs

teal-notify-protocol/src/lib.rs
```

- **teald 側**：ENFORCE の `ACCESS_DENIED` と `run_ai_analysis_worker()` の高確度検出を通知イベントに変換。7属性で集約し、roles.json の通知先を解決し、通知種別に応じた固定長 `tokio::sync::mpsc::channel`（128/896）へ `try_send()` する。キューから取り出した通知を独立した IPC Sender タスクが送る。
- **共通プロトコル**：バージョン、notification_id、kind（AI/DENY）、宛先、イベント情報、ポリシー Epoch、関連 Event ID を持つ。リクエストサイズ・宛先数・フィールド長に上限を設ける。長さ付きフレーミングと `serde` を用いる。SMTP 認証情報は含めない。
- **teal-mailer 側**：systemd が引き継いだ Unix リスニングソケットから受信し、認証された teald からの IPC 要求のみ受付。通知種別で AI/DENY の独立 Worker に振り分け、それぞれの送信レートを守り、SMTP へ送信する。メール本文は受信した構造化データから生成し、機密情報やヘッダー注入を防ぐ。
- **応答方式**：IPC 応答は `AcceptedBySmtp`、`RetryableError`、`PermanentError` などを返す。SMTP 受理前に送信済み扱いにしない。通信断による結果不明時は重複送信があり得るため notification_id で識別する。
- **再送の責任**：同じ通知の再送制御は原則として teald 側 IPC Sender に集約する。mailer 側は1要求を所定レート内で送信して結果を返す。二重の再送ループは作らない。
- **送信中データ**：teald の IPC Sender はチャネルから受信済みのジョブを SMTP 応答が確定するまで保持し、再接続や再送に使用する。チャネル中1024件とは別の少数の in-flight ジョブを明示的に管理する。
- **Socket Activation**：`teal-mailer.socket` を配置し、`teal-mailer` で systemd から渡された listen fd を利用する。直接 `UnixListener::bind()` する処理とは異なるため、引き継ぎの実装・テストが必要。
- SMTP 送信ライブラリは `lettre` を候補とする。teald は SMTP 送信に依存しない。

### 8.1 モジュール分割の基本原則

- `teald` は「どの事象を誰に通知するか」を判断する。SMTP 接続・認証・メール本文の MIME 生成は行わない。
- `teal-mailer` は「受け取った通知をメールとして送る」ことだけを担当する。アクセス制御、DENY 集約、AI 再判定、ロール解決は行わない。
- `teal-notify-protocol` は両プロセスが参照する通知データと IPC メッセージの型・形式を定義する。どちらの実行バイナリにも依存しない。
- 通知生成元（カーネル応答・監査イベント処理・AI 解析処理）は、IPC、SMTP、ファイル I/O の完了を待たない。通知送信と復旧処理は独立したタスクに限定する。
- 以下の関数名・構造体名は**実装インターフェースの設計例**であり、既存の `teald` の型・所有権・エラー設計に合わせて最終決定する。

### 8.2 `teald/src/notification/` — ファイル別機能

#### `mod.rs` — 通知サブシステムの初期化・統括

**責務：** 通知機能のエントリーポイントとライフサイクルを管理する。

- 通知モジュールの公開、および設定・通知先スナップショットの受け取り。
- Notification Manager、AI/DENY それぞれの固定長チャネル、独立した IPC Sender タスクの初期化。
- 既存の DENY イベント処理と `run_ai_analysis_worker()` から利用できる `NotificationHandle` の提供。
- 正常停止時の新規受付停止、送信中ジョブの整理、未送信データと集約状態の保存。
- 通知機能の初期化失敗を記録しつつ、アクセス制御本体を停止させない障害分離。

**主要 API（例）：** `init(config, roles_snapshot) -> Result<NotificationHandle, NotificationError>`、`shutdown(handle) -> Result<(), NotificationError>`。

#### `config.rs` — `notifications.json` の読み込み・検証

**責務：** `teald` が必要とする通知生成・集約・配送経路の設定を管理する。

- JSON のデシリアライズ、設定バージョンと構造の検証。
- ENFORCE モード条件、DENY 集約窓・上限・Target サンプル数、AI 確度閾値の検証。
- AI 128件／DENY 896件（合計1024件）のキュー設定、IPC ソケットパス、タイムアウト、再送設定の検証。
- `recipient_roles` と Roles v1.0 のロール定義の照合、ロール更新時のスナップショット整合性の管理。
- SMTP ホスト・ポート・Credential の値は扱わない（`teal-mailer/config.rs` の責務）。

**主要型（例）：** `NotificationConfig`、`DenyNotificationConfig`、`AiNotificationConfig`、`QueueConfig`、`IpcConfig`。

#### `event.rs` — 通知元イベントの整形

**責務：** 既存の監査／解析イベントを通知向けの内部データに変換する。

- ENFORCE で実際に拒否された `ACCESS_DENIED` イベントから必要情報を抽出する。
- AI 解析結果から `f64` 確度、根拠、関連 Event ID、対象ホスト、操作内容を抽出する。
- Event ID、Notification ID、発生時刻、Policy Epoch、操作対象などの保持。
- 既存の監査ログを再生成せず、既存ログと照合できる識別情報を維持する。
- 通知メールに載せる情報が過度に機密性を持たないよう、サイズ制限や表示対象の選別に必要な正規化を行う。

**主要型（例）：** `NotificationEvent::{Deny, Ai}`、`DenyNotificationEvent`、`AiNotificationEvent`。

#### `manager.rs` — 通知条件の判定・ロール解決・振り分け

**責務：** 通知の要否を決め、他モジュールへ処理を指示する中心コンポーネント。

- `enabled` と ENFORCE モード条件を確認する。
- DENY 通知は攻撃判定を行わず、`aggregation.rs` に渡す。
- AI 通知は閾値以上の解析結果だけを対象とする（閾値の初期仮値0.95）。
- Roles v1.0 の通知先リストから宛先メールアドレスを解決し、重複宛先を除去する。
- DENY 初回通知・集約通知を DENY キューに、AI 通知を AI キューに振り分ける。
- キュー満杯時に `queue.rs` / `recovery.rs` の過負荷処理を呼び出す。

**主要 API（例）：** `submit_deny(event)`、`submit_ai(event)`。いずれも通知生成元で IPC・SMTP・ディスク I/O を待たない。

#### `aggregation.rs` — DENY の時間窓集約とグループ管理

**責務：** 大量 DENY を調査に役立つ単位でまとめ、通知件数を削減する。

- 7属性（Hostname、UID、Program、Action、Rule ID、Target の親ディレクトリ、Policy Epoch）から `AggregationKey` を作成する。
- 各グループの回数、最初／最後の発生時刻、代表 Event ID、個別 Target サンプル最大10件を保持する。
- 最初の DENY は即時通知キューへ投入する対象として返し、以降は初回基準の固定300秒窓で集約する。
- 時間窓満了時には新規イベントの有無を確認し、必要な集約通知だけを生成する。
- 1000グループ超過時は最古グループを排出対象として返す。キュー満杯なら有界な超過情報として処理する。
- ファイル以外の Target の集約キー正規化は操作種別ごとに定める。

**主要型／API（例）：** `AggregationKey`、`DenyAggregate`、`add_event(event) -> Vec<DenyNotification>`、`flush_expired() -> Vec<DenyNotification>`。**SMTP・IPC 処理は行わない。**

#### `queue.rs` — 固定長通知チャネルと過負荷制御

**責務：** 通知生成経路から通信・配送処理を切り離す。

- `tokio::sync::mpsc::channel` を AI 128件、DENY 896件で用意する（合計1024件）。
- 通知生成側は `try_send()` によって投入し、満杯でも待機しない。
- DENY キュー満杯時は有界な超過件数・概要を計上し、後続の通知へ反映する。
- AI キュー満杯時は、非ブロッキングの有界な緊急退避要求を `recovery.rs` に委譲する。
- キュー投入失敗・滞留・退避失敗などを診断情報として計測する。
- チャネルから取り出された *in-flight* ジョブは1024件の待機容量に含まれないため、その同時件数にも別途上限を設ける。

**主要 API（例）：** `try_enqueue_ai(notification) -> EnqueueResult`、`try_enqueue_deny(notification) -> EnqueueResult`。

#### `ipc_client.rs` — Unix Domain Socket 通信と再送

**責務：** `teal-mailer` への配送要求と応答管理を担当する。

- `/run/teal/teal-notify.sock` への接続、再接続、送受信、タイムアウト、長さ付きフレーム処理。
- AI/DENY ごとに独立した IPC Sender タスクを動かし、一方の送信待ちが他方を塞がないようにする。
- プロトコルバージョン、通知 ID、配送応答の対応付けを確認する。
- `AcceptedBySmtp` を受け取って初めて送信成功とする。`RetryableError` と通信結果不明時は再送方針に従う。
- `PermanentError` は無制限に再送せず、原因・通知 ID を記録する。
- 通知をチャネルから取り出した後も、応答が確定するまで保持する。SMTP 再送の制御は原則として **teald 側に一本化**する。

**主要 API（例）：** `send_notification(&NotificationRequest) -> Result<DeliveryResponse, IpcError>`。通信中の待機は独立した送信タスク内に限定する。

#### `recovery.rs` — 未送信通知の保存・復旧

**責務：** 正常終了時と一部の過負荷時に、通知データの回復可能性を確保する。

- 正常シャットダウン時に AI/DENY の待機通知、未確定 *in-flight* ジョブ、集約中データを保存する。
- 起動時に保存データを検証して復元し、通知 ID を保ったまま再送・集約を再開する。
- AI キュー満杯時の有界な非同期緊急退避と、退避済み通知の回収を担う。
- 保存先（`/var/lib/teal/notifications/`）の権限・容量・保持期間を制御する。
- 一時ファイルからのアトミックな置換などを用い、部分書き込み・破損を検出する。
- 異常終了・電源断時のオンメモリ通知消失や、通信結果不明時の重複送信は v1.0 の既知の制約として扱う。

**主要 API（例）：** `save_pending(&PendingNotificationState)`、`restore_pending() -> PendingNotificationState`、`spool_ai(notification)`。

### 8.3 `teal-mailer/src/` — ファイル別機能

#### `main.rs` — サービス起動・終了処理

**責務：** 独立した `teal-mailer` プロセス全体を起動・監督する。

- `mailer.json` の読み込み・検証、systemd Credentials からの SMTP 認証情報取得。
- SMTP クライアント、AI/DENY Mail Worker、IPC Server の初期化。
- `teal-mailer.socket` の Socket Activation で引き継がれるリスニング fd を利用する。
- サービス停止シグナル、エラー報告、正常終了処理を担当する。
- Credential 復号・読み込みに失敗した場合は mailer の起動を失敗させるが、`teald.service` の起動・アクセス制御とは独立させる。

#### `config.rs` — `mailer.json` の読み込み・検証

**責務：** メール配送に固有の設定を管理する。

- SMTP ホスト、ポート、送信元アドレス、TLS 要件、認証用 Credential 名の検証。
- AI 10通/分、DENY 5通/分（いずれも初期仮値）の独立したレート制限設定を管理する。
- SMTP 接続・送信のタイムアウトやエラー分類に必要なパラメータを保持する。
- 認証情報の実値と TEAL のロール・ポリシー設定は管理しない。

**主要型（例）：** `MailerConfig`、`SmtpConfig`、`RateLimitConfig`。

#### `credentials.rs` — systemd Credentials からの認証情報取得

**責務：** SMTP 認証に必要なユーザー名とパスワードを安全に読み取る。

- `$CREDENTIALS_DIRECTORY/smtp_user`、`$CREDENTIALS_DIRECTORY/smtp_password` を読み取る。
- 設定された Credential 名の検証と、読込失敗・値欠落の検出。
- ログ・`Debug` 出力へのパスワード露出を防ぐ保護型の利用（例：`SecretString`）。
- Credential の復号は systemd の責務とし、本モジュールに独自の暗号処理を実装しない。

**主要型／API（例）：** `SmtpCredentials`、`load_credentials() -> Result<SmtpCredentials, CredentialError>`。

#### `ipc_server.rs` — IPC 受付・検証・振り分け

**責務：** `teald` からの通知だけを安全に受け付け、送信結果を返す。

- systemd から引き継いだ Unix リスニングソケットで接続を受け付ける。
- Socket の権限に加え、`SO_PEERCRED` 等で接続元を確認する。
- 長さ付きフレーミング、最大メッセージ長、プロトコルバージョン、フィールド長、宛先数を検証する。
- `NotificationPayload::{Ai, Deny}` に応じて専用 Worker に振り分ける。
- 無制限の接続／保留要求を作らず、AI/DENY の独立性と同時処理件数上限を保つ。
- SMTP の受理またはエラー結果を、元の通知 ID とともに IPC 応答として返す。

**主要 API（例）：** `handle_request(request) -> DeliveryResponse`。

#### `ai_worker.rs` — AI 通知のメール生成・レート制御

**責務：** AI 解析結果を、攻撃の疑いを伝えるメールとして送信する。

- AI 通知の本文・件名（例：`Suspected Attack Detected`）を生成する。
- 確度、判定根拠、関連 Event ID、対象ホスト・操作を表示する。
- AI 専用の送信レート上限を適用し、DENY Worker による待ち行列とは独立して動作する。
- `smtp.rs` へメール送信を依頼し、SMTP 応答を IPC 側に返す。
- AI の攻撃判定や閾値判定を再実行しない。

**主要 API（例）：** `process_ai_notification(notification) -> DeliveryResult`。

#### `deny_worker.rs` — DENY 通知のメール生成・レート制御

**責務：** 操作拒否の事実を伝え、原因調査を促すメールを送信する。

- 初回 DENY と集約 DENY の件名・本文を生成する。
- 発生回数、集約期間、Target サンプル最大10件、Policy Epoch、代表 Event ID を表示する。
- 集約上限超過による早期排出であればその旨を明記する。
- DENY 専用の送信レート上限を適用し、`smtp.rs` で送信して結果を返す。
- 攻撃と断定せず、人為的ミス・ポリシー不備・不正操作の可能性を調査対象として示す。
- DENY のグループ集約処理は行わない（`teald/notification/aggregation.rs` が担当）。

**主要 API（例）：** `process_deny_notification(notification) -> DeliveryResult`。

#### `smtp.rs` — SMTP プロトコルと送信結果

**責務：** Mail Worker から共通利用される SMTP 送信機能を提供する。

- SMTP 接続、TLS とサーバー証明書の検証、SMTP AUTH、メール送信を行う。
- `lettre` 等を利用してメールヘッダー・本文を正しく生成／送出する。
- タイムアウト、SMTP 応答コード、暫定的な送信失敗と恒久的な送信失敗を区別する。
- メール本文・宛先に含まれる外部由来データのサイズと形式を検証し、ヘッダー注入や機密漏洩を抑止する。
- AI/DENY Worker から共通利用するが、Worker ごとのレート制限は `ai_worker.rs` と `deny_worker.rs` に置く。
- **送信成功は SMTP サーバーによる受理**を意味し、受信者のメールボックスへの最終配送を保証しない。

**主要 API（例）：** `send(message) -> Result<SmtpAcceptance, SmtpError>`。

### 8.4 `teal-notify-protocol/src/lib.rs` — 共通 IPC プロトコル

**責務：** 両プロセス間のデータ契約を唯一の場所で定義する。

- `PROTOCOL_VERSION` と互換性検証ルールを定義する。
- `NotificationRequest`、`NotificationPayload::{Ai, Deny}`、`AiNotification`、`DenyNotification` を定義する。
- 通知 ID、送信先リスト、発生時刻、関連 Event ID、DENY の Policy Epoch・集約情報、AI の確度・根拠を扱う。
- `DeliveryResponse` と配送状態 `AcceptedBySmtp` / `RetryableError` / `PermanentError` を定義する。
- `serde` を使ったシリアライズ・デシリアライズと、長さ付きフレーミングの形式・最大サイズを規定する。
- リクエスト内に SMTP 認証情報を含めない。またファイル I/O、ソケット接続、メール送信は実装しない。

型構成の概念例（詳細フィールドは各通知データ型に定義する）：

```rust
pub const PROTOCOL_VERSION: u16 = 1;

pub enum NotificationPayload {
    Ai(AiNotification),
    Deny(DenyNotification),
}

pub struct NotificationRequest {
    pub version: u16,
    pub notification_id: String,
    pub recipients: Vec<String>,
    pub payload: NotificationPayload,
}

pub enum DeliveryStatus {
    AcceptedBySmtp,
    RetryableError,
    PermanentError,
}

pub struct DeliveryResponse {
    pub notification_id: String,
    pub status: DeliveryStatus,
    pub error_code: Option<String>,
}
```

実装時は各型に必要な `serde::{Serialize, Deserialize}` 等を付与し、メッセージ数・フィールド長の制限も検証する。

### 8.5 IPC 配送の状態遷移と責任範囲

1. `teald` の Notification Manager が通知 ID と宛先を確定し、通知種別ごとの固定長キューへ投入する。
2. `teald` の IPC Sender がキューから取得したジョブを *in-flight* として保持し、Unix Domain Socket で送信する。
3. `teal-mailer` が要求を検証し、該当 Worker がレート制限に従って SMTP 送信する。**IPC で受信した時点では送信済みにしない。**
4. SMTP サーバーが受理すると `AcceptedBySmtp` を返す。`teald` は応答を確認して送信完了とする。
5. 一時失敗は `RetryableError` として返し、再送制御は `teald` の IPC Sender に一本化する。恒久失敗は `PermanentError` とし、無限再送を避ける。
6. SMTP 受理後に IPC が切断されると結果不明になり、再送により重複メールが発生し得る。`notification_id` により追跡するが、v1.0 は厳密な一回限りの配送を保証しない。

IPC Sender が SMTP 応答を待っても、待機するのは通知用の独立タスクだけであり、カーネルへの応答や AI 解析の実行を待たせない。AI/DENY は別々の IPC Sender・Worker・送信レートを持つ。ただし同じ SMTP サーバーの共通障害や全体制限までは分離できない。

### 8.6 モジュール間の依存と実装順序

```text
teald/notification/mod.rs
    ├── config.rs
    ├── event.rs ──> manager.rs ──> aggregation.rs
    │                      └──────> queue.rs
    ├── ipc_client.rs ────────────> teal-notify-protocol
    └── recovery.rs

teal-mailer/main.rs
    ├── config.rs
    ├── credentials.rs
    ├── ipc_server.rs ────────────> teal-notify-protocol
    ├── ai_worker.rs ──────┐
    └── deny_worker.rs ────┴──────> smtp.rs
```

依存方向は `teal-notify-protocol` を共通の下位クレートとし、`teald` と `teal-mailer` の間に直接の Rust クレート依存を作らない。実装・テストの順序は第10章の Phase 1〜5に従う。

## 9. 信頼性とセキュリティ

### 9.1 レート制限・優先度

- teal-mailer 内で AI / DENY それぞれ独立した Mail Worker と送信レート上限を持たせる（初期仮値は AI 10通/分、DENY 5通/分）。
- teald 側の固定長通知チャネルは合計1024件（AI 128 / DENY 896）。**teal-mailer には同規模の重複キューを置かない。** 送信中要求とソケット接続数の上限を別に定義する。
- AI の送信処理が DENY の大量発生に塞がれないよう、両種の IPC Sender と Mail Worker を独立させる。SMTP 共有の停止・全体接続制限には影響され得る。

### 9.2 キュー満杯・mailer 停止・IPC 障害

| 状況 | 対処 |
| --- | --- |
| teald の DENY キュー満杯 | 個別メール追加を止め、有界な超過件数集約で後続通知に反映。監査ログは通常どおり。 |
| teald の AI キュー満杯 | 別の有界な非同期退避処理に渡し、権限を制限したローカルファイルへ退避を試みる。失敗を記録する。 |
| 集約グループ1000件超過 | 最古グループを DENY キューへ非ブロッキング投入。満杯なら超過計数へ移し、集約状態の上限を維持する。 |
| teal-mailer 停止・資格情報復号失敗 | teald は動作継続。IPC Sender が接続失敗/タイムアウトを検出して有界なバックオフと再送を行う。 |
| SMTP 遅延・停止 | mailer は結果を返す／タイムアウト。teald は未確定通知を保持して再試行し、キューが満杯になれば上記動作へ移行する。 |
| IPC 応答不明 | SMTP が受理済みの可能性があり、再送による重複が起こり得る。notification_id を保持する。 |

- イベント生成側で IPC 接続、ファイル書き込み、SMTP 応答待ちをしてはいけない。`try_send()` のみを使用する。
- AI 退避処理の入口も固定長とする。ファイル I/O 失敗・ディスク満杯・異常終了時の損失は既知の制約とする。
- 送信レート制限はキュー満杯を防ぐ保証にはならない。キューあふれを計測・診断できるようにする。

### 9.3 正常終了・再起動

- teald は正常シャットダウン時に AI/DENY 待機キュー、IPC 送信中の未確定ジョブ、集約中データをローカルファイルへ保存し、再起動時に復元する。
- mailer の正常停止は teald を停止しない。送信途中の SMTP 応答が不明な場合は再試行で重複メールがあり得る。
- teald 自身の異常終了・電源断ではメモリ上の未送信通知が失われる可能性がある。これは v1.0 の既知の制約。
- 保存・退避ファイルのアクセス権限、容量、保持期間、部分書き込み検出などを規定する。

### 9.4 IPC とサービスの保護

- 通知用 Unix Domain Socket のパスは、`teal_common/src/lib.rs` に `TEAL_NOTIFY_SOCKET_PATH` として定義する。値は `/run/teal/teal-notify.sock` とする。`teald` および `teal-mailer` はこの共通定数を参照する。ソケットの生成と管理は `teal-mailer.socket` が担当する。
- サーバーは可能なら `SO_PEERCRED` で送信元の UID/PID を確認する。ソケット権限だけでなく、接続元を検証する。
- mailer は最小権限ユーザーで動作し、systemd の sandboxing を利用する。mailer には TEAL のポリシーやデバイスを変更する権限を与えない。
- `LoadCredentialEncrypted=` は mailer にのみ設定する。復号失敗で mailer が失敗しても teald は停止しない。
- root 侵害時の秘密漏洩や偽通知に対する保護の限界を認識し、必要に応じ TEAL の LSM ポリシーで mailer・ソケット・Credentials のアクセスを制御する。
- 既存監査ログ（ALLOW / DENY 全件）への追加・変更は不要。

### 9.5 systemd unit の例

`/etc/systemd/system/teal-mailer.socket`：

```ini
[Unit]
Description=TEAL notification mailer socket

[Socket]
ListenStream=/run/teal/teal-notify.sock
SocketMode=0600
DirectoryMode=0755
Accept=no

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/teal-mailer.service`：

```ini
[Unit]
Description=TEAL notification mailer

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

- ソケット起動に対応する mailer 実装が必要。`User=teal-mailer` 用のシステムユーザーは別途用意する。サービスへの `Requires=teald.service` やその逆向きの依存は設けない。
- 有効化は `systemctl daemon-reload` と `systemctl enable --now teal-mailer.socket` を例とする。mailer.service はソケット要求で起動する。

## 10. 実装順序

| 段階 | 内容 |
| --- | --- |
| Phase 1 | `teal-notify-protocol` と `teal-mailer` を追加。Unix IPC と SMTP 認証情報読み込み、メール単発送信、mailer.socket/service の起動テスト |
| Phase 2 | teald 側 Notification Manager・固定長 AI/DENY キュー・IPC Sender を追加し、`ACCESS_DENIED` の初回通知を実装 |
| Phase 3 | 7属性（Policy Epoch 含む）の5分集約、Target 最大10件、集約グループ上限1000件・追い出し処理を実装 |
| Phase 4 | AI の高確度検出通知、関連 DENY Event ID、AI/DENY 独立 Mail Worker およびレート制限を実装 |
| Phase 5 | キュー満杯、mailer 起動失敗、Credential 復号失敗、SMTP 停止、再送・退避・正常再起動・障害切り分けをテスト |

## 11. 詳細設計・検証事項

既存基本仕様（2種類の通知、7属性での集約、Target 最大10件、集約上限1000、Roles v1.0 に通知先を追加、AI 閾値0.95仮値、合計1024件、AI/DENY 独立レート）は維持する。

実装時の検証事項：

- Unix Stream のフレーミング（長さ制限、プロトコル版）、接続元認証、IPC タイムアウトおよび同時接続数の上限。
- メール送信成否を通知済みとみなす時点（SMTP 受理応答）、`notification_id`、再送時の重複許容と記録。
- システム再起動・teald 再起動時に保留中の通知を復元できること。未確定 in-flight の保存。
- SMTP の全体レート上限や同時接続枠が AI と DENY の独立性に与える影響。
- mailer.socket が生きている一方、Credentials 復号失敗で mailer.service が起動できない場合にも teald が正常動作すること。
- `teald` が非 root 実行される構成での Unix Socket 権限設定。
- 非ファイル Target 正規化、古い集約グループの選択、DENY 超過情報、AI 緊急退避容量。
- AI `confidence` の校正・0.95 閾値の妥当性。

## 12. 設計方針のまとめ

TEAL Security Alert Notification は、アクセス制御や AI 解析とは独立した通知機能として実装する。

1. **DENY は調査開始のトリガー。** ポリシーにより操作が拒否された事実を通知し、攻撃であるという判断は行わない。
2. **AI 高確度判定はセキュリティ対応のトリガー。** 攻撃の疑いと判断根拠を通知する。関連する DENY があれば Event ID で関連付け、両方送信する。
3. **DENY は初回即時通知・5分集約。** 集約キーは Hostname、UID、Program、Action、Rule ID、Target 親ディレクトリ、Policy Epoch。Target サンプル最大10件、グループ上限1000件とする。
4. **AI/DENY は teald 側の独立キューと、teal-mailer 側の独立 Mail Worker を使う。** 容量合計1024件、Unix Domain Socket 経由で送信し、各系統に送信レート制限を適用する。
5. **満杯時もイベント生成元を待機させない。** DENY は超過件数を集約し、AI は非同期緊急退避を試みる。正常終了時には未送信・送信中・集約データを teald が保存し、再起動時に再開する。
6. **既存の監査ログを維持する。** ALLOW / DENY の全記録は既存機能を利用する。
7. **SMTP 資格情報と送信障害を teald から分離する。** `teal-mailer.service` だけが systemd Credentials を読み、SMTP の起動失敗でアクセス制御を停止させない。

実装ブランチ名は `feature/security-alert-notification` とする。

