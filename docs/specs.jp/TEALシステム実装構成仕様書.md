# TEAL システム実装構成仕様書

---

## 1. システム概要

本システムは、Linuxカーネル空間とユーザー空間が連携し、特権操作や重要データへのアクセスに対して「MPA（Multi-Party Authorization）」および「ゼロトラスト制御」を強制するセキュリティ機構である。

### 構成コンポーネント

システムは以下の3つの機能モジュールで構成される。

| コンポーネント | 動作領域 | 役割 |
| --- | --- | --- |
| **teal_lsm** | Kernel | **【センサー】** LSM (Linux Security Module) フックを使用し、システムコールやファイルアクセスを捕捉する。 |
| **teal_module** | Kernel | **【通信・制御】** ユーザー空間との通信管理、プロセスの一時停止・再開制御、および**プロセスのクレデンシャル（`cred`）に基づく高速キャッシュ判定（Fast Path）**を担当する。 |
| **teald** | User | **【頭脳・判定】** ポリシー管理、外部認証システムとの連携、承認者への通知、最終的な許可/拒否の判定を行うデーモン。 |


### 1.1 真のDefault-Deny（プロセスベース実行制御）

本システムは、監視対象のファイルリスト（ターゲットリスト）に依存しない。特定のファイルのみを監視した場合、攻撃者がリスト外のテンポラリファイルを用いてペイロードを展開する「安全地帯」を生むためである。
本システムが Default-Deny とするのは「ファイルへのアクセス」ではなく、「承認されていないプロセスによるあらゆる自律的アクション」である。事前に `teald` から権限を付与されていないプロセスは、対象が重要ファイルであろうと無名ファイルであろうと、実行および特定のI/O操作がデフォルトでブロックされる。

---

## 2. 動作モード定義

システムは以下の2つのモードを有し、動的に切り替え可能とする。

1. **AUDITモード（学習・監視フェーズ）**
    * すべての動作を許可する。
    * ポリシー違反や監視対象の動作はログとして出力する。
    * **特徴:** システムのパフォーマンスに影響を与えないよう、ノンブロッキング（非同期）で動作する。


2. **ENFORCEモード（防御フェーズ）**
    * ポリシーに基づき、動作を厳格に制御する。
    * **特徴:** 承認済み動作は「高速パス」で処理し、未承認の重要動作のみを「承認待ち（ブロッキング）」にするハイブリッド構造。

### 2.1 AUDITモードにおけるログストーム対策（動的Fast Path）

AUDITモードはすべての操作を許可するが、大量のI/Oを行うプロセス（コンパイラ等）によるカーネル・ユーザー間の通信バッファ（Netlink等）のオーバーフローを防ぐため、以下の制御を行う。

* `teald` は、AUDITモードであっても既知の高負荷プロセス（例：`make`, `gcc`）からの初回 `REQ` に対して、明示的に `SILENT_IO` および `INHERIT` フラグを付与したチケットを発行する。
* これにより、当該プロセスおよびその子プロセスが生成する無数のテンポラリファイルへのI/Oログはカーネル内でスキップ（Fast Path）され、通信量を劇的に削減しつつ、大枠のプロファイリングに必要なプロセス起動ログのみを安全に収集する。


### 補足： AUDIT→ENFORCE 移行時の一時状態の取り扱い

`START` により AUDIT から ENFORCE へ移行する際、teald は **移行前に存在した一時状態**が ENFORCE 下の動作へ影響することを防ぐため、以下を実施する。

1. teald が保持する **承認待ち状態（Pending）、Draft、未処理要求リスト等の一時状態を全て破棄**する。
2. 破棄対象には、承認途中の管理操作（例：START Pending）および Pre-Approval Draft を含む。
3. 移行後に必要な操作は、ENFORCE 下で改めて要求・承認を行う。

---

## 3. 詳細動作フロー

### 3.1 ENFORCEモード（防御時）

**目的:** 既知の許可済み動作は遅延なく通し、未知・重要操作のみ人間承認（MPA）を強制する。

1. **HOOK (teal_lsm)**
    * 対象のシステム動作をフックする。


2. **FAST PATH CHECK (teal_check_ticket_match)**
    * カーネル内のチケットキャッシュを確認する。
    * **【Hit】有効なチケットがある場合:**
        * uses_left を減算する。
    * **消費完了判定 (`uses_left == 0`):**
        * 当該チケットを「無効（Invalid）」状態にマークし、再利用を即座に防ぐ。
        * ユーザー空間へ **`INFO:CONSUMED` メッセージ** を発行（キューイング）する。
        * *※メモリ解放はメッセージ送信完了後、またはRCUにより安全に行う。*


        * 即座に `return 0` (許可) を返す。


    * **【Miss】チケットがない場合:**
        * ステップ3 (Slow Path) へ進む。




3. **REQUEST QUEUING (teal_module)**
    * 動作リクエスト（プロセスID, 操作内容, 対象ファイル等）を作成し、リストに登録する。
    * 該当プロセスを `wait_event_interruptible` 状態にし、CPUを解放してスリープさせる。


4. **JUDGEMENT (teald)**
    * カーネルからのイベントを検知し、リクエストを読み出す。
    * ポリシー判定を行う（Need Approval / Deny / Auto Allow）。


5. **RESPONSE (teald → teal_module)**
    * 判定結果をカーネルへ書き込む。
    * *※承認(Allow)の場合は、今後のためにカーネル内の「AllowList」にチケットを登録する。*


6. **UNBLOCK (teal_module → teal_lsm)**
    * スリープしていたプロセスを起床（Wake up）させる。
    * 判定結果に基づきリターンコードを返す（0 または -EACCES）。



### 3.2 AUDITモード（監視時）

**目的:** システムを止めずにログを収集する。

1. **HOOK (teal_lsm)**
    * システム動作をフックする。


2. **ASYNC LOGGING (teal_module)**
    * 動作情報をリングバッファまたはNetlinkソケット等の非同期キューに投入する。
    * teald の応答を**待たずに**、即座に `return 0` (許可) を返す。


3. **COLLECT (teald)**
    * ユーザー空間の都合の良いタイミングでキューからログを回収し、記録する。


### 3.3 Fail-Safe モード（teald 停止・応答不能時）

**目的:** 攻撃による `teald` の無効化（DoSや強制終了）を防ぎ、制御不能な状態での操作を許さない（Fail-Safe）。

カーネルモジュール（teal_module）は、`teald` との通信途絶（UDS切断または応答タイムアウト）を検知した瞬間、システムを自動的に **Fail-Safe モード** へ移行させる。本モード下の挙動は以下の通り定義する。

1. **Slow Path (新規承認要求) の即時遮断 (Default Deny)**
    * 承認待ちキュー（Pending Queue）に入っているリクエストは全て破棄し、呼び出し元プロセスへ `EACCES` (Permission Denied) を返す。
    * 新規に発生した承認が必要な操作（`open`, `execve` 等）に対しても、`teald` への問い合わせを行わず、即座に `EACCES` を返す。
    * これにより、攻撃者が「承認サーバをダウンさせてセキュリティを回避する」攻撃を無効化する。


2. **Fast Path (キャッシュ) の取り扱い**
    * **有効期限内のチケット:** カーネルメモリ内に残存する有効なチケットによる操作は許可する（業務継続性のため）。ただし、セキュリティレベル設定（Strict Mode）によっては、これらも一括無効化するオプションを用意する。
    * **期限切れ:** 更新（Refresh）ができないため、期限が切れた時点で即座に Deny となる。


3. **ネットワーク封鎖 (Network Lockdown)**
    * TEAL-NET 機能により、ホワイトリスト（静的許可リスト）に定義された「管理用通信（例: 監視サーバへのHeartbeat、緊急用コンソール接続）」以外の **全ての Outbound 通信を遮断** する。
    * これにより、データ搾取（Exfiltration）および C2 通信を物理的に近い状態で阻止する。


4. **警告と復旧 (Alert & Recovery)**
    * **ログ出力:** カーネルリングバッファ (`dmesg`) に `[TEAL] CRITICAL: Daemon lost. Entering Fail-Safe Mode.` を出力する。
    * **復旧手順:** 管理者が物理コンソール（またはBMC/iDRAC）経由でログインし、原因調査後に `teald` を再起動する。
    * カーネルは `teald` の再接続を検知した時点で、自動的に **ENFORCE モード** へ復帰する。
    * **Deadman Switch (Optional):** ハードウェアウォッチドッグ連携が有効な場合、`teald` からの Heartbeat 途絶が指定秒数（例: 10秒）継続した時点で、カーネルパニックまたはハードウェアリセットを誘発し、物理的にシステムを停止させる。



---

## 4. 高速パス（チケットキャッシュ）仕様

TEAL は性能と可用性のため、カーネル内に **「承認済みトークン（Ticket）」の検証済みキャッシュ**を保持し、ホットパスの判定を **ミリ秒未満**で完結させる。
システムパフォーマンスの低下を防ぐため、`teald` が許可した操作はカーネル内でキャッシュ（チケット）として管理され、2回目以降の同一操作、または許可されたプロセスによる後続操作はIPC通信をバイパスする（Fast Path）。

### 4.1 チケットの種別とデータ構造

本バージョンより、チケットは対象の性質に応じて以下の2種類を定義し、カーネル内で使い分ける。

1. **客体バインディング型**
    * **用途:** 特定の既存ファイルやディレクトリに対するアクセス許可。
    * **必須識別子:** `object_id` (Device ID + Inode number)
    * **挙動:** 対象となる特定のInodeに対するアクセス時のみFast Pathが適用される。
2. **主体（プロセス）コンテキスト型**
    * **用途:** コンパイラやバッチ処理など、大量のテンポラリファイルや無名ファイルを生成する信頼されたプロセスのI/O許可。
    * **必須識別子:** `subject_id` (PID または Credential ID) ※`object_id` は不要（`0:0` などのAny扱いとする）。
    * **挙動:** このチケットを保持するプロセス（主体）が行う操作は、対象ファイル（客体）が何であれFast Pathが適用される。

### 4.2 プロセス・コンテキストによる判定と継承メカニズム

#### 4.2.1 cred へのチケット格納

主体コンテキスト型のチケットは、グローバルなリストではなく、各プロセスのクレデンシャル構造体（`struct cred->security`）内で管理される。`teal_module` はファイルアクセス要求が発生した際、対象のファイル名やパスを評価する前に、まず実行元プロセスの `cred` を評価し、有効なチケットを保持しているかを確認する。

#### 4.2.2 無名ファイルとJITコンパイラ等のメモリ内実行への対応

パス名を持たない一時ファイル（`O_TMPFILE`）やメモリ内ファイル（`memfd_create`）へのアクセス時においても、プロセス（主体）の権限を評価する。

* **メモリ内実行のきめ細かな制御:** Node.jsやJava等の正規のJITコンパイラに対しては、ポリシーにより事前の実行許可チケットを付与することで、正規のファイルレス実行を阻害しない。
* 一方、有効なチケットを持たないプロセス（例：乗っ取られた `nginx`）による未知の `memfd_create` および実行要求は、ポリシーのコンテキスト外とみなされ、即座にフックされ STOPバリア の対象となる。

#### 4.2.3 チケットの継承 (Ticket Inheritance)

`INHERIT` フラグを持つチケットが付与されたプロセス（例：信頼されたビルドプロセス `make` など）が新しいプロセスを生成した場合、LSMフック（`cred_prepare` 等）を介して、親のチケット情報が子プロセスの `cred` へ安全にコピー（継承）される。これにより、子プロセスが生成する大量の一時ファイルについてもIPC通信のボトルネックを排除できる。

### 4.3 無名ファイルとIPCの階層的バイパス機構 (Tier 1 / Tier 2)

Linux環境において高頻度で発生する無名ファイル（パイプ、epoll等）や一時ファイル（tmpfs等）に対するI/Oによるログストーム（`ENOBUFS`）とポリシー爆発を防ぐため、カーネル内の Fast Path にはファイルシステムの物理特性（`s_magic`）に基づく「2層のバイパスアーキテクチャ」を実装する。

#### Tier 1: 全プロセス無条件バイパス (Global Fast Path)

* **対象マジックナンバー:** `PIPEFS_MAGIC` (無名パイプ), `ANON_INODE_FS_MAGIC` (epoll, eventfd, timerfd 等)
* **設計意図:** これらはディスクに保存されず、純粋なプロセス内部またはプロセス間のメモリ上通信にすぎない。マルウェアが利用してもシステム破壊や永続化は不可能であるため、システム全体の安定稼働を優先し、**対象プロセスがいかなる権限状態であっても、TEALの監視対象から無条件で除外し即時許可する。**
* **運用上の効果:** ポリシー管理者は、パイプやイベントループに関する名無しの許可ルール（JSON）を一切記述する必要がなくなる。

Tier 1 においては、ファイルシステム種別 (`s_magic`) による判定に加え、
一部の無害なキャラクタデバイスを例外的に許可対象とする。

対象はデバイス番号（Major/Minor）による明示ホワイトリストで定義する。

識別は `S_ISCHR(inode->i_mode)` を満たすキャラクタデバイスに対し、
`imajor(inode)` および `iminor(inode)` により行う。

Tier 1 に含めてよい特殊デバイスは、以下の条件を全て満たすキャラクタデバイスに限る。

1. `S_ISCHR(inode->i_mode)` を満たすこと
2. デバイス番号 (Major, Minor) による明示ホワイトリストに列挙されていること
3. 永続化媒体ではないこと
4. 外部通信または主体間通信の媒体ではないこと
5. システム状態に依存した意味的な出力またはブロック挙動を持たないこと
6. 監査対象から除外しても、攻撃検知・事後解析上の価値が実質的に失われないこと

現時点で Tier 1 に含める特殊デバイスは以下の3つのみとする。

- `/dev/null` (Major 1, Minor 3)
- `/dev/zero` (Major 1, Minor 5)
- `/dev/full` (Major 1, Minor 7)

これ以外の特殊デバイスは、同じ Major 番号を持つ場合であっても Tier 1 に含めてはならない。

※ Major番号による包括許可は禁止する。

#### Tier 2: 主体コンテキスト特権バイパス (SILENT_IO Fast Path)

* **対象マジックナンバー:** `TMPFS_MAGIC` (/tmp, /dev/shm), `SOCKFS_MAGIC` (UNIXドメインソケット), または `O_TMPFILE` フラグ付きファイル
* **設計意図:** 共有メモリやソケットは、Dockerデーモン等への不正アクセスやデータ窃取の温床になり得るため、無条件バイパスは危険である。したがって、これらへの高頻度アクセスは、**クレデンシャル（`cred`）に `SILENT_IO` 特権フラグを持つプロセス（および `INHERIT` により継承した子プロセス）からの要求であった場合のみ** Fast Path を適用し、監査ログを抑制して即時許可する。
* **運用上の効果:** LibreOfficeやDBエンジンのような、一時ファイルを大量に消費する巨大な正規アプリケーションのパフォーマンス低下と通信バッファ溢れを、ピンポイントで制圧できる。

※対象ファイルが Tier 1 にも Tier 2 にも該当しない通常ファイル（ext4, xfs等）であった場合は、プロセスが `SILENT_IO` を保持していても Fast Path は適用されず、通常の客体バインディング（Slow Path およびチケットキャッシュ）による厳密なゼロトラスト判定へフォールバックする。

### 4.4. 名無しオブジェクト（IPC/パイプ等）に対する超高速バイパスアーキテクチャ

#### 4.4.1 背景と目的
デスクトップ環境の入力メソッド（Mozc等）やコンパイラなど、システム上必須かつ無害なプロセスは、UNIXドメインソケットやパイプなどの「名無しオブジェクト」に対して、1秒間に数百回以上のプロセス間通信（IPC）やI/Oを発生させる。
これらのアクセスに対し、都度カーネル内でパス文字列の構築（`d_path`）およびマッチング評価を行うことは、深刻なパフォーマンス低下（ボトルネック）と監査ログの爆発（ログストーム）を引き起こす。
本アーキテクチャは、文字列評価を完全に排除し、**O(1)の処理量で安全なアクセス制御を実現するフェーズ分離型アルゴリズム**を定義する。

#### 4.4.2 フェーズ分離型アルゴリズムの設計
毎回のI/O時に重いポリシー評価を行うのではなく、評価を「プロセス起動時」と「I/O実行時」の2フェーズに完全に分離する。

##### フェーズ1: 起動時の重い評価と権限付与（Control Plane / Slow Path）
対象のプロセスが起動（`execve`）した最初の1回のみ、`teald` が主体（Subject）を評価する。

1. teald は起動したプロセスの実行ファイルパス（`origin_program`）を取得する。
2. ポリシーと照合し、対象プロセスであれば「名無しオブジェクトへのアクセスを無条件で許可する」という特権フラグ（例: `TEAL_ALLOW_NAMELESS_IPC`）を付与したチケットを発行する。
3. teal_module（カーネル）は、このチケットを受信し、プロセス自身の権限構造体（`cred` 等のセキュリティコンテキスト領域）にフラグとしてキャッシュする。

##### フェーズ2: I/O時の超高速判定（Data Plane / Tier 2 Fast Path）
プロセスが実際に大量の通信やI/O（`connect`, `open` 等）を開始した際の処理。

1. teal_lsm（カーネルフック）は、パス文字列の取得を行う**前**に、対象オブジェクトの `inode->i_mode` を確認する。
2. オブジェクトがソケット（`S_ISSOCK`）やパイプ（`S_ISFIFO`）などの名無しオブジェクトである場合、カレントプロセスの `cred` にキャッシュされた `TEAL_ALLOW_NAMELESS_IPC` フラグをビット演算で確認する。
3. フラグがセットされていれば、文字列評価を一切行わず、即座にアクセスを許可（`ALLOW`）する。監査ログも生成しない（Silent IO）。
4. 通常のファイル（`S_ISREG` 等）であった場合のみ、パス文字列を取得し、通常のルールベース評価（Slow Path）へフォールバックする。

#### 4.4.3 ポリシースキーマの拡張（v1.3以降）
上記のアーキテクチャをユーザー空間から制御するため、ポリシースキーマ（`policy_v1_2.schema.json`）を以下のように拡張する。

1. **`rule_type` の新設:**
   オブジェクト（`object`）の指定を強制せず、主体（`subject`）単独で評価を完結させるための宣言として `"rule_type": "subject_only"` を導入する。
2. **`ticket_profile` への特権フラグ追加:**
   発行するチケットの性質を定義するプロファイルに、名無しオブジェクトへのO(1)アクセス権限を示すフラグを新設する。

**【ポリシー記述例：MozcのIPCバイパス】**

```json5
{
  "id": "mozc-nameless-ipc-bypass",
  "rule_type": "subject_only",
  "reason": "Mozcエンジンの高頻度IPCログストーム抑止と文字列評価バイパス",
  "subject": {
    "origin_program": "/usr/lib/ibus-mozc/ibus-engine-mozc"
  },
  "action": {
    "ops": ["connect"]
  },
  "effect": "allow",
  "ticket_profile": {
    "allow_nameless_ipc": true,  // 【新設】名無しオブジェクトのパス評価をスキップ
    "silent_io": true,           // 監査ログの発行を抑制
    "inherit": true              // 生成されるワーカー/スレッドにも権限を継承
  }
}
```

#### 4.4.4 本設計による効果

* **CPU負荷の極小化:** 最も高頻度で呼ばれるLSMフック内での処理が、数回のメモリアクセスとビット演算のみ（サブナノ秒）で完結する。
* **ログ爆発の防止:** 正規プロセスの無害なシステム通信が監査ログのバッファ（NetlinkのENOBUFS等）を枯渇させる事態を未然に防ぐ。
* **ゼロトラストの維持:** 対象をソケットやパイプ等の「永続化されない名無しオブジェクト」に限定しているため、攻撃者がこの仕組みを悪用してディスク上の重要ファイル（`/etc/shadow` 等）にアクセスすることは構造上不可能である。

### 4.5 Ticket 仕様（共通）

#### (1) Ticket に含める必須情報（Key / Value）

**Subject（主体）**

* `uid`: 対象ユーザー
* `origin_program_id`: 実行バイナリ識別子 (Dev + Inode)
* `origin_script_id`: スクリプト識別子 (Dev + Inode, 未使用時は0:0)
* **`origin_applet_hash`**: Multi-call Binary用識別ハッシュ (teald計算値)

**Object（客体）**

* `object_id`: 対象リソース識別子 (Dev + Inode)、主体コンテキスト型の場合は 0:0 とする

**Action（操作）**

* `op`: 論理操作マスク

**Meta（管理情報）**

* `expires_at`: 有効期限（短期）
* `uses_left`: 残り使用回数（原則 1）
* **`ticket_id`**: 失効/監査用ID（u64）
* **`policy_epoch`**: ポリシー世代（発行時点の世代）

#### (2) Intent/Reality ハッシュ

* `intent_hash` / `reality_hash` は監査ログおよびUser空間での照合用に保持するが、Fast Path の照合キーとしては使用しない。

### 4.6 Multi-call Binary 対応フロー

`busybox` のような単一バイナリが、起動名 (`argv[0]`) によって振る舞いを変える場合の対応。

1. **Slow Path:** カーネルは `applet_name` (例: "ls") を `teald` へ送る。
2. **Teald 判定:** ポリシーに基づき `applet_name` を検証し、ハッシュ化 (u64) して Ticket に含める。
3. **Fast Path:** カーネルは実行時の `argv[0]` 等から簡易ハッシュを計算し、キャッシュ内の `origin_applet_hash` と照合する。
    * *※Alphaフェーズではハッシュ計算を省略し、0固定とする（9章参照）。*

### 4.6 事前承認チケットの遅延バインディング (Strict Context Lazy Binding)

オペレーターの事前申請による人間承認（MPA）ルートにおいて、`teald` は承認完了時点でファイルシステムにアクセスして `inode` を取得してはならない。TOCTOU（Time-of-Check to Time-of-Use）攻撃の排除、I/Oブロッキングの回避、および監査ログの完全性保証のため、以下の遅延バインディングおよびJIT Hydration方式を必須とする。

#### (1) データ構造と格納先 (State Management)
状態管理の不整合を防ぐため、ライフサイクルに応じて明確に格納先マップを分離する。

* **`PreApprovalDraft`**: 承認待ちの下書きデータ。ファイルパスやデバイス・inode情報はプレースホルダー（`"-"` や `0:0`）を保持。`state.fast.drafts` に格納される。

* **`ApprovedTicket`**: 承認完了後の実行待ち、および実行中のチケットデータ。消費トラッキング用の `uses_left` や `ttl_sec` を保持。`state.fast.tickets` に格納される。

#### (2) 処理シーケンス (Lifecycle Sequence)

**フェーズ1: チケット作成と承認（ユーザーランド単独処理）**

1. **[作成]** `teal-cli ticket <rule-id>` コマンド受信時：
    * 必要な情報と `rule_id`, `mpa_state` を含む `PreApprovalDraft` を生成。
    * inode情報等は `0:0` とし、`state.fast.drafts` に保存する。

2. **[承認]** `teal-cli approve <draft-id>` コマンド受信時：
    * MPAのしきい値（Threshold）を満たした場合、対象の `PreApprovalDraft` を `state.fast.drafts` から削除（`remove`）する。
    * 同時に `ApprovedTicket` へ昇格させ、`state.fast.tickets` に保存（待機状態へ移行）する。

**フェーズ2: 実体化とキャッシュ登録（カーネル連携 / JIT Hydration）**

3. **[REQ受信]** Fast Laneにてカーネルから `REQ` を受信し、ポリシー評価結果が `NeedApproval` となった場合：
    * `state.fast.tickets` を検索し、対象の `rule_id` に合致し、かつ**未実体化（`origin_program_id.dev == 0` 等）の `ApprovedTicket`** が存在するかチェックする。
    * 存在した場合、REQから得られた実際のコンテキスト（`dev:ino` や生パス文字列）を用いて、チケットのプレースホルダー情報を上書き（Hydration）する。

4. **[応答]** 実体化した `ApprovedTicket` を用いて、以下の順序でカーネルへ応答する。
    * ① `TICKET_ADD` 送信: カーネルのキャッシュテーブルへ登録。
    * ② `APPROVE <req.id>` 送信: フリーズ中のプロセスを再開。
    * *(※レースコンディション防止のため、必ず TICKET_ADD を先に送信すること)*

**フェーズ3: 監査ログ出力と破棄（ライフサイクルの終焉）**

5. **[INFO受信]** Slow Laneにてカーネルから消費（`CONSUME`）または期限切れ（`EXPIRE`）の `INFO` を受信した場合：
    * `state.fast.tickets` から該当チケットを取得（`get_mut`）。
    * REQ受信時に書き込んでおいたリッチなコンテキスト（実行元バイナリパス等）を用いて監査ログを出力する。
    * `CONSUME` の場合は `uses_left` を減算する。

6. **[破棄]** `uses_left == 0` に到達、または `EXPIRE` イベントを受信した時点で、対象チケットを `state.fast.tickets` から完全に削除（`remove`）する。

### 4.8 PAT (Post-Approval Ticketing)

Slow Path で同一操作が短時間に再発するケース（I/Oリトライ等）を高速化する任意拡張機能。

* 照合キーは IBTC と同様に `Dev + Inode` のみとし、コンテンツハッシュ検証は行わない。
* `pat_enabled`: false（デフォルト無効）

### 4.9 失効・GC・世代管理

#### 無効化・削除フロー

チケットの削除は、単なるメモリ解放ではなく、**「監査イベントの完了」** と同期して行う。

1. **消費完了 (Consumption):** `uses_left == 0` になった瞬間、カーネルは `INFO:CONSUMED` イベントを生成する。
2. **期限切れ (Expiration):** アクセス時に `expires_at` 切れを検知した場合、設定により `INFO:EXPIRED` を発行する。
3. **メモリ解放:** `teald` へのメッセージ送信完了を以て、カーネル内の構造体を破棄する。

### 4.10 ポリシー世代管理 (Epoch) の運用モデル

`policy_epoch` は、システム全体の権限状態を **O(1)** で瞬時に転換する機構である。

1. **基本メカニズム:**
    * カーネルはグローバル変数 `current_epoch` を保持。
    * Fast Path 判定時、`ticket_epoch != current_epoch` ならば即時無効（Cache Miss）とする。


2. **推奨ユースケース:**
    * **ポリシー更新時:** 設定リロード時に Epoch をインクリメントし、古いルールのチケットを一括無効化する。
    * **緊急停止:** `tealctl flush` 等で Epoch を更新し、全ての自動許可を停止する（Global Kill Switch）。
    * **定期再審査:** 1日1回などの定期更新で、権限の永続化（メモリリーク）を防ぐ。

### 4.11 スクリプト実行主体のキャッシュ最適化 (Script Identity Optimization)**

スクリプト（例: `python app.py`）実行時の Fast Path 判定において、毎回パス文字列から Inode を解決することは、I/O負荷および TOCTOU (Time-of-Check Time-of-Use) 脆弱性の観点から推奨されない。
そのため、以下のキャッシュ機構を実装する。

1. **メタデータ生成時のキャッシュ (`bprm` Hook):**
プロセス生成時（`bprm_check_security` 等）、インタープリタ経由の実行を検知した場合、そのスクリプトファイルの `Dev:Inode` を取得し、タスク構造体（`teal_task_meta`）に保存する。
2. **O(1) 判定:**
`teal_file_open` 等の Fast Path 判定時は、ファイルシステムへのアクセスを行わず、Ticket 内の `origin_script_id` と、タスク構造体にキャッシュされた `script_id` を整数比較するだけで判定を完了させる。

---


## 5. カーネルモジュール制御フックおよびアクション定義

### 5.1 LSM制御フック一覧（セキュリティ・インジェクションポイント）

本システムは、LinuxカーネルのLSM（Linux Security Module）フレームワークを利用し、操作が実行される直前のVFS（Virtual File System）層またはソケット層で処理をインターセプトする。
各ポリシーアクションを強制するためにカーネルモジュール（`teal_lsm`）が登録するLSMフックAPIの定義、および判定対象となるコンテキストは以下の通りである。

| ポリシー表記 (Action.ops) | LSMフック名 (Kernel API) | 引数と取得データ | 制御対象システムコール（例） | 備考 |
| --- | --- | --- | --- | --- |
| **`READ`** | `file_permission` | `struct file *` (パス、inode) | `read(2)`, `pread(2)` | 読み出し監査・遮断 |
| **`WRITE`** | `file_permission` | `struct file *` (パス、inode) | `write(2)`, `pwrite(2)` | 書き込み監査・遮断 |
| **`EXECUTE`** | `bprm_check_security` | `struct linux_binprm *` (バイナリパス) | `execve(2)`, `execveat(2)` | プロセス起動制御 |
| **`DELETE`** | `path_unlink` | `const struct path *dir`<BR>`path_rmdir` | `unlink(2)`, `rmdir(2)`, `unlinkat(2)`<BR>`struct dentry *dentry` | **ファイル/ディレクトリ削除** |
| **`RENAME`** | `path_rename` | `const struct path *old_dir`<BR>`struct dentry *old_dentry` 等 | `rename(2)`, `renameat(2)` | ファイル/ディレクトリ移動 |
| **`CONNECT`** | `socket_connect` | `struct socket *`, `struct sockaddr *` | `connect(2)` | アウトバウンド通信制御 |

#### 5.1.1 削除操作（DELETE）における `path_` フック採用の技術的根拠

削除操作のインターセプトには `inode_unlink` も存在するが、本システムでは **`path_unlink`** および **`path_rmdir`** を採用する。
`inode_unlink` では、引数としてマウントツリー情報（`vfsmount`）を持たない `struct inode` しか渡されないため、コンテナ環境やマルチマウント環境において、ポリシー照合のキーとなる「正確な絶対パス」の復元（`d_path` の利用）が不可能になる。`path_` 系のフックを使用することで、`struct dentry` と親ディレクトリの `struct path` から一貫した絶対パスを動的に解決し、ユーザー空間（`teald`）へ高精度な客体（Object）情報を提供することを保証する。

### 5.2 カーネル内部イベントとポリシーアクションのマッピング定義

カーネル空間（C層・Rust層）のイベント定数、ユーザー空間へ通知されるバイナリマスク、およびポリシー上の文字列表記のマッピング仕様を以下に定義する。

#### 5.2.1 操作マスク（Ops Mask）およびイベントID定義

カーネルモジュール内部および Generic Netlink の TLV 属性（`TEAL_ATTR_OP`）で利用される操作フラグ（ビットマスク）は以下の通りとする。

```rust
// カーネル内部イベント定数 (teal_rs / teald 共通定義)
pub const EVENT_READ: i32    = 1;
pub const EVENT_EXECUTE: i32 = 2;
pub const EVENT_WRITE: i32   = 4;
pub const EVENT_UNLINK: i32  = 8;  // path_unlink / path_rmdir からトリガー
pub const EVENT_RENAME: i32  = 16;
pub const EVENT_CONNECT: i32 = 32;

// ポリシーエンジンで評価されるアクションビットマスク (Ops)
pub const O_READ: u32    = 1 << 0; // 0x0001
pub const O_EXECUTE: u32 = 1 << 1; // 0x0002
pub const O_WRITE: u32   = 1 << 2; // 0x0004
pub const O_DELETE: u32  = 1 << 3; // 0x0008
pub const O_RENAME: u32  = 1 << 4; // 0x0010
pub const O_CONNECT: u32 = 1 << 5; // 0x0020

```

#### 5.2.2 相互変換マッピングルール

* **カーネル空間（LSM -> Rustバインディング）**:
`path_unlink` または `path_rmdir` フックにより捕捉された操作は、コンテキスト抽出後、一括して内部イベント `EVENT_UNLINK` として `teal_decision_logic` へ集約される。
* **ユーザー空間への伝播とポリシーパース**:
Netlink メッセージ生成時、`EVENT_UNLINK` は操作マスク `O_DELETE (0x0008)` に変換され、`TEAL_ATTR_OP` 属性に格納される。`teald` 内のポリシーエンジン（`teal_policy_engine`）は、このマスク値をパースし、ポリシーファイル上の `"DELETE"` アクション文字列と完全一致で照合を行う。


---

## 6. インターフェース実装仕様 (TLV/バイナリ通信プロトコル)

**【変更の背景】**
従来採用していたコロン（`:`）およびスペース区切りのプレーンテキスト通信は、プロセス名（`APPLET`）やファイルパス（`PROGRAM`, `TARGET`）に区切り文字が含まれた際にパースエラーやプロトコル破壊を引き起こす脆弱性が判明した。これを解決し、かつシリアライズ/デシリアライズのCPUオーバーヘッドを削減するため、**Generic Netlinkを用いたTLV（Type-Length-Value）バイナリ通信**へと仕様を移行する。

**実装ノート:** `INFO` メッセージには可変長の `args` 文字列を含めない。これはメモリアロケーションのオーバーヘッドとNetlink帯域を節約するためである。Fast Path においては I/O 負荷回避のため**この処理を行わない**ことを標準とする。

#### 通信チャネル

**Generic Netlink Socket (必須)**

  * Family Name: `teal_ctrl`

-----

### 6.1 Netlink コマンド定義 (Message Types)

カーネル・ユーザー空間間でやり取りされるメッセージ種別（Command）を以下の通り定義する。

| コマンド名 | 方向 | 役割 | 従来の文字列コマンド |
| :--- | :--- | :--- | :--- |
| `TEAL_CMD_REQ` | Kernel → User | Slow Path における承認要求 | `REQ:...` |
| `TEAL_CMD_INFO` | Kernel → User | Fast Path の状態通知（消費/失効） | `INFO:...` |
| `TEAL_CMD_APPROVE` | User → Kernel | 判定結果（許可）とWake up | `APPROVE <id>` |
| `TEAL_CMD_DENY` | User → Kernel | 判定結果（拒否）とWake up | `DENY <id>` |
| `TEAL_CMD_TICKET_ADD` | User → Kernel | Fast Path キャッシュの登録 | `TICKET_ADD ...` |

-----

### 6.2 Netlink 属性定義 (Attributes / TLV)

メッセージに付与される個々のデータフィールド（TLVのType/インデックス定義）を以下に定める。
これにより、**可変長文字列にコロンやNUL文字以外の任意のバイナリが含まれても安全に伝送可能**となる。
（※本一覧の並び順は、カーネルモジュール内の Enum 定義 `teal_nl_attrs` およびバリデーションポリシー `teal_nl_policy` の定義順に完全準拠する）

| 属性 (Attribute) | データ型 | 格納されるデータ・用途 |
| --- | --- | --- |
| `TEAL_ATTR_UNSPEC` | - | 未使用 (0) |
| `TEAL_ATTR_TRANS_ID` | `u64` | Transport ID (カーネル・User間の一意な通信ID) |
| `TEAL_ATTR_PID` | `u32` | プロセスID (`current->tgid`) |
| `TEAL_ATTR_PPID` | `u32` | 親プロセスID |
| `TEAL_ATTR_SESSIONID` | `u32` | セッションID |
| `TEAL_ATTR_UID` | `u32` | 実効ユーザーID (`euid`) |
| `TEAL_ATTR_GID` | `u32` | 実効グループID (`egid`) |
| `TEAL_ATTR_PROG_DEV` | `u32` | 実行バイナリのデバイス番号 (Major:Minor結合値) |
| `TEAL_ATTR_PROG_INO` | `u64` | 実行バイナリのInode番号 |
| `TEAL_ATTR_PROGRAM` | `String` | 実行バイナリの絶対パス (NUL終端) |
| `TEAL_ATTR_ACTION` | `String` | 操作種別 (`file_open`, `task_exec` 等) |
| `TEAL_ATTR_TARGET_DEV` | `u32` | 操作対象オブジェクトのデバイス番号（`dev_t`） |
| `TEAL_ATTR_TARGET_INO` | `u64` | 操作対象オブジェクトのInode番号（`ino_t`） |
| `TEAL_ATTR_TARGET` | `String` | 操作対象オブジェクトの絶対パス |
| **`TEAL_ATTR_OP`** | `u32` | **操作フラグのビットマスク（ポリシー評価用、新設）** |
| **`TEAL_ATTR_EXPIRES_AT`** | `u64` | **キャッシュチケット等の有効期限タイムスタンプ（新設）** |
| `TEAL_ATTR_SCRIPT_DEV` | `u32` | スクリプトのデバイス番号 (未使用時0) |
| `TEAL_ATTR_SCRIPT_INO` | `u64` | スクリプトのInode番号 (未使用時0) |
| `TEAL_ATTR_SCRIPT` | `String` | スクリプトの絶対パス |
| `TEAL_ATTR_APPLET` | `String` | マルチコールバイナリ用識別名 (`current->comm`) ※区切り文字衝突問題はTLV化により解消 |
| `TEAL_ATTR_LSM_LABEL` | `String` | SELinux等のラベル ※バイナリ化に伴い16進数エンコードは不要とし、生文字列を送信 |
| `TEAL_ATTR_ARGS_HEAD` | `String` | 引数の先頭部分 （最大128 bytes, Optional） ※正規化文字列の先頭のみを格納する軽量要約フィールド |
| `TEAL_ATTR_FLAGS` | `u32` | リクエスト属性ビットマスク |
| `TEAL_ATTR_INFO_EVT` | `u8` | INFOイベント種別 (`0`: CONSUMED, `1`: EXPIRED) |
| `TEAL_ATTR_USES_LEFT` | `u32` | 残り使用回数 |
| `TEAL_ATTR_TICKET_ID` | `u64` | 監査・失効指定用のユニークID |
| `TEAL_ATTR_EPOCH` | `u32` | ポリシー世代番号 |
| `TEAL_ATTR_AUDIT_FLG` | `u32` | 監査挙動フラグ (`0x0`: Std, `0x1`: Silent, `0x2`: Strict) |
| `TEAL_ATTR_APPLET_HASH` | `u64` | Multi-call Binary用識別ハッシュ |

#### 6.2.1 破壊的変更（DELETEアクション）時における客体コンテキスト抽出仕様

ファイルおよびディレクトリの削除操作（DELETE）は、操作完了後に「対象がVFS上から抹消される」という破壊的変更の特性を持つ。そのため、LSMフック（`path_unlink` / `path_rmdir`）が実行されるタイミング（削除の実行直前）において、カーネルモジュールは以下のルールに従って客体コンテキストを凍結の上、Netlink属性へパッキングしなければならない。

* **`TEAL_ATTR_OP` の設定**: 5.2.1項に定義される操作フラグビットマスクのうち、`O_DELETE (0x0008)` を強制セットする。
* **`TEAL_ATTR_TARGET` の抽出**: 削除フックに渡された `const struct path *dir` と `struct dentry *dentry` から `struct path` を再構成し、カーネル内関数（`d_path` 等）を用いてヌル終端の絶対パス文字列（最大 `PATH_MAX`）を安全にバッファへ展開・格納する。
* **`TEAL_ATTR_TARGET_DEV` の抽出**: 削除対象オブジェクトを保持するファイルシステムのスーパーブロックからデバイス番号を取得（`dentry->d_sb->s_dev`）し、`u32` 型のネットワークバイナリデータとして格納する。
* **`TEAL_ATTR_TARGET_INO` の抽出**: 対象 `dentry` が有効な inode を保持していることを確認の上、`d_inode(dentry)->i_ino` から inode 番号を `u64` 型として抽出・格納する。

-----

### 6.3 メッセージ構成要件

#### 6.3.1. REQ（承認依頼: `TEAL_CMD_REQ`）

カーネルがSlow Path時に送信する。従来文字列として結合していた25フィールドの情報を、個別のAttributeとしてNetlinkメッセージにパッキング（`nla_put`）して送信する。

  * **必須属性:** `TRANS_ID`, `PID`, `UID`, `PROG_DEV`, `PROG_INO`, `PROGRAM`, `ACTION`, `APPLET` 等、対象特定に必要な全てのメタデータ。

#### 6.3.2. INFO（状態通知: `TEAL_CMD_INFO`）

Fast Pathでの消費を通知する。パス文字列は含めず、識別子のみをパッキングする。

  * **必須属性:** `INFO_EVT`, `TICKET_ID`, `UID`, `USES_LEFT`, `PROG_DEV`, `PROG_INO`, `TARGET_DEV`, `TARGET_INO`.

#### 6.3.3. TICKET_ISSUE (許可応答とキャッシュ発行: `TEAL_CMD_TICKET_ADD`）

`teald` からカーネルへ、操作の許可とFast Path用キャッシュ（チケット）の発行を指示する。

* **属性の必須要件:**
    * **客体バインディング型**チケットを発行する場合: `TARGET_DEV`, `TARGET_INO` を必須とする。
    * **主体コンテキスト型**チケットを発行する場合: `TARGET_PID` または `TARGET_CRED_ID` を必須とする。この場合、特定の実体ファイルに依存しないため、`TARGET_DEV`, `TARGET_INO` は**省略可（またはゼロ埋め）**として扱う。
* **フラグ定義 (Ticket Flags):**
    * `0x01 (SILENT_IO)`: このプロセスが行うテンポラリファイルや無名ファイルへのI/Oについて、`teald` への `REQ` 送信と監査ログ生成を抑制し、カーネル内で自動許可する。
    * `0x02 (INHERIT)`: `fork` および `exec` 時に、このチケットの権限（有効期限および `SILENT_IO` 等のフラグ）を子プロセスへ自動的に継承させる。

-----

### 6.4 構造体定義 (C言語) のアップデート

カーネル内の構造体 `struct teal_request` は変更不要だが、文字列フォーマット化（`snprintf`）処理はすべて削除され、代わりに Netlink 用のパッキング関数群（`nla_put_u32`, `nla_put_string`, `nla_put_u64` 等）へ置き換えられる。

これにより、カーネル内の処理において\*\*「文字列バッファの長さ計算」や「区切り文字のエスケープ」といった不要なオーバーヘッドが消滅\*\*する。

-----

#### 6.5 データ取得責務分界 (Data Responsibility Matrix)

競合状態（TOCTOU）の回避とシステムパフォーマンスの最適化のため、各情報の取得責務を以下のように規定する。

| データ項目 | 取得場所 | 理由・実装方針 |
| --- | --- | --- |
| **PID, UID, GID** | **Kernel** | プロセス属性の基本情報であり、後から変更される可能性があるため。 |
| **PPID, SessionID** | **Kernel** | 親プロセスの消失やセッション離脱による追跡不能リスクを回避するため。 |
| **Target Inode (および関連デバイス番号)** | **Kernel** | **【必須】** パス解決時のTOCTOU攻撃（シンボリックリンク差し替え）を完全に防ぐため。**`teald` (ユーザー空間) は、いかなる場合（事前承認時を含む）もファイルシステムにアクセスして `inode` の自己解決を行わない。**必ずカーネルがフックした瞬間の絶対不変の識別子（REQ経由で受信したもの）を使用する。 |
| **LSM Label** | **Kernel** | プロセスの `exec` 等によるドメイン遷移前の状態を正確に記録するため。 |
| **Applet Name** | **Kernel** | BusyBox等のマルチコールバイナリにおいて、実行された瞬間の機能名 (`comm`) を特定するため。 |
| **Arguments (head)** | **Kernel** | 重要コマンドに限り、実行時の引数をカーネル内でキャプチャする（戦略的選別）。 |
| **File Hash** | **User (teald)** | カーネル内でのハッシュ計算負荷を回避するため、通知受信後に `teald` が計算する（リスク受容）。 |
| **SSH/Env Context** | **User (teald)** | 環境変数のパース負荷をカーネルから排除するため、`SessionID` をキーに `teald` が解決する。 |

---

## 7. 監査ログと証跡管理 (Audit & Evidence)

### 7.1 リクエストID体系と役割 (Identity Strategy)

TEALシステムでは、カーネル通信の効率性と監査ログの追跡性を両立するため、以下の2種類のIDを使い分ける。

1.  **Transport ID (Kernel Space: `u64`)**
    * **定義:** REQ メッセージ（`TEAL_CMD_REQ`）に含まれる **`TEAL_ATTR_TRANS_ID` 属性**。
    * **生成:** デバイスドライバー（teal_module）が内部カウンタ (`atomic64_inc`) を用いて生成する連番。
    * **役割:** カーネルと `teald` 間での通信ハンドシェイク用。ホストの稼働期間（ドライバーロード中）のみ一意性が保証される。
    * **ログ:** 原則として監査ログには記録しない（デバッグ用トレースを除く）。

2.  **Audit ID (User Space: `UUID`)**
    * **定義:** 監査ログ（JSON）の `id` フィールド。
    * **生成:** `teald` が `REQ` を受信し、内部でリクエスト構造体を生成した瞬間に発行する。
    * **形式:** **UUID v7 (Time-ordered)** または v4。
    * **役割:** 分散環境および長期保存における一意な識別子。SIEMや外部システムでの検索キーとして使用する。

**実装要件:**
`teald` は受信した `Transport ID` と生成した `Audit ID` をメモリ上で紐付けて管理し、カーネルへの応答（Allow/Deny）には必ず `Transport ID` を使用すること。


### 7.2 パス解決とログエンリッチメント (Path Resolution Strategy)

カーネルから受信する `INFO` メッセージにはファイルパスが含まれないため、`teald` はログ保存時に以下のロジックでパス情報を復元（Enrichment）する。

1. **Intent Binding (推奨・高速):**
    * 受信した `ticket_id` (u64) を **システム標準ID形式 (`T-<seq>`) に変換** し、これをキーとして、`teald` がメモリ内に保持している「発行済みチケット台帳（Intent Ledger）」を検索する。
    * チケット発行時に使用したパス（例: `/etc/shadow`）をログの `path` フィールドに転記する。
    * **メリット:** 高速であり、チケット発行時の「意図（Intent）」と実際の「結果（Reality）」を正確に紐付けられる。


2. **Inode Reverse Lookup (補完・低速):**
    * チケット情報が見つからない場合（再起動後など）、または監査専用モードの場合、`find` やファイルシステム走査を用いて `inode` からパスの逆引きを試みる。
    * ※負荷が高いため、必要最小限の利用に留める。



### 7.3 データ構造 (A) Fast Path Log Schema (Ticket Consumed)

Fast Path ログは、カーネルキャッシュ（チケット）に基づいて自動許可された操作の記録である。
**設計思想（案B - Performance Optimized）:**
頻繁に発生するイベントであるため、カーネルからの通信オーバーヘッドを最小化する。したがって、可変長のコマンド引数（args）や環境変数はカーネルから送信せず、ログ上では**チケット発行時の意図（Intent）**への参照、または省略とする。

* **目的:** 「いつ、誰が、どのチケットの権利を行使したか」の記録 (Proof of Use)
* **特徴:** 軽量、高頻度、引数はチケット発行時に検証済みとみなす

```json5
{
  "ver": "1.5",
  "id": "UUID-fast-...",        // Log Entry ID
  "type": "TICKET_CONSUMED",    // Fast Path
  "ts": "2026-02-09T10:10:00Z",
  "host": "prod-db01",

  // 1. Reality (実行事実)
  "syscall_context": {
    "uid": 1000,
    "pid": 4530,
    "action": "exec", // または open, unlink 等
    
    // Subject (実行主体)
    "subject": {
      "path": "/usr/bin/cat",   // inodeから解決
      "hash": "sha256:e3b0c44...", // tealdがバイナリから事後計算（改変検知用）
      
      // 【注意】Fast Pathではパフォーマンス優先のため、
      // 実行時の生引数（Raw Args）は記録しない。
      // 具体的な引数制限は Ticket ID に紐付く Slow Path ログを参照する。
      "args": null 
    },

    // Object (操作対象)
    "object": {
      "path": "/etc/shadow",    // inodeから解決
      "inode": 9999
    }
  },

  // 2. Authorization Reference (承認の根拠)
  "ticket_context": {
    "ticket_id": 1001,          // ← Slow Path (Ticket Issued) ログとの紐付けキー
    "uses_left": 0,             // 残り回数
    "policy_rule": "admin_ops_01"
  }
}
```

### 7.4 リクエストID生成と管理 (Request ID Strategy)

システム全体の追跡性（Traceability）とカーネル通信の効率性を両立するため、内部処理用IDと監査用IDを明確に分離して実装する。

1. **Transport ID (Kernel Space: `u64`)**
    * 定義: struct teal_request 内の `id` メンバ。
    * 生成: カーネルモジュール内で `atomic64_inc_return` 等を用いて生成される単調増加整数。
    * 役割: カーネルと `teald` 間での一時的なリクエスト/レスポンスの紐付け（ハンドシェイク）にのみ使用する。
    * スコープ: ホストの稼働期間中のみ一意（再起動によりリセットされる）。

2. **Audit ID (User Space: `UUID`)**
    * 定義: 監査ログ（JSON）内の `id` フィールド。
    * 生成: teald が `REQ` メッセージを受信し、内部でイベントオブジェクトを生成した瞬間に発行する。
    * 形式: **UUID v7 (Time-ordered)** の採用を推奨する。これにより、分散環境での一意性と時系列ソート性能を両立させる。
    * 役割: ログ解析、SIEM連携、および長期的な監査証跡の識別子。

**実装要件:**
`teald` はメモリ上で `Transport ID` と `Audit ID` のマッピングを管理し、カーネルへの応答（`APPROVE/DENY`）には `Transport ID` を使用し、外部へのログ出力には `Audit ID` を使用すること。


### 7.5 データ構造 (B) Slow Path Log Schema (Interactive Decision)

Slow Path（同期承認時）のログは、`teald` が下した判定結果およびキャッシュ戦略に応じて、以下の3種類の `type` を使用する。
特に **`ACCESS_DENIED` は攻撃検知における最重要イベント** として扱われる。

1. **`TICKET_ISSUED` (許可・キャッシュ登録):**
    * 承認を行い、かつカーネル内にチケット（キャッシュ）を生成した状態。
    * 後続の `TICKET_CONSUMED` (Fast Path) ログの親となる。
    * ticket_context フィールドが**必須**となる。


2. **`ACCESS_ALLOWED` (許可・キャッシュなし):**
    * 今回の要求のみを許可（One-time Allow）した状態。
    * 監査モード（Audit Mode）や、キャッシュ不可（No-Cache）ルールに該当する場合がこれにあたる。
    * チケットは生成されないため、同一操作があっても次回も再度 Slow Path となる。


3. **`ACCESS_DENIED` (拒否):**
    * ポリシー違反または承認者による否決が発生した状態。
    * **対象操作の実行およびチケットの発行が共にブロックされる。**



**JSONスキーマ例 (ACCESS_DENIED の場合):**

```json5
{
  "ver": "1.5",
  "id": "UUID-deny-...",            
  "type": "ACCESS_DENIED",          // ★重要: アクセス拒否ログ
  "ts": "2026-02-09T10:05:00Z",
  "host": "prod-db01",

  // 1. 拒否された操作内容 (Reality)
  "syscall_context": {
    "uid": 1000,
    "pid": 4523,
    "action": "exec",           
    "subject": { 
        "path": "/usr/bin/curl",
        "hash": "sha256:bad_hash..." 
    },
    "object": { 
        "path": "192.168.1.50",
        "kind": "network"
    }
  },

  // 2. 拒否の根拠 (Policy Eval)
  "policy_eval": {
    "rule_id": "block_outbound_traffic",
    "decision": "DENY",
    "cache_policy": "none"

    // 発行されたチケット情報 (キャッシュ有効時のみ存在)
    "issued_ticket": {
      "ticket_id": "T-a1b2c3d4e5f6",  // 発行された動的チケットID
      "ttl_sec": 3600                  // 有効期限
    }
  },

  // 3. 拒否理由詳細 (Denial Reason)
  "denial_reason": {
    "code": "POLICY_VIOLATION",
    "message": "Outbound connection to unauthorized IP is blocked."
  }
}

```

**JSONスキーマ例 (teal-cli start許可 の場合):**

```json5
{
  "timestamp": "2026-02-15T10:00:00Z",
  "req_id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "INTERACTIVE_DECISION",
  "log_version": "1.0",
  "syscall_context": {
    "subject": {
      "pid": 4021,
      "uid": 1000,
      "comm": "teal-cli",
      "exe_path": "/bin/teal-cli",
      "args": ["start"]
    },
    "object": {
      "path": "system:mode/enforce",  // ★仮想パス
      "inode": 0,
      "fs_type": "none"
    }
  },
  "policy_eval": {
    "rule_id": "admin_change_mode_01",
    "rule_description": "Enforceモードへの移行承認",
    "matched_file": "00-admin.json",
    "mpa_level_required": 2,
    "decision": "ALLOW"
  },
  "mpa_proof": {
    "threshold": "2-of-3",
    "approvers": [ ... ]
  }
}
```

#### 7.5.1 ログ種別定義 (Log Types)

監査ログのトップレベルフィールド `type` には、イベントの発生要因と処理経路（Path）を識別するため、以下の列挙値（SCREAMING_SNAKE_CASE）を使用する。

| ログ種別 (type) | 分類 | 説明・発生タイミング |
| --- | --- | --- |
| **`INTERACTIVE_DECISION`** | Slow Path | **承認判定** |
|     |     | 承認フローを経て許可されたログ。**チケットが発行された場合、そのIDとTTL情報を含む。** |
| **`ACCESS_ALLOWED`** | Slow Path | **自動許可** |
|     |     | ポリシーにより即時許可されたログ。**`ttl_sec > 0` の設定によりチケットが発行された場合、その情報を含む。** |
| **`ACCESS_DENIED`** | Slow Path | **アクセス拒否** |
|     |     | ポリシー評価の結果、拒否（`deny`）された場合、または不正なリクエストとして破棄された時点で記録される。 |
| **`TICKET_CONSUMED`** | Fast Path | **チケット使用** |
|     |     | 発行済みチケットがカーネル内の Fast Path キャッシュでヒットし、ユーザ空間 (`teald`) を介さずに高速処理されたイベント。 |
|     |     | ※ カーネルからの `INFO` 通知に基づき非同期で記録される。 |
| **`TICKET_EXPIRED`** | Internal | **チケット期限切れ** |
|     |     | 発行されたチケットが一度も使用されないまま TTL (Time To Live) を経過し、ガベージコレクション（Sweeper）によって破棄された時点で記録される。 |



### 7.6 監査チェーン (Audit Chain) と正規化モデル

TEALシステムの監査ログは、ストレージ効率と検証可能性を両立するため、リレーショナルな「監査チェーン」モデルを採用する。

1. **正規化 (Normalization):**
    * 重厚な承認情報（BLS署名、承認者のMFAコンテキストなど）は、**Slow Path ログ（チケット発行時）** にのみ記録する。
    * その後の繰り返し実行（Fast Path）は、`ticket_id` を介してこの親ログを参照する。


2. **検証プロセス (Verification):**
    * 監査ツールは、Fast Path ログの `ticket_context.ticket_id` をキーとして、対応する Slow Path ログを検索しなければならない。
    * **完全な証跡 = Fast Path ログ (実行事実) + Slow Path ログ (承認の正当性)**
    * これにより、数千回のバッチ処理実行（Fast Path）に対し、署名データ（Slow Path）を1つだけ保持すれば良いため、ログ容量を大幅に削減できる。


3. **ToCToU (Time-of-Check to Time-of-Use) 対策:**
    * Fast Path ログにも `syscall_context.subject.hash` を記録することで、承認時点（Slow Path）と実行時点（Fast Path）でバイナリが改変されていないことを事後検証可能にする。



### 7.7 コンテキスト解決とハッシュ検証 (Context Resolution)

`teald` は、カーネルからの `REQ` を受信した際、判定前に以下のロジックを用いて情報を補完（Enrichment）しなければならない。

1. **SSH / Login コンテキストの解決:**
    * pid から `/proc/<pid>/environ` を読み取り、`SSH_CLIENT`, `SSH_CONNECTION` 環境変数を抽出する。
    * または、`utmp`/`wtmp` データベースを参照し、`session_id` に紐付くログイン元 IP を特定する。
    * この処理は `Decision Worker` スレッド内で行い、承認者の UI に「誰がどこから接続しているか」を表示するために使用する。

2. **LSMラベルのデコード:**
    * `REQ` メッセージ内の `LSM_LABEL_HEX` フィールドを16進デコードし、元の文字列（例: `system_u:system_r:sshd_t:s0`）に復元する。
    * これにより、プロトコル上の区切り文字競合を回避しつつ、正確なコンテキストを記録する。

3. **実行バイナリのハッシュ計算:**
    * syscall_context.subject.hash は、`teald` が対象の `program` パスを `open()` し、SHA-256 を計算して付与する。
    * **TOCTOU対策:** カーネル側でバイナリがロックされているわけではないため、厳密には実行時点と乖離する可能性があるが、監査情報としては `teald` 視点でのハッシュを正とする。

4. **BLS 署名の集約:**
    * mpa_proof 内の `approvers` から個別の署名を集め、MPA Engine が BLS 署名集約（Signature Aggregation）を行う。
    * 集約された `aggregated_signature` のみが、最終的に発行される Ticket に含まれる署名と数学的に等価となる。

5. **TTY の特定:**
    * `/proc/<pid>/fd/0`, `1`, `2` のいずれかのシンボリックリンク先が `/dev/pts/` または `/dev/tty` で始まる場合、それを TTY とする。
    * デーモン等で TTY がない場合は `?` または `none` とする。

6. **SSH 接続情報の特定 (Ancestry Walk):**
    * 対象プロセスが `sudo` 等で環境変数を保持していない場合を考慮し、プロセスツリーを親 (`PPID`) 方向へ遡る。
    * 各プロセスの `/proc/<n>/environ` を解析し、最初に発見された `SSH_CLIENT` または `SSH_CONNECTION` 環境変数の値を採用する。


7. **認証方式 (Login Method) の特定:**
    * 環境変数 `SSH_USER_AUTH` が存在する場合、指定されたファイルを読み取り、認証方式（`publickey`, `password` 等）を記録する。
    * 取得できない場合（`sshd` 設定未対応時など）は、`unknown` を記録する。


### 7.8 コマンドライン引数の記録戦略 (Selective Argument Audit)

監査ログの完全性とシステムパフォーマンスのトレードオフを最適化するため、
コマンドライン引数 (`args`) の記録は「全件記録」ではなく、
以下の**「戦略的選別 (Targeted Audit Strategy)」**を採用する。

本仕様では、完全な引数列はカーネルから送信せず、
代わりに軽量な要約情報である `TEAL_ATTR_ARGS_HEAD` を用いる。

1. **デフォルト動作 (Applet Only):**
    * 一般的なコマンド（`ls`, `cat`, 自作アプリ等）については、
      **`<APPLET>` (プロセス名) のみを記録し、引数情報は送信しない。**
    * **理由:**
        ファイルアクセス制御においては Subject（誰が）と Object（何に）の情報で
        十分なケースが大半であり、不定長データを送るコストを回避するため。


2. **重要コマンドの選別記録 (Target List):**
    * 以下のカテゴリに属する「セキュリティ上重要なコマンド」に限り、
      **引数の先頭部分 (`ARGS_HEAD`)** をカーネルから抽出し、記録する。
    * `ARGS_HEAD` は完全な引数列ではなく、引数の要約情報である。

    * **対象例:**
        * **特権昇格・ID変更:** `sudo`, `su`, `doas`
        * **インタプリタ・シェル:** `python`, `perl`, `bash`, `sh`
        * **コンテナ・構成管理:** `docker`, `kubectl`, `systemctl`

    * **理由:**
        これらのコマンドは、引数によって挙動が大きく変化するため、
        先頭部分のみでも監査および異常検知に有効な情報となる。


    * **実装方式:**
        * **Phase 1:** カーネルモジュール内の静的配列（Allowlist）で対象を定義。
        * **Phase 2/3:** ユーザー空間 (`teald`) からの設定注入により、
          対象リストを動的に更新可能とする。


### 7.9 管理操作の監査 (Auditing Administrative Operations)

`teal-cli` を用いたシステムの状態変更（モード遷移やポリシー更新）は、セキュリティ上の最重要イベントである。したがって、これらのコマンド実行はカーネル空間のファイルアクセスと同様に、必ず `teald` のポリシー評価（Slow Path）を経由し、監査ログとして記録されなければならない。

#### 7.9.1. 監査対象コマンドとログ種別

| 操作コマンド | 動作内容 | 必須ログ種別 | 備考 |
| --- | --- | --- | --- |
| **`teal-cli start`** | Enforceモードへの移行 | `INTERACTIVE_DECISION` | **【重要】** 通常は管理者の承認（MPA）を経て実行されるべき操作。 |
| **`teal-cli stop`** | Auditモードへの降格 | `INTERACTIVE_DECISION` | 防御機能の停止を意味するため、最も厳格な承認と記録が求められる。 |
| **`teal-cli reload`** | 設定・ポリシーの再読み込み | `ACCESS_ALLOWED` | 自動化ツールによる実行が多いため、承認不要（Allow）設定となる場合が多いが、ログは必須。 |
| **`teal-cli flush`** | キャッシュ/Epochの破棄 | `ACCESS_ALLOWED` | 緊急停止措置として記録する。 |

#### 7.9.2. ログ記録仕様

管理操作のログは、6.5節で定義された **Slow Path Log Schema** に準拠して出力する。ただし、`syscall_context` 内のフィールドは以下のようにマッピングする。

* **Subject (主体):**
    * `uid`: コマンドを実行した管理者ユーザーのUID。
    * `comm`: "teal-cli"


* **Object (対象):**
    * `path`: 実行されたサブコマンドを仮想パスとして記録する（例: `system:mode/enforce`, `system:policy/reload`）。
    * または、操作対象の実体パス（例: `/etc/teal/policy.json`）。


* **Policy Eval:**
    * `rule_id`: 管理操作専用のルールID（例: `admin_change_mode`）を記録する。

---

## 8. 並行処理アーキテクチャ

本システムは、セキュリティ強度（Guard）とシステム性能（Performance）を両立させるため、カーネルおよび `teald` 内部において、制御フローと監査フローを明確に分離し、並行実行するアーキテクチャを採用する。

### 8.1 デュアルレーン・アーキテクチャ (Kernel-User Communication)

カーネル（teal_module）とユーザー空間（teald）の間には、特性の異なる2つの通信レーンを設け、用途に応じて使い分ける。

| レーン名称 | 通信方式 | 特性 | 用途 |
| :--- | :--- | :--- | :--- |
| **Control Lane** | 同期 (Blocking) | 高優先・低遅延 | **ENFORCEモードの判定**<br>承認依頼、ポリシー問い合わせ |
| **Audit Lane** | 非同期 (Non-blocking) | 高スループット | **AUDITモードのログ送出**<br>統計情報、Telemetry、Bulk Log |

* **Control Lane:** プロセスの実行を一時停止（Wait）させ、厳密な判定結果（Allow/Deny）を受け取るための経路。
* **Audit Lane:** リングバッファ等を使用し、プロセスの実行を阻害せずに一方的に情報を投げ込む経路。

### 8.2 Teald 内部スレッドモデル

`teald` デーモン内部では、ガード機能とAUDIT機能を異なるスレッド（または非同期タスク）で並行処理し、互いの遅延が干渉しない設計とする。

```text
[ Kernel Space ]            [ User Space: teald Process ]
      |                                   |
(1) Control Lane  ----------------->  [ Decision Worker (高優先度) ]
    (Request)                             | ・ポリシー照合
      |                                   | ・Allow/Deny 即時判定
      |<----------------------------------| ・Cache登録判断
      | (Response)                        |
      |                                   v
      |                               (内部Queue: 判定ログ)
      |                                   |
(2) Audit Lane    ----------------->  [ Audit Worker (バックグラウンド) ]
    (Log Stream)                          | ・BLS署名計算 (高負荷)
                                          | ・ディスクI/O (JSONL書き込み)
                                          | ・SIEM転送

```

* **Decision Worker (Guard):**
    * メモリ上のポリシーのみを参照し、**可能な限り最速で**カーネルへ応答を返す。
    * ディスクI/Oや重い暗号計算（署名）は行わず、Audit Workerへタスクを委譲（Fire-and-Forget）する。


* **Audit Worker (Log):**
    * 判定結果ログやAudit Laneからのログをバッファリングし、まとめて署名・保存する。
    * この処理が遅延しても、カーネル側のプロセス実行（Guard）には影響を与えない。



### 8.3 ハイブリッド運用（Selective Audit in Enforce Mode）

ENFORCEモード（防御）での稼働中であっても、特定の操作のみを「防御対象外」または「監視対象」とするハイブリッドな制御が可能である。

#### ケースA: 特定重要ファイルの常時監視 (No-Cache Audit)

* **シナリオ:** `/etc/shadow` へのアクセスは許可するが、いつ誰がアクセスしたか毎回必ず記録したい。
* **動作:**
    1. ポリシーで当該ファイルへのアクセスを `decision: audit` と定義。
    2. カーネルは毎回 Slow Path (Control Lane) で問い合わせる。
    3. teald はログを記録し、ステータス `TEAL_DECISION_AUDIT` (許可・キャッシュ不可) を返す。
    4. **結果:** プロセスはブロックされることなく実行されるが、キャッシュが効かないため**全アクセスの完全な証跡**が残る。



#### ケースB: 新規アプリの並行導入 (Partial Audit Mode)

* **シナリオ:** 既存システムは厳格に防御（ENFORCE）しつつ、新規導入するアプリXだけは動作検証のためログのみ取りたい（AUDIT）。
* **動作:**
    1. アプリX（`comm="new_app"`）に対するポリシーを `mode: audit` (または `allow_log`) に設定。
    2. 当該アプリの操作は Control Lane を経由するが、`teald` は即座に `ALLOW` を返しつつ、Audit Worker にログを流す。
    3. **結果:** システム全体のセキュリティレベル（ENFORCE）を下げずに、特定アプリの挙動学習が可能となる。

### 8.4 カーネル側のキャッシュ判定順序

**Fast Path におけるキャッシュ評価順序:**
カーネル（`teal_module`）はキャッシュヒット時、以下の順序で厳密な評価を行い、パフォーマンスとセキュリティ（ポリシー更新時の即時無効化）を両立する。

1. **Epoch (世代) の検証:**
    キャッシュエントリの `epoch` と、カーネルが保持するグローバルな `current_epoch` を比較する。不一致の場合は直ちにキャッシュミス（無効）とみなし、ユーザー空間(`teald`)へ評価をフォールバックする。これにより、ポリシー変更時の安全性が担保される。
2. **有効期限 (`expires_at`) の検証:**
    現在時刻がチケットの `expires_at` を超過していないか確認する。超過している場合はキャッシュミスとする。（※ `ticket_id = 0` の場合でも、定期的な再評価を担保するために有効期限のチェックは行われる）
3. **uses_left の減算**: チケットの残り回数を 1 減算。
4. **Silent & Unlimited モード (`ticket_id == 0`) の判定:**
    `ticket_id` が `0` の場合、`uses_left` の減算処理、および `INFO:CONSUMED` メッセージの生成・送信を完全にスキップし、即座に操作を許可（Allow）する。
5. **通常チケットの消費処理:**
    `ticket_id > 0` の場合は、`uses_left` が残っているか確認の上で 1 減算し、消費を通知するための `INFO` メッセージを Netlink キューにエンキューした上で操作を許可する。（`uses_left` が 0 になった場合はキャッシュから削除する）
6. **監査通知の送出判断**:
    * **Standard (0x0)**: `uses_left` が 0 になった場合、`INFO:CONSUMED` を生成。
    * **Silent (0x1)** または **`ticket_id == 0`**: 通知をスキップ。
    * **Strict (0x2)**: 無条件で `INFO:CONSUMED` を生成。

---

## 9. 管理インターフェース UX 規定

管理者が `TICKET` コマンドを使用した際のエラー応答を規定する。

### (1) エラー応答の原則

`teald` は、単なる `ERR` ではなく、**「どのリソースが解決できなかったか」** を具体的に特定できるエラーメッセージを返却しなければならない。

### (2) エラーメッセージ仕様（例）

* **パス解決エラー:**
    * `ERR_RESOLVE_FAILED: origin_program path '/usr/bin/custom_tool' not found`
    * `ERR_RESOLVE_FAILED: object path '/etc/secure/config.toml' not found`


* **ルール制約違反:**
    * `ERR_NOT_TICKETABLE: rule 'rule_web_01' contains glob pattern in object path, explicit path required`
    * `ERR_AMBIGUOUS_SUBJECT: rule 'rule_admin_any' matches multiple uids`



### (3) 実装への反映

* **CLI ツール:** 上記エラーをパースし、管理者に修正アクション（ファイル確認、ルール修正）を提示すること。
* **teald ログ:** 失敗した `stat()` 結果（ENOENT, EACCES 等）を詳細に記録すること。


---

## 10. ポリシー設定とパス照合ロジック (Policy Matching)

`teald` が管理者定義のポリシーファイル（JSON等）を読み込み、カーネルからのパス（REQ）と照合する際の仕様を規定する。
本ロジックは **Slow Path（ユーザー空間）** でのみ使用され、カーネル内の Fast Path（Inode判定）とは区別される。

### 10.1 パスマッチング種別

ポリシー設定におけるパス指定は、以下の3種類のマッチングモードをサポートする。文字列のプレフィックス（スキーム）によりモードを識別する。

| モード | プレフィックス | 記述例 | 動作仕様 |
| --- | --- | --- | --- |
| **Exact** | なし (Default) | `/usr/bin/vim` | パス文字列が完全一致する場合のみマッチする。正規化（Normalization）後のパスで比較を行う。 |
| **Prefix** | `prefix:` | `prefix:/opt/myapp/` | 指定されたパスで始まる全てのファイルにマッチする（ディレクトリ配下すべて）。 |
| **Glob** | `glob:` | `glob:/var/log/**/*.log` | シェルワイルドカードパターン（`*`, `?`, `**` 等）を使用してマッチングを行う。 |

### 10.2 判定優先順位

同一のファイルパスに対して複数のルールがマッチする場合の優先順位は、以下の通りとする。

1. すべてのファイルパスが**Exact (完全一致)** となるルールが最優先される。
2. 次に objectのファイルパスが**Exact (完全一致)** となるルールが最優先される。
3. 最後は残りのルール。

同一優先度のルールの優先順位は設定ファイルの記述順（上から下）とする。

### 10.3 実装要件

* **コンパイル:** `teald` は起動時に設定ファイルをパースし、Globパターン等の正規表現エンジン（または `globset` 等のオートマトン）を事前にコンパイル済み状態（`PathMatcher` 構造体）でメモリに保持しなければならない。
* **正規化:** カーネルから受信したパス、および設定ファイルのパスは、判定前に必ず正規化（`..` の削除、重複スラッシュの削除）を行うこと。

### 10.4 キャッシュと有効期限設定 (Caching & TTL Strategy)

各ルールには、許可判定後の「Fast Path（カーネルキャッシュ）」の有効期間を制御する `ttl_sec` パラメータを指定できる。

| パラメータ名 | 型 | 必須 | 説明 |
| --- | --- | --- | --- |
| **`ttl_sec`** | Integer | 任意 | **Fast Path 有効期限 (秒)**
|     |     |     | ・`0` (または省略): **キャッシュ無効**。毎回ユーザー空間 (`teald`) で監査と判定を行う。 |
|     |     |     | ・`1` 以上: **キャッシュ有効**。指定秒数有効なチケット (`T-xxx`) を発行し、期間内はカーネル内で高速処理する。 |

**設定例 (policy.json):**

```json5
  "rules": [
    {
      "id": "backup_daemon_allow",
      "reason": "バックアップ処理（頻繁なファイルアクセスがあるため1時間キャッシュ）",
      "effect": "allow",
      "ttl_sec": 3600,
    },

    {
      "id": "critical_config_change",
      "reason": "重要設定変更（1アクセスごとに監査ログを残すためキャッシュしない）",
      "effect": "allow",
      "ttl_sec": 0,
    }
  ]
```

### 10.4.1 監査レベル（Audit Level）のポリシー定義

ポリシー設定における各レベルの解釈は以下の通り。

| レベル | `audit_flags` | `ttl_sec` の推奨 | ユースケース |
| --- | --- | --- | --- |
| **`standard`** | `0x0` | 1 以上 | 一般的なユーザー操作（デフォルト）。 |
| **`silent`** | `0x1` | 1 以上 | 大量 I/O が発生する信頼済みバッチ処理。 |
| **`strict`** | `0x2` | 1 以上 (高速) | パフォーマンスを維持しつつ、全アクセスの証跡が必要な作業。 |
| **`strict`** | N/A | 0 (同期) | 1回たりとも未承認実行を許さない超重要ファイルへのアクセス。 |

### 10.5 キャッシュと監査戦略

#### 10.5.1 監査レベル（Audit Level）の定義

システムのパフォーマンスとセキュリティレベルのバランスを最適化するため、以下の3つの監査レベルを導入する。

| レベル | 名称 | `audit_flags` | `ticket_id` の扱い | 内部挙動 |
| --- | --- | --- | --- | --- |
| **Level 0** | **Standard** | `0x0` | **一意のID** | 完了時のみ通知。 |
| **Level 1** | **Silent** | `0x1` | **一意のID** | **ログ通知を抑制。** 管理・失効は可能。 |
| **Level 2** | **Strict** | `0x2` | **一意のID** | アクセスごとに毎回通知。 |

#### 10.5.2 設定パラメータ

ポリシーファイル（`policy.json`）で以下のパラメータを使用して制御する。

* **`ttl_sec`**: **Fast Path 有効期限 (秒)**
    * `0`: キャッシュ無効。毎回ユーザー空間で判定を行う（Strict用）。
    * `1` 以上: キャッシュ有効。


* **`audit_level`**: **ログ出力強度**
    * `standard`: 通常の事後監査（Level 0）。
    * `silent`: audit_flags = 0x1 によるログ抑制（管理・失効は可能）。メッセージの抑制による高速化（Level 1）。
    * `strict`: 毎回のリアルタイム監査（Level 2）。



#### 10.5.3 設定例 (policy.json)

```json5
{
  "version": "1.3",
  "ttl_minutes": 60,
  "sweep_minutes": 10,
  "rules": [
    {
      "id": "rule-001",
      "subject": { "origin_program": "/usr/bin/backup" },
      "object": { "path": "/data/backup/*" },
      "action": { "ops": ["read"] },
      "effect": "allow",
      "audit_level": "silent",
      "ttl_sec": 3600
    },
    {
      "id": "rule-002",
      "subject": { "user": "admin" },
      "object": { "path": "/etc/shadow" },
      "action": { "ops": ["read"] },
      "effect": "allow",
      "audit_level": "strict",
      "ttl_sec": 0
    }
  ]
}

```

---

## 11. ログイン環境および時間軸によるアクセス制御

### 11.1. 概要
本仕様は、従来の「誰が（UID）」「何に（Object）」というアクセス制御に加え、「どこから（Login Context）」「いつ（Time Window）」という多次元的な検証を導入し、クレデンシャル盗難や監視空白時間におけるリスクを最小化することを目的とする。

### 11.2. サブジェクト定義の拡張（Subject Enrichment）
ポリシーエンジンの判定対象となる `subject` オブジェクトに、以下の属性を動的にバインドする。

* **Login Context (環境識別子)**
    * `source_ip`: 接続元のIPv4/v6アドレスまたはCIDR。
    * `tty_device`: プロセスが紐付いているTTY（例: `/dev/pts/1`）。
    * `auth_method`: ログイン時に使用された認証方式（`publickey`, `password`, `fido2` 等）。
* **Temporal Context (時間識別子)**
    * `request_time`: `teald` がリクエストを受信したシステム時刻。

### 11.3. 環境情報の解決メカニズム（Ancestry Walk）
`teald` は判定リクエスト受信時、以下の手順でログイン環境を特定する。

1.  カーネルから通知された `pid` を起点にプロセスツリーを親方向に遡行する（Ancestry Walk）。
2.  ログインシェル（`bash`, `zsh`等）または `sshd` プロセスの `/proc/<pid>/environ` から、`SSH_CLIENT` および `SSH_CONNECTION` 環境変数を抽出する。
3.  抽出された情報を `Login Context` として判定ロジックへ渡す。

### 11.4. 時間軸による制御と猶予期間（Time-Window & Grace Period）
重要ファイル操作やMPA（多人数承認）を伴うアクションに対し、時間制約を課す。

* **Time-Window 判定**: ポリシーに記述された「曜日 ＋ 時間帯」の積集合で判定を行う。
* **一律猶予期間（Uniform Grace Period）の導入**:
    * トラブル対応および作業の整合性を保つため、**一律 60分** の猶予期間を設ける。
    * **動作仕様**: 
        1.  「許可時間内」に開始された操作に対し、`teald` はチケットを発行する。
        2.  チケットの有効期限（TTL）は、ポリシー指定の秒数に一律 60分（3600秒）を加算した値、または業務終了時刻から 60分後を上限として設定される。
        3.  一度発行されたチケットは、カーネルキャッシュ内で有効である限り、業務時間外になっても当該プロセスの継続実行を許可する。
        4.  業務時間外に新たに開始（`file_open` 等）を試みるプロセスについては、チケットが発行されず、即座に `DENY` となる。

### 11.5. ポリシー例（重要ファイルのMPA制御）

```json5
{
  "id": "critical-ops-with-context",
  "subject": {
    "uid": 1000,
    "login_context": {
      "source_ip": "192.168.1.0/24",
      "auth_method": "publickey"
    }
  },
  "time_constraints": [
    { "days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "window": { "start": "09:00", "end": "18:00" } }
  ],
  "object": { "path": "/etc/shadow" },
  "action": { "ops": ["write"] },
  "effect": "need_approval",
  "threshold": 2,
  "grace_period_sec": 3600
}
```

### 11.6. 例外処理（Break-Glass）
システム障害時等の緊急対応において、時間外かつ環境外からのアクセスが必要な場合は、以下のいずれかのルートで対応する。

1.  **物理コンソール**: `/dev/tty1` 等の物理端末からの操作は、環境チェックをスキップするようデフォルトポリシーで定義。
2.  **緊急延長申請**: `teal-cli` を用い、管理者2名以上の承認（MPA）を条件に、特定のチケットIDの有効期限を動的に延長する。

---

## 12. 信頼性とリカバリ設計

本章では、カーネル（`teal_lsm`）とデーモン（`teald`）間の通信が途絶した際の検知メカニズム、および安全なシステム復旧（自己修復）の手順を定義する。

### 12.1 通信異常の検知と状態リセット

* **検知条件**: Netlink 送受信における致命的エラー（`EPIPE`, `ECONNRESET`, `ENOENT`）または受信チャネルの閉鎖（`None` の受信）を検知した場合、通信断とみなす。
* **動的データのクリア**: 不整合防止のため、以下の管理データを直ちに破棄する。
    * **動作モード**: `is_enforce` を `false` (Audit Mode) へ初期化（フェイルセーフ）。
    * **世代管理**: `current_epoch` を `0` へ初期化し、カーネル側のリセットと同期させる。
    * **Fast Path**: 仕掛中のリクエスト（`drafts`）、承認済みチケット（`approved`）、ログ用キャッシュ（`tickets`）を全削除する。
    * **Slow Path**: 未完了の `pending_requests` および管理操作（`pending_start/stop`）を破棄する。
* **静的データの保持**: ユーザーの公開鍵（`registered_keys`）は「静的な信頼」に基づくため、通信断に関わらず保持を継続する。

### 12.2 スーパーバイザーによる自動復旧

* **監視役の責務**: `main.rs` のスーパーバイザー（メインタスク）が再接続を主導し、ワーカーを再起動する。
* **再試行戦略**: `teal_lsm` との通信が復旧するまで、指数バックオフアルゴリズム（初期1s、最大60s、回数無制限）を用いて試行を継続する。
* **再同期シーケンス**: 再接続成功時、`bundle.json` から最新の設定を再ロードし、カーネルへ `REGISTER` コマンドを発行してポリシーと世代（Epoch）の同期を完了させてから、各ワーカーを再生成する。

### 12.3 段階的セーフティネットとタイムアウト
通信断が継続する場合、設定されたタイムアウト（`fatal_timeout_min`: デフォルト30分、変更可能）に基づき以下のフェーズへ移行する。

* **Recovery (0〜5分)**: 指数バックオフによる自動復旧試行。
* **Alerting (5〜25分)**: 管理者へのアラート（syslog/外部通知）の継続的な発報。
* **Isolation (25〜30分)**: `AppState` を「Lockdown」へ移行。既存チケットを除き、新規の動的承認を制限する。
* **Final Action (30分超)**: 設定に基づき、`panic`（カーネルパニック誘発）、`halt`（システム停止）、または `ignore`（リトライ継続）の最終手段を実行する。

### 12.4 監視とエスカレーション (Logging & Alert)
リトライが継続している間、運用者が異常に気づけるよう以下のログレベル制御を行う。

* **警告 (WARN):** リトライ回数が1回〜5回までの間。「一時的な瞬断」として記録。
* **重大エラー (ERROR):** リトライが5回を超えた場合。LSMモジュールの致命的な不具合や不正なアンロードが疑われるため、システム管理者への通知（syslog/アラート）を発生させる。
* **情報 (INFO):** 再接続に成功し、ポリシーの `REGISTER` およびワーカーの再起動が完了した際に記録。


---

## 13. 実装フェーズと暫定措置 (Alpha Scope)

開発効率と機能検証を優先するため、機能実装を以下の2段階に分割する。

| フェーズ | 目的 | 実装方針 |
| --- | --- | --- |
| **Alpha (現在)** | **疎通・基本動作** | 厳密な検証（Hash計算、世代管理）を省略し、該当フィールドを `0` や `Dummy` で埋めることを許容する。 |
|     |     | ただし、**通信フォーマットはBeta版（最終形）に準拠**させ、将来的なカーネル改修コストを最小化する。 |
| **Beta / Final** | **完全なセキュリティ** | 「Multi-call binaryハッシュ」「Epoch管理」「Audit ID」をロジックとして完全実装し、正規の値を流す。 |

### Alpha版におけるパラメータ実装対照表

`TICKET_ADD` コマンドにおいて、以下のフィールドは暫定的な扱いとする。

| フィールド | Beta/Final (本来の仕様) | **Alpha (暫定実装)** |
| --- | --- | --- |
| `applet_hash` | `argv[0]`ハッシュ値 | **`0` (固定)** (検証スキップ) |
| `uses_left` | 残り回数 | **`0` or `1**` (onceフラグにより決定) |
| `epoch` | Policy Epoch | **`0` (固定)** |

**User Space 実装指針:**
Alpha版 `teald` は、コマンド生成時にこれらのフィールドに固定値 `0` を埋めて送信する。

**Kernel Space 実装指針:**
カーネルは全フィールドをパースするが、`applet_hash` が `0` の場合はハッシュ検証を行わない（常に一致とみなす）。これにより将来 `teald` が正規の値を送り始めた際、カーネル側の変更なしに機能が有効化される。

### Alpha版におけるパス解決の実装

* **Kernel:** `INFO` メッセージ生成時、パス文字列化のオーバーヘッドを省き、**`TEAL_ATTR_TARGET_INO` 等の属性（u64）に直接 Inode 番号をパッキング**する実装とする。
* **User (`teald`):**
    * 受信スレッドは `INFO` メッセージをパースし、構造体へマッピングする。
    * ログ保存スレッドは `ticket_id` を用いて、メモリ上の `IssuedTicketMap` からパス情報を取得する。
    * Alpha段階では、再起動等でマップが消失した場合の逆引き（Reverse Lookup）実装は省略し、パス不明（`UNKNOWN`）として記録することを許容する。

###　Beta / Final フェーズ実装項目:**
* `teal_task_meta` への Inode キャッシュ機構の実装。
* （Alphaフェーズでは、スクリプトパス判定は文字列比較または「スクリプト指定なし」のみをサポートする暫定実装でも可とする）

---

## 14. 将来の拡張に向けた補足 (Future Roadmap & Extensions)

本セクションでは、v1.5 以降の実装において予定されている拡張機能、およびデータ構造の将来的な予約値について定義する。これらは現行バージョンでの実装は必須ではないが、データスキーマの互換性を維持するために考慮する必要がある。

### 14.1 認証方式識別子の予約 (Authentication Methods)

`ApproverAction` 構造体等の `method` フィールドにおいて、将来サポート予定の認証方式を以下の通り定義・予約する。これにより、監査ログ上で「強固な認証を経た承認」と「簡易的な承認」を区別可能にする。

| 識別子 (`method`) | 分類 | 説明 | 実装フェーズ |
| :--- | :--- | :--- | :--- |
| **`local_ed25519`** | 鍵ファイル | ローカルファイルシステム上の秘密鍵による署名（現在のCLI実装）。 | **Alpha (Current)** |
| **`ssh_agent`** | 公開鍵認証 | SSH Agent (`ssh-rsa`, `ssh-ed25519`) への署名要求による承認。秘密鍵はメモリ上またはHSMに存在。 | Beta |
| **`fido2`** | ハードウェア | YubiKey 等の FIDO2/WebAuthn デバイスを使用した、物理的接触を伴う承認。 | Future |
| **`mfa_totp`** | 多要素 | 管理画面等でパスワードに加え、Time-based OTP (Google Authenticator等) を確認した場合。 | Future |
| **`passkey`** | 生体認証 | プラットフォーム認証（TouchID, Windows Hello）を利用した Passkey 署名。 | Future |

### 14.2 閾値暗号と分散承認 (Threshold Cryptography)

現在は `teald` が各承認者の署名を検証・集約しているが、将来的に **t-of-n 閾値署名 (Threshold BLS Signature)** への移行を想定する。

* **目的:** 単一の `teald` サーバーが侵害された場合でも、秘密鍵（または署名権限）全体が漏洩しない構造にする。
* **拡張方針:**
    * 承認者（Approver）は、分散鍵生成 (DKG) プロトコルにより生成された「秘密鍵シェア」を持つ。
    * ApproverAction.signature は署名シェア (Signature Share) として扱われる。
    * teald は署名シェアが閾値 ($t$) に達した時点で、それらを合成して単一の有効な署名を復元する。
    * これにより、監査ログ (`TICKET_ISSUED`) には「誰が承認したか」のリストと、「数学的に正当な単一署名」のみが記録される。

### 14.3 ポリシーエンジンの Wasm 化

現在の静的 JSON 設定に加え、複雑な条件判定（時刻、外部API連携、カスタムロジック）を可能にするため、ポリシーエンジンの **WebAssembly (Wasm) プラグイン対応** をロードマップに含める。

* **インターフェース:** OPA (Open Policy Agent) 互換、または Proxy-Wasm に準じたABIを策定する。
* **サンドボックス:** ユーザー定義ポリシーは Wasm ランタイム内で実行され、`teald` 本体のメモリ安全性と安定性を脅かさない設計とする。

### 14.4 ハードウェア Root of Trust (TPM Integration)

システムの完全性を物理層から保証するため、TPM 2.0 (Trusted Platform Module) との連携を設計に含める。

1.  **鍵のシール (Sealing):**
    * teald が使用する秘密鍵、および承認者のローカル鍵を TPM 内に生成・保管し、外部への持ち出しを不可能にする。
2.  **リモート構成証明 (Remote Attestation):**
    * カーネル (`teal_lsm`, `teal_module`) および `teald` のバイナリハッシュを PCR (Platform Configuration Registers) に測定する。
    * 承認者は承認操作を行う際、サーバーから送られた PCR 値を検証し、「改竄されていない正しい TEAL システムからの要求であること」を確認してから署名を行うフロー（Machine Identity 認証）を導入する。

### 14.5 真のゼロトラストと運用自動化を実現する

本仕様書（v1.x系列）の「プロセスベース・チケット継承モデル」を基盤とし、将来のバージョンで真のゼロトラストと運用自動化を実現するために、以下の機能を次期版のスコープとして定義する。

#### 14.5.1 ハッシュ値による厳密な実行制御と改ざん防止

ファイルパスの偽装やすり替え（正規バイナリへのマルウェア上書き）を見破るため、実行時のハッシュ値検証機構を導入する。

* **TLV通信の拡張:** カーネルからの `REQ` メッセージ、および `teald` からの `TICKET_ISSUE` メッセージの属性に、ファイルの完全性を示す `TARGET_HASH` (例: SHA-256) を追加する。
* **IMA連携:** カーネル内でのハッシュ計算は、Linux標準の IMA (Integrity Measurement Architecture) サブシステムから測定値を取得する方式を第一候補とする。
* teald は受信したハッシュ値と、自身が保持する正しいバイナリのハッシュ（ホワイトリスト）を突き合わせ、不一致の場合は実行を強制遮断（Deny）する。

#### 14.5.2 カーネル内ログ重複排除・レートリミット（AUDITモードのフェイルセーフ）

未知のスクリプト等がバグや攻撃によって意図せず無限ループに陥り、ミリ秒単位でI/Oログを生成した場合のセーフティネットをカーネル空間（`teal_module`）に実装する。

* 同一PIDが同一操作を短時間（例：1秒以内）に連続して行った場合、2回目以降の `teald` への `REQ` 送信を間引き、カーネル内でドロップまたはカウントアップのみを行う機構（`printk_ratelimit` 相当）を追加する。

#### 14.5.3 プロファイリングとポリシーの自動生成機能**

管理者の運用負荷を下げ、正確なホワイトリストを構築するため、`teald` に学習・分析エンジンを実装する。

* OSのパッケージマネージャ（`dpkg`, `rpm`等）と連携し、システム標準バイナリのハッシュ値ホワイトリストを自動構築する。
* AUDITモードで収集したプロセスのアクティビティログを分析し、「どのプロセスに `SILENT_IO` や `INHERIT` を付与すべきか」という最適化されたJSONポリシーのドラフトを自動生成し、管理者に提案する機能を実装する。

### 14.6 ネットワーク接続状態に連動したリカバリ制御

* **外部コンテキストの統合**: リカバリループにおいて、ネットワーク接続の有無を監視条件に含める。
* **条件付きプロセスの停止**: 「LSM 通信断 かつ ネットワーク断」が長時間続く場合、外部承認が不可能であることを考慮し、設定に応じてデーモンを安全に休止（Halt）させるオプションを提供する。

### 14.7 環境に応じたパラメータの動的チューニング

* **対策時間の最適化**: `fatal_timeout_min` をシステム毎の運用要件（開発/本番）に合わせて変更可能なプリセットとして管理する。
* **死因究明の強化**: `kdump` や `pstore` と連携し、パニック直前の `teald` 内部状態を永続ストレージにダンプして、再起動後の解析（Post-mortem analysis）を可能にする。

### 14.8 ログ管理の高度化と外部連携（将来拡張）

#### 14.8.1 ログファイル命名規則の標準化
将来的なクラウドストレージ（S3等）への自動転送や、長期アーカイブ時の検索性を高めるため、ローテーション後のファイル名にメタデータを付与する。

* **推奨形式**: `audit.jsonl.[YYYYMMDD].[POLICY_EPOCH].gz`
* **各項目の意味**:
    * `[YYYYMMDD]`: ログがローテーション（切り出し）された日付。
    * `[POLICY_EPOCH]`: そのログファイルが閉じられた時点での `current_epoch`（ポリシー世代）。これにより、ログ内容を解析する際に適用すべき正確なポリシーバージョンを即座に特定可能とする。

#### 14.8.2 ログの整合性保護
アーカイブされたログの改ざん検知のため、ローテーション完了時にファイル全体のハッシュ値（SHA-256）を計算し、署名付きメタデータファイルとして保存する機能を検討する。

---

## 付録：TEAL Policy Schema v1.3.1 (抜粋)

`audit_level` をサポートする JSON スキーマの定義。

```json5
{
  "properties": {
    "version": { "const": "1.3.1" },
    "rules": {
      "items": {
        "properties": {
          "audit_level": {
            "type": "string",
            "enum": ["silent", "standard", "strict"],
            "default": "standard"
          }
        }
      }
    }
  }
}

```

