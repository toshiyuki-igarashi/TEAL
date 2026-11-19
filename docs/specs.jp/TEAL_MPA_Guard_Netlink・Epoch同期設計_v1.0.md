# TEAL MPA Guard — Netlink登録・Epoch同期・障害時整合性設計 v1.0

- 策定日: 2026-11-17
- 状態: **設計案／未実装**
- 前提: `TEAL_MPA_Guard_カーネルデータ構造設計_v1.0.md`、`TEALシステム実装構成仕様書_2_2.md`、2026-11-17アップロードの `teal_lsm.c`・`netlink.rs`・`admin.rs`。実際のGit HEADは実装前に再照合する。

## 1. 目標と不変条件

Guardは`effect: need_approval`のルール群からコンパイルした**object × operationの安全側上位集合**。`subject`・申請者UID・承認者UIDをGuardの照合には使用しない。通常のポリシー照合・承認とJIT Hydrationはtealdが実行する。

1. **GuardとPolicy Epochを分離確定しない。** 完全に検証済みのGuardがない状態で新Epochを有効化しない。
2. 正常なGuard 0件と、Guard未同期／不完全を厳密に区別する。
3. 旧Guardを維持したまま新Guardを構築し、不可分に切り替える。登録失敗時に旧Guardを破棄しない。
4. 応答不能時に`UNPROTECTED`と**証明できない**場合はFail-Closed。明示的な`UNPROTECTED`だけ3秒後Fail-Open＋緊急記録。
5. `teald`切断・再起動で、既存チケットは無効化しても最後の完全なGuardは残す。切断を理由とした自動AUDIT移行／Guard無効化は禁止（防御モードと監視モードは分離）。
6. 申請者と実行者のUID同一性は検証しない。実行者の適格性は通常のpolicy.subjectが担当する。
7. ACK消失は「成功・失敗不明」。単純な再送やロールバックをせず、カーネル状態を読み直して解決する。
8. 既存`POLICY_UPDATE`の単なるEpoch更新経路を、Guard同期必須の運用時に利用できないようにする。

## 2. カーネルの管理状態

```c
struct teal_guard_staging {
    u64 tx_id;               /* tealdが生成する更新識別子 */
    u32 base_epoch;          /* last committed epoch */
    u32 next_epoch;
    u32 expected_entries;
    u32 received_entries;
    u32 total_bytes;
    u8 expected_sha256[32];
    u32 owner_tx_portid;     /* 現在登録済みTX socket */
    u64 owner_generation;    /* REGISTERごとに更新する接続世代 */
    unsigned long expires_jiffies;
    unsigned long *received_bitmap;
    struct teal_mpa_guard_snapshot *candidate;
};

/* 参照側は不変のsnapshotをRCUで読む。
 * writer側はticket/epoch/guard更新ロックで直列化。 */
struct teal_mpa_guard_snapshot __rcu *teal_guard_active;
struct teal_guard_staging *teal_guard_staging;
```

Guardの公開スナップショットは既存の`struct teal_mpa_guard_snapshot`（epoch、entry_count、state、entries）を使用。Kernelの`teal_last_epoch`は単調増加、`teal_current_epoch=0`は切断中のチケット無効を意味する**運用上の状態**。切断後も保持するGuardのepochは最後に確定した`teal_last_epoch`に対応する。Guard READYの真偽を`teal_current_epoch!=0`だけで判断しない。

初版制限値の提案: 最大1024エントリ、Guard保有メモリ総量1MiB、1パス最大4096バイト、stagingトランザクション1個。制限超過は全体を失敗にして**黙ってエントリを切り捨てない**。値は構成・メモリを測定して見直す。

## 3. Generic Netlinkプロトコル

既存family `teal_ctrl`、既存コマンド番号0～10・属性番号0～35は変更せず、追加分だけappendする。実装ではCとRustでenum値を明示的に照合し、互換性・機能バージョンを`REGISTER`で検証する。

| command（番号案） | 方向 | 内容 |
| --- | --- | --- |
| `TEAL_CMD_GUARD_BEGIN = 11` | teald → Kernel | Guard全件の転送開始。`base_epoch`、`next_epoch`、件数、digest、tx_idを登録。現行activeは不変 |
| `TEAL_CMD_GUARD_ADD = 12` | teald → Kernel | tx_id、0始まりindex、正規化済みGuardエントリ1件。index重複・未知tx_idはエラー |
| `TEAL_CMD_GUARD_ABORT = 13` | teald → Kernel | 未確定のstagingだけ破棄。activeは不変 |
| `TEAL_CMD_GUARD_STATUS = 14` | teald → Kernel | current_epoch / last_epoch / guard_epoch / READY / digest / active tx_idを返す（復旧・診断） |
| **既存 `TEAL_CMD_POLICY_UPDATE = 8` を拡張** | teald → Kernel | **Guard全体のCOMMITとEpoch進行を同じカーネル更新臨界区間で実行** |

新規属性（番号は36以降に追加）案：`GUARD_TX_ID:u64`、`GUARD_BASE_EPOCH:u32`、`GUARD_COUNT:u32`、`GUARD_SHA256:binary[32]`、`GUARD_INDEX:u32`、`GUARD_OP_MASK:u32`、`GUARD_OBJECT_TYPE:u8`、`GUARD_MATCH_TYPE:u8`、`GUARD_TARGET_MASK:u8`、`GUARD_PATH:NLA_NUL_STRING`、`GUARD_FORMAT_VERSION:u16`、`GUARD_TOTAL_BYTES:u32`、`GUARD_REUSE:u8`。ワイヤ上の列挙値・型・文字列長を厳密に定義する。長さ・index・opビット・path正規形・符号化を受信側で毎回検査する。

`GUARD_ADD`はv1では1件/メッセージ。各メッセージを`NLM_F_ACK`で確認し、すべてACKを受け取った後にのみCOMMITへ進む。将来のバッチ化はプロトコル拡張で扱う。転送欠落・ダイジェスト不一致・順序異常・無効データはCOMMIT失敗。

SHA-256は**完全性と診断用**（順序、マスク、パスを含む規定のバイナリ正規化表現のdigest）。鍵を持たないハッシュ自体はroot権限に対する改ざん防止手段ではない。

## 4. 状態遷移

```text
ACTIVE(E) ── GUARD_BEGIN(E+1) ──> STAGING(E+1) + ACTIVE(E)
  ↑                                      │
  │ GUARD_ABORT / error / disconnect     │ all GUARD_ADD + validation
  └──────────────────────────────────────┘
                                         ↓
                              POLICY_UPDATE(E+1, tx_id)
                                         │
                              [Kernel atomic COMMIT]
                                         ↓
                                    ACTIVE(E+1)
```

`GUARD_BEGIN`は`next_epoch == teal_last_epoch+1`かつ`base_epoch == teal_last_epoch`を要求（初期値0）。staging所有者は登録済みTX portidとREGISTER世代に固定。未完了stagingは一定時間（例30秒）で自動破棄。複数同時更新は`-EBUSY`。`BEGIN`の再送には別tx_idか、明示的ABORTを必要とする。

Kernel COMMITの検証：送信元、接続世代、tx_id、base_epoch、next_epoch、全件到着、範囲、SHA-256、snapshot READY、制限値、ポリシー更新ロックを検証する。失敗した場合はEpoch・active Guard・既存チケットを**一切変更しない**。成功時だけGuard公開とEpoch更新・旧チケット無効化・待機要求の失効を**一つの更新トランザクション**で実行し、その後ACKする。

**読取側の原子性:** `teal_current_epoch`を別のatomicに持つ既存コードではGuard pointerとの混在が起こり得る。望ましくは「epoch＋Guard pointer＋状態」を1つのRCU公開オブジェクトで読み、ticket処理との世代検査を統一する。暫定的に分離する場合、読取ったEpochとGuard epochが異なる・切替中で確証がない場合は必ず`UNKNOWN`としFail-Closed。要求待機が更新を跨ぐ場合は、**障害時点の最新Guardで再評価**する（古いGuardの分類結果をキャッシュしない）。

## 5. Rust（teald）側のシーケンス

既存`NlWriter`のTX workerは専用ソケットで`POLICY_UPDATE`のNetlink ACKまで待機する。これに `GuardBegin/GuardAdd/GuardAbort/GuardStatus/CommitPolicyEpoch` を追加し、**同じTXキューの順序制御**を使う。

1. staged policy bundleをコンパイルし、すべての`need_approval`ルールから保守的なGuard集合を生成。未対応のobject条件（例：glob）は上位集合へ変換、変換不能なら操作全体を保護。欠落させない。
2. `begin_ticket_transition()`で新規チケット発行を停止。さらに旧ポリシーからの`APPROVE`やREQ応答も更新を跨いで通さないよう、判定ワーカー側に世代境界を設ける。`DENY`は安全側のため通してよい。
3. `GUARD_BEGIN → GUARD_ADD×N`をそれぞれACK確認。`N=0`でもBEGINは必須（Guard未同期とは別）。
4. `POLICY_UPDATE(next_epoch, tx_id, expected_digest)` を送信し**カーネルでGuardとEpochを一括確定**。
5. ACK成功・状態整合確認後にRustの`policy_snapshot`と`management`を公開し、旧Draft/Approvedを破棄。新Epochで発行を再開。
6. ACK待ちタイムアウトや送信エラーでは成功・失敗が不明な場合がある。新しい要求の許可処理を止め、`GUARD_STATUS`で実際のcommitの有無・Epoch・digestを確認し、**決め打ちで再コミットしない**。状態復旧できなければtealdを停止して登録・完全再同期へ。

既存`execute_policy_update()`は（旧）`switch_policy_directory`→`synchronize_kernel_epoch`→`commit_policy_snapshot`。ディレクトリ切替でエラーになった場合にstagingを放置せずABORT。ACK喪失でKernel commit済みなら、旧ポリシーへ安易に戻さず状態確認が必要なのは現仕様と同じ。

## 6. FLUSH／再起動／モード遷移

- **`teal-cli flush`**：ポリシーそのものは不変でEpochだけ進む。active Guardの内容を**複製／再利用して新Epochへ付け替える** `POLICY_UPDATE`の明示的`GUARD_REUSE`モードを設ける。ただしlast_epoch・active digestを厳密照合し、未同期時は拒否。新GuardのないEpoch進行を許可しない。
- **`teald`再起動**：RX/TX切断で`teal_current_epoch=0`にしてチケット失効・stagingを破棄。**active Guardは維持**。新REGISTER後、次EpochでGuard全体を再送・COMMITし、READY確認後に通常判定へ復帰。
- **`START`（ENFORCEへ）**：active Guard READYであり、Guard/Kernel/Rust Epochが一致することを必須とする。未同期なら-EPERM。`REGISTER`だけではREADYとみなさない。
- **ENFORCE中の通信断**：自動で全操作許可のAUDITへ移さず、Guardを利用した障害時分類を続ける。`teald`が未接続なら3秒待ちではなく送信失敗経路から直ちに同じ分類へ進んでもよい（通知は必須）。
- **AUDITモード**：明示的に許可されたAUDITの目的は操作許可。従ってGuardの障害時保護を保証するのはENFORCE中に限る。AUDIT/STOPの認可は別途MPA/管理ポリシーで保護する。

## 7. エラー処理表

| 障害 | Kernelのactive Guard / Epoch | tealdの動作 |
| --- | --- | --- |
| BEGIN / ADDの検証失敗 | 旧Guard/旧Epochを維持 | ABORT、更新失敗として報告 |
| ADD途中でteald切断 | 旧Guardを保持、staging破棄、チケット失効 | 再REGISTER・完全再同期 |
| COMMIT検証失敗（`-EINVAL/-ESTALE/-ENOMEM`等） | 旧Guard/旧Epochを維持、旧チケットに手を触れない | エラー報告、新ポリシーは未確定 |
| COMMIT ACK消失 | **新旧どちらか不明** | STATUS照会・digest照合まで許可処理停止。安易にrollbackしない |
| KernelがGUARD_STATUSを返せない | 最終完全Guardを保持 | 再同期・安全側停止・独立監視通知 |
| Guard未初期化でENFORCE要求 | ENFORCE移行拒否 | Guardを完全登録してから再試行 |
| 要求処理中にEpoch変更 | 新Epoch/Guardが有効。旧REQ/ALLOW/TICKET_ADDは無効化 | 旧REQの応答を破棄、再評価 |
| Guard照合に必要なパスが欠落／切り詰め | `UNKNOWN`、timeout時DENY | 緊急通知に理由を含める |

## 8. セキュリティ境界上の制約

現行Kernelの`teal_nl_check_authorized()`は登録済みTX portidで制御コマンドを識別している。これは任意プロセスによる誤送信を減らすが、**侵害済みrootからのGuard改ざん・teald停止・`STOP`発行・ポリシーファイル置換を単独で防ぐ保証ではない**。TEALのroot侵害耐性を要求するなら、ポリシー更新承認の署名検証、保護された管理鍵、起動時信頼の確立、更新証跡などの追加設計が必要。

また、`TEAL_REQ_F_TRUNC`・objectパス長・new_targetの扱い、rootバイパス・SILENT_IO・通信断でのモード移行はGuardの到達性を左右する。Netlink同期だけでは捕捉されないLSM操作まで保護できないため、次の工程（Timeout/Send failure統合）と併せて監査する。

## 9. VMでの最低限の検証

1. Guard 0件READYと未同期の区別、START前の完全同期必須。
2. 既存Guard E、候補E+1のBEGINのみ／一部ADDのみ／digest不一致で旧Guardが残る。
3. 有効なGuardを完全転送してCOMMIT後のみE+1の保護が有効になる。
4. ACK喪失を模擬し、STATUSでE+1のdigest確認後にRust側同期を回復する。
5. `teal-cli flush`でEpochだけ増加してもGuard保護が失われない。
6. RX/TX切断・teald再起動でGuardを保持し、再REGISTERから次Epochへ復帰する。
7. Epoch境界で旧REQのAPPROVEや旧TICKET_ADDが新ポリシーへ持ち越されない。
8. `need_approval`ルールのsubjectが指定されていてもGuardはobject×op全体を保護する。
9. `iga`申請→MPA承認→`toshiyuki`実行の現行仕様に影響しない。
10. `teald`無応答時にMPA対象READをDENY、他のREADを条件付きALLOWし、双方の障害を記録できる（この最後の試験は次工程のタイムアウト実装後）。

## 10. 今後の実装順序

1. C/Rust双方のenum拡張、型付きNetlinkパケット、BEGIN/ADD/ABORT/STATUS、staging制限とテスト。
2. `POLICY_UPDATE`をGuard+Epochの一括commitへ拡張。`FLUSH`のGuard REUSE対応。
3. RustのGuard生成・送信・再同期、management snapshot・許可応答のEpoch境界保護。
4. KernelのGuard分類ヘルパーを`teal_req_wait`／Netlink送信失敗時に接続。カーネル側バイパス・モード遷移を点検。
5. 独立した緊急イベント・通知経路、VMで故障注入試験。

**この文書は設計案であり実装パッチではない。** 実装前に現行Git HEADで、特に`REGISTER`・`POLICY_UPDATE`・`FLUSH`・`START/STOP`・teald `send_sync_epoch()`の振る舞いを再確認する。
