# TEAL MPA Guard — カーネル側データ構造設計 v1.0

- 策定日: 2026-11-17
- 対象: TEAL LSM / `teald` / Generic Netlink
- 状態: **設計案。未実装。**
- 参照: `TEALシステム実装構成仕様書_2_2.md`、2026-11-17時点の`teal_lsm.c`およびFast Path v5差分

## 1. 目的と境界

MPA Guardは、**`teald`の応答が3秒以内に得られない、または通信送信に失敗した場合の許可・拒否を分類するための、カーネル常駐の保護対象集合**である。通常時のポリシー判定をカーネルへ移植しない。

| 条件 | 判断 |
|---|---|
| Fast Pathの有効なチケットがヒット | 従来どおり即時許可。MPA Guardは消費済みチケットの代替ではない |
| `teald`から明示的なAPPROVE/DENY | 従来どおり明示的判定に従う |
| `teald`が正常にNeedApprovalを判定・未承認 | `teald`が即時DENYを返す（実装済み） |
| 無応答3秒・通信障害でGuardに一致 | `-EACCES`（Fail-Closed） |
| 無応答3秒・通信障害でGuardに非一致が確認できる | `0`（Fail-Open）および緊急イベント |
| Guardの未登録・不整合・対象判定不能 | 安全側に `-EACCES`。運用モード起動前にGuard同期必須 |

申請者と利用者は一致不要。Guardは`subject`や申請者UIDによって狭めず、`object × operation`の安全側上位集合として生成する。通常時は`teald`がポリシーの`subject`、`object`、`action`、MPA承認を確認する。チケットのJIT Hydration時には実行要求からUID・バイナリ・対象等を確定し、以後のFast Pathは当該チケットの束縛条件を検査する。

## 2. データ構造（概念C定義）

```c
enum teal_guard_object_type {
    TEAL_GUARD_PATH = 1,
    TEAL_GUARD_NETWORK = 2,  /* CONNECT拡張時 */
    TEAL_GUARD_ANY = 3,      /* 保守的な全対象 */
};

enum teal_guard_match_type {
    TEAL_GUARD_EXACT = 1,
    TEAL_GUARD_PREFIX = 2,
    TEAL_GUARD_ALL = 3,
};

#define TEAL_GUARD_SOURCE       (1U << 0)
#define TEAL_GUARD_DESTINATION  (1U << 1)

struct teal_mpa_guard_entry {
    u32 op_mask;            /* TEAL_EVENT_READ/WRITE/UNLINK/... と共通 */
    u8 object_type;         /* PATH / NETWORK / ANY */
    u8 match_type;          /* EXACT / PREFIX / ALL */
    u8 target_mask;         /* SOURCE / DESTINATION。RENAMEは両方考慮 */
    u8 reserved;
    u16 path_len;           /* バイト長。NUL終端を別途保証 */
    char *path;             /* 不変の正規化済みパス。ALLではNULL */
};

enum teal_guard_state {
    TEAL_GUARD_UNINITIALIZED = 0,
    TEAL_GUARD_READY,
    TEAL_GUARD_INVALID,
};

struct teal_mpa_guard_snapshot {
    struct rcu_head rcu;
    u32 epoch;
    u32 entry_count;
    u32 state;                  /* 完全生成済みのみREADY */
    struct teal_mpa_guard_entry *entries;
};

static struct teal_mpa_guard_snapshot __rcu *teal_guard_active;
static DEFINE_MUTEX(teal_guard_update_mutex);
```

**実装上の前提:** スナップショットと配下のエントリ・文字列は公開後に書き換えない。読者はRCU read-side critical section内で参照し、切替後の旧スナップショットはRCU grace period経過後に解放する。`teal_guard_active == NULL`は「MPA対象0件」ではなく「未同期」。正常に生成された0件スナップショットのみ「MPA保護対象なし」を意味する。

Guardは**Fast Pathチケットとは別のデータ構造**で管理する。Guardには個別チケットのTTL、使用回数、申請者・承認者UID、Hydration済みdev:inodeを持たせない。

## 3. キーとマッチング規則

### 3.1 ファイル

- `Exact`: 正規化済み完全パスの一致。
- `Prefix`: 指定ディレクトリ自身と配下を、境界を考慮して一致。`/backup/`は`/backup2/`に一致しない。
- `Glob`: 初期版ではカーネルに完全なglobエンジンを実装せず、`teald`で**安全側のprefix上位集合**に変換する。例: `glob:/var/log/**/*.log` → `prefix:/var/log/`。安全なprefixを抽出できなければ当該操作について`ALL`。
- 複数Guardエントリに一致した場合は保護対象（OR）とする。通常ポリシーの優先順位をカーネルで再評価しないため、正常時に許可される操作を障害時だけ拒否する可能性は許容する。
- カーネル内でpathnameを解決できない場合、文字列が途中で切れた場合、mount/bind mount/symlink/rename等でパスの同一性が証明できない場合は、`UNPROTECTED`と断定せず`UNKNOWN`へ倒す。**inode一致だけでは、同じパスに新たに作られたファイルを保護できない**ため、inodeを唯一の保護キーにしない。

### 3.2 RENAME

RENAMEでは移動元と移動先のいずれも保護対象となり得る。`old_target`・`new_target`の双方を評価し、片方でも保護対象ならFail-Closed。新しい宛先inodeが存在しない場合もパスで判定する。文字列が取れない側は`UNKNOWN`とする。

### 3.3 Operation

カーネルで既存の`TEAL_EVENT_READ=1`, `WRITE=2`, `EXECUTE=4`, `DELETE=8`, `UNLINK=16`, `RENAME=32`, `CHMOD=64`, `CHOWN=128`, `CONNECT=256`をそのままビットマスクで用いる。複合opは交差するいずれかのビットで保護対象とする。

### 3.4 ネットワーク

`CONNECT`のobjectはファイルパスではない。初期版でCIDR/IP・ポート・IPv4/IPv6などの照合を実装しない場合、`need_approval`のCONNECTルールから`TEAL_GUARD_ANY + TEAL_EVENT_CONNECT`を生成して全CONNECTを安全側で保護する。未対応を黙ってエントリから落としてはならない。将来は`NETWORK`オブジェクトでIP/CIDR、ポート範囲、protocolを保持する。

## 4. 照合結果は3値

```c
enum teal_guard_result {
    TEAL_GUARD_UNPROTECTED = 0,
    TEAL_GUARD_PROTECTED   = 1,
    TEAL_GUARD_UNKNOWN     = 2,
};
```

- `PROTECTED`: 完全なGuard集合のいずれかとobject×opが一致 → DENY。
- `UNPROTECTED`: 正常なGuardスナップショットから、すべての関係する対象が非一致と証明できる → ALLOW＋緊急通知。
- `UNKNOWN`: Guard未同期、epoch不整合、破損、不完全なpath/op、必要な照合方式未対応 → DENY＋緊急通知。

3秒待機・送信失敗はいずれも共通の`teal_guard_failure_decision(req, reason)`を通す。システムコールの割込み（`-EINTR`）は別途維持する。

## 5. Epoch・更新と障害時の保持

### 5.1 原子更新

1. `teald`がポリシーをコンパイルし、`effect: need_approval`全件から安全側のGuardスナップショットを生成する。
2. Kernel側で`GUARD_BEGIN(new_epoch, count)` → `GUARD_ADD(...)`を受信し、非公開のstaging snapshotを構築・検証する。
3. `GUARD_COMMIT`と既存の`POLICY_UPDATE`を**不可分な1トランザクション**として扱う。新Guardが完全でない場合、Epochは公開せず失敗を返す。
4. 完全なGuardとEpochを公開してからACKを返し、旧GuardはRCUで遅延解放する。
5. ポリシー更新中の障害では旧Guardを維持。Guard無しで新Epochだけが有効になることは禁止する。

**設計上の注意:** 現行`teal_current_epoch`はGuardとは独立した`atomic_t`であり、ポリシー更新時に先にEpochを公開している。この更新順序は変更する必要がある。読者が別世代のEpochとGuardを混在参照した場合は`UNKNOWN`扱いでDENYする。更新途中の要求が誤ってFail-Openしないことを優先する。

### 5.2 teald切断・再起動

現行コードのNetlink切断時処理は`teal_current_epoch = 0`としてFast Pathチケットを失効させる。これは維持してよい。一方、**Guardスナップショットは破棄しない**。Guardの世代は最後に正常にコミットされたポリシーを基準に保持し、`teal_current_epoch == 0`だけを理由にGuardを未同期扱いにしない。新しいGuardの完全コミットまでは前回のGuardを保守的に利用する。

ENFORCEモードへの移行は、Guardスナップショットの正常同期が条件。`0件READY`と`未同期`は厳密に区別する。

## 6. 実装箇所と現在のソースとの差分

- `teal_lsm.c`の`struct teal_request`に機械判定可能なop値、パス有効性/切り詰め情報を追加。現状は`action[16]`、`target[256]`、`new_target[256]`の文字列中心なので、**Guardが対象外と誤認しないために**入力の完全性フラグが必要。
- `teal_req_wait()`の3秒タイムアウト時の一律APPROVEを、Guard分類で返す方針に変更。
- `teal_wait_for_approval()`のNetlink送信失敗時の一律ALLOWも、同じGuard分類で変更。送信失敗の種類にかかわらず記録する。
- `teal_nl_recv_policy_update()`は現在Epoch確定とチケットフラッシュを行うだけで、Guardは持たない。Guardのstaging/COMMITと原子的に統合する。
- `teal_nl_notifier()`および`teal_nl_recv_register()`はGuardを破棄せず、既存のチケット失効とGuard保持を区別する。
- `teal_should_bypass_all()`等の既存バイパスはGuard照合以前に動作する箇所がある。**Guardは現行LSMで捕捉されSlow Pathへ進んだ要求の障害時分類**であり、あらゆるバイパスの安全性を保証するものではない。MPA対象のフック到達性、特権バイパスは別途検証する。

## 7. 検索方式とメモリ上限

初版はスナップショット内の固定配列を線形検索してよい。照合は原則タイムアウト・送信失敗時にしか行われず、まず正しさが優先される。ただし、DoS対策として件数・パス長・総使用メモリに明確な上限を設け、超過時はGuard生成・登録に失敗しENFORCE移行を許さない。多数ルールや障害時の頻発アクセスが問題になったら、Exactをハッシュ、PrefixをTrieへ最適化する。途中で静かにルールを切り捨ててはならない。

## 8. 独立緊急通知への引継ぎ

Guard自体は同期的にメールを送らない。`TIMEOUT`・`SEND_FAILURE`・`UNREGISTERED_GUARD`・`EPOCH_MISMATCH`ごとに、Kernel ring-buffer等へrate-limitedログと非失効カウンタを記録する。次段階で別プロセス`teal-watchd`が読み出し、最初の異常を即時通知、後続を集約する。`teald`の内部キューやNetlink TXには依存させない。root侵害時には同一ホストの監視プロセスも妨害され得るため、外部からのheartbeat監視を追加候補とする。

## 9. 最低限のVM試験

1. `need_approval`, Exact `/etc/hostname`, READ：teald停止後3秒でDENY。
2. 同ファイルのWRITE（保護ルール無し）：teald停止後3秒でALLOW、緊急イベント記録。
3. 別ファイルREAD（保護ルール無し）：3秒でALLOW、緊急イベント記録。
4. 正常なtealdからの明示的APPROVE/DENY、およびMPA承認済みチケット：従来どおり。
5. `max_uses`超過・TTL切れ：Fast Path Miss後、Guardを正しく適用。
6. RENAMEの移動元・移動先の各一致、存在しない移動先の一致。
7. Prefix・Glob上位集合、パス切り詰め/取得失敗は絶対にFail-Openしない。
8. Guard未初期化、Guard転送途中の切断、Epoch切替の競合：旧Guard保持または安全側拒否。
9. teald切断・再接続後もGuardが残存し、完全な新Guardがコミットされた時だけ切り替わる。
10. MPAチケット申請者と実行者のUIDが異なっても、通常のpolicy.subjectに適合すれば使用可能。

## 10. 未解決・次工程で具体化する事項

- ネットワークGuardの厳密なCIDR・Port照合（初版はCONNECT全体を安全側で保護）。
- パス正規化とマウント名前空間・bind mount・hardlink・symlinkの整合性。曖昧ならUNKNOWNとして拒否するが、完全防御にはオブジェクト同一性評価の追加が必要。
- Kernelに残る既存の特権バイパスがMPA対象へ到達し得る範囲。
- Guard登録/更新を誰が認証・承認できるか（現在のNetlink登録資格だけではroot侵害に対する完全性を保証できない）。
- 更新のACK仕様、部分転送、通信順序、カーネルメモリ上限と制限値の確定。

**実装順序案:** (1) 構造体・3値分類ヘルパー → (2) Guard stagingとEpoch同時コミット → (3) タイムアウト／送信失敗への統合 → (4) 独立通知 → (5) VM障害試験。

> 注：これは設計資料であり、カーネルの変更パッチではない。実装時には現行Git HEADとの照合・ビルド・KUnit/VM試験が必要。
