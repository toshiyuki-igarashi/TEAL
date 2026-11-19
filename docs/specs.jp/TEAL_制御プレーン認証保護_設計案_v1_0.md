# TEAL 制御プレーンの認証・保護設計案 v1.0

**日付:** 2026-11-19  
**対象:** `teal_lsm.c` / `teal_module` / `teald` / Generic Netlink / 管理CLI  
**状態:** **設計案・未実装**。現行Git HEADは直接参照していない。共有済み`teal_lsm(20261119-041732).c`とStage 1/2パッチ、2026-11-19のQEMU試験結果に基づく。`/dev/teal`の現行Rustハンドラは未精査。

## 1. 目的と脅威モデル

**目的:** `root`が侵害されても、カーネル内のENFORCE、MPA Guard、MPA承認の強制力を維持し、侵害済みrootが偽tealdを登録したり正規tealdを乗っ取って、重要操作を無承認で許可できないようにする。

**攻撃者の想定:** ホスト上でUID 0、一般的なCAP_SYS_ADMIN/CAP_MAC_ADMIN/CAP_SYS_PTRACE等の権限を持つ。`teald`の停止・再起動、Netlink送受信、管理CLI操作、一般のファイル変更、プロセス操作を試みる。**カーネルの任意コード実行、検証済み起動チェーンの突破、外部の承認者秘密鍵の取得は原則スコープ外**とする。ただしrootからカーネルを改変できる通常の経路（モジュール挿入、kexec、BPF、`/dev/mem`など）は別途閉鎖が必要である。ホストrootに実質的なカーネル改変権限が残る構成では、この目標は保証できない。

**信頼の起点:** カーネルに固定または厳格に検証された信頼鍵・ポリシー、起動時の完全性（必要ならSecure/Measured Boot、IMA appraisal、dm-/fs-verity等）、およびホストから独立した人間承認用秘密鍵。**TGID・UID・パス・CAP・Netlink PortID・単なるハッシュ・TPM PCR値だけを単独の認証根拠にしない。**

## 2. 現行コードで確認できるリスク

1. `teal_nl_recv_register`: `CAP_MAC_ADMIN || CAP_SYS_ADMIN`、RX空き、TXの同TGIDを確認する。切断後、rootは偽RX/TXを登録し得る。
2. `teal_nl_check_authorized`: `init_net`と登録済みTX PortIDを確認する。**本物のtealdの識別証明ではない**。
3. `teal_should_bypass_current`: 登録済み`teal_daemon_tgid`と現在のTGIDが等しければ、すべての関連LSM判定をスキップする。偽REGISTERが成功するとGuardを迂回し得る。
4. READY/Guard SHA-256/Epochの照合は**状態整合性**であり、コマンド送信者の正当性やMPA承認の証明ではない。
5. カーネルが`MODE_SWITCH(0)`、`APPROVE`、`TICKET_ADD`、`POLICY_UPDATE`などの重要コマンドをTX登録主体に委任している。teald侵害時の独立した安全確認が必要。
6. 2026-11-19のQEMU試験で偽のPythonプロセスが`REGISTER`できることを確認済み。`READY`不正Epoch/不正SHAの拒否とRECOVERING中Guardの動作は合格。ただしREGISTER本人性は未解決。
7. `teal-cli register`（承認者公開鍵を`teald`に登録）とGeneric Netlink `TEAL_CMD_REGISTER`（デーモンRX/TX登録）は**別機能**。前者だけを強化しても偽デーモンは防げない。

## 3. 守るべき不変条件

- **I-1 登録認証:** RX REGISTERはカーネルが信頼できる実行ドメインからしか受け入れない。TXは同じ登録世代・実行主体に束縛する。rootのCAPだけでは登録を認めない。
- **I-2 バイパス縮小:** デーモンのTGIDが一致しても、保護対象のREAD/WRITE/UNLINK/RENAME/CONNECT等が全面免除されない。必要な制御プレーンI/Oだけ限定的・明示的に許可する。
- **I-3 ENFORCE固定:** root単独で`MODE_SWITCH(AUDIT)`や保護範囲縮小・Guard削除を実行できない。これらは独立した認可証拠をカーネルが検証する。
- **I-4 MPA強制:** GuardでMPA対象と分類されたREQの`APPROVE`と関連`TICKET_ADD`は、実際の要求内容・Epoch・期限等に束縛された正当なMPA承認なしには受け付けない。通常時も適用する。
- **I-5 接続寿命:** REGISTER世代・TGID・信頼実行コンテキストを送信時も照合し、exec・プロセス終了・RX/TX切断・FD流出・世代変更があればREADYを失効する。旧世代メッセージは無効。
- **I-6 障害時継続:** 認証失敗またはデーモン停止ではENFORCEを維持し、旧Guardによる`PROTECTED/UNKNOWN→DENY`を実行する。自動AUDIT移行しない。
- **I-7 回復可能性:** 正規のtealdは同じ信頼条件を満たして新Epochで再登録・同期・READY復旧できる。復旧不能時には事前に定義された独立のbreak-glass経路だけを使う。

## 4. 2種類の認証を分離

### 4.1 実行主体の認証（REGISTER）

**推薦モデル:** カーネルが、起動時に確立した保護済みの「TEAL trusted daemon domain」の実行プロセスだけをREGISTERに受け入れる。これは単なるバイナリパス検査ではなく、次のすべてを満たす必要がある。

1. **コード/設定の完全性:** 実行ファイル・必要な動的ライブラリ・起動パラメータ・ユニット設定・teald管理設定・ポリシーの信頼済みイメージ／署名を検証。IMA appraisalまたはfs-/dm-verityを選定し、検証鍵とポリシーをrootが差し替えられないよう固定。
2. **実行ドメイン:** TEAL LSM内で信頼済み実行のみに付与されるラベル／コンテキスト。UIDや任意のrootプロセスに付与させない。現行カーネル6.8.12およびTEALのtask->security利用との互換性を実装前に確認。
3. **稼働中の改変防止:** `ptrace`、`process_vm_writev`、`/proc/PID/mem`、`pidfd_getfd`、不正なFD引継ぎ、実行時ライブラリ／設定差替え、悪意ある`LD_PRELOAD`等を許可しない。`PR_SET_DUMPABLE=0`だけに頼らない。必要なLSMフック・systemd confinement・能力削減を組み合わせる。
4. **再接続:** 新しく正規実行・検証されたtealdにだけ、新REGISTERを許可する。起動時の唯一のPIDに固定するだけでは再起動できなくなる。
5. **毎コマンド確認:** `init_net`、現行TX PortID、RX/TXセッション世代、要求送信者の実行ドメイン、正しいTGIDと生存性を確認。Netlink FDが別TGIDに移されても有効にしない。

**注意:** 外部承認者によるチャレンジ署名やTPM鍵の使用を追加することはできるが、ホストrootがその署名を取得・中継できる経路が残ると「署名がある」だけでは本人性を保証しない。TPM PCRは一般に起動測定の根拠であり、*その時点で動いているtealdプロセスの未改変性*を単独で証明しない。

### 4.2 カーネル側の独立した管理命令認可

登録されたtealdであっても、**任意の高リスク操作を単独で許可できる主体としては扱わない**。

| Netlink/デバイスコマンド | 提案する追加制約 |
|---|---|
| REGISTER RX/TX | 信頼実行ドメイン＋世代・TGID束縛。CAPだけでは不可 |
| GUARD_STATUS | 適切な読み取り権限。状態照会に限定 |
| DAEMON_READY | 正規登録者＋同一世代＋Epoch/Guard SHA-256一致。従来の条件を維持 |
| DENY | 正規登録者のみ。非許可方向なのでMPA不要（DoS対策と監査は別途） |
| APPROVE | 通常要求は登録者。Guard対象の要求はカーネルがMPA証拠を独立検証 |
| TICKET_ADD | チケットを正規の承認済みREQと結び付け、Guard対象ならMPA証拠・スコープ・TTL・使用回数を検証。ワイルドカード権限を禁止または厳格化 |
| MODE_SWITCH(ENFORCE) | 正規登録者＋Guard READY＋ポリシー整合性 |
| MODE_SWITCH(AUDIT) | ENFORCE中は独立したMPA承認／break-glass証拠が必須 |
| GUARD_BEGIN/ADD/COMMIT | ENFORCE中は無承認でGuard範囲を変更しない。正規再接続時の同一digest再COMMITと、承認されたポリシー変更を区別 |
| GUARD_REUSE | 同一digest＋連続Epoch＋正規登録者。失効/再同期を監査 |
| PAM_SESSION_ADD/DEL | 正規登録者に限定。PAMイベントの真正性も別途保証 |
| `/dev/teal`の各ioctl等 | Netlinkと同じ責任分担で棚卸し。`START/STOP/JIT_ALLOW/REGISTER_DAEMON`等の代替経路を残さない |

**短期的な硬化:** 独立したMPA証拠を検証できるまでは、ENFORCE解除・Guard縮小等をカーネルで拒否するロックモードを試験用に設ける。これは既存STOP等の運用を変更するため、隔離VMでの検証と明示的なbreak-glass手順を前提とする。**単にNetlink PortIDを厳格化しただけではroot侵害耐性は完成しない。**

## 5. MPA認可証拠のデータモデル（概念）

カーネルがGuard対象操作に対する許可証拠として検証する署名付き構造の例：

```text
TEAL-MPA-PROOF/v1
  schema_version
  action_type (APPROVE | TICKET_ISSUE | ENFORCE_STOP | GUARD_REPLACE)
  boot_instance_id / freshness_nonce
  daemon_generation
  policy_epoch
  active_guard_sha256
  kernel_request_id または更新transaction_id
  canonical_action + canonical_object_identity + subject/context
  ticket_scope (対象/操作/実行主体/TTL/使用回数; 該当する場合)
  valid_until
  approvals[] = { approver_key_id, role, signature }
```

検証に必要な**承認者公開鍵・ロール集合・必要承認数・失効状態**は、侵害済みrootが自由に変更できないカーネル保護済み認可ポリシーから取得する。tealdがその場で通知したroleやthresholdを無条件に信用しない。

- 必ずドメイン分離・正規化シリアライズ・再利用防止・署名検証を行う。
- `APPROVE`はカーネルが保持する未完了REQと証拠の内容を厳密に結び付ける。
- `TICKET_ADD`は既に認可済みのREQ以上の権限を付与できない。単に署名済みの`ticket_id`があるだけでは足りない。
- 管理操作（STOP、Guard変更）の署名対象は変更前後のGuard/ポリシーダイジェスト、現在Epoch、操作理由・期限を含む。
- 既存のBLS集約署名をカーネルで直接検証するか、検証可能な別の署名形式とするかは、**Linux 6.8.12に存在する検証APIと監査可能な実装**を確認してから決定する。新しいLinux用のCrypto APIが同じ形で6.8に存在すると仮定しない。
- カーネル署名検証が実装できない場合、別のrootから独立した検証主体（専用ハードウェア/TEE/隔離VMなど）を信頼境界として定義する。侵害可能な同一ホストの別プロセスへの単純移譲は独立検証ではない。

## 6. TGID全面バイパスの置換方針

現行の`teal_should_bypass_current()`による**登録TGIDの全面免除**を廃止する方向とする。tealdの再帰的な判定デッドロックを避けるために必要なI/Oは、カーネル内の**不変の最小許可ポリシー**で限定する。

- 対象を信頼済みtealdの、予め定義された監査ログ・管理ソケット・必要な設定読取・限定された外部承認サーバ接続等に絞る。
- READ/EXEC/CONNECT等を操作別に判断し、保護対象のREADや任意ファイル削除等への全体免除は認めない。
- 信頼ドメイン自体の実装不備によるバイパスを避けるため、まず各LSMフックがどこで`teal_should_bypass_all()`を呼ぶか棚卸しする。
- 未登録または偽REGISTER状態のプロセスは、この限定免除を得られない。
- 動作上どうしても自己参照する箇所があれば、正当化した個別操作・個別リソースだけを許可し、将来の一般化を防ぐユニットテストを用意する。

## 7. REGISTER/READY状態遷移（予定）

```text
[ENFORCE / Guard READY / teald切断]
       |
       | 信頼実行ドメインのREGISTERのみ認可
       v
[BOUND / RECOVERING / tickets invalid]
       |
       | Guard同一性確認・新Epoch COMMIT
       v
[BOUND / RECOVERING / Guard新Epoch]
       |
       | ワーカー開始、ポリシー固定、DAEMON_READY確認
       v
[BOUND / READY / ENFORCE]
```

偽REGISTER・不正TX・不正READYでは状態変更しない。切断・認証失敗時はENFORCE/Guardを保持し、チケット等を失効する。REGISTER以外の操作も、必要に応じて`teal_daemon_lifecycle_mutex`等の既存ロック下で再認証し、世代を照合する。FDを他プロセスに引き継いでソケットだけを生かすケースも防ぐ。

## 8. 推奨開発段階

**Phase A：攻撃面の棚卸しと契約定義（最優先）**
- 全Netlinkハンドラ、`teal_module`の`/dev/teal`コマンド、LSM bypass箇所を実コードで確認。
- 各操作をread-only／非許可操作／通常許可／MPA必須／緊急復旧に分類。
- `CAPだけのREGISTER`、偽TX、偽STOP、偽APPROVE、tealdプロセスメモリ改変を再現する隔離VMテストを準備。

**Phase B：登録とデーモンの実行ドメイン（カーネル＋起動環境）**
- 改竄防止されたバイナリ/設定の実行ドメイン設計とrootによる侵害経路閉鎖。
- REGISTERをその実行ドメインだけに限定、TXとコマンドを世代・TGID・実行ドメインに束縛。
- 正規の再起動・再登録は維持し、root偽REGISTERを拒否。

**Phase C：LSM全面バイパス縮小**
- tealdに必要な最小内部I/Oのみ静的・狭域Allow。全操作bypassを廃止。
- デッドロック回帰、RECOVERING/READY、MPA Guard READなどを再試験。

**Phase D：カーネル独立のMPA強制**
- ENFORCE降格、Guard縮小、保護対象APPROVE/TICKETに署名済みMPA証拠必須。
- カーネルの認可ポリシー/鍵の保護と更新・失効を設計。
- 署名の再利用、異なるREQへの横流し、部分一致、既承認範囲を超えるチケットを拒否。

**Phase E：起動・TPM・回復の強化**
- 署名済み起動チェーン・IMA / fs-verity / dm-verity・TPM quote・外部承認・独立監査等を統合。
- 物理コンソール等を前提としたbreak-glassを定義。root単独でのAUDIT解除・鍵更新を認めない。

## 9. 合格基準（隔離QEMU）

1. `teald`正常稼働中は偽RX REGISTERを拒否。停止後も、普通のroot PythonはREGISTERを拒否される。拒否によってEpoch/Guardが変わらない。
2. 信頼済みtealdは新Epochで再REGISTER、Guard COMMIT→DAEMON_READYを完了できる。
3. `teald`切断・偽REGISTER後もENFORCE維持。保護READはEACCES、非保護READはALLOW（従来の障害時Guard分類）。
4. PID/TGIDだけを偽装した処理、旧セッションのTX FD、FDを受け渡された別プロセス、偽証明/リプレイは拒否。
5. `teald`へのptrace、process_vm_writev、`/proc/PID/mem`、危険な共有ライブラリ注入が拒否される。
6. 正当なローカルrootであっても、独立MPA証拠のないENFORCE停止・Guard縮小・保護APPROVE・保護TICKETは拒否。
7. 正当な独立MPA証拠でのみ上述の操作が成功。要求内容・Epoch・期限・鍵・ロールなどが違えば失敗。
8. RECOVERING中の障害・ACK喪失・teald再起動でも防御が緩まない。
9. 負荷試験を含め、RX/TXのDrops、READY遷移、PAMセッション更新が既存レベルを悪化させない。

**既存の異常系Python試験に関する注意:** 今回の強化後は、偽のPythonプロセスがREGISTERできるという旧テストの前提が成立しなくなる。試験を削除するのではなく、認証拒否テストと、カーネル内KUnit／特別に隔離された試験ビルドでのGuard内部状態テストに分離する。製品ビルドに任意のテスト登録バイパスを残さない。

## 10. 未決事項と優先度

- **要確認:** 現行Rust `teal_module`の`/dev/teal`ハンドラ、`REGISTER_DAEMON`、`JIT_ALLOW`等が同じ承認境界にあるか。
- **要確認:** Linux 6.8.12 のIMA・LSMフック・暗号検証APIとTEAL standalone LSM構成の互換性。
- **要決定:** 信頼teald実行環境は「ホスト内のカーネル強制ドメイン」か「隔離VM/TEE/外部承認プロキシ」か。前者は性能と運用が有利だが、rootからのプロセス改変経路を閉じる実装範囲が大きい。
- **要決定:** MPA証拠をカーネルが直接検証するための署名形式（既存BLSとの関係）。
- **要決定:** 独立承認が得られない障害時の復旧・更新・break-glass（ENFORCE維持、保護操作拒否を初期値）。

## 11. 関連資料

- TEALシステム実装構成仕様書 v2.2：制御プレーン、MPA、TPM/IMAの構想（ただし一部の旧再接続記述は現実装と異なる）。
- Kernel-MPA/TEAL/TEAL-NET総合防御アーキテクチャ：7.2制御プレーンとデッドロック、7.3カーネル防御。
- TEAL MPA Guard Netlink Epoch同期設計 v1.0：登録済みTX PortIDのみでは侵害rootを排除できないという注記。
- Linux IMA appraisal: https://github.com/linux-integrity/ima-doc/blob/main/ima-concepts.rst
- Linux fs-verity: https://docs.kernel.org/filesystems/fsverity.html
- Linux lockdown: https://documentation.ubuntu.com/security/security-features/kernel-protections/
- Linux ptrace access checks: https://www.man7.org/linux/man-pages/man2/ptrace.2.html

---

**結論:** 本段階は設計のみ。特に「認証されたtealdだから高リスクAPPROVEを全面信用する」という状態を残すと、REGISTER認証だけを強化してもroot侵害耐性は成立しない。信頼済み実行ドメインと独立したMPA証拠検証の両方を最終要件とする。
