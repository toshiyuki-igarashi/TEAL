// src/evidence/schema.rs
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

use teal_policy_engine::types::Effect;
use crate::types::MpaState;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")] // JSON出力時は "ACCESS_DENIED" のようになる
pub enum LogType {
    /// 1. Slow Path: ユーザー空間での判定 (MPAや承認プロセスを含む)
    /// ※ PolicyEvalResult を詳細に含む
    InteractiveDecision,

    /// 2. Slow Path: ポリシーによる自動許可 (承認プロセスなし)
    /// ※ InteractiveDecision と統合しても良いが、分けると「自動」か「手動」か区別しやすい
    AccessAllowed,

    /// 3. Slow Path: ポリシーによる拒否、または不正なリクエストによる拒否
    AccessDenied,

    /// 4. Internal: カーネルに対してチケットを発行した (TEAL -> Kernel)
    /// ※ 「許可」と「チケット発行」のタイムラグや失敗を追跡するために重要
    TicketIssued,

    /// 5. Fast Path: カーネルキャッシュによる高速通過 (Kernel -> Audit)
    /// ※ ユーザー空間デーモンを経由せず処理されたもの
    TicketConsumed,

    /// 6. Internal: 未使用のまま期限切れとなったチケット (Sweeper)
    TicketExpired,

    /// 7. Internal: ポリシーの対象外
    NotManaged,
}

// 共通ヘッダー的なトップレベル構造
#[derive(Serialize, Deserialize, Debug)]
pub struct AuditLogEntry {
    pub ver: String,
    pub id: String,
    #[serde(rename = "type")]
    pub log_type: LogType,
    pub ts: DateTime<Utc>,
    pub host: String,

    // 1. Reality (共通)
    pub syscall_context: SyscallContext,

    // 2. Context (Slow Path: 必須, Fast Path: 省略可)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_context: Option<EnvironmentContext>,

    // 3. Authorization (Slow Path: Proof, Fast Path: Ref)
    #[serde(flatten)]
    pub auth_info: AuthInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SyscallContext {
    pub uid: u32,
    pub user: String,
    pub pid: u32,
    pub action: String,
    pub subject: SubjectInfo,
    pub object: ObjectInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubjectInfo {
    pub path: String, // 実行バイナリ (例: /bin/bash, /usr/bin/busybox)
    pub hash: String, // SHA-256
    
    // アプレット名 (例: busybox経由で実行された "ls")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet: Option<String>, 

    // スクリプトパス (例: bashで実行された "/opt/scripts/deploy.sh")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_path: Option<String>, 

    // 実際のコマンドライン引数 (例: "-u root --force")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>, 
}

/// 操作対象オブジェクト情報 (Object Information)
/// カーネルがアクセスしようとしたリソースの情報
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObjectInfo {
    /// オブジェクト種別 (例: "file", "directory", "char_dev", "socket")
    pub kind: String,

    /// 解決された絶対パス (例: "/etc/shadow")
    pub path: String,

    /// inode番号
    pub inode: u64,
}

impl Default for ObjectInfo {
    fn default() -> Self {
        Self {
            kind: "unknown".to_string(),
            path: "unknown".to_string(),
            inode: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnvironmentContext {
    pub tty: String,
    pub ssh_client: Option<String>,
    pub login_method: String, // "publickey", "unknown" etc.
}

// Slow Path と Fast Path で分岐する部分
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)] // JSONの構造に合わせてフラット化
pub enum AuthInfo {
    // Slow Path: 署名を含む
    SlowPath {
        policy_eval: PolicyEvalResult,
        mpa_proof: MpaState,
    },
    // Fast Path: チケット参照のみ
    FastPath {
        ticket_context: TicketRef,
    },
}

/// ポリシー評価結果 (Policy Evaluation Result)
/// どのルールに基づき、どのような権限が要求されたかを記録する。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PolicyEvalResult {
    /// 適用されたルールID / 名前 (例: "admin_ops_01")
    pub rule_id: String,

    /// マッチしたポリシーファイル名 (例: "20-files.yaml")
    /// ※ デフォルト拒否などの場合は "implicit_deny" 等が入る想定
    pub matched_file: String,

    /// 要求されたMPAレベル（必要承認数） (例: 2)
    pub mpa_level_required: u32,

    /// 判定結果 (ALLOW または DENY)
    pub decision: Effect,

    /// 発行されたチケット情報 (キャッシュ有効時のみ存在)
    /// None の場合 = キャッシュ無効 (ttl=0) または 拒否(Deny)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_ticket: Option<IssuedTicketInfo>,
}

impl Default for PolicyEvalResult {
    fn default() -> Self {
        Self {
            rule_id: "unknown".to_string(),
            matched_file: "unknown".to_string(),
            mpa_level_required: 0,
            decision: Effect::Deny,
            issued_ticket: None,
        }
    }
}

// チケット情報の定義
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IssuedTicketInfo {
    pub ticket_id: String, // "T-xxxx..."
    pub ttl_sec: u64,      // 3600 など
}

/// チケット参照 (Ticket Reference)
/// Fast Path において、承認の根拠となったチケット情報を記録する。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TicketRef {
    /// 使用されたチケットID
    /// ※ このIDをキーにして Slow Path ログを検索することで、元の署名へ到達できる
    pub ticket_id: String,

    /// 実行時点での残り使用回数 (uses_left)
    /// ※ 0 ならば無制限チケット、または使い切り後の状態
    pub uses_left: u32,

    /// 適用されているポリシー名 (または "cached")
    /// ※ チケット発行時に決定されたルール名
    pub policy_rule: String,
}
