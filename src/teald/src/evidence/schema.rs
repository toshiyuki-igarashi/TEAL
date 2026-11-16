// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde::de::Error as _;

use crate::types::MpaState;
use teal_policy_engine::types::Effect;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")] // JSON出力時は "ACCESS_DENIED" のようになる
pub enum LogType {
    /// 1. Slow Path: ユーザー空間での判定 (MPAや承認プロセスを含む)
    ///    ※ PolicyEvalResult を詳細に含む
    InteractiveDecision,

    /// 2. Slow Path: ポリシーによる自動許可 (承認プロセスなし)
    ///    ※ InteractiveDecision と統合しても良いが、分けると「自動」か「手動」か区別しやすい
    AccessAllowed,

    /// 3. Slow Path: ポリシーによる拒否、または不正なリクエストによる拒否
    AccessDenied,

    /// 4. Internal: カーネルに対してチケットを発行した (TEAL -> Kernel)
    ///    ※ 「許可」と「チケット発行」のタイムラグや失敗を追跡するために重要
    TicketIssued,

    /// 5. Fast Path: カーネルキャッシュによる高速通過 (Kernel -> Audit)
    ///    ※ ユーザー空間デーモンを経由せず処理されたもの
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

    pub epoch: u32, // 判定に適用されたポリシーのepoch

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

    // ログインコンテキスト (TTY情報)
    // チケット一覧取得APIなど、TTYが存在しないコンテキストではJSONから省略される
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_tty: Option<String>,
}

/// 操作対象オブジェクト情報 (Object Information)
/// カーネルがアクセスしようとしたリソースの情報
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObjectInfo {
    /// オブジェクト種別 (例: "file", "directory")
    pub kind: String,

    /// ソースパス (移動元)
    pub path: String,
    pub inode: u64,
    pub device_id: u64,

    /// 移動先パス (RENAME時のみ使用)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_inode: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_device_id: Option<u64>,
}

impl Default for ObjectInfo {
    fn default() -> Self {
        Self {
            kind: "unknown".to_string(),
            path: "unknown".to_string(),
            inode: 0,
            device_id: 0,
            new_path: None,
            new_inode: None,
            new_device_id: None,
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
// JSON出力形式は従来どおりフラットな untagged 形式とする。
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum AuthInfo {
    SlowPath {
        policy_eval: PolicyEvalResult,
        mpa_proof: MpaState,
    },
    FastPath {
        ticket_context: TicketRef,
    },
}

// untagged の自動導出は内部フィールドのデシリアライズエラーを
// 「どのバリアントにも一致しない」にまとめてしまう。
// 入力側は明示的にフィールドで判別し、原因となったエラーを伝える。
impl<'de> Deserialize<'de> for AuthInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        if value.get("policy_eval").is_some() || value.get("mpa_proof").is_some() {
            #[derive(Deserialize)]
            struct SlowPathFields {
                policy_eval: PolicyEvalResult,
                mpa_proof: MpaState,
            }

            let fields: SlowPathFields =
                serde_json::from_value(value).map_err(D::Error::custom)?;
            Ok(Self::SlowPath {
                policy_eval: fields.policy_eval,
                mpa_proof: fields.mpa_proof,
            })
        } else if value.get("ticket_context").is_some() {
            #[derive(Deserialize)]
            struct FastPathFields {
                ticket_context: TicketRef,
            }

            let fields: FastPathFields =
                serde_json::from_value(value).map_err(D::Error::custom)?;
            Ok(Self::FastPath {
                ticket_context: fields.ticket_context,
            })
        } else {
            Err(D::Error::custom(
                "AuthInfo: expected policy_eval+mpa_proof or ticket_context",
            ))
        }
    }
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

// 過去の実ログと同一構造を使い、JSONLの互換性を確認する回帰テスト。
#[cfg(test)]
mod auth_info_compatibility_tests {
    use super::*;

    #[test]
    fn deserialize_slow_path_log_with_unlimited_ticket() {
        let log = serde_json::json!({
            "ver":"1.5",
            "id":"be0e2a78-62c7-417f-99c3-685e6438d444",
            "type":"ACCESS_ALLOWED",
            "ts":"2026-11-16T08:16:51.720112813Z",
            "host":"cfsz5",
            "epoch":1,
            "syscall_context":{
                "uid":0,
                "user":"root",
                "pid":285,
                "action":"READ",
                "subject":{
                    "path":"/usr/lib/systemd/systemd-journald",
                    "hash":"HASH_NOT_CALCULATED",
                    "applet":"systemd-journal",
                    "script_path":"-",
                    "args":"/usr/lib/systemd/systemd-journald"
                },
                "object":{
                    "kind":"unknown",
                    "path":"/proc/507/cgroup",
                    "inode":3394,
                    "device_id":21,
                    "new_path":"-"
                }
            },
            "environment_context":{
                "tty":"/dev/null",
                "ssh_client":null,
                "login_method":"unknown"
            },
            "policy_eval":{
                "rule_id":"",
                "matched_file":"unknown",
                "mpa_level_required":0,
                "decision":"allow",
                "issued_ticket":{
                    "ticket_id":"T-000000000",
                    "ttl_sec":u64::MAX
                }
            },
            "mpa_proof":{
                "threshold":0,
                "required_roles":[],
                "approvals":{},
                "aggregated_signature":null
            }
        });

        let entry: AuditLogEntry =
            serde_json::from_value(log).expect("SlowPath log must deserialize");
        match entry.auth_info {
            AuthInfo::SlowPath { policy_eval, mpa_proof } => {
                assert_eq!(policy_eval.issued_ticket.unwrap().ttl_sec, u64::MAX);
                assert_eq!(mpa_proof.threshold, 0);
            }
            AuthInfo::FastPath { .. } => panic!("expected SlowPath"),
        }
    }

    #[test]
    fn deserialize_fast_path_log() {
        let log = serde_json::json!({
            "ver":"1.5",
            "id":"fast-path-test",
            "type":"TICKET_CONSUMED",
            "ts":"2026-11-16T08:47:31Z",
            "host":"cfsz5",
            "epoch":2,
            "syscall_context":{
                "uid":1000,
                "user":"toshiyuki",
                "pid":100,
                "action":"READ",
                "subject":{"path":"/usr/bin/cat","hash":"HASH_NOT_CALCULATED"},
                "object":{"kind":"file","path":"/etc/hostname","inode":1,"device_id":1}
            },
            "ticket_context":{
                "ticket_id":"T-000000001",
                "uses_left":4,
                "policy_rule":"test-ssh-ip-allow"
            }
        });
        let entry: AuditLogEntry =
            serde_json::from_value(log).expect("FastPath log must deserialize");
        match entry.auth_info {
            AuthInfo::FastPath { ticket_context } => {
                assert_eq!(ticket_context.ticket_id, "T-000000001");
            }
            AuthInfo::SlowPath { .. } => panic!("expected FastPath"),
        }
    }
}
