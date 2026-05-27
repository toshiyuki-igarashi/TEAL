// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, IsTerminal, Read};
use std::path::Path;
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};
use std::time::Duration; // sleep のために追加
use std::thread;         // sleep のために追加

use anyhow::{Context, Result}; // エラーハンドリング用
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use clap::{Parser, Subcommand, ValueEnum};

use teal_policy_engine::types::Effect;

/// ユーザー入力を相対時間 ("15m", "2h") または 絶対時間 (RFC3339) として解釈するパーサー
fn parse_time(s: &str) -> std::result::Result<DateTime<Utc>, String> {
    // 1. まず相対時間 (例: "15m", "2h") としてパースを試みる
    if let Ok(duration) = humantime::parse_duration(s) {
        // 現在時刻から指定された期間を引く
        let chrono_duration = chrono::Duration::from_std(duration)
            .map_err(|e| format!("Duration conversion error: {}", e))?;
        return Ok(Utc::now() - chrono_duration);
    }
    
    // 2. 次に絶対時間 (例: "2024-03-17T10:00:00Z") としてパースを試みる
    if let Ok(sys_time) = humantime::parse_rfc3339_weak(s) {
        return Ok(DateTime::<Utc>::from(sys_time));
    }

    Err(format!("Invalid time format: '{}'. Use relative (e.g., '15m') or absolute time.", s))
}

/// ログスキーマ定義

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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_context: Option<EnvironmentContext>,

    // 3. Authorization (Slow Path: Proof, Fast Path: Ref)
    #[serde(flatten)]
    pub auth_info: AuthInfo,
}

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
pub struct EnvironmentContext {
    pub tty: String,
    #[serde(default)]
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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_ticket: Option<IssuedTicketInfo>,
}

/// MPA（多人数承認）の進行状態および最終的な証跡
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MpaState {
    // --- 1. Requirements (承認要件) ---

    /// 承認しきい値 (例: 2)
    /// ※ ロジック判定用には u32 が必須。ログ出力で "2-of-3"
    pub threshold: u32,

    /// 承認可能なロールのセット (例: {"admin", "sre_lead"})
    /// ※ ここに含まれるロールを持つユーザーのみが approvals に追加できる
    pub approver_roles: HashSet<String>,

    /// 必須ロール (例: {"security_manager"})
    /// ※ ここにあるロールが approvals 内に揃わないと完了しない (AND条件)
    pub required_roles: HashSet<String>,


    // --- 2. Current State & Evidence (承認の事実) ---

    /// 承認済みアクションのリスト <key: uid, value: Action詳細>
    pub approvals: HashMap<String, ApproverAction>,


    // --- 3. Final Result (暗号学的証拠) ---

    /// 集約されたBLS署名 (Aggregated Signature) (圧縮形式 96bytes)
    /// - None: 承認進行中
    /// - Some: 承認完了 (このバイト列が Ticket に埋め込まれる)
    #[serde(default, with = "option_hex")]
    pub aggregated_signature: Option<Vec<u8>>,
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

// チケット情報の定義
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IssuedTicketInfo {
    pub ticket_id: String, // "T-xxxx..."
    pub ttl_sec: u64,      // 3600 など
}

/// 承認アクションの記録
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApproverAction {
    /// 承認者ユーザー名
    /// ここでは汎用性を高めるため String としています (例: "1001" や "alice")
    #[serde(rename = "user")] // JSON出力時は "user" というキー名にする
    pub account: String,

    /// 承認時のロール (例: "ops_admin")
    pub role: String,

    /// 承認日時
    #[serde(rename = "ts")] // JSON出力時は "ts" (timestamp)
    pub approved_at: DateTime<Utc>,

    /// 認証方式
    pub method: String,

    /// 承認時のコメント/メモ (任意)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "note")] // JSON出力時は "note"
    pub comment: Option<String>,

    /// 個別のBLS署名シェア (圧縮形式 96bytes)
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

// --- ヘルパーモジュール ---
mod option_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => hex::decode(s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// ログファイルの初期化とリーダの作成
pub struct LogReader {
    reader: BufReader<File>,
}

impl LogReader {
    /// 指定されたパスから JSONL ファイルをオープンし、リーダを初期化する
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        // 1. 指定された JSONL ファイルをオープンする
        // 非破壊読み取り（読み取り専用）を徹底
        let file = File::open(&path)
            .with_context(|| format!("Failed to open log file: {:?}", path.as_ref()))?;

        // 2. 行単位のバッファ付きリーダを作成する
        // これにより、数GBのログでも1行ずつメモリに読み込む「ストリーム処理」が可能になる
        Ok(Self {
            reader: BufReader::new(file),
        })
    }

    /// 行単位でイテレートし、各行を処理する (Phase 1 の基盤)
    pub fn read_lines(self) -> io::Lines<BufReader<File>> {
        self.reader.lines()
    }
}

/// チケットインデックスの定義
/// チケットIDをキーに、発行時のコンテキストを保持する
type TicketIndex = HashMap<String, TicketMetadata>;

#[derive(Debug, Clone)]
pub struct TicketMetadata {
    original_path: String, // syscall_context.object.path から取得
//    rule_id: String,       // policy_eval.rule_id から取得
//    subject_path: String,  // syscall_context.subject.path から取得
}

/// 表示詳細レベルの定義
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum OutputMode {
    /// 必要最小限の情報のみを表示
    /// (Time, User, Action, Target, Result)
    ///
    Brief,

    /// 開発者向けの情報を追加表示
    /// (Brief + RuleID, TicketID, Epoch, Applet)
    ///
    Debug,

    /// 調査用の全情報を展開して表示
    /// (Debug + Args, Hash, LSM Label, SSH Context)
    ///
    Trace,
}

pub fn process_log_line(line: &str, index: &mut TicketIndex) -> anyhow::Result<AuditLogEntry> {
    // 1. デシリアライズ
    let entry: AuditLogEntry = serde_json::from_str(line)?;

    // 2. インデックスの更新（内部状態の変更のみに専念）
    match entry.log_type {
        LogType::InteractiveDecision | LogType::AccessAllowed => {
            if let AuthInfo::SlowPath { ref policy_eval, .. } = entry.auth_info {
                if let Some(ref ticket_info) = policy_eval.issued_ticket {
                    let meta = TicketMetadata {
                        original_path: entry.syscall_context.object.path.clone(),
//                        rule_id: policy_eval.rule_id.clone(),
//                        subject_path: entry.syscall_context.subject.path.clone(),
                    };
                    index.insert(ticket_info.ticket_id.clone(), meta);
                }
            }
        }
        LogType::TicketExpired => {
            if let AuthInfo::FastPath { ref ticket_context } = entry.auth_info {
                index.remove(&ticket_context.ticket_id); // メモリ解放
            }
        }
        _ => {}
    }

    // 3. パースしたデータを呼び出し元に返す
    Ok(entry)
}

fn header_output(mode: OutputMode) {
    match mode {
        OutputMode::Brief => {
            println!("TIME,USER,ACTION,TARGET,RESULT,RULE_ID");
        }
        OutputMode::Debug => {
            println!("TIME,LOG_TYPE,USER,ACTION,TARGET,ARGS,RESULT,RULE_ID,TICKET,EPOCH,PROG,SCRIPT,APPLET");
        }
        OutputMode::Trace => {
            eprintln!("[TODO] Trace mode will be implemented soon.");
        }
    }
}

fn format_output(entry: &AuditLogEntry, index: &TicketIndex, mode: OutputMode) {
    let target_path = if entry.log_type == LogType::TicketConsumed {
        if let AuthInfo::FastPath { ref ticket_context } = entry.auth_info {
            index.get(&ticket_context.ticket_id)
                .map(|m| m.original_path.as_str())
                .unwrap_or("UNKNOWN (Expired or Lost)")
        } else {
            "ERROR"
        }
    } else {
        &entry.syscall_context.object.path
    };

    // --- TTY判定と色付け ---
    let raw_result = extract_result(entry);
    
    // 出力先がターミナル(画面)かどうかを判定
    let is_tty = std::io::stdout().is_terminal();

    let display_result = if is_tty {
        // 画面出力の場合は色付け（ANSIエスケープシーケンス）
        match raw_result.as_str() {
            "ALLOW" => format!("\x1b[32mALLOW\x1b[0m"),         // 緑色
            "DENY" => format!("\x1b[31mDENY\x1b[0m"),           // 赤色
            "FAST PATH" => format!("\x1b[33mFAST PATH\x1b[0m"), // 黄色
            _ => raw_result,
        }
    } else {
        // ファイルへのリダイレクト時は色付けなしの純粋な文字列
        raw_result
    };

    match mode {
        OutputMode::Brief => {
            // 時間は to_rfc3339() で出力すると表計算ソフトでのパースが安定します
            println!("{},{},{},\"{}\",{},{}",
                entry.ts.to_rfc3339(),
                entry.syscall_context.user,
                entry.syscall_context.action.replace(",", " "),
                target_path,
                display_result,
                extract_rule_id(entry)
            );
        }
        OutputMode::Debug => {
            // ARGS などスペースを含む可能性がある列はダブルクォートで囲む
            println!("{},{},{},{},\"{}\",\"{}\",{},{},{},{},{},{},{}",
                entry.ts.to_rfc3339(),
                extract_log_type(entry),
                entry.syscall_context.user,
                entry.syscall_context.action.replace(",", " "),
                target_path,
                extract_args_short(entry).replace("\"", "\"\""), // CSVエスケープ処理
                display_result,
                extract_rule_id(entry),
                extract_ticket_id(entry),
                0, // extract_epoch(entry),
                extract_subject_path(entry),
                extract_script(entry),
                extract_applet(entry)
            );
        }
        OutputMode::Trace => {}
    }
}

// ログタイプ（Enum）をCSV出力用の文字列（SCREAMING_SNAKE_CASE）に変換する
fn extract_log_type(entry: &AuditLogEntry) -> &'static str {
    match entry.log_type {
        LogType::InteractiveDecision => "INTERACTIVE_DECISION",
        LogType::AccessAllowed => "ACCESS_ALLOWED",
        LogType::AccessDenied => "ACCESS_DENIED",
        LogType::TicketIssued => "TICKET_ISSUED",
        LogType::TicketConsumed => "TICKET_CONSUMED",
        LogType::TicketExpired => "TICKET_EXPIRED",
        LogType::NotManaged => "NOT_MANAGED",
    }
}

fn extract_rule_id(entry: &AuditLogEntry) -> &str {
    // 抽出ロジックの例
    match &entry.auth_info {
        // 1. Slow Path (InteractiveDecision, AccessAllowed, AccessDenied)
        // AuthInfo::SlowPath バリアントから policy_eval を取り出し、その rule_id を参照する
        AuthInfo::SlowPath { policy_eval, .. } => {
            &policy_eval.rule_id
        },

        // 2. Fast Path (TicketConsumed, TicketExpired)
        // 判定結果が存在しないため、ご要望に基づき "-" を返す
        AuthInfo::FastPath { .. } => {
            "-"
        },
    }
}

fn extract_result(entry: &AuditLogEntry) -> String {
    match &entry.auth_info {
        // Fast Path の場合: チケットを使用して実行された＝自動的に許可(キャッシュヒット)
        AuthInfo::FastPath { .. } => {
            "FAST PATH".to_string() 
        }
        // Slow Path の場合: ポリシーエンジンによる判定結果（Effect::Allow または Deny）を返す
        AuthInfo::SlowPath { policy_eval, .. } => {
            // ※ decision (Effect enum) が Display や Debug を実装している前提です
            // 例: Effect::Allow なら "ALLOW", Effect::Deny なら "DENY" に変換
            format!("{:?}", policy_eval.decision).to_uppercase()
        }
    }
}

fn extract_ticket_id(entry: &AuditLogEntry) -> String {
    match &entry.auth_info {
        // FastPathの場合: 消費したチケットIDを返す
        AuthInfo::FastPath { ticket_context } => {
            ticket_context.ticket_id.clone()
        }
        // SlowPathの場合: チケットが発行されていればそのIDを、なければ "-" を返す
        AuthInfo::SlowPath { policy_eval, .. } => {
            if let Some(issued) = &policy_eval.issued_ticket {
                issued.ticket_id.clone()
            } else {
                "-".to_string()
            }
        }
    }
}

// 実行プログラム名の抽出
fn extract_subject_path(entry: &AuditLogEntry) -> &str {
    &entry.syscall_context.subject.path
}

// スクリプト名の抽出 (存在しない場合は "-")
fn extract_script(entry: &AuditLogEntry) -> &str {
    entry.syscall_context.subject.script_path.as_deref().unwrap_or("-")
}

// アプレット名の抽出 (存在しない場合は "-")
fn extract_applet(entry: &AuditLogEntry) -> &str {
    entry.syscall_context.subject.applet.as_deref().unwrap_or("-")
}

// Argsの抽出（短縮版）
fn extract_args_short(entry: &AuditLogEntry) -> String {
    if let Some(args) = &entry.syscall_context.subject.args {
        // 例: 30文字で切り詰める
        if args.len() > 30 {
            format!("{}...", &args[..27])
        } else {
            args.clone()
        }
    } else {
        "-".to_string()
    }
}

/// プロファイリングにおける集計用の複合キー
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ProfileKey {
    pub user: String,
    pub subject_program: String, // 実行元バイナリパス
    pub origin_applet: String,
    pub object_path: String,     // 対象パス (またはプレフィックス)
    pub action: String,          // 操作 (Ops)
}

/// プロファイリングターゲット 
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum ProfileTarget {
    AllowDraft,
    AntiStorm,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreApprovalDefaults {
    pub ttl_sec_default: u64,
    pub ttl_sec_max: u64,
}

// ポリシードラフトのルート構造体
#[derive(Serialize, Deserialize, Clone)]
pub struct ProfiledPolicyDraft {
    pub version: String,
    
    // 省略可能なトップレベルフィールドを追加
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_effect: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_reason: Option<String>,
    
    pub ttl_minutes: u32,
    pub sweep_minutes: u32,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_approval_defaults: Option<PreApprovalDefaults>,
    
    pub rules: Vec<ProfiledRule>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfiledRule {
    pub id: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>, // annotate_reason 用に追加

    pub subject: SubjectObj,
    pub object: ObjectObj,
    pub action: ActionObj,
    pub effect: String,
    
    // 以下、特定のモードでのみ出力したいフィールドは Option にして skip_serializing_if を使う
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_level: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<usize>,
    
    pub ttl_sec: u64,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_profile: Option<TicketProfileObj>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SubjectObj {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    
    pub origin_program: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_applet: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ObjectObj {
    pub path: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ActionObj {
    pub ops: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TicketProfileObj {
    pub silent_io: bool,
    pub inherit: bool,
}

/// "READ, WRITE" のようなカンマ区切り文字列を Vec<String> に展開する
fn parse_ops(action_str: &str) -> Vec<String> {
    action_str.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// ルール集約のキーとなる条件（opsを外す）
#[derive(Hash, Eq, PartialEq, Clone)]
struct MergeKey {
    origin_program: String,
    origin_applet: Option<String>,
    user: Option<String>,
    effect: String,
    audit_level: Option<String>,
}

pub fn optimize_rules(rules: Vec<ProfiledRule>, annotate_reason: bool) -> Vec<ProfiledRule> {
    // 1. Grouping
    let mut groups: HashMap<MergeKey, Vec<ProfiledRule>> = HashMap::new();

    for rule in rules {
        let key = MergeKey {
            origin_program: rule.subject.origin_program.clone(),
            origin_applet: rule.subject.origin_applet.clone(),
            user: rule.subject.user.clone(),
            effect: rule.effect.clone(),
            audit_level: rule.audit_level.clone(),
        };
        groups.entry(key).or_insert_with(Vec::new).push(rule);
    }

    let mut optimized_rules = Vec::new();

    // 2 & 3. ソートと包含チェック
    for (_, mut group_rules) in groups {
        // パス長が短い順（昇順）、かつ、opsの数が多い順（降順）にソート
        group_rules.sort_by(|a, b| {
            let len_a = a.object.path.trim_start_matches("prefix:").trim_start_matches("glob:").len();
            let len_b = b.object.path.trim_start_matches("prefix:").trim_start_matches("glob:").len();
            
            len_a.cmp(&len_b)
                .then_with(|| b.action.ops.len().cmp(&a.action.ops.len()))
        });

        let mut kept_rules: Vec<ProfiledRule> = Vec::new();

        for current_rule in group_rules {
            let current_path = current_rule.object.path.clone();
            let mut is_shadowed = false;

            for kept_rule in &mut kept_rules {
                let kept_path = &kept_rule.object.path;

                // --- 1. パスの包含チェック ---
                let is_path_shadowed = if kept_path == &current_path {
                    true        // パスが完全に同じ場合
                } else if kept_path.starts_with("prefix:") {
                    let base_prefix = kept_path.trim_start_matches("prefix:");
                    let target_path = current_path.trim_start_matches("prefix:").trim_start_matches("glob:");
                    target_path.starts_with(base_prefix) // プレフィックスに包含されている場合
                } else {
                    false
                };

                // --- 2. Action (ops) の包含チェック ---
                // 現在のルールのすべてのopが、保持側ルールのopsに含まれているか（部分集合か）
                let is_ops_shadowed = current_rule.action.ops.iter()
                    .all(|op| kept_rule.action.ops.contains(op));

                // 両方包含されていれば、このルールは完全に不要（Shadowed）
                if is_path_shadowed && is_ops_shadowed {
                    is_shadowed = true;
                    
                    // 包含された旨を記録（annotate_reason が有効な場合）
                    if annotate_reason {
                        let new_reason = match &kept_rule.reason {
                            Some(r) => format!("{} (Merged with narrower paths/ops)", r),
                            None => "Merged with narrower paths/ops".to_string(),
                        };
                        kept_rule.reason = Some(new_reason);
                    }
                    break;
                }
            }

            if !is_shadowed {
                kept_rules.push(current_rule);
            }
        }
        optimized_rules.extend(kept_rules);
    }

    // --- IDの重複チェックとユニーク化 ---
    let mut seen_ids: HashMap<String, usize> = HashMap::new();
    for rule in &mut optimized_rules {
        let count = seen_ids.entry(rule.id.clone()).or_insert(0);
        if *count > 0 {
            // 重複があった場合、元のIDに "-1", "-2" のようにサフィックスを付与
            rule.id = format!("{}-{}", rule.id, count);
        }
        *count += 1;
    }

    // 4. 管理者の視認性を高める 4段階ソート
    optimized_rules.sort_by(|a, b| {
        a.subject.origin_program.cmp(&b.subject.origin_program)
            .then_with(|| a.subject.origin_applet.cmp(&b.subject.origin_applet))
            .then_with(|| a.object.path.cmp(&b.object.path))
            .then_with(|| a.subject.user.cmp(&b.subject.user))
    });

    optimized_rules
}

/// プロファイリング結果からポリシードラフトを生成し、標準出力へ書き出す
pub fn generate_profile_json(
    profile_counts: HashMap<ProfileKey, usize>,
    target: ProfileTarget,
    threshold: usize,
    optimize: bool,
) {
    eprintln!("[INFO] Starting heuristic abstraction...");

    let mut generated_rules: Vec<ProfiledRule> = Vec::new();

    // --- 1. 抽象化推論とルールの生成 ---
    for (key, count) in profile_counts {
        // Anti-Storm モード時の閾値チェック
        if target == ProfileTarget::AntiStorm && count < threshold {
            continue;
        }

        // パスの抽象化推論 (Heuristic Abstraction)
        // ※実装例: /tmp/ 等の一時ディレクトリへのアクセスをプレフィックス化する
        let mut final_path = key.object_path.clone();
        if final_path.contains("/tmp/") || final_path.contains("/var/run/") {
            if let Some(idx) = final_path.rfind('/') {
                final_path = format!("prefix:{}", &final_path[..idx + 1]);
            }
        }

        // Subjectの組み立て (存在しない場合はNoneにして出力から消す)
        let subject_obj = SubjectObj {
            user: if key.user.is_empty() || key.user == "-" { None } else { Some(key.user.clone()) },
            origin_program: key.subject_program.clone(),
            origin_applet: if key.origin_applet.is_empty() || key.origin_applet == "-" {
                                None
                            } else {
                                Some(key.origin_applet.clone())
                            },
        };

        // ルールIDの自動生成
        let rule_prefix = match target {
            ProfileTarget::AllowDraft => "allow",
            ProfileTarget::AntiStorm => "suppress",
        };
        let prog_name = key.subject_program.split('/').last().unwrap_or("unknown");
        let rule_id = format!("auto_{}_{}_{}", rule_prefix, prog_name, generated_rules.len());

        // Action (ops) の配列化
        let ops_list = parse_ops(&key.action);

        // ターゲットに応じたルールの組み立て
        let rule = match target {
            ProfileTarget::AllowDraft => ProfiledRule {
                id: rule_id,
                subject: subject_obj,
                object: ObjectObj { path: final_path },
                action: ActionObj { ops: ops_list },    // 展開したVecをセット
                effect: "allow".to_string(),
                audit_level: None,
                max_uses: None,
                ttl_sec: 3600,                          // デフォルト 1時間
                ticket_profile: None,
                reason: Some("Auto-generated allow draft".to_string()),
            },
            ProfileTarget::AntiStorm => ProfiledRule {
                id: rule_id,
                subject: subject_obj,
                object: ObjectObj { path: final_path },
                action: ActionObj { ops: ops_list },        // 展開したVecをセット
                effect: "allow".to_string(),
                audit_level: Some("silent".to_string()),    // ログを抑制
                max_uses: Some(10000),                      // キャッシュ回数を極端に長く
                ttl_sec: 86400,                             // 1日
                ticket_profile: Some(TicketProfileObj {
                    silent_io: true,
                    inherit: true,
                }),
                reason: Some(format!("Auto-generated suppress rule (count: {})", count)),
            },
        };

        generated_rules.push(rule);
    }

    // --- 2. 包含マージの実行 (最適化オプション有効時) ---
    if optimize {
        let before_count = generated_rules.len();
        generated_rules = optimize_rules(generated_rules, true); 
        let after_count = generated_rules.len();
        
        if before_count != after_count {
            eprintln!("[INFO] Optimization applied: {} rules merged/removed. ({} -> {})", 
                      before_count - after_count, before_count, after_count);
        }
    }

    // --- 3. 管理者の視認性を高める 4段階ソート ---
    generated_rules.sort_by(|a, b| {
        a.subject.origin_program.cmp(&b.subject.origin_program)
            .then_with(|| a.subject.origin_applet.cmp(&b.subject.origin_applet))
            .then_with(|| a.object.path.cmp(&b.object.path))
            .then_with(|| a.subject.user.cmp(&b.subject.user))
    });

    // --- 4. TEAL v1.3 スキーマ準拠の JSON オブジェクト出力 ---
    let draft = ProfiledPolicyDraft {
        version: "1.3".to_string(),
        
        default_effect: Some("allow".to_string()),
        default_reason: Some("No matching rule; default allow.".to_string()),
        
        ttl_minutes: 60,
        sweep_minutes: 5,
        
        pre_approval_defaults: Some(PreApprovalDefaults {
            ttl_sec_default: 600,
            ttl_sec_max: 900,
        }),
        
        rules: generated_rules,
    };

    let json_output = serde_json::to_string_pretty(&draft)
        .expect("Failed to serialize generated rules");

    // 標準出力へ書き出し (リダイレクト用)
    println!("{}", json_output);
    eprintln!("[INFO] Profile generation complete.");
}

#[derive(Parser)]
#[command(name = "teal-logview")]
#[command(about = "TEAL System Audit Log & Debugging Utility", long_about = None)]
struct Cli {
    /// 監査ログファイル (JSONL形式) へのパス
    #[arg(short, long, default_value = "/var/log/teal/audit.jsonl")]
    file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// ログ履歴の閲覧・フィルタリング
    View {
        /// 指定した時間以降のログを表示 (例: "15m", "2h", "2024-03-17T10:00:00Z")
        #[arg(long, value_parser = parse_time)]
        since: Option<DateTime<Utc>>,

        /// 指定した時間までのログを表示
        #[arg(long, value_parser = parse_time)]
        until: Option<DateTime<Utc>>,

        /// 特定のチケットID(T-xxxxxx)に関連する全ログを抽出
        #[arg(short, long)]
        ticket: Option<String>,

        /// 特定のポリシー世代(Epoch)のログに絞り込む
        #[arg(short, long)]
        epoch: Option<u32>,

        /// 拒否(ACCESS_DENIED)されたログのみを表示
        #[arg(long)]
        deny_only: bool,

        /// 特定の正規化パスへのアクセスをフィルタリング
        #[arg(short, long)]
        path: Option<String>,

        /// 出力詳細レベル
        #[arg(short, long, value_enum, default_value_t = OutputMode::Brief)]
        mode: OutputMode,
    },

    /// リアルタイムのログ監視
    Tail {
        #[arg(short, long, value_enum, default_value_t = OutputMode::Debug)]
        mode: OutputMode,
    },

    /// 特定のパスに対する現在の適用ルールとキャッシュ状態の確認
    Status {
        /// 確認対象のファイルパス
        path: String,
        
        /// 詳細なマッチングプロセス（優先順位など）を表示
        #[arg(short, long)]
        verbose: bool,
    },

    /// ログから実績ベースでポリシールールのドラフト(JSON)を自動生成する
    Profile {
        /// プロファイリングの対象期間 (例: "1h", "1d")
        #[arg(long, value_parser = parse_time)]
        since: Option<DateTime<Utc>>,

        /// 生成のターゲット（目的）を指定
        /// "allow-draft": DENYログから許可ルールを作成 / "anti-storm": 頻出ログから鎮静化ルールを作成
        #[arg(long, value_enum, default_value_t = ProfileTarget::AllowDraft)]
        target: ProfileTarget, 

        /// anti-storm時、ルール生成の対象とするログ発生回数の閾値
        #[arg(long, default_value_t = 1000)]
        threshold: usize,

        /// 生成されたルールの包含関係を評価し、冗長なルールを自動的に集約（削除）する
        #[arg(long, default_value_t = false)]
        optimize: bool,

        /// 拒否(ACCESS_DENIED)されたログのみをプロファイリングの対象とする
        #[arg(long)]
        deny_only: bool,
    },

    /// ポリシーファイルの冗長なルールを評価し、包含関係にあるルールを集約・最適化する
    Optimize {
        /// 最適化対象のポリシーファイル (JSON)。指定がない場合は標準入力(stdin)から読み込む
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,

        /// 結合されたルールの `reason` フィールドに「Merged with ...」等の追記を行うか
        #[arg(long, default_value_t = false)]
        annotate_reason: bool,
    },
}

fn resolve_target_path(entry: &AuditLogEntry, index: &TicketIndex) -> String {
    if entry.log_type == LogType::TicketConsumed {
        if let AuthInfo::FastPath { ref ticket_context } = entry.auth_info {
            index.get(&ticket_context.ticket_id)
                .map(|m| m.original_path.clone())
                .unwrap_or_else(|| "UNKNOWN (Expired or Lost)".to_string())
        } else {
            "ERROR".to_string()
        }
    } else {
        entry.syscall_context.object.path.clone()
    }
}

fn main() -> Result<()> {
    // 1. 仕様書に合わせて clap で定義した CLI 引数を解析
    let cli = Cli::parse();

    // 2. 解析した引数からログファイルのパスを取得
    let log_path = cli.file.clone();

    // 3. サブコマンドに応じた処理の分岐
    match cli.command {
        Commands::View { since, until, ticket, epoch, deny_only, path, mode } => {
            eprintln!("Starting log analysis: {}", log_path.display());
            
            let log_reader = LogReader::new(&log_path)?;
            let mut index: TicketIndex = HashMap::new();
            
            if let Some(ref t) = ticket {
                eprintln!("Filtering by Ticket ID: {}", t);
            }
            header_output(mode);

            // 4. 行単位のループ処理
            for line in log_reader.read_lines() {
                let line = line.context("Error reading line from log file")?;

                match process_log_line(&line, &mut index) {
                    Ok(entry) => {
                        // --- 1. 時間フィルタリング (要件 2.3) ---
                        // 指定時間より前ならスキップ
                        if let Some(since_time) = since {
                            if entry.ts < since_time { continue; }
                        }
                        // 指定時間より後ならスキップ
                        if let Some(until_time) = until {
                            if entry.ts > until_time { continue; }
                        }

                        // --- 2. ticket フィルタリング ---
                        if let Some(ref target) = ticket {
                            let entry_ticket = extract_ticket_id(&entry);
                            // ログが持つチケットIDと、指定されたチケットIDが一致しない場合はスキップ
                            if &entry_ticket != target {
                                continue;
                            }
                        }
                        
                        // --- 3. path フィルタリング ---
                        if let Some(ref filter_path) = path {
                            // 1. 操作対象(Object)のパスを解決 
                            // (TicketConsumedの場合はインデックスから復元する)
                            let target_path = resolve_target_path(&entry, &index);

                            // 2. 実行バイナリ(Subject)のパス
                            let subject_path = extract_subject_path(&entry);

                            // 3. 対象パス(Object)と実行パス(Subject)のどちらにも一致しない場合はスキップ
                            if target_path != *filter_path && subject_path != filter_path {
                                continue;
                            }
                        }

                        // --- 4. deny-only フィルタリング ---
                        if deny_only {
                            // extract_result の結果が "DENY" でなければスキップ
                            if extract_result(&entry) != "DENY" {
                                continue;
                            }
                        }
                        
                        // --- 5. epoch フィルタリング ---
                        if let Some(_e) = epoch {
                            // epoch がeでなければスキップ
                        }
                        
                        // ユーザーが指定した mode (Brief / Debug / Trace) を渡して出力
                        format_output(&entry, &index, mode);
                    },
                    Err(msg) => eprintln!("[ERROR] {}", msg),
                }
            }
        },
        Commands::Tail { mode } => {
            eprintln!("Starting live log monitoring (Tail mode): {}", log_path.display());

            // 1. ファイルをオープン
            let mut file = File::open(&log_path)
                .with_context(|| format!("Failed to open log file: {:?}", log_path))?;

            // 2. ファイルポインタを末尾(EOF)に移動させる (過去のログをスキップ)
            file.seek(SeekFrom::End(0))
                .context("Failed to seek to end of file")?;

            // 3. リーダとインデックスを初期化
            let mut reader = BufReader::new(file);
            let mut index: TicketIndex = HashMap::new();
            
            // ヘッダーを一度だけ出力
            header_output(mode);

            let mut line_buffer = String::new();

            // 4. 無限ループでファイルの追記を監視
            loop {
                line_buffer.clear();

                // 1行読み込みを試みる
                match reader.read_line(&mut line_buffer) {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            // EOF (末尾) に到達した。新しい行が書き込まれるまで少し待つ。
                            // 100ms スリープしてCPU負荷を抑える
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }

                        // 新しい行が読み込めたので処理
                        // read_line は改行文字も含んでしまうため、trim() しておく
                        let trimmed_line = line_buffer.trim();
                        if trimmed_line.is_empty() {
                            continue;
                        }

                        match process_log_line(trimmed_line, &mut index) {
                            Ok(entry) => {
                                // Tailモードではリアルタイムで出力する
                                format_output(&entry, &index, mode);
                            },
                            Err(msg) => eprintln!("[ERROR] Failed to process live log: {:?}", msg),
                        }
                    }
                    Err(e) => {
                        eprintln!("[ERROR] I/O error while tailing log: {}", e);
                        // 一時的なエラーかもしれないので、少し待って再試行
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            }
        },
        Commands::Status { path, verbose } => {
            // Status サブコマンドの処理
            eprintln!("Checking status for path: {}", path);
            if verbose {
                eprintln!("Verbose mode enabled.");
            }
        },
        Commands::Profile { since, target, threshold, optimize, deny_only } => {
            let log_reader = LogReader::new(&cli.file)?;
            let mut index = TicketIndex::new();
            
            // 集計用のHashMap (キー: ProfileKey, 値: 発生回数)
            let mut profile_counts: HashMap<ProfileKey, usize> = HashMap::new();

            eprintln!("[INFO] Starting profile generation. Target: {:?}", target);

            // 共通の reader を利用
            for line_result in log_reader.reader.lines() {
                let line = line_result.context("Error reading line from log file")?;
                if line.trim().is_empty() { continue; }

                // process_log_line 内でデシリアライズと index への追加が自動で行われる
                let entry = match process_log_line(&line, &mut index) {
                    Ok(e) => e,
                    Err(_) => continue, // パースエラーはスキップ
                };

                // 1-1. 時間フィルタリング (--since)
                if let Some(since_time) = since {
                    if entry.ts < since_time {
                        continue; // 指定時間より前のログは破棄
                    }
                }

               // 1-2. deny-only フィルタリング (--deny-only)
                if deny_only {
                    // extract_result の結果が "DENY" でなければスキップ
                    if extract_result(&entry) != "DENY" {
                        continue;
                    }
                }

                // 2. ターゲットに応じたフィルタリング
                match target {
                    ProfileTarget::AllowDraft => {
                        // User指摘反映: AUDITモード考慮
                        // 結果がDENY、または適応ルールがない(空文字 or "-")ものを対象とする
                        let result = extract_result(&entry);
                        let rule_id = extract_rule_id(&entry);
                        
                        if result != "DENY" && !rule_id.is_empty() && rule_id != "-" {
                            continue; 
                        }
                    }
                    ProfileTarget::AntiStorm => {
                        // Anti-Noise Mode: すべてのログを対象にする (フィルタなし)
                    }
                }

                // 3. 複合キーの作成と集計
                // ヘルパー関数でパスを解決 (String型で返る)
                let target_path = resolve_target_path(&entry, &index);

                let key = ProfileKey {
                    user: entry.syscall_context.user.clone(),
                    subject_program: extract_subject_path(&entry).to_string(),
                    origin_applet: extract_applet(&entry).to_string(),
                    object_path: target_path,
                    action: entry.syscall_context.action.clone(),
                };

                // カウントアップ
                *profile_counts.entry(key).or_insert(0) += 1;
            }

            // --- ここまでが集計 (Aggregation) フェーズ ---

            eprintln!("[INFO] Aggregation complete. Found {} unique patterns.", profile_counts.len());

            // 次のステップ: Heuristic Abstraction (抽象化推論) と JSON Generation (出力)
            generate_profile_json(profile_counts, target, threshold, optimize);
        },
        Commands::Optimize { file, annotate_reason } => {
            // ファイル指定がなければ標準入力から読み込む
            let input_data = if let Some(path) = file {
                std::fs::read_to_string(path).context("Failed to read policy file")?
            } else {
                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer).context("Failed to read from stdin")?;
                buffer
            };

            // JSONデシリアライズ
            let draft: ProfiledPolicyDraft = serde_json::from_str(&input_data)
                .context("Failed to parse policy JSON")?;

            // 最適化の実行
            let optimized_rules = optimize_rules(draft.rules, annotate_reason);

            // 新しいドラフトの構築
            let optimized_draft = ProfiledPolicyDraft {
                rules: optimized_rules,
                ..draft // version や ttl_minutes などは引き継ぐ
            };

            // JSONシリアライズして標準出力へ
            let json_output = serde_json::to_string_pretty(&optimized_draft)
                .context("Failed to serialize optimized rules")?;
            
            println!("{}", json_output);
        },
    }

    Ok(())
}

