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
use std::collections::HashMap;
use std::time::Duration; // sleep のために追加
use std::thread;         // sleep のために追加

use anyhow::{Context, Result}; // エラーハンドリング用
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use clap::{Parser, Subcommand, ValueEnum};

use teald::evidence::schema::{AuditLogEntry, AuthInfo, LogType};


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
    pub original_path: String,      // syscall_context.object.path から取得
    pub new_path: Option<String>,   // RENAME時の移動先パスをキャッシュ
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
                        new_path: entry.syscall_context.object.new_path.clone(), 
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
            println!("TIME,USER,ACTION,TARGET,NEW_TARGET,RESULT,RULE_ID");
        }
        OutputMode::Debug => {
            println!("TIME,LOG_TYPE,USER,ACTION,TARGET,NEW_TARGET,ARGS,RESULT,RULE_ID,TICKET,EPOCH,PROG,SCRIPT,APPLET");
        }
        OutputMode::Trace => {
            eprintln!("[TODO] Trace mode will be implemented soon.");
        }
    }
}

fn format_output(entry: &AuditLogEntry, index: &TicketIndex, mode: OutputMode) {
    // resolve_target_path を使って、タプルで両方受け取る
    let (target_path, new_target_opt) = resolve_target_path(entry, index);
    
    // NEW_TARGET が無い場合(None)は "-" を出力する
    let new_target_str = new_target_opt.unwrap_or_else(|| "-".to_string());

    // --- TTY判定と色付け ---
    let raw_result = extract_result(entry);
    
    let is_tty = std::io::stdout().is_terminal();

    let display_result = if is_tty {
        match raw_result.as_str() {
            "ALLOW" => format!("\x1b[32mALLOW\x1b[0m"),         // 緑色
            "DENY" => format!("\x1b[31mDENY\x1b[0m"),           // 赤色
            "FAST PATH" => format!("\x1b[33mFAST PATH\x1b[0m"), // 黄色
            _ => raw_result,
        }
    } else {
        raw_result
    };

    match mode {
        OutputMode::Brief => {
            println!("{},{},{},\"{}\",\"{}\",{},{}",
                entry.ts.to_rfc3339(),
                entry.syscall_context.user,
                entry.syscall_context.action.replace(",", " "),
                target_path,
                new_target_str,
                display_result,
                extract_rule_id(entry)
            );
        }
        OutputMode::Debug => {
            println!("{},{},{},{},\"{}\",\"{}\",\"{}\",{},{},{},{},{},{},{}",
                entry.ts.to_rfc3339(),
                extract_log_type(entry),
                entry.syscall_context.user,
                entry.syscall_context.action.replace(",", " "),
                target_path,
                new_target_str,
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
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct ProfileKey {
    pub user: String,
    pub subject_program: String,    // 実行元バイナリパス
    pub origin_applet: String,
    pub object_path: String,        // 対象パス (またはプレフィックス)
    pub new_path: Option<String>,   // RENAME の宛先も集計のキー（ハッシュ計算の対象）に含める
    pub action: String,             // 操作 (Ops)
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
    pub rule_type: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    pub subject: SubjectObj,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectObj>,
    
    pub action: ActionObj,
    pub effect: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_level: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<usize>,
    
    pub ttl_sec: u64,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_profile: Option<TicketProfileObj>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_roles: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SubjectObj {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_program: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_applet: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectObj {
    pub path: String,

    // 値が None の場合は JSON 出力時にキーごとスキップする
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ActionObj {
    pub ops: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TicketProfileObj {
    pub silent_io: bool,
    pub inherit: bool,
    
    // 名無しオブジェクト用の高速化フラグ
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_nameless_ipc: Option<bool>, 
}

/// "READ, WRITE" のようなカンマ区切り文字列を Vec<String> に展開する
fn parse_ops(action_str: &str) -> Vec<String> {
    action_str.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// ルール集約のキーとなる条件
#[derive(Hash, Eq, PartialEq, Clone)]
struct MergeKey {
    effect: String,
    audit_level: Option<String>,
}

/// 実質的なパスの長さを計算するヘルパー（prefix: や glob: を除外）
fn effective_path_len(path: &str) -> usize {
    path.trim_start_matches("prefix:")
        .trim_start_matches("glob:")
        .len()
}

/// パスまたはプログラム名の包含関係を評価するヘルパー
fn json_path_contains(kept: &str, target: &str) -> bool {
    if kept == target {
        return true; // 完全一致
    }
    if kept.starts_with("prefix:") {
        let base_prefix = kept.trim_start_matches("prefix:");
        let target_clean = target.trim_start_matches("prefix:").trim_start_matches("glob:");
        return target_clean.starts_with(base_prefix); // プレフィックス前方一致
    }
    false
}

/// 包含関係にある冗長なルールをクリーンアップし、ポリシーを最小化する
pub fn optimize_rules(rules: Vec<ProfiledRule>, annotate_reason: bool) -> Vec<ProfiledRule> {
    // 1. Grouping（バケツを Effect と AuditLevel に）
    // これにより、プログラムを跨いだクロスグループ・マージを同一バケツ内で一元評価可能にする
    let mut groups: HashMap<MergeKey, Vec<ProfiledRule>> = HashMap::new();

    for rule in rules {
        let key = MergeKey {
            effect: rule.effect.clone(),
            audit_level: rule.audit_level.clone(),
        };
        groups.entry(key).or_insert_with(Vec::new).push(rule);
    }

    let mut optimized_rules = Vec::new();

    // 2 & 3. 多次元ソートと包含チェック
    for (_, mut group_rules) in groups {
        // バケツの中で「最も適用範囲が広くて強いルール」が必ず先頭に来るように多段ソート
        group_rules.sort_by(|a, b| {
            let path_a_len = a.object.as_ref().map(|o| effective_path_len(&o.path)).unwrap_or(0);
            let path_b_len = b.object.as_ref().map(|o| effective_path_len(&o.path)).unwrap_or(0);

            // new_path の長さ計算
            let npath_a_len = a.object.as_ref().and_then(|o| o.new_path.as_deref()).map(effective_path_len).unwrap_or(0);
            let npath_b_len = b.object.as_ref().and_then(|o| o.new_path.as_deref()).map(effective_path_len).unwrap_or(0);

            // ① 対象オブジェクトのパスが短い順
            path_a_len.cmp(&path_b_len)
                // ② 移動先のパスが短い順（昇順）
                .then_with(|| npath_a_len.cmp(&npath_b_len))
                // ③ プログラムの指定範囲が広い順
                .then_with(|| {
                    let prog_a_len = a.subject.origin_program.as_deref().map(effective_path_len).unwrap_or(0);
                    let prog_b_len = b.subject.origin_program.as_deref().map(effective_path_len).unwrap_or(0);
                    prog_a_len.cmp(&prog_b_len)
                })
                // ④ アプレット指定がないのが先
                .then_with(|| a.subject.origin_applet.cmp(&b.subject.origin_applet))
                // ⑤ ユーザー指定がない(None)のが先（昇順: None < Some）
                .then_with(|| a.subject.user.cmp(&b.subject.user))
                // ⑥ アクションの権限（ops）の数が多い順（降順）
                .then_with(|| b.action.ops.len().cmp(&a.action.ops.len()))
        });

        let mut kept_rules: Vec<ProfiledRule> = Vec::new();

        for current_rule in group_rules {
            let mut is_shadowed = false;

            for kept_rule in &mut kept_rules {
                // --- A. Subject (Program) の包含チェック ---
                let is_prog_shadowed = kept_rule.subject.origin_program.is_none() 
                    || (kept_rule.subject.origin_program.as_deref().unwrap_or("") == "") 
                    || json_path_contains(
                        kept_rule.subject.origin_program.as_deref().unwrap_or(""),
                        current_rule.subject.origin_program.as_deref().unwrap_or("")
                    );

                // --- B. Subject (Applet) の包含チェック ---
                let is_applet_shadowed = kept_rule.subject.origin_applet.is_none()
                    || kept_rule.subject.origin_applet == current_rule.subject.origin_applet;

                // --- C. Subject (User) の包含チェック ---
                let is_user_shadowed = kept_rule.subject.user.is_none()
                    || kept_rule.subject.user == current_rule.subject.user;

                // --- D. Object (Path) の包含チェック ---
                let is_path_shadowed = match (&kept_rule.object, &current_rule.object) {
                    (None, None) => true,
                    (Some(kept_obj), Some(curr_obj)) => {
                        // 1. 移動元(path) の包含チェック
                        let path_match = json_path_contains(&kept_obj.path, &curr_obj.path);

                        // 2. 移動先(new_path) の包含チェック
                        let new_path_match = match (&kept_obj.new_path, &curr_obj.new_path) {
                            // kept側に制限がない(None)なら包含成立
                            (None, _) => true, 
                            // kept側に制限があるのに、curr側にないなら包含不可
                            (Some(_), None) => false, 
                            // 両方ある場合はパス文字列の包含チェック
                            (Some(kept_np), Some(curr_np)) => json_path_contains(kept_np, curr_np),
                        };

                        path_match && new_path_match
                    },
                    _ => false,
                };

                // --- E. Action (ops) の包含チェック ---
                let is_ops_shadowed = current_rule.action.ops.iter()
                    .all(|op| kept_rule.action.ops.contains(op));

                // 全ての多次元包含関係が成立すれば、後続ルールは完全に不要（Shadowed）
                if is_prog_shadowed && is_applet_shadowed && is_user_shadowed && is_path_shadowed && is_ops_shadowed {
                    is_shadowed = true;
                    if annotate_reason {
                        let new_reason = match &kept_rule.reason {
                            Some(r) => {
                                if r.contains("Merged with narrower rules") {
                                    r.clone()
                                } else {
                                    format!("{} (Merged with narrower rules)", r)
                                }
                            }
                            None => "Merged with narrower rules".to_string(),
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

    // 4. ルールIDの重複回避（ユニーク化サフィックスの付与）
    let mut seen_ids: HashMap<String, usize> = HashMap::new();
    for rule in &mut optimized_rules {
        let count = seen_ids.entry(rule.id.clone()).or_insert(0);
        if *count > 0 {
            rule.id = format!("{}-{}", rule.id, count);
        }
        *count += 1;
    }

    // 5. 管理者の視認性を高める最終5段階ソート
    optimized_rules.sort_by(|a, b| {
        a.subject.origin_program.cmp(&b.subject.origin_program)
            .then_with(|| a.subject.origin_applet.cmp(&b.subject.origin_applet))
            .then_with(|| {
                let path_a = a.object.as_ref().map(|o| o.path.as_str()).unwrap_or("");
                let path_b = b.object.as_ref().map(|o| o.path.as_str()).unwrap_or("");
                path_a.cmp(path_b)
            })
            // new_path を加えたソート
            .then_with(|| {
                let npath_a = a.object.as_ref().and_then(|o| o.new_path.as_deref()).unwrap_or("");
                let npath_b = b.object.as_ref().and_then(|o| o.new_path.as_deref()).unwrap_or("");
                npath_a.cmp(npath_b)
            })
            .then_with(|| a.subject.user.cmp(&b.subject.user))
    });

    optimized_rules
}

// プロファイリング結果からポリシードラフトを生成し、標準出力へ書き出す
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
        // 元パスの抽象化
        let mut final_path = key.object_path.clone();
        if final_path.contains("/tmp/") || final_path.contains("/var/run/") {
            if let Some(idx) = final_path.rfind('/') {
                final_path = format!("prefix:{}", &final_path[..idx + 1]);
            }
        }

        // new_path (移動先) の抽象化
        let mut final_new_path = key.new_path.clone();
        if let Some(ref mut np) = final_new_path {
            if np.contains("/tmp/") || np.contains("/var/run/") {
                if let Some(idx) = np.rfind('/') {
                    *np = format!("prefix:{}", &np[..idx + 1]);
                }
            }
        }

        // --- 名無しオブジェクト(subject_only)の判定 ---
        let is_nameless = final_path == "-" || final_path.is_empty();

        let (rule_type_val, object_val, allow_nameless_val) = if is_nameless {
            (Some("subject_only".to_string()), None, Some(true))
        } else {
            // 通常の場合: object を付与する
            (None, Some(ObjectObj { 
                path: final_path.clone(),
                new_path: final_new_path, // 抽象化済みの new_path をセット
            }), None)
        };

        // Subjectの組み立て (存在しない場合はNoneにして出力から消す)
        let subject_obj = SubjectObj {
            user: if key.user.is_empty() || key.user == "-" { None } else { Some(key.user.clone()) },
            origin_program: if key.subject_program.is_empty() || key.subject_program == "-" {
                None
            } else {
                Some(key.subject_program.clone())
            },
            origin_applet: if key.origin_applet.is_empty() || key.origin_applet == "-" {
                None
            } else {
                Some(key.origin_applet.clone())
            },
            roles: None, // または既存の実装に合わせる
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
                rule_type: rule_type_val.clone(),
                subject: subject_obj.clone(),
                object: object_val.clone(),
                action: ActionObj { ops: ops_list.clone() },
                effect: "allow".to_string(),
                audit_level: None,
                max_uses: None,
                ttl_sec: 3600,
                // 名無しの場合のみ ticket_profile を生成し allow_nameless_ipc をセット
                ticket_profile: if is_nameless {
                    Some(TicketProfileObj {
                        silent_io: false,
                        inherit: false,
                        allow_nameless_ipc: allow_nameless_val,
                    })
                } else {
                    None
                },
                reason: Some("Auto-generated allow draft".to_string()),
                required_roles: None,
                threshold: None,
            },
            ProfileTarget::AntiStorm => ProfiledRule {
                id: rule_id,
                rule_type: rule_type_val, 
                subject: subject_obj,
                object: object_val,
                action: ActionObj { ops: ops_list },
                effect: "allow".to_string(),
                audit_level: Some("silent".to_string()),
                max_uses: Some(10000),
                ttl_sec: 86400,
                ticket_profile: Some(TicketProfileObj {
                    silent_io: true,
                    inherit: true,
                    allow_nameless_ipc: allow_nameless_val,
                }),
                reason: Some(format!("Auto-generated suppress rule (count: {})", count)),
                required_roles: None,
                threshold: None,
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

    // --- 3. 管理者の視認性を高める 5段階ソート --- 
    generated_rules.sort_by(|a, b| {
        a.subject.origin_program.cmp(&b.subject.origin_program)
            .then_with(|| a.subject.origin_applet.cmp(&b.subject.origin_applet))
            .then_with(|| {
                let path_a = a.object.as_ref().map(|o| o.path.as_str()).unwrap_or("");
                let path_b = b.object.as_ref().map(|o| o.path.as_str()).unwrap_or("");
                path_a.cmp(path_b)
            })
            // new_path でのソート (4段目)
            .then_with(|| {
                let npath_a = a.object.as_ref().and_then(|o| o.new_path.as_deref()).unwrap_or("");
                let npath_b = b.object.as_ref().and_then(|o| o.new_path.as_deref()).unwrap_or("");
                npath_a.cmp(npath_b)
            })
            // 5段目: ユーザー
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

fn resolve_target_path(entry: &AuditLogEntry, index: &TicketIndex) -> (String, Option<String>) {
    if entry.log_type == LogType::TicketConsumed {
        if let AuthInfo::FastPath { ref ticket_context } = entry.auth_info {
            index.get(&ticket_context.ticket_id)
                // 前回追加した m.new_path も一緒に clone して返す
                .map(|m| (m.original_path.clone(), m.new_path.clone()))
                .unwrap_or_else(|| ("UNKNOWN (Expired or Lost)".to_string(), None))
        } else {
            ("ERROR".to_string(), None)
        }
    } else {
        // 通常ログの場合は syscall_context から両方取得
        (
            entry.syscall_context.object.path.clone(),
            entry.syscall_context.object.new_path.clone(),
        )
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
                            let (target_path, new_path_opt) = resolve_target_path(&entry, &index);

                            // 2. 実行バイナリ(Subject)のパス
                            let subject_path = extract_subject_path(&entry);

                            // 各パスがフィルター文字列と一致するか判定
                            let match_target  = target_path == *filter_path;
                            let match_subject = subject_path == filter_path;
                            let match_new     = new_path_opt.as_ref() == Some(filter_path);

                            // 3. どれにも一致しない場合はスキップ (1つでも一致すれば表示)
                            if !match_target && !match_subject && !match_new {
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
                // ヘルパー関数でパスを解決 (タプルで受け取る)
                let (target_path, new_path_opt) = resolve_target_path(&entry, &index);

                let key = ProfileKey {
                    user: entry.syscall_context.user.clone(),
                    subject_program: extract_subject_path(&entry).to_string(),
                    origin_applet: extract_applet(&entry).to_string(),
                    object_path: target_path,
                    new_path: new_path_opt,
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

