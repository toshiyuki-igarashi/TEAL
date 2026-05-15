// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::fmt;
use anyhow::{Result, anyhow};
use globset::Glob;

use crate::types::{Effect, AuditLevel};
use crate::errors::{CompileError, CompileWarnings};
use crate::raw::{RawPreApprovalDefaults, RawTicketProfile};

#[derive(Debug)]
pub struct CompiledPolicy {
    /// ポリシーバージョン（Raw の "1.2" 文字列はここで enum 化）
    pub version: PolicyVersion,

    /// 評価対象となるルール群（priority 昇順などに並び替え済み）
    pub rules: Vec<CompiledRule>,

    /// 管理対象パスの高速判定用インデックス
    pub scope: ManagedScopeIndex,

    /// Pre-Approval / JIT_ALLOW の既定値・上限（policy 最上位）
    pub pre_approval_defaults: CompiledPreApprovalDefaults,

    // ---- 互換・既存 decide() API 用 ----

    /// マッチしなかった場合のデフォルト action
    pub default_action: String,

    /// マッチしなかった場合の理由（ログ用）
    pub default_reason: String,
}

#[derive(Debug, Clone)]
pub struct CompiledPreApprovalDefaults {
    pub ttl_sec_default: u64,
    pub ttl_sec_max: Option<u64>,
}

impl From<&RawPreApprovalDefaults> for CompiledPreApprovalDefaults {
    fn from(r: &RawPreApprovalDefaults) -> Self {
        Self {
            ttl_sec_default: r.ttl_sec_default,
            ttl_sec_max: r.ttl_sec_max,
        }
    }
}

impl Default for CompiledPreApprovalDefaults {
    fn default() -> Self {
        Self {
            ttl_sec_default: 600,
            ttl_sec_max: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVersion {
    V1_2,
    V1_3,
}

#[derive(Debug, Clone, Default)]
pub struct ManagedScopeIndex {
    // ---- Object (対象パス) 用のインデックス ----
    pub exact_paths: HashSet<PathBuf>,
    pub prefixes: Vec<PathBuf>,
    pub globs: Vec<globset::GlobMatcher>,

    // ---- Subject (主体パス) 用のインデックス (SubjectOnlyルール用) ----
    pub subject_exact: HashSet<PathBuf>,
    pub subject_prefix: Vec<PathBuf>,
    pub subject_glob: Vec<globset::GlobMatcher>,
}

impl ManagedScopeIndex {
    pub fn union(&self, other: &Self) -> Self {
        // Object用のマージ
        let mut exact_paths = self.exact_paths.clone();
        exact_paths.extend(other.exact_paths.iter().cloned());
        let mut prefixes = self.prefixes.clone();
        prefixes.extend(other.prefixes.iter().cloned());
        let mut globs = self.globs.clone();
        globs.extend(other.globs.iter().cloned());

        // Subject用のマージ
        let mut subject_exact = self.subject_exact.clone();
        subject_exact.extend(other.subject_exact.iter().cloned());
        let mut subject_prefix = self.subject_prefix.clone();
        subject_prefix.extend(other.subject_prefix.iter().cloned());
        let mut subject_glob = self.subject_glob.clone();
        subject_glob.extend(other.subject_glob.iter().cloned());

        ManagedScopeIndex {
            exact_paths,
            prefixes,
            globs,
            subject_exact,
            subject_prefix,
            subject_glob,
        }
    }

    pub fn from_rules(rules: &[CompiledRule]) -> Self {
        let mut exact_paths = HashSet::new();
        let mut prefixes = Vec::new();
        let mut globs = Vec::new();

        let mut subject_exact = HashSet::new();
        let mut subject_prefix = Vec::new();
        let mut subject_glob = Vec::new();

        for r in rules {
            // 1. 通常ルールの場合：Objectのパスをインデックスに登録
            if r.rule_type != RuleType::SubjectOnly {
                if let Some(obj) = &r.object {
                    if let Some(pm) = &obj.path {
                        match pm {
                            PathMatcher::Exact(p) => { exact_paths.insert(p.clone()); },
                            PathMatcher::Prefix(p) => { prefixes.push(p.clone()); },
                            PathMatcher::Glob { matcher, .. } => { globs.push(matcher.clone()); },
                        }
                    }
                }
            }

            // 2. SubjectOnly ルールの場合：Subject (origin_program) のパスをインデックスに登録
            if r.rule_type == RuleType::SubjectOnly {
                if let Some(pm) = &r.subject.origin_program {
                    match pm {
                        PathMatcher::Exact(p) => { subject_exact.insert(p.clone()); },
                        PathMatcher::Prefix(p) => { subject_prefix.push(p.clone()); },
                        PathMatcher::Glob { matcher, .. } => { subject_glob.push(matcher.clone()); },
                    }
                }
            }
        }

        ManagedScopeIndex {
            exact_paths, prefixes, globs,
            subject_exact, subject_prefix, subject_glob,
        }
    }

    // ctx 全体を受け取るように変更
    pub fn is_request_managed(&self, ctx: &AccessContext) -> bool {
        // 1. まずアクセス先の Object パスが管理対象かチェック
        let obj_path = &ctx.object_path;
        if self.exact_paths.contains(obj_path) 
            || self.prefixes.iter().any(|p| obj_path.starts_with(p))
            || self.globs.iter().any(|g| g.is_match(obj_path)) 
        {
            return true;
        }

        // 2. Subject (origin_program) が SubjectOnly ルールの対象かチェック
        if let Some(prog) = &ctx.origin_program {
            if self.subject_exact.contains(prog) 
                || self.subject_prefix.iter().any(|p| prog.starts_with(p))
                || self.subject_glob.iter().any(|g| g.is_match(prog)) 
            {
                return true;
            }
        }

        false
    }
}

// 優先度を表現するEnum（数値が大きいほど優先）
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Specificity {
    Low = 0,    // Glob, Prefix など
    Medium = 1, // ObjectPath が Exact
    High = 2,   // Subject(Prog+Script) も ObjectPath も Exact
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub rule_type: RuleType, 
    pub effect: Effect,
    pub ttl_sec: u64,
    pub max_uses: u32,

    pub subject: SubjectMatcher,
    pub object: Option<ObjectMatcher>,
    pub action_match: ActionMatcher,

    pub approval: Option<ApprovalMatcher>,
    pub audit: AuditCfg,

    /// Pre-approval (JIT_ALLOW) configuration for this rule.
    pub pre_approval: CompiledPreApproval,

    pub audit_level: AuditLevel,
    pub out_reason: String,

    pub ticket_profile: TicketProfile,
}

impl CompiledRule {
    pub fn default_with_reason(effect: Effect, reason: &str) -> Self {
        Self {
            id: "default_rule".to_string(),
            rule_type: RuleType::Standard,
            effect,
            ttl_sec: 0,
            max_uses: 1,
            subject: SubjectMatcher {
                uid: None,
                required_roles: HashSet::new(),
                origin_program: None,
                origin_script: None,
                origin_applet: None,
            },
            object: Some(ObjectMatcher {
                path: Some(PathMatcher::Prefix(PathBuf::new())),
                kind: None,
            }),
            action_match: ActionMatcher::Any,
            approval: None,
            audit: AuditCfg {
                tag: None,
                log_level: None,
            },
            pre_approval: CompiledPreApproval {
                enabled: false,
            },
            audit_level: AuditLevel::Standard,
            out_reason: reason.to_string(),
            ticket_profile: TicketProfile{ flags: 0 },
        }
    }
}

impl CompiledRule {
    pub fn required_roles(&self) -> HashSet<String> {
        match &self.approval {
            Some(a) => a.required_roles.clone(),
            None => HashSet::new(),
        }
    }

    pub fn threshold(&self) -> u32 {
        match &self.approval {
            Some(a) => a.threshold,
            None => 0,
        }
    }

    pub fn calculate_specificity(&self) -> Specificity {
        // object が None、あるいは object.path が None の場合は false (Exactではない)
        let obj_exact = self.object.as_ref()
            .and_then(|obj| obj.path.as_ref())
            .map_or(false, |path| path.is_exact()); // PathMatcher::is_exact() がある前提
        
        // Subjectの評価
        let prog_exact = self.subject.origin_program.as_ref()
            .map_or(false, |p| p.is_exact());
            
        let script_exact = self.subject.origin_script.as_ref()
            .map_or(false, |p| p.is_exact());

        // 1. すべてがExactなら最高優先度
        if obj_exact && prog_exact && script_exact {
            return Specificity::High;
        }

        // 2. ObjectがExactなら中優先度
        if obj_exact {
            return Specificity::Medium;
        }

        // 3. それ以外 (subject_onlyでObjectがNoneのものや、Glob指定のもの) は低優先度
        Specificity::Low
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TicketProfile {
    pub flags: u32,
}

impl TicketProfile {
    pub fn from_raw(raw: &RawTicketProfile) -> Self {
        Self { flags: raw.to_u32() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Standard,
    SubjectOnly,
}

#[derive(Debug, Clone, Default)]
pub struct AuditCfg {
    pub tag: Option<String>,
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Clone)]
pub struct CompiledPreApproval {
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct SubjectMatcher {
    pub uid: Option<u32>,

    /// 要求主体が持つ roles の集合と、
    /// ルールが要求する roles の集合の関係
    pub required_roles: HashSet<String>,

    pub origin_program: Option<PathMatcher>,
    pub origin_script: Option<PathMatcher>,
    pub origin_applet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectMatcher {
    pub path: Option<PathMatcher>,
    pub kind: Option<ObjectKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    File,
    Dir,
    Socket,
    Pipe,
}

#[derive(Debug, Clone)]
pub enum PathMatcher {
    Exact(std::path::PathBuf),
    Prefix(std::path::PathBuf), // "/etc/teal.d/" 配下、など
    Glob { pattern: String, matcher: globset::GlobMatcher }, // "**/*.key" など
}

impl PathMatcher {
    pub fn compile_exact(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("path is empty".to_string());
        }

        let p = Path::new(s);

        if !p.is_absolute() {
            return Err(format!("path must be an absolute path: {}", s));
        }

        Ok(PathMatcher::Exact(PathBuf::from(p)))
    }

    pub fn is_exact(&self) -> bool {
        matches!(self, PathMatcher::Exact(_))
    }

    pub fn exact_path(&self) -> Result<PathBuf> {
        match self {
            PathMatcher::Exact(path) => Ok(path.clone()),
            _ => Err(anyhow!("path is not Exact (path type {:?})", self)),
        }
    }

    /// 文字列のプレフィックスを見て Exact / Prefix / Glob を判定してコンパイルする
    pub fn parse(input: &str) -> Result<Self, String> {
        if let Some(pattern) = input.strip_prefix("glob:") {
            // "glob:" 始まりの場合 -> Glob
            let glob = Glob::new(pattern)
                .map_err(|e| format!("Invalid glob pattern '{}': {}", pattern, e))?;
            let matcher = glob.compile_matcher();
            Ok(PathMatcher::Glob {
                pattern: pattern.to_string(),
                matcher,
            })
        } else if let Some(path_str) = input.strip_prefix("prefix:") {
            // "prefix:" 始まりの場合 -> Prefix
            Ok(PathMatcher::Prefix(PathBuf::from(path_str)))
        } else {
            // それ以外 -> Exact (既存互換)
            Ok(PathMatcher::Exact(PathBuf::from(input)))
        }
    }
}

impl fmt::Display for PathMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathMatcher::Exact(path) => write!(f, "{}", path.display()),
            PathMatcher::Prefix(path) => write!(f, "prefix:{}", path.display()),
            PathMatcher::Glob { pattern, .. } => write!(f, "glob:{}", pattern),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Action {
    Read,
    Write,
    Execute,
    Delete,
    Unlink,
    Rename,
    Chmod,
    Chown,
    Connect,

    #[default]
    Unknown,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "FILE_READ",
            Action::Write => "FILE_WRITE",
            Action::Execute => "FILE_EXECUTE",
            Action::Delete => "FILE_DELETE",
            Action::Unlink => "FILE_UNLINK",
            Action::Rename => "FILE_RENAME",
            Action::Chmod => "FILE_CHMOD",
            Action::Chown => "FILE_CHOWN",
            Action::Connect => "NET_CONNECT",
            Action::Unknown => "UNKNOWN_ACTION",
        }
    }

    pub fn parse(s: &str) -> Result<Self, CompileError> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "read"  => Ok(Action::Read),
            "write" => Ok(Action::Write),
            "execute"  => Ok(Action::Execute),
            "delete" => Ok(Action::Delete),
            "unlink" => Ok(Action::Unlink),
            "rename" => Ok(Action::Rename),
            "chmod" => Ok(Action::Chmod),
            "chown" => Ok(Action::Chown),
            "connect" => Ok(Action::Connect),
            "unknown" => Ok(Action::Unknown),
            _ => Err(CompileError::UnknownAction(s.to_string())),
        }
    }

    pub fn to_mask(&self) -> u32 {
        match self {
            Action::Read => 1,
            Action::Write => 2,
            Action::Execute => 4,
            Action::Delete => 8,
            Action::Unlink => 16,
            Action::Rename => 32,
            Action::Chmod => 64,
            Action::Chown => 128,
            Action::Connect => 256,
            Action::Unknown => 512,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ActionMatcher {
    /// すべての action にマッチ（明示的に書いた場合のみ）
    Any,

    /// 指定された action のいずれかにマッチ（OR）
    OneOf(HashSet<Action>),
}

impl ActionMatcher {
    /// 含まれているアクションの中から、任意の1つを取得します。
    pub fn pick_one(&self) -> Action {
        match self {
            Self::OneOf(set) => {
                set.iter().next().cloned().unwrap_or(Action::Unknown)
            }
            Self::Any => Action::Unknown, 
        }
    }

    /// 含まれているアクションをu32へマッピング。
    pub fn to_u32(&self) -> u32 {
        match self {
            ActionMatcher::Any => u32::MAX,
            ActionMatcher::OneOf(actions) => {
                let mut op: u32 = 0;
                for action in actions.iter() {
                    op |= action.to_mask();
                }
                op
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalMatcher {
    /// 何人分の承認が必要か
    pub threshold: u32,

    /// 承認者が持っていなければならないロール条件
    pub required_roles: HashSet<String>,
}

#[derive(Debug)]
pub enum ApprovalSpec {
    /// 承認不要（即時 allow / deny）
    None,

    /// 承認が必要
    Require {
        /// 何人の承認が必要か（例: 2 → 二人承認）
        threshold: u32,

        /// 承認者に必要なロール
        required_roles: HashSet<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSpec {
    /// 監査しない（既定）
    None,

    /// 監査する（通常ログ）
    Log,

    /// 監査のみ（実行は止めない／deny しない）
    AuditOnly,
}

/// 実行時評価の入力（teald が Request から作る）
#[derive(Debug, Clone)]
pub struct AccessContext {
    pub uid: u32,
    pub subject_roles: HashSet<String>, // 要求主体が持つロール集合
    pub origin_program: Option<PathBuf>,
    pub origin_script: Option<PathBuf>,
    pub origin_applet: Option<String>,
    pub action: Action,
    pub object_path: PathBuf,
    pub object_kind: Option<ObjectKind>,
}

/// v1.2の evaluate() は「一致したルール」を返せば最も楽（互換が簡単）
#[derive(Debug)]
pub enum Decision<'a> {
    Pass,
    Matched(&'a CompiledRule),
    NoMatchManaged,
}

pub fn default_policy() -> CompiledPolicy {
    CompiledPolicy {
        version: PolicyVersion::V1_3,
        rules: vec![],
        scope: ManagedScopeIndex::default(),
        default_action: "deny".to_string(),
        default_reason: "Default policy".to_string(),
        pre_approval_defaults: CompiledPreApprovalDefaults::default(),
    }
}

#[derive(Debug)]
pub struct CompiledRoles {
    pub roles_file: PathBuf,
    pub deny_if_role_unknown: bool,
    pub known_roles: HashSet<String>,
    pub core: CompiledRolesCore, // 役割定義/割当など
}

impl CompiledRoles {
    pub fn is_known_role(&self, r: &str) -> bool {
        self.known_roles.contains(r)
    }
}

#[derive(Debug)]
pub struct CompiledRolesCore {
    /// Known role definitions (validated, de-duplicated)
    pub roles: RoleCatalog,

    /// Subject → roles mapping (uid / user)
    pub assignments: SubjectRoleIndex,

    /// Group → roles mapping (gid / group name)
    pub group_assignments: GroupRoleIndex,

    /// Default behavior
    pub defaults: CompiledDefaults,
}

#[derive(Debug)]
pub struct RoleCatalog {
    /// All known role names
    pub known_roles: HashSet<String>,

    /// Optional metadata for audit / UI / lint
    pub meta: HashMap<String, RoleMeta>,
}

#[derive(Debug)]
pub struct RoleMeta {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub permissions: Vec<String>, // v1.x では評価に未使用
}

#[derive(Debug, Default)]
pub struct SubjectRoleIndex {
    /// uid → roles
    pub uid_roles: HashMap<u32, HashSet<String>>,
}

#[derive(Debug, Default)]
pub struct GroupRoleIndex {
    pub gid_roles: HashMap<u32, HashSet<String>>,
    pub group_roles: HashMap<String, HashSet<String>>,
}

#[derive(Debug)]
pub struct CompiledDefaults {
    /// Roles applied when no explicit assignment exists
    /// AND semantics
    pub roles_for_unknown_user: HashSet<String>,

    /// Fail-closed if an unknown role is referenced
    pub deny_if_role_unknown: bool,
}

#[derive(Debug)]
pub struct CompiledBundle {
    pub policy: CompiledPolicy,
    pub roles: CompiledRolesCore,
    pub warnings: CompileWarnings,
}

