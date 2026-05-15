use std::collections::{HashMap, HashSet};
use std::path::Path;
use globset::Glob;

use crate::types::{Effect};
use crate::raw::{
    RawRolesV1, RawPolicyV13, RawRule, RawSubject, RawObject, RawAction, RawRoleDef,
    RawDefaults, RawAssignment, RawGroupAssignment, RawPreApprovalDefaults, RawPreApproval
};
use crate::ir::{
    CompiledRolesCore, RoleMeta, RoleCatalog, CompiledDefaults, CompiledPreApprovalDefaults,
    SubjectRoleIndex, GroupRoleIndex, CompiledRoles, CompiledPolicy, ManagedScopeIndex,
    PolicyVersion, CompiledRule, SubjectMatcher, ObjectMatcher, ActionMatcher,
    ApprovalMatcher, AuditCfg, PathMatcher, Action, CompiledPreApproval, RuleType, TicketProfile
};
use crate::errors::{CompileWarnings, CompileError};
use crate::util::name_to_uid;

pub fn compile_roles_v1(
    raw: RawRolesV1,
) -> Result<(CompiledRolesCore, CompileWarnings), CompileError> {
    let mut warnings = CompileWarnings::default();

    // 1) Destructure raw to move ownership
    // ここで raw を分解し、各フィールドの所有権を取り出します
    let RawRolesV1 {
        schema_version,
        roles,
        assignments,
        group_assignments,
        defaults,
    } = raw;

    // 2) Version check
    if schema_version != "1.0" {
        return Err(CompileError::UnsupportedVersion(schema_version));
    }

    // 3) Build Catalog (Consumes `roles` vec)
    let role_catalog = build_role_catalog(roles, &mut warnings)?;

    // 4) Compile Defaults (Consumes `defaults` struct)
    let compiled_defaults = compile_defaults(defaults, &role_catalog, &mut warnings)?;

    // 5) Compile Assignments (Consumes `assignments` vec)
    let compiled_assignments = compile_assignments(assignments, &role_catalog, &compiled_defaults, &mut warnings)?;

    // 6) Compile Group Assignments (Consumes `group_assignments` vec)
    let compiled_group_assignments = compile_group_assignments(group_assignments, &role_catalog, &compiled_defaults, &mut warnings)?;

    let compiled = CompiledRolesCore {
        roles: role_catalog,
        assignments: compiled_assignments,
        group_assignments: compiled_group_assignments,
        defaults: compiled_defaults,
    };

    Ok((compiled, warnings))
}

// -----------------------------------------------------------------------------
// Sub-routines
// -----------------------------------------------------------------------------

fn build_role_catalog(
    raw_roles: Vec<RawRoleDef>,
    warnings: &mut CompileWarnings,
) -> Result<RoleCatalog, CompileError> {
    let mut known_roles = HashSet::new();
    let mut meta = HashMap::new();

    for r in raw_roles {
        // RawRoleDef { name, description, tags, permissions } を move する
        let RawRoleDef {
            name: raw_name,
            description,
            tags,
            permissions,
        } = r;

        let (name, name_warnings) = normalize_name("role", &raw_name)?;
        for w in name_warnings { warnings.warn(w); }

        validate_role_name(&name)?;

        if !known_roles.insert(name.clone()) {
            return Err(CompileError::DuplicateRoleName(name));
        }

        // move された tags/permissions をそのまま関数に渡す (Zero-copy)
        let (deduped_tags, tag_warns) = dedup_vec_keep_order(tags, |x| x.clone());
        for w in tag_warns {
            warnings.warn(format!("duplicate tag removed: role={} tag={}", name, w));
        }

        let (deduped_perms, perm_warns) = dedup_vec_keep_order(permissions, |x| x.clone());
        for w in perm_warns {
            warnings.warn(format!("duplicate permission removed: role={} permission={}", name, w));
        }

        // Description logic
        let desc_final = description.and_then(|d| {
            let t = d.trim().to_string();
            if t.is_empty() {
                warnings.warn(format!("empty description normalized to None: role={}", name));
                None
            } else if t != d {
                warnings.warn(format!("description trimmed: role={}", name));
                Some(t)
            } else {
                Some(d)
            }
        });

        meta.insert(
            name.clone(),
            RoleMeta {
                description: desc_final,
                tags: deduped_tags,
                permissions: deduped_perms,
            },
        );
    }

    Ok(RoleCatalog { known_roles, meta })
}

fn compile_defaults(
    raw_defaults: RawDefaults,
    roles: &RoleCatalog,
    warnings: &mut CompileWarnings,
) -> Result<CompiledDefaults, CompileError> {
    // raw_defaults.roles_for_unknown_user (Vec<String>) を move して渡す
    let roles_for_unknown_user = resolve_roles(
        raw_defaults.roles_for_unknown_user,
        roles,
        true, // Defaults are strictly checked
        "defaults.roles_for_unknown_user",
        warnings,
    )?;

    if !raw_defaults.deny_if_role_unknown {
        warnings.warn("deny_if_role_unknown=false is unsafe (fail-open)".to_string());
    }

    Ok(CompiledDefaults {
        roles_for_unknown_user,
        deny_if_role_unknown: raw_defaults.deny_if_role_unknown,
    })
}

fn compile_assignments(
    raw_assignments: Vec<RawAssignment>,
    roles: &RoleCatalog,
    defaults: &CompiledDefaults,
    warnings: &mut CompileWarnings,
) -> Result<SubjectRoleIndex, CompileError> {
    let mut index = SubjectRoleIndex::default();

    for a in raw_assignments {
        let RawAssignment { uid, user, roles: raw_role_list } = a;

        // 1) uid/user の指定矛盾などは従来の正規化ロジックを使う
        let target = normalize_assignment_target(uid, user.as_deref())?;
        let context = target.context_string();

        // 2) roles の解決（ここは従来通り）
        let role_set = resolve_roles(
            raw_role_list,
            roles,
            defaults.deny_if_role_unknown,
            &context,
            warnings,
        )?;

        if role_set.is_empty() {
            warnings.warn(format!(
                "assignment has no effective roles after filtering; skipped: {}",
                context
            ));
            continue;
        }

        match target {
            AssignmentTarget::Uid(u) => {
                merge_role_set(
                    &mut index.uid_roles,
                    u,
                    role_set,
                    warnings,
                    &format!("assignments[uid={}]", u),
                );
            }
            AssignmentTarget::User(name) => {
                let ctx = format!("assignments[user={}]", name);

                match name_to_uid(&name) {
                    Ok(u) => {
                        // 変換できたので uid_roles に統合
                        merge_role_set(
                            &mut index.uid_roles,
                            u,
                            role_set,
                            warnings,
                            &format!("{ctx} -> uid={u}"),
                        );
                    }
                    Err(_) => {
                        // user -> uid が分からない場合は warning を出してスキップ
                        warnings.warn(format!(
                            "user assignment dropped because user not found : user={} context={}",
                            name, ctx
                        ));
                        continue;
                    }
                }
            }
        }
    }

    Ok(index)
}

fn compile_group_assignments(
    raw_group_assignments: Vec<RawGroupAssignment>,
    roles: &RoleCatalog,
    defaults: &CompiledDefaults,
    warnings: &mut CompileWarnings,
) -> Result<GroupRoleIndex, CompileError> {
    let mut index = GroupRoleIndex::default();

    if !raw_group_assignments.is_empty() {
        warnings.warn("group_assignments are parsed but not used yet".to_string());
    }

    for ga in raw_group_assignments {
        let RawGroupAssignment { gid, group, roles: raw_role_list } = ga;

        let target = normalize_group_assignment_target(gid, group.as_deref())?;
        let context = target.context_string();

        let role_set = resolve_roles(
            raw_role_list, // Vec<String> moved here
            roles,
            defaults.deny_if_role_unknown,
            &context,
            warnings,
        )?;

        if role_set.is_empty() {
            warnings.warn(format!(
                "group_assignment has no effective roles after filtering; skipped: {}",
                context
            ));
            continue;
        }

        match target {
            GroupAssignmentTarget::Gid(g) => merge_role_set(
                &mut index.gid_roles,
                g,
                role_set,
                warnings,
                &format!("group_assignments[gid={}]", g),
            ),
            GroupAssignmentTarget::Group(g) => {
                // 先に context 文字列を作成して g を借用する
                let context = format!("group_assignments[group={}]", g);
                
                merge_role_set(
                    &mut index.group_roles,
                    g, // ここで g (String) の所有権を移動(Move)させる
                    role_set,
                    warnings,
                    &context,
                )
            },
        }
    }
    Ok(index)
}

/// 共通ロジック: ロール名リスト(Raw)を受け取り、正規化・検証・重複排除を行って Set を返す
/// 入力の raw_role_refs (Vec<String>) は消費されるため、無駄なコピーが発生しない
fn resolve_roles(
    raw_role_refs: Vec<String>, 
    roles: &RoleCatalog,
    deny_if_unknown: bool,
    context: &str,
    warnings: &mut CompileWarnings,
) -> Result<HashSet<String>, CompileError> {
    let mut role_set = HashSet::new();

    for rr in raw_role_refs {
        // normalize_name は内部でString生成が必要なシグネチャのため、ここでは参照を渡す
        let (role, ws) = normalize_name(&format!("role_ref({})", context), &rr)?;
        for w in ws { warnings.warn(w); }

        if !roles.known_roles.contains(&role) {
            if deny_if_unknown {
                return Err(CompileError::UnknownRoleReferenced {
                    role,
                    context: context.to_string(),
                });
            } else {
                warnings.warn(format!(
                    "unknown role dropped (deny_if_role_unknown=false): role={} context={}",
                    role, context
                ));
                continue;
            }
        }

        if !role_set.insert(role.clone()) {
            warnings.warn(format!(
                "duplicate role removed: role={} context={}",
                role, context
            ));
        }
    }

    Ok(role_set)
}

fn validate_role_name(name: &str) -> Result<(), CompileError> {
    // 例: 最低限の事故防止。pattern は schema にある前提でも保険として。
    if name.is_empty() {
        return Err(CompileError::InvalidRoleName {
            name: name.to_string(),
            reason: "empty".to_string(),
        });
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(CompileError::InvalidRoleName {
            name: name.to_string(),
            reason: "contains control chars".to_string(),
        });
    }
    Ok(())
}

fn normalize_name(kind: &str, s: &str) -> Result<(String, Vec<String>), CompileError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(CompileError::InvalidRoleName {
            name: s.to_string(),
            reason: format!("{} name is empty after trim", kind),
        });
    }
    let mut ws = vec![];
    if trimmed != s {
        ws.push(format!("{} normalized by trim: '{}' -> '{}'", kind, s, trimmed));
    }
    Ok((trimmed.to_string(), ws))
}

fn dedup_vec_keep_order<T, K>(
    v: Vec<T>,
    key_fn: impl Fn(&T) -> K,
) -> (Vec<T>, Vec<K>)
where
    K: std::hash::Hash + Eq,
{
    let mut seen = std::collections::HashSet::<K>::new();
    let mut out = Vec::with_capacity(v.len());
    let mut dups = vec![];

    for item in v {
        let k = key_fn(&item);
        if seen.contains(&k) {
            dups.push(k);
        } else {
            seen.insert(k);
            out.push(item);
        }
    }
    (out, dups)
}

fn merge_role_set<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, HashSet<String>>,
    key: K,
    incoming: HashSet<String>,
    warnings: &mut CompileWarnings,
    ctx: &str,
) {
    match map.get_mut(&key) {
        Some(existing) => {
            let before = existing.len();
            existing.extend(incoming);
            let after = existing.len();
            if after != before {
                warnings.warn(format!("duplicate target merged roles: {}", ctx));
            } else {
                warnings.warn(format!(
                    "duplicate target assignment had no new roles: {}",
                    ctx
                ));
            }
        }
        None => {
            map.insert(key, incoming);
        }
    }
}

enum AssignmentTarget {
    Uid(u32),
    User(String),
}
impl AssignmentTarget {
    fn context_string(&self) -> String {
        match self {
            AssignmentTarget::Uid(uid) => format!("assignments[uid={}]", uid),
            AssignmentTarget::User(u) => format!("assignments[user={}]", u),
        }
    }
}

fn normalize_assignment_target(
    uid: Option<u32>,
    user: Option<&str>,
) -> Result<AssignmentTarget, CompileError> {
    match (uid, user) {
        (None, None) => Err(CompileError::MissingAssignmentTarget),
        (Some(_), Some(_)) => Err(CompileError::AmbiguousAssignmentTarget),
        (Some(uid), None) => Ok(AssignmentTarget::Uid(uid)),
        (None, Some(user)) => {
            let t = user.trim();
            if t.is_empty() {
                return Err(CompileError::MissingAssignmentTarget);
            }
            Ok(AssignmentTarget::User(t.to_string()))
        }
    }
}

enum GroupAssignmentTarget {
    Gid(u32),
    Group(String),
}
impl GroupAssignmentTarget {
    fn context_string(&self) -> String {
        match self {
            GroupAssignmentTarget::Gid(gid) => format!("group_assignments[gid={}]", gid),
            GroupAssignmentTarget::Group(g) => format!("group_assignments[group={}]", g),
        }
    }
}

fn normalize_group_assignment_target(
    gid: Option<u32>,
    group: Option<&str>,
) -> Result<GroupAssignmentTarget, CompileError> {
    match (gid, group) {
        (None, None) => Err(CompileError::MissingGroupAssignmentTarget),
        (Some(_), Some(_)) => Err(CompileError::AmbiguousGroupAssignmentTarget),
        (Some(gid), None) => Ok(GroupAssignmentTarget::Gid(gid)),
        (None, Some(group)) => {
            let t = group.trim();
            if t.is_empty() {
                return Err(CompileError::MissingGroupAssignmentTarget);
            }
            Ok(GroupAssignmentTarget::Group(t.to_string()))
        }
    }
}
    
fn validate_pre_approval_defaults(p: &RawPreApprovalDefaults) -> Result<(), CompileError> {
    if let Some(max) = p.ttl_sec_max {
        if p.ttl_sec_default > max {
            return Err(CompileError::InvalidPreApprovalDefaults(format!(
                "ttl_sec_default ({}) exceeds ttl_sec_max ({})",
                p.ttl_sec_default, max
            )));
        }
    }
    Ok(())
}

pub fn compile_policy_v13(
    raw: RawPolicyV13,
    roles: &CompiledRoles,
) -> Result<(CompiledPolicy, CompileWarnings), CompileError> {
    let mut warnings = CompileWarnings::default();

    // --- 0. pre_approval_defaults semantic validation ---
    // (Schema can't express cross-field constraint like default <= max)
    validate_pre_approval_defaults(&raw.pre_approval_defaults)?;

    // --- 1. version check ---
    if raw.version != "1.3" {
        return Err(CompileError::UnsupportedVersion(raw.version));
    }

    // --- 2. rule id 重複チェック ---
    let mut seen_ids = std::collections::HashSet::new();
    for r in &raw.rules {
        if !seen_ids.insert(&r.id) {
            return Err(CompileError::DuplicateRuleId(r.id.clone()));
        }
    }

    // --- 3. pre_approval_defaults copy ---
    let pre_approval_defaults = CompiledPreApprovalDefaults::from(&raw.pre_approval_defaults);

    // --- 4. rule compile ---
    let mut compiled_rules = Vec::with_capacity(raw.rules.len());

    for rr in raw.rules {
        let rule = compile_rule_v13(&rr, roles, &mut warnings)?;
        compiled_rules.push(rule);
    }
    // ソート: 優先度が高い順（降順）、同じなら元の順序（安定ソート）
    compiled_rules.sort_by(|a, b| {
        let spec_a = a.calculate_specificity();
        let spec_b = b.calculate_specificity();
        
        // Ordの実装により Low < Medium < High となるため、
        // b.cmp(a) で降順（Highが先頭）になる
        spec_b.cmp(&spec_a)
    });

    // --- 5. managed scope build ---
    let scope = ManagedScopeIndex::from_rules(&compiled_rules);

    let policy = CompiledPolicy {
        version: PolicyVersion::V1_3,
        rules: compiled_rules,
        scope,
        pre_approval_defaults,

        // default (互換 or 保険)
        default_action: raw.default_effect.unwrap_or_else(|| Effect::Deny).as_str().to_string(),
        default_reason: raw.default_reason.unwrap_or_else(|| "no matching rule".to_string()),
    };

    Ok((policy, warnings))
}

fn validate_pre_approval_for_rule(
    rule_id: &str,
    p: &RawPreApproval,
    warnings: &mut CompileWarnings,
) -> Result<(), CompileError> {
    if let Some(ttl) = p.ttl_sec {
        if ttl < 1 {
            return Err(CompileError::InvalidValue(format!(
                "rule {}: pre_approval.ttl_sec must be >= 1",
                rule_id
            )));
        }
    }

    // 例: enabled=false なのに ttl 指定 → warning
    if !p.enabled && p.ttl_sec.is_some() {
        warnings.warnings.push(format!(
            "rule {}: pre_approval.ttl_sec is set but enabled=false; ttl_sec will be ignored",
            rule_id
        ));
    }

    Ok(())
}

/// RawRule(v1.3) -> CompiledRule 1件
///
/// - roles: roles.json からコンパイル済みロール定義（未知ロール検出などに使う）
/// - warnings: lint 的な警告（推奨フィールド不足等）を積む
///
/// NOTE:
/// - この関数は "panic しない" を優先し、足りない情報は安全側のデフォルトで埋める想定。
pub fn compile_rule_v13(
    rule: &RawRule,
    roles: &CompiledRoles,
    warnings: &mut CompileWarnings,
) -> Result<CompiledRule, CompileError> {
    // --- semantic validate (pre_approval) ---
    if let Some(p) = &rule.pre_approval {
        validate_pre_approval_for_rule(&rule.id, p, warnings)?;
    }

    // --- matchers ---
    let subject: SubjectMatcher = compile_subject_v13(&rule.subject, roles, warnings);
    let object: Option<ObjectMatcher> = compile_object_v13(&rule.object)?; 
    let action_match: ActionMatcher = compile_action_v13(&rule.action, warnings)?;

    // --- approval / audit ---
    
    // 1. RawRule から値を取り出し、デフォルト値を適用
    //    スキーマで "need_approval" 時は必須だが、Rust上は Option なので unwrap_or で安全策をとる
    let raw_threshold = rule.threshold.unwrap_or(0);
    let raw_roles = rule.required_roles.clone().unwrap_or_default();

    // 2. ApprovalMatcher の構築
    //    threshold が 1以上、または required_roles が指定されている場合に ApprovalMatcher を作成する
    //    (effect=Deny でも値が書いてあれば構造体には詰める方針)
    let approval: Option<ApprovalMatcher> = if raw_threshold > 0 || !raw_roles.is_empty() {
        Some(ApprovalMatcher {
            threshold: raw_threshold,
            // Vec<String> -> HashSet<String> へ変換
            required_roles: raw_roles.into_iter().collect(),
        })
    } else {
        None
    };

    // AuditCfg も RawRule 側に無いので、安全側デフォルトを採用
    let audit: AuditCfg = AuditCfg::default();

    // --- out_reason ---
    // reason が未指定なら、ログに残る説明を自動生成（最低限ルールIDとeffectを入れる）
    let out_reason: String = match rule.reason.as_deref() {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => {
            warnings.warn(format!(
                "rule.id={} has no reason; auto-generated default reason will be used",
                rule.id
            ));
            make_default_reason(&rule.id, &rule.effect)
        }
    };

        // --- pre_approval (Raw -> Compiled) ---
    let pre_approval = match &rule.pre_approval {
        Some(p) => CompiledPreApproval {
            enabled: p.enabled,
        },
        None => CompiledPreApproval {
            enabled: false,
        },
    };

    // --- rule_type のパース ---
    let rule_type = match rule.rule_type.as_str() {
        "subject_only" => RuleType::SubjectOnly,
        _ => RuleType::Standard,
    };

    Ok(CompiledRule {
        id: rule.id.clone(),
        rule_type,
        effect: rule.effect.clone(),
        audit_level: rule.audit_level.clone(),
        ttl_sec: rule.ttl_sec,
        max_uses: rule.max_uses,

        subject,
        object,
        action_match,

        approval,
        audit,
        pre_approval,

        out_reason,

        ticket_profile: TicketProfile::from_raw(&rule.ticket_profile),
    })
}

/// reason 未指定時のデフォルト文言（ログ向け）
fn make_default_reason(id: &str, effect: &Effect) -> String {
    // "why" が分からないと運用で詰むので、最低限は必ず埋める
    // 例: "ALLOW by rule=xyz" / "DENY by rule=xyz"
    let eff = match effect {
        Effect::Allow => "ALLOW",
        Effect::Deny => "DENY",
        Effect::NeedApproval => "NEED APPROVAL",
        Effect::AuditOnly => "AUDIT ONLY",
    };
    format!("{eff} by rule={id}")
}


// 1) 文字列の正規化（Option<String> -> Option<String>）
fn opt_trimmed_nonempty(
    field_name: &str,
    v: &Option<String>,
    warnings: &mut CompileWarnings,
) -> Option<String> {
    match v.as_ref() {
        None => None,
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                warnings.warn(format!("{field_name} is empty string; ignored"));
                None
            } else {
                Some(t.to_string())
            }
        }
    }
}

// 2) パス条件のコンパイル（Option<String> -> Option<PathMatcher>）
fn opt_compile_path(
    field_name: &str,
    v: &Option<String>,
    warnings: &mut CompileWarnings,
) -> Option<PathMatcher> {
    // まず文字列を取り出し、空白除去などを行う
    let s = opt_trimmed_nonempty(field_name, v, warnings)?;

    // 実装した parse メソッドを使う
    match PathMatcher::parse(&s) {
        Ok(pm) => Some(pm),
        Err(e) => {
            // Globの構文エラーなどをここで警告として出す
            warnings.warn(format!("{field_name} is invalid: {e}; ignored"));
            None
        }
    }
}

// 3) roles のコンパイル（Vec<String> -> HashSet<String>）
fn compile_required_roles(
    roles_raw: &[String],
    roles_db: &CompiledRoles,
    warnings: &mut CompileWarnings,
) -> HashSet<String> {
    let mut required_roles = HashSet::<String>::new();

    for raw in roles_raw {
        let r = raw.trim();
        if r.is_empty() {
            warnings.warn("subject.roles contains empty string; ignored");
            continue;
        }

        if required_roles.contains(r) {
            warnings.warn(format!("subject.roles contains duplicate role: {r}"));
            continue;
        }

        if !roles_db.is_known_role(r) {
            warnings.warn(format!("subject.roles contains unknown role: {r}"));
        }

        required_roles.insert(r.to_string());
    }

    required_roles
}

pub fn compile_subject_v13(
    subject: &RawSubject,
    roles: &CompiledRoles,
    warnings: &mut CompileWarnings,
) -> SubjectMatcher {
    // user/uid
    let uid = match subject.uid {
        Some(uid) => Some(uid),
        None => match opt_trimmed_nonempty("subject.user", &subject.user, warnings) {
            Some(user) => match name_to_uid(&user) {
                Ok(uid) => Some(uid),
                Err(_) => None,
            }
            None => None,
        },
    };

    // roles
    let required_roles = compile_required_roles(&subject.roles, roles, warnings);

    // origin_program/origin_script
    let origin_program =
        opt_compile_path("subject.origin_program", &subject.origin_program, warnings);

    let origin_script =
        opt_compile_path("subject.origin_script", &subject.origin_script, warnings);

    let origin_applet =
        opt_trimmed_nonempty("subject.origin_applet", &subject.origin_applet, warnings);

    SubjectMatcher {
        uid,
        required_roles,
        origin_program,
        origin_script,
        origin_applet,
    }
}

fn compile_path_matcher_v13(
    raw: &str
) -> Result<PathMatcher, CompileError> {
    // 1. 前後の空白除去
    let s = raw.trim();

    // 2. 空文字チェック
    if s.is_empty() {
        return Err(CompileError::InvalidObjectPath(
            "path must not be empty".into(),
        )); 
    }

    // 3. スキーム（接頭辞）による分岐
    if let Some(pattern) = s.strip_prefix("glob:") {
        // --- Glob モード ---

        // パスとして絶対パスかチェック
        if !pattern.starts_with('/') {
            return Err(CompileError::InvalidObjectPath(
                format!("glob pattern must be absolute (start with '/'): {}", pattern),
            ));
        }

        let glob = Glob::new(pattern)
            .map_err(|e| CompileError::InvalidObjectPath(e.to_string()))?;

        Ok(PathMatcher::Glob { 
            pattern: pattern.to_string(), 
            matcher: glob.compile_matcher() 
        })

    } else if let Some(path_str) = s.strip_prefix("prefix:") {
        // --- Prefix モード ---
        let p = Path::new(path_str);
        
        // パスとして絶対パスかチェック
        if !p.is_absolute() {
            return Err(CompileError::InvalidObjectPath(
                format!("prefix path must be absolute: {}", path_str),
            ));
        }

        Ok(PathMatcher::Prefix(p.to_path_buf()))

    } else {
        // --- Exact モード (デフォルト) ---
        let p = Path::new(s);
        
        if !p.is_absolute() {
            return Err(CompileError::InvalidObjectPath(
                format!("relative path is not allowed: {}", s),    
            ));
        }

        Ok(PathMatcher::Exact(p.to_path_buf()))
    }
}

pub fn compile_object_v13(
    raw_object: &Option<RawObject>,
) -> Result<Option<ObjectMatcher>, CompileError> {
    // 1. rule.object が None (subject_only) の場合は、即座に Ok(None) を返す
    let raw_obj = match raw_object {
        Some(obj) => obj,
        None => return Ok(None),
    };

    // 2. object が存在する場合は、その中の path 文字列をコンパイルする
    // （スキーマ上、object があるなら path は必須なので raw_obj.path は String）
    let path_matcher = compile_path_matcher_v13(&raw_obj.path)?;

    // 3. 構築した ObjectMatcher を Some で包んで返す
    Ok(Some(ObjectMatcher {
        path: Some(path_matcher),
        kind: None, // v1.3 では未使用 (将来 Socket などが入る余地)
    }))
}

pub fn compile_action_v13(
    action: &RawAction,
    warnings: &mut CompileWarnings,
) -> Result<ActionMatcher, CompileError> {
    // ops が空
    if action.ops.is_empty() {
        warnings.warn("action.ops is empty; treated as Any (unsafe, please specify explicitly)");
        return Ok(ActionMatcher::Any);
    }

    let mut set = HashSet::new();
    let mut has_any = false;

    for op in &action.ops {
        if op == "*" {
            has_any = true;
            continue;
        }

        let parsed = Action::parse(op)?;
        set.insert(parsed);
    }

    // "*" が含まれている場合
    if has_any {
        if !set.is_empty() {
            warnings.warn("action '*' mixed with specific actions; '*' takes precedence");
        }
        return Ok(ActionMatcher::Any);
    }

    if set.is_empty() {
        // "*" だけ or 無効な入力のみ
        warnings.warn("action resolved to empty set; treated as Any");
        Ok(ActionMatcher::Any)
    } else {
        Ok(ActionMatcher::OneOf(set))
    }
}

