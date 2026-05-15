use std::path::Path;

use crate::ir::{CompiledRule, AccessContext, SubjectMatcher, ObjectMatcher, ActionMatcher, PathMatcher, Action, ObjectKind};

pub fn rule_matches(rule: &CompiledRule, ctx: &AccessContext) -> bool {
    if match_object(&rule.object, &ctx.object_path, ctx.object_kind) && match_action(&rule.action_match, ctx.action) {
        match_subject(&rule.subject, ctx)
    } else {
        false
    }
}

pub fn match_subject(m: &SubjectMatcher, ctx: &AccessContext) -> bool {
    // uid match
    if let Some(rule_uid) = m.uid {
        if ctx.uid != rule_uid {
            return false;
        }
    }

    // roles match (OR)
    if !m.required_roles.is_empty() {
        let ok = m.required_roles.iter().any(|r| ctx.subject_roles.contains(r));
        if !ok {
            return false;
        }
    }

    // origin_program match (exec path / interpreter)
    if let Some(rule_pm) = m.origin_program.as_ref() {
        let ctx_prog = match ctx.origin_program.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !pathmatcher_matches(rule_pm, ctx_prog.as_path()) {
            return false;
        }
    }

    // origin_script match (shebang script)
    if let Some(rule_pm) = m.origin_script.as_ref() {
        let ctx_script = match ctx.origin_script.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !pathmatcher_matches(rule_pm, ctx_script.as_path()) {
            return false;
        }
    }

    // origin_applet match (argv[0] / task comm 相当)
    if let Some(rule_applet) = m.origin_applet.as_ref() {
        let ctx_applet = match ctx.origin_applet.as_ref() {
            Some(a) => a,
            None => return false,
        };
        if rule_applet != ctx_applet {
            return false;
        }
    }

    true
}

// 例：PathMatcher 側に合わせて実装（あなたの PathMatcher 定義に合わせて調整）
fn pathmatcher_matches(pm: &PathMatcher, path: &Path) -> bool {
    match pm {
        PathMatcher::Exact(p) => path == p.as_path(),
        PathMatcher::Prefix(prefix) => path.starts_with(prefix),
        PathMatcher::Glob { matcher, .. } => matcher.is_match(path),
    }
}

pub fn match_object(
    om: &Option<ObjectMatcher>, 
    object_path: &Path, 
    object_kind: Option<ObjectKind>
) -> bool {
    // 1. ルールに object 定義がない (subject_only) 場合はパス評価をスキップ (true)
    let matcher = match om {
        Some(m) => m,
        None => return true,
    };

    // 2. object 定義がある場合、まず path (Option<PathMatcher>) を評価
    if let Some(ref pm) = matcher.path {
        if !pathmatcher_matches(pm, object_path) {
            return false;
        }
    }
    // matcher.path が None の場合は、パスの文字列チェックをスキップ (true扱い)

    // 3. kind (Option<ObjectKind>) の評価
    if let Some(ref rule_kind) = matcher.kind {
        if let Some(ref ctx_kind) = object_kind {
            if ctx_kind != rule_kind {
                return false;
            }
        }
        // ctx_kind が None (判定不能) の場合はチェックをスキップ
    }

    true
}

pub fn match_action(m: &ActionMatcher, action: Action) -> bool {
    match m {
        ActionMatcher::Any => true,
        ActionMatcher::OneOf(set) => set.contains(&action),
    }
}

