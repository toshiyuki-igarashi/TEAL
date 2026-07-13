// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::path::Path;

use crate::types::{Action, SystemType};
use crate::ir::{CompiledRule, AccessContext, SubjectMatcher, ObjectMatcher, ActionMatcher, PathMatcher, ObjectKind};

pub fn rule_matches(rule: &CompiledRule, ctx: &AccessContext, system_type: SystemType) -> bool {
    // .as_deref() を使うことで、Option<PathBuf> を Option<&Path> に変換できます
    if match_object(
        &rule.object, 
        &ctx.object_path, 
        ctx.object_new_path.as_deref(),
        ctx.object_kind
    ) && match_action(&rule.action_match, ctx.action) {
        match_subject(&rule.subject, ctx, system_type)
    } else {
        false
    }
}

pub fn match_subject(
    m: &SubjectMatcher, 
    ctx: &AccessContext, 
    system_type: SystemType
) -> bool {
    // 1) uid match
    if let Some(rule_uid) = m.uid {
        if ctx.uid != rule_uid {
            return false;
        }
    }

    // 2) roles match (OR)
    if !m.required_roles.is_empty() {
        let ok = m.required_roles.iter().any(|r| ctx.subject_roles.contains(r));
        if !ok {
            return false;
        }
    }

    // 3) origin_program match (exec path / interpreter)
    if let Some(rule_pm) = m.origin_program.as_ref() {
        let ctx_prog = match ctx.origin_program.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !pathmatcher_matches(rule_pm, ctx_prog.as_path()) {
            return false;
        }
    }

    // 4) origin_script match (shebang script)
    if let Some(rule_pm) = m.origin_script.as_ref() {
        let ctx_script = match ctx.origin_script.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !pathmatcher_matches(rule_pm, ctx_script.as_path()) {
            return false;
        }
    }

    // 5) origin_applet match (argv[0] / task comm 相当)
    if let Some(rule_applet) = m.origin_applet.as_ref() {
        let ctx_applet = match ctx.origin_applet.as_ref() {
            Some(a) => a,
            None => return false,
        };
        if rule_applet != ctx_applet {
            return false;
        }
    }

    // 6) ログインコンテキストのチェック
    if let Some(login_ctx) = &m.login_context {

        // 1. 対話型TTYが要求されている場合
        if login_ctx.require_interactive_tty {
            // CUIの標準的な仮想端末（pts/X や ttyX）であるか
            let is_cui_terminal = ctx.session_tty.starts_with("pts") || ctx.session_tty.starts_with("tty");
            
            // system_type に応じて判定を切り替える
            let is_allowed_terminal = match system_type {
                SystemType::Server => {
                    // Server は厳格モード: GUI由来（:0 等）は一律で拒否し、純粋なCUI端末のみ許可
                    is_cui_terminal
                }
                SystemType::Workstation => {
                    // Workstation は柔軟モード: CUIに加え、X11やWayland等のローカルGUIセッション（例: ":0", ":1"）も対話型とみなす
                    is_cui_terminal || ctx.session_tty.starts_with(':')
                }
            };
            
            if !is_allowed_terminal {
                // 必要に応じてログ出力を挟むとデバッグが容易になります
                // error!("Interactive TTY required ({:?}), but got: '{}'", system_type, ctx.session_tty);
                return false;   // マッチ失敗（拒否）
            }
        }

        // 2. 正規のPAMログインセッションとの紐づけが要求されている場合
        if login_ctx.bind_registered_session {
            // AppState側で未登録と判定されていればDeny
            if !ctx.is_registered_session {
                return false; // マッチ失敗（不正なバックドアセッションとして拒否）
            }
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
    object_new_path: Option<&Path>,
    object_kind: Option<ObjectKind>
) -> bool {
    // 1. ルールに object 定義がない (subject_only) 場合はパス評価をスキップ
    let matcher = match om {
        Some(m) => m,
        None => return true,
    };

    // 2. path (Source) の評価
    if let Some(ref pm) = matcher.path {
        if !pathmatcher_matches(pm, object_path) {
            return false;
        }
    }

    // 3. new_path (Destination) の評価
    // ルールが new_path を定義している場合、必ず実値が必要
    if let Some(ref pm) = matcher.new_path {
        match object_new_path {
            Some(new_p) => {
                if !pathmatcher_matches(pm, new_p) {
                    return false;
                }
            }
            // ルールは「移動先」を条件にしているのに、
            // 実行時に移動先が指定されていない（例: 普通のREAD操作）場合は不一致とみなす
            None => return false,
        }
    }

    // 4. kind (ObjectKind) の評価
    if let Some(ref rule_kind) = matcher.kind {
        if let Some(ref ctx_kind) = object_kind {
            if ctx_kind != rule_kind {
                return false;
            }
        }
    }

    true
}

pub fn match_action(m: &ActionMatcher, action: Action) -> bool {
    match m {
        ActionMatcher::Any => true,
        ActionMatcher::OneOf(set) => set.contains(&action),
    }
}

