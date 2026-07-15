// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::path::Path;

use crate::types::{Action, SystemType};
use crate::ir::{ CompiledRule, AccessContext, SubjectMatcher, LoginContextMatcher,
    ObjectMatcher, ActionMatcher, PathMatcher, ObjectKind
};

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
        if !m.required_roles.iter().any(|r| ctx.subject_roles.contains(r)) {
            return false;
        }
    }

    // 3) origin_program match
    if let Some(rule_pm) = m.origin_program.as_ref() {
        let ctx_prog = match ctx.origin_program.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !pathmatcher_matches(rule_pm, ctx_prog.as_path()) {
            return false;
        }
    }

    // 4) origin_script match
    if let Some(rule_pm) = m.origin_script.as_ref() {
        let ctx_script = match ctx.origin_script.as_ref() {
            Some(p) => p,
            None => return false,
        };
        if !pathmatcher_matches(rule_pm, ctx_script.as_path()) {
            return false;
        }
    }

    // 5) origin_applet match
    if let Some(rule_applet) = m.origin_applet.as_ref() {
        let ctx_applet = match ctx.origin_applet.as_ref() {
            Some(a) => a,
            None => return false,
        };
        if rule_applet != ctx_applet {
            return false;
        }
    }

    // 6) ログインコンテキストのチェック (別関数に委譲)
    if let Some(login_ctx) = &m.login_context {
        if !match_login_context(login_ctx, ctx, system_type) {
            return false;
        }
    }

    true
}

/// PAMセッションと実行時TTYに基づく高度な環境コンテキスト評価を行う
fn match_login_context(
    login_ctx: &LoginContextMatcher, 
    ctx: &AccessContext, 
    system_type: SystemType
) -> bool {
    // --- 1. 対話型TTY要求の評価 ---
    if login_ctx.require_interactive_tty {
        let is_cui_terminal = ctx.session_tty.starts_with("pts") || ctx.session_tty.starts_with("tty");
        
        let is_allowed_terminal = match system_type {
            SystemType::Server => is_cui_terminal,
            SystemType::Workstation => is_cui_terminal || ctx.session_tty.starts_with(':'),
        };
        
        if !is_allowed_terminal {
            return false;
        }
    }

    // --- 2. PAMセッション紐付け（ファクト検証）の評価 ---
    if login_ctx.bind_registered_session {
        match &ctx.registered_session {
            // 【A】PAM台帳に完全一致するセッションが存在する場合
            Some(session) => {
                // a) 認証方式の厳格照合
                if let Some(required_auth) = &login_ctx.auth_method {
                    if session.auth_method.as_ref() != Some(required_auth) {
                        return false; 
                    }
                }

                // b) 接続元IPのCIDR範囲チェック
                if let Some(network) = &login_ctx.source_ip_network {
                    let ip_str = match &session.source_ip {
                        Some(ip) => ip,
                        None => return false, // ポリシーはIP制限を求めているが、セッションがローカル(None)のため拒否
                    };

                    // IPパースとCIDR包含判定
                    if let Ok(ip_addr) = ip_str.parse::<std::net::IpAddr>() {
                        if !network.contains(ip_addr) {
                            return false; // 範囲外
                        }
                    } else {
                        return false; // IPパースエラー
                    }
                }
            }
            
            // 【B】PAM台帳に直接の一致が見つからなかった場合
            None => {
                match system_type {
                    SystemType::Server => {
                        // サーバー環境では言い訳無用で即座に拒否 (Fail-Safe)
                        return false;
                    }
                    SystemType::Workstation => {
                        // ワークステーション環境におけるGUI由来プロセスの遅延救済
                        // IPや認証方式のファクト要求がある場合は、データがないため安全側に倒して拒否する
                        if login_ctx.auth_method.is_some() || login_ctx.source_ip_network.is_some() {
                            return false; 
                        }
                        // 要求が単なる bind_registered_session だけであれば、GUIセッションとして救済（trueを返す）
                    }
                }
            }
        }
    }

    // すべてのチェックを通過した
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

