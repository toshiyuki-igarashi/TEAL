// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use chrono::{Datelike, Local, NaiveDateTime, Timelike};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::ir::{
    AccessContext, ActionMatcher, CompiledRule, LoginContextMatcher, ObjectKind, ObjectMatcher,
    PathMatcher, RegisteredSession, SubjectMatcher, TimeConstraintMatcher,
};
use crate::types::{Action, SystemType};

pub fn rule_matches(
    rule: &CompiledRule,
    allowed_ssh_networks: &HashMap<u32, Vec<IpNetwork>>,
    ctx: &AccessContext,
    system_type: SystemType,
) -> bool {
    // .as_deref() を使うことで、Option<PathBuf> を Option<&Path> に変換できます
    if match_object(
        &rule.object,
        &ctx.object_path,
        ctx.object_new_path.as_deref(),
        ctx.object_kind,
    ) && match_action(&rule.action_match, ctx.action)
    {
        if !match_time_constraints(&rule.time_constraints) {
            return false;
        }

        match_subject(&rule.subject, allowed_ssh_networks, ctx, system_type)
    } else {
        false
    }
}

/// 時間制約は OR 条件。空なら時間制約なし。
/// 曜日・時刻は teald のホストローカル時間で評価する。
/// 週番号は ISO 8601 (月曜開始、1月4日を含む週が第1週)。
fn match_time_constraints(constraints: &[TimeConstraintMatcher]) -> bool {
    if constraints.is_empty() {
        return true;
    }

    match_time_constraints_at(constraints, Local::now().naive_local())
}

/// 指定されたローカル日時での時間制約判定（単体テスト用の純粋関数）。
fn match_time_constraints_at(constraints: &[TimeConstraintMatcher], now: NaiveDateTime) -> bool {
    if constraints.is_empty() {
        return true;
    }

    let minutes = now.hour() * 60 + now.minute();
    let date = now.date();

    constraints.iter().any(|c| {
        let start = c.start_minutes_from_midnight;
        let end = c.end_minutes_from_midnight;

        // 0は不正。start == endは曖昧なので無効とする。
        if c.week_interval == 0 || start >= 24 * 60 || end > 24 * 60 || start == end {
            return false;
        }

        // 第1週を起点に毎N週を許可する (1, 1+N, 1+2N, ...)。
        let matches_start_date = |start_date: chrono::NaiveDate| {
            (c.allowed_days.is_empty() || c.allowed_days.contains(&start_date.weekday()))
                && (start_date.iso_week().week() - 1) % c.week_interval == 0
        };

        if start < end {
            // 同日内: [start, end)
            start <= minutes && minutes < end && matches_start_date(date)
        } else if minutes >= start {
            // 日付跨ぎの開始側（例: 日曜23:00）
            matches_start_date(date)
        } else if minutes < end {
            // 日付跨ぎの終了側（例: 翌月曜01:00）
            // 周期・曜日は『開始日』で判定する（ISO年境界も同様）。
            date.pred_opt().is_some_and(matches_start_date)
        } else {
            false
        }
    })
}

fn match_subject(
    m: &SubjectMatcher,
    allowed_ssh_networks: &HashMap<u32, Vec<IpNetwork>>,
    ctx: &AccessContext,
    system_type: SystemType,
) -> bool {
    // 1) uid match
    if let Some(rule_uid) = m.uid {
        if ctx.uid != rule_uid {
            return false;
        }
    }

    // 2) roles match (OR)
    if !m.required_roles.is_empty()
        && !m
            .required_roles
            .iter()
            .any(|r| ctx.subject_roles.contains(r))
    {
        return false;
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
        if !match_login_context(login_ctx, allowed_ssh_networks, ctx, system_type) {
            return false;
        }
    }

    true
}

/// セッションの接続元IPが roles.json の許可範囲内かを検証するヘルパー
// session.source_ip の有無だけでリモートかローカルかを判別
fn is_ssh_source_allowed(
    allowed_ssh_networks: &HashMap<u32, Vec<IpNetwork>>,
    session: &RegisteredSession,
) -> bool {
    let Some(allowed_nets) = allowed_ssh_networks.get(&session.uid) else {
        return true; // 制限未設定のUIDは無条件パス
    };

    match session.source_ip.as_deref() {
        // リモート接続（SSHなど）: 厳格にCIDR判定
        Some(ip_str) => {
            if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
                allowed_nets.iter().any(|net| net.contains(ip_addr))
            } else {
                false // パース不能な不正IPは拒否
            }
        }
        // ローカル接続（物理コンソール、ローカルGUI）: IPチェックを免除して許可
        None => true,
    }
}

/// PAMセッションと実行時TTYに基づく高度な環境コンテキスト評価を行う
fn match_login_context(
    login_ctx: &LoginContextMatcher,
    allowed_ssh_networks: &HashMap<u32, Vec<IpNetwork>>,
    ctx: &AccessContext,
    system_type: SystemType,
) -> bool {
    // --- 1. 対話型TTY要求の評価 ---
    if login_ctx.require_interactive_tty {
        let is_cui_terminal =
            ctx.session_tty.starts_with("pts") || ctx.session_tty.starts_with("tty");

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
                    if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
                        if !network.contains(ip_addr) {
                            return false; // 範囲外
                        }
                    } else {
                        return false; // IPパースエラー
                    }
                }

                // c) uidに紐付けられた接続元IPのCIDR範囲チェック
                if !is_ssh_source_allowed(allowed_ssh_networks, session) {
                    return false;
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
                        if login_ctx.auth_method.is_some() || login_ctx.source_ip_network.is_some()
                        {
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

fn match_object(
    om: &Option<ObjectMatcher>,
    object_path: &Path,
    object_new_path: Option<&Path>,
    object_kind: Option<ObjectKind>,
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

fn match_action(m: &ActionMatcher, action: Action) -> bool {
    match m {
        ActionMatcher::Any => true,
        ActionMatcher::OneOf(set) => set.contains(&action),
    }
}

#[cfg(test)]
mod time_constraint_tests {
    use super::*;
    use chrono::{NaiveDate, Weekday};
    use std::collections::HashSet;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
    }

    fn monday_morning(interval: u32) -> TimeConstraintMatcher {
        TimeConstraintMatcher {
            allowed_days: HashSet::from([Weekday::Mon]),
            start_minutes_from_midnight: 9 * 60,
            end_minutes_from_midnight: 10 * 60,
            week_interval: interval,
        }
    }

    #[test]
    fn no_constraints() {
        assert!(match_time_constraints_at(&[], at(2026, 11, 2, 9, 0)));
    }

    #[test]
    fn every_two_iso_weeks() {
        let c = monday_morning(2);
        assert!(match_time_constraints_at(
            &[c.clone()],
            at(2026, 11, 2, 9, 0)
        )); // 第45週
        assert!(!match_time_constraints_at(
            &[c.clone()],
            at(2026, 11, 9, 9, 0)
        )); // 第46週
        assert!(match_time_constraints_at(
            &[c.clone()],
            at(2026, 11, 16, 9, 0)
        )); // 第47週
        assert!(!match_time_constraints_at(&[c], at(2026, 11, 16, 10, 0))); // 終了時刻は含まない
    }

    #[test]
    fn iso_week_resets_at_new_iso_year() {
        let c = monday_morning(2);
        assert!(match_time_constraints_at(
            &[c.clone()],
            at(2026, 12, 28, 9, 30)
        )); // 2026-W53
        assert!(match_time_constraints_at(&[c], at(2027, 1, 4, 9, 30))); // 2027-W01
    }

    #[test]
    fn overnight_uses_start_day_week_number() {
        let c = TimeConstraintMatcher {
            allowed_days: HashSet::from([Weekday::Sun]),
            start_minutes_from_midnight: 23 * 60,
            end_minutes_from_midnight: 2 * 60,
            week_interval: 2,
        };
        assert!(match_time_constraints_at(
            &[c.clone()],
            at(2027, 1, 10, 23, 30)
        )); // 2027-W01
        assert!(match_time_constraints_at(
            &[c.clone()],
            at(2027, 1, 11, 1, 0)
        )); // 月曜W02でも許可
        assert!(!match_time_constraints_at(&[c], at(2027, 1, 11, 2, 0)));
    }

    #[test]
    fn invalid_interval_fails_closed() {
        let c = monday_morning(0);
        assert!(!match_time_constraints_at(&[c], at(2026, 11, 2, 9, 30)));
    }
}
