// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};
use chrono::Local;

use super::bundle_diff::{SecurityImpact as MgmtImpact};
use super::{BundleDiffReport, RuleDiffItem, SecurityImpact};

/// HTML レポートを生成してファイル出力
pub fn generate_html_report(report: &BundleDiffReport, output_path: &Path) -> Result<()> {
    let html_content = render_html(report);
    fs::write(output_path, html_content)
        .with_context(|| format!("Failed to write HTML diff report: {}", output_path.display()))?;
    Ok(())
}

fn render_html(report: &BundleDiffReport) -> String {
    let generated_time = Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();

    // 統計集計
    let added_count = report.rule_diffs.iter().filter(|r| matches!(r, RuleDiffItem::Added { .. })).count();
    let removed_count = report.rule_diffs.iter().filter(|r| matches!(r, RuleDiffItem::Removed { .. })).count();
    let modified_count = report.rule_diffs.iter().filter(|r| matches!(r, RuleDiffItem::Modified { .. })).count();
    let relaxed_count = report.rule_diffs.iter().filter(|r| r.impact() == SecurityImpact::Relaxed).count();
    let hardened_count = report.rule_diffs.iter().filter(|r| r.impact() == SecurityImpact::Hardened).count();

    // ファイル単位でグループ化
    let mut file_groups: BTreeMap<&str, Vec<&RuleDiffItem>> = BTreeMap::new();
    for item in &report.rule_diffs {
        file_groups.entry(item.source_file()).or_default().push(item);
    }

    let mut out = String::new();

    out.push_str(r#"<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TEAL Policy Diff Report</title>
<style>
  :root {
    --bg: #0f172a;
    --card-bg: #1e293b;
    --card-border: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --relaxed-bg: #450a0a;
    --relaxed-border: #ef4444;
    --relaxed-text: #fca5a5;
    --hardened-bg: #052e16;
    --hardened-border: #22c55e;
    --hardened-text: #86efac;
    --neutral-bg: #1e293b;
    --neutral-border: #64748b;
    --neutral-text: #cbd5e1;
    --added-border: #3b82f6;
    --removed-border: #6b7280;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, monospace;
    background-color: var(--bg);
    color: var(--text-main);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  .header {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .header h1 { margin: 0 0 8px 0; font-size: 22px; display: flex; align-items: center; gap: 8px; }
  .header .meta { color: var(--text-muted); font-size: 13px; font-family: monospace; }
  
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-top: 16px;
  }
  .stat-card {
    background: #0b1120;
    border: 1px solid var(--card-border);
    border-radius: 6px;
    padding: 12px;
    text-align: center;
  }
  .stat-card .num { font-size: 20px; font-weight: bold; }
  .stat-card .label { font-size: 12px; color: var(--text-muted); }
  .text-relaxed { color: #f87171; }
  .text-hardened { color: #4ade80; }
  .text-added { color: #60a5fa; }
  .text-removed { color: #9ca3af; }

  .section-title { font-size: 18px; margin: 24px 0 12px 0; border-bottom: 2px solid var(--card-border); padding-bottom: 6px; }
  table.diff-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--card-bg);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 24px;
    font-size: 13px;
  }
  table.diff-table th, table.diff-table td {
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--card-border);
  }
  table.diff-table th { background: #111827; color: var(--text-muted); }

  .card-block {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
  }
  
  .file-group {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
  }
  .file-header {
    background: #1e293b;
    padding: 12px 16px;
    font-weight: bold;
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
  }
  .file-header:hover { background: #334155; }
  .file-body { padding: 12px 16px; display: flex; flex-direction: column; gap: 12px; }

  .rule-card {
    border-radius: 6px;
    border: 1px solid;
    padding: 12px;
    background: #0f172a;
  }
  .rule-card.relaxed { border-color: var(--relaxed-border); background: #1a0f14; }
  .rule-card.hardened { border-color: var(--hardened-border); background: #0c1a14; }
  .rule-card.neutral { border-color: var(--neutral-border); }
  .rule-card.added { border-color: var(--added-border); }
  .rule-card.removed { border-color: var(--removed-border); opacity: 0.85; }

  .rule-title {
    font-weight: bold;
    font-family: monospace;
    font-size: 14px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .badge {
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
  }
  .badge-relaxed { background: var(--relaxed-bg); color: var(--relaxed-text); border: 1px solid var(--relaxed-border); }
  .badge-hardened { background: var(--hardened-bg); color: var(--hardened-text); border: 1px solid var(--hardened-border); }
  .badge-neutral { background: var(--neutral-bg); color: var(--neutral-text); border: 1px solid var(--neutral-border); }
  .badge-added { background: #1e3a8a; color: #93c5fd; border: 1px solid var(--added-border); }
  .badge-removed { background: #374151; color: #d1d5db; border: 1px solid var(--removed-border); }

  .details-list {
    margin: 8px 0 0 0;
    padding-left: 20px;
    font-size: 13px;
    color: #e2e8f0;
  }
  .details-list li { margin-bottom: 4px; }
  pre.code-preview {
    background: #000;
    border: 1px solid #334155;
    padding: 10px;
    border-radius: 4px;
    font-size: 12px;
    overflow-x: auto;
    color: #a5f3fc;
    margin-top: 8px;
  }
</style>
</head>
<body>
<div class="container">
"#);

    // ヘッダー部
    out.push_str(&format!(r#"
  <div class="header">
    <h1>🛡️ TEAL Policy Diff Report</h1>
    <div class="meta">
      Generated: {}<br>
      Hash Transition: <code>{}</code> ➔ <code>{}</code>
    </div>
    <div class="stats-grid">
      <div class="stat-card"><div class="num">{}</div><div class="label">変更ファイル</div></div>
      <div class="stat-card"><div class="num text-relaxed">{}</div><div class="label">⚠️ 弱化 (Relaxed)</div></div>
      <div class="stat-card"><div class="num text-hardened">{}</div><div class="label">✅ 強化 (Hardened)</div></div>
      <div class="stat-card"><div class="num text-added">{}</div><div class="label">🔵 新規 (Added)</div></div>
      <div class="stat-card"><div class="num text-removed">{}</div><div class="label">⚫ 削除 (Removed)</div></div>
      <div class="stat-card"><div class="num">{}</div><div class="label">変更 (Modified)</div></div>
    </div>
  </div>
"#,
        generated_time,
        escape_html(&report.current_hash),
        escape_html(&report.new_hash),
        file_groups.len(),
        relaxed_count,
        hardened_count,
        added_count,
        removed_count,
        modified_count
    ));

    // 1. バンドル設定差分 (FullConfigDiff: management / roles / bundle)
    if let Some(ref config) = report.config_diff {
        out.push_str(r#"<div class="section-title">🏛️ バンドル構成・ガバナンス設定の差分</div>"#);

         // (1) Management Governance Policy
        if let Some(ref mgmt) = config.mgmt_diff {
            out.push_str(r#"<div class="card-block"><h3 style="margin-top:0;">Management Governance (MPA)</h3>"#);
            if mgmt.control_changes.is_empty() && mgmt.role_changes.is_empty() {
                out.push_str(r#"<p style="color:var(--text-muted);font-size:13px;">管理ポリシーに変更はありません。</p>"#);
            } else {
                // A. 管理ロールの UID 割り当て変更
                if !mgmt.role_changes.is_empty() {
                    out.push_str(r#"<h4 style="margin: 12px 0 6px 0; font-size: 14px;">管理ロール・メンバー変更</h4>"#);
                    out.push_str(r#"<table class="diff-table"><thead><tr><th>ロール名</th><th>追加UID</th><th>削除UID</th></tr></thead><tbody>"#);
                    for r in &mgmt.role_changes {
                        out.push_str(&format!(r#"
                        <tr>
                          <td><code>{}</code></td>
                          <td style="color:#86efac;">{}</td>
                          <td style="color:#fca5a5;">{}</td>
                        </tr>
                        "#,
                            escape_html(&r.role_name),
                            if r.added_uids.is_empty() { "-".into() } else { format!("{:?}", r.added_uids) },
                            if r.removed_uids.is_empty() { "-".into() } else { format!("{:?}", r.removed_uids) }
                        ));
                    }
                    out.push_str("</tbody></table>");
                }

                // B. コマンド制御 (MPA & 起案権限) の変更
                if !mgmt.control_changes.is_empty() {
                    out.push_str(r#"<h4 style="margin: 16px 0 6px 0; font-size: 14px;">コマンド制御・MPA設定変更</h4>"#);
                    out.push_str(r#"<table class="diff-table"><thead><tr><th>コマンド</th><th>影響度</th><th>変更内容</th></tr></thead><tbody>"#);
                    for c in &mgmt.control_changes {
                        let (badge_class, badge_label) = match c.impact {
                            MgmtImpact::Critical => ("badge-relaxed", "🚨 CRITICAL (MPA弱化)"),
                            MgmtImpact::Warning  => ("badge-relaxed", "⚠️ WARNING (ロール変更)"),
                            MgmtImpact::Stricter => ("badge-hardened", "🛡️ STRICTER (強化)"),
                            MgmtImpact::Neutral  => ("badge-neutral", "⚪ NEUTRAL"),
                        };
                        let mut details = Vec::new();
                        if let Some((old_t, new_t)) = c.threshold_change {
                            details.push(format!("Threshold: {} ➔ {}", old_t, new_t));
                        }
                        if let Some((old_e, new_e)) = c.mpa_enabled_change {
                            details.push(format!("MPA Enabled: {} ➔ {}", old_e, new_e));
                        }
                        // 起案可能ロール (initiator)
                        if !c.added_initiator_roles.is_empty() {
                            details.push(format!("追加された起案ロール: {:?}", c.added_initiator_roles));
                        }
                        if !c.removed_initiator_roles.is_empty() {
                            details.push(format!("削除された起案ロール: {:?}", c.removed_initiator_roles));
                        }
                        // 承認可能ロール (approver)
                        if !c.added_approver_roles.is_empty() {
                            details.push(format!("追加された承認ロール: {:?}", c.added_approver_roles));
                        }
                        if !c.removed_approver_roles.is_empty() {
                            details.push(format!("削除された承認ロール: {:?}", c.removed_approver_roles));
                        }

                        out.push_str(&format!(r#"
                        <tr>
                          <td><code>{}</code></td>
                          <td><span class="badge {}">{}</span></td>
                          <td>{}</td>
                        </tr>
                        "#, escape_html(&c.command), badge_class, badge_label, escape_html(&details.join(" / "))));
                    }
                    out.push_str("</tbody></table>");
                }
            }
            out.push_str("</div>");
        }

        // (2) Roles & Assignments
        if let Some(ref roles) = config.roles_diff {
            out.push_str(r#"<div class="card-block"><h3 style="margin-top:0;">Role & Subject Assignments</h3>"#);

            // ロール自体の定義追加・削除
            if !roles.added_roles.is_empty() || !roles.removed_roles.is_empty() {
                out.push_str(r#"<div style="margin-bottom: 12px;"><ul class="details-list">"#);
                for r in &roles.added_roles {
                    out.push_str(&format!(r#"<li style="color:#86efac;">+ 新規ロール定義: <code>{}</code></li>"#, escape_html(r)));
                }
                for r in &roles.removed_roles {
                    out.push_str(&format!(r#"<li style="color:#fca5a5;">- 削除されたロール定義: <code>{}</code></li>"#, escape_html(r)));
                }
                out.push_str("</ul></div>");
            }

            // 割り当て変更テーブル
            if !roles.assignment_changes.is_empty() || roles.default_roles_changed.is_some() {
                out.push_str(r#"<table class="diff-table"><thead><tr><th>対象</th><th>付与ロール (Granted)</th><th>剥奪ロール (Revoked)</th></tr></thead><tbody>"#);
                for a in &roles.assignment_changes {
                    out.push_str(&format!(r#"
                    <tr>
                      <td><b>{}</b></td>
                      <td style="color:#86efac;">{}</td>
                      <td style="color:#fca5a5;">{}</td>
                    </tr>
                    "#,
                        escape_html(&a.target),
                        if a.added.is_empty() { "-".into() } else { escape_html(&a.added.join(", ")) },
                        if a.removed.is_empty() { "-".into() } else { escape_html(&a.removed.join(", ")) }
                    ));
                }
                if let Some((old_d, new_d)) = &roles.default_roles_changed {
                    out.push_str(&format!(r#"
                    <tr>
                      <td><b>未知ユーザー (Defaults)</b></td>
                      <td colspan="2">旧: {:?} ➔ 新: {:?}</td>
                    </tr>
                    "#, old_d, new_d));
                }
                out.push_str("</tbody></table>");
            }

            out.push_str("</div>");
        }

        // (3) Bundle Files
        if let Some(ref bundle) = config.bundle_diff {
            out.push_str(r#"<div class="card-block"><h3 style="margin-top:0;">Bundle Policy Files</h3><ul class="details-list">"#);
            for f in &bundle.added_policies {
                out.push_str(&format!(r#"<li style="color:#86efac;">+ 追加ファイル: {}</li>"#, escape_html(f)));
            }
            for f in &bundle.removed_policies {
                out.push_str(&format!(r#"<li style="color:#fca5a5;">- 削除ファイル: {}</li>"#, escape_html(f)));
            }
            out.push_str("</ul></div>");
        }
    }

    // 2. Global Configurations 差分
    out.push_str(r#"<div class="section-title">⚙️ グローバルポリシー設定の差分</div>"#);
    if report.global_diffs.is_empty() {
        out.push_str(r#"<p style="color: var(--text-muted); font-size: 13px;">グローバル設定に変更はありません。</p>"#);
    } else {
        out.push_str(r#"
    <table class="diff-table">
      <thead>
        <tr>
          <th>項目 (Key)</th>
          <th>旧値 (Old)</th>
          <th>新値 (New)</th>
          <th>影響度 (Impact)</th>
          <th>説明</th>
        </tr>
      </thead>
      <tbody>
"#);
        for g in &report.global_diffs {
            let (badge_class, badge_label) = match g.impact {
                SecurityImpact::Relaxed => ("badge-relaxed", "🔴 RELAXED (弱化)"),
                SecurityImpact::Hardened => ("badge-hardened", "🟢 HARDENED (強化)"),
                SecurityImpact::Neutral => ("badge-neutral", "⚪ NEUTRAL"),
            };
            out.push_str(&format!(r#"
        <tr>
          <td><code>{}</code></td>
          <td style="color: #fca5a5;">{}</td>
          <td style="color: #86efac;">{}</td>
          <td><span class="badge {}">{}</span></td>
          <td style="color: var(--text-muted);">{}</td>
        </tr>
"#,
                escape_html(&g.key),
                escape_html(&g.old_value),
                escape_html(&g.new_value),
                badge_class,
                badge_label,
                escape_html(&g.description)
            ));
        }
        out.push_str("</tbody></table>");
    }

    // 3. ルール差分（ファイル別グループ表示）
    out.push_str(r#"<div class="section-title">📜 個別ルールの差分詳細</div>"#);
    if file_groups.is_empty() {
        out.push_str(r#"<p style="color: var(--text-muted); font-size: 13px;">ルールに変更はありません。</p>"#);
    } else {
        for (file_name, rules) in file_groups {
            let file_changed_count = rules.iter().filter(|r| !matches!(r, RuleDiffItem::Unchanged { .. })).count();
            
            out.push_str(&format!(r#"
    <div class="file-group">
      <div class="file-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
        <span>📁 {} <span style="font-size: 12px; color: var(--text-muted); margin-left: 8px;">(変更: {}ルール)</span></span>
        <span>▼</span>
      </div>
      <div class="file-body">
"#,
                escape_html(file_name),
                file_changed_count
            ));

            for item in rules {
                match item {
                    RuleDiffItem::Modified { id, impact, details, .. } => {
                        let (card_class, badge_class, badge_label) = match impact {
                            SecurityImpact::Relaxed => ("relaxed", "badge-relaxed", "🔴 変更 (弱化)"),
                            SecurityImpact::Hardened => ("hardened", "badge-hardened", "🟢 変更 (強化)"),
                            SecurityImpact::Neutral => ("neutral", "badge-neutral", "⚪ 変更 (ニュートラル)"),
                        };
                        out.push_str(&format!(r#"
        <div class="rule-card {}">
          <div class="rule-title">
            <span>rule_id: "{}"</span>
            <span class="badge {}">{}</span>
          </div>
          <ul class="details-list">
"#, card_class, escape_html(id), badge_class, badge_label));
                        for d in details {
                            out.push_str(&format!("<li>{}</li>", escape_html(d)));
                        }
                        out.push_str("</ul></div>");
                    }
                    RuleDiffItem::Added { rule, .. } => {
                        out.push_str(&format!(r#"
        <div class="rule-card added">
          <div class="rule-title">
            <span>rule_id: "{}"</span>
            <span class="badge badge-added">🔵 新規追加</span>
          </div>
          <div style="font-size: 12px; margin-top: 6px; color: var(--text-muted);">ルール定義プレビュー:</div>
          <pre class="code-preview">{}</pre>
        </div>
"#,
                            escape_html(&rule.id),
                            escape_html(&format!("{:#?}", rule))
                        ));
                    }
                    RuleDiffItem::Removed { rule, .. } => {
                        out.push_str(&format!(r#"
        <div class="rule-card removed">
          <div class="rule-title">
            <span>rule_id: "{}"</span>
            <span class="badge badge-removed">⚫ 削除</span>
          </div>
          <div style="font-size: 12px; margin-top: 6px; color: var(--text-muted);">削除されたルール定義:</div>
          <pre class="code-preview">{}</pre>
        </div>
"#,
                            escape_html(&rule.id),
                            escape_html(&format!("{:#?}", rule))
                        ));
                    }
                    RuleDiffItem::Unchanged { .. } => {}
                }
            }

            out.push_str("</div></div>");
        }
    }

    // JavaScript（アコーディオンの制御）
    out.push_str(r#"
</div>
<script>
  document.querySelectorAll('.file-header').forEach(header => {
    header.addEventListener('click', () => {
      const body = header.nextElementSibling;
      body.style.display = body.style.display === 'none' ? 'flex' : 'none';
      const arrow = header.querySelector('span:last-child');
      arrow.textContent = arrow.textContent === '▼' ? '▶' : '▼';
    });
  });
</script>
</body>
</html>
"#);

    out
}

/// HTML 特殊文字のエスケープ
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

