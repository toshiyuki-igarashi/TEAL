// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::ai::types::AiEvent;
use crate::ai::AggregatorConfig;
use crate::evidence::schema::LogType;

/// 引数パターンの客観的骨格（スケルトン）と統計
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiArgumentPattern {
    /// 抽出されたオプションフラグ列 (例: ["-s", "-X", "POST"])
    pub flags: Vec<String>,

    /// フラグ以外の位置引数 (ファイル名やURLなど) のトークン数
    pub non_flag_token_count: u32,

    /// シェル制御記号 (パイプ |, リダイレクト >, セミコロン ; 等) が含まれているか
    pub has_shell_operators: bool,

    /// 最初に出現した引数のサンプル
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_args_first: Option<String>,

    /// 最後に出現した引数のサンプル（引数が複数あり、かつ変化した場合のみ記録）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_args_last: Option<String>,

    /// 集約対象となったユニークな引数文字列の数 (1なら全イベント完全同一)
    pub unique_args_count: u64,
}

impl AiArgumentPattern {
    /// 生引数文字列から初期パターンを生成
    pub fn from_raw_args(args: Option<&str>) -> Option<Self> {
        let args_str = args?;
        let mut flags = Vec::new();
        let mut non_flag_token_count = 0;
        let mut has_shell_operators = false;

        for token in args_str.split_whitespace() {
            if matches!(token, "|" | ">" | ">>" | "<" | ";" | "&&" | "||") {
                has_shell_operators = true;
            } else if let Some((opt, _val)) =
                token.strip_prefix("--").and_then(|t| t.split_once('='))
            {
                // --option=value の形式:
                // フラグ部分 (--option) を追加し、value は非フラグトークンとしてカウント
                flags.push(format!("--{opt}"));
                non_flag_token_count += 1;
            } else if token.starts_with('-') {
                flags.push(token.to_string());
            } else {
                non_flag_token_count += 1;
            }
        }

        Some(Self {
            flags,
            non_flag_token_count,
            has_shell_operators,
            sample_args_first: Some(args_str.to_string()),
            sample_args_last: None,
            unique_args_count: 1,
        })
    }

    /// 2つの引数パターンが集約可能（構文構造が一致）かどうか
    pub fn is_compatible_with(
        &self,
        other_flags: &[String],
        other_non_flag_count: u32,
        other_has_shell_ops: bool,
    ) -> bool {
        self.flags == other_flags
            && self.non_flag_token_count == other_non_flag_count
            && self.has_shell_operators == other_has_shell_ops
    }
}

#[derive(Debug, Clone)]
pub struct AiAggregationResult {
    pub events: Vec<AiAggregatedEvent>,

    /// aggregation_id -> 集約元の全イベントID
    pub source_event_ids: HashMap<String, Vec<String>>,
}

/// 連続した同質操作シーケンスを客観的事実としてまとめた集約イベント
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAggregatedEvent {
    pub aggregation_id: String,

    // -------------------------------------------------------------------------
    // 1. 実行主体 (Subject Context) - 同一の実行単位
    // -------------------------------------------------------------------------
    pub user: String,
    pub pid: u32,
    pub binary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<AiArgumentPattern>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_client: Option<String>,

    // -------------------------------------------------------------------------
    // 2. 操作・認可 (Action & Policy Context) - TEALの判定事実
    // -------------------------------------------------------------------------
    pub action: String,
    pub log_type: LogType,
    /// 集約開始時のポリシー世代
    pub epoch_start: u32,
    /// 集約終了時のポリシー世代（途中でポリシーリロードがあった場合に記録）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_end: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,

    // -------------------------------------------------------------------------
    // 3. 時間・頻度パターン (Temporal & Volumetric Metrics) - 客観的メトリクス
    // -------------------------------------------------------------------------
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_ms: u64,
    pub event_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_interval_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_interval_ms: Option<u64>,

    // -------------------------------------------------------------------------
    // 4. 操作対象のスコープ (Object Scope) - 客観的なパス情報
    // -------------------------------------------------------------------------
    pub target_base_path: String,
    pub unique_target_count: u64,
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_new_path: Option<String>,

    // -------------------------------------------------------------------------
    // 5. 監査追跡性 (Auditability) - TEALの証拠チェーン
    // -------------------------------------------------------------------------
    /// 代表イベントID (先頭・末尾など最大3件)
    pub evidence_event_ids: Vec<String>,
}

/// 共通プレフィックス（基底ディレクトリ）を算出するヘルパー
fn common_base_path(paths: &[&str]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let first = paths[0];
    let mut prefix_len = first.len();

    for path in &paths[1..] {
        while !path.starts_with(&first[..prefix_len]) {
            if let Some(idx) = first[..prefix_len].rfind('/') {
                prefix_len = idx + 1;
            } else {
                return String::new();
            }
        }
    }
    first[..prefix_len].to_string()
}

/// 時系列の AiEvent リストを集約し、順序を維持した AiAggregatedEvent リストを生成
pub fn aggregate_events(
    analysis_id: &str,
    events: &[AiEvent],
    config: &AggregatorConfig,
) -> AiAggregationResult {
    if events.is_empty() {
        return AiAggregationResult {
            events: Vec::new(),
            source_event_ids: HashMap::new(),
        };
    }

    let mut aggregated = Vec::new();
    let mut source_event_ids = HashMap::new();
    let mut current_block: Option<AggregatingBlock> = None;
    let mut seq_num = 1;

    for event in events {
        match current_block.take() {
            None => {
                current_block = Some(AggregatingBlock::new(event));
            }
            Some(mut block) => {
                if block.can_merge(event, config) {
                    block.merge(event);
                    current_block = Some(block);
                } else {
                    let (aggregated_event, source_ids) =
                        block.finish(format!("{}-agg-{}", analysis_id, seq_num));
                    source_event_ids.insert(aggregated_event.aggregation_id.clone(), source_ids);
                    aggregated.push(aggregated_event);
                    seq_num += 1;

                    current_block = Some(AggregatingBlock::new(event));
                }
            }
        }
    }

    if let Some(block) = current_block {
        let (aggregated_event, source_ids) =
            block.finish(format!("{}-agg-{}", analysis_id, seq_num));
        source_event_ids.insert(aggregated_event.aggregation_id.clone(), source_ids);
        aggregated.push(aggregated_event);
    }

    AiAggregationResult {
        events: aggregated,
        source_event_ids,
    }
}

/// 集約処理の内部バッファ
struct AggregatingBlock<'a> {
    user: String,
    pid: u32,
    binary: String,
    script_path: Option<String>,
    applet: Option<String>,
    remote_client: Option<String>,
    action: String,
    log_type: LogType,
    rule: Option<String>,
    ticket_id: Option<String>,
    target_kind: String,

    epoch_start: u32,
    epoch_end: u32,

    start_time: DateTime<Utc>,
    last_time: DateTime<Utc>,
    event_count: u32,
    min_interval_ms: Option<u64>,
    max_interval_ms: Option<u64>,

    // 引数追跡
    args_pattern: Option<AiArgumentPattern>,
    unique_args: HashSet<&'a str>,

    // 対象パス追跡
    target_paths: Vec<&'a str>,
    sample_target: Option<String>,
    sample_new_path: Option<String>,

    // 証跡ID追跡 (先頭, 末尾など最大3つ)
    first_event_id: String,
    last_event_id: Option<String>,
    mid_event_id: Option<String>,

    source_event_ids: Vec<String>,
}

impl<'a> AggregatingBlock<'a> {
    fn new(event: &'a AiEvent) -> Self {
        let mut unique_args = HashSet::new();
        if let Some(ref a) = event.args {
            unique_args.insert(a.as_str());
        }

        Self {
            user: event.user.clone(),
            pid: event.pid,
            binary: event.binary.clone(),
            script_path: event.script_path.clone(),
            applet: event.applet.clone(),
            remote_client: event.remote_client.clone(),
            action: event.action.clone(),
            log_type: event.log_type.clone(),
            rule: event.rule.clone(),
            ticket_id: event.ticket_id.clone(),
            target_kind: event.target_kind.clone(),

            epoch_start: event.epoch,
            epoch_end: event.epoch,

            start_time: event.timestamp,
            last_time: event.timestamp,
            event_count: 1,
            min_interval_ms: None,
            max_interval_ms: None,

            args_pattern: AiArgumentPattern::from_raw_args(event.args.as_deref()),
            unique_args,

            target_paths: vec![event.target_path.as_str()],
            sample_target: Some(event.target_path.clone()),
            sample_new_path: event.new_path.clone(),

            first_event_id: event.event_id.clone(),
            last_event_id: None,
            mid_event_id: None,

            source_event_ids: vec![event.event_id.clone()],
        }
    }

    fn can_merge(&self, event: &AiEvent, config: &AggregatorConfig) -> bool {
        if self.event_count >= config.max_group_events {
            return false;
        }

        let gap_ms = (event.timestamp - self.last_time).num_milliseconds();

        if gap_ms < 0 || (gap_ms as u64) > config.max_gap_ms {
            return false;
        }

        // 主体、操作、認可状態の完全一致（epochは除外）
        if self.user != event.user
            || self.pid != event.pid
            || self.binary != event.binary
            || self.script_path != event.script_path
            || self.applet != event.applet
            || self.remote_client != event.remote_client
            || self.action != event.action
            || self.log_type != event.log_type
            || self.rule != event.rule
            || self.ticket_id != event.ticket_id
            || self.target_kind != event.target_kind
        {
            return false;
        }

        // 引数の互換性チェック
        match (&self.args_pattern, event.args.as_deref()) {
            (None, None) => true,
            (Some(_), None) | (None, Some(_)) => false,
            (Some(pattern), Some(new_args)) => {
                if let Some(new_pattern) = AiArgumentPattern::from_raw_args(Some(new_args)) {
                    pattern.is_compatible_with(
                        &new_pattern.flags,
                        new_pattern.non_flag_token_count,
                        new_pattern.has_shell_operators,
                    )
                } else {
                    false
                }
            }
        }
    }

    fn merge(&mut self, event: &'a AiEvent) {
        self.event_count += 1;
        self.epoch_end = event.epoch;

        // 間隔計算
        let interval = (event.timestamp - self.last_time).num_milliseconds();
        if interval >= 0 {
            let interval_ms = interval as u64;
            self.min_interval_ms = Some(
                self.min_interval_ms
                    .map_or(interval_ms, |min| min.min(interval_ms)),
            );
            self.max_interval_ms = Some(
                self.max_interval_ms
                    .map_or(interval_ms, |max| max.max(interval_ms)),
            );
        }
        self.last_time = event.timestamp;

        // 引数の更新
        if let Some(ref a) = event.args {
            self.unique_args.insert(a.as_str());
            if let Some(ref mut pat) = self.args_pattern {
                pat.sample_args_last = Some(a.clone());
            }
        }

        // 対象パスの追跡
        self.target_paths.push(event.target_path.as_str());
        if self.sample_new_path.is_none() && event.new_path.is_some() {
            self.sample_new_path = event.new_path.clone();
        }

        // 証跡IDの更新（2件目は中間、それ以降は末尾を更新）
        if self.event_count == 2 {
            self.last_event_id = Some(event.event_id.clone());
        } else if self.event_count > 2 {
            if self.mid_event_id.is_none() {
                self.mid_event_id = self.last_event_id.take();
            }
            self.last_event_id = Some(event.event_id.clone());
        }

        self.source_event_ids.push(event.event_id.clone());
    }

    fn finish(mut self, aggregation_id: String) -> (AiAggregatedEvent, Vec<String>) {
        let duration_ms = (self.last_time - self.start_time).num_milliseconds().max(0) as u64;

        if let Some(ref mut pat) = self.args_pattern {
            pat.unique_args_count = self.unique_args.len() as u64;
            // 変化がなかった場合は sample_args_last を None に戻してトークン節約
            if pat.unique_args_count <= 1 {
                pat.sample_args_last = None;
            }
        }

        let unique_targets: HashSet<&str> = self.target_paths.iter().copied().collect();
        let target_base_path = common_base_path(&self.target_paths);

        let mut evidence_event_ids = vec![self.first_event_id];
        if let Some(mid) = self.mid_event_id {
            evidence_event_ids.push(mid);
        }
        if let Some(last) = self.last_event_id {
            evidence_event_ids.push(last);
        }

        let epoch_end = if self.epoch_end != self.epoch_start {
            Some(self.epoch_end)
        } else {
            None
        };

        (
            AiAggregatedEvent {
                aggregation_id,
                user: self.user,
                pid: self.pid,
                binary: self.binary,
                script_path: self.script_path,
                applet: self.applet,
                args: self.args_pattern,
                remote_client: self.remote_client,

                action: self.action,
                log_type: self.log_type,
                epoch_start: self.epoch_start,
                epoch_end,
                rule: self.rule,
                ticket_id: self.ticket_id,

                start_time: self.start_time,
                end_time: self.last_time,
                duration_ms,
                event_count: self.event_count,
                min_interval_ms: self.min_interval_ms,
                max_interval_ms: self.max_interval_ms,

                target_base_path,
                unique_target_count: unique_targets.len() as u64,
                target_kind: self.target_kind,
                sample_target: self.sample_target,
                sample_new_path: self.sample_new_path,

                evidence_event_ids,
            },
            self.source_event_ids,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn make_test_event(
        id: &str,
        ts: DateTime<Utc>,
        target: &str,
        new_p: Option<&str>,
        args: Option<&str>,
        epoch: u32,
    ) -> AiEvent {
        AiEvent {
            event_id: id.to_string(),
            timestamp: ts,
            log_type: LogType::AccessAllowed,
            epoch,
            user: "root".to_string(),
            pid: 100,
            action: "RENAME".to_string(),
            binary: "/usr/bin/mv".to_string(),
            script_path: None,
            applet: None,
            args: args.map(|s| s.to_string()),
            target_path: target.to_string(),
            target_kind: "file".to_string(),
            new_path: new_p.map(|s| s.to_string()),
            remote_client: None,
            rule: None,
            ticket_id: None,
        }
    }

    #[test]
    fn test_mass_rename_aggregation() {
        let start = Utc::now();
        let events: Vec<AiEvent> = (0..20)
            .map(|i| {
                let ts = start + ChronoDuration::milliseconds(i * 100);
                let target = format!("/data/docs/file_{i:03}.txt");
                let new_p = format!("/data/docs/file_{i:03}.enc");
                let args = format!("file_{i:03}.txt file_{i:03}.enc");
                // 10件目でepochが更新されるシナリオ
                let epoch = if i < 10 { 1 } else { 2 };
                make_test_event(
                    &format!("evt-{i:03}"),
                    ts,
                    &target,
                    Some(&new_p),
                    Some(&args),
                    epoch,
                )
            })
            .collect();

        let result = aggregate_events("A-001", &events, &AggregatorConfig::default());

        // 20件が1件の集約イベントに圧縮されること
        assert_eq!(result.events.len(), 1);

        let agg = &result.events[0];

        assert_eq!(agg.aggregation_id, "A-001-agg-1");
        assert_eq!(agg.event_count, 20);
        assert_eq!(agg.unique_target_count, 20);
        assert_eq!(agg.target_base_path, "/data/docs/");
        assert_eq!(agg.epoch_start, 1);
        assert_eq!(agg.epoch_end, Some(2)); // epoch更新がメタデータとして残る

        let pat = agg.args.as_ref().unwrap();
        assert_eq!(pat.non_flag_token_count, 2);
        assert_eq!(pat.unique_args_count, 20);
        assert!(pat.sample_args_first.is_some());
        assert!(pat.sample_args_last.is_some());

        // 証跡IDは最初・中間・最後で最大3件
        assert_eq!(agg.evidence_event_ids.len(), 3);
        assert_eq!(agg.evidence_event_ids[0], "evt-000");
        assert_eq!(agg.evidence_event_ids[2], "evt-019");

        let source_ids = result.source_event_ids.get(&agg.aggregation_id).unwrap();

        assert_eq!(source_ids.len(), 20);
        assert_eq!(source_ids[0], "evt-000");
        assert_eq!(source_ids[19], "evt-019");
    }

    #[test]
    fn test_differing_args_flags_split() {
        let now = Utc::now();
        let e1 = make_test_event("e1", now, "/a", None, Some("-s http://ex.com"), 1);
        let e2 = make_test_event("e2", now, "/a", None, Some("-X POST http://ex.com"), 1);

        let result = aggregate_events("A-002", &[e1, e2], &AggregatorConfig::default());

        // 2つの集約グループが生成される
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.source_event_ids.len(), 2);

        // 各集約グループと元イベントIDの対応を確認
        for (i, agg) in result.events.iter().enumerate() {
            let source_ids = result
                .source_event_ids
                .get(&agg.aggregation_id)
                .expect("Source event IDs not found");

            assert_eq!(source_ids.len(), 1);

            let expected_id = format!("e{}", i + 1);
            assert_eq!(source_ids[0], expected_id);
        }
    }

    #[test]
    fn test_option_value_aggregation() {
        let now = Utc::now();

        let e1 = make_test_event("e1", now, "/a", None, Some("--output=file1.txt /data/a"), 1);

        let e2 = make_test_event("e2", now, "/b", None, Some("--output=file2.txt /data/b"), 1);

        let result = aggregate_events("A-003", &[e1, e2], &AggregatorConfig::default());

        assert_eq!(result.events.len(), 1);

        let agg = &result.events[0];
        let pattern = agg.args.as_ref().unwrap();

        assert_eq!(pattern.flags, vec!["--output"]);
        assert_eq!(pattern.non_flag_token_count, 2);
        assert_eq!(pattern.unique_args_count, 2);

        assert_eq!(
            result.source_event_ids[&agg.aggregation_id],
            vec!["e1", "e2"]
        );
    }

    #[test]
    fn test_aggregation_max_group_events() {
        let start = Utc::now();

        let events: Vec<AiEvent> = (0..100)
            .map(|i| {
                make_test_event(
                    &format!("evt-{i:03}"),
                    start + ChronoDuration::milliseconds(i * 100),
                    &format!("/data/file-{i:03}"),
                    None,
                    None,
                    1,
                )
            })
            .collect();

        let config = AggregatorConfig {
            max_gap_ms: 1000,
            max_group_events: 50,
        };

        let result = aggregate_events("test", &events, &config);

        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].event_count, 50);
        assert_eq!(result.events[1].event_count, 50);
    }

    #[test]
    fn test_aggregation_max_gap() {
        let start = Utc::now();

        let events = vec![
            make_test_event("e1", start, "/a", None, None, 1),
            make_test_event(
                "e2",
                start + ChronoDuration::milliseconds(500),
                "/b",
                None,
                None,
                1,
            ),
            make_test_event(
                "e3",
                start + ChronoDuration::milliseconds(2500),
                "/c",
                None,
                None,
                1,
            ),
        ];

        let config = AggregatorConfig {
            max_gap_ms: 1000,
            max_group_events: 100,
        };

        let result = aggregate_events("test", &events, &config);

        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].event_count, 2);
        assert_eq!(result.events[1].event_count, 1);
    }
}
