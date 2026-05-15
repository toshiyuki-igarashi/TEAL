// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
pub mod schema;
mod context;
mod storage;

use std::io;
use std::sync::OnceLock;

use chrono::Utc;
use tokio::sync::mpsc;
use tokio::task;
use uuid::Uuid;

use teal_policy_engine::util::{uid_to_name, ktime_prefix};
use teal_policy_engine::types::Effect;

use crate::types::{PreApprovalDraft, ApprovedTicket, PendingEntry, MgmtPendingStart, MgmtPendingStop, KernelEventLog};
use crate::utils::u32_to_str;
use self::schema::{
    AuditLogEntry, AuthInfo, LogType, ObjectInfo, PolicyEvalResult, SubjectInfo,
    SyscallContext, TicketRef, IssuedTicketInfo,
};

// グローバルなシングルトンインスタンス
static GLOBAL_MANAGER: OnceLock<EvidenceManager> = OnceLock::new();


/// 監査ログ管理マネージャー
/// メインスレッドとログ書き込みタスク（バックグラウンド）をつなぐ役割を持つ
pub struct EvidenceManager {
    /// ログエントリをバックグラウンドタスクへ送るための送信端
    /// バッファがいっぱいの場合は、送信側で待機(backpressure)が発生する
    tx: mpsc::Sender<AuditLogEntry>,
}

impl EvidenceManager {
    const FLUSH_INTERVAL_MS: u64 = 1000;    // 1秒

    /// 初期化関数 (main.rs の冒頭で一度だけ呼ぶ)
    pub fn init(buffer_size: usize) {
        let (tx, mut rx) = mpsc::channel(buffer_size);

        // 1. ログ書き込みタスク
        task::spawn(async move {
            while let Some(entry) = rx.recv().await {
                if let Err(e) = storage::write_log(&entry) {
                    eprintln!("{}[ERROR] Log Write Error: {}", ktime_prefix(), e);
                }
            }
        });

        // 2. 定期同期タスク (1秒おき)
        task::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(Self::FLUSH_INTERVAL_MS));
            loop {
                interval.tick().await;
                if let Err(e) = storage::force_flush() {
                    eprintln!("{}[ERROR] Log Flush Error: {}", ktime_prefix(), e);
                }
            }
        });

        // 3. SIGHUP 監視タスク (ローテーション用)
        // EvidenceManagerの責務として「ログの鮮度と継続性」を管理する
        task::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sighup = signal(SignalKind::hangup()).expect("Failed to setup SIGHUP handler");
            
            loop {
                sighup.recv().await;
                eprintln!("{}[INFO] SIGHUP received. Reopening audit log...", ktime_prefix());
                if let Err(e) = storage::reopen_log() {
                    eprintln!("{}[ERROR] Failed to rotate log via SIGHUP: {}", ktime_prefix(), e);
                }
            }
        });

        // GLOBAL_MANAGER にセット (2回呼ぶとパニックまたはエラーになる)
        if GLOBAL_MANAGER.set(EvidenceManager { tx }).is_err() {
            eprintln!("{}[ERROR]EvidenceManager is already initialized!", ktime_prefix());
        }
    }

    // ==========================================
    // Fast Path (Ticket Consumed)
    // ==========================================

    /// 便利関数: static アクセス
    pub fn instance() -> &'static EvidenceManager {
        GLOBAL_MANAGER.get().unwrap_or_else(|| {
            panic!("{}[ERROR]EvidenceManager is not initialized", ktime_prefix());
        })
    }

    /// 便利関数: インスタンス取得すら隠蔽して直接ログを打てるようにする
    pub async fn log_fast_path_static(log_type: LogType, event_log: &KernelEventLog, ticket: &ApprovedTicket) {
        // グローバルインスタンス経由で送信
        Self::instance().enqueue_fast_path(log_type, event_log, ticket).await;
    }

    /// Fast Path (チケット消費時) のログ記録
    /// 軽量化のため args は無し、TicketID参照のみ
    async fn enqueue_fast_path(&self, log_type: LogType, event_log: &KernelEventLog, ticket: &ApprovedTicket) {
        // Hash計算 (Slow Pathは実ファイルから計算)
        let hash = calculate_sha256(&ticket.origin_program).unwrap_or_else(|_| "HASH_CALC_FAILED".to_string());

        let entry = AuditLogEntry {
            ver: "1.5".to_string(),
            id: Uuid::new_v4().to_string(),
            log_type: log_type,
            ts: Utc::now(),
            host: get_hostname(),
            syscall_context: SyscallContext {
                uid: event_log.uid,
                user: uid_to_name(event_log.uid).unwrap_or_else(|_| "".to_string()),
                pid: 0,                         // pid: u32 => TODO: INFO より
                action: "-".to_string(),        // [TODO] INFOより
                subject: SubjectInfo {
                    path: ticket.origin_program.to_string(),
                    hash: hash,
                    applet: ticket.origin_applet.clone(),
                    script_path: ticket.origin_script.clone(),
                    args: None,
                },
                object: ObjectInfo {
                    kind: u32_to_str(ticket.op_mask),
                    path: ticket.object.clone(),
                    inode: event_log.obj_ino,
                },
            },
            environment_context: None,
            auth_info: AuthInfo::FastPath {
                ticket_context: TicketRef {
                    ticket_id: format!("T-{:09}", event_log.ticket_id),
                    uses_left: event_log.uses_left,
                    policy_rule: "cached".to_string(),
                },
            },
        };

        // チャネルに送信 (バッファがいっぱいの場合は待つ or エラーにする)
        // ここでは send().await で非同期に待つ設計
        self.send_entry(entry).await;
    }

    // ==========================================
    // Slow Path (Interactive Decision)
    // ==========================================

    /// 便利関数: static アクセス
    pub async fn log_slow_path_static(
        log_type: LogType,
        decision: Effect,
        is_cache: bool,
        ticket_id: &str,
        pending: &PendingEntry,
    ) {
        // グローバルインスタンス経由で送信
        Self::instance().enqueue_slow_path(log_type, decision, is_cache, ticket_id, pending).await;
    }

    /// Slow Path (承認時) のログ記録
    /// args, 署名情報などが必須
    pub async fn enqueue_slow_path(
        &self,
        log_type: LogType,
        decision: Effect,
        is_cache: bool,
        ticket_id: &str,
        pending: &PendingEntry,
    ) {
        // 1. Enrich: コンテキスト解決
        let env_ctx = context::ContextResolver::resolve(pending.subject.pid);
        
        // 2. Hash計算 (Slow Pathは実ファイルから計算)
        let hash = calculate_sha256(&pending.subject.program_path).unwrap_or_else(|_| "HASH_CALC_FAILED".to_string());

        // 3. 構造体組み立て
        let entry = AuditLogEntry {
            ver: "1.5".to_string(),
            id: pending.audit_id.clone(),
            log_type,
            ts: Utc::now(),
            host: get_hostname(),
            syscall_context: SyscallContext {
                uid: pending.subject.uid,
                user: uid_to_name(pending.subject.uid).unwrap_or_else(|_| "".to_string()),
                pid: pending.subject.pid,
                action: u32_to_str(pending.op),
                subject: SubjectInfo {
                    path: pending.subject.program_path.clone(),
                    hash,
                    applet: pending.subject.applet_name.clone(),
                    script_path: pending.subject.script_path.clone(),
                    args: None,
                },
                object: ObjectInfo {
                    kind: "unknown".to_string(),
                    path: pending.object.path.clone(),
                    inode: pending.object.inode,
                },
            },
            environment_context: Some(env_ctx),
            auth_info: AuthInfo::SlowPath {
                policy_eval: PolicyEvalResult {
                    rule_id: match &pending.rule_id {
                        Some(id) => id.clone(),
                        None => "".to_string(),
                    },
                    matched_file: "unknown".to_string(),
                    mpa_level_required: pending.mpa_state.threshold,
                    decision,
                    issued_ticket: if is_cache {
                        Some(IssuedTicketInfo {
                            ticket_id: ticket_id.to_string(),
                            ttl_sec: pending.ttl_seconds,
                        })
                    } else {
                        None
                    },
                },
                mpa_proof: pending.mpa_state.clone(),
            },
        };

        // 4. チャネルに送信 (バッファがいっぱいの場合は待つ or エラーにする)
        self.send_entry(entry).await;
    }

    /// 便利関数: static アクセス
    pub async fn log_ticket_add_static(
        log_type: LogType,
        decision: Effect,
        draft: &PreApprovalDraft,
        ticket: &ApprovedTicket,
    ) {
        // グローバルインスタンス経由で送信
        Self::instance().enqueue_ticket_add(log_type, decision, draft, ticket).await;
    }

    /// Ticket Add (承認時) のログ記録
    /// args, 署名情報などが必須
    pub async fn enqueue_ticket_add(
        &self,
        log_type: LogType,
        decision: Effect,
        draft: &PreApprovalDraft,
        ticket: &ApprovedTicket,
    ) {
        // 2. Hash計算 (Slow Pathは実ファイルから計算)
        let hash = calculate_sha256(&ticket.origin_program).unwrap_or_else(|_| "HASH_CALC_FAILED".to_string());

        // 3. 構造体組み立て
        let entry = AuditLogEntry {
            ver: "1.5".to_string(),
            id: draft.audit_id.clone(),
            log_type,
            ts: Utc::now(),
            host: get_hostname(),
            syscall_context: SyscallContext {
                uid: draft.uid,
                user: uid_to_name(ticket.uid).unwrap_or_else(|_| "".to_string()),
                pid: 0,
                action: u32_to_str(draft.op_mask),
                subject: SubjectInfo {
                    path: ticket.origin_program.clone(),
                    hash,
                    applet: ticket.origin_applet.clone(),
                    script_path: ticket.origin_script.clone(),
                    args: None,
                },
                object: ObjectInfo {
                    kind: "unknown".to_string(),
                    path: ticket.object.clone(),
                    inode: ticket.object_id.ino,
                },
            },
            environment_context: None,
            auth_info: AuthInfo::SlowPath {
                policy_eval: PolicyEvalResult {
                    rule_id: draft.rule_id.clone(),
                    matched_file: "unknown".to_string(),
                    mpa_level_required: draft.mpa_state.threshold,
                    decision,
                    issued_ticket: Some(IssuedTicketInfo {
                            ticket_id: ticket.ticket_id.clone(),
                            ttl_sec: ticket.ttl_sec,
                        }),
                },
                mpa_proof: draft.mpa_state.clone(),
            },
        };

        // 4. チャネルに送信 (バッファがいっぱいの場合は待つ or エラーにする)
        self.send_entry(entry).await;
    }

    /// 便利関数: static アクセス
    pub async fn log_enforce_start_static(
        log_type: LogType,
        decision: Effect,
        pending_start: &MgmtPendingStart,
    ) {
        // グローバルインスタンス経由で送信
        Self::instance().enqueue_enforce_start(log_type, decision, pending_start).await;
    }

    /// enforce mode start (承認時) のログ記録
    /// args, 署名情報などが必須
    pub async fn enqueue_enforce_start(
        &self,
        log_type: LogType,
        decision: Effect,
        pending_start: &MgmtPendingStart,
    ) {
        // 2. Hash計算 (Slow Pathは実ファイルから計算)
        let hash = calculate_sha256("/bin/teal-cli").unwrap_or_else(|_| "HASH_CALC_FAILED".to_string());

        // 3. 構造体組み立て
        let entry = AuditLogEntry {
            ver: "1.5".to_string(),
            id: pending_start.audit_id.clone(),
            log_type,
            ts: Utc::now(),
            host: get_hostname(),
            syscall_context: SyscallContext {
                uid: pending_start.initiator_uid,
                user: pending_start.initiator_user.clone(),
                pid: 0,
                action: "enable enforce mode".to_string(),
                subject: SubjectInfo {
                    path: "/bin/teal-cli".to_string(),
                    hash,
                    applet: None,
                    script_path: None,
                    args: Some("start".to_string()),
                },
                object: ObjectInfo {
                    kind: "unknown".to_string(),
                    path: "system:mode/enforce".to_string(),
                    inode: 0,
                },
            },
            environment_context: None,
            auth_info: AuthInfo::SlowPath {
                policy_eval: PolicyEvalResult {
                    rule_id: "".to_string(),
                    matched_file: "management.json".to_string(),
                    mpa_level_required: pending_start.mpa_state.threshold,
                    decision,
                    issued_ticket: None,
                },
                mpa_proof: pending_start.mpa_state.clone(),
            },
        };

        // 4. チャネルに送信 (バッファがいっぱいの場合は待つ or エラーにする)
        self.send_entry(entry).await;
    }

    /// 便利関数: static アクセス (STOP用)
    pub async fn log_enforce_stop_static(
        log_type: LogType,
        decision: Effect,
        pending_stop: &MgmtPendingStop,
    ) {
        // グローバルインスタンス経由で送信
        Self::instance().enqueue_enforce_stop(log_type, decision, pending_stop).await;
    }

    /// enforce mode stop (承認時) のログ記録
    pub async fn enqueue_enforce_stop(
        &self,
        log_type: LogType,
        decision: Effect,
        pending_stop: &MgmtPendingStop,
    ) {
        let hash = calculate_sha256("/bin/teal-cli").unwrap_or_else(|_| "HASH_CALC_FAILED".to_string());

        let entry = AuditLogEntry {
            ver: "1.5".to_string(),
            id: pending_stop.audit_id.clone(),
            log_type,
            ts: Utc::now(),
            host: get_hostname(),
            syscall_context: SyscallContext {
                uid: pending_stop.initiator_uid,
                user: pending_stop.initiator_user.clone(),
                pid: 0,
                action: "disable enforce mode".to_string(),
                subject: SubjectInfo {
                    path: "/bin/teal-cli".to_string(),
                    hash,
                    applet: None,
                    script_path: None,
                    args: Some("stop".to_string()),
                },
                object: ObjectInfo {
                    kind: "unknown".to_string(),
                    path: "system:mode/audit".to_string(),
                    inode: 0,
                },
            },
            environment_context: None,
            auth_info: AuthInfo::SlowPath {
                policy_eval: PolicyEvalResult {
                    rule_id: "".to_string(),
                    matched_file: "management.json".to_string(),
                    mpa_level_required: pending_stop.mpa_state.threshold,
                    decision,
                    issued_ticket: None,
                },
                mpa_proof: pending_stop.mpa_state.clone(),
            },
        };

        self.send_entry(entry).await;
    }

    // ==========================================
    // Helpers
    // ==========================================

    /// 共通の送信ロジック
    async fn send_entry(&self, entry: AuditLogEntry) {
        if let Err(e) = self.tx.send(entry).await {
            eprintln!("{}[ERROR]Evidence: Failed to send log to channel: {}", ktime_prefix(), e);
        }
    }
}


/// ホスト名を取得 (簡易実装)
fn get_hostname() -> String {
    hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string())
}

/// ファイルのSHA256ハッシュを計算
pub fn calculate_sha256(path: &str) -> io::Result<String> {
    use sha2::{Sha256, Digest};
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    Ok(format!("sha256:{:x}", result))
}

