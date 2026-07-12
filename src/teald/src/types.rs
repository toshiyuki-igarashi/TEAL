// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::fs::File;

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use hex;
use blst::min_pk::{Signature, AggregateSignature};

use teal_policy_engine::ir::CompiledRule;
use teal_policy_engine::util::{uid_to_name, normalize_tty_name, ktime_prefix};
use teal_policy_engine::types::{Effect, RuleType};

use crate::evidence;
use crate::state::app_state;
use crate::bundle::bundle;
use crate::ticket::{is_ticketable, make_draft_id, ticket_from_entry};
use crate::worker::admin::find_rule;

#[derive(Debug, Clone)]
pub struct Request {
    pub id: u64,
    pub pid: u32,
    pub ppid: u32,          // 親プロセスID
    pub session_id: u32,    // セッションID
    pub uid: u32,
    pub gid: u32,           // グループID

    pub prog_dev: u64,      // 実行バイナリのデバイス番号
    pub prog_ino: u64,      // 実行バイナリのinode番号
    pub raw_program: String,

    pub raw_action: String,

    pub target_dev: u64,    // 操作対象のデバイス番号
    pub target_ino: u64,    // 操作対象のinode番号
    pub raw_target: String,

    pub new_target_dev: u64,        // 移動先のデバイス番号
    pub new_target_ino: u64,        // 移動先のinode番号
    pub raw_new_target: Option<String>,     // 移動先のパス

    pub script_dev: u64,    // スクリプトのデバイス番号
    pub script_ino: u64,    // スクリプトのinode番号
    pub raw_script: Option<String>,

    pub raw_applet: Option<String>,
    
    pub lsm_label_hex: String,     // LSMラベル (Hexエンコード)
    pub args_head: Option<String>, // コマンドライン引数先頭
    pub flag: u32,                 // リクエスト属性フラグ

    pub is_audit: bool,
    pub session_tty: String,
}

#[derive(Debug)]
pub struct AppState {
    pub fast: FastState,
    pub slow: SlowState,
    pub dev: TealDeviceState,
    pub is_enforce: bool,
    pub current_epoch: u32, // カーネル側の定義(u32)に合わせる
}

impl AppState {
    /// 次のチケットID（シーケンス番号）を生成する
    pub fn generate_next_ticket_seq(&mut self) -> u64 {
        // wrapping_add により、u64::MAX の次はパニックせず 0 に戻る
        let mut next = self.fast.next_draft_seq.wrapping_add(1);
        
        // 0 は NotManaged 用の予約値なので、万が一 0 になった場合は 1 にスキップする
        if next == 0 {
            next = 1;
        }
        
        self.fast.next_draft_seq = next;
        next
    }

    /// 指定されたTTYとUIDが、PAMで認証済みの正規セッションか厳密に検証する
    pub fn check_registered_session(&self, tty: &str, uid: u32) -> bool {
        if tty.is_empty() || tty == "-" {
            return false; // TTYが存在しない場合は未登録とみなす
        }

        // 1. TTY名の正規化（例: "/dev/pts/1" や "pts1" をすべて "pts1" に統一）
        let normalized_key = normalize_tty_name(tty);

        // 2. システム関数 (getpwuid) を使って、カーネルから来た UID をユーザー名に変換
        let request_user = match uid_to_name(uid) {
            Ok(name) => name,
            Err(e) => {
                eprintln!("[WARN] teald-Auth: Failed to resolve UID {}: {}", uid, e);
                return false; // UIDがシステム上で解決できない場合は不正プロセスとして拒否
            }
        };

        // 3. PAMがセッション開始時に登録したユーザー名と厳密に突き合わせる（ハイジャック防止）
        if let Some(registered_user) = self.slow.active_tty_sessions.get(&normalized_key) {
            // カーネルが証明する実行ユーザー名と、PAM認証を通過してその端末を開いた本人が一致するか検証
            let is_valid = request_user == *registered_user;
            
            if !is_valid {
                eprintln!(
                    "[SECURITY ALERT] TTY Hijack detected! Process (UID={}, User='{}') tried to use TTY {} which belongs to Registered User '{}'",
                    uid, request_user, normalized_key, registered_user
                );
            }
            
            is_valid
        } else {
            // そもそもPAMによるログインセッションが確立されていない端末からの要求
            false
        }
    }
}

#[derive(Debug)]
pub struct FastState {
    pub drafts: HashMap<String, PreApprovalDraft>,
    pub approved: HashMap<String, ApprovedTicket>, // 承認されたticket
    pub tickets: HashMap<String, ApprovedTicket>,    // ログ表示用 denyされた時、あるいはticket消費時に削除
    pub next_draft_seq: u64,
}

impl FastState {
    pub fn has_draft_for_rule(&self, rule_id: &String) -> bool {
        // draftsの値（PreApprovalDraft）を走査し、
        // memberのrule_id が rule_id と一致するものが1つでもあれば true を返す
        self.drafts.values().any(|draft| &draft.rule_id == rule_id)
    }
}

#[derive(Debug)]
pub struct SlowState {
    pub pending_requests: HashMap<u64, PendingEntry>,
    pub registered_keys: HashMap<u32, String>, // uid -> hex public key

    pub pending_start: Option<MgmtPendingStart>,
    pub pending_stop: Option<MgmtPendingStop>,

    // PAMから通知されたアクティブなログインセッション
    // キー: TTY名 (例: "pts/1")
    // 値: ログインしたユーザー名 (例: "alice")
    pub active_tty_sessions: HashMap<String, String>, 
}

#[derive(Debug)]
pub struct TealDeviceState {
    pub dev_teal_path: String,
    pub device_file: Option<File>,
}

#[derive(Debug, Clone)]
pub struct PreApprovalDraft {
    pub draft_id: String,

    /// 監査用ID (UUID v7推奨)。ログやSIEMでの検索キー。
    pub audit_id: String,
    // 監査・説明用
    pub rule_id: String,

    // Strict Context Binding（確定済み）
    pub uid: u32,
    pub origin_program_id: EntityId,
    pub origin_script_id: Option<EntityId>,
    pub origin_applet: Option<String>,
    
    // --- Source (移動元) ---
    pub object_id: EntityId,
    
    // --- Destination (移動先: RENAME時のみ使用) ---
    // 承認プロセスで「どこに移動させるか」を確定させるために必要
    pub new_object_id: Option<EntityId>, 
    
    pub op_mask: u32,

    // --- MPA Control (承認状態) ---
    pub mpa_state: MpaState,

    // Ticket 属性
    pub ttl_sec: u64,
    pub max_uses: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovedTicket {
    pub ticket_id: String,

    // 監査・説明用
    pub rule_id: String,
    pub origin_program: String,
    pub origin_script: Option<String>,
    pub object: String,
    pub new_object: Option<String>,

    // Strict Context Binding（確定済み）
    pub uid: u32,
    pub origin_program_id: EntityId,
    pub origin_script_id: Option<EntityId>,
    pub origin_applet: Option<String>,
    pub object_id: EntityId,
    pub new_object_id: Option<EntityId>,
    pub op_mask: u32,

    // Ticket 属性
    pub ttl_sec: u64,
    pub max_uses: u32,
}

impl ApprovedTicket {
    pub fn from_result(result: &PolicyResult) -> Option<Self> {
        let rule_id = result.rule_id.as_ref()?;
        let ticket = result.ticket.as_ref()?;
        let rule = find_rule(rule_id).ok()?;

        let origin_program = rule.subject.origin_program
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "ANY".to_string());

        let origin_script = rule.subject.origin_script
            .as_ref()
            .map(|p| p.to_string());

        // --- パス系 ---
        let object = rule.object.as_ref()
                .and_then(|obj| obj.path.as_ref())
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
        
        // new_object の抽出
        let new_object = rule.object.as_ref()
                .and_then(|obj| obj.new_path.as_ref())
                .map(|p| p.to_string());

        // --- ID系 ---
        let origin_program_id = EntityId::new((ticket.prog_dev, ticket.prog_ino));
        let object_id = EntityId::new((ticket.target_dev, ticket.target_ino));
        
        // new_object_id の構築
        let new_object_id = if ticket.new_target_dev != 0 || ticket.new_target_ino != 0 {
            Some(EntityId::new((ticket.new_target_dev, ticket.new_target_ino)))
        } else {
            None
        };

        let origin_script_id = if ticket.script_dev != 0 || ticket.script_ino != 0 {
            Some(EntityId::new((ticket.script_dev, ticket.script_ino)))
        } else {
            None
        };

        Some(ApprovedTicket {
            ticket_id: ticket.ticket_id.clone(),
            rule_id: rule_id.clone(),
            origin_program,
            origin_script,
            object,
            new_object,
            
            uid: ticket.uid,
            origin_program_id,
            origin_script_id,
            origin_applet: rule.subject.origin_applet.clone(),
            object_id,
            new_object_id,
            op_mask: ticket.op,

            ttl_sec: rule.pre_approval.ttl_sec,
            max_uses: rule.max_uses,
        })
    }

    pub fn from_draft(draft: &PreApprovalDraft) -> Option<Self> {
        if let Ok(rule) = find_rule(&draft.rule_id) {
            let origin_program = rule.subject.origin_program
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "ANY".to_string());

            let origin_script = rule.subject.origin_script
                .as_ref()
                .map(|p| p.to_string());

            let object = rule.object.as_ref()
                .and_then(|obj| obj.path.as_ref())
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            
            // new_object の抽出
            let new_object = rule.object.as_ref()
                .and_then(|obj| obj.new_path.as_ref())
                .map(|p| p.to_string());

            Some(ApprovedTicket {
                ticket_id: draft.draft_id.clone(),
                rule_id: rule.id,
                origin_program,
                origin_script,
                object,
                new_object,
                
                uid: draft.uid,
                origin_program_id: draft.origin_program_id,
                origin_script_id: draft.origin_script_id,
                origin_applet: draft.origin_applet.clone(),
                object_id: draft.object_id,
                new_object_id: draft.new_object_id,
                op_mask: draft.op_mask,

                ttl_sec: rule.pre_approval.ttl_sec,
                max_uses: rule.max_uses,
            })
        } else {
            None
        }
    }

    pub async fn from_entry(entry: &PendingEntry) -> Option<Self> {
        let rule_id = entry.rule_id.clone().unwrap_or_else(|| "".to_string());

        let origin_program_id = EntityId::new((entry.subject.prog_dev, entry.subject.prog_ino));
        let object_id = EntityId::new((entry.object.device_id, entry.object.inode));
        
        // new_object_id の構築
        let new_object_id = if let (Some(dev), Some(ino)) = (entry.object.new_device_id, entry.object.new_inode) {
            Some(EntityId::new((dev, ino)))
        } else {
            None
        };
        
        let origin_script_id = if entry.subject.script_dev != 0 || entry.subject.script_ino != 0 {
            Some(EntityId::new((entry.subject.script_dev, entry.subject.script_ino)))
        } else {
            None
        };

        Some(ApprovedTicket {
            ticket_id: make_draft_id().await,
            rule_id,
            
            origin_program: entry.subject.program_path.clone(),
            origin_script: entry.subject.script_path.clone(),
            object: entry.object.path.clone(),
            new_object: entry.object.new_path.clone(), // ★追加
            
            uid: entry.subject.uid,
            origin_program_id,
            origin_script_id,
            origin_applet: entry.subject.applet_name.clone(),
            
            object_id,
            new_object_id,
            op_mask: entry.op,

            ttl_sec: entry.ttl_seconds,
            max_uses: entry.max_uses,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct EntityId {
    pub dev: u64,
    pub ino: u64,
}
impl EntityId {
    pub const fn new(ids: (u64, u64)) -> Self {
        let (dev, ino) = ids;
        Self { dev, ino }
    }
}
impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.dev, self.ino)
    }
}

#[derive(Debug, Clone)]
pub struct MgmtPendingStart {
    pub initiator_uid: u32,
    pub initiator_user: String,

    /// 監査用ID (UUID v7推奨)。ログやSIEMでの検索キー。
    pub audit_id: String,

    // --- MPA Control (承認状態) ---
    pub mpa_state: MpaState,
    pub timeout_minutes: u32,
}

#[derive(Debug, Clone)]
pub struct PendingEntry {
    // --- 1. Identity & Traceability (Section 6.1) ---
    /// 監査用ID (UUID v7推奨)。ログやSIEMでの検索キー。
    pub audit_id: String,
    /// カーネル応答用ID (u64)。teald内部でのみ使用し、ログには出さない。
    pub transport_id: u64,
    /// リクエスト発生時刻
    pub timestamp: DateTime<Utc>,

    // --- 2. Subject Context (誰が) ---
    pub subject: SubjectContext,

    // --- 3. Object Context (何を) ---
    pub object: ObjectContext,

    // --- 4. Action (どうする) ---
    /// 操作種別 (open, exec, unlink, etc.)
    pub op: u32,        // または enum Action

    // --- 5. Policy & Decision (なぜ/結果) ---
    /// マッチしたルールID
    pub rule_id: Option<String>,
    /// ルールの説明
    pub reason: String,
    /// ポリシー世代番号 (Section 4.6 Epoch管理)
    pub policy_epoch: u32,
    /// キャッシュ有効期間 (0ならAuditのみ)
    pub ttl_seconds: u64,
    /// キャッシュ有効回数
    pub max_uses: u32,

    // --- 6. MPA Control (承認状態) ---
    pub mpa_state: MpaState,
}

pub fn str_to_mask(action: &String) -> u32 {
    match action.trim() {
        "READ"      => 1,
        "WRITE"     => 2,
        "EXECUTE"   => 4,
        "DELETE"    => 8,
        "UNLINK"    => 16,
        "RENAME"    => 32,
        "CHMOD"     => 64,
        "CHOWN"     => 128,
        "CONNECT"   => 256,
        "UNKNOWN"   => 512,
        _           => 512,
    }
}

impl PendingEntry {
    /// 内部ヘルパー: Request からルール非依存のベース部分だけを構築する
    fn from_base_req(req: &Request) -> Self {
        let decoded_lsm = match hex::decode(&req.lsm_label_hex) {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| req.lsm_label_hex.clone()),
            Err(_) => req.lsm_label_hex.clone(),
        };

        // op_mask などはデフォルト値を入れておき、後で上書きする
        PendingEntry {
            audit_id: Uuid::new_v4().to_string(), 
            transport_id: req.id,
            timestamp: Utc::now(),
            subject: SubjectContext {
                pid: req.pid,
                ppid: req.ppid,
                uid: req.uid,
                gid: req.gid,
                session_id: req.session_id,
                prog_dev: req.prog_dev,
                prog_ino: req.prog_ino,
                program_path: req.raw_program.clone(),
                script_dev: req.script_dev,
                script_ino: req.script_ino,
                script_path: req.raw_script.clone(),
                applet_name: req.raw_applet.clone(),
                program_hash: evidence::calculate_sha256(&req.raw_program).unwrap_or_else(|_| "HASH_CALC_FAILED".to_string()),
                lsm_label: decoded_lsm,
                client_ip: None,
                auth_method: None,
                session_tty: req.session_tty.clone(),
                cmd_args: req.args_head.clone(),
            },
            object: ObjectContext {
                path: req.raw_target.clone(),
                inode: req.target_ino,       
                device_id: req.target_dev,

                // RENAME 時のみ有効な情報を変換
                // 値が 0 なら None にする（カーネルが「無し」を示す一般的な値が 0 の場合）
                new_path: req.raw_new_target.clone(),
                new_inode: if req.new_target_ino != 0 { Some(req.new_target_ino) } else { None },
                new_device_id: if req.new_target_dev != 0 { Some(req.new_target_dev) } else { None },
            },
            
            // 以下は呼び出し元 (from_rule / from_audit) で上書きされる
            op: str_to_mask(&req.raw_action),
            rule_id: None,
            reason: "".to_string(),
            policy_epoch: 0,
            ttl_seconds: u64::MAX,
            max_uses: 1,
            mpa_state: MpaState::default(),
        }
    }

    /// Control Lane 用: ルールにマッチした場合 (NeedApproval など) に生成する
    pub fn from_rule(rule: &CompiledRule, req: &Request) -> Self {
        let mut entry = Self::from_base_req(req);
        
        entry.op = rule.action_match.to_u32();
        entry.rule_id = Some(rule.id.clone());
        entry.reason = rule.out_reason.clone();
        entry.ttl_seconds = rule.pre_approval.ttl_sec;
        entry.max_uses = rule.max_uses;
        entry.mpa_state = MpaState {
            threshold: rule.threshold(),
            approver_roles: rule.approver_roles(),
            required_roles: rule.approver_roles(),
            approvals: HashMap::new(),
            aggregated_signature: None,
        };
        
        entry
    }

    /// Audit Lane 用: ルールの有無に関わらず、判定結果 (Effect) を元に生成する
    pub fn from_audit(req: &Request, rule_id: Option<String>, effect: Effect) -> Self {
        let mut entry = Self::from_base_req(req);
        
        entry.rule_id = rule_id;
        if let Some(ref id) = entry.rule_id {
            if let Ok(rule) = find_rule(&id) {
                entry.op = rule.action_match.to_u32();
                entry.ttl_seconds = rule.pre_approval.ttl_sec;
                entry.max_uses = rule.max_uses;
            }
        }
        
        // Effect に応じてダミーの操作マスクや理由を詰める
        // ※AUDITモードでは実際のアクセスはすべて通っているため、
        // 「本来はどう判定されるべきだったか(Effect)」を reason 等に記録する
        match effect {
            Effect::Allow => {
                entry.reason = "Audit Mode: Action would be ALLOWED by policy".to_string();
            }
            Effect::Deny => {
                entry.reason = "Audit Mode: Action would be DENIED by policy".to_string();
            }
            Effect::NeedApproval => {
                entry.reason = "Audit Mode: Action would require APPROVAL by policy".to_string();
            }
            Effect::AuditOnly => {
                entry.reason = "Audit Mode: Shadow Rule Evaluation".to_string();
            }
        }
        
        entry
    }

    pub fn from(rule: CompiledRule, req: &Request) -> Self {
        // カーネルから受け取ったHex文字列をデコードする
        let decoded_lsm = match hex::decode(&req.lsm_label_hex) {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| req.lsm_label_hex.clone()),
            Err(_) => req.lsm_label_hex.clone(),
        };

        PendingEntry {
            audit_id: Uuid::new_v4().to_string(), 
            transport_id: req.id, // カーネル通信用のIDを保持
            timestamp: Utc::now(),
            subject: SubjectContext {
                pid: req.pid,
                ppid: req.ppid,               // カーネルから渡された値をそのまま使用
                uid: req.uid,
                gid: req.gid,                 // カーネルから渡された値をそのまま使用
                session_id: req.session_id,   // カーネルから渡された値をそのまま使用
                prog_dev: req.prog_dev,
                prog_ino: req.prog_ino,
                program_path: req.raw_program.clone(),
                script_dev: req.script_dev,
                script_ino: req.script_ino,
                script_path: req.raw_script.clone(),
                applet_name: req.raw_applet.clone(),
                // teald側でのハッシュ計算
                program_hash: evidence::calculate_sha256(&req.raw_program).unwrap_or_else(|_| "HASH_CALC_FAILED".to_string()),
                lsm_label: decoded_lsm,
                client_ip: None,   // 後続のエンリッチ処理 (SSHコンテキスト解決) で埋める
                auth_method: None, // 後続のエンリッチ処理で埋める
                session_tty: req.session_tty.clone(),
                cmd_args: req.args_head.clone(),
            },
            object: ObjectContext {
                path: req.raw_target.clone(),
                // TOCTOU対策: teald側で解決せず、カーネルから受信した不変の値を必ず使う
                inode: req.target_ino,       
                device_id: req.target_dev,   

                // RENAME 時のみ有効な情報を変換
                // 値が 0 なら None にする（カーネルが「無し」を示す一般的な値が 0 の場合）
                new_path: req.raw_new_target.clone(),
                new_inode: if req.new_target_ino != 0 { Some(req.new_target_ino) } else { None },
                new_device_id: if req.new_target_dev != 0 { Some(req.new_target_dev) } else { None },
            },
            op: rule.action_match.to_u32(),
            rule_id: Some(rule.id.clone()),
            reason: rule.out_reason.clone(),
            policy_epoch: 0,
            ttl_seconds: rule.pre_approval.ttl_sec,
            max_uses: rule.max_uses,
            mpa_state: MpaState {
                threshold: rule.threshold(),
                approver_roles: rule.approver_roles(),
                required_roles: rule.approver_roles(),
                approvals: HashMap::new(),
                aggregated_signature: None,
            },
        }
    }

    /// is_cacheable は Rule を受け取り、draft, ticketを作成、TicketPayloadを返す (Lazy Binding)
    pub async fn is_cacheable(&self, rule: &CompiledRule) -> Result<(bool, Option<TicketPayload>, String), String> {
        if rule.pre_approval.ttl_sec > 0 {
            match is_ticketable(rule) {
                Ok(_) => (),
                Err(err) => {
                    return Err(err);
                }
            }

            let ticket = ticket_from_entry(rule, self).await;

            {
                let mut state = app_state().lock().await;
                if state.fast.has_draft_for_rule(&rule.id)  {
                    return Err(format!("ticket is already in waiting list for approval (id= {})", rule.id));
                }
                state.fast.tickets.insert(ticket.ticket_id.clone(), ticket.clone());
            }

            // スクリプトパスが無い場合は dev/ino を 0 にする
            let (script_dev, script_ino) = if self.subject.script_path.is_some() {
                (self.subject.script_dev, self.subject.script_ino)
            } else {
                (0, 0)
            };

            // SubjectOnly の場合は、相手先 (target) を 0 (Any) にする
            let (target_dev, target_ino) = if rule.rule_type == RuleType::SubjectOnly {
                (0, 0)
            } else {
                (self.object.device_id, self.object.inode)
            };

            // new_target のメタデータ抽出
            let (new_target_dev, new_target_ino) = if rule.rule_type == RuleType::SubjectOnly {
                (0, 0)
            } else {
                (self.object.new_device_id.unwrap_or(0), self.object.new_inode.unwrap_or(0))
            };

            // Netlink 送信用の構造体 (TicketPayload) を組み立てる
            let payload = TicketPayload {
                uid: self.subject.uid,
                op: rule.action_match.to_u32(),
                prog_dev: self.subject.prog_dev,
                prog_ino: self.subject.prog_ino,
                script_dev,
                script_ino,
                applet_hash: 0,             // Alpha版暫定
                target_dev,
                target_ino,
                new_target_dev,
                new_target_ino,
                expires_in_sec: rule.pre_approval.ttl_sec,
                flags: rule.ticket_profile.flags,
                uses_left: rule.max_uses,
                ticket_id: ticket.ticket_id.clone(),
                epoch: self.policy_epoch,   // Alpha版暫定: 0
                audit_flags: rule.audit_level.to_u32(),
            };

            Ok((true, Some(payload), ticket.ticket_id))
        } else {
            Ok((false, None, "".to_string()))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubjectContext {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub session_id: u32,

    // Execution Paths
    pub prog_dev: u64,      // 追加: 実行バイナリのデバイス番号
    pub prog_ino: u64,      // 追加: 実行バイナリのinode番号
    pub program_path: String,
    pub script_dev: u64,    // 追加: スクリプトのデバイス番号
    pub script_ino: u64,    // 追加: スクリプトのinode番号
    pub script_path: Option<String>, // "none" の場合は None
    pub applet_name: Option<String>, // Busybox等の実名

    // Integrity & Security Context (Section 6.7)
    /// 実行バイナリの事後計算ハッシュ (TOCTOU対策/監査用)
    pub program_hash: String, 
    /// SELinux/AppArmorラベル (Hexデコード済み)
    pub lsm_label: String,

    // Environment Context (Section 6.7)
    /// 接続元IP (SSH_CLIENT等から解決)
    pub client_ip: Option<String>,
    /// ログイン認証方式 (publickey/password)
    pub auth_method: Option<String>,

    /// カーネルから取得したTTY情報
    pub session_tty: String,

    // Selective Arguments (Section 6.8)
    /// 重要コマンドのみ記録される引数 (Truncated)
    pub cmd_args: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectContext {
    // --- Source (移動元) ---
    pub path: String,
    pub inode: u64,         // パスが変わっても追跡できるよう、必ずDev:Inodeを持つ
    pub device_id: u64,     // major:minor encoded

    // --- Destination (移動先: RENAME時のみ使用) ---
    pub new_path: Option<String>,
    pub new_inode: Option<u64>,
    pub new_device_id: Option<u64>,

}

// -------------------------------------------------------------------
// 1. データ構造 (変更なし)
// -------------------------------------------------------------------

/// MPA（多人数承認）の進行状態および最終的な証跡
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MpaState {
    // --- 1. Requirements (承認要件) ---

    /// 承認しきい値 (例: 2)
    /// ※ ロジック判定用には u32 が必須。ログ出力で "2-of-3"
    pub threshold: u32,

    /// 承認可能なロールのセット (例: {"admin", "sre_lead"})
    /// ※ ここに含まれるロールを持つユーザーのみが approvals に追加できる
    pub approver_roles: HashSet<String>,

    /// 必須ロール (例: {"security_manager"})
    /// ※ ここにあるロールが approvals 内に揃わないと完了しない (AND条件)
    pub required_roles: HashSet<String>,


    // --- 2. Current State & Evidence (承認の事実) ---

    /// 承認済みアクションのリスト <key: uid, value: Action詳細>
    pub approvals: HashMap<u32, ApproverAction>,


    // --- 3. Final Result (暗号学的証拠) ---

    /// 集約されたBLS署名 (Aggregated Signature) (圧縮形式 96bytes)
    /// - None: 承認進行中
    /// - Some: 承認完了 (このバイト列が Ticket に埋め込まれる)
    #[serde(default, with = "option_hex")]
    pub aggregated_signature: Option<Vec<u8>>,
}

impl MpaState {
    /// 承認要件を満たしているか判定する
    pub fn is_fulfilled(&self) -> bool {
        // 1. 数（しきい値）のチェック
        if self.approvals.len() < self.threshold as usize {
            return false;
        }

        // 2. 必須ロールのチェック (Required Roles)
        if !self.required_roles.is_empty() {
            let provided_roles: HashSet<&String> = self.approvals.values()
                .map(|a| &a.role)
                .collect();
            
            for req in &self.required_roles {
                if !provided_roles.contains(req) {
                    return false; // 必須ロールが不足
                }
            }
        }

        true
    }

    pub fn insert_approver(&mut self, args: &SignedCmdArgs) {
        let b = bundle();
        let user_roles = b.roles
            .assignments
            .uid_roles
            .get(&args.uid)                           
            .cloned()
            .unwrap_or_default();
        let mut approver_role = "".to_string();
        for role in user_roles {
            if self.approver_roles.contains(&role) {
                self.required_roles.remove(&role);
                approver_role = role.clone();
            }
        }
        let approver = ApproverAction {
            account: uid_to_name(args.uid).unwrap_or_else(|_| "".to_string()),
            role: approver_role,
            approved_at: Utc::now(),
            method: "".to_string(),
            comment: None,
            signature: 
                match hex::decode(args.sig_hex.clone()) {
                    Ok(signature) => signature,
                    Err(msg) => {
                        eprintln!("{}[ERROR] {}", ktime_prefix(), msg);
                        Vec::new()
                    }
                }
        };
        self.approvals.insert(args.uid, approver);
    }

// -------------------------------------------------------------------
// 2. BLS集約ロジックの実装
// -------------------------------------------------------------------

    /// [CORE LOGIC] BLS署名を集約する
    pub fn try_aggregate(&mut self) -> Result<(), String> {
        if !self.is_fulfilled() {
            return Err("Approval requirements (threshold or required roles) are not met.".to_string());
        }

        // 1. バイト列から Signature オブジェクトへ変換 (デシリアライズ & 検証)
        let signatures: Result<Vec<Signature>, String> = self.approvals.values()
            .map(|action| {
                Signature::from_bytes(&action.signature)
                    .map_err(|e| format!("Invalid signature format (User: {}): {:?}", action.account, e))
            })
            .collect();

        let signatures = signatures?;
        if signatures.is_empty() {
            return Err("No signatures found.".to_string());
        }

        // 2. 署名の集約 (Aggregation)
        // blst の AggregateSignature ヘルパーを使用
        // 1. 署名の参照を集めたベクタを作成
        let sig_refs: Vec<&Signature> = signatures.iter().collect();

        // 2. aggregate 関数で集約 (第2引数は sanity check フラグ。通常 true)
        let agg = AggregateSignature::aggregate(&sig_refs, true)
            .map_err(|e| format!("Failed to aggregate signatures: {:?}", e))?;

        // 3. 集約署名をバイト列 (圧縮形式) に戻す
        // to_signature() で Signature型にし、to_bytes() で Vec<u8> 化
        let agg_sig_bytes = agg.to_signature().to_bytes();

        self.aggregated_signature = Some(agg_sig_bytes.to_vec());
        Ok(())
    }
}

/// 承認アクションの記録
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApproverAction {
    /// 承認者ユーザー名
    /// ここでは汎用性を高めるため String としています (例: "1001" や "alice")
    #[serde(rename = "user")] // JSON出力時は "user" というキー名にする
    pub account: String,

    /// 承認時のロール (例: "ops_admin")
    pub role: String,

    /// 承認日時
    #[serde(rename = "ts")] // JSON出力時は "ts" (timestamp)
    pub approved_at: DateTime<Utc>,

    /// 認証方式
    pub method: String,

    /// 承認時のコメント/メモ (任意)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "note")] // JSON出力時は "note"
    pub comment: Option<String>,

    /// 個別のBLS署名シェア (圧縮形式 96bytes)
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

// --- ヘルパーモジュール ---
mod option_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => hex::decode(s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KernelEventLog {
//    pub event: String,          // <EVENT>
    pub ticket_id: u64,         // <TICKET_ID>
    pub uid: u32,               // <UID>
    pub uses_left: u32,         // <USES_LEFT>
//    pub org_dev: u64,           // <ORG_DEV>
//    pub org_ino: u64,           // <ORG_INO>
    pub obj_dev: u64,           // <OBJ_DEV>
    pub obj_ino: u64,           // <OBJ_INO>
    pub new_obj_dev: Option<u64>,           // <NEW_OBJ_DEV>
    pub new_obj_ino: Option<u64>,           // <NEW_OBJ_INO>
//    pub res: String,            // <RES>
}

/// 特急レーンでの最終的なポリシー判定結果 (リネーム: DecisionKind -> PolicyDecision)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    NeedApproval,
    AuditOnly,
    NotManaged,
    NoRuleMatched,
    Approved(ApprovedTicket),
}

/// STOPコマンド（AUDITへの降格）の保留状態
#[derive(Debug, Clone)]
pub struct MgmtPendingStop {
    pub initiator_uid: u32,
    pub initiator_user: String,
    pub audit_id: String,
    pub mpa_state: MpaState,
    pub timeout_minutes: u32,
}

/// ワーカー間でやり取りする非同期メッセージ（事後報告イベント）
#[derive(Debug, Clone)]
pub enum InternalEvent {
    /// 特急レーン（CTL）での判定が完了した事後報告
    Resolved {
        req_line: String,
        parsed_req: Request,
        decision: PolicyDecision,
        rule_id: Option<String>,
        ticket_id: Option<String>,
    },
    // ... (以下、MpaApproved 等の他のバリアントはそのまま)
    MpaApproved {
        draft: PreApprovalDraft,
        ticket: ApprovedTicket,
    },
    EntryApproved {
        entry: PendingEntry,
        cacheable: bool,
        ticket_id: String,
    },
    StartApproved {
        pending_start: MgmtPendingStart,
    },
    StopApproved {
        pending_stop: MgmtPendingStop,
    },
    DraftDenied {
        draft: PreApprovalDraft,
        ticket: ApprovedTicket,
        denier_uid: u32,
    },
    EntryDenied {
        entry: PendingEntry,
        denier_uid: u32,
    },
    StartDenied {
        pending_start: MgmtPendingStart,
        denier_uid: u32,
    },
    StopDenied {
        pending_stop: MgmtPendingStop,
        denier_uid: u32,
    },
}

#[derive(Debug)]
pub struct SignedCmdArgs {
    pub id: String,
    pub uid: u32,
    pub sig_hex: String,
}

// --- ポリシー評価と型 ---
#[derive(Debug)]
pub struct PolicyResult {
    /// 最終的な判定結果
    pub decision: PolicyDecision,
    
    /// マッチしたルールID（NotManaged や NoRuleMatched の場合は None）
    pub rule_id: Option<String>,
    
    /// TICKET発行に必要なペイロード（Allow の場合のみ Some）
    pub ticket: Option<TicketPayload>,
}

/// チケット生成用データ（仕様書 v1.7 準拠）
#[derive(Debug, Clone)]
pub struct TicketPayload {
    pub uid: u32,
    pub op: u32,                // 論理操作マスク
    pub prog_dev: u64,
    pub prog_ino: u64,
    pub script_dev: u64,
    pub script_ino: u64,
    pub applet_hash: u64,       // Alphaフェーズは 0
    pub target_dev: u64,
    pub target_ino: u64,
    pub new_target_dev: u64,
    pub new_target_ino: u64,
    pub expires_in_sec: u64,    // TTL
    pub flags: u32,             // チケットの振る舞いフラグ (SILENT_IO | INHERIT) [0x1 SILENT_IO, 0x2 INHERIT]の論理和
    pub uses_left: u32,         // 残り使用回数
    pub ticket_id: String,      // "0" (予約値) または "T-xxxxxx"
    pub epoch: u32,             // 発行時点のポリシー世代
    pub audit_flags: u32,       // logの制御フラグ
}


