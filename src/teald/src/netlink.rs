// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::Result;
use neli::consts::genl::{Cmd, NlAttrType};
use neli::consts::nl::{NlmF, NlmFFlags};
use neli::consts::socket::NlFamily;
use neli::err::SerError;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::neli_enum;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::GenlBuffer;
use once_cell::sync::OnceCell;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::types::TicketPayload;
use teal_policy_engine::util::ktime_prefix;

// Legacy session-bound Fast Path flags are reserved and never transmitted.
// The PAM session registry remains available for issuance-time verification
// in teald, but no login attributes are included in TICKET_ADD.
const TEAL_TICKET_FLG_SESSION_BOUND: u32 = 1 << 5;
const TEAL_TICKET_FLG_LOGIN_REQUIRED: u32 = 1 << 6;
const TEAL_UNSET_AUDIT_ID: u32 = u32::MAX;

fn ticket_wire_flags(flags: u32) -> Result<u32> {
    anyhow::ensure!(
        flags & (TEAL_TICKET_FLG_SESSION_BOUND | TEAL_TICKET_FLG_LOGIN_REQUIRED) == 0,
        "session-bound ticket flags are deprecated"
    );
    Ok(flags)
}

// PAM notification handler uses the same authenticated TX socket as TICKET_ADD.
// Keeps the caller's public start_pam_listener() signature unchanged.
static PAM_NETLINK_WRITER: OnceCell<NlWriter> = OnceCell::new();
pub(crate) fn pam_netlink_writer() -> Option<NlWriter> {
    PAM_NETLINK_WRITER.get().cloned()
}

// --- グローバル受信 PortID 管理 ---
static RX_PORTID: AtomicU32 = AtomicU32::new(0);
static KERNEL_NEXT_EPOCH: AtomicU32 = AtomicU32::new(0);
static KERNEL_GUARD_VERSION: AtomicU32 = AtomicU32::new(0);
static KERNEL_GUARD_COMMIT_VERSION: AtomicU32 = AtomicU32::new(0);
// u32::MAX = not yet negotiated. Never assume AUDIT on missing data.
static KERNEL_RUNTIME_MODE: AtomicU32 = AtomicU32::new(u32::MAX);
static KERNEL_READY_VERSION: AtomicU32 = AtomicU32::new(0);
static NEXT_SEQ: AtomicU32 = AtomicU32::new(1000);

pub fn kernel_next_epoch() -> u32 {
    KERNEL_NEXT_EPOCH.load(Ordering::Acquire)
}

pub fn kernel_guard_version() -> u32 {
    KERNEL_GUARD_VERSION.load(Ordering::Acquire)
}

/// Runtime mode returned by the kernel's RX REGISTER (0=AUDIT, 1=ENFORCE).
/// This is NOT DaemonMode's internal numeric representation.
pub fn kernel_runtime_mode() -> Result<u32> {
    let mode = KERNEL_RUNTIME_MODE.load(Ordering::Acquire);
    anyhow::ensure!(mode <= 1, "kernel REGISTER runtime mode was not negotiated");
    Ok(mode)
}

fn ensure_guard_supported() -> Result<()> {
    anyhow::ensure!(
        kernel_guard_version() == GUARD_FORMAT_VERSION as u32,
        "kernel does not advertise MPA Guard wire v1 (kernel must be updated first)"
    );
    Ok(())
}

fn ensure_guard_commit_supported() -> Result<()> {
    anyhow::ensure!(
        KERNEL_GUARD_COMMIT_VERSION.load(Ordering::Acquire) == 1,
        "kernel does not advertise atomic Guard COMMIT v1"
    );
    Ok(())
}

fn parse_guard_commit_capability(msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<u16> {
    for attr in msg.get_attr_handle().iter() {
        if attr.nla_type.nla_type == TealAttr::GuardCommitVersion {
            return Ok(u16::from_ne_bytes(attr.nla_payload.as_ref().try_into()?));
        }
    }
    Ok(0)
}

fn parse_guard_capability(msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<u16> {
    for attr in msg.get_attr_handle().iter() {
        if attr.nla_type.nla_type == TealAttr::GuardFormatVersion {
            return Ok(u16::from_ne_bytes(attr.nla_payload.as_ref().try_into()?));
        }
    }
    Ok(0) // Older kernel: staging operations not available.
}

fn parse_register_ready_version(msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<u16> {
    for attr in msg.get_attr_handle().iter() {
        if attr.nla_type.nla_type == TealAttr::ReadyVersion {
            let version = u16::from_ne_bytes(attr.nla_payload.as_ref().try_into()?);
            anyhow::ensure!(version == 1, "unsupported kernel READY handshake version={version}");
            return Ok(version);
        }
    }
    anyhow::bail!("kernel REGISTER missing READY handshake capability (update kernel first)")
}

fn ensure_ready_supported() -> Result<()> {
    anyhow::ensure!(
        KERNEL_READY_VERSION.load(Ordering::Acquire) == 1,
        "kernel does not advertise DAEMON_READY handshake v1"
    );
    Ok(())
}

fn parse_register_runtime_mode(msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<u32> {
    for attr in msg.get_attr_handle().iter() {
        if attr.nla_type.nla_type == TealAttr::RuntimeMode {
            let bytes: [u8; 4] = attr.nla_payload.as_ref().try_into()
                .map_err(|_| anyhow::anyhow!("invalid REGISTER runtime mode length"))?;
            let mode = u32::from_ne_bytes(bytes);
            anyhow::ensure!(mode <= 1, "invalid kernel runtime mode: {mode}");
            return Ok(mode);
        }
    }
    anyhow::bail!("kernel REGISTER reply missing RuntimeMode (update kernel first)")
}

fn parse_register_epoch(msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<u32> {
    for attr in msg.get_attr_handle().iter() {
        if attr.nla_type.nla_type == TealAttr::Epoch {
            let epoch = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?);
            anyhow::ensure!(epoch != 0, "kernel returned invalid Epoch=0");
            return Ok(epoch);
        }
    }
    anyhow::bail!("REGISTER reply missing TEAL_ATTR_EPOCH")
}

pub fn set_rx_portid(portid: u32) {
    RX_PORTID.store(portid, Ordering::Relaxed);
}

pub fn get_rx_portid() -> u32 {
    RX_PORTID.load(Ordering::Relaxed)
}

// ==========================================
// 1. C言語カーネルモジュールとの型マッピング
// ==========================================

#[neli_enum(serialized_type = "u8")]
pub enum TealCmd {
    Unspec = 0,
    Register = 1,
    Req = 2,
    Info = 3,
    Approve = 4,
    Deny = 5,
    TicketAdd = 6,
    ModeSwitch = 7,
    PolicyUpdate = 8,
    PamSessionAdd = 9,
    PamSessionDel = 10,
    GuardBegin = 11,
    GuardAdd = 12,
    GuardAbort = 13,
    GuardStatus = 14,
    DaemonReady = 15,
}
impl Cmd for TealCmd {}

#[neli_enum(serialized_type = "u16")]
pub enum TealAttr {
    Unspec = 0,
    TransId = 1,
    Pid = 2,
    Ppid = 3,
    SessionId = 4,
    Uid = 5,
    Gid = 6,
    ProgDev = 7,
    ProgIno = 8,
    Program = 9,
    Action = 10,
    TargetDev = 11,
    TargetIno = 12,
    Target = 13,
    Op = 14,
    ExpiresAt = 15,
    ScriptDev = 16,
    ScriptIno = 17,
    Script = 18,
    Applet = 19,
    LsmLabel = 20,
    ArgsHead = 21,
    Flags = 22,
    InfoEvt = 23,
    UsesLeft = 24,
    TicketId = 25,
    Epoch = 26,
    AuditFlg = 27,
    AppletHash = 28,

    // --- RENAME対応用 ---
    NewTargetDev = 29,
    NewTargetIno = 30,
    NewTarget = 31,

    // --- ログインコンテキスト（TTY）用 ---
    SessionTty = 32,
    Lane = 33,
    AuditSessionId = 34,
    LoginUid = 35,
    GuardTxId = 36,
    GuardBaseEpoch = 37,
    GuardCount = 38,
    GuardSha256 = 39,
    GuardIndex = 40,
    GuardOpMask = 41,
    GuardObjectType = 42,
    GuardMatchType = 43,
    GuardTargetMask = 44,
    GuardPath = 45,
    GuardFormatVersion = 46,
    GuardTotalBytes = 47,
    GuardReuse = 48,
    GuardLastEpoch = 49,
    GuardEpoch = 50,
    GuardState = 51,
    GuardStaged = 52,
    GuardReceived = 53,
    GuardNextEpoch = 54,
    GuardActiveSha256 = 55,
    GuardCommitVersion = 56,
    RuntimeMode = 57,
    RecoveryState = 58,
    ReadyVersion = 59,
}
impl NlAttrType for TealAttr {}

// MPA Guard wire v1; Stage 2 activates complete Guard snapshots via POLICY_UPDATE.
const GUARD_FORMAT_VERSION: u16 = 1;
const GUARD_MAX_ENTRIES: usize = 1024;
const GUARD_MAX_PATH: usize = 4096;
const GUARD_MAX_MEMORY: usize = 1024 * 1024;
const GUARD_RECORD_OVERHEAD: usize = 9;
const GUARD_OP_BITS: u32 = 0x1ff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GuardObjectType {
    Path = 1,
    Any = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GuardMatchType {
    Exact = 1,
    Prefix = 2,
    All = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardEntry {
    pub op_mask: u32,
    pub object_type: GuardObjectType,
    pub match_type: GuardMatchType,
    pub target_mask: u8,       // 1=source, 2=destination
    pub path: Option<Vec<u8>>, // Linux pathname bytes (not lossy UTF-8)
}

#[derive(Debug, Clone)]
pub struct GuardBegin {
    pub tx_id: u64,
    pub base_epoch: u32,
    pub next_epoch: u32,
    pub expected_count: u32,
    pub total_bytes: u32, // sum of canonical records: (9 + path.len()) per entry
    pub sha256: [u8; 32], // expected canonical Guard digest, verified at COMMIT
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardStatus {
    pub current_epoch: u32,
    pub last_epoch: u32,
    pub guard_epoch: u32,
    pub guard_state: u8, // 0=UNINITIALIZED, 1=READY, 2=INVALID
    pub daemon_ready: bool, // kernel RECOVERING=0, READY=1
    pub active_sha256: Option<[u8; 32]>,
    pub staged: bool,
    pub staged_tx_id: Option<u64>,
    pub base_epoch: Option<u32>,
    pub next_epoch: Option<u32>,
    pub expected_count: Option<u32>,
    pub received_count: Option<u32>,
    pub total_bytes: Option<u32>,
    pub sha256: Option<[u8; 32]>,
}

fn guard_path_valid(path: &[u8]) -> bool {
    if path.is_empty()
        || path.len() > GUARD_MAX_PATH
        || path[0] != b'/'
        || path.iter().any(|&b| b == 0)
    {
        return false;
    }
    for component in path.split(|&b| b == b'/').skip(1) {
        if component == b"." || component == b".." {
            return false;
        }
    }
    // Interior empty components reject repeated slashes; final trailing slash is allowed.
    let mut iter = path.split(|&b| b == b'/').skip(1).peekable();
    while let Some(component) = iter.next() {
        if component.is_empty() && iter.peek().is_some() {
            return false;
        }
    }
    true
}

impl GuardEntry {
    pub fn validate(&self) -> Result<usize> {
        anyhow::ensure!(
            self.op_mask != 0 && self.op_mask & !GUARD_OP_BITS == 0,
            "invalid Guard operation mask"
        );
        let expected_mask = if self.op_mask & 32 != 0 { 3 } else { 1 };
        anyhow::ensure!(
            self.target_mask == expected_mask,
            "invalid Guard target mask (RENAME requires SOURCE|DESTINATION)"
        );
        match (self.object_type, self.match_type, self.path.as_deref()) {
            (GuardObjectType::Path, GuardMatchType::Exact | GuardMatchType::Prefix, Some(path)) => {
                anyhow::ensure!(guard_path_valid(path), "invalid normalized Guard path");
                Ok(GUARD_RECORD_OVERHEAD + path.len())
            }
            (GuardObjectType::Any, GuardMatchType::All, None) => Ok(GUARD_RECORD_OVERHEAD),
            _ => {
                anyhow::bail!("unsupported Guard entry shape; use ANY/ALL for unsupported objects")
            }
        }
    }
}

impl GuardBegin {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.tx_id != 0, "Guard tx_id must be nonzero");
        anyhow::ensure!(
            self.base_epoch != u32::MAX && self.next_epoch == self.base_epoch + 1,
            "Guard next_epoch must equal base_epoch + 1"
        );
        let count = self.expected_count as usize;
        let payload_bytes = self.total_bytes as usize;
        // Conservatively upper-bound kernel entry struct/bitmap allocation.
        let memory_bound = 256 + count * 32 + (count + 63) / 64 * 8 + payload_bytes + count;
        anyhow::ensure!(
            count <= GUARD_MAX_ENTRIES
                && payload_bytes >= count * GUARD_RECORD_OVERHEAD
                && (count != 0 || payload_bytes == 0)
                && memory_bound <= GUARD_MAX_MEMORY,
            "Guard staging exceeds limits"
        );
        Ok(())
    }
}

// ==========================================
// 2. ワーカーへ渡すためのメッセージ構造体
// ==========================================

#[derive(Debug)]
pub enum TealNetlinkMessage {
    Req(Box<TealReq>),
    Info(TealInfo),
}

#[derive(Debug, Default)]
pub struct TealReq {
    pub trans_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub session_id: u32,
    pub uid: u32,
    pub gid: u32,
    pub prog_dev: u32,
    pub prog_ino: u64,
    pub program: String,
    pub action: String,

    pub target_dev: u32,
    pub target_ino: u64,
    pub target: String,
    pub new_target_dev: u32,
    pub new_target_ino: u64,
    pub new_target: String, // RENAMEでない場合は空文字列 "" が入る想定

    pub script_dev: u32,
    pub script_ino: u64,
    pub script: String,
    pub applet: String,
    pub lsm_label: String,
    pub args_head: String,
    pub flags: u32,

    // ログインコンテキスト（TTY情報）
    // カーネルから送られてこない（非対話型プロセス）場合はデフォルトで空文字列 "" になる
    pub session_tty: String,
    pub audit_session_id: Option<u32>,
    pub loginuid: Option<u32>,
}

#[derive(Debug, Default)]
pub struct TealInfo {
    pub is_expired: bool, // INFO_EVT (0: CONSUMED, 1: EXPIRED)
    pub ticket_id: u64,
    pub uid: u32,
    pub uses_left: u32,
    pub prog_dev: u32,
    pub prog_ino: u64,
    pub target_dev: u32,
    pub target_ino: u64,

    // RENAME 用の移動先情報
    pub new_target_dev: u32,
    pub new_target_ino: u64,
}

// --- [定義] 送信リクエストの列挙型 ---
#[derive(Debug)]
pub enum NetlinkSendRequest {
    Approve(u64),
    Deny(u64),
    TicketAdd(TicketPayload),
    PamSessionUpdate {
        sid: u32,
        loginuid: u32,
        add: bool,
        ack: oneshot::Sender<Result<()>>,
    },
    ModeSwitch(u32, oneshot::Sender<Result<()>>),
    SyncEpoch(u32, oneshot::Sender<Result<()>>),
    CommitGuard {
        epoch: u32,
        tx_id: u64,
        sha256: [u8; 32],
        ack: oneshot::Sender<Result<()>>,
    },
    ReuseGuard {
        epoch: u32,
        sha256: [u8; 32],
        ack: oneshot::Sender<Result<()>>,
    },
    GuardBegin(GuardBegin, oneshot::Sender<Result<()>>),
    GuardAdd {
        tx_id: u64,
        index: u32,
        entry: GuardEntry,
        ack: oneshot::Sender<Result<()>>,
    },
    GuardAbort(u64, oneshot::Sender<Result<()>>),
    GuardStatus(oneshot::Sender<Result<GuardStatus>>),
    DaemonReady {
        epoch: u32,
        sha256: [u8; 32],
        ack: oneshot::Sender<Result<()>>,
    },
}

// --- [構造体] 軽量化された NlWriter ---
#[derive(Clone)]
pub struct NlWriter {
    pub tx: mpsc::Sender<NetlinkSendRequest>,
    pub family_id: u16,
    ticket_transition: Arc<AtomicBool>,
}

/// RAII: all cloned NlWriter instances share this transition gate.
/// Dropping the guard resumes ticket dispatch.
pub struct TicketTransitionGuard {
    gate: Arc<AtomicBool>,
}
impl Drop for TicketTransitionGuard {
    fn drop(&mut self) {
        self.gate.store(false, Ordering::Release);
    }
}

impl NlWriter {
    pub fn ticket_transition_active(&self) -> bool {
        self.ticket_transition.load(Ordering::Acquire)
    }

    pub fn begin_ticket_transition(&self) -> Result<TicketTransitionGuard> {
        self.ticket_transition
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("ticket transition already active"))?;
        Ok(TicketTransitionGuard {
            gate: Arc::clone(&self.ticket_transition),
        })
    }

    pub async fn send_approve(&self, trans_id: u64) -> Result<()> {
        self.tx
            .send(NetlinkSendRequest::Approve(trans_id))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue APPROVE"))
    }

    pub async fn send_deny(&self, trans_id: u64) -> Result<()> {
        self.tx
            .send(NetlinkSendRequest::Deny(trans_id))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue DENY"))
    }

    pub async fn send_ticket_add(&self, ticket: TicketPayload) -> Result<()> {
        anyhow::ensure!(
            !self.ticket_transition_active(),
            "TICKET_ADD suspended during epoch transition"
        );
        ticket_wire_flags(ticket.flags)?;
        self.tx
            .send(NetlinkSendRequest::TicketAdd(ticket))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue TICKET_ADD"))
    }

    /// Update the kernel-side verified login table. This method waits for the
    /// kernel ACK; enqueue success alone does NOT establish PAM registration.
    pub async fn send_pam_session_update(&self, sid: u32, loginuid: u32, add: bool) -> Result<()> {
        anyhow::ensure!(
            sid != TEAL_UNSET_AUDIT_ID && loginuid != TEAL_UNSET_AUDIT_ID,
            "invalid PAM login identifiers"
        );
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::PamSessionUpdate {
                sid,
                loginuid,
                add,
                ack: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue PAM session update"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("PAM kernel ACK timed out"))?
            .map_err(|_| anyhow::anyhow!("Netlink sender stopped before PAM ACK"))?
    }

    pub async fn send_mode_switch(&self, mode: u32) -> Result<()> {
        anyhow::ensure!(mode <= 1, "invalid mode");
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::ModeSwitch(mode, ack))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue MODE_SWITCH"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("MODE_SWITCH ACK timed out"))?
            .map_err(|_| anyhow::anyhow!("Netlink sender stopped before MODE_SWITCH ACK"))?
    }

    /// Stage a Guard generation. Phase 1 does not change active policy or Epoch.
    pub async fn guard_begin(&self, begin: GuardBegin) -> Result<()> {
        ensure_guard_supported()?;
        begin.validate()?;
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::GuardBegin(begin, ack))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue GUARD_BEGIN"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("GUARD_BEGIN ACK timed out"))?
            .map_err(|_| anyhow::anyhow!("Guard worker exited"))?
    }

    pub async fn guard_add(&self, tx_id: u64, index: u32, entry: GuardEntry) -> Result<()> {
        ensure_guard_supported()?;
        anyhow::ensure!(
            tx_id != 0 && (index as usize) < GUARD_MAX_ENTRIES,
            "invalid Guard tx_id/index"
        );
        entry.validate()?;
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::GuardAdd {
                tx_id,
                index,
                entry,
                ack,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue GUARD_ADD"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("GUARD_ADD ACK timed out"))?
            .map_err(|_| anyhow::anyhow!("Guard worker exited"))?
    }

    pub async fn guard_abort(&self, tx_id: u64) -> Result<()> {
        ensure_guard_supported()?;
        anyhow::ensure!(tx_id != 0, "invalid Guard tx_id");
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::GuardAbort(tx_id, ack))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue GUARD_ABORT"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("GUARD_ABORT ACK timed out"))?
            .map_err(|_| anyhow::anyhow!("Guard worker exited"))?
    }

    pub async fn guard_status(&self) -> Result<GuardStatus> {
        ensure_guard_supported()?;
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::GuardStatus(ack))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue GUARD_STATUS"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("GUARD_STATUS timed out"))?
            .map_err(|_| anyhow::anyhow!("Guard worker exited"))?
    }

    /// Complete RECOVERING only after policy and worker initialization.
    /// READY is bound to the active committed Epoch and Guard SHA-256.
    pub async fn daemon_ready_verified(
        &self,
        epoch: u32,
        expected_sha256: [u8; 32],
    ) -> Result<GuardStatus> {
        ensure_ready_supported()?;
        anyhow::ensure!(epoch != 0, "DAEMON_READY requires a nonzero Epoch");
        let before = self.guard_status().await?;
        anyhow::ensure!(
            before.current_epoch == epoch
                && before.last_epoch == epoch
                && before.guard_epoch == epoch
                && before.guard_state == 1
                && !before.staged
                && before.active_sha256 == Some(expected_sha256),
            "DAEMON_READY precondition failed: epoch={epoch}, kernel={before:?}"
        );
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::DaemonReady {
                epoch,
                sha256: expected_sha256,
                ack,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue DAEMON_READY"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("DAEMON_READY ACK timed out"))?
            .map_err(|_| anyhow::anyhow!("Netlink sender stopped before DAEMON_READY ACK"))??;
        let after = self.guard_status().await?;
        anyhow::ensure!(
            after.daemon_ready
                && after.current_epoch == epoch
                && after.last_epoch == epoch
                && after.guard_epoch == epoch
                && after.active_sha256 == Some(expected_sha256)
                && !after.staged,
            "DAEMON_READY ACK received but kernel READY state mismatched: {after:?}"
        );
        Ok(after)
    }

    /// COMMIT is valid only after all BEGIN/ADD ACKs. On timeout the result
    /// is UNKNOWN: use GUARD_STATUS to reconcile, not a blind retry.
    pub async fn guard_commit(&self, epoch: u32, tx_id: u64, sha256: [u8; 32]) -> Result<()> {
        ensure_guard_commit_supported()?;
        anyhow::ensure!(epoch != 0 && tx_id != 0, "invalid COMMIT epoch/tx_id");
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::CommitGuard {
                epoch,
                tx_id,
                sha256,
                ack,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue Guard COMMIT"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("Guard COMMIT ACK timed out: reconcile using STATUS"))?
            .map_err(|_| anyhow::anyhow!("Netlink sender stopped during Guard COMMIT"))?
    }

    /// Rebind a previously committed Guard to next Epoch (e.g. FLUSH).
    pub async fn guard_reuse(&self, epoch: u32, sha256: [u8; 32]) -> Result<()> {
        ensure_guard_commit_supported()?;
        anyhow::ensure!(epoch != 0, "invalid REUSE epoch");
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(NetlinkSendRequest::ReuseGuard { epoch, sha256, ack })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue Guard REUSE"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow::anyhow!("Guard REUSE ACK timed out: reconcile using STATUS"))?
            .map_err(|_| anyhow::anyhow!("Netlink sender stopped during Guard REUSE"))?
    }

    /// Compatibility entrypoint for the existing daemon STARTUP ONLY.
    /// This intentionally no longer sends an unguarded POLICY_UPDATE.
    /// Policy replacement MUST use sync_guard_manifest(new_bundle), while
    /// FLUSH MUST use reuse_guard_verified().
    pub async fn send_sync_epoch(&self, epoch: u32) -> Result<()> {
        ensure_guard_commit_supported()?;
        let current = crate::bundle::policy_snapshot();
        let manifest = compile_guard_manifest(&current.bundle)?;
        let before = self.guard_status().await?;
        let _status = self
            .sync_guard_manifest(&manifest, before.last_epoch, epoch)
            .await?;
        eprintln!(
            "{}[INFO] Initial Guard synchronized: epoch={}, entries={}",
            ktime_prefix(),
            epoch,
            manifest.entries.len()
        );
        Ok(())
    }
}

// ==========================================
// 3. ソケット初期化とメイン処理
// ==========================================

/// カーネルの "teal_ctrl" ファミリーを解決し、非同期ソケットを準備する
/// 戻り値: (送信用ハンドル, Decisionワーカー用Receiver, Auditワーカー用Receiver)
pub async fn init_socket() -> Result<(
    NlWriter,
    mpsc::Receiver<TealNetlinkMessage>,
    mpsc::Receiver<TealNetlinkMessage>,
)> {
    // --- 1. ソケット接続とファミリー解決 ---
    let mut rx_sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;

    let fd = rx_sock.as_raw_fd();
    let size: i32 = 16 * 1024 * 1024; // ★ 16MB に変更

    unsafe {
        // ★ SO_RCVBUFFORCE を使用して rmem_max をバイパス
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        );

        // CAP_NET_ADMIN がない等の理由で失敗した場合は通常の SO_RCVBUF にフォールバック
        if ret < 0 {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size) as libc::socklen_t,
            );
        }
    }

    let family_id = rx_sock.resolve_genl_family("teal_ctrl")?;
    eprintln!(
        "{}[INFO] Resolved teal_ctrl family ID: {}",
        ktime_prefix(),
        family_id
    );

    // --- 2. REGISTER 送信 (同期ハンドシェイク) ---
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Lane,
        1u32.to_ne_bytes().as_ref(),
    )?);

    let genlhdr = Genlmsghdr::new(TealCmd::Register, 1, attrs);
    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    );
    rx_sock.send(nlhdr)?;
    // REGISTERには通常のGeneric Netlink応答とNLMSG_ERROR(ACK)の両方が届く。
    // 最初のrecv()だけを読み捨てず、必ずEpochを含む応答を待つ。
    let next_epoch = loop {
        let reply = rx_sock
            .recv::<u16, Genlmsghdr<TealCmd, TealAttr>>()?
            .ok_or_else(|| anyhow::anyhow!("REGISTER socket closed"))?;
        match reply.nl_payload {
            NlPayload::Payload(genl) if genl.cmd == TealCmd::Register => {
                KERNEL_GUARD_VERSION
                    .store(parse_guard_capability(&genl)? as u32, Ordering::Release);
                KERNEL_GUARD_COMMIT_VERSION.store(
                    parse_guard_commit_capability(&genl)? as u32,
                    Ordering::Release,
                );
                let next_epoch = parse_register_epoch(&genl)?;
                // Required: no implicit AUDIT fallback on old/invalid kernel.
                let runtime_mode = parse_register_runtime_mode(&genl)?;
                let ready_version = parse_register_ready_version(&genl)?;
                KERNEL_READY_VERSION.store(ready_version as u32, Ordering::Release);
                KERNEL_RUNTIME_MODE.store(runtime_mode, Ordering::Release);
                break next_epoch;
            }
            NlPayload::Payload(_) => continue,
            _ => continue, // Successful ACK may arrive before/after reply.
        }
    };
    KERNEL_NEXT_EPOCH.store(next_epoch, Ordering::Release);
    let rx_portid = rx_sock.pid().unwrap_or(0);
    anyhow::ensure!(rx_portid != 0, "Netlink PortID missing");
    set_rx_portid(rx_portid);
    eprintln!(
        "{}[INFO] REGISTER next kernel Epoch: {}",
        ktime_prefix(),
        next_epoch
    );

    // RXソケットとは独立したTXソケット
    let mut tx_sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;

    // TX REGISTER
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Lane,
        2u32.to_ne_bytes().as_ref(),
    )?);

    let genlhdr = Genlmsghdr::new(TealCmd::Register, 1, attrs);

    let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);

    let mut nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    );

    nlhdr.nl_seq = seq;
    tx_sock.send(nlhdr)?;

    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };

    let rc = unsafe {
        libc::setsockopt(
            tx_sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };

    anyhow::ensure!(
        rc == 0,
        "TX SO_RCVTIMEO failed: {}",
        std::io::Error::last_os_error()
    );

    // TX REGISTERのACKを待つ
    loop {
        let reply = tx_sock
            .recv::<u16, Genlmsghdr<TealCmd, TealAttr>>()?
            .ok_or_else(|| anyhow::anyhow!("TX REGISTER socket closed"))?;

        if reply.nl_seq != seq {
            continue;
        }

        match reply.nl_payload {
            NlPayload::Ack(_) => {
                eprintln!(
                    "{}[INFO] TX REGISTER acknowledged: portid={:?}",
                    ktime_prefix(),
                    tx_sock.pid()
                );
                break;
            }
            NlPayload::Err(e) => {
                anyhow::bail!("TX REGISTER failed: {:?}", e);
            }
            _ => continue,
        }
    }

    let tx_sock = Arc::new(StdMutex::new(tx_sock));

    let (send_tx, send_rx) = mpsc::channel(10240);

    let ticket_transition = Arc::new(AtomicBool::new(false));

    let nl_tx = NlWriter {
        tx: send_tx,
        family_id,
        ticket_transition: Arc::clone(&ticket_transition),
    };

    let worker_sock = Arc::clone(&tx_sock);

    tokio::spawn(async move {
        netlink_send_worker_loop(send_rx, worker_sock, family_id, ticket_transition).await;
    });

    PAM_NETLINK_WRITER
        .set(nl_tx.clone())
        .map_err(|_| anyhow::anyhow!("PAM Netlink writer registered more than once"))?;

    // RX REGISTER supplied the kernel-owned runtime mode. Never send
    // MODE_SWITCH(0) at daemon startup: this would silently disable ENFORCE.

    // --- 5. 受信スレッドの起動 ---
    let (tx_decision, rx_decision) = mpsc::channel(1024);
    let (tx_audit, rx_audit) = mpsc::channel(1024);

    thread::spawn(move || {
        eprintln!(
            "{}[INFO] Netlink dedicated receiver thread started.",
            ktime_prefix()
        );
        enum Incoming {
            Request(Box<TealReq>),
            Information(TealInfo),
            Ignore,
            Error(String),
        }
        loop {
            // Parse the message while holding the socket guard: neli 0.6 may
            // return data borrowed from its internal receive buffer.
            let incoming = {
                match rx_sock.recv::<u16, Genlmsghdr<TealCmd, TealAttr>>() {
                    Ok(Some(msg)) => match msg.nl_payload {
                        NlPayload::Payload(genl) => match genl.cmd {
                            TealCmd::Req => match parse_req_msg(&genl) {
                                Ok(req) => Incoming::Request(Box::new(req)),
                                Err(e) => Incoming::Error(format!("REQ parse failed: {e}")),
                            },
                            TealCmd::Info => match parse_info_msg(&genl) {
                                Ok(info) => Incoming::Information(info),
                                Err(e) => Incoming::Error(format!("INFO parse failed: {e}")),
                            },
                            _ => Incoming::Ignore,
                        },
                        NlPayload::Ack(_) => Incoming::Ignore,
                        _ => Incoming::Ignore,
                    },
                    Ok(None) => Incoming::Ignore,
                    Err(e) => Incoming::Error(format!("{:?}", e)),
                }
            };
            match incoming {
                Incoming::Request(req) => {
                    let is_audit = (req.flags & 1) != 0;
                    let _ = if is_audit {
                        tx_audit.blocking_send(TealNetlinkMessage::Req(req))
                    } else {
                        tx_decision.blocking_send(TealNetlinkMessage::Req(req))
                    };
                }
                Incoming::Information(info) => {
                    let _ = tx_audit.blocking_send(TealNetlinkMessage::Info(info));
                }
                Incoming::Ignore => {}
                Incoming::Error(err_str) => {
                    if err_str.contains("EAGAIN")
                        || err_str.contains("WouldBlock")
                        || err_str.contains("timed out")
                        || err_str.contains("Resource temporarily unavailable")
                    {
                        continue;
                    }
                    eprintln!("{}[ERROR-NETLINK] recv: {}", ktime_prefix(), err_str);
                }
            }
        }
    });

    // 準備が整った nl_tx (Sender内包) を返す
    Ok((nl_tx, rx_decision, rx_audit))
}

// ==========================================
// 4. TLV パースヘルパー (C -> Rust)
// ==========================================

fn parse_req_msg(genl_msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<TealReq> {
    let mut req = TealReq::default();

    for attr in genl_msg.get_attr_handle().iter() {
        match attr.nla_type.nla_type {
            TealAttr::TransId => {
                req.trans_id = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::Pid => req.pid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Ppid => req.ppid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::SessionId => {
                req.session_id = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::Uid => req.uid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Gid => req.gid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ProgDev => {
                req.prog_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::ProgIno => {
                req.prog_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::TargetDev => {
                req.target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::TargetIno => {
                req.target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::ScriptDev => {
                req.script_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::ScriptIno => {
                req.script_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::Flags => {
                req.flags = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }

            // 文字列のパース（終端のNUL文字をトリムしてString化）
            TealAttr::Program => {
                req.program = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::Action => {
                req.action = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::Target => {
                req.target = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::Script => {
                req.script = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::Applet => {
                req.applet = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::LsmLabel => {
                req.lsm_label = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::ArgsHead => {
                req.args_head = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }

            TealAttr::NewTargetDev => {
                req.new_target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::NewTargetIno => {
                req.new_target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::NewTarget => {
                req.new_target = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }

            // SessionTty の文字列パース
            TealAttr::SessionTty => {
                req.session_tty = String::from_utf8_lossy(attr.nla_payload.as_ref())
                    .trim_end_matches('\0')
                    .to_string()
            }
            TealAttr::AuditSessionId => {
                req.audit_session_id =
                    Some(u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?));
            }
            TealAttr::LoginUid => {
                req.loginuid = Some(u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?));
            }

            _ => {}
        }
    }

    Ok(req)
}

fn parse_info_msg(genl_msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<TealInfo> {
    let mut info = TealInfo::default();

    for attr in genl_msg.get_attr_handle().iter() {
        match attr.nla_type.nla_type {
            TealAttr::InfoEvt => info.is_expired = attr.nla_payload.as_ref()[0] == 1,
            TealAttr::TicketId => {
                info.ticket_id = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::Uid => info.uid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::UsesLeft => {
                info.uses_left = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::ProgDev => {
                info.prog_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::ProgIno => {
                info.prog_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::TargetDev => {
                info.target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::TargetIno => {
                info.target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::NewTargetDev => {
                info.new_target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }
            TealAttr::NewTargetIno => {
                info.new_target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?)
            }

            _ => {}
        }
    }
    Ok(info)
}

// Wait for the ACK corresponding to a specific POLICY_UPDATE sequence.
// Ignore replies belonging to earlier TX commands.
fn wait_netlink_command_ack(sock: &NlSocketHandle, seq: u32, operation: &str) -> Result<()> {
    // SO_RCVTIMEO is already configured for the TX socket.
    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 65536];

    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n < 0 {
            let err = std::io::Error::last_os_error();

            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            anyhow::bail!("{} ACK recv failed: {}", operation, err);
        }

        if n == 0 {
            anyhow::bail!("TX socket closed while waiting for Netlink ACK");
        }

        let n = n as usize;
        let mut offset = 0usize;

        // One datagram may contain multiple Netlink messages.
        while offset + 16 <= n {
            let header = &buf[offset..];

            let len = u32::from_ne_bytes(header[0..4].try_into()?) as usize;
            let msg_type = u16::from_ne_bytes(header[4..6].try_into()?);
            let msg_seq = u32::from_ne_bytes(header[8..12].try_into()?);

            if len < 16 || len > n - offset {
                anyhow::bail!("Malformed Netlink response");
            }

            // Only accept responses from the kernel.
            if msg_seq == seq {
                // NLMSG_ERROR = 2
                // This message carries both success ACK and errors.
                if msg_type == 2 {
                    if len < 20 {
                        anyhow::bail!("Short Netlink ACK");
                    }

                    let error = i32::from_ne_bytes(header[16..20].try_into()?);

                    if error == 0 {
                        eprintln!(
                            "{}[INFO] {} ACK received: seq={}",
                            ktime_prefix(),
                            operation,
                            seq
                        );
                        return Ok(());
                    }

                    anyhow::bail!("{} rejected by kernel: errno={}", operation, error);
                }
            }

            // Netlink messages are aligned to 4 bytes.
            offset += (len + 3) & !3;
        }

        if offset < n {
            anyhow::bail!("Truncated Netlink response");
        }
    }
}

// --- [ワーカー] 送信専用メインループ ---
pub async fn netlink_send_worker_loop(
    mut rx: mpsc::Receiver<NetlinkSendRequest>,
    sock_mutex: Arc<StdMutex<NlSocketHandle>>,
    family_id: u16,
    ticket_transition: Arc<AtomicBool>,
) {
    eprintln!(
        "{}[INFO] Netlink Send Worker started on dedicated TX socket.",
        ktime_prefix()
    );
    while let Some(req) = rx.recv().await {
        match req {
            NetlinkSendRequest::SyncEpoch(epoch, response) => {
                let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);

                let packet = match build_sync_epoch_packet(family_id, epoch) {
                    Ok(mut packet) => {
                        packet.nl_seq = seq;
                        packet
                    }
                    Err(e) => {
                        let _ = response.send(Err(e));
                        continue;
                    }
                };

                let result = (|| -> Result<()> {
                    let mut sock = sock_mutex.lock().unwrap();

                    // Send POLICY_UPDATE with a unique sequence number.
                    sock.send(packet)?;

                    // Wait for the corresponding ACK.
                    wait_netlink_command_ack(&sock, seq, "POLICY_UPDATE")
                })();

                let _ = response.send(result);
            }
            NetlinkSendRequest::ModeSwitch(mode, ack) => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_mode_switch_packet(family_id, mode),
                    "MODE_SWITCH",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::CommitGuard {
                epoch,
                tx_id,
                sha256,
                ack,
            } => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_guard_commit_packet(family_id, epoch, tx_id, &sha256),
                    "GUARD_COMMIT",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::ReuseGuard { epoch, sha256, ack } => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_guard_reuse_packet(family_id, epoch, &sha256),
                    "GUARD_REUSE",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::GuardBegin(begin, ack) => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_guard_begin_packet(family_id, &begin),
                    "GUARD_BEGIN",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::GuardAdd {
                tx_id,
                index,
                entry,
                ack,
            } => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_guard_add_packet(family_id, tx_id, index, &entry),
                    "GUARD_ADD",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::GuardAbort(tx_id, ack) => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_guard_abort_packet(family_id, tx_id),
                    "GUARD_ABORT",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::DaemonReady { epoch, sha256, ack } => {
                let result = send_guard_command(
                    &sock_mutex,
                    NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
                    build_daemon_ready_packet(family_id, epoch, &sha256),
                    "DAEMON_READY",
                );
                let _ = ack.send(result);
            }
            NetlinkSendRequest::GuardStatus(ack) => {
                let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
                let result = (|| -> Result<GuardStatus> {
                    let mut packet = build_guard_status_packet(family_id)?;
                    packet.nl_seq = seq;
                    let mut sock = sock_mutex.lock().unwrap();
                    sock.send(packet)?;
                    wait_guard_status(&sock, seq, family_id)
                })();
                let _ = ack.send(result);
            }
            NetlinkSendRequest::PamSessionUpdate {
                sid,
                loginuid,
                add,
                ack,
            } => {
                let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
                let result = (|| -> Result<()> {
                    let mut packet = build_pam_session_packet(family_id, sid, loginuid, add)?;
                    packet.nl_seq = seq;
                    let mut sock = sock_mutex.lock().unwrap();
                    sock.send(packet)?;
                    wait_netlink_command_ack(
                        &sock,
                        seq,
                        if add {
                            "PAM_SESSION_ADD"
                        } else {
                            "PAM_SESSION_DEL"
                        },
                    )
                })();
                let _ = ack.send(result);
            }
            other => {
                // Dispatch-time check also covers requests queued before suspension.
                if let NetlinkSendRequest::TicketAdd(ref ticket) = other {
                    if ticket_transition.load(Ordering::Acquire) {
                        eprintln!(
                            "{}[INFO] dropping TICKET_ADD during epoch transition",
                            ktime_prefix()
                        );
                        continue;
                    }
                    if ticket.epoch != crate::bundle::policy_snapshot().epoch {
                        eprintln!(
                            "{}[WARN] dropping stale TICKET_ADD epoch={}",
                            ktime_prefix(),
                            ticket.epoch
                        );
                        continue;
                    }
                }
                let packet = match other {
                    NetlinkSendRequest::Approve(id) => build_approve(family_id, id),
                    NetlinkSendRequest::Deny(id) => build_deny(family_id, id),
                    NetlinkSendRequest::TicketAdd(ref ticket) => {
                        build_ticket_add(family_id, ticket)
                    }
                    NetlinkSendRequest::SyncEpoch(..)
                    | NetlinkSendRequest::PamSessionUpdate { .. }
                    | NetlinkSendRequest::GuardBegin(..)
                    | NetlinkSendRequest::GuardAdd { .. }
                    | NetlinkSendRequest::GuardAbort(..)
                    | NetlinkSendRequest::GuardStatus(..)
                    | NetlinkSendRequest::ModeSwitch(..)
                    | NetlinkSendRequest::CommitGuard { .. }
                    | NetlinkSendRequest::ReuseGuard { .. }
                    | NetlinkSendRequest::DaemonReady { .. } => unreachable!(),
                };
                match packet {
                    Ok(packet) => {
                        let result = {
                            let mut sock = sock_mutex.lock().unwrap();
                            sock.send(packet)
                        };

                        if let Err(e) = result {
                            eprintln!(
                                "{}[ERROR] Netlink Dispatch failure: {:?}",
                                ktime_prefix(),
                                e
                            );

                            if is_fatal_netlink_error(&e) {
                                return;
                            }
                        }
                    }

                    Err(e) => {
                        eprintln!("{}[ERROR] Netlink packet build: {}", ktime_prefix(), e);
                    }
                }
            }
        }
    }
}

// --- [ヘルパー] 致命的エラー判定 ---
fn is_fatal_netlink_error(e: &SerError) -> bool {
    match e {
        SerError::Wrapped(boxed_err) => {
            let err_str = format!("{:?}", boxed_err);
            err_str.contains("BrokenPipe")
                || err_str.contains("ConnectionReset")
                || err_str.contains("NotConnected")
        }
        _ => false,
    }
}

type GuardPacket = Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>;

fn send_guard_command(
    sock_mutex: &Arc<StdMutex<NlSocketHandle>>,
    seq: u32,
    packet: Result<GuardPacket>,
    operation: &str,
) -> Result<()> {
    let mut packet = packet?;
    packet.nl_seq = seq;
    let mut sock = sock_mutex.lock().unwrap();
    sock.send(packet)?;
    wait_netlink_command_ack(&sock, seq, operation)
}

// Macros preserve neli's inferred owned payload type (Buffer) across versions.
macro_rules! guard_attr_bytes {
    ($attrs:expr, $key:expr, $value:expr) => {
        $attrs.push(Nlattr::new(false, false, $key, $value)?);
    };
}
macro_rules! guard_packet {
    ($family_id:expr, $cmd:expr, $attrs:expr, $ack:expr) => {{
        let flags = if $ack {
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack])
        } else {
            NlmFFlags::new(&[NlmF::Request])
        };
        Nlmsghdr::new(
            None,
            $family_id,
            flags,
            None,
            None,
            NlPayload::Payload(Genlmsghdr::new($cmd, 1, $attrs)),
        )
    }};
}

fn build_guard_begin_packet(family_id: u16, begin: &GuardBegin) -> Result<GuardPacket> {
    begin.validate()?;
    let mut attrs = GenlBuffer::new();
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardTxId,
        begin.tx_id.to_ne_bytes().as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardBaseEpoch,
        begin.base_epoch.to_ne_bytes().as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::Epoch,
        begin.next_epoch.to_ne_bytes().as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardCount,
        begin.expected_count.to_ne_bytes().as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardTotalBytes,
        begin.total_bytes.to_ne_bytes().as_ref()
    );
    guard_attr_bytes!(attrs, TealAttr::GuardSha256, begin.sha256.as_ref());
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardFormatVersion,
        GUARD_FORMAT_VERSION.to_ne_bytes().as_ref()
    );
    Ok(guard_packet!(family_id, TealCmd::GuardBegin, attrs, true))
}

fn build_guard_add_packet(
    family_id: u16,
    tx_id: u64,
    index: u32,
    entry: &GuardEntry,
) -> Result<GuardPacket> {
    anyhow::ensure!(
        tx_id != 0 && (index as usize) < GUARD_MAX_ENTRIES,
        "invalid Guard tx_id/index"
    );
    entry.validate()?;
    let mut attrs = GenlBuffer::new();
    guard_attr_bytes!(attrs, TealAttr::GuardTxId, tx_id.to_ne_bytes().as_ref());
    guard_attr_bytes!(attrs, TealAttr::GuardIndex, index.to_ne_bytes().as_ref());
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardOpMask,
        entry.op_mask.to_ne_bytes().as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardObjectType,
        [entry.object_type as u8].as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardMatchType,
        [entry.match_type as u8].as_ref()
    );
    guard_attr_bytes!(
        attrs,
        TealAttr::GuardTargetMask,
        [entry.target_mask].as_ref()
    );
    if let Some(ref path) = entry.path {
        let mut nul_path = Vec::with_capacity(path.len() + 1);
        nul_path.extend_from_slice(path);
        nul_path.push(0);
        guard_attr_bytes!(attrs, TealAttr::GuardPath, nul_path.as_slice());
    }
    Ok(guard_packet!(family_id, TealCmd::GuardAdd, attrs, true))
}

fn build_guard_abort_packet(family_id: u16, tx_id: u64) -> Result<GuardPacket> {
    anyhow::ensure!(tx_id != 0, "invalid Guard tx_id");
    let mut attrs = GenlBuffer::new();
    guard_attr_bytes!(attrs, TealAttr::GuardTxId, tx_id.to_ne_bytes().as_ref());
    Ok(guard_packet!(family_id, TealCmd::GuardAbort, attrs, true))
}

fn build_guard_commit_packet(
    family_id: u16,
    epoch: u32,
    tx_id: u64,
    sha256: &[u8; 32],
) -> Result<GuardPacket> {
    anyhow::ensure!(epoch != 0 && tx_id != 0, "invalid COMMIT epoch/tx_id");
    let mut attrs = GenlBuffer::new();
    guard_attr_bytes!(attrs, TealAttr::Epoch, epoch.to_ne_bytes().as_ref());
    guard_attr_bytes!(attrs, TealAttr::GuardTxId, tx_id.to_ne_bytes().as_ref());
    guard_attr_bytes!(attrs, TealAttr::GuardSha256, sha256.as_ref());
    Ok(guard_packet!(family_id, TealCmd::PolicyUpdate, attrs, true))
}

fn build_guard_reuse_packet(family_id: u16, epoch: u32, sha256: &[u8; 32]) -> Result<GuardPacket> {
    anyhow::ensure!(epoch != 0, "invalid REUSE epoch");
    let mut attrs = GenlBuffer::new();
    guard_attr_bytes!(attrs, TealAttr::Epoch, epoch.to_ne_bytes().as_ref());
    guard_attr_bytes!(attrs, TealAttr::GuardReuse, [1u8].as_ref());
    guard_attr_bytes!(attrs, TealAttr::GuardSha256, sha256.as_ref());
    Ok(guard_packet!(family_id, TealCmd::PolicyUpdate, attrs, true))
}

fn build_daemon_ready_packet(
    family_id: u16,
    epoch: u32,
    sha256: &[u8; 32],
) -> Result<GuardPacket> {
    anyhow::ensure!(epoch != 0, "invalid DAEMON_READY Epoch=0");
    let mut attrs = GenlBuffer::new();
    guard_attr_bytes!(attrs, TealAttr::Epoch, epoch.to_ne_bytes().as_ref());
    guard_attr_bytes!(attrs, TealAttr::GuardSha256, sha256.as_ref());
    Ok(guard_packet!(family_id, TealCmd::DaemonReady, attrs, true))
}

fn build_guard_status_packet(family_id: u16) -> Result<GuardPacket> {
    Ok(guard_packet!(
        family_id,
        TealCmd::GuardStatus,
        GenlBuffer::new(),
        false
    ))
}

// Parse the typed Generic Netlink STATUS response on the TX socket.
// The kernel reply is a Generic Netlink message, not NLMSG_ERROR ACK.
fn parse_guard_status_response(
    buf: &[u8],
    family_id: u16,
    seq: u32,
) -> Result<Option<GuardStatus>> {
    if buf.len() < 16 {
        anyhow::bail!("short netlink header");
    }
    let msg_type = u16::from_ne_bytes(buf[4..6].try_into()?);
    let msg_seq = u32::from_ne_bytes(buf[8..12].try_into()?);
    // nlmsg_pid is not the sender address. For genlmsg_put_reply(), it may
    // contain the requesting TX socket's Port ID, which is nonzero.
    // Verify the sender via recvmsg()'s sockaddr_nl in wait_guard_status().
    if msg_seq != seq {
        return Ok(None);
    }
    if msg_type == 2 {
        // NLMSG_ERROR
        anyhow::ensure!(buf.len() >= 20, "short GUARD_STATUS error message");
        let error = i32::from_ne_bytes(buf[16..20].try_into()?);
        anyhow::bail!("GUARD_STATUS rejected by kernel: errno={error}");
    }
    anyhow::ensure!(
        msg_type == family_id && buf.len() >= 20 && buf[16] == 14,
        "unexpected GUARD_STATUS reply"
    );
    let mut attrs = std::collections::HashMap::<u16, &[u8]>::new();
    let mut offset = 20;
    while offset < buf.len() {
        anyhow::ensure!(buf.len() - offset >= 4, "short Guard attribute");
        let len = u16::from_ne_bytes(buf[offset..offset + 2].try_into()?) as usize;
        let key = u16::from_ne_bytes(buf[offset + 2..offset + 4].try_into()?) & 0x3fff;
        anyhow::ensure!(
            len >= 4 && len <= buf.len() - offset,
            "invalid Guard attribute length"
        );
        anyhow::ensure!(
            attrs.insert(key, &buf[offset + 4..offset + len]).is_none(),
            "duplicate Guard status attribute"
        );
        offset += (len + 3) & !3;
    }
    let get_u32 = |key: u16| -> Result<u32> {
        let b = attrs
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("missing Guard attribute {key}"))?;
        anyhow::ensure!(b.len() == 4, "invalid Guard u32 attribute");
        Ok(u32::from_ne_bytes((*b).try_into()?))
    };
    let get_u8 = |key: u16| -> Result<u8> {
        let b = attrs
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("missing Guard attribute {key}"))?;
        anyhow::ensure!(b.len() == 1, "invalid Guard u8 attribute");
        Ok(b[0])
    };
    let staged = get_u8(52)? != 0;
    let mut status = GuardStatus {
        current_epoch: get_u32(26)?,
        last_epoch: get_u32(49)?,
        guard_epoch: get_u32(50)?,
        guard_state: get_u8(51)?,
        daemon_ready: match get_u8(58)? {
            0 => false,
            1 => true,
            value => anyhow::bail!("invalid kernel RECOVERY_STATE={value}"),
        },
        active_sha256: None,
        staged,
        staged_tx_id: None,
        base_epoch: None,
        next_epoch: None,
        expected_count: None,
        received_count: None,
        total_bytes: None,
        sha256: None,
    };
    if status.guard_state == 1 {
        let sha = attrs
            .get(&55)
            .ok_or_else(|| anyhow::anyhow!("READY Guard missing active digest"))?;
        anyhow::ensure!(sha.len() == 32, "invalid active Guard digest length");
        status.active_sha256 = Some((*sha).try_into()?);
    }
    if staged {
        let b = attrs
            .get(&36)
            .ok_or_else(|| anyhow::anyhow!("missing staged tx_id"))?;
        anyhow::ensure!(b.len() == 8, "invalid tx_id length");
        status.staged_tx_id = Some(u64::from_ne_bytes((*b).try_into()?));
        status.base_epoch = Some(get_u32(37)?);
        status.next_epoch = Some(get_u32(54)?);
        status.expected_count = Some(get_u32(38)?);
        status.received_count = Some(get_u32(53)?);
        status.total_bytes = Some(get_u32(47)?);
        let sha = attrs
            .get(&39)
            .ok_or_else(|| anyhow::anyhow!("missing staged digest"))?;
        anyhow::ensure!(sha.len() == 32, "invalid staged digest length");
        status.sha256 = Some((*sha).try_into()?);
    }
    Ok(Some(status))
}

fn wait_guard_status(sock: &NlSocketHandle, seq: u32, family_id: u16) -> Result<GuardStatus> {
    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 65536];
    loop {
        // The datagram source is carried by recvmsg()'s sockaddr_nl, NOT
        // the nlmsg_pid field inside the received Netlink message header.
        let mut peer: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_name = (&mut peer as *mut libc::sockaddr_nl).cast();
        hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;

        let n = unsafe { libc::recvmsg(fd, &mut hdr, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            anyhow::bail!("GUARD_STATUS recvmsg failed: {err}");
        }
        if n == 0 {
            anyhow::bail!("GUARD_STATUS socket closed");
        }
        anyhow::ensure!(
            hdr.msg_namelen as usize >= std::mem::size_of::<libc::sockaddr_nl>()
                && peer.nl_family == libc::AF_NETLINK as libc::sa_family_t
                && peer.nl_pid == 0,
            "GUARD_STATUS datagram did not originate from the kernel"
        );
        anyhow::ensure!(
            hdr.msg_flags & libc::MSG_TRUNC == 0,
            "truncated GUARD_STATUS datagram"
        );
        let mut offset = 0usize;
        let n = n as usize;
        while offset + 16 <= n {
            let len = u32::from_ne_bytes(buf[offset..offset + 4].try_into()?) as usize;
            anyhow::ensure!(
                len >= 16 && len <= n - offset,
                "malformed GUARD_STATUS datagram"
            );
            if let Some(status) =
                parse_guard_status_response(&buf[offset..offset + len], family_id, seq)?
            {
                return Ok(status);
            }
            offset += (len + 3) & !3;
        }
        anyhow::ensure!(offset == n, "truncated GUARD_STATUS response");
    }
}

// --- [構築ロジック] 各パケットのビルド ---
fn build_approve(
    family_id: u16,
    trans_id: u64,
) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::TransId,
        trans_id.to_ne_bytes().as_ref(),
    )?);
    let genlhdr = Genlmsghdr::new(TealCmd::Approve, 1, attrs);
    Ok(Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    ))
}

fn build_deny(
    family_id: u16,
    trans_id: u64,
) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::TransId,
        trans_id.to_ne_bytes().as_ref(),
    )?);
    let genlhdr = Genlmsghdr::new(TealCmd::Deny, 1, attrs);
    Ok(Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    ))
}

fn build_ticket_add(
    family_id: u16,
    ticket: &TicketPayload,
) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let flags = ticket_wire_flags(ticket.flags)?;
    let mut expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    expires_at = if ticket.expires_in_sec < u64::MAX {
        expires_at + ticket.expires_in_sec
    } else {
        u64::MAX
    };
    let numeric_ticket_id: u64 = ticket
        .ticket_id
        .trim_start_matches("T-")
        .parse()
        .unwrap_or(0);

    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Uid,
        ticket.uid.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Op,
        ticket.op.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::ProgDev,
        (ticket.prog_dev as u32).to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::ProgIno,
        ticket.prog_ino.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::ScriptDev,
        (ticket.script_dev as u32).to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::ScriptIno,
        ticket.script_ino.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::TargetDev,
        (ticket.target_dev as u32).to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::TargetIno,
        ticket.target_ino.to_ne_bytes().as_ref(),
    )?);

    // RENAME 用の移動先情報 (Dev/Ino)
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::NewTargetDev,
        (ticket.new_target_dev as u32).to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::NewTargetIno,
        ticket.new_target_ino.to_ne_bytes().as_ref(),
    )?);

    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::ExpiresAt,
        expires_at.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Flags,
        flags.to_ne_bytes().as_ref(),
    )?);

    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::UsesLeft,
        ticket.uses_left.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::TicketId,
        numeric_ticket_id.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Epoch,
        ticket.epoch.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::AuditFlg,
        ticket.audit_flags.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::AppletHash,
        ticket.applet_hash.to_ne_bytes().as_ref(),
    )?);

    let genlhdr = Genlmsghdr::new(TealCmd::TicketAdd, 1, attrs);
    Ok(Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    ))
}

fn build_mode_switch_packet(
    family_id: u16,
    mode: u32,
) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Flags,
        mode.to_ne_bytes().as_ref(),
    )?);
    let genlhdr = Genlmsghdr::new(TealCmd::ModeSwitch, 1, attrs);
    Ok(Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    ))
}

fn build_pam_session_packet(
    family_id: u16,
    sid: u32,
    loginuid: u32,
    add: bool,
) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    anyhow::ensure!(
        sid != u32::MAX && loginuid != u32::MAX,
        "invalid PAM session"
    );
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::AuditSessionId,
        sid.to_ne_bytes().as_ref(),
    )?);
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::LoginUid,
        loginuid.to_ne_bytes().as_ref(),
    )?);
    let cmd = if add {
        TealCmd::PamSessionAdd
    } else {
        TealCmd::PamSessionDel
    };
    let genlhdr = Genlmsghdr::new(cmd, 1, attrs);
    Ok(Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    ))
}

fn build_sync_epoch_packet(
    family_id: u16,
    epoch: u32,
) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        TealAttr::Epoch,
        epoch.to_ne_bytes().as_ref(),
    )?);
    let genlhdr = Genlmsghdr::new(TealCmd::PolicyUpdate, 1, attrs);
    Ok(Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    ))
}

/// Generic Netlink のプロトコル番号 ("16")
const NETLINK_GENERIC_ETH: &str = "16";
/// 設定された受信バッファサイズ (16MB) に対するカーネル内部の実割り当てサイズ (32MB)
const NETLINK_EFFECTIVE_RCVBUF_BYTES: f64 = 32.0 * 1024.0 * 1024.0;

/// Netlink 受信ソケットの (バッファ使用率%, ドロップ数) を取得する
pub fn get_netlink_socket_metrics() -> (f64, u64) {
    let target_portid = get_rx_portid();
    if target_portid == 0 {
        return (0.0, 0);
    }

    let file = match File::open("/proc/net/netlink") {
        Ok(f) => f,
        Err(_) => return (0.0, 0),
    };

    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // フォーマット: sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
        //               0  1   2   3      4    5    6    7     8     9
        if fields.len() < 9 || fields[0] == "sk" {
            continue;
        }

        let eth = fields[1];
        let portid_val: u32 = fields[2].parse().unwrap_or(0);

        // ★ Generic Netlink (16) かつ 受信ソケットの PortID と完全一致する行を特定
        if eth == NETLINK_GENERIC_ETH && portid_val == target_portid {
            let rmem: f64 = fields[4].parse().unwrap_or(0.0);
            let drops: u64 = fields[8].parse().unwrap_or(0);

            let usage_pct = (rmem / NETLINK_EFFECTIVE_RCVBUF_BYTES) * 100.0;
            return (usage_pct.min(100.0), drops);
        }
    }

    (0.0, 0)
}

#[cfg(test)]
mod ticket_issue_flags_tests {
    use super::*;

    #[test]
    fn register_mode_is_required_and_strictly_validated() {
        fn reply(mode: Option<&[u8]>) -> Genlmsghdr<TealCmd, TealAttr> {
            let mut attrs = GenlBuffer::new();
            if let Some(bytes) = mode {
                attrs.push(Nlattr::new(false, false, TealAttr::RuntimeMode, bytes)
                    .expect("build runtime mode attr"));
            }
            Genlmsghdr::new(TealCmd::Register, 1, attrs)
        }
        assert!(parse_register_runtime_mode(&reply(None)).is_err());
        assert_eq!(parse_register_runtime_mode(&reply(Some(&0u32.to_ne_bytes()))).unwrap(), 0);
        assert_eq!(parse_register_runtime_mode(&reply(Some(&1u32.to_ne_bytes()))).unwrap(), 1);
        assert!(parse_register_runtime_mode(&reply(Some(&2u32.to_ne_bytes()))).is_err());
        assert!(parse_register_runtime_mode(&reply(Some(&[1u8]))).is_err());
    }

    #[test]
    fn ordinary_and_suppression_tickets_have_no_session_binding() {
        for flags in [0, 1, 1 << 2, 1 << 4] {
            assert_eq!(ticket_wire_flags(flags).unwrap(), flags);
        }
    }

    #[test]
    fn deprecated_session_flags_cannot_be_issued() {
        assert!(ticket_wire_flags(TEAL_TICKET_FLG_SESSION_BOUND).is_err());
        assert!(ticket_wire_flags(TEAL_TICKET_FLG_LOGIN_REQUIRED).is_err());
    }
}

#[cfg(test)]
mod guard_staging_wire_tests {
    use super::*;

    fn entry() -> GuardEntry {
        GuardEntry {
            op_mask: 1,
            object_type: GuardObjectType::Path,
            match_type: GuardMatchType::Exact,
            target_mask: 1,
            path: Some(b"/etc/hostname".to_vec()),
        }
    }
    #[test]
    fn ready_capability_is_required_and_versioned() {
        fn reply(version: Option<&[u8]>) -> Genlmsghdr<TealCmd, TealAttr> {
            let mut attrs = GenlBuffer::new();
            if let Some(value) = version {
                attrs.push(Nlattr::new(false, false, TealAttr::ReadyVersion, value).unwrap());
            }
            Genlmsghdr::new(TealCmd::Register, 1, attrs)
        }
        assert!(parse_register_ready_version(&reply(None)).is_err());
        assert_eq!(parse_register_ready_version(&reply(Some(&1u16.to_ne_bytes()))).unwrap(), 1);
        assert!(parse_register_ready_version(&reply(Some(&2u16.to_ne_bytes()))).is_err());
        assert!(parse_register_ready_version(&reply(Some(&[1u8]))).is_err());
    }

    #[test]
    fn accepts_a_normalized_path_and_exact_packet() {
        let e = entry();
        assert_eq!(e.validate().unwrap(), GUARD_RECORD_OVERHEAD + 13);
        let p = build_guard_add_packet(32, 1, 0, &e).unwrap();
        match p.nl_payload {
            NlPayload::Payload(genl) => {
                assert_eq!(genl.cmd, TealCmd::GuardAdd);
                assert!(genl
                    .get_attr_handle()
                    .iter()
                    .any(|a| a.nla_type.nla_type == TealAttr::GuardPath
                        && a.nla_payload.as_ref() == b"/etc/hostname\0"));
            }
            _ => panic!("expected Guard payload"),
        }
    }
    #[test]
    fn rename_guard_must_include_both_paths() {
        let mut e = entry();
        e.op_mask = 32;
        assert!(e.validate().is_err());
        e.target_mask = 3;
        assert!(e.validate().is_ok());
        e.op_mask = 1;
        assert!(e.validate().is_err());
    }
    #[test]
    fn rejects_dangerous_path_shapes() {
        for path in [
            b"etc/passwd".as_slice(),
            b"/a//b",
            b"/a/../b",
            b"/a/./b",
            b"/a\0b",
        ] {
            let mut e = entry();
            e.path = Some(path.to_vec());
            assert!(e.validate().is_err(), "accepted {:?}", path);
        }
        let mut e = entry();
        e.path = Some(vec![b'a'; GUARD_MAX_PATH + 1]);
        assert!(e.validate().is_err());
    }
    #[test]
    fn enforces_count_epoch_and_budget() {
        let mut begin = GuardBegin {
            tx_id: 1,
            base_epoch: 4,
            next_epoch: 5,
            expected_count: 1,
            total_bytes: GUARD_RECORD_OVERHEAD as u32,
            sha256: [0u8; 32],
        };
        assert!(begin.validate().is_ok());
        assert!(build_guard_begin_packet(32, &begin).is_ok());
        begin.expected_count = GUARD_MAX_ENTRIES as u32 + 1;
        assert!(begin.validate().is_err());
        begin.expected_count = 1;
        begin.next_epoch = 7;
        assert!(begin.validate().is_err());
        begin.next_epoch = 5;
        begin.total_bytes = (GUARD_MAX_MEMORY + 1) as u32;
        assert!(begin.validate().is_err());
    }
    #[test]
    fn parses_status_reply_and_rejects_duplicate_tlvs() {
        fn push_attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
            let len = (payload.len() + 4) as u16;
            buf.extend_from_slice(&len.to_ne_bytes());
            buf.extend_from_slice(&kind.to_ne_bytes());
            buf.extend_from_slice(payload);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        let mut pkt = vec![0u8; 20];
        pkt[4..6].copy_from_slice(&32u16.to_ne_bytes());
        pkt[8..12].copy_from_slice(&700u32.to_ne_bytes());
        // genlmsg_put_reply() may write the requester's nonzero Port ID
        // into nlmsg_pid; sender authentication is on recvmsg sockaddr_nl.
        pkt[12..16].copy_from_slice(&4242682424u32.to_ne_bytes());
        pkt[16] = 14; // GuardStatus
        push_attr(&mut pkt, 26, &0u32.to_ne_bytes());
        push_attr(&mut pkt, 49, &4u32.to_ne_bytes());
        push_attr(&mut pkt, 50, &0u32.to_ne_bytes());
        push_attr(&mut pkt, 51, &[0u8]);
        push_attr(&mut pkt, 52, &[0u8]);
        push_attr(&mut pkt, 58, &[0u8]);
        let size = pkt.len() as u32;
        pkt[0..4].copy_from_slice(&size.to_ne_bytes());
        let s = parse_guard_status_response(&pkt, 32, 700).unwrap().unwrap();
        assert_eq!(s.last_epoch, 4);
        assert_eq!(s.guard_epoch, 0);
        assert!(!s.staged);
        assert!(!s.daemon_ready);
        let mut ready_packet = pkt.clone();
        let ready_offset = ready_packet
            .windows(4)
            .position(|w| w == [5, 0, 58, 0])
            .expect("RECOVERY_STATE TLV");
        ready_packet[ready_offset + 4] = 1;
        assert!(parse_guard_status_response(&ready_packet, 32, 700)
            .unwrap().unwrap().daemon_ready);
        assert!(parse_guard_status_response(&pkt, 32, 701)
            .unwrap()
            .is_none());
        push_attr(&mut pkt, 52, &[1u8]); // duplicate staged flag
        let size = pkt.len() as u32;
        pkt[0..4].copy_from_slice(&size.to_ne_bytes());
        assert!(parse_guard_status_response(&pkt, 32, 700).is_err());
    }

    #[test]
    fn daemon_ready_packet_requires_epoch_and_binds_digest() {
        assert!(build_daemon_ready_packet(32, 0, &[0u8; 32]).is_err());
        let digest = [0x51u8; 32];
        let packet = build_daemon_ready_packet(32, 9, &digest).unwrap();
        match packet.nl_payload {
            NlPayload::Payload(genl) => {
                assert_eq!(genl.cmd, TealCmd::DaemonReady);
                let attrs = genl.get_attr_handle();
                assert!(attrs.iter().any(|attr|
                    attr.nla_type.nla_type == TealAttr::Epoch
                        && attr.nla_payload.as_ref() == 9u32.to_ne_bytes()));
                assert!(attrs.iter().any(|attr|
                    attr.nla_type.nla_type == TealAttr::GuardSha256
                        && attr.nla_payload.as_ref() == digest));
            }
            _ => panic!("expected DAEMON_READY packet"),
        }
    }

    #[test]
    fn builds_commit_and_reuse_packets_with_typed_attributes() {
        let digest = [0x42u8; 32];
        let p = build_guard_commit_packet(32, 9, 1234, &digest).unwrap();
        match p.nl_payload {
            NlPayload::Payload(genl) => {
                assert_eq!(genl.cmd, TealCmd::PolicyUpdate);
                let attrs = genl.get_attr_handle();
                assert!(attrs
                    .iter()
                    .any(|a| a.nla_type.nla_type == TealAttr::GuardTxId
                        && a.nla_payload.as_ref() == 1234u64.to_ne_bytes()));
                assert!(attrs
                    .iter()
                    .any(|a| a.nla_type.nla_type == TealAttr::GuardSha256
                        && a.nla_payload.as_ref() == digest));
            }
            _ => panic!("COMMIT should have a payload"),
        }
        let p = build_guard_reuse_packet(32, 10, &digest).unwrap();
        match p.nl_payload {
            NlPayload::Payload(genl) => {
                assert_eq!(genl.cmd, TealCmd::PolicyUpdate);
                assert!(genl
                    .get_attr_handle()
                    .iter()
                    .any(|a| a.nla_type.nla_type == TealAttr::GuardReuse
                        && a.nla_payload.as_ref() == [1u8]));
            }
            _ => panic!("REUSE should have a payload"),
        }
        assert!(build_guard_commit_packet(32, 0, 1234, &digest).is_err());
    }

    #[test]
    fn any_all_accepts_empty_object_only() {
        let mut e = entry();
        e.object_type = GuardObjectType::Any;
        e.match_type = GuardMatchType::All;
        e.path = None;
        assert_eq!(e.validate().unwrap(), GUARD_RECORD_OVERHEAD);
        e.path = Some(b"/etc/hostname".to_vec());
        assert!(e.validate().is_err());
    }
}

// Opt-in VM integration test. Not part of teald's normal startup or admin API.
// Run ONLY with teald.service stopped; it temporarily becomes the RX/TX owner.
#[cfg(test)]
mod guard_staging_live_tests {
    use super::*;
    use anyhow::{Context, Result};

    fn check_errno(error: anyhow::Error, operation: &str, errno: i32) -> Result<()> {
        let message = format!("{error:#}");
        anyhow::ensure!(
            message.contains(&format!("errno=-{errno}")),
            "{operation}: expected errno=-{errno}, got {message}"
        );
        println!("[PASS] {operation}: errno=-{errno}");
        Ok(())
    }

    async fn run_live_test() -> Result<()> {
        // Registering a second RX socket can evict the production daemon.
        // Refuse to run unless the service was explicitly stopped first.
        let service = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "teald.service"])
            .status()
            .context("systemctl is required for the VM safety check")?;
        anyhow::ensure!(
            !service.success(),
            "teald.service is active: stop it before running this ignored test"
        );
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "run the prebuilt test binary with sudo (REGISTER requires privileges)"
        );

        // init_socket uses the same RX/TX REGISTER, version negotiation and
        // authenticated TX worker as normal teald. No mode change on REGISTER.
        let (writer, _rx_decision, _rx_audit) = init_socket().await?;
        anyhow::ensure!(
            kernel_guard_version() == 1,
            "kernel Guard wire v1 unavailable"
        );
        let before = writer.guard_status().await?;
        println!("[INFO] GUARD_STATUS before: {before:?}");
        anyhow::ensure!(!before.staged, "unexpected existing staging transaction");
        anyhow::ensure!(before.last_epoch != u32::MAX, "last epoch overflow");
        // The initial policy may be out of sync while teald is stopped.
        // BEGIN deliberately uses the *last committed* kernel epoch.
        let tx_id = ((std::process::id() as u64) << 32) | 0x5445_414c;
        let entry = GuardEntry {
            op_mask: 1, // READ
            object_type: GuardObjectType::Path,
            match_type: GuardMatchType::Exact,
            target_mask: 1, // source
            path: Some(b"/etc/hostname".to_vec()),
        };
        let record_bytes = entry.validate()? as u32;
        let begin = GuardBegin {
            tx_id,
            base_epoch: before.last_epoch,
            next_epoch: before.last_epoch + 1,
            expected_count: 1,
            total_bytes: record_bytes,
            sha256: [0x5a; 32], // Stage 1: length checked; digest not verified until Phase 2
        };

        // Even on assertion/error, release staging before the test exits.
        let outcome = async {
            writer.guard_begin(begin.clone()).await?;
            println!("[PASS] GUARD_BEGIN ACK");

            let s = writer.guard_status().await?;
            println!("[INFO] GUARD_STATUS after BEGIN: {s:?}");
            anyhow::ensure!(
                s.staged && s.staged_tx_id == Some(tx_id),
                "staging not created"
            );
            anyhow::ensure!(
                s.base_epoch == Some(begin.base_epoch)
                    && s.next_epoch == Some(begin.next_epoch)
                    && s.expected_count == Some(1)
                    && s.received_count == Some(0)
                    && s.total_bytes == Some(record_bytes)
                    && s.sha256 == Some(begin.sha256),
                "BEGIN status mismatch"
            );
            anyhow::ensure!(
                s.current_epoch == before.current_epoch
                    && s.last_epoch == before.last_epoch
                    && s.guard_state == 0
                    && s.guard_epoch == 0,
                "staging unexpectedly activated or changed epoch"
            );
            println!("[PASS] GUARD_STATUS staged=1, received=0, active=0");

            let error = writer
                .guard_begin(begin.clone())
                .await
                .expect_err("duplicate BEGIN must fail");
            check_errno(error, "duplicate BEGIN", libc::EBUSY)?;

            writer.guard_add(tx_id, 0, entry.clone()).await?;
            println!("[PASS] GUARD_ADD index=0 ACK");
            let s = writer.guard_status().await?;
            println!("[INFO] GUARD_STATUS after ADD: {s:?}");
            anyhow::ensure!(
                s.staged
                    && s.staged_tx_id == Some(tx_id)
                    && s.received_count == Some(1)
                    && s.expected_count == Some(1),
                "ADD status mismatch"
            );
            println!("[PASS] GUARD_STATUS staged=1, received=1");

            let error = writer
                .guard_add(tx_id, 0, entry.clone())
                .await
                .expect_err("duplicate ADD must fail");
            check_errno(error, "duplicate ADD index=0", libc::EEXIST)?;
            let error = writer
                .guard_add(tx_id, 1, entry.clone())
                .await
                .expect_err("out-of-range ADD must fail");
            check_errno(error, "out-of-range ADD index=1", libc::ERANGE)?;
            let s = writer.guard_status().await?;
            anyhow::ensure!(
                s.received_count == Some(1),
                "rejected ADD modified staging counter"
            );
            println!("[PASS] rejected ADD preserved received=1");

            writer.guard_abort(tx_id).await?;
            println!("[PASS] GUARD_ABORT ACK");
            let s = writer.guard_status().await?;
            println!("[INFO] GUARD_STATUS after ABORT: {s:?}");
            anyhow::ensure!(
                !s.staged && s.staged_tx_id.is_none(),
                "staging remains after ABORT"
            );
            anyhow::ensure!(
                s.current_epoch == before.current_epoch
                    && s.last_epoch == before.last_epoch
                    && s.guard_state == 0
                    && s.guard_epoch == 0,
                "ABORT changed active policy or epoch"
            );
            println!("[PASS] GUARD_STATUS staged=0, active=0, epoch unchanged");

            let error = writer
                .guard_abort(tx_id)
                .await
                .expect_err("duplicate ABORT must fail");
            check_errno(error, "duplicate ABORT", libc::ESTALE)?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Ok(s) = writer.guard_status().await {
            if s.staged && s.staged_tx_id == Some(tx_id) {
                if let Err(e) = writer.guard_abort(tx_id).await {
                    eprintln!("[WARN] cleanup GUARD_ABORT failed: {e:#}");
                }
            }
        }
        outcome?;
        println!("[PASS] ALL Guard staging live checks (no COMMIT performed)");
        Ok(())
    }

    // Destructive VM-only test: after the first actual Guard COMMIT, the
    // legacy teald startup/flush sender cannot advance the epoch. Reboot the
    // disposable VM after this test; do not run on production machines.
    async fn run_commit_live_test() -> Result<()> {
        let service = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "teald.service"])
            .status()
            .context("systemctl is required for VM safety check")?;
        anyhow::ensure!(!service.success(), "stop teald.service first");
        anyhow::ensure!(unsafe { libc::geteuid() } == 0, "test requires root");

        let (writer, _rx_decision, _rx_audit) = init_socket().await?;
        ensure_guard_commit_supported()?;
        let before = writer.guard_status().await?;
        println!("[INFO] Before COMMIT: {before:?}");
        anyhow::ensure!(
            before.guard_state == 0 && !before.staged,
            "requires a fresh VM boot without a committed Guard"
        );
        anyhow::ensure!(before.last_epoch < u32::MAX - 2, "epoch overflow");

        let path = b"/etc/hostname".to_vec();
        let entry = GuardEntry {
            op_mask: 1,
            object_type: GuardObjectType::Path,
            match_type: GuardMatchType::Exact,
            target_mask: 1,
            path: Some(path),
        };
        let record_bytes = entry.validate()? as u32;
        // SHA256(LE32(1) | 01,01,01 | LE16(13) | b"/etc/hostname")
        let good_digest = [
            0x43, 0xae, 0x21, 0xfe, 0xd6, 0xff, 0x55, 0xfb, 0x77, 0xae, 0xdc, 0xb3, 0xb4, 0x47,
            0x0d, 0x9d, 0xe9, 0x25, 0xf0, 0x8f, 0x31, 0x52, 0x05, 0x0e, 0xac, 0xd2, 0x6a, 0xdf,
            0x53, 0xc3, 0x37, 0x97,
        ];
        let epoch = before.last_epoch + 1;
        let bad_tx = ((std::process::id() as u64) << 32) | 0xBAD1;
        let mut begin = GuardBegin {
            tx_id: bad_tx,
            base_epoch: before.last_epoch,
            next_epoch: epoch,
            expected_count: 1,
            total_bytes: record_bytes,
            sha256: [0x5a; 32],
        };
        writer.guard_begin(begin.clone()).await?;
        writer.guard_add(bad_tx, 0, entry.clone()).await?;
        let err = writer
            .guard_commit(epoch, bad_tx, begin.sha256)
            .await
            .expect_err("bad digest must fail COMMIT");
        check_errno(err, "invalid digest COMMIT", libc::EBADMSG)?;
        let status = writer.guard_status().await?;
        anyhow::ensure!(
            status.last_epoch == before.last_epoch && status.guard_state == 0 && status.staged,
            "failed COMMIT mutated active state"
        );
        writer.guard_abort(bad_tx).await?;
        println!("[PASS] Failed COMMIT preserved active state and epoch");

        let good_tx = bad_tx + 1;
        begin.tx_id = good_tx;
        begin.sha256 = good_digest;
        writer.guard_begin(begin).await?;
        writer.guard_add(good_tx, 0, entry).await?;
        writer.guard_commit(epoch, good_tx, good_digest).await?;
        let status = writer.guard_status().await?;
        println!("[INFO] After COMMIT: {status:?}");
        anyhow::ensure!(
            status.guard_state == 1
                && status.guard_epoch == epoch
                && status.last_epoch == epoch
                && status.current_epoch == epoch
                && !status.staged
                && status.active_sha256 == Some(good_digest),
            "COMMIT did not atomically activate Guard + Epoch"
        );
        println!("[PASS] Atomic Guard+Epoch COMMIT and active digest");

        // Guard READY後は、旧方式のEpoch-only POLICY_UPDATEを拒否すること。
        let (ack, rx) = oneshot::channel();

        writer
            .tx
            .send(NetlinkSendRequest::SyncEpoch(epoch + 1, ack))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to queue legacy POLICY_UPDATE"))?;

        let result = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .context("legacy POLICY_UPDATE ACK timed out")?
            .context("Netlink worker stopped before legacy POLICY_UPDATE ACK")?;

        let err = result.expect_err("legacy epoch-only update must be rejected");
        check_errno(err, "legacy POLICY_UPDATE after READY", libc::EPERM)?;

        // 拒否によって、GuardとEpochが変更されていないことも確認。
        let status = writer.guard_status().await?;

        anyhow::ensure!(
            status.guard_state == 1
                && status.last_epoch == epoch
                && status.current_epoch == epoch
                && status.guard_epoch == epoch
                && status.active_sha256 == Some(good_digest)
                && !status.staged,
            "rejected legacy POLICY_UPDATE modified Guard or Epoch"
        );

        writer.guard_reuse(epoch + 1, good_digest).await?;
        let status = writer.guard_status().await?;
        anyhow::ensure!(
            status.guard_state == 1
                && status.last_epoch == epoch + 1
                && status.guard_epoch == epoch + 1
                && status.active_sha256 == Some(good_digest),
            "REUSE changed Guard contents or failed to advance Epoch"
        );
        println!("[PASS] Guard REUSE advanced Epoch without changing digest");

        let err = writer
            .guard_reuse(epoch + 2, [0x22; 32])
            .await
            .expect_err("wrong digest REUSE must fail");
        check_errno(err, "REUSE digest mismatch", libc::ESTALE)?;
        let status = writer.guard_status().await?;
        anyhow::ensure!(
            status.last_epoch == epoch + 1 && status.active_sha256 == Some(good_digest),
            "rejected REUSE modified committed state"
        );
        println!("[PASS] ALL atomic Guard COMMIT checks; reboot the VM now");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "DESTRUCTIVE VM only: leaves committed Guard; REBOOT VM after test"]
    async fn guard_commit_live_integration() {
        if let Err(error) = run_commit_live_test().await {
            panic!("Guard COMMIT live integration failed: {error:#}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "VM only: stop teald.service, then run test binary as root"]
    async fn guard_staging_live_integration() {
        if let Err(error) = run_live_test().await {
            panic!("Guard Netlink live integration failed: {error:#}");
        }
    }
}

// === MPA Guard source-of-truth compiler and synchronizer (Stage 3 candidate) ===
// Guard is a conservative object x operation superset; no subject/UID binding.
// NOTE: SHA-256 is used for transport integrity, NOT update authorization.
use std::os::unix::ffi::OsStrExt;
use teal_policy_engine::ir::{ActionMatcher, CompiledBundle, PathMatcher};

const GUARD_RENAME_BIT: u32 = 32;
const GUARD_CONNECT_BIT: u32 = 256;

#[derive(Debug, Clone)]
pub struct GuardManifest {
    pub entries: Vec<GuardEntry>,
    pub total_bytes: u32,
    pub sha256: [u8; 32],
}

fn guard_all(op_mask: u32) -> GuardEntry {
    GuardEntry {
        op_mask,
        object_type: GuardObjectType::Any,
        match_type: GuardMatchType::All,
        target_mask: if op_mask & GUARD_RENAME_BIT != 0 {
            3
        } else {
            1
        },
        path: None,
    }
}

fn path_guard(op_mask: u32, matcher: Option<&PathMatcher>) -> GuardEntry {
    // Unrepresentable glob, missing path, non-canonical path => protect ALL.
    let Some(matcher) = matcher else {
        return guard_all(op_mask);
    };
    let (match_type, path) = match matcher {
        PathMatcher::Exact(p) => (GuardMatchType::Exact, p.as_os_str().as_bytes()),
        PathMatcher::Prefix(p) if p.as_os_str().as_bytes().ends_with(b"/") => {
            (GuardMatchType::Prefix, p.as_os_str().as_bytes())
        }
        // A partial-component prefix (e.g. /etc/hos*) may also match
        // /etc/hostname2. Kernel v1 Prefix is component-boundary aware.
        // Until the IR semantics are reviewed, prefer ANY/ALL over undercoverage.
        PathMatcher::Prefix(_) => return guard_all(op_mask),
        PathMatcher::Glob { .. } => return guard_all(op_mask),
    };
    if !guard_path_valid(path) {
        return guard_all(op_mask);
    }
    GuardEntry {
        op_mask,
        object_type: GuardObjectType::Path,
        match_type,
        target_mask: if op_mask & GUARD_RENAME_BIT != 0 {
            3
        } else {
            1
        },
        path: Some(path.to_vec()),
    }
}

fn append_unique(entries: &mut Vec<GuardEntry>, item: GuardEntry) {
    if !entries.contains(&item) {
        entries.push(item);
    }
}

/// Converts every need_approval rule into a conservative Guard superset.
/// Unsupported path representations expand to ANY/ALL (never silently omitted).
/// No subject/role/UID constraints enter this classification.
pub fn compile_guard_manifest(bundle: &CompiledBundle) -> Result<GuardManifest> {
    let mut entries = Vec::new();
    for rule in &bundle.policy.rules {
        if rule.effect.as_str() != "need_approval" {
            continue;
        }
        let raw_ops = rule.action_match.to_u32();
        // ActionMatcher::to_u32() is already used for single-action tickets,
        // but its multi-action encoding is not available for review here.
        // A multi-action or ANY policy is therefore broadened to ALL ops.
        let exactly_one = matches!(&rule.action_match,
            ActionMatcher::OneOf(set) if set.len() == 1);
        let ops = if !exactly_one || raw_ops == 0 || raw_ops & !GUARD_OP_BITS != 0 {
            GUARD_OP_BITS
        } else {
            raw_ops
        };
        // CONNECT has no path semantics in Guard wire v1; always ANY/ALL.
        if ops & GUARD_CONNECT_BIT != 0 {
            append_unique(&mut entries, guard_all(GUARD_CONNECT_BIT));
        }
        // RENAME compares old and new path separately; split it from all
        // other bits because its mandatory target_mask differs (3 vs 1).
        if ops & GUARD_RENAME_BIT != 0 {
            if let Some(object) = rule.object.as_ref() {
                if object.path.is_none() && object.new_path.is_none() {
                    append_unique(&mut entries, guard_all(GUARD_RENAME_BIT));
                } else {
                    if let Some(m) = object.path.as_ref() {
                        append_unique(&mut entries, path_guard(GUARD_RENAME_BIT, Some(m)));
                    }
                    if let Some(m) = object.new_path.as_ref() {
                        append_unique(&mut entries, path_guard(GUARD_RENAME_BIT, Some(m)));
                    }
                }
            } else {
                append_unique(&mut entries, guard_all(GUARD_RENAME_BIT));
            }
        }
        let other = ops & !(GUARD_CONNECT_BIT | GUARD_RENAME_BIT);
        if other != 0 {
            append_unique(
                &mut entries,
                path_guard(other, rule.object.as_ref().and_then(|o| o.path.as_ref())),
            );
        }
    }
    // A broad ANY/ALL entry subsumes all path entries for its operation bits.
    // Do not attempt more complicated compression that could shrink protection.
    let mut reduced = Vec::new();
    for item in &entries {
        if item.object_type == GuardObjectType::Path
            && entries.iter().any(|e| {
                e.object_type == GuardObjectType::Any && e.op_mask & item.op_mask == item.op_mask
            })
        {
            continue;
        }
        reduced.push(item.clone());
    }
    anyhow::ensure!(
        reduced.len() <= GUARD_MAX_ENTRIES,
        "compiled Guard requires {} entries; maximum is {} (refusing truncation)",
        reduced.len(),
        GUARD_MAX_ENTRIES
    );
    let mut encoded = Vec::new();
    for entry in &reduced {
        entry.validate()?;
        let path = entry.path.as_deref().unwrap_or(&[]);
        anyhow::ensure!(path.len() <= u16::MAX as usize, "Guard path too long");
        encoded.extend_from_slice(&entry.op_mask.to_le_bytes());
        encoded.push(entry.object_type as u8);
        encoded.push(entry.match_type as u8);
        encoded.push(entry.target_mask);
        encoded.extend_from_slice(&(path.len() as u16).to_le_bytes());
        encoded.extend_from_slice(path);
    }
    anyhow::ensure!(
        encoded.len() <= u32::MAX as usize,
        "Guard encoding too long"
    );
    let total_bytes = encoded.len() as u32;
    let sha256 = guard_sha256(&encoded);
    let manifest = GuardManifest {
        entries: reduced,
        total_bytes,
        sha256,
    };
    GuardBegin {
        tx_id: 1,
        base_epoch: 0,
        next_epoch: 1,
        expected_count: manifest.entries.len() as u32,
        total_bytes: manifest.total_bytes,
        sha256: manifest.sha256,
    }
    .validate()?;
    Ok(manifest)
}

// SHA-256 FIPS 180-4. A tiny self-contained implementation avoids adding a
// new library dependency to teald. Its known vectors are checked below.
fn guard_sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let length = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&length.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

impl NlWriter {
    /// Transfer and commit a candidate. Returns READY status after validation.
    /// The caller must stop the emission of new permits/tickets during this call.
    pub async fn sync_guard_manifest(
        &self,
        manifest: &GuardManifest,
        base_epoch: u32,
        next_epoch: u32,
    ) -> Result<GuardStatus> {
        ensure_guard_commit_supported()?;
        let before = self.guard_status().await?;
        anyhow::ensure!(
            before.last_epoch == base_epoch && !before.staged,
            "kernel Guard state not ready for BEGIN (last={}, staged={})",
            before.last_epoch,
            before.staged
        );
        anyhow::ensure!(
            next_epoch
                == base_epoch
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("epoch overflow"))?,
            "Guard requires next consecutive Epoch"
        );
        let tx_id = u64::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into()?) | 1;
        let begin = GuardBegin {
            tx_id,
            base_epoch,
            next_epoch,
            expected_count: manifest.entries.len() as u32,
            total_bytes: manifest.total_bytes,
            sha256: manifest.sha256,
        };
        self.guard_begin(begin).await?;
        // BEGIN/ADD errors are pre-COMMIT; best-effort abort, never publish partial data.
        for (index, entry) in manifest.entries.iter().enumerate() {
            if let Err(error) = self.guard_add(tx_id, index as u32, entry.clone()).await {
                if let Err(abort_error) = self.guard_abort(tx_id).await {
                    eprintln!("[ERROR] GUARD_ABORT during staging cleanup: {abort_error:#}");
                }
                return Err(error);
            }
        }
        // Lost COMMIT ACK: kernel might already have committed. Never blindly retry.
        if let Err(error) = self.guard_commit(next_epoch, tx_id, manifest.sha256).await {
            if let Ok(status) = self.guard_status().await {
                if status.guard_state == 1
                    && status.last_epoch == next_epoch
                    && status.guard_epoch == next_epoch
                    && status.current_epoch == next_epoch
                    && status.active_sha256 == Some(manifest.sha256)
                    && !status.staged
                {
                    return Ok(status);
                }
            }
            anyhow::bail!("GUARD_COMMIT outcome uncertain: {error:#}; prohibit further permits until recovery");
        }
        let status = self.guard_status().await?;
        anyhow::ensure!(
            status.guard_state == 1
                && status.last_epoch == next_epoch
                && status.current_epoch == next_epoch
                && status.guard_epoch == next_epoch
                && !status.staged
                && status.active_sha256 == Some(manifest.sha256),
            "GUARD_COMMIT ACKed but STATUS mismatch; kernel/userland state uncertain"
        );
        Ok(status)
    }

    /// Advance Epoch without changing Guard contents (FLUSH only).
    pub async fn reuse_guard_verified(
        &self,
        base_epoch: u32,
        next_epoch: u32,
    ) -> Result<GuardStatus> {
        let before = self.guard_status().await?;
        anyhow::ensure!(
            before.guard_state == 1
                && before.last_epoch == base_epoch
                && before.guard_epoch == base_epoch
                && !before.staged,
            "Guard is not READY for reuse"
        );
        let digest = before
            .active_sha256
            .ok_or_else(|| anyhow::anyhow!("missing active digest"))?;
        anyhow::ensure!(
            next_epoch
                == base_epoch
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("epoch overflow"))?,
            "REUSE requires next consecutive Epoch"
        );
        let update = self.guard_reuse(next_epoch, digest).await;
        let status = self.guard_status().await?;
        if status.guard_state == 1
            && status.last_epoch == next_epoch
            && status.guard_epoch == next_epoch
            && status.current_epoch == next_epoch
            && status.active_sha256 == Some(digest)
            && !status.staged
        {
            return Ok(status);
        }
        if let Err(error) = update {
            anyhow::bail!("GUARD_REUSE outcome uncertain: {error:#}");
        }
        anyhow::bail!("GUARD_REUSE ACKed but STATUS mismatch");
    }
}

#[cfg(test)]
mod guard_sync_compiler_tests {
    use super::*;
    #[test]
    fn digest_matches_sha256_vectors() {
        let empty = guard_sha256(b"");
        assert_eq!(
            empty,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
        let abc = guard_sha256(b"abc");
        assert_eq!(
            abc,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let mut record = Vec::new();
        record.extend_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(&[1, 1, 1]);
        record.extend_from_slice(&(13u16).to_le_bytes());
        record.extend_from_slice(b"/etc/hostname");
        assert_eq!(
            guard_sha256(&record),
            [
                0x43, 0xae, 0x21, 0xfe, 0xd6, 0xff, 0x55, 0xfb, 0x77, 0xae, 0xdc, 0xb3, 0xb4, 0x47,
                0x0d, 0x9d, 0xe9, 0x25, 0xf0, 0x8f, 0x31, 0x52, 0x05, 0x0e, 0xac, 0xd2, 0x6a, 0xdf,
                0x53, 0xc3, 0x37, 0x97
            ]
        );
    }
}
