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
use neli::genl::{Genlmsghdr, Nlattr};
use neli::types::GenlBuffer;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::neli_enum;
use neli::err::SerError;
use std::thread;
use std::sync::Arc;
use std::os::fd::AsRawFd;
use tokio::sync::{mpsc, Mutex};

use teal_policy_engine::util::ktime_prefix;
use crate::types::TicketPayload;

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
    NewTarget    = 31,

    // --- ログインコンテキスト（TTY）用 ---
    SessionTty   = 32,
}
impl NlAttrType for TealAttr {}


// ==========================================
// 2. ワーカーへ渡すためのメッセージ構造体
// ==========================================

#[derive(Debug)]
pub enum TealNetlinkMessage {
    Req(TealReq),
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
    ModeSwitch(u32),
}

// --- [構造体] 軽量化された NlWriter ---
#[derive(Clone)]
pub struct NlWriter {
    pub tx: mpsc::Sender<NetlinkSendRequest>,
    pub family_id: u16,
}

impl NlWriter {
    pub async fn send_approve(&self, trans_id: u64) -> Result<()> {
        self.tx.send(NetlinkSendRequest::Approve(trans_id)).await
            .map_err(|_| anyhow::anyhow!("Failed to queue APPROVE"))
    }

    pub async fn send_deny(&self, trans_id: u64) -> Result<()> {
        self.tx.send(NetlinkSendRequest::Deny(trans_id)).await
            .map_err(|_| anyhow::anyhow!("Failed to queue DENY"))
    }

    pub async fn send_ticket_add(&self, ticket: TicketPayload) -> Result<()> {
        self.tx.send(NetlinkSendRequest::TicketAdd(ticket)).await
            .map_err(|_| anyhow::anyhow!("Failed to queue TICKET_ADD"))
    }

    pub async fn send_mode_switch(&self, mode: u32) -> Result<()> {
        self.tx.send(NetlinkSendRequest::ModeSwitch(mode)).await
            .map_err(|_| anyhow::anyhow!("Failed to queue MODE_SWITCH"))
    }
}

// ==========================================
// 3. ソケット初期化とメイン処理
// ==========================================

/// カーネルの "teal_ctrl" ファミリーを解決し、非同期ソケットを準備する
/// 戻り値: (送信用ハンドル, Decisionワーカー用Receiver, Auditワーカー用Receiver)
pub async fn init_socket() -> Result<(NlWriter, mpsc::Receiver<TealNetlinkMessage>, mpsc::Receiver<TealNetlinkMessage>)> {
    // --- 1. ソケット接続とファミリー解決 ---
    let mut rx_sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;

    // 受信バッファを 4MB 程度に引き上げる (デフォルトは 256KB 程度)
    let fd = rx_sock.as_raw_fd();
    let size: i32 = 4 * 1024 * 1024; 
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }

    let rx_portid = rx_sock.pid().unwrap_or(0);
    let family_id = rx_sock.resolve_genl_family("teal_ctrl")?;
    eprintln!("{}[INFO] Resolved teal_ctrl family ID: {}", ktime_prefix(), family_id);

    // 送信用ソケットを独立して接続
    let tx_sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
    let tx_portid = tx_sock.pid().unwrap_or(0);
    let sock_arc: Arc<Mutex<NlSocketHandle>> = Arc::new(Mutex::new(tx_sock));

    eprintln!("{}[INFO] teald RX PortID (Receiving): {}", ktime_prefix(), rx_portid);
    eprintln!("{}[INFO] teald TX PortID (Sending)  : {}", ktime_prefix(), tx_portid);

    // --- 2. REGISTER 送信 (同期) ---
    // ここはまだワーカーがいないので rx_sock を使って直接ハンドシェイク
    let genlhdr: Genlmsghdr<TealCmd, TealAttr> = Genlmsghdr::new(TealCmd::Register, 1, GenlBuffer::new());
    let nlhdr = Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request, NlmF::Ack]), None, None, NlPayload::Payload(genlhdr));
    rx_sock.send(nlhdr)?;
    let _ = rx_sock.recv::<u16, Genlmsghdr<TealCmd, TealAttr>>()?;

    // --- 3. 送信ワーカーの準備と起動 ---
    let (send_tx, send_rx) = mpsc::channel(10240);
    let nl_tx = NlWriter { tx: send_tx, family_id };

    // ワーカーを起動。sock_arc の所有権を渡す。
    let worker_sock = Arc::clone(&sock_arc);
    tokio::spawn(async move {
        netlink_send_worker_loop(send_rx, worker_sock, family_id).await;
    });

    // --- 4. 初期モード同期 (ModeSwitch) ---
    nl_tx.send_mode_switch(0).await?; 

    // --- 5. 受信スレッドの起動 ---
    let (tx_decision, rx_decision) = mpsc::channel(1024);
    let (tx_audit, rx_audit) = mpsc::channel(1024);
    
    thread::spawn(move || {
       eprintln!("{}[INFO] Netlink dedicated receiver thread started.", ktime_prefix());
        
        loop {
            let msg_res = rx_sock.recv::<u16, Genlmsghdr<TealCmd, TealAttr>>();

            match msg_res {
                // ★ msg に中身が入っていた場合（成功ルート）
                Ok(Some(msg)) => {
                    if let NlPayload::Payload(genl_msg) = msg.nl_payload {
                        match genl_msg.cmd {
                            TealCmd::Req => {
                                match parse_req_msg(&genl_msg) {
                                    Ok(req) => {
                                        let is_audit = (req.flags & 1) != 0;                                        
                                        if is_audit {
                                            let _ = tx_audit.blocking_send(TealNetlinkMessage::Req(req));
                                        } else {
                                            let _ = tx_decision.blocking_send(TealNetlinkMessage::Req(req));
                                        }
                                    }
                                    Err(e) => eprintln!("{}[ERROR-NETLINK] PARSE FAILED: {:?}", ktime_prefix(), e),
                                }
                            }
                            TealCmd::Info => {
                                if let Ok(info) = parse_info_msg(&genl_msg) {
                                    let _ = tx_audit.blocking_send(TealNetlinkMessage::Info(info));
                                }
                            }
                            _ => {} 
                        }
                    }
                }
                // ★ neli がパケットをこっそり捨てた（中身が空だった）場合
                Ok(None) => {
                    eprintln!("{}[WARN-NETLINK] recv returned Ok(None). (Empty packet or dropped)", ktime_prefix());
                }
                // ★ シーケンス番号不一致などのエラーが起きた場合
                Err(e) => {
                    let err_str = format!("{:?}", e);
                    if err_str.contains("ENOBUFS") || err_str.contains("No buffer space available") {
                        eprintln!("{}[CRITICAL-NETLINK] BUFFER OVERFLOW DETECTED (ENOBUFS)!", ktime_prefix());
                        eprintln!("{}[CRITICAL-NETLINK] Kernel dropped packets because teald is too slow to read or buffer (4MB) is full.", ktime_prefix());
                        eprintln!("{}[CRITICAL-NETLINK] ACTION REQUIRED: Optimize policies using SILENT_IO tickets to reduce kernel IPC.", ktime_prefix());
                    } else {
                        // その他の通信エラー（シーケンス番号のズレなど）
                        eprintln!("{}[ERROR-NETLINK] recv error (Ignored): {:?}", ktime_prefix(), e);
                    }
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
            TealAttr::TransId   => req.trans_id = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Pid       => req.pid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Ppid      => req.ppid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::SessionId => req.session_id = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Uid       => req.uid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Gid       => req.gid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ProgDev   => req.prog_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ProgIno   => req.prog_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::TargetDev => req.target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::TargetIno => req.target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ScriptDev => req.script_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ScriptIno => req.script_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Flags     => req.flags = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            
            // 文字列のパース（終端のNUL文字をトリムしてString化）
            TealAttr::Program   => req.program = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),
            TealAttr::Action    => req.action = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),
            TealAttr::Target    => req.target = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),
            TealAttr::Script    => req.script = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),
            TealAttr::Applet    => req.applet = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),
            TealAttr::LsmLabel  => req.lsm_label = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),
            TealAttr::ArgsHead  => req.args_head = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),

            TealAttr::NewTargetDev => req.new_target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::NewTargetIno => req.new_target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::NewTarget    => req.new_target    = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),

            // SessionTty の文字列パース
            TealAttr::SessionTty   => req.session_tty    = String::from_utf8_lossy(attr.nla_payload.as_ref()).trim_end_matches('\0').to_string(),

            _ => {} 
        }
    }
    Ok(req)
}

fn parse_info_msg(genl_msg: &Genlmsghdr<TealCmd, TealAttr>) -> Result<TealInfo> {
    let mut info = TealInfo::default();
    
    for attr in genl_msg.get_attr_handle().iter() {
        match attr.nla_type.nla_type {
            TealAttr::InfoEvt     => info.is_expired = attr.nla_payload.as_ref()[0] == 1,
            TealAttr::TicketId    => info.ticket_id = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::Uid         => info.uid = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::UsesLeft    => info.uses_left = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ProgDev     => info.prog_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::ProgIno     => info.prog_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::TargetDev   => info.target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::TargetIno   => info.target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::NewTargetDev => info.new_target_dev = u32::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),
            TealAttr::NewTargetIno => info.new_target_ino = u64::from_ne_bytes(attr.nla_payload.as_ref().try_into()?),

            _ => {}
        }
    }
    Ok(info)
}

// --- [ワーカー] 送信専用メインループ ---
pub async fn netlink_send_worker_loop(
    mut rx: mpsc::Receiver<NetlinkSendRequest>,
    sock_mutex: Arc<Mutex<NlSocketHandle>>,
    family_id: u16,
) {
    eprintln!("{}[INFO] Netlink Send Worker: Serialized dispatcher started.", ktime_prefix());

    while let Some(req) = rx.recv().await {
        // ここが唯一のソケットロック取得ポイント
        let mut sock = sock_mutex.lock().await;

        let nl_res = match req {
            NetlinkSendRequest::Approve(id) => sock.send(build_approve(family_id, id).unwrap()),
            NetlinkSendRequest::Deny(id) => sock.send(build_deny(family_id, id).unwrap()),
            NetlinkSendRequest::TicketAdd(ticket) => sock.send(build_ticket_add(family_id, &ticket).unwrap()),
            NetlinkSendRequest::ModeSwitch(mode) => sock.send(build_mode_switch_packet(family_id, mode).unwrap()),
        };

        if let Err(e) = nl_res {
            eprintln!("{}[ERROR] Netlink Dispatch failure: {:?}", ktime_prefix(), e);
            
            // 致命的エラー判定
            if is_fatal_netlink_error(&e) {
                eprintln!("{}[FATAL] Connection lost (EPIPE/ECONNRESET). Exiting send worker.", ktime_prefix());
                // ワーカーが終了することで、受信側のReceiverも閉じられ、全体のリカバリが連鎖する
                return; 
            }
        }
    }
}

// --- [ヘルパー] 致命的エラー判定 ---
fn is_fatal_netlink_error(e: &SerError) -> bool {
    match e {
        SerError::Wrapped(boxed_err) => {
            let err_str = format!("{:?}", boxed_err);
            err_str.contains("BrokenPipe") || err_str.contains("ConnectionReset") || err_str.contains("NotConnected")
        },
        _ => false,
    }
}

// --- [構築ロジック] 各パケットのビルド ---
fn build_approve(family_id: u16, trans_id: u64) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(false, false, TealAttr::TransId, trans_id.to_ne_bytes().as_ref())?);
    let genlhdr = Genlmsghdr::new(TealCmd::Approve, 1, attrs);
    Ok(Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(genlhdr)))
}

fn build_deny(family_id: u16, trans_id: u64) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(false, false, TealAttr::TransId, trans_id.to_ne_bytes().as_ref())?);
    let genlhdr = Genlmsghdr::new(TealCmd::Deny, 1, attrs);
    Ok(Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(genlhdr)))
}

fn build_ticket_add(family_id: u16, ticket: &TicketPayload) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut expires_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    expires_at = if ticket.expires_in_sec < u64::MAX { expires_at + ticket.expires_in_sec } else { u64::MAX };
    let numeric_ticket_id: u64 = ticket.ticket_id.trim_start_matches("T-").parse().unwrap_or(0);

    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(false, false, TealAttr::Uid, ticket.uid.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::Op, ticket.op.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::ProgDev, (ticket.prog_dev as u32).to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::ProgIno, ticket.prog_ino.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::ScriptDev, (ticket.script_dev as u32).to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::ScriptIno, ticket.script_ino.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::TargetDev, (ticket.target_dev as u32).to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::TargetIno, ticket.target_ino.to_ne_bytes().as_ref())?);

    // RENAME 用の移動先情報 (Dev/Ino)
    attrs.push(Nlattr::new(false, false, TealAttr::NewTargetDev, (ticket.new_target_dev as u32).to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::NewTargetIno, ticket.new_target_ino.to_ne_bytes().as_ref())?);
    
    attrs.push(Nlattr::new(false, false, TealAttr::ExpiresAt, expires_at.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::Flags, ticket.flags.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::UsesLeft, ticket.uses_left.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::TicketId, numeric_ticket_id.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::Epoch, ticket.epoch.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::AuditFlg, ticket.audit_flags.to_ne_bytes().as_ref())?);
    attrs.push(Nlattr::new(false, false, TealAttr::AppletHash, ticket.applet_hash.to_ne_bytes().as_ref())?);

    let genlhdr = Genlmsghdr::new(TealCmd::TicketAdd, 1, attrs);
    Ok(Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(genlhdr)))
}

fn build_mode_switch_packet(family_id: u16, mode: u32) -> Result<Nlmsghdr<u16, Genlmsghdr<TealCmd, TealAttr>>> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(false, false, TealAttr::Flags, mode.to_ne_bytes().as_ref())?);
    let genlhdr = Genlmsghdr::new(TealCmd::ModeSwitch, 1, attrs);
    Ok(Nlmsghdr::new(None, family_id, NlmFFlags::new(&[NlmF::Request]), None, None, NlPayload::Payload(genlhdr)))
}
