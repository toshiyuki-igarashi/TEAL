// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Mutex};
use tokio::signal;

use std::sync::{Arc, OnceLock};
use std::collections::HashMap;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Result, Context};

mod types;
pub mod worker;

mod roles;
mod policy;
mod bundle;
mod decide;
mod management;
mod common;
mod ticket;
mod evidence;
mod utils;

// Netlink通信用モジュール
mod netlink; 

use crate::types::{AppState, FastState, SlowState, TealDeviceState, InternalEvent};
use crate::bundle::{load_from_bundle, bundle};
use crate::management::load_from_management;
use crate::evidence::EvidenceManager;

use teal_policy_engine::util::ktime_prefix;

static APP_STATE: OnceLock<Arc<Mutex<AppState>>> = OnceLock::new();

pub fn set_app_state(state: Arc<Mutex<AppState>>) {
    APP_STATE.set(state).expect("APP_STATE already initialized");
}

pub fn app_state() -> &'static Arc<Mutex<AppState>> {
    APP_STATE.get().expect("APP_STATE not initialized")
}

/// 1) state の初期化
async fn init_state() {
    set_app_state(
        Arc::new(Mutex::new(AppState {
            fast: FastState {
                drafts: HashMap::new(),
                approved: HashMap::new(),
                tickets: HashMap::new(),
                next_draft_seq: 0,
            },
            slow: SlowState {
                pending_requests: HashMap::new(),
                registered_keys: HashMap::new(),
                pending_start: None,
                pending_stop: None,
            },
            dev: TealDeviceState {
                // NetlinkのファミリーID等を保持するように後で変更します
                dev_teal_path: String::from("netlink:teal_ctrl"),
                device_file: None, 
            },
            is_enforce: false,
            current_epoch: 0,
        }))
    )
}

/// 2) admin unix socket を初期化して listener を返す
async fn init_admin_socket(socket_path: &str) -> Result<UnixListener> {
    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path).context("remove existing admin socket")?;
    }

    let listener = UnixListener::bind(socket_path).context("bind admin unix socket")?;

    #[cfg(unix)]
    {
        std::fs::set_permissions(socket_path, PermissionsExt::from_mode(0o777))
            .with_context(|| format!("chmod 0777 for {}", socket_path))?;
    }

    eprintln!(
        "{}[INFO] Admin interface listening on {}",
        ktime_prefix(),
        socket_path
    );

    Ok(listener)
}

/// 3) メインのワーカー群を起動し、待機する
pub async fn run_workers(
    nl_tx: netlink::NlWriter,                                   // ★ 送信用ハンドル
    rx_decision: mpsc::Receiver<netlink::TealNetlinkMessage>,   // ★ Decision用受信
    rx_audit: mpsc::Receiver<netlink::TealNetlinkMessage>,      // ★ Audit用受信
    listener: UnixListener,
) -> Result<()> {
    let (internal_tx, internal_rx) = mpsc::channel::<InternalEvent>(5000);
    let admin_tx = internal_tx.clone();

    // ① Audit Worker
    let nl_tx_audit = nl_tx.clone();
    let audit_handle = tokio::spawn(async move {
        crate::worker::audit::audit_worker_loop(rx_audit, internal_rx, nl_tx_audit).await;
    });

    // ② Decision Worker
    let nl_tx_decision = nl_tx.clone();
    let decision_handle = tokio::spawn(async move {
        crate::worker::decision::decision_worker_loop(rx_decision, internal_tx, nl_tx_decision).await;
    });

    // ③ Admin Socket Worker (管理ソケット)
    let nl_tx_admin = nl_tx.clone();
    let admin_handle = tokio::spawn(async move {
        crate::worker::admin::admin_socket_loop(listener, admin_tx, nl_tx_admin).await; 
    });

    tokio::select! {
        _ = signal::ctrl_c() => {}
        res = async { tokio::try_join!(audit_handle, decision_handle, admin_handle) } => {
            if let Err(e) = res {
                eprintln!("{}[ERROR] A worker panicked: {}", ktime_prefix(), e);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("{}[INFO] Starting TEAL Daemon (Netlink Mode)...", ktime_prefix());

    load_from_bundle()?;
    let b = bundle();
    load_from_management(&b.roles)?;

    init_state().await;
    EvidenceManager::init(1024);

    // ==============================================================
    // Generic Netlink 初期化処理
    // ==============================================================
    
    let (nl_tx, rx_decision, rx_audit) = netlink::init_socket().await
        .context("Failed to initialize Netlink socket")?;

    eprintln!("{}[INFO] Successfully attached to Kernel via Generic Netlink", ktime_prefix());

    // ==============================================================

    let listener = init_admin_socket("/tmp/teald.sock").await?;

    // ワーカー起動へ
    run_workers(nl_tx, rx_decision, rx_audit, listener).await
}
