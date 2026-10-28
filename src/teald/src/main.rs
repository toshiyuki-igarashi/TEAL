// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::time::Duration;
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::mpsc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};

use teald::ai;
use teald::bundle::{
    bundle, init_bundle_at_epoch, load_bundle_from_dir, policy_snapshot, DEFAULT_TEAL_DIR,
};
use teald::evidence::EvidenceManager;
use teald::management::load_from_management;
use teald::netlink::{
    get_netlink_socket_metrics, init_socket, kernel_next_epoch, NlWriter, TealNetlinkMessage,
};
use teald::pam_server::start_pam_listener;
use teald::ticket::preload_silent_directory_tickets;
use teald::types::{set_daemon_mode, DaemonMode, InternalEvent};

use teal_policy_engine::util::ktime_prefix;

/// 1) state の初期化
use teald::state::init_state;

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
    nl_tx: NlWriter,                                 // ★ 送信用ハンドル
    rx_decision: mpsc::Receiver<TealNetlinkMessage>, // ★ Decision用受信
    rx_audit: mpsc::Receiver<TealNetlinkMessage>,    // ★ Audit用受信
    listener: UnixListener,
) -> Result<()> {
    let (internal_tx, internal_rx) = mpsc::channel::<InternalEvent>(5000);
    let admin_tx = internal_tx.clone();

    // ① Audit Worker
    let nl_tx_audit = nl_tx.clone();
    let audit_handle = tokio::spawn(async move {
        teald::worker::audit::audit_worker_loop(rx_audit, internal_rx, nl_tx_audit).await;
    });

    // ② Decision Worker
    let nl_tx_decision = nl_tx.clone();
    let decision_handle = tokio::spawn(async move {
        teald::worker::decision::decision_worker_loop(rx_decision, internal_tx, nl_tx_decision)
            .await;
    });

    // ③ Admin Socket Worker (管理ソケット)
    let nl_tx_admin = nl_tx.clone();
    let admin_handle = tokio::spawn(async move {
        teald::worker::admin::admin_socket_loop(listener, admin_tx, nl_tx_admin).await;
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

// --- 定数定義 ---
/// ログストーム観測用の初期待ち時間（秒）
const INIT_WAIT: Duration = Duration::from_secs(15);

/// ログストーム収束待機時のポーリング間隔（秒）
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// 収束判定のしきい値（バッファ使用率 5% 未満）
const SETTLED_BUFFER_THRESHOLD_PCT: f64 = 5.0;

/// 収束と判定するために必要な連続成功回数（3秒連続）
const SETTLED_CONSECUTIVE_THRESHOLD: u32 = 3;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!(
        "{}[INFO] Starting TEAL Daemon (Netlink Mode)...",
        ktime_prefix()
    );

    // 起動直後は確実に DRAIN モードに設定
    set_daemon_mode(DaemonMode::Drain);

    // まずポリシーを検証・コンパイルするが、Epochはまだ確定しない。
    // REGISTERの返答でカーネルが指示するEpochを受け取ってから公開する。
    let compiled =
        load_bundle_from_dir(DEFAULT_TEAL_DIR).context("Failed to load and compile TEAL bundle")?;

    // ==============================================================
    // Generic Netlink 初期化処理
    // ==============================================================
    let (nl_tx, rx_decision, rx_audit) = init_socket()
        .await
        .context("Failed to initialize Netlink socket")?;

    eprintln!(
        "{}[INFO] Successfully attached to Kernel via Generic Netlink",
        ktime_prefix()
    );

    // REGISTERの応答(EPOCH=last_epoch+1)をローカルSnapshotに反映する。
    // 重要: 新Epochは、カーネルのPOLICY_UPDATE ACKまで運用状態と見なさない。
    let next_epoch = kernel_next_epoch();
    anyhow::ensure!(next_epoch != 0, "REGISTER did not return a valid Epoch");
    init_bundle_at_epoch(compiled, next_epoch)?;
    let b = bundle();
    load_from_management(&b.roles)?;

    // 初期要求を処理するワーカーや事前チケット登録を始める前に同期を確定する。
    // netlink.rsのsend_sync_epoch()はカーネルACKを待つ実装が必須。
    nl_tx
        .send_sync_epoch(next_epoch)
        .await
        .with_context(|| format!("Kernel POLICY_UPDATE ACK failed for Epoch {}", next_epoch))?;
    anyhow::ensure!(
        policy_snapshot().epoch == next_epoch,
        "PolicySnapshot Epoch mismatch after kernel ACK"
    );
    eprintln!(
        "{}[INFO] Initial policy Epoch {} synchronized with kernel",
        ktime_prefix(),
        next_epoch
    );

    init_state().await;

    let ai_runtime = ai::init_ai().map_err(|e| anyhow::anyhow!(e))?;

    EvidenceManager::init(1024, ai_runtime);

    let listener = init_admin_socket("/tmp/teald.sock").await?;

    // PAMリスナーをバックグラウンドタスクとして起動
    tokio::spawn(async {
        start_pam_listener().await;
    });

    let nl_tx_monitor = nl_tx.clone();

    // ==============================================================
    // ログストーム収束監視タスク (Drain -> Audit 自動移行)
    // ==============================================================
    tokio::spawn(async move {
        eprintln!(
            "{}[INFO] teald: Started in DRAIN mode. Absorbing boot storm...",
            ktime_prefix()
        );

        // ★ ここで silent_io かつ prefix: なディレクトリ包括チケットを一括投入！
        if let Err(e) = preload_silent_directory_tickets(&nl_tx_monitor).await {
            eprintln!(
                "{}[WARN] Failed to preload directory tickets: {}",
                ktime_prefix(),
                e
            );
        }

        // 1. 起動直後の過渡期を無条件待機 (この間にチケットがカーネルに定着する)
        tokio::time::sleep(INIT_WAIT).await;

        eprintln!(
            "{}[INFO] teald: Monitoring Netlink buffer settle...",
            ktime_prefix()
        );
        let mut settled_consecutive = 0;
        let mut interval = tokio::time::interval(POLL_INTERVAL);

        // 監視タスク専用の前回ドロップ数保持（admin.rs と競合させない）
        let (_, mut prev_drops) = get_netlink_socket_metrics();

        loop {
            interval.tick().await;

            let (usage_pct, current_drops) = get_netlink_socket_metrics();
            let drops_delta = current_drops.saturating_sub(prev_drops);
            prev_drops = current_drops;

            // バッファ使用率が 5% 未満、かつ新たなパケットドロップが 0
            if usage_pct < SETTLED_BUFFER_THRESHOLD_PCT && drops_delta == 0 {
                settled_consecutive += 1;

                if settled_consecutive >= SETTLED_CONSECUTIVE_THRESHOLD {
                    eprintln!(
                        "{}[INFO] teald: Log storm settled. Transitioning to AUDIT mode.",
                        ktime_prefix()
                    );

                    // モードを AUDIT に切り替え（worker/audit が通常ログ処理を開始）
                    set_daemon_mode(DaemonMode::Audit);
                    break;
                }
            } else {
                settled_consecutive = 0;
            }
        }
    });

    // メインワーカー起動へ
    run_workers(nl_tx, rx_decision, rx_audit, listener).await
}
