// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use std::time::Duration;
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::{mpsc, oneshot};

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
    compile_guard_manifest, get_netlink_socket_metrics, init_socket, kernel_next_epoch,
    kernel_runtime_mode, NlWriter, TealNetlinkMessage,
};
use teald::pam_server::start_pam_listener;
use teald::ticket::preload_silent_directory_tickets;
use teald::types::{set_daemon_mode, DaemonMode, InternalEvent};

use teal_common::{TEALD_ADMIN_SOCKET_PATH, TEAL_SOCKET_ROOT};
use teal_policy_engine::util::ktime_prefix;

/// 1) state の初期化
use teald::state::init_state;

/// 2) admin unix socket を初期化して listener を返す
async fn init_admin_socket(socket_path: &str) -> Result<UnixListener> {
    // ★ 保険: 親ディレクトリ (/run/teal) が存在しない場合は作成
    tokio::fs::create_dir_all(TEAL_SOCKET_ROOT)
        .await
        .context("create admin socket directory")?;

    if std::path::Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path).context("remove existing admin socket")?;
    }

    let listener = UnixListener::bind(socket_path).context("bind admin unix socket")?;

    #[cfg(unix)]
    {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
            .with_context(|| format!("chmod 0666 for {}", socket_path))?;
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
    inherited_kernel_mode: u32,
    startup_ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let (internal_tx, internal_rx) = mpsc::channel::<InternalEvent>(5000);
    let admin_tx = internal_tx.clone();

    // Worker tasks acknowledge entry into their event loops before READY.
    // Pending requests remain Guard-classified in the kernel until handshake ACK.
    let (audit_started_tx, audit_started_rx) = oneshot::channel();
    let (decision_started_tx, decision_started_rx) = oneshot::channel();
    let (admin_started_tx, admin_started_rx) = oneshot::channel();
    let (admin_release_tx, admin_release_rx) = oneshot::channel();

    // ① Audit Worker
    let nl_tx_audit = nl_tx.clone();
    let audit_handle = tokio::spawn(async move {
        let _ = audit_started_tx.send(());
        teald::worker::audit::audit_worker_loop(rx_audit, internal_rx, nl_tx_audit).await;
    });

    // ② Decision Worker
    let nl_tx_decision = nl_tx.clone();
    let decision_handle = tokio::spawn(async move {
        let _ = decision_started_tx.send(());
        teald::worker::decision::decision_worker_loop(rx_decision, internal_tx, nl_tx_decision)
            .await;
    });

    // ③ Admin Socket Worker (管理ソケット)
    let nl_tx_admin = nl_tx.clone();
    let admin_handle = tokio::spawn(async move {
        let _ = admin_started_tx.send(());
        // Do not accept management commands while the kernel is RECOVERING.
        if admin_release_rx.await.is_ok() {
            teald::worker::admin::admin_socket_loop(listener, admin_tx, nl_tx_admin).await;
        }
    });

    tokio::try_join!(audit_started_rx, decision_started_rx, admin_started_rx)
        .context("Worker startup failed before DAEMON_READY")?;

    let snapshot = policy_snapshot();
    let guard = compile_guard_manifest(&snapshot.bundle)
        .context("Failed to compile Guard before DAEMON_READY")?;
    if inherited_kernel_mode == 1 {
        set_daemon_mode(DaemonMode::Enforce);
    }
    // ACK + GUARD_STATUS verification is mandatory. No mode downgrade on error.
    if let Err(e) = nl_tx
        .daemon_ready_verified(snapshot.epoch, guard.sha256)
        .await
    {
        set_daemon_mode(DaemonMode::Drain);
        return Err(e).context("DAEMON_READY handshake failed; kernel remains RECOVERING");
    }
    eprintln!(
        "{}[INFO] DAEMON_READY confirmed: epoch={}, kernel_mode={}",
        ktime_prefix(), snapshot.epoch,
        if inherited_kernel_mode == 1 { "ENFORCE" } else { "AUDIT" }
    );
    // Management commands and startup preloading are released only after ACK.
    let _ = admin_release_tx.send(());
    let _ = startup_ready_tx.send(());
    if inherited_kernel_mode == 1 {
        let nl_tx_preload = nl_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = preload_silent_directory_tickets(&nl_tx_preload).await {
                eprintln!("{}[WARN] ENFORCE recovery ticket preload failed: {e}", ktime_prefix());
            }
        });
    }

    let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = terminate.recv() => {},
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

    // Until kernel mode and Guard are verified, discard audit traffic.
    // Kernel ENFORCE, if previously set, remains active throughout.
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
    let inherited_kernel_mode = kernel_runtime_mode()?;
    init_bundle_at_epoch(compiled, next_epoch)?;
    let b = bundle();
    load_from_management(&b.roles)?;

    // On an ENFORCE reconnect, do not replace the last committed Guard
    // with a different manifest as an implicit side effect of startup.
    // A different Guard must be handled by an explicitly authorized update.
    if inherited_kernel_mode == 1 {
        let before = nl_tx.guard_status().await
            .context("GUARD_STATUS before ENFORCE recovery")?;
        let manifest = compile_guard_manifest(&policy_snapshot().bundle)
            .context("compile policy Guard for ENFORCE recovery")?;
        anyhow::ensure!(
            before.guard_state == 1
                && before.guard_epoch == before.last_epoch
                && before.last_epoch.checked_add(1) == Some(next_epoch)
                && !before.staged
                && before.active_sha256 == Some(manifest.sha256),
            "ENFORCE recovery blocked: committed Guard and policy manifest differ \
             (kernel last={}, guard={}, new epoch={}, staged={}); refusing implicit policy change",
            before.last_epoch, before.guard_epoch, next_epoch, before.staged
        );
        eprintln!(
            "{}[INFO] ENFORCE recovery: old Guard verified, last_epoch={}, next_epoch={}",
            ktime_prefix(), before.last_epoch, next_epoch
        );
    }

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

    // Phase 4: AI/DENY notification transport.
    // Real DENY events are submitted by the audit worker.
    // AI smoke injection is enabled only by the Cargo feature
    // and TEAL_AI_SMOKE_TEST=1.
    let notification_runtime = match teald::notification::start(
        teald::notification::NotificationTransportConfig::default(),
    ) {
        Ok(runtime) => {
            if teald::notification::install_global(runtime.handle()).is_err() {
                eprintln!(
                    "{}[WARN] Notification transport already installed",
                    ktime_prefix()
                );
            } else {
                eprintln!(
                    "{}[INFO] Notification AI/DENY queues started",
                    ktime_prefix()
                );

                #[cfg(feature = "ai-notify-smoke")]
                if std::env::var("TEAL_AI_SMOKE_TEST").ok().as_deref() == Some("1") {
                    use teald::notification::ai_event::{submit, AiAttackEvent};

                    let related_ids = ["TEST-AUDIT-001", "TEST-AUDIT-002"];

                    let analysis_id = format!("PHASE4-SMOKE-{}", uuid::Uuid::new_v4());

                    let event = AiAttackEvent {
                        analysis_id: &analysis_id,
                        hostname: "",
                        confidence: 0.98,
                        reason: "Phase 4 smoke test: simulated high-confidence AI detection",
                        related_event_ids: &related_ids,
                        program: "/usr/bin/cat",
                        action: "READ",
                        target: "/var/tmp/teal-deny-integration-test.txt",
                    };

                    match submit(event, &[]) {
                        Ok(()) => {
                            eprintln!("{}[INFO] Phase 4 AI smoke event enqueued", ktime_prefix())
                        }
                        Err(e) => eprintln!(
                            "{}[ERROR] Phase 4 AI smoke enqueue failed: {:?}",
                            ktime_prefix(),
                            e
                        ),
                    }
                }
            }
            Some(runtime)
        }
        Err(error) => {
            eprintln!(
                "{}[WARN] Notification transport disabled: {}",
                ktime_prefix(),
                error
            );
            None
        }
    };

    // Install the global notification transport before AI workers can run.
    EvidenceManager::init(1024, ai_runtime);

    // ソケット配置ディレクトリの作成と権限設定
    if let Err(e) = std::fs::create_dir_all(TEAL_SOCKET_ROOT) {
        eprintln!(
            "{}[WARN] Failed to create {} directory: {}",
            ktime_prefix(),
            TEAL_SOCKET_ROOT,
            e
        );
    } else {
        #[cfg(unix)]
        let _ = std::fs::set_permissions(TEAL_SOCKET_ROOT, std::fs::Permissions::from_mode(0o755));
    }

    let listener = init_admin_socket(TEALD_ADMIN_SOCKET_PATH).await?;

    // PAMリスナーをバックグラウンドタスクとして起動
    tokio::spawn(async {
        start_pam_listener().await;
    });

    // The startup monitor/preloader is dormant until the kernel confirms READY.
    let (startup_ready_tx, startup_ready_rx) = oneshot::channel::<()>();
    if inherited_kernel_mode == 1 {
        eprintln!(
            "{}[INFO] ENFORCE recovery: waiting for worker startup and DAEMON_READY, epoch={}",
            ktime_prefix(), next_epoch
        );
    } else {
        let nl_tx_monitor = nl_tx.clone();

        // ==============================================================
        // ログストーム収束監視タスク (Drain -> Audit for AUDIT-only boot)
        // ==============================================================
        tokio::spawn(async move {
            // No initial audit preload until handshake has completed.
            if startup_ready_rx.await.is_err() {
                return;
            }
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
    }

    // メインワーカー起動へ
    let worker_result = run_workers(
        nl_tx, rx_decision, rx_audit, listener,
        inherited_kernel_mode, startup_ready_tx,
    ).await;

    // 通知システムの終了処理
    if let Some(runtime) = notification_runtime {
        if let Err(e) = runtime.shutdown().await {
            eprintln!("[TEAL][notify][ERROR] graceful notification save failed: {e}");
        }
    }

    // 監査ログの終了処理
    if let Err(e) = EvidenceManager::shutdown_global().await {
        eprintln!("[TEAL][audit][ERROR] graceful shutdown failed: {e}");
    }

    worker_result
}
