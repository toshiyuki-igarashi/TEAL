// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

//! TEAL Phase 2 step 1: non-blocking notification queues and IPC senders.
//!
//! Confirmed DENY events are aggregated in fixed five-minute windows before
//! enqueue. Recipient-role resolution and persistence are separate steps.

pub mod admin_mutation;
pub mod aggregation;
pub mod ai_event;
pub mod config;
pub mod deny_event;
pub mod ipc_client;
pub mod queue;
pub mod recovery;
mod shutdown_save;

use std::sync::{Arc, Mutex, OnceLock, Weak};
use tokio::{sync::mpsc, task::JoinHandle};

pub use ai_event::{AiAttackEvent, AiSubmitError};
pub use config::NotificationTransportConfig;
pub use queue::{EnqueueError, NotificationHandle, NotificationKind, NotificationStats};

use queue::NotificationCounters;

/// Global read-only entry point for future event handlers.
/// Registration is once per teald process, after policy initialization.
static GLOBAL_NOTIFIER: OnceLock<NotificationHandle> = OnceLock::new();

// Admin requests must use the *same* store as the active runtime, including
// deployments with a nondefault recovery_path. A Weak reference avoids keeping
// a stale store alive after the runtime is dropped. Never open a second store
// from an admin connection.
static ADMIN_RECOVERY_STORE: OnceLock<Mutex<Weak<recovery::RecoveryStore>>> = OnceLock::new();
static ADMIN_RETRY_CONFIG: OnceLock<Mutex<Option<NotificationTransportConfig>>> = OnceLock::new();

pub(crate) fn admin_retry_config() -> Option<NotificationTransportConfig> {
    admin_recovery_store()?;
    ADMIN_RETRY_CONFIG.get()?.lock().ok()?.clone()
}

pub(crate) fn admin_recovery_store() -> Option<Arc<recovery::RecoveryStore>> {
    let guard = ADMIN_RECOVERY_STORE.get()?.lock().ok()?;
    guard.upgrade()
}

fn publish_admin_recovery_store(
    store: &Arc<recovery::RecoveryStore>,
    config: &NotificationTransportConfig,
) {
    let lock = ADMIN_RECOVERY_STORE.get_or_init(|| Mutex::new(Weak::new()));
    let mut guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Arc::downgrade(store);
    let config_lock = ADMIN_RETRY_CONFIG.get_or_init(|| Mutex::new(None));
    *config_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(config.clone());
}

pub fn global_handle() -> Option<&'static NotificationHandle> {
    GLOBAL_NOTIFIER.get()
}

pub fn install_global(handle: NotificationHandle) -> Result<(), NotificationHandle> {
    GLOBAL_NOTIFIER.set(handle)
}

/// Owns AI/DENY independent senders, the emergency writer and the shared
/// shutdown protocol. The handle clones remain usable by audit producers,
/// but become immediately non-accepting when graceful shutdown begins.
#[derive(Debug)]
pub struct NotificationRuntime {
    handle: NotificationHandle,
    ai_worker: JoinHandle<Vec<recovery::PendingNotification>>,
    deny_worker: JoinHandle<Vec<recovery::PendingNotification>>,
    emergency_worker: JoinHandle<()>,
    sender_shutdown: tokio::sync::watch::Sender<bool>,
    emergency_shutdown: tokio::sync::watch::Sender<bool>,
    storage: Arc<recovery::RecoveryStore>,
    config: NotificationTransportConfig,
}

impl NotificationRuntime {
    pub fn handle(&self) -> NotificationHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> std::io::Result<()> {
        use tokio::time::timeout;
        self.handle.stop_accepting();
        let grace = self.config.shutdown_grace;
        let NotificationRuntime {
            ai_worker,
            deny_worker,
            mut emergency_worker,
            sender_shutdown,
            emergency_shutdown,
            storage,
            config,
            ..
        } = self;
        // Finish or spool all emergency requests before freezing the AI sender.
        let _ = emergency_shutdown.send(true);
        match timeout(grace, &mut emergency_worker).await {
            Ok(Ok(())) => {}
            other => {
                eprintln!("[TEAL][notify][ERROR] emergency shutdown incomplete: {other:?}");
                emergency_worker.abort();
            }
        }
        let _ = sender_shutdown.send(true);
        let ai_jobs = join_sender(ai_worker, grace, "AI").await?;
        let mut pending = ai_jobs;
        pending.extend(join_sender(deny_worker, grace, "DENY").await?);
        // Aggregate in-flight 5-minute DENY windows into a recoverable summary.
        // The partial window will be delivered once after restart.
        pending.extend(
            deny_event::drain_aggregation_on_shutdown()
                .into_iter()
                .map(recovery::PendingNotification::fresh),
        );
        // One shared 15-second deadline across ALL save attempts and delays.
        // The configured max attempts (3 by default) is an independent cap.
        let result = shutdown_save::persist_with_retry(&config, || {
            let store = Arc::clone(&storage);
            let jobs = pending.clone();
            async move { store.save_pending_async(jobs).await }
        })
        .await;
        match result {
            Ok(()) => {
                eprintln!(
                    "[TEAL][notify] shutdown snapshot saved: pending={}",
                    pending.len()
                );
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "[TEAL][notify][ERROR] shutdown snapshot SAVE_FAILED: pending={} error={error}",
                    pending.len()
                );
                Err(error)
            }
        }
    }
}

async fn join_sender(
    mut task: JoinHandle<Vec<recovery::PendingNotification>>,
    limit: std::time::Duration,
    name: &str,
) -> std::io::Result<Vec<recovery::PendingNotification>> {
    match tokio::time::timeout(limit, &mut task).await {
        Ok(Ok(jobs)) => Ok(jobs),
        other => {
            task.abort();
            eprintln!("[TEAL][notify][ERROR] {name} sender shutdown incomplete: {other:?}");
            Err(std::io::Error::other(
                "notification sender shutdown incomplete",
            ))
        }
    }
}

async fn run_emergency_writer(
    mut rx: mpsc::Receiver<teal_notify_protocol::NotificationRequest>,
    ai_tx: mpsc::Sender<teal_notify_protocol::NotificationRequest>,
    store: Arc<recovery::RecoveryStore>,
    counters: Arc<NotificationCounters>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::sync::atomic::Ordering;
    loop {
        let req = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                // The emergency channel has a fixed capacity (64 by default).
                // Flush all queued requests to disk without blocking producers.
                while let Ok(req) = rx.try_recv() {
                    if let Err(e) = store.spool_ai_async(recovery::PendingNotification::fresh(req)).await {
                        counters.ai_spool_failed.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[TEAL][notify][AI][ERROR] emergency shutdown spool failed: {e}");
                    }
                }
                break;
            }
            message = rx.recv() => match message { Some(req) => req, None => break },
        };
        let id = req.notification_id.clone();
        if let Err(e) = store
            .spool_ai_async(recovery::PendingNotification::fresh(req.clone()))
            .await
        {
            counters.ai_spool_failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("[TEAL][notify][AI][ERROR] emergency spool failed: id={id:?} error={e}");
            continue;
        }
        // Requeue in-process as soon as capacity is available. On shutdown the
        // saved emergency record stays for next-start recovery.
        let placed = tokio::select! {
            biased;
            _ = shutdown.changed() => false,
            result = ai_tx.send(req) => result.is_ok(),
        };
        if placed {
            if let Err(e) = store.clear_spooled_async(id.clone()).await {
                eprintln!(
                    "[TEAL][notify][AI][WARN] emergency cleanup uncertain: id={id:?} error={e}"
                );
            }
        }
    }
}

pub fn start(config: NotificationTransportConfig) -> Result<NotificationRuntime, &'static str> {
    config.validate()?;
    let _ = deny_event::cached_hostname();
    let storage = recovery::RecoveryStore::open(&config).map_err(|err| {
        eprintln!("[TEAL][notify][ERROR] recovery initialization failed: {err}");
        "notification recovery initialization failed"
    })?;
    let restored = storage.restore_pending().map_err(|err| {
        eprintln!("[TEAL][notify][ERROR] recovery restoration failed: {err}");
        "notification recovery restoration failed"
    })?;
    let (ai_tx, ai_rx) = mpsc::channel(config.ai_queue_capacity);
    let (deny_tx, deny_rx) = mpsc::channel(config.deny_queue_capacity);
    let (emergency_tx, emergency_rx) = mpsc::channel(config.ai_emergency_spool_capacity);
    let counters = Arc::new(NotificationCounters::default());
    let handle = NotificationHandle::new(ai_tx.clone(), deny_tx, counters.clone())
        .with_emergency(emergency_tx);
    let (sender_shutdown, sender_stop_rx) = tokio::sync::watch::channel(false);
    let (emergency_shutdown, emergency_stop_rx) = tokio::sync::watch::channel(false);

    let (ai_saved, deny_saved): (Vec<_>, Vec<_>) = restored.into_iter().partition(|job| {
        queue::NotificationKind::from_request(&job.request) == NotificationKind::Ai
    });
    let ai_worker = tokio::spawn(ipc_client::run_sender_managed(
        NotificationKind::Ai,
        ai_rx,
        config.clone(),
        counters.clone(),
        Some(Arc::clone(&storage)),
        Some(sender_stop_rx.clone()),
        ai_saved,
    ));
    let deny_worker = tokio::spawn(ipc_client::run_sender_managed(
        NotificationKind::Deny,
        deny_rx,
        config.clone(),
        counters.clone(),
        Some(Arc::clone(&storage)),
        Some(sender_stop_rx),
        deny_saved,
    ));
    let emergency_worker = tokio::spawn(run_emergency_writer(
        emergency_rx,
        ai_tx,
        Arc::clone(&storage),
        counters,
        emergency_stop_rx,
    ));
    publish_admin_recovery_store(&storage, &config);
    Ok(NotificationRuntime {
        handle,
        ai_worker,
        deny_worker,
        emergency_worker,
        sender_shutdown,
        emergency_shutdown,
        storage,
        config,
    })
}
