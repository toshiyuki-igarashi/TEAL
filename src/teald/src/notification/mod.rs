// SPDX-License-Identifier: MIT
//! TEAL Phase 2 step 1: non-blocking notification queues and IPC senders.
//!
//! Confirmed DENY events are aggregated in fixed five-minute windows before
//! enqueue. Recipient-role resolution and persistence are separate steps.

pub mod aggregation;
pub mod config;
pub mod deny_event;
pub mod ipc_client;
pub mod queue;

use std::sync::{Arc, OnceLock};
use tokio::{sync::mpsc, task::JoinHandle};

pub use config::NotificationTransportConfig;
pub use queue::{EnqueueError, NotificationHandle, NotificationKind, NotificationStats};

use queue::NotificationCounters;

/// Global read-only entry point for future event handlers.
/// Registration is once per teald process, after policy initialization.
static GLOBAL_NOTIFIER: OnceLock<NotificationHandle> = OnceLock::new();

pub fn global_handle() -> Option<&'static NotificationHandle> {
    GLOBAL_NOTIFIER.get()
}

pub fn install_global(handle: NotificationHandle) -> Result<(), NotificationHandle> {
    GLOBAL_NOTIFIER.set(handle)
}

/// Holds the sender tasks and a clonable handle used by event producers.
/// Dropping JoinHandles detaches workers; this step does not implement a
/// crash-safe or graceful-drain lifecycle.
#[derive(Debug)]
pub struct NotificationRuntime {
    handle: NotificationHandle,
    _ai_worker: JoinHandle<()>,
    _deny_worker: JoinHandle<()>,
}

impl NotificationRuntime {
    pub fn handle(&self) -> NotificationHandle {
        self.handle.clone()
    }
}

pub fn start(config: NotificationTransportConfig) -> Result<NotificationRuntime, &'static str> {
    config.validate()?;
    // Cache once outside the audit worker to avoid per-event filesystem I/O.
    let _ = deny_event::cached_hostname();
    let (ai_tx, ai_rx) = mpsc::channel(config.ai_queue_capacity);
    let (deny_tx, deny_rx) = mpsc::channel(config.deny_queue_capacity);
    let counters = Arc::new(NotificationCounters::default());
    let handle = NotificationHandle::new(ai_tx, deny_tx, counters.clone());

    let ai_worker = tokio::spawn(ipc_client::run_sender(
        NotificationKind::Ai,
        ai_rx,
        config.clone(),
        counters.clone(),
    ));
    let deny_worker = tokio::spawn(ipc_client::run_sender(
        NotificationKind::Deny,
        deny_rx,
        config,
        counters,
    ));

    Ok(NotificationRuntime {
        handle,
        _ai_worker: ai_worker,
        _deny_worker: deny_worker,
    })
}
