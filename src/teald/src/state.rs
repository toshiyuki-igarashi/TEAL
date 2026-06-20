// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use tokio::sync::Mutex; 
use std::sync::{Arc, OnceLock}; // ArcとOnceLockはstdでOK
use std::collections::HashMap;
use crate::types::{AppState, FastState, SlowState, TealDeviceState}; // types.rsを参照

static APP_STATE: OnceLock<Arc<Mutex<AppState>>> = OnceLock::new();

pub fn set_app_state(state: Arc<Mutex<AppState>>) {
    APP_STATE.set(state).expect("APP_STATE already initialized");
}

pub fn app_state() -> &'static Arc<Mutex<AppState>> {
    APP_STATE.get().expect("APP_STATE not initialized")
}

/// state の初期化
pub async fn init_state() {
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
                dev_teal_path: String::from("netlink:teal_ctrl"),
                device_file: None, 
            },
            is_enforce: false,
            current_epoch: 0,
        }))
    )
}
