// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * 
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::Result;
use colored::Colorize;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::send_command;

/// ログストーム収束待機時のポーリング間隔（秒）
const POLL_INTERVAL: Duration = Duration::from_secs(10);

pub fn run(wait_settle: bool, timeout_sec: u64, json_mode: bool) -> Result<()> {
    if !wait_settle {
        let resp = send_command("STATUS", false)?;
        print_status(&resp, json_mode);
        return Ok(());
    }

    // ログストーム収束待機モード (--wait-settle)
    println!("{}", "⏳ Waiting for TEAL queues and buffers to settle...".cyan());
    let start_time = Instant::now();
    let timeout = Duration::from_secs(timeout_sec);

    loop {
        if start_time.elapsed() > timeout {
            anyhow::bail!("Timeout ({}s) exceeded: log storm did not settle.", timeout_sec);
        }

        // 共通関数経由で STATUS を問い合わせ
        match send_command("STATUS", false) {
            Ok(resp) => {
                let is_settled = check_settled(&resp);
                if is_settled {
                    println!("{}", "✔ System settled successfully.".green().bold());
                    print_status(&resp, json_mode);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to teald: {}. Retrying...", e);
            }
        }

        sleep(POLL_INTERVAL);
    }

    Ok(())
}

fn check_settled(resp: &str) -> bool {
    // teald のレスポンス解析（後ほど実装）
    !resp.contains("\"is_storming\":true")
}

fn print_status(resp: &str, _json_mode: bool) {
    println!("{}", resp);
}
