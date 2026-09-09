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

use teald::common::NetlinkStatus;

use crate::send_command;

/// ログストーム収束待機時のポーリング間隔（秒）
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// 収束判定のしきい値（バッファ使用率 10% 未満）
const SETTLED_BUFFER_THRESHOLD_PCT: f64 = 10.0;

pub fn run(wait_settle: bool, timeout_sec: u64, json_mode: bool) -> Result<()> {
    if !wait_settle {
        // 単発取得モード: 従来通り STATUS で全情報を取得
        let resp = send_command("STATUS", false)?;
        print_status(&resp, json_mode);
        return Ok(());
    }

    // ログストーム収束待機モード (--wait-settle)
    println!("{}", "⏳ Waiting for TEAL Netlink buffer to settle...".cyan());
    let start_time = Instant::now();
    let timeout = Duration::from_secs(timeout_sec);

    loop {
        if start_time.elapsed() > timeout {
            anyhow::bail!("Timeout ({}s) exceeded: Netlink buffer did not settle.", timeout_sec);
        }

        // ★ ロックを奪い合わないよう NETLINK_STATUS を送る
        match send_command("NETLINK_STATUS", false) {
            Ok(resp) => {
                if let Ok(nl_stat) = serde_json::from_str::<NetlinkStatus>(&resp) {
                    println!(
                        "  [Check] Buffer usage: {:.1}%, Drops: {}",
                        nl_stat.buffer_usage_pct, nl_stat.drops
                    );

                    // バッファ使用率が安全圏に落ちたら収束と判断
                    if nl_stat.buffer_usage_pct < SETTLED_BUFFER_THRESHOLD_PCT {
                        println!("{}", "✔ System settled successfully.".green().bold());
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to teald: {}. Retrying...", e);
            }
        }

        sleep(POLL_INTERVAL);
    }

    // 収束後、最後に完全なステータスを取得して表示
    let final_resp = send_command("STATUS", false)?;
    print_status(&final_resp, json_mode);

    Ok(())
}

fn print_status(resp: &str, _json_mode: bool) {
    println!("{}", resp);
}
