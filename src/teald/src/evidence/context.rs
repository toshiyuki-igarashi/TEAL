// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::fs;

pub struct ContextResolver;

impl ContextResolver {
    /// PIDから環境コンテキストを生成する
    pub fn resolve(pid: u32) -> super::schema::EnvironmentContext {
        let tty = Self::resolve_tty(pid).unwrap_or_else(|| "none".to_string());
        let ssh_client = Self::resolve_ssh_client(pid); // Ancestry Walk実装

        super::schema::EnvironmentContext {
            tty,
            ssh_client,
            login_method: "unknown".to_string(), // 今回は簡易実装
        }
    }

    /// /proc/<pid>/fd/0 のリンク先を確認
    fn resolve_tty(pid: u32) -> Option<String> {
        let path = format!("/proc/{}/fd/0", pid);
        fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// プロセスツリーを遡って SSH_CLIENT を探す (Ancestry Walk)
    fn resolve_ssh_client(start_pid: u32) -> Option<String> {
        let mut current_pid = start_pid;

        // 最大10階層まで親を辿る
        for _ in 0..10 {
            if current_pid == 0 || current_pid == 1 {
                break;
            }
            if let Some(client) = Self::read_env_var(current_pid, "SSH_CLIENT") {
                return Some(client);
            }
            // 親PIDを取得してツリーを遡る
            match Self::get_ppid(current_pid) {
                Some(ppid) if ppid != current_pid => current_pid = ppid,
                _ => break,
            }
        }
        None
    }

    /// /proc/<pid>/stat から親プロセスID (PPID) を取得
    fn get_ppid(pid: u32) -> Option<u32> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        // stat のフォーマット: pid (comm) state ppid ...
        // コマンド名 (comm) に空白や括弧が含まれる可能性があるため、最後の ')' の後ろからパース
        let rparen = stat.rfind(')')?;
        let rest = stat.get(rparen + 1..)?;
        let mut fields = rest.split_whitespace();
        // fields: [state (0番目), ppid (1番目), ...]
        fields.nth(1)?.parse::<u32>().ok()
    }

    fn read_env_var(pid: u32, key: &str) -> Option<String> {
        let path = format!("/proc/{}/environ", pid);
        let content = fs::read(path).ok()?;

        // environは null区切り
        for chunk in content.split(|&b| b == 0) {
            let s = String::from_utf8_lossy(chunk);
            if s.starts_with(key) {
                // "SSH_CLIENT=1.2.3.4 5555 22" -> "1.2.3.4"
                return s.split('=').nth(1).map(|v| v.to_string());
            }
        }
        None
    }
}
