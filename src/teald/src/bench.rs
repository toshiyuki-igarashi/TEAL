// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use std::env;
use std::fs::File;
use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone)]
enum TestKind {
    Exec { cmd: String, cmd_args: Vec<String> },
    Open { path: String },
}

#[derive(Debug, Clone)]
struct Config {
    kind: TestKind,
    loops: u64,   // operations per run
    repeat: u32,  // number of runs (samples)
    warmup: bool, // run once without recording
    raw: bool,    // print raw samples
}

#[derive(Debug, Clone, Copy)]
struct Stats {
    median: u64,
    p95: u64,
    p99: u64,
    min: u64,
    max: u64,
}

fn usage_and_exit(msg: Option<&str>) -> ! {
    if let Some(m) = msg {
        eprintln!("Error: {m}\n");
    }
    eprintln!(
        "Usage:
  tealbench exec --loops N [--repeat R] [--no-warmup] [--raw] -- <cmd> [args...]
  tealbench open --loops N [--repeat R] [--no-warmup] [--raw] --path <file>

Examples:
  tealbench exec --loops 1000 --repeat 10 -- /bin/true
  tealbench exec --loops 1000 -- /bin/echo hello
  tealbench open --loops 200000 --repeat 10 --path /tmp/bench/file
"
    );
    std::process::exit(2);
}

fn parse_u64(s: &str, name: &str) -> u64 {
    s.parse::<u64>()
        .unwrap_or_else(|_| usage_and_exit(Some(&format!("invalid {name}: {s}"))))
}

fn parse_u32(s: &str, name: &str) -> u32 {
    s.parse::<u32>()
        .unwrap_or_else(|_| usage_and_exit(Some(&format!("invalid {name}: {s}"))))
}

fn parse_args() -> Config {
    let mut it = env::args().skip(1);

    let sub = it.next().unwrap_or_else(|| usage_and_exit(None));

    let mut loops: Option<u64> = None;
    let mut repeat: u32 = 10;
    let mut warmup: bool = true;
    let mut raw: bool = false;

    // For "open"
    let mut path: Option<String> = None;

    // For "exec"
    let mut cmd: Option<String> = None;
    let mut cmd_args: Vec<String> = Vec::new();

    // Simple manual option parser (no external crates)
    // Rules:
    // - exec: requires `--` separator, everything after `--` is command+args
    // - open: requires `--path <file>`
    let mut after_double_dash: bool = false;

    while let Some(a) = it.next() {
        if after_double_dash {
            if cmd.is_none() {
                cmd = Some(a);
            } else {
                cmd_args.push(a);
            }
            continue;
        }

        match a.as_str() {
            "--loops" => {
                let v = it.next().unwrap_or_else(|| usage_and_exit(Some("missing value for --loops")));
                loops = Some(parse_u64(&v, "loops"));
            }
            "--repeat" => {
                let v =
                    it.next().unwrap_or_else(|| usage_and_exit(Some("missing value for --repeat")));
                repeat = parse_u32(&v, "repeat");
                if repeat == 0 {
                    usage_and_exit(Some("--repeat must be >= 1"));
                }
            }
            "--no-warmup" => warmup = false,
            "--raw" => raw = true,
            "--path" => {
                let v = it.next().unwrap_or_else(|| usage_and_exit(Some("missing value for --path")));
                path = Some(v);
            }
            "--" => after_double_dash = true,
            _ => usage_and_exit(Some(&format!("unknown option: {a}"))),
        }
    }

    let loops = loops.unwrap_or_else(|| usage_and_exit(Some("--loops is required")));
    if loops == 0 {
        usage_and_exit(Some("--loops must be >= 1"));
    }

    let kind = match sub.as_str() {
        "exec" => {
            let cmd = cmd.unwrap_or_else(|| usage_and_exit(Some("exec requires `-- <cmd> [args...]`")));
            TestKind::Exec { cmd, cmd_args }
        }
        "open" => {
            let path = path.unwrap_or_else(|| usage_and_exit(Some("open requires --path <file>")));
            TestKind::Open { path }
        }
        _ => usage_and_exit(Some("subcommand must be one of: exec, open")),
    };

    Config {
        kind,
        loops,
        repeat,
        warmup,
        raw,
    }
}

fn bench_exec(cmd: &str, cmd_args: &[String], loops: u64) -> std::io::Result<u64> {
    let start = Instant::now();
    for _ in 0..loops {
        let status = Command::new(cmd).args(cmd_args).status()?;
        // Prevent compiler from optimizing too aggressively.
        black_box(status.success());
    }
    Ok(start.elapsed().as_nanos() as u64)
}

fn bench_open(path: &str, loops: u64) -> std::io::Result<u64> {
    let start = Instant::now();
    for _ in 0..loops {
        let f = File::open(path)?;
        // Keep something observable.
        black_box(f);
        // drop(f) closes
    }
    Ok(start.elapsed().as_nanos() as u64)
}

fn compute_stats(mut xs: Vec<u64>) -> Stats {
    xs.sort_unstable();
    let n = xs.len();
    let min = xs[0];
    let max = xs[n - 1];

    // median
    let median = if n % 2 == 1 {
        xs[n / 2]
    } else {
        let a = xs[(n / 2) - 1];
        let b = xs[n / 2];
        (a / 2) + (b / 2) + ((a & 1) & (b & 1)) // exact average without overflow
    };

    // percentile helper: nearest-rank (ceil(p*n)) with p in [0,1]
    let pct = |p: f64| -> u64 {
        let mut idx = (p * n as f64).ceil() as isize - 1;
        if idx < 0 {
            idx = 0;
        }
        if idx as usize >= n {
            idx = (n - 1) as isize;
        }
        xs[idx as usize]
    };

    let p95 = pct(0.95);
    let p99 = pct(0.99);

    Stats {
        median,
        p95,
        p99,
        min,
        max,
    }
}

fn main() {
    let cfg = parse_args();

    // Optional warmup (not recorded)
    if cfg.warmup {
        let _ = match &cfg.kind {
            TestKind::Exec { cmd, cmd_args } => bench_exec(cmd, cmd_args, cfg.loops),
            TestKind::Open { path } => bench_open(path, cfg.loops),
        };
    }

    let mut per_ops: Vec<u64> = Vec::with_capacity(cfg.repeat as usize);

    for run in 1..=cfg.repeat {
        let total_ns_res = match &cfg.kind {
            TestKind::Exec { cmd, cmd_args } => bench_exec(cmd, cmd_args, cfg.loops),
            TestKind::Open { path } => bench_open(path, cfg.loops),
        };

        let total_ns = match total_ns_res {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: test failed on run {run}: {e}");
                std::process::exit(1);
            }
        };

        let per_op_ns = total_ns / cfg.loops;
        if cfg.raw {
            // raw line: easy for awk/grep
            match &cfg.kind {
                TestKind::Exec { .. } => {
                    println!(
                        "raw kind=exec run={} loops={} total_ns={} per_op_ns={}",
                        run, cfg.loops, total_ns, per_op_ns
                    );
                }
                TestKind::Open { .. } => {
                    println!(
                        "raw kind=open run={} loops={} total_ns={} per_op_ns={}",
                        run, cfg.loops, total_ns, per_op_ns
                    );
                }
            }
        }

        per_ops.push(per_op_ns);
    }

    let st = compute_stats(per_ops);

    // summary line (stable format)
    match &cfg.kind {
        TestKind::Exec { cmd, cmd_args } => {
            // Render command for metadata
            let mut full = String::new();
            full.push_str(cmd);
            for a in cmd_args {
                full.push(' ');
                full.push_str(a);
            }
            println!(
                "kind=exec loops={} repeat={} metric=per_op_ns median={} p95={} p99={} min={} max={} cmd=\"{}\"",
                cfg.loops, cfg.repeat, st.median, st.p95, st.p99, st.min, st.max, full
            );
        }
        TestKind::Open { path } => {
            println!(
                "kind=open loops={} repeat={} metric=per_op_ns median={} p95={} p99={} min={} max={} path=\"{}\"",
                cfg.loops, cfg.repeat, st.median, st.p95, st.p99, st.min, st.max, path
            );
        }
    }
}

