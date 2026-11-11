// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use blst::min_pk::SecretKey;
use clap::{Parser, Subcommand};
use colored::Colorize;
use uuid::Uuid;

// Policy Engine からのインポート
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::raw::RawPolicyV14;

// teald クレートから共通型をインポート
use teal_common::TEALD_ADMIN_SOCKET_PATH;
use teald::common::{is_mgmt_id, DecisionKind};

// teal-cli 内部に移した verify モジュール
mod verify;
use verify::ast::TealIrModel;

mod cmd;

// ==========================================
// 1. CLI引数の構造体定義 (clap)
// ==========================================

/// TEAL Command Line Interface
#[derive(Parser, Debug)]
#[command(name = "teal-cli", version, about = "TEAL System Management CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate BLS keypair
    Keygen,
    /// Register public key to teald
    Register,
    /// Show pending requests
    List,
    /// Manage undelivered AI and DENY notifications
    Notify {
        #[command(subcommand)]
        command: NotifyCommands,
    },
    /// Approve with digital signature
    Approve {
        /// Request ID to approve
        id: String,

        /// Audit ID for management commands
        audit_id: Option<String>,
    },
    /// Reject request
    Deny {
        /// Request ID to deny
        id: String,

        /// Audit ID for management commands
        audit_id: Option<String>,
    },
    /// Request ticket request
    Ticket {
        /// Rule ID
        rule_id: String,
    },
    /// Start Enforce mode
    Start,
    /// Stop Enforce mode and start Audit mode
    Stop,
    /// Show policy differences and security impact
    Diff {
        #[arg(long)]
        html: Option<std::path::PathBuf>,
    },
    /// Initialize staging directory by copying current policies
    StageInit {
        /// Force overwrite even if the staging directory already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Update policies and increment Epoch
    PolicyUpdate,
    /// Flush caches (Global Kill Switch)
    Flush,
    /// Activate Break-Glass Mode
    Emergency {
        /// Emergency token
        token: String,
    },
    /// Show TEAL daemon status and queue health
    Status {
        /// Wait until log storm and queues settle before exiting
        #[arg(long)]
        wait_settle: bool,

        /// Timeout in seconds when waiting for settle (default: 120)
        #[arg(long, default_value_t = 120)]
        timeout: u64,

        /// Output status in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Verify policy rules
    Verify {
        /// Policy JSON file path
        policy_file: String,

        /// Goal YAML file path
        #[arg(long)]
        goal: Option<String>,

        /// Enable visualization output
        #[arg(long)]
        visualize: bool,

        /// Enable debug output
        #[arg(long)]
        debug: bool,
    },
}

/// Undelivered notification management.
#[derive(Subcommand, Debug)]
enum NotifyCommands {
    /// List undelivered notifications (newest first)
    List {
        /// Number of records to skip (default: 0)
        #[arg(long, default_value_t = 0)]
        offset: usize,

        /// Number of records per page (1..=100, default: 50)
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// Output the complete server response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show one undelivered notification by its original notification ID
    Show {
        notification_id: String,

        /// Output the complete server response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Explicitly retry an undelivered notification (may duplicate an earlier delivery)
    Retry {
        notification_id: String,
        /// Acknowledge the possibility of duplicate SMTP delivery
        #[arg(long)]
        yes: bool,
        /// Print the full JSON response
        #[arg(long)]
        json: bool,
    },
    /// Archive an undelivered notification as administratively resolved
    Resolve {
        notification_id: String,
        /// Confirm this state-changing administrative action
        #[arg(long)]
        yes: bool,
        /// Print the full JSON response
        #[arg(long)]
        json: bool,
    },
}

// ==========================================
// 2. メインロジック
// ==========================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen => {
            cmd::keygen::run()?;
        }
        Commands::Register => {
            let dir = cmd::keygen::teal_key_dir()?;
            let pub_path = dir.join("id_bls.pub");

            if !pub_path.exists() {
                anyhow::bail!(
                    "Error: Public key '{}' not found. Run `teal-cli keygen` first.",
                    pub_path.display()
                );
            }

            let hex_key = fs::read_to_string(&pub_path)
                .with_context(|| format!("read public key {}", pub_path.display()))?;

            send_command(&format!("REGISTER {}", hex_key.trim()), true)?;
        }
        Commands::List => {
            send_command("LIST", true)?;
        }
        Commands::Notify { command } => match command {
            NotifyCommands::List {
                offset,
                limit,
                json,
            } => cmd::notify::list(*offset, *limit, *json)?,
            NotifyCommands::Show {
                notification_id,
                json,
            } => cmd::notify::show(notification_id, *json)?,
            NotifyCommands::Retry {
                notification_id,
                yes,
                json,
            } => cmd::notify::retry(notification_id, *yes, *json)?,
            NotifyCommands::Resolve {
                notification_id,
                yes,
                json,
            } => cmd::notify::resolve(notification_id, *yes, *json)?,
        },
        Commands::Approve { id, audit_id } => {
            run_signed_decision(DecisionKind::Approve, id, audit_id.as_deref())?;
        }

        Commands::Deny { id, audit_id } => {
            run_signed_decision(DecisionKind::Deny, id, audit_id.as_deref())?;
        }
        Commands::Ticket { rule_id } => {
            run_signed_decision(DecisionKind::Ticket, rule_id, None)?;
        }
        Commands::Start => {
            run_signed_decision(DecisionKind::Start, "", None)?;
        }
        Commands::Stop => {
            run_signed_decision(DecisionKind::Stop, "", None)?;
        }
        Commands::Diff { html } => {
            cmd::diff::run(html.clone())?;
        }
        Commands::StageInit { force } => {
            cmd::stage_init::run(*force)?;
        }
        Commands::PolicyUpdate => {
            cmd::update::run()?;
        }
        Commands::Flush => {
            send_command("FLUSH", true)?;
        }
        Commands::Emergency { token } => {
            send_command(&format!("EMERGENCY {}", token), true)?;
        }
        Commands::Status {
            wait_settle,
            timeout,
            json,
        } => {
            cmd::status::run(*wait_settle, *timeout, *json)?;
        }
        Commands::Verify {
            policy_file,
            goal,
            visualize,
            debug,
        } => {
            run_verify(policy_file, goal.as_deref(), *visualize, *debug)?;
        }
    }
    Ok(())
}

/// ポリシーの形式検証（Alloy連携）を実行する
fn run_verify(policy_file: &str, goal: Option<&str>, visualize: bool, debug: bool) -> Result<()> {
    let path = Path::new(policy_file);

    // 拡張子を除いたファイル名を抽出（ポリシーの識別名として利用）
    let policy_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("default_policy")
        .to_string();

    // ゴール定義（YAML）の読み込みとパース
    let mut goals: Vec<verify::VerifyGoal> = Vec::new();
    if let Some(goal_path) = goal {
        let yaml_str = std::fs::read_to_string(goal_path)
            .with_context(|| format!("Failed to read goal yaml file: {}", goal_path))?;
        goals = serde_yaml::from_str(&yaml_str)
            .with_context(|| format!("Failed to deserialize goal yaml: {}", goal_path))?;
        println!(
            "=> ゴール定義ファイル '{}' を読み込みました ({} 個のゴール)",
            goal_path,
            goals.len()
        );
    } else {
        println!("=> ゴール定義(--goal)が指定されていません。ポリシーの論理矛盾チェックのみを実行します。");
    }

    // ポリシー本体（JSON）の読み込みとパース
    let v = load_json_file(path)
        .with_context(|| format!("Failed to load policy json: {}", policy_file))?;
    let policy: RawPolicyV14 = serde_json::from_value(v)
        .with_context(|| format!("Failed to deserialize policy raw struct: {}", policy_file))?;

    // Alloy用の中間論理モデル (TEAL-IR) の構築
    println!("{} 中間論理モデル(Teal-IR)を構築中...", "-> [1/3]".cyan());
    let model = TealIrModel::from_raw(&policy, &goals, &policy_name)?;

    // Executorの初期化と実行
    let jar_path = env::var("TEAL_ALLOY_JAR").unwrap_or_else(|_| "alloy-cli.jar".to_string());
    println!("{} Alloyトランスパイラを初期化中...", "-> [2/3]".cyan());
    let mut executor = verify::VerifyExecutor::new(&jar_path);

    executor.execute(&model, visualize, debug)?;

    Ok(())
}

// 署名と検証で共通のドメイン分離タグ (DST)
const TEAL_DST: &[u8] = b"TEAL_SYSTEM_V1_MPA_SIG";

// 署名付きの決定コマンドを送る共通関数（user なし）
fn run_signed_decision(kind: DecisionKind, id: &str, audit_id: Option<&str>) -> Result<()> {
    let key_path = cmd::keygen::teal_private_key_path()?;

    if !key_path.exists() {
        anyhow::bail!(
            "TEAL identity not found. Please run 'teal-cli keygen' first.\nPath: {}",
            key_path.display()
        );
    }

    let key_bytes = fs::read(&key_path)
        .with_context(|| format!("Failed to read private key at {}", key_path.display()))?;

    let signing_key = SecretKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid BLS private key format: {:?}", e))?;

    let is_mgmt_decision =
        matches!(kind, DecisionKind::Approve | DecisionKind::Deny) && is_mgmt_id(id);
    if is_mgmt_decision && audit_id.is_none() {
        anyhow::bail!("audit_id is required for management commands");
    }

    if !is_mgmt_decision && audit_id.is_some() {
        anyhow::bail!("audit_id is only valid for management APPROVE/DENY");
    }
    if let Some(value) = audit_id {
        Uuid::parse_str(value).context("Invalid audit_id UUID")?;
    }

    // 署名対象と送信コマンドを同じ条件で生成する
    let (message, command) = if is_mgmt_decision {
        let audit_id = audit_id.ok_or_else(|| {
            anyhow::anyhow!("audit_id is required for management approval/denial")
        })?;

        (
            format!("{}:{}:{}", kind.as_str(), id, audit_id),
            format!("{} {} {} ", kind.as_str(), id, audit_id),
        )
    } else {
        (
            format!("{}:{}", kind.as_str(), id),
            format!("{} {} ", kind.as_str(), id),
        )
    };

    let signature = signing_key.sign(message.as_bytes(), TEAL_DST, &[]);
    let sig_hex = hex::encode(signature.to_bytes());

    let cmd = format!("{}{}", command, sig_hex);

    send_command(&cmd, true)?;

    println!("Decision '{}' sent for request '{}'.", kind.as_str(), id);
    Ok(())
}

/// teald の管理ソケットにコマンドを送信する共通関数
/// print_resp が true の場合は画面に出力し、いずれの場合もレスポンス文字列を返す
pub fn send_command(cmd: &str, print_resp: bool) -> Result<String> {
    let socket_path = TEALD_ADMIN_SOCKET_PATH;
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to teald at {}", socket_path))?;

    // コマンド末尾に改行がない場合は付与して送信
    if !cmd.ends_with('\n') {
        stream.write_all(format!("{}\n", cmd).as_bytes())?;
    } else {
        stream.write_all(cmd.as_bytes())?;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    if print_resp {
        print!("{}", response); // サーバー応答末尾に \n が含まれるため print! を推奨
    }

    Ok(response)
}

#[cfg(test)]
mod notify_cli_tests {
    use super::*;

    #[test]
    fn list_defaults_and_subcommand_are_distinct() {
        let cli = Cli::try_parse_from(["teal-cli", "notify", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notify {
                command: NotifyCommands::List {
                    offset: 0,
                    limit: 50,
                    json: false
                }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["teal-cli", "list"]).unwrap().command,
            Commands::List
        ));
    }

    #[test]
    fn list_options_and_show_id_are_parsed() {
        let cli = Cli::try_parse_from([
            "teal-cli", "notify", "list", "--offset", "50", "--limit", "25", "--json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notify {
                command: NotifyCommands::List {
                    offset: 50,
                    limit: 25,
                    json: true
                }
            }
        ));
        let cli = Cli::try_parse_from(["teal-cli", "notify", "show", "N-AI-001"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notify {
                command: NotifyCommands::Show { notification_id, json: false }
            } if notification_id == "N-AI-001"
        ));
    }

    #[test]
    fn notify_mutation_commands_are_parsed() {
        // --yes is checked by cmd::notify at execution time, not by clap.
        let cli = Cli::try_parse_from(["teal-cli", "notify", "retry", "N-1"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notify {
                command: NotifyCommands::Retry {
                    notification_id,
                    yes: false,
                    json: false,
                }
            } if notification_id == "N-1"
        ));

        let cli = Cli::try_parse_from(["teal-cli", "notify", "resolve", "N-1", "--yes", "--json"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notify {
                command: NotifyCommands::Resolve {
                    notification_id,
                    yes: true,
                    json: true,
                }
            } if notification_id == "N-1"
        ));
    }

    #[test]
    fn unknown_notify_commands_are_rejected() {
        assert!(Cli::try_parse_from(["teal-cli", "notify", "remove", "N-1"]).is_err());
        assert!(Cli::try_parse_from(["teal-cli", "notify", "retry"]).is_err());
        assert!(Cli::try_parse_from(["teal-cli", "notify", "resolve"]).is_err());
        assert!(Cli::try_parse_from(["teal-cli", "notify", "show"]).is_err());
        assert!(Cli::try_parse_from(["teal-cli", "notify", "retry", "N-1", "extra"]).is_err());
    }
}
