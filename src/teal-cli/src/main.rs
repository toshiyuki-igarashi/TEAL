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

// Policy Engine からのインポート
use teal_policy_engine::load::load_json_file;
use teal_policy_engine::raw::RawPolicyV14;

// teald クレートから共通型をインポート
use teald::common::DecisionKind;

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
    /// Approve with digital signature
    Approve {
        /// Request ID to approve
        id: String,
    },
    /// Reject request
    Deny {
        /// Request ID to deny
        id: String,
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

            send_command(&format!("REGISTER {}", hex_key.trim()))?;
        }
        Commands::List => {
            send_command("LIST")?;
        }
        Commands::Approve { id } => {
            run_signed_decision(DecisionKind::Approve, id)?;
        }
        Commands::Deny { id } => {
            run_signed_decision(DecisionKind::Deny, id)?;
        }
        Commands::Ticket { rule_id } => {
            run_signed_decision(DecisionKind::Ticket, rule_id)?;
        }
        Commands::Start => {
            run_signed_decision(DecisionKind::Start, "")?;
        }
        Commands::Stop => {
            run_signed_decision(DecisionKind::Stop, "")?;
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
            send_command("FLUSH")?;
        }
        Commands::Emergency { token } => {
            send_command(&format!("EMERGENCY {}", token))?;
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
fn run_verify(
    policy_file: &str,
    goal: Option<&str>,
    visualize: bool,
    debug: bool,
) -> Result<()> {
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
fn run_signed_decision(kind: DecisionKind, id: &str) -> Result<()> {
    // パス解決 (エラーならここでreturn)
    let key_path = cmd::keygen::teal_private_key_path()?;

    if !key_path.exists() {
        anyhow::bail!("TEAL identity not found. Please run 'teal-cli keygen' first.\nPath: {}", key_path.display());
    }

    // --- BLS鍵の読み込み ---
    let key_bytes = fs::read(&key_path)
        .with_context(|| format!("Failed to read private key at {}", key_path.display()))?;
    
    let signing_key = SecretKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid BLS private key format: {:?}", e))?;

    // 1. 署名対象メッセージ (集約のため UID は含めない)
    // 承認者全員がこの "APPROVE:req-123" という同一データに署名する
    let message = format!("{}:{}", kind.as_str(), id);

    // 2. 署名 (BLS)
    let signature = signing_key.sign(message.as_bytes(), TEAL_DST, &[]);
    let sig_hex = hex::encode(signature.to_bytes());

    // 3. 送信コマンド (UID は送らない)
    // Server側は peer_cred で誰からのコマンドかを特定する
    // Format: <KIND> <ID> <SIGNATURE>
    let cmd = format!("{} {} {}", kind.as_str(), id, sig_hex);

    // 実際の送信処理 (実装済みと仮定)
    send_command(&cmd)?;
    
    println!("Decision '{}' sent for request '{}'.", kind.as_str(), id);
    Ok(())
}


fn send_command(cmd: &str) -> Result<()> {
    let socket_path = "/tmp/teald.sock";
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to teald at {}", socket_path))?;
    
    stream.write_all(cmd.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{}", response);
    Ok(())
}
