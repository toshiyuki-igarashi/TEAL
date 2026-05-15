// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use anyhow::{Context, Result};
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::fs::PermissionsExt; // Unix用
use std::{fs, path::{Path, PathBuf}};
use blst::min_pk::SecretKey; // min_pk モードを選択
use rand::{RngCore, thread_rng};
use colored::Colorize;

use teal_policy_engine::load::load_json_file;
use teal_policy_engine::raw::RawPolicyV13;
use crate::common::DecisionKind;
use crate::verify::ast::TealIrModel;

mod common;
mod verify;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let sub_cmd = args[1].as_str();

    match sub_cmd {
        "keygen" => {
            if args.len() >= 3 {
                println!("Usage: teal-cli keygen");
                return Ok(());
            }
            generate_user_key()?;
        }
        "register" => {
            if args.len() >= 3 {
                println!("Usage: teal-cli register");
                return Ok(());
            }

            let dir = teal_key_dir()?;
            let pub_path = dir.join("id_bls.pub");

            if !pub_path.exists() {
                eprintln!(
                    "Error: Public key '{}' not found. Run `teal-cli keygen` first.",
                    pub_path.display()
                );
                return Ok(());
            }

            let hex_key = fs::read_to_string(&pub_path)
                .with_context(|| format!("read public key {}", pub_path.display()))?;

            send_command(&format!("REGISTER {}", hex_key.trim()))?;
        }
        "list" => {
            send_command("LIST")?;
        }
        "approve" => {
            if args.len() < 3 {
                println!("Usage: teal-cli approve <ID>");
                return Ok(());
            }
            run_signed_decision(DecisionKind::Approve, &args[2])?;
        }
        "deny" => {
            if args.len() < 3 {
                println!("Usage: teal-cli deny <ID>");
                return Ok(());
            }
            run_signed_decision(DecisionKind::Deny, &args[2])?;
        }
        "ticket" => {
            if args.len() < 3 {
                println!("Usage: teal-cli ticket <RULE_ID>");
                return Ok(());
            }
            run_signed_decision(DecisionKind::Ticket, &args[2])?;
        }
        "start" => {
            if args.len() != 2 {
                println!("Usage: teal-cli start");
                return Ok(());
            }
            run_signed_decision(DecisionKind::Start, "")?;
        }
        "stop" => {
            if args.len() != 2 {
                println!("Usage: teal-cli stop");
                return Ok(());
            }
            run_signed_decision(DecisionKind::Stop, "")?;
        }
        "emergency" => {
            if args.len() < 3 {
                println!("Usage: teal-cli emergency <TOKEN>");
                return Ok(());
            }
            let token = &args[2];
            send_command(&format!("EMERGENCY {}", token))?;
        }
        "verify" => {
            if args.len() < 3 {
                println!("Usage: teal-cli verify <policy.json> [--goal <goal.yaml>] [--visualize] [--debug]");
                return Ok(());
            }

            // 引数から入力パスを取得
            let input_path_str = &args[2]; 
            let path = std::path::Path::new(input_path_str);

            // ファイル名からポリシー名（識別子）を抽出
            let policy_name = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("default_policy")
                .to_string(); // 後で使うためにStringとして持っておく

            let visualize_flag = args.iter().any(|arg| arg == "--visualize");
            let debug_flag = args.iter().any(|arg| arg == "--debug");

            // ゴール定義の読み込み
            let mut goals: Vec<verify::VerifyGoal> = Vec::new(); 
            if let Some(pos) = args.iter().position(|arg| arg == "--goal") {
                if pos + 1 < args.len() {
                    let goal_path = &args[pos + 1];
                    let yaml_str = std::fs::read_to_string(goal_path)
                        .with_context(|| format!("Failed to read goal yaml file: {}", goal_path))?;
                    goals = serde_yaml::from_str(&yaml_str)
                        .with_context(|| format!("Failed to deserialize goal yaml: {}", goal_path))?;
                    println!("=> ゴール定義ファイル '{}' を読み込みました ({} 個のゴール)", goal_path, goals.len());
                } else {
                    anyhow::bail!("--goal option requires a file path.");
                }
            } else {
                println!("=> ゴール定義(--goal)が指定されていません。ポリシーの論理矛盾チェックのみを実行します。");
            }

            // 1. ポリシーJSONのパース
            let v = load_json_file(path)
                .with_context(|| format!("Failed to load policy json: {}", input_path_str))?;
            let policy: RawPolicyV13 = serde_json::from_value(v)
                .with_context(|| format!("Failed to deserialize policy raw struct: {}", input_path_str))?;

            // 2. 中間論理モデル (TealIrModel) の構築
            println!("{} 中間論理モデル(Teal-IR)を構築中...", "-> [1/3]".cyan());
            let model = TealIrModel::from_raw(&policy, &goals, &policy_name)?;

            // 3. 検証実行 (Executorの起動)
            let jar_path = env::var("TEAL_ALLOY_JAR")
                .unwrap_or_else(|_| "alloy-cli.jar".to_string());

            // 4. 検証エグゼキューターの初期化と実行
            println!("{} Alloyトランスパイラを初期化中...", "-> [2/3]".cyan());
            let mut executor = verify::VerifyExecutor::new(&jar_path);
            
            // 内部で transpile -> run_alloy -> parse_xml -> report が走る
            executor.execute(&model, visualize_flag, debug_flag)?;
        }
        _ => print_usage(),
    }
    Ok(())
}

// 署名と検証で共通のドメイン分離タグ (DST)
const TEAL_DST: &[u8] = b"TEAL_SYSTEM_V1_MPA_SIG";

/// 秘密鍵のパスを取得 (エラー時はResultを返す)
fn teal_private_key_path() -> Result<PathBuf> {
    let home = env::var("HOME")
        .context("Environment variable $HOME not set")?;
    
    Ok(Path::new(&home)
        .join(".teal")
        .join("id_bls"))
}

// 署名付きの決定コマンドを送る共通関数（user なし）
fn run_signed_decision(kind: DecisionKind, id: &str) -> Result<()> {
    // パス解決 (エラーならここでreturn)
    let key_path = teal_private_key_path()?;

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

fn teal_key_dir() -> Result<PathBuf> {
    let home = env::var("HOME").context("$HOME not set")?;
    Ok(PathBuf::from(home).join(".teal"))
}

fn generate_user_key() -> Result<()> {
    let dir = teal_key_dir()?;
    
    // ディレクトリ作成
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    // ディレクトリ権限設定: 0700 (rwx------)
    // これにより、このディレクトリ内のファイル一覧すら他人には見えなくなります
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&dir)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&dir, perms)?;
    }

    let sk_path = dir.join("id_bls");
    let pk_path = dir.join("id_bls.pub");
    
    // ---------------------------------------------------------
    // 1. 鍵生成 (Key Generation)
    // ---------------------------------------------------------
    let mut rng = thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    // BLS秘密鍵の生成 (IKMから)
    let sk = SecretKey::key_gen(&ikm, &[])
        .map_err(|e| anyhow::anyhow!("Key gen failed: {:?}", e))?;

    // 対応する公開鍵の導出
    let pk = sk.sk_to_pk();

    // ---------------------------------------------------------
    // 2. 秘密鍵の保存 (Secret Key)
    // ---------------------------------------------------------
    let sk_bytes = sk.to_bytes(); 
    std::fs::write(&sk_path, sk_bytes)?;

    // 【重要】ファイル権限設定: 0600 (rw-------)
    // 他人からの読み取りを完全にブロックします
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&sk_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&sk_path, perms)?;
    }

    // ---------------------------------------------------------
    // 3. 公開鍵の保存 (Public Key)
    // ---------------------------------------------------------
    // 設定ファイル(YAML/TOML)にコピペしやすいよう、Hex文字列で保存するのが一般的です
    let pk_bytes = pk.to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    std::fs::write(&pk_path, &pk_hex)?;
    
    // 公開鍵は公開して問題ないので、権限は 644 でOK
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&pk_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&pk_path, perms)?;
    }

    println!("Success!");
    println!("Private Key: {} (Permissions secured)", sk_path.display());
    println!("Public Key : {} (Share this with admin)", pk_path.display());
    println!("\nYour Public Key (Hex): {}", pk_hex);

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

fn print_usage() {
    println!("Usage:");
    println!("  teal-cli keygen                 Generate Ed25519 keypair");
    println!("  teal-cli register               Register public key to teald");
    println!("  teal-cli list                   Show pending requests");
    println!("  teal-cli approve <ID>           Approve with digital signature");
    println!("  teal-cli deny <ID>              Reject request");
    println!("  teal-cli ticket <ID>            Request ticket request");
    println!("  teal-cli start                  Start Enforce mode");
    println!("  teal-cli stop                   Stop Enforce mode and start Audit mode");
    println!("  teal-cli emergency <TOKEN>      Activate Break-Glass Mode");
    println!("  teal-cli verify <POLICY_FILE> [--goal <goal.yaml>] [--visualize] [--debug]    Verify policy rules");
}
