// SPDX-License-Identifier: MIT
/*
 * TEAL CLI (teal-cli)
 * 
 * Copyright (c) 2026 Toshiyuki Igarashi
 */

use anyhow::{Context, Result};
use blst::min_pk::SecretKey;
use rand::{thread_rng, RngCore};
use std::env;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// TEAL のユーザー鍵ディレクトリ (~/.teal) のパスを取得
pub fn teal_key_dir() -> Result<PathBuf> {
    let home = env::var("HOME").context("$HOME not set")?;
    Ok(PathBuf::from(home).join(".teal"))
}

/// 秘密鍵 (~/.teal/id_bls) のパスを取得 (update/approve コマンド等でも共用)
pub fn teal_private_key_path() -> Result<PathBuf> {
    Ok(teal_key_dir()?.join("id_bls"))
}

/// 公開鍵 (~/.teal/id_bls.pub) のパスを取得
pub fn teal_public_key_path() -> Result<PathBuf> {
    Ok(teal_key_dir()?.join("id_bls.pub"))
}

/// `teal-cli keygen` コマンドの実体ハンドラ
pub fn run() -> Result<()> {
    let dir = teal_key_dir()?;

    // 1. ディレクトリ作成
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    // ディレクトリ権限設定: 0700 (rwx------)
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&dir)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&dir, perms)?;
    }

    let sk_path = teal_private_key_path()?;
    let pk_path = teal_public_key_path()?;

    // 2. BLS鍵ペアの生成
    let mut rng = thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[])
        .map_err(|e| anyhow::anyhow!("Key gen failed: {:?}", e))?;
    let pk = sk.sk_to_pk();

    // 3. 秘密鍵の保存 (0600)
    let sk_bytes = sk.to_bytes();
    fs::write(&sk_path, sk_bytes)?;

    #[cfg(unix)]
    {
        let metadata = fs::metadata(&sk_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&sk_path, perms)?;
    }

    // 4. 公開鍵の保存 (0644 / Hex形式)
    let pk_bytes = pk.to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    fs::write(&pk_path, &pk_hex)?;

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
