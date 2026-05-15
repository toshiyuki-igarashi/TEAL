// SPDX-License-Identifier: MIT
/*
 * TEAL Daemon (teald)
 *
 * Copyright (c) 2026 Toshiyuki Igarashi
 */
use anyhow::{Context, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use std::fs;
use std::path::Path;
use rand::Rng; // randクレートを使用

// ★TPMライブラリ (7.6.0対応)
use tss_esapi::{
    tcti_ldr::TctiNameConf,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
        key_bits::RsaKeyBits,
    },
    structures::{
        Digest, PublicBuilder, PublicRsaParametersBuilder,
        SymmetricDefinitionObject, PublicKeyRsa,
        RsaExponent, RsaScheme,
        // ★以下の2つを追加してください
        RsaDecryptionScheme, HashScheme,
        Data, 
    },
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
};

const VAULT_FILE: &str = "/etc/teal.d/vault.dat";     // 暗号化されたデータ本体
const ENC_KEY_FILE: &str = "/etc/teal.d/vault.key";   // TPMで暗号化されたAES鍵

// --- TPM Helper Functions ---

fn get_tpm_context() -> Result<tss_esapi::Context> {
    // QEMU環境に合わせてTCTIを設定 (/dev/tpm0)
    let tcti_conf = TctiNameConf::from_environment_variable().unwrap_or_else(|_| {
        TctiNameConf::from_str("device:/dev/tpm0").expect("Invalid TCTI config")
    });
    let context = tss_esapi::Context::new(tcti_conf)
        .context("TPM Connect Error")?;
    Ok(context)
}

// SRK (Storage Root Key) を作成
// ※実質的にはデータを直接守るための親鍵ではなく、汎用的な暗号化鍵として作成します
fn create_srk(context: &mut tss_esapi::Context) -> Result<KeyHandle> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true) // 復号に使用
        .with_sign_encrypt(false) // 署名には使わない
        .with_restricted(false) // ★修正: "false" にして汎用キーにする
        .build().map_err(|e| anyhow::anyhow!("Attr Build Error: {}", e))?;

    // ★修正: 汎用キー用のパラメータビルダを使用
    // restricted(false) の場合、symmetric は Null である必要があります
    let rsa_params = PublicRsaParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .build().map_err(|e| anyhow::anyhow!("RSA Params Error: {}", e))?;

    let public_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(Digest::default())
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build().map_err(|e| anyhow::anyhow!("Pub Template Error: {}", e))?;

    let key_result = context.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(
            Hierarchy::Owner,
            public_template,
            None,
            None,
            None,
            None,
        )
    }).map_err(|e| anyhow::anyhow!("Create Primary Error: {}", e))?;

    Ok(key_result.key_handle)
}

// --- Main Vault Logic ---

// AES鍵を取得する (なければ生成してTPMで封印)
fn get_or_create_aes_key() -> Result<[u8; 32]> {
    let mut ctx = get_tpm_context()?;
    let srk_handle = create_srk(&mut ctx)?;

    if Path::new(ENC_KEY_FILE).exists() {
        // --- 復号 (Unseal) ---
        println!("[teald-vault] Loading TPM-encrypted key...");
        let encrypted_key = fs::read(ENC_KEY_FILE)?;
        
        let decrypted = ctx.execute_with_nullauth_session(|c| {
            c.rsa_decrypt(
                srk_handle,
                encrypted_key.try_into().unwrap(), 
                // ★修正: Null から OAEP(Sha256) へ変更
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                Data::default() 
            )
        }).map_err(|e| anyhow::anyhow!("TPM Decryption Failed! Error: {}", e))?;

        // これで decrypted はパディングが除去され、純粋な32バイトになります
        let key_bytes: [u8; 32] = decrypted.as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("Decrypted key length mismatch. Got {} bytes", decrypted.len()))?;
        
        Ok(key_bytes)
    } else {
        // --- 生成と封印 (Seal) ---
        println!("[teald-vault] Generating new AES key via TPM RNG...");
        
        let random_bytes = ctx.get_random(32)
            .map_err(|e| anyhow::anyhow!("TPM RNG Error: {}", e))?;
        let key_bytes: [u8; 32] = random_bytes.as_slice().try_into().unwrap();

        // TPMを使って暗号化 (Seal)
        let encrypted = ctx.execute_with_nullauth_session(|c| {
            c.rsa_encrypt(
                srk_handle,
                key_bytes.to_vec().try_into().unwrap(),
                // ★修正: Null から OAEP(Sha256) へ変更
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                Data::default()
            )
        }).map_err(|e| anyhow::anyhow!("TPM Encryption Error: {}", e))?;

        fs::write(ENC_KEY_FILE, encrypted.as_slice())?;
        println!("[teald-vault] AES key sealed by TPM and saved to {}.", ENC_KEY_FILE);

        Ok(key_bytes)
    }
}

// データを封印 (Encrypt)
pub fn seal_data(data: &[u8]) -> Result<()> {
    let key_bytes = get_or_create_aes_key()?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Nonceの生成 (randクレートを使用)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);

    fs::write(VAULT_FILE, combined)?;
    println!("[teald-vault] Data sealed successfully into {}.", VAULT_FILE);
    Ok(())
}

// データを開封 (Decrypt)
pub fn unseal_data() -> Result<Vec<u8>> {
    if !Path::new(VAULT_FILE).exists() {
        return Err(anyhow::anyhow!("Vault file not found"));
    }
    
    // ここでTPMにアクセスできないとエラーになる
    let key_bytes = get_or_create_aes_key()?;
    
    let combined = fs::read(VAULT_FILE)?;
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Corrupted vault data"));
    }

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&combined[0..12]);
    let ciphertext = &combined[12..];

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    println!("[teald-vault] Data unsealed successfully via TPM-protected key.");
    Ok(plaintext)
}

// 移行ロジック
pub fn migrate_key(plain_path: &str) -> Result<Vec<u8>> {
    if Path::new(VAULT_FILE).exists() {
        return unseal_data();
    }
    if Path::new(plain_path).exists() {
        println!("[teald-vault] Found plaintext key. Migrating to TPM Vault...");
        let content = fs::read(plain_path)?;
        seal_data(&content)?;
        
        let check = unseal_data()?;
        if check != content {
            return Err(anyhow::anyhow!("Integrity check failed!"));
        }

        println!("[teald-vault] Wiping plaintext key...");
        fs::remove_file(plain_path)?;
        println!("[teald-vault] Migration Complete.");
        return Ok(content);
    }
    Err(anyhow::anyhow!("No key found."))
}
