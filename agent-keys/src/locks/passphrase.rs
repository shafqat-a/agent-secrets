use crate::vault::crypto::{decrypt, encrypt, EncryptedBlob};
use anyhow::{Context, Result};
use argon2::Argon2;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8] = b"AGLP";
const VERSION: u8 = 1;
const TYPE_PASSPHRASE: u8 = 3;
const SALT_SIZE: usize = 32;

#[derive(ZeroizeOnDrop)]
pub struct PassphraseLock {
    pub passphrase: String,
}

impl PassphraseLock {
    pub fn new(_id: String, passphrase: String) -> Self {
        Self { passphrase }
    }

    pub fn encrypt_master_key(&self, master_key: &[u8; 32]) -> Result<Vec<u8>> {
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut derived_key = derive_key(self.passphrase.as_bytes(), &salt)?;

        let plaintext = master_key.as_slice();
        let blob = encrypt(plaintext, &derived_key)?;
        derived_key.zeroize();

        let mut result = Vec::new();
        result.extend_from_slice(MAGIC);
        result.push(VERSION);
        result.push(TYPE_PASSPHRASE);
        result.extend_from_slice(&salt);
        result.extend_from_slice(&blob.to_bytes());
        Ok(result)
    }

    pub fn decrypt_master_key(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        if ciphertext.len() < MAGIC.len() + 1 + 1 + SALT_SIZE {
            anyhow::bail!("passphrase lock file too short");
        }
        if &ciphertext[..MAGIC.len()] != MAGIC {
            anyhow::bail!("invalid passphrase lock magic bytes");
        }
        if ciphertext[MAGIC.len()] != VERSION {
            anyhow::bail!("unsupported passphrase lock version");
        }
        if ciphertext[MAGIC.len() + 1] != TYPE_PASSPHRASE {
            anyhow::bail!("unsupported lock type");
        }

        let salt_start = MAGIC.len() + 2;
        let salt = &ciphertext[salt_start..salt_start + SALT_SIZE];
        let mut derived_key = derive_key(self.passphrase.as_bytes(), salt)?;

        let blob_bytes = &ciphertext[salt_start + SALT_SIZE..];
        let blob = EncryptedBlob::from_bytes(blob_bytes)?;
        let mut plaintext = decrypt(&blob, &derived_key).context("wrong passphrase")?;
        derived_key.zeroize();
        if plaintext.len() != 32 {
            anyhow::bail!("invalid master key length");
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(master_key)
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut derived_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {:?}", e))?;
    Ok(derived_key)
}
