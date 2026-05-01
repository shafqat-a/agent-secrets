use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;

const VAULT_MAGIC: &[u8; 4] = b"AGKY";
const VAULT_VERSION: u8 = 1;
const NONCE_SIZE: usize = 16;
const AES_GCM_NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
}

impl EncryptedBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len() + TAG_SIZE);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result.extend_from_slice(&self.tag);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NONCE_SIZE + TAG_SIZE {
            anyhow::bail!("encrypted blob too short");
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[..NONCE_SIZE]);
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&bytes[bytes.len() - TAG_SIZE..]);
        let ciphertext = bytes[NONCE_SIZE..bytes.len() - TAG_SIZE].to_vec();
        Ok(Self {
            nonce,
            ciphertext,
            tag,
        })
    }
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedBlob> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    encrypt_with_nonce(plaintext, key, nonce_bytes)
}

pub fn encrypt_with_nonce(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce_bytes: [u8; NONCE_SIZE],
) -> Result<EncryptedBlob> {
    let cipher = Aes256Gcm::new_from_slice(key).context("invalid encryption key length")?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes[..AES_GCM_NONCE_SIZE]);
    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {:?}", e))?;

    // aes-gcm returns ciphertext || tag
    let ciphertext_len = ciphertext_with_tag.len() - TAG_SIZE;
    let mut ciphertext = Vec::with_capacity(ciphertext_len);
    ciphertext.extend_from_slice(&ciphertext_with_tag[..ciphertext_len]);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&ciphertext_with_tag[ciphertext_len..]);

    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
        tag,
    })
}

pub fn decrypt(blob: &EncryptedBlob, key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).context("invalid decryption key length")?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&blob.nonce[..AES_GCM_NONCE_SIZE]);

    // Reassemble ciphertext || tag for aes-gcm
    let mut ciphertext_with_tag = Vec::with_capacity(blob.ciphertext.len() + TAG_SIZE);
    ciphertext_with_tag.extend_from_slice(&blob.ciphertext);
    ciphertext_with_tag.extend_from_slice(&blob.tag);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| anyhow::anyhow!("decryption failed (wrong key or tampered data): {:?}", e))?;
    Ok(plaintext)
}

pub fn encode_vault_blob(blob: &EncryptedBlob) -> Vec<u8> {
    let mut result = Vec::with_capacity(5 + NONCE_SIZE + blob.ciphertext.len() + TAG_SIZE);
    result.extend_from_slice(VAULT_MAGIC);
    result.push(VAULT_VERSION);
    result.extend_from_slice(&blob.to_bytes());
    result
}

pub fn decode_vault_blob(bytes: &[u8]) -> Result<EncryptedBlob> {
    if bytes.len() >= 5 && &bytes[..4] == VAULT_MAGIC {
        if bytes[4] != VAULT_VERSION {
            anyhow::bail!("unsupported vault version");
        }
        EncryptedBlob::from_bytes(&bytes[5..])
    } else {
        // Backward-compatible read path for vaults created by the early prototype.
        EncryptedBlob::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [1u8; 32];
        let plaintext = b"hello world";
        let blob = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&blob, &key).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
