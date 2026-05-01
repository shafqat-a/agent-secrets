use crate::machine_id::derive_machine_key;
use crate::vault::crypto::{decrypt, encrypt_with_nonce, EncryptedBlob};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

const SESSION_VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    pub version: u8,
    pub mode: SessionMode,
    pub master_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SessionMode {
    Read,
    Write,
}

impl Session {
    pub fn new(master_key: [u8; 32], mode: SessionMode) -> Self {
        Self {
            version: SESSION_VERSION,
            mode,
            master_key,
        }
    }

    pub fn load() -> Result<Option<Self>> {
        let path = session_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path)
            .with_context(|| format!("failed to read session file: {}", path.display()))?;
        let blob = EncryptedBlob::from_bytes(&data)?;
        let salt = blob.nonce;
        let mut machine_key = derive_machine_key(&salt)?;
        let mut plaintext = decrypt(&blob, &machine_key)
            .context("failed to decrypt session file (machine changed?)")?;
        let session: Session =
            rmp_serde::from_slice(&plaintext).context("corrupted session file")?;
        machine_key.zeroize();
        plaintext.zeroize();
        Ok(Some(session))
    }

    pub fn save(&self) -> Result<()> {
        let path = session_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut plaintext = rmp_serde::to_vec(self)?;
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        let mut machine_key = derive_machine_key(&salt)?;
        let blob = encrypt_with_nonce(&plaintext, &machine_key, salt)?;
        machine_key.zeroize();
        plaintext.zeroize();
        std::fs::write(&path, blob.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }

    pub fn delete() -> Result<()> {
        let path = session_path()?;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn exists() -> bool {
        session_path().map(|p| p.exists()).unwrap_or(false)
    }

    pub fn require_write(&self) -> Result<()> {
        if self.mode != SessionMode::Write {
            anyhow::bail!("vault is in read-only mode. Run `agent-secrets unlock` without --read to enable writes.");
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

fn session_path() -> Result<PathBuf> {
    let dirs =
        ProjectDirs::from("", "", "agent-secrets").context("could not determine cache directory")?;
    Ok(dirs.cache_dir().join("session"))
}
