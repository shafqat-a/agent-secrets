use anyhow::{Context, Result};
use directories::UserDirs;
use std::io::{Read, Write};
use std::str::FromStr;

pub struct SshLock {
    pub pubkey: String,
}

impl SshLock {
    pub fn new(_id: String, pubkey: String) -> Self {
        Self { pubkey }
    }

    pub fn encrypt_master_key(&self, master_key: &[u8; 32]) -> Result<Vec<u8>> {
        let recipient = age::ssh::Recipient::from_str(&self.pubkey)
            .map_err(|e| anyhow::anyhow!("invalid SSH public key: {:?}", e))?;
        let recipients: [&dyn age::Recipient; 1] = [&recipient];
        let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
            .context("failed to create encryptor")?;
        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(master_key)?;
        writer.finish()?;
        Ok(encrypted)
    }

    pub fn decrypt_master_key(ciphertext: &[u8]) -> Result<[u8; 32]> {
        // Try all SSH private keys in ~/.ssh/
        let ssh_dir = UserDirs::new()
            .context("could not find home directory")?
            .home_dir()
            .join(".ssh");

        let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();

        // Try common private key files
        for name in ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"] {
            let path = ssh_dir.join(name);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match age::ssh::Identity::from_buffer(
                        std::io::Cursor::new(content),
                        Some(path.display().to_string()),
                    ) {
                        Ok(identity) => match resolve_encrypted_identity(identity, &path) {
                            Ok(id) => identities.push(Box::new(id)),
                            Err(e) => eprintln!("warning: {}: {}", path.display(), e),
                        },
                        Err(e) => {
                            eprintln!("warning: could not parse {}: {}", path.display(), e)
                        }
                    }
                }
            }
        }

        if identities.is_empty() {
            anyhow::bail!("no usable SSH private keys found in ~/.ssh/");
        }

        let cursor = std::io::Cursor::new(ciphertext);
        let decryptor = age::Decryptor::new(cursor).context("failed to parse SSH lock file")?;

        let mut plaintext = Vec::new();
        let refs: Vec<&dyn age::Identity> = identities.iter().map(|i| i.as_ref()).collect();
        let mut reader = decryptor
            .decrypt(refs.into_iter())
            .context("no matching SSH key found to decrypt lock")?;
        reader.read_to_end(&mut plaintext)?;

        if plaintext.len() != 32 {
            anyhow::bail!("invalid master key length");
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&plaintext);
        Ok(master_key)
    }
}

/// If the identity is encrypted, prompt for passphrase and decrypt it.
fn resolve_encrypted_identity(
    identity: age::ssh::Identity,
    path: &std::path::Path,
) -> Result<age::ssh::Identity> {
    match identity {
        age::ssh::Identity::Unencrypted(_) => Ok(identity),
        age::ssh::Identity::Encrypted(enc) => {
            let prompt = format!("Passphrase for SSH key {}: ", path.display());
            let passphrase = rpassword::prompt_password(&prompt)?;
            let decrypted = enc
                .decrypt(passphrase.into())
                .map_err(|_| anyhow::anyhow!("incorrect passphrase"))?;
            Ok(decrypted.into())
        }
        age::ssh::Identity::Unsupported(u) => {
            anyhow::bail!("unsupported SSH key: {:?}", u)
        }
    }
}
