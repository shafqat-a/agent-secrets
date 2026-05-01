use crate::config::Config;
use crate::locks::passphrase::PassphraseLock;
use crate::locks::ssh::SshLock;
use crate::session::{Session, SessionMode};
use age::Identity;
use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

pub fn run(read_only: bool, ssh_key_from_env: Option<String>) -> Result<()> {
    let agent_secrets_dir = super::find_agent_secrets_dir()?;
    let config = super::load_config(&agent_secrets_dir)?;

    // Try loading existing session first
    if let Some(session) = Session::load()? {
        println!(
            "Vault is already unlocked ({} mode).",
            mode_name(&session.mode)
        );
        return Ok(());
    }

    let master_key = try_unlock(&agent_secrets_dir, &config, ssh_key_from_env.as_deref())?;

    let mode = if read_only {
        SessionMode::Read
    } else {
        SessionMode::Write
    };

    let session = Session::new(master_key, mode.clone());
    session.save()?;
    println!("Vault unlocked in {} mode.", mode_name(&mode));
    Ok(())
}

fn try_unlock(
    agent_secrets_dir: &Path,
    config: &Config,
    ssh_key_from_env: Option<&str>,
) -> Result<[u8; 32]> {
    if let Some(env_name) = ssh_key_from_env {
        let mut key = std::env::var(env_name)
            .with_context(|| format!("environment variable '{}' is not set", env_name))?;
        for lock in config.locks.iter().filter(|lock| lock.lock_type == "ssh") {
            if let Ok(master_key) = unlock_ssh_with_identity(agent_secrets_dir, lock, &key, env_name) {
                key.zeroize();
                return Ok(master_key);
            }
        }
        key.zeroize();
        anyhow::bail!("no SSH lock could be decrypted with key from {}", env_name);
    }

    // If only one lock, try it directly
    if config.locks.len() == 1 {
        let lock = &config.locks[0];
        return unlock_with_lock(agent_secrets_dir, lock);
    }

    // Multiple locks: prompt user
    println!("Multiple unlock methods available:");
    for (i, lock) in config.locks.iter().enumerate() {
        println!("  {}) {} ({})", i + 1, lock.id, lock.lock_type);
    }
    println!("  q) Quit");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim();
    if choice == "q" {
        anyhow::bail!("unlock cancelled");
    }
    let idx: usize = choice.parse().context("invalid choice")?;
    let lock = config.locks.get(idx - 1).context("invalid choice")?;
    unlock_with_lock(agent_secrets_dir, lock)
}

fn unlock_with_lock(agent_secrets_dir: &Path, lock: &crate::config::LockConfig) -> Result<[u8; 32]> {
    let lock_path = agent_secrets_dir.join(&lock.file);
    let ciphertext = std::fs::read(&lock_path)
        .with_context(|| format!("failed to read lock file: {}", lock_path.display()))?;

    match lock.lock_type.as_str() {
        "ssh" => SshLock::decrypt_master_key(&ciphertext),
        "passphrase" => {
            let passphrase = rpassword::prompt_password("Passphrase: ")?;
            let pl = PassphraseLock::new(lock.id.clone(), passphrase);
            pl.decrypt_master_key(&ciphertext)
        }
        _ => anyhow::bail!("unknown lock type: {}", lock.lock_type),
    }
}

fn unlock_ssh_with_identity(
    agent_secrets_dir: &Path,
    lock: &crate::config::LockConfig,
    private_key: &str,
    env_name: &str,
) -> Result<[u8; 32]> {
    let lock_path = agent_secrets_dir.join(&lock.file);
    let ciphertext = std::fs::read(&lock_path)
        .with_context(|| format!("failed to read lock file: {}", lock_path.display()))?;
    let identity = age::ssh::Identity::from_buffer(
        std::io::Cursor::new(private_key),
        Some(format!("${}", env_name)),
    )
    .map_err(|e| anyhow::anyhow!("invalid SSH private key in environment: {:?}", e))?;

    let identity = resolve_encrypted_identity(identity, env_name)?;

    let cursor = std::io::Cursor::new(ciphertext);
    let decryptor = age::Decryptor::new(cursor).context("failed to parse SSH lock file")?;
    let identities: [&dyn Identity; 1] = [&identity];
    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .context("SSH key from environment did not match this lock")?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    if plaintext.len() != 32 {
        anyhow::bail!("invalid master key length");
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(master_key)
}

fn resolve_encrypted_identity(
    identity: age::ssh::Identity,
    source: &str,
) -> Result<age::ssh::Identity> {
    match identity {
        age::ssh::Identity::Unencrypted(_) => Ok(identity),
        age::ssh::Identity::Encrypted(enc) => {
            let prompt = format!("Passphrase for SSH key {}: ", source);
            let passphrase = rpassword::prompt_password(&prompt)?;
            let decrypted = enc
                .decrypt(passphrase.into())
                .map_err(|_| anyhow::anyhow!("incorrect passphrase for SSH key {}", source))?;
            Ok(decrypted.into())
        }
        age::ssh::Identity::Unsupported(u) => {
            anyhow::bail!("unsupported SSH key ({}): {:?}", source, u)
        }
    }
}

fn mode_name(mode: &SessionMode) -> &'static str {
    match mode {
        SessionMode::Read => "read-only",
        SessionMode::Write => "write",
    }
}
