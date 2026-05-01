use crate::cli::LockCommands;
use crate::config::LockConfig;
use crate::locks::passphrase::PassphraseLock;
use crate::locks::ssh::SshLock;
use crate::session::Session;
use anyhow::{Context, Result};
use chrono::Utc;

pub fn run(cmd: LockCommands) -> Result<()> {
    match cmd {
        LockCommands::AddSsh { pubkey_path } => add_ssh(pubkey_path),
        LockCommands::AddPassphrase => add_passphrase(),
        LockCommands::List => list_locks(),
        LockCommands::Remove { id } => remove_lock(id),
    }
}

fn add_ssh(pubkey_path: String) -> Result<()> {
    let session = require_unlocked_session()?;
    let agent_keys_dir = super::find_agent_keys_dir()?;
    let mut config = super::load_config(&agent_keys_dir)?;
    super::load_vault(&agent_keys_dir, &config, &session)?;

    let pubkey = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("failed to read pubkey: {}", pubkey_path))?;
    let fingerprint = ssh_fingerprint(pubkey.trim())?;
    let id = format!(
        "ssh-{}",
        &fingerprint
            .replace(":", "")
            .replace("SHA256:", "")
            .replace('/', "-")[..8.min(fingerprint.len())]
    );

    if config.find_lock(&id).is_some() {
        anyhow::bail!("lock '{}' already exists", id);
    }

    let lock = SshLock::new(id.clone(), pubkey.trim().to_string());
    let ciphertext = lock.encrypt_master_key(&session.master_key)?;
    let lock_filename = format!("{}.enc", id);
    let lock_path = agent_keys_dir.join("locks").join(&lock_filename);
    std::fs::write(&lock_path, ciphertext)?;

    config.locks.push(LockConfig {
        id,
        lock_type: "ssh".to_string(),
        file: format!("locks/{}", lock_filename),
        fingerprint: Some(fingerprint),
        comment: Some(pubkey_path),
        public_key: Some(pubkey.trim().to_string()),
        created_at: Utc::now().to_rfc3339(),
    });
    super::save_config(&agent_keys_dir, &config)?;
    println!("SSH lock added.");
    Ok(())
}

fn add_passphrase() -> Result<()> {
    let session = require_unlocked_session()?;
    let agent_keys_dir = super::find_agent_keys_dir()?;
    let mut config = super::load_config(&agent_keys_dir)?;

    let pass = rpassword::prompt_password("Enter a strong passphrase: ")?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if pass != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let id = format!("passphrase-{}", random_id());
    let lock = PassphraseLock::new(id.clone(), pass);
    let ciphertext = lock.encrypt_master_key(&session.master_key)?;
    let lock_path = agent_keys_dir.join("locks").join(format!("{}.enc", id));
    std::fs::write(&lock_path, ciphertext)?;

    config.locks.push(LockConfig {
        id: id.clone(),
        lock_type: "passphrase".to_string(),
        file: format!("locks/{}.enc", id),
        fingerprint: None,
        comment: None,
        public_key: None,
        created_at: Utc::now().to_rfc3339(),
    });
    super::save_config(&agent_keys_dir, &config)?;
    println!("Passphrase lock added.");
    Ok(())
}

fn list_locks() -> Result<()> {
    let agent_keys_dir = super::find_agent_keys_dir()?;
    let config = super::load_config(&agent_keys_dir)?;
    for lock in &config.locks {
        println!("{} ({})", lock.id, lock.lock_type);
        if let Some(fp) = &lock.fingerprint {
            println!("  fingerprint: {}", fp);
        }
        if let Some(comment) = &lock.comment {
            println!("  comment: {}", comment);
        }
    }
    Ok(())
}

fn remove_lock(id: String) -> Result<()> {
    let _session = require_unlocked_session()?;
    let agent_keys_dir = super::find_agent_keys_dir()?;
    let mut config = super::load_config(&agent_keys_dir)?;

    if config.locks.len() <= 1 {
        anyhow::bail!("cannot remove the last lock. Add another lock first to avoid lockout.");
    }

    let lock = config
        .find_lock(&id)
        .ok_or_else(|| anyhow::anyhow!("lock '{}' not found", id))?;
    let lock_path = agent_keys_dir.join(&lock.file);
    if lock_path.exists() {
        std::fs::remove_file(lock_path)?;
    }
    config.remove_lock(&id);
    super::save_config(&agent_keys_dir, &config)?;
    println!("Lock '{}' removed.", id);
    Ok(())
}

fn require_unlocked_session() -> Result<Session> {
    match Session::load()? {
        Some(s) => Ok(s),
        None => anyhow::bail!("vault is locked. Run `agent-secrets unlock` first."),
    }
}

fn ssh_fingerprint(pubkey: &str) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    let hash = hasher.finalize();
    Ok(format!("SHA256:{}", BASE64.encode(&hash[..16])))
}

fn random_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect::<String>()
        .to_lowercase()
}
