use crate::config::{Config, LockConfig};
use crate::locks::passphrase::PassphraseLock;
use crate::locks::ssh::SshLock;
use crate::vault::Vault;
use anyhow::{Context, Result};
use chrono::Utc;
use directories::UserDirs;
use rand::RngCore;
use std::path::PathBuf;
use zeroize::Zeroize;

pub fn run(ssh_paths: Vec<String>, passphrase: bool, force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let agent_secrets_dir = cwd.join(".agent-secrets");

    if agent_secrets_dir.exists() && !force {
        anyhow::bail!(".agent-secrets already exists. Use --force to overwrite.");
    }

    if agent_secrets_dir.exists() {
        std::fs::remove_dir_all(&agent_secrets_dir)?;
    }
    std::fs::create_dir_all(agent_secrets_dir.join("locks"))?;

    // Generate master key
    let mut master_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_key);

    let mut config = Config::new("vault.vlt".to_string());
    let vault = Vault::new();

    // SSH locks
    if ssh_paths.is_empty() {
        // Auto-detect SSH keys
        let ssh_dir = UserDirs::new()
            .map(|dirs| dirs.home_dir().join(".ssh"))
            .unwrap_or_default();
        let mut candidates = Vec::new();
        for name in ["id_ed25519.pub", "id_rsa.pub"] {
            let path = ssh_dir.join(name);
            if path.exists() {
                candidates.push(path);
            }
        }
        for path in select_ssh_keys(candidates)? {
            let pubkey = std::fs::read_to_string(&path)?;
            add_ssh_lock(
                &mut config,
                &master_key,
                pubkey.trim(),
                &path.display().to_string(),
            )?;
        }
    } else {
        for path in &ssh_paths {
            let pubkey = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read SSH pubkey: {}", path))?;
            add_ssh_lock(&mut config, &master_key, pubkey.trim(), path)?;
        }
    }

    // Passphrase lock
    if passphrase {
        let pass = rpassword::prompt_password("Enter a strong passphrase for vault unlock: ")?;
        let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
        if pass != confirm {
            anyhow::bail!("passphrases do not match");
        }
        let id = format!("passphrase-{}", random_id());
        let lock = PassphraseLock::new(id.clone(), pass);
        let ciphertext = lock.encrypt_master_key(&master_key)?;
        let lock_path = agent_secrets_dir.join("locks").join(format!("{}.enc", id));
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
    }

    if config.locks.is_empty() {
        anyhow::bail!("no locks configured. Add at least one SSH key or use --passphrase.");
    }

    // Save config
    config.save(agent_secrets_dir.join("config.toml"))?;

    // Save empty vault (encrypted)
    use crate::vault::crypto::encrypt;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let vault_bytes = vault.to_bytes()?;
    let blob = encrypt(&vault_bytes, &master_key)?;
    let vault_b64 = BASE64.encode(crate::vault::crypto::encode_vault_blob(&blob));
    std::fs::write(agent_secrets_dir.join("vault.vlt"), vault_b64)?;
    master_key.zeroize();

    println!(
        "Initialized .agent-secrets/ with {} lock(s).",
        config.locks.len()
    );
    Ok(())
}

fn select_ssh_keys(candidates: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    match candidates.len() {
        0 => Ok(Vec::new()),
        1 => {
            println!("Detected SSH public key:");
            println!("  1) {}", candidates[0].display());
            println!("Use this key? [Y/n]");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            match input.trim().to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => Ok(candidates),
                _ => Ok(Vec::new()),
            }
        }
        _ => {
            println!("Detected SSH public keys:");
            for (i, path) in candidates.iter().enumerate() {
                println!("  {}) {}", i + 1, path.display());
            }
            println!("Select keys to use (comma-separated numbers, 'all', or 'none'):");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let choice = input.trim().to_ascii_lowercase();
            if choice == "all" || choice.is_empty() {
                return Ok(candidates);
            }
            if choice == "none" || choice == "n" {
                return Ok(Vec::new());
            }

            let mut selected = Vec::new();
            for part in choice.split(',') {
                let idx: usize = part.trim().parse().context("invalid SSH key selection")?;
                let path = candidates
                    .get(idx.checked_sub(1).context("invalid SSH key selection")?)
                    .context("invalid SSH key selection")?;
                selected.push(path.clone());
            }
            Ok(selected)
        }
    }
}

fn add_ssh_lock(
    config: &mut Config,
    master_key: &[u8; 32],
    pubkey: &str,
    source: &str,
) -> Result<()> {
    let fingerprint = ssh_fingerprint(pubkey)?;
    let id = format!(
        "ssh-{}",
        &fingerprint
            .replace(":", "")
            .replace("SHA256:", "")
            .replace('/', "-")[..8]
    );
    let lock = SshLock::new(id.clone(), pubkey.to_string());
    let ciphertext = lock.encrypt_master_key(master_key)?;
    let lock_filename = format!("{}.enc", id);
    let agent_secrets_dir = std::env::current_dir()?.join(".agent-secrets");
    let lock_path = agent_secrets_dir.join("locks").join(&lock_filename);
    std::fs::write(&lock_path, ciphertext)
        .with_context(|| format!("failed to write lock file: {}", lock_path.display()))?;
    config.locks.push(LockConfig {
        id,
        lock_type: "ssh".to_string(),
        file: format!("locks/{}", lock_filename),
        fingerprint: Some(fingerprint),
        comment: Some(source.to_string()),
        public_key: Some(pubkey.to_string()),
        created_at: Utc::now().to_rfc3339(),
    });
    Ok(())
}

fn ssh_fingerprint(pubkey: &str) -> Result<String> {
    // Simple hash-based fingerprint
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
