use crate::locks::passphrase::PassphraseLock;
use crate::locks::ssh::SshLock;
use crate::session::{Session, SessionMode};
use anyhow::Result;
use rand::RngCore;

pub fn run() -> Result<()> {
    let session = match Session::load()? {
        Some(s) => s,
        None => anyhow::bail!("vault is locked. Run `agent-secrets unlock` first."),
    };
    session.require_write()?;

    let agent_keys_dir = super::find_agent_keys_dir()?;
    let config = super::load_config(&agent_keys_dir)?;
    let vault = super::load_vault(&agent_keys_dir, &config, &session)?;

    // Generate new master key
    let mut new_master_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_master_key);

    // Re-encrypt all lock files before replacing the vault key.
    for lock_config in &config.locks {
        let lock_path = agent_keys_dir.join(&lock_config.file);
        match lock_config.lock_type.as_str() {
            "ssh" => {
                let pubkey = lock_config.public_key.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot rotate SSH lock '{}' because its public key is missing; remove and re-add this lock first",
                        lock_config.id
                    )
                })?;
                let lock = SshLock::new(lock_config.id.clone(), pubkey.clone());
                std::fs::write(lock_path, lock.encrypt_master_key(&new_master_key)?)?;
            }
            "passphrase" => {
                let passphrase = rpassword::prompt_password(format!(
                    "Passphrase for lock '{}': ",
                    lock_config.id
                ))?;
                let lock = PassphraseLock::new(lock_config.id.clone(), passphrase);
                std::fs::write(lock_path, lock.encrypt_master_key(&new_master_key)?)?;
            }
            other => anyhow::bail!("unknown lock type '{}' for {}", other, lock_config.id),
        }
    }

    let new_session = Session::new(new_master_key, SessionMode::Write);
    super::save_vault(&agent_keys_dir, &config, &vault, &new_session)?;
    new_session.save()?;

    println!("Master key rotated.");
    Ok(())
}
