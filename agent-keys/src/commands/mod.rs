pub mod close;
pub mod context;
pub mod env;
pub mod file;
pub mod init;
pub mod kv;
pub mod lock;
pub mod rotate;
pub mod run;
pub mod status;
pub mod unlock;

use crate::config::Config;
use crate::session::Session;
use crate::vault::crypto::{decode_vault_blob, decrypt, encode_vault_blob, encrypt};
use crate::vault::Vault;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::path::{Path, PathBuf};

pub fn find_agent_keys_dir() -> Result<PathBuf> {
    let current = std::env::current_dir()?;
    let candidate = current.join(".agent-keys");
    if candidate.exists() {
        return Ok(candidate);
    }
    anyhow::bail!(
        "no .agent-keys directory found in current directory. Run `agent-keys init` first."
    );
}

pub fn load_config(agent_keys_dir: &Path) -> Result<Config> {
    let path = agent_keys_dir.join("config.toml");
    Config::load(path)
}

pub fn save_config(agent_keys_dir: &Path, config: &Config) -> Result<()> {
    let path = agent_keys_dir.join("config.toml");
    config.save(path)
}

pub fn load_vault(agent_keys_dir: &Path, config: &Config, session: &Session) -> Result<Vault> {
    let vault_path = agent_keys_dir.join(&config.vault);
    let vault_content = std::fs::read_to_string(&vault_path)
        .with_context(|| format!("failed to read vault file: {}", vault_path.display()))?;
    let vault_bytes = BASE64
        .decode(vault_content.trim())
        .context("vault file is not valid base64")?;
    let blob = decode_vault_blob(&vault_bytes)?;
    let plaintext = decrypt(&blob, &session.master_key)
        .context("failed to decrypt vault (corrupted or wrong master key)")?;
    Vault::from_bytes(&plaintext)
}

pub fn save_vault(
    agent_keys_dir: &Path,
    config: &Config,
    vault: &Vault,
    session: &Session,
) -> Result<()> {
    session.require_write()?;
    let vault_path = agent_keys_dir.join(&config.vault);
    let plaintext = vault.to_bytes()?;
    let blob = encrypt(&plaintext, &session.master_key)?;
    let vault_b64 = BASE64.encode(encode_vault_blob(&blob));
    // Write atomically using a temp file
    let temp_path = vault_path.with_extension("tmp");
    std::fs::write(&temp_path, vault_b64)?;
    std::fs::rename(&temp_path, &vault_path)?;
    Ok(())
}

pub fn get_active_context() -> Result<String> {
    let dirs = directories::ProjectDirs::from("", "", "agent-keys")
        .context("could not determine config directory")?;
    let pref_path = dirs.config_local_dir().join("active_context");
    if pref_path.exists() {
        let name = std::fs::read_to_string(&pref_path)?;
        Ok(name.trim().to_string())
    } else {
        Ok("default".to_string())
    }
}

pub fn set_active_context(name: &str) -> Result<()> {
    let dirs = directories::ProjectDirs::from("", "", "agent-keys")
        .context("could not determine config directory")?;
    let pref_path = dirs.config_local_dir().join("active_context");
    if let Some(parent) = pref_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&pref_path, name)?;
    Ok(())
}

pub fn resolve_context(cli_context: Option<String>) -> Result<String> {
    match cli_context {
        Some(ctx) => Ok(ctx),
        None => get_active_context(),
    }
}
