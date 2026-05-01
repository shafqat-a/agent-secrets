use crate::session::Session;
use anyhow::Result;

pub fn run() -> Result<()> {
    match Session::load()? {
        Some(session) => {
            println!("Status: unlocked");
            println!(
                "Mode: {}",
                match session.mode {
                    crate::session::SessionMode::Read => "read-only",
                    crate::session::SessionMode::Write => "write",
                }
            );
            // Try to count secrets
            if let Ok(agent_keys_dir) = super::find_agent_keys_dir() {
                if let Ok(config) = super::load_config(&agent_keys_dir) {
                    if let Ok(vault) = super::load_vault(&agent_keys_dir, &config, &session) {
                        let ctx_count = vault.contexts.len();
                        let total_kv: usize = vault.contexts.values().map(|c| c.kv.len()).sum();
                        let total_files: usize =
                            vault.contexts.values().map(|c| c.files.len()).sum();
                        println!("Contexts: {}", ctx_count);
                        println!("Total KV pairs: {}", total_kv);
                        println!("Total files: {}", total_files);
                    }
                }
                if let Ok(config) = super::load_config(&agent_keys_dir) {
                    println!("Locks: {}", config.locks.len());
                }
            }
        }
        None => {
            println!("Status: locked");
            if let Ok(agent_keys_dir) = super::find_agent_keys_dir() {
                if let Ok(config) = super::load_config(&agent_keys_dir) {
                    println!("Locks: {}", config.locks.len());
                }
            }
        }
    }
    Ok(())
}
