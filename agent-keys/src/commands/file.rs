use crate::cli::FileCommands;
use crate::session::Session;
use anyhow::{Context, Result};

pub fn run(cmd: FileCommands) -> Result<()> {
    let session = match Session::load()? {
        Some(s) => s,
        None => anyhow::bail!("vault is locked. Run `agent-secrets unlock` first."),
    };
    let agent_secrets_dir = super::find_agent_secrets_dir()?;
    let config = super::load_config(&agent_secrets_dir)?;
    let mut vault = super::load_vault(&agent_secrets_dir, &config, &session)?;

    match cmd {
        FileCommands::Read {
            vault_path,
            local_path,
            context,
        } => {
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault
                .get_context(&ctx_name)
                .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;
            let data = ctx.get_file(&vault_path).ok_or_else(|| {
                anyhow::anyhow!("file '{}' not found in context '{}'", vault_path, ctx_name)
            })?;
            match local_path {
                Some(path) => {
                    std::fs::write(&path, data)
                        .with_context(|| format!("failed to write file: {}", path))?;
                    println!("File written to: {}", path);
                }
                None => {
                    use std::io::Write;
                    std::io::stdout().write_all(data)?;
                }
            }
        }
        FileCommands::Write {
            vault_path,
            local_path,
            context,
        } => {
            session.require_write()?;
            let data = std::fs::read(&local_path)
                .with_context(|| format!("failed to read file: {}", local_path))?;
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault.ensure_context(&ctx_name);
            ctx.set_file(vault_path, data);
            super::save_vault(&agent_secrets_dir, &config, &vault, &session)?;
            println!("File stored in vault.");
        }
        FileCommands::Remove {
            vault_path,
            context,
        } => {
            session.require_write()?;
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault
                .get_context_mut(&ctx_name)
                .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;
            if ctx.remove_file(&vault_path).is_some() {
                super::save_vault(&agent_secrets_dir, &config, &vault, &session)?;
                println!("File removed.");
            } else {
                anyhow::bail!("file '{}' not found in context '{}'", vault_path, ctx_name);
            }
        }
        FileCommands::List { context } => {
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault
                .get_context(&ctx_name)
                .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;
            for path in ctx.list_files() {
                println!("{}", path);
            }
        }
    }

    Ok(())
}
