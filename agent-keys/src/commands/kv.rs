use crate::cli::KvCommands;
use crate::session::Session;
use anyhow::Result;
use std::io::Read;

pub fn run(cmd: KvCommands) -> Result<()> {
    let session = match Session::load()? {
        Some(s) => s,
        None => anyhow::bail!("vault is locked. Run `agent-secrets unlock` first."),
    };
    let agent_secrets_dir = super::find_agent_secrets_dir()?;
    let config = super::load_config(&agent_secrets_dir)?;
    let mut vault = super::load_vault(&agent_secrets_dir, &config, &session)?;

    match cmd {
        KvCommands::Get {
            key,
            context,
            no_newline,
        } => {
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault
                .get_context(&ctx_name)
                .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;
            match ctx.get(&key) {
                Some(value) => {
                    if no_newline {
                        print!("{}", value);
                    } else {
                        println!("{}", value);
                    }
                }
                None => anyhow::bail!("key '{}' not found in context '{}'", key, ctx_name),
            }
        }
        KvCommands::Set {
            key,
            value,
            from_stdin,
            context,
        } => {
            session.require_write()?;
            let value = if from_stdin {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf.trim_end().to_string()
            } else if let Some(v) = value {
                v
            } else {
                rpassword::prompt_password("Enter value: ")?
            };
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault.ensure_context(&ctx_name);
            ctx.set(key, value);
            super::save_vault(&agent_secrets_dir, &config, &vault, &session)?;
            println!("Secret set.");
        }
        KvCommands::Remove { key, context } => {
            session.require_write()?;
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault
                .get_context_mut(&ctx_name)
                .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;
            if ctx.remove(&key).is_some() {
                super::save_vault(&agent_secrets_dir, &config, &vault, &session)?;
                println!("Secret removed.");
            } else {
                anyhow::bail!("key '{}' not found in context '{}'", key, ctx_name);
            }
        }
        KvCommands::List { context } => {
            let ctx_name = super::resolve_context(context)?;
            let ctx = vault
                .get_context(&ctx_name)
                .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;
            for key in ctx.list_keys() {
                println!("{}", key);
            }
        }
    }

    Ok(())
}
