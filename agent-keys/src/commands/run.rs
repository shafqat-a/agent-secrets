use crate::session::Session;
use anyhow::{Context, Result};

pub fn run(context: Option<String>, command: Vec<String>) -> Result<()> {
    let session = match Session::load()? {
        Some(s) => s,
        None => {
            super::unlock::run(true, None)?;
            Session::load()?.ok_or_else(|| anyhow::anyhow!("failed to create session"))?
        }
    };
    let agent_secrets_dir = super::find_agent_secrets_dir()?;
    let config = super::load_config(&agent_secrets_dir)?;
    let vault = super::load_vault(&agent_secrets_dir, &config, &session)?;

    let ctx_name = super::resolve_context(context)?;
    let ctx = vault
        .get_context(&ctx_name)
        .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;

    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Inject env vars
    for (key, value) in &ctx.kv {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().context("failed to spawn command")?;
    let status = child.wait().context("failed to wait for command")?;

    if !status.success() {
        anyhow::bail!("command exited with status: {}", status);
    }

    Ok(())
}
