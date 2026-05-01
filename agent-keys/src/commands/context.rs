use crate::cli::ContextCommands;
use anyhow::Result;

pub fn run(cmd: ContextCommands) -> Result<()> {
    match cmd {
        ContextCommands::List => list(),
        ContextCommands::Use { name } => use_context(&name),
        ContextCommands::Current => current(),
    }
}

fn list() -> Result<()> {
    let session = match crate::session::Session::load()? {
        Some(s) => s,
        None => anyhow::bail!("vault is locked. Run `agent-secrets unlock` first."),
    };
    let agent_keys_dir = super::find_agent_keys_dir()?;
    let config = super::load_config(&agent_keys_dir)?;
    let vault = super::load_vault(&agent_keys_dir, &config, &session)?;

    let active = super::get_active_context()?;
    println!("Contexts:");
    for name in vault.contexts.keys() {
        let marker = if name == &active { " *" } else { "" };
        println!("  {}{}", name, marker);
    }
    Ok(())
}

fn use_context(name: &str) -> Result<()> {
    super::set_active_context(name)?;
    println!("Active context set to: {}", name);
    Ok(())
}

fn current() -> Result<()> {
    let name = super::get_active_context()?;
    println!("{}", name);
    Ok(())
}
