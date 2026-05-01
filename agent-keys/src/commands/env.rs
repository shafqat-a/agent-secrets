use crate::session::Session;
use anyhow::Result;

pub fn run(context: Option<String>, format: String) -> Result<()> {
    let session = match Session::load()? {
        Some(s) => s,
        None => anyhow::bail!("vault is locked. Run `agent-keys unlock` first."),
    };
    let agent_keys_dir = super::find_agent_keys_dir()?;
    let config = super::load_config(&agent_keys_dir)?;
    let vault = super::load_vault(&agent_keys_dir, &config, &session)?;

    let ctx_name = super::resolve_context(context)?;
    let ctx = vault
        .get_context(&ctx_name)
        .ok_or_else(|| anyhow::anyhow!("context '{}' not found", ctx_name))?;

    match format.as_str() {
        "bash" | "sh" => {
            for (key, value) in &ctx.kv {
                println!("export {}='{}'", key, escape_shell(value));
            }
        }
        "fish" => {
            for (key, value) in &ctx.kv {
                println!("set -x {} '{}'", key, escape_shell(value));
            }
        }
        "powershell" => {
            for (key, value) in &ctx.kv {
                println!("$env:{} = '{}'", key, escape_ps(value));
            }
        }
        "json" => {
            let map: std::collections::HashMap<_, _> = ctx.kv.iter().collect();
            println!("{}", serde_json::to_string_pretty(&map)?);
        }
        "github" => {
            for (key, value) in &ctx.kv {
                println!("{}={}", key, value);
            }
        }
        _ => anyhow::bail!("unknown format: {}", format),
    }

    Ok(())
}

fn escape_shell(s: &str) -> String {
    s.replace('\'', "'\"'\"'")
}

fn escape_ps(s: &str) -> String {
    s.replace('"', "`\"").replace('\'', "''")
}
