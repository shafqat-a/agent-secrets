mod cli;
mod commands;
mod config;
mod locks;
mod machine_id;
mod session;
mod vault;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            ssh,
            passphrase,
            force,
        } => {
            commands::init::run(ssh, passphrase, force)?;
        }
        Commands::Unlock {
            read,
            ssh_key_from_env,
        } => {
            commands::unlock::run(read, ssh_key_from_env)?;
        }
        Commands::Close => {
            commands::close::run()?;
        }
        Commands::Status => {
            commands::status::run()?;
        }
        Commands::Context(sub) => {
            commands::context::run(sub)?;
        }
        Commands::Kv(sub) => {
            commands::kv::run(sub)?;
        }
        Commands::File(sub) => {
            commands::file::run(sub)?;
        }
        Commands::Run { context, command } => {
            commands::run::run(context, command)?;
        }
        Commands::Env { context, format } => {
            commands::env::run(context, format)?;
        }
        Commands::Lock(sub) => {
            commands::lock::run(sub)?;
        }
        Commands::Rotate => {
            commands::rotate::run()?;
        }
    }

    Ok(())
}
