use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agent-keys")]
#[command(about = "A cross-platform secrets manager with SSH and passphrase unlock")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault in the current repository
    Init {
        #[arg(long)]
        ssh: Vec<String>,
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        force: bool,
    },
    /// Unlock the vault and create a session
    Unlock {
        #[arg(long)]
        read: bool,
        #[arg(long = "ssh-key-from-env")]
        ssh_key_from_env: Option<String>,
    },
    /// Close the session and lock the vault
    Close,
    /// Show vault status
    Status,
    /// Manage contexts
    #[command(subcommand)]
    Context(ContextCommands),
    /// Manage key-value secrets
    #[command(subcommand)]
    Kv(KvCommands),
    /// Manage files in the vault
    #[command(subcommand)]
    File(FileCommands),
    /// Run a command with secrets as environment variables
    Run {
        #[arg(long)]
        context: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Print secrets as shell export statements
    Env {
        #[arg(long)]
        context: Option<String>,
        #[arg(long, default_value = "bash")]
        format: String,
    },
    /// Manage locks
    #[command(subcommand)]
    Lock(LockCommands),
    /// Rotate the master key
    Rotate,
}

#[derive(Subcommand)]
pub enum ContextCommands {
    /// List all contexts
    List,
    /// Set the active context
    Use { name: String },
    /// Show the current active context
    Current,
}

#[derive(Subcommand)]
pub enum KvCommands {
    /// Get a secret value
    Get {
        key: String,
        #[arg(long)]
        context: Option<String>,
        #[arg(long)]
        no_newline: bool,
    },
    /// Set a secret value
    Set {
        key: String,
        #[arg(long)]
        value: Option<String>,
        #[arg(long)]
        from_stdin: bool,
        #[arg(long)]
        context: Option<String>,
    },
    /// Remove a secret
    Remove {
        key: String,
        #[arg(long)]
        context: Option<String>,
    },
    /// List all keys
    List {
        #[arg(long)]
        context: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum FileCommands {
    /// Read a file from the vault
    Read {
        vault_path: String,
        local_path: Option<String>,
        #[arg(long)]
        context: Option<String>,
    },
    /// Write a local file into the vault
    Write {
        vault_path: String,
        local_path: String,
        #[arg(long)]
        context: Option<String>,
    },
    /// Remove a file from the vault
    Remove {
        vault_path: String,
        #[arg(long)]
        context: Option<String>,
    },
    /// List all files
    List {
        #[arg(long)]
        context: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum LockCommands {
    /// Add an SSH public key lock
    AddSsh { pubkey_path: String },
    /// Add a passphrase lock
    AddPassphrase,
    /// List all locks
    List,
    /// Remove a lock by ID
    Remove { id: String },
}
