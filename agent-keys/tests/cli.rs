use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Serializes tests that use `script` to allocate pseudo-ttys, avoiding races.
static SCRIPT_LOCK: Mutex<()> = Mutex::new(());

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_agent-secrets")
}

fn temp_dir(name: &str) -> std::io::Result<PathBuf> {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("agent-secrets-{name}-{id}"));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn command(repo: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.current_dir(repo)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", home.join(".config"));
    cmd
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_and_unlock(repo: &Path, home: &Path) -> std::io::Result<()> {
    let Some((pubkey, private_key)) = generate_ssh_key(home)? else {
        eprintln!("skipping test: ssh-keygen is unavailable");
        return Ok(());
    };

    assert_success(
        command(repo, home)
            .args(["init", "--ssh"])
            .arg(&pubkey)
            .output()?,
    );
    assert_success(
        command(repo, home)
            .args(["unlock", "--ssh-key-from-env", "AGENT_KEYS_TEST_KEY"])
            .env("AGENT_KEYS_TEST_KEY", private_key)
            .output()?,
    );
    Ok(())
}

fn generate_ssh_key(home: &Path) -> std::io::Result<Option<(PathBuf, String)>> {
    generate_ssh_key_with_passphrase(home, "")
}

fn generate_ssh_key_with_passphrase(
    home: &Path,
    passphrase: &str,
) -> std::io::Result<Option<(PathBuf, String)>> {
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir)?;
    let key_path = ssh_dir.join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-f"])
        .arg(&key_path)
        .status();

    match status {
        Ok(status) if status.success() => {
            let private_key = fs::read_to_string(&key_path)?;
            Ok(Some((key_path.with_extension("pub"), private_key)))
        }
        _ => Ok(None),
    }
}

/// Run a command under `script` to provide a pseudo-tty for rpassword prompts.
fn script_command(
    repo: &Path,
    home: &Path,
    args: &[&str],
    input: &str,
) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new("script");
    cmd.arg("-q")
        .arg("-c")
        .arg(
            std::iter::once(binary().to_string())
                .chain(args.iter().map(|s| s.to_string()))
                .collect::<Vec<_>>()
                .join(" "),
        )
        .arg("/dev/null")
        .current_dir(repo)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn()?;
    {
        use std::io::Write;
        let stdin = child.stdin.take().unwrap();
        let mut stdin = stdin;
        stdin.write_all(input.as_bytes())?;
    }
    child.wait_with_output()
}

#[test]
fn ssh_env_unlock_and_kv_roundtrip() -> std::io::Result<()> {
    let root = temp_dir("ssh-env")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "API_KEY", "--value", "secret-value"])
            .output()?,
    );
    let output = command(&repo, &home)
        .args(["kv", "get", "API_KEY", "--no-newline"])
        .output()?;
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret-value");

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn ssh_encrypted_key_unlock_and_kv_roundtrip() -> std::io::Result<()> {
    let _guard = SCRIPT_LOCK.lock().unwrap();

    let root = temp_dir("ssh-enc")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    let Some((pubkey, _private_key)) = generate_ssh_key_with_passphrase(&home, "testpass")? else {
        eprintln!("skipping test: ssh-keygen is unavailable");
        return Ok(());
    };

    assert_success(
        command(&repo, &home)
            .args(["init", "--ssh"])
            .arg(&pubkey)
            .output()?,
    );

    // Unlock interactively: script provides a tty so rpassword can read the passphrase.
    let output = script_command(&repo, &home, &["unlock"], "testpass\n")?;
    assert_success(output);

    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "API_KEY", "--value", "secret-value"])
            .output()?,
    );
    let output = command(&repo, &home)
        .args(["kv", "get", "API_KEY", "--no-newline"])
        .output()?;
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret-value");

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn ssh_env_encrypted_key_unlock() -> std::io::Result<()> {
    let _guard = SCRIPT_LOCK.lock().unwrap();

    let root = temp_dir("ssh-env-enc")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    let Some((pubkey, _private_key)) = generate_ssh_key_with_passphrase(&home, "envpass")? else {
        eprintln!("skipping test: ssh-keygen is unavailable");
        return Ok(());
    };

    assert_success(
        command(&repo, &home)
            .args(["init", "--ssh"])
            .arg(&pubkey)
            .output()?,
    );

    // Unlock via env variable; encrypted key triggers passphrase prompt.
    let output = script_command(
        &repo,
        &home,
        &["unlock", "--ssh-key-from-env", "AGENT_KEYS_TEST_KEY"],
        "envpass\n",
    )?;
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn file_write_and_read_roundtrip() -> std::io::Result<()> {
    let root = temp_dir("file")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    let source = repo.join("source.bin");
    let output = repo.join("output.bin");
    fs::write(&source, b"file-secret\nwith-two-lines")?;
    assert_success(
        command(&repo, &home)
            .args(["file", "write", "configs/source.bin"])
            .arg(&source)
            .output()?,
    );
    assert_success(
        command(&repo, &home)
            .args(["file", "read", "configs/source.bin"])
            .arg(&output)
            .output()?,
    );
    assert_eq!(fs::read(source)?, fs::read(output)?);

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn env_export_formats() -> std::io::Result<()> {
    let root = temp_dir("env")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "API_KEY", "--value", "secret123"])
            .output()?,
    );

    // Bash format
    let output = command(&repo, &home)
        .args(["env", "--format", "bash"])
        .output()?;
    assert_success(output.clone());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("export API_KEY='secret123'"),
        "bash: {}",
        stdout
    );

    // JSON format
    let output = command(&repo, &home)
        .args(["env", "--format", "json"])
        .output()?;
    assert_success(output.clone());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"API_KEY\": \"secret123\""),
        "json: {}",
        stdout
    );

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn run_injects_env_vars() -> std::io::Result<()> {
    let root = temp_dir("run")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "API_KEY", "--value", "injected"])
            .output()?,
    );

    let output = command(&repo, &home)
        .args(["run", "--", "printenv", "API_KEY"])
        .output()?;
    assert_success(output.clone());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "injected");

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn context_scoped_kv() -> std::io::Result<()> {
    let root = temp_dir("ctx")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "DB", "--context", "dev", "--value", "dev-db"])
            .output()?,
    );
    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "DB", "--context", "prod", "--value", "prod-db"])
            .output()?,
    );

    // Default context should not have DB
    let output = command(&repo, &home).args(["kv", "get", "DB"]).output()?;
    assert!(!output.status.success());

    // Read from specific contexts
    let output = command(&repo, &home)
        .args(["kv", "get", "DB", "--context", "dev", "--no-newline"])
        .output()?;
    assert_success(output.clone());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "dev-db");

    let output = command(&repo, &home)
        .args(["kv", "get", "DB", "--context", "prod", "--no-newline"])
        .output()?;
    assert_success(output.clone());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "prod-db");

    // List contexts
    let output = command(&repo, &home).args(["context", "list"]).output()?;
    assert_success(output.clone());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dev"));
    assert!(stdout.contains("prod"));

    // Set active context and read without --context
    assert_success(
        command(&repo, &home)
            .args(["context", "use", "prod"])
            .output()?,
    );
    let output = command(&repo, &home)
        .args(["kv", "get", "DB", "--no-newline"])
        .output()?;
    assert_success(output.clone());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "prod-db");

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn read_only_rejects_writes() -> std::io::Result<()> {
    let root = temp_dir("ro")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    // Close any existing session and unlock in read-only mode
    let _ = command(&repo, &home).arg("close").output();
    assert_success(
        command(&repo, &home)
            .args([
                "unlock",
                "--read",
                "--ssh-key-from-env",
                "AGENT_KEYS_TEST_KEY",
            ])
            .env(
                "AGENT_KEYS_TEST_KEY",
                fs::read_to_string(home.join(".ssh/id_ed25519"))?,
            )
            .output()?,
    );

    // Read should work
    assert_success(command(&repo, &home).args(["kv", "list"]).output()?);

    // Write should fail
    let output = command(&repo, &home)
        .args(["kv", "set", "X", "--value", "y"])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("read-only"),
        "expected read-only error, got: {}",
        stderr
    );

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn lock_add_passphrase_and_remove_ssh() -> std::io::Result<()> {
    let _guard = SCRIPT_LOCK.lock().unwrap();

    let root = temp_dir("lock-mgmt")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    // Add a passphrase lock (interactive prompt)
    let output = script_command(
        &repo,
        &home,
        &["lock", "add-passphrase"],
        "newpass\nnewpass\n",
    )?;
    assert_success(output);

    // List locks: should now have 2
    let output = command(&repo, &home).args(["lock", "list"]).output()?;
    assert_success(output.clone());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().filter(|l| l.contains("ssh-")).count(), 1);
    assert_eq!(
        stdout.lines().filter(|l| l.contains("passphrase-")).count(),
        1
    );

    // Remove the SSH lock
    let ssh_lock_id = stdout
        .lines()
        .find(|l| l.contains("ssh-"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_string();
    assert_success(
        command(&repo, &home)
            .args(["lock", "remove", &ssh_lock_id])
            .output()?,
    );

    // Verify only passphrase lock remains
    let output = command(&repo, &home).args(["lock", "list"]).output()?;
    assert_success(output.clone());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("passphrase-"));
    assert!(!stdout.contains("ssh-"));

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn rotate_rekeys_vault() -> std::io::Result<()> {
    let root = temp_dir("rotate")?;
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&home)?;

    init_and_unlock(&repo, &home)?;
    if !repo.join(".agent-keys").exists() {
        return Ok(());
    }

    assert_success(
        command(&repo, &home)
            .args(["kv", "set", "SECRET", "--value", "before-rotate"])
            .output()?,
    );

    // Rotate (should work because only SSH lock exists; public key is stored in config)
    assert_success(command(&repo, &home).arg("rotate").output()?);

    // Re-unlock and verify data survived
    assert_success(
        command(&repo, &home)
            .args(["unlock", "--ssh-key-from-env", "AGENT_KEYS_TEST_KEY"])
            .env(
                "AGENT_KEYS_TEST_KEY",
                fs::read_to_string(home.join(".ssh/id_ed25519"))?,
            )
            .output()?,
    );
    let output = command(&repo, &home)
        .args(["kv", "get", "SECRET", "--no-newline"])
        .output()?;
    assert_success(output.clone());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "before-rotate");

    let _ = fs::remove_dir_all(root);
    Ok(())
}
