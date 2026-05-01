use anyhow::{Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_machine_key(salt: &[u8]) -> Result<[u8; 32]> {
    let machine_id = get_machine_id()?;
    let username = get_username()?;
    let home_dir = get_home_dir()?;

    let ikm = format!("{}:{}:{}", machine_id, username, home_dir);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(b"agent-secrets-session", &mut okm)
        .map_err(|e| anyhow::anyhow!("hkdf expand failed: {:?}", e))?;
    Ok(okm)
}

fn get_machine_id() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        let id =
            std::fs::read_to_string("/etc/machine-id").context("failed to read /etc/machine-id")?;
        Ok(id.trim().to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .context("failed to run ioreg")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                let parts: Vec<&str> = line.split('"').collect();
                if parts.len() >= 4 {
                    return Ok(parts[3].to_string());
                }
            }
        }
        anyhow::bail!("could not find IOPlatformUUID")
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("reg")
            .args([
                "query",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .context("failed to query registry")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("MachineGuid") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(guid) = parts.last() {
                    return Ok(guid.to_string());
                }
            }
        }
        anyhow::bail!("could not find MachineGuid")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("unsupported platform for machine ID")
    }
}

fn get_username() -> Result<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .context("could not determine username")
}

fn get_home_dir() -> Result<String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("could not determine home directory")
}
