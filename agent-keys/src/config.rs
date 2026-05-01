use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub version: u32,
    pub vault: String,
    pub locks: Vec<LockConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LockConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub lock_type: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub created_at: String,
}

impl Config {
    pub fn new(vault: String) -> Self {
        Self {
            version: 1,
            vault,
            locks: Vec::new(),
        }
    }

    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config: {}", path.as_ref().display()))?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn find_lock(&self, id: &str) -> Option<&LockConfig> {
        self.locks.iter().find(|l| l.id == id)
    }

    pub fn remove_lock(&mut self, id: &str) -> bool {
        let before = self.locks.len();
        self.locks.retain(|l| l.id != id);
        self.locks.len() < before
    }
}
