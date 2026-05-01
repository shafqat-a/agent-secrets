use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod crypto;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Vault {
    pub contexts: HashMap<String, Context>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Context {
    pub kv: HashMap<String, String>,
    pub files: HashMap<String, Vec<u8>>,
}

impl Vault {
    pub fn new() -> Self {
        let mut contexts = HashMap::new();
        contexts.insert("default".to_string(), Context::default());
        Self { contexts }
    }

    pub fn get_context(&self, name: &str) -> Option<&Context> {
        self.contexts.get(name)
    }

    pub fn get_context_mut(&mut self, name: &str) -> Option<&mut Context> {
        self.contexts.get_mut(name)
    }

    pub fn ensure_context(&mut self, name: &str) -> &mut Context {
        self.contexts.entry(name.to_string()).or_default()
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(rmp_serde::from_slice(bytes)?)
    }
}

impl Context {
    pub fn get(&self, key: &str) -> Option<&String> {
        self.kv.get(key)
    }

    pub fn set(&mut self, key: String, value: String) {
        self.kv.insert(key, value);
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.kv.remove(key)
    }

    pub fn list_keys(&self) -> Vec<&String> {
        self.kv.keys().collect()
    }

    pub fn get_file(&self, path: &str) -> Option<&Vec<u8>> {
        self.files.get(path)
    }

    pub fn set_file(&mut self, path: String, data: Vec<u8>) {
        self.files.insert(path, data);
    }

    pub fn remove_file(&mut self, path: &str) -> Option<Vec<u8>> {
        self.files.remove(path)
    }

    pub fn list_files(&self) -> Vec<&String> {
        self.files.keys().collect()
    }
}
