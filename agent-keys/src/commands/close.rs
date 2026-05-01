use crate::session::Session;
use anyhow::Result;

pub fn run() -> Result<()> {
    if Session::exists() {
        Session::delete()?;
        println!("Vault locked. Session closed.");
    } else {
        println!("Vault is already locked.");
    }
    Ok(())
}
