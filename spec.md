# Agent Keys — Specification

## 1. Overview

**Agent Keys** is a cross-platform secrets manager written in Rust. It stores API keys, passwords, credentials, and small files in an encrypted vault that can be safely committed to a public Git repository. The vault is unlocked via SSH keys or a passphrase.

### Goals
- Commit secrets to public Git repos without exposing credentials
- Unlock on any machine using an SSH key or a passphrase
- Run seamlessly on macOS, Windows, and Linux
- Zero external runtime dependencies (single static binary)
- Organize secrets into environments (contexts) like `dev`, `staging`, and `prod`

---

## 2. Security Model

### Threat Model
| Scenario | Protection |
|----------|------------|
| Vault file leaked / in public repo | Encrypted with AES-256-GCM; useless without the master key |
| Laptop stolen | Vault locked; no plaintext secrets on disk |
| Attacker modifies vault file | AEAD authentication detects tampering |
| Memory dump during runtime | `zeroize` clears key material from RAM after use |
| Session file copied to another machine | Encrypted with a machine-derived key; unreadable elsewhere |
| Insider leaves team | Remove their lock file; they can no longer decrypt |

### Encryption Architecture (Layered)

```
┌─────────────────────────────────────┐
│  Vault (vault.vlt)                  │
│  Secrets encrypted with Master Key  │
│  (AES-256-GCM)                      │
└─────────────────────────────────────┘
                   ▲
                   │ decrypts
┌─────────────────────────────────────┐
│  Master Key (32 random bytes)       │
│  Stored only in memory at runtime   │
└─────────────────────────────────────┘
                   ▲
         ┌────────┴────────┐
         │                 │
┌──────────────┐  ┌─────────────────┐
│ Lock: SSH    │  │ Lock: Passphrase│
│ ssh-abc.enc  │  │ passphrase-xyz  │
│ Master key   │  │ .enc            │
│ encrypted to │  │ Master key      │
│ SSH pubkey   │  │ encrypted with  │
│ via age      │  │ Argon2+AES-GCM  │
└──────────────┘  └─────────────────┘
```

**Why layered?**
- Add or remove authentication methods without re-encrypting the entire vault
- Support multiple users/keys unlocking the same vault
- A lost SSH key does not mean a lost vault if a passphrase lock also exists

---

## 3. File Format

### Repository Structure
```
repo/
├── .agent-secrets/
│   ├── config.toml              # Public metadata
│   ├── vault.vlt                # Base64-encoded encrypted vault
│   └── locks/
│       ├── ssh-abc123.enc       # Master key encrypted to SSH pubkey
│       └── passphrase-xyz.enc   # Master key encrypted to passphrase
```

All files in `.agent-secrets/` are safe to commit to a public repository.

### `config.toml` (Public)
```toml
version = 1
vault = "vault.vlt"

[[locks]]
id = "ssh-abc123"
type = "ssh"
file = "locks/ssh-abc123.enc"
fingerprint = "SHA256:abcd..."
comment = "shafqat@macbook-pro"
created_at = "2026-04-30T00:00:00Z"

[[locks]]
id = "passphrase-xyz"
type = "passphrase"
file = "locks/passphrase-xyz.enc"
created_at = "2026-04-30T00:00:00Z"
```

### `vault.vlt` (Encrypted)
The file is **base64-encoded text** (not raw binary).

Underlying binary format:
```
[4 bytes]   Magic: "AGKY"
[1 byte]    Version: 0x01
[16 bytes]  Nonce
[N bytes]   Ciphertext (AES-256-GCM)
[16 bytes]  Authentication tag
```

Plaintext payload (before encryption) is a structured document containing **contexts**. Each context holds:
- A key-value store (`HashMap<String, String>`)
- A file store (`HashMap<Path, Bytes>`)

Example logical structure:
```
default/
  kv/
    LOCAL_API_KEY = "local-..."
dev/
  kv/
    DATABASE_URL = "postgres://dev/..."
  files/
    config/app.yml = <binary data>
prod/
  kv/
    DATABASE_URL = "postgres://prod/..."
  files/
    certs/tls.crt = <binary data>
```

### Lock Files

#### SSH Lock (`locks/ssh-<fp>.enc`)
- Uses the `age` encryption format with an SSH public key as recipient
- The plaintext of the lock file is the 32-byte master key (binary)
- Supports OpenSSH Ed25519 and RSA (4096+) public keys

#### Passphrase Lock (`locks/passphrase-<id>.enc`)
- Uses Argon2id to derive a 256-bit key from the user's passphrase
- Salt (32 bytes) is stored in the lock file header
- The master key is encrypted with the derived key via AES-256-GCM
- Format:
  ```
  [4 bytes]  Magic: "AGLP"
  [1 byte]   Version: 0x01
  [1 byte]   Type: 0x03 (passphrase)
  [32 bytes] Salt
  [N bytes]  Ciphertext (AES-256-GCM)
  ```

---

## 4. Contexts

Contexts are **organizational namespaces** inside a single vault. They are not security boundaries — anyone who unlocks the vault can access any context. Use **separate vaults** if you need true isolation (e.g., interns vs. production).

### Default Context
If no context is specified, the `default` context is used.

### Context Commands
```bash
agent-secrets context list              # Show all contexts in the vault
agent-secrets context use prod          # Set active context for this session
agent-secrets context current           # Print the active context name
```

### Scoped Commands
```bash
agent-secrets kv get DATABASE_URL              # Uses active context
agent-secrets kv get DATABASE_URL --context dev  # Override for one command
agent-secrets file read certs/tls.crt --context prod
```

---

## 5. Session Management

### Session File
When the vault is unlocked, an encrypted session file is written to the platform cache directory:
- **macOS:** `~/Library/Caches/agent-secrets/session`
- **Linux:** `~/.cache/agent-secrets/session`
- **Windows:** `%LOCALAPPDATA%\agent-secrets\session`

The session file contains the **master key encrypted with a machine-derived key**.

#### Machine Key Derivation
```
session_key = HKDF-SHA256(
    secret = machine_id + username + home_directory_path,
    salt   = random_salt_from_session_file_header
)
```

| Platform | Machine ID Source |
|----------|-------------------|
| Linux | `/etc/machine-id` |
| macOS | `IOPlatformUUID` |
| Windows | `MachineGuid` registry key |

**Properties:**
- Survives reboots (file stays on disk).
- Unreadable on a different machine or user account.
- If hardware/OS changes enough to break the machine ID, the session file fails to decrypt and the user is prompted to authenticate normally.
- **Explicitly deleted** when `agent-secrets close` is run.

### Session Modes
The session file includes a mode flag:
- **`read`**: Vault is decrypted in memory. KV and files can be read. Write operations are rejected.
- **`write`**: Vault is decrypted in memory. Full read and write access is allowed.

This is a **safety switch**, not a cryptographic boundary. The same lock (SSH or passphrase) unlocks both modes. The user chooses the mode at unlock time.

---

## 6. Commands

### Core Commands

#### `agent-secrets init`
Initialize a new vault in the current repository.
- Detects SSH public keys in `~/.ssh/` (id_ed25519.pub, id_rsa.pub)
- Prompts user to select which key(s) to use
- Prompts for an optional passphrase lock
- Generates a random 32-byte master key
- Creates `.agent-secrets/` directory with config, vault, and initial lock file(s)
- Vault starts with a single empty `default` context

**Options:**
```
--ssh <path>        Specify SSH public key(s) to use
--passphrase        Also add a passphrase lock during init
--force             Overwrite existing vault
```

#### `agent-secrets unlock [--read]`
Unlock the vault and create the session file.
- Prompts for authentication method if multiple locks exist
- `--read` opens the vault in read-only safety mode
- Session survives until `close` is called

#### `agent-secrets close`
Delete the session file and lock the vault.
- Subsequent commands will require authentication again

#### `agent-secrets status`
Show vault status: locked/unlocked, mode (read/write), active context, number of secrets, number of locks.

#### `agent-secrets kv get <KEY>`
Retrieve and print a single secret value.
- Uses active context unless `--context` is provided
- Prints raw value to stdout

**Options:**
```
--context <name>    Read from a specific context
--no-newline        Print without trailing newline
```

#### `agent-secrets kv set <KEY>`
Add or update a secret.
- Prompts for value (hidden input)
- Encrypts into vault and atomically rewrites `vault.vlt`

**Options:**
```
--value <value>     Provide value via flag (useful for scripts)
--from-stdin        Read value from stdin
--context <name>    Write to a specific context (creates if missing)
```

#### `agent-secrets kv remove <KEY>`
Remove a secret from the active context.

#### `agent-secrets kv list`
List all keys in the active context without revealing values.

#### `agent-secrets file write <VAULT-PATH> <LOCAL-PATH>`
Write a local file into the vault.
- Example: `agent-secrets file write prod/certs/tls.crt ./tls.crt`

#### `agent-secrets file read <VAULT-PATH> [LOCAL-PATH]`
Read a file from the vault.
- If `LOCAL-PATH` is omitted, prints raw bytes to stdout
- If `LOCAL-PATH` is provided, writes the file to disk

#### `agent-secrets file remove <VAULT-PATH>`
Remove a file from the vault.

#### `agent-secrets file list`
List all file paths stored in the active context.

#### `agent-secrets run -- <COMMAND...>`
Run a command with secrets injected as environment variables.
- Unlocks vault (or uses session)
- Sets all KV secrets from the active context as env vars (keys are prefixed if configured)
- Spawns child process
- Clears master key from memory before handing control to child

**Example:**
```bash
agent-secrets run -- python app.py
agent-secrets run --context prod -- npm start
```

#### `agent-secrets env`
Print secrets as shell export statements.

**Example:**
```bash
eval $(agent-secrets env)
```

**Options:**
```
--context <name>    Export from a specific context
--format <shell>    Output format: bash, fish, powershell, json
```

### Context Commands

#### `agent-secrets context list`
List all contexts in the vault.

#### `agent-secrets context use <NAME>`
Set the active context for the current session. The context name is stored in a local preference file (not the vault), so different terminals can use different contexts simultaneously.

#### `agent-secrets context current`
Print the currently active context name.

### Lock Management

#### `agent-secrets lock add-ssh <PUBKEY>`
Add a new SSH public key as an unlock method.

#### `agent-secrets lock add-passphrase`
Add a passphrase lock.
- Prompts for a strong passphrase
- Generates Argon2id parameters and salt
- Creates new lock file

#### `agent-secrets lock list`
List all registered unlock methods.

#### `agent-secrets lock remove <ID>`
Remove an unlock method by its ID.
- Requires vault to be unlocked
- **Prevents removal of the last lock** (to avoid lockout)

### Utility Commands

#### `agent-secrets rotate`
Generate a new master key and re-encrypt the vault.
- Re-encrypts all lock files with the new master key
- Useful if a lock file may have been compromised

---

## 7. Cross-Platform Support

### Supported Platforms
| OS | Architecture | Status |
|----|-------------|--------|
| macOS | x86_64, Apple Silicon (arm64) | Primary |
| Linux | x86_64, arm64 | Primary |
| Windows | x86_64 | Primary |

### Platform-Specific Details

#### SSH Key Discovery
| Platform | Default SSH Directory |
|----------|----------------------|
| macOS / Linux | `~/.ssh/` |
| Windows | `%USERPROFILE%\.ssh\` |

#### Configuration & Cache Directories
| Platform | Config | Cache (session file) |
|----------|--------|---------------------|
| macOS | `~/Library/Application Support/agent-secrets/` | `~/Library/Caches/agent-secrets/` |
| Linux | `~/.config/agent-secrets/` | `~/.cache/agent-secrets/` |
| Windows | `%APPDATA%\agent-secrets\` | `%LOCALAPPDATA%\agent-secrets\` |

#### Session Machine ID Sources
| Platform | Source |
|----------|--------|
| Linux | `/etc/machine-id` |
| macOS | `IOPlatformUUID` |
| Windows | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid` |

---

## 8. Tech Stack

| Component | Crate | Version |
|-----------|-------|---------|
| CLI framework | `clap` | ^4.x |
| SSH-age encryption | `age` (with `ssh` feature) | ^0.11 |
| Symmetric encryption | `aes-gcm` | ^0.10 |
| KDF / hashing | `argon2`, `hkdf`, `sha2` | latest |
| SSH key parsing | `ssh-key` | ^0.6 |
| Serialization | `serde` + `rmp-serde` (MessagePack) | ^1.x / ^1.x |
| Cross-platform dirs | `directories` | ^5.x |
| Secure input | `rpassword` | ^7.x |
| Memory zeroization | `zeroize` | ^1.x |
| Error handling | `thiserror` | ^1.x |

---

## 9. CI / CD Integration

For GitHub Actions and other CI environments:

```yaml
- name: Unlock secrets
  env:
    AGENT_SECRETS_SSH_KEY: ${{ secrets.DEPLOY_KEY }}
  run: |
    agent-secrets unlock --ssh-key-from-env AGENT_SECRETS_SSH_KEY
    agent-secrets env --format github >> "$GITHUB_ENV"
```

Or pipe directly:
```bash
agent-secrets env --format bash >> .env
```

---

## 10. Design Principles

1. **Public by default** — The vault and lock files are designed to be committed. No `.gitignore` required.
2. **Always locked on disk** — The `.vlt` file is never written as plaintext. Decryption happens only in RAM at runtime.
3. **Use existing credentials** — Leverage SSH keys users already have. Passphrase is available as a fallback.
4. **Fail closed** — Any error during unlock leaves the vault locked. No partial decryption.
5. **Memory hygiene** — Clear key material as soon as possible. Never write plaintext secrets to disk.
6. **Unix philosophy** — Compose with shell pipes and env var injection. Don't replace your shell.
7. **Contexts over roles** — Organize secrets by environment, not by user permissions. Keep access control simple.

---

*Version: 2.0*
*Last updated: 2026-04-30*
