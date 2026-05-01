# Agent Keys

Agent Keys is a Rust command-line secrets manager for projects that need to keep API keys, passwords, certificates, service credentials, and small private files close to the code that uses them without exposing those secrets in Git. It stores secrets in an encrypted vault under `.agent-keys/`, and the encrypted files are designed to be safe to commit to a public or private repository.

The core idea is simple:

- your repository contains only encrypted vault data and encrypted lock files;
- your machine unlocks the vault with an SSH key or passphrase;
- commands can read secrets, write secrets, export them as environment variables, or inject them into a child process;
- teams can add and remove unlock methods without re-encrypting every stored secret by hand.

Agent Keys is especially useful for local development, Docker-based application launches, and Kubernetes deployment pipelines where you want a clear source of truth for encrypted project secrets while still controlling when and where plaintext values appear.

> Status: this project is early. The CLI builds and has coverage for the main SSH unlock, key-value, and file round trips, but you should still review the security model and operational workflow before using it for production secrets.

---

## Table of Contents

1. [Why Agent Keys Exists](#why-agent-secrets-exists)
2. [Security Model](#security-model)
3. [Repository Layout](#repository-layout)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Core Commands](#core-commands)
7. [Contexts](#contexts)
8. [Docker Usage](#docker-usage)
9. [Docker Compose Usage](#docker-compose-usage)
10. [Kubernetes Usage](#kubernetes-usage)
11. [CI/CD Usage](#cicd-usage)
12. [Team Workflows](#team-workflows)
13. [Operational Guidance](#operational-guidance)
14. [Troubleshooting](#troubleshooting)
15. [Development](#development)
16. [Roadmap](#roadmap)

---

## Why Agent Keys Exists

Most application projects eventually need secrets:

- database URLs;
- cloud provider keys;
- API tokens;
- webhook signing secrets;
- TLS certificates;
- application encryption keys;
- service account files;
- small config files that contain credentials.

The usual approaches all have tradeoffs.

`.env` files are easy, but they are plaintext. They are often copied between machines manually, pasted into chat, or accidentally committed.

Cloud secret managers are strong, but they add a remote dependency. They also make local development harder when a developer is offline or does not have cloud permissions yet.

Kubernetes Secrets are useful for cluster injection, but the YAML payload is only base64 encoded unless you add encryption and access-control layers around it.

Password managers are good for human workflows, but awkward for shell pipelines, Docker, Kubernetes, and reproducible local setup.

Agent Keys takes a different approach: keep the encrypted secret bundle in the repository, but keep the ability to decrypt it outside the repository. The vault can move with the code. The unlock key stays with the developer, CI runner, or deployment system.

This is not a replacement for every enterprise secret-management system. It is a project-local encrypted vault that works well when:

- developers need a shared set of local development secrets;
- a repository needs encrypted non-production credentials;
- CI needs to decrypt secrets during a build or deploy;
- Docker containers need environment variables at runtime;
- Kubernetes manifests or generated Secret objects need to be built from an encrypted source;
- teams want encrypted secret changes to go through pull requests.

---

## Security Model

Agent Keys uses a layered encryption model.

The vault file stores your actual secret data. It is encrypted with a random 32-byte master key. The master key is not committed directly. Instead, the master key is encrypted into one or more lock files.

Supported lock types:

- SSH locks: the master key is encrypted to an SSH public key using `age`.
- Passphrase locks: the master key is encrypted with a key derived from a passphrase using Argon2 and AES-GCM.

This lets you add several ways to unlock the same vault:

- one SSH key for each developer;
- one passphrase backup lock;
- one CI/deploy SSH key;
- short-lived locks for contractors or temporary machines.

When someone leaves the team, remove their lock and commit the updated `.agent-keys/config.toml` and lock directory. For stronger protection after a possible lock compromise, rotate the master key.

### What Is Safe To Commit

The `.agent-keys/` directory is intended to be committed.

It contains:

- `.agent-keys/config.toml`: public vault metadata and lock metadata;
- `.agent-keys/vault.vlt`: encrypted vault content;
- `.agent-keys/locks/*.enc`: encrypted master-key locks.

These files should not contain plaintext secrets. If they do, treat it as a bug and do not commit them.

### What Is Not Safe To Commit

Do not commit:

- private SSH keys;
- passphrases;
- exported `.env` files generated from the vault;
- Kubernetes Secret YAML generated with plaintext values;
- Docker Compose override files that contain plaintext values;
- logs that include secret output.

### Session Files

After unlock, Agent Keys writes an encrypted session file to the platform cache directory. The session file stores the master key encrypted with a machine-derived key. This avoids prompting for every command while keeping the session file bound to a specific machine/user environment.

Use:

```bash
agent-secrets close
```

to delete the session file and lock the vault again.

### Read-Only Mode

Unlock with:

```bash
agent-secrets unlock --read
```

to create a read-only session. Read-only mode allows commands such as `kv get`, `file read`, `env`, and `run`, but rejects writes like `kv set`, `file write`, lock changes, and rotation.

This is a safety mode, not a separate cryptographic boundary. The same unlock method can create read or write sessions.

---

## Repository Layout

After initialization, a repository contains:

```text
repo/
├── .agent-keys/
│   ├── config.toml
│   ├── vault.vlt
│   └── locks/
│       ├── ssh-abc123.enc
│       └── passphrase-xyz.enc
└── your-application-files...
```

The Rust crate currently lives in:

```text
agent-secrets/
├── Cargo.toml
├── Cargo.lock
├── src/
└── tests/
```

The top-level `spec.md` contains the product specification.

---

## Installation

### Prebuilt Binaries

Download a prebuilt binary from the [GitHub Releases](https://github.com/yourusername/agent-secrets/releases) page.

Linux / macOS:

```bash
tar xzf agent-secrets-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 agent-secrets ~/.local/bin/agent-secrets
```

Windows (PowerShell):

```powershell
Expand-Archive agent-secrets-x86_64-pc-windows-msvc.zip -DestinationPath .\agent-secrets
```

### Build From Source

If you have the Rust toolchain installed:

```bash
cargo install --path agent-secrets
```

Or clone and build manually:

```bash
cd agent-secrets
cargo build --release
```

The binary is written to:

```bash
target/release/agent-secrets
```

Install it somewhere on your `PATH`:

```bash
install -m 0755 target/release/agent-secrets ~/.local/bin/agent-secrets
```

or run it directly:

```bash
./target/release/agent-secrets --help
```

### Package Managers

Homebrew (macOS / Linux):

```bash
brew tap yourusername/agent-secrets
brew install agent-secrets
```

> A community Homebrew formula is welcome. Please open an issue if you maintain one.

### Requirements

For normal usage:

- an SSH key pair, or a passphrase lock;
- a Git repository or project directory;
- the `agent-secrets` binary.

For building from source:

- Rust toolchain (1.70+);
- Cargo.

For SSH-key integration tests:

- `ssh-keygen`.

---

## Quick Start

Move into the repository where you want to store encrypted secrets:

```bash
cd my-app
```

Initialize a vault using an explicit SSH public key:

```bash
agent-secrets init --ssh ~/.ssh/id_ed25519.pub
```

Or initialize with a passphrase lock:

```bash
agent-secrets init --passphrase
```

Commit the encrypted vault:

```bash
git add .agent-keys/
git commit -m "Add encrypted Agent Keys vault"
```

Unlock the vault:

```bash
agent-secrets unlock
```

Add a secret:

```bash
agent-secrets kv set DATABASE_URL --value "postgres://user:pass@localhost:5432/app"
```

Read it back:

```bash
agent-secrets kv get DATABASE_URL
```

Print shell exports:

```bash
agent-secrets env
```

Run an application with all key-value secrets injected as environment variables:

```bash
agent-secrets run -- npm start
```

Close the session:

```bash
agent-secrets close
```

---

## Core Commands

### Initialize A Vault

```bash
agent-secrets init
```

When no `--ssh` option is supplied, Agent Keys looks for common SSH public keys in `~/.ssh/` and asks which ones to use.

Explicit SSH key:

```bash
agent-secrets init --ssh ~/.ssh/id_ed25519.pub
```

Multiple SSH keys:

```bash
agent-secrets init --ssh ~/.ssh/id_ed25519.pub --ssh ./deploy_key.pub
```

Passphrase lock:

```bash
agent-secrets init --passphrase
```

Force reinitialize an existing vault:

```bash
agent-secrets init --ssh ~/.ssh/id_ed25519.pub --force
```

Be careful with `--force`; it replaces the existing `.agent-keys/` directory.

### Unlock

```bash
agent-secrets unlock
```

Read-only unlock:

```bash
agent-secrets unlock --read
```

Unlock using an SSH private key stored in an environment variable:

```bash
export AGENT_KEYS_SSH_KEY="$(cat ~/.ssh/id_ed25519)"
agent-secrets unlock --ssh-key-from-env AGENT_KEYS_SSH_KEY
```

This is useful in CI and deployment automation.

### Close

```bash
agent-secrets close
```

This deletes the encrypted session file. Future commands will require unlock again.

### Status

```bash
agent-secrets status
```

Shows whether the vault is locked or unlocked, the current session mode, active context, lock count, and stored secret counts where possible.

### Key-Value Secrets

Set a secret interactively:

```bash
agent-secrets kv set API_KEY
```

Set a secret from a flag:

```bash
agent-secrets kv set API_KEY --value "abc123"
```

Set a secret from stdin:

```bash
printf '%s' "$DATABASE_URL" | agent-secrets kv set DATABASE_URL --from-stdin
```

Get a secret:

```bash
agent-secrets kv get API_KEY
```

Get without a newline:

```bash
agent-secrets kv get API_KEY --no-newline
```

List keys without revealing values:

```bash
agent-secrets kv list
```

Remove a key:

```bash
agent-secrets kv remove API_KEY
```

### File Secrets

Store a local file in the vault:

```bash
agent-secrets file write certs/tls.crt ./tls.crt
```

Read a file to stdout:

```bash
agent-secrets file read certs/tls.crt
```

Read a file to disk:

```bash
agent-secrets file read certs/tls.crt ./tls.crt
```

List stored file paths:

```bash
agent-secrets file list
```

Remove a file:

```bash
agent-secrets file remove certs/tls.crt
```

### Environment Export

Bash/sh:

```bash
agent-secrets env --format bash
```

Fish:

```bash
agent-secrets env --format fish
```

PowerShell:

```powershell
agent-secrets env --format powershell
```

JSON:

```bash
agent-secrets env --format json
```

GitHub Actions environment-file format:

```bash
agent-secrets env --format github
```

### Run A Command

```bash
agent-secrets run -- node server.js
```

Everything in the active context's key-value store is injected into the child process environment.

Example:

```bash
agent-secrets kv set DATABASE_URL --value "postgres://localhost/app"
agent-secrets run -- printenv DATABASE_URL
```

---

## Contexts

Contexts are namespaces inside one vault. They are useful for separating values by environment:

- `default`;
- `dev`;
- `staging`;
- `prod`;
- `ci`.

Contexts are not permission boundaries. Anyone who can unlock the vault can read all contexts. Use separate vaults if you need true access isolation.

List contexts:

```bash
agent-secrets context list
```

Use a context:

```bash
agent-secrets context use dev
```

Show current context:

```bash
agent-secrets context current
```

Set a value in a specific context:

```bash
agent-secrets kv set DATABASE_URL --context dev --value "postgres://dev/db"
agent-secrets kv set DATABASE_URL --context prod --value "postgres://prod/db"
```

Read from a specific context:

```bash
agent-secrets kv get DATABASE_URL --context prod
```

Run with a specific context:

```bash
agent-secrets run --context staging -- npm start
```

---

## Docker Usage

Docker has a common secret-handling problem: you want containers to receive environment variables or files, but you do not want plaintext `.env` files committed to the repo.

Agent Keys can sit outside the container and inject secrets at `docker run` time.

### Pattern 1: Host Unlock, Container Env Injection

Unlock on the host:

```bash
agent-secrets unlock --read
```

Run the app container with values from Agent Keys:

```bash
agent-secrets run -- docker run --rm \
  -p 3000:3000 \
  my-app:latest
```

Because `agent-secrets run` injects all key-value secrets into the child process environment, `docker run` receives those environment variables and passes them to the container when you include `-e` flags.

For explicit variables:

```bash
docker run --rm \
  -e DATABASE_URL="$(agent-secrets kv get DATABASE_URL --no-newline)" \
  -e API_KEY="$(agent-secrets kv get API_KEY --no-newline)" \
  my-app:latest
```

This keeps plaintext values out of files, but they still exist in the process environment. Treat shell history and process inspection accordingly.

### Pattern 2: Generate A Temporary Env File

Some workflows prefer Docker's `--env-file`.

Generate a temporary `.env` file:

```bash
tmp_env="$(mktemp)"
agent-secrets env --format bash \
  | sed 's/^export //' \
  | sed "s/'//g" > "$tmp_env"

docker run --rm --env-file "$tmp_env" my-app:latest
rm -f "$tmp_env"
```

This is convenient, but it writes plaintext to disk. Only do this in a secure temporary directory, remove the file immediately, and avoid this pattern on shared machines.

### Pattern 3: Keep Agent Keys Out Of The Image

Recommended production pattern:

- build images without secrets;
- do not copy `.agent-keys/` into the image;
- inject secrets at runtime from the host, CI system, or orchestrator.

Example Dockerfile:

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
CMD ["node", "server.js"]
```

Run:

```bash
agent-secrets run --context prod -- docker run --rm \
  -e DATABASE_URL \
  -e API_KEY \
  my-app:latest
```

The `-e NAME` form tells Docker to copy the variable from the host environment into the container. Since `agent-secrets run` provides those variables to `docker run`, Docker can forward them.

### Pattern 4: Inject File Secrets With Bind Mounts

If your app expects a credential file:

```bash
tmp_dir="$(mktemp -d)"
agent-secrets file read service-account.json "$tmp_dir/service-account.json"

docker run --rm \
  -v "$tmp_dir/service-account.json:/run/secrets/service-account.json:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/service-account.json \
  my-app:latest

rm -rf "$tmp_dir"
```

This writes plaintext to disk temporarily. Prefer tmpfs-backed paths where possible:

```bash
tmp_dir="/dev/shm/agent-secrets-$$"
mkdir -p "$tmp_dir"
agent-secrets file read service-account.json "$tmp_dir/service-account.json"
docker run --rm \
  -v "$tmp_dir/service-account.json:/run/secrets/service-account.json:ro" \
  my-app:latest
rm -rf "$tmp_dir"
```

### Pattern 5: Runtime Entrypoint Inside The Container

You can install `agent-secrets` inside a container and decrypt at startup, but this is usually less desirable because the container then needs:

- `.agent-keys/`;
- a private SSH key or passphrase;
- enough filesystem access to store a session.

If you do use this pattern, mount the private key as a runtime secret, not as part of the image:

```bash
docker run --rm \
  -v "$PWD/.agent-keys:/app/.agent-keys:ro" \
  -v "$HOME/.ssh/id_ed25519:/run/keys/agent_keys:ro" \
  -e AGENT_KEYS_SSH_KEY="$(cat ~/.ssh/id_ed25519)" \
  my-app-with-agent-secrets:latest \
  sh -lc 'agent-secrets unlock --ssh-key-from-env AGENT_KEYS_SSH_KEY && agent-secrets run -- ./server'
```

For most teams, host-side unlock and runtime injection is cleaner.

---

## Docker Compose Usage

Docker Compose supports environment variables from the shell, `.env` files, and `env_file`. Agent Keys works best when Compose reads variables from the shell environment created by `agent-secrets run`.

### Compose File

```yaml
services:
  app:
    image: my-app:latest
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: ${DATABASE_URL}
      API_KEY: ${API_KEY}
```

Run:

```bash
agent-secrets run --context dev -- docker compose up
```

Compose expands `${DATABASE_URL}` and `${API_KEY}` from its process environment.

### Compose With Explicit Export

If your shell supports process substitution:

```bash
eval "$(agent-secrets env --format bash)"
docker compose up
```

This places secrets into your current shell environment until you unset them or close the shell. Prefer `agent-secrets run` when possible because the secrets are scoped to the child process.

### Compose With Temporary Env File

```bash
tmp_env="$(mktemp)"
agent-secrets env --format json \
  | jq -r 'to_entries[] | "\(.key)=\(.value)"' > "$tmp_env"

docker compose --env-file "$tmp_env" up
rm -f "$tmp_env"
```

This is convenient for existing Compose workflows but carries the plaintext-on-disk warning.

### Compose Profiles And Contexts

Use Agent Keys contexts to match Compose profiles:

```bash
agent-secrets kv set DATABASE_URL --context dev --value "postgres://dev"
agent-secrets kv set DATABASE_URL --context staging --value "postgres://staging"

agent-secrets run --context dev -- docker compose --profile dev up
agent-secrets run --context staging -- docker compose --profile staging up
```

---

## Kubernetes Usage

Kubernetes has its own Secret object, but a standard Secret manifest stores values as base64, not as strong encryption in Git. If you commit raw Secret YAML, anyone with repository access can decode the values.

Agent Keys can be used as the encrypted source of truth and then generate Kubernetes Secret objects during deployment.

### Recommended Model

For GitOps or CI/CD:

1. Commit `.agent-keys/` to the repository.
2. Store the CI/deploy private key in the CI platform secret store.
3. During deployment, unlock Agent Keys.
4. Generate Kubernetes Secret objects or pipe values into `kubectl`.
5. Do not commit generated plaintext Secret YAML.

### Create A Kubernetes Secret From KV Values

Unlock:

```bash
export AGENT_KEYS_SSH_KEY="$DEPLOY_PRIVATE_KEY"
agent-secrets unlock --read --ssh-key-from-env AGENT_KEYS_SSH_KEY
```

Create or update a Secret:

```bash
kubectl create secret generic my-app-secrets \
  --from-literal=DATABASE_URL="$(agent-secrets kv get DATABASE_URL --context prod --no-newline)" \
  --from-literal=API_KEY="$(agent-secrets kv get API_KEY --context prod --no-newline)" \
  --dry-run=client -o yaml \
  | kubectl apply -f -
```

This avoids writing plaintext YAML to disk.

### Create A Kubernetes Secret From All KV Values

You can convert JSON output into `kubectl` flags:

```bash
args="$(
  agent-secrets env --context prod --format json \
    | jq -r 'to_entries[] | "--from-literal=\(.key)=\(.value|@sh)"'
)"

eval "kubectl create secret generic my-app-secrets $args --dry-run=client -o yaml" \
  | kubectl apply -f -
```

Be careful with shell quoting. For critical production workflows, prefer a small script in Python, Go, or Rust that parses JSON and invokes Kubernetes APIs without `eval`.

### Create A Secret From File Values

Store a certificate:

```bash
agent-secrets file write certs/tls.crt ./tls.crt --context prod
agent-secrets file write certs/tls.key ./tls.key --context prod
```

Deploy it:

```bash
tmp_dir="$(mktemp -d)"
agent-secrets file read certs/tls.crt "$tmp_dir/tls.crt" --context prod
agent-secrets file read certs/tls.key "$tmp_dir/tls.key" --context prod

kubectl create secret tls my-app-tls \
  --cert="$tmp_dir/tls.crt" \
  --key="$tmp_dir/tls.key" \
  --dry-run=client -o yaml \
  | kubectl apply -f -

rm -rf "$tmp_dir"
```

Prefer memory-backed temporary directories if available:

```bash
tmp_dir="/dev/shm/agent-secrets-k8s-$$"
mkdir -p "$tmp_dir"
```

### Use Secrets In A Deployment

Example Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
        - name: app
          image: ghcr.io/example/my-app:latest
          envFrom:
            - secretRef:
                name: my-app-secrets
```

The secret object is generated at deploy time from Agent Keys. The Deployment itself can stay committed.

### Use Separate Contexts For Namespaces

Example:

```bash
agent-secrets kv set DATABASE_URL --context dev --value "postgres://dev"
agent-secrets kv set DATABASE_URL --context prod --value "postgres://prod"
```

Deploy dev:

```bash
kubectl -n dev create secret generic my-app-secrets \
  --from-literal=DATABASE_URL="$(agent-secrets kv get DATABASE_URL --context dev --no-newline)" \
  --dry-run=client -o yaml \
  | kubectl apply -f -
```

Deploy prod:

```bash
kubectl -n prod create secret generic my-app-secrets \
  --from-literal=DATABASE_URL="$(agent-secrets kv get DATABASE_URL --context prod --no-newline)" \
  --dry-run=client -o yaml \
  | kubectl apply -f -
```

### GitOps Warning

If you use Argo CD, Flux, or another GitOps controller, do not commit generated plaintext Kubernetes Secret manifests unless your repository has another encryption layer such as Sealed Secrets or SOPS.

Agent Keys can generate the Secret object in CI and apply it directly. For pure GitOps, pair Agent Keys with a controller-friendly encryption format, or use Agent Keys to feed the system that creates sealed/encrypted manifests.

### Init Containers

An init-container pattern is possible but usually not recommended. It requires shipping Agent Keys and the encrypted vault to the cluster and providing an unlock key inside the cluster. If you do this, mount the private key from a Kubernetes Secret and make sure the decrypted output is written only to a shared memory volume or Kubernetes Secret API, not to a persistent disk.

Most deployments should decrypt before applying manifests, not inside the cluster.

---

## CI/CD Usage

### GitHub Actions

Store the deploy private key in GitHub Actions secrets, for example `AGENT_KEYS_SSH_KEY`.

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Agent Keys
        run: |
          cargo build --release --manifest-path agent-secrets/Cargo.toml
          sudo install -m 0755 agent-secrets/target/release/agent-secrets /usr/local/bin/agent-secrets

      - name: Unlock vault
        env:
          AGENT_KEYS_SSH_KEY: ${{ secrets.AGENT_KEYS_SSH_KEY }}
        run: |
          agent-secrets unlock --read --ssh-key-from-env AGENT_KEYS_SSH_KEY

      - name: Export app env
        run: |
          agent-secrets env --context prod --format github >> "$GITHUB_ENV"

      - name: Deploy
        run: |
          ./scripts/deploy.sh
```

For Kubernetes:

```yaml
      - name: Apply Kubernetes secrets
        env:
          AGENT_KEYS_SSH_KEY: ${{ secrets.AGENT_KEYS_SSH_KEY }}
        run: |
          agent-secrets unlock --read --ssh-key-from-env AGENT_KEYS_SSH_KEY
          kubectl create secret generic my-app-secrets \
            --from-literal=DATABASE_URL="$(agent-secrets kv get DATABASE_URL --context prod --no-newline)" \
            --dry-run=client -o yaml \
            | kubectl apply -f -
```

### CI Safety Notes

- Use read-only unlock in CI unless the job truly needs to modify the vault.
- Do not print secret values.
- Do not upload generated env files as artifacts.
- Keep CI private keys scoped to the repositories and environments that need them.
- Rotate locks when CI credentials are replaced.

---

## Team Workflows

### Add A Teammate

Ask for their SSH public key:

```bash
agent-secrets lock add-ssh ./alice.pub
git add .agent-keys/
git commit -m "Add Alice Agent Keys lock"
git push
```

The teammate can pull and unlock with their matching private key.

### Add A Backup Passphrase

```bash
agent-secrets unlock
agent-secrets lock add-passphrase
git add .agent-keys/
git commit -m "Add backup passphrase lock"
```

Store the passphrase in a secure password manager.

### Remove A Teammate

```bash
agent-secrets unlock
agent-secrets lock list
agent-secrets lock remove ssh-deadbeef
git add .agent-keys/
git commit -m "Remove old Agent Keys lock"
```

If you believe the removed key had been compromised, rotate the master key:

```bash
agent-secrets rotate
git add .agent-keys/
git commit -m "Rotate Agent Keys master key"
```

### Review Secret Changes

Secret values are encrypted, so pull requests cannot show plaintext diffs. Reviewers should look for:

- expected lock changes;
- expected vault update;
- no plaintext `.env` or generated Secret YAML;
- no private keys.

---

## Operational Guidance

### Prefer Read-Only Sessions For Deployment

```bash
agent-secrets unlock --read
```

Read-only mode reduces accidental writes from deployment scripts.

### Use Contexts Carefully

Contexts help organize environments, but they do not restrict access. If production secrets must be limited to a smaller group, use a separate repository or vault.

### Avoid Long-Lived Plaintext Files

When a workflow needs a temporary file, put it in a secure temp directory, remove it quickly, and avoid storing it in the project tree.

### Keep Images Secret-Free

Docker images should not contain:

- `.agent-keys/`;
- private SSH keys;
- generated env files;
- generated Kubernetes Secret manifests.

Inject secrets at runtime.

### Rotate On Suspicion

Rotate when:

- a private unlock key may have leaked;
- a laptop is lost;
- a CI secret is exposed;
- a teammate leaves and had access to production values;
- plaintext values were printed into logs.

---

## Troubleshooting

### `no .agent-keys directory found`

Run the command from the repository root, or initialize first:

```bash
agent-secrets init --ssh ~/.ssh/id_ed25519.pub
```

### `vault is locked`

Unlock:

```bash
agent-secrets unlock
```

or in CI:

```bash
agent-secrets unlock --read --ssh-key-from-env AGENT_KEYS_SSH_KEY
```

### `no SSH private keys found in ~/.ssh/`

Use a passphrase lock, place your private key in the default SSH location, or use env unlock:

```bash
export AGENT_KEYS_SSH_KEY="$(cat ~/.ssh/id_ed25519)"
agent-secrets unlock --ssh-key-from-env AGENT_KEYS_SSH_KEY
```

### `wrong passphrase`

Check that you selected the correct passphrase lock and typed the right passphrase. If another lock exists, unlock with that and add a new passphrase lock.

### Docker Container Does Not See Variables

Make sure Docker forwards the variables:

```bash
agent-secrets run -- docker run --rm -e DATABASE_URL -e API_KEY my-app
```

`agent-secrets run` sets variables for the `docker` process. Docker only forwards variables that you pass with `-e` or define in Compose.

### Kubernetes Secret Was Applied But App Still Fails

Check:

- namespace;
- Secret name;
- Deployment `envFrom` or `env` references;
- whether pods were restarted after Secret update;
- whether the value was stored in the expected Agent Keys context.

---

## Development

Build:

```bash
cd agent-secrets
cargo build
```

Run tests:

```bash
cargo test -- --test-threads=1
```

> Integration tests use the filesystem and pseudo-terminals; single-threaded execution avoids races.

Check formatting:

```bash
cargo fmt --check
```

Run compiler checks:

```bash
cargo check
```

Dependencies are resolved with standard Cargo/crates.io metadata. `Cargo.lock` is committed for reproducible application builds.

---

## Roadmap

Planned or recommended improvements:

- encrypted SSH private key passphrase prompts;
- migration command for older SSH locks missing stored public-key metadata;
- more integration tests for `env`, `run`, lock add/remove, rotate, contexts, and read-only mode;
- manual verification on macOS and Windows;
- stronger end-to-end zeroization coverage;
- signed release artifacts;
- packaged installation instructions for Linux, macOS, and Windows.

---

## License

Agent Keys is licensed under the [MIT License](LICENSE).
