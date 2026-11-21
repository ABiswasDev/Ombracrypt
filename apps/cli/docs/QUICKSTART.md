# Ombracrypt CLI Quickstart & Operational Manual

Welcome to the **Ombracrypt CLI** operational guide. This document provides step-by-step instructions for installing, configuring, and operating every feature of the Ombracrypt terminal application.

Ombracrypt is an offline, zero-telemetry, post-quantum hybrid cryptographic vault engineered for terminal power users, automation pipelines, and headless servers. It maintains **100% bit-for-bit container parity with the Ombracrypt Desktop GUI (v2)**. Any vault (`.obv`) or key (`.obp`/`.obk`) created by the CLI can be seamlessly authenticated and extracted by the GUI, and vice versa.

---

## Table of Contents

1. [Installation & Setup](#1-installation--setup)
2. [Command Surface Overview](#2-command-surface-overview)
3. [Step 1: Pre-Flight Storage & Path Inspection (`inspect`)](#3-step-1-pre-flight-storage--path-inspection-inspect)
4. [Step 2: Locking Data into a Quantum Vault (`encrypt`)](#4-step-2-locking-data-into-a-quantum-vault-encrypt)
   * [Mode A: Encrypt with Fresh Keypair Generation](#mode-a-encrypt-with-fresh-keypair-generation-obp--obk)
   * [Mode B: One-Way Sealing to a Public Key](#mode-b-one-way-sealing-to-a-recipient-public-key-obp)
5. [Step 3: Unlocking & Extracting a Vault (`decrypt`)](#5-step-3-unlocking--extracting-a-vault-decrypt)
6. [Step 4: Provisioning Standalone Keypairs (`keygen`)](#6-step-4-provisioning-standalone-keypairs-keygen)
7. [Step 5: Reclaiming Staging Remnants (`clean`)](#7-step-5-reclaiming-staging-remnants-clean)
8. [Anti-Coercion: Duress Trapdoor Protocol](#8-anti-coercion-duress-trapdoor-protocol)
9. [Automation, Scripting & Headless Pipelines](#9-automation-scripting--headless-pipelines)
10. [Troubleshooting & Security Invariants](#10-troubleshooting--security-invariants)

---

## 1. Installation & Setup

### Pre-Compiled Standalone Binaries
Download the official standalone release for your platform from the [GitHub Releases](https://github.com/ABiswasDev/ombracrypt-cli/releases) page:

* **Linux (x86_64):** `ombracrypt-v2.0.0-linux-x64.tar.gz`
* **macOS Apple Silicon (ARM64):** `ombracrypt-v2.0.0-macos-arm64.tar.gz`
* **macOS Intel (x86_64):** `ombracrypt-v2.0.0-macos-x64.tar.gz`
* **Windows (x86_64):** `ombracrypt-v2.0.0-windows-x64.zip`

#### Linux & macOS Installation
```bash
# 1. Unpack the tarball
tar -xvf ombracrypt-v2.0.0-linux-x64.tar.gz

# 2. Grant execution permissions
chmod +x ombracrypt

# 3. Move the binary into your system PATH
sudo mv ombracrypt /usr/local/bin/

# 4. Verify installation
ombracrypt --version
```

#### Windows Installation
Extract `ombracrypt.exe` from the `.zip` archive into a folder of your choice (e.g., `C:\Tools\Ombracrypt`), and add that folder to your system `PATH`, or invoke it directly from PowerShell or Command Prompt:
```powershell
.\ombracrypt.exe --version
```

### Compiling from Source
If you prefer building from source, ensure you have the latest stable [Rust toolchain](https://rustup.rs/) installed:
```bash
git clone https://github.com/ABiswasDev/ombracrypt-cli.git
cd ombracrypt-cli

# Run compilation check & full 56-test cryptographic suite (57 on Windows)
cargo check --all-targets
cargo test --release -- --nocapture

# Compile the release binary
cargo build --release
```
The compiled executable will be located at `./target/release/ombracrypt`.

---

## 2. Command Surface Overview

Ombracrypt CLI provides five dedicated subcommands designed for high-security workflows:

| Subcommand | Primary Operational Purpose |
| :--- | :--- |
| **`inspect`** | Evaluates required vs available disk capacity and detects filesystem path collisions prior to execution. |
| **`encrypt`** | Streams a directory or file into an authenticated `.obv` vault via bounded memory AEAD streaming. |
| **`decrypt`** | Authenticates and decapsulates an `.obv` vault using an `.obk` private key, extracting contents directly in memory. |
| **`keygen`** | Generates standalone, reusable public sealing keys (`.obp`) and private decapsulation keys (`.obk`). |
| **`clean`** | Scans and reclaims abandoned `.ombracrypt_stage_*` staging folders following interruptions or crashes. |

To inspect options for any command, append `--help`:
```bash
ombracrypt encrypt --help
ombracrypt decrypt --help
```

---

## 3. Step 1: Pre-Flight Storage & Path Inspection (`inspect`)

Before initiating encryption on massive datasets or extracting gigabyte-sized vaults, run `inspect` to verify storage capacity and prevent out-of-disk crashes.

```bash
# Inspecting an encryption operation:
ombracrypt inspect --mode encrypt --target "/home/user/Documents/Financials"

# Inspecting a decryption operation:
ombracrypt inspect \
  --mode decrypt \
  --target "/backups/Financials.obv" \
  --key "/keys/Financials.obk" \
  --output-dir "/restores"
```

### Human-Readable Output Example
```plaintext
:: OMBRACRYPT PRE-FLIGHT STORAGE ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ Mode:               ENCRYPT
▶ Target:             /home/user/Documents/Financials
▶ Destination:        /home/user/Documents
▶ Required Free:      124.50 MB
▶ Available Free:     48120.25 MB
▶ Sufficient Space:   YES
▶ Path Conflicts:     None (Clear)
▶ Summary:            Required: 124.50 MB | Available: 48120.25 MB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Scripting with Machine-Readable JSON
For automation scripts, pass the `--json` flag:
```bash
ombracrypt inspect --mode encrypt --target "/data/records" --json
```
```json
{
  "required_bytes": 130548121,
  "available_bytes": 50458763264,
  "raw_bytes": 128450110,
  "item_count": 412,
  "sufficient": true,
  "conflict_error": null,
  "key_fingerprint": null,
  "summary": "Required: 124.50 MB | Available: 48120.25 MB"
}
```

> [!NOTE]
> If a file or folder of the same name already exists in the destination, `inspect` detects the collision and reports it under `conflict_error`.

---

## 4. Step 2: Locking Data into a Quantum Vault (`encrypt`)

Ombracrypt encrypts files and entire directory trees **on-the-fly through bounded 1&nbsp;MiB in-process memory buffers** directly into authenticated AEAD ciphertext blocks. **No unencrypted `.tar` archive is ever written to disk.**

### Mode A: Encrypt with Fresh Keypair Generation (`.obp` + `.obk`)

This is the standard mode for personal storage and offline backups. It creates the encrypted vault (`.obv`) and generates a mathematically linked private decapsulation key (`.obk`) and public sealing key (`.obp`).

```bash
ombracrypt encrypt --target "/home/user/Documents/Financials"
```

#### Step-by-Step Interactive Flow:
1. **Interactive Prompt:** The CLI prompts for a **Master Password** with masked entry (asterisks) and asks for confirmation.
2. **Deception Passcode (Optional):** Prompts for an optional **Deception Passcode** (press `ENTER` to skip if not needed for your threat model).
3. **Execution:** An animated `indicatif` progress bar displays streaming throughput and cryptographic milestone percentages.
4. **Completion:** Upon success, three files are produced:
   * `Financials.obv` — The authenticated encrypted vault.
   * `Financials.obk` — Your offline private key (restricted to `0600` owner-only permissions).
   * `Financials.obp` — The public key corresponding to this keypair.

```plaintext
:: OMBRACRYPT QUANTUM VAULT [v2.0.0]
   Post-Quantum Hybrid Cryptographic Vault (CAL-1.0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ Operation: ENCRYPT (Quantum Lock)
▶ Target:    /home/user/Documents/Financials
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▶ Initializing Streaming Cryptographic Pipeline...
[00:00:02] [━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━] 100% Processing cryptographic pipeline...

✔ Operation Successful: Vault locked (.obv) & Keypair generated [Key ID: 3C78B2A1-94EF11D2-7CA88910-E2104F98].
```

#### Customizing Destination Directories & Algorithms:
By default, the CLI places the vault and keys in the parent folder of the target. You can redirect them using `-o / --output-dir` and `-k / --key-dir`:
```bash
ombracrypt encrypt \
  --target "/home/user/Documents/Financials" \
  --output-dir "/mnt/secure_backup" \
  --key-dir "/media/usb_key" \
  --cipher xchacha20 \
  --kem xwing
```

* `--cipher`: Choose between `xchacha20` *(default, XChaCha20-Poly1305)* and `aes256gcm` *(AES-256-GCM)*.
* `--kem`: Choose between `xwing` *(default, NIST FIPS 203 ML-KEM-768 + X25519)* and `cypherpunk` *(NIST FIPS 203 ML-KEM-1024 + X25519)*.

---

### Mode B: One-Way Sealing to a Recipient Public Key (`.obp`)

When encrypting data intended for another user, group, or backup server, you can seal the vault directly against their public key using `-p / --public-key`. 

> [!IMPORTANT]
> In this mode, **no private `.obk` key is generated**. The vault is mathematically sealed such that only the holder of the recipient's private key can decapsulate it.

```bash
ombracrypt encrypt \
  --target "/data/quarterly_audit" \
  --public-key "/keys/auditor_alice.obp" \
  --output-dir "/exports"
```

1. The CLI loads the recipient's `.obp` key, validates its header (`OBPK\x02`), and encapsulates a fresh hybrid post-quantum shared secret.
2. Prompts for a Master Password to derive the symmetric key-derivation layer.
3. Streams the directory into `/exports/quarterly_audit.obv`.
4. Only Alice (holding `auditor_alice.obk` and knowing the Master Password) can extract the vault.

---

## 5. Step 3: Unlocking & Extracting a Vault (`decrypt`)

To decrypt and extract an `.obv` vault, provide both the vault file and your corresponding `.obk` private key:

```bash
ombracrypt decrypt \
  --target "/mnt/secure_backup/Financials.obv" \
  --key "/media/usb_key/Financials.obk"
```

#### Specifying Extraction Destination:
By default, the decrypted directory is extracted into the parent directory of the vault. You can choose any destination using `-o / --output-dir`:
```bash
ombracrypt decrypt \
  --target "/mnt/secure_backup/Financials.obv" \
  --key "/media/usb_key/Financials.obk" \
  --output-dir "/home/user/Restores"
```

#### Operational Guarantees During Decryption:
* **In-Memory Streaming:** Decryption occurs on-the-fly. Ciphertext chunks (up to 1&nbsp;MiB) are decapsulated, verified via AEAD authentication tags with header hash AAD binding, and unpacked directly into target files.
* **Zip-Slip & Symlink Immunity:** Defensive path sanitization rejects entries containing `..` or leading slashes, and verifies all paths remain inside the target staging directory.
* **Atomic Directory Rename:** Decrypted contents are staged inside a secure temporary directory protected by an advisory lock (`.active.lock`). Only when the final chunk tag is verified and tar checksums match is the folder published atomically via `atomic_publish_dir_noreplace`.
* **Zero Collision Overwrites:** If `/home/user/Restores/Financials` already exists, Ombracrypt aborts immediately without modifying existing files.

---

## 6. Step 4: Provisioning Standalone Keypairs (`keygen`)

The `keygen` subcommand allows administrators and security teams to generate standalone post-quantum keypairs without encrypting a payload immediately.

```bash
# Generate a standard X-Wing keypair named 'alice'
ombracrypt keygen --name "alice" --output-dir "/home/user/keys"

# Generate a high-security Cypherpunk (ML-KEM-1024) keypair
ombracrypt keygen --name "infrastructure_cold" --output-dir "/keys" --kem cypherpunk
```

### Resulting Files:
* **X-Wing Profile (Default):**
  * `<NAME>.obp` (Public Sealing Key, **1,222 bytes**) — Shareable with anyone who needs to encrypt files for you.
  * `<NAME>.obk` (Private Decapsulation Key, **86 bytes**) — Kept offline and secret, permissions restricted to `0600`.
* **Cypherpunk Profile (`--kem cypherpunk`):**
  * `<NAME>.obp` (Public Sealing Key, **1,606 bytes**).
  * `<NAME>.obk` (Private Decapsulation Key, **3,254 bytes**) — Encapsulates full ML-KEM-1024 decapsulation key $d_k$ (3,168 B) + X25519 static private key (32 B) + metadata and phantom duress block. Restricted to `0600`.

```plaintext
:: OMBRACRYPT QUANTUM VAULT [v2.0.0]
   Post-Quantum Hybrid Cryptographic Vault (CAL-1.0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ Operation: KEYGEN (Generate Reusable Keypair)
▶ Target:    alice
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ Generated Keypair (alice.obp + alice.obk) | Key ID: 7D45A2F9-C10283E4-AA82B019-3318CD21
```

> [!TIP]
> The printed **Key ID** is a 128-bit SHA-256 fingerprint formatted as `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`. You can use it to verify key integrity across communication channels.

---

## 7. Step 5: Reclaiming Staging Remnants (`clean`)

Ombracrypt uses isolated staging directories (`.ombracrypt_stage_<STEM>_<UUID>/`) guarded by OS-level file locks (`.active.lock`) to ensure transactional atomicity. If a machine experiences sudden power loss, hardware shutdown, or forceful termination (`kill -9`), orphaned staging remnants may remain.

The `clean` command inspects target folders, checks advisory locks, and safely purges stale remnants without touching active transfers. It supports passing multiple targets, automatically deduplicates paths, and resolves file paths to their parent directories:

```bash
# Clean current directory
ombracrypt clean

# Clean multiple directories at once
ombracrypt clean -d "/mnt/backup1" -d "/mnt/backup2" -d "/data"

# Pass files directly (clean resolves to their parent directories)
ombracrypt clean -d "/mnt/backup1/vault.obv"
```

```plaintext
▶ Scanning directory for orphaned staging artifacts: /mnt/backup1
▶ Scanning directory for orphaned staging artifacts: /mnt/backup2
▶ Scanning directory for orphaned staging artifacts: /data
✔ Successfully cleaned 2 staging artifact(s) (148.20 MB reclaimed).
```

> [!NOTE]
> The cleaner strictly verifies that the directory matches Ombracrypt staging naming conventions, verifies that no other running process holds `.active.lock`, and preserves all non-staging files and symlinks. Silent mode (`-q / --quiet`) suppresses all terminal output.

---

## 8. Anti-Coercion: Duress Trapdoor Protocol

Ombracrypt includes an interactive anti-coercion mechanism known as the **Duress Trapdoor**, engineered for scenarios where a user is under physical duress or hostile interrogation and compelled to provide decryption credentials.

### How the Trapdoor Works
1. **Configuration:** When encrypting a vault or running `keygen`, you can optionally enter a secondary **Deception Passcode** (which must be distinct from your Master Password).
2. **The Threat Scenario:** An adversary physically compels you to unlock your vault (`Financials.obv`) with your key (`Financials.obk`).
3. **The Duress Input:** When the CLI prompts for the Master Password, you enter your **Deception Passcode** instead.
4. **The Silent Scramble:**
   * The decapsulation engine detects the valid deception signature in the key's 32-byte phantom verification block.
   * It immediately performs an in-place CSPRNG overwrite against the `.obk` file on disk, shredding the private key material with cryptographically secure random bytes (while verifying `st_nlink > 1` protection to prevent hardlink tampering).
   * It flushes hardware buffers (`fsync`) and returns a generic failure message:
     ```plaintext
     ✖ ERROR: Decryption Failed! Data corruption or mismatched cryptographic key.
     ```
5. **The Outcome:** To the adversary, the file still exists on disk with identical file size and timestamps, appearing as though a normal password typo occurred. In reality, the post-quantum private key has been permanently destroyed. **The vault is mathematically unrecoverable by anyone, including the adversary and yourself.**

> [!CAUTION]
> Duress activation is strictly irreversible. Use this mechanism only in genuine emergencies.

---

## 9. Automation, Scripting & Headless Pipelines

Ombracrypt CLI is fully equipped for unattended servers, CI/CD runners, and automated backup scripts.

### 1. Ingesting Credentials via Environment Variables
Set `OMBRACRYPT_PASSWORD` (and optionally `OMBRACRYPT_DECEPTION_PASSCODE`):

```bash
export OMBRACRYPT_PASSWORD="CorrectHorseBatteryStaple2026!"

# Encrypt quietly (-q suppresses banners and progress bars)
ombracrypt encrypt \
  --target "/var/backups/db" \
  --output-dir "/mnt/cold_storage" \
  --quiet

# Decrypt quietly
ombracrypt decrypt \
  --target "/mnt/cold_storage/db.obv" \
  --key "/mnt/cold_storage/db.obk" \
  --output-dir "/var/restore" \
  --quiet
```

You can also specify custom variable names using `--password-env`:
```bash
ombracrypt encrypt \
  --target "/var/backups/db" \
  --password-env "PROD_VAULT_SECRET" \
  --quiet
```

### 2. Ingesting Credentials via Files
Store passcodes in permission-restricted files (e.g., `chmod 0400 /etc/vault.key`):
```bash
ombracrypt encrypt \
  --target "/data/sensitive" \
  --password-file "/etc/vault.key" \
  --output-dir "/backups" \
  --quiet
```

### 3. Ingesting Credentials via Standard Input (Pipes)
When Ombracrypt detects that standard input is not a terminal TTY, it automatically consumes credentials from the pipe:
```bash
echo -n "MySuperSecurePassword" | ombracrypt encrypt \
  --target "/data/payroll" \
  --output-dir "/backups" \
  --quiet
```

### 4. Automated Daily Backup Shell Script
```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="/opt/production_data"
BACKUP_DIR="/mnt/encrypted_backups"
PUBKEY="/root/keys/infrastructure_backup.obp"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "[+] Initiating Pre-Flight Assessment..."
ombracrypt inspect --mode encrypt --target "$TARGET_DIR" --output-dir "$BACKUP_DIR" --json

echo "[+] Sealing Post-Quantum Vault for $TIMESTAMP..."
export OMBRACRYPT_PASSWORD="$(cat /root/secrets/vault_master.pass)"

ombracrypt encrypt \
  --target "$TARGET_DIR" \
  --public-key "$PUBKEY" \
  --output-dir "$BACKUP_DIR" \
  --quiet

echo "[✓] Backup completed successfully."
```

---

## 10. Troubleshooting & Security Invariants

### "Destination already exists in the output folder"
* **Cause:** Ombracrypt enforces strict collision-proof atomic publication. It will never overwrite an existing vault, key, or extracted directory.
* **Solution:** Specify an alternative `--output-dir`, or move/rename the existing directory before running the operation.

### "Insufficient Disk Space to extract vault"
* **Cause:** Pre-flight space estimation determined that the available free disk space on the target volume is smaller than the uncompressed vault payload.
* **Solution:** Free space on the destination drive or mount an external drive with sufficient capacity.

### "Invalid Private Key (.obk): Unrecognized header or corrupted file"
* **Cause:** The supplied key file does not begin with `OBSK\x02` or has been truncated or corrupted.
* **Note:** If the Duress Trapdoor was previously activated on this key, the header has been permanently overwritten with random noise.

### "Operation aborted by user"
* **Cause:** An operating system termination signal was received.
  * **Unix (Linux/macOS):** Handles `SIGINT` (Ctrl+C), `SIGTERM`, and `SIGHUP` via `ctrlc`'s `termination` feature.
  * **Windows:** Handles Console Control Events (`CTRL_C_EVENT`, `CTRL_CLOSE_EVENT`).
* **Cooperative Rollback:** Ombracrypt intercepts the signal non-blockingly via an atomic cancellation barrier. It halts chunk streaming, closes active file handles, and triggers `CommitRollbackGuard` and `TempFileGuard`/`TempDirGuard` to execute atomic staging rollback and artifact removal before process termination.
* **Uncatchable Signals:** Uncatchable terminations (such as `SIGKILL` / `kill -9` or sudden power outages) cannot run user-space signal handlers; any abandoned staging folders from such events can be swept at any time by running `ombracrypt clean`.

---

## Cross-Platform GUI Interoperability Checklist

| Action | CLI Execution | Desktop GUI Action |
| :--- | :--- | :--- |
| **Open Vault in GUI** | `ombracrypt encrypt -t "/data"` | Drag `data.obv` and `data.obk` into Ombracrypt Desktop GUI → Enter password → Click **Unlock Vault**. |
| **Open GUI Vault in CLI** | Encrypt folder in Desktop GUI | `ombracrypt decrypt -t "data.obv" -k "data.obk"` |
| **Share Public Key** | `ombracrypt keygen -n "alice"` | Provide `alice.obp` to any GUI or CLI user to seal vaults for Alice. |
