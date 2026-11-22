# Ombracrypt CLI Quickstart & Operational Guide

Welcome to the **Ombracrypt CLI** quickstart guide. This document provides step-by-step instructions for installing, configuring, and operating the terminal interface (`apps/cli` in the [Ombracrypt](https://github.com/ABiswasDev/Ombracrypt) workspace).

Ombracrypt is an offline, zero-telemetry, post-quantum hybrid cryptographic vault engineered for terminal users, automation scripts, and headless servers. Ombracrypt Desktop and Ombracrypt CLI share the canonical `ombracrypt-core` cryptographic and filesystem engine and `OMBV02` container format; cross-application compatibility for vaults (`.obv`) and keys (`.obp`/`.obk`) is verified through shared-core interoperability tests and frozen `v2.1.0` compatibility fixtures.

---

## Table of Contents

1. [Installation & Setup](#1-installation--setup)
2. [Command Surface Overview](#2-command-surface-overview)
3. [Step 1: Pre-Flight Storage & Path Inspection (`inspect`)](#3-step-1-pre-flight-storage--path-inspection-inspect)
4. [Step 2: Locking Data into a Quantum Vault (`encrypt`)](#4-step-2-locking-data-into-a-quantum-vault-encrypt)
   * [Mode A: Encrypt with Fresh Keypair Generation](#mode-a-encrypt-with-fresh-keypair-generation-obp--obk)
   * [Mode B: One-Way Sealing to a Recipient Public Key](#mode-b-one-way-sealing-to-a-recipient-public-key-obp)
5. [Step 3: Unlocking & Extracting a Vault (`decrypt`)](#5-step-3-unlocking--extracting-a-vault-decrypt)
6. [Step 4: Provisioning Standalone Keypairs (`keygen`)](#6-step-4-provisioning-standalone-keypairs-keygen)
7. [Step 5: Reclaiming Staging Remnants (`clean`)](#7-step-5-reclaiming-staging-remnants-clean)
8. [Anti-Coercion: Duress Trapdoor Protocol](#8-anti-coercion-duress-trapdoor-protocol)
9. [Automation, Scripting & Headless Pipelines](#9-automation-scripting--headless-pipelines)
10. [Troubleshooting & Operational Boundaries](#10-troubleshooting--operational-boundaries)

---

## 1. Installation & Setup

### Pre-Compiled Standalone Binaries

Download the standalone CLI release (`cli-v*` tags) and its `.sha256` checksum from the [Ombracrypt GitHub Releases](https://github.com/ABiswasDev/Ombracrypt/releases) page:

* **Linux (x86_64):** `ombracrypt-cli-v2.1.0-linux-x86_64.tar.gz` (+ `.sha256`)
* **macOS Apple Silicon (ARM64):** `ombracrypt-cli-v2.1.0-macos-aarch64.tar.gz` (+ `.sha256`)
* **macOS Intel (x86_64):** `ombracrypt-cli-v2.1.0-macos-x86_64.tar.gz` (+ `.sha256`)
* **Windows (x86_64):** `ombracrypt-cli-v2.1.0-windows-x86_64.zip` (+ `.sha256`)

#### Linux & macOS Installation

```bash
# 1. Verify the SHA-256 checksum (Linux: sha256sum; macOS: shasum -a 256)
sha256sum -c ombracrypt-cli-v2.1.0-linux-x86_64.tar.gz.sha256

# 2. Unpack the tarball
tar -xzf ombracrypt-cli-v2.1.0-linux-x86_64.tar.gz

# 3. Grant execution permissions
chmod +x ombracrypt

# 4. Move the binary into your system PATH
sudo mv ombracrypt /usr/local/bin/

# 5. Verify installation (shows CLI version, core crate version, and OMBV02 format)
ombracrypt --version
```

#### Windows Installation

Verify the `.zip` archive against its `.sha256` file, extract `ombracrypt.exe` into a folder of your choice (for example, `C:\Tools\Ombracrypt`), and add that folder to your system `PATH` or invoke it directly:

```powershell
Get-FileHash -Algorithm SHA256 .\ombracrypt-cli-v2.1.0-windows-x86_64.zip
Get-Content .\ombracrypt-cli-v2.1.0-windows-x86_64.zip.sha256
.\ombracrypt.exe --version
```

### Compiling from Source

The CLI requires only the stable [Rust toolchain](https://rustup.rs/) (no Node.js or Tauri desktop dependencies):

```bash
git clone https://github.com/ABiswasDev/Ombracrypt.git
cd Ombracrypt

# Verify compilation and run core + CLI interoperability tests
cargo check -p ombracrypt-cli --all-targets
cargo test -p ombracrypt-core -p ombracrypt-cli --release -- --nocapture

# Compile the locked release binary
cargo build --release --locked -p ombracrypt-cli
```

The compiled executable is located at `./target/release/ombracrypt` (`target\release\ombracrypt.exe` on Windows).

---

## 2. Command Surface Overview

Ombracrypt CLI provides five subcommands:

| Subcommand | Primary Operational Purpose |
| :--- | :--- |
| **`inspect`** | Evaluates required vs. available disk capacity and detects filesystem path collisions prior to execution. |
| **`encrypt`** | Streams a target directory into an authenticated `.obv` vault via bounded-memory AEAD streaming. |
| **`decrypt`** | Authenticates and decapsulates an `.obv` vault using an `.obk` private key, staging extraction safely before atomic publication. |
| **`keygen`** | Generates standalone, reusable public sealing keys (`.obp`) and private decapsulation keys (`.obk`). |
| **`clean`** | Scans and reclaims abandoned `.ombracrypt_stage_*` staging remnants following interruptions or crashes. |

To inspect options for any command, append `--help`:

```bash
ombracrypt encrypt --help
ombracrypt decrypt --help
```

---

## 3. Step 1: Pre-Flight Storage & Path Inspection (`inspect`)

Before encrypting large datasets or extracting multi-gigabyte vaults, run `inspect` to verify available disk space and check for destination path conflicts.

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

For automation scripts, pass `--json`:

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

Ombracrypt streams target directory trees **on-the-fly through bounded in-process memory buffers** (chunks up to 1&nbsp;MiB) directly into authenticated AEAD ciphertext blocks. **No unencrypted `.tar` archive is written to disk during encryption.**

### Mode A: Encrypt with Fresh Keypair Generation (`.obp` + `.obk`)

This is the standard mode for personal storage and offline backups. It creates the encrypted vault (`.obv`) along with a paired private decapsulation key (`.obk`) and public sealing key (`.obp`).

```bash
ombracrypt encrypt --target "/home/user/Documents/Financials"
```

#### Step-by-Step Interactive Flow

1. **Master Password:** The CLI prompts for a **Master Password** with masked entry and asks for confirmation.
2. **Deception Passcode (Optional):** Prompts for an optional **Deception Passcode** (press `ENTER` to skip if not needed).
3. **Execution:** A progress bar tracks streaming progress and cryptographic phases.
4. **Completion:** Upon success, three files are created:
   * `Financials.obv` — The authenticated encrypted vault.
   * `Financials.obk` — Your offline private key (created with `0600` owner-only permissions on POSIX filesystems; inherits parent directory ACLs on Windows).
   * `Financials.obp` — The public sealing key corresponding to this keypair.

```plaintext
:: OMBRACRYPT QUANTUM VAULT [v2.1.0]
   Post-Quantum Hybrid Cryptographic Vault (CAL-1.0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ Operation: ENCRYPT (Quantum Lock)
▶ Target:    /home/user/Documents/Financials
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▶ Initializing Streaming Cryptographic Pipeline...
[00:00:02] [━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━] 100% Processing cryptographic pipeline...

✔ Operation Successful: Vault locked (.obv) & Keypair generated [Key ID: 3C78B2A1-94EF11D2-7CA88910-E2104F98].
```

#### Customizing Destination Directories & Algorithms

By default, the CLI places the vault and keys in the parent folder of the target. Redirect them with `-o / --output-dir` and `-k / --key-dir`:

```bash
ombracrypt encrypt \
  --target "/home/user/Documents/Financials" \
  --output-dir "/mnt/secure_backup" \
  --key-dir "/media/usb_key" \
  --cipher xchacha20 \
  --kem xwing
```

* `--cipher`: `xchacha20` *(default, XChaCha20-Poly1305)* or `aes256gcm` *(AES-256-GCM)*.
* `--kem`: `xwing` *(default, NIST FIPS 203 ML-KEM-768 + X25519)* or `cypherpunk` *(custom non-standard ML-KEM-1024 + X25519)*.

> [!NOTE]
> Store `.obk` private keys only inside private, user-owned directories or physically controlled offline media. On Windows, `.obk` creation inherits parent directory ACLs, and common removable-media filesystems (`FAT32`, `exFAT`) do not support POSIX permission bits or NTFS ACLs.

---

### Mode B: One-Way Sealing to a Recipient Public Key (`.obp`)

When encrypting data intended for another user, team, or backup receiver, seal directly against their public key using `-p / --public-key`.

> [!IMPORTANT]
> In this mode, **no private `.obk` key is generated**. Only the holder of the matching `.obk` private key (and the chosen Master Password) can unlock the resulting vault.

```bash
ombracrypt encrypt \
  --target "/data/quarterly_audit" \
  --public-key "/keys/auditor_alice.obp" \
  --output-dir "/exports"
```

1. The CLI loads `auditor_alice.obp`, validates its header (`OBPK\x02`), and encapsulates a fresh hybrid post-quantum shared secret.
2. Prompts for a Master Password to derive the symmetric key layer.
3. Streams the directory into `/exports/quarterly_audit.obv`.

---

## 5. Step 3: Unlocking & Extracting a Vault (`decrypt`)

Provide both the `.obv` vault file and its matching `.obk` private key:

```bash
ombracrypt decrypt \
  --target "/mnt/secure_backup/Financials.obv" \
  --key "/media/usb_key/Financials.obk"
```

#### Specifying Extraction Destination

By default, the decrypted directory is published in the parent directory of the vault. Choose another destination with `-o / --output-dir`:

```bash
ombracrypt decrypt \
  --target "/mnt/secure_backup/Financials.obv" \
  --key "/media/usb_key/Financials.obk" \
  --output-dir "/home/user/Restores"
```

#### Operational Guarantees During Decryption

* **Bounded-Memory Chunk Authentication:** Ciphertext chunks (up to 1&nbsp;MiB) are decapsulated and verified via AEAD authentication tags with header-hash AAD binding as they stream.
* **Archive Safety Checks:** Defensive TAR parsing rejects `..` traversal, absolute prefixes, duplicate paths, non-regular entries (symlinks, hard links, FIFOs, devices), and excessive recursion depths (<= 64 levels).
* **Same-Filesystem Staging & Atomic Publication:** Extracted files unpack into an isolated staging wrapper (`.ombracrypt_stage_*/payload/`) on the destination filesystem guarded by an exclusive `.active.lock` sentinel. Only after the final chunk authenticates is `payload/` promoted atomically via platform-native no-clobber directory renames.
* **No Silent Overwrites:** If `/home/user/Restores/Financials` already exists (or is a dangling symlink), Ombracrypt fails closed without modifying existing files.

---

## 6. Step 4: Provisioning Standalone Keypairs (`keygen`)

Generate standalone reusable keypairs without encrypting a payload immediately:

```bash
# Generate a standard X-Wing keypair named 'alice'
ombracrypt keygen --name "alice" --output-dir "/home/user/keys"

# Generate a Cypherpunk (ML-KEM-1024 + X25519) keypair
ombracrypt keygen --name "infrastructure_cold" --output-dir "/keys" --kem cypherpunk
```

### Resulting Files

* **X-Wing Profile (Default):**
  * `<NAME>.obp` (Public Sealing Key, **1,222 bytes**) — Shareable for one-way vault sealing.
  * `<NAME>.obk` (Private Decapsulation Key, **86 bytes**) — Keep offline and protected (`0600` on POSIX filesystems; inherits parent ACLs on Windows).
* **Cypherpunk Profile (`--kem cypherpunk`):**
  * `<NAME>.obp` (Public Sealing Key, **1,606 bytes**).
  * `<NAME>.obk` (Private Decapsulation Key, **3,254 bytes**) — Stores ML-KEM-1024 decapsulation key d<sub>k</sub> (3,168 B), X25519 private key (32 B), header metadata, and 32-byte phantom duress block.

```plaintext
:: OMBRACRYPT QUANTUM VAULT [v2.1.0]
   Post-Quantum Hybrid Cryptographic Vault (CAL-1.0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ Operation: KEYGEN (Generate Reusable Keypair)
▶ Target:    alice
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ Generated Keypair (alice.obp + alice.obk) | Key ID: 7D45A2F9-C10283E4-AA82B019-3318CD21
```

> [!TIP]
> The printed **Key ID** is a 128-bit SHA-256 fingerprint formatted as `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX` for out-of-band verification.

---

## 7. Step 5: Reclaiming Staging Remnants (`clean`)

Decryption uses same-filesystem staging wrappers (`.ombracrypt_stage_*`) guarded by `.active.lock` sentinels. If a run is halted by power loss, process kill (`SIGKILL`/`SIGTERM`), or a locked-file cleanup warning, run `clean` to inspect and sweep abandoned staging remnants:

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
> `clean` rejects symlink roots, skips active locked operations and symlinks, preserves unrecognized non-empty folders, and reports any incomplete removals explicitly rather than claiming a clean sweep. Run it only on private, user-controlled directories (not untrusted multi-user shared folders). Use `-q / --quiet` to suppress terminal output.

---

## 8. Anti-Coercion: Duress Trapdoor Protocol

The optional **Duress Trapdoor** provides an interactive coercion countermeasure when unlocking a vault.

### How It Works

1. **Configuration:** When encrypting a vault with fresh keys (`ombracrypt encrypt` without `--public-key`), set a secondary **Deception Passcode** distinct from your Master Password. *(Standalone `keygen` intentionally omits the Duress Trapdoor—writing 32 bytes of CSPRNG noise instead, matching Ombracrypt Desktop—to prevent cross-vault passphrase collisions when senders seal against a shared `.obp` key.)
2. **Duress Input:** If compelled to unlock a vault (`Financials.obv`), enter your **Deception Passcode** at the password prompt.
3. **In-Place Overwrite Attempt:**
   * The engine verifies the deception passcode in constant time against the 32-byte phantom block in the `.obk` file.
   * It validates that the `.obk` target is a regular file within size bounds (not a symlink, and rejecting `st_nlink > 1` hard links on Unix), overwrites the file in place with CSPRNG noise, flushes via `sync_all()`, and returns a generic error:
     ```plaintext
     ✖ ERROR: Decryption Failed! Data corruption or mismatched cryptographic key.
     ```

> [!CAUTION]
> Duress activation irreversibly corrupts the targeted local `.obk` file on disk. If no separate offline backup of that key exists, the vault cannot be decrypted with it. However, previously copied `.obk` files, SSD wear-leveling, filesystem snapshots, and copy-on-write filesystems (Btrfs, ZFS, APFS) remain outside this protection.

---

## 9. Automation, Scripting & Headless Pipelines

Ombracrypt CLI supports non-interactive execution for scripts and scheduled backups. Intentional leading/trailing passphrase whitespace is preserved (only trailing `\r`/`\n` line terminators are stripped).

### 1. Environment Variables

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

Use `--password-env <VAR>` to read from a custom environment variable name.

### 2. Restricted Password Files

```bash
ombracrypt encrypt \
  --target "/data/sensitive" \
  --password-file "/etc/vault.key" \
  --output-dir "/backups" \
  --quiet
```

### 3. Standard Input Pipe

When standard input is not a TTY, Ombracrypt reads the password from stdin:

```bash
echo -n "MySuperSecurePassword" | ombracrypt encrypt \
  --target "/data/payroll" \
  --output-dir "/backups" \
  --quiet
```

### 4. Automated Backup Script Example

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="/opt/production_data"
BACKUP_DIR="/mnt/encrypted_backups"
PUBKEY="/root/keys/infrastructure_backup.obp"

echo "[+] Running Pre-Flight Assessment..."
ombracrypt inspect --mode encrypt --target "$TARGET_DIR" --output-dir "$BACKUP_DIR" --json

echo "[+] Sealing Post-Quantum Vault..."
ombracrypt encrypt \
  --target "$TARGET_DIR" \
  --public-key "$PUBKEY" \
  --output-dir "$BACKUP_DIR" \
  --password-file "/root/secrets/vault_master.pass" \
  --quiet

echo "[✓] Backup completed."
```

---

## 10. Troubleshooting & Operational Boundaries

### "Destination already exists in the output folder"

* **Cause:** Ombracrypt enforces collision-proof atomic publication and refuses to overwrite an existing vault, key, or extracted directory.
* **Solution:** Choose a different `--output-dir` or move/rename the existing item first.

### "Insufficient Disk Space to extract vault"

* **Cause:** Pre-flight estimation found less free space on the destination filesystem than required for the payload.
* **Solution:** Free disk space or extract to another volume with sufficient capacity.

### "Invalid Private Key (.obk): Unrecognized header or corrupted file"

* **Cause:** The key file does not start with `OBSK\x02`, is truncated, or was previously overwritten by the Duress Trapdoor.

### "Operation aborted by user" (`Ctrl+C`)

* **Cause:** `Ctrl+C` (`SIGINT` on Unix, `CTRL_C_EVENT` on Windows) was received.
* **Best-Effort Rollback:** The CLI sets an atomic cancellation flag, stops streaming at the next cancellation boundary, and attempts to remove in-flight staging artifacts. If OS locks or permission errors prevent full cleanup, the CLI prints an explicit incomplete-cleanup warning so you can inspect the path or run `ombracrypt clean`.
* **Unintercepted Signals & Crashes:** Termination signals not intercepted by the CLI (`SIGTERM`, `SIGHUP`, `SIGKILL`) and power failures exit without running cancellation cleanup; recover any leftover `.ombracrypt_stage_*` directories afterward with `ombracrypt clean`.

For full security policies and filesystem boundaries, see [SECURITY.md](../../SECURITY.md).

---

## Desktop & CLI Interoperability Quick Check

| Action | CLI Execution | Desktop GUI Action |
| :--- | :--- | :--- |
| **Unlock CLI Vault in Desktop** | `ombracrypt encrypt -t "/data"` | Open Ombracrypt Desktop → Switch to **Decrypt** → Select `data.obv`, `data.obk`, and output folder → Enter password → Click **Unlock Vault**. |
| **Unlock Desktop Vault in CLI** | Lock folder in Ombracrypt Desktop | `ombracrypt decrypt -t "data.obv" -k "data.obk" -o "/restore"` |
| **Share Public Sealing Key** | `ombracrypt keygen -n "alice"` | Share `alice.obp` with any Desktop or CLI user to seal vaults for Alice without sharing `alice.obk`. |