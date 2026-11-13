# Ombracrypt Quick Start & Operational Security Guide

Ombracrypt is an offline, zero-escrow file encryption utility engineered to protect sensitive data against both classical adversaries and future quantum cryptanalysis ("Harvest Now, Decrypt Later" attacks). 

This guide details the two fundamental operating modes of Ombracrypt, step-by-step procedures for encryption and decryption, the duress zeroization failsafe, and operational hygiene rules for the post-quantum era.

---

## Operating Modes: Choose Your Use Case

Ombracrypt is architected to eliminate centralized points of compromise (such as cloud key vaults, identity provider tokens, or remote escrow servers). It serves two primary workflows:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                             OMBRACRYPT MODES                               │
├─────────────────────────────────────┬──────────────────────────────────────┤
│ 1. Single-User Sovereign Backup     │ 2. Asymmetric Group Sharing          │
│    (Untrusted Cloud & Cold Archiving)│    (Teams & Automated Pipelines)    │
├─────────────────────────────────────┼──────────────────────────────────────┤
│ • You encrypt data for yourself.    │ • Contributors seal data for you.    │
│ • `.obv` vault stored anywhere      │ • Contributors only need your public │
│   (Google Drive, Dropbox, AWS S3).  │   key (`.obp`) to encrypt.           │
│ • Private `.obk` kept strictly      │ • Contributors cannot decrypt what   │
│   offline on air-gapped media.      │   they just encrypted.               │
│ • Requires your Master Passphrase + │ • Only the recipient's private key   │
│   your `.obk` file to unlock.       │   (`.obk`) + passphrase can decrypt. │
└─────────────────────────────────────┴──────────────────────────────────────┘
```

---

## Core Cryptographic Artifacts

Every Ombracrypt operation revolves around three distinct file types:

| Artifact | File Extension | Role | Sensitivity | Distribution |
| :--- | :--- | :--- | :--- | :--- |
| **Encrypted Vault** | `.obv` | Authenticated ciphertext container holding directory trees and data chunks. | Ciphertext | Public / Cloud / Shared Drives |
| **Private Quantum Key** | `.obk` | Contains serialized hybrid private key material (ML-KEM + X25519) required for decryption. | **CRITICAL SECRET** | Keep strictly offline / Air-gapped |
| **Public Sealing Key** | `.obp` | Asymmetric public key used by contributors to seal new vaults for a recipient. | Public Information | Share freely with teams/pipelines |

---

## Mode 1: Single-User Sovereign Backup & Cloud Archiving

Use this mode to back up sensitive files to commercial cloud storage (Google Drive, OneDrive, AWS S3, Dropbox) without trusting the cloud provider, their infrastructure, or subpoena susceptibility.

### Encryption Procedure

#### Step 1: Configure Cryptographic Engines
1. Launch Ombracrypt and ensure **Key Handling Mode** is set to **Generate Keys & Encrypt Vault (.obk + .obp)**.
2. Under **Cipher Algorithm**, select your symmetric AEAD engine:
   - `XChaCha20-Poly1305 (256-bit)` (recommended default; 192-bit extended nonce resilience).
   - `AES-256-GCM (Hardware Accel)` (hardware acceleration where supported).
3. Under **Hybrid KEM Profile**, select your hybrid post-quantum encapsulation profile:
   - **X-Wing (ML-KEM-768 + X25519):** Standards-track profile (IETF Internet-Draft draft-11).
   - **Cypherpunk (ML-KEM-1024 + X25519):** High-security Category 5 profile.
4. Enter and confirm a strong **Master Password**.
5. *(Optional)* Expand **Advanced Coercion Defense (Duress Trapdoor)** to configure a **Deception Passcode**.

#### Step 2: Select Directories & Lock Vault
1. Under **Source Location**, click **Select Input Folder to Encrypt** and choose the directory you want to secure.
2. Under **Vault Destination (.obv)**, click **Select Vault Output Folder** to choose where the encrypted `.obv` vault will be written.
3. Under **Key Destination (.obk / .obp)**, click **Select Folder to Save Keys (.obk / .obp)** to choose where your keypair will be saved.
4. Confirm that the storage telemetry banner reports **Storage Verified ✓**.
5. Click **Lock Vault**. Ombracrypt will stream the directory tree in memory, derive chunk keys, and commit the authenticated `.obv`, `.obk`, and `.obp` files.
6. Wait for all three progress milestones and the progress bar to reach 100%.

#### Step 3: Key Separation & Cloud Upload
Upon completion, artifacts are written to their respective configured directories:
* `[FolderName].obv` (Encrypted Vault) is written to your chosen **Vault Destination**.
* `[FolderName].obk` (Private Key) and `[FolderName].obp` (Public Key) are written to your chosen **Key Destination** (when generating a new keypair; using an existing `.obp` produces no new private key).

> **Mandatory Security Action:**  
> 1. Move `[FolderName].obk` immediately to an air-gapped, offline storage drive (e.g., hardware-encrypted USB).  
> 2. Sync `[FolderName].obv` to your cloud backup, NAS, or remote archive.  
> 3. Verify that the `.obk` file is **never** uploaded to the cloud alongside the `.obv` vault.

---

### Decryption Procedure (Restoration)

1. Connect your offline media containing your `.obk` file to your workstation.
2. Open Ombracrypt and switch the top mode capsule to **Decrypt**.
3. Under **Encrypted Vault File**, click **Select Vault File (.obv)** to choose the downloaded `.obv` container.
4. Under **Extraction Destination Folder**, click **Select Extraction Output Folder** to choose where the restored folder will be published.
5. Under **Private Key Location (.obk)**, click **Select Private Key (.obk)** to choose the corresponding `.obk` file from your offline media.
6. Enter your **Master Password**.
7. Click **Unlock Vault**.
8. The engine authenticates the stream chunk-by-chunk into an isolated staging workspace and atomically publishes the restored folder upon full cryptographic verification.

---

## Mode 2: Asymmetric Group Sharing & Pipelines

Use this mode when collaborators, remote contractors, or automated backup agents need to package and send sensitive assets to you without granting them read access to historical archives or other users' data.

```text
Recipient (Data Steward)                  Sender (Contributor / CI/CD)
────────────────────────                  ────────────────────────────
1. Initializes Keypair
   ├── Keeps .obk strictly offline
   └── Publishes .obp ─────────────────>  2. Receives Recipient's .obp
                                                │
                                                ▼
                                          3. Encrypts Folder using:
                                             ├── Recipient's .obp
                                             └── Master Passphrase
                                                │
                                                ▼
                                          4. Uploads .obv to shared folder / S3
                                                │
5. Downloads .obv <─────────────────────────────┘
   Decrypts using:
   ├── Recipient's private .obk
   └── Master Passphrase
```

### Collaborative Workflow Steps

#### 1. Recipient Generates and Publishes Sealing Key
1. In **Encrypt** mode, set **Key Handling Mode** to **Generate Keypair Only (.obk + .obp)**.
2. Choose your **Hybrid KEM Profile** (`X-Wing` or `Cypherpunk`), enter a **Keypair File Prefix** (e.g., `team_lead`), and click **Select Folder to Save Keypair (.obk + .obp)**.
3. Click **Generate Keypair** to produce `team_lead.obk` and `team_lead.obp`. *(Note: Standalone reusable keypairs do not embed a Master Password or Duress Trapdoor; Master Passwords are set per vault during encryption, and omitting the duress block prevents cross-vault passphrase collisions.)*
4. The recipient moves `team_lead.obk` to isolated offline storage and sends `team_lead.obp` to team members, commits it to a repository, or uploads it to a CI/CD server.

#### 2. Sender Seals Vault (One-Way Encryption)
1. In **Encrypt** mode, click **Select Input Folder to Encrypt** to choose the folder to send, and click **Select Vault Output Folder** for the `.obv` destination.
2. Under **Key Handling Mode**, select **Seal with Existing Public Key (.obp)**, then click **Select Public Key (.obp)** to choose `team_lead.obp`.
3. Select the **Cipher Algorithm**, enter and confirm the agreed project **Master Password**, and click **Lock Vault**.
4. The resulting `project_data.obv` file is created.

> **One-Way Invariant:** The sender **cannot inspect, read, or decrypt** `project_data.obv` once encryption completes. Only holders of `team_lead.obk` can unlock it.

#### 3. Transit via Untrusted Channels
The sender uploads `project_data.obv` across any shared medium:
* Public or enterprise cloud storage (Dropbox, Google Drive, Box).
* S3 buckets or FTP servers.
* Email attachments or physical drives.

#### 4. Recipient Unlocks Vault
The recipient downloads `project_data.obv`, launches Ombracrypt, provides their local `team_lead.obk`, enters the passphrase, and extracts the plain directory structure.

---

## Coercion Defense: Deception Passcode (Duress Failsafe)

The Deception Passcode is a local private-key overwrite countermeasure intended for physical coercion, border inspections, or hostile access demands.

### Mechanism & Behavior

1. **Pre-Configuration:** When locking a single-user vault using **Generate Keys & Encrypt Vault (.obk + .obp)**, expand **Advanced Coercion Defense (Duress Trapdoor)** and define both a **Master Password** and an alternate **Deception Passcode**. *(Standalone keypairs created via **Generate Keypair Only** omit duress configuration to prevent collisions across multiple vaults.)*
2. **Duress Invocation:** When forced to open the vault under duress, enter the **Deception Passcode** in the password field instead of the real password.
3. **Plausible Error Display:** The application displays an authentic, indistinguishable authentication error:  
   `Decryption Failed! Data corruption or mismatched cryptographic key.`
4. **In-Place Overwrite Attempt:** Behind the scenes, the engine opens the targeted `.obk` file and overwrites the key payload in place with random noise from an OS-level CSPRNG (`getrandom`/`BCryptGenRandom`). Outer headers and file sizes remain completely unchanged.
5. **Key Neutralization:** Overwriting the local `.obk` private key payload breaks the mathematical decapsulation chain for that specific file copy. If no other usable copy of the private key exists, overwriting the selected `.obk` prevents decryption using that key material. Previously copied keys and storage-level remnants remain outside this protection.

> **Warning:** Duress execution attempts an in-place cryptographic overwrite against the selected local `.obk` file. Physical erasure cannot be guaranteed on solid-state media (SSDs/NVMe) subject to controller-level wear-leveling, filesystem snapshots, copy-on-write filesystems, or where secondary offline backups exist. Never test your duress code against your only copy of a production key.

---

## Operational Security: Do's and Don'ts

### A. Single-User Cloud & Cold-Storage Backups

#### Do
* **Maintain the Two-Location Rule:** Keep `.obv` files on your preferred storage (local drive or cloud) and your `.obk` files on an offline, air-gapped medium (such as a hardware-encrypted USB key).
* **Maintain a Cold Redundant Key Backup:** Keep an exact duplicate of your `.obk` file stored in a fireproof physical safe or safe-deposit box. If your primary USB drive fails and you lose the `.obk`, your data is lost forever.
* **Verify Passphrases Independently:** Record high-entropy master passphrases in an offline password manager or physical vault ledger.
* **Allow Atomic Promotion to Finish:** Let the progress indicator reach 100% and wait for the success dialogue before disconnecting drives, renaming folders, or turning off the machine.

#### Don't
* **Don't store `.obv` and `.obk` files in the same cloud folder:** Syncing both files to the same Google Drive or Dropbox folder reduces your split-factor security back to a single passphrase vulnerability.
* **Don't name files predictably on sensitive cloud storage:** If metadata privacy is critical, rename your `.obv` file to a non-descriptive string before cloud synchronization to prevent traffic analysis.
* **Don't test Deception Passcodes on live production keys:** Test duress triggers only on disposable test folders using temporary keys.

---

### B. Team Collaboration & Automated Pipelines

#### Do
* **Restrict Private Key Footprint:** Ensure only the designated recipient holds the `.obk` private key file. All sending agents (contractors, CI/CD runners, automated backup tasks) should strictly hold the `.obp` public sealing key.
* **Distribute Passphrases Out-of-Band:** Share project master passphrases over end-to-end encrypted messaging (e.g., Signal) or verified voice channels—never in the same repository or ticket where the `.obv` vault is uploaded.
* **Retire Old Public Keys on Personnel Changes:** If a team lead or data steward leaves the organization, generate a fresh keypair (`.obk`/`.obp`) and distribute the new `.obp` key for all subsequent vault encryptions.

#### Don't
* **Don't embed `.obk` private keys in CI/CD server secrets:** Build servers and automated runners should only ever possess the public `.obp` key for one-way vault sealing. If a runner is breached, an attacker cannot decrypt past archives.
* **Don't transmit `.obk` files via email or messaging platforms:** Private keys must never traverse a network unencrypted. If a private key must be migrated between workstations, carry it across on an air-gapped USB drive or highly secured sharing protocol.
* **Don't share a single `.obk` file across multiple untrusted departments:** When compartmentalizing sensitive team assets, generate dedicated keypairs per department or classification level.

---

### C. Post-Quantum Data Hygiene Principles

1. **Defense Against "Harvest Now, Decrypt Later" (HNDL):** Adversaries currently intercept and hoard encrypted cloud traffic, waiting for fault-tolerant quantum computers to crack RSA and classical ECC. Ombracrypt's hybrid KEM (ML-KEM + X25519) ensures that even if classical elliptic curves fall in the future, the lattice-based ML-KEM layer shields the vault key.
2. **Zero Escrow Invariant:** Ombracrypt does not use recovery servers, backdoor accounts, or administrative bypasses. Mathematical certainty is your protector and your liability: if you lose both your master password and your `.obk` file, no entity on Earth can restore your files.
3. **Clean Workspace Practices:** Ombracrypt uses zeroizing in-memory buffers to scrub plaintext chunks from memory after encryption. To prevent operating system pagefile leakage on shared workstations, run your workflows on full-disk encrypted OS drives (BitLocker, FileVault, or LUKS).