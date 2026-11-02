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
| **Private Quantum Key** | `.obk` | Contains wrapped hybrid private key material (ML-KEM + X25519) required for decryption. | **CRITICAL SECRET** | Keep strictly offline / Air-gapped |
| **Public Sealing Key** | `.obp` | Asymmetric public key used by contributors to seal new vaults for a recipient. | Public Information | Share freely with teams/pipelines |

---

## Mode 1: Single-User Sovereign Backup & Cloud Archiving

Use this mode to back up sensitive files to commercial cloud storage (Google Drive, OneDrive, AWS S3, Dropbox) without trusting the cloud provider, their infrastructure, or subpoena susceptibility.

### Encryption Procedure

#### Step 1: Configure Cryptographic Engines
1. Launch Ombracrypt.
2. Under **Cipher Algorithm**, select your symmetric AEAD engine:
   - `XChaCha20-Poly1305` (recommended default; 192-bit extended nonce resilience).
   - `AES-256-GCM` (hardware-accelerated AES-NI).
3. Under **KEM Algorithm**, select your hybrid post-quantum encapsulation profile:
   - **IETF X-Wing:** Standard hybrid (`ML-KEM-768` + `X25519`).
   - **Cypherpunk:** High-security profile (`ML-KEM-1024` + `X25519`).
4. Enter and confirm a strong **Master Password**.
5. *(Optional)* Expand **Advanced Security Options** to configure a **Deception Passcode** for coercion defense.

#### Step 2: Select Source Directory & Lock Vault
1. Click **Encrypt Folder** and choose the directory you want to secure.
2. Confirm the displayed target directory path.
3. Click **Lock Vault**. Ombracrypt will compress the tree into an in-memory stream, derive chunk keys, and produce authenticated chunks.
4. Wait for the progress indicator to reach 100%.

#### Step 3: Key Separation & Cloud Upload
Upon completion, three linked artifacts will exist in the parent folder of the source directory:
* `[FolderName].obv` (Encrypted Vault)
* `[FolderName].obk` (Private Key)
* `[FolderName].obp` (Public Key)

> **Mandatory Security Action:**  
> 1. Move `[FolderName].obk` immediately to an air-gapped, offline storage drive (e.g., hardware-encrypted USB).  
> 2. Sync `[FolderName].obv` to your cloud backup, NAS, or remote archive.  
> 3. Verify that the `.obk` file is **never** uploaded to the cloud alongside the `.obv` vault.

---

### Decryption Procedure (Restoration)

1. Connect your offline media containing your `.obk` file to your workstation.
2. Open Ombracrypt and navigate to the **Decrypt Vault** view.
3. Under **Vault File**, select the `.obv` vault downloaded from your cloud backup.
4. Under **Key File**, select the corresponding `.obk` file from your offline media.
5. Enter your **Master Password**.
6. Click **Unlock Vault**.
7. The engine authenticates the stream chunk-by-chunk into an isolated staging workspace and atomically publishes the restored folder upon full cryptographic verification.

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
1. The recipient generates an Ombracrypt keypair.
2. The recipient securely stores their `.obk` private key offline.
3. The recipient sends their public key (`team_lead.obp`) to team members, commits it to a Git repository, or uploads it to a CI/CD server.

#### 2. Sender Seals Vault (One-Way Encryption)
1. The sender opens Ombracrypt and selects the folder to send.
2. Instead of generating a new private key, the sender loads `team_lead.obp` into the public key input.
3. The sender enters the agreed project passphrase and locks the vault.
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

The Deception Passcode is a cryptographic zeroization mechanism designed for physical coercion, border inspections, or hostile access demands.

### Mechanism & Behavior

1. **Pre-Configuration:** When locking a vault, define both a **Master Password** and an alternate **Deception Passcode**.
2. **Duress Invocation:** When forced to open the vault under duress, enter the **Deception Passcode** in the password field instead of the real password.
3. **Plausible Error Display:** The application displays an authentic, indistinguishable authentication error:  
   `Decryption Failed! Data corruption or mismatched cryptographic key.`
4. **Permanent In-Place Zeroization:** Behind the scenes, the engine opens the targeted `.obk` file and irreversibly overwrites the encapsulated key payload with random noise from an OS-level CSPRNG (`getrandom`/`BCryptGenRandom`). Outer headers and file sizes remain completely unchanged.
5. **Irreversible Neutralization:** Because Ombracrypt relies on split-factor cryptography, destroying the `.obk` private key payload breaks the mathematical chain forever. The `.obv` vault becomes mathematically unrecoverable to everyone, including yourself and the adversary.

> **Warning:** Duress zeroization executes instantly and permanently destroys the target `.obk` file. Never test your duress code against your only copy of a production key.

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