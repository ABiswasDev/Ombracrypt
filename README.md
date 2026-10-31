<p align="center">
  <img src="images/banner.png" alt="Ombracrypt Banner" width="800">
</p>

<h1 align="center">Ombracrypt</h1>

<p align="center">
  <strong>Zero-Trust Post-Quantum Cryptographic Vault for Cross-Platform Data Sovereignty</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-2d2d2d?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Security-Post--Quantum%20Hybrid%20KEM-blue?style=for-the-badge" alt="Security">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-CAL--1.0-28a745?style=for-the-badge" alt="License"></a>
</p>

---

## Executive Summary

Ombracrypt is an offline, network-isolated desktop cryptographic vault designed to secure high-value files and directories against contemporary interception and future quantum cryptanalysis. Built on a memory-safe Rust core and the lightweight Tauri desktop framework, Ombracrypt safeguards data at rest against "Store Now, Decrypt Later" (SNDL) attacks by combining lattice-based post-quantum cryptography with classical elliptic-curve key exchange.

Ombracrypt streams folder archives directly through an authenticated encryption pipeline in volatile memory. Encrypted payloads (`.obv`) and cryptographic keys (`.obk` / `.obp`) are separated by design, enabling users to store encrypted data on untrusted public clouds or external media while retaining private key material on offline hardware.

<p align="center">
  <img src="images/Tool_shot.png" alt="Ombracrypt Interface" width="450">
</p>

> **Important Notice on Versioning & Deprecation:**  
> All active engineering and future development continue exclusively on and from the **v2.x.x** architecture[cite: 20, 21]. All releases prior to version 2.0.0 (including the v1.x series) are officially **deprecated**. No further upgrades, feature backports, or security patches will be issued for legacy builds. Pre-compiled binaries for legacy releases will remain accessible on GitHub for archival and historical compatibility, but all active deployments must migrate to v2.0.0+.

### Key Capabilities

* **Dual-Profile Hybrid KEM:** Combines post-quantum lattice primitives with classical Diffie-Hellman to resist quantum algorithms while retaining classical computational hardness[cite: 3, 25].
* **In-Memory Encryption Streaming:** Streams directory trees directly into an authenticated encryption pipeline in 1&nbsp;MiB chunks without generating an intermediate unencrypted TAR archive on disk[cite: 8, 9, 25].
* **Cryptographic Artifact Separation (`.obv` / `.obk` / `.obp`):** Encrypted vaults (`.obv`) are mathematically decoupled from private keys (`.obk`)[cite: 8, 25]. Public sealing keys (`.obp`) enable one-way vault encryption without exposing private decapsulation keys[cite: 8, 25].
* **Interactive Duress Response:** An optional deception passcode triggers an in-place CSPRNG overwrite attempt against the selected private key file, followed by a standard authentication error response[cite: 4, 8, 25].
* **Defensive Filesystem Architecture:** Enforces pre-flight storage allocation checks, canonical source-destination overlap prevention, advisory sentinel locking, transactional rollback guards, and defensive TAR parsing[cite: 5, 8, 9, 25].
* **Offline & Telemetry-Free:** Operates entirely locally without network access, external servers, user accounts, or diagnostic telemetry.

---

## Downloads & Artifact Overview

Binary releases are packaged across major desktop platforms[cite: 20, 21, 25]:

| Operating System | Package Formats | Distribution Target |
| :--- | :--- | :--- |
| **Linux** | `.deb`, `.AppImage` | Debian, Ubuntu, Linux Mint, Fedora, Arch |
| **Windows** | `.msi`, `.exe` | Windows 10, Windows 11 (x64) |
| **macOS** | `.dmg` | macOS 12+ (Universal / Apple Silicon & Intel) |

Pre-compiled packages and release assets are available on the [GitHub Releases](https://github.com/ABiswasDev/Ombracrypt/releases) page.

### The Three Vault Artifacts

[ Input Folder ]  ───(Encrypt)───>  [ Vault Payload: .obv ]
[ Private Key:   .obk ]  <── Keep Private & Offline
[ Public Key:    .obp ]  <── Reusable for Sealing

1. **`.obv` (Encrypted Vault):** The authenticated, encrypted payload containing the streaming TAR archive, encrypted chunk streams, authenticated metadata, and KEM ciphertext[cite: 8, 9]. Safe for public cloud storage or transit.
2. **`.obk` (Private Key File):** The private decapsulation key file required to decrypt the corresponding vault[cite: 3, 8]. Must be stored securely on a separate drive or hardware vault.
3. **`.obp` (Public Sealing Key):** The public encapsulation key file[cite: 3, 8]. Can be shared with automated backup agents or external collaborators to encrypt vaults without granting them the ability to decrypt existing archives[cite: 8, 10, 12].

---

## Cryptographic Specification & Architecture

Ombracrypt employs a layered defense architecture combining memory-hard password derivation, post-quantum hybrid key encapsulation, and authenticated symmetric streaming.
---

## Cryptographic Specification & Architecture

Ombracrypt employs a layered defense architecture combining memory-hard password derivation, post-quantum hybrid key encapsulation, and authenticated symmetric streaming.

```text
                    +-----------------------------+
                    |  User Passphrase (PIN/Pass) |
                    +-----------------------------+
                                  |
                                  v
                   [ Argon2id KDF (64 MiB, 3 T) ]
                                  |
                                  v
                      +-----------------------+
                      | Symmetric Key (32 B)  |
                      +-----------------------+
                                  |
   +------------------------------+-------------------------------+
   |                                                              |
   v                                                              v
+-----------------------+                             +-----------------------+
|  KEM Profile 1:       |                             |  KEM Profile 2:       |
|  IETF X-Wing          |                             |  Cypherpunk Custom    |
|  (ML-KEM-768+X25519)  |                             |  (ML-KEM-1024+X25519) |
+-----------------------+                             +-----------------------+
   |                                                              |
   +------------------------------+-------------------------------+
                                  |
                                  v
                     [ Hybrid Shared Secret (32 B) ]
                                  |
                                  v
            +--------------------------------------------+
            | RFC 5869 HKDF-SHA256 Master Key Expansion  |
            +--------------------------------------------+
                                  |
                                  v
                      +-----------------------+
                      | Master Key (32 Bytes) |
                      +-----------------------+
                                  |
                                  v
               [ 1 MiB Chunked AEAD Streaming Engine ]
               [ XChaCha20-Poly1305 or AES-256-GCM   ]
```

### 1. Hybrid Key Encapsulation Mechanisms (KEM)

Ombracrypt provides two hybrid key encapsulation profiles:

| Profile Name | Specification Reference | Components | Ciphertext Wire Size | Private Key Structure (`.obk`) |
| :--- | :--- | :--- | :--- | :--- |
| **Profile 1: X-Wing** | IETF `draft-connolly-cfrg-xwing-kem-11` (Informational Draft) | NIST FIPS 203 ML-KEM-768 + X25519 | 1,120 bytes[cite: 9] | 86 bytes (32-byte canonical seed + duress block)[cite: 3] |
| **Profile 2: Cypherpunk** | Ombracrypt Custom Non-Standard Hybrid Profile | NIST FIPS 203 ML-KEM-1024 + X25519 | 1,600 bytes[cite: 9] | 3,254 bytes (Expanded key material + duress block)[cite: 3] |

#### Profile 1: X-Wing (ML-KEM-768 + X25519)
Profile 1 implements the hybrid post-quantum key encapsulation mechanism specified in IETF Informational Internet-Draft `draft-connolly-cfrg-xwing-kem-11`[cite: 3]:
* **Key Derivation:** A 32-byte seed expands via SHAKE256 into 96 bytes[cite: 3]. The first 64 bytes seed deterministic key generation for ML-KEM-768 ($d \parallel z$), while the final 32 bytes form the scalar for X25519[cite: 3].
* **Volatile RAM Expansion:** Private keys (`.obk`) store the 32-byte seed directly[cite: 3]. Key expansion occurs strictly inside volatile memory upon unlock; expanded key material is zeroized immediately after decapsulation[cite: 3].
* **SHA3-256 Combiner:** Shared secret synthesis strictly follows the draft concatenation formula using the official 6-byte ASCII domain separator `\.//^\`[cite: 3]:
  $$\text{ss} = \text{SHA3-256}\left(\text{ss}_{\text{ML-KEM}} \parallel \text{ss}_{\text{X25519}} \parallel \text{ct}_{\text{X25519}} \parallel \text{pk}_{\text{X25519}} \parallel \texttt{"\textbackslash.//\textasciicircum\textbackslash"}\right)$$

#### Profile 2: Cypherpunk (ML-KEM-1024 + X25519)
A custom hybrid profile engineered for environments seeking Category 5 post-quantum security parameters:
* **Primitives:** Combines NIST FIPS 203 ML-KEM-1024 with classical RFC 7748 X25519[cite: 3].
* **Combiner:** Follows the same cryptographic combiner pattern using the isolated 6-byte domain separator `OMBMX2`[cite: 3].
* **Standardization Notice:** Profile 2 is a custom Ombracrypt construction. While its underlying primitives (FIPS 203 and RFC 7748) are standardized, the hybrid combination itself is not an IETF or NIST standard.

#### Post-Quantum Primitives Implementation
ML-KEM encapsulation and decapsulation operations are executed by the `fips203` crate, a pure-Rust, `#![no_std]`, constant-time implementation of the finalized NIST FIPS 203 standard[cite: 3].

---

### 2. Password Key Derivation & Master Key Synthesis

* **Argon2id Memory-Hard KDF:** User passphrases pass through Argon2id configured with explicit parameters:
  * Memory Cost ($m$): $65{,}536\text{ KiB}$ ($64\text{ MiB}$)
  * Time Cost ($t$): $3\text{ passes}$
  * Parallelism ($p$): $4\text{ lanes}$
  * Salt: 16 cryptographically secure random bytes generated per vault operation.
* **RFC 5869 HKDF-SHA256 Master Key Expansion:** The 32-byte Argon2id output and the 32-byte KEM hybrid shared secret concatenate into a 64-byte input keying material ($\text{IKM}$). HKDF-SHA256 expands this input with the vault salt and domain context `OMBRACRYPT-V2-MASTER-KEY` into a uniform 256-bit symmetric Master Key:
  $$\text{MasterKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{Salt}, \text{ArgonKey} \parallel \text{HybridSS}), \texttt{"OMBRACRYPT-V2-MASTER-KEY"}, 32)$$

---

## Filesystem Safety & Defensive Architecture

Writing and extracting archives on shared or untrusted storage introduces race conditions and namespace collisions. Ombracrypt addresses these through defensive filesystem guards implemented in `fs_guard.rs`[cite: 5, 11, 25].

### Staging Lifecycle & Concurrency Safeguards
* **Restricted Staging Artifacts:** Staged files use a strict 54-byte namespace (`.ombracrypt_part_<32hex>.part` with `0600` permissions on Unix)[cite: 5, 11]. Extraction directories use a strict 50-byte namespace (`.ombracrypt_stage_<32hex>` with `0700` permissions on Unix)[cite: 5, 11].
* **Sentinel Locking:** Active extraction staging directories contain an exclusively locked `.active.lock` file descriptor[cite: 5, 11].
* **Post-Lock File-Identity Validation:** Background cleaners attempting to sweep abandoned directories verify the locked file handle against the filesystem before unlinking[cite: 11]. On Unix, the cleaner verifies `st_nlink > 0` and checks matching `st_dev` and `st_ino`[cite: 11]. On Windows, the cleaner inspects `BY_HANDLE_FILE_INFORMATION` via `GetFileInformationByHandle` to confirm volume serial number and file index matching, preventing stale-handle deletion races[cite: 11].
* **Process-Local Registry:** A thread-safe global registry tracks active staging paths within the process, preventing internal worker threads from cleaning files currently being written[cite: 5, 11].


---

## Interactive Duress Key Overwrite

Ombracrypt includes an optional defensive countermeasure for physical coercion scenarios.

### Protocol Operation
When generating a keypair, the user can define an optional **Deception Passcode** alongside their primary Master Password[cite: 8, 25]:
1. **The Phantom Block:** A 32-byte block is derived via Argon2id from the Deception Passcode and an independent salt, then stored within the `.obk` file[cite: 3, 25]. If no passcode is configured, 32 bytes of CSPRNG noise are written[cite: 3, 25].
2. **Duress Verification:** During decryption, the entered passphrase is verified in constant time against the Phantom Block[cite: 3, 25].
3. **In-Place Overwrite Attempt:** If the Deception Passcode matches[cite: 4, 8, 25]:
   * The `.obk` target is checked using file metadata to verify it is a regular file within valid bounds ($64\text{ B} \le \text{size} \le 8{,}192\text{ B}$) and not a symlink.
   * On Unix, `st_dev` and `st_ino` are checked across `open()` to prevent TOCTOU link substitution[cite: 4].
   * The file is overwritten with CSPRNG noise and flushed via `sync_all()`.
   * The application halts and returns the generic authentication failure message:
     ```
     Decryption Failed! Data corruption or mismatched cryptographic key.
     ```
4. **Defensive Intent:** This provides an interactive defensive measure under immediate duress[cite: 25]. However, it does not provide cryptographic plausible deniability against advanced forensic analysis (see Threat Model)[cite: 25].

---

## Threat Model & Boundaries

### In Scope
* **Post-Quantum Data Confidentiality:** Protecting static archives on cloud storage or untrusted media against future cryptanalysis by quantum computers[cite: 25].
* **Cryptographic Agility:** Supporting both XChaCha20-Poly1305 and AES-256-GCM symmetric streaming alongside standard (X-Wing) and high-security (Cypherpunk) KEM profiles[cite: 3, 8, 25].
* **Artifact Decoupling:** Enabling workflows where vault data (`.obv`) and private keys (`.obk`) reside on isolated media[cite: 25].
* **Archive Safety:** Defending host filesystems against Zip-Slip traversal, symlink hijacking, and archive bomb denial-of-service during extraction[cite: 9, 25].
* **Interactive Coercion Response:** Providing a mechanism to destroy private key material in place when forced to enter credentials[cite: 4, 25].

### Out of Scope & Operational Realities
* **Compromised Host Operating Systems:** Cannot protect against active kernel rootkits, memory scrapers, keyloggers, or compromised display servers on the host machine[cite: 25].
* **Zero-Escrow Recovery:** There are no backdoors, recovery keys, or escrow bypasses[cite: 25]. A lost Master Password or lost `.obk` file renders data permanently unrecoverable[cite: 25].
* **Offline Phantom Block Analysis:** The Duress Trapdoor is an interactive countermeasure[cite: 25]. An adversary who clones the `.obk` file prior to the interaction can bypass the in-place overwrite[cite: 25].
* **Flash Storage Wear-Leveling Residue:** Overwriting an `.obk` file flushes CSPRNG noise to the filesystem, but SSD controllers using dynamic wear-leveling may retain latent physical flash blocks until trimmed or garbage-collected[cite: 25].
* **Decryption Staging Residue:** Encryption streams directly from memory without writing temporary TAR archives to disk[cite: 8, 9, 25]. Decryption extracts validated plaintext files into a restricted local staging folder before atomic publication[cite: 8, 9, 25]. A crash or power loss during extraction can leave partial plaintext files in that staging folder until cleared by the user[cite: 25].

---

## Verification & Conformance Test Suite

The cryptographic implementation and filesystem safety invariants are validated through automated test suites on Linux, macOS, and Windows via GitHub Actions:

```bash
cd src-tauri
cargo test --release

Coverage Breakdown

The test suite covers:   
tests.rs+ 1

    X-Wing Independent Reference KAT (test_sprint10_xwing_independent_reference_kat): Byte-exact verification against independent Known-Answer Test fixtures generated with Cloudflare CIRCL v1.6.5, validating public key encoding (1,216 bytes), ciphertext layout (1,120 bytes), ephemeral X25519 scalar multiplication, and decapsulated shared secret matching.   
    tests.rs+ 1

    IETF Combiner KAT (test_sprint9_xwing_combiner_specification_kat): Validates the SHA3-256 combiner against the static literal test vector using the \.//^\ domain separator.   
    tests.rs+ 1

    NIST FIPS 202 & RFC 7748 KATs (test_sprint6_nist_fips202_and_rfc7748_official_kat_vectors): Asserts SHA3-256, SHAKE256, and X25519 Diffie-Hellman operations against official standards vectors.   
    tests.rs+ 1

    Implicit Rejection Verification: Asserts that decapsulating corrupted ML-KEM ciphertexts triggers implicit rejection, returning an alternate pseudorandom key rather than failing noisily.   
    tests.rs+ 1

    Filesystem Race & Concurrency Tests: Validates multi-threaded contention using Arc<Barrier> across simultaneous file and directory publishers (atomic_publish_noreplace and atomic_publish_dir_noreplace), asserting that winning publishers commit atomically while losers fail closed without clobbering data.   
    tests.rs+ 1

    Sentinel & Stale FD Validation: Tests active locked directory protection, stale sentinel reclamation, and post-lock file-identity verification (st_nlink == 0 on Unix and BY_HANDLE_FILE_INFORMATION index validation on Windows).   
    tests.rs+ 1

    Notice: Automated regression tests and Known-Answer Tests confirm specification conformance and implementation consistency, but do not substitute for an independent third-party security audit.

Building from Source
Prerequisites

    Git[cite: 25]

    Node.js (v18 or higher)[cite: 25]

    Rust & Cargo (latest stable toolchain)[cite: 25]

System Dependencies

    Linux (Debian / Ubuntu / Linux Mint):
    Bash

    sudo apt-get update
    sudo apt-get install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
                            libssl-dev libgtk-3-dev libayatana-appindicator3-dev \
                            librsvg2-dev libxdo-dev

    macOS: Xcode Command Line Tools[cite: 25]:
    Bash

    xcode-select --install

    Windows: Visual Studio C++ Build Tools with the Desktop development with C++ workload[cite: 25].

Compilation Steps
Bash

# 1. Clone the repository
git clone [https://github.com/ABiswasDev/Ombracrypt.git](https://github.com/ABiswasDev/Ombracrypt.git)
cd Ombracrypt

# 2. Install reproducible frontend dependencies
npm ci

# 3. Launch application in desktop development mode
npm run tauri dev

# 4. Compile optimized standalone installer bundles
npm run tauri build

Compiled desktop bundles (.deb, .AppImage, .msi, .exe, .dmg) are output to src-tauri/target/release/bundle/[cite: 25].
Project Structure
Plaintext

ombracrypt/
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Multi-platform CI regression suite
│       └── release.yml                # Multi-platform release bundle packaging
├── docs/
│   └── QUICKSTART.md                  # User onboarding & key generation guide[cite: 25]
├── images/                            # Application captures and schematics[cite: 25]
├── src/                               # Frontend Presentation Layer (Tauri WebView)[cite: 25]
│   ├── index.html                     # Fixed-geometry workspace layout & controls[cite: 17, 25]
│   ├── main.js                        # IPC event dispatchers, progress telemetry[cite: 18, 25]
│   └── styles.css                     # Ombraveil dark UI styling & typography[cite: 19, 25]
├── src-tauri/                         # Native Rust Core Engine[cite: 25]
│   ├── capabilities/
│   │   └── default.json               # Desktop security policy & IPC permissions[cite: 20, 21]
│   ├── tests/
│   │   └── fixtures/
│   │       └── xwing_revision11/      # CIRCL v1.6.5 Known-Answer Test fixtures[cite: 10, 12]
│   ├── Cargo.toml                     # Manifest (fips203, x25519-dalek, sha3, argon2)[cite: 25]
│   ├── tauri.conf.json                # Fixed window geometry & app metadata[cite: 20, 21, 25]
│   └── src/
│       ├── main.rs                    # Desktop application entry point[cite: 7, 25]
│       ├── lib.rs                     # Tauri command handlers & application state[cite: 6, 25]
│       ├── crypto.rs                  # Hybrid KEM (X-Wing & Cypherpunk), Argon2id, HKDF[cite: 3, 25]
│       ├── fs_guard.rs                # Staging namespaces, sentinel locking, atomic commit[cite: 5, 11, 25]
│       ├── pipeline.rs                # Streaming encryption & decryption controllers[cite: 8, 25]
│       ├── stream.rs                  # In-memory chunked AEAD readers/writers & TAR guards[cite: 9, 25]
│       ├── deception.rs               # Duress key scrambling & metadata validation[cite: 4, 25]
│       └── tests.rs                   # Multi-platform regression & KAT test suite[cite: 10, 12, 25]
├── tools/
│   └── xwing-fixture-generator/       # Go / CIRCL reference KAT generator
├── package.json                       # Node workspace & build scripts[cite: 25]
├── SECURITY.md                        # Vulnerability disclosure policy
└── LICENSE                            # Cryptographic Autonomy License 1.0[cite: 25]

Author & Maintainer

    Abhishek Biswas – Lead Architect & Maintainer – @ABiswasDev[cite: 25]

License & Legal Terms

    Cryptographic Autonomy License 1.0 (CAL-1.0): Ombracrypt is open-source software licensed under the Cryptographic Autonomy License (CAL-1.0)[cite: 25]. You are free to inspect, modify, and redistribute this software[cite: 25]. Any deployment or derivative service offered over a network legally requires providing users access to the source code, their data, and their cryptographic keys/credentials, guaranteeing data sovereignty without vendor lock-in[cite: 25].

    Cryptographic & Research Notice: Ombracrypt is designed for defensive personal data sovereignty[cite: 25]. The maintainers assume zero liability for data loss resulting from forgotten passwords, lost key files, or unauthorized use[cite: 25]. Users are solely responsible for ensuring compliance with cryptographic import, export, and usage regulations in their respective jurisdictions[cite: 25].

    ⚠️ Critical Security Warning & Zero-Recovery Notice

        Zero Backdoors, Zero Escrow: Ombracrypt enforces a mathematical zero-knowledge security architecture[cite: 25]. There are no backdoor master keys, recovery phrases, password reset mechanisms, or administrative bypasses[cite: 25]. If you forget your Master Password or lose your .obk private key file, your data is cryptographically unrecoverable[cite: 25]. Maintain independent, verified backups of your private keys in offline, tamper-evident physical storage[cite: 25].

        Irreversible Duress Key Destruction: Entering your optional Deception Passcode permanently and irreversibly destroys the target .obk private key on disk by overwriting it with cryptographically secure random noise[cite: 4, 25]. Once triggered, any vault protected exclusively by that key can never be decrypted again[cite: 4, 25]. Use this countermeasure only with full awareness of its irreversible consequences[cite: 4, 25].