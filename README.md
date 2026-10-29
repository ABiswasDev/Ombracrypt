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

Ombracrypt is an offline, network-isolated desktop cryptographic vault designed to secure high-value data against contemporary threats and future quantum cryptanalysis. Built on a memory-safe Rust core and the lightweight Tauri desktop framework, Ombracrypt safeguards data at rest against "Store Now, Decrypt Later" (SNDL) interception by combining lattice-based post-quantum cryptography with classical elliptic-curve security.

Ombracrypt streams archives directly through an authenticated encryption pipeline in memory. Encrypted payloads (`.obv`) and cryptographic keys (`.obk` / `.obp`) are separated by design, enabling users to store encrypted data on public clouds or untrusted media while retaining private key material on offline hardware.

<p align="center">
  <img src="images/Tool_shot.png" alt="Ombracrypt Interface" width="450">
</p>

### Key Capabilities

* **Dual-Profile Hybrid KEM:** Combines post-quantum lattice primitives with classical Diffie-Hellman to resist quantum algorithms while preserving classical hardness.
* **Zero Disk Remanence Streaming:** Encrypts and extracts multi-gigabyte folder archives directly in volatile RAM in 1&nbsp;MiB authenticated chunks—eliminating unencrypted temporary archive files on disk.
* **Physical Key Separation (`.obv` / `.obk` / `.obp`):** Encrypted vaults (`.obv`) are mathematically decoupled from private keys (`.obk`). Public key certificates (`.obp`) enable one-way vault sealing without private key exposure.
* **Plausibly Deniable Anti-Coercion Trapdoor:** An optional deception passcode triggers a hardware-verified secure random overwrite of the target key file under physical coercion, throwing a standard authentication error to preserve plausible deniability.
* **Strict Filesystem Isolation:** Enforces pre-flight storage allocation checks, canonical overlap rejection, atomic transaction rollback guards, and defensive TAR parsing (anti-traversal, depth limits, and permission sanitization).
* **Air-Gapped & Telemetry-Free:** Operates without network access, external servers, cloud accounts, or diagnostic beacons.

---

## Cryptographic Specification & Architecture

Ombracrypt utilizes a layered cryptographic construction combining memory-hard password derivation, post-quantum hybrid key encapsulation, and authenticated symmetric streaming.

```
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
| **Profile 1: X-Wing** | IETF `draft-connolly-cfrg-xwing-kem-11` (Informational) | NIST FIPS 203 ML-KEM-768 + X25519 | 1,120 bytes | 86 bytes (32-byte canonical seed + duress block) |
| **Profile 2: Cypherpunk** | Ombracrypt Custom Hybrid Profile | NIST FIPS 203 ML-KEM-1024 + X25519 | 1,600 bytes | 3,254 bytes (Expanded key material + duress block) |

#### Profile 1: X-Wing (ML-KEM-768 + X25519)
Profile 1 implements the hybrid post-quantum key encapsulation mechanism specified in IETF Informational Internet-Draft `draft-connolly-cfrg-xwing-kem-11`:
* **Key Derivation:** A 32-byte seed expands via SHAKE256 into 96 bytes. The first 64 bytes seed deterministic key generation for ML-KEM-768 ($d \parallel z$), while the final 32 bytes form the scalar for X25519.
* **On-the-Fly Expansion:** Private keys (`.obk`) store the 32-byte seed directly. Key expansion occurs exclusively inside volatile RAM upon unlock; expanded key material is zeroized immediately after decapsulation.
* **SHA3-256 Combiner:** Shared secret synthesis strictly follows the draft concatenation formula using the official 6-byte ASCII domain separator `\.//^\`:
  $$\text{ss} = \text{SHA3-256}\left(\text{ss}_{\text{ML-KEM}} \parallel \text{ss}_{\text{X25519}} \parallel \text{ct}_{\text{X25519}} \parallel \text{pk}_{\text{X25519}} \parallel \texttt{"\textbackslash.//\textasciicircum\textbackslash"}\right)$$

#### Profile 2: Cypherpunk (ML-KEM-1024 + X25519)
An Ombracrypt custom hybrid profile engineered for environments requiring maximum lattice security:
* **Prims:** Combines NIST FIPS 203 ML-KEM-1024 (providing Category 5 security matching AES-256) with classical X25519.
* **Combiner:** Follows the same cryptographic combiner pattern using the isolated 6-byte domain separator `OMBMX2`.

#### Post-Quantum Primitives Implementation
Post-quantum ML-KEM encapsulation and decapsulation operations are executed by the `fips203` crate, a pure-Rust, `#![no_std]`, constant-time implementation of the finalized NIST FIPS 203 standard.

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

### 3. Streaming AEAD Engine (Zero Disk Remanence)

Older encryption utilities often bundle unencrypted files into a `.tar` archive on disk before passing it to a cipher, creating unencrypted recovery vectors during crashes. Ombracrypt eliminates this vulnerability via an integrated **in-memory streaming AEAD pipeline**:

* **Direct Pipeline Streaming:** Selected directory trees stream directly through a memory buffer into the authenticated cipher. Plaintext TAR blocks exist only within a 1&nbsp;MiB volatile buffer, which is immediately encrypted and flushed to the final `.obv` vault.
* **Symmetric Ciphers:**
  * **XChaCha20-Poly1305:** 256-bit key with an extended 192-bit (24-byte) random base nonce.
  * **AES-256-GCM:** 256-bit key with a 96-bit (12-byte) random base nonce.
* **Per-Chunk Nonce Incrementing:** Each 1&nbsp;MiB chunk counter ($c_i$) increments deterministically via 64-bit little-endian XOR against the base nonce, preventing nonce reuse across multi-terabyte streams:
  $$\text{Nonce}_i = \text{BaseNonce} \oplus (i \ll 0)$$
* **Header-Bound Associated Data (AAD):** Every encrypted chunk incorporates a 41-byte authenticated data payload:
  $$\text{AAD}_i = \text{SHA-256}(\text{VaultHeader}) \parallel \text{ChunkIndex}_{64} \parallel \text{IsFinal}_{8}$$
  Modifying any parameter in the vault header or reordering/truncating chunks breaks the AEAD tag verification and causes immediate extraction termination.

---

## Filesystem Safety & Defensive Architecture

Writing and extracting encrypted archives on untrusted filesystems introduces security hazards. Ombracrypt mitigates these through strict defensive invariants implemented in `fs_guard.rs`.

### Transactional Commit & Rollback Guards
* **Staging Protection:** All incomplete writes generate unique hidden staging artifacts (`.part` files or `.ombracrypt_stage_*` directories) with restricted permissions (`0600` for private keys, `0700` for extraction directories on Unix).
* **Atomic Hard-Link Publication:** Completed staging artifacts promote to their final destination via atomic hard-links. If a file collision occurs, the operation aborts.
* **Race-Free O_EXCL Fallback:** On filesystems lacking hard-link support (e.g., FAT32, exFAT USB drives), Ombracrypt reserves the final destination using atomic exclusive creation (`O_CREAT | O_EXCL`) before copying data, preventing TOCTOU file-clobbering races.
* **Rollback on Failure:** Multi-file transactions (e.g., generating `.obp` and `.obk` alongside `.obv`) use an armed rollback guard. If any operation fails, all newly committed files in that transaction are unlinked automatically.
* **Active Staging Registry:** A global in-memory registry tracks active staging paths and applies advisory file locks. Scoped cleanup routines will not remove staging files that are actively being written by another thread.

### Archive Bomb & Path Traversal Mitigations
Untrusted TAR archives inside `.obv` containers pass through strict boundary checks during decryption:
* **Zip-Slip Traversal Prevention:** Rejects paths containing parent directories (`..`), root prefixes (`/`), or volume markers.
* **Disallowed Entry Types:** Strips all special filesystem objects (symlinks, hard links, fifos, character devices, block devices). Only regular files and directories are unpacked.
* **Anti-Bomb Recursion Limits:** Enforces a maximum directory depth of $\le 64$ levels, maximum path length of $\le 512$ bytes, and a component limit of $\le 255$ bytes.
* **Entry Cap & Collision Guards:** Restricts archives to a maximum of $50{,}000$ entries, rejecting archives containing duplicate or conflicting internal paths.
* **Privilege Stripping:** Unpacks files with safe standard permissions (`0644` / `0755`), explicitly stripping `setuid`, `setgid`, and sticky bits (`07000`).

---

## Anti-Coercion & Plausible Deniability

Ombracrypt includes a duress mechanism designed for physical coercion scenarios.

### The Duress Protocol
When generating a private key (`.obk`), the user can define an optional **Deception Passcode** alongside their primary Master Password.
1. **The Phantom Block:** A 32-byte block is generated via Argon2id using the Deception Passcode and an independent random duress salt, then appended to the end of the `.obk` key file. (If no passcode is provided, 32 bytes of secure CSPRNG noise are written).
2. **Interactive Duress Activation:** When unlocking a vault, Ombracrypt checks the candidate password against the Phantom Block in constant time.
3. **Verified In-Place Scrambling:** If the Deception Passcode is entered:
   * The `.obk` file is verified via file metadata to prevent symlink substitution.
   * The file is overwritten from byte 0 to its full length with CSPRNG noise and flushed to physical disk.
   * The application returns a standard error message:
     ```
     Decryption Failed! Data corruption or mismatched cryptographic key.
     ```
4. **Plausible Deniability:** Because the error message and latency closely match an authentic AEAD authentication failure, an observer cannot determine whether the key was destroyed by a trapdoor or if the user simply made a typographical error.

---

## Threat Model & Boundaries

### In Scope
* **Post-Quantum Data Confidentiality:** Defending archives stored on public clouds or untrusted media against future quantum computing decryption attacks.
* **Cryptographic Agility:** User-configurable ciphers (XChaCha20-Poly1305 / AES-256-GCM) and KEM profiles.
* **Physical Key Separation:** Keeping payload archives (`.obv`) separated from private key files (`.obk`).
* **Offline Anti-Tampering:** Cryptographic authentication of all header fields, nonces, chunk indexes, and payload streams.
* **Physical Coercion Mitigation:** In-place cryptographic key destruction via the Duress Trapdoor.

### Out of Scope
* **Compromised Host Operating Systems:** Ombracrypt cannot protect against active kernel rootkits, physical memory scrapers, hardware keyloggers, or compromised display servers.
* **Credential Recovery:** Absolute zero-knowledge design. There are no recovery phrases, escrow mechanisms, or master administrative overrides. Forgotten passwords or lost `.obk` files result in unrecoverable data.
* **Offline Trapdoor Extraction:** The Duress Trapdoor is an interactive behavioral defense. An adversary with offline access to both the `.obk` file and the vault can inspect or strip the Phantom Block prior to attempting brute-force attacks.
* **NAND Flash Wear-Leveling Residue:** The Duress Trapdoor overwrites the `.obk` file with CSPRNG noise. On modern SSDs and flash storage with internal wear leveling, underlying controller remapping may retain latent physical sectors until hardware garbage collection or TRIM runs.
* **Decryption Crash Residue:** While encryption streams without ever creating a temporary archive on disk, decryption unpacks validated plaintext to a restricted local staging folder before moving it to the destination. A forced crash or sudden power failure during extraction may leave partial plaintext files in that staging area.
---

## Verification & Conformance Test Suite

The cryptographic engine and pipeline guards are validated through a 36-test automated regression suite:

```bash
cd src-tauri
cargo test --release
```

### Coverage Highlights

* **IETF Combiner KAT (`test_sprint9_xwing_combiner_specification_kat`):** Validates the SHA3-256 combiner against the static literal vector for $ss_{\text{ML-KEM}} \parallel ss_{\text{X25519}} \parallel ct_{\text{X25519}} \parallel pk_{\text{X25519}} \parallel \texttt{"\textbackslash.//\textasciicircum\textbackslash"}$.
* **Independent End-to-End KAT (`test_sprint10_xwing_independent_reference_kat`):** Validates the entire chain from a fixed 32-byte seed: verifies the 1,216-byte raw public key payload, 1,120-byte combined ciphertext, ephemeral X25519 derivation per RFC 7748, and decapsulated shared secret matching.
* **Standards KATs (`test_sprint6_nist_fips202_and_rfc7748_official_kat_vectors`):** Asserts SHA3-256 and SHAKE256 against NIST FIPS 202 vectors, and X25519 Diffie-Hellman against RFC 7748 Appendix A vectors.
* **Implicit Rejection Verification:** Asserts that decapsulating tampered ML-KEM ciphertexts triggers implicit rejection, returning an alternate pseudorandom key rather than failing noisily.
* **Filesystem & Bomb Defense:** Asserts rejection of path traversals (`..`), duplicate archive entries, directory recursion $> 64$ levels, and verified stripping of `07000` setuid bits.
* **Transactional Rollback Verification:** Simulates mid-transaction commit failures to ensure partially written files are wiped without leaving unauthenticated remnants on disk.

---

## Building from Source

### Prerequisites

* [Git](https://git-scm.com/)
* [Node.js](https://nodejs.org/) (v18 or higher)
* [Rust & Cargo](https://rustup.rs/) (latest stable toolchain)

#### Operating System Dependencies

* **Linux (Debian / Ubuntu / Mint):**
  ```bash
  sudo apt-get update
  sudo apt-get install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
                          libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
  ```
* **macOS:** Xcode Command Line Tools:
  ```bash
  xcode-select --install
  ```
* **Windows:** Visual Studio C++ Build Tools with the **Desktop development with C++** workload installed.

### Compilation

```bash
# 1. Clone the repository
git clone https://github.com/ABiswasDev/Ombracrypt.git
cd Ombracrypt

# 2. Install frontend dependencies
npm install

# 3. Launch application in development mode
npm run tauri dev

# 4. Build optimized standalone release package
npm run tauri build
```

Compiled native installers (`.deb`, `.rpm`, `.msi`, `.exe`, `.dmg`) are output to `src-tauri/target/release/bundle/`.

---

## Project Structure

```plaintext
ombracrypt/
├── package.json              # Node workspace configuration
├── docs/                     # Engineering documentation and specifications
│   ├── ARCHITECTURE.md       # Pipeline isolation, stream mechanics, error trapping
│   ├── CRYPTOGRAPHY.md       # Formal cryptanalysis and KEM combiner proofs
│   └── QUICKSTART.md         # Illustrated usage guide
├── images/                   # UI captures, schematics, and vector branding
├── src/                      # Frontend Presentation Layer (Tauri WebView)
│   ├── index.html            # Core workspace layout and cryptographic modal dialogs
│   ├── main.js               # IPC event bus, state management, progress updates
│   └── styles.css            # Responsive layout styling
└── src-tauri/                # Native Rust Core Engine
    ├── Cargo.toml            # Manifest (fips203, x25519-dalek, sha3, argon2, zeroize)
    ├── tauri.conf.json       # Desktop permissions, capabilities, and bundle metadata
    └── src/
        ├── main.rs           # Desktop application entry point
        ├── lib.rs            # IPC command dispatchers and state management
        ├── crypto.rs         # Hybrid KEM (X-Wing & Cypherpunk), Argon2id, HKDF
        ├── fs_guard.rs       # Path canonicalization, atomic commit, bomb defenses
        ├── pipeline.rs       # In-memory streaming encryption & decryption controllers
        ├── stream.rs         # Chunked AEAD readers/writers, TAR parser sanitization
        ├── deception.rs      # Physical duress protocol & CSPRNG key scrambling
        └── tests.rs          # 36-test verification & reference KAT suite
```

---

## Author & Contributors

* **Abhishek Biswas** – *Lead Maintainer & Author* – [@ABiswasDev](https://github.com/ABiswasDev)

---

## License & Legal Terms

* **Cryptographic Autonomy License 1.0 (CAL-1.0):** Ombracrypt is open-source software licensed under the Cryptographic Autonomy License (CAL-1.0). You are free to inspect, modify, and redistribute this software. Any deployment or derivative service offered over a network legally requires providing users access to the source code, their data, and their cryptographic keys/credentials, guaranteeing data sovereignty without vendor lock-in.
* **Cryptographic & Research Notice:** Ombracrypt is designed for defensive personal data sovereignty. The maintainers assume zero liability for data loss resulting from forgotten passwords, lost key files, or unauthorized use. Users are solely responsible for ensuring compliance with cryptographic import, export, and usage regulations in their respective jurisdictions.