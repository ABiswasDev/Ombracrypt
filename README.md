<p align="center">
  <img src="images/banner.png" alt="Ombracrypt Banner" width="800">
</p>

<h1 align="center">Ombracrypt</h1>

<p align="center">
  <strong>The zero-trust quantum vault for cross-platform data sovereignty.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/ABiswasDev/Ombracrypt?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/license/ABiswasDev/Ombracrypt?style=flat-square" alt="License">
</p>

### Overview & Features

Ombracrypt is a network-isolated, cross-platform Post-Quantum Cryptographic (PQC) file encryption utility dedicated to securing digital assets. It is explicitly designed to defend against future quantum computing-based cyberattacks, ensuring absolute data privacy without relying on external infrastructure or cloud services. The application combines an intuitive interface with a high-performance cryptographic engine.

<p align="center">
  <img src="images/Tool_shot.png" alt="Ombracrypt Interface" width="450">
</p>

* **Cross-Platform:** Native installers generated via automated CI/CD for Linux, Windows, and macOS.
* **Network-isolated Execution:** No telemetry, no cloud accounts, and no internet connection required.
* **Modern Cryptography:** Utilizes NIST-standard file encryption algorithms validated through CAVP and CMVP.
* **Hybrid KEM Architecture:** Employs a hybrid Key Encapsulation Mechanism (KEM) that combines traditional cryptography with Post-Quantum Cryptography (PQC) to provide enhanced encryption.


## Security & Threat Model
Transparency is paramount in cryptographic tooling. Ombracrypt is strictly designed to secure data at rest against modern and future threats, but it operates under the assumption that the host environment itself is secure.

**In Scope:**
*   **Post-Quantum Resilience:** Protecting Ombracrypt Vaults (`.obv`) stored on untrusted public clouds or shared media against "Store Now, Decrypt Later" (SNDL) attacks utilizing quantum computing.
*   **Cryptographic Agility:** Offering a modular selection of symmetric ciphers and Key Encapsulation Mechanisms (KEMs), empowering users to calibrate the trade-off between cryptographic strength and processing overhead.
*   **Secure Bundling:** Consolidating multiple heterogeneous files into a single encrypted `.obv` vault for streamlined, organized data management.
*   **Physical & Local Security:** Mitigating unauthorized local access and protecting payloads against the physical theft of offline storage devices.
*   **Supply Chain Integrity:** Ensuring transparent, verifiable release binaries through automated GitHub Actions CI/CD 
*   **Anti-Coercion (Deception Passcode):** Mitigates interactive physical duress via an optional secondary passcode that silently overwrites the Ombracrypt Key (`.obk`) with random noise and returns a standard decryption failure error to maintain plausible deniability.

**Out of Scope:**
*   **Endpoint Compromise:** Defending against active keyloggers, memory scraping, screen-recording malware, or inherently compromised host operating systems.
*   **Data Recovery:** Retrieving encrypted payloads if the master passphrase is forgotten or the Ombracrypt Key (`.obk`) file is permanently lost. Our zero-knowledge architecture means there are absolutely no backdoors.

## Core Architecture and Cryptanalysis (v0.4.3)

* **Hybrid KEM Engine:** Implements the X-Wing hybrid paradigm, fusing classical X25519 Elliptic Curve Diffie-Hellman with Post-Quantum ML-KEM (Kyber-768/1024) through a SHA-256 combiner to mitigate both classical and quantum attacks.
* **Chunked Streaming Engine:** Utilizes a strict 1MB chunked streaming architecture, enabling the encryption of large payloads while maintaining a low, predictable RAM footprint.
* **Hardware-Level Failsafes:** Engineered with OS-level error interception to catch hardware-bound interruptions (such as filesystem storage exhaustion) and trigger secure rollback cleanup.
* **Memory Zeroization:** Integrates the `zeroize` crate to force automatic memory scrubbing of all ephemeral keys, passcodes, and shared secrets from active RAM upon task completion.

## Known Limitations & Mitigation Best Practices

Ombracrypt is designed with strict security parameters, but users must understand its operational boundaries. Below are the known limitations alongside actionable best practices to mitigate them.

### 1. Operational & Environmental Risks
*   **Crash Data Remanence (`.tmp.tar` Vulnerability):** To encrypt large payloads without exhausting RAM, the engine dynamically bundles your selected files into a temporary `.tmp.tar` file on your local disk. If your computer loses power, crashes, or the OS forcefully kills the process mid-encryption, the secure rollback protocol will not execute, leaving the unencrypted archive exposed on your drive.
    *   *Best Practice:* If an unexpected crash occurs during encryption, manually inspect the target directory and securely delete any lingering `.tmp.tar` files. Avoid encrypting highly sensitive payloads on unstable hardware or failing drives.
*   **Endpoint Compromise:** Ombracrypt assumes the host operating system is secure. It provides zero protection against active keyloggers, memory-scraping malware, screen recorders, or rootkits.
    *   *Best Practice:* Only execute Ombracrypt on trusted, malware-free machines. For extreme threat models, execute the encryption pipeline on a completely air-gapped system or a Live USB Linux environment.

### 2. Cryptographic & Human Factors
*   **Zero-Knowledge Absolute Data Loss:** There are no backdoors, secondary master keys, or recovery mechanisms. If you forget your Master Password, or if the `.obk` key file is deleted or corrupted, your data is mathematically unrecoverable.
    *   *Best Practice:* Maintain physical, offline backups of your `.obk` key files (e.g., on secure USB drives) separated logically and physically from the encrypted `.obv` vaults.
*   **The Password Bottleneck:** The X-Wing Hybrid KEM secures the payload against quantum algorithms (like Shor's), but the vault remains locked by a symmetric key derived from your human password. A weak password bypasses the quantum defenses entirely.
    *   *Best Practice:* Utilize a high-entropy, cryptographically strong Master Password (such as a 6-word Diceware passphrase) to maximize the Argon2id KDF bottleneck.

### 3. Duress Trapdoor Constraints
*   **Offline Trapdoor Bypass:** The Plausibly Deniable Duress Trapdoor strictly defends against interactive physical coercion. It does not protect against offline analysis; an attacker who steals your `.obk` file can use a hex editor to manually delete the final 32 bytes (the Phantom Block), disabling the trapdoor entirely before attempting to brute-force the file.
    *   *Best Practice:* Rely on the trapdoor solely for real-time physical duress scenarios where you are forced to interact with the application UI. The trapdoor is a behavioral defense, not a mathematical absolute.
*   **Irreversible Destruction:** Triggering the trapdoor is permanently destructive. It overwrites the Kyber and X25519 private keys with cryptographically secure random noise, locking the vault forever.
    *   *Best Practice:* Never test the Deception Passcode on a live vault without backing up the `.obk` file first. To ensure you do not permanently lose your own data after surviving a coercion event, you must rely on a hidden, offline backup of your original `.obk` file.

## Documentation

For a comprehensive understanding of Ombracrypt's operation, engineering, and cryptographic proofs, please refer to our dedicated documentation files:

* **[Quick Start Guide](docs/QUICKSTART.md):** Visual, step-by-step instructions for encrypting and decrypting your first vault.
* **[System Architecture](docs/ARCHITECTURE.md):** A detailed breakdown of the Tauri/Rust isolation, the IPC bridge, and the memory-safe streaming engine.
* **[Cryptographic Threat Model](docs/CRYPTOGRAPHY.md):** In-depth cryptanalysis, entropy proofs, and the complete Post-Quantum Key Encapsulation pipeline.

## Download &Installation

Download the latest stable release from our [Releases Page](https://github.com/ABiswasDev/Ombracrypt/releases).

* **Linux (Debian-based distributions):** Download and install the `.deb` package.
* **Linux (Red Hat-based distributions):** Download and install the `.rpm` package.
* **Windows:** Download and run the `.exe` or `.msi` setup file.
* **macOS:** Mount the `.dmg` image or extract the `.app.tar.gz` archive.

To secure your data, first organize your target files into a single directory. Launch Ombracrypt, select this directory via the interface, choose your preferred cryptographic algorithms, and set a strong Master Password (and an optional Deception Passcode). The engine will process the folder and output a Quantum-Safe Vault (.obv) and a corresponding Ombracrypt Key (.obk).

To restore your files, select your `.obv` vault and `.obk` key file, input your master passphrase, and initiate the decryption process. 

## Author & Contributors

* **Abhishek Biswas** – *Lead Maintainer* – [@ABiswasDev](https://github.com/ABiswasDev)

## License & Legal Disclaimer

* **AGPL-3.0 License:** Ombracrypt is strictly open-source and licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). This is a strong copyleft license designed to keep the code free and open. Any individual or organization that modifies, distributes, or offers this software as a service over a network is legally required to release their modified source code under the exact same AGPL-3.0 license. This prevents proprietary capture or closed-source commercialization of the project. We welcome code reviews, audits, and contributions to ensure the highest standard of security. Any violation of these terms—including the unauthorized distribution or monetization of closed-source derivatives—constitutes copyright infringement and will be met with strict legal enforcement.

* **Liability & Ethical Use:** Ombracrypt is an experimental R&D project created solely to enhance cryptographic awareness and provide robust personal data security. The developer and maintainers assume zero responsibility or liability for any misuse, unethical application, or illegal activity conducted using this software. It is provided strictly for educational and personal data-protection purposes. Users assume full, sole responsibility for ensuring their use of this software complies with all applicable local, regional, and international laws, and adheres strictly to the terms of the AGPL-3.0 license.

## Developer Guide: Building from Source

Ombracrypt utilizes a Tauri architecture, bridging a lightweight web frontend with a high-performance Rust cryptographic core. If you wish to audit the code, contribute, or compile the application locally, follow these steps.

**1. Prerequisites**
Ensure your development environment has the following core tools installed:
*   [Git](https://git-scm.com/)
*   [Node.js](https://nodejs.org/) (v18 or higher)
*   [Rust & Cargo](https://rustup.rs/) (latest stable toolchain)

**Platform-Specific Dependencies:**
*   **Windows:** You must install the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/). During the installer setup, ensure the **"Desktop development with C++"** workload is selected. *(Note: Windows 10 users may also need to install the WebView2 runtime; it is pre-installed on Windows 11).*
*   **macOS:** You must install the Xcode Command Line Tools to compile the C and Rust dependencies. Open your terminal and run:
    ```bash
    xcode-select --install
    ```
*   **Linux (Debian/Ubuntu/Mint):** You must install the WebKit and GTK packages required by Tauri. Open your terminal and run:
    ```bash
    sudo apt update
    sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
    ```

**2. Local Setup & Execution**
```bash
# Clone the repository
git clone https://github.com/ABiswasDev/Ombracrypt.git
cd Ombracrypt

# Install frontend dependencies
npm install

# Launch the application in development mode (with hot-reloading)
npm run tauri dev
```

**3. Building for Production**
To build the optimized release binaries for your current operating system, run:
`npm run tauri build`

The compiled installation files will be generated inside the `src-tauri/target/release/bundle/` directory.

**4. Contribution & Automated CI/CD Releases**
Ombracrypt uses a GitHub Actions CI/CD pipeline to automatically compile, sign, and draft cross-platform releases for Windows, macOS, and Linux. 

**For Contributors (Standard Flow):**
```bash
# 1. Create a feature branch
git checkout -b feature/your-feature-name

# 2. Commit your changes with a descriptive message
git add .
git commit -m "feat: added new cipher UI"

# 3. Push and open a Pull Request on GitHub
git push origin feature/your-feature-name
```

**For Maintainers (Triggering the Pipeline):**
The automated release script is triggered by pushing a version tag to the main branch.
```bash
# Pushing a new version tag runs the CI/CD pipeline
git tag v0.4.3
git push origin v0.4.3
```

## Project structure

```plaintext
ombracrypt/
├── package.json              # Node dependencies, scripts, and build runners
├── docs/                     # Architectural specifications and threat models
│   ├── ARCHITECTURE.md       # Pipeline mechanics, memory zeroization, error trapping
│   └── CRYPTOGRAPHY.md       # Formal cryptanalysis, KEM proofs, and entropy calculations
│   └── QUICKSTART.md         # Tutorial for using Application
├── images/                   # Architecture schematics, diagrams, and UI assets
├── src/                      # Frontend Presentation Layer (Tauri Webview)
│   ├── index.html            # Main application layout and modal views
│   ├── main.js               # UI event bindings, state teardown, and IPC invocations
│   ├── styles.css            # Layout styling and UI visual design
│   └── assets/               # Frontend vector icons and branding assets
│
└── src-tauri/                # Cryptographic Core & Backend (Native Rust)
    ├── Cargo.toml            # Rust dependencies (pqcrypto-kyber, x25519-dalek, zeroize)
    ├── tauri.conf.json       # Tauri system configuration, permissions, and build targets
    ├── build.rs              # Native platform build script
    └── src/
        ├── main.rs           # Desktop application runtime entry point
        ├── lib.rs            # IPC command router & immediate memory zeroization wrapper
        ├── crypto.rs         # Hybrid KEM (Kyber + X25519), Argon2id KDF, XOR key synthesis
        ├── pipeline.rs       # 1MB chunked streaming engine, TAR I/O, AEAD ciphers
        └── deception.rs      # Duress trapdoor protocol & silent .obk random-noise scrambler
```

## Edge-Case Validation & Testing

Ombracrypt’s cryptographic core is engineered to handle extreme edge cases and hostile environmental conditions. When running local builds or contributing to the repository, ensure your changes pass the following validation matrix.

### 1. Filesystem & I/O Boundaries (Legacy & Core)
*   **Zero-Byte Payloads:** Encrypting completely empty directories or 0-byte files to ensure the TAR bundler and AEAD cipher do not panic on null inputs.
*   **Deep Path Nesting:** Processing directory trees that exceed standard OS character limits (e.g., >256 characters on Windows) to validate structural preservation.
*   **Permission Walls:** Attempting to ingest files with strict read-only or elevated-admin-only permissions to ensure the engine gracefully skips or halts without corrupting the active vault stream.
*   **Storage Exhaustion:** Filling the host drive to 99% capacity prior to encryption/decryption to verify that the OS-level `disk full` hardware interrupt correctly triggers the secure rollback and artifact deletion protocol.
*   **RAM Exhaustion Override:** Encrypting a payload significantly larger than the host machine's total available RAM (e.g., a 25GB file on a 16GB system) to validate the 1MB chunked streaming pipeline.

### 2. Cryptographic Integrity (v0.4.3 Upgrades)
*   **Key File Truncation:** Passing an `.obk` file smaller than 32 bytes to the decryption engine. The engine must immediately abort before attempting to slice the Phantom Block, preventing out-of-bounds memory panics.
*   **Header Tampering:** Modifying a single byte of the public salt, nonce, or Hybrid Ciphertext within the `.obv` file using a hex editor. The HKDF and AEAD authentication tags must instantly reject the payload.
*   **Process Termination (SIGKILL):** Force-killing the application mid-encryption to validate the known environmental limitation (leaving the `.tmp.tar` on disk) versus mid-decryption.

### 3. Deception Protocol Mechanics (v0.4.3 Upgrades)
*   **The Trapdoor Trigger:** Entering the exact Deception Passcode into the main decryption prompt. The test must verify that the UI returns a standard cipher failure error, while the `.obk` file is verified via hex-editor to be permanently overwritten with 100% random noise.
*   **Blank Passcode Parsing:** Leaving the Deception Passcode blank during encryption, and attempting to decrypt with a blank password. The engine must recognize the 32-byte appended block as random noise, not a hashed blank string, ensuring the trapdoor does not misfire.
*   **Accidental Trigger Prevention (Password Mismatch):** Attempting to decrypt the vault with an incorrect Master Password, a typo, or a random string. The test must verify that the trapdoor is strictly bypassed, the `.obk` key file remains entirely intact, and the engine safely halts with a standard authentication failure.