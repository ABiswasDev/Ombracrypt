# Ombracrypt System Architecture

## 1. System Overview (Tauri & Rust Isolation)

Ombracrypt is built upon the Tauri framework, enforcing a strict architectural separation between the presentation layer and the cryptographic execution environment. This design ensures that memory management and filesystem operations are isolated from the web-based frontend.

**The Presentation Layer (Tauri Webview)**
The frontend UI is responsible for state management, visual feedback, and the initial capture of user parameters (e.g., target file paths, cryptographic profile selection, and the Master/Deception Passcodes). 

**The Cryptographic Core (Compiled Rust Binary)**
The backend is a natively compiled Rust binary. It manages filesystem I/O, byte manipulation, streaming, and cryptographic execution. The Rust core operates without external network dependencies, ensuring local-only execution and zero telemetry.

**The IPC Command Bridge**
Communication between the frontend and the backend is routed through Tauri's Inter-Process Communication (IPC) bridge. 
* Data passed through the IPC is strictly typed and sanitized. 
* The frontend invokes the Rust backend asynchronously, passing the required passcodes and paths.
* When the Rust core receives the command, the frontend discards the sensitive inputs from its state. The Rust core executes the cryptographic operations and returns execution statuses (success metrics, progress updates, or errors) back to the UI.

<p align="center">
  <img src="/images/arch1.png" alt="Ombracrypt System Architecture Diagram" width="800">
</p>

## 2. Memory-Safe Streaming Pipeline & Modularity (v0.4.3)

Version 0.4.3 introduces a modular Rust backend (separated into `crypto.rs`, `pipeline.rs`, `deception.rs`, and a routing `lib.rs`) and utilizes a deterministic, disk-streaming pipeline to manage memory consumption.

* **On-the-Fly Archiving:** Target directories are piped directly into a temporary `.tar` stream, mitigating the need to hold the entire uncompressed dataset in active memory.
* **1MB Strict Chunking:** The unencrypted stream is sequentially segmented into 1MB chunks.
* **Continuous Execution:** The cryptographic engine processes each 1MB chunk through the selected AEAD cipher (AES-256-GCM or XChaCha20-Poly1305) and flushes the ciphertext directly to the `.obv` output file. 

This read-encrypt-write cycle maintains a low memory footprint, enabling the encryption of large payloads restricted primarily by the host machine's available disk space rather than RAM capacity.

## 3. OS-Level Error Trapping & Operational Limitations

To maintain data integrity during I/O operations, the Rust core implements OS-level hardware interrupt handling. However, specific operational vulnerabilities remain out of scope for the current software level.

* **Storage Exhaustion Interception:** If the local filesystem reaches maximum capacity during the chunked write process, the engine intercepts the OS-level "disk full" error.
* **Secure Rollback:** Upon an intercepted hardware failure or decryption validation failure, the engine initiates a rollback protocol, unlinking and deleting the partially constructed `.obv`, `.tmp.tar`, and `.obk` files to prevent corrupted vaults.
* **Out-of-Scope Vulnerability (Data Remanence on Crash):** The archiving pipeline utilizes a temporary `.tmp.tar` file written to the disk before chunked encryption begins. **If the application is forcefully terminated by the OS, crashes, or loses power during the encryption loop, the secure rollback protocol will not execute.** This leaves the unencrypted `.tmp.tar` file exposed on the local disk. Users operating in highly volatile environments should be aware of this limitation.

## 4. Application State & Cryptographic Zeroization

Ombracrypt relies on the `zeroize` crate to manage the lifecycle of cryptographic key material in active system memory.

* **Frontend State Drop:** The Tauri Webview drops the Master Password and Deception Passcode from its internal state upon IPC command resolution.
* **Backend Memory Wiping:** The Rust core wraps critical variables (human passcodes, the Argon2id hash, KEM Shared Secrets, and the synthesized Hybrid Master Key) in `Zeroizing` memory structures. Rust's ownership model automatically overwrites these specific memory allocations with zeros when the variables go out of scope (upon function completion or failure).
* **Scope Limitation:** While the primary application state is zeroized, intermediate buffers within third-party dependencies or OS-level page files/swap memory may temporarily hold sensitive fragments outside of Ombracrypt's direct control.

## 5. Plausibly Deniable Duress Trapdoor

Ombracrypt v0.4.3 introduces a coercion failsafe mechanism designed specifically to protect users subjected to interactive, physical threat models (e.g., rubber-hose cryptanalysis). 

**The Mechanism:**
During encryption, users may optionally set a **Deception Passcode**. The cryptographic engine hashes this passcode via Argon2id (using the vault's salt) and appends a 32-byte "Dummy Block" to the end of the `.obk` key file. If no deception passcode is provided, 32 bytes of cryptographically secure random noise are appended instead. This ensures all `.obk` files possess an identical structural footprint, maintaining plausible deniability.

**The Trigger:**
If an adversary physically forces the user to decrypt the vault using the Ombracrypt UI, the user inputs the Deception Passcode into the main password prompt.
1. The backend hashes the input and compares it against the final 32 bytes of the `.obk` file.
2. Upon a match, the trapdoor routes execution to the deception module.
3. The engine silently overwrites the entire `.obk` file with cryptographically secure random noise, permanently destroying the Kyber and X25519 private keys.
4. The UI returns a standard generic error (`Decryption Failed! Data corruption or mismatched cryptographic key.`), mirroring a standard symmetric cipher failure.

**Critical Limitations & Out-of-Scope Threat Vectors:**
* **Irreversible Destruction:** Triggering the trapdoor is permanently destructive. The vault becomes mathematically inaccessible unless the user has maintained a physically air-gapped backup of the original `.obk` file.
* **Physical UI Coercion Only:** This protocol is strictly designed for physical coercion where the adversary forces the user to interact with the standard Ombracrypt interface. **It does not protect against offline cryptographic analysis.** An adversary who steals the `.obk` file and analyzes the open-source architecture can simply use a hex-editor to truncate the final 32 bytes of the file, entirely bypassing the trapdoor trigger prior to attempting offline brute-force attacks.