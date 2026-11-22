# Security Policy

## Supported Versions

Ombracrypt is currently transitioning from legacy classical builds to post-quantum hybrid architectures. Security audits, vulnerability triaging, and active patches are prioritized for the **v2.1.0-beta** release track and the `main` development branch.

| Version | Status | Supported | Notes |
| :--- | :--- | :--- | :--- |
| **`v2.1.0-beta`** | Current Beta | ✅ | Primary focus for active security testing, audits, and fixes. |
| **`v1.0.x`** | Legacy | ⚠️ | Critical security fixes only (deprecated architecture). |

## Reporting a Vulnerability

As an offline-first cryptographic vault designed for hybrid post-quantum confidentiality, Ombracrypt takes implementation correctness, memory safety, and cryptographic integrity seriously.

**Please do not report security vulnerabilities via public GitHub issues, discussions, or pull requests.** Public disclosure before a remediation patch is released exposes all active users to unnecessary risk.

### Private Reporting Channels

If you discover a vulnerability, implementation flaw, side-channel leakage, memory-safety issue, or bypass in the cryptographic pipeline, report it privately via:

* **Email:** [ombraveil.choice471@passinbox.com](mailto:ombraveil.choice471@passinbox.com)
* **GitHub Private Advisory:** If enabled on the repository, submit via the **Security** tab under **Report a vulnerability**.
* **LinkedIn:** Direct message via the [Ombraveil LinkedIn Page](https://www.linkedin.com/company/ombraveil/).

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:

1. **Vulnerability Summary:** A clear explanation of the vulnerability and its potential security impact (e.g., unauthorized decapsulation, AEAD chunk truncation, filesystem traversal, duress overwrite bypass).
2. **Environment Details:**
   * Ombracrypt exact version / Git commit hash (e.g., `v2.1.0-beta`).
   * Operating System and version (Linux distribution, Windows version, or macOS release).
   * Selected KEM profile (X-Wing or Cypherpunk) and symmetric cipher (AES-256-GCM or XChaCha20-Poly1305), if applicable.
3. **Reproduction Steps:** Minimal proof-of-concept (PoC) code, malformed archive/key samples, or reproduction instructions.
4. **Impact Assessment:** Expected vs. actual behavior, and whether exploitation requires local filesystem access, memory inspection, or specific threat models.

## Response Protocol

* **Acknowledgment:** You will receive an initial confirmation of your report within **48 to 72 hours**.
* **Triage & Validation:** The maintainers will evaluate the issue against the shared Rust core (`crates/ombracrypt-core`: `fips203`, `x25519-dalek`, `argon2`, `fs_guard/`, and `stream.rs`), the Tauri Desktop IPC boundary, and the CLI interface.
* **Coordination & Patching:** If validated, a fix will be implemented in a private branch, verified against the regression test suite, and published in an expedited patch release.
* **Credit & Attribution:** With your consent, you will be acknowledged in the release notes and repository changelog for your responsible disclosure.

## Local Filesystem Trust Boundary & Operational Scope

Ombracrypt is designed for single-user, locally controlled storage environments. The following filesystem boundaries apply to both Ombracrypt Desktop and Ombracrypt CLI:

### Same-Filesystem Staging & Shared Directory Boundaries

* **Same-Mount Atomic Publication:** During decryption, Ombracrypt stages extracted plaintext inside a temporary directory on the **same filesystem/mount point** as the target output directory. This layout is intentional and required so final publication can use atomic no-clobber directory renames without falling back to cross-device (`EXDEV`) plaintext copies on USB drives or secondary partitions.
* **Untrusted Multi-User Directories Out of Scope:** Encrypting, decrypting, generating `.obk` keys, or running Staging Hygiene cleanup inside world-writable or untrusted multi-user shared directories is outside the supported threat model. If another local account has write access to your extraction or key destination directory, that account can already observe, tamper with, or delete plaintext files in that folder.
* **Staging Cleaner Scope:** Orphaned staging recovery identifies abandoned `.ombracrypt_stage_*` directories and partial staging files using naming patterns, sentinel lock files (`.active.lock`), and handle identity checks. It skips active locked operations and symlinks, and removes empty markerless staging wrappers non-recursively (`rmdir`), but it does not establish cryptographic provenance against hostile local co-tenants sharing write access to the same directory.

### Platform Key Permissions & Removable Media

* **Linux & macOS:** Private key files (`.obk`) and private staging files are created with owner-only `0600` permissions, and staging directories use `0700` permissions on POSIX filesystems that honor Unix mode bits.
* **Windows & Non-NTFS Media:** On Windows, file and directory creation currently inherits parent directory ACLs rather than applying custom Win32 DACLs. Additionally, common removable cold-storage filesystems (`FAT32`, `exFAT`) do not support NTFS ACLs or Unix permission bits. Store `.obk` private keys and extract decrypted vaults only inside private, user-owned directories (such as your Windows user profile on NTFS) or physically controlled offline media.

### Cancellation, Concurrency & Best-Effort Rollback

* **Single-Operation Isolation (Desktop):** Ombracrypt Desktop enforces single-flight execution in both the frontend and Rust backend, isolating heavy cryptographic and filesystem work on blocking worker threads with per-operation cancellation tokens so overlapping submissions cannot interfere with each other's cancellation state.
* **Graceful Cancellation & Honest Reporting:** Cancellation (`Cancel` in Desktop, or `Ctrl+C` / `SIGINT` in CLI) halts processing at the next cancellation boundary and attempts staging rollback. Because OS file locks or permission changes can prevent immediate removal, Ombracrypt reports incomplete cleanup warnings whenever staging removal cannot be confirmed. Users should check reported paths or run Staging Hygiene (`ombracrypt clean` or the Desktop Maintenance modal) after any interrupted operation.