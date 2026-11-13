# Security Policy

## Supported Versions

Ombracrypt is currently transitioning from legacy classical builds to post-quantum hybrid architectures. Security audits, vulnerability triaging, and active patches are prioritized for the **v2.0.0-beta** evaluation release and the `main` development branch.

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
* **Triage & Validation:** The maintainers will evaluate the issue against the Rust core (`fips203`, `x25519-dalek`, `argon2`, `fs_guard.rs`, and `stream.rs`) and Tauri IPC boundary.
* **Coordination & Patching:** If validated, a fix will be implemented in a private branch, verified against the regression test suite, and published in an expedited patch release.
* **Credit & Attribution:** With your consent, you will be acknowledged in the release notes and repository changelog for your responsible disclosure.