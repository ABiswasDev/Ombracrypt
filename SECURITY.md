# Security Policy

## Supported Versions

Currently, only the stable production releases are actively supported with security patches. Experimental or beta builds are deprecated.

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | ✅                 |
| v0.x.x  | ❌ (Deprecated)    |

## Reporting a Vulnerability

As a cryptographic vault designed for zero-trust, post-quantum security, Ombracrypt takes all potential vulnerabilities seriously. 

**Please do not report security vulnerabilities through public GitHub issues or discussions.** Publicly disclosing a flaw before a patch is available puts all current users at risk.

If you believe you have discovered a security vulnerability, memory leak, hardware synchronization flaw, or cryptographic implementation bypass, please report it privately using one of the following methods:

*   **Email:** [ombraveil.choice471@passinbox.com](mailto:ombraveil.choice471@passinbox.com)
*   **LinkedIn:** Send a direct message via the [Ombraveil LinkedIn Page](https://www.linkedin.com/company/ombraveil/).

### What to Include in Your Report
To help validate and resolve the issue as quickly as possible, please provide:
*   A concise description of the vulnerability and its potential impact.
*   The exact version of Ombracrypt (e.g., v1.0.0) and the operating system environment.
*   Step-by-step instructions to reproduce the issue.
*   Any relevant system logs, crash dumps, or memory profiles.

## Response Protocol

1.  **Acknowledgment:** You will receive a private confirmation acknowledging receipt of your report within 48 to 72 hours.
2.  **Triage:** The issue will be evaluated and tested against the active Rust cryptographic pipeline and Tauri frontend.
3.  **Patching:** If validated, a fix will be engineered and pushed in an expedited security release.
4.  **Attribution:** With your explicit consent, you will be formally credited in the public release notes and repository changelog for responsibly disclosing the vulnerability.