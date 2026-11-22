# Frozen v2.1.0 Compatibility Fixtures (`OMBV02`)

This directory stores immutable `v2.1.0` golden artifacts used by `apps/cli/tests/interop_tests.rs` (`test_frozen_v2_1_golden_fixture_compatibility`) to guard against accidental wire-format, header, AAD, or key-file regressions across future releases.

## Committed Artifacts

| File | Size (Bytes) | Description |
| :--- | ---: | :--- |
| `golden_v2_1.obv` | 3,770 | Encrypted `OMBV02` test vault (`xwing` ML-KEM-768 + X25519, `xchacha20` XChaCha20-Poly1305) |
| `golden_v2_1.obk` | 86 | Matching canonical X-Wing private decapsulation key (synthetic test key; no duress passcode) |
| `golden_v2_1.obp` | 1,222 | Matching public sealing key |
| `expected_plaintext.txt` | 61 | Canonical UTF-8 LF reference payload (`Ombracrypt v2.1.0 immutable wire-format compatibility vector\n`) |

## Provenance & Test Parameters

* **Generating Engine:** `ombracrypt-core` `v2.1.0` (`encrypt_vault_core`), shared by both Ombracrypt Desktop and Ombracrypt CLI.
* **Synthetic Test Password:** `GoldenFixturePassword#2026!`
* **Extracted Payload Path:** `golden_v2_1/vector.txt` (normalized to LF line endings when compared against `expected_plaintext.txt` on Windows checkouts).
* **Assertions Verified in CI:**
  1. The current `ombracrypt` CLI binary decrypts `golden_v2_1.obv` using `golden_v2_1.obk` and reproduces the exact reference payload bytes.
  2. The current `ombracrypt` CLI binary seals a fresh payload against the frozen `golden_v2_1.obp` public key, and `ombracrypt-core` decrypts it using `golden_v2_1.obk`.

## Immutability Policy

* **Do not regenerate or overwrite these files** during routine development or test runs.
* Missing fixture files are treated as a **hard test failure** in CI so backward-compatibility regressions cannot be silently skipped.
* Any future format-version vector (for example, `v2.2.x`) should be added as a separate, versioned fixture set rather than replacing `golden_v2_1.*`.
* These keys are public synthetic test vectors committed to version control and must never be used to protect real data.