//! Cross-Application Interoperability & End-to-End CLI Test Suite
//!
//! Verifies all four KEM x Cipher combinations (X-Wing / Cypherpunk x XChaCha20 / AES-256-GCM),
//! standalone keygen + .obp recipient sealing, inspect JSON output, staged cleanup,
//! GUI <-> CLI cross-compatibility over the shared `ombracrypt-core` engine, and immutable
//! frozen `v2.1.0` golden fixture compatibility.

use ombracrypt_core::fs_guard::TempDirGuard;
use ombracrypt_core::pipeline::{decrypt_vault_core, encrypt_vault_core};
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn create_temp_dir(label: &str) -> (PathBuf, TempDirGuard) {
    let mut rnd = [0u8; 6];
    OsRng.fill_bytes(&mut rnd);
    let dir = std::env::temp_dir().join(format!(
        "ombracrypt_cli_test_{}_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        label, rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]
    ));
    fs::create_dir_all(&dir).unwrap();
    let guard = TempDirGuard::new(dir.clone());
    (dir, guard)
}

#[test]
fn test_cli_version_banner_reports_workspace_and_core_versions() {
    let bin = env!("CARGO_BIN_EXE_ombracrypt");
    let output = Command::new(bin).arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    assert!(stdout.contains(ombracrypt_core::CORE_VERSION));
    assert!(stdout.contains("OMBV02"));
}

#[test]
fn test_cli_and_gui_core_four_profile_bidirectional_interop() {
    let bin = env!("CARGO_BIN_EXE_ombracrypt");
    let combinations = [
        ("xwing", "xchacha20"),
        ("xwing", "aes256gcm"),
        ("cypherpunk", "xchacha20"),
        ("cypherpunk", "aes256gcm"),
    ];

    for (kem, cipher) in combinations {
        let (ws, _guard) = create_temp_dir(&format!("{}_{}", kem, cipher));
        let src_dir = ws.join("payload_dir");
        let cli_vault_dir = ws.join("cli_vault");
        let gui_extract_dir = ws.join("gui_extract");
        let gui_vault_dir = ws.join("gui_vault");
        let cli_extract_dir = ws.join("cli_extract");

        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&cli_vault_dir).unwrap();
        fs::create_dir_all(&gui_extract_dir).unwrap();
        fs::create_dir_all(&gui_vault_dir).unwrap();
        fs::create_dir_all(&cli_extract_dir).unwrap();

        let expected_content = format!("Bidirectional parity payload for {} + {}", kem, cipher);
        fs::write(src_dir.join("parity.txt"), &expected_content).unwrap();

        let pass_file = ws.join("pass.txt");
        fs::write(&pass_file, "InteropSecret#2026!\n").unwrap();

        // 1. CLI encrypts -> Core/GUI decrypts
        let enc_out = Command::new(bin)
            .args([
                "encrypt",
                "--target",
                src_dir.to_str().unwrap(),
                "--output-dir",
                cli_vault_dir.to_str().unwrap(),
                "--kem",
                kem,
                "--cipher",
                cipher,
                "--password-file",
                pass_file.to_str().unwrap(),
                "--quiet",
            ])
            .output()
            .unwrap();
        assert!(
            enc_out.status.success(),
            "CLI encrypt failed ({kem}/{cipher}): {}",
            String::from_utf8_lossy(&enc_out.stderr)
        );

        let cli_obv = cli_vault_dir.join("payload_dir.obv");
        let cli_obk = cli_vault_dir.join("payload_dir.obk");

        decrypt_vault_core(
            None,
            cli_obv.to_str().unwrap(),
            Some(cli_obk.to_str().unwrap()),
            gui_extract_dir.to_str().unwrap(),
            "InteropSecret#2026!",
            None,
        )
        .unwrap_or_else(|e| panic!("Core/GUI decrypt failed ({kem}/{cipher}): {e}"));

        assert_eq!(
            fs::read_to_string(gui_extract_dir.join("payload_dir/parity.txt")).unwrap(),
            expected_content
        );

        // 2. Core/GUI encrypts -> CLI decrypts
        encrypt_vault_core(
            None,
            src_dir.to_str().unwrap(),
            gui_vault_dir.to_str().unwrap(),
            gui_vault_dir.to_str().unwrap(),
            false,
            cipher,
            kem,
            "InteropSecret#2026!",
            "",
            None,
        )
        .unwrap_or_else(|e| panic!("Core/GUI encrypt failed ({kem}/{cipher}): {e}"));

        let gui_obv = gui_vault_dir.join("payload_dir.obv");
        let gui_obk = gui_vault_dir.join("payload_dir.obk");

        let dec_out = Command::new(bin)
            .args([
                "decrypt",
                "--target",
                gui_obv.to_str().unwrap(),
                "--key",
                gui_obk.to_str().unwrap(),
                "--output-dir",
                cli_extract_dir.to_str().unwrap(),
                "--password-file",
                pass_file.to_str().unwrap(),
                "--quiet",
            ])
            .output()
            .unwrap();
        assert!(
            dec_out.status.success(),
            "CLI decrypt failed ({kem}/{cipher}): {}",
            String::from_utf8_lossy(&dec_out.stderr)
        );

        assert_eq!(
            fs::read_to_string(cli_extract_dir.join("payload_dir/parity.txt")).unwrap(),
            expected_content
        );
    }
}

#[test]
fn test_cli_keygen_public_sealing_inspect_and_clean_commands() {
    let bin = env!("CARGO_BIN_EXE_ombracrypt");
    let (ws, _guard) = create_temp_dir("keygen_seal_inspect");
    let keys_dir = ws.join("keys");
    let src_dir = ws.join("docs");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("extracted");

    for d in [&keys_dir, &src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(
        src_dir.join("contract.txt"),
        b"Zero-escrow public key sealing",
    )
    .unwrap();

    // 0. Standalone keygen must reject duress CLI flags (GUI/CLI parity)
    let bad_kg = Command::new(bin)
        .args([
            "keygen",
            "--name",
            "rejected",
            "--output-dir",
            keys_dir.to_str().unwrap(),
            "--deception-passcode-env",
            "OMBRACRYPT_DECEPTION_PASSCODE",
        ])
        .output()
        .unwrap();
    assert!(
        !bad_kg.status.success(),
        "Standalone keygen must not accept --deception-passcode-env"
    );

    // 1. Keygen (must ignore OMBRACRYPT_DECEPTION_PASSCODE so matching vault passwords never trigger duress)
    let kg_out = Command::new(bin)
        .args([
            "keygen",
            "--name",
            "alice",
            "--output-dir",
            keys_dir.to_str().unwrap(),
            "--kem",
            "xwing",
            "--quiet",
        ])
        .env("OMBRACRYPT_DECEPTION_PASSCODE", "SealSecret99!")
        .output()
        .unwrap();
    assert!(kg_out.status.success());

    let obp = keys_dir.join("alice.obp");
    let obk = keys_dir.join("alice.obk");
    assert!(obp.exists() && obk.exists());

    // 2. Inspect JSON
    let insp_out = Command::new(bin)
        .args([
            "inspect",
            "--mode",
            "encrypt",
            "--target",
            src_dir.to_str().unwrap(),
            "--output-dir",
            vault_dir.to_str().unwrap(),
            "--key",
            obp.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(insp_out.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&insp_out.stdout).unwrap();
    assert_eq!(json_val["sufficient"], true);

    // 3. Seal with .obp
    let seal_out = Command::new(bin)
        .args([
            "encrypt",
            "--target",
            src_dir.to_str().unwrap(),
            "--output-dir",
            vault_dir.to_str().unwrap(),
            "--public-key",
            obp.to_str().unwrap(),
            "--quiet",
        ])
        .env("OMBRACRYPT_PASSWORD", "SealSecret99!")
        .output()
        .unwrap();
    assert!(seal_out.status.success());

    // 4. Decrypt with .obk using the exact same string that was in OMBRACRYPT_DECEPTION_PASSCODE
    let dec_out = Command::new(bin)
        .args([
            "decrypt",
            "--target",
            vault_dir.join("docs.obv").to_str().unwrap(),
            "--key",
            obk.to_str().unwrap(),
            "--output-dir",
            out_dir.to_str().unwrap(),
            "--quiet",
        ])
        .env("OMBRACRYPT_PASSWORD", "SealSecret99!")
        .output()
        .unwrap();
    assert!(dec_out.status.success());
    assert_eq!(
        fs::read(out_dir.join("docs/contract.txt")).unwrap(),
        b"Zero-escrow public key sealing"
    );

    // 5. Clean command
    let clean_out = Command::new(bin)
        .args([
            "clean",
            "--target-dir",
            out_dir.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(clean_out.status.success());
}

#[test]
fn test_frozen_v2_1_golden_fixture_compatibility() {
    let bin = env!("CARGO_BIN_EXE_ombracrypt");
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/desktop_v2");
    let frozen_obv = fixture_dir.join("golden_v2_1.obv");
    let frozen_obk = fixture_dir.join("golden_v2_1.obk");
    let frozen_obp = fixture_dir.join("golden_v2_1.obp");
    let frozen_plain = fixture_dir.join("expected_plaintext.txt");
    let golden_password = "GoldenFixturePassword#2026!";

    assert!(
        frozen_obv.exists() && frozen_obk.exists() && frozen_obp.exists() && frozen_plain.exists(),
        "Missing committed frozen v2.1.0 golden fixture(s) in {}. Historical compatibility fixtures are required and must not be skipped.",
        fixture_dir.display()
    );

    const EXPECTED_GOLDEN_BYTES: &[u8] =
        b"Ombracrypt v2.1.0 immutable wire-format compatibility vector\n";
    let disk_plain = String::from_utf8(fs::read(&frozen_plain).unwrap())
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(disk_plain.as_bytes(), EXPECTED_GOLDEN_BYTES);
    let expected_bytes = EXPECTED_GOLDEN_BYTES.to_vec();

    let (ws, _guard) = create_temp_dir("verify_golden");
    let cli_out = ws.join("cli_from_golden");
    let sealed_dir = ws.join("sealed_with_golden_obp");
    let core_out = ws.join("core_from_sealed");
    for d in [&cli_out, &sealed_dir, &core_out] {
        fs::create_dir_all(d).unwrap();
    }

    // 1. Frozen v2.1.0 .obv + .obk -> Current CLI decrypts
    let dec_out = Command::new(bin)
        .args([
            "decrypt",
            "--target",
            frozen_obv.to_str().unwrap(),
            "--key",
            frozen_obk.to_str().unwrap(),
            "--output-dir",
            cli_out.to_str().unwrap(),
            "--quiet",
        ])
        .env("OMBRACRYPT_PASSWORD", golden_password)
        .output()
        .unwrap();
    assert!(
        dec_out.status.success(),
        "Current CLI failed to decrypt frozen v2.1.0 vault: {}",
        String::from_utf8_lossy(&dec_out.stderr)
    );
    assert_eq!(
        fs::read(cli_out.join("golden_v2_1/vector.txt")).unwrap(),
        expected_bytes
    );

    // 2. Frozen v2.1.0 .obp -> Current CLI seals -> Core decrypts with frozen .obk
    let reseal_src = ws.join("reseal_payload");
    fs::create_dir_all(&reseal_src).unwrap();
    fs::write(reseal_src.join("vector.txt"), &expected_bytes).unwrap();

    let seal_out = Command::new(bin)
        .args([
            "encrypt",
            "--target",
            reseal_src.to_str().unwrap(),
            "--output-dir",
            sealed_dir.to_str().unwrap(),
            "--public-key",
            frozen_obp.to_str().unwrap(),
            "--quiet",
        ])
        .env("OMBRACRYPT_PASSWORD", golden_password)
        .output()
        .unwrap();
    assert!(
        seal_out.status.success(),
        "Current CLI failed to seal against frozen v2.1.0 .obp: {}",
        String::from_utf8_lossy(&seal_out.stderr)
    );

    decrypt_vault_core(
        None,
        sealed_dir.join("reseal_payload.obv").to_str().unwrap(),
        Some(frozen_obk.to_str().unwrap()),
        core_out.to_str().unwrap(),
        golden_password,
        None,
    )
    .expect("Core failed to decrypt vault sealed with frozen v2.1.0 .obp");

    assert_eq!(
        fs::read(core_out.join("reseal_payload/vector.txt")).unwrap(),
        expected_bytes
    );
}
