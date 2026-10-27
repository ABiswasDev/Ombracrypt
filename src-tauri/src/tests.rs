use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::{Path, PathBuf};
use tar::EntryType;

use crate::fs_guard::{
    read_bounded_key_file, CommitRollbackGuard, TempDirGuard, MAX_KEY_FILE_BYTES,
};
use crate::pipeline::{decrypt_vault_core, encrypt_vault_core};
use crate::stream::{sanitize_tar_path, validate_tar_entry_type, CHUNK_SIZE};

fn create_test_workspace(name: &str) -> (PathBuf, TempDirGuard) {
    let mut rnd = [0u8; 6];
    OsRng.fill_bytes(&mut rnd);
    let dir = std::env::temp_dir().join(format!(
        "ombracrypt_test_{}_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        name, rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5]
    ));
    fs::create_dir_all(&dir).unwrap();
    let guard = TempDirGuard::new(dir.clone());
    (dir, guard)
}

#[test]
fn test_roundtrip_xwing_xchacha20_and_zero_temp_files() {
    let (ws, _guard) = create_test_workspace("xwing_xchacha");
    let src_dir = ws.join("sample_payload");
    let vault_dir = ws.join("vault_out");
    let key_dir = ws.join("keys_out");
    let extract_dir = ws.join("extract_out");

    fs::create_dir_all(src_dir.join("nested")).unwrap();
    fs::create_dir_all(&vault_dir).unwrap();
    fs::create_dir_all(&key_dir).unwrap();
    fs::create_dir_all(&extract_dir).unwrap();

    let secret_data = b"Post-Quantum FIPS 203 ML-KEM-768 + X25519 Test Payload";
    fs::write(src_dir.join("nested/secret.txt"), secret_data).unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        key_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "CorrectHorseBatteryStaple!",
        "DuressCode999",
    )
    .expect("Encryption should succeed");

    let obv_path = vault_dir.join("sample_payload.obv");
    let obk_path = key_dir.join("sample_payload.obk");
    let obp_path = key_dir.join("sample_payload.obp");
    assert!(obv_path.exists() && obk_path.exists() && obp_path.exists());

    // Verify only the .obv file exists in vault_dir (zero leftover .part files)
    assert_eq!(fs::read_dir(&vault_dir).unwrap().count(), 1);

    decrypt_vault_core(
        None,
        obv_path.to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        extract_dir.to_str().unwrap(),
        "CorrectHorseBatteryStaple!",
    )
    .expect("Decryption should succeed");

    let recovered = fs::read(extract_dir.join("sample_payload/nested/secret.txt")).unwrap();
    assert_eq!(recovered, secret_data);
}

#[test]
fn test_roundtrip_cypherpunk_aes256gcm() {
    let (ws, _guard) = create_test_workspace("cypherpunk_aes");
    let src_dir = ws.join("alpha");
    let vault_dir = ws.join("vault");
    let key_dir = ws.join("keys");
    let extract_dir = ws.join("out");

    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&vault_dir).unwrap();
    fs::create_dir_all(&key_dir).unwrap();
    fs::create_dir_all(&extract_dir).unwrap();

    let payload = vec![0xABu8; CHUNK_SIZE + 25_000];
    fs::write(src_dir.join("large.bin"), &payload).unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        key_dir.to_str().unwrap(),
        false,
        "aes256gcm",
        "cypherpunk",
        "MasterPass#2026",
        "",
    )
    .expect("Multi-chunk encryption should succeed");

    let obv_path = vault_dir.join("alpha.obv");
    let obk_path = key_dir.join("alpha.obk");

    decrypt_vault_core(
        None,
        obv_path.to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        extract_dir.to_str().unwrap(),
        "MasterPass#2026",
    )
    .expect("Multi-chunk decryption should succeed");

    let restored = fs::read(extract_dir.join("alpha/large.bin")).unwrap();
    assert_eq!(restored, payload);
}

#[test]
fn test_public_key_obp_sealing_workflow() {
    let (ws, _guard) = create_test_workspace("obp_seal");
    let src_dir = ws.join("docs");
    let key_dir = ws.join("keys");
    let vault_dir_1 = ws.join("v1");
    let vault_dir_2 = ws.join("v2");
    let out_1 = ws.join("out1");
    let out_2 = ws.join("out2");

    for d in [&src_dir, &key_dir, &vault_dir_1, &vault_dir_2, &out_1, &out_2] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("note.txt"), b"Group Seal Verified").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir_1.to_str().unwrap(),
        key_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "1234",
        "5555",
    )
    .unwrap();

    let obp_path = key_dir.join("docs.obp");
    let obk_path = key_dir.join("docs.obk");

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir_2.to_str().unwrap(),
        obp_path.to_str().unwrap(),
        true,
        "xchacha20",
        "xwing",
        "2345",
        "",
    )
    .unwrap();

    decrypt_vault_core(
        None,
        vault_dir_1.join("docs.obv").to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        out_1.to_str().unwrap(),
        "1234",
    )
    .expect("Vault 1 must unlock with 1234");

    decrypt_vault_core(
        None,
        vault_dir_2.join("docs.obv").to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        out_2.to_str().unwrap(),
        "2345",
    )
    .expect("Vault 2 must unlock with 2345");
}

#[test]
fn test_audit_p0_collision_preserves_existing_obk_and_obv() {
    let (ws, _guard) = create_test_workspace("collision_safety");
    let src_dir = ws.join("sample");
    let out_dir = ws.join("out");

    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    fs::write(src_dir.join("secret.txt"), b"top secret").unwrap();

    let existing_obk = out_dir.join("sample.obk");
    let original_key_bytes = b"ORIGINAL_PROTECTED_KEY_MATERIAL";
    fs::write(&existing_obk, original_key_bytes).unwrap();
    fs::create_dir_all(out_dir.join("sample.obv")).unwrap();

    let res = encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        false,
        "aes256gcm",
        "xwing",
        "pass123",
        "",
    );

    assert!(res.is_err(), "Collision must be rejected");
    assert_eq!(
        fs::read(&existing_obk).unwrap(),
        original_key_bytes,
        "Existing .obk must never be clobbered on error"
    );
}

#[test]
fn test_wrong_password_rejected_and_staging_cleaned() {
    let (ws, _guard) = create_test_workspace("wrong_pass");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("file.txt"), b"sensitive").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "RightPassword",
        "DuressPassword",
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");
    let obk_before = fs::read(&obk).unwrap();

    let err = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "WrongPasswordTypo",
    );

    assert!(err.is_err());
    assert_eq!(fs::read(&obk).unwrap(), obk_before, "Typo must not scramble .obk");
    assert!(
        fs::read_dir(&out_dir).unwrap().next().is_none(),
        "Staging directory must be completely removed on failure"
    );
}

#[test]
fn test_header_tampering_aad_rejection() {
    let (ws, _guard) = create_test_workspace("header_tamper");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("file.txt"), b"immutable header test").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        false,
        "aes256gcm",
        "xwing",
        "Pass1234",
        "",
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    // Flip 1 bit inside the uncompressed_size metadata field in the header (byte offset 20)
    let mut vault_bytes = fs::read(&obv).unwrap();
    vault_bytes[20] ^= 0x01;
    fs::write(&obv, &vault_bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
    );
    assert!(res.is_err(), "Tampered header must fail AEAD AAD verification");
}

#[test]
fn test_duress_trapdoor_scrambles_obk() {
    let (ws, _guard) = create_test_workspace("duress");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("file.txt"), b"destroy key on duress").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "RealSecret123",
        "PanicDuress999",
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");
    let original_obk = fs::read(&obk).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "PanicDuress999",
    );
    assert!(res.is_err());

    let scrambled_obk = fs::read(&obk).unwrap();
    assert_ne!(scrambled_obk, original_obk, ".obk must be overwritten with random noise");
}

#[test]
fn test_zip_slip_path_traversal_sanitization() {
    assert!(sanitize_tar_path(Path::new("../../etc/passwd")).is_err());
    assert!(sanitize_tar_path(Path::new("/etc/shadow")).is_err());
    assert!(sanitize_tar_path(Path::new("safe/subdir/file.txt")).is_ok());
}

// =========================================================================
// SPRINT 1 & SPRINT 2 ADVERSARIAL SECURITY REGRESSION TESTS
// =========================================================================

#[test]
fn test_sprint1_kdf_parameter_dos_bomb_rejected() {
    let (ws, _guard) = create_test_workspace("kdf_bomb");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("file.txt"), b"kdf bomb test").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "Pass1234",
        "",
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    // Maliciously overwrite m_cost (bytes 7..11) with 4 GiB (4_194_304 KiB)
    let mut vault_bytes = fs::read(&obv).unwrap();
    vault_bytes[7..11].copy_from_slice(&4_194_304u32.to_le_bytes());
    fs::write(&obv, &vault_bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
    );
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Untrusted or unsupported Argon2id"));
}

#[test]
fn test_sprint1_mismatched_cipher_and_nonce_rejected_without_panic() {
    let (ws, _guard) = create_test_workspace("cipher_nonce_mismatch");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("file.txt"), b"nonce test").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        false,
        "xchacha20", // cipher_id = 1, nonce_len = 24
        "xwing",
        "Pass1234",
        "",
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    // Tamper cipher_id (byte 5) to AES-256-GCM (2) while leaving nonce_len = 24
    let mut vault_bytes = fs::read(&obv).unwrap();
    vault_bytes[5] = 2;
    fs::write(&obv, &vault_bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
    );
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Invalid cipher ID or mismatched nonce"));
}

#[test]
fn test_sprint1_oversized_key_file_rejected_before_allocation() {
    let (ws, _guard) = create_test_workspace("oversized_key");
    let huge_key_path = ws.join("huge.obk");
    fs::write(&huge_key_path, vec![0u8; (MAX_KEY_FILE_BYTES as usize) + 100]).unwrap();

    let res = read_bounded_key_file(huge_key_path.to_str().unwrap(), "Private Key (.obk)");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("outside valid key bounds"));
}

#[test]
fn test_sprint1_tar_entry_allowlist_blocks_special_files() {
    assert!(validate_tar_entry_type(EntryType::Regular).is_ok());
    assert!(validate_tar_entry_type(EntryType::Directory).is_ok());
    assert!(validate_tar_entry_type(EntryType::Fifo).is_err());
    assert!(validate_tar_entry_type(EntryType::Char).is_err());
    assert!(validate_tar_entry_type(EntryType::Block).is_err());
    assert!(validate_tar_entry_type(EntryType::Symlink).is_err());
}

#[test]
fn test_sprint2_overlapping_source_and_output_directories_rejected() {
    let (ws, _guard) = create_test_workspace("overlap");
    let src_dir = ws.join("project");
    let nested_vault_dir = src_dir.join("vaults");
    let nested_key_dir = src_dir.join("keys");
    let external_dir = ws.join("external");

    for d in [&src_dir, &nested_vault_dir, &nested_key_dir, &external_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("code.rs"), b"fn main() {}").unwrap();

    // Case 1: Vault output folder inside source folder
    let res1 = encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        nested_vault_dir.to_str().unwrap(),
        external_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "Pass123",
        "",
    );
    assert!(res1.is_err());
    assert!(res1.unwrap_err().contains("inside the Input Folder"));

    // Case 2: Key output folder inside source folder
    let res2 = encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        external_dir.to_str().unwrap(),
        nested_key_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "Pass123",
        "",
    );
    assert!(res2.is_err());
    assert!(res2.unwrap_err().contains("inside the Input Folder"));
}

#[test]
fn test_sprint2_transactional_commit_rolls_back_on_partial_failure() {
    let (ws, _guard) = create_test_workspace("commit_rollback");
    let part_1 = ws.join(".key.1.part");
    let final_1 = ws.join("key.obk");
    let part_2 = ws.join(".vault.2.part");
    let final_2 = ws.join("vault.obv");

    fs::write(&part_1, b"KEY_DATA").unwrap();
    fs::write(&part_2, b"VAULT_DATA").unwrap();
    fs::write(&final_2, b"EXISTING_VAULT_DO_NOT_TOUCH").unwrap();

    {
        let mut commit_guard = CommitRollbackGuard::new();
        assert!(commit_guard.commit_file(&part_1, &final_1).is_ok());
        assert!(final_1.exists());
        assert!(commit_guard.commit_file(&part_2, &final_2).is_err());
    }

    assert!(!final_1.exists(), "First committed artifact must be rolled back");
    assert_eq!(fs::read(&final_2).unwrap(), b"EXISTING_VAULT_DO_NOT_TOUCH");
}

// =========================================================================
// SPRINT 3 & SPRINT 4 CONFORMANCE, FINGERPRINT & TRUNCATION TESTS
// =========================================================================

#[test]
fn test_sprint3_xwing_shake256_deterministic_keygen_and_vectors() {
    let seed = [0x42u8; 32];
    let exp1 = crate::crypto::expand_xwing_seed(&seed);
    let exp2 = crate::crypto::expand_xwing_seed(&seed);
    assert_eq!(*exp1, *exp2, "SHAKE256 seed expansion must be deterministic");

    let (obp1, obk1, kid1) =
        crate::crypto::generate_xwing_keypair_from_seed(&seed, "duress").unwrap();
    let (obp2, obk2, kid2) =
        crate::crypto::generate_xwing_keypair_from_seed(&seed, "duress").unwrap();

    assert_eq!(kid1, 1);
    assert_eq!(kid2, 1);
    assert_eq!(
        obp1, obp2,
        "Deterministic X-Wing seed must produce identical .obp public keys"
    );
    assert_eq!(
        &obk1[22..obk1.len() - 32],
        &obk2[22..obk2.len() - 32],
        "Deterministic X-Wing seed must produce identical ML-KEM-768 + X25519 secret keys"
    );
}

#[test]
fn test_sprint3_xwing_combiner_conformance_vector() {
    let mlkem_ss = [0x11u8; 32];
    let x25519_ss = [0x22u8; 32];
    let ct_x = [0x33u8; 32];
    let pk_x = [0x44u8; 32];

    let out1 = crate::crypto::compute_hybrid_combiner(
        &mlkem_ss,
        &x25519_ss,
        &ct_x,
        &pk_x,
        crate::crypto::XWING_LABEL,
    );
    let out2 = crate::crypto::compute_hybrid_combiner(
        &mlkem_ss,
        &x25519_ss,
        &ct_x,
        &pk_x,
        crate::crypto::CYPHERPUNK_LABEL,
    );

    assert_ne!(
        *out1, *out2,
        "Domain separation label must produce distinct combiner outputs"
    );

    let mut pk_x_tampered = pk_x;
    pk_x_tampered[0] ^= 0x01;
    let out_tampered = crate::crypto::compute_hybrid_combiner(
        &mlkem_ss,
        &x25519_ss,
        &ct_x,
        &pk_x_tampered,
        crate::crypto::XWING_LABEL,
    );
    assert_ne!(
        *out1, *out_tampered,
        "X-Wing combiner must bind recipient X25519 public key"
    );
}

#[test]
fn test_sprint3_obp_and_obk_fingerprints_match_identically() {
    for profile in ["xwing", "cypherpunk"] {
        let (obp_bytes, obk_bytes, _) =
            crate::crypto::generate_keypair_blobs(profile, "duress123").unwrap();
        let fp_pub = crate::crypto::compute_obp_fingerprint(&obp_bytes).unwrap();
        let fp_priv = crate::crypto::compute_obk_public_fingerprint(&obk_bytes).unwrap();
        assert_eq!(
            fp_pub, fp_priv,
            "Public (.obp) and Private (.obk) key fingerprints must match for profile {}",
            profile
        );
        assert_eq!(fp_pub.len(), 19); // Format: XXXX-XXXX-XXXX-XXXX
    }
}

#[test]
fn test_sprint4_truncated_vault_ciphertext_rejected_and_cleaned() {
    let (ws, _guard) = create_test_workspace("truncated_vault");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let out_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &out_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("payload.bin"), vec![0x5Au8; 65_536]).unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "Pass1234",
        "",
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    // Truncate the last 10 bytes of the encrypted vault stream
    let mut bytes = fs::read(&obv).unwrap();
    bytes.truncate(bytes.len() - 10);
    fs::write(&obv, &bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
    );
    assert!(res.is_err(), "Truncated vault must be rejected");
    assert!(
        fs::read_dir(&out_dir).unwrap().next().is_none(),
        "Staging directory must be wiped when truncation is detected"
    );
}