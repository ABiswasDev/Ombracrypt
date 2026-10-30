use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use std::thread;
use tar::EntryType;
use fs2::FileExt;

use crate::fs_guard::{
    atomic_publish_dir_noreplace, atomic_publish_noreplace, clean_scoped_staging_dir,
    create_public_staging_file, read_bounded_key_file, verify_locked_sentinel,
    CommitRollbackGuard, TempDirGuard, MAX_KEY_FILE_BYTES,
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
        None,
    )
    .expect("Encryption should succeed");

    let obv_path = vault_dir.join("sample_payload.obv");
    let obk_path = key_dir.join("sample_payload.obk");
    let obp_path = key_dir.join("sample_payload.obp");
    assert!(obv_path.exists() && obk_path.exists() && obp_path.exists());

    assert_eq!(fs::read_dir(&vault_dir).unwrap().count(), 1);

    decrypt_vault_core(
        None,
        obv_path.to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        extract_dir.to_str().unwrap(),
        "CorrectHorseBatteryStaple!",
        None,
    )
    .expect("Decryption should succeed");

    let recovered = fs::read(extract_dir.join("sample_payload/nested/secret.txt")).unwrap();
    assert_eq!(recovered, secret_data);
    assert!(
        fs::symlink_metadata(extract_dir.join("sample_payload/.active.lock")).is_err(),
        "Internal .active.lock sentinel must never exist in extracted output"
    );
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
        None,
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
        None,
    )
    .expect("Multi-chunk decryption should succeed");

    let restored = fs::read(extract_dir.join("alpha/large.bin")).unwrap();
    assert_eq!(restored, payload);
    assert!(
        fs::symlink_metadata(extract_dir.join("alpha/.active.lock")).is_err(),
        "Internal .active.lock sentinel must never exist in extracted output"
    );
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
        None,
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
        None,
    )
    .unwrap();

    decrypt_vault_core(
        None,
        vault_dir_1.join("docs.obv").to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        out_1.to_str().unwrap(),
        "1234",
        None,
    )
    .expect("Vault 1 must unlock with 1234");

    decrypt_vault_core(
        None,
        vault_dir_2.join("docs.obv").to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        out_2.to_str().unwrap(),
        "2345",
        None,
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
        None,
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
        None,
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
        None,
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
        None,
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    let mut vault_bytes = fs::read(&obv).unwrap();
    vault_bytes[20] ^= 0x01;
    fs::write(&obv, &vault_bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
        None,
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
        None,
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
        None,
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
        None,
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    let mut vault_bytes = fs::read(&obv).unwrap();
    vault_bytes[7..11].copy_from_slice(&4_194_304u32.to_le_bytes());
    fs::write(&obv, &vault_bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
        None,
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
        "xchacha20",
        "xwing",
        "Pass1234",
        "",
        None,
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    let mut vault_bytes = fs::read(&obv).unwrap();
    vault_bytes[5] = 2;
    fs::write(&obv, &vault_bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
        None,
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
        None,
    );
    assert!(res1.is_err());
    assert!(res1.unwrap_err().contains("inside the Input Folder"));

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
        None,
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
        "Deterministic X-Wing seed must produce identical seed payload"
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
        assert_eq!(fp_pub.len(), 35); // 128-bit format: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
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
        None,
    )
    .unwrap();

    let obv = vault_dir.join("data.obv");
    let obk = vault_dir.join("data.obk");

    let mut bytes = fs::read(&obv).unwrap();
    bytes.truncate(bytes.len() - 10);
    fs::write(&obv, &bytes).unwrap();

    let res = decrypt_vault_core(
        None,
        obv.to_str().unwrap(),
        Some(obk.to_str().unwrap()),
        out_dir.to_str().unwrap(),
        "Pass1234",
        None,
    );
    assert!(res.is_err(), "Truncated vault must be rejected");
    assert!(
        fs::read_dir(&out_dir).unwrap().next().is_none(),
        "Staging directory must be wiped when truncation is detected"
    );
}

#[cfg(unix)]
#[test]
fn test_sprint5_obk_file_created_with_0600_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let (ws, _guard) = create_test_workspace("obk_perms");
    let src_dir = ws.join("data");
    let vault_dir = ws.join("vault");
    let key_dir = ws.join("keys");

    for d in [&src_dir, &vault_dir, &key_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("secret.txt"), b"perm check").unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        key_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "Pass1234",
        "",
        None,
    )
    .unwrap();

    let obk_meta = fs::metadata(key_dir.join("data.obk")).unwrap();
    assert_eq!(
        obk_meta.permissions().mode() & 0o777,
        0o600,
        "Private key (.obk) must have strict 0600 owner-only permissions"
    );
}

#[test]
fn test_sprint5_plaintext_buffer_zeroized_before_clear() {
    let mut buf = zeroize::Zeroizing::new(vec![0xAAu8; 64]);
    let ptr = buf.as_ptr();
    let cap = buf.capacity();
    assert!(cap >= 64);

    crate::stream::clear_and_zeroize_buffer(&mut buf);
    assert_eq!(buf.len(), 0);

    let raw_capacity_slice = unsafe { std::slice::from_raw_parts(ptr, 64) };
    assert!(
        raw_capacity_slice.iter().all(|&b| b == 0),
        "Underlying vector capacity must be zeroed out before length is cleared"
    );
}

#[test]
fn test_sprint5_decrypt_reader_empty_slice_read_does_not_advance_stream() {
    use std::io::{Cursor, Read};
    let mut reader = crate::stream::ChunkedDecryptReader {
        inner: Cursor::new(vec![0xFFu8; 128]),
        cipher_id: 1,
        master_key: zeroize::Zeroizing::new([0u8; 32]),
        base_nonce: vec![0u8; 24],
        header_hash: [0u8; 32],
        buffer: zeroize::Zeroizing::new(Vec::new()),
        read_pos: 0,
        chunk_index: 0,
        bytes_read_from_vault: 0,
        vault_body_size: 128,
        reached_final_chunk: false,
        app: None,
        last_percent: 40,
        cancellation_token: None,
    };

    let mut empty_buf: [u8; 0] = [];
    let n = reader.read(&mut empty_buf).expect("Empty read must succeed");
    assert_eq!(n, 0);
    assert_eq!(
        reader.chunk_index, 0,
        "Empty buffer read must not consume chunks"
    );
    assert_eq!(reader.bytes_read_from_vault, 0);
}

#[test]
fn test_sprint5_unknown_cipher_and_kem_rejected_explicitly() {
    let (ws, _guard) = create_test_workspace("unknown_algos");
    let src_dir = ws.join("data");
    let out_dir = ws.join("out");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    fs::write(src_dir.join("f.txt"), b"test").unwrap();

    let bad_cipher = encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        false,
        "aes128_unknown",
        "xwing",
        "Pass123",
        "",
        None,
    );
    assert!(bad_cipher.is_err());
    assert!(bad_cipher.unwrap_err().contains("Unsupported cipher"));

    let bad_kem = encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "rsa2048_unknown",
        "Pass123",
        "",
        None,
    );
    assert!(bad_kem.is_err());
    assert!(bad_kem.unwrap_err().contains("Unsupported KEM"));
}

#[test]
fn test_sprint5_duress_scramble_rejects_symlinks_and_oversized_targets() {
    let (ws, _guard) = create_test_workspace("duress_guards");
    let huge_file = ws.join("huge.obk");
    fs::write(&huge_file, vec![0x41u8; (MAX_KEY_FILE_BYTES as usize) + 50]).unwrap();

    let res_huge = crate::deception::scramble_key_file_verified(huge_file.to_str().unwrap());
    assert!(res_huge.is_err(), "Duress scramble must reject oversized files");

    #[cfg(unix)]
    {
        let target_file = ws.join("real_target.txt");
        let symlink_path = ws.join("symlink.obk");
        fs::write(&target_file, vec![0x42u8; 256]).unwrap();
        std::os::unix::fs::symlink(&target_file, &symlink_path).unwrap();

        let res_sym = crate::deception::scramble_key_file_verified(symlink_path.to_str().unwrap());
        assert!(res_sym.is_err(), "Duress scramble must reject symlinks");
        assert_eq!(
            fs::read(&target_file).unwrap(),
            vec![0x42u8; 256],
            "Symlink target must remain untouched"
        );
    }
}

#[test]
fn test_sprint6_nist_fips202_and_rfc7748_official_kat_vectors() {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{Digest, Sha3_256, Shake256};
    use x25519_dalek::{PublicKey, StaticSecret};

    let digest_abc = Sha3_256::digest(b"abc");
    let expected_sha3_abc: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    assert_eq!(digest_abc.as_slice(), &expected_sha3_abc);

    let mut shake = Shake256::default();
    shake.update(b"");
    let mut xof = shake.finalize_xof();
    let mut shake_out = [0u8; 32];
    xof.read(&mut shake_out);
    let expected_shake_empty: [u8; 32] = [
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb,
        0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5,
        0x76, 0x2f,
    ];
    assert_eq!(shake_out, expected_shake_empty);

    let alice_sk_bytes: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let bob_sk_bytes: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let expected_shared_secret: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    let alice_sk = StaticSecret::from(alice_sk_bytes);
    let bob_sk = StaticSecret::from(bob_sk_bytes);
    let bob_pk = PublicKey::from(&bob_sk);
    let shared = alice_sk.diffie_hellman(&bob_pk);
    assert_eq!(shared.as_bytes(), &expected_shared_secret);
}

#[test]
fn test_sprint6_xwing_deterministic_encaps_decaps_and_implicit_rejection() {
    let key_seed = [0x11u8; 32];
    let ephem_seed = [0x22u8; 64];

    let (obp, obk, _) = crate::crypto::generate_xwing_keypair_from_seed(&key_seed, "").unwrap();
    let (ct1, ss1) = crate::crypto::encapsulate_xwing_deterministic(&obp, &ephem_seed).unwrap();
    let (ct2, ss2) = crate::crypto::encapsulate_xwing_deterministic(&obp, &ephem_seed).unwrap();

    assert_eq!(ct1, ct2, "Deterministic X-Wing encapsulation must produce identical ciphertext");
    assert_eq!(*ss1, *ss2, "Deterministic X-Wing encapsulation must produce identical shared secret");

    let (duress, decaps_ss) =
        crate::crypto::decapsulate_with_obk(1, &obk, &ct1, "MasterPass").unwrap();
    assert!(!duress);
    assert_eq!(*decaps_ss.unwrap(), *ss1);

    let mut tampered_ct = ct1.clone();
    tampered_ct[0] ^= 0xFF;
    let (_, rejected_ss) =
        crate::crypto::decapsulate_with_obk(1, &obk, &tampered_ct, "MasterPass").unwrap();
    assert_ne!(
        *rejected_ss.unwrap(),
        *ss1,
        "Corrupted ML-KEM ciphertext must trigger implicit rejection and yield a different shared secret"
    );
}

#[test]
fn test_sprint6_duplicate_tar_entry_paths_rejected() {
    use std::io::Cursor;
    use tar::{Builder, Header};

    let (ws, _guard) = create_test_workspace("dup_tar");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        let data1 = b"first version";
        let mut h1 = Header::new_gnu();
        h1.set_size(data1.len() as u64);
        h1.set_entry_type(EntryType::Regular);
        h1.set_mode(0o644);
        h1.set_cksum();
        builder
            .append_data(&mut h1, "nested/dup.txt", &data1[..])
            .unwrap();

        let data2 = b"second version attempting overwrite";
        let mut h2 = Header::new_gnu();
        h2.set_size(data2.len() as u64);
        h2.set_entry_type(EntryType::Regular);
        h2.set_mode(0o644);
        h2.set_cksum();
        builder
            .append_data(&mut h2, "nested/dup.txt", &data2[..])
            .unwrap();
        builder.finish().unwrap();
    }

    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let res = crate::stream::extract_tar_archive_safely(&mut archive, &ws, 1024 * 1024);
    assert!(res.is_err(), "Duplicate TAR paths must be rejected");
    assert!(res.unwrap_err().contains("duplicate or conflicting"));
}

#[cfg(unix)]
#[test]
fn test_sprint6_malicious_tar_setuid_and_setgid_bits_stripped() {
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use tar::{Builder, Header};

    let (ws, _guard) = create_test_workspace("suid_tar");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        let payload = b"#!/bin/sh\necho pwned\n";
        let mut header = Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o7777);
        header.set_cksum();
        builder
            .append_data(&mut header, "bin/suid_binary", &payload[..])
            .unwrap();
        builder.finish().unwrap();
    }

    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    crate::stream::extract_tar_archive_safely(&mut archive, &ws, 1024 * 1024)
        .expect("Extraction should succeed while stripping privileged bits");

    let meta = fs::metadata(ws.join("bin/suid_binary")).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o7000,
        0,
        "setuid, setgid, and sticky bits (0o7000) must be completely stripped upon extraction"
    );
}

// =========================================================================
// SPRINT 8 BACKEND INVARIANTS, MID-STREAM CANCELLATION & SCOPED CLEANER TESTS
// =========================================================================

#[test]
fn test_sprint8_backend_rejects_empty_master_pin() {
    let (ws, _guard) = create_test_workspace("empty_pin");
    let src = ws.join("src");
    let out = ws.join("out");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(src.join("f.txt"), b"data").unwrap();

    let res = encrypt_vault_core(
        None,
        src.to_str().unwrap(),
        out.to_str().unwrap(),
        out.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "   ",
        "",
        None,
    );
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Master Password cannot be empty"));
}

#[test]
fn test_sprint8_backend_rejects_identical_master_and_duress() {
    let (ws, _guard) = create_test_workspace("identical_pins");
    let src = ws.join("src");
    let out = ws.join("out");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(src.join("f.txt"), b"data").unwrap();

    let res = encrypt_vault_core(
        None,
        src.to_str().unwrap(),
        out.to_str().unwrap(),
        out.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "SamePassword123",
        "SamePassword123",
        None,
    );
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("cannot match Master Password"));
}

#[test]
fn test_sprint8_mid_stream_cancellation_cleans_staging_artifacts() {
    let (ws, _guard) = create_test_workspace("cancel_clean");
    let src = ws.join("src");
    let out = ws.join("out");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&out).unwrap();

    let large_payload = vec![0x33u8; CHUNK_SIZE * 3];
    fs::write(src.join("payload.dat"), &large_payload).unwrap();

    let cancel_flag = Arc::new(AtomicBool::new(true));

    let res = encrypt_vault_core(
        None,
        src.to_str().unwrap(),
        out.to_str().unwrap(),
        out.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "Password#1234",
        "",
        Some(cancel_flag),
    );

    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Operation aborted by user"));

    let leftover_count = fs::read_dir(&out).unwrap().count();
    assert_eq!(
        leftover_count, 0,
        "All staging files must be cleaned upon mid-stream cancellation"
    );
}

#[test]
fn test_sprint8_scoped_cleaner_purges_only_matching_artifacts() {
    let (ws, _guard) = create_test_workspace("scoped_cleaner");
    let legit_file = ws.join("important_user_doc.txt");
    let unrelated_part = ws.join(".abandoned.obv.123456.part");
    let stale_part = ws.join(".ombracrypt_part_0123456789abcdef0123456789abcdef.part");
    let stale_stage = ws.join(".ombracrypt_stage_0123456789abcdef0123456789abcdef");

    fs::write(&legit_file, b"KEEP THIS FILE").unwrap();
    fs::write(&unrelated_part, vec![0u8; 1024]).unwrap();
    fs::write(&stale_part, vec![0u8; 1024]).unwrap();
    fs::create_dir_all(stale_stage.join("nested")).unwrap();
    fs::write(stale_stage.join("nested/junk.txt"), vec![0u8; 2048]).unwrap();
    fs::write(stale_stage.join(".active.lock"), b"").unwrap();

    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 2, "Only Ombracrypt staging artifacts must be purged");
    assert_eq!(freed, 3072);

    assert!(legit_file.exists(), "Legitimate files must not be touched");
    assert!(
        unrelated_part.exists(),
        "Unrelated hidden .part files must be strictly preserved"
    );
    assert!(!stale_part.exists(), "Stale Ombracrypt staging part file must be purged");
    assert!(!stale_stage.exists(), "Stale Ombracrypt staging dir must be purged");
}

#[test]
fn test_sprint8_tar_bomb_excessive_directory_depth_rejected() {
    use std::io::Cursor;
    use tar::{Builder, Header};

    let (ws, _guard) = create_test_workspace("tar_depth");
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        let deep_path: String = (0..70).map(|i| format!("d{}/", i)).collect::<Vec<_>>().join("") + "file.txt";
        let mut h = Header::new_gnu();
        h.set_size(4);
        h.set_entry_type(EntryType::Regular);
        h.set_mode(0o644);
        h.set_cksum();
        builder.append_data(&mut h, deep_path, &b"test"[..]).unwrap();
        builder.finish().unwrap();
    }

    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let res = crate::stream::extract_tar_archive_safely(&mut archive, &ws, 1024 * 1024);
    assert!(res.is_err(), "Excessive path depth (>64) must be rejected");
    assert!(res.unwrap_err().contains("path depth exceeds maximum safety limit"));
}

// =========================================================================
// SPRINT 9 CANONICAL X-WING SPECIFICATION KAT & DECRYPTION CANCEL TESTS
// =========================================================================

#[test]
fn test_sprint9_canonical_xwing_obk_86_bytes_and_seed_decapsulation() {
    let (obp_bytes, obk_bytes, kem_id) =
        crate::crypto::generate_keypair_blobs("xwing", "DuressTest123").unwrap();

    assert_eq!(kem_id, 1);
    assert_eq!(
        obk_bytes.len(),
        86,
        "Canonical X-Wing .obk private key must be exactly 86 bytes"
    );
    assert_eq!(
        obp_bytes.len(),
        1222,
        "X-Wing .obp public key must be exactly 1222 bytes"
    );

    let pub_fp = crate::crypto::compute_obp_fingerprint(&obp_bytes).unwrap();
    let priv_fp = crate::crypto::compute_obk_public_fingerprint(&obk_bytes).unwrap();
    assert_eq!(pub_fp, priv_fp);

    let (ct, ss_enc, _) = crate::crypto::encapsulate_with_obp(&obp_bytes).unwrap();
    assert_eq!(ct.len(), 1088 + 32);
    assert_eq!(ss_enc.len(), 32);

    let (duress, ss_dec_opt) =
        crate::crypto::decapsulate_with_obk(1, &obk_bytes, &ct, "MasterPass").unwrap();
    assert!(!duress);
    assert_eq!(*ss_dec_opt.unwrap(), *ss_enc);

    let (duress_triggered, _) =
        crate::crypto::decapsulate_with_obk(1, &obk_bytes, &ct, "DuressTest123").unwrap();
    assert!(duress_triggered, "Duress trapdoor must trigger on matching duress passcode");
}

#[test]
fn test_sprint9_xwing_combiner_specification_kat() {
    let mlkem_ss = [0x5Au8; 32];
    let x25519_ss = [0xA5u8; 32];
    let ct_x = [0x3Cu8; 32];
    let pk_x = [0xC3u8; 32];

    let expected_ss: [u8; 32] = [
        0xD1u8, 0xD4u8, 0x29u8, 0x83u8, 0x7Bu8, 0x23u8, 0x79u8, 0xF1u8,
        0x95u8, 0xE5u8, 0x42u8, 0x4Eu8, 0x5Au8, 0x59u8, 0x1Fu8, 0xDEu8,
        0x76u8, 0x3Bu8, 0x60u8, 0x43u8, 0xCAu8, 0xE7u8, 0xBFu8, 0x4Du8,
        0x6Cu8, 0x6Cu8, 0x9Bu8, 0x0Du8, 0x59u8, 0xFEu8, 0x50u8, 0x43u8,
    ];

    let actual_ss = crate::crypto::compute_hybrid_combiner(
        &mlkem_ss,
        &x25519_ss,
        &ct_x,
        &pk_x,
        crate::crypto::XWING_LABEL,
    );

    assert_eq!(
        actual_ss.as_slice(),
        &expected_ss,
        "Combiner output must match static independent SHA3-256 Known-Answer Test vector"
    );
}

#[test]
fn test_sprint9_decryption_cancellation_sanitized_message() {
    let (ws, _guard) = create_test_workspace("decrypt_cancel");
    let src_dir = ws.join("src");
    let vault_dir = ws.join("vault");
    let key_dir = ws.join("keys");
    let extract_dir = ws.join("out");

    for d in [&src_dir, &vault_dir, &key_dir, &extract_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(src_dir.join("data.bin"), vec![0x42u8; CHUNK_SIZE * 2]).unwrap();

    encrypt_vault_core(
        None,
        src_dir.to_str().unwrap(),
        vault_dir.to_str().unwrap(),
        key_dir.to_str().unwrap(),
        false,
        "xchacha20",
        "xwing",
        "MasterPass123!",
        "",
        None,
    )
    .unwrap();

    let obv_path = vault_dir.join("src.obv");
    let obk_path = key_dir.join("src.obk");

    let cancel_flag = Arc::new(AtomicBool::new(true));
    let res = decrypt_vault_core(
        None,
        obv_path.to_str().unwrap(),
        Some(obk_path.to_str().unwrap()),
        extract_dir.to_str().unwrap(),
        "MasterPass123!",
        Some(cancel_flag),
    );

    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert_eq!(
        err_msg, "Operation aborted by user.",
        "Decryption cancel must return concise sanitized error"
    );

    assert_eq!(
        fs::read_dir(&extract_dir).unwrap().count(),
        0,
        "Extraction directory must be left completely empty upon cancellation"
    );
}

// =========================================================================
// SPRINT 10 INDEPENDENT SPECIFICATION REFERENCE KAT
// =========================================================================

#[test]
fn test_sprint10_xwing_independent_reference_kat() {
    const EXPECTED_PUBLIC_KEY: &[u8] =
        include_bytes!("../tests/fixtures/xwing_revision11/public_key.bin");
    const EXPECTED_CIPHERTEXT: &[u8] =
        include_bytes!("../tests/fixtures/xwing_revision11/ciphertext.bin");
    const EXPECTED_SHARED_SECRET: &[u8] =
        include_bytes!("../tests/fixtures/xwing_revision11/shared_secret.bin");

    let seed = [0x42u8; 32];
    let ephem_seed = [0x99u8; 64];

    let (obp, obk, kem_id) =
        crate::crypto::generate_xwing_keypair_from_seed(&seed, "DuressTrapdoor999").unwrap();

    assert_eq!(kem_id, 1, "Profile ID must be 1 (X-Wing)");
    assert_eq!(obk.len(), 86, "Canonical X-Wing .obk must be 86 bytes");
    assert_eq!(obp.len(), 1222, "Ombracrypt .obp must be 6-byte header + 1,216-byte raw X-Wing public key");

    let raw_pk = &obp[6..];
    assert_eq!(raw_pk.len(), 1216);
    assert_eq!(
        raw_pk, EXPECTED_PUBLIC_KEY,
        "Raw X-Wing public key differs from independent reference fixture"
    );

    let (ct, ss_enc) =
        crate::crypto::encapsulate_xwing_deterministic(&obp, &ephem_seed).unwrap();
    assert_eq!(ct.len(), 1120);
    assert_eq!(
        ct.as_slice(), EXPECTED_CIPHERTEXT,
        "X-Wing ciphertext differs from independent reference fixture"
    );
    assert_eq!(ss_enc.len(), 32);
    assert_eq!(
        &ss_enc[..], EXPECTED_SHARED_SECRET,
        "X-Wing shared secret differs from independent reference fixture"
    );

    let (duress, ss_dec_opt) = crate::crypto::decapsulate_with_obk(
        1,
        &obk,
        &ct,
        "MasterPassword",
    )
    .unwrap();
    assert!(!duress, "Duress flag must be false for normal master password");
    let ss_dec = ss_dec_opt.expect("Decapsulation must return shared secret");
    assert_eq!(*ss_dec, *ss_enc, "Decapsulated shared secret must match encapsulated shared secret");

    let (duress_triggered, _) = crate::crypto::decapsulate_with_obk(
        1,
        &obk,
        &ct,
        "DuressTrapdoor999",
    )
    .unwrap();
    assert!(duress_triggered, "Duress trapdoor must trigger when duress passcode is supplied");

    let mut corrupted_ct = ct.clone();
    corrupted_ct[0] ^= 0x01;
    let (_, ss_rejected) = crate::crypto::decapsulate_with_obk(
        1,
        &obk,
        &corrupted_ct,
        "MasterPassword",
    )
    .unwrap();
    assert_ne!(
        *ss_rejected.unwrap(),
        *ss_enc,
        "Corrupted ciphertext must implicitly reject and produce a distinct shared secret"
    );
}

// =========================================================================
// FILESYSTEM ATOMIC NO-REPLACE & SCOPED STAGING REGRESSION SUITE
// =========================================================================

#[test]
fn test_fs_guard_atomic_no_replace_publishes_successfully() {
    let temp_dir = std::env::temp_dir().join(format!(
        "ombracrypt_test_publish_ok_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let staging_path = temp_dir.join(".payload.part");
    let final_path = temp_dir.join("payload.obv");

    std::fs::write(&staging_path, b"CONFIDENTIAL_PAYLOAD_DATA").unwrap();

    let res = crate::fs_guard::atomic_publish_noreplace(&staging_path, &final_path);
    assert!(res.is_ok(), "Publication must succeed on clean target");

    assert!(final_path.exists(), "Final file must exist after publication");
    let read_back = std::fs::read(&final_path).unwrap();
    assert_eq!(read_back, b"CONFIDENTIAL_PAYLOAD_DATA");
    assert!(!staging_path.exists(), "Staged .part file must be consumed");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_fs_guard_atomic_no_replace_prevents_destination_overwrite() {
    let temp_dir = std::env::temp_dir().join(format!(
        "ombracrypt_test_collision_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let staging_path = temp_dir.join(".malicious_clobber.part");
    let final_path = temp_dir.join("critical_data.obv");

    std::fs::write(&final_path, b"PRE_EXISTING_IMMUTABLE_VAULT").unwrap();
    std::fs::write(&staging_path, b"OVERWRITE_ATTEMPT_DATA").unwrap();

    let res = crate::fs_guard::atomic_publish_noreplace(&staging_path, &final_path);
    assert!(
        res.is_err(),
        "Publication must fail closed when destination already exists"
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Refusing to overwrite existing file"),
        "Error message must explicitly cite collision refusal: {}",
        err_msg
    );

    let dest_content = std::fs::read(&final_path).unwrap();
    assert_eq!(
        dest_content, b"PRE_EXISTING_IMMUTABLE_VAULT",
        "Pre-existing destination file was clobbered or truncated!"
    );

    assert!(
        staging_path.exists(),
        "Staged source file must remain intact upon publication error"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_fs_guard_atomic_no_replace_fails_closed_on_unsupported_fs() {
    let temp_dir = std::env::temp_dir().join(format!(
        "ombracrypt_test_unsupported_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let staging_path = temp_dir.join(".staged_work.part");
    let final_path = temp_dir.join("target.obv");

    std::fs::write(&staging_path, b"STAGED_PAYLOAD").unwrap();

    let res =
        crate::fs_guard::atomic_publish_noreplace_internal(&staging_path, &final_path, true);
    assert!(
        res.is_err(),
        "Must abort when filesystem lacks no-replace support"
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("does not support atomic no-replace publication"),
        "Must return explicit unsupported filesystem error: {}",
        err_msg
    );

    assert!(
        !final_path.exists(),
        "Target file must not be created when operation is unsupported"
    );
    assert!(staging_path.exists(), "Source part file must remain untouched");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_fs_guard_active_locked_staging_file_skipped_by_cleaner() {
    let (ws, _guard) = create_test_workspace("locked_cleaner");
    let active_part = ws.join(".ombracrypt_part_11112222333344445555666677778888.part");

    let mut locked_file = create_public_staging_file(&active_part).unwrap();
    locked_file.write_all(&vec![0xEEu8; 512]).unwrap();
    locked_file.sync_all().unwrap();

    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 0, "Active locked staging file must NOT be purged");
    assert_eq!(freed, 0);
    assert!(active_part.exists(), "Active staging file must remain intact");

    drop(locked_file);

    let (cleaned_after, freed_after) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned_after, 1, "Unlocked staging file must now be purged");
    assert_eq!(freed_after, 512);
    assert!(!active_part.exists());
}

#[test]
fn test_fs_guard_atomic_dir_publication_publishes_successfully() {
    let (ws, _guard) = create_test_workspace("dir_publish_ok");
    let stage_dir = ws.join(".ombracrypt_stage_11112222333344445555666677778888");
    let final_dir = ws.join("final_extracted_vault");

    fs::create_dir_all(stage_dir.join("subdir")).unwrap();
    fs::write(stage_dir.join("subdir/file.txt"), b"EXTRACTED_CONTENT").unwrap();

    let res = atomic_publish_dir_noreplace(&stage_dir, &final_dir);
    assert!(res.is_ok(), "Directory publication must succeed on clean target");

    assert!(final_dir.exists(), "Final directory must exist");
    assert!(final_dir.join("subdir/file.txt").exists());
    assert_eq!(
        fs::read(final_dir.join("subdir/file.txt")).unwrap(),
        b"EXTRACTED_CONTENT"
    );
    assert!(!stage_dir.exists(), "Staging directory must be moved");
}

#[test]
fn test_fs_guard_atomic_dir_publication_prevents_overwrite_of_existing_dir() {
    let (ws, _guard) = create_test_workspace("dir_collision");
    let stage_dir = ws.join(".ombracrypt_stage_11112222333344445555666677778888");
    let final_dir = ws.join("existing_target_dir");

    fs::create_dir_all(&stage_dir).unwrap();
    fs::write(stage_dir.join("new_file.txt"), b"NEW_DATA").unwrap();

    fs::create_dir_all(&final_dir).unwrap();

    let res = atomic_publish_dir_noreplace(&stage_dir, &final_dir);
    assert!(
        res.is_err(),
        "Directory publication must fail closed when destination directory already exists"
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Refusing to overwrite existing destination"),
        "Error must cite refusal to overwrite existing destination: {}",
        err_msg
    );

    assert!(stage_dir.exists(), "Staging directory must remain intact");
    assert!(!final_dir.join("new_file.txt").exists(), "Existing directory must not be clobbered");
}

#[test]
fn test_fs_guard_atomic_dir_publication_prevents_overwrite_of_file() {
    let (ws, _guard) = create_test_workspace("dir_file_collision");
    let stage_dir = ws.join(".ombracrypt_stage_11112222333344445555666677778888");
    let final_path = ws.join("existing_file");

    fs::create_dir_all(&stage_dir).unwrap();
    fs::write(&final_path, b"DO_NOT_OVERWRITE").unwrap();

    let res = atomic_publish_dir_noreplace(&stage_dir, &final_path);
    assert!(res.is_err(), "Must fail closed if destination is an existing file");
    assert_eq!(fs::read(&final_path).unwrap(), b"DO_NOT_OVERWRITE");
    assert!(stage_dir.exists());
}

#[cfg(unix)]
#[test]
fn test_fs_guard_atomic_dir_publication_rejects_dangling_symlink() {
    let (ws, _guard) = create_test_workspace("dir_dangling_symlink");
    let stage_dir = ws.join(".ombracrypt_stage_11112222333344445555666677778888");
    let final_dir = ws.join("dangling_link");

    fs::create_dir_all(&stage_dir).unwrap();
    let nonexistent_target = ws.join("nonexistent_target");
    std::os::unix::fs::symlink(&nonexistent_target, &final_dir).unwrap();

    let res = atomic_publish_dir_noreplace(&stage_dir, &final_dir);
    assert!(
        res.is_err(),
        "Must fail closed when destination is a dangling symlink"
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Refusing to overwrite existing destination"),
        "Must refuse overwrite: {}",
        err_msg
    );
    assert!(stage_dir.exists());
}

// =========================================================================
// CONCURRENT PUBLISHERS, SENTINEL LOCKS & NAMESPACE REGRESSION TESTS
// =========================================================================

#[test]
fn test_fs_guard_concurrent_two_publishers_collision_barrier() {
    let (ws, _guard) = create_test_workspace("concurrent_publishers");
    let final_target = ws.join("contended_vault.obv");

    let part_a = ws.join(".ombracrypt_part_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.part");
    let part_b = ws.join(".ombracrypt_part_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.part");

    let payload_a = vec![0x11u8; 4096];
    let payload_b = vec![0x22u8; 4096];

    fs::write(&part_a, &payload_a).unwrap();
    fs::write(&part_b, &payload_b).unwrap();

    let barrier = Arc::new(Barrier::new(2));

    let part_a_clone = part_a.clone();
    let final_target_clone1 = final_target.clone();
    let barrier_clone1 = barrier.clone();

    let handle_a = thread::spawn(move || {
        barrier_clone1.wait();
        atomic_publish_noreplace(&part_a_clone, &final_target_clone1)
    });

    let part_b_clone = part_b.clone();
    let final_target_clone2 = final_target.clone();
    let barrier_clone2 = barrier.clone();

    let handle_b = thread::spawn(move || {
        barrier_clone2.wait();
        atomic_publish_noreplace(&part_b_clone, &final_target_clone2)
    });

    let res_a = handle_a.join().unwrap();
    let res_b = handle_b.join().unwrap();

    let (ok_count, err_count) = match (&res_a, &res_b) {
        (Ok(()), Err(e)) | (Err(e), Ok(())) => {
            assert!(
                e.contains("Refusing to overwrite existing file"),
                "Losing publisher must fail with collision refusal: {}",
                e
            );
            (1, 1)
        }
        _ => (0, 0),
    };
    assert_eq!((ok_count, err_count), (1, 1), "Exactly one concurrent publication must succeed");

    let winner_bytes = fs::read(&final_target).unwrap();
    assert!(
        winner_bytes == payload_a || winner_bytes == payload_b,
        "Published vault must match winner payload completely"
    );

    let remaining_parts = (if part_a.exists() { 1 } else { 0 }) + (if part_b.exists() { 1 } else { 0 });
    assert_eq!(remaining_parts, 1, "Only the loser's staging file remains intact");
}

#[test]
fn test_fs_guard_concurrent_two_directory_publishers_collision_barrier() {
    let (ws, _guard) = create_test_workspace("concurrent_dir_publishers");
    let final_target = ws.join("contended_extracted_dir");

    let stage_a = ws.join(".ombracrypt_stage_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let stage_b = ws.join(".ombracrypt_stage_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    fs::create_dir_all(&stage_a).unwrap();
    fs::create_dir_all(&stage_b).unwrap();

    let payload_a = b"PAYLOAD_VERSION_A";
    let payload_b = b"PAYLOAD_VERSION_B";

    fs::write(stage_a.join("data.txt"), payload_a).unwrap();
    fs::write(stage_b.join("data.txt"), payload_b).unwrap();

    let barrier = Arc::new(Barrier::new(2));

    let stage_a_clone = stage_a.clone();
    let final_target_clone1 = final_target.clone();
    let barrier_clone1 = barrier.clone();

    let handle_a = thread::spawn(move || {
        barrier_clone1.wait();
        atomic_publish_dir_noreplace(&stage_a_clone, &final_target_clone1)
    });

    let stage_b_clone = stage_b.clone();
    let final_target_clone2 = final_target.clone();
    let barrier_clone2 = barrier.clone();

    let handle_b = thread::spawn(move || {
        barrier_clone2.wait();
        atomic_publish_dir_noreplace(&stage_b_clone, &final_target_clone2)
    });

    let res_a = handle_a.join().unwrap();
    let res_b = handle_b.join().unwrap();

    let (ok_count, err_count) = match (&res_a, &res_b) {
        (Ok(()), Err(e)) | (Err(e), Ok(())) => {
            assert!(
                e.contains("Refusing to overwrite existing destination"),
                "Losing directory publisher must fail with collision refusal: {}",
                e
            );
            (1, 1)
        }
        _ => (0, 0),
    };
    assert_eq!((ok_count, err_count), (1, 1), "Exactly one concurrent directory publication must succeed");

    let winner_bytes = fs::read(final_target.join("data.txt")).unwrap();
    assert!(
        winner_bytes == payload_a || winner_bytes == payload_b,
        "Published directory content must match winner payload completely"
    );

    let remaining_stages = (if stage_a.exists() { 1 } else { 0 }) + (if stage_b.exists() { 1 } else { 0 });
    assert_eq!(remaining_stages, 1, "Only the loser's staging directory remains intact");
}

#[test]
fn test_fs_guard_active_locked_extraction_dir_skipped_by_cleaner() {
    let (ws, _guard) = create_test_workspace("active_extraction_cleaner");
    let stage_dir = ws.join(".ombracrypt_stage_33333333333333333333333333333333");
    fs::create_dir_all(&stage_dir).unwrap();

    let sentinel_path = stage_dir.join(".active.lock");
    let sentinel_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&sentinel_path)
        .unwrap();

    // Hold exclusive lock (simulating active extraction writer)
    sentinel_file.try_lock_exclusive().unwrap();
    fs::write(stage_dir.join("extracted_chunk.bin"), vec![0x99u8; 1024]).unwrap();

    // Cleaner must skip the active directory completely
    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 0, "Active extraction directory must NOT be purged");
    assert_eq!(freed, 0);

    assert!(stage_dir.exists(), "Staging directory must remain untouched");
    assert!(sentinel_path.exists());
    assert!(stage_dir.join("extracted_chunk.bin").exists());

    drop(sentinel_file);
}

#[test]
fn test_fs_guard_stale_extraction_dir_purged_when_lock_released() {
    let (ws, _guard) = create_test_workspace("stale_extraction_cleaner");
    let stage_dir = ws.join(".ombracrypt_stage_44444444444444444444444444444444");
    fs::create_dir_all(&stage_dir).unwrap();

    let sentinel_path = stage_dir.join(".active.lock");
    let sentinel_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&sentinel_path)
        .unwrap();

    // Genuinely acquire exclusive lock before releasing handle
    sentinel_file.try_lock_exclusive().unwrap();

    fs::write(stage_dir.join("stale_file.bin"), vec![0x88u8; 2048]).unwrap();

    // Drop lock handle (simulating abandoned or crashed process)
    drop(sentinel_file);

    // Cleaner should now acquire lock and purge the stale extraction folder
    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 1, "Abandoned extraction directory must be purged");
    assert_eq!(freed, 2048);
    assert!(!stage_dir.exists(), "Stale staging directory must be unlinked");
}

#[test]
fn test_fs_guard_missing_sentinel_extraction_dir_skipped() {
    let (ws, _guard) = create_test_workspace("missing_sentinel_cleaner");
    let stage_dir = ws.join(".ombracrypt_stage_55555555555555555555555555555555");
    fs::create_dir_all(&stage_dir).unwrap();
    fs::write(stage_dir.join("unprotected.bin"), vec![0x77u8; 512]).unwrap();

    // Directory without .active.lock sentinel must be skipped (either non-Ombracrypt or in-flight initialization)
    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 0, "Directory without sentinel must be skipped");
    assert_eq!(freed, 0);
    assert!(stage_dir.exists());
}

#[test]
fn test_fs_guard_cleaner_ignores_malformed_names() {
    let (ws, _guard) = create_test_workspace("malformed_names_cleaner");
    let short_file = ws.join(".ombracrypt_part_1234.part");
    let non_hex_file = ws.join(".ombracrypt_part_nothexcharacters123456789012345.part");
    let short_dir = ws.join(".ombracrypt_stage_short");
    let non_hex_dir = ws.join(".ombracrypt_stage_nothexcharacters123456789012345");

    fs::write(&short_file, b"DATA").unwrap();
    fs::write(&non_hex_file, b"DATA").unwrap();
    fs::create_dir_all(&short_dir).unwrap();
    fs::create_dir_all(&non_hex_dir).unwrap();

    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 0, "Malformed names must never be touched by cleaner");
    assert_eq!(freed, 0);

    assert!(short_file.exists());
    assert!(non_hex_file.exists());
    assert!(short_dir.exists());
    assert!(non_hex_dir.exists());
}

#[cfg(unix)]
#[test]
fn test_fs_guard_cleaner_preserves_staging_symlinks() {
    let (ws, _guard) = create_test_workspace("symlink_cleaner");
    let real_file = ws.join("user_real_file.txt");
    fs::write(&real_file, b"DO_NOT_DELETE").unwrap();

    let fake_part_symlink = ws.join(".ombracrypt_part_66666666666666666666666666666666.part");
    std::os::unix::fs::symlink(&real_file, &fake_part_symlink).unwrap();

    let real_dir = ws.join("user_real_dir");
    fs::create_dir_all(&real_dir).unwrap();
    let fake_stage_symlink = ws.join(".ombracrypt_stage_77777777777777777777777777777777");
    std::os::unix::fs::symlink(&real_dir, &fake_stage_symlink).unwrap();

    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 0, "Symlinks must be rejected without traversal");
    assert_eq!(freed, 0);

    assert!(fake_part_symlink.exists());
    assert!(fake_stage_symlink.exists());
    assert!(real_file.exists(), "Target file must remain untouched");
    assert!(real_dir.exists(), "Target directory must remain untouched");
}

#[test]
fn test_stream_tar_blocks_reserved_sentinel_path() {
    assert!(
        sanitize_tar_path(Path::new(".active.lock")).is_err(),
        "Archive entry named .active.lock must be rejected"
    );
    assert!(
        sanitize_tar_path(Path::new(".active.lock/nested.txt")).is_err(),
        "Archive paths under .active.lock must be rejected"
    );
    assert!(
        sanitize_tar_path(Path::new("safe_dir/.active.lock")).is_ok(),
        "Nested subfolder files named .active.lock are not at the top level and are permitted"
    );
}

#[cfg(unix)]
#[test]
fn test_fs_guard_stale_open_sentinel_fd_race_rejected() {
    use std::os::unix::fs::MetadataExt;

    let (ws, _guard) = create_test_workspace("stale_fd_race");
    let stage_dir = ws.join(".ombracrypt_stage_88888888888888888888888888888888");
    fs::create_dir_all(&stage_dir).unwrap();
    let sentinel_path = stage_dir.join(".active.lock");

    // 1. Extractor creates and locks sentinel
    let extractor_sentinel = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&sentinel_path)
        .unwrap();
    extractor_sentinel.try_lock_exclusive().unwrap();

    // 2. Cleaner opens sentinel descriptor before it is unlinked
    let cleaner_stale_sentinel = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&sentinel_path)
        .unwrap();

    // 3. Extractor unlinks sentinel and drops lock
    fs::remove_file(&sentinel_path).unwrap();
    drop(extractor_sentinel);

    // 4. Stale handle can now lock the unlinked inode
    assert!(cleaner_stale_sentinel.try_lock_exclusive().is_ok());
    assert_eq!(cleaner_stale_sentinel.metadata().unwrap().nlink(), 0);

    // 5. Verify post-lock validation directly rejects the stale handle
    assert!(
        !verify_locked_sentinel(&cleaner_stale_sentinel, &sentinel_path),
        "verify_locked_sentinel must reject unlinked file descriptor"
    );

    // 6. Verify cleaner rejects the directory because post-lock validation detects unlinked sentinel
    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 0, "Directory with unlinked sentinel must not be purged");
    assert_eq!(freed, 0);
    assert!(stage_dir.exists(), "Staging directory must remain intact");

    drop(cleaner_stale_sentinel);
}

#[cfg(windows)]
#[test]
fn test_fs_guard_windows_sentinel_identity_and_replacement() {
    let (ws, _guard) = create_test_workspace("win_sentinel_id");
    let stage_dir = ws.join(".ombracrypt_stage_99999999999999999999999999999999");
    fs::create_dir_all(&stage_dir).unwrap();
    let sentinel_path = stage_dir.join(".active.lock");
    let other_path = stage_dir.join("other_file.bin");

    let sentinel_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&sentinel_path)
        .unwrap();
    sentinel_file.try_lock_exclusive().unwrap();

    let other_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&other_path)
        .unwrap();

    // 1. Valid matching handle and path must verify successfully
    assert!(
        verify_locked_sentinel(&sentinel_file, &sentinel_path),
        "Active locked sentinel must match its valid path on Windows"
    );

    // 2. Mismatched file index must be rejected
    assert!(
        !verify_locked_sentinel(&sentinel_file, &other_path),
        "verify_locked_sentinel must reject mismatched file index on Windows"
    );

    // 3. Nonexistent path must be rejected
    let missing_path = stage_dir.join(".nonexistent.lock");
    assert!(
        !verify_locked_sentinel(&sentinel_file, &missing_path),
        "verify_locked_sentinel must reject non-existent path on Windows"
    );

    drop(sentinel_file);
    drop(other_file);
}