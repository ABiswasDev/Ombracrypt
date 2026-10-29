use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tar::EntryType;

use crate::fs_guard::{
    clean_scoped_staging_dir, read_bounded_key_file, CommitRollbackGuard, TempDirGuard,
    MAX_KEY_FILE_BYTES,
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

    let cancel_flag = Arc::new(AtomicBool::new(true)); // Pre-trip cancellation flag

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
    let stale_part = ws.join(".abandoned.obv.123456.part");
    let stale_stage = ws.join(".ombracrypt_stage_data_abcdef");

    fs::write(&legit_file, b"KEEP THIS FILE").unwrap();
    fs::write(&stale_part, vec![0u8; 1024]).unwrap();
    fs::create_dir_all(stale_stage.join("nested")).unwrap();
    fs::write(stale_stage.join("nested/junk.txt"), vec![0u8; 2048]).unwrap();

    let (cleaned, freed) = clean_scoped_staging_dir(&ws).unwrap();
    assert_eq!(cleaned, 2);
    assert_eq!(freed, 3072);

    assert!(legit_file.exists(), "Legitimate files must not be touched");
    assert!(!stale_part.exists());
    assert!(!stale_stage.exists());
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
    // Canonical X-Wing Profile 1: 5B magic + 1B kem_id + 16B salt + 32B seed + 32B phantom block = 86 bytes
    assert_eq!(
        obk_bytes.len(),
        86,
        "Canonical X-Wing .obk private key must be exactly 86 bytes (32-byte seed representation)"
    );

    // .obp Public Key: 5B magic + 1B kem_id + 1184B ML-KEM-768 ek + 32B X25519 pk = 1222 bytes
    assert_eq!(
        obp_bytes.len(),
        1222,
        "X-Wing .obp public key must be exactly 1222 bytes"
    );

    // Public and Private key fingerprints must match
    let pub_fp = crate::crypto::compute_obp_fingerprint(&obp_bytes).unwrap();
    let priv_fp = crate::crypto::compute_obk_public_fingerprint(&obk_bytes).unwrap();
    assert_eq!(pub_fp, priv_fp);

    // Deterministic encapsulation & decapsulation
    let (ct, ss_enc, _) = crate::crypto::encapsulate_with_obp(&obp_bytes).unwrap();
    assert_eq!(ct.len(), 1088 + 32); // 1120 bytes
    assert_eq!(ss_enc.len(), 32);

    let (duress, ss_dec_opt) =
        crate::crypto::decapsulate_with_obk(1, &obk_bytes, &ct, "MasterPass").unwrap();
    assert!(!duress);
    assert_eq!(*ss_dec_opt.unwrap(), *ss_enc);

    // Trigger duress on the 86-byte key
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

    // Independent FIPS 202 SHA3-256 Known-Answer Test literal
    // Formula per draft-connolly-cfrg-xwing-kem §5:
    // ss = SHA3-256(ss_m || ss_x || ct_x || pk_x || r"\.//^\")
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

    let cancel_flag = Arc::new(AtomicBool::new(true)); // Pre-tripped cancellation
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

    // Fixed input values shared with the independent Go/CIRCL harness
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

    // Complementary local decapsulation, duress, and implicit-rejection checks
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

    // Establish pre-existing destination file
    std::fs::write(&final_path, b"PRE_EXISTING_IMMUTABLE_VAULT").unwrap();
    // Staged incoming replacement
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

    // Destination file must remain 100% unaltered
    let dest_content = std::fs::read(&final_path).unwrap();
    assert_eq!(
        dest_content, b"PRE_EXISTING_IMMUTABLE_VAULT",
        "Pre-existing destination file was clobbered or truncated!"
    );

    // Staged source must remain intact so caller's RAII guard manages cleanup
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

    // Injected simulated unsupported syscall error
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

    // Target must NOT be created via fallback rename or copy
    assert!(
        !final_path.exists(),
        "Target file must not be created when operation is unsupported"
    );
    // Source remains untouched for caller cleanup
    assert!(staging_path.exists(), "Source part file must remain untouched");

    let _ = std::fs::remove_dir_all(&temp_dir);
}