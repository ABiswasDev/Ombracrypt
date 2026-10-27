use argon2::{Algorithm, Argon2, Params, Version};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::{ml_kem_1024, ml_kem_768};
use hkdf::Hkdf;
use rand::{rngs::OsRng, CryptoRng, Error as RandError, RngCore};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::num::NonZeroU32;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const OBP_MAGIC: &[u8; 5] = b"OBPK\x02";
pub const OBK_MAGIC: &[u8; 5] = b"OBSK\x02";

// Explicit Hardened Argon2id Parameters (64 MiB RAM, 3 Passes, 4 Lanes)
pub const ARGON2_M_COST: u32 = 65_536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

// Official IETF X-Wing Domain Label ("\.//^\")
pub const XWING_LABEL: &[u8; 6] = &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
// Domain Label for ML-KEM-1024 + X25519 High-Security Profile
pub const CYPHERPUNK_LABEL: &[u8; 6] = b"OMBMX2";

/// Deterministic CSPRNG reader over a fixed seed slice for FIPS 203 / X-Wing seed expansion
struct SliceRng<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceRng<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> RngCore for SliceRng<'a> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.try_fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        if self.pos + dest.len() > self.data.len() {
            return Err(RandError::from(NonZeroU32::new(1).unwrap()));
        }
        dest.copy_from_slice(&self.data[self.pos..self.pos + dest.len()]);
        self.pos += dest.len();
        Ok(())
    }
}

impl<'a> CryptoRng for SliceRng<'a> {}

/// Expands a 32-byte X-Wing seed into 96 bytes via SHAKE256 per draft-connolly-cfrg-xwing-kem
pub fn expand_xwing_seed(seed: &[u8; 32]) -> Zeroizing<[u8; 96]> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut shake = sha3::Shake256::default();
    shake.update(seed);
    let mut reader = shake.finalize_xof();
    let mut out = Zeroizing::new([0u8; 96]);
    reader.read(&mut *out);
    out
}

/// Computes the official X-Wing / Hybrid SHA3-256 combiner digest
pub fn compute_hybrid_combiner(
    mlkem_ss: &[u8],
    x25519_ss: &[u8; 32],
    ephemeral_x25519_pk: &[u8; 32],
    recipient_x25519_pk: &[u8; 32],
    domain_label: &[u8; 6],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    hasher.update(mlkem_ss);
    hasher.update(x25519_ss);
    hasher.update(ephemeral_x25519_pk);
    hasher.update(recipient_x25519_pk);
    hasher.update(domain_label);
    let digest = hasher.finalize();

    let mut hybrid_ss = Zeroizing::new([0u8; 32]);
    hybrid_ss.copy_from_slice(&digest);
    hybrid_ss
}

/// Computes a human-verifiable SHA-256 fingerprint (XXXX-XXXX-XXXX-XXXX) of a canonical .obp Public Key
pub fn compute_obp_fingerprint(obp_bytes: &[u8]) -> Result<String, String> {
    if obp_bytes.len() < 6 + 32 || &obp_bytes[..5] != OBP_MAGIC {
        return Err("Invalid Public Key (.obp): Unrecognized header or corrupted file.".to_string());
    }
    let kem_id = obp_bytes[5];
    let expected_len = match kem_id {
        1 => 6 + ml_kem_768::EK_LEN + 32,
        2 => 6 + ml_kem_1024::EK_LEN + 32,
        _ => return Err("Invalid Public Key (.obp): Unsupported KEM profile ID.".to_string()),
    };
    if obp_bytes.len() != expected_len {
        return Err(
            "Invalid Public Key (.obp): File size does not match KEM profile.".to_string(),
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(obp_bytes);
    let digest = hasher.finalize();

    Ok(format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    ))
}

/// Reconstructs the public key components from an .obk Private Key to compute its matching Key ID fingerprint
pub fn compute_obk_public_fingerprint(obk_bytes: &[u8]) -> Result<String, String> {
    if obk_bytes.len() < 6 + 16 + 32 + 32 || &obk_bytes[..5] != OBK_MAGIC {
        return Err(
            "Invalid Private Key (.obk): Unrecognized header or corrupted file.".to_string(),
        );
    }
    let kem_id = obk_bytes[5];
    let (expected_obk_len, ek_len) = match kem_id {
        1 => (6 + 16 + ml_kem_768::DK_LEN + 32 + 32, ml_kem_768::EK_LEN),
        2 => (6 + 16 + ml_kem_1024::DK_LEN + 32 + 32, ml_kem_1024::EK_LEN),
        _ => return Err("Invalid Private Key (.obk): Unsupported KEM profile ID.".to_string()),
    };
    if obk_bytes.len() != expected_obk_len {
        return Err(
            "Invalid Private Key (.obk): File size does not match KEM profile.".to_string(),
        );
    }

    let secret_body = &obk_bytes[22..obk_bytes.len() - 32];
    let mlkem_dk_slice = &secret_body[..secret_body.len() - 32];
    let x25519_sk_slice = &secret_body[secret_body.len() - 32..];

    // Per FIPS 203 §7.1, the ML-KEM Encapsulation Key (ek) is stored inside dk at [dk_len - 64 - ek_len .. dk_len - 64]
    let ek_start = mlkem_dk_slice.len() - 64 - ek_len;
    let ek_end = mlkem_dk_slice.len() - 64;
    let mlkem_ek_slice = &mlkem_dk_slice[ek_start..ek_end];

    let mut sk_arr = Zeroizing::new([0u8; 32]);
    sk_arr.copy_from_slice(x25519_sk_slice);
    let x25519_sk = StaticSecret::from(*sk_arr);
    let x25519_pk = PublicKey::from(&x25519_sk);

    let mut canonical_obp = Vec::with_capacity(6 + ek_len + 32);
    canonical_obp.extend_from_slice(OBP_MAGIC);
    canonical_obp.push(kem_id);
    canonical_obp.extend_from_slice(mlkem_ek_slice);
    canonical_obp.extend_from_slice(x25519_pk.as_bytes());

    compute_obp_fingerprint(&canonical_obp)
}

/// Deterministically derives a per-chunk nonce from the base nonce and chunk counter
pub fn increment_nonce(base: &[u8], counter: u64) -> Vec<u8> {
    let mut nonce = base.to_vec();
    let counter_bytes = counter.to_le_bytes();
    let len = nonce.len();
    for i in 0..8 {
        nonce[len - 8 + i] ^= counter_bytes[i];
    }
    nonce
}

fn build_argon2(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Argon2<'static>, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("Invalid Argon2id parameters: {}", e))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derives a 32-byte key and generates a fresh 16-byte random salt using explicit Argon2id parameters
pub fn derive_key(pin: &str) -> Result<(Zeroizing<[u8; 32]>, [u8; 16]), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key_with_params(pin, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    Ok((key, salt))
}

/// Derives a 32-byte key using explicit Argon2id parameters extracted from the vault header
pub fn derive_key_with_params(
    pin: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    let argon = build_argon2(m_cost, t_cost, p_cost)?;
    argon
        .hash_password_into(pin.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Argon2id key derivation failed: {}", e))?;
    Ok(key)
}

/// Generates the 32-byte Phantom Block for the .obk key file (Duress Trapdoor)
pub fn generate_phantom_block(passcode: &str, duress_salt: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut block = vec![0u8; 32];
    if passcode.trim().is_empty() {
        OsRng.fill_bytes(&mut block);
    } else {
        let argon = build_argon2(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
        argon
            .hash_password_into(passcode.as_bytes(), duress_salt, &mut block)
            .map_err(|e| format!("Argon2id hashing failed for duress block: {}", e))?;
    }
    Ok(block)
}

/// Verifies in constant time whether the entered password matches the Duress Phantom Block
pub fn check_duress_passcode(
    candidate_pin: &str,
    duress_salt: &[u8],
    phantom_block: &[u8],
) -> Result<bool, String> {
    if candidate_pin.trim().is_empty() || phantom_block.len() != 32 {
        return Ok(false);
    }
    let derived = derive_key_with_params(
        candidate_pin,
        duress_salt,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )?;
    Ok(bool::from(derived.as_slice().ct_eq(phantom_block)))
}

/// Deterministically generates an X-Wing (ML-KEM-768 + X25519) keypair from a 32-byte seed via SHAKE256
pub fn generate_xwing_keypair_from_seed(
    seed: &[u8; 32],
    deception_passcode: &str,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, u8), String> {
    let expanded = expand_xwing_seed(seed);
    let mut mlkem_rng = SliceRng::new(&expanded[..64]);
    let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut mlkem_rng)
        .map_err(|_| "FIPS 203 ML-KEM-768 deterministic keygen failed.".to_string())?;

    let mut x25519_sk_arr = Zeroizing::new([0u8; 32]);
    x25519_sk_arr.copy_from_slice(&expanded[64..96]);
    let x25519_sk = StaticSecret::from(*x25519_sk_arr);
    let x25519_pk = PublicKey::from(&x25519_sk);

    let mlkem_ek_bytes = ek.into_bytes().to_vec();
    let mlkem_dk_bytes = Zeroizing::new(dk.into_bytes().to_vec());
    let kem_id = 1u8;

    let mut obp_bytes = Vec::with_capacity(6 + mlkem_ek_bytes.len() + 32);
    obp_bytes.extend_from_slice(OBP_MAGIC);
    obp_bytes.push(kem_id);
    obp_bytes.extend_from_slice(&mlkem_ek_bytes);
    obp_bytes.extend_from_slice(x25519_pk.as_bytes());

    let mut duress_salt = [0u8; 16];
    OsRng.fill_bytes(&mut duress_salt);
    let phantom_block = generate_phantom_block(deception_passcode, &duress_salt)?;

    let mut obk_bytes = Zeroizing::new(Vec::with_capacity(6 + 16 + mlkem_dk_bytes.len() + 32 + 32));
    obk_bytes.extend_from_slice(OBK_MAGIC);
    obk_bytes.push(kem_id);
    obk_bytes.extend_from_slice(&duress_salt);
    obk_bytes.extend_from_slice(&mlkem_dk_bytes);
    obk_bytes.extend_from_slice(&*x25519_sk_arr);
    obk_bytes.extend_from_slice(&phantom_block);

    Ok((obp_bytes, obk_bytes, kem_id))
}

/// Generates serialized Public Key (.obp) and Private Key (.obk) byte payloads
pub fn generate_keypair_blobs(
    kem_choice: &str,
    deception_passcode: &str,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, u8), String> {
    if kem_choice != "cypherpunk" {
        let mut xwing_seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *xwing_seed);
        return generate_xwing_keypair_from_seed(&xwing_seed, deception_passcode);
    }

    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = PublicKey::from(&x25519_sk);

    let (ek, dk) = ml_kem_1024::KG::try_keygen()
        .map_err(|_| "FIPS 203 ML-KEM-1024 key generation failed.".to_string())?;
    let mlkem_ek_bytes = ek.into_bytes().to_vec();
    let mlkem_dk_bytes = Zeroizing::new(dk.into_bytes().to_vec());
    let kem_id = 2u8;

    let mut obp_bytes = Vec::with_capacity(6 + mlkem_ek_bytes.len() + 32);
    obp_bytes.extend_from_slice(OBP_MAGIC);
    obp_bytes.push(kem_id);
    obp_bytes.extend_from_slice(&mlkem_ek_bytes);
    obp_bytes.extend_from_slice(x25519_pk.as_bytes());

    let mut duress_salt = [0u8; 16];
    OsRng.fill_bytes(&mut duress_salt);
    let phantom_block = generate_phantom_block(deception_passcode, &duress_salt)?;

    let mut obk_bytes = Zeroizing::new(Vec::with_capacity(6 + 16 + mlkem_dk_bytes.len() + 32 + 32));
    obk_bytes.extend_from_slice(OBK_MAGIC);
    obk_bytes.push(kem_id);
    obk_bytes.extend_from_slice(&duress_salt);
    obk_bytes.extend_from_slice(&mlkem_dk_bytes);
    let x25519_sk_bytes = Zeroizing::new(x25519_sk.to_bytes());
    obk_bytes.extend_from_slice(&*x25519_sk_bytes);
    obk_bytes.extend_from_slice(&phantom_block);

    Ok((obp_bytes, obk_bytes, kem_id))
}

/// Encapsulates a hybrid shared secret against a serialized .obp Public Key using the X-Wing SHA3-256 combiner
pub fn encapsulate_with_obp(obp_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>, u8), String> {
    if obp_bytes.len() < 6 + 32 || &obp_bytes[..5] != OBP_MAGIC {
        return Err("Invalid Public Key (.obp): Unrecognized header or corrupted file.".to_string());
    }

    let kem_id = obp_bytes[5];
    let key_body = &obp_bytes[6..];
    let mlkem_ek_len = key_body.len() - 32;
    let mlkem_ek_slice = &key_body[..mlkem_ek_len];
    let x25519_pk_slice = &key_body[mlkem_ek_len..];

    let mut recipient_pk_arr = [0u8; 32];
    recipient_pk_arr.copy_from_slice(x25519_pk_slice);
    let recipient_x25519_pk = PublicKey::from(recipient_pk_arr);

    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);
    let x25519_ss = ephemeral_sk.diffie_hellman(&recipient_x25519_pk);

    let (mlkem_ss_bytes, mlkem_ct_bytes, domain_label) = if kem_id == 2 {
        let ek_arr: [u8; ml_kem_1024::EK_LEN] = mlkem_ek_slice
            .try_into()
            .map_err(|_| "Invalid ML-KEM-1024 public key length.".to_string())?;
        let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_arr)
            .map_err(|_| "Invalid ML-KEM-1024 encapsulation key.".to_string())?;
        let (ssk, ct) = ek
            .try_encaps()
            .map_err(|_| "ML-KEM-1024 encapsulation failed.".to_string())?;
        (
            Zeroizing::new(ssk.into_bytes()),
            ct.into_bytes().to_vec(),
            CYPHERPUNK_LABEL,
        )
    } else if kem_id == 1 {
        let ek_arr: [u8; ml_kem_768::EK_LEN] = mlkem_ek_slice
            .try_into()
            .map_err(|_| "Invalid ML-KEM-768 public key length.".to_string())?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr)
            .map_err(|_| "Invalid ML-KEM-768 encapsulation key.".to_string())?;
        let (ssk, ct) = ek
            .try_encaps()
            .map_err(|_| "ML-KEM-768 encapsulation failed.".to_string())?;
        (
            Zeroizing::new(ssk.into_bytes()),
            ct.into_bytes().to_vec(),
            XWING_LABEL,
        )
    } else {
        return Err(format!("Unsupported KEM ID in public key: {}", kem_id));
    };

    let hybrid_ss = compute_hybrid_combiner(
        &*mlkem_ss_bytes,
        x25519_ss.as_bytes(),
        ephemeral_pk.as_bytes(),
        recipient_x25519_pk.as_bytes(),
        domain_label,
    );

    let mut combined_ct = mlkem_ct_bytes;
    combined_ct.extend_from_slice(ephemeral_pk.as_bytes());

    Ok((combined_ct, hybrid_ss, kem_id))
}

/// Parses .obk, verifies whether the Duress Trapdoor was triggered, and decapsulates the hybrid shared secret
pub fn decapsulate_with_obk(
    expected_kem_id: u8,
    obk_bytes: &[u8],
    combined_ct: &[u8],
    candidate_pin: &str,
) -> Result<(bool, Option<Zeroizing<[u8; 32]>>), String> {
    if obk_bytes.len() < 6 + 16 + 32 + 32 || &obk_bytes[..5] != OBK_MAGIC {
        return Err("Integrity Error: Invalid or corrupted Private Key (.obk) format.".to_string());
    }

    let key_kem_id = obk_bytes[5];
    if key_kem_id != expected_kem_id {
        return Err(
            "Algorithm Mismatch: Key file (.obk) KEM profile does not match the vault.".to_string(),
        );
    }

    let duress_salt = &obk_bytes[6..22];
    let phantom_block = &obk_bytes[obk_bytes.len() - 32..];

    if check_duress_passcode(candidate_pin, duress_salt, phantom_block)? {
        return Ok((true, None));
    }

    if combined_ct.len() <= 32 {
        return Err("Integrity Error: Vault KEM ciphertext is truncated.".to_string());
    }

    let secret_body = &obk_bytes[22..obk_bytes.len() - 32];
    let mlkem_dk_len = secret_body.len() - 32;
    let mlkem_dk_slice = &secret_body[..mlkem_dk_len];
    let x25519_sk_slice = &secret_body[mlkem_dk_len..];

    let mlkem_ct_len = combined_ct.len() - 32;
    let mlkem_ct_slice = &combined_ct[..mlkem_ct_len];
    let ephemeral_pk_slice = &combined_ct[mlkem_ct_len..];

    let (mlkem_ss_bytes, domain_label) = if expected_kem_id == 2 {
        let dk_arr: [u8; ml_kem_1024::DK_LEN] = mlkem_dk_slice
            .try_into()
            .map_err(|_| "Integrity Error: Invalid ML-KEM-1024 secret key length.".to_string())?;
        let ct_arr: [u8; ml_kem_1024::CT_LEN] = mlkem_ct_slice
            .try_into()
            .map_err(|_| "Integrity Error: Invalid ML-KEM-1024 ciphertext length.".to_string())?;
        let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_arr)
            .map_err(|_| "Integrity Error: Corrupted ML-KEM-1024 private key.".to_string())?;
        let ct = ml_kem_1024::CipherText::try_from_bytes(ct_arr)
            .map_err(|_| "Integrity Error: Corrupted ML-KEM-1024 ciphertext.".to_string())?;
        let ssk = dk
            .try_decaps(&ct)
            .map_err(|_| "ML-KEM-1024 decapsulation failed.".to_string())?;
        (Zeroizing::new(ssk.into_bytes()), CYPHERPUNK_LABEL)
    } else if expected_kem_id == 1 {
        let dk_arr: [u8; ml_kem_768::DK_LEN] = mlkem_dk_slice
            .try_into()
            .map_err(|_| "Integrity Error: Invalid ML-KEM-768 secret key length.".to_string())?;
        let ct_arr: [u8; ml_kem_768::CT_LEN] = mlkem_ct_slice
            .try_into()
            .map_err(|_| "Integrity Error: Invalid ML-KEM-768 ciphertext length.".to_string())?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr)
            .map_err(|_| "Integrity Error: Corrupted ML-KEM-768 private key.".to_string())?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr)
            .map_err(|_| "Integrity Error: Corrupted ML-KEM-768 ciphertext.".to_string())?;
        let ssk = dk
            .try_decaps(&ct)
            .map_err(|_| "ML-KEM-768 decapsulation failed.".to_string())?;
        (Zeroizing::new(ssk.into_bytes()), XWING_LABEL)
    } else {
        return Err(format!("Unsupported KEM ID: {}", expected_kem_id));
    };

    let mut sk_arr = Zeroizing::new([0u8; 32]);
    sk_arr.copy_from_slice(x25519_sk_slice);
    let recipient_x25519_sk = StaticSecret::from(*sk_arr);
    let recipient_x25519_pk = PublicKey::from(&recipient_x25519_sk);

    let mut eph_pk_arr = [0u8; 32];
    eph_pk_arr.copy_from_slice(ephemeral_pk_slice);
    let ephemeral_x25519_pk = PublicKey::from(eph_pk_arr);

    let x25519_ss = recipient_x25519_sk.diffie_hellman(&ephemeral_x25519_pk);

    let hybrid_ss = compute_hybrid_combiner(
        &*mlkem_ss_bytes,
        x25519_ss.as_bytes(),
        ephemeral_x25519_pk.as_bytes(),
        recipient_x25519_pk.as_bytes(),
        domain_label,
    );

    Ok((false, Some(hybrid_ss)))
}

/// Synthesizes the 256-bit Master Key via RFC 5869 HKDF-SHA256
pub fn compute_master_key(
    argon_key: &[u8; 32],
    ss_bytes: &[u8; 32],
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(argon_key);
    ikm[32..].copy_from_slice(ss_bytes);

    let hk = Hkdf::<Sha256>::new(Some(salt), &*ikm);
    let mut master_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"OMBRACRYPT-V2-MASTER-KEY", &mut *master_key)
        .map_err(|_| "HKDF master key expansion failed.".to_string())?;
    Ok(master_key)
}