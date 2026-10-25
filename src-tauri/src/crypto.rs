use argon2::{Algorithm, Argon2, Params, Version};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::{ml_kem_1024, ml_kem_768};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
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
const XWING_LABEL: &[u8; 6] = &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
// Domain Label for ML-KEM-1024 + X25519 High-Security Profile
const CYPHERPUNK_LABEL: &[u8; 6] = b"OMBMX2";

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

/// Generates serialized Public Key (.obp) and Private Key (.obk) byte payloads
pub fn generate_keypair_blobs(
    kem_choice: &str,
    deception_passcode: &str,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, u8), String> {
    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = PublicKey::from(&x25519_sk);

    let (mlkem_ek_bytes, mlkem_dk_bytes, kem_id) = if kem_choice == "cypherpunk" {
        let (ek, dk) = ml_kem_1024::KG::try_keygen()
            .map_err(|_| "FIPS 203 ML-KEM-1024 key generation failed.".to_string())?;
        (ek.into_bytes().to_vec(), Zeroizing::new(dk.into_bytes().to_vec()), 2u8)
    } else {
        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|_| "FIPS 203 ML-KEM-768 key generation failed.".to_string())?;
        (ek.into_bytes().to_vec(), Zeroizing::new(dk.into_bytes().to_vec()), 1u8)
    };

    // Assemble .obp (Public Sealing Key): [Magic 5B][kem_id 1B][ML-KEM EncapsKey][X25519 PublicKey 32B]
    let mut obp_bytes = Vec::with_capacity(6 + mlkem_ek_bytes.len() + 32);
    obp_bytes.extend_from_slice(OBP_MAGIC);
    obp_bytes.push(kem_id);
    obp_bytes.extend_from_slice(&mlkem_ek_bytes);
    obp_bytes.extend_from_slice(x25519_pk.as_bytes());

    // Generate dedicated duress salt & phantom block for .obk
    let mut duress_salt = [0u8; 16];
    OsRng.fill_bytes(&mut duress_salt);
    let phantom_block = generate_phantom_block(deception_passcode, &duress_salt)?;

    // Assemble .obk (Private Key): [Magic 5B][kem_id 1B][duress_salt 16B][ML-KEM DecapsKey][X25519 SecretKey 32B][Phantom 32B]
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

    // Ephemeral X25519 ECDH
    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);
    let x25519_ss = ephemeral_sk.diffie_hellman(&recipient_x25519_pk);

    // FIPS 203 ML-KEM Encapsulation
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

    // Official X-Wing Combiner: SHA3-256(SS_MLKEM || SS_X25519 || CT_X25519 || PK_X25519 || Label)
    let mut hasher = Sha3_256::new();
    hasher.update(&*mlkem_ss_bytes);
    hasher.update(x25519_ss.as_bytes());
    hasher.update(ephemeral_pk.as_bytes());
    hasher.update(recipient_x25519_pk.as_bytes());
    hasher.update(domain_label);
    let digest = hasher.finalize();

    let mut hybrid_ss = Zeroizing::new([0u8; 32]);
    hybrid_ss.copy_from_slice(&digest);

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
        return Err("Algorithm Mismatch: Key file (.obk) KEM profile does not match the vault.".to_string());
    }

    let duress_salt = &obk_bytes[6..22];
    let phantom_block = &obk_bytes[obk_bytes.len() - 32..];

    // 1. Check Duress Trapdoor before decapsulation
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

    // 2. FIPS 203 ML-KEM Decapsulation
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

    // 3. Classical X25519 Decapsulation
    let mut sk_arr = Zeroizing::new([0u8; 32]);
    sk_arr.copy_from_slice(x25519_sk_slice);
    let recipient_x25519_sk = StaticSecret::from(*sk_arr);
    let recipient_x25519_pk = PublicKey::from(&recipient_x25519_sk);

    let mut eph_pk_arr = [0u8; 32];
    eph_pk_arr.copy_from_slice(ephemeral_pk_slice);
    let ephemeral_x25519_pk = PublicKey::from(eph_pk_arr);

    let x25519_ss = recipient_x25519_sk.diffie_hellman(&ephemeral_x25519_pk);

    // 4. Official X-Wing Combiner: SHA3-256(SS_MLKEM || SS_X25519 || CT_X25519 || PK_X25519 || Label)
    let mut hasher = Sha3_256::new();
    hasher.update(&*mlkem_ss_bytes);
    hasher.update(x25519_ss.as_bytes());
    hasher.update(ephemeral_x25519_pk.as_bytes());
    hasher.update(recipient_x25519_pk.as_bytes());
    hasher.update(domain_label);
    let digest = hasher.finalize();

    let mut hybrid_ss = Zeroizing::new([0u8; 32]);
    hybrid_ss.copy_from_slice(&digest);

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