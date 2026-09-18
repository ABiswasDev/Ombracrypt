use argon2::Argon2;
use pqcrypto_kyber::{kyber1024, kyber768};
use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};
use x25519_dalek::{StaticSecret, PublicKey};
use zeroize::Zeroizing;

/// Safely increments the nonce for each streaming chunk to prevent cryptographic reuse
pub fn increment_nonce(base: &[u8], counter: u64) -> Vec<u8> {
    let mut nonce = base.to_vec();
    let counter_bytes = counter.to_le_bytes();
    let len = nonce.len();
    for i in 0..8 {
        nonce[len - 8 + i] ^= counter_bytes[i];
    }
    nonce
}

/// Derives a fresh 32-byte key and a 16-byte random salt for encryption
pub fn derive_key(pin: &str) -> Result<(Zeroizing<[u8; 32]>, [u8; 16]), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(pin.as_bytes(), &salt, &mut *key)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?;
    Ok((key, salt))
}

/// Derives a 32-byte key using an existing salt extracted from the vault header
pub fn derive_key_with_salt(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(pin.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?;
    Ok(key)
}

/// Generates the 32-byte Phantom Block for the end of the .obk file ==> Plausibly Deniable Duress Trapdoor.
pub fn generate_phantom_block(passcode: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut block = vec![0u8; 32];
    if passcode.trim().is_empty() {
        OsRng.fill_bytes(&mut block);
    } else {
        Argon2::default()
            .hash_password_into(passcode.as_bytes(), salt, &mut block)
            .map_err(|e| format!("Argon2 hashing failed for phantom block: {}", e))?;
    }
    Ok(block)
}

/// HYBRID KEM: Generates X25519 + Kyber pairs, combines secrets via SHA-256, and packs payloads
pub fn generate_hybrid_kem(kem_choice: &str) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Zeroizing<Vec<u8>>, u8), String> {
    // 1. Classical X25519 (ECDH)
    let vault_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let vault_public = PublicKey::from(&vault_secret);
    let x25519_ss = ephemeral_secret.diffie_hellman(&vault_public);

    // 2. Quantum Kyber
    let (kyber_sk, kyber_ct, kyber_ss, kem_id) = if kem_choice == "cypherpunk" {
        let (pk, sk) = kyber1024::keypair();
        let (ss, ct) = kyber1024::encapsulate(&pk);
        (sk.as_bytes().to_vec(), ct.as_bytes().to_vec(), ss.as_bytes().to_vec(), 2)
    } else {
        let (pk, sk) = kyber768::keypair();
        let (ss, ct) = kyber768::encapsulate(&pk);
        (sk.as_bytes().to_vec(), ct.as_bytes().to_vec(), ss.as_bytes().to_vec(), 1)
    };

    // 3. The Combiner (SHA-256 HKDF)
    let mut hasher = Sha256::new();
    hasher.update(&kyber_ss);
    hasher.update(x25519_ss.as_bytes());
    let hybrid_ss = hasher.finalize().to_vec();

    // 4. Pack the Payloads (.obk gets both private keys, .obv gets both ciphertexts/public keys)
    let mut combined_sk = kyber_sk;
    combined_sk.extend_from_slice(&vault_secret.to_bytes());

    let mut combined_ct = kyber_ct;
    combined_ct.extend_from_slice(ephemeral_public.as_bytes());

    Ok((
        Zeroizing::new(combined_sk),
        combined_ct,
        Zeroizing::new(hybrid_ss),
        kem_id
    ))
}

/// HYBRID DECAPSULATION: Extracts both keys, performs classical DH and quantum decapsulation, and hashes to restore the key
pub fn decapsulate_hybrid_kem(kem_id: u8, combined_sk: &[u8], combined_ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if combined_sk.len() < 32 || combined_ct.len() < 32 {
        return Err("Integrity Error: Key or ciphertext payload is too short.".to_string());
    }

    // Split arrays back into their Quantum and Classical halves
    let kyber_sk_len = combined_sk.len() - 32;
    let kyber_ct_len = combined_ct.len() - 32;

    let kyber_sk_bytes = &combined_sk[..kyber_sk_len];
    let x25519_sk_bytes = &combined_sk[kyber_sk_len..];
    let kyber_ct_bytes = &combined_ct[..kyber_ct_len];
    let x25519_pk_bytes = &combined_ct[kyber_ct_len..];

    // 1. Quantum Kyber Decapsulation
    let kyber_ss = if kem_id == 2 {
        let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(kyber_sk_bytes)
            .map_err(|_| "Integrity Error: The provided key file is invalid.".to_string())?;
        let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(kyber_ct_bytes)
            .map_err(|_| "Integrity Error: Vault header is structurally compromised.".to_string())?;
        pqcrypto_kyber::kyber1024::decapsulate(&ct, &sk).as_bytes().to_vec()
    } else {
        let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(kyber_sk_bytes)
            .map_err(|_| "Integrity Error: The provided key file is invalid.".to_string())?;
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(kyber_ct_bytes)
            .map_err(|_| "Integrity Error: Vault header is structurally compromised.".to_string())?;
        pqcrypto_kyber::kyber768::decapsulate(&ct, &sk).as_bytes().to_vec()
    };

    // 2. Classical X25519 Decapsulation (DH)
    let mut sk_array = [0u8; 32];
    sk_array.copy_from_slice(x25519_sk_bytes);
    let vault_secret = StaticSecret::from(sk_array);

    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(x25519_pk_bytes);
    let ephemeral_public = PublicKey::from(pk_array);

    let x25519_ss = vault_secret.diffie_hellman(&ephemeral_public);

    // 3. The Combiner (SHA-256 HKDF)
    let mut hasher = Sha256::new();
    hasher.update(&kyber_ss);
    hasher.update(x25519_ss.as_bytes());
    let hybrid_ss = hasher.finalize().to_vec();

    Ok(Zeroizing::new(hybrid_ss))
}

/// Synthesizes the final master key by XORing the Argon2 output and the Hybrid Shared Secret
pub fn compute_master_key(argon_key: &[u8; 32], ss_bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut final_master_key = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        final_master_key[i] = argon_key[i] ^ ss_bytes[i];
    }
    final_master_key
}