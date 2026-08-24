# Cryptographic Specifications

## Key Derivation & Hybrid Synthesis
A 16-byte cryptographically secure salt is generated via OS entropy. The user password and salt are hashed via Argon2id to generate a 256-bit base key. A Post-Quantum KEM (Kyber) generates a shared secret. Finally, the Argon2 base key and KEM shared secret are XOR'd to synthesize the unbreakable Master Key.

## Vault Header Structure (.obv)
`[CipherID (1)] [KemID (1)] [Salt (16)] [NonceLen (1)] [Nonce (12/24)] [CT_Len (2)] [Ciphertext] [Encrypted Payload]`