# Ombracrypt
The zero-trust quantum vault.

Ombracrypt is a local, offline, quantum-resistant cryptographic engine designed to enforce absolute data sovereignty. It utilizes hybrid Post-Quantum Cryptography (PQC) encapsulation and authenticated ciphers to protect local directories from both classical and quantum attacks.

## Operational Limitations (v0.2.2)
* The engine currently evaluates archives directly in memory. 
* Do not encrypt directories larger than your available system RAM to prevent kernel panics.