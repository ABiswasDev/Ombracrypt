package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/sha3"
)

func main() {
	fmt.Println("=== Generating Independent X-Wing Draft-11 Fixtures via CIRCL v1.6.5 ===")

	// 1. Fixed test vectors (Draft-11 §5.2.1 & §5.4.1)
	seed := bytes.Repeat([]byte{0x42}, 32)
	ephemSeed := bytes.Repeat([]byte{0x99}, 64)

	// 2. Expand private seed via SHAKE256 to 96 bytes:
	//    [0..64]: ML-KEM-768 seed (d || z)
	//    [64..96]: X25519 scalar
	shake := sha3.NewShake256()
	shake.Write(seed)
	expanded := make([]byte, 96)
	shake.Read(expanded)

	// Derive ML-KEM-768 Keypair using CIRCL's DeriveKeyPair
	scheme := mlkem768.Scheme()
	pkKEM, _ := scheme.DeriveKeyPair(expanded[:64])
	pkKEMBytes, err := pkKEM.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal ML-KEM PK: %v", err))
	}

	// Derive X25519 Keypair per RFC 7748
	curve := ecdh.X25519()
	skX, err := curve.NewPrivateKey(expanded[64:96])
	if err != nil {
		panic(fmt.Sprintf("Failed to derive X25519 SK: %v", err))
	}
	pkXBytes := skX.PublicKey().Bytes()

	// Composite Raw Public Key (1,184 + 32 = 1,216 bytes)
	var rawPK []byte
	rawPK = append(rawPK, pkKEMBytes...)
	rawPK = append(rawPK, pkXBytes...)

	if len(rawPK) != 1216 {
		panic(fmt.Sprintf("Invalid PK length: %d (expected 1216)", len(rawPK)))
	}

	// 3. Deterministic Encapsulation using CIRCL's EncapsulateDeterministically
	//    ephemSeed[0..32]: ML-KEM encapsulation randomness (m)
	//    ephemSeed[32..64]: X25519 ephemeral private scalar
	ctKEM, ssKEM, err := scheme.EncapsulateDeterministically(pkKEM, ephemSeed[:32])
	if err != nil {
		panic(fmt.Sprintf("Failed ML-KEM EncapsulateDeterministically: %v", err))
	}

	ephSkX, err := curve.NewPrivateKey(ephemSeed[32:64])
	if err != nil {
		panic(fmt.Sprintf("Failed to derive ephemeral X25519 SK: %v", err))
	}
	ephPkXBytes := ephSkX.PublicKey().Bytes()

	// Ephemeral ECDH shared secret
	ssX, err := ephSkX.ECDH(skX.PublicKey())
	if err != nil {
		panic(fmt.Sprintf("Failed X25519 ECDH: %v", err))
	}

	// Composite Ciphertext (1,088 + 32 = 1,120 bytes)
	var combinedCT []byte
	combinedCT = append(combinedCT, ctKEM...)
	combinedCT = append(combinedCT, ephPkXBytes...)

	if len(combinedCT) != 1120 {
		panic(fmt.Sprintf("Invalid CT length: %d (expected 1120)", len(combinedCT)))
	}

	// 4. Shared Secret Synthesis (Draft-11 Combiner)
	// ss = SHA3-256(ss_kem || ss_x || ct_x || pk_x || "\.//^\")
	// Domain separator bytes: 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c
	domainSep := []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}
	h := sha3.New256()
	h.Write(ssKEM)
	h.Write(ssX)
	h.Write(ephPkXBytes) // ct_x25519
	h.Write(pkXBytes)    // pk_x25519
	h.Write(domainSep)
	sharedSecret := h.Sum(nil)

	if len(sharedSecret) != 32 {
		panic(fmt.Sprintf("Invalid SS length: %d (expected 32)", len(sharedSecret)))
	}

	// 5. Ensure output directory exists
	outDir := filepath.Join("..", "..", "src-tauri", "tests", "fixtures", "xwing_revision11")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create fixture dir: %v", err))
	}

	// 6. Write binary fixtures
	pkPath := filepath.Join(outDir, "public_key.bin")
	ctPath := filepath.Join(outDir, "ciphertext.bin")
	ssPath := filepath.Join(outDir, "shared_secret.bin")

	os.WriteFile(pkPath, rawPK, 0644)
	os.WriteFile(ctPath, combinedCT, 0644)
	os.WriteFile(ssPath, sharedSecret, 0644)

	// 7. Calculate SHA-256 digests for provenance
	pkHash := sha256.Sum256(rawPK)
	ctHash := sha256.Sum256(combinedCT)
	ssHash := sha256.Sum256(sharedSecret)

	provenance := fmt.Sprintf(`# X-Wing Revision 11 Fixture Provenance Record

- **Generated At**: %s
- **Specification**: IETF draft-connolly-cfrg-xwing-kem-11 (Informational)
- **ML-KEM Reference Engine**: Cloudflare CIRCL v1.6.5 (github.com/cloudflare/circl/kem/mlkem/mlkem768)
- **X25519 Reference Engine**: Go crypto/ecdh (Go 1.25.1)
- **Combiner Hash Engine**: golang.org/x/crypto/sha3 (SHA3-256)

## Deterministic Seed Inputs
- **Private Key Seed (32 bytes)**: [0x42; 32]
- **Ephemeral Encapsulation Seed (64 bytes)**: [0x99; 64]

## Generated Artifacts & SHA-256 Digests
- **public_key.bin** (1,216 bytes):
  `+"`%s`"+`
- **ciphertext.bin** (1,120 bytes):
  `+"`%s`"+`
- **shared_secret.bin** (32 bytes):
  `+"`%s`"+`
`, time.Now().UTC().Format(time.RFC3339), hex.EncodeToString(pkHash[:]), hex.EncodeToString(ctHash[:]), hex.EncodeToString(ssHash[:]))

	provPath := filepath.Join(outDir, "PROVENANCE.md")
	os.WriteFile(provPath, []byte(provenance), 0644)

	fmt.Println("Successfully generated all fixtures:")
	fmt.Printf(" - %s (1,216 bytes)\n", pkPath)
	fmt.Printf(" - %s (1,120 bytes)\n", ctPath)
	fmt.Printf(" - %s (32 bytes)\n", ssPath)
	fmt.Printf(" - %s\n", provPath)
}
