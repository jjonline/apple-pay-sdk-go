package processing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"

	"errors"
)

// DecryptResponse calls DecryptToken(r.Token)
func (p *Processing) DecryptResponse(r *Response) (*Token, error) {
	return p.DecryptToken(&r.Token)
}

// DecryptToken decrypts an Apple Pay token
func (p *Processing) DecryptToken(t *PKPaymentToken) (*Token, error) {
	if p.processingCertificate == nil {
		return nil, errors.New("nil processing certificate")
	}
	// Verify the signature before anything
	if err := t.verifySignature(); err != nil {
		return nil, fmt.Errorf("invalid token signature: %w", err)
	}

	var key []byte
	var err error
	switch t.PaymentData.Version {
	case vEcV1:
		// Compute the encryption key for EC-based tokens
		key, err = p.computeEncryptionKey(t)
	case vRsaV1:
		// Decrypt the encryption key for RSA-based tokens
		key, err = p.unwrapEncryptionKey(t)
	}
	if err != nil {
		return nil, fmt.Errorf("error retrieving the encryption key: %w", err)
	}

	// Decrypt the token
	plaintextToken, err := t.decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the token: %w", err)
	}

	// Parse the token
	parsedToken := &Token{}
	_ = json.Unmarshal(plaintextToken, parsedToken)

	return parsedToken, nil
}

// EC

// computeEncryptionKey uses the token's ephemeral EC key, the processing
// private key, and the merchant ID to compute the encryption key
// It is only used for the EC_v1 format
func (p *Processing) computeEncryptionKey(t *PKPaymentToken) ([]byte, error) {
	// Load the required keys
	pub, err := t.ephemeralPublicKey()
	if err != nil {
		return nil, fmt.Errorf("unable to parse the public key: %w", err)
	}
	priv, ok := p.processingCertificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("non-elliptic processing private key")
	}

	// Generate the shared secret
	sharedSecret := ecdheSharedSecret(pub, priv)

	// Final key derivation from the shared secret and the hash of the merchant ID
	key := deriveEncryptionKey(sharedSecret, p.identifierHash())

	return key, nil
}

// identifierHash hashes m.config.MerchantIdentifier with SHA-256
func (p *Processing) identifierHash() []byte {
	h := sha256.New()
	h.Write([]byte(p.identifier))
	return h.Sum(nil)
}

// ephemeralPublicKey parsed the ephemeral public key in a PKPaymentToken
func (t *PKPaymentToken) ephemeralPublicKey() (*ecdsa.PublicKey, error) {
	// Parse the ephemeral public key
	pubI, err := x509.ParsePKIXPublicKey(
		t.PaymentData.Header.EphemeralPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing the public key: %w", err)
	}
	pub, ok := pubI.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid EC public key")
	}
	return pub, nil
}

// ecdheSharedSecret computes the shared secret between an EC public key and a
// EC private key, according to RFC5903 Section 9
func ecdheSharedSecret(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) *big.Int {
	z, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return z
}

// deriveEncryptionKey derives the symmetric encryption key of the token payload
// from a ECDHE shared secret and a hash of the merchant ID
// It uses the function described in NIST SP 800-56A, section 5.8.1
// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func deriveEncryptionKey(sharedSecret *big.Int, merchantIDHash []byte) []byte {
	// Only one round of the function is required
	counter := []byte{0, 0, 0, 1}
	// Apple-defined KDF parameters
	kdfAlgorithm := []byte("\x0Did-aes256-GCM")
	kdfPartyU := []byte("Apple")
	kdfPartyV := merchantIDHash

	// SHA256( counter || sharedSecret || algorithm || partyU || partyV )
	h := sha256.New()
	h.Write(counter)
	h.Write(sharedSecret.Bytes())
	h.Write(kdfAlgorithm)
	h.Write(kdfPartyU)
	h.Write(kdfPartyV)

	return h.Sum(nil)
}

// RSA

// unwrapEncryptionKey uses the merchant's RSA processing key to decrypt the
// encryption key stored in the token
// It is only used for the RSA_v1 format
func (p *Processing) unwrapEncryptionKey(t *PKPaymentToken) ([]byte, error) {
	priv, ok := p.processingCertificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("processing key is not RSA")
	}

	cipherText := t.PaymentData.Header.WrappedKey
	if cipherText == nil {
		return nil, errors.New("empty key ciphertext")
	}

	hash := sha256.New()
	key, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the key: %w", err)
	}

	return key, nil
}

// AES

// decrypt does the symmetric decryption of the payment token using AES-256-GCM
func (t *PKPaymentToken) decrypt(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating the block cipher: %w", err)
	}
	// Block size 16 mandated by Apple, works with the default 12
	aesGCM, _ := cipher.NewGCMWithNonceSize(block, 16)
	nonce := make([]byte, aesGCM.NonceSize())
	plaintext, err := aesGCM.Open(nil, nonce, t.PaymentData.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the data: %w", err)
	}
	return plaintext, nil
}
