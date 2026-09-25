package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// deriveKey turns an arbitrary-length secret into a 32-byte AES-256 key via SHA-256, so
// callers can share an existing secret (e.g. the panel's session secret) instead of
// minting and storing a second one.
func deriveKey(secret []byte) [32]byte {
	return sha256.Sum256(secret)
}

// EncryptString encrypts plaintext with AES-256-GCM under a key derived from secret. The
// nonce is random per call and prepended to the ciphertext; the result is base64-encoded.
//
// This is confidentiality-only protection for values that must be recovered in plaintext
// later (unlike HashPasswordAsBcrypt, which is one-way and cannot be reversed) - e.g. a
// remote node's admin password, which the poller must resubmit on every login. It does not
// protect against an attacker who can read the key material itself.
func EncryptString(plaintext string, secret []byte) (string, error) {
	key := deriveKey(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString reverses EncryptString. It fails if secret does not match the key the
// value was encrypted under, or if the value has been tampered with (GCM is authenticated).
func DecryptString(ciphertext string, secret []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	key := deriveKey(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("crypto: ciphertext too short")
	}
	nonce, sealed := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
