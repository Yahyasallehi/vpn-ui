package crypto

import "testing"

func TestEncryptDecryptStringRoundTrip(t *testing.T) {
	secret := []byte("a-test-secret-of-arbitrary-length")
	plaintext := "correct horse battery staple"

	ciphertext, err := EncryptString(plaintext, secret)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	if ciphertext == plaintext {
		t.Fatalf("ciphertext must not equal plaintext")
	}

	got, err := DecryptString(ciphertext, secret)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if got != plaintext {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptStringProducesDifferentCiphertextEachTime(t *testing.T) {
	secret := []byte("a-test-secret")
	plaintext := "same input"

	a, err := EncryptString(plaintext, secret)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	b, err := EncryptString(plaintext, secret)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	if a == b {
		t.Fatalf("expected distinct ciphertexts for the same plaintext (random nonce), got identical values")
	}
}

func TestDecryptStringFailsWithWrongKey(t *testing.T) {
	ciphertext, err := EncryptString("secret data", []byte("key-one"))
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	if _, err := DecryptString(ciphertext, []byte("key-two")); err == nil {
		t.Fatalf("expected DecryptString to fail with the wrong key, got nil error")
	}
}

func TestDecryptStringFailsOnTamperedCiphertext(t *testing.T) {
	secret := []byte("a-test-secret")
	ciphertext, err := EncryptString("secret data", secret)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	tampered := []byte(ciphertext)
	// Flip a byte in the middle of the base64 payload to corrupt the sealed data.
	tampered[len(tampered)/2] ^= 0x01
	if _, err := DecryptString(string(tampered), secret); err == nil {
		t.Fatalf("expected DecryptString to fail on tampered ciphertext, got nil error")
	}
}

func TestDecryptStringFailsOnGarbageInput(t *testing.T) {
	if _, err := DecryptString("not-valid-base64-or-ciphertext!!", []byte("key")); err == nil {
		t.Fatalf("expected DecryptString to fail on garbage input, got nil error")
	}
}
