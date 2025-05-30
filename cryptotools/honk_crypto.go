package cryptotools

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func DeriveVaultKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32) // time, memory, threads, keyLen
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16) // 128-bit salt
	_, err := rand.Read(salt)
	return salt, err
}

func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes for XChaCha20
	_, err := rand.Read(nonce)
	return nonce, err
}

func EncryptEntry(entryData, key []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	nonce, err = GenerateNonce()
	if err != nil {
		return nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, entryData, nil)
	return nonce, ciphertext, nil
}

func DecryptEntry(ciphertext, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DeriveEntryKey(vaultKey []byte, entryID string) []byte {
	h := hmac.New(sha256.New, vaultKey)
	h.Write([]byte(entryID))
	return h.Sum(nil)
}

func ComputeEntryHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func VerifyEntryHMAC(key, data, expectedMac []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), expectedMac)
}

// Base64Encode is a helper to encode bytes for storage
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode is a helper to decode base64 data
func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
