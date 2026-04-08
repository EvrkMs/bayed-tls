package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	AuthPlaintext = "AUTHOK"
	VPNConfirm    = "VPNOK"
)

// Keys holds derived key material for a bayed-tls session.
type Keys struct {
	AuthKey []byte // 32 bytes — auth beacon encryption
	C2SKey  []byte // 32 bytes — client → server tunnel
	S2CKey  []byte // 32 bytes — server → client tunnel
}

// DeriveKeys derives session keys from PSK and TLS handshake randoms.
//
//	salt = clientRandom || serverRandom
//	Each key = HKDF-SHA256(PSK, salt, info)
func DeriveKeys(psk, clientRandom, serverRandom []byte) (*Keys, error) {
	salt := make([]byte, 0, 64)
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	derive := func(info string) ([]byte, error) {
		r := hkdf.New(sha256.New, psk, salt, []byte(info))
		key := make([]byte, 32)
		if _, err := io.ReadFull(r, key); err != nil {
			return nil, fmt.Errorf("hkdf(%s): %w", info, err)
		}
		return key, nil
	}

	authKey, err := derive("bayed-auth")
	if err != nil {
		return nil, err
	}
	c2s, err := derive("bayed-c2s")
	if err != nil {
		return nil, err
	}
	s2c, err := derive("bayed-s2c")
	if err != nil {
		return nil, err
	}

	return &Keys{AuthKey: authKey, C2SKey: c2s, S2CKey: s2c}, nil
}

// MakeAuthPayload creates the encrypted auth beacon.
// Nonce = clientRandom[:12].
func MakeAuthPayload(authKey, clientRandom []byte) ([]byte, error) {
	if len(authKey) != 32 || len(clientRandom) < 12 {
		return nil, errors.New("invalid key or nonce length")
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, clientRandom[:12], []byte(AuthPlaintext), nil), nil
}

// VerifyAuthPayload decrypts and verifies the auth beacon.
func VerifyAuthPayload(authKey, clientRandom, ciphertext []byte) bool {
	if len(authKey) != 32 || len(clientRandom) < 12 {
		return false
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	plaintext, err := gcm.Open(nil, clientRandom[:12], ciphertext, nil)
	if err != nil {
		return false
	}
	return string(plaintext) == AuthPlaintext
}

// MakeConfirmPayload creates the server's confirmation message.
// Nonce = serverRandom[:12].
func MakeConfirmPayload(authKey, serverRandom []byte) ([]byte, error) {
	if len(authKey) != 32 || len(serverRandom) < 12 {
		return nil, errors.New("invalid key or nonce length")
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, serverRandom[:12], []byte(VPNConfirm), nil), nil
}

// VerifyConfirmPayload verifies the server's confirmation message.
func VerifyConfirmPayload(authKey, serverRandom, ciphertext []byte) bool {
	if len(authKey) != 32 || len(serverRandom) < 12 {
		return false
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	plaintext, err := gcm.Open(nil, serverRandom[:12], ciphertext, nil)
	if err != nil {
		return false
	}
	return string(plaintext) == VPNConfirm
}
