package bayed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	authPlaintext = "AUTHOK"
	vpnConfirm    = "VPNOK"
)

// Conn is an encrypted bayed-tls connection that implements net.Conn.
// After a successful handshake (via Server() or Client()), the returned
// *Conn can be used transparently by any protocol layer above.
//
// On the wire, each Write/Read maps to one TLS Application Data record,
// encrypted with AES-256-GCM and sequential nonces.
type Conn struct {
	raw     net.Conn
	reader  io.Reader
	sendGCM cipher.AEAD
	recvGCM cipher.AEAD
	sendSeq uint64
	recvSeq uint64
	mu      sync.Mutex // protects writes
	readBuf []byte     // buffered plaintext from partial reads

	// Exported fields for upper protocol layers to inspect.
	Verified     bool   // true if client was authenticated
	ServerName   string // SNI used during handshake
}

// newConn creates an encrypted connection from derived keys.
func newConn(raw net.Conn, reader io.Reader, c2sKey, s2cKey []byte, isClient bool) (*Conn, error) {
	var sendKey, recvKey []byte
	if isClient {
		sendKey, recvKey = c2sKey, s2cKey
	} else {
		sendKey, recvKey = s2cKey, c2sKey
	}

	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, err
	}
	sendGCM, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, err
	}

	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, err
	}
	recvGCM, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, err
	}

	return &Conn{
		raw:     raw,
		reader:  reader,
		sendGCM: sendGCM,
		recvGCM: recvGCM,
	}, nil
}

func makeNonce(seq uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// Write encrypts p and sends it as a TLS Application Data record.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nonce := makeNonce(c.sendSeq)
	c.sendSeq++

	ciphertext := c.sendGCM.Seal(nil, nonce, p, nil)
	if err := writeTLSRecord(c.raw, recordTypeApplicationData, ciphertext); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read decrypts one TLS record and returns plaintext.
func (c *Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	recType, payload, _, err := readTLSRecord(c.reader)
	if err != nil {
		return 0, err
	}
	if recType != recordTypeApplicationData {
		return 0, fmt.Errorf("unexpected record type: 0x%02x", recType)
	}

	nonce := makeNonce(c.recvSeq)
	c.recvSeq++

	plaintext, err := c.recvGCM.Open(nil, nonce, payload, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = make([]byte, len(plaintext)-n)
		copy(c.readBuf, plaintext[n:])
	}
	return n, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.raw.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.raw.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

// SetDeadline sets the deadline for both reads and writes.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

// HandshakeAddress returns the SNI address used during handshake.
// This is used by Xray's routing layer.
func (c *Conn) HandshakeAddress() string {
	return c.ServerName
}

// --- internal crypto helpers ---

type keys struct {
	authKey []byte // 32 bytes
	c2sKey  []byte // 32 bytes
	s2cKey  []byte // 32 bytes
}

func deriveKeys(psk, clientRandom, serverRandom []byte) (*keys, error) {
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

	return &keys{authKey: authKey, c2sKey: c2s, s2cKey: s2c}, nil
}

func makeAuthPayload(authKey, clientRandom []byte) ([]byte, error) {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, clientRandom[:12], []byte(authPlaintext), nil), nil
}

func verifyAuthPayload(authKey, clientRandom, ciphertext []byte) bool {
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
	return string(plaintext) == authPlaintext
}

func makeConfirmPayload(authKey, serverRandom []byte) ([]byte, error) {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, serverRandom[:12], []byte(vpnConfirm), nil), nil
}

func verifyConfirmPayload(authKey, serverRandom, ciphertext []byte) bool {
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
	return string(plaintext) == vpnConfirm
}
