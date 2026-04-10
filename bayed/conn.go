package bayed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
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

	sendNonceBase [12]byte
	recvNonceBase [12]byte

	// Exported fields for upper protocol layers to inspect.
	Verified     bool   // true if client was authenticated
	ServerName   string // SNI used during handshake
}

// newConn creates an encrypted connection from derived keys.
func newConn(raw net.Conn, reader io.Reader, k *keys, isClient bool) (*Conn, error) {
	var sendKey, recvKey, sendNonce, recvNonce []byte
	if isClient {
		sendKey, recvKey = k.c2sKey, k.s2cKey
		sendNonce, recvNonce = k.c2sNonceBase, k.s2cNonceBase
	} else {
		sendKey, recvKey = k.s2cKey, k.c2sKey
		sendNonce, recvNonce = k.s2cNonceBase, k.c2sNonceBase
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

	conn := &Conn{
		raw:     raw,
		reader:  reader,
		sendGCM: sendGCM,
		recvGCM: recvGCM,
	}
	copy(conn.sendNonceBase[:], sendNonce)
	copy(conn.recvNonceBase[:], recvNonce)
	return conn, nil
}

func makeNonce(base [12]byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, base[:])
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBuf[i]
	}
	return nonce
}

// Write encrypts p and sends it as a TLS Application Data record.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nonce := makeNonce(c.sendNonceBase, c.sendSeq)
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

	nonce := makeNonce(c.recvNonceBase, c.recvSeq)
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
	authKey      []byte // 32 bytes
	c2sKey       []byte // 32 bytes
	s2cKey       []byte // 32 bytes
	c2sNonceBase []byte // 12 bytes
	s2cNonceBase []byte // 12 bytes
}

func deriveKeys(psk, clientRandom, serverRandom []byte) (*keys, error) {
	salt := make([]byte, 0, 64)
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	derive := func(info string, size int) ([]byte, error) {
		r := hkdf.New(sha256.New, psk, salt, []byte(info))
		key := make([]byte, size)
		if _, err := io.ReadFull(r, key); err != nil {
			return nil, fmt.Errorf("hkdf(%s): %w", info, err)
		}
		return key, nil
	}

	authKey, err := derive("bayed-auth", 32)
	if err != nil {
		return nil, err
	}
	c2s, err := derive("bayed-c2s", 32)
	if err != nil {
		return nil, err
	}
	s2c, err := derive("bayed-s2c", 32)
	if err != nil {
		return nil, err
	}
	c2sNonce, err := derive("bayed-c2s-nonce", 12)
	if err != nil {
		return nil, err
	}
	s2cNonce, err := derive("bayed-s2c-nonce", 12)
	if err != nil {
		return nil, err
	}

	return &keys{
		authKey:      authKey,
		c2sKey:       c2s,
		s2cKey:       s2c,
		c2sNonceBase: c2sNonce,
		s2cNonceBase: s2cNonce,
	}, nil
}

func makeAuthPayload(authKey, clientRandom []byte) ([]byte, error) {
	// Pad to realistic HTTP request size (406–1605 bytes plaintext)
	// to avoid fingerprinting by fixed payload length.
	padSize, err := cryptoRandIntn(1200)
	if err != nil {
		return nil, fmt.Errorf("rand pad: %w", err)
	}
	plaintext := make([]byte, len(authPlaintext)+400+padSize)
	copy(plaintext, authPlaintext)
	if _, err := rand.Read(plaintext[len(authPlaintext):]); err != nil {
		return nil, fmt.Errorf("rand fill: %w", err)
	}

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, clientRandom[:12], plaintext, nil), nil
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
	if len(plaintext) < len(authPlaintext) {
		return false
	}
	return subtle.ConstantTimeCompare(plaintext[:len(authPlaintext)], []byte(authPlaintext)) == 1
}

func makeConfirmPayload(authKey, serverRandom []byte) ([]byte, error) {
	// Pad to realistic HTTP response size to avoid fingerprinting.
	padSize, err := cryptoRandIntn(1200)
	if err != nil {
		return nil, fmt.Errorf("rand pad: %w", err)
	}
	plaintext := make([]byte, len(vpnConfirm)+400+padSize)
	copy(plaintext, vpnConfirm)
	if _, err := rand.Read(plaintext[len(vpnConfirm):]); err != nil {
		return nil, fmt.Errorf("rand fill: %w", err)
	}

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, serverRandom[:12], plaintext, nil), nil
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
	if len(plaintext) < len(vpnConfirm) {
		return false
	}
	return subtle.ConstantTimeCompare(plaintext[:len(vpnConfirm)], []byte(vpnConfirm)) == 1
}

// cryptoRandIntn returns a cryptographically random int in [0, n).
func cryptoRandIntn(n int) (int, error) {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(r.Int64()), nil
}
