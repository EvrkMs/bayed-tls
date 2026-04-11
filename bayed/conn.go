package bayed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// debugSplice enables splice-phase debug logging to stderr.
	debugSplice = false

	// authTagSize is the size of the HMAC-SHA256 auth tag prepended to the
	// first client->server record (zero round-trip auth).
	authTagSize = 32

	// paddingRecords is the number of initial records (both directions) that
	// get random padding to defeat TLS-in-TLS size fingerprinting.
	paddingRecords = 8

	// Padding is adaptive: rand(0, max(minPaddingFloor, dataLen * paddingFraction)).
	// Small records stay small (like real HTTPS), large ones get more noise.
	minPaddingFloor = 16  // at least 16 bytes of padding
	paddingFraction = 0.3 // up to ~30% of data size
	maxPaddingCap   = 128 // hard cap to avoid bloat

	// maxPlaintext is the maximum data size per TLS record. Larger Write
	// calls are automatically split into multiple records. This prevents
	// generating oversized TLS records that would be rejected by the peer
	// or be anomalous to DPI. Matches standard TLS record limit.
	maxPlaintext = 16384

	// maxSequence is the safety limit for AES-GCM sequence numbers.
	// Prevents theoretical nonce reuse. No single TCP connection
	// will ever send 2^48 (≈281 trillion) records.
	maxSequence uint64 = 1 << 48
)

// splicePhase tracks whether the connection should switch to direct
// passthrough after the padding phase (Vision-style splice).
type splicePhase int

const (
	// spliceDetecting: during padding phase, inspecting data for inner TLS.
	spliceDetecting splicePhase = iota
	// spliceDirect: inner TLS detected → after padding, pass data through
	// without bayed encryption (the inner TLS already encrypts it).
	spliceDirect
	// spliceEncrypt: no inner TLS → keep bayed encryption after padding.
	spliceEncrypt
)

// Conn is an encrypted bayed-tls v2 connection that implements net.Conn.
// After a successful handshake (via Server() or Client()), the returned
// *Conn can be used transparently by any protocol layer above.
//
// v2 features:
//   - Zero round-trip auth: auth tag is embedded in the first data record
//   - Adaptive padding: first N records get random padding to break
//     TLS-in-TLS size fingerprinting
//   - Vision-style splice: if inner traffic is TLS, padding phase
//     hides handshake sizes, then direct passthrough for data phase
//   - No separate auth/confirm exchange
type Conn struct {
	raw     net.Conn
	reader  io.Reader
	sendGCM cipher.AEAD
	recvGCM cipher.AEAD
	sendSeq uint64
	recvSeq uint64
	mu      sync.Mutex // protects writes

	readBuf []byte // buffered plaintext from partial reads

	sendNonceBase [12]byte
	recvNonceBase [12]byte

	// Padding state: counts records to decide when to stop padding.
	sendCount int
	recvCount int

	// Splice state: each direction is detected independently.
	// Both sides see the same data, so they arrive at the same decision.
	sendSplice splicePhase
	recvSplice splicePhase

	// pendingAuthTag is set by the client constructor. On the first Write,
	// the tag is prepended to the caller's data (zero round-trip auth).
	pendingAuthTag []byte

	// closed is set by Close to prevent Write-after-Close panics.
	closed bool

	// Exported fields for upper protocol layers to inspect.
	Verified   bool   // true if client was authenticated
	ServerName string // SNI used during handshake
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
//
// Phase 1 (first paddingRecords): encrypted + adaptive padding.
//   During this phase, data is inspected for inner TLS records.
//
// Phase 2 (after paddingRecords):
//   - If inner TLS was detected (spliceDirect): data is written as-is
//     inside a TLS AppData record (no bayed encryption). The inner TLS
//     already provides encryption, and record sizes now match real TLS.
//   - If no inner TLS (spliceEncrypt): data is encrypted with AES-GCM
//     (no padding).
//
// Wire format for padded records:
//
//	[AES-GCM ciphertext of: real_data || random_padding || 2-byte real_data_length]
//
// Wire format for encrypted (no padding):
//
//	[AES-GCM ciphertext of: real_data]
//
// Wire format for direct (splice):
//
//	[raw bytes — no outer TLS framing, inner TLS records pass as-is]
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	// On the first Write, prepend the auth tag (zero round-trip auth).
	data := p
	if c.pendingAuthTag != nil {
		data = make([]byte, len(c.pendingAuthTag)+len(p))
		copy(data, c.pendingAuthTag)
		copy(data[len(c.pendingAuthTag):], p)
		c.pendingAuthTag = nil
	}

	// Fast path: Phase 2a splice — raw passthrough, no TLS framing.
	// Inner TLS records flow directly to the wire, producing record
	// sizes identical to a direct connection (no +5B overhead).
	if c.sendCount >= paddingRecords && c.sendSplice == spliceDirect {
		if debugSplice {
			fmt.Fprintf(os.Stderr, "[splice-W] raw %dB\n", len(data))
		}
		_, err := c.raw.Write(data)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}

	// Split oversized payloads into standard TLS-sized records to
	// avoid generating anomalous record sizes visible to DPI.
	for len(data) > 0 {
		n := len(data)
		if n > maxPlaintext {
			n = maxPlaintext
		}
		if err := c.writeRecord(data[:n]); err != nil {
			return 0, err
		}
		data = data[n:]
	}
	// Increment sendCount per Write() call, not per TLS record.
	// This ensures the entire Write stays in Phase 1 even when the
	// chunking loop splits data > maxPlaintext into multiple records.
	// Without this, a large Write could straddle Phase 1 / Phase 2,
	// causing raw splice to start mid-inner-TLS-record (DPI-visible).
	if c.sendCount < paddingRecords {
		c.sendCount++
	}
	return len(p), nil
}

// writeRecord sends one data chunk as a single TLS Application Data record.
// Must be called with c.mu held.
func (c *Conn) writeRecord(data []byte) error {
	if c.sendCount < paddingRecords {
		// --- Phase 1: encrypted + padded ---
		if c.sendSplice == spliceDetecting && isTLSLike(data) {
			c.sendSplice = spliceDirect
			if debugSplice {
				fmt.Fprintf(os.Stderr, "[splice] send TLS detected at count=%d len=%d\n", c.sendCount, len(data))
			}
		}
		if debugSplice && c.sendSplice == spliceDetecting {
			fmt.Fprintf(os.Stderr, "[splice] send count=%d len=%d first5=%x splice=detecting\n", c.sendCount, len(data), data[:min(5, len(data))])
		}
		maxPad := int(float64(len(data)) * paddingFraction)
		if maxPad < minPaddingFloor {
			maxPad = minPaddingFloor
		}
		if maxPad > maxPaddingCap {
			maxPad = maxPaddingCap
		}
		padSize := cryptoRandIntnUnsafe(maxPad + 1)
		plaintext := make([]byte, len(data)+padSize+2)
		copy(plaintext, data)
		_, _ = rand.Read(plaintext[len(data) : len(data)+padSize])
		binary.BigEndian.PutUint16(plaintext[len(data)+padSize:], uint16(len(data)))
		// sendCount is now incremented in Write() after the loop,
		// not here. See the comment there for rationale.

		if c.sendSeq >= maxSequence {
			return errSequenceOverflow
		}
		nonce := makeNonce(c.sendNonceBase, c.sendSeq)
		c.sendSeq++
		ciphertext := c.sendGCM.Seal(nil, nonce, plaintext, nil)
		return writeTLSRecord(c.raw, recordTypeApplicationData, ciphertext)
	}

	if c.sendSplice == spliceDirect {
		// --- Phase 2a: raw splice — write bytes directly without outer
		// TLS record framing. Reached when sendCount >= paddingRecords
		// and the fast path in Write() didn't fire (Phase 2b fallback
		// during the same Write that completed Phase 1 is impossible now
		// that sendCount increments per-Write, but kept for safety).
		_, err := c.raw.Write(data)
		return err
	}

	// --- Phase 2b: encrypted, no padding ---
	if c.sendSplice == spliceDetecting {
		c.sendSplice = spliceEncrypt
	}
	if c.sendSeq >= maxSequence {
		return errSequenceOverflow
	}
	nonce := makeNonce(c.sendNonceBase, c.sendSeq)
	c.sendSeq++
	ciphertext := c.sendGCM.Seal(nil, nonce, data, nil)
	return writeTLSRecord(c.raw, recordTypeApplicationData, ciphertext)
}

// Read decrypts one TLS record and returns plaintext.
//
// Phase 1 (padded records): decrypt + strip padding. Also detects inner TLS.
// Phase 2a (spliceDirect): raw read — payload is plaintext inner TLS data.
// Phase 2b (spliceEncrypt): decrypt without padding.
func (c *Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Phase 2a splice: raw passthrough — read directly without outer TLS
	// record deframing. Inner TLS handles its own framing/reassembly.
	if c.recvCount >= paddingRecords && c.recvSplice == spliceDirect {
		n, err := c.reader.Read(p)
		if debugSplice && n > 0 {
			fmt.Fprintf(os.Stderr, "[splice-R] raw %dB\n", n)
		}
		return n, err
	}

	recType, payload, _, err := readTLSRecord(c.reader)
	if err != nil {
		return 0, err
	}
	if recType != recordTypeApplicationData {
		return 0, fmt.Errorf("unexpected record type: 0x%02x", recType)
	}

	var plaintext []byte

	if c.recvCount < paddingRecords {
		// --- Phase 1: decrypt + depad ---
		if c.recvSeq >= maxSequence {
			return 0, errSequenceOverflow
		}
		nonce := makeNonce(c.recvNonceBase, c.recvSeq)
		c.recvSeq++

		plaintext, err = c.recvGCM.Open(nil, nonce, payload, nil)
		if err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}

		c.recvCount++
		if len(plaintext) < 2 {
			return 0, fmt.Errorf("padded record too short: %d", len(plaintext))
		}
		realLen := int(binary.BigEndian.Uint16(plaintext[len(plaintext)-2:]))
		if realLen > len(plaintext)-2 {
			return 0, fmt.Errorf("invalid padding length: real=%d total=%d", realLen, len(plaintext))
		}
		plaintext = plaintext[:realLen]

		// Detect inner TLS for splice decision.
		if c.recvSplice == spliceDetecting && isTLSLike(plaintext) {
			c.recvSplice = spliceDirect
			if debugSplice {
				fmt.Fprintf(os.Stderr, "[splice] recv TLS detected at count=%d len=%d\n", c.recvCount, len(plaintext))
			}
		}
		if debugSplice && c.recvSplice == spliceDetecting {
			fmt.Fprintf(os.Stderr, "[splice] recv count=%d len=%d first5=%x splice=detecting\n", c.recvCount, len(plaintext), plaintext[:min(5, len(plaintext))])
		}
	} else if c.recvSplice == spliceDirect {
		// --- Phase 2a: should not reach here (raw read fast path above) ---
		plaintext = payload
	} else {
		// --- Phase 2b: encrypted, no padding (non-TLS inner traffic) ---
		if c.recvSplice == spliceDetecting {
			c.recvSplice = spliceEncrypt
		}
		if c.recvSeq >= maxSequence {
			return 0, errSequenceOverflow
		}
		nonce := makeNonce(c.recvNonceBase, c.recvSeq)
		c.recvSeq++
		plaintext, err = c.recvGCM.Open(nil, nonce, payload, nil)
		if err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = make([]byte, len(plaintext)-n)
		copy(c.readBuf, plaintext[n:])
	}
	return n, nil
}

// Close closes the underlying connection and zeros key material.
func (c *Conn) Close() error {
	c.mu.Lock()
	c.closed = true
	// Best-effort: zero nonce material from memory. The AES key inside
	// cipher.AEAD cannot be zeroed from Go (runtime limitation), but we
	// clear what we can to reduce the window for memory forensics.
	for i := range c.sendNonceBase {
		c.sendNonceBase[i] = 0
	}
	for i := range c.recvNonceBase {
		c.recvNonceBase[i] = 0
	}
	c.pendingAuthTag = nil
	c.readBuf = nil
	c.mu.Unlock()
	// raw.Close() outside the lock so it doesn't deadlock with a
	// concurrent Read blocked on the underlying connection.
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
	authKey      []byte // 32 bytes - used for HMAC auth tag
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

// makeAuthTag produces a 32-byte HMAC-SHA256 tag for zero-round-trip auth.
// The tag is prepended to the first client->server data record.
// Tag = HMAC-SHA256(authKey, client_random || server_random || "bayed-v2")
func makeAuthTag(authKey, clientRandom, serverRandom []byte) []byte {
	h := hmac.New(sha256.New, authKey)
	h.Write(clientRandom)
	h.Write(serverRandom)
	h.Write([]byte("bayed-v2"))
	return h.Sum(nil)
}

// verifyAuthTag checks the 32-byte HMAC tag (constant-time).
func verifyAuthTag(authKey, clientRandom, serverRandom, tag []byte) bool {
	expected := makeAuthTag(authKey, clientRandom, serverRandom)
	return hmac.Equal(expected, tag)
}

// zero overwrites all key material with zeros. Called after keys have been
// copied into cipher.AEAD / nonce arrays to reduce the exposure window.
func (k *keys) zero() {
	for i := range k.authKey {
		k.authKey[i] = 0
	}
	for i := range k.c2sKey {
		k.c2sKey[i] = 0
	}
	for i := range k.s2cKey {
		k.s2cKey[i] = 0
	}
	for i := range k.c2sNonceBase {
		k.c2sNonceBase[i] = 0
	}
	for i := range k.s2cNonceBase {
		k.s2cNonceBase[i] = 0
	}
}

// isTLSLike checks if data starts with what looks like a TLS record header.
// Used to detect inner TLS traffic for Vision-style splice.
//
// The check is deliberately strict:
//   - Content type must be a valid TLS type
//   - Version bytes must be TLS 1.0–1.3
//   - Claimed record length must be plausible AND fit within the data buffer
//
// The length cross-check (length+5 ≤ len(data)) is the key defense against
// false positives from random binary data. Without it, any 5-byte sequence
// matching the header pattern would trigger splice → unencrypted passthrough.
func isTLSLike(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// Valid TLS content types: Handshake (0x16), ApplicationData (0x17),
	// ChangeCipherSpec (0x14), Alert (0x15)
	switch data[0] {
	case 0x14, 0x15, 0x16, 0x17:
		// ok
	default:
		return false
	}
	// TLS version: 0x0301 (1.0), 0x0302 (1.1), 0x0303 (1.2/1.3)
	if data[1] != 0x03 || data[2] > 0x03 {
		return false
	}
	// Record length: 1..16640 (16384 + 256 overhead).
	// Cross-check: the claimed TLS record must fit in the available data.
	// This prevents false positives from random data that coincidentally
	// has valid-looking header bytes but an inconsistent length field.
	length := int(binary.BigEndian.Uint16(data[3:5]))
	return length > 0 && length <= maxRecordPayload && length+recordHeaderSize <= len(data)
}

// cryptoRandIntn returns a cryptographically random int in [0, n).
func cryptoRandIntn(n int) (int, error) {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(r.Int64()), nil
}

// cryptoRandIntnUnsafe is like cryptoRandIntn but panics on error.
// Used only for non-security-critical padding sizes.
func cryptoRandIntnUnsafe(n int) int {
	v, err := cryptoRandIntn(n)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return v
}
