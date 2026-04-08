package common

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// Conn is an encrypted bidirectional connection that looks like
// TLS Application Data on the wire. Each Write produces one TLS record,
// each Read consumes one TLS record.
type Conn struct {
	raw     net.Conn
	reader  io.Reader
	sendGCM cipher.AEAD
	recvGCM cipher.AEAD
	sendSeq uint64
	recvSeq uint64
	mu      sync.Mutex // protects writes
	readBuf []byte     // buffered plaintext from partial reads
}

// NewConn creates an encrypted bayed-tls connection.
// isClient determines key assignment:
//
//	client: send=c2sKey, recv=s2cKey
//	server: send=s2cKey, recv=c2sKey
func NewConn(raw net.Conn, reader io.Reader, c2sKey, s2cKey []byte, isClient bool) (*Conn, error) {
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
	if err := WriteTLSRecord(c.raw, RecordTypeApplicationData, ciphertext); err != nil {
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

	recType, payload, _, err := ReadTLSRecord(c.reader)
	if err != nil {
		return 0, err
	}
	if recType != RecordTypeApplicationData {
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
