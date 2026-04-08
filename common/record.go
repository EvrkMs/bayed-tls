// Package common implements the bayed-tls protocol primitives:
// TLS record I/O, hello parsing, key derivation, authentication,
// encrypted tunnel connection, and stream framing.
//
// These are shared between client and server.
package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TLS record content types.
const (
	RecordTypeChangeCipherSpec byte = 0x14
	RecordTypeAlert            byte = 0x15
	RecordTypeHandshake        byte = 0x16
	RecordTypeApplicationData  byte = 0x17
)

// TLS handshake message types.
const (
	HandshakeTypeClientHello byte = 0x01
	HandshakeTypeServerHello byte = 0x02
)

const (
	RecordHeaderSize = 5
	MaxRecordPayload = 16384 + 256 // 16 KB + encryption overhead
)

// ReadTLSRecord reads one TLS record from r.
// Returns the content type, payload, full raw bytes (header+payload), and error.
func ReadTLSRecord(r io.Reader) (recType byte, payload []byte, raw []byte, err error) {
	hdr := make([]byte, RecordHeaderSize)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, nil, err
	}

	recType = hdr[0]
	length := int(binary.BigEndian.Uint16(hdr[3:5]))

	if length > MaxRecordPayload {
		return 0, nil, nil, fmt.Errorf("TLS record too large: %d bytes", length)
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, nil, err
		}
	}

	raw = make([]byte, RecordHeaderSize+length)
	copy(raw, hdr)
	copy(raw[RecordHeaderSize:], payload)

	return recType, payload, raw, nil
}

// WriteTLSRecord writes a TLS record with the given content type and payload.
func WriteTLSRecord(w io.Writer, recType byte, payload []byte) error {
	hdr := make([]byte, RecordHeaderSize)
	hdr[0] = recType
	hdr[1] = 0x03
	hdr[2] = 0x03 // TLS 1.2 on the wire (standard for TLS 1.3)
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(payload)))

	buf := make([]byte, 0, RecordHeaderSize+len(payload))
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// ParseClientHelloRandom extracts client_random (32 bytes) from a
// Handshake record payload containing a ClientHello message.
func ParseClientHelloRandom(payload []byte) ([]byte, error) {
	if len(payload) < 38 {
		return nil, errors.New("payload too short for ClientHello")
	}
	if payload[0] != HandshakeTypeClientHello {
		return nil, fmt.Errorf("not ClientHello (type=0x%02x)", payload[0])
	}
	random := make([]byte, 32)
	copy(random, payload[6:38])
	return random, nil
}

// ParseServerHelloRandom extracts server_random (32 bytes) from a
// Handshake record payload containing a ServerHello message.
func ParseServerHelloRandom(payload []byte) ([]byte, error) {
	if len(payload) < 38 {
		return nil, errors.New("payload too short for ServerHello")
	}
	if payload[0] != HandshakeTypeServerHello {
		return nil, fmt.Errorf("not ServerHello (type=0x%02x)", payload[0])
	}
	random := make([]byte, 32)
	copy(random, payload[6:38])
	return random, nil
}
