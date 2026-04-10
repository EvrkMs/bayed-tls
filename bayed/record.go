package bayed

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TLS record content types.
const (
	recordTypeChangeCipherSpec byte = 0x14
	recordTypeAlert            byte = 0x15
	recordTypeHandshake        byte = 0x16
	recordTypeApplicationData  byte = 0x17
)

// TLS handshake message types.
const (
	handshakeTypeClientHello byte = 0x01
	handshakeTypeServerHello byte = 0x02
)

const (
	recordHeaderSize = 5
	maxRecordPayload = 16384 + 256
)

func readTLSRecord(r io.Reader) (recType byte, payload []byte, raw []byte, err error) {
	hdr := make([]byte, recordHeaderSize)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, nil, err
	}

	recType = hdr[0]
	length := int(binary.BigEndian.Uint16(hdr[3:5]))

	if length > maxRecordPayload {
		return 0, nil, nil, fmt.Errorf("TLS record too large: %d bytes", length)
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, nil, err
		}
	}

	raw = make([]byte, recordHeaderSize+length)
	copy(raw, hdr)
	copy(raw[recordHeaderSize:], payload)

	return recType, payload, raw, nil
}

func writeTLSRecord(w io.Writer, recType byte, payload []byte) error {
	hdr := make([]byte, recordHeaderSize)
	hdr[0] = recType
	hdr[1] = 0x03
	hdr[2] = 0x03 // TLS 1.2 on the wire (standard for TLS 1.3)
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(payload)))

	buf := make([]byte, 0, recordHeaderSize+len(payload))
	buf = append(buf, hdr...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

func parseClientHelloRandom(payload []byte) ([]byte, error) {
	if len(payload) < 38 {
		return nil, errors.New("payload too short for ClientHello")
	}
	if payload[0] != handshakeTypeClientHello {
		return nil, fmt.Errorf("not ClientHello (type=0x%02x)", payload[0])
	}
	random := make([]byte, 32)
	copy(random, payload[6:38])
	return random, nil
}

// parseClientHelloSNI extracts the SNI (server_name) from a ClientHello payload.
// Returns "" if SNI is not present or cannot be parsed.
func parseClientHelloSNI(payload []byte) string {
	// payload[0] = handshake type (1 byte)
	// payload[1:4] = length (3 bytes)
	// payload[4:6] = client version (2 bytes)
	// payload[6:38] = random (32 bytes)
	// payload[38] = session_id length
	if len(payload) < 39 {
		return ""
	}
	if payload[0] != handshakeTypeClientHello {
		return ""
	}
	off := 38
	// Skip session ID
	sidLen := int(payload[off])
	off += 1 + sidLen
	if off+2 > len(payload) {
		return ""
	}
	// Skip cipher suites
	csLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2 + csLen
	if off+1 > len(payload) {
		return ""
	}
	// Skip compression methods
	cmLen := int(payload[off])
	off += 1 + cmLen
	if off+2 > len(payload) {
		return ""
	}
	// Extensions length
	extLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	extEnd := off + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		off += 4
		if off+extDataLen > extEnd {
			break
		}
		if extType == 0x0000 { // server_name extension
			// SNI list: 2 bytes total length, then entries
			data := payload[off : off+extDataLen]
			if len(data) < 5 {
				break
			}
			// listLen := int(binary.BigEndian.Uint16(data[0:2]))
			nameType := data[2]
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if nameType == 0 && 5+nameLen <= len(data) {
				return string(data[5 : 5+nameLen])
			}
			break
		}
		off += extDataLen
	}
	return ""
}

func parseServerHelloRandom(payload []byte) ([]byte, error) {
	if len(payload) < 38 {
		return nil, errors.New("payload too short for ServerHello")
	}
	if payload[0] != handshakeTypeServerHello {
		return nil, fmt.Errorf("not ServerHello (type=0x%02x)", payload[0])
	}
	random := make([]byte, 32)
	copy(random, payload[6:38])
	return random, nil
}
