package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame commands.
const (
	CmdConnect    byte = 0x01 // Client → Server: request TCP connection
	CmdConnectOK  byte = 0x02 // Server → Client: connection established
	CmdConnectErr byte = 0x03 // Server → Client: connection failed
	CmdData       byte = 0x04 // Bidirectional: relay data
	CmdClose      byte = 0x05 // Bidirectional: close stream
)

// MaxFramePayload is the maximum payload size in a single frame.
const MaxFramePayload = 16384 // 16 KB

// Frame is the multiplexed tunnel frame.
//
// Wire format:
//
//	[4-byte stream_id, big-endian]
//	[1-byte cmd]
//	[2-byte payload_length, big-endian]
//	[payload...]
const FrameHeaderSize = 7

type Frame struct {
	StreamID uint32
	Cmd      byte
	Payload  []byte
}

// WriteFrame writes a frame to w as a single write.
func WriteFrame(w io.Writer, f *Frame) error {
	if len(f.Payload) > MaxFramePayload {
		return fmt.Errorf("payload too large: %d > %d", len(f.Payload), MaxFramePayload)
	}

	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.StreamID)
	buf[4] = f.Cmd
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(f.Payload)))
	copy(buf[FrameHeaderSize:], f.Payload)

	_, err := w.Write(buf)
	return err
}

// ReadFrame reads a single frame from r.
func ReadFrame(r io.Reader) (*Frame, error) {
	hdr := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}

	f := &Frame{
		StreamID: binary.BigEndian.Uint32(hdr[0:4]),
		Cmd:      hdr[4],
	}
	payloadLen := binary.BigEndian.Uint16(hdr[5:7])

	if payloadLen > MaxFramePayload {
		return nil, errors.New("frame payload exceeds maximum")
	}

	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}

	return f, nil
}
