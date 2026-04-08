package server

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/EvrkMs/bayed-tls/common"
)

// Tunnel handles multiplexed streams over an encrypted connection.
type Tunnel struct {
	conn    io.ReadWriter
	streams sync.Map // streamID → net.Conn
}

// NewTunnel creates a new tunnel multiplexer.
func NewTunnel(conn io.ReadWriter) *Tunnel {
	return &Tunnel{conn: conn}
}

// Serve reads frames and dispatches them. Blocks until the connection closes.
func (t *Tunnel) Serve() {
	for {
		f, err := common.ReadFrame(t.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[tunnel] read frame: %v", err)
			}
			return
		}

		switch f.Cmd {
		case common.CmdConnect:
			t.handleConnect(f)
		case common.CmdData:
			t.handleData(f)
		case common.CmdClose:
			t.handleClose(f)
		default:
			log.Printf("[tunnel] unknown cmd 0x%02x stream=%d", f.Cmd, f.StreamID)
		}
	}
}

func (t *Tunnel) handleConnect(f *common.Frame) {
	addr := string(f.Payload)
	log.Printf("[tunnel] CONNECT stream=%d → %s", f.StreamID, addr)

	target, err := net.DialTimeout("tcp", addr, 10e9)
	if err != nil {
		log.Printf("[tunnel] dial %s: %v", addr, err)
		_ = common.WriteFrame(t.conn, &common.Frame{
			StreamID: f.StreamID,
			Cmd:      common.CmdConnectErr,
		})
		return
	}

	t.streams.Store(f.StreamID, target)

	_ = common.WriteFrame(t.conn, &common.Frame{
		StreamID: f.StreamID,
		Cmd:      common.CmdConnectOK,
	})

	go func() {
		defer target.Close()
		defer t.streams.Delete(f.StreamID)

		buf := make([]byte, 16*1024)
		for {
			n, err := target.Read(buf)
			if n > 0 {
				werr := common.WriteFrame(t.conn, &common.Frame{
					StreamID: f.StreamID,
					Cmd:      common.CmdData,
					Payload:  buf[:n],
				})
				if werr != nil {
					return
				}
			}
			if err != nil {
				break
			}
		}

		_ = common.WriteFrame(t.conn, &common.Frame{
			StreamID: f.StreamID,
			Cmd:      common.CmdClose,
		})
	}()
}

func (t *Tunnel) handleData(f *common.Frame) {
	v, ok := t.streams.Load(f.StreamID)
	if !ok {
		return
	}
	conn := v.(net.Conn)
	if _, err := conn.Write(f.Payload); err != nil {
		conn.Close()
		t.streams.Delete(f.StreamID)
	}
}

func (t *Tunnel) handleClose(f *common.Frame) {
	v, ok := t.streams.Load(f.StreamID)
	if !ok {
		return
	}
	v.(net.Conn).Close()
	t.streams.Delete(f.StreamID)
}
