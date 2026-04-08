// Package client implements the bayed-tls client-side library.
//
// Usage:
//
//	c := client.New(client.Config{
//	    ServerAddr:  "server:443",
//	    SNI:         "google.com",
//	    PSK:         []byte("secret"),
//	    Fingerprint: "chrome-pq",
//	})
//
//	if err := c.Connect(); err != nil { ... }
//
//	// Open a stream through the tunnel:
//	stream, err := c.OpenStream("httpbin.org:80")
//	stream.Write([]byte("GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"))
//
//	// Or use the built-in SOCKS5 proxy:
//	c.ListenSOCKS5("127.0.0.1:1080")
package client

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/refraction-networking/utls"

	"github.com/EvrkMs/bayed-tls/common"
)

// Config configures a bayed-tls client.
type Config struct {
	ServerAddr  string // proxy server address (e.g. "1.2.3.4:443")
	SNI         string // TLS SNI (e.g. "google.com")
	PSK         []byte // pre-shared key
	Insecure    bool   // skip certificate verification (testing only)
	Fingerprint string // uTLS fingerprint: chrome-pq, chrome, firefox, safari, ios, edge, random, go
	FakePSK     bool   // inject fake pre_shared_key extension (~50% of connections)
	PoolSize    int    // number of parallel TCP connections (0 or 1 = single conn)
}

// Client manages a bayed-tls connection.
type Client struct {
	cfg Config
	vpn io.ReadWriter

	mu      sync.Mutex
	streams sync.Map // streamID → chan *common.Frame
	nextID  atomic.Uint32
	writeMu sync.Mutex
}

// New creates a new client.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// Connect establishes the encrypted tunnel.
func (c *Client) Connect() error {
	// ── Step 1: Raw TCP ──
	tcpConn, err := net.DialTimeout("tcp", c.cfg.ServerAddr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("tcp dial: %w", err)
	}

	// ── Step 2: uTLS handshake ──
	tlsCfg := &tls.Config{
		ServerName:         c.cfg.SNI,
		InsecureSkipVerify: c.cfg.Insecure,
	}

	helloID := ResolveFingerprint(c.cfg.Fingerprint)
	uconn := tls.UClient(tcpConn, tlsCfg, helloID)

	// Optionally inject fake PSK (~50% of connections) to look like session resumption.
	if c.cfg.FakePSK && shouldUseFakePSK() {
		if err := uconn.BuildHandshakeState(); err != nil {
			tcpConn.Close()
			return fmt.Errorf("build handshake state: %w", err)
		}
		if err := applyFakePSK(uconn, defaultFakePSK); err != nil {
			log.Printf("[bayed-client] fake PSK injection failed (non-fatal): %v", err)
		}
	}

	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return fmt.Errorf("tls handshake: %w", err)
	}

	log.Printf("[bayed-client] TLS handshake OK (version=0x%04x, cipher=0x%04x)",
		uconn.ConnectionState().Version,
		uconn.ConnectionState().CipherSuite)

	// ── Step 3: Extract randoms ──
	clientRandom := uconn.HandshakeState.Hello.Random
	if len(clientRandom) != 32 {
		tcpConn.Close()
		return fmt.Errorf("client_random wrong length: %d", len(clientRandom))
	}
	serverRandom := uconn.HandshakeState.ServerHello.Random
	if len(serverRandom) != 32 {
		tcpConn.Close()
		return fmt.Errorf("server_random wrong length: %d", len(serverRandom))
	}

	// ── Step 4: Derive keys ──
	keys, err := common.DeriveKeys(c.cfg.PSK, clientRandom, serverRandom)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("derive keys: %w", err)
	}

	// ── Step 5: Auth beacon ──
	authPayload, err := common.MakeAuthPayload(keys.AuthKey, clientRandom)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("make auth: %w", err)
	}

	if err := common.WriteTLSRecord(tcpConn, common.RecordTypeApplicationData, authPayload); err != nil {
		tcpConn.Close()
		return fmt.Errorf("write auth: %w", err)
	}
	log.Printf("[bayed-client] auth beacon sent (%d bytes)", len(authPayload))

	// ── Step 6: Wait for server confirmation ──
	tcpBuf := bufio.NewReader(tcpConn)

	for i := 0; i < 10; i++ {
		recType, payload, _, err := common.ReadTLSRecord(tcpBuf)
		if err != nil {
			tcpConn.Close()
			return fmt.Errorf("read confirm: %w", err)
		}
		if recType != common.RecordTypeApplicationData {
			continue
		}
		if common.VerifyConfirmPayload(keys.AuthKey, serverRandom, payload) {
			log.Printf("[bayed-client] server confirmed!")
			break
		}
		log.Printf("[bayed-client] skipping non-VPN record (%d bytes)", len(payload))
	}

	// ── Step 7: Encrypted tunnel ──
	conn, err := common.NewConn(tcpConn, tcpBuf, keys.C2SKey, keys.S2CKey, true)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("create conn: %w", err)
	}

	c.vpn = conn
	c.nextID.Store(1)

	go c.readLoop()

	log.Printf("[bayed-client] tunnel established to %s (SNI=%s)", c.cfg.ServerAddr, c.cfg.SNI)
	return nil
}

// OpenStream opens a multiplexed stream (TCP CONNECT through the tunnel).
func (c *Client) OpenStream(addr string) (*Stream, error) {
	id := c.nextID.Add(1) - 1

	ch := make(chan *common.Frame, 64)
	c.streams.Store(id, ch)

	c.writeMu.Lock()
	err := common.WriteFrame(c.vpn, &common.Frame{
		StreamID: id,
		Cmd:      common.CmdConnect,
		Payload:  []byte(addr),
	})
	c.writeMu.Unlock()

	if err != nil {
		c.streams.Delete(id)
		return nil, err
	}

	f, ok := <-ch
	if !ok {
		c.streams.Delete(id)
		return nil, fmt.Errorf("stream closed before connect response")
	}
	if f.Cmd == common.CmdConnectErr {
		c.streams.Delete(id)
		return nil, fmt.Errorf("server refused: %s", addr)
	}
	if f.Cmd != common.CmdConnectOK {
		c.streams.Delete(id)
		return nil, fmt.Errorf("unexpected response: 0x%02x", f.Cmd)
	}

	return &Stream{id: id, client: c, ch: ch}, nil
}

func (c *Client) readLoop() {
	for {
		f, err := common.ReadFrame(c.vpn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[bayed-client] read: %v", err)
			}
			return
		}

		v, ok := c.streams.Load(f.StreamID)
		if !ok {
			continue
		}
		ch := v.(chan *common.Frame)

		select {
		case ch <- f:
		default:
			log.Printf("[bayed-client] stream %d: channel full, dropping", f.StreamID)
		}
	}
}

// Stream represents a single TCP connection through the tunnel.
type Stream struct {
	id     uint32
	client *Client
	ch     chan *common.Frame
	buf    []byte
	closed bool
}

func (s *Stream) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	if s.closed {
		return 0, io.EOF
	}

	f, ok := <-s.ch
	if !ok {
		s.closed = true
		return 0, io.EOF
	}

	switch f.Cmd {
	case common.CmdData:
		n := copy(p, f.Payload)
		if n < len(f.Payload) {
			s.buf = f.Payload[n:]
		}
		return n, nil
	case common.CmdClose:
		s.closed = true
		return 0, io.EOF
	default:
		return 0, fmt.Errorf("unexpected cmd: 0x%02x", f.Cmd)
	}
}

func (s *Stream) Write(p []byte) (int, error) {
	s.client.writeMu.Lock()
	defer s.client.writeMu.Unlock()

	err := common.WriteFrame(s.client.vpn, &common.Frame{
		StreamID: s.id,
		Cmd:      common.CmdData,
		Payload:  p,
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *Stream) Close() error {
	s.client.writeMu.Lock()
	defer s.client.writeMu.Unlock()

	s.client.streams.Delete(s.id)
	return common.WriteFrame(s.client.vpn, &common.Frame{
		StreamID: s.id,
		Cmd:      common.CmdClose,
	})
}
