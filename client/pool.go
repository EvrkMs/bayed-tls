package client

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// Pool manages multiple parallel bayed-tls connections to the same server.
// Streams are distributed round-robin across live connections.
// From the ISP's perspective this looks like a browser with multiple
// tabs open to the same website (normal behavior).
type Pool struct {
	cfg   Config
	size  int
	conns []*poolConn
	mu    sync.RWMutex

	nextID    atomic.Uint32 // global stream ID counter
	nextConn  atomic.Uint32 // round-robin index
	streamMap sync.Map      // streamID → *poolConn (which connection owns this stream)
}

// poolConn wraps a single Client connection.
type poolConn struct {
	client *Client
	index  int
	alive  bool
}

// NewPool creates a connection pool.
func NewPool(cfg Config, size int) *Pool {
	if size < 2 {
		size = 2
	}
	return &Pool{
		cfg:  cfg,
		size: size,
	}
}

// Connect establishes all connections in the pool.
// Connections are opened sequentially with a staggered delay to look natural.
func (p *Pool) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.conns = make([]*poolConn, 0, p.size)
	p.nextID.Store(1)

	var firstErr error
	for i := 0; i < p.size; i++ {
		c := New(p.cfg)
		if err := c.Connect(); err != nil {
			log.Printf("[pool] conn %d/%d failed: %v", i+1, p.size, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pc := &poolConn{client: c, index: i, alive: true}
		p.conns = append(p.conns, pc)
		log.Printf("[pool] conn %d/%d established", i+1, p.size)
	}

	if len(p.conns) == 0 {
		return fmt.Errorf("pool: all %d connections failed, first error: %w", p.size, firstErr)
	}

	// Start read loops for all connections.
	for _, pc := range p.conns {
		go p.readLoop(pc)
	}

	log.Printf("[pool] %d/%d connections ready", len(p.conns), p.size)
	return nil
}

// pick selects the next live connection via round-robin.
func (p *Pool) pick() (*poolConn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	n := len(p.conns)
	if n == 0 {
		return nil, fmt.Errorf("pool: no live connections")
	}

	// Try all connections starting from the round-robin position.
	start := p.nextConn.Add(1) - 1
	for i := 0; i < n; i++ {
		pc := p.conns[(int(start)+i)%n]
		if pc.alive {
			return pc, nil
		}
	}
	return nil, fmt.Errorf("pool: all connections dead")
}

// OpenStream opens a multiplexed stream on the next available connection.
func (p *Pool) OpenStream(addr string) (*PoolStream, error) {
	pc, err := p.pick()
	if err != nil {
		return nil, err
	}

	stream, err := pc.client.OpenStream(addr)
	if err != nil {
		// Mark connection as dead and try another.
		pc.alive = false
		pc2, err2 := p.pick()
		if err2 != nil {
			return nil, fmt.Errorf("pool: all connections failed: %w", err)
		}
		stream, err = pc2.client.OpenStream(addr)
		if err != nil {
			pc2.alive = false
			return nil, err
		}
		pc = pc2
	}

	return &PoolStream{stream: stream, connIdx: pc.index}, nil
}

// readLoop reads frames from a connection and dispatches them.
// This is already handled by Client.readLoop, so this is a no-op watcher.
func (p *Pool) readLoop(pc *poolConn) {
	// Client.readLoop is started in Client.Connect().
	// We just watch for the connection dying (when readLoop exits, the
	// client's vpn field will eventually error on write).
}

// PoolStream wraps a Stream with pool metadata.
type PoolStream struct {
	stream  *Stream
	connIdx int
}

func (ps *PoolStream) Read(p []byte) (int, error)  { return ps.stream.Read(p) }
func (ps *PoolStream) Write(p []byte) (int, error) { return ps.stream.Write(p) }
func (ps *PoolStream) Close() error                { return ps.stream.Close() }

// ListenSOCKS5 starts a SOCKS5 proxy using the pool.
func (p *Pool) ListenSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("[pool-socks5] listening on %s (%d connections)", addr, len(p.conns))

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[pool-socks5] accept: %v", err)
			continue
		}
		go p.handleSOCKS5(conn)
	}
}

func (p *Pool) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// Auth negotiation
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// Request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	ver, cmd := buf[0], buf[1]
	if ver != 0x05 || cmd != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atype := buf[3]
	var target string

	switch atype {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
		port := int(buf[8])<<8 | int(buf[9])
		target = net.JoinHostPort(ip.String(), itoa(port))

	case 0x03: // Domain
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return
		}
		domain := string(buf[5 : 5+dlen])
		port := int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
		target = net.JoinHostPort(domain, itoa(port))

	case 0x04: // IPv6
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		target = net.JoinHostPort(ip.String(), itoa(port))

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := p.OpenStream(target)
	if err != nil {
		log.Printf("[pool-socks5] open stream to %s: %v", target, err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{})
	go func() {
		io.Copy(stream, conn)
		close(done)
	}()
	io.Copy(conn, stream)
	<-done
}
