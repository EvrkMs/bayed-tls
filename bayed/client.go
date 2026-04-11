package bayed

import (
	"bufio"
	"fmt"
	"net"

	tls "github.com/refraction-networking/utls"
)

// Client performs the client-side bayed-tls v2 handshake on an already-dialed
// TCP connection. It does the uTLS handshake (with the selected fingerprint),
// derives keys from PSK + randoms, and returns an encrypted *Conn.
//
// v2: Zero round-trip auth. The auth tag is embedded in the first data record
// sent by the upper protocol layer (via Write). No separate auth beacon or
// server confirmation is exchanged.
//
// The returned *Conn implements net.Conn and can be used by the upper protocol
// layer (e.g. VLESS, VMess) for transparent data transfer.
func Client(c net.Conn, config *ClientConfig) (*Conn, error) {
	l := config.logger()

	// Wrap conn in bufio before uTLS handshake so that any bytes read
	// ahead by the TCP stack during handshake remain accessible after.
	tcpBuf := bufio.NewReaderSize(c, 16384)
	wrapped := &readerConn{Conn: c, r: tcpBuf}

	// Step 1: uTLS handshake
	tlsCfg := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	helloID := resolveFingerprint(config.Fingerprint)
	uconn := tls.UClient(wrapped, tlsCfg, helloID)

	if err := uconn.Handshake(); err != nil {
		c.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	if config.Show {
		l.Printf("[bayed] TLS handshake OK (version=0x%04x, cipher=0x%04x)",
			uconn.ConnectionState().Version,
			uconn.ConnectionState().CipherSuite)
	}

	// Step 2: Extract randoms
	clientRandom := uconn.HandshakeState.Hello.Random
	if len(clientRandom) != 32 {
		c.Close()
		return nil, fmt.Errorf("client_random wrong length: %d", len(clientRandom))
	}
	serverRandom := uconn.HandshakeState.ServerHello.Random
	if len(serverRandom) != 32 {
		c.Close()
		return nil, fmt.Errorf("server_random wrong length: %d", len(serverRandom))
	}

	// Step 3: Derive keys
	k, err := deriveKeys(config.PSK, clientRandom, serverRandom)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("derive keys: %w", err)
	}
	defer k.zero() // zero key material on all exit paths

	// Step 4: Compute auth tag for zero-RT authentication.
	// The tag will be prepended to the first Write by the upper layer.
	authTag := makeAuthTag(k.authKey, clientRandom, serverRandom)

	// Step 5: Build encrypted conn.
	// We use the raw connection (bypassing uTLS) for bayed data frames,
	// and the tcpBuf reader to consume any bytes buffered during handshake.
	rawConn := uconn.NetConn()

	conn, err := newConn(rawConn, tcpBuf, k, true)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("create conn: %w", err)
	}
	conn.pendingAuthTag = authTag
	conn.Verified = true
	conn.ServerName = config.ServerName

	if config.Show {
		l.Printf("[bayed] v2 client ready (auth tag will be embedded in first write)")
	}

	return conn, nil
}

// --- fingerprint helpers ---

// readerConn wraps a net.Conn so that Read() goes through a bufio.Reader.
// This preserves any bytes buffered during the uTLS handshake that would
// otherwise be lost when switching to raw conn I/O.
type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func resolveFingerprint(name string) tls.ClientHelloID {
	switch name {
	case "chrome", "":
		return tls.HelloChrome_Auto
	case "chrome-pq":
		return tls.HelloChrome_120_PQ
	case "chrome-131":
		return tls.HelloChrome_131
	case "chrome-133":
		return tls.HelloChrome_133
	case "firefox":
		return tls.HelloFirefox_Auto
	case "safari":
		return tls.HelloSafari_Auto
	case "ios":
		return tls.HelloIOS_Auto
	case "edge":
		return tls.HelloEdge_Auto
	case "random":
		return tls.HelloRandomized
	case "go":
		return tls.HelloGolang
	default:
		return tls.HelloChrome_Auto
	}
}
