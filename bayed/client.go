package bayed

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	tls "github.com/refraction-networking/utls"
)

// Client performs the client-side bayed-tls handshake on an already-dialed
// TCP connection. It does the uTLS handshake (with Chrome fingerprint),
// authenticates via PSK-derived beacon, and returns an encrypted *Conn.
//
// The returned *Conn implements net.Conn and can be used by the upper protocol
// layer (e.g. VLESS, VMess) for transparent data transfer.
func Client(c net.Conn, config *ClientConfig) (*Conn, error) {
	l := config.logger()

	// Step 1: uTLS handshake
	tlsCfg := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	helloID := resolveFingerprint(config.Fingerprint)
	uconn := tls.UClient(c, tlsCfg, helloID)

	// Optionally inject fake PSK
	if config.FakePSK && shouldInjectFakePSK() {
		if err := uconn.BuildHandshakeState(); err != nil {
			c.Close()
			return nil, fmt.Errorf("build handshake state: %w", err)
		}
		if err := injectFakePSK(uconn); err != nil && config.Show {
			l.Printf("[bayed] fake PSK injection failed (non-fatal): %v", err)
		}
	}

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

	// Step 4: Send auth beacon
	authPayload, err := makeAuthPayload(k.authKey, clientRandom)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("make auth: %w", err)
	}

	// Auth beacon is sent as raw TLS record on the underlying TCP conn,
	// not through the uTLS conn, because we need to bypass the TLS layer.
	rawConn := uconn.NetConn()
	if err := writeTLSRecord(rawConn, recordTypeApplicationData, authPayload); err != nil {
		c.Close()
		return nil, fmt.Errorf("write auth: %w", err)
	}

	if config.Show {
		l.Printf("[bayed] auth beacon sent (%d bytes)", len(authPayload))
	}

	// Step 5: Wait for server confirmation
	tcpBuf := bufio.NewReader(rawConn)

	for i := 0; i < 10; i++ {
		recType, payload, _, err := readTLSRecord(tcpBuf)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("read confirm: %w", err)
		}
		if recType != recordTypeApplicationData {
			continue
		}
		if verifyConfirmPayload(k.authKey, serverRandom, payload) {
			if config.Show {
				l.Printf("[bayed] server confirmed!")
			}

			// Step 6: Encrypted tunnel
			conn, err := newConn(rawConn, tcpBuf, k.c2sKey, k.s2cKey, true)
			if err != nil {
				c.Close()
				return nil, fmt.Errorf("create conn: %w", err)
			}
			conn.Verified = true
			conn.ServerName = config.ServerName
			return conn, nil
		}
	}

	c.Close()
	return nil, fmt.Errorf("server did not confirm within 10 records")
}

// --- fingerprint helpers ---

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

// --- fake PSK helpers ---

func shouldInjectFakePSK() bool {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false
	}
	return n.Int64() == 1
}

func injectFakePSK(uconn *tls.UConn) error {
	identity := make([]byte, 224) // Chrome-like session ticket size
	if _, err := rand.Read(identity); err != nil {
		return err
	}

	binder := make([]byte, 32) // SHA-256
	if _, err := rand.Read(binder); err != nil {
		return err
	}

	ageN, err := rand.Int(rand.Reader, big.NewInt(600000))
	if err != nil {
		return err
	}

	cache := tls.NewLRUClientSessionCache(1)
	uconn.SetSessionCache(cache)

	return uconn.SetPskExtension(&tls.FakePreSharedKeyExtension{
		Identities: []tls.PskIdentity{
			{
				Label:               identity,
				ObfuscatedTicketAge: uint32(ageN.Int64()),
			},
		},
		Binders: [][]byte{binder},
	})
}
