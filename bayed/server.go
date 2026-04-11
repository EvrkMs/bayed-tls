package bayed

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// Server performs the server-side bayed-tls v2 handshake on an already-accepted
// TCP connection. It reads the ClientHello, proxies the TLS handshake to the
// upstream, detects the zero-RT auth tag in the first data record, and returns
// an encrypted *Conn.
//
// v2 changes from v1:
//   - Zero round-trip: no auth beacon + confirm exchange. The auth tag is
//     embedded in the first encrypted data record from the client.
//   - The server tries to decrypt each ApplicationData record from the client
//     with bayed keys (seq=0). If decryption succeeds and the first 32 bytes
//     match the expected HMAC tag, the client is authenticated.
//   - No confirmation record is sent from server to client.
//
// If the client is not a bayed-tls client, the connection is transparently
// proxied to the upstream (passthrough) and Server returns (nil, ErrNotBayed).
//
// The returned *Conn implements net.Conn and can be used by the upper protocol
// layer (e.g. VLESS, VMess) for transparent data transfer.
func Server(c net.Conn, config *ServerConfig) (*Conn, error) {
	l := config.logger()
	remote := c.RemoteAddr().String()

	clientBuf := bufio.NewReader(c)

	// Step 1: Read ClientHello
	recType, payload, raw, err := readTLSRecord(clientBuf)
	if err != nil {
		return nil, err
	}
	if recType != recordTypeHandshake {
		return nil, ErrNotBayed
	}

	clientRandom, err := parseClientHelloRandom(payload)
	if err != nil {
		return nil, err
	}

	// Extract SNI from ClientHello for routing
	sni := parseClientHelloSNI(payload)

	// Step 2: Resolve upstream by SNI
	upstreamAddr := config.resolveUpstream(sni)
	if upstreamAddr == "" {
		if config.Show {
			l.Printf("[bayed] %s: SNI %q not in upstream list, rejecting", remote, sni)
		}
		return nil, ErrNotBayed
	}

	// Step 2b: Rate limit upstream handshakes
	if !config.acquireHandshake() {
		if config.Show {
			l.Printf("[bayed] %s: rate limited, rejecting", remote)
		}
		return nil, ErrNotBayed
	}

	upstream, err := net.DialTimeout("tcp", upstreamAddr, config.upstreamTimeout())
	if err != nil {
		return nil, err
	}
	upstreamBuf := bufio.NewReader(upstream)

	// Forward ClientHello to upstream
	if _, err := upstream.Write(raw); err != nil {
		upstream.Close()
		return nil, err
	}

	// Step 3: Read ServerHello from upstream
	recType, payload, raw, err = readTLSRecord(upstreamBuf)
	if err != nil {
		upstream.Close()
		return nil, err
	}

	var serverRandom []byte
	if recType == recordTypeHandshake {
		serverRandom, err = parseServerHelloRandom(payload)
		if err != nil && config.Show {
			l.Printf("[bayed] %s: parse ServerHello: %v", remote, err)
		}
	}

	// Forward ServerHello to client
	if _, err := c.Write(raw); err != nil {
		upstream.Close()
		return nil, err
	}

	// No server_random → cannot authenticate, do passthrough
	if serverRandom == nil {
		go func() { _, _ = io.Copy(c, upstreamBuf) }()
		_, _ = io.Copy(upstream, clientBuf)
		upstream.Close()
		return nil, ErrNotBayed
	}

	// Step 4: Derive keys
	k, err := deriveKeys(config.PSK, clientRandom, serverRandom)
	if err != nil {
		upstream.Close()
		return nil, err
	}
	defer k.zero() // zero key material on all exit paths

	// Prepare AES-GCM for trial decryption of client records.
	recvBlock, err := aes.NewCipher(k.c2sKey)
	if err != nil {
		upstream.Close()
		return nil, err
	}
	recvGCM, err := cipher.NewGCM(recvBlock)
	if err != nil {
		upstream.Close()
		return nil, err
	}
	var recvNonceBase [12]byte
	copy(recvNonceBase[:], k.c2sNonceBase)

	// Step 5: Proxy with zero-RT auth detection.
	//
	// upstream→client goroutine forwards all upstream records to the client.
	// Main loop reads client records and tries bayed decryption on each
	// ApplicationData record. On success → authenticated.
	//
	// Attack mitigations:
	//   - maxAuthAttempts limits trial decryptions to prevent CPU waste (DoS)
	//   - authPhaseTTL bounds the auth detection window (slow-read attacks)
	//   - cWriteMu prevents the upstream goroutine from writing a stale raw
	//     upstream record after auth succeeds (would corrupt the bayed stream)
	const (
		maxAuthAttempts = 5                // max AppData records to trial-decrypt
		authPhaseTTL    = 30 * time.Second // max time for auth detection phase
	)

	var (
		cWriteMu        sync.Mutex // protects writes to c + upstreamStopped flag
		upstreamStopped bool
	)
	upstreamDone := make(chan struct{})

	go func() {
		defer close(upstreamDone)
		for {
			_, _, raw, readErr := readTLSRecord(upstreamBuf)
			if readErr != nil {
				// Upstream died on its own (not our shutdown).
				// Close client to unblock main loop — no point
				// keeping a client whose upstream is gone.
				cWriteMu.Lock()
				if !upstreamStopped {
					c.Close()
				}
				cWriteMu.Unlock()
				return
			}
			cWriteMu.Lock()
			if upstreamStopped {
				cWriteMu.Unlock()
				return
			}
			_, writeErr := c.Write(raw)
			cWriteMu.Unlock()
			if writeErr != nil {
				return
			}
		}
	}()

	// Bound the auth detection window. If the client doesn't authenticate
	// within authPhaseTTL, fall back to pure passthrough.
	_ = c.SetReadDeadline(time.Now().Add(authPhaseTTL))

	authAttempts := 0
	for {
		recType, payload, raw, err = readTLSRecord(clientBuf)
		if err != nil {
			break
		}

		if recType == recordTypeApplicationData && authAttempts < maxAuthAttempts {
			authAttempts++
			// Try bayed decryption (seq=0, always the first data record).
			nonce := makeNonce(recvNonceBase, 0)
			plaintext, decErr := recvGCM.Open(nil, nonce, payload, nil)
			if decErr == nil {
				// Decryption succeeded — this is a bayed record.
				// Strip Vision-style padding (first record is always padded).
				if len(plaintext) < 2 {
					break // malformed
				}
				realLen := int(binary.BigEndian.Uint16(plaintext[len(plaintext)-2:]))
				if realLen > len(plaintext)-2 {
					break // malformed
				}
				data := plaintext[:realLen]

				// Check auth tag (first 32 bytes)
				if len(data) < authTagSize {
					break // too short to contain auth tag
				}
				if !verifyAuthTag(k.authKey, clientRandom, serverRandom, data[:authTagSize]) {
					break // auth tag mismatch — treat as non-bayed
				}

				if config.Show {
					l.Printf("[bayed] %s: v2 client authenticated (zero-RT)", remote)
				}

				// Clear the auth-phase deadline before switching to bayed mode.
				_ = c.SetReadDeadline(time.Time{})

				// Auth OK — stop upstream goroutine cleanly.
				// cWriteMu ensures no stale upstream record is written to c
				// between our decision and the goroutine stopping.
				cWriteMu.Lock()
				upstreamStopped = true
				cWriteMu.Unlock()
				upstream.Close()
				<-upstreamDone

				// Create encrypted conn (no confirmation sent in v2).
				// recvSeq starts at 1 because we already consumed seq=0.
				// recvCount starts at 1 because the first padded record was consumed.
				conn, err := newConn(c, clientBuf, k, false)
				if err != nil {
					return nil, err
				}
				conn.recvSeq = 1
				conn.recvCount = 1
				conn.Verified = true
				conn.ServerName = sni

				// Buffer remaining user data (after auth tag) for first Read.
				userData := data[authTagSize:]
				if len(userData) > 0 {
					conn.readBuf = make([]byte, len(userData))
					copy(conn.readBuf, userData)
				}

				return conn, nil
			}
		}

		// Not a bayed record (or auth attempts exhausted) — forward to upstream.
		if _, err := upstream.Write(raw); err != nil {
			break
		}
	}

	// Client disconnected or auth window expired — passthrough completed.
	cWriteMu.Lock()
	upstreamStopped = true
	cWriteMu.Unlock()
	upstream.Close()
	<-upstreamDone
	return nil, ErrNotBayed
}
