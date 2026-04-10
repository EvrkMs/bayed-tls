package bayed

import (
	"bufio"
	"io"
	"net"
)

// Server performs the server-side bayed-tls handshake on an already-accepted
// TCP connection. It reads the ClientHello, proxies the TLS handshake to the
// upstream, detects the auth beacon, and returns an encrypted *Conn.
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

	// Step 2: Connect to upstream
	upstream, err := net.DialTimeout("tcp", config.UpstreamAddr, config.upstreamTimeout())
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
		go io.Copy(c, upstreamBuf)
		io.Copy(upstream, clientBuf)
		upstream.Close()
		return nil, ErrNotBayed
	}

	// Step 4: Derive keys
	k, err := deriveKeys(config.PSK, clientRandom, serverRandom)
	if err != nil {
		upstream.Close()
		return nil, err
	}

	// Step 5: Proxy with auth detection
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		io.Copy(c, upstreamBuf)
	}()

	for {
		recType, payload, raw, err = readTLSRecord(clientBuf)
		if err != nil {
			break
		}

		if recType == recordTypeApplicationData {
			if verifyAuthPayload(k.authKey, clientRandom, payload) {
				if config.Show {
					l.Printf("[bayed] %s: client authenticated", remote)
				}

				// Auth OK — stop proxying upstream
				upstream.Close()
				<-upstreamDone

				// Send confirmation
				confirm, err := makeConfirmPayload(k.authKey, serverRandom)
				if err != nil {
					return nil, err
				}
				if err := writeTLSRecord(c, recordTypeApplicationData, confirm); err != nil {
					return nil, err
				}

				// Create encrypted conn
				conn, err := newConn(c, clientBuf, k.c2sKey, k.s2cKey, false)
				if err != nil {
					return nil, err
				}
				conn.Verified = true
				conn.ServerName = string(clientRandom) // placeholder; SNI from ClientHello TODO
				return conn, nil
			}
		}

		// Not auth beacon — forward to upstream
		if _, err := upstream.Write(raw); err != nil {
			break
		}
	}

	// Client disconnected without authenticating — passthrough completed
	upstream.Close()
	<-upstreamDone
	return nil, ErrNotBayed
}
