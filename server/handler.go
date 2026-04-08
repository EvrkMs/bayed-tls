// Package server implements the bayed-tls server-side library.
//
// The main entry point is Handler, which can be used in two ways:
//
// 1. Standalone server:
//
//	srv := server.NewServer(server.Config{...})
//	log.Fatal(srv.ListenAndServe())
//
// 2. Integrated into an existing server (e.g. VLESS):
//
//	h := &server.Handler{
//	    PSK:          myPSK,
//	    UpstreamAddr: "google.com:443",
//	}
//	// In your accept loop:
//	h.HandleConn(conn)
package server

import (
	"bufio"
	"io"
	"log"
	"net"
	"time"

	"github.com/EvrkMs/bayed-tls/common"
)

// Handler processes incoming connections and detects bayed-tls clients.
// This is the integration point for embedding into existing servers.
type Handler struct {
	// PSK is the pre-shared key for client authentication.
	PSK []byte

	// UpstreamAddr is the real TLS server to proxy non-VPN traffic to
	// (e.g. "google.com:443"). This is the "camouflage" destination.
	UpstreamAddr string

	// UpstreamTimeout is the timeout for connecting to the upstream.
	// Default: 10 seconds.
	UpstreamTimeout time.Duration

	// Logger is an optional logger. If nil, log.Default() is used.
	Logger *log.Logger
}

func (h *Handler) log() *log.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return log.Default()
}

func (h *Handler) upstreamTimeout() time.Duration {
	if h.UpstreamTimeout > 0 {
		return h.UpstreamTimeout
	}
	return 10 * time.Second
}

// HandleConn processes a single incoming TCP connection.
//
// It reads the ClientHello, proxies the TLS handshake to the upstream,
// then checks if the client sends a valid bayed-tls auth beacon.
// If yes — establishes an encrypted VPN tunnel.
// If no — transparently proxies the connection to the upstream (passthrough).
//
// The connection is closed when this method returns.
func (h *Handler) HandleConn(clientConn net.Conn) {
	defer clientConn.Close()
	remote := clientConn.RemoteAddr().String()
	l := h.log()

	clientBuf := bufio.NewReader(clientConn)

	// ── Step 1: Read ClientHello ──
	recType, payload, raw, err := common.ReadTLSRecord(clientBuf)
	if err != nil {
		l.Printf("[bayed] %s: read ClientHello: %v", remote, err)
		return
	}
	if recType != common.RecordTypeHandshake {
		l.Printf("[bayed] %s: expected Handshake, got 0x%02x", remote, recType)
		return
	}

	clientRandom, err := common.ParseClientHelloRandom(payload)
	if err != nil {
		l.Printf("[bayed] %s: parse ClientHello: %v", remote, err)
		return
	}

	// ── Step 2: Connect to upstream ──
	upstream, err := net.DialTimeout("tcp", h.UpstreamAddr, h.upstreamTimeout())
	if err != nil {
		l.Printf("[bayed] %s: upstream dial %s: %v", remote, h.UpstreamAddr, err)
		return
	}
	defer upstream.Close()
	upstreamBuf := bufio.NewReader(upstream)

	// Forward ClientHello to upstream
	if _, err := upstream.Write(raw); err != nil {
		l.Printf("[bayed] %s: forward ClientHello: %v", remote, err)
		return
	}

	// ── Step 3: Read ServerHello from upstream ──
	recType, payload, raw, err = common.ReadTLSRecord(upstreamBuf)
	if err != nil {
		l.Printf("[bayed] %s: read ServerHello: %v", remote, err)
		return
	}

	var serverRandom []byte
	if recType == common.RecordTypeHandshake {
		serverRandom, err = common.ParseServerHelloRandom(payload)
		if err != nil {
			l.Printf("[bayed] %s: parse ServerHello: %v (passthrough)", remote, err)
		}
	}

	// Forward ServerHello to client
	if _, err := clientConn.Write(raw); err != nil {
		l.Printf("[bayed] %s: forward ServerHello: %v", remote, err)
		return
	}

	// Can't parse randoms → dumb passthrough
	if serverRandom == nil {
		l.Printf("[bayed] %s: no server_random, passthrough", remote)
		go io.Copy(clientConn, upstreamBuf)
		io.Copy(upstream, clientBuf)
		return
	}

	// ── Step 4: Derive keys ──
	keys, err := common.DeriveKeys(h.PSK, clientRandom, serverRandom)
	if err != nil {
		l.Printf("[bayed] %s: derive keys: %v", remote, err)
		return
	}

	// ── Step 5: Proxy with auth detection ──
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		io.Copy(clientConn, upstreamBuf)
	}()

	for {
		recType, payload, raw, err = common.ReadTLSRecord(clientBuf)
		if err != nil {
			break
		}

		if recType == common.RecordTypeApplicationData {
			if common.VerifyAuthPayload(keys.AuthKey, clientRandom, payload) {
				l.Printf("[bayed] %s: ✓ client authenticated", remote)

				upstream.Close()
				<-upstreamDone

				h.serveTunnel(clientConn, clientBuf, keys, serverRandom, remote)
				return
			}
		}

		if _, err := upstream.Write(raw); err != nil {
			break
		}
	}

	upstream.Close()
	<-upstreamDone
	l.Printf("[bayed] %s: closed (passthrough)", remote)
}

func (h *Handler) serveTunnel(
	clientConn net.Conn,
	clientBuf *bufio.Reader,
	keys *common.Keys,
	serverRandom []byte,
	remote string,
) {
	l := h.log()

	confirm, err := common.MakeConfirmPayload(keys.AuthKey, serverRandom)
	if err != nil {
		l.Printf("[bayed] %s: make confirm: %v", remote, err)
		return
	}
	if err := common.WriteTLSRecord(clientConn, common.RecordTypeApplicationData, confirm); err != nil {
		l.Printf("[bayed] %s: write confirm: %v", remote, err)
		return
	}

	conn, err := common.NewConn(clientConn, clientBuf, keys.C2SKey, keys.S2CKey, false)
	if err != nil {
		l.Printf("[bayed] %s: create conn: %v", remote, err)
		return
	}

	l.Printf("[bayed] %s: tunnel established", remote)

	tunnel := NewTunnel(conn)
	tunnel.Serve()

	l.Printf("[bayed] %s: tunnel closed", remote)
}
