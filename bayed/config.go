// Package bayed implements the bayed-tls stealth handshake and encrypted
// connection primitive. It is designed as an external library that can be
// integrated into Xray-core (or other proxies) as a security/handshake method
// alongside Reality, plain TLS, etc.
//
// The API is intentionally minimal:
//
//	Server(conn, *ServerConfig) (*Conn, error)   — server-side handshake
//	Client(conn, *ClientConfig) (*Conn, error)   — client-side handshake
//
// After handshake, *Conn implements net.Conn and can be used as a transparent
// encrypted pipe by the upper protocol layer (VLESS, VMess, etc.).
package bayed

import (
	"log"
	"sync/atomic"
	"time"
)

// ServerConfig configures the server-side bayed-tls handshake.
type ServerConfig struct {
	// PSK is the pre-shared key used for client authentication.
	PSK []byte

	// UpstreamAddr is the primary upstream TLS server (e.g. "google.com:443").
	// Kept for backward compatibility. If Upstreams is set, this is ignored.
	UpstreamAddr string

	// Upstreams is a list of upstream TLS servers for round-robin rotation.
	// Each entry is "host:port" (e.g. "www.google.com:443").
	// Using multiple upstreams distributes handshake load and avoids
	// anti-abuse bans from a single provider.
	Upstreams []string

	// UpstreamTimeout is the dial timeout for the upstream server.
	// Default: 10s.
	UpstreamTimeout time.Duration

	// Show enables verbose debug output.
	Show bool

	// Logger is an optional logger. If nil, log.Default() is used.
	Logger *log.Logger

	// Internal round-robin counter.
	rrCounter atomic.Uint64
}

func (c *ServerConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}

func (c *ServerConfig) upstreamTimeout() time.Duration {
	if c.UpstreamTimeout > 0 {
		return c.UpstreamTimeout
	}
	return 10 * time.Second
}

// pickUpstream returns the next upstream address using round-robin.
// If Upstreams is empty, falls back to UpstreamAddr.
func (c *ServerConfig) pickUpstream() string {
	ups := c.Upstreams
	if len(ups) == 0 {
		return c.UpstreamAddr
	}
	idx := c.rrCounter.Add(1) - 1
	return ups[idx%uint64(len(ups))]
}

// ClientConfig configures the client-side bayed-tls handshake.
type ClientConfig struct {
	// PSK is the pre-shared key.
	PSK []byte

	// ServerName is the TLS SNI hostname (e.g. "google.com").
	ServerName string

	// Fingerprint selects the uTLS ClientHello fingerprint.
	// Supported: "chrome", "chrome-pq", "chrome-131", "chrome-133",
	// "firefox", "safari", "ios", "edge", "random", "go".
	Fingerprint string

	// InsecureSkipVerify skips TLS certificate verification (testing only).
	InsecureSkipVerify bool

	// Show enables verbose debug output.
	Show bool

	// Logger is an optional logger. If nil, log.Default() is used.
	Logger *log.Logger
}

func (c *ClientConfig) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.Default()
}
