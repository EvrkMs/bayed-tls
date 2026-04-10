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
	"time"
)

// ServerConfig configures the server-side bayed-tls handshake.
type ServerConfig struct {
	// PSK is the pre-shared key used for client authentication.
	PSK []byte

	// UpstreamAddr is the real TLS server to proxy non-VPN traffic to
	// (e.g. "google.com:443"). Unauthenticated connections are
	// transparently forwarded here (active probe resistance).
	UpstreamAddr string

	// UpstreamTimeout is the dial timeout for the upstream server.
	// Default: 10s.
	UpstreamTimeout time.Duration

	// Show enables verbose debug output.
	Show bool

	// Logger is an optional logger. If nil, log.Default() is used.
	Logger *log.Logger
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
