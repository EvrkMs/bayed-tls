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
	"net"
	"strings"
	"sync"
	"time"
)

// ServerConfig configures the server-side bayed-tls handshake.
type ServerConfig struct {
	// PSK is the pre-shared key used for client authentication.
	PSK []byte

	// UpstreamAddr is the primary upstream TLS server (e.g. "www.google.com:443").
	// Used when Upstreams is empty. This is the default mode.
	UpstreamAddr string

	// Upstreams is an optional list of allowed upstream TLS servers.
	// Each entry is "host:port" (e.g. "www.google.com:443").
	// When set, the server matches the client's SNI against this list
	// and routes to the matching upstream. Unknown SNIs are rejected.
	// All upstreams should belong to the same ASN/provider for stealth.
	Upstreams []string

	// MaxHandshakesPerSec limits the rate of upstream TLS handshakes.
	// 0 means unlimited. Recommended: 50–200 for production.
	MaxHandshakesPerSec int

	// UpstreamTimeout is the dial timeout for the upstream server.
	// Default: 10s.
	UpstreamTimeout time.Duration

	// Show enables verbose debug output.
	Show bool

	// Logger is an optional logger. If nil, log.Default() is used.
	Logger *log.Logger

	// Internal: SNI→upstream lookup map, built lazily.
	upstreamMap  map[string]string
	upstreamOnce sync.Once

	// Internal: rate limiter.
	handshakeLimiter *rateLimiter
	limiterOnce      sync.Once
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

// resolveUpstream returns the upstream address for a given client SNI.
// With a single upstream (UpstreamAddr), it always returns that address.
// With multiple Upstreams, it matches SNI against the host part of each entry.
// Returns "" if no match found.
func (c *ServerConfig) resolveUpstream(sni string) string {
	if len(c.Upstreams) == 0 {
		return c.UpstreamAddr
	}

	c.upstreamOnce.Do(func() {
		c.upstreamMap = make(map[string]string, len(c.Upstreams))
		for _, addr := range c.Upstreams {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			c.upstreamMap[strings.ToLower(host)] = addr
		}
	})

	if addr, ok := c.upstreamMap[strings.ToLower(sni)]; ok {
		return addr
	}

	// SNI not in allowed list
	return ""
}

// acquireHandshake checks the rate limiter. Returns true if allowed.
func (c *ServerConfig) acquireHandshake() bool {
	if c.MaxHandshakesPerSec <= 0 {
		return true
	}
	c.limiterOnce.Do(func() {
		c.handshakeLimiter = newRateLimiter(c.MaxHandshakesPerSec)
	})
	return c.handshakeLimiter.allow()
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
