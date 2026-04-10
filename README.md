# bayed-tls

Stealth TLS handshake library for Go — a drop-in security method for proxy frameworks like Xray-core, similar to Reality.

## What it does

bayed-tls authenticates VPN/proxy clients through a real TLS 1.3 handshake with a legitimate server (e.g. `google.com`). Unauthenticated connections are transparently proxied to the upstream — making the server indistinguishable from a real website.

**Not a VPN or proxy itself** — this is a handshake/auth library. Use it inside Xray-core, V2Ray, or your own proxy.

## API

```go
import "github.com/EvrkMs/bayed-tls/bayed"

// Server-side: wrap an accepted connection
conn, err := bayed.Server(tcpConn, &bayed.ServerConfig{
    PSK:          []byte("secret"),
    UpstreamAddr: "google.com:443",
})
// conn implements net.Conn — pass to VLESS/VMess/etc.

// Client-side: wrap a dialed connection
conn, err := bayed.Client(tcpConn, &bayed.ClientConfig{
    PSK:         []byte("secret"),
    ServerName:  "google.com",
    Fingerprint: "chrome",
})
// conn implements net.Conn — pass to VLESS/VMess/etc.
```

## How it works

1. Client performs a real TLS 1.3 handshake with `google.com` through the bayed server (uTLS, Chrome fingerprint)
2. Server proxies handshake to real upstream, extracts `client_random` + `server_random`
3. Both sides derive keys via `HKDF-SHA256(PSK, randoms)`
4. Client sends AES-GCM encrypted auth beacon
5. Server verifies → closes upstream → returns encrypted `net.Conn`
6. If auth fails → connection stays proxied to `google.com` (passthrough)

## Features

- **Chrome fingerprint** — uTLS mimics Chrome 133/131/120-PQ, Firefox, Safari, Edge, etc.
- **Passthrough** — unauthenticated clients get real `google.com` (active probe resistant)
- **Fake PSK** — optional fake `pre_shared_key` extension (~50% of connections look like session resumption)
- **Full net.Conn** — implements `Read`, `Write`, `Close`, `SetDeadline`, etc.
- **Xray-compatible** — designed as a security type alongside Reality/TLS

## Integration with Xray-core

Add as a Go dependency:

```
go get github.com/EvrkMs/bayed-tls
```

Then use `bayed.Server()` / `bayed.Client()` in your transport handler, just like `reality.Server()` / `reality.UClient()`.

## Security

| What DPI sees | Result |
|---------------|--------|
| TLS ClientHello | Real Chrome fingerprint to `google.com` |
| Active probe | Real `google.com` response (passthrough) |
| Auth mechanism | AES-GCM beacon, derived from PSK + TLS randoms via HKDF-SHA256 |
| After auth | AES-256-GCM encrypted pipe (TLS Application Data records) |

## Structure

```
bayed/
  config.go     — ServerConfig, ClientConfig
  server.go     — Server(conn, config) → (*Conn, error)
  client.go     — Client(conn, config) → (*Conn, error)
  conn.go       — Conn (net.Conn), crypto helpers
  record.go     — TLS record I/O
  errors.go     — ErrNotBayed
```

## License

MIT
