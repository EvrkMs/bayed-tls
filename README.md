# bayed-tls

Stealth VPN tunnel disguised as regular HTTPS traffic to Google.

**How it works:** the client performs a real TLS 1.3 handshake with `google.com` through the bayed-tls server, making traffic indistinguishable from a normal browser visit. Authentication happens *after* the encrypted handshake via a beacon — no markers in the ClientHello.

## Features

- **Chrome fingerprint** — uTLS mimics real Chrome (133, 131, 120-PQ) ClientHello
- **Passthrough** — non-VPN clients are transparently proxied to Google (active probe resistant)
- **Fake PSK** — optional `pre_shared_key` extension makes ~50% of connections look like session resumption
- **Connection pool** — multiple parallel TLS connections like a browser with many tabs
- **Stream multiplexing** — multiple TCP streams over a single encrypted connection
- **SOCKS5 proxy** — built-in local proxy for easy client usage

## Quick Start

### Server

```bash
bayed-server -listen :443 -upstream google.com:443 -psk "your-secret"
```

### Client

```bash
bayed-client -server your-server:443 -sni google.com -psk "your-secret" -socks 127.0.0.1:1080
```

### Docker

```bash
# Server
docker run -d -p 443:443 ghcr.io/evrkms/bayed-tls-server:latest \
  -listen :443 -upstream google.com:443 -psk "your-secret"

# Client
docker run -d -p 1080:1080 ghcr.io/evrkms/bayed-tls-client:latest \
  -server your-server:443 -sni google.com -psk "your-secret" -socks 0.0.0.0:1080
```

## Client Flags

| Flag           | Default          | Description                                         |
|----------------|------------------|-----------------------------------------------------|
| `-server`      | *required*       | Server address (`host:port`)                        |
| `-sni`         | `google.com`     | TLS SNI hostname                                    |
| `-psk`         | *required*       | Pre-shared key (or `BAYED_PSK` env)                 |
| `-socks`       | `127.0.0.1:1080` | Local SOCKS5 listen address                         |
| `-fingerprint` | `chrome`         | TLS fingerprint (`uTLS version v1.8.2`)             |
| `-fake-psk`    | `false`          | Inject fake `pre_shared_key` in ~50% of connections |
| `-pool`        | `0`              | Number of parallel connections (0 = single)         |
| `-insecure`    | `false`          | Skip TLS certificate verification                   |

## Server Flags

| Flag        | Default          | Description                         |
|-------------|------------------|-------------------------------------|
| `-listen`   | `:443`           | Listen address                      |
| `-upstream` | `google.com:443` | Real TLS server for passthrough     |
| `-psk`      | *required*       | Pre-shared key (or `BAYED_PSK` env) |

## Architecture

```
Client                          Server                        Google
  │                               │                             │
  │── TLS ClientHello (Chrome) ──→│── forward ClientHello ─────→│
  │←── ServerHello ──────────────←│←── forward ServerHello ────←│
  │── [encrypted]  ──────────────→│                             │
  │   ... TLS handshake ...       │   ... TLS handshake ...     │
  │                               │                             │
  │── auth beacon  ──────────────→│ ✓ verify PSK+HKDF           |
  │←── confirm  ─────────────────←│ ✗ disconnect upstream       │
  │                               │                             │
  │══ encrypted tunnel (AES-GCM) ═╡                             │
  │   ├─ stream 1: TCP proxy      │                             │
  │   ├─ stream 2: TCP proxy      │                             │
  │   └─ stream N: TCP proxy      │                             │
```

- **DPI sees:** normal TLS 1.3 handshake to `google.com`, standard ciphersuites
- **Active probe sees:** real `google.com` response (passthrough)
- **Auth beacon:** AES-GCM encrypted, derived from `PSK + client_random + server_random` via HKDF-SHA256

## Building

```bash
# Binaries
CGO_ENABLED=0 go build -o bayed-server ./cmd/bayed-server/
CGO_ENABLED=0 go build -o bayed-client ./cmd/bayed-client/

# Docker
docker build -f Dockerfile.server -t bayed-server .
docker build -f Dockerfile.client -t bayed-client .
```

## Project Structure

```
cmd/
  bayed-server/    # server entrypoint
  bayed-client/    # client entrypoint
client/
  client.go        # TLS tunnel + stream mux
  fakepsk.go       # fake pre_shared_key injection
  fingerprint.go   # uTLS Chrome/Firefox/Safari profiles
  pool.go          # connection pool (multi-TCP)
  socks5.go        # SOCKS5 proxy
server/
  server.go        # TCP listener
  handler.go       # handshake proxy + auth detection
  tunnel.go        # stream demux + TCP relay
common/
  auth.go          # HKDF key derivation + beacon
  conn.go          # AES-GCM encrypted connection
  frame.go         # stream multiplexing frames
  record.go        # TLS record I/O
```

## License

MIT
