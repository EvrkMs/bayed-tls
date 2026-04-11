package bayed

import "errors"

// ErrNotBayed is returned by Server when the connection is not a bayed-tls
// client. The connection has been transparently proxied to the upstream
// (passthrough mode). This is expected behavior, not a real error.
var ErrNotBayed = errors.New("bayed: not a bayed-tls client (passthrough)")

// errSequenceOverflow is returned when the AES-GCM sequence counter
// exceeds the safety limit. This prevents theoretical nonce reuse.
// In practice no single TCP connection sends 2^48 records.
var errSequenceOverflow = errors.New("bayed: sequence number overflow")
