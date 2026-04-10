package bayed

import "errors"

// ErrNotBayed is returned by Server when the connection is not a bayed-tls
// client. The connection has been transparently proxied to the upstream
// (passthrough mode). This is expected behavior, not a real error.
var ErrNotBayed = errors.New("bayed: not a bayed-tls client (passthrough)")
