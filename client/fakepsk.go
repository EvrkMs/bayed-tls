package client

import (
	"crypto/rand"
	"math/big"

	tls "github.com/refraction-networking/utls"
)

// fakePSKConfig controls fake PSK injection.
type fakePSKConfig struct {
	// Enabled turns on fake PSK for ~50% of connections.
	Enabled bool
	// IdentityLen is the size of the fake session ticket (default 224, Chrome-like).
	IdentityLen int
	// BinderLen is the HMAC binder size (32 = SHA-256, 48 = SHA-384).
	BinderLen int
}

var defaultFakePSK = fakePSKConfig{
	IdentityLen: 224,
	BinderLen:   32, // SHA-256 — matches TLS_AES_128_GCM_SHA256
}

// shouldUseFakePSK returns true ~50% of the time (crypto/rand).
func shouldUseFakePSK() bool {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false
	}
	return n.Int64() == 1
}

// applyFakePSK injects a fake pre_shared_key extension into the UConn
// after BuildHandshakeState has been called. This makes the ClientHello
// look like a session resumption (repeat visit) to DPI.
//
// The server (google.com) will silently ignore the invalid PSK and
// perform a full handshake — this is standard TLS 1.3 behavior.
func applyFakePSK(uconn *tls.UConn, cfg fakePSKConfig) error {
	identityLen := cfg.IdentityLen
	if identityLen <= 0 {
		identityLen = defaultFakePSK.IdentityLen
	}
	binderLen := cfg.BinderLen
	if binderLen <= 0 {
		binderLen = defaultFakePSK.BinderLen
	}

	// Generate random session ticket identity.
	identity := make([]byte, identityLen)
	if _, err := rand.Read(identity); err != nil {
		return err
	}

	// Generate random binder.
	binder := make([]byte, binderLen)
	if _, err := rand.Read(binder); err != nil {
		return err
	}

	// Random obfuscated ticket age (0–600000 ms, ~10 min window).
	ageN, err := rand.Int(rand.Reader, big.NewInt(600000))
	if err != nil {
		return err
	}

	// Set session cache (required for FakePreSharedKeyExtension.writeToUConn).
	cache := tls.NewLRUClientSessionCache(1)
	uconn.SetSessionCache(cache)

	// Inject via SetPskExtension.
	return uconn.SetPskExtension(&tls.FakePreSharedKeyExtension{
		Identities: []tls.PskIdentity{
			{
				Label:               identity,
				ObfuscatedTicketAge: uint32(ageN.Int64()),
			},
		},
		Binders: [][]byte{binder},
	})
}
