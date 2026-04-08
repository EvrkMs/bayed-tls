package client

import (
	"log"

	tls "github.com/refraction-networking/utls"
)

// ResolveFingerprint maps a human-readable name to a uTLS ClientHelloID.
// Exported so callers can check available fingerprints.
func ResolveFingerprint(name string) tls.ClientHelloID {
	switch name {
	case "chrome-pq", "":
		return tls.HelloChrome_120_PQ // Chrome 120 + X25519Kyber768 + extension shuffle
	case "chrome":
		return tls.HelloChrome_Auto
	case "firefox":
		return tls.HelloFirefox_Auto
	case "safari":
		return tls.HelloSafari_Auto
	case "ios":
		return tls.HelloIOS_Auto
	case "edge":
		return tls.HelloEdge_Auto
	case "random":
		return tls.HelloRandomized
	case "go":
		return tls.HelloGolang
	default:
		log.Printf("[bayed-client] unknown fingerprint %q, using chrome-pq", name)
		return tls.HelloChrome_120_PQ
	}
}

// Fingerprints returns the list of supported fingerprint names.
func Fingerprints() []string {
	return []string{"chrome-pq", "chrome", "firefox", "safari", "ios", "edge", "random", "go"}
}
