package client

import (
	"log"

	tls "github.com/refraction-networking/utls"
)

// ResolveFingerprint maps a human-readable name to a uTLS ClientHelloID.
// Exported so callers can check available fingerprints.
func ResolveFingerprint(name string) tls.ClientHelloID {
	switch name {
	case "chrome", "":
		return tls.HelloChrome_Auto // latest Chrome (currently 133, ML-KEM)
	case "chrome-pq":
		return tls.HelloChrome_120_PQ // Chrome 120-129 + X25519Kyber768Draft00 + shuffle
	case "chrome-131":
		return tls.HelloChrome_131 // Chrome 131+ X25519MLKEM768
	case "chrome-133":
		return tls.HelloChrome_133 // Chrome 133+
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
		log.Printf("[bayed-client] unknown fingerprint %q, using chrome (auto)", name)
		return tls.HelloChrome_Auto
	}
}

// Fingerprints returns the list of supported fingerprint names.
func Fingerprints() []string {
	return []string{"chrome-pq", "chrome-131", "chrome-133", "chrome", "firefox", "safari", "ios", "edge", "random", "go"}
}
