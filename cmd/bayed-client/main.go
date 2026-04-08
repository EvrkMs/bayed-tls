// bayed-client is the standalone bayed-tls client with SOCKS5 proxy.
package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/EvrkMs/bayed-tls/client"
)

func main() {
	serverAddr := flag.String("server", "", "server address (host:port)")
	sni := flag.String("sni", "google.com", "TLS SNI")
	psk := flag.String("psk", "", "pre-shared key")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification")
	fingerprint := flag.String("fingerprint", "chrome", "TLS fingerprint: chrome, chrome-pq, chrome-131, chrome-133, firefox, safari, ios, edge, random, go")
	fakePSK := flag.Bool("fake-psk", false, "inject fake pre_shared_key extension (~50%% of connections)")
	poolSize := flag.Int("pool", 0, "number of parallel connections (0 = single connection)")
	flag.Parse()

	if *psk == "" {
		*psk = os.Getenv("BAYED_PSK")
	}
	if *serverAddr == "" || *psk == "" {
		flag.Usage()
		log.Fatal("server address and PSK are required")
	}
	if *sni == "" {
		host, _, err := net.SplitHostPort(*serverAddr)
		if err == nil {
			*sni = host
		}
	}

	cfg := client.Config{
		ServerAddr:  *serverAddr,
		SNI:         *sni,
		PSK:         []byte(*psk),
		Insecure:    *insecure,
		Fingerprint: *fingerprint,
		FakePSK:     *fakePSK,
		PoolSize:    *poolSize,
	}

	if *poolSize >= 2 {
		p := client.NewPool(cfg, *poolSize)
		log.Printf("[main] connecting pool (%d conns) to %s (SNI: %s)...", *poolSize, *serverAddr, *sni)
		if err := p.Connect(); err != nil {
			log.Fatalf("pool connect: %v", err)
		}
		log.Printf("[main] SOCKS5 proxy on %s (pool mode)", *socksAddr)
		log.Fatal(p.ListenSOCKS5(*socksAddr))
	} else {
		c := client.New(cfg)
		log.Printf("[main] connecting to %s (SNI: %s)...", *serverAddr, *sni)
		if err := c.Connect(); err != nil {
			log.Fatalf("connect: %v", err)
		}
		log.Printf("[main] SOCKS5 proxy on %s", *socksAddr)
		log.Fatal(c.ListenSOCKS5(*socksAddr))
	}
}
