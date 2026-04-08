// bayed-server is the standalone bayed-tls server.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/EvrkMs/bayed-tls/server"
)

func main() {
	listen := flag.String("listen", ":443", "listen address")
	upstream := flag.String("upstream", "google.com:443", "upstream TLS server")
	psk := flag.String("psk", "", "pre-shared key")
	flag.Parse()

	if *psk == "" {
		*psk = os.Getenv("BAYED_PSK")
	}
	if *psk == "" {
		log.Fatal("PSK required: use -psk or BAYED_PSK env var")
	}

	srv := server.NewServer(server.Config{
		ListenAddr:   *listen,
		UpstreamAddr: *upstream,
		PSK:          []byte(*psk),
	})
	log.Fatal(srv.ListenAndServe())
}
