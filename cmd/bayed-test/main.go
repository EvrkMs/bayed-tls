// bayed-test is an interactive CLI for testing the bayed-tls tunnel.
//
// Usage:
//
//	bayed-test -server 172.20.1.10:443 -psk secret
//
// Then interactively:
//
//	> connect     — establish the tunnel
//	> curl URL    — fetch a URL through the tunnel
//	> ip          — show your exit IP (via httpbin.org)
//	> status      — show tunnel status
//	> quit        — exit
package main

import (
	"bufio"
	"fmt"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/EvrkMs/bayed-tls/client"
)

var c *client.Client
var connected bool

func main() {
	serverAddr := flag.String("server", "", "server address (host:port)")
	sni := flag.String("sni", "google.com", "TLS SNI")
	psk := flag.String("psk", "", "pre-shared key")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification")
	fingerprint := flag.String("fingerprint", "chrome-pq", "TLS fingerprint")
	flag.Parse()

	if *psk == "" {
		*psk = os.Getenv("BAYED_PSK")
	}
	if *serverAddr == "" || *psk == "" {
		flag.Usage()
		log.Fatal("server address and PSK are required")
	}

	c = client.New(client.Config{
		ServerAddr:  *serverAddr,
		SNI:         *sni,
		PSK:         []byte(*psk),
		Insecure:    *insecure,
		Fingerprint: *fingerprint,
	})

	fmt.Println("bayed-tls test CLI")
	fmt.Println("Commands: connect, curl <url>, ip, status, quit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "connect":
			doConnect()
		case "curl":
			if len(parts) < 2 {
				fmt.Println("usage: curl <url>")
				continue
			}
			doCurl(parts[1])
		case "ip":
			doCurl("http://httpbin.org/ip")
		case "status":
			if connected {
				fmt.Println("Connected ✓")
			} else {
				fmt.Println("Not connected")
			}
		case "quit", "exit", "q":
			fmt.Println("bye")
			return
		default:
			fmt.Printf("unknown command: %s\n", cmd)
		}
	}
}

func doConnect() {
	if connected {
		fmt.Println("Already connected")
		return
	}
	fmt.Println("Connecting...")
	if err := c.Connect(); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	connected = true
	fmt.Println("Connected ✓")
}

func doCurl(url string) {
	if !connected {
		fmt.Println("Not connected. Run 'connect' first.")
		return
	}

	// Parse the URL to get host:port
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	// Use SOCKS5 — start a temporary listener
	go func() {
		// We'll use OpenStream directly instead
	}()

	// Simple approach: open a stream and do a raw HTTP request
	host := extractHost(url)
	port := "80"
	if strings.HasPrefix(url, "https://") {
		port = "443"
	}

	// Extract path
	path := "/"
	hostPort := host
	if idx := strings.Index(host, "/"); idx != -1 {
		path = host[idx:]
		hostPort = host[:idx]
	}
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":" + port
	} else {
		// Already has port, extract clean host for Host header
		h, _, _ := strings.Cut(hostPort, ":")
		host = h
	}

	stream, err := c.OpenStream(hostPort)
	if err != nil {
		fmt.Printf("Error opening stream to %s: %v\n", hostPort, err)
		return
	}
	defer stream.Close()

	// Determine clean host for Host header
	cleanHost := hostPort
	if idx := strings.Index(cleanHost, ":"); idx != -1 {
		cleanHost = cleanHost[:idx]
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: bayed-test/1.0\r\n\r\n", path, cleanHost)
	if _, err := stream.Write([]byte(req)); err != nil {
		fmt.Printf("Error writing: %v\n", err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP %d %s\n", resp.StatusCode, resp.Status)
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func extractHost(url string) string {
	// Remove scheme
	u := url
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	return u
}
