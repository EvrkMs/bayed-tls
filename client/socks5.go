package client

import (
	"io"
	"log"
	"net"
)

// ListenSOCKS5 starts a SOCKS5 proxy that tunnels connections through the VPN.
func (c *Client) ListenSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("[socks5] listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[socks5] accept: %v", err)
			continue
		}
		go c.handleSOCKS5(conn)
	}
}

func (c *Client) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// Auth negotiation
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// Request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	ver, cmd := buf[0], buf[1]
	if ver != 0x05 || cmd != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atype := buf[3]
	var addr string

	switch atype {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
		port := int(buf[8])<<8 | int(buf[9])
		addr = net.JoinHostPort(ip.String(), itoa(port))

	case 0x03: // Domain
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return
		}
		domain := string(buf[5 : 5+dlen])
		port := int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
		addr = net.JoinHostPort(domain, itoa(port))

	case 0x04: // IPv6
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		addr = net.JoinHostPort(ip.String(), itoa(port))

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := c.OpenStream(addr)
	if err != nil {
		log.Printf("[socks5] open stream to %s: %v", addr, err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{})
	go func() {
		io.Copy(stream, conn)
		close(done)
	}()
	io.Copy(conn, stream)
	<-done
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(buf[i+1:])
}
