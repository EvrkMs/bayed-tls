package server

import (
	"log"
	"net"
)

// Config is the configuration for a standalone bayed-tls server.
type Config struct {
	ListenAddr   string // e.g. ":443"
	UpstreamAddr string // e.g. "google.com:443"
	PSK          []byte
}

// Server is a standalone TCP server that wraps Handler.
// Use this for quick deployment; for integration use Handler directly.
type Server struct {
	handler Handler
	cfg     Config
}

// NewServer creates a standalone server.
func NewServer(cfg Config) *Server {
	return &Server{
		cfg: cfg,
		handler: Handler{
			PSK:          cfg.PSK,
			UpstreamAddr: cfg.UpstreamAddr,
		},
	}
}

// ListenAndServe starts accepting TCP connections.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	log.Printf("[bayed-server] listening on %s, upstream: %s", s.cfg.ListenAddr, s.cfg.UpstreamAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[bayed-server] accept: %v", err)
			continue
		}
		go s.handler.HandleConn(conn)
	}
}
