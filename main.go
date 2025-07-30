package main

import (
	"flag"
	"log"

	"github.com/pvormste/certgen/internal/server"
)

func main() {
	// Parse command line flags
	addr := flag.String("addr", ":9595", "HTTP service address")
	flag.Parse()

	// Create and start server
	srv, err := server.NewServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Printf("Starting certificate generator service on %s", *addr)
	if err := srv.Start(*addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
