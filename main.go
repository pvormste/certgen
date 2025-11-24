package main

import (
	"flag"
	"log"
	"os"

	"github.com/pvormste/certgen/internal/server"
)

func main() {
	// Default to port 80, but allow override via flag or environment variable
	defaultAddr := ":80"
	if port := os.Getenv("PORT"); port != "" {
		defaultAddr = port
	}

	// Parse command line flags
	addr := flag.String("addr", defaultAddr, "HTTP service address")
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
