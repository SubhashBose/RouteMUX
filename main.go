package main

import (
	"fmt"
	"log"
	"os"
	"routemux/daemon"
)

func main() {
	daemon.Handle(daemon.Config{
		OnStart: run,
		AppName: "RouteMUX",
	})
}

func run() {
	cfg, err := parseAll(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	server, err := newServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Printf("RouteMUX starting on %s", server.listenAddr())
	if err := server.run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
