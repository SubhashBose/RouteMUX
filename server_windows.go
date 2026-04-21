//go:build windows

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func (s *server) setupSignals(srv *http.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("RouteMUX received %s, shutting down...", sig)
				srv.Shutdown(context.Background())
				return
			}
		}
	}()
}
