//go:build windows

package daemon

import (
	"log"
	"fmt"
	"os"
)

type Config struct {
	OnStart       func()
	AppName       string
	PidfilePrefix string
	Logger        *log.Logger
}

const DAEMONIZE_SUPPORTED = false

func Handle(cfg Config) {
	// Daemonizing is not supported on Windows.
	// Running attached to terminal only.

	command, _ := parseArgs(os.Args[1:])

	switch command {
	case "start", "stop", "status":
		Unsupported()
	default:
		// No control command — run normally, attached to terminal.
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
	}
}

// parseArgs separates the last occurrence of start/stop/status from the rest.
// Returns ("", original) if no control command is found.
func parseArgs(args []string) (command string, rest []string) {
	for i := len(args) - 1; i >= 0; i-- {
		switch args[i] {
		case "start", "stop", "status":
			rest = make([]string, 0, len(args)-1)
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return args[i], rest
		}
	}
	return "", args
}

func Unsupported() {
	// Check if already running.
	fmt.Printf("Daemonizing is not supported on Windows.\n")
}