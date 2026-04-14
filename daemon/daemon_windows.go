//go:build windows

package daemon

import (
	"log"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	//"golang.org/x/sys/windows"
)

// Config holds optional settings for the daemon.
type Config struct {
	// OnStart is called in the daemon process after it has started.
	// Put your main program logic here.
	OnStart func()

	// AppName is the name of the application.
	// Defaults to the basename of the current executable.
	AppName string

	// PidfilePrefix is the prefix for the PID file.
	// Defaults to the basename of the current executable.
	PidfilePrefix string

	//HashKey to be used for the PID file. Default is current working directory
	HashKey string

	// WaitAfterStart is how long to wait after forking before confirming the
	// daemon is still alive. Defaults to 500ms.
	WaitAfterStart time.Duration

	// WatchdogRestartDelay is how long the watchdog waits before restarting a
	// crashed worker. Defaults to 2s.
	WatchdogRestartDelay time.Duration

	// Logger file to used for daemon-internal messages. Logging defaults to log.Default().
	LoggerFile string

	// WatchdogLogger file to used for watchdog messages. Logging defaults to log.Default().
	// Defaults to same as Logger if it is set, otherwise log file is PID-file basename with "-watchdog.log".
	WatchdogLoggerFile string

	// Restart (when watch-start) worker on clean exit too. Default is restart on error only
	// Default value false.
	RestartOnCleanExit bool
	
	// (internal variables) Logger is used for daemon-internal messages. Defaults to log.Default().
	logger *log.Logger

	pidFile string
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

func getProcessArgs(pid int) ([]string, error) {
    // Windows requires opening the process and reading its PEB (Process
    // Environment Block) via NtQueryInformationProcess — quite involved.
    // The x/sys/windows package doesn't expose a simple wrapper for this,
    // so the easiest route is shelling out to wmic:
    out, err := exec.Command("wmic", "process", "where",
        fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine", "/format:value").Output()
    if err != nil {
        return nil, err
    }
    // parse "CommandLine=./myapp --foo\r\n\r\n"
    line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "CommandLine="))
    return strings.Fields(line), nil
}