// Package daemon provides self-daemonizing functionality for Go programs.
// It handles start/stop/status commands, PID file management, and graceful shutdown.
package daemon

import (
	"crypto/md5"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const pidFileEnvVar = "DAEMON_PID_FILE"

// Config holds optional settings for the daemon.
type Config struct {
	// OnStart is called in the daemon process after it has started.
	// Put your main program logic here.
	OnStart func()

	AppName string

	PidfilePrefix string

	// Logger is used for daemon-internal messages. Defaults to log.Default().
	Logger *log.Logger
}

// Handle inspects os.Args for "start", "stop", or "status" commands and acts accordingly.
// It strips those control words before passing remaining args to the forked child.
//
// Usage pattern:
//
//	func main() {
//	    daemon.Handle(daemon.Config{
//	        OnStart: func() { /* your real program logic */ },
//	    })
//	}
//
// Commands:
//
//	./myapp [flags] start   — daemonize; child runs with [flags] only
//	./myapp [flags] stop    — kill the running daemon
//	./myapp [flags] status  — print whether the daemon is running
//	./myapp [flags]         — run attached to the terminal (no daemonizing)
func Handle(cfg Config) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.AppName == "" {
		exe, _:= os.Executable()
		cfg.AppName = filepath.Base(exe)
	}
	if cfg.PidfilePrefix == "" {
		exe, _:= os.Executable()
		cfg.PidfilePrefix = filepath.Base(exe)
	}

	// If we ARE the daemon child, set up graceful shutdown and run OnStart.
	if pidFile := os.Getenv(pidFileEnvVar); pidFile != "" {
		setupGracefulShutdown(pidFile, &cfg)
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
		return
	}

	// Parse control command out of os.Args.
	command, passArgs := parseArgs(os.Args[1:])

	pidFile, err := pidFilePath(cfg.PidfilePrefix)
	if err != nil {
		cfg.Logger.Fatalf("%s daemon: cannot determine PID file path: %v", cfg.AppName, err)
	}

	switch command {
	case "start":
		handleStart(pidFile, passArgs, &cfg)
	case "stop":
		handleStop(pidFile, &cfg)
	case "status":
		handleStatus(pidFile, &cfg)
	default:
		// No control command — run normally, attached to terminal.
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
	}
}

// ---- internal ---------------------------------------------------------------

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

// pidFilePath computes /tmp/rm-<md5(uid+cwd)>.pid
func pidFilePath(prefix string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	cwd, _ = filepath.Abs(cwd)
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	exe, _ = filepath.Abs(exe)
	uid := os.Getuid()
	raw := fmt.Sprintf("%d%s%s", uid, cwd, exe)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))
	return filepath.Join(os.TempDir(), prefix+"-"+hash+".pid"), nil
}

func handleStart(pidFile string, childArgs []string, cfg *Config) {
	// Check if already running.
	if pid, err := readPID(pidFile); err == nil {
		if processExists(pid) {
			fmt.Printf("%s already running (PID %d). Use 'stop' first.\n", cfg.AppName, pid)
			os.Exit(0)
		}
		// Stale PID file — remove it.
		os.Remove(pidFile)
	}

	exe, err := os.Executable()
	if err != nil {
		cfg.Logger.Fatalf("%s daemon: cannot find executable: %v", cfg.AppName, err)
	}
	exe, _ = filepath.Abs(exe)

	cmd := exec.Command(exe, childArgs...)
	cmd.Env = append(os.Environ(), pidFileEnvVar+"="+pidFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		cfg.Logger.Fatalf("%s daemon: failed to start child process: %v", cfg.AppName, err)
	}

	pid := cmd.Process.Pid
	if err := writePID(pidFile, pid); err != nil {
		cfg.Logger.Fatalf("%s daemon: failed to write PID file: %v", cfg.AppName, err)
	}
	cmd.Process.Release()

	fmt.Printf("%s daemon started (PID %d)\n", cfg.AppName, pid)
	//fmt.Printf("PID file: %s\n", pidFile)
}

func handleStop(pidFile string, cfg *Config) {
	pid, err := readPID(pidFile)
	if err != nil {
		fmt.Printf("%s instance is not running.\n", cfg.AppName)
		return
	}
	if !processExists(pid) {
		fmt.Printf("%s instance is not running.\nProcess did not exit gracefully. Cleaning up.\n", cfg.AppName)
		os.Remove(pidFile)
		return
	}

	proc, err := os.FindProcess(pid)

	// Send SIGTERM first (graceful), fall back to SIGKILL if needed.
	fmt.Printf("Sending SIGTERM to %s PID %d...\n", cfg.AppName, pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		cfg.Logger.Fatalf("%s daemon: failed to signal process: %v", cfg.AppName, err)
	}
	fmt.Println("Done.")
}

func handleStatus(pidFile string, cfg *Config) {
	pid, err := readPID(pidFile)
	if err != nil {
		fmt.Printf("Status: %s stopped\n", cfg.AppName)
		return
	}
	if processExists(pid) {
		fmt.Printf("Status: %s running (PID %d)\n", cfg.AppName, pid)
		//fmt.Printf("PID file: %s\n", pidFile)
	} else {
		fmt.Printf("Status: %s stopped\nBut process did not exit gracefully. Cleaning up.\n", cfg.AppName)
		os.Remove(pidFile)
	}
}

// setupGracefulShutdown registers SIGTERM/SIGINT handlers that delete the PID
// file before the process exits.
func setupGracefulShutdown(pidFile string, cfg *Config) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-ch
		cfg.Logger.Printf("%s daemon: received %s, shutting down...", cfg.AppName, sig)
		if err := os.Remove(pidFile); err == nil {
			//cfg.Logger.Printf("daemon: removed PID file %s", pidFile)
		}
		os.Exit(0)
	}()
}

func writePID(path string, pid int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644)
}

func readPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// processExists checks whether a process with the given PID is alive.
func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 checks existence without actually sending a signal.
	return proc.Signal(syscall.Signal(0)) == nil
}