//go:build !windows

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
	"time"
	"bufio"
	"io"
)

const DAEMONIZE_SUPPORTED = true

const pidFileEnvVar  = "DAEMON_PID_FILE"
const watchdogEnvVar = "DAEMON_IS_WATCHDOG"
const workerEnvVar   = "DAEMON_IS_WORKER"

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

	// WaitAfterStart is how long to wait after forking before confirming the
	// daemon is still alive. Defaults to 500ms.
	WaitAfterStart time.Duration

	// WatchdogRestartDelay is how long the watchdog waits before restarting a
	// crashed worker. Defaults to 2s.
	WatchdogRestartDelay time.Duration

	// Logger is used for daemon-internal messages. Defaults to log.Default().
	Logger *log.Logger

	// WatchdogLogFile is the path to the watchdog log file.
    // Defaults to same as Logger if it is set, otherwise same as PID-file basename with "-watchdog.log".
	WatchdogLogger *log.Logger
}

// Handle inspects os.Args for control commands and acts accordingly.
//
// Commands:
//
//	./myapp [flags] start        — daemonize; child runs with [flags] only
//	./myapp [flags] watch-start  — daemonize with watchdog auto-restart
//	./myapp [flags] stop         — kill the running daemon or watchdog
//	./myapp [flags] restart      — stop then start again
//	./myapp [flags] status       — print whether the daemon is running
//	./myapp [flags]              — run attached to the terminal (no daemonizing)
func Handle(cfg Config) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.AppName == "" {
		exe, _ := os.Executable()
		cfg.AppName = filepath.Base(exe)
	}
	if cfg.PidfilePrefix == "" {
		exe, _ := os.Executable()
		cfg.PidfilePrefix = filepath.Base(exe)
	}
	if cfg.WaitAfterStart == 0 {
		cfg.WaitAfterStart = 500 * time.Millisecond
	}
	if cfg.WatchdogRestartDelay == 0 {
		cfg.WatchdogRestartDelay = 2 * time.Second
	}
	//if cfg.WatchdogLogger == nil {
	//	cfg.WatchdogLogger = cfg.Logger
	//}

	// Role: plain worker (child of watchdog) — just run OnStart, no PID file handling.
	if os.Getenv(workerEnvVar) == "1" {
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
		return
	}

	// Role: watchdog daemon — monitor and restart the worker.
	if os.Getenv(watchdogEnvVar) == "1" {
		pidFile := os.Getenv(pidFileEnvVar)
		cfg.AppName = cfg.AppName + " watchdog"
		runWatchdog(pidFile, &cfg)
		return
	}

	// Role: plain daemon — set up graceful shutdown and run OnStart.
	if pidFile := os.Getenv(pidFileEnvVar); pidFile != "" {
		setupGracefulShutdown(pidFile, &cfg, nil)
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
		return
	}

	// Role: parent — parse command and act.
	command, passArgs := parseArgs(os.Args[1:])

	pidFile, err := pidFilePath(cfg.PidfilePrefix)
	if err != nil {
		cfg.Logger.Fatalf("%s daemon: cannot determine PID file path: %v", cfg.AppName, err)
	}

	switch command {
	case "start":
		handleStart(pidFile, passArgs, &cfg)
	case "watch-start":
		handleWatchStart(pidFile, passArgs, &cfg)
	case "stop":
		_ = handleStop(pidFile, &cfg)
	case "restart":
		handleRestart(pidFile, &cfg)
	case "status":
		handleStatus(pidFile, &cfg)
	default:
		// No control command — run normally attached to terminal.
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
	}
}

// ---- internal ---------------------------------------------------------------

func parseArgs(args []string) (command string, rest []string) {
	for i := len(args) - 1; i >= 0; i-- {
		switch args[i] {
		case "start", "watch-start", "stop", "restart", "status":
			rest = make([]string, 0, len(args)-1)
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return args[i], rest
		}
	}
	return "", args
}

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

// forkDaemon launches exe with the given args and env as a detached daemon.
// It waits up to cfg.WaitAfterStart to confirm it didn't crash immediately.
// Returns the PID of the started process.
func forkDaemon(exe string, args []string, env []string, cfg *Config) int {
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from terminal
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		cfg.Logger.Fatalf("%s: failed to fork process: %v", cfg.AppName, err)
	}

	pid := cmd.Process.Pid

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	select {
	case err := <-exited:
		if err != nil {
			cfg.Logger.Fatalf("%s: process exited immediately: %v", cfg.AppName, err)
		} else {
			cfg.Logger.Fatalf("%s: process exited immediately with no error", cfg.AppName)
		}
	case <-time.After(cfg.WaitAfterStart):
		// still alive
	}

	cmd.Process.Release()
	return pid
}

func handleStart(pidFile string, childArgs []string, cfg *Config) {
	if pid, err := readPID(pidFile); err == nil {
		if processExists(pid) {
			fmt.Printf("%s already running (PID %d). Use 'stop' first.\n", cfg.AppName, pid)
			os.Exit(0)
		}
		os.Remove(pidFile)
	}

	exe, _ := filepath.Abs(mustExecutable())

	env := append(os.Environ(), pidFileEnvVar+"="+pidFile)
	pid := forkDaemon(exe, childArgs, env, cfg)

	if err := writePID(pidFile, pid); err != nil {
		cfg.Logger.Fatalf("%s: failed to write PID file: %v", cfg.AppName, err)
	}
	fmt.Printf("%s daemon started (PID %d)\n", cfg.AppName, pid)
}

func handleWatchStart(pidFile string, childArgs []string, cfg *Config) {
	if pid, err := readPID(pidFile); err == nil {
		if processExists(pid) {
			fmt.Printf("%s already running (PID %d). Use 'stop' first.\n", cfg.AppName, pid)
			os.Exit(0)
		}
		os.Remove(pidFile)
	}

	exe, _ := filepath.Abs(mustExecutable())

	env := append(os.Environ(),
		pidFileEnvVar+"="+pidFile,
		watchdogEnvVar+"=1",
	)
	pid := forkDaemon(exe, childArgs, env, cfg)

	if err := writePID(pidFile, pid); err != nil {
		cfg.Logger.Fatalf("%s: failed to write PID file: %v", cfg.AppName, err)
	}
	fmt.Printf("%s watchdog started (PID %d)\n", cfg.AppName, pid)
	if cfg.WatchdogLogger == nil {
		fmt.Printf("Watchdog log: %s\n", strings.TrimSuffix(pidFile, ".pid") + "-watchdog.log")
	}
}

// runWatchdog is the watchdog loop. It runs inside the detached watchdog process,
// repeatedly spawning the worker and restarting it if it crashes.
func runWatchdog(pidFile string, cfg *Config) {
	exe, _ := filepath.Abs(mustExecutable())

	if cfg.WatchdogLogger == nil {
		wg_logfile:= strings.TrimSuffix(pidFile, ".pid") + "-watchdog.log"
		
        f, err := os.OpenFile(wg_logfile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
        if err == nil {
            cfg.Logger = log.New(f, "", log.LstdFlags)
            cfg.Logger.Printf("%s: started logging to %s", cfg.AppName, wg_logfile)
        }
    } else {
		cfg.Logger=cfg.WatchdogLogger
	}

	// Build a clean env for the worker: strip watchdog/pidfile markers, add worker marker.
	baseEnv := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, watchdogEnvVar+"=") ||
			strings.HasPrefix(e, pidFileEnvVar+"=") {
			continue
		}
		baseEnv = append(baseEnv, e)
	}
	workerEnv := append(baseEnv, workerEnvVar+"=1")

	// currentWorker is updated each restart so the signal handler can always
	// reach the live worker process.
	var currentWorker *exec.Cmd
	setupGracefulShutdown(pidFile, cfg, &currentWorker)

	attempt := 0
	for {
		attempt++
		cfg.Logger.Printf("%s: starting worker (attempt %d)", cfg.AppName, attempt)

		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Env = workerEnv
		// No Setsid — worker is a plain child of the watchdog.
		cmd.Stdin = nil
		//cmd.Stdout = nil
		//cmd.Stderr = nil

		// pipeToLogger connects an io.Reader to a logger, prefixing each line.
		pipeToLogger := func(r io.Reader, logger *log.Logger, prefix string) {
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				logger.Printf("%s %s", prefix, scanner.Text())
			}
		}
		// Connect stdout and stderr pipes to the logger
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			cfg.Logger.Printf("%s: failed to create stdout pipe: %v", cfg.AppName, err)
		} else {
			go pipeToLogger(stdoutPipe, cfg.Logger, "[stdout]")
		}

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			cfg.Logger.Printf("%s: failed to create stderr pipe: %v", cfg.AppName, err)
		} else {
			go pipeToLogger(stderrPipe, cfg.Logger, "[stderr]")
		}

		if err := cmd.Start(); err != nil {
			cfg.Logger.Printf("%s: failed to start worker: %v — retrying in %s",
				cfg.AppName, err, cfg.WatchdogRestartDelay)
			time.Sleep(cfg.WatchdogRestartDelay)
			continue
		}

		currentWorker = cmd
		err = cmd.Wait() // blocks until worker exits
		currentWorker = nil

		if err != nil {
			cfg.Logger.Printf("%s: worker crashed (%v) — restarting in %s",
				cfg.AppName, err, cfg.WatchdogRestartDelay)
			time.Sleep(cfg.WatchdogRestartDelay)
		} else {
			// Clean exit (exit code 0) means intentional stop — watchdog exits too.
			cfg.Logger.Printf("%s: worker exited cleanly, shutting down", cfg.AppName)
			os.Remove(pidFile)
			os.Exit(0)
		}
	}
}

func handleStop(pidFile string, cfg *Config) bool {
	pid, err := readPID(pidFile)
	if err != nil {
		fmt.Printf("%s is not running.\n", cfg.AppName)
		return false
	}
	if !processExists(pid) {
		fmt.Printf("%s is not running (stale PID %d). Cleaning up.\n", cfg.AppName, pid)
		os.Remove(pidFile)
		return false
	}

	proc, _ := os.FindProcess(pid)
	fmt.Printf("Sending SIGTERM to %s (PID %d)...\n", cfg.AppName, pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		os.Remove(pidFile)
		cfg.Logger.Fatalf("%s: failed to signal process: %v", cfg.AppName, err)
	}

	// Wait for the process to actually exit.
	for processExists(pid) {
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("Stopped.")
	return true
}

func handleRestart(pidFile string, cfg *Config) {
	// Remember the args the running process was launched with so we can
	// restart it with the same flags.
	var passArgs []string
	if pid, err := readPID(pidFile); err == nil {
		if args, err := getProcessArgs(pid); err == nil {
			passArgs = args[1:]
		}
	}

	if handleStop(pidFile, cfg) {
		handleStart(pidFile, passArgs, cfg)
	}
}

func handleStatus(pidFile string, cfg *Config) {
	pid, err := readPID(pidFile)
	if err != nil {
		fmt.Printf("Status: %s stopped\n", cfg.AppName)
		return
	}
	if processExists(pid) {
		fmt.Printf("Status: %s running (PID %d)\n", cfg.AppName, pid)
		/*if args, err := getProcessArgs(pid); err == nil {
			fmt.Printf("Command: %s\n", strings.Join(args, " "))
		}*/
	} else {
		fmt.Printf("Status: %s stopped\nBut process did not exit gracefully. Cleaning up.\n", cfg.AppName)
		os.Remove(pidFile)
	}
}

// setupGracefulShutdown registers SIGTERM/SIGINT handlers that optionally
// forward the signal to a worker process, remove the PID file, and exit.
// workerCmd may be nil (plain daemon) or a pointer to the current worker cmd
// (watchdog) — the pointer itself is stable but the cmd it points to changes
// each restart, so the handler always signals the live worker.
func setupGracefulShutdown(pidFile string, cfg *Config, workerCmd **exec.Cmd) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-ch
		cfg.Logger.Printf("%s: received %s, shutting down...", cfg.AppName, sig)
		if workerCmd != nil && *workerCmd != nil && (*workerCmd).Process != nil {
			cfg.Logger.Printf("%s watchdog: forwarding %s to worker (PID %d)",
				cfg.AppName, sig, (*workerCmd).Process.Pid)
			(*workerCmd).Process.Signal(sig.(syscall.Signal))
		}
		os.Remove(pidFile)
		os.Exit(0)
	}()
}

// ---- helpers ----------------------------------------------------------------

func mustExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot determine executable path: %v", err)
	}
	return exe
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

func getProcessArgs(pid int) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return nil, fmt.Errorf("process %d has no cmdline", pid)
	}
	return strings.Split(trimmed, "\x00"), nil
}