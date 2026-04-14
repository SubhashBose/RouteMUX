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

	//HashKey to be used for the PID file. Default is current working directory
	HashKey string

	// WaitAfterStart is how long to wait after forking before confirming the
	// daemon is still alive. Defaults to 500ms.
	WaitAfterStart time.Duration

	// WatchdogRestartDelay is how long the watchdog waits before restarting a worker.
	// Defaults to 2s.
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
	if cfg.LoggerFile == "" {
		cfg.logger = log.Default()
	} else {
		f, err := os.OpenFile(cfg.LoggerFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			cfg.logger = log.New(f, "", log.LstdFlags)
			//cfg.logger.Printf("%s: started logging to %s", cfg.AppName, cfg.LoggerFile)
		}
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
	//if cfg.watchdogLogger == nil {
	//	cfg.watchdogLogger = cfg.logger
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
		cfg.pidFile = os.Getenv(pidFileEnvVar)
		cfg.AppName = cfg.AppName + " watchdog"
		runWatchdog(&cfg)
		return
	}

	// Role: plain daemon — set up graceful shutdown and run OnStart.
	if pidFile := os.Getenv(pidFileEnvVar); pidFile != "" {
		cfg.pidFile = pidFile
		setupGracefulShutdown(&cfg, nil)
		if cfg.OnStart != nil {
			cfg.OnStart()
		}
		return
	}

	// Role: parent — parse command and act.
	command, passArgs := parseArgs(os.Args[1:])

	pidFile, err := pidFilePath(cfg)
	cfg.pidFile = pidFile
	if err != nil {
		cfg.logger.Fatalf("%s daemon: cannot determine PID file path: %v", cfg.AppName, err)
	}

	switch command {
	case "start":
		handleStart(passArgs, &cfg)
	case "watch-start":
		handleWatchStart(passArgs, &cfg)
	case "stop":
		_ = handleStop(&cfg)
	case "restart":
		handleRestart(&cfg)
	case "status":
		handleStatus(&cfg)
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

func pidFilePath(cfg Config) (string, error) {
	if cfg.HashKey == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		cfg.HashKey, _ = filepath.Abs(cwd)
	}
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	exe, _ = filepath.Abs(exe)
	uid := os.Getuid()
	raw := fmt.Sprintf("%d%s%s", uid, cfg.HashKey, exe)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))
	return filepath.Join(os.TempDir(), cfg.PidfilePrefix+"-"+hash+".pid"), nil
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
		cfg.logger.Fatalf("%s: failed to fork process: %v", cfg.AppName, err)
	}

	pid := cmd.Process.Pid

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	select {
	case err := <-exited:
		if err != nil {
			cfg.logger.Fatalf("%s: process exited immediately: %v", cfg.AppName, err)
		} else {
			cfg.logger.Fatalf("%s: process exited immediately with no error", cfg.AppName)
		}
	case <-time.After(cfg.WaitAfterStart):
		// still alive
	}

	cmd.Process.Release()
	return pid
}

func handleStart(childArgs []string, cfg *Config) {
	if pid, _, err := readPID(cfg.pidFile); err == nil {
		if processExists(pid) {
			fmt.Printf("%s already running (PID %d). Use 'stop' first.\n", cfg.AppName, pid)
			os.Exit(0)
		}
		os.Remove(cfg.pidFile)
	}

	if wg_logf := getWatchdogLogfileName(cfg); cfg.LoggerFile != wg_logf && fileExists(wg_logf) {
		os.Remove(wg_logf)
	}

	exe, _ := filepath.Abs(mustExecutable())

	env := append(os.Environ(), pidFileEnvVar+"="+cfg.pidFile)
	pid := forkDaemon(exe, childArgs, env, cfg)

	if err := writePID(cfg.pidFile, pid, "start"); err != nil {
		cfg.logger.Fatalf("%s: failed to write PID file: %v", cfg.AppName, err)
	}
	fmt.Printf("%s daemon started (PID %d)\n", cfg.AppName, pid)
}

func handleWatchStart(childArgs []string, cfg *Config) {
	if pid, _, err := readPID(cfg.pidFile); err == nil {
		if processExists(pid) {
			fmt.Printf("%s already running (PID %d). Use 'stop' first.\n", cfg.AppName, pid)
			os.Exit(0)
		}
		os.Remove(cfg.pidFile)
	}

	if wg_logf := getWatchdogLogfileName(cfg); cfg.LoggerFile != wg_logf && fileExists(wg_logf) {
		os.Remove(wg_logf)
	}

	exe, _ := filepath.Abs(mustExecutable())

	env := append(os.Environ(),
		pidFileEnvVar+"="+cfg.pidFile,
		watchdogEnvVar+"=1",
	)
	pid := forkDaemon(exe, childArgs, env, cfg)

	if err := writePID(cfg.pidFile, pid, "watch-start"); err != nil {
		cfg.logger.Fatalf("%s: failed to write PID file: %v", cfg.AppName, err)
	}
	fmt.Printf("%s watchdog started (PID %d)\n", cfg.AppName, pid)
	fmt.Printf("Watchdog log: %s\n", getWatchdogLogfileName(cfg))
}

func getWatchdogLogfileName(cfg *Config) string {
	if cfg.WatchdogLoggerFile !="" {
		return cfg.WatchdogLoggerFile
	}
	if cfg.LoggerFile != "" {
		return cfg.LoggerFile
	}
	return strings.TrimSuffix(cfg.pidFile, ".pid") + "-watchdog.log"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// runWatchdog is the watchdog loop. It runs inside the detached watchdog process,
// repeatedly spawning the worker and restarting it if it crashes.
func runWatchdog(cfg *Config) {
	exe, _ := filepath.Abs(mustExecutable())

	if wg_logf := getWatchdogLogfileName(cfg); wg_logf != cfg.LoggerFile {
		cfg.WatchdogLoggerFile= wg_logf
		
        f, err := os.OpenFile(cfg.WatchdogLoggerFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err == nil {
            cfg.logger = log.New(f, "", log.LstdFlags)
			cfg.LoggerFile = cfg.WatchdogLoggerFile
            cfg.logger.Printf("%s: started logging to %s", cfg.AppName, cfg.WatchdogLoggerFile)
        }
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
	setupGracefulShutdown(cfg, &currentWorker)

	attempt := 0
	for {
		attempt++
		cfg.logger.Printf("%s: starting worker (attempt %d)", cfg.AppName, attempt)

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
			cfg.logger.Printf("%s: failed to create stdout pipe: %v", cfg.AppName, err)
		} else {
			go pipeToLogger(stdoutPipe, cfg.logger, "Worker [stdout]:")
		}

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			cfg.logger.Printf("%s: failed to create stderr pipe: %v", cfg.AppName, err)
		} else {
			go pipeToLogger(stderrPipe, cfg.logger, "Worker [stderr]:")
		}

		if err := cmd.Start(); err != nil {
			cfg.logger.Printf("%s: failed to start worker: %v — retrying in %s",
				cfg.AppName, err, cfg.WatchdogRestartDelay)
			time.Sleep(cfg.WatchdogRestartDelay)
			continue
		}

		currentWorker = cmd
		err = cmd.Wait() // blocks until worker exits
		currentWorker = nil

		if err != nil || cfg.RestartOnCleanExit {
			time.Sleep(10 * time.Millisecond)
			status_msg := "exited cleanly"
			if err != nil {
				status_msg = fmt.Sprintf("crashed (%v)", err)
			}
			cfg.logger.Printf("%s: worker %s — restarting in %s",
				cfg.AppName, status_msg, cfg.WatchdogRestartDelay)
			time.Sleep(cfg.WatchdogRestartDelay - 10 * time.Millisecond)
		} else {
			// Clean exit (exit code 0) means intentional stop — watchdog exits too.
			cfg.logger.Printf("%s: worker exited cleanly, shutting down", cfg.AppName)
			os.Remove(cfg.pidFile)
			os.Exit(0)
		}
	}
}

func handleStop(cfg *Config) bool {
	pid, _, err := readPID(cfg.pidFile)
	if err != nil {
		fmt.Printf("%s is not running.\n", cfg.AppName)
		return false
	}
	if !processExists(pid) {
		fmt.Printf("%s is not running (stale PID %d). Cleaning up.\n", cfg.AppName, pid)
		os.Remove(cfg.pidFile)
		return false
	}

	proc, _ := os.FindProcess(pid)
	fmt.Printf("Sending SIGTERM to %s (PID %d)...\n", cfg.AppName, pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		os.Remove(cfg.pidFile)
		cfg.logger.Fatalf("%s: failed to signal process: %v", cfg.AppName, err)
	}

	// Wait for the process to actually exit.
	for processExists(pid) {
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("Stopped.")
	return true
}

func handleRestart(cfg *Config) {
	_, mode, _ := readPID(cfg.pidFile)
    if mode == "" {
        mode = "start" // fallback
    }

	// Remember the args the running process was launched with so we can
	// restart it with the same flags.
	var passArgs []string
	if pid, _, err := readPID(cfg.pidFile); err == nil {
		if args, err := getProcessArgs(pid); err == nil {
			passArgs = args[1:]
		}
	}

	if handleStop(cfg) {
		cfg.WatchdogLoggerFile = getWatchdogLogfileName(cfg)+" " // making file nonexistent, tricking to not delete the file on restart
		switch mode {
        case "watch-start":
            handleWatchStart(passArgs, cfg)
        default:
            handleStart(passArgs, cfg)
        }
	}
}

func handleStatus(cfg *Config) {
	if wg_logf := getWatchdogLogfileName(cfg); fileExists(wg_logf) {
		fmt.Printf("Watchdog log: %s\n", wg_logf)
		tailFile(wg_logf, 10)
	} else if cfg.LoggerFile != "" {
		fmt.Printf("Log file: %s\n", cfg.LoggerFile)
		tailFile(cfg.LoggerFile, 10)
	}

	pid, mode, err := readPID(cfg.pidFile)
	if err != nil {
		fmt.Printf("Status: %s stopped\n", cfg.AppName)
		return
	}

	if mode == "watch-start" {
		mode = "watchdog"
	} else {
		mode = "daemon"
	}

	if processExists(pid) {
		fmt.Printf("Status: %s %s running (PID %d)\n", cfg.AppName, mode, pid)
		/*if args, err := getProcessArgs(pid); err == nil {
			fmt.Printf("Command: %s\n", strings.Join(args, " "))
		}*/
	} else {
		fmt.Printf("Status: %s stopped\nBut process did not exit gracefully. Cleaning up.\n", cfg.AppName)
		os.Remove(cfg.pidFile)
	}
}

// setupGracefulShutdown registers SIGTERM/SIGINT handlers that optionally
// forward the signal to a worker process, remove the PID file, and exit.
// workerCmd may be nil (plain daemon) or a pointer to the current worker cmd
// (watchdog) — the pointer itself is stable but the cmd it points to changes
// each restart, so the handler always signals the live worker.
func setupGracefulShutdown(cfg *Config, workerCmd **exec.Cmd) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-ch
		cfg.logger.Printf("%s: received %s, shutting down...", cfg.AppName, sig)
		if workerCmd != nil && *workerCmd != nil && (*workerCmd).Process != nil {
			cfg.logger.Printf("%s: forwarding %s to worker (PID %d)",
				cfg.AppName, sig, (*workerCmd).Process.Pid)
			(*workerCmd).Process.Signal(sig.(syscall.Signal))

			// Wait for worker to exit, but don't wait forever.
			workerDone := make(chan struct{}, 1)
			go func() {
				(*workerCmd).Wait()
				close(workerDone)
			}()

			select {
			case <-workerDone:
				cfg.logger.Printf("%s: worker exited cleanly", cfg.AppName)
			case <-time.After(10 * time.Second):
				cfg.logger.Printf("%s: worker did not exit in time, forcing kill", cfg.AppName)
				(*workerCmd).Process.Kill()
			}
		}
		os.Remove(cfg.pidFile)
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

func writePID(path string, pid int, mode string) error {
    return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"+mode+"\n"), 0644)
}

func readPID(path string) (int, string, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return 0, "", err
    }
    lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
    pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
    if err != nil {
        return 0, "", err
    }
    mode := "start" // default for old PID files that don't have mode
    if len(lines) > 1 {
        mode = strings.TrimSpace(lines[1])
    }
    return pid, mode, nil
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

func tailFile(path string, n int) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	// Get file size
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("could not stat file: %w", err)
	}
	fileSize := info.Size()

	// Scan backwards to find n newlines
	bufSize := int64(4096)
	linesFound := 0
	offset := fileSize
	var startPos int64

	for offset > 0 && linesFound <= n {
		if offset < bufSize {
			bufSize = offset
		}
		offset -= bufSize

		buf := make([]byte, bufSize)
		_, err := f.ReadAt(buf, offset)
		if err != nil {
			return fmt.Errorf("could not read file: %w", err)
		}

		for i := len(buf) - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				linesFound++
				if linesFound == n {
					startPos = offset + int64(i) + 1
					break
				}
			}
		}
	}

	// Seek to start position and print
	_, err = f.Seek(startPos, io.SeekStart)
	if err != nil {
		return fmt.Errorf("could not seek file: %w", err)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fmt.Println("  ", scanner.Text())
	}
	fmt.Println()

	return scanner.Err()
}