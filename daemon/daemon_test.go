package daemon

import "testing"

// parseArgs is in daemon_unix.go (build tag !windows) and daemon_windows.go.
// These tests run on the current platform.


// ---- daemon parseArgs tests ----

func TestParseArgs_Start(t *testing.T) {
	cmd, rest := parseArgs([]string{"--port", "8080", "start"})
	if cmd != "start" {
		t.Errorf("command = %q, want start", cmd)
	}
	if len(rest) != 2 || rest[0] != "--port" || rest[1] != "8080" {
		t.Errorf("rest = %v, want [--port 8080]", rest)
	}
}

func TestParseArgs_Stop(t *testing.T) {
	cmd, rest := parseArgs([]string{"stop"})
	if cmd != "stop" {
		t.Errorf("command = %q, want stop", cmd)
	}
	if len(rest) != 0 {
		t.Errorf("rest should be empty, got %v", rest)
	}
}

func TestParseArgs_Status(t *testing.T) {
	cmd, rest := parseArgs([]string{"--config", "cfg.yml", "status"})
	if cmd != "status" {
		t.Errorf("command = %q, want status", cmd)
	}
	if len(rest) != 2 {
		t.Errorf("rest = %v, want [--config cfg.yml]", rest)
	}
}

func TestParseArgs_Restart(t *testing.T) {
	cmd, rest := parseArgs([]string{"--port", "443", "restart"})
	if cmd != "restart" {
		t.Errorf("command = %q, want restart", cmd)
	}
	if len(rest) != 2 || rest[0] != "--port" || rest[1] != "443" {
		t.Errorf("rest = %v, want [--port 443]", rest)
	}
}

func TestParseArgs_NoCommand(t *testing.T) {
	cmd, rest := parseArgs([]string{"--port", "8080", "--config", "c.yml"})
	if cmd != "" {
		t.Errorf("command should be empty for no daemon command, got %q", cmd)
	}
	if len(rest) != 4 {
		t.Errorf("rest = %v, should be unchanged original args", rest)
	}
}

func TestParseArgs_CommandInMiddle(t *testing.T) {
	// parseArgs scans right-to-left — last occurrence of command word wins
	cmd, rest := parseArgs([]string{"--port", "8080", "start", "--config", "cfg.yml"})
	if cmd != "start" {
		t.Errorf("command = %q, want start", cmd)
	}
	// "start" stripped, rest preserves original order minus "start"
	if len(rest) != 4 {
		t.Errorf("rest = %v", rest)
	}
}

func TestParseArgs_Empty(t *testing.T) {
	cmd, rest := parseArgs([]string{})
	if cmd != "" {
		t.Errorf("empty args: command should be empty, got %q", cmd)
	}
	if len(rest) != 0 {
		t.Errorf("empty args: rest should be empty, got %v", rest)
	}
}