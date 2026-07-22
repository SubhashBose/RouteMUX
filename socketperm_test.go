package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseSocketPerm_Forms(t *testing.T) {
	tests := []struct {
		spec     string
		wantMode os.FileMode
		hasMode  bool
		wantUID  int
		wantGID  int
	}{
		{"", 0, false, -1, -1},
		{"660", 0o660, true, -1, -1},
		{"0660", 0o660, true, -1, -1},
		{"0600", 0o600, true, -1, -1},
		{"777", 0o777, true, -1, -1},
		// numeric user/group so the test doesn't depend on system accounts
		{"0660:1000", 0o660, true, 1000, -1},
		{"0660:1000:2000", 0o660, true, 1000, 2000},
		{"0660::2000", 0o660, true, -1, 2000},
		{":1000", 0, false, 1000, -1},
		{"::2000", 0, false, -1, 2000},
		{":1000:2000", 0, false, 1000, 2000},
	}
	for _, tt := range tests {
		sp, err := parseSocketPerm(tt.spec)
		if err != nil {
			t.Errorf("%q: unexpected error %v", tt.spec, err)
			continue
		}
		if sp.HasMode != tt.hasMode || (tt.hasMode && sp.Mode != tt.wantMode) {
			t.Errorf("%q: mode = %04o (has=%v), want %04o (has=%v)", tt.spec, sp.Mode, sp.HasMode, tt.wantMode, tt.hasMode)
		}
		if sp.UID != tt.wantUID {
			t.Errorf("%q: uid = %d, want %d", tt.spec, sp.UID, tt.wantUID)
		}
		if sp.GID != tt.wantGID {
			t.Errorf("%q: gid = %d, want %d", tt.spec, sp.GID, tt.wantGID)
		}
	}
}

func TestParseSocketPerm_ModeIsOctal(t *testing.T) {
	// "660" must be octal 0660 (rw-rw----), never decimal 660.
	sp, err := parseSocketPerm("660")
	if err != nil {
		t.Fatal(err)
	}
	if sp.Mode != 0o660 {
		t.Errorf("mode = %04o, want 0660 (octal interpretation)", sp.Mode)
	}
}

func TestParseSocketPerm_Errors(t *testing.T) {
	bad := []string{
		"999", // invalid octal digit
		"0660:no-such-user-xyz",
		"0660::no-such-group-xyz",
		"0660:a:b:c", // too many parts
		"abc",        // not a number
	}
	for _, spec := range bad {
		if _, err := parseSocketPerm(spec); err == nil {
			t.Errorf("%q: expected an error", spec)
		}
	}
}

func TestParseSocketPerm_IsSet(t *testing.T) {
	sp, _ := parseSocketPerm("")
	if sp.isSet() {
		t.Error("empty spec should not be 'set'")
	}
	sp, _ = parseSocketPerm("660")
	if !sp.isSet() {
		t.Error("mode-only spec should be 'set'")
	}
	sp, _ = parseSocketPerm("::2000")
	if !sp.isSet() {
		t.Error("group-only spec should be 'set'")
	}
}

// TestSocketPerm_AppliedToRealSocket verifies the mode actually lands on the
// socket file, independent of the process umask.
func TestSocketPerm_AppliedToRealSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	sp, err := parseSocketPerm("0660")
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.apply(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %04o, want 0660", got)
	}
}

func TestSocketPerm_NoSpecLeavesUmaskMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	before, _ := os.Stat(path)

	sp, _ := parseSocketPerm("")
	if err := sp.apply(path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Errorf("mode changed with empty spec: %04o -> %04o", before.Mode().Perm(), after.Mode().Perm())
	}
}

func TestCLI_SocketPermFlag(t *testing.T) {
	cfg, err := parseAll([]string{
		"--listen", "unix:/tmp/x.sock", "--socket-perm", "0660::" + strconv.Itoa(os.Getgid()),
		"--route", "/", "--dest", "http://x/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SocketPerm == nil || !cfg.SocketPerm.HasMode || cfg.SocketPerm.Mode != 0o660 {
		t.Errorf("SocketPerm not parsed from CLI: %+v", cfg.SocketPerm)
	}
	if cfg.SocketPerm.GID != os.Getgid() {
		t.Errorf("gid = %d, want %d", cfg.SocketPerm.GID, os.Getgid())
	}
	if cfg.SocketPerm.UID != -1 {
		t.Errorf("uid should be unset, got %d", cfg.SocketPerm.UID)
	}
}

func TestCLI_SocketPermInvalid(t *testing.T) {
	if _, err := parseAll([]string{"--socket-perm", "abc", "--route", "/", "--dest", "http://x/"}); err == nil {
		t.Error("invalid --socket-perm should error")
	}
}

func TestYAML_SocketPerm(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	os.WriteFile(p, []byte(fmt.Sprintf(`
global:
  listen: unix:/tmp/x.sock
  socket-perm: "0660::%d"
  port: 8080
vhosts:
  - domains: ["*"]
    routes:
      /: {dest: "http://localhost:1/"}
`, os.Getgid())), 0o644)
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SocketPerm == nil || cfg.SocketPerm.Mode != 0o660 || cfg.SocketPerm.GID != os.Getgid() {
		t.Errorf("YAML socket-perm not parsed: %+v", cfg.SocketPerm)
	}
}

func TestYAML_SocketPermInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	os.WriteFile(p, []byte(`
global:
  socket-perm: "not-a-mode"
  port: 8080
vhosts:
  - domains: ["*"]
    routes:
      /: {dest: "http://localhost:1/"}
`), 0o644)
	if _, err := loadConfigFile(p); err == nil {
		t.Error("invalid socket-perm in YAML should error at load")
	}
}

func TestReload_SocketPermRequiresRestart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	write := func(perm string) {
		os.WriteFile(p, []byte(fmt.Sprintf(`
global:
  port: 8080
  socket-perm: "%s"
vhosts:
  - domains: ["*"]
    routes:
      /: {dest: "http://localhost:1/"}
`, perm)), 0o644)
	}
	write("0660")
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConfigPath = p
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Change socket-perm and reload: it must be reverted, not applied.
	write("0600")
	srv.Reload(true)
	if got := srv.state.Load().cfg.SocketPerm; got == nil || got.Mode != 0o660 {
		t.Errorf("socket-perm should be reverted to 0660 on reload, got %+v", got)
	}
}