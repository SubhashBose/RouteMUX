//go:build windows

package main

import "os"

// reraiseSignal is a no-op on Windows. syscall.Kill does not exist on Windows,
// and the conventional Unix signal exit codes (130, 143) have no equivalent.
// The process exits with code 0 after a clean shutdown.
func reraiseSignal(sig os.Signal) {}