//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// reraiseSignal restores the default signal handler and re-sends the signal
// to this process, causing it to die with the conventional exit code:
// 130 (128+SIGINT) for Ctrl+C, or 143 (128+SIGTERM) for kill/daemon stop.
//
// syscall.Kill is asynchronous, so we block on select{} until the signal lands.
func reraiseSignal(sig os.Signal) {
	signal.Reset(sig.(syscall.Signal))
	syscall.Kill(os.Getpid(), sig.(syscall.Signal)) //nolint:errcheck
	select {}                                        // block until signal is delivered
}