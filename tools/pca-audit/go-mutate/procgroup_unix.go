//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// the test run is its own process group so a timeout kills go test AND the test binary it spawned
func setProcessGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killProcessGroup(c *exec.Cmd) { syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
