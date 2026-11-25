//go:build windows

package main

import (
	"os/exec"
	"strconv"
)

// Windows has no process groups or SIGKILL: taskkill /T /F ends go test and the whole tree below it (the test binary) with TerminateProcess.
func setProcessGroup(*exec.Cmd) {}

func killProcessGroup(c *exec.Cmd) {
	exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(c.Process.Pid)).Run()
	c.Process.Kill()
}
