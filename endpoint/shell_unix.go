//go:build !windows

package endpoint

import "os/exec"

// shellCommand returns a command that runs command with sh -c.
func shellCommand(command string) *exec.Cmd {
	return exec.Command("sh", "-c", command)
}
