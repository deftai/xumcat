//go:build windows

package endpoint

import (
	"os"
	"os/exec"
	"syscall"
)

// shellCommand returns a command that runs command with cmd.exe (%ComSpec%):
//
//	cmd.exe /d /s /c "command"
//
// The command line is passed verbatim (SysProcAttr.CmdLine) rather than
// through exec.Command's argument quoting: cmd.exe does not parse its command
// line with the C runtime's rules, so quoting command as an argument would
// change it. With /s, cmd.exe strips the outer quotes and runs exactly what is
// between them. /d skips the AutoRun commands in the registry.
func shellCommand(command string) *exec.Cmd {
	shell := os.Getenv("ComSpec")
	if shell == "" {
		shell = "cmd.exe"
	}
	cmd := exec.Command(shell)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: syscall.EscapeArg(shell) + ` /d /s /c "` + command + `"`,
	}
	return cmd
}
