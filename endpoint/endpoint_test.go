package endpoint

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deftai/xumcat/internal/testcert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in, canon string
		listen    bool
		wantErr   bool
	}{
		{"tcp:localhost:22", "tcp:localhost:22", false, false},
		{"tcp:[::1]:22", "tcp:[::1]:22", false, false},
		{"tls:example.com:443", "tls:example.com:443", false, false},
		{"tcp-listen:8080", "tcp-listen:8080", true, false},
		{"tcp-listen:127.0.0.1:8080", "tcp-listen:127.0.0.1:8080", true, false},
		{"unix:/run/x.sock", "unix:/run/x.sock", false, false},
		{"unix-listen:/run/x.sock", "unix-listen:/run/x.sock", true, false},
		{"stdio", "stdio", false, false},
		{"-", "stdio", false, false},
		{"exec: cat -u ", "exec:cat -u", false, false},
		{"tcp:22", "", false, true},
		{"tcp::22", "", false, true},
		{"tcp-listen:", "", false, true},
		{"unix:", "", false, true},
		{"exec:", "", false, true},
		{"ftp:x", "", false, true},
		{"nonsense", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			a, err := Parse(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.canon, a.String())
			assert.Equal(t, tt.listen, a.IsListen())
		})
	}
}

func TestMatch(t *testing.T) {
	pathStyle(t, false)
	allow := []string{"tcp:localhost:*", "unix:/run/app/*.sock", "exec:cat"}
	assert.True(t, Match(allow, "tcp:localhost:22"))
	assert.False(t, Match(allow, "tcp:evil.com:22"))
	assert.True(t, Match(allow, "unix:/run/app/a.sock"))
	assert.False(t, Match(allow, "unix:/run/app/sub/a.sock"))
	assert.True(t, Match(allow, "exec:cat"))
	assert.False(t, Match(allow, "exec:cat /etc/passwd"))
	assert.False(t, Match(allow, "tcp-listen:22"), "listening targets are never allowed")
	assert.False(t, Match(allow, "garbage"))
}

func echoServer(t *testing.T, l net.Listener) {
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.(interface{ CloseWrite() error }).CloseWrite()
			}()
		}
	}()
}

func roundTrip(t *testing.T, c Conn) {
	t.Helper()
	go func() {
		c.Write([]byte("hello"))
		c.CloseWrite()
	}()
	b, err := io.ReadAll(c)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(b))
	c.Close()
}

func TestDialAndListen(t *testing.T) {
	l, err := Listen("tcp-listen:127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	echoServer(t, netListener{}.unwrap(l))
	c, err := Dial(context.Background(), "tcp:"+l.Addr().String(), Options{})
	require.NoError(t, err)
	roundTrip(t, c)

	sock := filepath.Join(t.TempDir(), "e.sock")
	ul, err := Listen("unix-listen:" + sock)
	require.NoError(t, err)
	echoServer(t, netListener{}.unwrap(ul))
	_, err = ListenUnix(sock)
	assert.ErrorContains(t, err, "in use")
	c, err = Dial(context.Background(), "unix:"+sock, Options{})
	require.NoError(t, err)
	roundTrip(t, c)
	ul.Close()

	_, err = Dial(context.Background(), "tcp-listen:1", Options{})
	assert.Error(t, err)
	_, err = Listen("tcp:localhost:1")
	assert.Error(t, err)
	_, err = Dial(context.Background(), "tcp:127.0.0.1:1", Options{})
	assert.Error(t, err)
}

func (netListener) unwrap(l Listener) net.Listener { return l.(netListener).Listener }

func TestStaleUnixSocketIsReplaced(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	_, err = os.Lstat(sock)
	require.NoError(t, err, "stale socket file left behind")
	l2, err := ListenUnix(sock)
	require.NoError(t, err)
	l2.Close()
}

func TestDialTLS(t *testing.T) {
	srvCfg, cliCfg := testcert.New()
	l, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.(*tls.Conn).CloseWrite()
			}()
		}
	}()
	c, err := Dial(context.Background(), "tls:"+l.Addr().String(), Options{TLS: cliCfg})
	require.NoError(t, err)
	roundTrip(t, c)
	_, err = Dial(context.Background(), "tls:"+l.Addr().String(), Options{})
	assert.Error(t, err, "untrusted certificate")
}

// TestMain lets exec: tests run this test binary as a portable stand-in for
// cat and sleep, so they need no Unix tools on Windows.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "xumcat-helper-cat":
			io.Copy(os.Stdout, os.Stdin)
			os.Exit(0)
		case "xumcat-helper-args":
			fmt.Print(strings.Join(os.Args[2:], "|"))
			os.Exit(0)
		case "xumcat-helper-sleep":
			time.Sleep(10 * time.Second)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// helper returns a shell command that runs this test binary in a helper mode.
func helper(t *testing.T, mode string) string {
	exe, err := os.Executable()
	require.NoError(t, err)
	return `"` + exe + `" xumcat-helper-` + mode
}

func TestExec(t *testing.T) {
	var stderr bytes.Buffer
	toStderr := "; echo done >&2"
	if runtime.GOOS == "windows" {
		toStderr = " & >&2 echo done"
	}
	c, err := Dial(context.Background(), "exec:"+helper(t, "cat")+toStderr, Options{Stderr: &stderr})
	require.NoError(t, err)
	roundTrip(t, c)
	assert.Equal(t, "done", strings.TrimSpace(stderr.String()), "the command runs through the shell")

	c, err = Exec(context.Background(), helper(t, "sleep"), nil)
	require.NoError(t, err)
	start := time.Now()
	c.Close()
	assert.Less(t, time.Since(start), 4*time.Second, "a command that ignores EOF is killed")
}

// The command reaches the shell unchanged: quoted arguments keep their
// spaces (with cmd.exe this relies on /s and a verbatim command line).
func TestExecQuoting(t *testing.T) {
	c, err := Exec(context.Background(), helper(t, "args")+` a "b c" "" d`, nil)
	require.NoError(t, err)
	c.CloseWrite()
	b, err := io.ReadAll(c)
	require.NoError(t, err)
	c.Close()
	assert.Equal(t, "a|b c||d", string(b))
}

func TestExecUnixShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec: runs through cmd.exe on Windows")
	}
	c, err := Exec(context.Background(), `printf '%s' "$0"`, nil)
	require.NoError(t, err)
	b, err := io.ReadAll(c)
	require.NoError(t, err)
	c.Close()
	assert.Equal(t, "sh", string(b), "Unix commands still run under sh -c")
}

func TestExecWindowsShell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe is Windows-only")
	}
	t.Setenv("XUMCAT_TEST_VAR", "from-cmd")
	c, err := Exec(context.Background(), "echo %XUMCAT_TEST_VAR%", nil)
	require.NoError(t, err)
	b, err := io.ReadAll(c)
	require.NoError(t, err)
	c.Close()
	assert.Equal(t, "from-cmd", strings.TrimSpace(string(b)), "the command runs under cmd.exe")
}

func TestStdioConn(t *testing.T) {
	assert.NotNil(t, Stdio())
}
