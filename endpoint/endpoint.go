// Package endpoint parses and opens the socat-style endpoint addresses
// shared by xumcat and the pipe/1 profile:
//
//	tcp:host:port        TCP connect
//	tcp-listen:[host:]port  TCP listen
//	tls:host:port        TLS connect
//	unix:/path           Unix-socket connect
//	unix-listen:/path    Unix-socket listen
//	stdio                this process's stdin/stdout
//	exec:command args…   run a command (via sh -c, or cmd.exe /c on Windows)
//	                     and use its stdin/stdout
package endpoint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Conn is a bidirectional byte stream that can half-close.
type Conn interface {
	io.ReadWriteCloser
	// CloseWrite signals EOF to the other end; reading continues.
	CloseWrite() error
}

// Address is a parsed endpoint address.
type Address struct {
	Kind    string // tcp, tcp-listen, tls, unix, unix-listen, stdio, exec
	Host    string
	Port    string
	Path    string
	Command string
}

// String returns the canonical form of the address.
func (a Address) String() string {
	switch a.Kind {
	case "tcp", "tls":
		return a.Kind + ":" + net.JoinHostPort(a.Host, a.Port)
	case "tcp-listen":
		if a.Host == "" {
			return a.Kind + ":" + a.Port
		}
		return a.Kind + ":" + net.JoinHostPort(a.Host, a.Port)
	case "unix", "unix-listen":
		return a.Kind + ":" + a.Path
	case "exec":
		return "exec:" + a.Command
	default:
		return a.Kind
	}
}

// IsListen reports whether the address accepts connections.
func (a Address) IsListen() bool { return strings.HasSuffix(a.Kind, "-listen") }

// Parse parses an endpoint address.
func Parse(s string) (Address, error) {
	if s == "stdio" || s == "-" {
		return Address{Kind: "stdio"}, nil
	}
	kind, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Address{}, fmt.Errorf("endpoint %q: expected kind:address", s)
	}
	a := Address{Kind: kind}
	var err error
	switch kind {
	case "tcp", "tls":
		a.Host, a.Port, err = net.SplitHostPort(rest)
		if err == nil && (a.Host == "" || a.Port == "") {
			err = errors.New("need host:port")
		}
	case "tcp-listen":
		if !strings.Contains(rest, ":") {
			a.Port = rest
		} else {
			a.Host, a.Port, err = net.SplitHostPort(rest)
		}
		if err == nil && a.Port == "" {
			err = errors.New("need a port")
		}
	case "unix", "unix-listen":
		a.Path = rest
		if rest == "" {
			err = errors.New("need a path")
		}
	case "exec":
		a.Command = strings.TrimSpace(rest)
		if a.Command == "" {
			err = errors.New("need a command")
		}
	default:
		err = errors.New("unknown kind (want tcp, tcp-listen, tls, unix, unix-listen, stdio or exec)")
	}
	if err != nil {
		return Address{}, fmt.Errorf("endpoint %q: %w", s, err)
	}
	return a, nil
}

// Options configure Dial and Listen.
type Options struct {
	// TLS is used for tls: addresses. ServerName defaults to the host.
	TLS *tls.Config
	// Stderr receives exec: commands' stderr (default os.Stderr).
	Stderr io.Writer
}

// Dial opens a connecting address (tcp, tls, unix, stdio, exec).
func Dial(ctx context.Context, addr string, o Options) (Conn, error) {
	a, err := Parse(addr)
	if err != nil {
		return nil, err
	}
	return DialAddress(ctx, a, o)
}

// DialAddress is Dial for a parsed address.
func DialAddress(ctx context.Context, a Address, o Options) (Conn, error) {
	var d net.Dialer
	switch a.Kind {
	case "tcp":
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.Host, a.Port))
		if err != nil {
			return nil, err
		}
		return c.(*net.TCPConn), nil
	case "tls":
		cfg := &tls.Config{}
		if o.TLS != nil {
			cfg = o.TLS.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = a.Host
		}
		td := tls.Dialer{NetDialer: &d, Config: cfg}
		c, err := td.DialContext(ctx, "tcp", net.JoinHostPort(a.Host, a.Port))
		if err != nil {
			return nil, err
		}
		return c.(*tls.Conn), nil
	case "unix":
		c, err := d.DialContext(ctx, "unix", a.Path)
		if err != nil {
			return nil, err
		}
		return c.(*net.UnixConn), nil
	case "stdio":
		return Stdio(), nil
	case "exec":
		return Exec(ctx, a.Command, o.Stderr)
	default:
		return nil, fmt.Errorf("endpoint %s: cannot dial a listening address", a)
	}
}

// Listener accepts connections on a listening address.
type Listener interface {
	Accept() (Conn, error)
	Close() error
	Addr() net.Addr
}

type netListener struct {
	net.Listener
	cleanup func()
}

func (l netListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return c.(Conn), nil
}

func (l netListener) Close() error {
	err := l.Listener.Close()
	if l.cleanup != nil {
		l.cleanup()
	}
	return err
}

// Listen opens a listening address (tcp-listen, unix-listen).
func Listen(addr string) (Listener, error) {
	a, err := Parse(addr)
	if err != nil {
		return nil, err
	}
	switch a.Kind {
	case "tcp-listen":
		l, err := net.Listen("tcp", net.JoinHostPort(a.Host, a.Port))
		if err != nil {
			return nil, err
		}
		return netListener{Listener: l}, nil
	case "unix-listen":
		l, err := ListenUnix(a.Path)
		if err != nil {
			return nil, err
		}
		return netListener{Listener: l}, nil
	default:
		return nil, fmt.Errorf("endpoint %s: not a listening address", a)
	}
}

// ListenUnix listens on a Unix socket, replacing a stale socket file.
func ListenUnix(p string) (net.Listener, error) {
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
		if c, err := net.DialTimeout("unix", p, 100*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("unix socket %s is in use", p)
		}
		os.Remove(p)
	}
	l, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	l.(*net.UnixListener).SetUnlinkOnClose(true)
	return l, nil
}

// ─── stdio ──────────────────────────────────────────────────────────────────

type stdioConn struct {
	once sync.Once
}

// Stdio returns this process's stdin/stdout as a Conn. CloseWrite closes stdout.
func Stdio() Conn { return &stdioConn{} }

func (*stdioConn) Read(b []byte) (int, error)  { return os.Stdin.Read(b) }
func (*stdioConn) Write(b []byte) (int, error) { return os.Stdout.Write(b) }
func (c *stdioConn) CloseWrite() error {
	var err error
	c.once.Do(func() { err = os.Stdout.Close() })
	return err
}
func (c *stdioConn) Close() error { return c.CloseWrite() }

// ─── exec ───────────────────────────────────────────────────────────────────

type execConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	once   sync.Once
	waited chan struct{}
}

// Exec runs command with sh -c (on Windows, cmd.exe /d /s /c) and connects
// to its stdin and stdout.
// CloseWrite closes its stdin; Close also waits briefly for it to exit,
// then kills it.
func Exec(ctx context.Context, command string, stderr io.Writer) (Conn, error) {
	cmd := shellCommand(command)
	if stderr == nil {
		stderr = os.Stderr
	}
	cmd.Stderr = stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &execConn{cmd: cmd, stdin: in, stdout: out, waited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(c.waited)
	}()
	return c, nil
}

func (c *execConn) Read(b []byte) (int, error)  { return c.stdout.Read(b) }
func (c *execConn) Write(b []byte) (int, error) { return c.stdin.Write(b) }
func (c *execConn) CloseWrite() error           { return c.stdin.Close() }

func (c *execConn) Close() error {
	c.once.Do(func() {
		c.stdin.Close()
		select {
		case <-c.waited:
		case <-time.After(2 * time.Second):
			_ = c.cmd.Process.Kill()
			<-c.waited
		}
	})
	return nil
}
