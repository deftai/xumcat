package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	xumux "github.com/deftai/libxumux-go"
	"github.com/deftai/xumcat/pipe"
	"github.com/deftai/xumcat/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func echo(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return l.Addr().String()
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().String()
}

func startServe(t *testing.T, args ...string) string {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, append([]string{"tcp+xumux://" + addr}, args...)) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	return "tcp+xumux://" + addr
}

// app is the local application xumcat connects to: it sends msg and returns what comes back.
func app(t *testing.T, msg string) (addr string, got chan string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	got = make(chan string, 1)
	go func() {
		defer l.Close()
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Write([]byte(msg))
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	return l.Addr().String(), got
}

func TestRelayThroughServe(t *testing.T) {
	target := echo(t)
	url := startServe(t, "-allow", "tcp:"+target, "-token", "tok")
	appAddr, got := app(t, "hello over xumux")
	require.NoError(t, relay(context.Background(), []string{"tcp:" + appAddr, url, "-t", "tcp:" + target, "-token", "tok"}))
	assert.Equal(t, "hello over xumux", <-got)

	// URL first works too (socat style).
	appAddr, got = app(t, "swapped")
	require.NoError(t, relay(context.Background(), []string{url, "tcp:" + appAddr, "-t", "tcp:" + target, "-token", "tok"}))
	assert.Equal(t, "swapped", <-got)
}

func TestRelayErrors(t *testing.T) {
	target := echo(t)
	url := startServe(t, "-allow", "tcp:"+target, "-token", "tok")
	appAddr, _ := app(t, "x")
	err := relay(context.Background(), []string{"tcp:" + appAddr, url, "-t", "tcp:127.0.0.1:1", "-token", "tok"})
	assert.ErrorContains(t, err, "refused (4010)")
	err = relay(context.Background(), []string{"tcp:" + appAddr, url, "-token", "bad"})
	assert.ErrorContains(t, err, "4000")
	assert.ErrorContains(t, relay(context.Background(), []string{"stdio"}), "need an ENDPOINT")
	assert.ErrorContains(t, relay(context.Background(), []string{"stdio", "stdio+xumux"}), "both")
	assert.ErrorContains(t, relay(context.Background(), []string{"stdio", "tcp+xumux://10.9.9.9:1", "-token", "x"}), "unencrypted")
	assert.Error(t, relay(context.Background(), []string{"bogus:", "tcp+xumux://127.0.0.1:1"}))
}

func TestForwardListener(t *testing.T) {
	target := echo(t)
	url := startServe(t, "-default", "tcp:"+target)
	listen := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay(ctx, []string{"tcp-listen:" + listen, url}) }()
	var c net.Conn
	require.Eventually(t, func() bool {
		var err error
		c, err = net.Dial("tcp", listen)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	for i := 0; i < 3; i++ {
		if i > 0 {
			var err error
			c, err = net.Dial("tcp", listen)
			require.NoError(t, err)
		}
		c.Write([]byte("ping"))
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		assert.Equal(t, "ping", string(b))
		c.Close()
	}
	cancel()
	assert.NoError(t, <-done)
}

func TestServeErrors(t *testing.T) {
	ctx := context.Background()
	assert.ErrorContains(t, serve(ctx, nil), "need at least one")
	assert.ErrorContains(t, serve(ctx, []string{"tcp+xumux://127.0.0.1:1"}), "no targets allowed")
	assert.Error(t, serve(ctx, []string{"bogus://", "-allow", "x"}))
	assert.Error(t, serve(ctx, []string{"tcp+xumux://127.0.0.1:1", "-allow", "x", "-tls-cert", "/nope", "-tls-key", "/nope"}))
}

func TestPing(t *testing.T) {
	url := startServe(t, "-allow", "tcp:x:1")
	var out bytes.Buffer
	s, err := connect(context.Background(), url, "", &common{})
	require.NoError(t, err)
	defer closeSession(s)
	require.NoError(t, pingLoop(context.Background(), s, 2, time.Millisecond, &out))
	assert.Equal(t, 3, strings.Count(out.String(), "\n"))
	assert.Contains(t, out.String(), "2 sent, 0 lost")
	assert.ErrorContains(t, ping(context.Background(), nil), "need one XUMUX-URL")
	assert.NoError(t, ping(context.Background(), []string{url, "-c", "1"}))
}

func TestVersionAndHelpers(t *testing.T) {
	assert.NoError(t, run([]string{"version"}))
	var l stringList
	l.Set("a")
	l.Set("b")
	assert.Equal(t, "a,b", l.String())
	c := common{tokenFile: "/does/not/exist"}
	_, err := c.loadToken()
	assert.Error(t, err)
}

// captureOutput points the CLI's stdout and stderr at buffers for one test.
func captureOutput(t *testing.T) (out, errOut *bytes.Buffer) {
	out, errOut = new(bytes.Buffer), new(bytes.Buffer)
	oldOut, oldErr := stdout, stderr
	stdout, stderr = out, errOut
	t.Cleanup(func() { stdout, stderr = oldOut, oldErr })
	return out, errOut
}

func TestHelpGoesToStdout(t *testing.T) {
	out, errOut := captureOutput(t)
	tests := []struct {
		args []string
		want []string
	}{
		{[]string{"-h"}, []string{"xumcat — relay byte streams", "Relay flags:", "-plaintext-auth"}},
		{[]string{"--help"}, []string{"Relay flags:"}},
		{[]string{"help"}, []string{"Relay flags:"}},
		{[]string{"help", "serve"}, []string{"Usage: xumcat serve", "-allow PATTERN"}},
		{[]string{"serve", "-h"}, []string{"Usage: xumcat serve"}},
		{[]string{"help", "ping"}, []string{"Usage: xumcat ping", "-c int"}},
		{[]string{"ping", "--help"}, []string{"Usage: xumcat ping"}},
	}
	for _, tt := range tests {
		out.Reset()
		errOut.Reset()
		assert.Equal(t, 0, exitCode(run(tt.args), errOut), "%v", tt.args)
		for _, w := range tt.want {
			assert.Contains(t, out.String(), w, "%v", tt.args)
		}
		assert.Empty(t, errOut.String(), "%v writes nothing to stderr", tt.args)
		for _, line := range strings.Split(out.String(), "\n") {
			assert.LessOrEqual(t, displayWidth(line), 80, "%v: %q", tt.args, line)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	ctx := context.Background()
	out, errOut := captureOutput(t)
	code := func(err error) int { errOut.Reset(); return exitCode(err, errOut) }

	assert.Equal(t, 0, code(nil))
	assert.Equal(t, 2, code(relay(ctx, []string{"-bogus"})))
	assert.Equal(t, "xumcat: flag provided but not defined: -bogus\nRun 'xumcat -h' for help.\n", errOut.String())
	assert.Equal(t, 2, code(serve(ctx, []string{"-nope"})))
	assert.Contains(t, errOut.String(), "Run 'xumcat serve -h' for help.")
	assert.Equal(t, 2, code(relay(ctx, []string{"stdio"})))
	assert.Contains(t, errOut.String(), "need an ENDPOINT and a XUMUX-URL")
	assert.Equal(t, 2, code(run([]string{"help", "nope"})))
	assert.Equal(t, 2, code(run([]string{"help", "a", "b"})))
	assert.Empty(t, out.String(), "usage errors write nothing to stdout")

	// No arguments: the full usage, on stderr.
	errOut.Reset()
	err := relay(ctx, nil)
	assert.Contains(t, errOut.String(), "Relay flags:")
	assert.Equal(t, 2, exitCode(err, errOut))
	assert.Empty(t, out.String())

	assert.Equal(t, 1, code(errors.New("connection refused")))
	assert.Equal(t, "xumcat: connection refused\n", errOut.String())
}

// displayWidth is the terminal width of line, with tab stops every 8 columns.
func displayWidth(line string) int {
	w := 0
	for _, r := range line {
		if r == '\t' {
			w += 8 - w%8
		} else {
			w++
		}
	}
	return w
}

func TestParseSizeAndWindowOptions(t *testing.T) {
	for in, want := range map[string]int64{"1048576": 1 << 20, "512KiB": 512 << 10, "16MiB": 16 << 20, "16mib": 16 << 20,
		"1GiB": 1 << 30, "64M": 64 << 20, "2MB": 2e6, "0": 0, " 8 MiB ": 8 << 20} {
		got, err := parseSize(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "x", "-1", "1.5MiB", "4GiB", "9999999999"} {
		_, err := parseSize(in)
		assert.Error(t, err, in)
	}

	var c common
	assert.Equal(t, int64(0), c.options().MaxChannelWindow, "unset: library default")
	require.NoError(t, c.maxWindow.Set("0"))
	assert.Equal(t, int64(-1), c.options().MaxChannelWindow, "0 turns auto-tuning off")
	require.NoError(t, c.maxWindow.Set("64MiB"))
	require.NoError(t, c.connWindow.Set("256MiB"))
	o := c.options()
	assert.Equal(t, int64(64<<20), o.MaxChannelWindow)
	assert.Equal(t, int64(256<<20), o.ConnectionWindow)
	assert.Equal(t, "67108864", c.maxWindow.String())
	assert.Equal(t, "", (&size{}).String())
	assert.Error(t, relay(context.Background(), []string{"-max-window", "lots", "stdio", "stdio+xumux"}))
}

func TestMaxConnsBusy(t *testing.T) {
	url := startServe(t, "-max-conns", "1", "-default", "tcp:"+echo(t))
	connect := func() (*xumux.Session, error) {
		fc, err := transport.Dial(context.Background(), url, transport.Options{})
		if err != nil {
			return nil, err
		}
		s, _, err := xumux.Connect(context.Background(), fc, xumux.ClientConfig{}, xumux.Options{})
		return s, err
	}
	// startServe's probe connections may hold the one slot for a moment.
	var first *xumux.Session
	require.Eventually(t, func() bool {
		var err error
		first, err = connect()
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	defer first.Close(context.Background(), xumux.CodeNormal, "")

	_, err := connect()
	var ce *xumux.CloseError
	require.True(t, errors.As(err, &ce), "%v", err)
	assert.Equal(t, pipe.CodeBusy, ce.Code)
	assert.Contains(t, ce.Reason, "too many connections")
}
