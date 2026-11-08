package transport

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xumux "github.com/deftai/libxumux-go"
	"github.com/deftai/xumcat/internal/testcert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in        string
		scheme    string
		host      string
		path      string
		encrypted bool
		wantErr   bool
	}{
		{"ws://example.com/xumux", "ws", "example.com:80", "/xumux", false, false},
		{"wss://example.com", "wss", "example.com:443", "/", true, false},
		{"ws://localhost:8080/x", "ws", "localhost:8080", "/x", true, false},
		{"tcp+xumux://10.0.0.1:7000", "tcp+xumux", "10.0.0.1:7000", "", false, false},
		{"tcp+xumux://127.0.0.1:7000", "tcp+xumux", "127.0.0.1:7000", "", true, false},
		{"tls+xumux://h:7000", "tls+xumux", "h:7000", "", true, false},
		{"unix+xumux:/run/x.sock", "unix+xumux", "", "/run/x.sock", true, false},
		{"stdio+xumux", "stdio+xumux", "", "", true, false},
		{"exec+xumux:ssh host xumcat serve stdio+xumux", "exec+xumux", "", "", true, false},
		{"tcp+xumux://h", "", "", "", false, true},
		{"ws://", "", "", "", false, true},
		{"unix+xumux:", "", "", "", false, true},
		{"exec+xumux:", "", "", "", false, true},
		{"http://x", "", "", "", false, true},
		{"tcp:localhost:22", "", "", "", false, true},
		{"nonsense", "", "", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			u, err := Parse(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				assert.False(t, IsURL(tt.in))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.scheme, u.Scheme)
			assert.Equal(t, tt.host, u.Host)
			assert.Equal(t, tt.path, u.Path)
			assert.Equal(t, tt.encrypted, u.Encrypted())
		})
	}
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().String()
}

// roundTrip serves url, connects a client to it and pings once.
func roundTrip(t *testing.T, url string, srv, cli Options) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- Serve(ctx, url, srv, func(fc xumux.FrameConn) {
			s, _, err := xumux.Accept(ctx, fc, xumux.ServerConfig{}, xumux.Options{PingInterval: -1})
			if err == nil {
				<-s.Done()
			}
		})
	}()
	var fc xumux.FrameConn
	var err error
	require.Eventually(t, func() bool {
		fc, err = Dial(ctx, url, cli)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond, "dial %s: %v", url, err)
	s, _, err := xumux.Connect(ctx, fc, xumux.ClientConfig{}, xumux.Options{PingInterval: -1})
	require.NoError(t, err)
	_, err = s.Ping(ctx)
	require.NoError(t, err)
	require.NoError(t, s.Close(ctx, xumux.CodeNormal, ""))
	cancel()
	select {
	case err := <-served:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestTransports(t *testing.T) {
	srvTLS, cliTLS := testcert.New()
	sock := filepath.Join(t.TempDir(), "x.sock")
	t.Run("tcp", func(t *testing.T) { roundTrip(t, "tcp+xumux://"+freePort(t), Options{}, Options{}) })
	t.Run("tls", func(t *testing.T) {
		roundTrip(t, "tls+xumux://"+freePort(t), Options{TLS: srvTLS}, Options{TLS: cliTLS})
	})
	t.Run("unix", func(t *testing.T) { roundTrip(t, "unix+xumux:"+sock, Options{}, Options{}) })
	t.Run("ws", func(t *testing.T) { roundTrip(t, "ws://"+freePort(t)+"/xumux", Options{}, Options{}) })
	t.Run("wss", func(t *testing.T) {
		roundTrip(t, "wss://"+freePort(t)+"/xumux", Options{TLS: srvTLS}, Options{TLS: cliTLS})
	})
}

func TestServeErrors(t *testing.T) {
	ctx := context.Background()
	assert.ErrorContains(t, Serve(ctx, "exec+xumux:cat", Options{}, nil), "dialled")
	assert.ErrorContains(t, Serve(ctx, "wss://"+freePort(t), Options{}, nil), "certificate")
	assert.ErrorContains(t, Serve(ctx, "tls+xumux://"+freePort(t), Options{}, nil), "certificate")
	assert.Error(t, Serve(ctx, "bogus://x", Options{}, nil))
	_, err := Dial(ctx, "bogus://x", Options{})
	assert.Error(t, err)
	_, err = Dial(ctx, "tcp+xumux://127.0.0.1:1", Options{})
	assert.Error(t, err)
}

func TestWebSocketRequiresSubprotocol(t *testing.T) {
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, "ws://"+addr+"/", Options{}, func(xumux.FrameConn) { t.Error("handler must not run") })
	var c *websocket.Conn
	require.Eventually(t, func() bool {
		var err error
		c, _, err = websocket.Dial(ctx, "ws://"+addr+"/", nil)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	_, _, err := c.Read(ctx)
	assert.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err))

	// A server that ignores the subprotocol is rejected by the client.
	plain := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err == nil {
			c.Read(context.Background())
		}
	})}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go plain.Serve(l)
	defer plain.Close()
	_, err = Dial(ctx, "ws://"+l.Addr().String()+"/", Options{})
	assert.ErrorContains(t, err, "subprotocol")
}

func TestWebSocketErrorLog(t *testing.T) {
	srvTLS, _ := testcert.New()
	addr := freePort(t)
	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, "wss://"+addr+"/", Options{TLS: srvTLS, ErrorLog: log.New(&buf, "", 0)}, func(xumux.FrameConn) {})
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return false
		}
		c.Write([]byte("not a TLS handshake\r\n\r\n"))
		c.Close()
		return strings.Contains(buf.String(), "TLS handshake error")
	}, 3*time.Second, 50*time.Millisecond, "the listener's HTTP errors reach Options.ErrorLog")
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
