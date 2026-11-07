package pipe

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deftai/xumcat/endpoint"
	"github.com/deftai/xumcat/xumux"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// tcpPair returns two connected TCP conns (they support CloseWrite).
func tcpPair(t *testing.T) (endpoint.Conn, endpoint.Conn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	a, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	return a.(*net.TCPConn), (<-ch).(*net.TCPConn)
}

// sessions connects a client to a server that runs r.
func sessions(t *testing.T, r *Responder) *xumux.Session {
	a, b := net.Pipe()
	opts := xumux.Options{PingInterval: -1, CloseTimeout: 500 * time.Millisecond}
	go func() {
		so := opts
		so.Acceptor = r.Acceptor()
		xumux.Accept(context.Background(), xumux.NewStreamConn(b), xumux.ServerConfig{}, so)
	}()
	s, _, err := xumux.Connect(context.Background(), xumux.NewStreamConn(a), xumux.ClientConfig{}, opts)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close(context.Background(), xumux.CodeNormal, "") })
	return s
}

func TestRelayBothDirections(t *testing.T) {
	// The server's target is an echo service reached through a TCP pair.
	targetNear, targetFar := tcpPair(t)
	go func() {
		io.Copy(targetFar, targetFar)
		targetFar.CloseWrite()
	}()
	var mu sync.Mutex
	var logs []string
	r := &Responder{Allow: []string{"tcp:echo:1"}, Logf: func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() },
		Dial: func(context.Context, string) (endpoint.Conn, error) { return targetNear, nil }}
	s := sessions(t, r)
	ch, err := Open(ctx(t), s, "p", "tcp:echo:1")
	require.NoError(t, err)

	appNear, appFar := tcpPair(t)
	relayed := make(chan error, 1)
	go func() { relayed <- Relay(ctx(t), ch, appNear) }()
	data := make([]byte, 1_000_000)
	rand.Read(data)
	go func() {
		appFar.Write(data)
		appFar.CloseWrite()
	}()
	got, err := io.ReadAll(appFar)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, got), "echoed bytes match")
	require.NoError(t, <-relayed)
	mu.Lock()
	assert.NotEmpty(t, logs)
	mu.Unlock()
}

func TestResponderRefusals(t *testing.T) {
	r := &Responder{Allow: []string{"tcp:127.0.0.1:*"}}
	s := sessions(t, r)
	code := func(spec xumux.ChannelSpec) int {
		_, err := s.OpenChannel(ctx(t), spec)
		var ce *xumux.CloseError
		require.True(t, errors.As(err, &ce), "%v", err)
		return ce.Code
	}
	assert.Equal(t, xumux.CodeChannelRefused, code(xumux.ChannelSpec{Name: "x", Reliable: true, Ordered: true}), "no profile")
	unreliable := Spec("x", "tcp:127.0.0.1:1")
	unreliable.Reliable = false
	assert.Equal(t, xumux.CodeChannelRefused, code(unreliable))
	assert.Equal(t, xumux.CodeChannelRefused, code(Spec("x", "")), "no target and no default")
	assert.Equal(t, xumux.CodeChannelRefused, code(Spec("x", "tcp:10.0.0.1:22")), "not allowed")
	assert.Equal(t, CodeTargetUnreachable, code(Spec("x", "tcp:127.0.0.1:1")), "unreachable")
}

func TestResponderDefaultTarget(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() { c, _ := l.Accept(); c.Write([]byte("banner")); c.Close() }()
	target := "tcp:" + l.Addr().String()
	s := sessions(t, &Responder{Allow: []string{target}, Default: target})
	ch, err := Open(ctx(t), s, "p", "")
	require.NoError(t, err)
	near, far := tcpPair(t)
	go Relay(ctx(t), ch, near)
	far.CloseWrite()
	b, _ := io.ReadAll(far)
	assert.Equal(t, "banner", string(b))
}

// A raw xumux peer that speaks pipe/1 by hand, to test RESET and bad types.
func rawPipe(t *testing.T) (*xumux.Channel, *xumux.Channel) {
	got := make(chan *xumux.Channel, 1)
	a, b := net.Pipe()
	opts := xumux.Options{PingInterval: -1, CloseTimeout: 300 * time.Millisecond}
	so := opts
	so.Acceptor = func(context.Context, xumux.ChannelRequest) (xumux.Handler, error) {
		return func(c *xumux.Channel) { got <- c }, nil
	}
	go xumux.Accept(context.Background(), xumux.NewStreamConn(b), xumux.ServerConfig{}, so)
	s, _, err := xumux.Connect(context.Background(), xumux.NewStreamConn(a), xumux.ClientConfig{}, opts)
	require.NoError(t, err)
	ch, err := Open(ctx(t), s, "p", "x")
	require.NoError(t, err)
	return ch, <-got
}

func TestResetFromPeer(t *testing.T) {
	ch, peer := rawPipe(t)
	near, far := tcpPair(t)
	relayed := make(chan error, 1)
	go func() { relayed <- Relay(ctx(t), ch, near) }()
	require.NoError(t, peer.Send(ctx(t), TypeData, []byte("partial")))
	require.NoError(t, peer.Send(ctx(t), TypeReset, []byte(`{"code":1001,"reason":"target died"}`)))
	err := <-relayed
	var re *ResetError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, "target died", re.Reason)
	assert.Contains(t, re.Error(), "reset")
	b, _ := io.ReadAll(far)
	assert.Equal(t, "partial", string(b))
}

func TestUnknownTypeClosesChannel(t *testing.T) {
	ch, peer := rawPipe(t)
	near, _ := tcpPair(t)
	relayed := make(chan error, 1)
	go func() { relayed <- Relay(ctx(t), ch, near) }()
	require.NoError(t, peer.Send(ctx(t), 0x7F, nil))
	assert.ErrorContains(t, <-relayed, "unknown pipe/1 message type")
	<-peer.Done()
	assert.Equal(t, xumux.CodeProtocolError, peer.CloseInfo().Code)
}

func TestLocalReadErrorSendsReset(t *testing.T) {
	ch, peer := rawPipe(t)
	relayed := make(chan error, 1)
	go func() { relayed <- Relay(ctx(t), ch, failingConn{}) }()
	m, err := peer.Receive(ctx(t))
	require.NoError(t, err)
	assert.Equal(t, TypeReset, m.Type)
	assert.Contains(t, string(m.Payload), "disk on fire")
	assert.ErrorContains(t, <-relayed, "disk on fire")
}

type failingConn struct{}

func (failingConn) Read([]byte) (int, error)    { return 0, errors.New("disk on fire") }
func (failingConn) Write(b []byte) (int, error) { return len(b), nil }
func (failingConn) Close() error                { return nil }
func (failingConn) CloseWrite() error           { return nil }
