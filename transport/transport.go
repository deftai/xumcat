// Package transport dials and serves xumux connections by URL:
//
//	ws://host:port/path, wss://…   WebSocket binding (subprotocol "xumux")
//	tcp+xumux://host:port          TCP binding
//	tls+xumux://host:port          TCP binding under TLS
//	unix+xumux:/path               TCP binding on a Unix socket
//	stdio+xumux                    stdio binding on this process
//	exec+xumux:command             stdio binding on a spawned command (dial only)
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coder/websocket"

	"github.com/deftai/xumcat/endpoint"
	"github.com/deftai/xumcat/xumux"
)

// Subprotocol is the WebSocket subprotocol of the xumux binding.
const Subprotocol = "xumux"

// Options configure Dial and Serve.
type Options struct {
	// TLS: client config for wss/tls+xumux dials, server config (with
	// certificates) for wss/tls+xumux listeners.
	TLS *tls.Config
	// Header is sent with the WebSocket upgrade request.
	Header http.Header
	// MaxFramePayload bounds WebSocket reads (default xumux.DefaultMaxFramePayload).
	MaxFramePayload uint32
	// Stderr receives exec+xumux commands' stderr.
	Stderr io.Writer
}

// URL is a parsed xumux URL.
type URL struct {
	Scheme  string
	Host    string // host:port
	Path    string // WebSocket path or Unix socket path
	Command string // exec+xumux
	Raw     string
}

// Parse parses a xumux URL.
func Parse(raw string) (URL, error) {
	if raw == "stdio+xumux" || raw == "stdio+xumux:" {
		return URL{Scheme: "stdio+xumux", Raw: raw}, nil
	}
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok {
		return URL{}, fmt.Errorf("xumux URL %q: missing scheme", raw)
	}
	u := URL{Scheme: scheme, Raw: raw}
	switch scheme {
	case "ws", "wss", "tcp+xumux", "tls+xumux":
		p, err := url.Parse(raw)
		if err != nil {
			return URL{}, fmt.Errorf("xumux URL %q: %w", raw, err)
		}
		u.Host = p.Host
		if scheme == "ws" || scheme == "wss" {
			u.Path = p.RequestURI()
		}
		if u.Host == "" {
			return URL{}, fmt.Errorf("xumux URL %q: missing host", raw)
		}
		if p.Port() == "" {
			switch scheme {
			case "ws":
				u.Host = net.JoinHostPort(p.Hostname(), "80")
			case "wss":
				u.Host = net.JoinHostPort(p.Hostname(), "443")
			default:
				return URL{}, fmt.Errorf("xumux URL %q: missing port", raw)
			}
		}
	case "unix+xumux":
		u.Path = rest
		if u.Path == "" {
			return URL{}, fmt.Errorf("xumux URL %q: missing socket path", raw)
		}
	case "exec+xumux":
		u.Command = strings.TrimSpace(rest)
		if u.Command == "" {
			return URL{}, fmt.Errorf("xumux URL %q: missing command", raw)
		}
	default:
		return URL{}, fmt.Errorf("xumux URL %q: unknown scheme (want ws, wss, tcp+xumux, tls+xumux, unix+xumux, stdio+xumux or exec+xumux)", raw)
	}
	return u, nil
}

// IsURL reports whether s looks like a xumux URL rather than an endpoint.
func IsURL(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// Encrypted reports whether the transport protects credentials in transit:
// TLS, or a local binding (stdio, Unix socket, exec) (core §3.7).
func (u URL) Encrypted() bool {
	switch u.Scheme {
	case "wss", "tls+xumux", "unix+xumux", "stdio+xumux", "exec+xumux":
		return true
	}
	host, _, _ := net.SplitHostPort(u.Host)
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// Dial opens a xumux transport to u.
func Dial(ctx context.Context, raw string, o Options) (xumux.FrameConn, error) {
	u, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "ws", "wss":
		return dialWebSocket(ctx, u, o)
	case "tcp+xumux":
		return dialStream(ctx, "tcp:"+u.Host, o)
	case "tls+xumux":
		return dialStream(ctx, "tls:"+u.Host, o)
	case "unix+xumux":
		return dialStream(ctx, "unix:"+u.Path, o)
	case "stdio+xumux":
		return xumux.NewStreamConn(endpoint.Stdio()), nil
	default: // exec+xumux
		return dialStream(ctx, "exec:"+u.Command, o)
	}
}

func dialStream(ctx context.Context, addr string, o Options) (xumux.FrameConn, error) {
	c, err := endpoint.Dial(ctx, addr, endpoint.Options{TLS: o.TLS, Stderr: o.Stderr})
	if err != nil {
		return nil, err
	}
	return xumux.NewStreamConn(c), nil
}

func readLimit(o Options) int64 {
	limit := o.MaxFramePayload
	if limit == 0 {
		limit = xumux.DefaultMaxFramePayload
	}
	return int64(max(limit, xumux.ControlMaxPayload)) + xumux.HeaderSize
}

func dialWebSocket(ctx context.Context, u URL, o Options) (xumux.FrameConn, error) {
	opts := &websocket.DialOptions{Subprotocols: []string{Subprotocol}, HTTPHeader: o.Header}
	if o.TLS != nil {
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: o.TLS}}
	}
	c, _, err := websocket.Dial(ctx, u.Raw, opts)
	if err != nil {
		return nil, err
	}
	if c.Subprotocol() != Subprotocol {
		c.Close(websocket.StatusProtocolError, "subprotocol xumux required")
		return nil, errors.New("server did not accept the xumux WebSocket subprotocol")
	}
	c.SetReadLimit(readLimit(o))
	return xumux.NewMessageConn(&wsTransport{c: c}), nil
}

type wsTransport struct {
	c    *websocket.Conn
	once sync.Once
}

func (t *wsTransport) ReadMessage() ([]byte, error) {
	typ, b, err := t.c.Read(context.Background())
	if err != nil {
		if s := websocket.CloseStatus(err); s == websocket.StatusNormalClosure || s == websocket.StatusGoingAway {
			return nil, io.EOF
		}
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, xumux.ErrTextMessage
	}
	return b, nil
}

func (t *wsTransport) WriteMessage(b []byte) error {
	return t.c.Write(context.Background(), websocket.MessageBinary, b)
}

func (t *wsTransport) Close() error {
	var err error
	t.once.Do(func() { err = t.c.Close(websocket.StatusNormalClosure, "") })
	return err
}

// Serve accepts xumux transports on u and calls handle for each, in its own
// goroutine; handle should return when the connection is finished. Serve
// returns when ctx is cancelled or the listener fails. For stdio+xumux it
// serves the one connection and returns.
func Serve(ctx context.Context, raw string, o Options, handle func(xumux.FrameConn)) error {
	u, err := Parse(raw)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "stdio+xumux":
		handle(xumux.NewStreamConn(endpoint.Stdio()))
		return nil
	case "exec+xumux":
		return errors.New("exec+xumux can only be dialled")
	case "ws", "wss":
		return serveWebSocket(ctx, u, o, handle)
	}
	var l net.Listener
	switch u.Scheme {
	case "tcp+xumux":
		l, err = net.Listen("tcp", u.Host)
	case "tls+xumux":
		if o.TLS == nil || len(o.TLS.Certificates) == 0 {
			return errors.New("tls+xumux listener needs a certificate")
		}
		l, err = tls.Listen("tcp", u.Host, o.TLS)
	case "unix+xumux":
		l, err = endpoint.ListenUnix(u.Path)
	}
	if err != nil {
		return err
	}
	return serveListener(ctx, l, handle)
}

// serveListener serves xumux stream connections from an existing listener.
func serveListener(ctx context.Context, l net.Listener, handle func(xumux.FrameConn)) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle(xumux.NewStreamConn(c))
		}()
	}
}

func serveWebSocket(ctx context.Context, u URL, o Options, handle func(xumux.FrameConn)) error {
	path := u.Path
	if path == "" {
		path = "/"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			return
		}
		if c.Subprotocol() != Subprotocol {
			c.Close(websocket.StatusPolicyViolation, "subprotocol xumux required")
			return
		}
		c.SetReadLimit(readLimit(o))
		handle(xumux.NewMessageConn(&wsTransport{c: c}))
	})
	l, err := net.Listen("tcp", u.Host)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux}
	stop := context.AfterFunc(ctx, func() { srv.Close() })
	defer stop()
	if u.Scheme == "wss" {
		if o.TLS == nil || len(o.TLS.Certificates) == 0 {
			l.Close()
			return errors.New("wss listener needs a certificate")
		}
		srv.TLSConfig = o.TLS
		err = srv.ServeTLS(l, "", "")
	} else {
		err = srv.Serve(l)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
