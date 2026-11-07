// Command xumcat relays byte streams over xumux connections, like netcat
// or socat with multiplexing: one xumux connection carries any number of
// pipe/1 channels, each connected to an endpoint on the far side.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/deftai/xumcat/endpoint"
	"github.com/deftai/xumcat/pipe"
	"github.com/deftai/xumcat/transport"
	"github.com/deftai/xumcat/xumux"
)

var version = "dev"

const usage = `xumcat — relay byte streams over xumux

Usage:
  xumcat [flags] ENDPOINT XUMUX-URL     connect ENDPOINT to a pipe/1 channel
  xumcat serve [flags] XUMUX-URL...     answer pipe/1 channels
  xumcat ping [flags] XUMUX-URL         measure round-trip time
  xumcat version

Endpoints (pipe/1 addresses):
  tcp:HOST:PORT  tls:HOST:PORT  unix:PATH  stdio  exec:COMMAND
  tcp-listen:[HOST:]PORT  unix-listen:PATH   (one channel per accepted connection)

xumux URLs:
  ws://HOST:PORT/PATH  wss://…  tcp+xumux://HOST:PORT  tls+xumux://HOST:PORT
  unix+xumux:PATH  stdio+xumux  exec+xumux:COMMAND

Examples:
  xumcat serve tcp+xumux://:7000 -allow 'tcp:localhost:*'
  xumcat stdio tcp+xumux://server:7000 -t tcp:localhost:22
  xumcat tcp-listen:8080 exec+xumux:'ssh host xumcat serve stdio+xumux -allow tcp:localhost:80' -t tcp:localhost:80

Run 'xumcat serve -h' or 'xumcat ping -h' for their flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xumcat:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return serve(ctx, args[1:])
		case "ping":
			return ping(ctx, args[1:])
		case "version", "-version", "--version":
			fmt.Println("xumcat", version, "xumux", fmt.Sprintf("%d.%d.%d", xumux.Version[0], xumux.Version[1], xumux.Version[2]))
			return nil
		}
	}
	return relay(ctx, args)
}

// parseInterspersed lets flags appear before, between or after positional args.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type common struct {
	token, tokenFile string
	insecure         bool
	verbose          bool
	plaintextAuth    bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.token, "token", "", "shared token for HELLO auth")
	fs.StringVar(&c.tokenFile, "token-file", "", "read the token from a file")
	fs.BoolVar(&c.verbose, "v", false, "log to stderr")
}

func (c *common) loadToken() (string, error) {
	if c.tokenFile == "" {
		return c.token, nil
	}
	b, err := os.ReadFile(c.tokenFile)
	return strings.TrimSpace(string(b)), err
}

func (c *common) logf(format string, args ...any) {
	if c.verbose {
		fmt.Fprintf(os.Stderr, "xumcat: "+format+"\n", args...)
	}
}

// ─── relay ──────────────────────────────────────────────────────────────────

func relay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("xumcat", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	var c common
	c.register(fs)
	target := fs.String("t", "", "endpoint the server connects the channel to (default: the server's -default)")
	name := fs.String("name", "pipe", "channel name")
	fs.BoolVar(&c.insecure, "insecure", false, "skip TLS certificate verification")
	fs.BoolVar(&c.plaintextAuth, "plaintext-auth", false, "allow sending the token over an unencrypted transport")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		fs.Usage()
		return errors.New("need an ENDPOINT and a XUMUX-URL")
	}
	local, remote := pos[0], pos[1]
	if transport.IsURL(local) && !transport.IsURL(remote) {
		local, remote = remote, local
	}
	ep, err := endpoint.Parse(local)
	if err != nil {
		return err
	}
	u, err := transport.Parse(remote)
	if err != nil {
		return err
	}
	if ep.Kind == "stdio" && u.Scheme == "stdio+xumux" {
		return errors.New("stdio cannot be both the endpoint and the xumux transport")
	}
	token, err := c.loadToken()
	if err != nil {
		return err
	}
	if token != "" && !u.Encrypted() && !c.plaintextAuth {
		return fmt.Errorf("refusing to send the token over %s, which is unencrypted (use wss://, tls+xumux:// or a local transport, or -plaintext-auth)", u.Scheme)
	}

	s, err := connect(ctx, u.Raw, token, &c)
	if err != nil {
		return err
	}
	defer closeSession(s)

	if !ep.IsListen() {
		conn, err := endpoint.DialAddress(ctx, ep, endpoint.Options{})
		if err != nil {
			return err
		}
		return pipeOne(ctx, s, conn, *name, *target, &c)
	}

	l, err := endpoint.Listen(local)
	if err != nil {
		return err
	}
	c.logf("listening on %s", l.Addr())
	go func() {
		select {
		case <-ctx.Done():
		case <-s.Done():
		}
		l.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if e := s.Err(); e != nil {
				return e
			}
			select {
			case <-s.Done():
				return nil
			default:
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pipeOne(ctx, s, conn, *name, *target, &c); err != nil {
				fmt.Fprintln(os.Stderr, "xumcat:", err)
			}
		}()
	}
}

func connect(ctx context.Context, rawURL, token string, c *common) (*xumux.Session, error) {
	o := transport.Options{}
	if c.insecure {
		o.TLS = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit -insecure
	}
	fc, err := transport.Dial(ctx, rawURL, o)
	if err != nil {
		return nil, err
	}
	cfg := xumux.ClientConfig{Application: "xumcat/1"}
	if token != "" {
		cfg.Auth = map[string]any{"type": "token", "token": token}
	}
	s, _, err := xumux.Connect(ctx, fc, cfg, xumux.Options{})
	if err != nil {
		return nil, err
	}
	c.logf("connected to %s", rawURL)
	return s, nil
}

func closeSession(s *xumux.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Close(ctx, xumux.CodeNormal, "")
}

func pipeOne(ctx context.Context, s *xumux.Session, conn endpoint.Conn, name, target string, c *common) error {
	ch, err := pipe.Open(ctx, s, name, target)
	if err != nil {
		conn.Close()
		var ce *xumux.CloseError
		if errors.As(err, &ce) {
			return fmt.Errorf("channel refused (%d): %s", ce.Code, ce.Reason)
		}
		return err
	}
	c.logf("channel %d open", ch.ID())
	err = pipe.Relay(ctx, ch, conn)
	c.logf("channel %d closed", ch.ID())
	return err
}

// ─── serve ──────────────────────────────────────────────────────────────────

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("xumcat serve", flag.ContinueOnError)
	var c common
	c.register(fs)
	var allow stringList
	fs.Var(&allow, "allow", "allow targets matching this endpoint pattern, e.g. 'tcp:localhost:*' (repeatable)")
	def := fs.String("default", "", "target for channels that name none")
	cert := fs.String("tls-cert", "", "certificate file for wss:// and tls+xumux:// listeners")
	key := fs.String("tls-key", "", "key file for wss:// and tls+xumux:// listeners")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: xumcat serve [flags] XUMUX-URL...\n\nAnswers pipe/1 channels by connecting them to allowed targets.\n\n")
		fs.PrintDefaults()
	}
	urls, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(urls) == 0 {
		fs.Usage()
		return errors.New("need at least one XUMUX-URL to listen on")
	}
	if *def != "" {
		allow = append(allow, *def)
	}
	if len(allow) == 0 {
		return errors.New("no targets allowed: pass -allow PATTERN (and/or -default ADDR)")
	}
	token, err := c.loadToken()
	if err != nil {
		return err
	}
	o := transport.Options{}
	if *cert != "" || *key != "" {
		pair, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return err
		}
		o.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}
	for _, raw := range urls {
		u, err := transport.Parse(raw)
		if err != nil {
			return err
		}
		if token == "" && !u.Encrypted() && u.Scheme != "stdio+xumux" {
			fmt.Fprintf(os.Stderr, "xumcat: warning: %s accepts connections without a token\n", raw)
		}
	}

	responder := &pipe.Responder{Allow: allow, Default: *def, Logf: c.logf}
	sc := xumux.ServerConfig{}
	if token != "" {
		sc.Authorize = func(_ context.Context, h *xumux.Hello) error {
			got, _ := h.Auth["token"].(string)
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				return &xumux.Refusal{Code: xumux.CodeAuthFailed, Reason: "bad token"}
			}
			return nil
		}
	}
	handle := func(fc xumux.FrameConn) {
		s, h, err := xumux.Accept(ctx, fc, sc, xumux.Options{Acceptor: responder.Acceptor()})
		if err != nil {
			c.logf("handshake failed: %v", err)
			return
		}
		c.logf("client connected (%s)", h.Application)
		select {
		case <-s.Done():
		case <-ctx.Done():
			closeSession(s)
		}
		c.logf("client disconnected (%d)", s.CloseInfo().Code)
	}

	errc := make(chan error, len(urls))
	for _, raw := range urls {
		c.logf("serving %s", raw)
		go func() { errc <- transport.Serve(ctx, raw, o, handle) }()
	}
	for range urls {
		if err := <-errc; err != nil {
			return err
		}
	}
	return nil
}

// ─── ping ───────────────────────────────────────────────────────────────────

func ping(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("xumcat ping", flag.ContinueOnError)
	var c common
	c.register(fs)
	fs.BoolVar(&c.insecure, "insecure", false, "skip TLS certificate verification")
	count := fs.Int("c", 4, "number of pings (0 = until interrupted)")
	interval := fs.Duration("i", time.Second, "interval between pings")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: xumcat ping [flags] XUMUX-URL")
	}
	token, err := c.loadToken()
	if err != nil {
		return err
	}
	s, err := connect(ctx, pos[0], token, &c)
	if err != nil {
		return err
	}
	defer closeSession(s)
	return pingLoop(ctx, s, *count, *interval, os.Stdout)
}

func pingLoop(ctx context.Context, s *xumux.Session, count int, interval time.Duration, out io.Writer) error {
	for i := 0; count == 0 || i < count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(interval):
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		rtt, err := s.Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(out, "seq=%d lost (%v)\n", i, err)
			continue
		}
		fmt.Fprintf(out, "seq=%d rtt=%s\n", i, rtt.Round(time.Microsecond))
	}
	st := s.Stats()
	fmt.Fprintf(out, "%d sent, %d lost, srtt=%s rttvar=%s\n", st.ProbesSent, st.ProbesLost, st.SRTT.Round(time.Microsecond), st.RTTVar.Round(time.Microsecond))
	return nil
}
