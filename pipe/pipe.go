// Package pipe implements the xumux pipe/1 profile: one bidirectional byte
// stream with half-close per channel.
package pipe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	xumux "github.com/deftai/libxumux-go"
	"github.com/deftai/xumcat/endpoint"
)

// Profile is the metadata.profile value of a pipe/1 channel.
const Profile = "pipe/1"

// Message types.
const (
	TypeData  byte = 0x01
	TypeEOF   byte = 0x02
	TypeReset byte = 0x03
)

// CodeTargetUnreachable refuses a channel whose target cannot be reached.
const CodeTargetUnreachable = 4500

// maxChunk caps DATA messages; they are never fragmented.
const maxChunk = 32 << 10

// Spec describes a pipe/1 channel. An empty target lets the responder choose.
func Spec(name, target string) xumux.ChannelSpec {
	md := map[string]any{"profile": Profile}
	if target != "" {
		md["target"] = target
	}
	return xumux.ChannelSpec{Name: name, Reliable: true, Ordered: true, Metadata: md}
}

// Open opens a pipe/1 channel asking the peer to connect it to target.
func Open(ctx context.Context, s *xumux.Session, name, target string) (*xumux.Channel, error) {
	return s.OpenChannel(ctx, Spec(name, target))
}

// Responder answers pipe/1 channel requests by connecting them to a target.
type Responder struct {
	// Allow lists the targets peers may ask for, as endpoint.Match patterns.
	Allow []string
	// Default is the target used when a request names none ("" refuses).
	Default string
	// Dial opens a target. It defaults to endpoint.Dial.
	Dial func(ctx context.Context, target string) (endpoint.Conn, error)
	// Logf, if set, logs channel events.
	Logf func(format string, args ...any)
	// MaxProcs caps how many exec: targets run at once across every
	// connection using this Responder (0: no limit).
	MaxProcs int

	once  sync.Once
	procs chan struct{}
}

// procConn releases a process slot when the relay closes the conn.
type procConn struct {
	endpoint.Conn
	release func()
}

func (c *procConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func (r *Responder) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// Acceptor returns an xumux Acceptor that accepts pipe/1 channels.
func (r *Responder) Acceptor() xumux.Acceptor {
	r.once.Do(func() {
		if r.MaxProcs > 0 {
			r.procs = make(chan struct{}, r.MaxProcs)
		}
	})
	return func(ctx context.Context, req xumux.ChannelRequest) (xumux.Handler, error) {
		if p, _ := req.Metadata["profile"].(string); p != Profile {
			return nil, &xumux.Refusal{Code: xumux.CodeChannelRefused, Reason: fmt.Sprintf("unsupported profile %q", p)}
		}
		if !req.Reliable || !req.Ordered {
			return nil, &xumux.Refusal{Code: xumux.CodeChannelRefused, Reason: "pipe/1 channels must be reliable and ordered"}
		}
		target, _ := req.Metadata["target"].(string)
		if target == "" {
			target = r.Default
		}
		if target == "" {
			return nil, &xumux.Refusal{Code: xumux.CodeChannelRefused, Reason: "no target"}
		}
		if !endpoint.Match(r.Allow, target) {
			r.logf("channel %d: refused target %s (not allowed)", req.ID, target)
			return nil, &xumux.Refusal{Code: xumux.CodeChannelRefused, Reason: "target not allowed"}
		}
		dial := r.Dial
		if dial == nil {
			dial = func(ctx context.Context, t string) (endpoint.Conn, error) {
				return endpoint.Dial(ctx, t, endpoint.Options{})
			}
		}
		release := func() {}
		if r.procs != nil && strings.HasPrefix(target, "exec:") {
			select {
			case r.procs <- struct{}{}:
				var once sync.Once
				release = func() { once.Do(func() { <-r.procs }) }
			default:
				r.logf("channel %d: refused %s (process limit %d reached)", req.ID, target, r.MaxProcs)
				return nil, &xumux.Refusal{Code: xumux.CodeChannelRefused, Reason: "too many processes running"}
			}
		}
		conn, err := dial(ctx, target)
		if err != nil {
			release()
			r.logf("channel %d: %s unreachable: %v", req.ID, target, err)
			return nil, &xumux.Refusal{Code: CodeTargetUnreachable, Reason: err.Error()}
		}
		conn = &procConn{Conn: conn, release: release}
		r.logf("channel %d: connected to %s", req.ID, target)
		return func(ch *xumux.Channel) {
			err := Relay(ctx, ch, conn)
			r.logf("channel %d: closed (%v)", ch.ID(), errOrOK(err))
		}, nil
	}
}

func errOrOK(err error) any {
	if err == nil {
		return "ok"
	}
	return err
}

type resetMsg struct {
	Code   int    `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// ResetError reports that the far end of the pipe failed.
type ResetError struct {
	Code   int
	Reason string
}

func (e *ResetError) Error() string {
	return fmt.Sprintf("pipe reset by peer (%d): %s", e.Code, e.Reason)
}

// Relay copies bytes between ch and conn until both directions have ended,
// then closes the channel and conn. It returns nil after a clean exchange
// of EOFs, a *ResetError if the peer's end failed, or the error that
// ended the relay.
func Relay(ctx context.Context, ch *xumux.Channel, conn endpoint.Conn) error {
	defer conn.Close()
	// Credit is returned only once bytes are written to conn (pipe/1).
	ch.SetManualCredit(true)
	chunk := min(maxChunk, int(ch.Session().RemoteLimits().MaxFramePayload))

	var mu sync.Mutex
	var sentEOF, gotEOF, stopping bool
	var result error
	// stop records why the relay is ending, then closes conn, so the reader
	// goroutine's resulting error is not mistaken for a local failure.
	stop := func(err error) {
		mu.Lock()
		if result == nil {
			result = err
		}
		stopping = true
		mu.Unlock()
		conn.Close()
	}
	finish := func(code int, reason string, err error) {
		mu.Lock()
		if result == nil {
			result = err
		}
		mu.Unlock()
		go ch.Close(context.Background(), code, reason)
	}
	bothEOF := func(sent, got bool) {
		mu.Lock()
		sentEOF, gotEOF = sentEOF || sent, gotEOF || got
		done := sentEOF && gotEOF
		mu.Unlock()
		if done {
			finish(xumux.CodeNormal, "", nil)
		}
	}

	// conn -> channel
	go func() {
		buf := make([]byte, chunk)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if e := ch.Send(ctx, TypeData, buf[:n]); e != nil {
					return // channel closed; the other direction reports why
				}
			}
			if errors.Is(err, io.EOF) {
				if ch.Send(ctx, TypeEOF, nil) == nil {
					bothEOF(true, false)
				}
				return
			}
			if err != nil {
				mu.Lock()
				deliberate := stopping
				mu.Unlock()
				if deliberate {
					return
				}
				msg, _ := json.Marshal(resetMsg{Code: xumux.CodeGoingAway, Reason: err.Error()})
				_ = ch.Send(ctx, TypeReset, msg)
				finish(xumux.CodeGoingAway, "local end failed", err)
				return
			}
		}
	}()

	// channel -> conn
	for {
		m, err := ch.Receive(ctx)
		if err != nil {
			stop(nil)
			<-ch.Done()
			mu.Lock()
			defer mu.Unlock()
			if result != nil || errors.Is(err, io.EOF) {
				return result
			}
			return err
		}
		switch m.Type {
		case TypeData:
			if _, err := conn.Write(m.Payload); err != nil {
				finish(xumux.CodeGoingAway, "local write failed", err)
				continue
			}
			ch.ReturnCredit(len(m.Payload))
		case TypeEOF:
			// Writes above are synchronous, so earlier DATA is already written.
			_ = conn.CloseWrite()
			bothEOF(false, true)
		case TypeReset:
			var r resetMsg
			_ = json.Unmarshal(m.Payload, &r)
			stop(&ResetError{Code: r.Code, Reason: r.Reason})
			finish(xumux.CodeGoingAway, "", nil)
		default:
			finish(xumux.CodeProtocolError, fmt.Sprintf("unknown pipe/1 message type %#x", m.Type), fmt.Errorf("unknown pipe/1 message type %#x", m.Type))
		}
	}
}
