// Package pipe connects xumux pipe/1 channels to endpoints: a Responder
// that dials allow-listed targets for the pipes peers open, and Relay,
// which copies between a pipe and a local connection. The profile itself
// (pipe.Conn, a net.Conn) is in github.com/deftai/libxumux-go/pipe.
package pipe

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	xumux "github.com/deftai/libxumux-go"
	lpipe "github.com/deftai/libxumux-go/pipe"
	"github.com/deftai/xumcat/endpoint"
)

// Profile is the metadata.profile value of a pipe/1 channel.
const Profile = lpipe.Profile

// Message types.
const (
	TypeData  = lpipe.TypeData
	TypeEOF   = lpipe.TypeEOF
	TypeReset = lpipe.TypeReset
)

// CodeTargetUnreachable refuses a channel whose target cannot be reached.
const CodeTargetUnreachable = lpipe.CodeTargetUnreachable

// CodeBusy (4011 BUSY) refuses a connection or channel because a resource
// shared across connections is exhausted: xumcat's -max-conns and
// -max-procs limits. It moves to libxumux-go (xumux.CodeBusy) in a later
// release.
const CodeBusy = 4011

// ResetError reports that the far end of the pipe failed.
type ResetError = lpipe.ResetError

// Spec describes a pipe/1 channel. An empty target lets the responder choose.
func Spec(name, target string) xumux.ChannelSpec { return lpipe.Spec(name, target) }

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
		if err := lpipe.IsPipe(req); err != nil {
			return nil, err
		}
		target := lpipe.Target(req)
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
				return nil, &xumux.Refusal{Code: CodeBusy, Reason: "too many processes running"}
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

// Relay copies bytes between the pipe/1 channel ch and conn until both
// directions have ended, then closes both. It returns nil after a clean
// exchange of EOFs, a *ResetError if the peer's end failed, or the error
// that ended the relay. A failure of conn is reported to the peer as a
// RESET.
//
// Each direction is an io.Copy over a pipe.Conn: DATA is never
// fragmented, and credit goes back to the peer only once conn has taken
// the bytes, as pipe/1 requires.
func Relay(ctx context.Context, ch *xumux.Channel, conn endpoint.Conn) error {
	p := lpipe.NewConn(ch)
	defer conn.Close()
	defer p.Close()

	// stop closes conn on purpose, so that the read it unblocks is not
	// taken for a failure of conn.
	var stopping atomic.Bool
	// localErr is the failure of conn, if any, recorded before the RESET
	// goes out: that RESET closes the channel, and the error the pipe
	// side then sees is only a consequence.
	var localErr atomic.Pointer[error]
	fail := func(err error, reason string) {
		localErr.CompareAndSwap(nil, &err)
		_ = p.Reset(xumux.CodeGoingAway, reason)
	}
	stop := func() {
		stopping.Store(true)
		conn.Close()
	}
	stopCtx := context.AfterFunc(ctx, func() { p.Close() })
	defer stopCtx()

	// conn -> pipe
	local := make(chan error, 1)
	go func() {
		r := &errReader{r: conn}
		_, err := io.Copy(p, r)
		switch {
		case r.err != nil && !stopping.Load():
			fail(r.err, r.err.Error())
			local <- r.err
		case err == nil:
			_ = p.CloseWrite()
			local <- nil
		default:
			local <- nil // the pipe ended; the other direction says why
		}
	}()

	// pipe -> conn
	w := &errWriter{w: conn}
	_, err := io.Copy(w, p)
	var result error
	switch {
	case w.err != nil && !stopping.Load():
		fail(w.err, "local write failed: "+w.err.Error())
		result = w.err
	case err == nil:
		_ = conn.CloseWrite() // the peer's EOF, after all its DATA
	default:
		// A RESET, a protocol error, a closed channel. After a RESET or a
		// protocol error, the deferred p.Close closes the channel with the
		// failure's code (1001 or 1002), not 1000.
		result = err
	}
	// After stop, the conn -> pipe goroutine is not waited for: closing
	// some conns (stdin) cannot interrupt a read already in progress, and
	// it has nothing left to report.
	var lerr error
	if result != nil {
		stop()
	} else {
		// Everything the peer sent has been written. Wait for conn's
		// side to end, or for the channel to close first (the peer is
		// done with the pipe).
		select {
		case lerr = <-local:
		case <-ch.Done():
			stop()
			select {
			case lerr = <-local:
			default:
			}
		}
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e := localErr.Load(); e != nil {
		return *e
	}
	var re *ResetError
	if errors.As(result, &re) {
		return re
	}
	if lerr != nil {
		return lerr
	}
	return result
}

// errReader and errWriter remember the error of the local connection, to
// tell it apart from the pipe's.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(b []byte) (int, error) {
	n, err := e.r.Read(b)
	if err != nil && err != io.EOF {
		e.err = err
	}
	return n, err
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(b []byte) (int, error) {
	n, err := e.w.Write(b)
	if err != nil {
		e.err = err
	}
	return n, err
}
