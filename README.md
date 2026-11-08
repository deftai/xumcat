# xumcat

`xumcat` is netcat/socat for [xumux](https://github.com/deftai/xumux): it relays byte streams over a xumux connection. One connection (WebSocket, TCP, TLS, a Unix socket, stdio or an SSH session) carries any number of streams side by side, each one a [`pipe/1`](https://github.com/deftai/xumux/blob/main/spec/profiles/pipe.md) channel with its own flow control.

The xumux protocol itself is implemented by [libxumux-go](https://github.com/deftai/libxumux-go), a standalone Go module. It was written from the spec independently of the TypeScript [libxumux](https://github.com/deftai/libxumux) and is tested against it in both directions.

> **Status:** xumux 0.2.0-draft. The wire format can still change before 1.0.

## Install

```sh
go install github.com/deftai/xumcat/cmd/xumcat@latest
```

or download a binary from [Releases](https://github.com/deftai/xumcat/releases), or `make build` for `bin/xumcat`.

## Quick start

```sh
# On the server: answer pipe/1 channels, but only to local SSH and web ports.
xumcat serve tcp+xumux://:7000 -allow tcp:localhost:22 -allow 'tcp:localhost:80*' -token-file /etc/xumcat.token

# On a client: use the remote SSH port as stdin/stdout…
ssh -o ProxyCommand='xumcat stdio tcp+xumux://server:7000 -t tcp:localhost:22 -token-file ~/.xumcat.token -plaintext-auth' server

# …or forward a local port. Every accepted connection becomes a channel on one xumux connection.
xumcat tcp-listen:8080 wss://server/xumux -t tcp:localhost:8080 -token-file ~/.xumcat.token

# No listener at all: run the server end over SSH (the stdio binding).
xumcat tcp-listen:5432 exec+xumux:'ssh db xumcat serve stdio+xumux -allow tcp:localhost:5432' -t tcp:localhost:5432

# Round-trip time on the connection.
xumcat ping wss://server/xumux
```

Arguments are an **endpoint** and a **xumux URL**, in either order:

| Endpoints (`pipe/1` addresses) | |
|---|---|
| `tcp:HOST:PORT`, `tls:HOST:PORT`, `unix:PATH` | connect |
| `tcp-listen:[HOST:]PORT`, `unix-listen:PATH` | listen; one channel per accepted connection |
| `stdio` | this process's stdin/stdout |
| `exec:COMMAND` | run `sh -c COMMAND` (Windows: `cmd.exe /c`, [details](docs/usage.md#exec-on-windows)) and use its stdin/stdout |

| xumux URLs | Binding |
|---|---|
| `ws://HOST:PORT/PATH`, `wss://…` | WebSocket, subprotocol `xumux` |
| `tcp+xumux://HOST:PORT`, `tls+xumux://HOST:PORT` | TCP (magic `XMUX`) |
| `unix+xumux:PATH` | TCP binding on a Unix socket |
| `stdio+xumux` | stdio binding on this process |
| `exec+xumux:COMMAND` | stdio binding on a spawned command, e.g. `ssh host xumcat serve stdio+xumux` |

See [docs/usage.md](docs/usage.md) for every flag.

## Security

- **`serve` connects only to targets you allow.** `-allow` takes endpoint patterns with `*` and `?` wildcards (`tcp:localhost:*`, `tcp:10.0.0.?:22`, `unix:/run/app/*.sock`), matched field by field ([details](docs/usage.md#allow-list-patterns)). With no `-allow` and no `-default`, `serve` refuses to start. An unrestricted allow-list turns the server into an open proxy. `exec:` patterns must be exact commands, and allowing one lets clients run that command.
- **Limits.** `serve` handles at most 256 connections (`-max-conns`) and 64 running `exec:` targets (`-max-procs`) at once, refusing more with `4011` (BUSY), and each connection at most 1024 channels. A peer that stops reading while still sending frames that need replies is disconnected with `4004` once 1 MiB of replies is queued (`xumux.Options.MaxControlQueue`).
- **`-token` / `-token-file`** puts a shared token in HELLO `auth`. The server compares it in constant time and refuses with `4000` otherwise. The client will not send a token over an unencrypted transport to a non-loopback host unless you pass `-plaintext-auth`. Use `wss://` or `tls+xumux://` (server: `-tls-cert`, `-tls-key`), or run over SSH with `exec+xumux:`.
- `serve` warns when a network listener has no token.

## The Go library

```go
import (
	xumux "github.com/deftai/libxumux-go"
	"github.com/deftai/xumcat/transport"
)

fc, _ := transport.Dial(ctx, "wss://example.com/xumux", transport.Options{})
s, res, err := xumux.Connect(ctx, fc, xumux.ClientConfig{
	Application: "myapp/1",
	Channels:    []xumux.ChannelSpec{{Name: "data", Reliable: true, Ordered: true}},
}, xumux.Options{})
ch := res.Channels[0]
ch.Send(ctx, 0x01, []byte("hello"))   // blocks for flow-control credit
msg, err := ch.Receive(ctx)           // io.EOF after a normal close
rtt, err := ch.Ping(ctx)              // per-channel round-trip time
```

A server uses `xumux.Accept` with an `Options.Acceptor`, which decides on every channel the peer opens. The protocol core is [libxumux-go](https://github.com/deftai/libxumux-go); this repository adds:

| Package | |
|---|---|
| [`transport`](transport) | xumux URLs: dial and serve WebSocket, TCP, TLS, Unix, stdio, exec |
| [`pipe`](pipe) | The `pipe/1` profile: `Open`, `Relay`, and an allow-listing `Responder` |
| [`endpoint`](endpoint) | Endpoint addresses: parse, dial, listen, allow-list matching |

## Development

```sh
make check          # fmt, vet, race tests, coverage (≥75% per package)
make test/e2e       # xumcat <-> xumcat with real processes: transports, forwarding, flow control, auth
make help
```

## License

MIT
