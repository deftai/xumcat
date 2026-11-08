# xumcat usage

## `xumcat [flags] ENDPOINT XUMUX-URL`

Opens a xumux connection to XUMUX-URL and connects ENDPOINT to a `pipe/1` channel on it. The two arguments may come in either order. Flags may come anywhere.

If ENDPOINT is a listening address (`tcp-listen:`, `unix-listen:`), xumcat keeps the one xumux connection open and opens a new channel for every accepted connection. Otherwise it relays one stream and exits once both directions have ended.

| Flag | |
|---|---|
| `-t ADDR` | Endpoint the server should connect the channel to (`metadata.target`). Without it, the server's `-default` applies. |
| `-name NAME` | Channel name (default `pipe`). |
| `-token TOKEN`, `-token-file FILE` | Shared token sent in HELLO `auth` as `{"type":"token","token":…}`. |
| `-plaintext-auth` | Allow sending the token over `ws://` or `tcp+xumux://` to a non-loopback host. |
| `-insecure` | Skip TLS certificate verification. |
| `-max-window SIZE` | Largest receive window one channel may grow to (default `16MiB`; `0` turns auto-tuning off). See [Receive windows](#receive-windows). |
| `-conn-window SIZE` | Stop growing windows once their sum on a connection reaches this (default `64MiB`). |
| `-v` | Log connection and channel events to stderr. |

Exit status is 0 after a clean exchange (and for `-h`), 1 if the connection or relay fails, and 2 for a usage mistake such as a missing argument or an unknown flag. `xumcat help [serve|ping]` and `-h` print help to stdout. A refused channel prints the peer's code, for example `channel refused (4500): dial tcp …: connection refused`.

## `xumcat serve [flags] XUMUX-URL...`

Listens on each URL (`stdio+xumux` serves the one connection on stdin/stdout) and answers `pipe/1` channels by connecting them to their target.

| Flag | |
|---|---|
| `-allow PATTERN` | Allow targets matching an endpoint pattern (repeatable). See [Allow-list patterns](#allow-list-patterns). |
| `-default ADDR` | Target for channels that name none (allowed implicitly). |
| `-token TOKEN`, `-token-file FILE` | Require this token in HELLO `auth`. |
| `-tls-cert FILE`, `-tls-key FILE` | Certificate for `wss://` and `tls+xumux://` listeners. |
| `-max-window SIZE` | Largest receive window one channel may grow to (default `16MiB`; `0` turns auto-tuning off). See [Receive windows](#receive-windows). |
| `-conn-window SIZE` | Stop growing windows once their sum on a connection reaches this (default `64MiB`). |
| `-max-conns N` | Serve at most N connections at once (default `256`; `0` = no limit). Others are refused during the handshake with `4004`. |
| `-max-procs N` | Run at most N `exec:` targets at once, across all connections (default `64`; `0` = no limit). Others are refused with `4010`. |
| `-v` | Log to stderr (including failed TLS handshakes and bad HTTP requests). |

Channel refusals use the spec's codes: `4010` (profile not `pipe/1`, no target, target not allowed, or too many processes) and `4500` (target unreachable).

### Allow-list patterns

A pattern is an endpoint address in which `*` (any run of characters) and `?` (one character) may appear. It's matched field by field, not as one string:

- **`tcp:` and `tls:`.** The host and port are matched separately.
  - Wildcards never match a `.`, so `*.example.com` matches `api.example.com` but not `a.b.example.com`.
  - A host made only of digits, dots and wildcards, or containing a `:`, is an **IP pattern**. It matches IP literals only, never a DNS name: `10.0.0.*` matches `10.0.0.7` but not a name such as `10.0.0.7.example.net`.
  - IPv6 works: `tcp:[::1]:*`. Exact IPs compare by value, so `[0:0::1]` matches `[::1]`.
  - A host of `*` alone matches any host.
  - Ports must be numbers from 1 to 65535.
- **`unix:`.** Wildcards stay within one path segment. Patterns and target paths must be absolute, and targets must already be clean, with no `..`, `.`, `//` or trailing `/`. On Linux, abstract names (`@name`) are the exception to "absolute", and must be clean in the same way. On other systems an `@` path is relative, so it is refused.
- **`exec:`.** Matched exactly. `serve` refuses to start if an `exec:` pattern has a wildcard: the command runs through `sh -c`, so a wildcard would let a peer append shell syntax.
- There are no character classes: `[` and `]` are literal.

Name patterns trust DNS: `tcp:*.corp.example:*` allows whatever those names resolve to.

## `xumcat ping [flags] XUMUX-URL`

Sends probes on channel 0 and prints each round-trip time, then SRTT and RTTVAR (RFC 6298).

| Flag | |
|---|---|
| `-c N` | Number of probes (default 4; 0 = until interrupted). |
| `-i DURATION` | Interval (default `1s`). |
| `-token`, `-token-file`, `-insecure`, `-v` | As above. |

## Protocol behaviour

- **Limits:** xumcat declares the spec defaults (64 KiB frames, 256 KiB messages, 256 KiB initial window per channel) and sends 16 KiB fragments, interleaving channels round-robin.
- **Credit:** `pipe/1` returns credit only after bytes are written to the local end, so a slow local consumer slows down that one channel and no other.
- **Keepalive:** a ping on channel 0 after 30 s of silence, and a close with `4008` if nothing arrives within 10 s after that (the server's values apply).
- **Close:** after a CLOSE exchange each side half-closes its write side, then closes the transport.

## Receive windows

One channel can have at most a window of data in flight, so it can't go faster than window ÷ round-trip time. The initial 256 KiB window gives about 5 MB/s at 50 ms or 2.6 MB/s at 100 ms. To keep long links fast, the receiver auto-tunes:

- Each channel starts at the 256 KiB initial window.
- If the sender uses a whole window in under two round trips, the window is what's limiting it, so the receiver doubles the window. It grants the extra credit in its next WINDOW_UPDATE.
- The round-trip time comes from probes. When none has completed yet, one is sent.
- A window grows up to `-max-window` (default 16 MiB, about 160 MB/s at 100 ms).
- No window grows once the sum of all channel windows on the connection would pass `-conn-window` (default 64 MiB). Initial windows are always granted, even on top of windows that already grew, so the total is at most `-conn-window` + (open channels × 256 KiB). With the defaults and `serve`'s 1024-channel limit, that's 320 MiB at worst.
- Windows don't shrink. A channel's window leaves the total when the channel closes, though data it received that hasn't been read yet stays buffered until it is.
- The round-trip time is re-measured, at most once a second, while growth checks fail, so windows keep growing if the path gets slower.

Each side tunes its own receive windows, so set the flags on the side that receives the bulk data: `serve` for uploads, the client for downloads. Auto-tuning is purely local and needs nothing from the peer, so it works with any xumux implementation. Measured through a delay proxy on one machine, a single channel moving 50 MB:

| RTT | Fixed 256 KiB window | Auto-tuned |
|---|---|---|
| 10 ms | 21 MB/s | 352 MB/s |
| 50 ms | 4.4 MB/s | 77 MB/s |
| 100 ms | 2.4 MB/s | 42 MB/s |
| 200 ms | 1.2 MB/s | 22 MB/s |

These figures include the ramp-up. Longer transfers get closer to the `-max-window` ÷ RTT limit.
