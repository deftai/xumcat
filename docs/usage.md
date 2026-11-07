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
| `-v` | Log connection and channel events to stderr. |

Exit status is 0 after a clean exchange (and for `-h`), 1 if the connection or relay fails, and 2 for a usage mistake such as a missing argument or an unknown flag. `xumcat help [serve|ping]` and `-h` print help to stdout. A refused channel prints the peer's code, for example `channel refused (4500): dial tcp …: connection refused`.

## `xumcat serve [flags] XUMUX-URL...`

Listens on each URL (`stdio+xumux` serves the one connection on stdin/stdout) and answers `pipe/1` channels by connecting them to their target.

| Flag | |
|---|---|
| `-allow PATTERN` | Allow targets matching an endpoint pattern (repeatable). `*` and `?` match within one path segment. |
| `-default ADDR` | Target for channels that name none (allowed implicitly). |
| `-token TOKEN`, `-token-file FILE` | Require this token in HELLO `auth`. |
| `-tls-cert FILE`, `-tls-key FILE` | Certificate for `wss://` and `tls+xumux://` listeners. |
| `-v` | Log to stderr. |

Channel refusals use the spec's codes: `4010` (profile not `pipe/1`, no target, or target not allowed) and `4500` (target unreachable).

## `xumcat ping [flags] XUMUX-URL`

Sends probes on channel 0 and prints each round-trip time, then SRTT and RTTVAR (RFC 6298).

| Flag | |
|---|---|
| `-c N` | Number of probes (default 4; 0 = until interrupted). |
| `-i DURATION` | Interval (default `1s`). |
| `-token`, `-token-file`, `-insecure`, `-v` | As above. |

## Protocol behaviour

- **Limits:** xumcat declares the spec defaults (64 KiB frames, 256 KiB messages, 256 KiB window per channel) and sends 16 KiB fragments, interleaving channels round-robin.
- **Credit:** `pipe/1` returns credit only after bytes are written to the local end, so a slow local consumer slows down that one channel and no other.
- **Keepalive:** a ping on channel 0 after 30 s of silence, and a close with `4008` if nothing arrives within 10 s after that (the server's values apply).
- **Close:** after a CLOSE exchange each side half-closes its write side, then closes the transport.
