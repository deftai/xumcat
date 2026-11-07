#!/usr/bin/env bash
# xumcat <-> xumcat end-to-end tests: real processes, real sockets, no mocks.
#
#   e2e/run.sh [scenario...]     default: all scenarios
#
# Scenarios: transports halfclose forward flowcontrol sharedfc auth ping failure
# Environment: XUMCAT (binary, default bin/xumcat), E2E_MB (transfer size, default 50).
# Needs bash, python3, curl, openssl, nc. Uses TCP ports 17001-17501 on 127.0.0.1.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
X=${XUMCAT:-$HERE/../bin/xumcat}
X=$(cd "$(dirname "$X")" && pwd)/$(basename "$X")
[ -x "$X" ] || { echo "no xumcat binary at $X (run 'make build' or set XUMCAT)"; exit 2; }
PY="python3 -I $HERE/helpers.py"
TOKEN=s3cret
WORK=$(mktemp -d)
cd "$WORK"
pids=()
pass=0 fail=0

cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; cd /; rm -rf "$WORK"; }
trap cleanup EXIT
sha256() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }

head -c $(( ${E2E_MB:-50} * 1000000 )) /dev/urandom > big.bin
echo hello > small.txt
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem \
  -days 1 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
SUM=$(sha256 < big.bin)
SIZE=$(wc -c < big.bin | tr -d ' ')
echo "xumcat: $("$X" version)   work dir: $WORK"
bg() { "$@" & pids+=($!); }
ok() { pass=$((pass+1)); printf '  PASS  %s\n' "$*"; }
no() { fail=$((fail+1)); printf '  FAIL  %s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then ok "$3"; else no "$3 (got '$1', want '$2')"; fi; }
waitport() { for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return; sleep 0.05; done; echo "port $1 never opened"; }
now() { python3 -c 'import time; print(time.time())'; }
mbps() { python3 -c "print(f'{$1/1e6/max($2,1e-3):.0f} MB/s')"; }

# Targets
bg $PY echo 17001; waitport 17001
bg python3 -I -m http.server 17002 --bind 127.0.0.1 -d . >/dev/null 2>&1; waitport 17002

ALLOW=(-allow 'tcp:127.0.0.1:*' -allow 'exec:wc -c' -allow 'exec:yes' -token "$TOKEN")
TLS=(-tls-cert cert.pem -tls-key key.pem)

scenario_transports() {
  echo "== $((SIZE/1000000)) MB round trip through an echo target, per transport (sha256 checked)"
  bg $X serve tcp+xumux://127.0.0.1:17101 tls+xumux://127.0.0.1:17102 ws://127.0.0.1:17103/x wss://127.0.0.1:17104/x unix+xumux:x.sock "${ALLOW[@]}" "${TLS[@]}" 2>serve.log
  waitport 17101; waitport 17102; waitport 17103; waitport 17104
  for url in tcp+xumux://127.0.0.1:17101 tls+xumux://127.0.0.1:17102 ws://127.0.0.1:17103/x wss://127.0.0.1:17104/x unix+xumux:x.sock \
             "exec+xumux:$X serve stdio+xumux -allow tcp:127.0.0.1:17001"; do
    flags=(-t tcp:127.0.0.1:17001)
    case "$url" in exec*) ;; *) flags+=(-token "$TOKEN");; esac
    case "$url" in tls*|wss*) flags+=(-insecure);; esac
    t0=$(now)
    got=$($X stdio "$url" "${flags[@]}" < big.bin 2>err.txt | sha256); rc=$?
    t1=$(now); dt=$(python3 -c "print($t1-$t0)")
    label="${url%%:*}  $(mbps $((SIZE*2)) "$dt") both ways"
    if [ "$got" = "$SUM" ] && [ ! -s err.txt ]; then ok "$label"; else no "$label: sha mismatch or stderr: $(head -c 200 err.txt)"; fi
  done
}

scenario_halfclose() {
  echo "== half-close: target replies only after our EOF"
  got=$(head -c 10000000 /dev/zero | $X stdio tcp+xumux://127.0.0.1:17101 -t 'exec:wc -c' -token $TOKEN 2>&1 | tr -d ' ')
  check "$got" 10000000 "exec:wc -c counts all 10000000 bytes, then the relay ends"
  got=$(printf '' | $X stdio tcp+xumux://127.0.0.1:17101 -t 'exec:wc -c' -token $TOKEN 2>&1 | tr -d ' ')
  check "$got" 0 "empty input: immediate EOF still gets the reply"
}

scenario_forward() {
  echo "== port forwarding: one xumux connection, one channel per TCP connection"
  bg $X tcp-listen:127.0.0.1:17201 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17001 -token $TOKEN 2>fwd.log
  waitport 17201
  r=$($PY fanout 17201 100 200000); check "${r%% *}" 100/100 "100 concurrent 200 kB echo round trips ($r)"
  r=$($PY fanout 17201 500 1000); check "${r%% *}" 500/500 "500 concurrent short connections ($r)"
  bg $X tcp-listen:127.0.0.1:17202 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17002 -token $TOKEN 2>fwd2.log
  waitport 17202
  got=$(curl -s http://127.0.0.1:17202/big.bin | sha256)
  check "$got" "$SUM" "curl GET $((SIZE/1000000)) MB over HTTP through the forward"
  codes=$(for i in $(seq 20); do curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:17202/small.txt & done; wait)
  check "$(echo "$codes" | grep -c 200)" 20 "20 parallel HTTP requests all 200"
}

scenario_flowcontrol() {
  echo "== a stalled channel: bounded buffering, server unaffected"
  # One forward = one xumux connection. Channel A: infinite 'yes' into a reader that stalls.
  nc -z 127.0.0.1 17101 2>/dev/null || { bg $X serve tcp+xumux://127.0.0.1:17101 "${ALLOW[@]}" 2>serve.log; waitport 17101; }
  bg $X tcp-listen:127.0.0.1:17301 tcp+xumux://127.0.0.1:17101 -t 'exec:yes' -token $TOKEN 2>fc.log
  bg $X tcp-listen:127.0.0.1:17302 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17002 -token $TOKEN 2>fc2.log
  waitport 17301; waitport 17302
  $PY stall 17301 6 > stall.out & spid=$!
  sleep 1
  spid_rss() { ps -o rss= -p "$1" | tr -d ' '; }
  srv=$(pgrep -f "serve tcp.xumux://127.0.0.1:17101" | head -1); [ -n "$srv" ] || { no "server pid not found"; return; }
  rss0=$(spid_rss "$srv"); echo "        server pid $srv, RSS $((rss0/1024)) MB before"
  got=$(curl -s http://127.0.0.1:17302/big.bin | sha256)
  check "$got" "$SUM" "$((SIZE/1000000)) MB transfer completes while a 'yes' channel is stalled"
  sleep 2
  rss1=$(spid_rss "$srv")
  wait $spid
  queued=$(cat stall.out)
  # Credit bounds what can pile up for the stalled channel: window (256 KiB) + socket buffers.
  if [ "$queued" -lt 4000000 ]; then ok "stalled reader had only $queued bytes waiting (bounded by credit + socket buffers)"; else no "stalled reader had $queued bytes waiting"; fi
  growth=$(( (rss1 - rss0) / 1024 ))
  if [ "$growth" -lt 50 ]; then ok "server RSS grew ${growth} MB during the stall"; else no "server RSS grew ${growth} MB during the stall"; fi
}

scenario_sharedfc() {
  echo "== flow control on ONE xumux connection: stalled channel + busy channel"
  bg $X tcp-listen:127.0.0.1:17401 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17002 -token $TOKEN 2>sfc.log
  waitport 17401
  # Channel A: a big download read at 50 kB/s, so its channel runs out of credit.
  curl -s --limit-rate 50k -o /dev/null http://127.0.0.1:17401/big.bin & cpid=$!
  sleep 1
  t0=$(now)
  got=$(curl -s http://127.0.0.1:17401/big.bin | sha256)
  dt=$(python3 -c "print($(now)-$t0)")
  check "$got" "$SUM" "fast $((SIZE/1000000)) MB on the same connection as a 50 kB/s channel ($(mbps $SIZE "$dt"))"
  kill $cpid 2>/dev/null; wait $cpid 2>/dev/null
}

scenario_auth() {
  echo "== auth and allow-list"
  out=$(echo hi | $X stdio tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17001 -token wrong 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4000)" "1:1" "wrong token refused with 4000"
  out=$(echo hi | $X stdio tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17001 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4000)" "1:1" "missing token refused with 4000"
  out=$(echo hi | $X stdio tcp+xumux://127.0.0.1:17101 -t exec:sh -token $TOKEN 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4010)" "1:1" "target exec:sh not allowed (4010)"
  out=$(echo hi | $X stdio tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:1 -token $TOKEN 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4500)" "1:1" "unreachable target (4500)"
  out=$(echo hi | $X stdio tls+xumux://127.0.0.1:17102 -t tcp:127.0.0.1:17001 -token $TOKEN 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -ci certificate)" "1:1" "self-signed cert rejected without -insecure"
}

scenario_ping() {
  echo "== ping"
  out=$($X ping tcp+xumux://127.0.0.1:17101 -token $TOKEN -c 5 -i 100ms 2>&1)
  echo "$out" | sed 's/^/        /'
  check "$(echo "$out" | grep -c '5 sent, 0 lost')" 1 "5 pings, none lost"
}

scenario_failure() {
  echo "== failure: the server dies mid-transfer"
  bg $X serve tcp+xumux://127.0.0.1:17501 -allow 'exec:yes' 2>/dev/null; spid=$!
  waitport 17501
  ( sleep 1; kill -9 $spid ) &
  t0=$(now)
  $X stdio tcp+xumux://127.0.0.1:17501 -t exec:yes 2>err.txt >/dev/null; rc=$?
  dt=$(python3 -c "print(round($(now)-$t0,1))")
  if [ $rc -eq 1 ] && python3 -c "import sys; sys.exit(0 if $dt < 3 else 1)"; then ok "client exits 1 within ${dt}s: $(head -c 120 err.txt)"; else no "rc=$rc after ${dt}s: $(head -c 200 err.txt)"; fi
}

for s in "${@:-transports halfclose forward flowcontrol sharedfc auth ping failure}"; do for x in $s; do scenario_$x; done; done
echo
echo "passed $pass, failed $fail"
[ -s serve.log ] && { echo "--- serve.log"; head -20 serve.log; }
[ "$fail" -eq 0 ]
