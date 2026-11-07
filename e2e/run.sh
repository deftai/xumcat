#!/usr/bin/env bash
# xumcat <-> xumcat end-to-end tests: real processes, real sockets, no mocks.
#
#   e2e/run.sh [scenario...]     default: all scenarios
#
# Scenarios: transports halfclose forward flowcontrol sharedfc auth ping failure
# Environment: XUMCAT (binary, default bin/xumcat), E2E_MB (transfer size, default 50).
# Needs bash, python3, perl, curl, openssl, nc. Uses TCP ports 17001-17501 on 127.0.0.1.
set -u
SCENARIOS="transports halfclose forward flowcontrol sharedfc auth ping failure"
HERE=$(cd "$(dirname "$0")" && pwd)
X=${XUMCAT:-$HERE/../bin/xumcat}
X=$(cd "$(dirname "$X")" && pwd)/$(basename "$X")
[ -x "$X" ] || { echo "no xumcat binary at $X (run 'make build' or set XUMCAT)"; exit 2; }
selected=("${@:-$SCENARIOS}")
for s in ${selected[*]}; do
  case " $SCENARIOS " in *" $s "*) ;; *) echo "unknown scenario '$s' (want: $SCENARIOS)"; exit 2;; esac
done

PY="python3 -I $HERE/helpers.py"
TOKEN=s3cret
WORK=$(mktemp -d)
cd "$WORK"
pids=()
pass=0 fail=0

cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; cd /; rm -rf "$WORK"; }
trap cleanup EXIT
sha256() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
# t SECONDS CMD...: run CMD, killing it with SIGALRM (exit 142) if it takes longer.
t() { perl -e '$s = shift; alarm $s; exec @ARGV or die "exec: $!"' "$@"; }
bg() { "$@" & pids+=($!); }
ok() { pass=$((pass+1)); printf '  PASS  %s\n' "$*"; }
no() { fail=$((fail+1)); printf '  FAIL  %s\n' "$*"; }
check() { if [ "$1" = "$2" ]; then ok "$3"; else no "$3 (got '$1', want '$2')"; fi; }
waitport() { for _ in $(seq 200); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.05; done; no "port $1 never opened"; return 1; }
now() { python3 -c 'import time; print(time.time())'; }
mbps() { python3 -c "print(f'{$1/1e6/max($2,1e-3):.0f} MB/s')"; }
rss_mb() { echo $(( $(ps -o rss= -p "$1" | tr -d ' ') / 1024 )); }
# below A B: succeed if A < B (floats)
below() { python3 -c "import sys; sys.exit(0 if $1 < $2 else 1)"; }

head -c $(( ${E2E_MB:-50} * 1000000 )) /dev/urandom > big.bin
echo hello > small.txt
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem \
  -days 1 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
SUM=$(sha256 < big.bin)
SIZE=$(wc -c < big.bin | tr -d ' ')
MB=$((SIZE/1000000))
echo "xumcat: $("$X" version)   work dir: $WORK"

# Targets, and the shared server every scenario uses.
ALLOW=(-allow 'tcp:127.0.0.1:*' -allow 'exec:wc -c' -allow 'exec:yes' -token "$TOKEN")
bg $PY echo 17001
bg python3 -I -m http.server 17002 --bind 127.0.0.1 -d . >/dev/null 2>&1
bg "$X" serve tcp+xumux://127.0.0.1:17101 tls+xumux://127.0.0.1:17102 ws://127.0.0.1:17103/x \
  wss://127.0.0.1:17104/x unix+xumux:x.sock "${ALLOW[@]}" -tls-cert cert.pem -tls-key key.pem 2>serve.log
SERVER=$!
for p in 17001 17002 17101 17102 17103 17104; do waitport $p || exit 1; done

scenario_transports() {
  echo "== $MB MB round trip through an echo target, per transport (sha256 checked)"
  for url in tcp+xumux://127.0.0.1:17101 tls+xumux://127.0.0.1:17102 ws://127.0.0.1:17103/x wss://127.0.0.1:17104/x unix+xumux:x.sock \
             "exec+xumux:$X serve stdio+xumux -allow tcp:127.0.0.1:17001"; do
    flags=(-t tcp:127.0.0.1:17001)
    case "$url" in exec*) ;; *) flags+=(-token "$TOKEN");; esac
    case "$url" in tls*|wss*) flags+=(-insecure);; esac
    t0=$(now)
    got=$(t 120 "$X" stdio "$url" "${flags[@]}" < big.bin 2>err.txt | sha256)
    dt=$(python3 -c "print($(now)-$t0)")
    label="${url%%:*}  $(mbps $((SIZE*2)) "$dt") both ways"
    if [ "$got" = "$SUM" ] && [ ! -s err.txt ]; then ok "$label"; else no "$label: sha mismatch or stderr: $(head -c 200 err.txt)"; fi
  done
}

scenario_halfclose() {
  echo "== half-close: target replies only after our EOF"
  got=$(head -c 10000000 /dev/zero | t 60 "$X" stdio tcp+xumux://127.0.0.1:17101 -t 'exec:wc -c' -token $TOKEN 2>&1 | tr -d ' ')
  check "$got" 10000000 "exec:wc -c counts all 10000000 bytes, then the relay ends"
  got=$(printf '' | t 30 "$X" stdio tcp+xumux://127.0.0.1:17101 -t 'exec:wc -c' -token $TOKEN 2>&1 | tr -d ' ')
  check "$got" 0 "empty input: immediate EOF still gets the reply"
}

scenario_forward() {
  echo "== port forwarding: one xumux connection, one channel per TCP connection"
  bg "$X" tcp-listen:127.0.0.1:17201 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17001 -token $TOKEN 2>fwd.log
  waitport 17201 || return
  r=$(t 120 $PY fanout 17201 100 200000); check "${r%% *}" 100/100 "100 concurrent 200 kB echo round trips ($r)"
  r=$(t 120 $PY fanout 17201 500 1000); check "${r%% *}" 500/500 "500 concurrent short connections ($r)"
  bg "$X" tcp-listen:127.0.0.1:17202 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17002 -token $TOKEN 2>fwd2.log
  waitport 17202 || return
  got=$(curl -s --max-time 120 http://127.0.0.1:17202/big.bin | sha256)
  check "$got" "$SUM" "curl GET $MB MB over HTTP through the forward"
  codes=$(for i in $(seq 20); do curl -s --max-time 30 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:17202/small.txt & done; wait)
  check "$(echo "$codes" | grep -c 200)" 20 "20 parallel HTTP requests all 200"
}

scenario_flowcontrol() {
  echo "== a stalled channel: bounded buffering on both ends"
  # Channel A: an endless 'yes' stream into a reader that stalls for 6 s.
  bg "$X" tcp-listen:127.0.0.1:17301 tcp+xumux://127.0.0.1:17101 -t 'exec:yes' -token $TOKEN 2>fc.log; fwd=$!
  bg "$X" tcp-listen:127.0.0.1:17302 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17002 -token $TOKEN 2>fc2.log
  waitport 17301 && waitport 17302 || return
  srv0=$(rss_mb $SERVER); fwd0=$(rss_mb $fwd)
  echo "        before: server RSS $srv0 MB, forwarder RSS $fwd0 MB"
  t 30 $PY stall 17301 6 > stall.out & spid=$!
  sleep 1
  got=$(curl -s --max-time 120 http://127.0.0.1:17302/big.bin | sha256)
  check "$got" "$SUM" "$MB MB transfer completes while a 'yes' channel is stalled"
  sleep 2
  srv1=$(rss_mb $SERVER); fwd1=$(rss_mb $fwd)
  wait $spid
  queued=$(cat stall.out)
  # Credit bounds what can pile up: the window plus socket buffers.
  if [ -n "$queued" ] && [ "$queued" -lt 4000000 ]; then ok "stalled reader had only $queued bytes waiting"; else no "stalled reader had '$queued' bytes waiting"; fi
  if [ $((srv1 - srv0)) -lt 50 ]; then ok "server RSS grew $((srv1 - srv0)) MB during the stall"; else no "server RSS grew $((srv1 - srv0)) MB during the stall"; fi
  if [ $((fwd1 - fwd0)) -lt 50 ]; then ok "forwarder RSS grew $((fwd1 - fwd0)) MB during the stall"; else no "forwarder RSS grew $((fwd1 - fwd0)) MB during the stall"; fi
}

scenario_sharedfc() {
  echo "== flow control on ONE xumux connection: slow channel + fast channel"
  bg "$X" tcp-listen:127.0.0.1:17401 tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17002 -token $TOKEN 2>sfc.log
  waitport 17401 || return
  # Channel A: a download read at 50 kB/s, so its channel runs out of credit.
  curl -s --max-time 600 --limit-rate 50k -o /dev/null http://127.0.0.1:17401/big.bin & cpid=$!
  sleep 1
  t0=$(now)
  got=$(curl -s --max-time 60 http://127.0.0.1:17401/big.bin | sha256)
  dt=$(python3 -c "print($(now)-$t0)")
  check "$got" "$SUM" "fast $MB MB on the same connection as a 50 kB/s channel ($(mbps $SIZE "$dt"))"
  # The slow download needs ~$((SIZE/50000)) s; the fast one must not have waited for it.
  if kill -0 $cpid 2>/dev/null && below "$dt" 30; then ok "the fast transfer finished in $(printf %.1f "$dt") s while the slow one was still running"
  else no "the fast transfer took $(printf %.1f "$dt") s, or the slow one had already ended"; fi
  kill $cpid 2>/dev/null; wait $cpid 2>/dev/null
}

scenario_auth() {
  echo "== auth and allow-list"
  out=$(echo hi | t 30 "$X" stdio tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17001 -token wrong 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4000)" "1:1" "wrong token refused with 4000"
  out=$(echo hi | t 30 "$X" stdio tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:17001 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4000)" "1:1" "missing token refused with 4000"
  out=$(echo hi | t 30 "$X" stdio tcp+xumux://127.0.0.1:17101 -t exec:sh -token $TOKEN 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4010)" "1:1" "target exec:sh not allowed (4010)"
  out=$(echo hi | t 30 "$X" stdio tcp+xumux://127.0.0.1:17101 -t tcp:127.0.0.1:1 -token $TOKEN 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -c 4500)" "1:1" "unreachable target (4500)"
  out=$(echo hi | t 30 "$X" stdio tls+xumux://127.0.0.1:17102 -t tcp:127.0.0.1:17001 -token $TOKEN 2>&1); rc=$?
  check "$rc:$(echo "$out" | grep -ci certificate)" "1:1" "self-signed cert rejected without -insecure"
}

scenario_ping() {
  echo "== ping"
  out=$(t 30 "$X" ping tcp+xumux://127.0.0.1:17101 -token $TOKEN -c 5 -i 100ms 2>&1)
  echo "$out" | sed 's/^/        /'
  check "$(echo "$out" | grep -c '5 sent, 0 lost')" 1 "5 pings, none lost"
}

scenario_failure() {
  echo "== failure: the server dies mid-transfer"
  "$X" serve tcp+xumux://127.0.0.1:17501 -allow 'exec:yes' 2>/dev/null & victim=$!
  pids+=($victim)
  waitport 17501 || return
  ( sleep 1; kill -9 $victim ) &
  t0=$(now)
  t 10 "$X" stdio tcp+xumux://127.0.0.1:17501 -t exec:yes 2>err.txt >/dev/null; rc=$?
  dt=$(python3 -c "print(round($(now)-$t0,1))")
  wait $victim 2>/dev/null
  if [ $rc -eq 1 ] && below "$dt" 3 && grep -q "xumux: connection lost:" err.txt; then
    ok "client exits 1 within ${dt}s reporting a lost connection: $(head -c 100 err.txt)"
  else
    no "rc=$rc after ${dt}s (want 1 within 3 s and 'connection lost'): $(head -c 200 err.txt)"
  fi
}

for s in ${selected[*]}; do "scenario_$s"; done
echo
echo "passed $pass, failed $fail"
[ -s serve.log ] && { echo "--- serve.log"; head -20 serve.log; }
[ "$fail" -eq 0 ]
