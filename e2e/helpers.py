"""Test helpers for xumcat <-> xumcat runs.

  echo PORT                 TCP echo server; half-closes after the client's EOF
  stall PORT SECONDS        connect, read nothing for SECONDS, then report bytes waiting
  fanout PORT N SIZE        N concurrent echo round trips of SIZE random bytes; print ok count
"""
import os, socket, sys, threading, time


def echo(port):
    srv = socket.create_server(("127.0.0.1", port), reuse_port=True)
    srv.listen(256)

    def handle(c):
        c.settimeout(120)  # a stuck client cannot pin a thread forever
        with c:
            try:
                while True:
                    b = c.recv(65536)
                    if not b:
                        break
                    c.sendall(b)
                c.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def stall(port, seconds):
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    time.sleep(seconds)
    c.setblocking(False)
    n = 0
    try:
        while True:
            b = c.recv(1 << 20)
            if not b:
                break
            n += len(b)
    except BlockingIOError:
        pass
    print(n)


def fanout(port, n, size):
    ok = []
    lock = threading.Lock()

    def one():
        data = os.urandom(size)
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=30)
            threading.Thread(target=lambda: (c.sendall(data), c.shutdown(socket.SHUT_WR)), daemon=True).start()
            buf = bytearray()
            while True:
                b = c.recv(65536)
                if not b:
                    break
                buf += b
            if bytes(buf) == data:
                with lock:
                    ok.append(1)
        except OSError as e:
            print("error:", e, file=sys.stderr)

    ts = [threading.Thread(target=one) for _ in range(n)]
    t = time.time()
    for x in ts:
        x.start()
    for x in ts:
        x.join()
    print(f"{len(ok)}/{n} {time.time() - t:.2f}s")


if __name__ == "__main__":
    cmd, args = sys.argv[1], [float(a) if "." in a else int(a) for a in sys.argv[2:]]
    {"echo": echo, "stall": stall, "fanout": fanout}[cmd](*args)
