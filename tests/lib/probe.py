import argparse, errno, os, socket, struct, sys, threading, time

def family(v6):
    return socket.AF_INET6 if v6 else socket.AF_INET

def send_all(c, a):
    if a.file:
        with open(a.file, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                c.sendall(chunk)
    else:
        c.sendall(a.token.encode())
        if a.half_close_reply:
            # The client shut down its write side; keep serving it anyway.
            time.sleep(0.2)
            c.sendall(b"still-here")
    if a.hold:
        time.sleep(a.hold)
    c.close()

def serve(a):
    f = family(a.v6)
    s = socket.socket(f, socket.SOCK_DGRAM if a.udp else socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if a.v6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if a.dual else 1)
    s.bind((a.bind, a.port))
    print("listening", flush=True)
    if a.udp:
        while True:
            data, peer = s.recvfrom(65535)
            s.sendto(a.token.encode() + b":" + data, peer)
    else:
        # Large enough that the concurrency cases exercise needlecast, not this backlog.
        s.listen(256)
        while True:
            c, peer = s.accept()
            # Not necessarily what `ss` reports, which is the whole point.
            print("accepted_peer=%s:%d" % (peer[0], peer[1]), flush=True)
            print("getpeername=%s:%d" % (c.getpeername()[0], c.getpeername()[1]), flush=True)
            threading.Thread(target=lambda c=c: send_all(c, a), daemon=True).start()

SO_NO_CHECK = 11

def label(i):
    return "" if i == 1 else str(i)

def make_payload(a):
    if a.payload_size:
        # Non-uniform, so a truncated or reordered datagram is detectable.
        return bytes((i * 7 + 13) % 256 for i in range(a.payload_size))
    return a.payload.encode()

def churn(a):
    ok = 0
    for _ in range(a.repeat_connects):
        try:
            c = socket.create_connection((a.host, a.port), timeout=a.timeout)
            if c.recv(65535):
                ok += 1
            c.close()
        except OSError:
            pass
    print("completed=%d" % ok)
    return 0 if ok == a.repeat_connects else 3

def concurrent(a):
    results = []
    lock = threading.Lock()

    def one():
        try:
            c = socket.create_connection((a.host, a.port), timeout=a.timeout)
            got = bool(c.recv(65535))
            c.close()
        except OSError:
            got = False
        with lock:
            results.append(got)

    threads = [threading.Thread(target=one) for _ in range(a.concurrent)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("completed=%d" % sum(results))
    return 0 if all(results) else 3

def connect(a):
    if a.repeat_connects:
        return churn(a)
    if a.concurrent:
        return concurrent(a)
    f = family(a.v6)
    s = socket.socket(f, socket.SOCK_DGRAM if a.udp else socket.SOCK_STREAM)
    s.settimeout(a.timeout)
    try:
        if a.udp and a.unconnected:
            # One socket, so `--gate` lets a test change the world between datagrams.
            for i in range(1, a.repeat + 1):
                if i > 1 and a.gate:
                    deadline = time.monotonic() + a.timeout
                    while not os.path.exists(a.gate):
                        if time.monotonic() > deadline:
                            print("error=GATE_TIMEOUT")
                            return 4
                        time.sleep(0.05)
                payload = make_payload(a)
                if a.no_check:
                    s.setsockopt(socket.SOL_SOCKET, SO_NO_CHECK, 1)
                s.sendto(payload, (a.host, a.port))
                data, peer = s.recvfrom(1 << 17)
                print("peer%s=%s:%d" % (label(i), peer[0], peer[1]), flush=True)
                if a.payload_size:
                    print("echo_len%s=%d" % (label(i), len(data)), flush=True)
                    print("echo_ok%s=%s" % (label(i), data.endswith(b":" + payload)), flush=True)
                else:
                    print("data%s=%s" % (label(i), data.decode()), flush=True)
            return 0
        if a.linger0:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
        s.connect((a.host, a.port))
        peer = s.getpeername()
        print("peer=%s:%d" % (peer[0], peer[1]))
        if a.udp:
            s.send(make_payload(a))
            data = s.recv(1 << 17)
            print("data=" + data.decode())
            return 0
        if a.out:
            # The digest is left to the test, so it compares against the file the server sent
            # rather than anything derived here.
            total = 0
            with open(a.out, "wb") as fh:
                while True:
                    chunk = s.recv(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk)
                    total += len(chunk)
            print("bytes=%d" % total)
            return 0
        if a.half_close:
            # A tool that half-closes must not have the connection torn down under it.
            s.shutdown(socket.SHUT_WR)
        data = s.recv(65535)
        print("data=" + data.decode(), flush=True)
        if a.half_close:
            more = s.recv(65535)
            print("after_half_close=" + more.decode(), flush=True)
        if a.hold:
            time.sleep(a.hold)
        return 0
    except socket.timeout:
        # A dropped SYN is a materially different finding from a refusal.
        print("error=TIMEOUT")
        return 3
    except OSError as e:
        name = errno.errorcode.get(e.errno, str(e.errno))
        print("error=" + name)
        return 3

p = argparse.ArgumentParser()
sub = p.add_subparsers(dest="cmd", required=True)

sv = sub.add_parser("serve")
sv.add_argument("--bind", required=True)
sv.add_argument("--port", type=int, required=True)
sv.add_argument("--token", required=True)
sv.add_argument("--udp", action="store_true")
sv.add_argument("--v6", action="store_true")
sv.add_argument("--dual", action="store_true")
sv.add_argument("--file")
sv.add_argument("--hold", type=float, default=0.0)
sv.add_argument("--half-close-reply", action="store_true")
sv.set_defaults(fn=serve)

cn = sub.add_parser("connect")
cn.add_argument("--host", required=True)
cn.add_argument("--port", type=int, required=True)
cn.add_argument("--udp", action="store_true")
cn.add_argument("--v6", action="store_true")
cn.add_argument("--unconnected", action="store_true")
cn.add_argument("--payload", default="ping")
cn.add_argument("--repeat", type=int, default=1)
cn.add_argument("--gate")
cn.add_argument("--out")
cn.add_argument("--payload-size", type=int, default=0)
cn.add_argument("--no-check", action="store_true")
cn.add_argument("--hold", type=float, default=0.0)
cn.add_argument("--half-close", action="store_true")
cn.add_argument("--linger0", action="store_true")
cn.add_argument("--repeat-connects", type=int, default=0)
cn.add_argument("--concurrent", type=int, default=0)
cn.add_argument("--timeout", type=float, default=5.0)
cn.set_defaults(fn=connect)

a = p.parse_args()
sys.exit(a.fn(a) or 0)
