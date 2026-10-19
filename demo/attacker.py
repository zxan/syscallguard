#!/usr/bin/env python3
# attacker.py: the exfiltration listener for the SyscallGuard demo. Runs on the HOST laptop.
# Track: D (Demo kit & verification). Python stdlib only.
#
# On stage this window is meant to stay EMPTY: the kernel blocks the tagged agent before any
# byte leaves the VM. If anything does arrive, that is a failure of the guard, so we make it
# unmissable (banner + byte count + a decoded preview). A periodic "waiting" line shows the
# listener is alive and simply hearing nothing.
import argparse
import socket
import threading
from datetime import datetime


def ts():
    return datetime.now().strftime("%H:%M:%S")


def alarm(proto, peer, data):
    line = "!" * 60
    print(f"\n{line}", flush=True)
    print(f"[{ts()}] RECEIVED {len(data)} bytes over {proto} from {peer}", flush=True)
    preview = data[:200].decode("utf-8", "replace").replace("\n", "\\n")
    print(f"           DATA: {preview}", flush=True)
    print(f"{line}\n", flush=True)


def tcp_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    while True:
        conn, peer = s.accept()
        with conn:
            # Short timeout: read whatever arrives, but don't hang forever on an HTTP client
            # (curl) that holds the connection open waiting for a reply.
            conn.settimeout(1.0)
            data = b""
            try:
                while chunk := conn.recv(4096):
                    data += chunk
            except (TimeoutError, OSError):
                pass
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")   # so curl exits 0
            except OSError:
                pass
        alarm("TCP", f"{peer[0]}:{peer[1]}", data)


def udp_server(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    while True:
        data, peer = s.recvfrom(65535)
        alarm("UDP", f"{peer[0]}:{peer[1]}", data)


def main():
    ap = argparse.ArgumentParser(description="Attacker exfil listener (demo). Should stay empty.")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    for target in (tcp_server, udp_server):
        threading.Thread(target=target, args=(args.host, args.port), daemon=True).start()
    print(f"attacker listening on {args.host}:{args.port} (TCP+UDP) -- this window should stay empty",
          flush=True)

    stop = threading.Event()
    try:
        while not stop.wait(10):
            print(f"[{ts()}] waiting... (nothing received, good)", flush=True)
    except KeyboardInterrupt:
        print("\nattacker stopped", flush=True)


if __name__ == "__main__":
    main()
