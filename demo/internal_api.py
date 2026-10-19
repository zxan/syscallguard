#!/usr/bin/env python3
# internal_api.py: the allowlisted internal API mock for the SyscallGuard demo.
# Track: D (Demo kit & verification). Python stdlib only. Runs unprivileged in the VM.
#
# This is the *legitimate* destination: a tagged agent may still reach 127.0.0.1, so work
# keeps succeeding while exfiltration to anywhere else is blocked. Logs every request to
# stdout so the stage audience can see real work landing here.
#
#   python3 demo/internal_api.py --port 8080
import argparse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def _log(self, what):
        print(f"[{datetime.now():%H:%M:%S}] {what}", flush=True)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)   # drain the body; this is a mock, we don't inspect it
        self._log(f"POST {self.path} -> 200 ({n} bytes received, logged, discarded)")
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._log(f"GET {self.path} -> 200")
        body = b'{"service":"acme-invoice","status":"up"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass   # replaced by _log; silence the default stderr spam


def main():
    ap = argparse.ArgumentParser(description="Allowlisted internal API mock (demo).")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"internal API listening on http://{args.host}:{args.port}  (POST /ingest)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\ninternal API stopped", flush=True)


if __name__ == "__main__":
    main()
