"""Effectiveness POC — the reflector (device B): ground truth of what crossed the control.

This is the "second deployable" secvitals' own decision record (CONFIRMED.md §7) says an
east-west / effectiveness test needs. It runs on infrastructure YOU control on the far
side of the security stack under test — a lab VM, a cloud host — *not* on the demo host.
The demo host still runs no listener; only the sender (the harness) lives there. That is
how the paired sender/receiver architecture is reconciled with secvitals' "no network surface on
the demo host" guardrail: the surface moves to a box you own and expect to be reachable.

What it does, and nothing more:

  POST /probe/<run_id>/<token>   body = the probe payload. Records token -> sha256(body).
                                 It never executes, resolves, renders or stores the raw
                                 payload — only its length and digest. Inert by design.
  GET  /ledger/<run_id>          Returns the run's {token: {sha256,len,ts}} as JSON, with
                                 an HMAC-SHA256 signature over the exact body in the
                                 X-Reflector-Sig header, so the harness can trust that this
                                 ground truth was not spoofed in transit.
  GET  /healthz                  Liveness of the reflector's management endpoint.

Security posture (it is the one component that DOES listen, so it is built defensively):
  * stdlib only, no shell, no third-party deps, argv-free.
  * Request bodies are capped (MAX_BODY) — a receiver is not a file drop.
  * Only digests + tokens are retained; payloads are discarded after hashing.
  * The ledger is HMAC-signed with a shared secret; there is no auth beyond that and no
    write path other than recording a digest, so a stray reader learns only digests.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import json
import os
import re
import socketserver
import threading
import time

MAX_BODY = 64 * 1024                    # a receiver, not a file drop
_PATH_PROBE = re.compile(r"^/probe/([A-Za-z0-9._-]{1,64})/([A-Za-z0-9]{1,64})$")
_PATH_LEDGER = re.compile(r"^/ledger/([A-Za-z0-9._-]{1,64})$")
DEFAULT_SECRET = "secvitals-reflector-shared-secret-change-me"


class Ledger:
    """Thread-safe in-memory record of what actually arrived, per run."""

    def __init__(self):
        self._runs = {}
        self._lock = threading.Lock()

    def record(self, run_id, token, body):
        digest = hashlib.sha256(body).hexdigest()
        with self._lock:
            run = self._runs.setdefault(run_id, {})
            run[token] = {"sha256": digest, "len": len(body), "ts": _utc()}
        return digest

    def entries(self, run_id):
        with self._lock:
            return dict(self._runs.get(run_id, {}))


def _utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sign(secret, body_bytes):
    return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    # set on the server instance
    ledger: Ledger
    secret: str

    server_version = "SecvitalsReflector/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    # -- helpers -------------------------------------------------------------
    def _send_json(self, code, obj, sign_body=False):
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if sign_body:
            self.send_header("X-Reflector-Sig", sign(self.server.secret, body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            return None
        return self.rfile.read(length) if length else b""

    # -- routes --------------------------------------------------------------
    def do_POST(self):
        m = _PATH_PROBE.match(self.path)
        if not m:
            return self._send_json(404, {"error": "not found"})
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "payload too large"})
        run_id, token = m.group(1), m.group(2)
        digest = self.server.ledger.record(run_id, token, body)
        self._send_json(200, {"ok": True, "token": token, "sha256": digest})

    def do_GET(self):
        if self.path == "/healthz":
            return self._send_json(200, {"ok": True, "ts": _utc()})
        m = _PATH_LEDGER.match(self.path)
        if not m:
            return self._send_json(404, {"error": "not found"})
        run_id = m.group(1)
        entries = self.server.ledger.entries(run_id)
        # NB: the body is signed so the harness can trust this ground truth; scoring
        # treats an unverifiable ledger as ERROR-for-all, never as a wall of blocks.
        self._send_json(200, {"run_id": run_id, "count": len(entries), "entries": entries},
                        sign_body=True)


class ReflectorServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, ledger, secret, verbose=False):
        super().__init__(addr, Handler)
        self.ledger = ledger
        self.secret = secret
        self.verbose = verbose


def start_reflector(host="127.0.0.1", port=0, secret=DEFAULT_SECRET, verbose=False):
    """Start a reflector in a background thread. Returns (server, (host, port), thread).
    Used by the harness's self-contained --demo and by the tests."""
    server = ReflectorServer((host, port), Ledger(), secret, verbose=verbose)
    bound = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, (bound[0], bound[1]), thread


def main(argv=None):
    p = argparse.ArgumentParser(prog="reflector",
                                description="Effectiveness-POC reflector (run this on the far "
                                            "side of the control, on infra you own)")
    p.add_argument("--bind", default="0.0.0.0", help="interface to bind (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=8899, help="port to listen on (default 8899)")
    p.add_argument("--secret", default=os.environ.get("SECVITALS_REFLECTOR_SECRET", DEFAULT_SECRET),
                   help="shared HMAC secret (or set SECVITALS_REFLECTOR_SECRET)")
    p.add_argument("--verbose", action="store_true", help="log every request")
    args = p.parse_args(argv)
    server = ReflectorServer((args.bind, args.port), Ledger(), args.secret, verbose=args.verbose)
    host, port = server.server_address
    print(f"reflector listening on {host}:{port}  (ledger is HMAC-signed)")
    print("  POST /probe/<run_id>/<token>   GET /ledger/<run_id>   GET /healthz")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
