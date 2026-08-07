"""MINION POC — a mock inline control (DEMO / TEST ONLY).

In a real engagement there is NO mock: the harness sends probes straight at the
reflector's public address and the customer's actual inline stack (IDS/IPS, SWG, DLP)
sits in the path and decides what passes. This module exists only so the whole paired
loop — sender -> [control] -> receiver — can be shown end-to-end on a single machine
over loopback, with something in the middle that behaves like an enforcing control.

It is a tiny HTTP-aware forwarder that, per a fixed signature policy, either:

  * ``drop``     — closes the connection without forwarding (an inline block: the probe
                   never reaches the far side, so its token is absent from the ledger),
  * ``sanitize`` — rewrites the matched bytes and forwards the altered request (a proxy
                   "mishandling" the payload: the token arrives but the digest differs),
  * otherwise    — forwards the request untouched (allowed: token arrives intact).

It is deliberately dumb string-matching — it is a stand-in, not a real detection engine.
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import threading

# Fixed demo policy. Each malicious probe in probes.json carries one of these markers;
# the benign probes carry none, so they forward clean.
DEFAULT_POLICY = [
    ("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "drop"),
    ("jndi:", "drop"),
    ("BlackSun", "drop"),
    ("sqlmap", "drop"),
    ("4111111111111111", "drop"),
    ("uid=0(root)", "drop"),
    ("class.module.classLoader", "sanitize"),   # neutralised in transit -> MANGLED
]


def _read_http_message(sock, first=b""):
    """Read one HTTP message (head + body-by-Content-Length) from a blocking socket.
    Returns (head_bytes, body_bytes) or (None, None) on a short/broken read."""
    buf = bytearray(first)
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return (None, None)
        buf += chunk
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                length = 0
            break
    body = bytearray(rest)
    while len(body) < length:
        chunk = sock.recv(min(4096, length - len(body)))
        if not chunk:
            break
        body += chunk
    return head, bytes(body)


def _set_content_length(head, new_len):
    out = []
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            out.append(b"Content-Length: " + str(new_len).encode())
        elif line.lower().startswith(b"connection:"):
            continue                                    # we set our own below
        else:
            out.append(line)
    out.append(b"Connection: close")                    # so upstream closes -> read to EOF
    return b"\r\n".join(out)


def decide(policy, path, body):
    """Return (action, altered_body). action in {'allow','drop','sanitize'}."""
    hay = path.encode() + b"\n" + body
    altered = body
    action = "allow"
    for marker, act in policy:
        mb = marker.encode()
        if mb in hay:
            if act == "drop":
                return "drop", body
            if act == "sanitize":
                altered = altered.replace(mb, b"SANITIZED")
                action = "sanitize"
    return action, altered


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(10)
        try:
            head, body = _read_http_message(sock)
        except (socket.timeout, OSError):
            return
        if head is None:
            return
        request_line = head.split(b"\r\n", 1)[0]
        try:
            path = request_line.split(b" ")[1].decode("latin-1")
        except IndexError:
            path = ""
        policy = self.server.policy
        action, altered = decide(policy, path, body)
        if self.server.verbose:
            print(f"[control] {request_line.decode('latin-1', 'replace')}  -> {action}")
        if action == "drop":
            return                                       # inline block: close, forward nothing

        new_head = _set_content_length(head, len(altered))
        upstream = self.server.upstream
        try:
            with socket.create_connection(upstream, timeout=10) as up:
                up.sendall(new_head + b"\r\n\r\n" + altered)
                resp_head, resp_body = _read_http_message(up, first=b"")
                # upstream may send more than Content-Length implies under keep-alive edge
                # cases; drain to EOF to be safe.
                extra = b""
                if resp_head is not None:
                    up.settimeout(1.0)
                    try:
                        while True:
                            chunk = up.recv(4096)
                            if not chunk:
                                break
                            extra += chunk
                    except (socket.timeout, OSError):
                        pass
            if resp_head is None:
                return
            sock.sendall(resp_head + b"\r\n\r\n" + resp_body + extra)
        except OSError:
            return


class ControlServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, upstream, policy=None, verbose=False):
        super().__init__(addr, _Handler)
        self.upstream = upstream
        self.policy = policy or DEFAULT_POLICY
        self.verbose = verbose


def start_control(upstream, host="127.0.0.1", port=0, policy=None, verbose=False):
    """Start the mock control in a background thread. Returns (server, (host,port), thread)."""
    server = ControlServer((host, port), upstream, policy=policy, verbose=verbose)
    bound = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, (bound[0], bound[1]), thread


def main(argv=None):
    p = argparse.ArgumentParser(prog="minion_control",
                                description="MINION POC mock inline control (DEMO ONLY — "
                                            "stands in for the real security stack)")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8898)
    p.add_argument("--upstream", required=True, metavar="HOST:PORT",
                   help="the reflector to forward allowed traffic to")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)
    host, _, port = args.upstream.partition(":")
    server = ControlServer((args.bind, args.port), (host, int(port)), verbose=args.verbose)
    bhost, bport = server.server_address
    print(f"MINION mock control on {bhost}:{bport} -> reflector {args.upstream} (DEMO ONLY)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
