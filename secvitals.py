#!/usr/bin/env python3
"""Security Vitals — a local security-trigger console.

Fires security-trigger traffic on a button click and classifies the LOCAL result
(allowed / blocked / error). The host sits behind HPE Aruba EdgeConnect; traffic
egresses the SD-WAN and is inspected by EdgeConnect (ECOS Suricata v7) and the SSE
Secure Web Gateway / BrightCloud WebCC. This app polls no management API — the
presenter verifies on the Orchestrator/EC dashboard already on screen.

Design (see CONFIRMED.md):
  * Single code artifact, stdlib only. UI served over a loopback-bound http.server
    and opened in the browser. Runs inside WSL (native bash; no wsl.exe shelling).
  * Fixed server-side catalog (config/catalog.yaml). The UI sends a trigger id; a
    command is NEVER built from client input. subprocess with an argv list, no
    shell=True, per-trigger timeout, captured stdout/stderr/returncode.
  * Three-state classifier: `blocked` and `error` never collapse.

This module is import-safe: importing it starts nothing (everything is behind
main()). The self-update mechanism is added in a later commit.
"""

import argparse
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "0.1.0"
APP_NAME = "Security Vitals"

log = logging.getLogger("secvitals")

# --- Self-update: pinned source + embedded verification key (see docs/UPDATE_SECURITY.md).
# The manifest URL is a NON-OVERRIDABLE constant: there is no --update-url flag, because
# the update channel is a code-execution channel and a substitutable source is an RCE
# vector. Releases are signed offline; this app ships only the PUBLIC key and fails
# closed on any verification failure.
UPDATE_MANIFEST_URL = "https://github.com/robertsonc/secvitals/releases/latest/download/manifest.json"

# PLACEHOLDER / DEV public key. Replace with your own release public key before relying
# on the update channel (see docs/UPDATE_SECURITY.md). The matching private key is NOT
# published, so until you install your own key every update fails closed — the safe state.
UPDATE_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAohXeujQKdTKz1X+m40+x
g2/fdCNZe+bHgUl4ylL/XSvAvjm+LR7GyuQaYDihDSmqZJ/bh3FImw71jIFFCwkV
iJbQA+OpNUBCuGx4S5cHQQLJRINjmsEuzi+rfPvDfpwdbzUoF3MI/Wlc9XVg33qt
hSglZ7jDsdAM/ssa+qg4Dx4nT+Gs9WXPReSpLPTKgaaCLpa5OZSRlksEJwkKxlA6
wvd5rpSu61LDm7U9fLSoCScHFfoBLoffzUMFXOKZ1dAEAvnPWPwaMimtYt7Mw5XL
d8S039/wTLTjbGklBn2dBT+aM5wefmdsfLs78GjQxZZET5iBa1/rvokUdTByQauO
MwIDAQAB
-----END PUBLIC KEY-----
"""

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_DIR = os.path.join(HERE, "config")
DEFAULT_ASSETS_DIR = os.path.join(HERE, "assets")

# Known catalog vocabularies (fixed allowlists).
CLASSES = {"ns-ids", "ns-webcc", "ns-iprep", "ew"}   # `ew` reserved / deferred
RUNNERS = {"tmnids", "curl"}                          # `tcp443` reserved for Phase 3 IP-rep
FLAGS = {"needs_internet", "needs_et_ruleset", "hits_live_suspect_hosts"}
SEVERITIES = {"info", "warn", "crit"}

# tmNIDS is a download-and-execute channel, so its bytes are pinned by default and
# verification is MANDATORY (fail closed). If 3CORESec updates tmNIDS upstream, verify
# the new binary out-of-band, recompute its SHA-256, and set tmnids.sha256 in
# settings.yaml (which overrides this constant). See docs/UPDATE_SECURITY.md.
TMNIDS_SHA256 = "7016952b1713d09aac0b17bc05d1cc9c589c5ab1ed441233b9413717494fa0c4"
TMNIDS_MAX_BYTES = 4 * 1024 * 1024

# UI result states — `blocked` and `error` MUST stay distinct.
ALLOWED, BLOCKED, ERROR, INVALID = "allowed", "blocked", "error", "invalid"


# ===========================================================================
# Vendored minimal YAML loader
# ---------------------------------------------------------------------------
# Just enough YAML to load config/catalog.yaml and config/settings.yaml without a
# third-party dependency: block mappings + sequences (indentation-based), flow
# collections {a: b} / [a, b], quoted and plain scalars, ints/floats/bools/null,
# and `# ` comments. It is deliberately strict and only ever parses trusted local
# config shipped with the app (never client input), so a parse quirk is a
# correctness concern, not a security boundary. Unsupported constructs raise.
# ===========================================================================
class YamlError(ValueError):
    """Raised when the vendored loader cannot parse the input."""


def _strip_comment(s):
    """Remove a trailing ` # comment`, respecting quotes. A `#` is only a comment
    when at line start or preceded by whitespace (so URLs like http://x#y survive)."""
    in_s = in_d = False
    for i, c in enumerate(s):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif c == "#" and not in_s and not in_d and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
    return s


def _logical_lines(text):
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.strip() == "" or raw.lstrip().startswith("#"):
            continue
        lead = raw[:len(raw) - len(raw.lstrip())]   # all leading whitespace
        if "\t" in lead:
            raise YamlError(f"line {lineno}: tabs are not allowed in indentation")
        indent = len(lead)
        content = _strip_comment(raw).strip()
        if content == "":
            continue
        out.append((indent, content, lineno))
    return out


def _find_kv_colon(s):
    """Index of the ':' that separates a mapping key from its value (colon followed
    by a space or end-of-string, outside quotes/flow), or -1."""
    in_s = in_d = False
    depth = 0
    for i, c in enumerate(s):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
            elif c == ":" and depth == 0 and (i + 1 == len(s) or s[i + 1] == " "):
                return i
    return -1


def _split_flow_items(s):
    """Split a flow collection body on top-level commas, respecting quotes/nesting."""
    items, depth, in_s, in_d, start = [], 0, False, False, 0
    for i, c in enumerate(s):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
            elif c == "," and depth == 0:
                items.append(s[start:i])
                start = i + 1
    tail = s[start:]
    if tail.strip() != "" or items:
        items.append(tail)
    return [x.strip() for x in items]


def _parse_scalar(s):
    s = s.strip()
    if s == "":
        return None
    if s[0] == "[":
        if s[-1] != "]":
            raise YamlError(f"unterminated flow sequence: {s}")
        body = s[1:-1].strip()
        if body == "":
            return []
        return [_parse_scalar(x) for x in _split_flow_items(body)]
    if s[0] == "{":
        if s[-1] != "}":
            raise YamlError(f"unterminated flow mapping: {s}")
        body = s[1:-1].strip()
        out = {}
        if body == "":
            return out
        for item in _split_flow_items(body):
            ci = _find_kv_colon(item)
            if ci < 0:
                # allow `key:` with empty value or `key: value`
                if item.endswith(":"):
                    out[_parse_scalar(item[:-1])] = None
                    continue
                raise YamlError(f"flow mapping item is not key: value: {item!r}")
            out[_parse_scalar(item[:ci])] = _parse_scalar(item[ci + 1:])
        return out
    if (s[0] == '"' and s[-1] == '"' and len(s) >= 2):
        return _unescape_double(s[1:-1])
    if (s[0] == "'" and s[-1] == "'" and len(s) >= 2):
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in ("null", "~"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"[-+]?\d+", s):
        return int(s)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?", s) and re.search(r"[.eE]", s):
        return float(s)
    return s


def _unescape_double(s):
    out, i = [], 0
    simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0"}
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "u" and i + 5 < len(s) + 1 and re.fullmatch(r"[0-9a-fA-F]{4}", s[i + 2:i + 6] or ""):
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _parse_map(lines, i, indent):
    m = {}
    while i < len(lines):
        ind, content, lineno = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise YamlError(f"line {lineno}: unexpected indentation in mapping")
        if content == "-" or content.startswith("- "):
            raise YamlError(f"line {lineno}: sequence item where a mapping key was expected")
        ci = _find_kv_colon(content)
        if ci < 0:
            raise YamlError(f"line {lineno}: expected 'key: value', got {content!r}")
        key = _parse_scalar(content[:ci])
        rest = content[ci + 1:].strip()
        if rest == "":
            i += 1
            if i < len(lines) and lines[i][0] > indent:
                val, i = _parse_node(lines, i)
            elif (i < len(lines) and lines[i][0] == indent
                  and (lines[i][1] == "-" or lines[i][1].startswith("- "))):
                # YAML allows a block sequence at the same indent as its parent key.
                val, i = _parse_seq(lines, i, indent)
            else:
                val = None
        else:
            val = _parse_scalar(rest)
            i += 1
        m[key] = val
    return m, i


def _parse_seq(lines, i, indent):
    seq = []
    while i < len(lines):
        ind, content, lineno = lines[i]
        if ind < indent or not (content == "-" or content.startswith("- ")):
            break
        if ind > indent:
            raise YamlError(f"line {lineno}: unexpected indentation in sequence")
        rest = "" if content == "-" else content[2:].strip()
        if rest == "":
            i += 1
            if i < len(lines) and lines[i][0] > indent:
                val, i = _parse_node(lines, i)
            else:
                val = None
            seq.append(val)
        elif _find_kv_colon(rest) >= 0:
            # "- key: value" begins a mapping; its other keys sit at indent+2.
            vindent = indent + 2
            sub = [(vindent, rest, lineno)]
            i += 1
            while i < len(lines) and lines[i][0] >= vindent:
                sub.append(lines[i])
                i += 1
            val, _ = _parse_map(sub, 0, vindent)
            seq.append(val)
        else:
            seq.append(_parse_scalar(rest))
            i += 1
    return seq, i


def _parse_node(lines, i):
    _, content, _ = lines[i]
    indent = lines[i][0]
    if content == "-" or content.startswith("- "):
        return _parse_seq(lines, i, indent)
    return _parse_map(lines, i, indent)


def yaml_load(text):
    """Parse a YAML subset. Returns dict / list / scalar / None."""
    lines = _logical_lines(text)
    if not lines:
        return None
    value, idx = _parse_node(lines, 0)
    if idx != len(lines):
        raise YamlError(f"line {lines[idx][2]}: unexpected content {lines[idx][1]!r}")
    return value


def yaml_load_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml_load(fh.read())


# ===========================================================================
# Configuration + catalog models
# ===========================================================================
class ConfigError(Exception):
    """Raised on an invalid settings.yaml or catalog.yaml."""


def _dget(d, path, default=None):
    """Nested dict get: _dget(settings, 'server.port', 8787)."""
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


@dataclasses.dataclass
class Settings:
    raw: dict

    @property
    def host(self):
        return str(_dget(self.raw, "server.host", "127.0.0.1"))

    @property
    def port(self):
        return int(_dget(self.raw, "server.port", 8787))

    @property
    def open_browser(self):
        return bool(_dget(self.raw, "server.open_browser", True))

    @property
    def enable_live_suspect_hosts(self):
        return bool(_dget(self.raw, "enable_live_suspect_hosts", False))

    @property
    def default_timeout(self):
        return float(_dget(self.raw, "run.default_timeout_s", 30))

    @property
    def control_host(self):
        # A known-good, high-reputation control endpoint. When set (default), a control
        # egress probe distinguishes a genuine inline drop (`blocked`) from a broken
        # environment (`error`). Set to "" to disable and fall back to the catalog's
        # declared expected_on_block predicate.
        return (_dget(self.raw, "run.control_host", "1.1.1.1") or "").strip()

    @property
    def control_port(self):
        return int(_dget(self.raw, "run.control_port", 443))

    @property
    def control_enabled(self):
        return bool(self.control_host)

    @property
    def min_run_interval(self):
        # Server-side rate limit: minimum spacing between consecutive trigger runs, so a
        # "run all" (or a fast clicker) can't flood the SD-WAN / EC dashboard / SIEM.
        return float(_dget(self.raw, "run.min_interval_s", 0.75))

    @property
    def tmnids_url(self):
        return str(_dget(self.raw, "tmnids.url", ""))

    @property
    def tmnids_cache_path(self):
        p = _dget(self.raw, "tmnids.cache_path", "") or ""
        return p or os.path.join(_cache_dir(), "tmNIDS")

    @property
    def tmnids_sha256(self):
        # Config overrides the built-in pin; the pin is never empty, so verification
        # is always mandatory (fail closed).
        return ((_dget(self.raw, "tmnids.sha256", "") or "").strip() or TMNIDS_SHA256)

    @property
    def tmnids_timeout(self):
        return float(_dget(self.raw, "tmnids.download_timeout_s", 20))


@dataclasses.dataclass
class Trigger:
    id: str
    label: str
    cls: str
    runner: str
    argv: list
    flags: list
    severity: str
    threat_class: str
    expected_fire: str
    talking_point: str
    expected_on_allow: dict
    expected_on_block: dict
    params: list
    timeout: float

    @staticmethod
    def from_dict(d, default_timeout):
        if not isinstance(d, dict):
            raise ConfigError(f"catalog entry is not a mapping: {d!r}")
        tid = d.get("id")
        if not isinstance(tid, str) or not re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,63}", tid):
            raise ConfigError(f"catalog entry has an invalid id: {tid!r}")
        cls = d.get("class")
        if cls not in CLASSES:
            raise ConfigError(f"{tid}: class must be one of {sorted(CLASSES)}, got {cls!r}")
        runner = d.get("runner")
        if runner not in RUNNERS:
            raise ConfigError(f"{tid}: runner must be one of {sorted(RUNNERS)}, got {runner!r}")
        argv = d.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise ConfigError(f"{tid}: argv must be a non-empty list of strings, got {argv!r}")
        flags = d.get("flags") or []
        if not isinstance(flags, list) or any(f not in FLAGS for f in flags):
            raise ConfigError(f"{tid}: flags must be a subset of {sorted(FLAGS)}, got {flags!r}")
        sev = d.get("severity", "info")
        if sev not in SEVERITIES:
            raise ConfigError(f"{tid}: severity must be one of {sorted(SEVERITIES)}, got {sev!r}")
        allow = d.get("expected_on_allow") or {}
        block = d.get("expected_on_block") or {}
        if not isinstance(allow, dict) or not isinstance(block, dict):
            raise ConfigError(f"{tid}: expected_on_allow/expected_on_block must be mappings")
        _validate_predicate(tid, "expected_on_allow", allow)
        _validate_predicate(tid, "expected_on_block", block)
        params = d.get("params") or []
        _validate_params(tid, params, argv)
        return Trigger(
            id=tid,
            label=str(d.get("label", tid)),
            cls=cls,
            runner=runner,
            argv=list(argv),
            flags=list(flags),
            severity=sev,
            threat_class=str(d.get("threat_class", "")),
            expected_fire=str(d.get("expected_fire", "")),
            talking_point=str(d.get("talking_point", "")),
            expected_on_allow=allow,
            expected_on_block=block,
            params=params,
            timeout=float(d.get("timeout_s", default_timeout)),
        )

    def gated_disabled(self, settings):
        return ("hits_live_suspect_hosts" in self.flags
                and not settings.enable_live_suspect_hosts)

    def to_public(self, settings):
        return {
            "id": self.id,
            "label": self.label,
            "class": self.cls,
            "runner": self.runner,
            "flags": self.flags,
            "severity": self.severity,
            "threat_class": self.threat_class,
            "expected_fire": self.expected_fire,
            "talking_point": self.talking_point,
            "params": [{"name": p["name"],
                        "allow": p.get("allow"),
                        "required": p.get("required", True)} for p in self.params],
            "gated_disabled": self.gated_disabled(settings),
        }


_PRED_KEYS = {"rc": int, "rc_nonzero": bool, "body_contains": str,
              "http_code": int, "http_code_in": list}


def _validate_predicate(tid, name, pred):
    """Validate expected_on_allow/expected_on_block contents at LOAD time, so a bad
    config fails loudly at startup rather than crashing a request thread at classify."""
    for key, value in pred.items():
        if key not in _PRED_KEYS:
            raise ConfigError(f"{tid}: {name} has unknown key {key!r}")
        exp = _PRED_KEYS[key]
        if exp is bool and not isinstance(value, bool):
            raise ConfigError(f"{tid}: {name}.{key} must be a boolean")
        if exp is int and (not isinstance(value, int) or isinstance(value, bool)):
            raise ConfigError(f"{tid}: {name}.{key} must be an integer")
        if exp is str and not isinstance(value, str):
            raise ConfigError(f"{tid}: {name}.{key} must be a string")
        if exp is list and (not isinstance(value, list)
                            or not all(isinstance(x, int) and not isinstance(x, bool) for x in value)):
            raise ConfigError(f"{tid}: {name}.{key} must be a list of integers")


def _validate_params(tid, params, argv):
    if not isinstance(params, list):
        raise ConfigError(f"{tid}: params must be a list")
    names = set()
    for p in params:
        if not isinstance(p, dict) or "name" not in p:
            raise ConfigError(f"{tid}: each param needs a name")
        name = p["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]{1,32}", name):
            raise ConfigError(f"{tid}: bad param name {name!r}")
        if "allow" not in p and "pattern" not in p:
            # Fail closed: a param with neither an allowlist nor a pattern is refused.
            raise ConfigError(f"{tid}: param {name} must declare an 'allow' list or a 'pattern'")
        if "allow" in p and not isinstance(p["allow"], list):
            raise ConfigError(f"{tid}: param {name} 'allow' must be a list")
        if "pattern" in p:
            if not isinstance(p["pattern"], str):
                raise ConfigError(f"{tid}: param {name} 'pattern' must be a string")
            try:
                re.compile(p["pattern"])          # fail at startup, not at click time
            except re.error as e:
                raise ConfigError(f"{tid}: param {name} has an invalid regex pattern: {e}") from e
        names.add(name)
    used = {tok[1:-1] for tok in argv if isinstance(tok, str) and tok.startswith("{") and tok.endswith("}")}
    missing = used - names
    if missing:
        raise ConfigError(f"{tid}: argv references undeclared params {sorted(missing)}")


def load_settings(config_dir):
    path = os.path.join(config_dir, "settings.yaml")
    try:
        raw = yaml_load_file(path)
    except (OSError, YamlError) as e:
        raise ConfigError(f"could not load {path}: {e}") from e
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return Settings(raw=raw)


def load_catalog(config_dir, settings):
    path = os.path.join(config_dir, "catalog.yaml")
    try:
        raw = yaml_load_file(path)
    except (OSError, YamlError) as e:
        raise ConfigError(f"could not load {path}: {e}") from e
    if not isinstance(raw, list) or not raw:
        raise ConfigError(f"{path}: expected a non-empty list of triggers")
    triggers, seen = [], set()
    for entry in raw:
        t = Trigger.from_dict(entry, settings.default_timeout)
        if t.id in seen:
            raise ConfigError(f"duplicate trigger id: {t.id}")
        seen.add(t.id)
        triggers.append(t)
    return triggers


# ===========================================================================
# tmNIDS binary cache (download once; never re-download per click)
# ===========================================================================
class TmnidsError(Exception):
    """Raised when the tmNIDS binary cannot be made available."""


class TmnidsCache:
    def __init__(self, url, cache_path, sha256, timeout):
        self.url = url
        self.path = cache_path
        self.sha256 = (sha256 or "").lower()
        self.timeout = timeout
        self._lock = threading.Lock()

    def ensure(self):
        """Return the path to a ready-to-exec tmNIDS binary, downloading it once if
        needed. Verification against the SHA-256 pin is MANDATORY and fails closed —
        the binary is downloaded and executed, so TLS host auth alone is not enough
        (a TLS-terminating SWG is in-path). Raises TmnidsError (→ `error`, never
        `blocked`)."""
        with self._lock:
            if not self.sha256:
                raise TmnidsError("no tmNIDS SHA-256 pin configured — refusing to run")
            if os.path.exists(self.path) and os.access(self.path, os.X_OK):
                self._verify_file(self.path)          # re-verify the cached binary each time
                return self.path
            if not self.url:
                raise TmnidsError("no tmnids.url configured")
            if not self.url.lower().startswith("https:"):
                raise TmnidsError(f"tmnids.url must be https, got {self.url!r}")
            data = self._download()
            got = hashlib.sha256(data).hexdigest()
            if not hmac.compare_digest(got, self.sha256):
                raise TmnidsError(
                    f"tmNIDS sha256 mismatch — refusing (pinned {self.sha256[:12]}…, got {got[:12]}…). "
                    "If 3CORESec updated tmNIDS, verify the new binary and set tmnids.sha256 in settings.yaml.")
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".dl"
            try:
                with open(tmp, "wb") as fh:
                    fh.write(data)
                os.chmod(tmp, 0o755)
                os.replace(tmp, self.path)
            except OSError as e:
                _quiet_remove(tmp)
                raise TmnidsError(f"could not install binary: {e}") from e
            log.info("tmNIDS cached at %s (%d bytes, sha256 verified)", self.path, len(data))
            return self.path

    def _verify_file(self, path):
        try:
            with open(path, "rb") as fh:
                got = hashlib.sha256(fh.read()).hexdigest()
        except OSError as e:
            raise TmnidsError(f"could not read cached binary: {e}") from e
        if not hmac.compare_digest(got, self.sha256):
            raise TmnidsError("cached binary fails the pinned sha256 — refusing to run")

    def _download(self):
        req = urllib.request.Request(self.url, headers={"User-Agent": "secvitals/%s" % __version__})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                final = getattr(resp, "url", None) or self.url
                if not final.lower().startswith("https:"):   # no http, no https->http redirect
                    raise TmnidsError(f"refusing non-https download URL {final}")
                data = resp.read(TMNIDS_MAX_BYTES + 1)        # bounded — no memory DoS
        except (urllib.error.URLError, OSError) as e:
            raise TmnidsError(f"download failed: {e}") from e
        if len(data) > TMNIDS_MAX_BYTES:
            raise TmnidsError("tmNIDS download exceeds the size limit — refusing")
        if not data:
            raise TmnidsError("download was empty")
        return data


def _cache_dir():
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "SecurityVitals", "cache")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "secvitals")


def _quiet_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


# ===========================================================================
# Runner  —  subprocess with an argv list, no shell=True, per-trigger timeout
# ===========================================================================
@dataclasses.dataclass
class RunResult:
    argv: list = dataclasses.field(default_factory=list)
    rc: int = None
    stdout: str = ""
    stderr: str = ""
    http_code: int = None
    duration_s: float = 0.0
    timed_out: bool = False
    error_reason: str = None   # set => classified as `error`
    control_ok: bool = None    # egress control probe (tmnids); None = not run


class ParamError(Exception):
    """Raised when client-supplied params fail per-trigger validation."""


# curl exit codes (see CONFIRMED.md §5)
BLOCKED_RC = {28, 7, 56}          # timeout, connection refused, recv reset — consistent with a drop
BROKEN_RC = {6, 5, 35, 60, 77}    # DNS, proxy DNS, TLS handshake, cert — environment, not policy

_ENV_ERR_SIGS = (
    "could not resolve", "couldn't resolve", "name or service not known",
    "temporary failure in name resolution", "no address associated",
    "no route to host", "network is unreachable", "connection refused by proxy",
    "ssl certificate problem", "certificate verify failed",
)

_TMNIDS_SELECTOR = re.compile(r"-([1-9]|1[0-5]|99)$")


def build_argv(trigger, params):
    """Build the exact argv from the FIXED catalog template plus validated params.
    A command is never constructed from raw client input."""
    params = params or {}
    if not isinstance(params, dict):
        raise ParamError("params must be an object")
    resolved = {}
    declared = {p["name"] for p in trigger.params}
    for extra in set(params) - declared:
        raise ParamError(f"unknown param {extra!r}")
    for spec in trigger.params:
        name = spec["name"]
        if name not in params:
            if spec.get("required", True):
                raise ParamError(f"missing required param {name!r}")
            continue
        val = params[name]
        if not isinstance(val, str):
            raise ParamError(f"param {name!r} must be a string")
        if len(val) > 512 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in val):
            raise ParamError(f"param {name!r} contains control characters or is too long")
        allow = spec.get("allow")
        pattern = spec.get("pattern")
        if allow is not None:
            if val not in allow:
                raise ParamError(f"param {name!r} value is not in the allowlist")
        elif pattern is not None:
            try:
                matched = re.fullmatch(pattern, val)
            except re.error as e:
                raise ParamError(f"param {name!r} pattern error: {e}") from e
            if not matched:
                raise ParamError(f"param {name!r} value fails its pattern")
        else:
            raise ParamError(f"param {name!r} has no allowlist or pattern")  # fail closed
        resolved[name] = val
    argv = []
    for tok in trigger.argv:
        if isinstance(tok, str) and tok.startswith("{") and tok.endswith("}"):
            nm = tok[1:-1]
            if nm not in resolved:
                raise ParamError(f"unresolved argv token {tok}")
            argv.append(resolved[nm])
        else:
            argv.append(tok)
    return argv


def run_trigger(trigger, params, settings, tmnids_cache):
    """Execute one trigger and return a RunResult. Never raises for expected
    failure modes — those become error_reason (→ `error`)."""
    try:
        argv = build_argv(trigger, params)
    except ParamError as e:
        return RunResult(error_reason=f"invalid parameters: {e}")

    if trigger.runner == "tmnids":
        if len(argv) < 2 or not _TMNIDS_SELECTOR.fullmatch(argv[1]):
            return RunResult(argv=argv, error_reason=f"tmnids selector not allowed: {argv[1:]!r}")
        try:
            binpath = tmnids_cache.ensure()
        except TmnidsError as e:
            return RunResult(argv=argv, error_reason=f"tmNIDS binary unavailable: {e}")
        argv = [binpath] + list(argv[1:])

    start = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=trigger.timeout, check=False)
    except FileNotFoundError as e:
        return RunResult(argv=argv, error_reason=f"executable not found: {e}",
                         duration_s=time.monotonic() - start)
    except PermissionError as e:
        return RunResult(argv=argv, error_reason=f"permission denied: {e}",
                         duration_s=time.monotonic() - start)
    except subprocess.TimeoutExpired as e:
        return RunResult(argv=argv, rc=None, timed_out=True,
                         stdout=_dec(e.stdout), stderr=_dec(e.stderr),
                         duration_s=time.monotonic() - start)
    except OSError as e:
        return RunResult(argv=argv, error_reason=f"could not execute: {e}",
                         duration_s=time.monotonic() - start)

    dur = time.monotonic() - start
    out, err = _dec(proc.stdout), _dec(proc.stderr)
    res = RunResult(argv=argv, rc=proc.returncode, stdout=out, stderr=err, duration_s=dur)
    if trigger.runner == "curl":
        res.http_code = _parse_http_code(out)
    else:
        # Non-curl (tmNIDS): distinguish a genuine inline drop (`blocked`) from a broken
        # environment (`error`), and never report a false `blocked`.
        if _env_error_signature(err):
            res.error_reason = "environment error (name resolution / route / TLS): " + _first_line(err)
        elif not _pred_match(trigger.expected_on_allow, res) and settings.control_enabled:
            # The expected response did not come back. A control egress probe to a known-
            # good host tells us whether general egress works (=> this specific flow was
            # dropped => blocked) or the whole environment is broken (=> error). This is
            # reliable where a hardcoded English stderr blocklist is not.
            res.control_ok = _tcp_probe(settings.control_host, settings.control_port,
                                        min(6.0, trigger.timeout))
    return res


def _tcp_probe(host, port, timeout):
    """Return True iff a TCP connection to host:port completes within `timeout`."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _dec(b):
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    return b.decode("utf-8", "replace")


def _first_line(s):
    for line in (s or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def _env_error_signature(stderr):
    low = (stderr or "").lower()
    return any(sig in low for sig in _ENV_ERR_SIGS)


def _parse_http_code(stdout):
    """curl is invoked with -w '%{http_code}|...' as the LAST stdout line."""
    for line in reversed((stdout or "").splitlines()):
        m = re.match(r"^\s*(\d{3})\|", line)
        if m:
            return int(m.group(1))
    return None


# ===========================================================================
# Classifier  —  three states that never collapse
# ===========================================================================
def classify_curl(rc, http_code):
    if rc == 0:
        if http_code is None:
            return ERROR                       # can't confirm a pass — fail toward honest
        return BLOCKED if http_code in (403, 451) else ALLOWED
    if rc in BROKEN_RC:
        return ERROR
    if rc in BLOCKED_RC:
        return BLOCKED
    return ERROR   # unknown rc is an error, not a block — fail toward honest


def _pred_match(pred, result):
    if not pred:
        return False
    if "rc" in pred and result.rc != pred["rc"]:
        return False
    if pred.get("rc_nonzero") and (result.rc is None or result.rc == 0):
        return False
    if "body_contains" in pred and pred["body_contains"] not in (result.stdout or ""):
        return False
    if "http_code" in pred and result.http_code != pred["http_code"]:
        return False
    if "http_code_in" in pred and result.http_code not in (pred.get("http_code_in") or []):
        return False
    return True


def classify(trigger, result):
    """Return (state, reason). state ∈ {allowed, blocked, error}."""
    if result.error_reason:
        return ERROR, result.error_reason
    if result.timed_out:
        # Honest: a full-process timeout is more likely a hung environment than a
        # clean inline drop (tmNIDS' own sub-request would self-time-out first).
        return ERROR, f"timed out after {trigger.timeout:g}s"
    if trigger.runner == "curl":
        state = classify_curl(result.rc, result.http_code)
        return state, f"curl rc={result.rc}, http={result.http_code}"
    # tmNIDS / default: expectation-driven, with control-probe disambiguation.
    if _pred_match(trigger.expected_on_allow, result):
        return ALLOWED, "matched expected_on_allow"
    if result.control_ok is True:
        return BLOCKED, "egress control OK but the trigger's expected response did not return — dropped inline"
    if result.control_ok is False:
        return ERROR, "egress control probe failed — environment, not policy"
    # No control signal (control probe disabled): fall back to the catalog's declared
    # block predicate, as an operator-accepted, less-certain path.
    if _pred_match(trigger.expected_on_block, result):
        return BLOCKED, "matched expected_on_block (egress control disabled)"
    return ERROR, f"result matched neither expected_on_allow nor expected_on_block (rc={result.rc})"


# ===========================================================================
# Application state
# ===========================================================================
class App:
    def __init__(self, settings, triggers, config_dir):
        self.settings = settings
        self.triggers = triggers
        self.by_id = {t.id: t for t in triggers}
        self.config_dir = config_dir
        self.token = secrets.token_urlsafe(32)
        self.tmnids = TmnidsCache(settings.tmnids_url, settings.tmnids_cache_path,
                                  settings.tmnids_sha256, settings.tmnids_timeout)
        self._run_lock = threading.Lock()   # serialize triggers — clean before/after on stage
        self._last_run_end = 0.0            # for server-side rate limiting

    def run(self, trigger_id, params):
        trigger = self.by_id.get(trigger_id)
        if trigger is None:
            return None, {"error": "unknown trigger id"}
        if trigger.gated_disabled(self.settings):
            return trigger, {
                "state": INVALID,
                "reason": ("this trigger reaches live suspect infrastructure and is disabled "
                           "(enable_live_suspect_hosts is false)"),
                "expected_fire": trigger.expected_fire,
            }
        if not self._run_lock.acquire(blocking=False):
            return trigger, {"state": ERROR, "reason": "another trigger is already running"}
        try:
            gap = self.settings.min_run_interval - (time.monotonic() - self._last_run_end)
            if gap > 0:
                time.sleep(min(gap, 5.0))       # server-side rate limiting (spacing)
            log.info("run start id=%s", trigger_id)
            result = run_trigger(trigger, params, self.settings, self.tmnids)
            state, reason = classify(trigger, result)
            log.info("run done id=%s state=%s rc=%s dur=%.2fs argv=%s",
                     trigger_id, state, result.rc, result.duration_s, _redact(result.argv))
            return trigger, {
                "state": state,
                "reason": reason,
                "rc": result.rc,
                "http_code": result.http_code,
                "duration_s": round(result.duration_s, 3),
                "expected_fire": trigger.expected_fire,
                "stdout": _clip(result.stdout, 4000),
                "stderr": _clip(result.stderr, 4000),
                "argv": _redact(result.argv),
            }
        finally:
            self._last_run_end = time.monotonic()
            self._run_lock.release()


def _clip(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n] + f"\n… ({len(s) - n} more bytes truncated)"


def _redact(argv):
    # argv comes from the fixed catalog; show the basename of an absolute exec path.
    if not argv:
        return []
    out = list(argv)
    if os.path.isabs(out[0]):
        out[0] = os.path.basename(out[0])
    return out


# ===========================================================================
# HTTP server (loopback only) + request handler
# ===========================================================================
def _is_loopback(host):
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return socket.inet_aton(host)[0:1] == b"\x7f"   # 127.0.0.0/8
    except OSError:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "SecVitals/" + __version__
    protocol_version = "HTTP/1.1"
    timeout = 15   # bound a stalled read so a slow client can't pin a daemon thread

    @property
    def app(self):
        return self.server.app

    def log_message(self, fmt, *args):
        log.debug("http %s - %s", self.address_string(), fmt % args)

    # ---- security gates ----
    def _host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return _is_loopback(host) if host else False

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        m = re.match(r"^https?://([^/:]+)", origin)
        return bool(m and _is_loopback(m.group(1)))

    def _token_ok(self):
        tok = self.headers.get("X-Secvitals-Token", "")
        return hmac.compare_digest(tok, self.app.token)

    # ---- responses ----
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None, close=False):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        # Self-contained page: block any external resource load.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                         "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
        if close:
            self.close_connection = True
            self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, close=False):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8", close=close)

    def do_GET(self):
        if not self._host_ok():
            return self._json(421, {"error": "bad Host header"})
        path = self.path.split("?", 1)[0]
        if path == "/":
            html = INDEX_HTML.replace("__TOKEN__", self.app.token).replace("__VERSION__", __version__)
            return self._send(200, html, "text/html; charset=utf-8")
        if path == "/api/catalog":
            return self._json(200, {
                "version": __version__,
                "enable_live_suspect_hosts": self.app.settings.enable_live_suspect_hosts,
                "triggers": [t.to_public(self.app.settings) for t in self.app.triggers],
            })
        if path == "/api/status":
            return self._json(200, {"app": APP_NAME, "version": __version__, "ok": True})
        if path == "/assets/hpe_logo.svg":
            return self._serve_asset("hpe_logo.svg", "image/svg+xml")
        return self._json(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        # Always consume the request body first, so an early rejection does not leave
        # unread bytes that corrupt the next request on a keep-alive connection.
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > 64 * 1024:
            return self._json(413, {"error": "request body missing or too large"}, close=True)
        raw = self.rfile.read(length) if length else b""
        if path != "/api/run":
            return self._json(404, {"error": "not found"})
        if not self._host_ok() or not self._origin_ok():
            return self._json(421, {"error": "request origin not allowed"})
        if not self._token_ok():
            return self._json(403, {"error": "missing or invalid session token"})
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "invalid JSON body"})
        if not isinstance(body, dict):
            return self._json(400, {"error": "body must be a JSON object"})
        trigger_id = body.get("id")
        params = body.get("params") or {}
        if not isinstance(trigger_id, str):
            return self._json(400, {"error": "missing trigger id"})
        if not isinstance(params, dict):
            return self._json(400, {"error": "params must be an object"})
        trigger, result = self.app.run(trigger_id, params)
        if trigger is None:
            return self._json(404, result)
        return self._json(200, result)

    def _serve_asset(self, name, ctype):
        path = os.path.join(DEFAULT_ASSETS_DIR, name)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return self._json(404, {"error": "asset not found"})
        return self._send(200, data, ctype)


def make_server(app):
    httpd = ThreadingHTTPServer((app.settings.host, app.settings.port), Handler)
    httpd.app = app
    httpd.daemon_threads = True
    return httpd


# ===========================================================================
# Embedded web UI (self-contained; HPE visual identity reused from netvitals)
# ===========================================================================
INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Vitals</title>
<style>
:root{
  --bg:#1a1d21; --surface:#23272e; --panel:#2c313a; --grid:#363b44;
  --ink:#f2f4f5; --dim:#9aa3ad; --faint:#6f787c;
  --hpe:#01A982; --hpe-dk:#017a5e;
  --info:#00B0E6; --warn:#FF8300; --crit:#E0574a; --gold:#FEC901;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
  --mono:ui-monospace,"Cascadia Code","SF Mono",Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:"Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
  font-size:15px;line-height:1.5;padding:clamp(14px,3vw,34px)}
.wrap{max-width:1100px;margin:0 auto}
a{color:var(--hpe)}
.eyebrow{font:600 11px/1 var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--hpe)}
header.head{display:flex;align-items:center;gap:16px;padding-bottom:16px;border-bottom:2px solid var(--grid)}
.logo{width:40px;height:40px;flex:none;display:grid;place-items:center;color:var(--hpe)}
.logo svg{width:100%;height:100%}
h1{margin:.2em 0 0;font-size:clamp(20px,3vw,28px);font-weight:800;letter-spacing:-.01em}
.head .meta{margin-left:auto;text-align:right;color:var(--dim);font:12px/1.5 var(--mono)}
.path{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:16px 0 6px;font-size:12.5px;color:var(--dim)}
.node{background:var(--panel);border:1px solid var(--grid);border-radius:8px;padding:6px 10px}
.node.sensor{border-color:var(--hpe);box-shadow:inset 0 0 0 1px var(--hpe)}
.arrow{color:var(--faint);font-weight:700}
.notice{margin:14px 0;padding:11px 14px;border-radius:10px;border:1px solid var(--grid);
  background:var(--surface);color:var(--dim);font-size:13px}
.notice b{color:var(--ink)}
.notice.live{border-color:var(--warn)}
.toolbar{display:flex;align-items:center;gap:12px;margin:16px 0 4px;flex-wrap:wrap}
.toolbar .kv{color:var(--dim)}
button.ghost{appearance:none;border:1px solid var(--grid);border-radius:8px;background:var(--panel);
  color:var(--ink);font:700 13px/1 "Segoe UI",sans-serif;padding:9px 16px;cursor:pointer}
button.ghost:hover{border-color:var(--hpe)}
button.ghost:disabled{color:var(--faint);cursor:not-allowed}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;margin-top:14px}
.card{background:var(--surface);border:1px solid var(--grid);border-radius:12px;padding:15px 16px;
  box-shadow:var(--shadow);border-left:3px solid var(--faint);display:flex;flex-direction:column;gap:9px}
.card.sev-info{border-left-color:var(--info)} .card.sev-warn{border-left-color:var(--warn)} .card.sev-crit{border-left-color:var(--crit)}
.card.disabled{opacity:.62}
.card h3{margin:0;font-size:15.5px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font:600 10.5px/1.4 var(--mono);padding:2px 8px;border-radius:999px;border:1px solid var(--grid);color:var(--dim);white-space:nowrap}
.chip.cls{color:var(--hpe);border-color:var(--hpe-dk)}
.chip.flag-live{color:var(--warn);border-color:var(--warn)}
.fire-row{font-size:12.5px;color:var(--dim)}
.fire-row .sid{color:var(--hpe);font-family:var(--mono);font-weight:700}
.talk{font-size:12.5px;color:var(--faint)}
.actions{display:flex;align-items:center;gap:10px;margin-top:2px}
button.fire{appearance:none;border:0;border-radius:8px;background:var(--hpe);color:#04120e;
  font:700 13px/1 "Segoe UI",sans-serif;padding:9px 16px;cursor:pointer}
button.fire:hover{background:var(--hpe-dk);color:#eafff8}
button.fire:disabled{background:var(--panel);color:var(--faint);cursor:not-allowed}
.state{font:700 12px/1 var(--mono);padding:6px 10px;border-radius:7px;letter-spacing:.02em;white-space:nowrap}
.state.allowed{background:rgba(0,176,230,.14);color:var(--info);border:1px solid var(--info)}
.state.blocked{background:rgba(1,169,130,.16);color:var(--hpe);border:1px solid var(--hpe)}
.state.error{background:rgba(224,87,74,.16);color:var(--crit);border:1px solid var(--crit)}
.state.invalid{background:rgba(254,201,1,.14);color:var(--gold);border:1px solid var(--gold)}
.state.running{background:var(--panel);color:var(--dim);border:1px solid var(--grid)}
.result{font-size:12.5px;color:var(--dim);border-top:1px dashed var(--grid);padding-top:9px;display:none}
.result.show{display:block}
.result .reason{color:var(--ink);margin-bottom:6px}
details{margin-top:6px}
summary{cursor:pointer;color:var(--faint);font-size:12px}
pre{background:var(--bg);border:1px solid var(--grid);border-radius:7px;padding:8px;overflow:auto;
  max-height:200px;font:12px/1.45 var(--mono);color:var(--ink);white-space:pre-wrap;word-break:break-word}
.kv{font-family:var(--mono);font-size:11.5px;color:var(--dim)}
footer{margin-top:26px;padding-top:12px;border-top:1px solid var(--grid);color:var(--faint);font:12px/1.5 var(--mono)}
</style></head>
<body><div class="wrap">
  <header class="head">
    <div class="logo" aria-hidden="true"><svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M2 21h8l3-11 6 20 4-13 3 6h9" stroke-linejoin="round" stroke-linecap="round"/></svg></div>
    <div>
      <div class="eyebrow">HPE Aruba · EdgeConnect demo toolbox</div>
      <h1>Security Vitals</h1>
    </div>
    <div class="meta">v__VERSION__<br><span id="path-src">Windows + WSL</span></div>
  </header>

  <div class="path">
    <span class="node">Source · WSL</span><span class="arrow">→</span>
    <span class="node sensor">EdgeConnect · Suricata v7 / WebCC</span><span class="arrow">→</span>
    <span class="node">Internet</span>
    <span style="margin-left:8px">verify on the Orchestrator / EC dashboard — this console polls no API</span>
  </div>

  <div id="live-notice" class="notice" style="display:none"></div>

  <div class="toolbar">
    <button id="run-all" class="ghost">Run all enabled</button>
    <button id="stop-all" class="ghost" style="display:none">Stop</button>
    <span id="run-all-status" class="kv"></span>
  </div>

  <div id="grid" class="grid" aria-live="polite"></div>
  <p id="empty" style="color:var(--dim)"></p>

  <footer>
    tmNIDS © 3CORESec · SIDs = Emerging Threats / GPL rulesets ·
    <span id="foot-state">loading…</span>
  </footer>
</div>
<script>
const TOKEN = "__TOKEN__";
const REG = [];                 // [{t, card, btn, state, res}]
let stopFlag = false;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt != null) e.textContent = txt; return e; };
const fmt = v => (v==null? "—" : v);

async function loadCatalog(){
  const r = await fetch("/api/catalog", {headers:{"Accept":"application/json"}});
  const data = await r.json();
  const enabledCount = data.triggers.filter(t => !t.gated_disabled).length;
  document.getElementById("foot-state").textContent =
    "catalog " + data.triggers.length + " trigger(s) · live-suspect hosts " +
    (data.enable_live_suspect_hosts ? "ENABLED" : "disabled");
  const ln = document.getElementById("live-notice");
  if (!data.enable_live_suspect_hosts){
    ln.style.display = "block"; ln.className = "notice";
    ln.innerHTML = "<b>Live suspect-infrastructure triggers are disabled.</b> " +
      "Triggers that reach real suspect hosts / live Tor nodes are greyed out. " +
      "Set <span class='kv'>enable_live_suspect_hosts: true</span> in config/settings.yaml to run them in a lab.";
  }
  const grid = document.getElementById("grid");
  grid.innerHTML = ""; REG.length = 0;
  for (const t of data.triggers) grid.appendChild(card(t));

  const runBtn = document.getElementById("run-all");
  runBtn.textContent = "Run all enabled (" + enabledCount + ")";
  runBtn.disabled = enabledCount === 0;
  runBtn.addEventListener("click", runAll);
  document.getElementById("stop-all").addEventListener("click", () => { stopFlag = true; });
}

function card(t){
  const c = el("div", "card sev-" + (t.severity||"info"));
  if (t.gated_disabled) c.classList.add("disabled");
  c.appendChild(el("h3", null, t.label));
  const chips = el("div", "chips");
  chips.appendChild(el("span", "chip cls", t.class));
  for (const f of (t.flags||[])){
    const live = f === "hits_live_suspect_hosts";
    chips.appendChild(el("span", "chip" + (live ? " flag-live" : ""), f.replace(/_/g," ")));
  }
  c.appendChild(chips);
  if (t.expected_fire){
    const fr = el("div", "fire-row"); fr.innerHTML = "Expect: <span class='sid'></span>";
    fr.querySelector(".sid").textContent = t.expected_fire; c.appendChild(fr);
  }
  if (t.talking_point) c.appendChild(el("div", "talk", t.talking_point));

  const actions = el("div", "actions");
  const btn = el("button", "fire", t.gated_disabled ? "Disabled" : "Fire trigger");
  btn.disabled = !!t.gated_disabled;
  const state = el("span", "state", ""); state.style.display = "none";
  actions.appendChild(btn); actions.appendChild(state);
  c.appendChild(actions);
  const res = el("div", "result");
  c.appendChild(res);

  const entry = {t, card: c, btn, state, res};
  REG.push(entry);
  btn.addEventListener("click", () => runOne(entry));
  return c;
}

async function runOne(entry){
  const {t, btn, state, res} = entry;
  btn.disabled = true;
  state.style.display = ""; state.className = "state running"; state.textContent = "running…";
  res.className = "result";
  try{
    const r = await fetch("/api/run", {
      method:"POST",
      headers:{"Content-Type":"application/json","X-Secvitals-Token":TOKEN},
      body: JSON.stringify({id: t.id})
    });
    const d = await r.json();
    render(d, state, res);
    return d.state;
  }catch(e){
    state.className = "state error"; state.textContent = "error";
    res.className = "result show"; res.textContent = "request failed: " + e;
    return "error";
  }finally{
    btn.disabled = !!t.gated_disabled;
  }
}

async function runAll(){
  const runBtn = document.getElementById("run-all");
  const stopBtn = document.getElementById("stop-all");
  const status = document.getElementById("run-all-status");
  const enabled = REG.filter(e => !e.t.gated_disabled);
  if (!enabled.length) return;
  stopFlag = false;
  runBtn.disabled = true; stopBtn.style.display = "";
  const tally = {allowed:0, blocked:0, error:0, invalid:0};
  let i = 0;
  for (const e of enabled){
    if (stopFlag){ status.textContent = "stopped after " + i + "/" + enabled.length; break; }
    i++;
    status.textContent = "running " + i + "/" + enabled.length + ": " + e.t.label;
    e.card.scrollIntoView({block:"nearest", behavior:"smooth"});
    const s = await runOne(e);
    tally[s] = (tally[s]||0) + 1;
    if (i < enabled.length && !stopFlag) await sleep(500);   // client pacing; server also spaces
  }
  if (!stopFlag)
    status.textContent = "done — " + tally.allowed + " allowed · " + tally.blocked + " blocked · " + tally.error + " error";
  runBtn.disabled = false; stopBtn.style.display = "none";
}

function render(d, state, res){
  const s = d.state || "error";
  const labels = {allowed:"sent · allowed", blocked:"sent · blocked", error:"error", invalid:"disabled"};
  state.className = "state " + s; state.textContent = labels[s] || s;
  res.className = "result show";
  res.innerHTML = "";
  res.appendChild(el("div", "reason", d.reason || ""));
  const kv = el("div", "kv",
    ["rc=" + fmt(d.rc), d.http_code!=null?("http="+d.http_code):null,
     d.duration_s!=null?(d.duration_s+"s"):null].filter(Boolean).join("   "));
  res.appendChild(kv);
  if (d.argv){ res.appendChild(detail("argv", d.argv.join(" "))); }
  if (d.stdout){ res.appendChild(detail("stdout", d.stdout)); }
  if (d.stderr){ res.appendChild(detail("stderr", d.stderr)); }
}
function detail(label, text){
  const dt = el("details"); dt.appendChild(el("summary", null, label));
  dt.appendChild(el("pre", null, text)); return dt;
}

loadCatalog().catch(e => { document.getElementById("empty").textContent = "failed to load catalog: " + e; });
</script>
</body></html>
"""


# ===========================================================================
# Self-update  —  pinned source, offline-signed manifest, verify-before-apply,
# fail closed. Ports netvitals' mechanism/UX (atomic .new -> os.replace, .bak,
# check-vs-apply split) and ADDS authenticity it never had. See docs/UPDATE_SECURITY.md.
# ---------------------------------------------------------------------------
# RSA-2048 / SHA-256 PKCS#1 v1.5 signature verification, pure stdlib. RSA verify is
# modular exponentiation with the public exponent; PKCS#1 v1.5 verify is a STRICT
# comparison against the fully reconstructed padded block (no lax parsing → no
# Bleichenbacher-style forgery). Interoperates with `openssl dgst -sha256 -sign`.
# ===========================================================================
class UpdateError(Exception):
    """Raised on any update problem. The caller always fails closed."""


_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _der_read(data, i):
    """Read one DER TLV starting at index i. Returns (tag, value_bytes, next_index)."""
    if i + 2 > len(data):
        raise UpdateError("truncated DER")
    tag = data[i]
    ln = data[i + 1]
    i += 2
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or i + nbytes > len(data):
            raise UpdateError("bad DER length")
        ln = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    if i + ln > len(data):
        raise UpdateError("DER value exceeds buffer")
    return tag, data[i:i + ln], i + ln


def _parse_rsa_pub(pem):
    """Extract (n, e) from an RSA public key PEM (SubjectPublicKeyInfo or PKCS#1)."""
    body = re.sub(r"-----[^-]+-----", "", pem).replace("\n", "").replace("\r", "").strip()
    try:
        der = _b64decode_strict(body)   # binascii.Error is a ValueError subclass
    except ValueError as e:
        raise UpdateError(f"public key is not valid base64: {e}") from e
    if "BEGIN RSA PUBLIC KEY" in pem:                # PKCS#1 RSAPublicKey
        _, seq, _ = _der_read(der, 0)
        _, nb, k = _der_read(seq, 0)
        _, eb, _ = _der_read(seq, k)
        return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")
    _, spki, _ = _der_read(der, 0)                   # SubjectPublicKeyInfo SEQUENCE
    _, _alg, j = _der_read(spki, 0)                  # AlgorithmIdentifier SEQUENCE
    tag_bs, bs, _ = _der_read(spki, j)               # BIT STRING
    if tag_bs != 0x03 or not bs:
        raise UpdateError("malformed public key (expected BIT STRING)")
    _, seq, _ = _der_read(bs[1:], 0)                 # drop 'unused bits' byte -> RSAPublicKey
    _, nb, k = _der_read(seq, 0)
    _, eb, _ = _der_read(seq, k)
    return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")


def _b64decode_strict(s):
    import base64
    return base64.b64decode(s, validate=True)


def verify_rsa_sha256(pubkey_pem, message, signature):
    """Return True iff `signature` is a valid RSA/SHA-256 PKCS#1 v1.5 signature over
    `message` under `pubkey_pem`. Never raises for a bad signature — returns False."""
    try:
        n, e = _parse_rsa_pub(pubkey_pem)
    except UpdateError:
        return False
    if n <= 0 or e <= 0:
        return False
    k = (n.bit_length() + 7) // 8
    if k < 64 or len(signature) != k:                # RSA-2048 => k == 256
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest_info = _SHA256_DIGESTINFO + hashlib.sha256(message).digest()
    ps_len = k - 3 - len(digest_info)
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest_info
    return hmac.compare_digest(em, expected)


def _update_http_get(url, timeout, max_bytes):
    req = urllib.request.Request(url, headers={"User-Agent": "secvitals/%s" % __version__})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final = getattr(resp, "url", None) or url
            if url.lower().startswith("https:") and not final.lower().startswith("https:"):
                raise UpdateError(f"refusing redirect to insecure URL {final}")
            data = resp.read(max_bytes + 1)
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"download failed: {e}") from e
    if len(data) > max_bytes:
        raise UpdateError("response larger than expected — refusing")
    return data


def parse_manifest(manifest_bytes):
    try:
        m = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise UpdateError(f"manifest is not valid JSON/UTF-8: {e}") from e
    if not isinstance(m, dict):
        raise UpdateError("manifest is not an object")
    for key in ("version", "artifact", "sha256"):
        if not isinstance(m.get(key), str):
            raise UpdateError(f"manifest missing string field {key!r}")
    if m["artifact"] != "secvitals.py":
        raise UpdateError(f"unexpected artifact name {m['artifact']!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", m["sha256"]):
        raise UpdateError("manifest sha256 is not a 64-hex digest")
    if _version_tuple(m["version"]) is None:
        raise UpdateError("manifest version is not parseable")
    return m


def _version_tuple(s):
    nums = re.findall(r"\d+", s or "")[:3]
    return tuple(int(x) for x in nums) if nums else None


def check_update(manifest_url=UPDATE_MANIFEST_URL, pubkey=UPDATE_PUBKEY, timeout=15):
    """Fetch + verify the release manifest. Return the manifest dict if a strictly
    newer, correctly-SIGNED release is available, else None. Raises UpdateError and
    fails closed on any verification failure."""
    if not pubkey or "BEGIN" not in pubkey:
        raise UpdateError("no update public key configured — refusing to update")
    manifest_bytes = _update_http_get(manifest_url, timeout, 64 * 1024)
    sig_bytes = _update_http_get(manifest_url + ".sig", timeout, 4096)
    if not verify_rsa_sha256(pubkey, manifest_bytes, sig_bytes):
        raise UpdateError("manifest signature did not verify — refusing (fail closed)")
    m = parse_manifest(manifest_bytes)
    remote, local = _version_tuple(m["version"]), _version_tuple(__version__)
    if remote <= local:
        return None
    return m


def download_and_install(manifest, manifest_url=UPDATE_MANIFEST_URL, pubkey=UPDATE_PUBKEY,
                         timeout=30, target=None):
    """Fetch the artifact named by an already-verified manifest, check its SHA-256,
    install atomically (.new -> os.replace, keep .bak), and re-verify the on-disk file
    before returning. Raises UpdateError; never leaves a partial file in place.
    `target` defaults to this file; tests pass a temp path."""
    if getattr(sys, "frozen", False):
        raise UpdateError("packaged executable can't replace itself — download the new version")
    want = manifest["sha256"].lower()
    base = manifest_url.rsplit("/", 1)[0]
    artifact_url = base + "/" + manifest["artifact"]
    data = _update_http_get(artifact_url, timeout, 16 * 1024 * 1024)
    got = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(got, want):
        raise UpdateError(f"artifact sha256 mismatch (manifest {want[:12]}…, got {got[:12]}…)")
    # The signed manifest binds this hash; also sanity-check it is plausibly this app.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise UpdateError(f"artifact is not UTF-8: {e}") from e
    if "SecVitals" not in text and "Security Vitals" not in text:
        raise UpdateError("artifact does not look like Security Vitals — refusing")

    target = target or os.path.abspath(__file__)
    tmp, backup = target + ".new", target + ".bak"
    try:
        with open(target, "rb") as fh:
            current = fh.read()
        with open(backup, "wb") as fh:
            fh.write(current)
        with open(tmp, "wb") as fh:
            fh.write(data)
        with open(tmp, "rb") as fh:                  # re-verify the bytes on disk (TOCTOU)
            if not hmac.compare_digest(hashlib.sha256(fh.read()).hexdigest(), want):
                raise UpdateError("on-disk artifact failed re-verification — refusing to swap")
        os.replace(tmp, target)                      # atomic on the same filesystem
    except OSError as e:
        _quiet_remove(tmp)
        raise UpdateError(f"install failed: {e}") from e
    return target


def perform_update(manifest_url=UPDATE_MANIFEST_URL, apply=True, pubkey=UPDATE_PUBKEY):
    """CLI driver. Exit codes: 0 up-to-date/updated, 1 failed, 3 update-available (check)."""
    print(f"{APP_NAME} {__version__}")
    print(f"Checking {manifest_url} …")
    try:
        m = check_update(manifest_url, pubkey)
    except UpdateError as e:
        print(f"Update check failed: {e}", file=sys.stderr)
        return 1
    if m is None:
        print("Already up to date.")
        return 0
    print(f"New signed version available: {m['version']}")
    if not apply:
        return 3
    try:
        target = download_and_install(m, manifest_url, pubkey)
    except UpdateError as e:
        print(f"Update failed: {e}", file=sys.stderr)
        return 1
    print(f"Updated to {m['version']} — previous saved as {os.path.basename(target)}.bak")
    print("Restart the console to run the new version.")
    return 0


# ===========================================================================
# Entry point
# ===========================================================================
def setup_logging(verbose):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


def parse_args(argv):
    p = argparse.ArgumentParser(prog="secvitals", description=APP_NAME)
    p.add_argument("--config-dir", default=DEFAULT_CONFIG_DIR,
                   help="directory holding settings.yaml and catalog.yaml")
    p.add_argument("--port", type=int, default=None, help="override the listen port (loopback only)")
    p.add_argument("--no-browser", action="store_true", help="do not try to open a browser")
    p.add_argument("--verbose", action="store_true", help="debug logging")
    p.add_argument("--check-update", action="store_true",
                   help="check the pinned, signed release source for a newer version and exit")
    p.add_argument("--update", action="store_true",
                   help="verify and install a newer signed release, then exit (fails closed)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    setup_logging(args.verbose)

    if args.check_update or args.update:
        # Update is a code-execution channel: pinned source, signed manifest, fail closed.
        return perform_update(UPDATE_MANIFEST_URL, apply=args.update)

    try:
        settings = load_settings(args.config_dir)
        if args.port is not None:
            settings.raw.setdefault("server", {})["port"] = args.port
        triggers = load_catalog(args.config_dir, settings)
    except ConfigError as e:
        log.error("configuration error: %s", e)
        return 2

    if not _is_loopback(settings.host):
        log.error("refusing to bind non-loopback host %r — this app is not a LAN service", settings.host)
        return 2

    app = App(settings, triggers, args.config_dir)
    try:
        httpd = make_server(app)
    except OSError as e:
        log.error("could not bind %s:%s — %s", settings.host, settings.port, e)
        return 2

    url = f"http://{settings.host}:{settings.port}/"
    log.info("%s %s serving on %s (%d triggers)", APP_NAME, __version__, url, len(triggers))
    print(f"\n  {APP_NAME} {__version__}")
    print(f"  Open in the Windows browser:  {url}\n")
    if settings.open_browser and not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception as e:  # webbrowser can raise on headless WSL — never fatal
            log.debug("could not open a browser automatically: %s", e)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
