#!/usr/bin/env python3
"""Security Vitals — a local security-trigger console.

Fires security-trigger traffic on a button click and classifies the LOCAL result
(allowed / blocked / error). The host sits behind an inline security stack; traffic
egresses and is inspected by the network's IDS/IPS and Secure Web Gateway. This app
polls no management API — the presenter verifies on the inline stack's management
console already on screen.

Design (see CONFIRMED.md):
  * Single code artifact, stdlib only. Self-contained Tkinter window (no browser, no
    local server). Everything runs NATIVELY — no WSL: curl commands go through the
    system curl (curl.exe on Windows 10 1803+), and `dns` / `tcp` triggers use small
    stdlib socket probes. Each trigger reproduces the exact requests a tmNIDS test
    sends, so the same IDS/IPS signatures trip without shelling any
    third-party binary.
  * Fixed catalog (config/catalog.yaml). A trigger's commands are FIXED there; nothing
    is built from free text. subprocess with an argv list, no shell=True, per-trigger
    timeout, captured stdout/stderr/returncode. A trigger may fire several requests.
  * Three-state classifier: `blocked` and `error` never collapse. A native probe that
    doesn't complete is disambiguated by a control egress probe, so a broken environment
    reports `error`, never a false `blocked`.

This module is import-safe: importing it starts nothing (everything is behind main()).
"""

import argparse
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

__version__ = "0.6.0"
APP_NAME = "Security Vitals"

log = logging.getLogger("secvitals")

# --- Self-update: pinned source + embedded verification key (see docs/UPDATE_SECURITY.md).
# The manifest URL is a NON-OVERRIDABLE constant: there is no --update-url flag, because
# the update channel is a code-execution channel and a substitutable source is an RCE
# vector. Releases are signed offline; this app ships only the PUBLIC key and fails
# closed on any verification failure.
UPDATE_MANIFEST_URL = "https://github.com/robertsonc/secvitals/releases/latest/download/manifest.json"

# Release verification key (RSA-2048). Rotating this is order-dependent: clients trust
# only the key in the build they are already running, so a new key must arrive inside a
# release signed with the OLD one. See the rotation section of docs/UPDATE_SECURITY.md.
UPDATE_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqNE7pkVUXTli5dBDijnS
RopSwNTh+C2F9z971VRJ1mi4FRVpLXQ+zjpLZYRJpZh1jIP5XmePWGEjwcKDnnet
JhQRZe2Qp9Gf3vrK0exaQZtvpe//TqftO71qBBOlvyTs3tLnm78GMCWkiJB+N6ND
EFyKWIwe4yfwgnpWmvoPr+P8ZYxw/0bCjy8Q0f5MoXOFjD8Wyr5qYBlaU/Vu1U5X
74RKP2SotOTRMPxOjFYbf6E4Fk/FqIi6sDsRX1unM3XO9jlU4xC41FU7F+QEMkLk
YyIG2L3Wgj4zbD1AwP5QDvrIZzHtRvUvq7QHorlkXy7SxgdvCMBEXmIB3f/VrgHX
RwIDAQAB
-----END PUBLIC KEY-----
"""

_THIS_FILE = os.path.abspath(__file__)          # used by the updater to replace this file
HERE = os.path.dirname(_THIS_FILE)
DEFAULT_CONFIG_DIR = os.path.join(HERE, "config")
DEFAULT_ASSETS_DIR = os.path.join(HERE, "assets")

# Known catalog vocabularies (fixed allowlists).
CLASSES = {"ns-ids", "ns-webcc", "ns-iprep", "ns-dlp", "ew"}   # `ew` reserved / deferred
# All runners execute NATIVELY (Windows or Linux) — no WSL, no download-and-execute:
#   curl = curl.exe / curl (ships with Windows 10 1803+); dns / tcp = built-in stdlib
#   probes; iprep = built-in IP-reputation probe. A trigger reproduces the exact requests
#   a tmNIDS test sends (curl URLs/headers/UAs, a DNS query, a TCP connect), so it trips
#   the same IDS/IPS signatures without shelling a third-party binary.
RUNNERS = {"curl", "dns", "tcp", "iprep"}
FLAGS = {"needs_internet", "needs_et_ruleset", "hits_live_suspect_hosts"}
SEVERITIES = {"info", "warn", "crit"}

# Where a presenter looks for THIS class of signal on the inline stack's own console.
# A catalog entry may override with its own `console_hint`; these are the fallbacks.
# Deliberately vendor-neutral — every stack names these views differently.
CLASS_CONSOLE_HINT = {
    "ns-ids": "IDS/IPS alert or threat log — filter by the 5-tuple below and the run time; expect the SID above.",
    "ns-webcc": "Web/URL filtering log — filter by destination host or URL; expect the category above with action Deny.",
    "ns-iprep": "IP reputation / threat-intel hits — filter by the destination IPs below.",
    "ns-dlp": "DLP / content-inspection log — filter by the 5-tuple below; expect the data pattern above.",
    "ew": "East-west / segmentation policy log — filter by the source and destination zones.",
}

# Windows has no /dev/null; catalog commands use the {devnull} token, substituted to
# os.devnull at run time (see build_command). It is a fixed safe value, never client input.
DEVNULL_TOKEN = "{devnull}"

# UI result states — `blocked` and `error` MUST stay distinct.
ALLOWED, BLOCKED, ERROR, INVALID = "allowed", "blocked", "error", "invalid"
RATIO = "ratio"   # IP reputation reports N-of-M, never a single verdict


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
        return bool(self.control_endpoints)

    @property
    def origin_failover(self):
        """Fixed map of origin host -> alternate host, applied ONLY when a request
        honestly ERRORS (DNS/TLS failure), never past a blocked or allowed result.

        EMPTY BY DEFAULT. It preserves signal count when an origin is down, but it also
        changes what is on the wire: an alternate that does not serve the same content
        can turn a real signal into a benign request that never trips anything. Enable it
        only with an alternate you control and have checked."""
        raw = _dget(self.raw, "run.origin_failover", None)
        out = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if (isinstance(key, str) and isinstance(value, str)
                        and key.strip() and value.strip()):
                    out[key.strip()] = value.strip()
        return out

    @property
    def control_endpoints(self):
        """Ordered control endpoints as (kind, host, port).

        A SINGLE control host is a single point of failure for the whole blocked-vs-error
        decision: if the customer's policy happens to deny 1.1.1.1, every native probe
        drop degrades to `error` and real blocks are masked. Egress is considered up if
        ANY endpoint answers.

        `kind` is "tcp" or "dns" so the control can be transport-matched — a network that
        permits DNS while denying outbound TCP/443 would otherwise produce a false
        `error` for DNS triggers."""
        raw = _dget(self.raw, "run.control_endpoints", None)
        out = []
        if isinstance(raw, list) and raw:
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                host = str(entry.get("host", "") or "").strip()
                if not host:
                    continue
                kind = str(entry.get("kind", "tcp") or "tcp").strip().lower()
                if kind not in ("tcp", "dns"):
                    kind = "tcp"
                try:
                    port = int(entry.get("port", 53 if kind == "dns" else 443))
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535:
                    out.append((kind, host, port))
        if out:
            return out
        # Fall back to the historical single endpoint so existing installs behave the same.
        if self.control_host:
            return [("tcp", self.control_host, self.control_port)]
        return []

    @property
    def min_run_interval(self):
        # Server-side rate limit: minimum spacing between consecutive trigger runs, so a
        # "run all" (or a fast clicker) can't flood the inline security stack / SIEM.
        return float(_dget(self.raw, "run.min_interval_s", 0.75))

    @property
    def tor_list_url(self):
        return str(_dget(self.raw, "webcc.tor_list_url", "") or "")

    @property
    def tor_list_ttl(self):
        return float(_dget(self.raw, "webcc.tor_list_ttl_s", 3600))

    @property
    def ip_rep_sample(self):
        return int(_dget(self.raw, "webcc.ip_rep_sample", 6))

    @property
    def node_probe_timeout(self):
        return float(_dget(self.raw, "webcc.node_probe_timeout_s", 5))


@dataclasses.dataclass
class Trigger:
    id: str
    label: str
    cls: str
    runner: str
    commands: list          # list of argv-lists — a trigger may fire several requests
    flags: list
    severity: str
    threat_class: str
    expected_fire: str
    talking_point: str
    expected_on_allow: dict
    expected_on_block: dict
    params: list
    timeout: float
    console_hint: str = ""      # optional "where to look on the inline console"

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
        # Accept `commands: [[...], [...]]` (multi-request) or `argv: [...]` (single); the
        # iprep runner needs neither (its probe is built in).
        commands = d.get("commands")
        if commands is None and d.get("argv") is not None:
            commands = [d.get("argv")]
        if commands is None and runner == "iprep":
            commands = [["iprep"]]
        if not isinstance(commands, list) or not commands:
            raise ConfigError(f"{tid}: needs a non-empty 'commands' (list of argv lists)")
        for cmd in commands:
            if not isinstance(cmd, list) or not cmd or not all(isinstance(a, str) for a in cmd):
                raise ConfigError(f"{tid}: each command must be a non-empty list of strings, got {cmd!r}")
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
        _validate_params(tid, params, commands)
        hint = d.get("console_hint", "")
        if not isinstance(hint, str):
            raise ConfigError(f"{tid}: console_hint must be a string")
        if len(hint) > 300:
            raise ConfigError(f"{tid}: console_hint is too long (max 300 characters)")
        return Trigger(
            id=tid,
            label=str(d.get("label", tid)),
            cls=cls,
            runner=runner,
            commands=[list(c) for c in commands],
            flags=list(flags),
            severity=sev,
            threat_class=str(d.get("threat_class", "")),
            expected_fire=str(d.get("expected_fire", "")),
            talking_point=str(d.get("talking_point", "")),
            expected_on_allow=allow,
            expected_on_block=block,
            params=params,
            timeout=float(d.get("timeout_s", default_timeout)),
            console_hint=hint,
        )

    def gated_disabled(self, settings):
        return ("hits_live_suspect_hosts" in self.flags
                and not settings.enable_live_suspect_hosts)

    def on_wire_count(self, settings):
        """How many requests this trigger actually puts ON THE WIRE.

        For most runners that is one per catalog command. The `iprep` runner is the
        exception: its single `["iprep"]` command fans out to `webcc.ip_rep_sample`
        node probes, so counting commands under-reports it (6x at the default sample).
        This is the number to quote when promising a known quantity of signals."""
        if self.runner == "iprep":
            return max(1, int(settings.ip_rep_sample))
        return len(self.commands)

    def console_hint_text(self):
        """Where to look for this trigger on the inline stack's console: the catalog's
        own `console_hint` when it declares one, else the per-class default."""
        return self.console_hint or CLASS_CONSOLE_HINT.get(self.cls, "")

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
            "console_hint": self.console_hint_text(),
            "request_count": len(self.commands),
            "wire_request_count": self.on_wire_count(settings),
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


_BUILTIN_TOKENS = {"devnull"}   # substituted by build_command, not catalog params


def _validate_params(tid, params, commands):
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
    used = {tok[1:-1] for cmd in commands for tok in cmd
            if isinstance(tok, str) and tok.startswith("{") and tok.endswith("}")}
    missing = used - names - _BUILTIN_TOKENS
    if missing:
        raise ConfigError(f"{tid}: commands reference undeclared params {sorted(missing)}")


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




def _quiet_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


class TorNodeCache:
    """Fetch + cache the Tor relay IP list with a TTL — not refetched on every click."""

    def __init__(self, url, ttl):
        self.url = url
        self.ttl = ttl
        self._lock = threading.Lock()
        self._nodes = None
        self._fetched_at = 0.0

    def get(self):
        """Return a list of relay IPv4 strings. Raises urllib/OSError on fetch failure
        (the caller maps that to `error`)."""
        with self._lock:
            now = time.monotonic()
            if self._nodes is not None and (now - self._fetched_at) < self.ttl:
                return self._nodes
            nodes = self._fetch()
            self._nodes, self._fetched_at = nodes, now
            return nodes

    def _fetch(self):
        if not self.url.lower().startswith("https:"):
            raise OSError(f"tor_list_url must be https, got {self.url!r}")
        req = urllib.request.Request(self.url, headers={"User-Agent": "secvitals/%s" % __version__})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read(8 * 1024 * 1024).decode("utf-8", "replace")
        return _parse_tor_ips(data)


def _parse_tor_ips(text):
    """Extract well-formed IPv4 addresses from the node list, skipping comments/junk."""
    out = []
    for line in (text or "").splitlines():
        ip = line.strip()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and all(0 <= int(o) <= 255 for o in ip.split(".")):
            out.append(ip)
    return out


# ===========================================================================
# Runner  —  native execution: curl.exe / stdlib probes, argv lists, no shell
# ===========================================================================
# Every trigger runs NATIVELY (Windows or Linux): curl commands go through curl.exe /
# curl; `dns` and `tcp` triggers use small stdlib socket probes. A trigger may fire
# several requests (Trigger.commands) — e.g. the five malware User-Agents — reproducing
# exactly what the corresponding tmNIDS test sends so the same signatures trip, without
# shelling any third-party binary. `blocked` and `error` still never collapse.
@dataclasses.dataclass
class SubResult:
    argv: list = dataclasses.field(default_factory=list)   # command as displayed
    rc: int = None
    http_code: int = None
    stdout: str = ""
    stderr: str = ""
    ok: bool = None            # dns/tcp probe: did the expected thing happen?
    error_reason: str = None   # environment failure for THIS request (→ error)
    timed_out: bool = False
    flow: dict = None          # 5-tuple actually put on the wire (see _flow)
    failover_from: str = ""    # original origin, when an ERROR triggered a failover


@dataclasses.dataclass
class RunResult:
    subs: list = dataclasses.field(default_factory=list)
    duration_s: float = 0.0
    control_ok: bool = None    # egress control probe (dns/tcp only); None = not run
    control_detail: str = ""   # which endpoint answered, for the details pane
    error_reason: str = None   # trigger-level error (e.g. param error) → error


class ParamError(Exception):
    """Raised when supplied params fail per-trigger validation."""


# curl exit codes (see CONFIRMED.md §5) — identical on Windows and Linux curl.
BLOCKED_RC = {28, 7, 56}          # timeout, connection refused, recv reset — consistent with a drop
BROKEN_RC = {6, 5, 35, 60, 77}    # DNS, proxy DNS, TLS handshake, cert — environment, not policy


# ---------------------------------------------------------------------------
# 5-tuple capture — what actually went on the wire, for correlating a click with the
# flow / event records in the inline stack's management console. Every runner reports the same shape:
# src-ip, src-port, protocol, dst-ip, dst-port (+ the dialled hostname, when there is
# one). Nothing here changes what is SENT; it only records the endpoints.
#
# curl is the awkward case: the socket lives in another process, so the endpoints come
# back through curl's own --write-out. The catalog's `-w` format is extended IN CODE
# rather than in catalog.yaml, because a self-update ships secvitals.py alone — an
# install that updates in place keeps its existing catalog, and would otherwise never
# report a tuple. The displayed command stays exactly what the catalog declares.
FLOW_MARK = "SECV-5TUPLE"
_FLOW_WRITEOUT = "\\n" + FLOW_MARK + "|%{local_ip}|%{local_port}|%{remote_ip}|%{remote_port}\\n"
_FLOW_RE = re.compile(r"^" + FLOW_MARK + r"\|([^|\n]*)\|([^|\n]*)\|([^|\n]*)\|([^|\n]*)[ \t]*$",
                      re.MULTILINE)


def _flow(proto, src_ip="", src_port="", dst_ip="", dst_port="", host=""):
    """One 5-tuple record. Unknown fields stay empty and render as '—' — never guessed."""
    def clean(v):
        v = "" if v is None else str(v).strip()
        # An old curl that doesn't know a --write-out variable echoes it literally.
        return "" if ("%" in v or "{" in v or v in ("0", "0.0.0.0", "::")) else v[:64]
    dst_ip, host = clean(dst_ip), clean(host)
    if not dst_ip and _is_ip_literal(host):     # the command dialled an address, not a name
        dst_ip = host
    return {"proto": proto, "src_ip": clean(src_ip), "src_port": clean(src_port),
            "dst_ip": dst_ip, "dst_port": clean(dst_port), "host": host}


def _is_ip_literal(s):
    if not s:
        return False
    if ":" in s:                                 # IPv6 literal
        return all(c in "0123456789abcdefABCDEF:" for c in s)
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) < 256 for p in parts)


def _url_endpoint(argv):
    """(host, port) from the first http(s) URL in a curl argv — the destination the
    command asked for, used when curl never got far enough to report a peer."""
    for tok in argv or []:
        if isinstance(tok, str) and tok.startswith(("http://", "https://")):
            scheme, _, rest = tok.partition("://")
            authority = rest.split("/", 1)[0].rpartition("@")[2]
            if authority.startswith("["):                      # IPv6 literal
                host, _, tail = authority[1:].partition("]")
                port = tail[1:] if tail.startswith(":") else ""
            else:
                host, _, port = authority.partition(":")
            return host, (port or ("443" if scheme == "https" else "80"))
    return "", ""


def _swap_url_host(argv, old_host, new_host):
    """Rewrite ONLY the host of http(s) URLs in a fixed command. Every other token —
    headers, user-agents, payload bodies — is untouched, so the signal itself is
    unchanged; only where it is sent differs."""
    out = []
    for tok in argv:
        if isinstance(tok, str) and tok.startswith(("http://", "https://")):
            scheme, _, rest = tok.partition("://")
            authority, slash, tail = rest.partition("/")
            userinfo, at, hostport = authority.rpartition("@")
            host, colon, port = hostport.partition(":")
            if host == old_host:
                hostport = new_host + colon + port
                tok = scheme + "://" + userinfo + at + hostport + slash + tail
        out.append(tok)
    return out


def _curl_flow_argv(argv):
    """The argv actually executed: the catalog's command with the 5-tuple fields appended
    to its --write-out format (or a --write-out added, if it has none)."""
    out = list(argv)
    for i, tok in enumerate(out):
        if tok == "-w" and i + 1 < len(out):
            out[i + 1] = out[i + 1] + _FLOW_WRITEOUT
            return out
    return out + ["-w", _FLOW_WRITEOUT]


def _take_curl_flow(stdout, argv):
    """Split curl's stdout into (stdout without the marker line, flow). The marker line is
    ours, not the trigger's output, so it never reaches the details pane."""
    host, url_port = _url_endpoint(argv)
    m = _FLOW_RE.search(stdout or "")
    if not m:
        return stdout, _flow("TCP", dst_port=url_port, host=host)
    src_ip, src_port, dst_ip, dst_port = m.groups()
    cleaned = _FLOW_RE.sub("", stdout).replace("\n\n", "\n").strip("\n")
    flow = _flow("TCP", src_ip, src_port, dst_ip, dst_port, host)
    if not flow["dst_port"]:              # curl too old to report the peer port
        flow["dst_port"] = url_port
    return cleaned, flow


def _resolve_params(trigger, params):
    """Validate supplied params against the per-trigger allowlist/pattern once; the same
    resolved values fill every command. Commands are never built from free text."""
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
    return resolved


def build_command(template, resolved):
    """Resolve one fixed command template into a concrete argv: the {devnull} token plus
    any validated params. Anything in braces that isn't a resolved param is refused."""
    argv = []
    for tok in template:
        if tok == DEVNULL_TOKEN:
            argv.append(os.devnull)
        elif isinstance(tok, str) and tok.startswith("{") and tok.endswith("}"):
            nm = tok[1:-1]
            if nm not in resolved:
                raise ParamError(f"unresolved token {tok}")
            argv.append(resolved[nm])
        else:
            argv.append(tok)
    return argv


def run_trigger(trigger, params, settings):
    """Run every command of one trigger natively and return a RunResult. Never raises for
    expected failure modes — those become per-request error_reason (→ `error`)."""
    try:
        resolved = _resolve_params(trigger, params)
    except ParamError as e:
        return RunResult(error_reason=f"invalid parameters: {e}")

    start = time.monotonic()
    subs, need_control = [], False
    for template in trigger.commands:
        try:
            argv = build_command(template, resolved)
        except ParamError as e:
            subs.append(SubResult(argv=list(template), error_reason=f"invalid parameters: {e}"))
            continue
        if trigger.runner == "curl":
            subs.append(_run_curl_with_failover(argv, trigger.timeout, settings))
        elif trigger.runner == "dns":
            s = _run_dns(argv, trigger.timeout)
            subs.append(s)
            need_control = need_control or (s.ok is False and not s.error_reason)
        elif trigger.runner == "tcp":
            s = _run_tcp(argv, trigger.timeout)
            subs.append(s)
            need_control = need_control or (s.ok is False and not s.error_reason)
        else:
            subs.append(SubResult(argv=argv, error_reason=f"unsupported runner {trigger.runner!r}"))

    res = RunResult(subs=subs, duration_s=time.monotonic() - start)
    # A native probe (dns/tcp) that didn't complete could be an inline drop OR a broken
    # environment — a control egress probe to a known-good host tells the two apart, so a
    # broken environment is `error`, never a false `blocked`. curl doesn't need this: its
    # own exit code already separates a drop (7/28/56) from an environment failure (60/…).
    if need_control and settings.control_enabled:
        res.control_ok, res.control_detail = probe_control(
            settings, min(6.0, trigger.timeout),
            prefer_kind=("dns" if trigger.runner == "dns" else "tcp"))
    return res


def _run_curl_with_failover(argv, timeout, settings):
    """Run a curl command; on an ENVIRONMENT error only, retry once against a configured
    alternate origin.

    Never applied past a blocked or allowed result: a policy outcome is the answer, and
    retrying it elsewhere would launder it. The retry is kept only if it produced a real
    policy result — otherwise the original honest error stands."""
    sub = _run_curl(argv, timeout)
    if classify_curl(sub.rc, sub.http_code) != ERROR or sub.rc not in BROKEN_RC:
        return sub
    host, _port = _url_endpoint(argv)
    alternate = settings.origin_failover.get(host) if host else None
    if not alternate:
        return sub
    retry = _run_curl(_swap_url_host(argv, host, alternate), timeout)
    if classify_curl(retry.rc, retry.http_code) == ERROR:
        return sub                      # the failover did not help — keep the truth
    retry.failover_from = host
    log.info("origin failover: %s -> %s", host, alternate)
    return retry


def _run_curl(argv, timeout):
    exec_argv = _curl_flow_argv(argv)          # argv stays the catalog's, for display
    try:
        proc = subprocess.run(exec_argv, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as e:
        return SubResult(argv=argv, error_reason=f"curl not found ({e}) — Windows 10 1803+ ships curl.exe")
    except subprocess.TimeoutExpired as e:
        out, flow = _take_curl_flow(_dec(e.stdout), argv)
        return SubResult(argv=argv, timed_out=True, stdout=out, stderr=_dec(e.stderr), flow=flow)
    except OSError as e:
        return SubResult(argv=argv, error_reason=f"could not execute curl: {e}")
    out, flow = _take_curl_flow(_dec(proc.stdout), argv)
    return SubResult(argv=argv, rc=proc.returncode, http_code=_parse_http_code(out),
                     stdout=out, stderr=_dec(proc.stderr), flow=flow)


def _run_dns(argv, timeout):
    """`dns` command: ["dns", "<name>", "@<server>"] — a native A-record query."""
    qname, server = None, "8.8.8.8"
    for a in argv[1:]:
        if a.startswith("@"):
            server = a[1:] or server
        elif qname is None:
            qname = a
    if not qname:
        return SubResult(argv=argv, error_reason="dns: no query name in command")
    ok, detail, err, flow = _dns_query(qname, server, min(float(timeout), 8.0))
    if err:
        return SubResult(argv=argv, ok=False, error_reason=err, flow=flow)
    return SubResult(argv=argv, ok=ok, stdout=detail, flow=flow)


def _run_tcp(argv, timeout):
    """`tcp` command: ["tcp-connect", "<host>", "<port>"] — a native TCP connect/banner."""
    if len(argv) < 3:
        return SubResult(argv=argv, error_reason="tcp: command needs a host and port")
    host, port = argv[1], argv[2]
    try:
        port = int(port)
    except (TypeError, ValueError):
        return SubResult(argv=argv, error_reason=f"tcp: bad port {port!r}")
    ok, detail, err, flow = _tcp_banner(host, port, min(float(timeout), 8.0))
    if err:
        return SubResult(argv=argv, ok=False, error_reason=err, flow=flow)
    return SubResult(argv=argv, ok=ok, stdout=detail, flow=flow)


def _sock_flow(sock, proto, host, dst_ip="", dst_port=""):
    """The 5-tuple of a live socket. getsockname() is what the stack actually bound, so
    the src-port here is the one the management console will show for this flow."""
    src_ip = src_port = ""
    try:
        local = sock.getsockname()
        src_ip, src_port = local[0], local[1]
    except OSError:
        pass
    if not dst_ip:
        try:
            peer = sock.getpeername()
            dst_ip, dst_port = peer[0], peer[1]
        except OSError:
            pass
    return _flow(proto, src_ip, src_port, dst_ip, dst_port, host)


def _dns_query(qname, server="8.8.8.8", timeout=5.0):
    """Send a minimal DNS A-query over UDP and wait for a response. Returns
    (ok, detail, err, flow): ok True if ANY response came back (the query crossed the wire
    and the resolver was reachable), ok False on timeout (no response — possibly a policy
    drop), err set only for a local/environment failure."""
    try:
        labels = qname.rstrip(".").split(".")
        q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels) + b"\x00"
        packet = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
    except (UnicodeError, ValueError) as e:
        return (False, "", f"dns: bad query name {qname!r}: {e}", None)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flow = _flow("UDP", dst_ip=server, dst_port=53, host=qname)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        flow = _sock_flow(sock, "UDP", qname, server, 53)   # bound only once sent
        data, _ = sock.recvfrom(4096)
        rcode = data[3] & 0x0F if len(data) >= 4 else -1
        answers = struct.unpack(">H", data[6:8])[0] if len(data) >= 8 else 0
        return (True, f"DNS {qname} @{server}: response (rcode={rcode}, answers={answers})",
                None, flow)
    except socket.timeout:
        return (False, f"DNS {qname} @{server}: no response (timeout)", None, flow)
    except OSError as e:
        return (False, "", f"dns: {e}", flow)
    finally:
        sock.close()


def _tcp_banner(host, port, timeout):
    """Connect and read any greeting banner. Returns (ok, detail, err, flow): ok True if
    the TCP connection established, ok False on refuse/timeout (possibly a policy drop),
    err set only for name-resolution / local failures (environment, not policy)."""
    flow = _flow("TCP", dst_port=port, host=host)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            flow = _sock_flow(sock, "TCP", host)
            sock.settimeout(min(timeout, 3.0))
            try:
                banner = sock.recv(128)
            except OSError:
                banner = b""
        txt = banner.decode("latin-1", "replace").strip()
        return (True, f"TCP {host}:{port} connected" + (f" — {txt[:80]!r}" if txt else ""),
                None, flow)
    except socket.gaierror as e:
        return (False, "", f"tcp: could not resolve {host}: {e}", flow)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return (False, f"TCP {host}:{port}: {e.__class__.__name__}", None, flow)


def _tcp_probe_flow(host, port, timeout):
    """(ok, flow) for a TCP connect to host:port — the probe plus the 5-tuple it used."""
    flow = _flow("TCP", dst_port=port, host=host)
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            return True, _sock_flow(sock, "TCP", host)
    except (OSError, ValueError):
        return False, flow


def _tcp_probe(host, port, timeout):
    """Return True iff a TCP connection to host:port completes within `timeout`."""
    return _tcp_probe_flow(host, port, timeout)[0]


def probe_control(settings, timeout=6.0, prefer_kind=None):
    """Is general egress working? Returns (ok, detail).

    Tries every configured control endpoint and succeeds if ANY answers, so one filtered
    control host can no longer mask real inline blocks. Endpoints matching `prefer_kind`
    are tried first: a DNS trigger should be disambiguated by a DNS control where one
    exists, because a network that permits DNS while denying TCP/443 would otherwise
    report a false `error`."""
    endpoints = settings.control_endpoints
    if not endpoints:
        return None, "no control endpoint configured"
    if prefer_kind:
        endpoints = ([e for e in endpoints if e[0] == prefer_kind]
                     + [e for e in endpoints if e[0] != prefer_kind])
    tried = []
    for kind, host, port in endpoints:
        if kind == "dns":
            ok, _detail, err, _flow = _dns_query("example.com", host, min(timeout, 5.0))
            ok = bool(ok) and not err
        else:
            ok = _tcp_probe(host, port, min(timeout, 6.0))
        tried.append(f"{kind}:{host}:{port}={'ok' if ok else 'fail'}")
        if ok:
            return True, "egress confirmed via " + tried[-1]
    return False, "all control endpoints failed (" + ", ".join(tried) + ")"


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


def _parse_http_code(stdout):
    """curl is invoked with -w '%{http_code}|...' as the LAST stdout line."""
    for line in reversed((stdout or "").splitlines()):
        m = re.match(r"^\s*(\d{3})\|", line)
        if m:
            return int(m.group(1))
    return None


# ===========================================================================
# Classifier  —  three states that never collapse; multi-request triggers aggregate
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


def _pred_matches(pred, s):
    """True iff EVERY key declared in `pred` matches this request's observation.

    An empty/absent predicate never matches, so a catalog entry that declares nothing
    keeps the default classification. An unknown key fails closed (load-time
    validation already rejects those, so this is belt-and-braces)."""
    if not pred:
        return False
    for key, want in pred.items():
        if key == "rc":
            if s.rc != want:
                return False
        elif key == "rc_nonzero":
            if bool(s.rc not in (0, None)) is not bool(want):
                return False
        elif key == "body_contains":
            # NB: a command that sends its body to {devnull} leaves only curl's own
            # --write-out line here, so body_contains only bites when the catalog
            # entry deliberately keeps the response body.
            if want not in (s.stdout or ""):
                return False
        elif key == "http_code":
            if s.http_code != want:
                return False
        elif key == "http_code_in":
            if s.http_code not in (want or []):
                return False
        else:
            return False
    return True


def _classify_sub(trigger, s, control_ok):
    if s.error_reason:
        return ERROR, s.error_reason
    if s.timed_out:
        return ERROR, f"timed out after {trigger.timeout:g}s"
    if trigger.runner == "curl":
        # Reachable-only refinement. A COMPLETED request (rc 0) can still have been
        # denied by a gateway that serves a block page at 200 or redirects to one —
        # which the exit-code mapping alone reads as `allowed`. Refining only rc 0
        # means an environment failure can never be promoted to `blocked`, and a real
        # inline drop (rc 28/7/56) is never demoted to `allowed`.
        if s.rc == 0:
            if _pred_matches(trigger.expected_on_block, s):
                return BLOCKED, f"curl rc=0, http={s.http_code} — matched expected_on_block"
            if _pred_matches(trigger.expected_on_allow, s):
                return ALLOWED, f"curl rc=0, http={s.http_code} — matched expected_on_allow"
        return classify_curl(s.rc, s.http_code), f"curl rc={s.rc}, http={s.http_code}"
    # dns / tcp native probe
    if s.ok:
        return ALLOWED, s.stdout or "reached"
    if control_ok is True:
        return BLOCKED, "egress control OK but the probe did not complete — dropped inline"
    if control_ok is False:
        return ERROR, "egress control probe failed — environment, not policy"
    return ERROR, "probe did not complete and egress control was unavailable"


def classify(trigger, result):
    """Return (state, reason). state ∈ {allowed, blocked, error}. For a multi-request
    trigger, aggregate honestly: `blocked` only when every REACHABLE request was dropped,
    `error` only when all failed on the environment; the split is always shown."""
    if result.error_reason:
        return ERROR, result.error_reason
    subs = result.subs or []
    if not subs:
        return ERROR, "no requests were run"
    states = [_classify_sub(trigger, s, result.control_ok)[0] for s in subs]
    if len(subs) == 1:
        return states[0], _classify_sub(trigger, subs[0], result.control_ok)[1]
    a, b, e = states.count(ALLOWED), states.count(BLOCKED), states.count(ERROR)
    summary = f"{a} allowed / {b} blocked / {e} error across {len(subs)} requests"
    reachable = a + b
    if reachable == 0:
        return ERROR, summary + " — all failed on the environment, not policy"
    if b == reachable:
        return BLOCKED, summary + " — every reachable request was dropped inline"
    if a == reachable:
        return ALLOWED, summary
    return (BLOCKED if b > a else ALLOWED), summary + " (mixed — see details)"


# ===========================================================================
# Catalog provenance  —  prove the traffic matches the reviewed catalog
# ===========================================================================
# The update channel authenticates secvitals.py, but NOT the catalog — and the catalog is
# what decides where traffic goes. Anyone able to write the config directory could point
# a trigger somewhere else while every other guardrail (argv-only, no shell, validated
# params) still held. Signing it closes that gap.
#
# Fail-VISIBLE, not fail-closed, by default: existing installs have no signature and must
# keep working, so an unsigned catalog is reported honestly rather than refused. Use
# --strict-catalog (or strict_catalog in settings) to refuse anything not verified.
CATALOG_VERIFIED, CATALOG_UNSIGNED, CATALOG_MODIFIED = "verified", "unsigned", "modified"


def catalog_signature_status(config_dir, pubkey=UPDATE_PUBKEY):
    """(status, detail) for config/catalog.yaml against config/catalog.yaml.sig.

    Uses the same RSA-2048/SHA-256 verifier as the update channel, so there is one
    signature implementation to trust rather than two."""
    catalog = os.path.join(config_dir or DEFAULT_CONFIG_DIR, "catalog.yaml")
    sig_path = catalog + ".sig"
    try:
        with open(catalog, "rb") as fh:
            payload = fh.read()
    except OSError as e:
        return CATALOG_MODIFIED, f"catalog could not be read: {e}"
    if not os.path.exists(sig_path):
        return CATALOG_UNSIGNED, ("no catalog.yaml.sig alongside the catalog — its "
                                  "contents are not authenticated")
    try:
        with open(sig_path, "rb") as fh:
            signature = fh.read()
    except OSError as e:
        return CATALOG_MODIFIED, f"catalog signature could not be read: {e}"
    if not pubkey or "BEGIN" not in pubkey:
        return CATALOG_MODIFIED, "no verification key is configured"
    if verify_rsa_sha256(pubkey, payload, signature):
        return CATALOG_VERIFIED, ("catalog signature verified — the fired traffic matches "
                                  "the reviewed catalog")
    return CATALOG_MODIFIED, ("catalog signature did NOT verify — this catalog is not the "
                              "one that was signed")


# ===========================================================================
# Environment readiness  —  a pre-flight gate, NOT a policy predictor
# ===========================================================================
# This answers exactly one question: "can this console run its triggers from here?"
# It deliberately does NOT try to predict whether any given trigger will be blocked.
# Confusing readiness with policy would put a guess on stage next to real results, so
# every message below stays inside the readiness framing.
_CURL_CHECK = {"present": None, "version": ""}
_CURL_LOCK = threading.Lock()


def curl_present(_runner=None):
    """Is a usable curl on PATH? Cached — the binary does not appear mid-demo."""
    with _CURL_LOCK:
        if _CURL_CHECK["present"] is not None:
            return _CURL_CHECK["present"], _CURL_CHECK["version"]
    run = _runner or (lambda: subprocess.run(["curl", "--version"], capture_output=True,
                                             timeout=10, check=False))
    present, version = False, ""
    try:
        proc = run()
        present = proc.returncode == 0
        version = _first_line(_dec(proc.stdout))
    except (OSError, subprocess.SubprocessError) as e:
        present, version = False, str(e)
    with _CURL_LOCK:
        _CURL_CHECK["present"], _CURL_CHECK["version"] = present, version
    return present, version


def reset_environment_cache():
    with _CURL_LOCK:
        _CURL_CHECK["present"], _CURL_CHECK["version"] = None, ""


def environment_report(settings, triggers=None):
    """Readiness facts, plus a plain-language verdict. Never a policy prediction."""
    present, version = curl_present()
    control_ok, control_detail = probe_control(settings, 6.0)
    checks = [
        {"name": "curl", "ok": present,
         "detail": (version if present else
                    "curl was not found on PATH — HTTP triggers cannot run "
                    "(Windows 10 1803+ ships curl.exe)")},
        {"name": "egress control", "ok": bool(control_ok), "detail": control_detail},
    ]
    if triggers is not None:
        needs_curl = sum(1 for t in triggers if t.runner == "curl")
        checks.append({"name": "catalog", "ok": True,
                       "detail": f"{len(triggers)} triggers loaded, {needs_curl} need curl"})
    ready = all(c["ok"] for c in checks)
    return {
        "ready": ready,
        "checks": checks,
        "verdict": ("Ready: the console can run its triggers from here."
                    if ready else
                    "Not ready: fix the failing check(s) below before the demo."),
        "note": ("This is a readiness check only. It says nothing about whether any "
                 "trigger will be allowed or blocked — that is what firing them is for."),
    }


def format_environment_report(report):
    out = ["PRE-FLIGHT — can this console run its triggers from here?", ""]
    for check in report["checks"]:
        out.append(f"  [{'ok  ' if check['ok'] else 'FAIL'}] {check['name']:<16} {check['detail']}")
    out += ["", report["verdict"], "", report["note"]]
    return "\n".join(out)


# ===========================================================================
# Application state
# ===========================================================================
class App:
    def __init__(self, settings, triggers, config_dir=None):
        self.settings = settings
        self.triggers = triggers
        self.by_id = {t.id: t for t in triggers}
        self.config_dir = config_dir
        self.tor_cache = TorNodeCache(settings.tor_list_url, settings.tor_list_ttl)
        self._run_lock = threading.Lock()   # serialize triggers — clean before/after on stage
        self._last_run_end = 0.0            # rate limiting between runs

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
        # A missing curl is an environment fact, and the same one for every HTTP trigger.
        # Reporting it as INVALID with a fix beats a wall of identical `error` cards that
        # a presenter has to decode mid-demo.
        if trigger.runner == "curl" and not curl_present()[0]:
            return trigger, {
                "state": INVALID,
                "reason": ("curl was not found on PATH, so this trigger cannot run. "
                           "Windows 10 1803+ ships curl.exe; install or repair it. "
                           "This is not a policy result."),
                "expected_fire": trigger.expected_fire,
            }
        if not self._run_lock.acquire(blocking=False):
            return trigger, {"state": ERROR, "reason": "another trigger is already running"}
        try:
            gap = self.settings.min_run_interval - (time.monotonic() - self._last_run_end)
            if gap > 0:
                time.sleep(min(gap, 5.0))       # rate limiting (spacing between runs)
            log.info("run start id=%s", trigger_id)
            if trigger.runner == "iprep":
                out = self._run_iprep(trigger)
                log.info("run done id=%s state=%s", trigger_id, out.get("state"))
                return trigger, out
            result = run_trigger(trigger, params, self.settings)
            state, reason = classify(trigger, result)
            log.info("run done id=%s state=%s reqs=%d dur=%.2fs",
                     trigger_id, state, len(result.subs), result.duration_s)
            first = result.subs[0] if result.subs else None
            flows = [s.flow for s in result.subs]
            return trigger, {
                "state": state,
                "reason": reason,
                "rc": (first.rc if first else None),
                "http_code": (first.http_code if first else None),
                "duration_s": round(result.duration_s, 3),
                "expected_fire": trigger.expected_fire,
                "console_hint": trigger.console_hint_text(),
                "verify_key": verification_key(trigger, state, flows),
                "requests": len(result.subs),
                "wire_requests": trigger.on_wire_count(self.settings),
                "stdout": _clip(_format_subs(result.subs), 6000),
                "flow": _clip(_format_flows(flows), 4000),
                "stderr": "",
            }
        finally:
            self._last_run_end = time.monotonic()
            self._run_lock.release()

    def _run_iprep(self, trigger):
        """IP-reputation probe: a control egress probe first (fail => whole test invalid),
        then connect to the first N Tor nodes on :443 and report a RATIO (never a single
        verdict). Called while the run lock is held."""
        s = self.settings
        if not s.control_enabled:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": "IP reputation needs a control probe — set run.control_host"}
        control_ok, control_detail = probe_control(s, 6.0)
        if not control_ok:
            return {"state": INVALID, "expected_fire": trigger.expected_fire,
                    "reason": (f"control probe failed ({control_detail}) — egress is "
                               "broken, so the whole test is invalid (not blocked)")}
        try:
            nodes = self.tor_cache.get()
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": f"could not fetch the Tor node list: {e}"}
        sample = nodes[:max(1, s.ip_rep_sample)]
        if not sample:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": "the Tor node list was empty"}
        blocked = reached = 0
        details, flows = [], []
        for ip in sample:
            ok, flow = _tcp_probe_flow(ip, 443, s.node_probe_timeout)
            flows.append(flow)
            if ok:
                reached += 1
                details.append(f"{ip}:443  reached  (not blocked by IP reputation)")
            else:
                blocked += 1
                details.append(f"{ip}:443  blocked  (timeout/reset)")
        return {
            "state": RATIO,
            "ratio": {"blocked": blocked, "reached": reached, "total": len(sample)},
            "reason": (f"{blocked} of {len(sample)} Tor nodes blocked by IP reputation "
                       "(control OK). A ratio, not a single verdict — a lone reach may be a "
                       "live relay; the inline IP-reputation stats are authoritative."),
            "expected_fire": trigger.expected_fire,
            "console_hint": trigger.console_hint_text(),
            "verify_key": verification_key(trigger, f"{blocked}/{len(sample)} blocked", flows),
            "requests": len(sample),
            "wire_requests": trigger.on_wire_count(s),
            "stdout": "\n".join(details),
            "flow": _clip(_format_flows(flows), 4000),
        }


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


def _format_subs(subs):
    """Render each of a trigger's requests + its outcome for the details pane."""
    lines = []
    for i, s in enumerate(subs or [], 1):
        head = f"[{i}] $ " + " ".join(_redact(s.argv))
        meta = []
        if s.rc is not None:
            meta.append(f"rc={s.rc}")
        if s.http_code is not None:
            meta.append(f"http={s.http_code}")
        if s.ok is not None:
            meta.append("reached" if s.ok else "no-response")
        if s.timed_out:
            meta.append("timed-out")
        if s.error_reason:
            meta.append(f"error: {s.error_reason}")
        if s.failover_from:
            meta.append(f"ORIGIN FAILOVER from {s.failover_from} — verify the alternate "
                        "serves the same content")
        if meta:
            head += "\n      " + "   ".join(meta)
        probe = _first_line(s.stdout) if s.ok is not None else ""
        if probe:
            head += "\n      " + probe
        err = _first_line(s.stderr)
        if err:
            head += "\n      [stderr] " + err
        lines.append(head)
    return "\n".join(lines)


FLOW_COLUMNS = [("#", "n"), ("PROTO", "proto"), ("SRC-IP", "src_ip"), ("SRC-PORT", "src_port"),
                ("DST-IP", "dst_ip"), ("DST-PORT", "dst_port"), ("DST-HOST", "host")]


def _format_flows(flows):
    """Render the 5-tuples one request per row, aligned, for correlating this run with the
    flow / event records in the inline stack's management console. An endpoint the run never learned prints
    as '—' rather than a plausible-looking guess."""
    rows = []
    for i, f in enumerate(flows or [], 1):
        if not f:
            continue
        r = {"n": str(i)}
        for key in ("proto", "src_ip", "src_port", "dst_ip", "dst_port", "host"):
            r[key] = str(f.get(key) or "") or "—"
        if r["host"] == r["dst_ip"]:
            r["host"] = "—"                      # the command dialled a literal address
        rows.append(r)
    if not rows or all(r["src_ip"] == "—" and r["dst_ip"] == "—" for r in rows):
        return ""
    widths = [max(len(title), *(len(r[key]) for r in rows)) for title, key in FLOW_COLUMNS]
    out = ["  ".join(t.ljust(w) for (t, _), w in zip(FLOW_COLUMNS, widths)).rstrip()]
    for r in rows:
        out.append("  ".join(r[k].ljust(w) for (_, k), w in zip(FLOW_COLUMNS, widths)).rstrip())
    return "\n".join(out)


# ===========================================================================
# Verification key  —  one pasteable line that ties a click to the console
# ===========================================================================
def verification_key(trigger, state, flows, when=None):
    """A single greppable line the presenter pastes straight into the inline stack's
    console filter: when · what · which flow · what we saw locally. Built only from
    what the run actually observed — an endpoint the run never learned prints '—'
    rather than a plausible-looking guess."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                       time.gmtime(time.time() if when is None else when))
    flow = next((f for f in (flows or []) if f), None) or {}

    def v(key):
        return str(flow.get(key) or "") or "—"

    endpoint = f"{v('src_ip')}:{v('src_port')} -> {v('dst_ip')}:{v('dst_port')}"
    host = str(flow.get("host") or "")
    if host and host != flow.get("dst_ip"):
        endpoint += f" ({host})"
    expect = _first_line(trigger.expected_fire) or trigger.label
    return f"{ts} | {trigger.id} | expect {expect} | {endpoint} | local:{state}"


# ===========================================================================
# Signal manifest  —  the KNOWN QUANTITY, computed without sending anything
# ===========================================================================
def _command_destination(runner, argv):
    """Where one command is aimed, for the manifest. Never sends anything."""
    if runner == "curl":
        host, port = _url_endpoint(argv)
        return f"{host}:{port}" if host else ""
    if runner == "dns":
        qname, server = None, "8.8.8.8"
        for a in argv[1:]:
            if a.startswith("@"):
                server = a[1:] or server
            elif qname is None:
                qname = a
        return f"{qname} @{server}:53" if qname else ""
    if runner == "tcp":
        return f"{argv[1]}:{argv[2]}" if len(argv) >= 3 else ""
    if runner == "iprep":
        return "live Tor relays :443"
    return ""


def _preview_commands(trigger):
    """The concrete argv list each command WOULD run — the real resolve/build path,
    stopped before any subprocess or socket. Triggers with unsupplied required params
    fall back to the raw template rather than failing the whole preview."""
    try:
        resolved = _resolve_params(trigger, {})
    except ParamError:
        return [list(c) for c in trigger.commands]
    out = []
    for template in trigger.commands:
        try:
            out.append(build_command(template, resolved))
        except ParamError:
            out.append(list(template))
    return out


def signal_manifest(triggers, settings):
    """Everything a full run would put on the wire, WITHOUT sending a byte.

    This is the answer to 'how many signals am I about to generate?' — and it counts
    the `iprep` fan-out honestly (see Trigger.on_wire_count), which a naive count of
    catalog commands under-reports."""
    rows, classes = [], {}
    enabled = gated = signals = signals_if_gate_on = 0
    for t in triggers:
        is_gated = t.gated_disabled(settings)
        count = t.on_wire_count(settings)
        signals_if_gate_on += count
        cmds = _preview_commands(t)
        dests = [d for d in (_command_destination(t.runner, c) for c in cmds) if d]
        rows.append({
            "id": t.id, "label": t.label, "class": t.cls, "runner": t.runner,
            "severity": t.severity, "threat_class": t.threat_class,
            "wire_request_count": count, "gated_disabled": is_gated,
            "flags": list(t.flags), "destinations": dests,
            "expected_fire": t.expected_fire, "console_hint": t.console_hint_text(),
            "commands": [_redact(c) for c in cmds],
        })
        if is_gated:
            gated += 1
            continue
        enabled += 1
        signals += count
        slot = classes.setdefault(t.cls, {"class": t.cls,
                                          "label": CLASS_LABEL.get(t.cls, t.cls),
                                          "triggers": 0, "signals": 0})
        slot["triggers"] += 1
        slot["signals"] += count
    return {
        "profile": "lab" if settings.enable_live_suspect_hosts else "default",
        "enable_live_suspect_hosts": settings.enable_live_suspect_hosts,
        "totals": {"triggers_enabled": enabled, "triggers_gated": gated,
                   "triggers_total": len(triggers), "signals": signals,
                   "signals_if_gate_enabled": signals_if_gate_on},
        "classes": [classes[k] for k in classes],
        "triggers": rows,
    }


def format_signal_manifest(manifest, verbose=False):
    """Render a signal manifest as presenter-readable text."""
    t = manifest["totals"]
    profile = ("LAB — live-suspect gate ON" if manifest["enable_live_suspect_hosts"]
               else "DEFAULT — live-suspect gate OFF")
    out = ["SIGNAL MANIFEST — what a full run would put on the wire (nothing is sent)",
           f"Profile: {profile}", ""]
    for c in manifest["classes"]:
        out.append(f"{c['label']}   —   {c['triggers']} triggers, {c['signals']} signals")
        for r in manifest["triggers"]:
            if r["class"] != c["class"] or r["gated_disabled"]:
                continue
            dest = ", ".join(r["destinations"][:3])
            if len(r["destinations"]) > 3:
                dest += f", +{len(r['destinations']) - 3} more"
            out.append(f"  {r['id']:<22} {r['wire_request_count']:>2} signal(s)  "
                       f"{r['severity']:<4}  {dest}")
            if verbose and r["expected_fire"]:
                out.append(f"  {'':<22}    expect: {r['expected_fire']}")
            if verbose:
                for argv in r["commands"]:
                    out.append(f"  {'':<22}    $ " + " ".join(argv))
        out.append("")
    gated = [r for r in manifest["triggers"] if r["gated_disabled"]]
    if gated:
        out.append(f"DISABLED — reaches live suspect infrastructure ({len(gated)}): "
                   + ", ".join(r["id"] for r in gated))
        out.append("  Enable with enable_live_suspect_hosts in settings.yaml — a lab you control only.")
        out.append("")
    out.append(f"TOTAL: {t['signals']} signals across {t['triggers_enabled']} enabled triggers")
    if t["triggers_gated"]:
        out.append(f"       {t['signals_if_gate_enabled']} signals if the live-suspect gate is enabled "
                   f"({t['triggers_total']} triggers)")
    return "\n".join(out)


# ===========================================================================
# Tkinter console  —  self-contained window (no browser, no local server)
# ===========================================================================
# Visual identity mirrored from netvitals: same palette, EKG heartbeat, dark
# cards. Trigger cards are rendered from the fixed local catalog; a click fires the
# trigger in-process (App.run on a background thread) and renders the three honest states
# (allowed / blocked / error, plus the iprep ratio) — blocked is the product win, error is
# the environment, and the two never collapse.
GUI_BG = "#1a1d21"
GUI_SURFACE = "#23272e"
GUI_PANEL = "#2c313a"
GUI_PANEL_HI = "#333a44"
GUI_GRID = "#363b44"
GUI_INK = "#f2f4f5"
GUI_DIM = "#9aa3ad"
GUI_FAINT = "#6f787c"
GUI_ACCENT = "#01A982"
GUI_ACCENT_DK = "#017a5e"
GUI_INFO = "#00B0E6"
GUI_WARN = "#FF8300"
GUI_CRIT = "#E0574a"
GUI_GOLD = "#FEC901"
GUI_FONT = "Segoe UI"
GUI_MONO = "Consolas"

SEV_COLOR = {"info": GUI_INFO, "warn": GUI_WARN, "crit": GUI_CRIT}

# The row status line reports WHEN a trigger last ran and HOW MANY times — not a local
# verdict. The inline security stack's own console is authoritative for
# allowed-vs-blocked; the console's own read of the run still shows up in the expanded
# row and in the details. Colour is used only to flag a run that did NOT fire (error /
# gated off), because that is an environment problem the presenter needs to see at a glance.
STATE_FG = {ERROR: GUI_CRIT, INVALID: GUI_GOLD}
CLASS_LABEL = {
    "ns-ids":   "NORTH-SOUTH · IDS / IPS",
    "ns-webcc": "NORTH-SOUTH · WEB CATEGORIES & REPUTATION  (SWG)",
    "ns-iprep": "NORTH-SOUTH · IP REPUTATION",
    "ns-dlp":   "NORTH-SOUTH · DATA LOSS PREVENTION  (content inspection)",
    "ew":       "EAST-WEST",
}


def _draw_logo(cv):
    """Padlock silhouette (shadow) crossed by a green EKG pulse — the same mark as
    the web build's SVG, drawn on a 42x40 canvas."""
    f = GUI_FAINT
    cv.create_arc(14, 10, 26, 22, start=0, extent=180, style="arc", outline=f, width=2)  # shackle
    cv.create_line(14, 16, 14, 21, fill=f, width=2)
    cv.create_line(26, 16, 26, 21, fill=f, width=2)
    cv.create_rectangle(10, 20, 30, 35, fill=GUI_PANEL, outline=f, width=1)              # body
    cv.create_oval(18.5, 25, 21.5, 28, fill=f, outline=f)                                # keyhole
    cv.create_line(20, 27, 20, 31, fill=f, width=2)
    cv.create_line(1, 27, 14, 27, 17.5, 16, 22, 34, 25.5, 27, 41, 27,                    # EKG pulse
                   fill=GUI_ACCENT, width=2, capstyle="round", joinstyle="round")


def _set_window_icon(root):
    """Give the window — and, on Windows, the taskbar — the lock+EKG icon. The
    AppUserModelID makes Windows group the app under its OWN taskbar button/icon instead
    of a generic pythonw one, so Security Vitals and Network Vitals each show their logo."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecurityVitals.Console")
        except Exception:
            pass
        ico = os.path.join(DEFAULT_ASSETS_DIR, "secvitals.ico")
        try:
            if os.path.isfile(ico):
                root.iconbitmap(default=ico)
        except Exception:                      # non-fatal: a missing/bad icon just falls back
            pass


def _gui_button(parent, text, cmd, primary=False):
    return tk.Button(parent, text=text, command=cmd,
                     bg=(GUI_ACCENT if primary else GUI_PANEL),
                     fg=("#04120e" if primary else GUI_INK),
                     activebackground=GUI_ACCENT_DK, activeforeground="white",
                     relief="flat", bd=0, highlightthickness=0, padx=14, pady=6,
                     font=(GUI_FONT, 9, "bold"), cursor="hand2")


def run_gui(settings, triggers, app, config_dir=None):
    """Build and run the console window. Raises RuntimeError when no display is
    available (headless without Xvfb / no X server)."""
    global tk
    import tkinter as tk
    import queue

    try:
        root = tk.Tk()
    except tk.TclError as e:
        raise RuntimeError(f"no display available: {e}") from e
    root.title(f"{APP_NAME} {__version__}")
    root.geometry("980x700")
    root.minsize(600, 440)
    root.configure(bg=GUI_BG)
    _set_window_icon(root)

    by_id = {t.id: t for t in triggers}
    cards = {}                                  # trigger id -> widget/var bundle
    run_state = {"running": False, "stop": False}
    ui_queue = queue.Queue()                    # background run threads -> main thread ONLY

    def pump():
        try:
            while True:
                fn = ui_queue.get_nowait()
                try:
                    fn()
                except tk.TclError:
                    return                       # window went away mid-update
        except queue.Empty:
            pass
        try:
            root.after(80, pump)
        except tk.TclError:
            pass

    def _set_status(tid, text, fg=GUI_FAINT):
        c = cards.get(tid)
        if c:
            c["status"].configure(text=text, fg=fg)

    def copy_text(text, tid=None):
        """Put text on the system clipboard (Tk-local; no network surface)."""
        if not text:
            return
        try:
            root.clipboard_clear()
            root.clipboard_append(text)
        except tk.TclError:
            return
        if tid:
            _set_status(tid, "verification key copied", GUI_ACCENT)

    def set_result(tid, out):
        c = cards.get(tid)
        if not c:
            return
        state = out.get("state", ERROR)
        c["runs"] += 1
        runs = f"{c['runs']} run" + ("" if c["runs"] == 1 else "s")
        _set_status(tid, f"last run {time.strftime('%H:%M:%S')}  ·  {runs}",
                    STATE_FG.get(state, GUI_DIM))
        c["reason"].configure(text=out.get("reason", ""))
        c["reason"].pack(anchor="w", fill="x", pady=(2, 0))
        kv = []
        if out.get("rc") is not None:
            kv.append(f"rc={out['rc']}")
        if out.get("http_code") is not None:
            kv.append(f"http={out['http_code']}")
        if out.get("duration_s") is not None:
            kv.append(f"{out['duration_s']}s")
        if out.get("wire_requests", 1) > 1:
            kv.append(f"{out['wire_requests']} signals")
        c["kv"].configure(text="    ".join(kv))
        c["set_pane"]("cmd", (out.get("stdout") or "").strip())
        c["set_pane"]("flow", (out.get("flow") or "").strip())
        # The pasteable one-liner that ties this click to a row on the inline console.
        c["verify_key"] = out.get("verify_key", "")
        if c["verify_key"]:
            c["set_pane"]("verify", c["verify_key"] + "\n\n" + (out.get("console_hint") or ""))
            c["copy"].pack(side="left", padx=6)
        c["fire"].configure(state="normal")

    def fire(tid):
        if run_state["running"]:
            return
        t = by_id.get(tid)
        if t is None:
            return
        c = cards.get(tid)
        if c:
            c["fire"].configure(state="disabled")
        _set_status(tid, "running…", GUI_DIM)

        def work():
            try:
                _t, out = app.run(tid, {})
            except Exception as e:                 # never let a run thread die silently
                out = {"state": ERROR, "reason": f"{e.__class__.__name__}: {e}"}
            ui_queue.put(lambda: set_result(tid, out))
        threading.Thread(target=work, daemon=True).start()

    def run_all_worker(ids):
        n = len(ids)
        for i, tid in enumerate(ids):
            if run_state["stop"]:
                break
            try:
                _t, out = app.run(tid, {})           # App.run rate-limits between runs itself
            except Exception as e:
                out = {"state": ERROR, "reason": f"{e.__class__.__name__}: {e}"}
            ui_queue.put(lambda tid=tid, out=out: set_result(tid, out))
            ui_queue.put(lambda i=i: status_var.set(f"Run all — {i + 1}/{n}"))
        ui_queue.put(run_all_done)

    def start_run_all():
        if run_state["running"]:
            return
        ids = [t.id for t in triggers if not by_id[t.id].gated_disabled(settings)]
        if not ids:
            return
        run_state["running"], run_state["stop"] = True, False
        run_all_btn.pack_forget()
        stop_btn.pack(side="left", pady=2)
        for tid in ids:
            c = cards.get(tid)
            if c:
                c["fire"].configure(state="disabled")
            _set_status(tid, "running…", GUI_DIM)
        threading.Thread(target=run_all_worker, args=(ids,), daemon=True).start()

    def run_all_done():
        run_state["running"] = False
        stop_btn.pack_forget()
        run_all_btn.pack(side="left", pady=2)
        status_var.set("")
        for tid in cards:
            if not by_id[tid].gated_disabled(settings):
                cards[tid]["fire"].configure(state="normal")

    def stop_run_all():
        run_state["stop"] = True
        status_var.set("Stopping after the current trigger…")

    # ---- header -----------------------------------------------------------
    header = tk.Frame(root, bg=GUI_BG, padx=16, pady=12)
    header.pack(fill="x", side="top")
    logo = tk.Canvas(header, width=42, height=40, bg=GUI_BG, highlightthickness=0)
    logo.pack(side="left", padx=(0, 12))
    _draw_logo(logo)
    titlebox = tk.Frame(header, bg=GUI_BG)
    titlebox.pack(side="left", anchor="w")
    tk.Label(titlebox, text=APP_NAME, fg=GUI_INK, bg=GUI_BG,
             font=(GUI_FONT, 20, "bold")).pack(anchor="w")
    meta = tk.Frame(header, bg=GUI_BG)
    meta.pack(side="right", anchor="e")
    tk.Label(meta, text=f"v{__version__}", fg=GUI_DIM, bg=GUI_BG,
             font=(GUI_MONO, 9)).pack(anchor="e")
    # The known quantity, stated up front: how many signals a full run puts on the wire.
    enabled_triggers = [t for t in triggers if not t.gated_disabled(settings)]
    planned_signals = sum(t.on_wire_count(settings) for t in enabled_triggers)
    tk.Label(meta, text=f"{planned_signals} signals · {len(enabled_triggers)} triggers",
             fg=GUI_ACCENT, bg=GUI_BG, font=(GUI_MONO, 9, "bold")).pack(anchor="e")

    # ---- toolbar ----------------------------------------------------------
    bar = tk.Frame(root, bg=GUI_BG, padx=16)
    bar.pack(fill="x")
    run_all_btn = _gui_button(bar, "▶  Run all enabled", start_run_all, primary=True)
    run_all_btn.pack(side="left", pady=2)
    stop_btn = _gui_button(bar, "■  Stop", stop_run_all)          # packed only while running
    preview_btn = _gui_button(bar, "☰  Signal manifest",
                              lambda: open_manifest_dialog(root, triggers, settings))
    preview_btn.pack(side="left", padx=6, pady=2)
    upd_btn = _gui_button(bar, "⟳  Check for updates", lambda: open_update_dialog(root))
    upd_btn.pack(side="right", pady=2)
    status_var = tk.StringVar(value="")
    tk.Label(bar, textvariable=status_var, fg=GUI_DIM, bg=GUI_BG,
             font=(GUI_MONO, 9)).pack(side="left", padx=14)

    # ---- live-infrastructure gate notice ---------------------------------
    gated = [t for t in triggers if t.gated_disabled(settings)]
    if gated:
        tk.Label(root, bg=GUI_SURFACE, fg=GUI_DIM, justify="left", anchor="w",
                 font=(GUI_FONT, 9), padx=12, pady=8, wraplength=920,
                 highlightbackground=GUI_WARN, highlightthickness=1,
                 text=(f"{len(gated)} trigger(s) reach LIVE suspect infrastructure / live Tor nodes and "
                       "are disabled (enable_live_suspect_hosts is false in settings.yaml). Enable only "
                       "in a lab you control.")).pack(fill="x", padx=16, pady=(6, 0))

    # ---- scrollable card area --------------------------------------------
    body = tk.Frame(root, bg=GUI_BG)
    body.pack(fill="both", expand=True, padx=8, pady=(8, 8))
    scroll = tk.Canvas(body, bg=GUI_BG, highlightthickness=0)
    vbar = tk.Scrollbar(body, orient="vertical", command=scroll.yview)
    inner = tk.Frame(scroll, bg=GUI_BG)
    inner_id = scroll.create_window((0, 0), window=inner, anchor="nw")
    scroll.configure(yscrollcommand=vbar.set)
    scroll.pack(side="left", fill="both", expand=True)
    vbar.pack(side="right", fill="y")
    inner.bind("<Configure>", lambda e: scroll.configure(scrollregion=scroll.bbox("all")))
    scroll.bind("<Configure>", lambda e: scroll.itemconfigure(inner_id, width=e.width))
    scroll.bind_all("<MouseWheel>", lambda e: scroll.yview_scroll(int(-1 * (e.delta / 120)) if e.delta else 0, "units"))
    scroll.bind_all("<Button-4>", lambda e: scroll.yview_scroll(-1, "units"))
    scroll.bind_all("<Button-5>", lambda e: scroll.yview_scroll(1, "units"))

    def _make_pane(parent, title):
        """L3 detail pane: a toggle line + a text box that only appears once there is
        content and the presenter opens it. Returns (set_content, reset)."""
        state = {"open": False, "text": ""}
        btn = tk.Label(parent, fg=GUI_FAINT, bg=GUI_SURFACE, font=(GUI_MONO, 9), cursor="hand2")
        box = tk.Text(parent, height=8, bg=GUI_BG, fg=GUI_INK, insertbackground=GUI_INK,
                      font=(GUI_MONO, 9), relief="flat", highlightthickness=1,
                      highlightbackground=GUI_GRID, wrap="none", padx=8, pady=6)

        def _render():
            btn.configure(text=("▾ " if state["open"] else "▸ ") + title)
            if state["open"]:
                box.configure(state="normal")
                box.delete("1.0", "end")
                box.insert("1.0", state["text"] or "(no output)")
                box.configure(state="disabled")
                box.pack(fill="x", pady=(4, 0))
            else:
                box.pack_forget()

        def toggle(_e=None):
            state["open"] = not state["open"]
            _render()
        btn.bind("<Button-1>", toggle)

        def set_content(text):
            state["text"] = text or ""
            if state["text"]:
                btn.pack(anchor="w", pady=(8, 0))
            else:
                btn.pack_forget()
                state["open"] = False
            _render()

        def reset():
            state["open"] = False
            box.pack_forget()
            btn.pack_forget()
            state["text"] = ""
        return set_content, reset

    def build_card(t):
        disabled = t.gated_disabled(settings)
        expand = {"open": False}
        wrap = tk.Frame(inner, bg=GUI_GRID)                       # 1px border via padding
        wrap.pack(fill="x", padx=8, pady=3)
        row = tk.Frame(wrap, bg=GUI_SURFACE)
        row.pack(fill="x", padx=1, pady=1)
        accent = tk.Frame(row, bg=SEV_COLOR.get(t.severity, GUI_FAINT), width=3)
        accent.pack(side="left", fill="y")
        card = tk.Frame(row, bg=GUI_SURFACE)
        card.pack(side="left", fill="both", expand=True)

        # ---- L1: always-visible summary header (click to expand) ----------
        head = tk.Frame(card, bg=GUI_SURFACE, padx=12, pady=8, cursor="hand2")
        head.pack(fill="x")
        caret = tk.Label(head, text="▸", fg=GUI_FAINT, bg=GUI_SURFACE, font=(GUI_MONO, 10))
        caret.pack(side="left", padx=(0, 8))
        tk.Label(head, text=t.label, fg=(GUI_FAINT if disabled else GUI_INK), bg=GUI_SURFACE,
                 font=(GUI_FONT, 11, "bold"), anchor="w", justify="left").pack(side="left")
        if "hits_live_suspect_hosts" in t.flags:
            tk.Label(head, text="LIVE", fg=GUI_WARN, bg=GUI_SURFACE, font=(GUI_MONO, 8),
                     padx=6, pady=1, highlightbackground=GUI_WARN, highlightthickness=1).pack(side="left", padx=8)
        status = tk.Label(head, text=("disabled (live)" if disabled else "not run"),
                          fg=(GUI_GOLD if disabled else GUI_FAINT), bg=GUI_SURFACE, font=(GUI_MONO, 9))
        status.pack(side="right")

        # ---- L2: context + action, hidden until the row is expanded -------
        # NB: a widget's own -pady is a single distance; the (top, bottom) tuple form is
        # only valid on .pack() (see toggle_expand), never in the constructor.
        body_l2 = tk.Frame(card, bg=GUI_SURFACE, padx=12)

        chips = tk.Frame(body_l2, bg=GUI_SURFACE)
        chips.pack(fill="x", pady=(2, 0))

        def chip(text, fg, bd):
            tk.Label(chips, text=text, fg=fg, bg=GUI_SURFACE, font=(GUI_MONO, 8),
                     padx=6, pady=1, highlightbackground=bd, highlightthickness=1).pack(side="left", padx=(0, 5))

        chip(t.cls, GUI_ACCENT, GUI_ACCENT_DK)
        if t.threat_class:
            chip(t.threat_class, GUI_DIM, GUI_GRID)
        chip(t.severity, SEV_COLOR.get(t.severity, GUI_DIM), SEV_COLOR.get(t.severity, GUI_GRID))
        # How many signals THIS trigger puts on the wire (iprep fans out; see on_wire_count).
        wire_n = t.on_wire_count(settings)
        chip(f"{wire_n} signal" + ("" if wire_n == 1 else "s"), GUI_DIM, GUI_GRID)

        if t.expected_fire:
            tk.Label(body_l2, text=t.expected_fire, fg=GUI_DIM, bg=GUI_SURFACE, font=(GUI_MONO, 9),
                     anchor="w", justify="left", wraplength=820).pack(fill="x", pady=(8, 0))
        if t.talking_point:
            tk.Label(body_l2, text=t.talking_point, fg=GUI_FAINT, bg=GUI_SURFACE, font=(GUI_FONT, 9),
                     anchor="w", justify="left", wraplength=820).pack(fill="x", pady=(4, 0))
        hint = t.console_hint_text()
        if hint:
            tk.Label(body_l2, text="↳ " + hint, fg=GUI_INFO, bg=GUI_SURFACE, font=(GUI_FONT, 9),
                     anchor="w", justify="left", wraplength=820).pack(fill="x", pady=(4, 0))

        actions = tk.Frame(body_l2, bg=GUI_SURFACE)
        actions.pack(fill="x", pady=(10, 0))
        fire_btn = _gui_button(actions, "Fire", lambda tid=t.id: fire(tid), primary=True)
        if disabled:
            fire_btn.configure(state="disabled", text="Disabled (live)")
        fire_btn.pack(side="left")
        copy_btn = _gui_button(actions, "Copy verification key",
                               lambda tid=t.id: copy_text(cards[tid].get("verify_key"), tid))
        kv = tk.Label(actions, text="", fg=GUI_DIM, bg=GUI_SURFACE, font=(GUI_MONO, 9))
        kv.pack(side="left", padx=12)

        reason = tk.Label(body_l2, text="", fg=GUI_INK, bg=GUI_SURFACE, font=(GUI_FONT, 9),
                          anchor="w", justify="left", wraplength=860)

        # ---- L3: detail panes, each disclosed on demand -------------------
        set_cmd, reset_cmd = _make_pane(body_l2, "command/payload details")
        set_flow, reset_flow = _make_pane(body_l2, "5-tuple details")
        set_verify, reset_verify = _make_pane(body_l2, "verification key (paste into the console)")
        panes = {"cmd": set_cmd, "flow": set_flow, "verify": set_verify}

        def set_pane(which, text):
            fn = panes.get(which)
            if fn:
                fn(text)

        if disabled:
            reason.configure(text=("Reaches live suspect infrastructure — enable "
                                   "enable_live_suspect_hosts in a controlled lab to run it."),
                             fg=GUI_GOLD)
            reason.pack(anchor="w", fill="x", pady=(6, 0))

        def toggle_expand(_e=None):
            expand["open"] = not expand["open"]
            caret.configure(text="▾" if expand["open"] else "▸")
            if expand["open"]:
                body_l2.pack(fill="x", pady=(0, 10))
            else:
                body_l2.pack_forget()
        for w in (head, caret):
            w.bind("<Button-1>", toggle_expand)
        # Clicking the label/status also toggles (they cover most of the row).
        for child in head.winfo_children():
            child.bind("<Button-1>", toggle_expand)

        cards[t.id] = {"status": status, "reason": reason, "kv": kv, "fire": fire_btn,
                       "copy": copy_btn, "set_pane": set_pane, "runs": 0, "verify_key": ""}

    order, seen = [], set()
    for t in triggers:
        if t.cls not in seen:
            seen.add(t.cls)
            order.append(t.cls)
    for cls in order:
        tk.Label(inner, text=CLASS_LABEL.get(cls, cls), fg=GUI_ACCENT, bg=GUI_BG,
                 font=(GUI_MONO, 9, "bold")).pack(anchor="w", padx=10, pady=(14, 2))
        for t in [x for x in triggers if x.cls == cls]:
            build_card(t)

    def on_close():
        run_state["stop"] = True
        try:
            root.destroy()
        except tk.TclError:
            pass
    root.protocol("WM_DELETE_WINDOW", on_close)

    pump()
    if os.environ.get("SECV_RENDER_ONCE"):        # headless smoke/CI test: lay out, then exit
        shot = os.environ.get("SECV_SHOT")

        def _finish():
            if shot:
                try:
                    subprocess.run(["scrot", "-o", shot], timeout=10)
                except Exception:                 # screenshot is best-effort only
                    pass
            root.destroy()
        # Optionally exercise the whole fire -> run_trigger -> set_result path in the real
        # window (catches result-rendering bugs a static layout pass can't).
        if os.environ.get("SECV_SELFTEST_FIRE"):
            for t in triggers:
                if not t.gated_disabled(settings):
                    root.after(200, lambda tid=t.id: fire(tid))
                    break
        root.update_idletasks()
        root.update()
        root.after(int(os.environ.get("SECV_RENDER_MS", "300")), _finish)
    root.mainloop()


def open_manifest_dialog(root, triggers, settings):
    """Show the signal manifest — every command a full run WOULD send and the exact
    signal count — without sending anything. This is the number to put on screen
    before you fire, so the room knows the quantity up front."""
    existing = getattr(root, "_secv_manifest_dialog", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    manifest = signal_manifest(triggers, settings)
    body = format_signal_manifest(manifest, verbose=True)
    totals = manifest["totals"]

    dlg = tk.Toplevel(root)
    root._secv_manifest_dialog = dlg
    dlg.title(f"{APP_NAME} — signal manifest")
    dlg.configure(bg=GUI_BG, padx=16, pady=12)
    dlg.transient(root)

    tk.Label(dlg, text=f"{totals['signals']} signals across "
                       f"{totals['triggers_enabled']} enabled triggers",
             fg=GUI_ACCENT, bg=GUI_BG, font=(GUI_FONT, 14, "bold")).pack(anchor="w")
    tk.Label(dlg, text="Nothing has been sent — this is the plan.",
             fg=GUI_DIM, bg=GUI_BG, font=(GUI_FONT, 9)).pack(anchor="w", pady=(2, 8))

    box = tk.Text(dlg, width=104, height=26, bg=GUI_BG, fg=GUI_INK, font=(GUI_MONO, 9),
                  relief="flat", highlightthickness=1, highlightbackground=GUI_GRID,
                  wrap="none", padx=8, pady=6)
    box.insert("1.0", body)
    box.configure(state="disabled")
    box.pack(fill="both", expand=True)

    btns = tk.Frame(dlg, bg=GUI_BG)
    btns.pack(anchor="e", fill="x", pady=(10, 0))

    def copy_all():
        try:
            root.clipboard_clear()
            root.clipboard_append(body)
        except tk.TclError:
            pass

    _gui_button(btns, "Close", dlg.destroy).pack(side="right")
    _gui_button(btns, "Copy", copy_all).pack(side="right", padx=6)


def open_update_dialog(root):
    """Check for / install a signed update from the console. The network is touched only
    after the user opens this dialog — the app never checks on its own. Verification (RSA
    signature over the manifest + SHA-256 of the artifact) fails closed on any problem."""
    existing = getattr(root, "_secv_update_dialog", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    dlg = tk.Toplevel(root)
    root._secv_update_dialog = dlg
    dlg.title(f"{APP_NAME} update")
    dlg.configure(bg=GUI_BG, padx=18, pady=14)
    dlg.resizable(False, False)
    dlg.transient(root)

    tk.Label(dlg, text=f"Installed version: {__version__}", fg=GUI_INK, bg=GUI_BG,
             font=(GUI_FONT, 11, "bold")).pack(anchor="w")
    status_var = tk.StringVar(value="Checking …")
    tk.Label(dlg, textvariable=status_var, fg=GUI_DIM, bg=GUI_BG, font=(GUI_FONT, 10),
             wraplength=440, justify="left").pack(anchor="w", pady=(6, 12))

    btns = tk.Frame(dlg, bg=GUI_BG)
    btns.pack(anchor="e", fill="x")
    state = {"manifest": None, "vstr": None}
    outcome = {}

    def check_worker():
        try:
            m = check_update()
            outcome["check"] = ("uptodate", __version__) if m is None else ("available", m)
        except Exception as e:
            outcome["check"] = ("error", str(e) or e.__class__.__name__)

    def install_worker():
        try:
            download_and_install(state["manifest"])
            outcome["install"] = ("done", None)
        except Exception as e:
            outcome["install"] = ("error", str(e) or e.__class__.__name__)

    def do_check():
        check_btn.configure(state="disabled")
        install_btn.pack_forget()
        status_var.set("Checking the pinned, signed release source …")
        threading.Thread(target=check_worker, daemon=True).start()

    def do_install():
        install_btn.configure(state="disabled")
        check_btn.configure(state="disabled")
        status_var.set("Downloading and verifying …")
        threading.Thread(target=install_worker, daemon=True).start()

    check_btn = _gui_button(btns, "Check again", do_check)
    install_btn = _gui_button(btns, "Install", do_install, primary=True)
    close_btn = _gui_button(btns, "Close", dlg.destroy)
    close_btn.pack(side="right")
    check_btn.pack(side="right", padx=(0, 6))

    def poll():
        if "check" in outcome:
            kind, val = outcome.pop("check")
            check_btn.configure(state="normal")
            if kind == "uptodate":
                status_var.set(f"You're on the latest version ({val}).")
            elif kind == "available":
                state["manifest"], state["vstr"] = val, val["version"]
                status_var.set(f"Version {state['vstr']} is available — signature verified. "
                               "Install swaps this file (previous kept as .bak).")
                install_btn.configure(state="normal")
                install_btn.pack(side="right", padx=(0, 6))
            else:
                status_var.set(f"Update check failed: {val}")
        if "install" in outcome:
            kind, val = outcome.pop("install")
            if kind == "done":
                status_var.set(f"Updated to {state['vstr']}. Restart {APP_NAME} to run the new version.")
                install_btn.pack_forget()
                return
            status_var.set(f"Install failed: {val}")
            check_btn.configure(state="normal")
            install_btn.configure(state="normal")
        try:
            dlg.after(150, poll)
        except tk.TclError:
            pass

    do_check()
    poll()


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


def _is_cert_error(exc):
    """True when exc is (or wraps) an SSL certificate-verification failure — the
    'unable to get local issuer certificate' class behind TLS-inspecting proxies."""
    import ssl
    candidates = (exc, getattr(exc, "reason", None), exc.__cause__)
    return any(isinstance(c, ssl.SSLCertVerificationError) for c in candidates if c is not None)


def _download_via_windows_tls(url, timeout, max_bytes, _curl=None, _ps="powershell"):
    """Fetch `url` with tools that validate TLS through Windows SChannel: curl.exe
    (Windows 10 1803+), then PowerShell. Python's OpenSSL fails with 'unable to get
    local issuer certificate' behind a corporate TLS-inspecting proxy whose root lives
    only in the Windows store — routing the download through curl/PowerShell applies the
    SAME trust decisions as Edge, so verification stays ON. Returns raw bytes."""
    import tempfile
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    errors = []
    if _curl is None:
        _curl = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "curl.exe")
        if not os.path.exists(_curl):
            _curl = "curl.exe"
    try:
        out = subprocess.run(
            [_curl, "-sSfL", "--proto", "=https", "--proto-redir", "=https",
             "--max-time", str(int(timeout) * 2), url],
            capture_output=True, creationflags=creation, timeout=timeout * 4)
        if out.returncode == 0 and out.stdout:
            return out.stdout[:max_bytes + 1]
        errors.append("curl: " + (out.stderr or b"").decode("utf-8", "replace").strip())
    except (OSError, subprocess.TimeoutExpired) as e:
        errors.append(f"curl: {e}")

    tmp = tempfile.NamedTemporaryFile(prefix="secv-update-", delete=False)
    tmp.close()
    env = dict(os.environ, SECV_UPDATE_URL=url, SECV_UPDATE_OUT=tmp.name)
    try:
        out = subprocess.run(
            [_ps, "-NoProfile", "-NonInteractive", "-Command",
             "$ProgressPreference = 'SilentlyContinue'; "
             "[Net.ServicePointManager]::SecurityProtocol = "
             "[Net.ServicePointManager]::SecurityProtocol -bor 3072; "
             "Invoke-WebRequest -UseBasicParsing -Uri $env:SECV_UPDATE_URL "
             "-OutFile $env:SECV_UPDATE_OUT"],
            capture_output=True, creationflags=creation, env=env, timeout=timeout * 4)
        if out.returncode == 0:
            with open(tmp.name, "rb") as fh:
                data = fh.read(max_bytes + 1)
            if data:
                return data
            errors.append("powershell: empty download")
        else:
            errors.append("powershell: " + (out.stderr or b"").decode("utf-8", "replace").strip())
    except (OSError, subprocess.TimeoutExpired) as e:
        errors.append(f"powershell: {e}")
    finally:
        _quiet_remove(tmp.name)
    raise UpdateError("; ".join(errors) or "no downloader available")


def _update_http_get(url, timeout, max_bytes):
    req = urllib.request.Request(url, headers={"User-Agent": "secvitals/%s" % __version__})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final = getattr(resp, "url", None) or url
            if url.lower().startswith("https:") and not final.lower().startswith("https:"):
                raise UpdateError(f"refusing redirect to insecure URL {final}")
            data = resp.read(max_bytes + 1)
    except (urllib.error.URLError, OSError) as e:
        # Behind a TLS-inspecting proxy Python's own trust chain fails; on Windows retry
        # through the system certificate store (curl/PowerShell). Verification stays on.
        if _is_cert_error(e) and sys.platform == "win32" and url.lower().startswith("https:"):
            data = _download_via_windows_tls(url, timeout, max_bytes)
        else:
            msg = f"download failed: {e}"
            if _is_cert_error(e):
                msg += (" — certificate verification failed (a TLS-inspecting proxy whose "
                        "root Python doesn't trust; on Windows the updater retries through "
                        "the system certificate store automatically)")
            raise UpdateError(msg) from e
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

    target = target or _THIS_FILE
    if not target:
        raise UpdateError("can't locate the installed file to update — run the update from the install folder")
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
# Headless mode  —  pre-brief validation, and a scriptable proof of the signal set
# ===========================================================================
# Runs the SAME App.run + classify() the window does, with no display. Intended for
# the pre-brief: fire from the customer's network before the meeting and find out that
# an origin is unreachable or the control probe is down BEFORE you are on stage.
#
# Exit codes are deliberately policy-neutral: a `blocked` result is the product
# working, never a failure. Only a broken environment or a usage/config problem is
# non-zero.
HEADLESS_OK, HEADLESS_PROBLEM, HEADLESS_USAGE = 0, 1, 2


def select_triggers(triggers, selector, settings):
    """Resolve a `--run` selector into an ordered trigger list (catalog order).

    `all` (or empty) selects everything, skipping live-suspect-gated triggers exactly
    as the window's "Run all enabled" does. Otherwise the selector is a comma-separated
    list of trigger ids and/or class names; an explicitly named trigger is NOT skipped,
    so asking for a gated one reports its disabled state instead of silently doing
    nothing. Raises ValueError on an unknown name."""
    if selector in (None, "", "all"):
        return [t for t in triggers if not t.gated_disabled(settings)]
    wanted = [w.strip() for w in str(selector).split(",") if w.strip()]
    by_id = {t.id: t for t in triggers}
    classes = {t.cls for t in triggers}
    unknown = [w for w in wanted if w not in by_id and w not in classes]
    if unknown:
        raise ValueError("unknown trigger id or class: " + ", ".join(sorted(set(unknown))))
    keep = set()
    for w in wanted:
        if w in by_id:
            keep.add(w)
        else:
            keep.update(t.id for t in triggers if t.cls == w)
    return [t for t in triggers if t.id in keep]


def run_headless(app, triggers, settings, selector="all", fmt="text", out=None):
    """Fire the selected triggers with no window and report honestly. Returns the
    process exit code (see HEADLESS_* above)."""
    out = sys.stdout if out is None else out
    try:
        chosen = select_triggers(triggers, selector, settings)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return HEADLESS_USAGE
    if not chosen:
        print("error: that selection matched no runnable triggers", file=sys.stderr)
        return HEADLESS_USAGE

    planned = sum(t.on_wire_count(settings) for t in chosen)
    if fmt != "json":
        print(f"Firing {len(chosen)} triggers — {planned} signals planned.\n", file=out)

    results, counts = [], {}
    for i, t in enumerate(chosen, 1):
        _t, res = app.run(t.id, {})
        state = res.get("state", ERROR)
        counts[state] = counts.get(state, 0) + 1
        record = {
            "id": t.id, "label": t.label, "class": t.cls, "runner": t.runner,
            "severity": t.severity, "state": state, "reason": res.get("reason", ""),
            "rc": res.get("rc"), "http_code": res.get("http_code"),
            "duration_s": res.get("duration_s"),
            "wire_requests": res.get("wire_requests", t.on_wire_count(settings)),
            "expected_fire": res.get("expected_fire", ""),
            "console_hint": res.get("console_hint", ""),
            "verify_key": res.get("verify_key", ""),
            "ratio": res.get("ratio"),
        }
        results.append(record)
        if fmt != "json":
            print(f"[{i:>2}/{len(chosen)}] {t.id:<22} {state:<8} "
                  f"{record['wire_requests']:>2} signal(s)", file=out)
            if record["reason"]:
                print(f"           {record['reason']}", file=out)
            if record["verify_key"]:
                print(f"           verify: {record['verify_key']}", file=out)

    problems = counts.get(ERROR, 0) + counts.get(INVALID, 0)
    fired = sum(r["wire_requests"] for r in results)
    summary = {
        "triggers": len(results), "signals": fired,
        "states": counts, "problems": problems,
        "profile": "lab" if settings.enable_live_suspect_hosts else "default",
    }
    if fmt == "json":
        json.dump({"summary": summary, "results": results}, out, indent=2)
        out.write("\n")
    else:
        breakdown = " / ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        print(f"\nSUMMARY: {len(results)} triggers · {fired} signals · {breakdown}", file=out)
        if problems:
            print(f"{problems} trigger(s) could not be evaluated (error/invalid) — "
                  "that is an environment or gating problem, not a policy result.", file=out)
        else:
            print("Every trigger produced a policy result. A `blocked` result is the "
                  "inline stack doing its job.", file=out)
    return HEADLESS_OK if problems == 0 else HEADLESS_PROBLEM


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
    p.add_argument("--verbose", action="store_true", help="debug logging")
    p.add_argument("--check-update", action="store_true",
                   help="check the pinned, signed release source for a newer version and exit")
    p.add_argument("--update", action="store_true",
                   help="verify and install a newer signed release, then exit (fails closed)")
    p.add_argument("--list", dest="list_triggers", action="store_true",
                   help="list the trigger catalog and the signal count, then exit (sends nothing)")
    p.add_argument("--dry-run", action="store_true",
                   help="print the full signal manifest — every command that WOULD be sent "
                        "and the exact signal count — then exit (sends nothing)")
    p.add_argument("--run", metavar="SELECTOR",
                   help="run headless (no window) and exit: 'all', or a comma-separated list "
                        "of trigger ids and/or classes. Exit 0 even when triggers are blocked; "
                        "non-zero only for error/invalid or a usage problem")
    p.add_argument("--format", choices=("text", "json"), default="text",
                   help="output format for --list / --dry-run / --run (default: text)")
    p.add_argument("--preflight", action="store_true",
                   help="check that this console can run its triggers from here (curl, "
                        "egress control), then exit. A readiness gate — NOT a prediction "
                        "of what policy will allow or block")
    p.add_argument("--strict-catalog", action="store_true",
                   help="refuse to start unless config/catalog.yaml carries a valid "
                        "signature (default: report the status and continue)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(list(sys.argv[1:]) if argv is None else list(argv))
    setup_logging(args.verbose)

    if args.check_update or args.update:
        # Update is a code-execution channel: pinned source, signed manifest, fail closed.
        return perform_update(UPDATE_MANIFEST_URL, apply=args.update)

    try:
        settings = load_settings(args.config_dir)
        triggers = load_catalog(args.config_dir, settings)
    except ConfigError as e:
        log.error("configuration error: %s", e)
        return 2

    # Catalog provenance: report it always, refuse only when asked to.
    cat_status, cat_detail = catalog_signature_status(args.config_dir)
    strict = args.strict_catalog or bool(_dget(settings.raw, "run.strict_catalog", False))
    if cat_status == CATALOG_VERIFIED:
        log.info("catalog: %s", cat_detail)
    else:
        log.warning("catalog %s: %s", cat_status, cat_detail)
    if strict and cat_status != CATALOG_VERIFIED:
        log.error("refusing to start: --strict-catalog is set and the catalog is %s",
                  cat_status)
        return 2

    # Preview / headless paths: no window, and --list/--dry-run send nothing at all.
    if args.list_triggers or args.dry_run:
        manifest = signal_manifest(triggers, settings)
        if args.format == "json":
            print(json.dumps(manifest, indent=2))
        else:
            print(format_signal_manifest(manifest, verbose=bool(args.dry_run)))
        return 0

    if args.preflight:
        report = environment_report(settings, triggers)
        report["catalog"] = {"status": cat_status, "detail": cat_detail}
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_environment_report(report))
            print(f"\n  catalog: {cat_status} — {cat_detail}")
        return 0 if report["ready"] else 1

    app = App(settings, triggers, args.config_dir)
    planned = sum(t.on_wire_count(settings) for t in triggers if not t.gated_disabled(settings))
    log.info("%s %s — %d triggers (%d enabled, %d signals), native execution on %s",
             APP_NAME, __version__, len(triggers),
             sum(1 for t in triggers if not t.gated_disabled(settings)), planned, sys.platform)

    if args.run:
        return run_headless(app, triggers, settings, args.run, args.format)

    try:
        run_gui(settings, triggers, app, args.config_dir)
    except RuntimeError as e:
        log.error("%s", e)
        print(f"{APP_NAME} is a desktop app and needs a display.\n"
              "On Windows run it with pythonw/py; under headless Linux use Xvfb.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
