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
import math
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

__version__ = "0.8.1"
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
RUNNERS = {"curl", "dns", "tcp", "iprep", "ew"}
FLAGS = {"needs_internet", "needs_et_ruleset", "hits_live_suspect_hosts"}
SEVERITIES = {"info", "warn", "crit"}

# Measurement mode — the assurance tier a trigger belongs to.
#   best-effort  : fired SINGLE-ENDED at a PUBLIC origin. Realistic and independent, but the
#                  customer's IDS/IPS MAY OR MAY NOT register an event, and the result is a
#                  heuristic LOCAL read. Every trigger in the shipping catalog is this tier.
#   ground-truth : fired DUAL-ENDED against a reflector you control, so arrival is confirmed
#                  on the far side and a block/allow/mishandle is a GENUINE, PROVABLE event.
#                  That tier is the reflector POC (see poc/ and docs/EFFECTIVENESS-ROADMAP.md);
#                  none ship in the console catalog yet, but the schema carries the label so
#                  the two tiers can be shown side by side and never confused.
MODES = {"best-effort", "ground-truth"}
DEFAULT_MODE = "best-effort"

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
    def ew_probe_timeout(self):
        """How long an east-west port probe waits. Short: internal RTTs are sub-millisecond,
        so a wait of seconds only slows the demo without changing any answer."""
        return float(_dget(self.raw, "east_west.probe_timeout_s", 3))

    @property
    def ipv6_control_url(self):
        """Known-good IPv6 endpoint used to tell "this host has no IPv6" apart from
        "the customer's policy dropped it". An address literal, so the answer does not
        depend on DNS returning AAAA. Empty disables IPv6 triggers (they report error)."""
        return str(_dget(self.raw, "run.ipv6_control_url",
                         "https://[2606:4700:4700::1111]/") or "").strip()

    @property
    def evidence_log_enabled(self):
        # Append each run to a local JSONL evidence log. Local disk only — there is
        # still no network surface and nothing is uploaded.
        return bool(_dget(self.raw, "evidence.log", True))

    @property
    def correlation_header(self):
        """Stamp an X-SecVitals-Run header on curl triggers so the customer's console
        can be filtered to exactly this run.

        DEFAULT OFF, deliberately. It adds a header to traffic whose whole job is to
        match a signature faithfully, and it marks the traffic as synthetic. Turn it on
        when correlation matters more than fidelity."""
        return bool(_dget(self.raw, "run.correlation_header", False))

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
    requires: list = dataclasses.field(default_factory=list)   # transports this needs
    mode: str = "best-effort"   # assurance tier: best-effort (heuristic) or ground-truth

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
        requires = d.get("requires") or []
        if not isinstance(requires, list) or any(r not in REQUIREMENTS for r in requires):
            raise ConfigError(f"{tid}: requires must be a subset of {sorted(REQUIREMENTS)}, "
                              f"got {requires!r}")
        hint = d.get("console_hint", "")
        if not isinstance(hint, str):
            raise ConfigError(f"{tid}: console_hint must be a string")
        if len(hint) > 300:
            raise ConfigError(f"{tid}: console_hint is too long (max 300 characters)")
        mode = d.get("mode", DEFAULT_MODE)
        if mode not in MODES:
            raise ConfigError(f"{tid}: mode must be one of {sorted(MODES)}, got {mode!r}")
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
            requires=list(requires),
            mode=mode,
        )

    def gated_disabled(self, settings):
        return ("hits_live_suspect_hosts" in self.flags
                and not settings.enable_live_suspect_hosts)

    def ew_target_name(self):
        """The east-west target this trigger names, or "" if it is not an ew trigger."""
        if self.runner != "ew":
            return ""
        cmd = self.commands[0] if self.commands else []
        return cmd[1] if len(cmd) > 1 else ""

    def unconfigured(self, settings):
        """True when this trigger cannot run HERE because the site has not defined its
        target. Distinct from gated (deliberately off) and from blocked (a policy
        result): "we never configured this" is its own honest answer."""
        name = self.ew_target_name()
        if not name:
            return False
        try:
            return name not in load_ew_targets(settings)
        except ConfigError:
            return True

    def unavailable_reason(self, settings):
        """Why this trigger will not run, or None if it will."""
        if self.gated_disabled(settings):
            return ("this trigger reaches live suspect infrastructure and is disabled "
                    "(enable_live_suspect_hosts is false)")
        if self.unconfigured(settings):
            return (f"no east-west target named {self.ew_target_name()!r} is configured — "
                    "add it under east_west.targets in settings.yaml. Not a policy result.")
        return None

    def on_wire_count(self, settings):
        """How many requests this trigger actually puts ON THE WIRE.

        For most runners that is one per catalog command. The `iprep` runner is the
        exception: its single `["iprep"]` command fans out to `webcc.ip_rep_sample`
        node probes, so counting commands under-reports it (6x at the default sample).
        This is the number to quote when promising a known quantity of signals."""
        if self.runner == "iprep":
            return max(1, int(settings.ip_rep_sample))
        if self.runner == "ew":
            try:
                target = load_ew_targets(settings).get(self.ew_target_name())
            except ConfigError:
                target = None
            return len(target.ports) if target else 0
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
            "mode": self.mode,
            "runner": self.runner,
            "flags": self.flags,
            "severity": self.severity,
            "threat_class": self.threat_class,
            "expected_fire": self.expected_fire,
            "talking_point": self.talking_point,
            "console_hint": self.console_hint_text(),
            "requires": list(self.requires),
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


# ===========================================================================
# East–west targets  —  the customer's own internal zones
# ===========================================================================
# North–south triggers can ship with fixed destinations because the internet is the same
# everywhere. East–west cannot: the targets are the customer's internal addresses, and
# they differ at every site. So the catalog names a TARGET, and the operator defines what
# that name means in settings.yaml — exactly the pattern M3 used for reputation feeds.
# A trigger can therefore only ever probe an address someone deliberately configured.
#
# Tier 1 only (CONFIRMED.md §7): a bare TCP connect, no payload and no listener needed.
# Tier 2 (payload signatures) needs a second deployable and stays deferred.
EW_TARGET_NAME_RE = r"[a-z0-9][a-z0-9\-]{0,31}"


@dataclasses.dataclass
class EwTarget:
    name: str
    label: str
    host: str
    control_port: int      # expected REACHABLE — proves the host is up
    ports: list            # ports policy is expected to DENY
    zone: str = ""

    def to_public(self):
        return {"name": self.name, "label": self.label, "host": self.host,
                "control_port": self.control_port, "ports": list(self.ports),
                "zone": self.zone}


def load_ew_targets(settings):
    """Read `east_west.targets` from settings.yaml.

    Absent is normal — a fresh install has no idea what the customer's zones are — and
    is not an error. Malformed IS an error, because a half-understood target would send
    packets somewhere nobody chose."""
    raw = _dget(settings.raw, "east_west.targets", None)
    if raw in (None, "", {}):
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("east_west.targets must be a mapping of name -> target")
    out = {}
    for name, body in raw.items():
        if not isinstance(name, str) or not re.fullmatch(EW_TARGET_NAME_RE, name):
            raise ConfigError(f"east_west.targets: invalid target name {name!r}")
        if not isinstance(body, dict):
            raise ConfigError(f"east_west.targets.{name}: must be a mapping")
        host = str(body.get("host", "") or "").strip()
        if not host:
            raise ConfigError(f"east_west.targets.{name}: needs a host (IP or name)")

        def _port(value, what):
            try:
                port = int(value)
            except (TypeError, ValueError):
                raise ConfigError(f"east_west.targets.{name}: {what} must be an integer") from None
            if not 1 <= port <= 65535:
                raise ConfigError(f"east_west.targets.{name}: {what} out of range")
            return port

        control_port = _port(body.get("control_port", 0), "control_port")
        ports = body.get("ports")
        if not isinstance(ports, list) or not ports:
            raise ConfigError(f"east_west.targets.{name}: needs a non-empty 'ports' list")
        ports = [_port(p, "ports entry") for p in ports]
        if control_port in ports:
            raise ConfigError(f"east_west.targets.{name}: control_port {control_port} must "
                              "not also be listed in ports — it is the reachability "
                              "reference, so it cannot also be a thing under test")
        out[name] = EwTarget(name=name, label=str(body.get("label", name)), host=host,
                             control_port=control_port, ports=ports,
                             zone=str(body.get("zone", "")))
    return out


# ===========================================================================
# Demo profiles  —  curated, ORDERED subsets of the catalog
# ===========================================================================
# A profile SELECTS existing triggers; it never defines new ones. That distinction is
# what keeps the fixed-catalog guarantee intact: a profile is a list of catalog ids and
# an order to run them in, nothing more. Unknown ids fail loudly at startup rather than
# half-way through a demo.
#
# Order is the point. "Run all" is catalog order; a profile is the order the story wants
# — which is what turns 55 signals into a five-minute narrative.
PROFILE_NAME_RE = r"[a-z0-9][a-z0-9\-]{0,31}"


@dataclasses.dataclass
class Profile:
    name: str
    label: str
    description: str
    trigger_ids: list

    def triggers(self, by_id):
        """The profile's triggers, in PROFILE order (not catalog order)."""
        return [by_id[tid] for tid in self.trigger_ids if tid in by_id]

    def on_wire_count(self, by_id, settings):
        return sum(t.on_wire_count(settings) for t in self.triggers(by_id)
                   if not t.gated_disabled(settings))

    def to_public(self, by_id, settings):
        chosen = self.triggers(by_id)
        gated = [t.id for t in chosen if t.gated_disabled(settings)]
        return {
            "name": self.name, "label": self.label, "description": self.description,
            "triggers": list(self.trigger_ids), "trigger_count": len(chosen),
            "gated": gated, "signals": self.on_wire_count(by_id, settings),
        }


def load_profiles(settings, triggers):
    """Read `profiles:` from settings.yaml and validate it against the catalog.

    Every referenced id must exist — a profile that names a trigger the catalog does not
    have is a configuration error, caught at startup, not a silent no-op on stage."""
    raw = _dget(settings.raw, "profiles", None)
    if raw in (None, "", {}):
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("profiles: must be a mapping of name -> profile")
    known = {t.id for t in triggers}
    out = {}
    for name, body in raw.items():
        if not isinstance(name, str) or not re.fullmatch(PROFILE_NAME_RE, name):
            raise ConfigError(f"profiles: invalid profile name {name!r}")
        if not isinstance(body, dict):
            raise ConfigError(f"profiles.{name}: must be a mapping")
        ids = body.get("triggers")
        if not isinstance(ids, list) or not ids:
            raise ConfigError(f"profiles.{name}: needs a non-empty 'triggers' list")
        if not all(isinstance(i, str) for i in ids):
            raise ConfigError(f"profiles.{name}: every trigger must be a string id")
        missing = [i for i in ids if i not in known]
        if missing:
            raise ConfigError(f"profiles.{name}: unknown trigger id(s) {sorted(set(missing))}")
        seen, ordered = set(), []
        for tid in ids:                      # keep first occurrence, drop repeats
            if tid not in seen:
                seen.add(tid)
                ordered.append(tid)
        out[name] = Profile(
            name=name,
            label=str(body.get("label", name)),
            description=str(body.get("description", "")),
            trigger_ids=ordered,
        )
    return out


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
    # An iprep trigger names a reputation feed. Resolve it now so a typo fails at
    # startup rather than at click time, in front of a customer.
    feeds = load_reputation_feeds(settings)
    for t in triggers:
        if t.runner != "iprep":
            continue
        cmd = t.commands[0] if t.commands else ["iprep"]
        name = cmd[1] if len(cmd) > 1 else "tor"
        if name not in feeds:
            known = ", ".join(sorted(feeds)) or "(none configured)"
            raise ConfigError(f"{t.id}: unknown reputation feed {name!r} — "
                              f"configured feeds: {known}")
    return triggers




def _quiet_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


class IpFeedCache:
    """Fetch + cache one IP-reputation feed with a TTL — not refetched on every click."""

    def __init__(self, url, ttl):
        self.url = url
        self.ttl = ttl
        self._lock = threading.Lock()
        self._nodes = None
        self._fetched_at = 0.0

    def get(self):
        """Return a list of IPv4 strings. Raises urllib/OSError on fetch failure
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
            raise OSError(f"reputation feed url must be https, got {self.url!r}")
        req = urllib.request.Request(self.url, headers={"User-Agent": "secvitals/%s" % __version__})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read(8 * 1024 * 1024).decode("utf-8", "replace")
        return _parse_ip_list(data)


TorNodeCache = IpFeedCache          # the pre-M3 name, kept so nothing external breaks


def _parse_ip_list(text):
    """Extract well-formed IPv4 addresses from a feed, skipping comments and junk.

    Deliberately strict: a line must be exactly an address. Feeds carry comment headers,
    CIDR ranges and timestamps, and guessing at those would put traffic somewhere the
    operator never authorised."""
    out = []
    for line in (text or "").splitlines():
        ip = line.strip()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and all(0 <= int(o) <= 255 for o in ip.split(".")):
            out.append(ip)
    return out


_parse_tor_ips = _parse_ip_list     # the pre-M3 name


# ---------------------------------------------------------------------------
# IP-reputation feeds. Each is a named, pinned https list of addresses plus the port to
# probe. A catalog trigger names a feed with a FIXED token (["iprep", "<feed>"]) — never
# a URL — so a trigger can only ever reach a destination an operator put in settings.
@dataclasses.dataclass
class ReputationFeed:
    name: str
    label: str
    url: str
    port: int
    ttl: float


def load_reputation_feeds(settings):
    """Feeds from settings, with the historical Tor feed always present as `tor` so
    existing installs keep working unchanged."""
    feeds = {}
    if settings.tor_list_url:
        feeds["tor"] = ReputationFeed(name="tor", label="Tor Proxy nodes",
                                      url=settings.tor_list_url, port=443,
                                      ttl=settings.tor_list_ttl)
    raw = _dget(settings.raw, "webcc.reputation_feeds", None)
    if raw in (None, "", {}):
        return feeds
    if not isinstance(raw, dict):
        raise ConfigError("webcc.reputation_feeds must be a mapping of name -> feed")
    for name, body in raw.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,31}", name):
            raise ConfigError(f"webcc.reputation_feeds: invalid feed name {name!r}")
        if not isinstance(body, dict):
            raise ConfigError(f"webcc.reputation_feeds.{name}: must be a mapping")
        url = str(body.get("url", "") or "").strip()
        if not url.lower().startswith("https:"):
            raise ConfigError(f"webcc.reputation_feeds.{name}: url must be https")
        try:
            port = int(body.get("port", 443))
        except (TypeError, ValueError):
            raise ConfigError(f"webcc.reputation_feeds.{name}: port must be an integer") from None
        if not 1 <= port <= 65535:
            raise ConfigError(f"webcc.reputation_feeds.{name}: port out of range")
        feeds[name] = ReputationFeed(
            name=name, label=str(body.get("label", name)), url=url, port=port,
            ttl=float(body.get("ttl_s", settings.tor_list_ttl)),
        )
    return feeds


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


# Optional per-run correlation header (settings: run.correlation_header, default OFF).
# It lets the customer filter their console to exactly this run — at the cost of adding
# a header to traffic whose entire job is to match a signature faithfully, and of
# marking that traffic as synthetic. That trade is the operator's to make, so it is
# off unless asked for. Like the 5-tuple write-out, it is applied IN CODE: a self-update
# ships secvitals.py alone, so an install keeps its existing catalog.
CORRELATION_HEADER = "X-SecVitals-Run"


def _curl_flow_argv(argv, run_id=None):
    """The argv actually executed: the catalog's command with the 5-tuple fields appended
    to its --write-out format (or a --write-out added, if it has none), plus the optional
    correlation header. The DISPLAYED command stays exactly what the catalog declares."""
    out = list(argv)
    if run_id:
        out += ["-H", f"{CORRELATION_HEADER}: {run_id}"]
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


# ===========================================================================
# Transport capability  —  so an absent transport reads as `error`, never `blocked`
# ===========================================================================
# IPv6 and HTTP/3 twins are how you find a policy blind spot: a control that inspects
# IPv4/TCP-443 and quietly ignores IPv6 or QUIC. But they introduce a specific way to
# LIE. If this host has no IPv6 route, `curl -6` exits 7 — which the classifier maps to
# `blocked`, and the demo would claim the customer's stack dropped traffic it never saw.
# Same for `--http3` on a curl built without HTTP/3.
#
# So a trigger declares what it needs (`requires: [ipv6]`), and the requirement is
# checked BEFORE the trigger runs. Unmet requirement => `error` with a plain reason.
# Never `blocked`.
REQUIREMENTS = {"ipv6", "http3"}

_CAPS = {"features": None, "ipv6": None, "ipv6_at": 0.0}
_CAPS_LOCK = threading.Lock()
_IPV6_TTL = 300.0          # re-probe occasionally; a laptop changes networks


def curl_features(_runner=None):
    """The feature words from `curl --version`, lowercased. Cached for the process —
    the curl binary does not change under us. Returns an empty set if curl is missing."""
    with _CAPS_LOCK:
        if _CAPS["features"] is not None:
            return _CAPS["features"]
    run = _runner or (lambda: subprocess.run(["curl", "--version"], capture_output=True,
                                             timeout=10, check=False))
    features = set()
    try:
        proc = run()
        for line in _dec(proc.stdout).splitlines():
            if line.lower().startswith("features:"):
                features = {w.strip().lower() for w in line.split(":", 1)[1].split() if w.strip()}
                break
    except (OSError, subprocess.SubprocessError):
        features = set()
    with _CAPS_LOCK:
        _CAPS["features"] = features
    return features


def ipv6_egress_ok(settings, _runner=None):
    """True iff this host can actually reach the internet over IPv6.

    Probes a literal IPv6 address so the answer does not depend on DNS returning AAAA.
    `-k` because we only care whether packets get there, not who answered. Cached
    briefly: an SE laptop moves between networks."""
    now = time.monotonic()
    with _CAPS_LOCK:
        if _CAPS["ipv6"] is not None and (now - _CAPS["ipv6_at"]) < _IPV6_TTL:
            return _CAPS["ipv6"]
    url = settings.ipv6_control_url
    if not url:
        return None                     # not configured: caller decides (=> error)
    argv = ["curl", "-6", "-s", "-S", "-k", "-o", os.devnull,
            "--connect-timeout", "5", "--max-time", "8", url]
    run = _runner or (lambda: subprocess.run(argv, capture_output=True, timeout=15,
                                             check=False))
    try:
        ok = run().returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    with _CAPS_LOCK:
        _CAPS["ipv6"], _CAPS["ipv6_at"] = ok, now
    return ok


def reset_capability_cache():
    """Forget cached capability answers (tests, and a deliberate re-probe)."""
    with _CAPS_LOCK:
        _CAPS["features"], _CAPS["ipv6"], _CAPS["ipv6_at"] = None, None, 0.0


def unmet_requirement(trigger, settings):
    """The reason this trigger CANNOT be evaluated here, or None if it can.

    Returning a reason produces `error` — an honest "we could not test this" — rather
    than a `blocked` that would credit the customer's stack with a drop it never made."""
    for need in trigger.requires:
        if need == "http3":
            if "http3" not in curl_features():
                return ("this curl has no HTTP/3 support, so QUIC cannot be tested here "
                        "(not a policy result)")
        elif need == "ipv6":
            ok = ipv6_egress_ok(settings)
            if ok is None:
                return ("IPv6 cannot be tested: no run.ipv6_control_url is configured, so "
                        "a failure could not be told apart from a policy block")
            if not ok:
                return ("this host has no working IPv6 egress, so an IPv6 trigger proves "
                        "nothing about policy (not a policy result)")
    return None


def run_trigger(trigger, params, settings, run_id=None):
    """Run every command of one trigger natively and return a RunResult. Never raises for
    expected failure modes — those become per-request error_reason (→ `error`)."""
    try:
        resolved = _resolve_params(trigger, params)
    except ParamError as e:
        return RunResult(error_reason=f"invalid parameters: {e}")

    # A transport this host cannot use is an ERROR, never a block (see unmet_requirement).
    unmet = unmet_requirement(trigger, settings)
    if unmet:
        return RunResult(error_reason=unmet)

    start = time.monotonic()
    subs, need_control = [], False
    for template in trigger.commands:
        try:
            argv = build_command(template, resolved)
        except ParamError as e:
            subs.append(SubResult(argv=list(template), error_reason=f"invalid parameters: {e}"))
            continue
        if trigger.runner == "curl":
            stamp = run_id if (run_id and settings.correlation_header) else None
            subs.append(_run_curl_with_failover(argv, trigger.timeout, settings,
                                                stamp))
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


def _run_curl_with_failover(argv, timeout, settings, run_id=None):
    """Run a curl command; on an ENVIRONMENT error only, retry once against a configured
    alternate origin.

    Never applied past a blocked or allowed result: a policy outcome is the answer, and
    retrying it elsewhere would launder it. The retry is kept only if it produced a real
    policy result — otherwise the original honest error stands."""
    sub = _run_curl(argv, timeout, run_id)
    if classify_curl(sub.rc, sub.http_code) != ERROR or sub.rc not in BROKEN_RC:
        return sub
    host, _port = _url_endpoint(argv)
    alternate = settings.origin_failover.get(host) if host else None
    if not alternate:
        return sub
    retry = _run_curl(_swap_url_host(argv, host, alternate), timeout, run_id)
    if classify_curl(retry.rc, retry.http_code) == ERROR:
        return sub                      # the failover did not help — keep the truth
    retry.failover_from = host
    log.info("origin failover: %s -> %s", host, alternate)
    return retry


def _run_curl(argv, timeout, run_id=None):
    exec_argv = _curl_flow_argv(argv, run_id)  # argv stays the catalog's, for display
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


# DNS query types the built-in probe can ask for. TXT and NULL matter because that is
# what DNS tunnelling actually uses — an A-record probe would not reproduce the shape a
# tunnelling signature looks for.
DNS_QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "NULL": 10,
              "SRV": 33, "ANY": 255}


def _run_dns(argv, timeout):
    """`dns` command: ["dns", "<name>", "@<server>", "type=TXT"] — a native DNS query.

    The `type=` token is optional and defaults to A; it is matched against a fixed
    allowlist, so it can never become an arbitrary value."""
    qname, server, qtype = None, "8.8.8.8", "A"
    for a in argv[1:]:
        if a.startswith("@"):
            server = a[1:] or server
        elif a.lower().startswith("type="):
            qtype = a.split("=", 1)[1].strip().upper()
        elif qname is None:
            qname = a
    if not qname:
        return SubResult(argv=argv, error_reason="dns: no query name in command")
    if qtype not in DNS_QTYPES:
        return SubResult(argv=argv,
                         error_reason=f"dns: unsupported query type {qtype!r} "
                                      f"(allowed: {', '.join(sorted(DNS_QTYPES))})")
    ok, detail, err, flow = _dns_query(qname, server, min(float(timeout), 8.0), qtype)
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


def _dns_query(qname, server="8.8.8.8", timeout=5.0, qtype="A"):
    """Send a minimal DNS query over UDP and wait for a response. Returns
    (ok, detail, err, flow): ok True if ANY response came back (the query crossed the wire
    and the resolver was reachable), ok False on timeout (no response — possibly a policy
    drop), err set only for a local/environment failure.

    NB an NXDOMAIN still counts as ok: the question crossed the wire, which is exactly
    what a DNS signature inspects. Whether the name resolves is beside the point."""
    qcode = DNS_QTYPES.get(str(qtype).upper(), 1)
    try:
        labels = qname.rstrip(".").split(".")
        if any(len(p.encode("ascii")) > 63 for p in labels):
            return (False, "", f"dns: label longer than 63 bytes in {qname!r}", None)
        q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels) + b"\x00"
        packet = (struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + q
                  + struct.pack(">HH", qcode, 1))
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
        return (True, f"DNS {qname} {qtype} @{server}: response "
                      f"(rcode={rcode}, answers={answers})", None, flow)
    except socket.timeout:
        return (False, f"DNS {qname} {qtype} @{server}: no response (timeout)", None, flow)
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


# East–west connect outcomes. Four, not three, because "no route from here" is a local
# environment fact and must never be filed alongside "dropped in transit by policy".
EW_OPEN, EW_REFUSED, EW_TIMEOUT, EW_UNREACHABLE = "open", "refused", "timeout", "unreachable"


def _tcp_connect_outcome(host, port, timeout):
    """(outcome, flow) for one east–west port probe.

      open        SYN-ACK — reachable, something is listening.
      refused     RST — the SYN ARRIVED and the host answered. Reachable; the port is
                  merely closed. Calling this "blocked" would credit the firewall with
                  work the host did.
      timeout     no answer at all — consistent with a drop in transit.
      unreachable ENETUNREACH/EHOSTUNREACH and friends: this host has no route, or a
                  router replied ICMP-unreachable. That is an environment fact, not a
                  policy verdict, so it is kept separate from `timeout`.

    Order matters below: socket.timeout and ConnectionRefusedError are both OSError
    subclasses, so they must be caught first."""
    flow = _flow("TCP", dst_port=port, host=host)
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            return EW_OPEN, _sock_flow(sock, "TCP", host)
    except socket.timeout:
        return EW_TIMEOUT, flow
    except ConnectionRefusedError:
        return EW_REFUSED, flow
    except (OSError, ValueError):
        return EW_UNREACHABLE, flow


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
# Run evidence  —  a per-run ledger, on local disk only
# ===========================================================================
# What this is FOR: after a demo, the SE needs to prove what was fired, when, from
# which endpoints, and what this host observed — so the customer can reconcile it
# against their own console at their own pace.
#
# What it deliberately is NOT: telemetry. Nothing is uploaded, nothing phones home,
# and there is still no listening socket. Every artifact is written to local disk and
# handed over by the presenter.
#
# The ledger is HASH-CHAINED: each record commits to the previous one, so a report can
# be shown to have not been quietly edited after the fact. The chain covers the
# machine-observed facts only — the presenter's "confirmed on console" annotation is
# added later by a human and is explicitly OUTSIDE the chain (see LEDGER_UNCHAINED).
CONFIRMED_UNSET, CONFIRMED_YES, CONFIRMED_NO = "unset", "confirmed", "not-seen"
CONFIRMED_STATES = (CONFIRMED_UNSET, CONFIRMED_YES, CONFIRMED_NO)

# Fields excluded from the hash chain: they are human annotations or chain metadata,
# not observations, and they change after the record is written.
LEDGER_UNCHAINED = ("confirmed", "hash", "prev_hash")


def _sha256_file(path):
    """SHA-256 of a file, or "" when it can't be read (never raises — a missing file
    must not stop a demo)."""
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def provenance(config_dir=None):
    """What produced this evidence: the app version plus digests of the code and the
    config that actually decided what was sent. Lets a reader confirm the run used the
    reviewed catalog, not a locally edited one."""
    cfg = config_dir or DEFAULT_CONFIG_DIR
    return {
        "app": APP_NAME,
        "version": __version__,
        "code_sha256": _sha256_file(_THIS_FILE),
        "catalog_sha256": _sha256_file(os.path.join(cfg, "catalog.yaml")),
        "settings_sha256": _sha256_file(os.path.join(cfg, "settings.yaml")),
    }


def new_run_id():
    """A short, unique id for one console session. os.urandom keeps this dependency-free
    and unpredictable; it is not a secret, just a correlation handle."""
    return os.urandom(8).hex()


def _utc(when=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() if when is None else when))


def _record_hash(record, prev_hash):
    """Commit to this record and everything before it. Canonical JSON (sorted keys,
    no whitespace) so the digest is reproducible by anyone re-reading the file."""
    payload = {k: v for k, v in record.items() if k not in LEDGER_UNCHAINED}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + blob).encode("utf-8")).hexdigest()


class RunLedger:
    """Every trigger fired in this session, in order, hash-chained."""

    def __init__(self, config_dir=None, run_id=None, started=None):
        self.run_id = run_id or new_run_id()
        self.started = _utc(started)
        self.provenance = provenance(config_dir)
        self.records = []
        self._lock = threading.Lock()

    def add(self, trigger, out, settings, when=None):
        """Append one fired trigger's honest result. Returns the stored record."""
        with self._lock:
            prev = self.records[-1]["hash"] if self.records else ""
            rec = {
                "seq": len(self.records) + 1,
                "ts": _utc(when),
                "run_id": self.run_id,
                "id": trigger.id,
                "label": trigger.label,
                "class": trigger.cls,
                "mode": trigger.mode,
                "runner": trigger.runner,
                "severity": trigger.severity,
                "threat_class": trigger.threat_class,
                "state": out.get("state", ERROR),
                "reason": out.get("reason", ""),
                "rc": out.get("rc"),
                "http_code": out.get("http_code"),
                "duration_s": out.get("duration_s"),
                "wire_requests": out.get("wire_requests", trigger.on_wire_count(settings)),
                "expected_fire": out.get("expected_fire", trigger.expected_fire),
                "console_hint": out.get("console_hint", trigger.console_hint_text()),
                "verify_key": out.get("verify_key", ""),
                "ratio": out.get("ratio"),
                "flows": [f for f in (out.get("flows") or []) if f],
                "confirmed": CONFIRMED_UNSET,
                "prev_hash": prev,
            }
            rec["hash"] = _record_hash(rec, prev)
            self.records.append(rec)
            return rec

    def set_confirmed(self, seq, value):
        """Record the presenter's own read of the customer's console. Deliberately
        separate from the machine observation, and outside the hash chain, so the two
        can never be confused for one another."""
        if value not in CONFIRMED_STATES:
            raise ValueError(f"confirmed must be one of {CONFIRMED_STATES}")
        with self._lock:
            for rec in self.records:
                if rec["seq"] == seq:
                    rec["confirmed"] = value
                    return rec
        return None

    def verify_chain(self):
        """Re-derive every digest. Returns (ok, first_bad_seq)."""
        prev = ""
        for rec in self.records:
            if rec.get("prev_hash") != prev or rec.get("hash") != _record_hash(rec, prev):
                return False, rec.get("seq")
            prev = rec["hash"]
        return True, None

    # -- summaries ---------------------------------------------------------
    def state_counts(self):
        counts = {}
        for rec in self.records:
            counts[rec["state"]] = counts.get(rec["state"], 0) + 1
        return counts

    def signals_fired(self):
        return sum(int(r.get("wire_requests") or 0) for r in self.records)

    def scorecard(self):
        """The reconciliation sheet: what the catalog EXPECTED to fire, what this host
        OBSERVED locally, and what the presenter CONFIRMED on the customer's console —
        three separate columns that are never merged, because they are three different
        kinds of evidence."""
        return [{
            "seq": r["seq"], "ts": r["ts"], "id": r["id"], "label": r["label"],
            "class": r["class"], "mode": r.get("mode", DEFAULT_MODE),
            "severity": r["severity"],
            "expected": r["expected_fire"], "observed": r["state"],
            "reason": r["reason"], "signals": r["wire_requests"],
            "confirmed": r["confirmed"], "verify_key": r["verify_key"],
        } for r in self.records]

    def coverage_matrix(self, triggers, settings):
        """Which policy dimensions this session actually exercised — and, honestly, which
        it did not. Empty cells are the point: they are the gaps to name out loud."""
        fired = {r["id"] for r in self.records}
        produced = {r["id"] for r in self.records
                    if r["state"] in (ALLOWED, BLOCKED, RATIO)}
        cells, classes, threats = {}, [], []
        for t in triggers:
            if t.cls not in classes:
                classes.append(t.cls)
            threat = t.threat_class or "(unclassified)"
            if threat not in threats:
                threats.append(threat)
            cell = cells.setdefault((t.cls, threat),
                                    {"catalog": 0, "enabled": 0, "fired": 0, "result": 0})
            cell["catalog"] += 1
            if not t.unavailable_reason(settings):
                cell["enabled"] += 1
            if t.id in fired:
                cell["fired"] += 1
            if t.id in produced:
                cell["result"] += 1
        gaps = []
        for cls in classes:
            for threat in threats:
                cell = cells.get((cls, threat))
                if cell and cell["catalog"] and not cell["fired"]:
                    gaps.append(f"{cls} / {threat}: {cell['catalog']} trigger(s) in the "
                                "catalog, none fired this session")
        for cls in sorted(CLASSES - set(classes)):
            gaps.append(f"{cls}: no triggers exist in the catalog at all")
        return {"classes": classes, "threats": threats,
                "cells": {f"{c}|{th}": v for (c, th), v in cells.items()},
                "gaps": gaps}

    # -- serialisation -----------------------------------------------------
    def to_dict(self, triggers=None, settings=None):
        ok, bad = self.verify_chain()
        doc = {
            "run_id": self.run_id,
            "started": self.started,
            "generated": _utc(),
            "provenance": self.provenance,
            "summary": {
                "triggers": len(self.records),
                "signals": self.signals_fired(),
                "states": self.state_counts(),
                "chain_ok": ok,
                "chain_first_bad_seq": bad,
            },
            "records": self.records,
        }
        if triggers is not None and settings is not None:
            doc["coverage"] = self.coverage_matrix(triggers, settings)
        return doc

    def to_json(self, triggers=None, settings=None):
        return json.dumps(self.to_dict(triggers, settings), indent=2, default=str)

    CSV_COLUMNS = ("seq", "ts", "run_id", "id", "label", "class", "mode", "runner",
                   "severity", "threat_class", "state", "reason", "rc", "http_code",
                   "duration_s", "wire_requests", "expected_fire", "confirmed",
                   "verify_key", "hash")

    def to_csv(self):
        import csv
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(self.CSV_COLUMNS),
                                extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for rec in self.records:
            writer.writerow({k: ("" if rec.get(k) is None else rec.get(k))
                             for k in self.CSV_COLUMNS})
        return buf.getvalue()

    def to_html(self, triggers=None, settings=None):
        return render_html_report(self, triggers, settings)


# --- the leave-behind -------------------------------------------------------
_STATE_CSS = {ALLOWED: "st-allowed", BLOCKED: "st-blocked", ERROR: "st-error",
              INVALID: "st-invalid", RATIO: "st-ratio"}
_CONFIRMED_LABEL = {CONFIRMED_UNSET: "—", CONFIRMED_YES: "confirmed on console",
                    CONFIRMED_NO: "not seen"}

_REPORT_CSS = """
:root { color-scheme: dark; }
body { background:#1a1d21; color:#f2f4f5; font-family:'Segoe UI',system-ui,sans-serif;
       margin:0; padding:32px; line-height:1.5; }
h1,h2 { margin:0 0 8px; } h1 { font-size:24px; } h2 { font-size:15px; margin-top:32px;
       text-transform:uppercase; letter-spacing:.08em; color:#01A982; }
.sub { color:#9aa3ad; font-size:13px; margin-bottom:24px; }
table { border-collapse:collapse; width:100%; font-size:13px; margin-top:8px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid #363b44;
        vertical-align:top; }
th { color:#9aa3ad; font-weight:600; font-size:11px; text-transform:uppercase;
     letter-spacing:.06em; }
code,.mono { font-family:Consolas,ui-monospace,monospace; font-size:12px; }
.badge { display:inline-block; padding:1px 8px; border-radius:3px; font-size:11px;
         font-family:Consolas,monospace; border:1px solid; }
.st-allowed { color:#00B0E6; border-color:#00B0E6; }
.st-blocked { color:#01A982; border-color:#01A982; }
.st-error   { color:#E0574a; border-color:#E0574a; }
.st-invalid { color:#FEC901; border-color:#FEC901; }
.st-ratio   { color:#FF8300; border-color:#FF8300; }
.card { background:#23272e; border:1px solid #363b44; border-radius:6px; padding:14px 18px;
        margin-bottom:10px; }
.kv { display:flex; flex-wrap:wrap; gap:24px; font-size:12px; color:#9aa3ad; }
.gap { color:#FEC901; } .ok { color:#01A982; } .bad { color:#E0574a; }
.note { color:#6f787c; font-size:12px; margin-top:6px; }
.wrap { overflow-x:auto; }
"""


def _esc(value):
    import html
    return html.escape("" if value is None else str(value), quote=True)


def render_html_report(ledger, triggers=None, settings=None):
    """One self-contained HTML file: no scripts, no external resources, everything
    escaped. This is the artifact the customer keeps — so it states plainly what was
    machine-observed locally, what the presenter attested, and what was NOT covered."""
    doc = ledger.to_dict(triggers, settings)
    summary, prov = doc["summary"], doc["provenance"]
    chain_ok = summary["chain_ok"]
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>{_esc(APP_NAME)} run {_esc(doc['run_id'])}</title>",
           f"<style>{_REPORT_CSS}</style></head><body>",
           f"<h1>{_esc(APP_NAME)} — demo evidence</h1>",
           f"<div class='sub'>Run <span class='mono'>{_esc(doc['run_id'])}</span> · "
           f"started {_esc(doc['started'])} · report generated {_esc(doc['generated'])}</div>"]

    # -- summary ----------------------------------------------------------
    states = " · ".join(f"{n} {_esc(s)}" for s, n in sorted(summary["states"].items()))
    out.append("<div class='card'><div class='kv'>"
               f"<div><strong>{summary['triggers']}</strong> triggers fired</div>"
               f"<div><strong>{summary['signals']}</strong> signals on the wire</div>"
               f"<div>{states or '—'}</div></div>")
    if chain_ok:
        out.append("<div class='note ok'>Evidence chain verified — every record commits "
                   "to the one before it.</div>")
    else:
        out.append("<div class='note bad'>Evidence chain BROKEN at record "
                   f"{_esc(summary['chain_first_bad_seq'])} — this report has been "
                   "altered after it was written.</div>")
    out.append("</div>")

    out.append("<div class='card'><div class='kv'>"
               f"<div>version <span class='mono'>{_esc(prov['version'])}</span></div>"
               f"<div>code <span class='mono'>{_esc(prov['code_sha256'][:16])}…</span></div>"
               f"<div>catalog <span class='mono'>{_esc(prov['catalog_sha256'][:16])}…</span></div>"
               f"<div>settings <span class='mono'>{_esc(prov['settings_sha256'][:16])}…</span></div>"
               "</div><div class='note'>Digests of the code and configuration that decided "
               "what was sent.</div></div>")

    # -- how to read it ---------------------------------------------------
    out.append("<h2>How to read this</h2><div class='card'><table>"
               "<tr><th>State</th><th>What it means</th></tr>"
               "<tr><td><span class='badge st-allowed'>allowed</span></td><td>The traffic "
               "completed. The control is in detect-only mode, or the category is not set "
               "to Deny.</td></tr>"
               "<tr><td><span class='badge st-blocked'>blocked</span></td><td>The flow was "
               "dropped inline — enforcement working.</td></tr>"
               "<tr><td><span class='badge st-error'>error</span></td><td><strong>Not a "
               "policy result.</strong> The trigger could not run (DNS, TLS, no route). "
               "Never read this as a block.</td></tr>"
               "<tr><td><span class='badge st-invalid'>invalid</span></td><td>Gated off, or "
               "the egress control probe failed.</td></tr>"
               "<tr><td><span class='badge st-ratio'>ratio</span></td><td>IP reputation "
               "reached N of M nodes — a ratio, never a single verdict.</td></tr>"
               "</table><div class='note'>Observed locally by the host that fired the "
               "traffic. The inline stack's own console remains authoritative.</div></div>")

    # -- scorecard --------------------------------------------------------
    out.append("<h2>Expected vs observed vs confirmed</h2><div class='wrap'><table>"
               "<tr><th>#</th><th>Time (UTC)</th><th>Trigger</th><th>Mode</th>"
               "<th>Expected to fire</th>"
               "<th>Observed locally</th><th>Confirmed on console</th><th>Signals</th></tr>")
    for row in ledger.scorecard():
        css = _STATE_CSS.get(row["observed"], "")
        out.append(
            f"<tr><td class='mono'>{row['seq']}</td><td class='mono'>{_esc(row['ts'])}</td>"
            f"<td><strong>{_esc(row['label'])}</strong><br><span class='mono' "
            f"style='color:#6f787c'>{_esc(row['id'])}</span></td>"
            f"<td class='mono'>{_esc(row.get('mode', 'best-effort'))}</td>"
            f"<td>{_esc(row['expected'])}</td>"
            f"<td><span class='badge {css}'>{_esc(row['observed'])}</span><div class='note'>"
            f"{_esc(row['reason'])}</div></td>"
            f"<td>{_esc(_CONFIRMED_LABEL.get(row['confirmed'], row['confirmed']))}</td>"
            f"<td class='mono'>{_esc(row['signals'])}</td></tr>")
    out.append("</table></div><div class='note'>“Mode” is the measurement tier: "
               "<strong>best-effort</strong> (single-ended to a public origin — a heuristic "
               "read that may or may not have registered an event) vs "
               "<strong>ground-truth</strong> (dual-ended over a reflector you control — a "
               "proven event). “Expected” is what the catalog says the signal should trip. "
               "“Observed locally” is this host's honest read. “Confirmed on console” is the "
               "presenter's own attestation — kept separate and outside the evidence chain.</div>")

    # -- coverage ---------------------------------------------------------
    coverage = doc.get("coverage")
    if coverage:
        out.append("<h2>Policy coverage</h2><div class='wrap'><table><tr><th>Class</th>")
        for threat in coverage["threats"]:
            out.append(f"<th>{_esc(threat)}</th>")
        out.append("</tr>")
        for cls in coverage["classes"]:
            out.append(f"<tr><td class='mono'>{_esc(cls)}</td>")
            for threat in coverage["threats"]:
                cell = coverage["cells"].get(f"{cls}|{threat}")
                if not cell or not cell["catalog"]:
                    out.append("<td class='note'>—</td>")
                else:
                    style = "ok" if cell["result"] else ("gap" if cell["enabled"] else "note")
                    out.append(f"<td class='{style} mono'>{cell['result']}/{cell['catalog']}</td>")
            out.append("</tr>")
        out.append("</table></div><div class='note'>Triggers that produced a policy result "
                   "/ triggers in the catalog.</div>")
        if coverage["gaps"]:
            out.append("<div class='card'><strong>Not exercised in this session</strong><ul>")
            for gap in coverage["gaps"]:
                out.append(f"<li class='gap'>{_esc(gap)}</li>")
            out.append("</ul><div class='note'>Named explicitly: a gap the customer cannot "
                       "see is a gap they cannot judge.</div></div>")

    # -- per-trigger detail ----------------------------------------------
    out.append("<h2>Flow detail</h2>")
    for rec in doc["records"]:
        out.append(f"<div class='card'><strong>{_esc(rec['label'])}</strong> "
                   f"<span class='mono' style='color:#6f787c'>{_esc(rec['id'])}</span>")
        if rec.get("verify_key"):
            out.append(f"<div class='mono note'>{_esc(rec['verify_key'])}</div>")
        if rec.get("flows"):
            out.append("<div class='wrap'><table><tr><th>Proto</th><th>Source</th>"
                       "<th>Destination</th><th>Host</th></tr>")
            for flow in rec["flows"]:
                src = f"{flow.get('src_ip') or '—'}:{flow.get('src_port') or '—'}"
                dst = f"{flow.get('dst_ip') or '—'}:{flow.get('dst_port') or '—'}"
                out.append(f"<tr><td class='mono'>{_esc(flow.get('proto'))}</td>"
                           f"<td class='mono'>{_esc(src)}</td><td class='mono'>{_esc(dst)}</td>"
                           f"<td class='mono'>{_esc(flow.get('host') or '—')}</td></tr>")
            out.append("</table></div>")
        out.append("</div>")

    out.append("<div class='note'>Generated locally by Security Vitals. Nothing in this "
               "report was uploaded or transmitted anywhere.</div></body></html>")
    return "\n".join(out)


# --- where evidence lands ---------------------------------------------------
def evidence_dir(settings=None):
    """Local, per-user directory for run evidence. Never inside the install folder,
    which may not be writable — and never anywhere off this machine."""
    configured = _dget(getattr(settings, "raw", {}) or {}, "evidence.dir", "") or ""
    if configured:
        return os.path.expanduser(str(configured))
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "SecVitals", "runs")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "secvitals", "runs")


def write_evidence(path, text):
    """Write one artifact, creating the directory. Returns the path; raises OSError."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def append_jsonl(path, record, max_bytes=8 * 1024 * 1024):
    """Append one record to the rolling evidence log, rotating once it gets large so a
    long-lived install can't fill a disk. Best-effort: evidence logging must never take
    the console down mid-demo."""
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            if os.path.getsize(path) >= max_bytes:
                os.replace(path, path + ".1")
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        return True
    except OSError as e:
        log.warning("could not append to the evidence log: %s", e)
        return False


def read_jsonl(path, limit=5000):
    """Read back evidence records (oldest first). Malformed lines are skipped, not fatal."""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    except OSError:
        return []
    return out[-limit:]


def last_session_records(path):
    """The most recent run's records, for re-rendering a session without re-firing."""
    records = read_jsonl(path)
    if not records:
        return []
    last_run = records[-1].get("run_id")
    return [r for r in records if r.get("run_id") == last_run]


class App:
    def __init__(self, settings, triggers, config_dir=None, ledger=None):
        self.settings = settings
        self.triggers = triggers
        self.by_id = {t.id: t for t in triggers}
        self.config_dir = config_dir
        self.feeds = load_reputation_feeds(settings)
        self._feed_caches = {}
        self._feed_lock = threading.Lock()
        # the pre-M3 attribute, still the Tor feed's cache
        self.tor_cache = self.feed_cache(self.feeds["tor"]) if "tor" in self.feeds else None
        self._run_lock = threading.Lock()   # serialize triggers — clean before/after on stage
        self._last_run_end = 0.0            # rate limiting between runs
        self.ledger = ledger if ledger is not None else RunLedger(config_dir)
        self.evidence_path = os.path.join(evidence_dir(settings), "evidence.jsonl")

    def feed_cache(self, feed):
        """One cache per feed URL, shared across runs so a click never refetches."""
        with self._feed_lock:
            cache = self._feed_caches.get(feed.url)
            if cache is None:
                cache = IpFeedCache(feed.url, feed.ttl)
                self._feed_caches[feed.url] = cache
            return cache

    def run(self, trigger_id, params):
        """Fire one trigger and record it. Every outcome — including `invalid` and
        `error` — lands in the ledger, because a demo's gaps are evidence too."""
        trigger, out = self._run_one(trigger_id, params)
        if trigger is not None:
            record = self.ledger.add(trigger, out, self.settings)
            out["seq"] = record["seq"]
            if self.settings.evidence_log_enabled:
                append_jsonl(self.evidence_path, record)
        return trigger, out

    def _run_one(self, trigger_id, params):
        trigger = self.by_id.get(trigger_id)
        if trigger is None:
            return None, {"error": "unknown trigger id"}
        unavailable = trigger.unavailable_reason(self.settings)
        if unavailable:
            return trigger, {"state": INVALID, "reason": unavailable,
                             "expected_fire": trigger.expected_fire}
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
            if trigger.runner == "ew":
                out = self._run_ew(trigger)
                log.info("run done id=%s state=%s", trigger_id, out.get("state"))
                return trigger, out
            if trigger.runner == "iprep":
                out = self._run_iprep(trigger)
                log.info("run done id=%s state=%s", trigger_id, out.get("state"))
                return trigger, out
            result = run_trigger(trigger, params, self.settings, self.ledger.run_id)
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
                "flows": [f for f in flows if f],
                "stderr": "",
            }
        finally:
            self._last_run_end = time.monotonic()
            self._run_lock.release()

    def _run_ew(self, trigger):
        """East–west tier 1: is this internal port reachable from this zone?

        A bare TCP connect, no payload, no listener required. Three outcomes per port,
        and the distinction between them is the whole feature:

          SYN-ACK (connect succeeds)  -> REACHABLE, and something is listening
          RST     (refused)           -> REACHABLE — the packet arrived and the host
                                         answered. Segmentation is NOT dropping it;
                                         the port is merely closed. Reporting this as
                                         "blocked" would credit the firewall with work
                                         the host did.
          timeout (no answer at all)  -> dropped in transit == segmentation working

        A timeout is only meaningful if the host is actually up, so a CONTROL PORT on the
        SAME target is probed first. Control unreachable => `error`: the host is down or
        unroutable, and nothing can be concluded about policy. Never a false `blocked`.
        Called while the run lock is held."""
        settings = self.settings
        try:
            targets = load_ew_targets(settings)
        except ConfigError as e:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": f"east-west targets are misconfigured: {e}"}
        target = targets.get(trigger.ew_target_name())
        if target is None:
            return {"state": INVALID, "expected_fire": trigger.expected_fire,
                    "reason": (f"no east-west target named {trigger.ew_target_name()!r} is "
                               "configured — add it under east_west.targets in "
                               "settings.yaml. Not a policy result.")}

        timeout = settings.ew_probe_timeout
        flows, details = [], []
        control_ok, control_flow = _tcp_probe_flow(target.host, target.control_port, timeout)
        flows.append(control_flow)
        if not control_ok:
            details.append(f"{target.host}:{target.control_port}  control  UNREACHABLE")
            return {
                "state": ERROR,
                "expected_fire": trigger.expected_fire,
                "console_hint": trigger.console_hint_text(),
                "reason": (f"the control port {target.host}:{target.control_port} did not "
                           "answer, so this host is down or unroutable from here. Nothing "
                           "can be concluded about segmentation policy (not a block)."),
                "requests": 0,
                "wire_requests": trigger.on_wire_count(settings),
                "stdout": "\n".join(details),
                "flow": _clip(_format_flows(flows), 4000),
            }
        details.append(f"{target.host}:{target.control_port}  control  reachable "
                       "(the host is up, so a timeout below is a policy drop)")

        dropped, reachable, unreachable = [], [], []
        for port in target.ports:
            outcome, flow = _tcp_connect_outcome(target.host, port, timeout)
            flows.append(flow)
            if outcome == EW_OPEN:
                reachable.append(port)
                details.append(f"{target.host}:{port}  SYN-ACK      reachable — open, "
                               "segmentation is not blocking this")
            elif outcome == EW_REFUSED:
                reachable.append(port)
                details.append(f"{target.host}:{port}  RST          reachable — closed on "
                               "the host, but the packet got there (not a firewall drop)")
            elif outcome == EW_TIMEOUT:
                dropped.append(port)
                details.append(f"{target.host}:{port}  timeout      dropped in transit — "
                               "segmentation working")
            else:
                unreachable.append(port)
                details.append(f"{target.host}:{port}  unreachable  no route / ICMP "
                               "unreachable — environment, not a policy result")

        total = len(target.ports)
        summary = (f"{len(dropped)} of {total} port(s) dropped in transit, "
                   f"{len(reachable)} reachable")
        if unreachable:
            summary += f", {len(unreachable)} unreachable (no route)"
        summary += " (control OK)"

        decided = len(dropped) + len(reachable)
        if not decided:
            # Every port failed for a routing reason: that says nothing about policy.
            state = ERROR
            reason = (summary + " — no port produced a policy result, so this is an "
                                "environment problem, not a block")
        elif dropped and not reachable:
            state, reason = BLOCKED, summary + " — segmentation is enforcing on every port tested"
        elif reachable and not dropped:
            state, reason = ALLOWED, summary + " — every port tested was reachable from this zone"
        else:
            state = BLOCKED if len(dropped) > len(reachable) else ALLOWED
            reason = summary + " (mixed — see the per-port breakdown)"
        return {
            "state": state,
            "reason": reason,
            "expected_fire": trigger.expected_fire,
            "console_hint": trigger.console_hint_text(),
            "ratio": {"blocked": len(dropped), "reached": len(reachable),
                      "unreachable": len(unreachable), "total": total},
            "requests": total,
            "wire_requests": trigger.on_wire_count(settings),
            "duration_s": None,
            "stdout": "\n".join(details),
            "flow": _clip(_format_flows(flows), 4000),
        }

    def _run_iprep(self, trigger):
        """IP-reputation probe: a control egress probe first (fail => whole test invalid),
        then connect to the first N Tor nodes on :443 and report a RATIO (never a single
        verdict). Called while the run lock is held."""
        s = self.settings
        # The catalog names a feed with a fixed token; it can never carry a URL.
        cmd = trigger.commands[0] if trigger.commands else ["iprep"]
        feed_name = cmd[1] if len(cmd) > 1 else "tor"
        feed = self.feeds.get(feed_name)
        if feed is None:
            known = ", ".join(sorted(self.feeds)) or "(none configured)"
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": f"unknown reputation feed {feed_name!r} — configured: {known}"}
        if not s.control_enabled:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": "IP reputation needs a control probe — set run.control_host"}
        control_ok, control_detail = probe_control(s, 6.0)
        if not control_ok:
            return {"state": INVALID, "expected_fire": trigger.expected_fire,
                    "reason": (f"control probe failed ({control_detail}) — egress is "
                               "broken, so the whole test is invalid (not blocked)")}
        try:
            nodes = self.feed_cache(feed).get()
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": f"could not fetch the {feed.label} feed: {e}"}
        sample = nodes[:max(1, s.ip_rep_sample)]
        if not sample:
            return {"state": ERROR, "expected_fire": trigger.expected_fire,
                    "reason": f"the {feed.label} feed was empty"}
        blocked = reached = 0
        details, flows = [], []
        for ip in sample:
            ok, flow = _tcp_probe_flow(ip, feed.port, s.node_probe_timeout)
            flows.append(flow)
            if ok:
                reached += 1
                details.append(f"{ip}:{feed.port}  reached  (not blocked by IP reputation)")
            else:
                blocked += 1
                details.append(f"{ip}:{feed.port}  blocked  (timeout/reset)")
        return {
            "state": RATIO,
            "ratio": {"blocked": blocked, "reached": reached, "total": len(sample)},
            "reason": (f"{blocked} of {len(sample)} {feed.label} addresses blocked by IP "
                       "reputation (control OK). A ratio, not a single verdict — a lone "
                       "reach may be a live host and a lone block may be an offline one; "
                       "the inline IP-reputation stats are authoritative."),
            "expected_fire": trigger.expected_fire,
            "console_hint": trigger.console_hint_text(),
            "verify_key": verification_key(trigger, f"{blocked}/{len(sample)} blocked", flows),
            "requests": len(sample),
            "wire_requests": trigger.on_wire_count(s),
            "stdout": "\n".join(details),
            "flow": _clip(_format_flows(flows), 4000),
            "flows": [f for f in flows if f],
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
    rows, classes, modes = [], {}, {}
    enabled = gated = unconfigured = signals = signals_if_gate_on = 0
    for t in triggers:
        # Three different reasons a trigger will not run, kept apart because they mean
        # different things: gated (deliberately off), unconfigured (this site never told
        # us where to probe), and runnable. Lumping them together would tell an operator
        # to flip a gate that cannot possibly help.
        is_gated = t.gated_disabled(settings)
        is_unconfigured = t.unconfigured(settings)
        count = t.on_wire_count(settings)
        if not is_unconfigured:
            signals_if_gate_on += count
        cmds = _preview_commands(t)
        dests = [d for d in (_command_destination(t.runner, c) for c in cmds) if d]
        rows.append({
            "id": t.id, "label": t.label, "class": t.cls, "mode": t.mode,
            "runner": t.runner,
            "severity": t.severity, "threat_class": t.threat_class,
            "wire_request_count": count, "gated_disabled": is_gated,
            "unconfigured": is_unconfigured,
            "unavailable_reason": t.unavailable_reason(settings),
            "flags": list(t.flags), "destinations": dests,
            "expected_fire": t.expected_fire, "console_hint": t.console_hint_text(),
            "commands": [_redact(c) for c in cmds],
        })
        if is_unconfigured:
            unconfigured += 1
            continue
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
        mslot = modes.setdefault(t.mode, {"mode": t.mode, "triggers": 0, "signals": 0})
        mslot["triggers"] += 1
        mslot["signals"] += count
    return {
        "profile": "lab" if settings.enable_live_suspect_hosts else "default",
        "enable_live_suspect_hosts": settings.enable_live_suspect_hosts,
        "totals": {"triggers_enabled": enabled, "triggers_gated": gated,
                   "triggers_unconfigured": unconfigured,
                   "triggers_total": len(triggers), "signals": signals,
                   "signals_if_gate_enabled": signals_if_gate_on},
        "classes": [classes[k] for k in classes],
        "modes": [modes[k] for k in modes],
        "triggers": rows,
    }


def format_profiles(profiles, by_id, settings):
    """The demo profiles on offer, with the exact signal count each one commits to."""
    if not profiles:
        return ("No demo profiles are defined. Add a `profiles:` section to "
                "config/settings.yaml to curate ordered run-sets.")
    out = ["DEMO PROFILES — curated, ordered run-sets (nothing is sent)", ""]
    for profile in profiles.values():
        pub = profile.to_public(by_id, settings)
        out.append(f"  {profile.name:<18} {pub['signals']:>3} signals across "
                   f"{pub['trigger_count']} triggers   {profile.label}")
        if profile.description:
            out.append(f"  {'':<18} {profile.description}")
        out.append(f"  {'':<18} order: " + " → ".join(profile.trigger_ids))
        if pub["gated"]:
            out.append(f"  {'':<18} gated off right now: " + ", ".join(pub["gated"]))
        out.append("")
    out.append("Run one with:  --profile <name> --run all")
    return "\n".join(out)


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
    gated = [r for r in manifest["triggers"]
             if r["gated_disabled"] and not r.get("unconfigured")]
    if gated:
        out.append(f"DISABLED — reaches live suspect infrastructure ({len(gated)}): "
                   + ", ".join(r["id"] for r in gated))
        out.append("  Enable with enable_live_suspect_hosts in settings.yaml — a lab you control only.")
        out.append("")
    missing = [r for r in manifest["triggers"] if r.get("unconfigured")]
    if missing:
        out.append(f"NOT CONFIGURED HERE ({len(missing)}): "
                   + ", ".join(r["id"] for r in missing))
        out.append("  These need a target for this site — define east_west.targets in "
                   "settings.yaml.")
        out.append("  Not gated, and not a policy result: we simply have not been told "
                   "where to probe.")
        out.append("")
    modes = {m["mode"]: m for m in manifest.get("modes", [])}
    be = modes.get("best-effort", {"triggers": 0, "signals": 0})
    gt = modes.get("ground-truth", {"triggers": 0, "signals": 0})
    out.append("MEASUREMENT MODE — what a result here can prove")
    out.append(f"  best-effort   {be['signals']:>3} signals / {be['triggers']:>2} triggers   "
               "single-ended to public origins — a heuristic local read (MAY OR MAY NOT "
               "register an IDS/IPS event)")
    out.append(f"  ground-truth  {gt['signals']:>3} signals / {gt['triggers']:>2} triggers   "
               "dual-ended over a reflector you control — proves a genuine event")
    if not gt["triggers"]:
        out.append("                    (no ground-truth triggers in the console catalog yet — "
                   "that tier is the reflector POC:")
        out.append("                     poc/, docs/EFFECTIVENESS-ROADMAP.md · "
                   "python3 poc/harness.py --manifest)")
    out.append("")
    out.append(f"TOTAL: {t['signals']} signals across {t['triggers_enabled']} enabled triggers")
    if t["triggers_gated"]:
        # Count only what the GATE can unlock. triggers_total would include triggers
        # that are unconfigured for this site, which no gate can make runnable —
        # exactly the kind of quiet overstatement the manifest exists to prevent.
        unlockable = t["triggers_total"] - t.get("triggers_unconfigured", 0)
        out.append(f"       {t['signals_if_gate_enabled']} signals if the live-suspect gate is enabled "
                   f"({unlockable} triggers)")
    return "\n".join(out)


# ===========================================================================
# Presenter session  —  an ordered walk with a live scoreboard
# ===========================================================================
# Deliberately pure: the presenter WINDOW is a thin renderer over this object, so the
# pacing, the progress arithmetic and the scoreboard are unit-testable without a display.
#
# The scoreboard counts what was OBSERVED LOCALLY and says so. It is a running tally of
# this host's own reads, never a claim about what the customer's stack did.
class PresenterSession:
    def __init__(self, triggers, settings, label="", description=""):
        self.triggers = list(triggers)
        self.settings = settings
        self.label = label or "All enabled triggers"
        self.description = description
        self.index = 0
        self.results = {}          # trigger id -> observed state

    # -- position ---------------------------------------------------------
    @property
    def total(self):
        return len(self.triggers)

    @property
    def current(self):
        if 0 <= self.index < self.total:
            return self.triggers[self.index]
        return None

    @property
    def done(self):
        return self.index >= self.total

    def advance(self):
        if self.index < self.total:
            self.index += 1
        return self.current

    def back(self):
        if self.index > 0:
            self.index -= 1
        return self.current

    def goto(self, index):
        self.index = max(0, min(int(index), self.total))
        return self.current

    def progress(self):
        """(position, total) — 1-based for display, clamped at the end."""
        return (min(self.index + 1, self.total) if self.total else 0, self.total)

    # -- signal accounting ------------------------------------------------
    def planned_signals(self):
        return sum(t.on_wire_count(self.settings) for t in self.triggers)

    def fired_signals(self):
        return sum(t.on_wire_count(self.settings) for t in self.triggers
                   if t.id in self.results)

    # -- scoreboard -------------------------------------------------------
    def record(self, trigger_id, state):
        self.results[trigger_id] = state
        return state

    def scoreboard(self):
        """Totals overall and per class, plus the count still to run."""
        by_state, by_class = {}, {}
        for t in self.triggers:
            slot = by_class.setdefault(t.cls, {"label": CLASS_LABEL.get(t.cls, t.cls),
                                               "total": 0, "fired": 0, "states": {}})
            slot["total"] += 1
            state = self.results.get(t.id)
            if state is None:
                continue
            slot["fired"] += 1
            slot["states"][state] = slot["states"].get(state, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1
        return {
            "label": self.label,
            "states": by_state,
            "classes": by_class,
            "fired": len(self.results),
            "remaining": self.total - len(self.results),
            "signals_fired": self.fired_signals(),
            "signals_planned": self.planned_signals(),
        }

    def summary_line(self):
        board = self.scoreboard()
        parts = " · ".join(f"{n} {s}" for s, n in sorted(board["states"].items()))
        return (f"{board['fired']}/{self.total} triggers · "
                f"{board['signals_fired']}/{board['signals_planned']} signals"
                + (f" · {parts}" if parts else ""))


# ===========================================================================
# Tkinter console  —  a self-contained spatial window (no browser, no server)
# ===========================================================================
# The console keeps netvitals' identity — the lock-and-EKG mark, the HPE green, the
# dark surface — but renders it as a spatial workspace: one lit backdrop, and frosted
# glass panels floating over it. Tk has no compositor and no alpha channel, so every
# "translucent" effect here is a colour computed against the exact backdrop pixel it
# sits on (see _backdrop_rgb / _frost_at). That is why the backdrop is an analytic
# field rather than an image file: a panel can ask what is behind it.
#
# Trigger cards are still rendered from the fixed local catalog and a click still fires
# in-process (App.run on a background thread), reporting the three honest states
# (allowed / blocked / error, plus the iprep ratio). What is new is that a click also
# *shows* the traffic: each on-wire signal leaves the host as a dot, holds at the
# inline stack, and then passes, breaks, or scatters — animation driven only by what
# the console actually observed, never by what it hopes happened.
GUI_BG = "#070a12"            # the window's floor, behind everything
GUI_BG_TOP = "#101c38"        # backdrop gradient — horizon
GUI_BG_BOT = "#05070f"        # backdrop gradient — deep
GUI_SURFACE = "#182033"       # nominal frost (real panels compute their own)
GUI_PANEL = "#1d2639"
GUI_PANEL_HI = "#27324a"
GUI_GRID = "#2a3450"
GUI_INK = "#eef2f8"
GUI_DIM = "#9fadc6"
GUI_FAINT = "#7d8ca9"
GUI_ACCENT = "#01A982"
GUI_ACCENT_DK = "#017a5e"
GUI_ACCENT_LT = "#3ee6b4"
GUI_INFO = "#00B0E6"
GUI_WARN = "#FF8300"
GUI_CRIT = "#E0574a"
GUI_GOLD = "#FEC901"
GUI_VIOLET = "#7a6cf0"
GUI_FONT = "Segoe UI"
GUI_MONO = "Consolas"

SEV_COLOR = {"info": GUI_INFO, "warn": GUI_WARN, "crit": GUI_CRIT}

# One colour per honest state, shared by the cards, the emission lanes and the
# presenter — so "blocked green" means the same thing everywhere in the window.
STATE_COLOR = {ALLOWED: GUI_INFO, BLOCKED: GUI_ACCENT, ERROR: GUI_CRIT,
               INVALID: GUI_GOLD, RATIO: GUI_WARN}

# The presenter's attestation cycles unset -> confirmed -> not-seen. It records what a
# human saw on the customer's console; it never changes this host's own observation.
CONFIRM_CYCLE = {CONFIRMED_UNSET: CONFIRMED_YES, CONFIRMED_YES: CONFIRMED_NO,
                 CONFIRMED_NO: CONFIRMED_UNSET}
CONFIRM_CYCLE_LABEL = {CONFIRMED_UNSET: "Console: not marked",
                       CONFIRMED_YES: "Console: confirmed ✓",
                       CONFIRMED_NO: "Console: not seen"}
CONFIRM_CYCLE_FG = {CONFIRMED_UNSET: GUI_INK, CONFIRMED_YES: GUI_ACCENT, CONFIRMED_NO: GUI_WARN}

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


# ---------------------------------------------------------------------------
# colour arithmetic — Tk has no alpha, so every blend is computed up front
# ---------------------------------------------------------------------------
def _rgb(colour):
    c = colour.lstrip("#")
    return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16))


def _hx(r, g, b):
    return "#%02x%02x%02x" % (max(0, min(255, int(r))), max(0, min(255, int(g))),
                              max(0, min(255, int(b))))


def _mix(a, b, t):
    """Blend hex colour `a` toward `b`. t=0 is a, t=1 is b."""
    ar, ag, ab = _rgb(a)
    br, bg, bb = _rgb(b)
    return _hx(ar + (br - ar) * t, ag + (bg - ag) * t, ab + (bb - ab) * t)


def _lift(colour, t=0.12):
    """Toward the light — highlights, hover states, specular edges."""
    return _mix(colour, "#ffffff", t)


def _sink(colour, t=0.30):
    """Toward the dark — wells, shadows, recessed panes."""
    return _mix(colour, "#000000", t)


def _num(value, default=0):
    """Geometry reads (winfo_*, bbox) are ints on a live interpreter and None under the
    headless build test, so every one of them goes through here — a layout pass must
    never raise just because it is measuring a widget that has no window yet."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bg_of(widget, default=GUI_SURFACE):
    """The colour actually behind a widget, so a child can blend into its parent
    instead of stamping a rectangle of some other shade on top of it."""
    try:
        value = widget.cget("bg")
    except Exception:
        return default
    return value if isinstance(value, str) and value.startswith("#") else default


# ---------------------------------------------------------------------------
# the backdrop: one analytic light field, painted once and sampled forever
# ---------------------------------------------------------------------------
# fx, fy, radius, colour, strength — soft light sources sitting behind the glass.
_AURORA = (
    (0.02, -0.10, 0.80, GUI_ACCENT, 0.58),
    (1.00, -0.02, 0.66, GUI_INFO, 0.40),
    (0.78, 1.10, 0.88, GUI_VIOLET, 0.52),
    (0.30, 0.58, 0.60, "#0d6a92", 0.22),
    (0.55, 0.24, 0.34, "#123a6e", 0.20),
)


# Parsed once. This function is called per cell of the backdrop — tens of thousands of
# times per generation — and re-parsing seven hex constants inside that loop was 60% of
# the paint. The unpacked forms below are the same values, resolved at import.
_BG_TOP_RGB = _rgb(GUI_BG_TOP)
_BG_BOT_RGB = _rgb(GUI_BG_BOT)
_AURORA_RGB = tuple((cx, cy, 1.0 / (rad * rad), _rgb(colour), strength)
                    for cx, cy, rad, colour, strength in _AURORA)


def _backdrop_rgb(fx, fy, aspect=1.45):
    """The backdrop colour at fractional position (fx, fy) of the window.

    Single source of truth: the painted image, every panel's frost tint and every
    drop shadow are derived from this one function, which is what keeps a "translucent"
    surface consistent with what is actually behind it."""
    tr, tg, tb = _BG_TOP_RGB
    dr, dg, db = _BG_BOT_RGB
    e = fy ** 0.72                      # ease the horizon high in the frame
    r = tr + (dr - tr) * e
    g = tg + (dg - tg) * e
    b = tb + (db - tb) * e
    for cx, cy, inv_rad2, (lr, lg, lb), strength in _AURORA_RGB:
        dx = fx - cx
        dy = (fy - cy) * aspect         # the light pools are wider than they are tall
        d2 = (dx * dx + dy * dy) * inv_rad2
        if d2 >= 1.0:
            continue
        k = (1.0 - d2)
        k = k * k * strength
        r += (lr - r) * k
        g += (lg - g) * k
        b += (lb - b) * k
    vx, vy = (fx - 0.5) * 2.0, (fy - 0.5) * 2.0     # corners fall away
    v = 1.0 - 0.26 * min(1.0, (vx * vx + vy * vy) * 0.5)
    return (r * v, g * v, b * v)


def _frost_at(fx, fy, lift=0.13, pickup=0.28, base="#141c2e", tint="#cfe0ff"):
    """The colour of a frosted pane sitting at (fx, fy).

    Real frosted glass is mostly its own material: it picks up some of the light behind
    it, blurred to a local average, and scatters the rest back as white. Taking the
    backdrop wholesale would tint every panel bright teal under the aurora and leave no
    contrast for the state colours, so the pane keeps a cool base and only *some* of
    what is behind it — which is also what makes two panes at different heights read as
    the same material rather than two different ones."""
    sample = _hx(*_backdrop_rgb(fx, fy))
    return _mix(_mix(base, sample, pickup), tint, lift)


def _backdrop_image(w, h, fy0=0.0, fy1=1.0):
    """Render a slice of the light field as a PhotoImage.

    Generated at a fraction of the window's resolution and zoomed back up: the field is
    smooth by construction, so the upscale costs nothing visually and the whole paint is
    one Tcl call instead of a million. `fy0`/`fy1` select the vertical slice of the field
    to draw, so a caller that only shows a strip pays only for that strip.

    Returns (image, source) — the caller must keep BOTH alive or Tk garbage-collects the
    pixels out from under the canvas."""
    w, h = max(16, int(w)), max(16, int(h))
    # The floor is 8, not 3. The field is smooth enough that at cell=8 the largest colour
    # step between adjacent source cells is 1/255 — below what an eye can resolve — while
    # the cell=3 floor made a header strip cost six times as much to paint.
    cell = max(8, int(math.sqrt(w * h / 45000.0)))
    cw, ch = int(w // cell) + 2, int(h // cell) + 2
    src = tk.PhotoImage(width=cw, height=ch)
    cache, rows = {}, []
    xs = [(i + 0.5) / cw for i in range(cw)]
    for j in range(ch):
        fy = fy0 + (fy1 - fy0) * ((j + 0.5) / ch)
        row = []
        for fx in xs:
            r, g, b = _backdrop_rgb(fx, fy)
            key = (int(r), int(g), int(b))
            colour = cache.get(key)
            if colour is None:
                colour = cache[key] = _hx(key[0], key[1], key[2])
            row.append(colour)
        rows.append("{" + " ".join(row) + "}")
    src.put(" ".join(rows))
    return src.zoom(cell), src


def _round_pts(x0, y0, x1, y1, r):
    """Corner points for a rounded rectangle drawn as a smoothed polygon. Each straight
    run repeats its endpoints so the spline pins the edges flat and only bends at the
    corners."""
    r = max(1.0, min(float(r), (x1 - x0) / 2.0, (y1 - y0) / 2.0))
    return [x0 + r, y0, x0 + r, y0, x1 - r, y0, x1 - r, y0, x1, y0,
            x1, y0 + r, x1, y0 + r, x1, y1 - r, x1, y1 - r, x1, y1,
            x1 - r, y1, x1 - r, y1, x0 + r, y1, x0 + r, y1, x0, y1,
            x0, y1 - r, x0, y1 - r, x0, y0 + r, x0, y0 + r, x0, y0]


def _glass(cv, x0, y0, x1, y1, fill, behind, radius=16, stroke=None, shadow=4,
           glow=None, glow_k=1.0, tags=()):
    """Draw one frosted surface: a soft drop shadow that fades into `behind`, the pane
    itself, and a specular hairline along the top edge where the light catches it."""
    ids = []
    for i in range(shadow, 0, -1):
        t = i / float(shadow)
        col = _mix(behind, "#000000", 0.30 * (1.0 - t) + 0.08)
        ids.append(cv.create_polygon(
            _round_pts(x0 - i * 0.6, y0 + i * 0.7, x1 + i * 0.6, y1 + i * 1.3, radius + i),
            smooth=True, splinesteps=10, fill=col, outline="", tags=tags))
    if glow and glow_k > 0.01:                 # a lit pane throws colour onto the backdrop
        for i in (7, 5, 3):
            ids.append(cv.create_polygon(
                _round_pts(x0 - i, y0 - i, x1 + i, y1 + i, radius + i),
                smooth=True, splinesteps=10, outline="",
                fill=_mix(behind, glow, (0.19 - i * 0.02) * glow_k), tags=tags))
    ids.append(cv.create_polygon(_round_pts(x0, y0, x1, y1, radius), smooth=True,
                                 splinesteps=12, fill=fill,
                                 outline=(stroke or _lift(fill, 0.20)), width=1, tags=tags))
    ids.append(cv.create_line(x0 + radius * 0.9, y0 + 1.5, x1 - radius * 0.9, y0 + 1.5,
                              fill=_lift(fill, 0.34), width=1, tags=tags))
    ids.append(cv.create_line(x0 + radius * 0.5, y1 - 1, x1 - radius * 0.5, y1 - 1,
                              fill=_sink(fill, 0.22), width=1, tags=tags))
    return ids


# ---------------------------------------------------------------------------
# one clock for everything that moves
# ---------------------------------------------------------------------------
class _Anim:
    """A single ~60 fps clock shared by the whole window.

    Every animated thing registers a callback here instead of running its own `after`
    loop, so motion costs one timer no matter how much is moving — and costs almost
    nothing when nothing is. A callback that raises is dropped, never propagated: a
    widget destroyed mid-flight must not be able to stop the clock."""

    def __init__(self, root):
        self.root = root
        self.jobs = []
        self._pending = None
        self._last = time.monotonic()
        self._ambient = True
        self._schedule(80)

    def set_ambient(self, on):
        """Ambient motion is the heartbeat: nice while someone is looking at it, pure
        waste while the console sits behind another window. Jobs that carry state (a
        lane resolving, a hover settling) are never paused — only the decoration is."""
        on = bool(on)
        if on != self._ambient:
            self._ambient = on
            self._schedule(16 if on else 90)

    def add(self, fn, ambient=False):
        """Register fn(dt, elapsed); return False from it to unregister. Adding always
        restarts the clock, because _tick stops it outright when nothing is moving.

        `ambient` marks a job that is always running and never urgent (the header's
        heartbeat): the clock runs at half rate while only those are registered, so a
        console left open on a desk costs a fraction of what an interaction costs."""
        self.jobs.append([fn, time.monotonic(), bool(ambient)])
        self._schedule(33 if ambient else 16)
        return fn

    def drop(self, fn):
        self.jobs = [j for j in self.jobs if j[0] is not fn]

    def _schedule(self, ms):
        try:
            if self._pending is not None:
                self.root.after_cancel(self._pending)
        except Exception:
            pass
        try:
            self._pending = self.root.after(ms, self._tick)
        except Exception:
            self._pending = None

    def _tick(self):
        self._pending = None                     # this one already fired; nothing to cancel
        now = time.monotonic()
        dt = min(0.05, max(0.001, now - self._last))
        self._last = now
        for job in list(self.jobs):
            if job[2] and not self._ambient:      # decoration, and nobody is looking
                continue
            try:
                alive = job[0](dt, now - job[1])
            except Exception:
                alive = False
            if alive is False:
                try:
                    self.jobs.remove(job)
                except ValueError:
                    pass
        if not self.jobs:
            return                               # nothing moving: stop the clock entirely
        if any(not job[2] for job in self.jobs):
            self._schedule(16)
        else:
            self._schedule(33 if self._ambient else 250)


def _ease(t):
    """Smoothstep — used everywhere a value has to arrive without a hard stop."""
    t = max(0.0, min(1.0, t))
    return t * t * (3.0 - 2.0 * t)


# ---------------------------------------------------------------------------
# controls
# ---------------------------------------------------------------------------
class _Pill:
    """A button drawn on a canvas: rounded, frosted, lit from within on hover.

    Tk's Button is a hard-edged platform rectangle that would break the surface
    everywhere it appeared, so the console draws its own — which also gives the press
    somewhere to put a little physicality."""

    def __init__(self, parent, text, command, kind="ghost", anim=None,
                 font=None, padx=15, pady=8):
        self.behind = _bg_of(parent)
        self.kind = kind
        self.command = command
        self.text = text
        self.enabled = True
        self.anim = anim
        self.font = font or (GUI_FONT, 9, "bold")
        self.padx, self.pady = padx, pady
        self.glow = 0.0
        self.target = 0.0
        self.press = 0.0
        self._job = None
        self.focused = False
        self.h = 30
        # takefocus stays on: this replaces a tk.Button, and a control you can reach
        # with Tab and fire with Return has to keep behaving that way.
        self.cv = tk.Canvas(parent, bg=self.behind, highlightthickness=0, bd=0,
                            width=90, height=self.h, cursor="hand2", takefocus=1)
        probe = self.cv.create_text(-500, -500, text=text, font=self.font, anchor="w")
        self.tw = self._measure(probe, len(text) * 7 + 8)
        try:
            self.cv.delete(probe)
        except Exception:
            pass
        self.w = int(self.tw + self.padx * 2)
        self.h = int(16 + self.pady * 2)
        try:
            self.cv.configure(width=self.w, height=self.h)
        except Exception:
            pass
        for seq, fn in (("<Enter>", self._enter), ("<Leave>", self._leave),
                        ("<Button-1>", self._focus_click), ("<ButtonRelease-1>", self._up),
                        ("<FocusIn>", self._focus_in), ("<FocusOut>", self._focus_out),
                        ("<Return>", self._activate), ("<space>", self._activate)):
            try:
                self.cv.bind(seq, fn)
            except Exception:
                pass
        self._render()

    def _measure(self, item, fallback):
        try:
            box = self.cv.bbox(item)
            return max(10, int(box[2] - box[0]))
        except Exception:
            return fallback

    # -- palette ----------------------------------------------------------
    def _colours(self):
        g = self.glow
        if not self.enabled:
            return (_lift(self.behind, 0.05), _lift(self.behind, 0.10), GUI_FAINT, None)
        if self.kind == "primary":
            fill = _mix(GUI_ACCENT_DK, GUI_ACCENT, 0.55 + 0.45 * g)
            return (fill, _mix(GUI_ACCENT_LT, "#ffffff", 0.15 * g), "#04140f", GUI_ACCENT)
        if self.kind == "danger":
            fill = _mix(_lift(self.behind, 0.06), GUI_CRIT, 0.55 + 0.4 * g)
            return (fill, GUI_CRIT, "#160707", GUI_CRIT)
        fill = _lift(self.behind, 0.07 + 0.09 * g)
        return (fill, _lift(self.behind, 0.20 + 0.22 * g), GUI_INK, None)

    def _render(self):
        cv = self.cv
        try:
            cv.delete("all")
        except Exception:
            return
        fill, stroke, ink, halo = self._colours()
        dy = 1.0 * self.press
        r = self.h / 2.0
        if halo and self.enabled:                 # a lit control spills onto its surround
            for i, t in ((4, 0.16), (2, 0.26)):
                cv.create_polygon(_round_pts(1 - i * 0.5, 1 - i * 0.5 + dy,
                                             self.w - 1 + i * 0.5, self.h - 2 + i * 0.5 + dy, r + i),
                                  smooth=True, splinesteps=8, outline="",
                                  fill=_mix(self.behind, halo, t * (0.35 + 0.65 * self.glow)))
        cv.create_polygon(_round_pts(1, 2 + dy, self.w - 1, self.h - 1 + dy, r),
                          smooth=True, splinesteps=10, fill=_sink(self.behind, 0.25),
                          outline="")
        cv.create_polygon(_round_pts(1, 1 + dy, self.w - 1, self.h - 2 + dy, r),
                          smooth=True, splinesteps=10, fill=fill, outline=stroke, width=1)
        if self.focused and self.enabled:          # keyboard focus has to be visible
            cv.create_polygon(_round_pts(3, 3 + dy, self.w - 3, self.h - 4 + dy, r - 2),
                              smooth=True, splinesteps=10, fill="", width=1,
                              outline=_lift(fill, 0.55))
        cv.create_text(self.w / 2.0, self.h / 2.0 + dy, text=self.text, fill=ink,
                       font=self.font)

    # -- interaction ------------------------------------------------------
    def _animate(self):
        if self.anim is None:
            self.glow = self.target
            self._render()
            return
        if self._job is not None:
            return

        def frame(dt, _elapsed):
            step = dt * 7.0
            done = True
            if abs(self.target - self.glow) > 0.01:
                self.glow += (self.target - self.glow) * min(1.0, step)
                done = False
            else:
                self.glow = self.target
            if abs(self.press) > 0.01:
                self.press *= max(0.0, 1.0 - step)
                done = False
            self._render()
            if done:
                self._job = None
                return False
            return True
        self._job = self.anim.add(frame)

    def _enter(self, _e=None):
        if self.enabled:
            self.target = 1.0
            self._animate()

    def _leave(self, _e=None):
        self.target = 0.0
        self._animate()

    def _focus_click(self, _e=None):
        try:
            self.cv.focus_set()
        except Exception:
            pass
        if self.enabled:
            self.press = 1.0
            self._render()

    def _up(self, _e=None):
        if not self.enabled:
            return
        self.press = 0.6
        self._animate()
        if callable(self.command):
            self.command()

    def _activate(self, _e=None):
        """Return/Space on a focused control, the same as a click."""
        if not self.enabled:
            return
        self.press = 1.0
        self._animate()
        if callable(self.command):
            self.command()
        return "break"

    def _focus_in(self, _e=None):
        self.focused = True
        self._render()

    def _focus_out(self, _e=None):
        self.focused = False
        self._render()

    # -- the tk.Button surface the rest of the console expects -------------
    def configure(self, **kw):
        if "state" in kw:
            self.enabled = kw.pop("state") != "disabled"
            try:
                self.cv.configure(cursor="hand2" if self.enabled else "arrow")
            except Exception:
                pass
        if "text" in kw:
            self.text = kw.pop("text")
            probe = self.cv.create_text(-500, -500, text=self.text, font=self.font, anchor="w")
            self.w = int(self._measure(probe, len(self.text) * 7 + 8) + self.padx * 2)
            try:
                self.cv.delete(probe)
                self.cv.configure(width=self.w)
            except Exception:
                pass
        if "bg" in kw:
            self.behind = kw.pop("bg")
            try:
                self.cv.configure(bg=self.behind)
            except Exception:
                pass
        self._render()

    config = configure

    def pack(self, **kw):
        self.cv.pack(**kw)
        return self

    def pack_forget(self):
        self.cv.pack_forget()

    def grid(self, **kw):
        self.cv.grid(**kw)
        return self

    def place(self, **kw):
        self.cv.place(**kw)
        return self


def _gui_button(parent, text, cmd, primary=False, anim=None, font=None):
    return _Pill(parent, text, cmd, kind=("primary" if primary else "ghost"),
                 anim=anim, font=font)


def _chip_row(parent, items, font=None, pad=7, gap=6, height=19):
    """A row of small rounded tags on one canvas — one widget instead of a dozen, and
    rounded, which a bordered tk.Label can never be."""
    behind = _bg_of(parent)
    font = font or (GUI_MONO, 8)
    cv = tk.Canvas(parent, bg=behind, highlightthickness=0, bd=0, height=height,
                   width=10, takefocus=0)
    x = 0
    for text, colour in items:
        probe = cv.create_text(-500, -500, text=text, font=font, anchor="w")
        try:
            box = cv.bbox(probe)
            tw = int(box[2] - box[0])
        except Exception:
            tw = len(text) * 6
        try:
            cv.delete(probe)
        except Exception:
            pass
        w = tw + pad * 2
        cv.create_polygon(_round_pts(x, 1, x + w, height - 1, (height - 2) / 2.0),
                          smooth=True, splinesteps=8,
                          fill=_mix(behind, colour, 0.13), outline=_mix(behind, colour, 0.55))
        cv.create_text(x + w / 2.0, height / 2.0, text=text, fill=_lift(colour, 0.25),
                       font=font)
        x += w + gap
    try:
        cv.configure(width=max(10, x))
    except Exception:
        pass
    return cv


# ---------------------------------------------------------------------------
# the emission lane — what a click actually does, drawn
# ---------------------------------------------------------------------------
class _Lane:
    """A strip that shows this trigger's signals leaving the host.

    Left node is this host. The gate two-thirds along is the inline IDS/IPS and secure
    web gateway. The right edge is the internet. Firing streams one dot per on-wire
    signal out of the host; they hold at the gate for as long as the verdict is unknown
    — which is exactly the truth, because nothing is known until the run returns — and
    then pass through it, break against it, or scatter.

    The lane only ever animates a state the console actually observed. An environment
    failure scatters (error); it never draws a block, for the same reason the classifier
    never reports one."""

    def __init__(self, parent, anim, width=210, height=26, behind=None, on_emit=None):
        self.anim = anim
        self.on_emit = on_emit
        self.behind = behind or _bg_of(parent)
        self.w, self.h = int(width), int(height)
        self.scale = max(0.85, self.h / 26.0)
        self.cv = tk.Canvas(parent, width=self.w, height=self.h, bg=self.behind,
                            highlightthickness=0, bd=0, takefocus=0)
        self.dots = []
        self.total = 0
        self.emitted = 0
        self.verdict = None
        self.passes = 0            # for `ratio`: how many of the batch got through
        self.flash = 0.0
        self.rest = None
        self._job = None
        self._t = 0.0                 # own clock: a re-fire restarts the stream cleanly
        self._label = ""
        self._draw_static()
        self.redraw()

    # -- geometry ---------------------------------------------------------
    def _geom(self):
        return (10.0 * self.scale, self.w * 0.63, self.w - 7.0 * self.scale, self.h / 2.0)

    def resize(self, width):
        width = int(width)
        if width == self.w or width < 60:
            return
        self.w = width
        try:
            self.cv.configure(width=width)
        except Exception:
            return
        self._draw_static()
        self.redraw()

    # -- driving ----------------------------------------------------------
    def fire(self, count, label=""):
        """Start streaming `count` signals. The verdict is not known yet — that is the
        point of the hold at the gate."""
        self.total = max(1, min(int(count or 1), 14))
        self.emitted = 0
        self.dots = []
        self.verdict = None
        self.passes = 0
        self.rest = None
        self._t = 0.0
        self._label = label
        self._start()

    def resolve(self, state, passes=None, label=""):
        self.verdict = state
        self.passes = passes if passes is not None else (self.total if state == ALLOWED else 0)
        self.flash = 1.0
        self._label = label or self._label
        if not self.total:                       # resolved without ever firing (gated)
            self.total, self.emitted = 0, 0
            self.rest = state
            self.redraw()
            return
        self._start()

    def clear(self):
        """Reset to an unfired lane — and give the clock back.

        This has to unregister explicitly. `_frame` only retires itself once a verdict
        has finished playing out, and clearing is precisely the act of removing the
        verdict, so a cleared lane would otherwise animate an empty wire forever and pin
        the shared clock at 16ms. `run_all_done` clears every lane that never reached a
        rest state, so the leak fired on every single run-all."""
        self.dots, self.total, self.emitted = [], 0, 0
        self.verdict, self.rest, self.flash = None, None, 0.0
        self._t = 0.0
        if self._job is not None and self.anim is not None:
            self.anim.drop(self._job)            # the stored object: `self._frame` builds
        self._job = None                         # a fresh bound method every access, and
        self.redraw()                            # drop() matches on identity

    def _start(self):
        if self._job is not None or self.anim is None:
            self.redraw()
            return
        self._job = self.anim.add(self._frame)

    def _frame(self, dt, _elapsed):
        self._t += dt
        elapsed = self._t
        x_host, x_gate, x_end, _y = self._geom()
        span = max(1.0, x_gate - x_host)
        speed = span / 0.62                       # a signal reaches the gate in ~0.6s
        while self.emitted < self.total and elapsed > self.emitted * 0.11:
            self.dots.append({"x": x_host, "phase": self.emitted * 1.7,
                              "mode": "fly", "age": 0.0, "vy": 0.0})
            self.emitted += 1
            if callable(self.on_emit):
                try:
                    self.on_emit()
                except Exception:
                    pass
        held = 0
        for dot in self.dots:
            dot["age"] += dt
            if dot["mode"] == "fly":
                dot["x"] += speed * dt
                if dot["x"] >= x_gate - 3.0 * self.scale:
                    dot["x"] = x_gate - 3.0 * self.scale
                    if self.verdict is None:
                        dot["mode"] = "held"
                    else:                         # a verdict that lands mid-flight still
                        dot["mode"] = self._outcome()   # gets the full resolve animation
                        dot["age"] = 0.0
            if dot["mode"] == "held":
                held += 1
                if self.verdict is not None:
                    dot["mode"] = self._outcome()
                    dot["age"] = 0.0
            elif dot["mode"] == "pass":
                dot["x"] += speed * 1.5 * dt
            elif dot["mode"] == "hit":
                dot["x"] -= speed * 0.8 * dt * max(0.0, 1.0 - dot["age"] * 1.6)
                dot["vy"] += 90.0 * dt
            elif dot["mode"] == "lost":
                dot["x"] += speed * 0.25 * dt
                dot["vy"] += 40.0 * dt
        # queued signals stack up behind the gate rather than sitting on top of each other
        if held:
            slot = 0
            for dot in self.dots:
                if dot["mode"] == "held":
                    dot["x"] = x_gate - (3.0 + slot * 4.2) * self.scale
                    slot += 1
        self.dots = [d for d in self.dots
                     if not (d["mode"] == "pass" and d["x"] > x_end + 6)
                     and not (d["mode"] in ("hit", "lost") and d["age"] > 0.9)]
        self.flash = max(0.0, self.flash - dt * 1.6)
        self.redraw(elapsed)
        if self.verdict is not None and not self.dots and self.emitted >= self.total \
                and self.flash <= 0.02:
            self.rest = self.verdict
            self._job = None
            self.redraw()
            return False
        if not self.total and not self.dots:     # armed but never fired (a stopped run,
            self._job = None                     # a worker that died) — do not spin
            return False
        return True

    def _outcome(self):
        """Which way this dot goes — chosen per dot so a ratio can show both."""
        if self.verdict == ALLOWED:
            return "pass"
        if self.verdict == BLOCKED:
            return "hit"
        if self.verdict == RATIO:
            taken = sum(1 for d in self.dots if d["mode"] == "pass")
            return "pass" if taken < self.passes else "hit"
        return "lost"

    # -- painting ---------------------------------------------------------
    def _draw_static(self):
        """The wire and the host node never change between frames, so they are laid down
        once per resize instead of once per frame. This used to be ~30 of the ~40 canvas
        items the lane destroyed and recreated 56 times a second."""
        cv = self.cv
        try:
            cv.delete("static")
        except Exception:
            return
        x_host, _x_gate, x_end, y = self._geom()
        s = self.scale
        wire = _mix(self.behind, GUI_DIM, 0.42)
        x = x_host + 5 * s                       # the wire out to the world
        while x < x_end:
            cv.create_line(x, y, x + 2.6 * s, y, fill=wire, width=max(1, int(1.1 * s)),
                           tags="static")
            x += 6.4 * s
        cv.create_oval(x_host - 4.6 * s, y - 4.6 * s, x_host + 4.6 * s, y + 4.6 * s,
                       fill=_mix(self.behind, GUI_DIM, 0.22), outline="", tags="static")
        cv.create_oval(x_host - 2.6 * s, y - 2.6 * s, x_host + 2.6 * s, y + 2.6 * s,
                       fill=_mix(self.behind, GUI_DIM, 0.85), outline="", tags="static")

    def redraw(self, elapsed=0.0):
        """Repaint only what moves: the gate, the dots and the caption."""
        cv = self.cv
        try:
            cv.delete("live")
        except Exception:
            return
        x_host, x_gate, x_end, y = self._geom()
        s = self.scale
        live = self.verdict is None and self.emitted and self.emitted <= self.total \
            and self._job is not None
        state = self.verdict or self.rest
        colour = STATE_COLOR.get(state, GUI_FAINT)

        gate_h = self.h * 0.36
        gate_c = colour if state else _mix(self.behind, GUI_DIM, 0.62)
        if live:                                  # breathing while the verdict is unknown
            gate_c = _mix(gate_c, GUI_ACCENT_LT, 0.30 + 0.30 * math.sin(elapsed * 5.0))
        halo = max(self.flash, 0.35 if live else 0.0)
        if halo > 0.02:
            for i, t in ((5, 0.18), (3, 0.30)):
                cv.create_rectangle(x_gate - (1.6 + i * 0.5) * s, y - gate_h - i,
                                    x_gate + (1.6 + i * 0.5) * s, y + gate_h + i,
                                    fill=_mix(self.behind, gate_c, t * halo), outline="",
                                    tags="live")
        cv.create_rectangle(x_gate - 1.4 * s, y - gate_h, x_gate + 1.4 * s, y + gate_h,
                            fill=gate_c, outline="", tags="live")

        for dot in self.dots:
            r = 2.6 * s
            if dot["mode"] == "pass":
                c, fade = STATE_COLOR.get(ALLOWED, GUI_INFO), 1.0 - _ease((dot["x"] - x_gate) / max(1.0, x_end - x_gate))
                r *= 0.85
            elif dot["mode"] == "hit":
                c, fade = GUI_ACCENT, max(0.0, 1.0 - dot["age"] * 1.15)
            elif dot["mode"] == "lost":
                c, fade = GUI_CRIT, max(0.0, 1.0 - dot["age"] * 1.15)
            else:
                c, fade = GUI_ACCENT_LT, 1.0
            dy = dot["vy"] * dot["age"] * 0.35
            if dot["mode"] == "held":
                dy = math.sin(elapsed * 6.0 + dot["phase"]) * 1.2 * s
            cx, cy = dot["x"], y + dy
            body = _mix(self.behind, c, max(0.12, fade))
            cv.create_oval(cx - r * 2.1, cy - r * 1.5, cx + r * 2.1, cy + r * 1.5,
                           fill=_mix(self.behind, c, 0.22 * fade), outline="", tags="live")
            cv.create_oval(cx - r, cy - r, cx + r, cy + r, fill=body, outline="",
                           tags="live")

        # Only the wall-sized lane gets a caption; in a card row the status text to its
        # right already says what happened, and a label here would sit on the wire.
        if self._label and self.h >= 44:
            cv.create_text(x_end, 2, text=self._label, anchor="ne",
                           fill=_mix(self.behind, colour if state else GUI_DIM, 0.85),
                           font=(GUI_MONO, 10), tags="live")


class _Pulse:
    """The header's live wire: a scrolling trace that spikes once for every signal that
    leaves this host, tinted by the last state the console observed.

    It rests flat when nothing is on the wire, and that is deliberate on two counts. It
    is honest — the trace then means "traffic", not "the process is alive" — and it is
    free: an idle console runs no animation at all, instead of redrawing a polyline
    thirty times a second on a laptop that is doing nothing."""

    def __init__(self, canvas, anim, x, y, w, h, behind, tag="pulse"):
        self.cv, self.tag = canvas, tag
        self.x, self.y, self.w, self.h = x, y, w, h
        self.behind = behind
        self.anim = anim
        self.n = 84
        self.samples = [0.0] * self.n
        self.colour = GUI_ACCENT
        self._acc = 0.0
        self._beat = 0.0
        self._draw_in = 0.0
        self._job = None

    def move(self, x, y, w, h, behind=None):
        self.x, self.y, self.w, self.h = x, y, w, h
        if behind:
            self.behind = behind
        self._render()

    def blip(self, colour=None, amp=1.0):
        """A signal went out. Wake the trace if it was resting."""
        if colour:
            self.colour = colour
        self._beat = max(self._beat, amp)
        if self._job is None and self.anim is not None:
            self._job = self.anim.add(self._frame, ambient=True)

    def _frame(self, dt, _elapsed):
        self._acc += dt
        step = 1.0 / 45.0
        moved = False
        while self._acc >= step:
            self._acc -= step
            self.samples.pop(0)
            value = self._beat
            self._beat *= 0.55
            if value < 0.02:
                value = 0.0
            self.samples.append(value)
            moved = True
        # Redraw at ~30fps rather than on every tick, and stop entirely once the last
        # beat has scrolled off the end — a console with nothing on the wire animates
        # nothing at all.
        self._draw_in -= dt
        if moved and self._draw_in <= 0.0:
            self._draw_in = 1.0 / 30.0
            self._render()
        if self._beat < 0.02 and not any(self.samples):
            self._job = None
            self._render()
            return False
        return True

    def _render(self):
        cv = self.cv
        try:
            cv.delete(self.tag)
        except Exception:
            return False
        base = self.y + self.h / 2.0
        dx = self.w / float(self.n - 1)
        pts, glow = [], []
        for i, v in enumerate(self.samples):
            # a spike, then the ring-down: the trace reads as one beat, not a bar chart
            k = v
            if i and self.samples[i - 1] > v:
                k = -v * 0.45
            px = self.x + i * dx
            py = base - k * (self.h * 0.44)
            pts.extend((px, py))
            glow.extend((px, py))
        if len(pts) >= 4:
            # No smooth=True: at 84 samples across ~170px the points are 2px apart, so a
            # spline through them is invisible — and it is 26% of the render, forever.
            cv.create_line(*glow, fill=_mix(self.behind, self.colour, 0.30), width=5,
                           capstyle="round", joinstyle="round", tags=self.tag)
            cv.create_line(*pts, fill=_mix(self.behind, self.colour, 0.95), width=1,
                           capstyle="round", joinstyle="round", tags=self.tag)
        return True


def _draw_logo(cv, x=0, y=0, scale=1.0, behind=GUI_BG, tags=()):
    """Padlock silhouette crossed by a green EKG pulse — the same mark as the web
    build's SVG, now lit: a soft halo behind the shackle and a bright core on the
    pulse, so the identity reads as a light source rather than a line drawing."""
    def p(*vals):
        return [(x + v * scale) if i % 2 == 0 else (y + v * scale) for i, v in enumerate(vals)]

    ring = _mix(behind, GUI_ACCENT, 0.16)
    cv.create_oval(*p(2, 4, 38, 40), fill=ring, outline="", tags=tags)
    cv.create_oval(*p(6, 8, 34, 36), fill=_mix(behind, GUI_ACCENT, 0.10), outline="", tags=tags)
    edge = _mix(behind, GUI_DIM, 0.75)
    cv.create_arc(*p(13, 9, 27, 23), start=0, extent=180, style="arc", outline=edge,
                  width=max(1, int(2 * scale)), tags=tags)
    cv.create_line(*p(13, 16, 13, 22), fill=edge, width=max(1, int(2 * scale)), tags=tags)
    cv.create_line(*p(27, 16, 27, 22), fill=edge, width=max(1, int(2 * scale)), tags=tags)
    cv.create_polygon(_round_pts(*(p(9, 21, 31, 36) + [4 * scale])), smooth=True,
                      splinesteps=8, fill=_lift(behind, 0.13), outline=edge, width=1, tags=tags)
    cv.create_oval(*p(18, 25, 22, 29), fill=edge, outline="", tags=tags)
    cv.create_line(*p(20, 28, 20, 32), fill=edge, width=max(1, int(2 * scale)), tags=tags)
    ekg = p(0, 28, 12, 28, 16, 15, 21, 36, 25, 28, 40, 28)
    cv.create_line(*ekg, fill=_mix(behind, GUI_ACCENT, 0.45), width=max(2, int(5 * scale)),
                   capstyle="round", joinstyle="round", tags=tags)
    cv.create_line(*ekg, fill=GUI_ACCENT_LT, width=max(1, int(1.6 * scale)),
                   capstyle="round", joinstyle="round", tags=tags)


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


# ---------------------------------------------------------------------------
# a secondary window that lives in the same space as the console
# ---------------------------------------------------------------------------
class _GlassDialog:
    """A Toplevel with the console's backdrop and a single frosted panel on it.

    Content goes into `self.body`, a plain Frame whose background is already the frost
    colour, so ordinary Labels blend into the pane. Call `show()` once the content is
    packed: it measures, sizes the window to fit, and paints the backdrop behind it."""

    PAD = 16          # backdrop margin around the pane
    INSET = 18        # pane margin around the content

    def __init__(self, root, title, min_width=520, resizable=False, fy=0.42):
        self.root = root
        self.win = tk.Toplevel(root)
        self.win.title(title)
        self.win.configure(bg=GUI_BG)
        self.win.transient(root)
        self.min_width = min_width
        self.behind = _hx(*_backdrop_rgb(0.5, fy))
        self.frost = _frost_at(0.5, fy, lift=0.15)
        self.cv = tk.Canvas(self.win, bg=GUI_BG, highlightthickness=0, bd=0)
        self.cv.pack(fill="both", expand=True)
        self.body = tk.Frame(self.cv, bg=self.frost)
        self.item = self.cv.create_window(self.PAD + self.INSET, self.PAD + self.INSET,
                                          anchor="nw", window=self.body)
        self._img = self._src = None
        self._wraps = []
        self._size = (0, 0)
        self._pending = None
        if resizable:
            try:
                self.win.bind("<Configure>", self._on_configure)
            except Exception:
                pass
        else:
            try:
                self.win.resizable(False, False)
            except Exception:
                pass
        try:
            self.win.protocol("WM_DELETE_WINDOW", self.destroy)
        except Exception:
            pass

    def wrap(self, widget, slack=0):
        """Register a label whose wraplength should follow the pane width."""
        self._wraps.append((widget, slack))
        return widget

    def show(self, width=None, height=None):
        try:
            self.body.update_idletasks()
        except Exception:
            pass
        bw = width or max(self.min_width, _num(self.body.winfo_reqwidth(), self.min_width))
        bh = height or _num(self.body.winfo_reqheight(), 200)
        w = int(bw + 2 * (self.PAD + self.INSET))
        h = int(bh + 2 * (self.PAD + self.INSET))
        try:                                     # open over the console, not in a corner
            px = _num(self.root.winfo_rootx(), 0)
            py = _num(self.root.winfo_rooty(), 0)
            pw = _num(self.root.winfo_width(), w)
            ph = _num(self.root.winfo_height(), h)
            x = max(0, px + (pw - w) // 2)
            y = max(0, py + max(24, (ph - h) // 3))
            self.win.geometry("%dx%d+%d+%d" % (w, h, x, y))
        except Exception:
            try:
                self.win.geometry("%dx%d" % (w, h))
            except Exception:
                pass
        self.repaint(w, h)

    def repaint(self, w=None, h=None):
        w = _num(w or self.win.winfo_width(), 0)
        h = _num(h or self.win.winfo_height(), 0)
        if w < 80 or h < 80 or (w, h) == self._size:
            return
        self._size = (w, h)
        try:
            self.cv.configure(width=w, height=h)
            self.cv.delete("chrome")
        except Exception:
            return
        try:
            self._img, self._src = _backdrop_image(w, h)
            self.cv.create_image(0, 0, anchor="nw", image=self._img, tags="chrome")
        except Exception:
            pass
        _glass(self.cv, self.PAD, self.PAD, w - self.PAD, h - self.PAD, self.frost,
               self.behind, radius=18, shadow=5, tags="chrome")
        inner = w - 2 * (self.PAD + self.INSET)
        try:
            self.cv.itemconfigure(self.item, width=inner,
                                  height=h - 2 * (self.PAD + self.INSET))
        except Exception:
            pass
        for widget, slack in self._wraps:
            try:
                widget.configure(wraplength=max(160, inner - slack))
            except Exception:
                pass

    def _on_configure(self, event=None):
        if event is not None and getattr(event, "widget", None) is not self.win:
            return
        try:
            if self._pending is not None:
                self.win.after_cancel(self._pending)
            self._pending = self.win.after(120, lambda: self.repaint())
        except Exception:
            pass

    def destroy(self):
        try:
            self.win.destroy()
        except Exception:
            pass


class _Tile:
    """A rounded, lifted pane *inside* another pane, packed like an ordinary widget.

    Same drawn-surface trick as the trigger cards: a canvas paints the rounded fill and
    the content frame floats on top of it (Tk always draws embedded windows above canvas
    items). It re-measures itself whenever its width changes or its content moves, so
    callers only have to remember `sync()` after they finish packing into `body`."""

    def __init__(self, parent, pad=13, lift=0.06, radius=13, glow=None):
        self.behind = _bg_of(parent)
        self.fill = _lift(self.behind, lift)
        self.pad, self.radius, self.glow = pad, radius, glow
        self.cv = tk.Canvas(parent, bg=self.behind, highlightthickness=0, bd=0, height=12,
                            takefocus=0)
        self.body = tk.Frame(self.cv, bg=self.fill)
        self.item = self.cv.create_window(pad, pad, anchor="nw", window=self.body)
        self._w = 0
        try:
            self.cv.bind("<Configure>", self._on_configure)
        except Exception:
            pass

    def _on_configure(self, event=None):
        w = _num(getattr(event, "width", None), 0) or _num(self.cv.winfo_width(), 0)
        if w < 40 or w == self._w:               # only a width change needs new geometry
            return
        self._w = w
        try:
            self.cv.itemconfigure(self.item, width=w - 2 * self.pad)
        except Exception:
            return
        self.sync()

    def sync(self):
        try:
            self.body.update_idletasks()
            h = _num(self.body.winfo_reqheight(), 30) + 2 * self.pad
            w = _num(self.cv.winfo_width(), 0)
            self.cv.configure(height=h)
            self.cv.delete("chrome")
        except Exception:
            return
        if w > 40:
            _glass(self.cv, 1, 1, w - 2, h - 4, self.fill, self.behind, radius=self.radius,
                   shadow=2, glow=self.glow, tags="chrome")

    def pack(self, **kw):
        self.cv.pack(**kw)
        return self

    def pack_forget(self):
        self.cv.pack_forget()


def _label(parent, text="", fg=GUI_INK, font=None, **kw):
    """A Label that inherits its parent's surface — the only way to keep text from
    stamping a differently-shaded rectangle onto a frosted pane."""
    kw.setdefault("anchor", "w")
    kw.setdefault("justify", "left")
    return tk.Label(parent, text=text, fg=fg, bg=_bg_of(parent),
                    font=font or (GUI_FONT, 10), **kw)


def _descendants(widget, acc=None):
    """A widget and everything inside it — used to bind pointer events to a whole
    card at once."""
    acc = [widget] if acc is None else acc
    try:
        children = widget.winfo_children()
    except Exception:
        return acc
    for child in children:
        acc.append(child)
        _descendants(child, acc)
    return acc


def _well(parent, height=8):
    """A recessed pane for raw output: darker than the glass it sits in, so a wall of
    monospace reads as *inside* the surface rather than painted on it."""
    frost = _bg_of(parent)
    return tk.Text(parent, height=height, bg=_sink(frost, 0.42), fg=GUI_INK,
                   insertbackground=GUI_INK, font=(GUI_MONO, 9), relief="flat",
                   highlightthickness=1, highlightbackground=_lift(frost, 0.10),
                   wrap="none", padx=10, pady=8, bd=0)


# ---------------------------------------------------------------------------
# the console window
# ---------------------------------------------------------------------------
def _fit_to_work_area(root, want_w, want_h):
    """Open at the requested size, or as much of it as the screen can actually show.

    A hard-coded geometry is a bug waiting for a 1366x768 laptop: the window opens taller
    than the desktop, the bottom of the card list is unreachable and the window sits over
    the taskbar — you cannot get to the Start button. Windows can report the work area
    (the desktop minus the taskbar) exactly, so ask it; elsewhere take the screen less a
    rough allowance for a panel."""
    sw = _num(root.winfo_screenwidth(), want_w)
    sh = _num(root.winfo_screenheight(), want_h)
    x0, y0 = 0, 0
    if sys.platform == "win32":
        try:
            import ctypes

            class _RECT(ctypes.Structure):
                _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                            ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
            rect = _RECT()
            if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
                x0, y0 = int(rect.left), int(rect.top)
                sw, sh = int(rect.right - rect.left), int(rect.bottom - rect.top)
        except Exception:                        # fall back to the raw screen size
            pass
    else:
        sh = max(240, sh - 60)
    w = max(560, min(want_w, sw - 40))
    h = max(400, min(want_h, sh - 40))
    try:
        root.geometry("%dx%d+%d+%d" % (w, h, x0 + max(0, (sw - w) // 2),
                                       y0 + max(0, (sh - h) // 3)))
        root.minsize(min(760, w), min(520, h))
    except Exception:
        pass
    return w, h


def run_gui(settings, triggers, app, config_dir=None, profiles=None):
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
    _fit_to_work_area(root, 1140, 820)
    root.configure(bg=GUI_BG)
    _set_window_icon(root)

    anim = _Anim(root)
    by_id = {t.id: t for t in triggers}
    cards = {}                                  # trigger id -> widget/var bundle
    pane_owner = {}                             # widget path -> the card it belongs to
    run_state = {"running": False, "stop": False}
    observed = {}                               # state -> count, this session
    ui_queue = queue.Queue()                    # background run threads -> main thread ONLY

    gated = [t for t in triggers if t.gated_disabled(settings)]
    enabled_triggers = [t for t in triggers if not t.unavailable_reason(settings)]
    planned_signals = sum(t.on_wire_count(settings) for t in enabled_triggers)

    HEAD_H = 200 if gated else 150
    BAR_Y0, BAR_H = 14, 118
    SIDE = 20                                   # card gutter
    CARD_PAD, CARD_GAP = 13, 11

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
            root.after(60, pump)
        except tk.TclError:
            pass

    # ---- the lit backdrop --------------------------------------------------
    # Only the header gets the painted field, and only the strip it actually shows: the
    # header never scrolls, so its image is laid down once and never moves. The card
    # stage gets a flat tone instead (see where it is created) — anything covering a
    # scrolling surface has to be re-rendered on every tick.
    STAGE_FY0 = 0.12                            # the header shows the field above this
    art = {"img": None, "src": None, "w": 0}

    def ensure_backdrop(w):
        if art["img"] is not None and abs(art["w"] - w) < 24:
            return art["img"]
        try:
            art["img"], art["src"] = _backdrop_image(w, HEAD_H, 0.0, STAGE_FY0)
            art["w"] = w
        except Exception:                        # no PhotoImage (or no memory): flat floor
            art["img"] = None
        return art["img"]

    # ---- header ----------------------------------------------------------
    head = tk.Canvas(root, bg=GUI_BG, highlightthickness=0, bd=0, height=HEAD_H)
    head.pack(fill="x", side="top")
    head_frost = _frost_at(0.5, 0.05, lift=0.16)
    head_behind = _hx(*_backdrop_rgb(0.5, 0.06))
    bar = tk.Frame(head, bg=head_frost)
    bar_item = head.create_window(34, BAR_Y0 + 72, anchor="nw", window=bar, height=34)
    pulse = _Pulse(head, anim, 0, 0, 10, 10, head_frost)

    def paint_head(w):
        try:
            head.delete("chrome")
        except Exception:
            return
        img = ensure_backdrop(max(w, 400))
        if img is not None:
            head.create_image(0, 0, anchor="nw", image=img, tags="chrome")
        _glass(head, SIDE - 2, BAR_Y0, w - SIDE + 2, BAR_Y0 + BAR_H, head_frost,
               head_behind, radius=20, shadow=5, tags="chrome")
        _draw_logo(head, 34, BAR_Y0 + 15, 1.0, behind=head_frost, tags="chrome")
        head.create_text(86, BAR_Y0 + 24, text=APP_NAME, anchor="w", fill=GUI_INK,
                         font=(GUI_FONT, 19, "bold"), tags="chrome")
        head.create_text(88, BAR_Y0 + 48, anchor="w", fill=GUI_FAINT, font=(GUI_FONT, 9),
                         text="inline security-stack console  ·  local result only, nothing uploaded",
                         tags="chrome")
        head.create_text(w - SIDE - 20, BAR_Y0 + 24, anchor="e", fill=GUI_ACCENT,
                         font=(GUI_MONO, 10, "bold"), tags="chrome",
                         text=f"{planned_signals} signals · {len(enabled_triggers)} triggers")
        head.create_text(w - SIDE - 20, BAR_Y0 + 46, anchor="e", fill=GUI_FAINT,
                         font=(GUI_MONO, 9), text=f"v{__version__}", tags="chrome")
        if w > 940:                              # the live wire needs room; small windows drop it
            px = w - SIDE - 258
            pulse.move(px - 176, BAR_Y0 + 10, 176, 34, head_frost)
            head.create_text(px - 176, BAR_Y0 + 52, anchor="w", fill=GUI_FAINT,
                             font=(GUI_MONO, 8), text="signal wire",
                             tags=("chrome", "wirecap"))
        else:
            pulse.move(-500, -500, 10, 10, head_frost)
        head.coords(bar_item, 34, BAR_Y0 + 72)
        head.itemconfigure(bar_item, width=w - 68)
        if gated:
            _glass(head, SIDE - 2, BAR_Y0 + BAR_H + 10, w - SIDE + 2, HEAD_H - 8,
                   _frost_at(0.5, 0.17, lift=0.11), _hx(*_backdrop_rgb(0.5, 0.17)),
                   radius=14, shadow=3, glow=GUI_WARN, tags="chrome")
            head.create_rectangle(SIDE + 8, BAR_Y0 + BAR_H + 22, SIDE + 11, HEAD_H - 20,
                                  fill=GUI_WARN, outline="", tags="chrome")
            head.create_text(
                SIDE + 24, BAR_Y0 + BAR_H + 20, anchor="nw", fill=GUI_DIM,
                font=(GUI_FONT, 9), width=max(200, w - 2 * SIDE - 60), tags="chrome",
                text=(f"{len(gated)} trigger(s) reach LIVE suspect infrastructure / live Tor "
                      "nodes and are disabled (enable_live_suspect_hosts is false in "
                      "settings.yaml). Enable only in a lab you control."))
        paint_tally(w)
        try:
            head.tag_raise("pulse")              # the live wire stays above the repaint
        except Exception:
            pass

    def paint_tally(w=None):
        """What this host has observed so far, in the header. It is this console's own
        read and the strip says so — the inline stack's console stays the authority for
        allowed-vs-blocked, and a running tally must not be mistaken for its verdict."""
        w = _num(w or head.winfo_width(), 0)
        try:
            head.delete("tally")
        except Exception:
            return
        if w <= 940 or not observed:
            return
        try:
            head.delete("wirecap")               # the tally takes the caption's line
        except Exception:
            pass
        cx = w - SIDE - 258 - 176
        item = head.create_text(cx, BAR_Y0 + 52, anchor="w", fill=GUI_FAINT,
                                font=(GUI_MONO, 8), text="observed", tags="tally")
        try:
            cx = head.bbox(item)[2] + 9
        except Exception:
            cx += 58
        for state in (BLOCKED, ALLOWED, RATIO, ERROR, INVALID):
            n = observed.get(state)
            if not n:
                continue
            colour = STATE_COLOR.get(state, GUI_DIM)
            head.create_oval(cx, BAR_Y0 + 49, cx + 6, BAR_Y0 + 55, fill=colour,
                             outline="", tags="tally")
            item = head.create_text(cx + 10, BAR_Y0 + 52, anchor="w", fill=_lift(colour, 0.2),
                                    font=(GUI_MONO, 8), text=f"{n} {state}", tags="tally")
            try:
                box = head.bbox(item)
                cx = box[2] + 10
            except Exception:
                cx += 62

    # ---- card stage ------------------------------------------------------
    # Flat, not a gradient, and deliberately so. Anything that covers the whole scrolling
    # surface — a pinned image OR a band gradient — has to be re-rendered across the
    # entire viewport on every scroll tick; measured, either one triples the cost of a
    # scroll. The canvas background is painted by X once and costs nothing to scroll, and
    # since cards cover the width, all that is ever visible of it is a 20px gutter and
    # the 11px gaps between panes — where a gradient is indistinguishable from a tone.
    stage = tk.Canvas(root, bg=_hx(*_backdrop_rgb(0.5, 0.55)), highlightthickness=0, bd=0)
    stage.pack(fill="both", expand=True)
    scroll_state = {"first": 0.0, "last": 1.0, "drag": None, "settling": False,
                    "job": None}

    def on_scrolled():
        """Runs on every scroll tick, so it does the least it possibly can: the field is
        painted in canvas coordinates and scrolls with the content, leaving only the
        scrollbar to move.

        It also puts hover to sleep for the duration. Scrolling drags whole cards under a
        stationary pointer, so Tk fires Enter/Leave for each one — without this, a flick
        of the wheel repaints a dozen panes for a pointer that never moved."""
        try:
            paint_scrollbar(stage.canvasy(0))
        except Exception:
            pass
        if not scroll_state["settling"]:
            scroll_state["settling"] = True
            for card in cards.values():
                if card["hover"]:
                    card["hover"] = card["hover_to"] = 0.0
                    draw_pane(card)
        try:
            if scroll_state["job"] is not None:
                root.after_cancel(scroll_state["job"])
            scroll_state["job"] = root.after(140, settle_scroll)
        except Exception:
            scroll_state["settling"] = False

    def settle_scroll():
        """The scroll has stopped: light whatever the pointer is genuinely over now."""
        scroll_state["job"] = None
        scroll_state["settling"] = False
        try:
            widget = root.winfo_containing(*root.winfo_pointerxy())
        except Exception:
            return
        for _ in range(8):                       # walk up to the card that owns it
            if widget is None:
                return
            tid = pane_owner.get(str(widget))
            if tid:
                set_hover(tid, 1.0)
                return
            widget = getattr(widget, "master", None)

    def paint_scrollbar(top=None):
        try:
            stage.delete("sbar")
            w = _num(stage.winfo_width(), 0)
            vh = _num(stage.winfo_height(), 0)
            top = stage.canvasy(0) if top is None else top
        except Exception:
            return
        if not w or not vh:
            return
        first, last = scroll_state["first"], scroll_state["last"]
        if last - first >= 0.999:
            return
        x = w - 11
        y0, y1 = top + 8, top + vh - 8
        span = y1 - y0
        stage.create_polygon(_round_pts(x, y0, x + 5, y1, 2.5), smooth=True, splinesteps=6,
                             fill=_lift(GUI_BG, 0.09), outline="", tags="sbar")
        ty0 = y0 + span * first
        ty1 = max(ty0 + 26, y0 + span * last)
        stage.create_polygon(_round_pts(x, ty0, x + 5, ty1, 2.5), smooth=True, splinesteps=6,
                             fill=_mix(GUI_BG, GUI_ACCENT, 0.42), outline="", tags="sbar")

    def on_yview(first, last):
        scroll_state["first"], scroll_state["last"] = float(first), float(last)
        on_scrolled()

    try:
        stage.configure(yscrollcommand=on_yview)
    except Exception:
        pass

    def wheel(event, delta):
        # bind_all reaches every widget in the application, dialogs included, so the
        # console's own list only scrolls when the pointer is actually over the console.
        try:
            if event is not None and event.widget.winfo_toplevel() is not root:
                return
            stage.yview_scroll(delta, "units")
        except Exception:
            pass

    stage.bind_all("<MouseWheel>",
                   lambda e: wheel(e, int(-1 * (e.delta / 120)) if e.delta else 0))
    stage.bind_all("<Button-4>", lambda e: wheel(e, -3))
    stage.bind_all("<Button-5>", lambda e: wheel(e, 3))
    stage.bind_all("<Prior>", lambda e: wheel(e, -12))
    stage.bind_all("<Next>", lambda e: wheel(e, 12))

    def sbar_press(event):
        w = _num(stage.winfo_width(), 0)
        if w and event.x >= w - 18:
            scroll_state["drag"] = event.y
            sbar_drag(event)

    def sbar_drag(event):
        if scroll_state["drag"] is None:
            return
        vh = _num(stage.winfo_height(), 1)
        span = max(1, vh - 16)
        frac = (event.y - 8) / float(span)
        visible = scroll_state["last"] - scroll_state["first"]
        try:
            stage.yview_moveto(max(0.0, min(1.0, frac - visible / 2.0)))
        except Exception:
            pass

    stage.bind("<Button-1>", sbar_press)
    stage.bind("<B1-Motion>", sbar_drag)
    stage.bind("<ButtonRelease-1>", lambda e: scroll_state.update(drag=None))

    # ---- shared card helpers ---------------------------------------------
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

    def cycle_confirmed(tid):
        """Advance this trigger's console attestation and store it on the ledger record."""
        card = cards.get(tid)
        if not card or not card.get("seq"):
            return
        card["confirmed"] = CONFIRM_CYCLE.get(card.get("confirmed", CONFIRMED_UNSET),
                                              CONFIRMED_UNSET)
        try:
            app.ledger.set_confirmed(card["seq"], card["confirmed"])
        except ValueError:
            return
        card["confirm"].configure(text=CONFIRM_CYCLE_LABEL[card["confirmed"]],
                                  fg=CONFIRM_CYCLE_FG[card["confirmed"]])

    def set_result(tid, out):
        c = cards.get(tid)
        if not c:
            return
        state = out.get("state", ERROR)
        c["runs"] += 1
        observed[state] = observed.get(state, 0) + 1
        paint_tally()
        ratio = out.get("ratio") or {}
        c["lane"].resolve(state, passes=ratio.get("reached"),
                          label=(f"{ratio['blocked']}/{ratio['total']} blocked"
                                 if ratio else state))
        pulse.blip(STATE_COLOR.get(state, GUI_ACCENT), 1.0)
        runs = f"{c['runs']} run" + ("" if c["runs"] == 1 else "s")
        _set_status(tid, f"last run {time.strftime('%H:%M:%S')}  ·  {runs}",
                    STATE_FG.get(state, GUI_DIM))
        c["reason"].configure(text=out.get("reason", ""))
        c["reason"].pack(anchor="w", fill="x", pady=(8, 0))
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
            c["copy"].pack(side="left", padx=(8, 0))
        c["seq"] = out.get("seq")
        if c["seq"]:
            c["confirmed"] = CONFIRMED_UNSET
            c["confirm"].configure(text=CONFIRM_CYCLE_LABEL[CONFIRMED_UNSET],
                                   fg=CONFIRM_CYCLE_FG[CONFIRMED_UNSET])
            c["confirm"].pack(side="left", padx=(8, 0))
        c["fire"].configure(state="normal")
        reflow(tid)

    def fire(tid):
        if run_state["running"]:
            return
        t = by_id.get(tid)
        if t is None:
            return
        c = cards.get(tid)
        if c:
            c["fire"].configure(state="disabled")
            c["lane"].fire(t.on_wire_count(settings), label="in flight")
        _set_status(tid, "running…", GUI_DIM)

        def work():
            try:
                _t, out = app.run(tid, {})
            except Exception as e:                 # never let a run thread die silently
                out = {"state": ERROR, "reason": f"{e.__class__.__name__}: {e}"}
            ui_queue.put(lambda: set_result(tid, out))
        threading.Thread(target=work, daemon=True).start()

    def arm_lane(tid):
        card = cards.get(tid)
        if card:
            card["lane"].fire(by_id[tid].on_wire_count(settings), label="in flight")
            _set_status(tid, "running…", GUI_DIM)

    def run_all_worker(ids):
        n = len(ids)
        for i, tid in enumerate(ids):
            if run_state["stop"]:
                break
            ui_queue.put(lambda tid=tid: arm_lane(tid))
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
        ids = [t.id for t in triggers if not by_id[t.id].unavailable_reason(settings)]
        if not ids:
            return
        run_state["running"], run_state["stop"] = True, False
        run_all_btn.pack_forget()
        stop_btn.pack(side="left", before=manifest_btn.cv)
        for tid in ids:
            c = cards.get(tid)
            if c:
                c["fire"].configure(state="disabled")
            _set_status(tid, "queued…", GUI_DIM)
        threading.Thread(target=run_all_worker, args=(ids,), daemon=True).start()

    def run_all_done():
        run_state["running"] = False
        stop_btn.pack_forget()
        run_all_btn.pack(side="left", before=manifest_btn.cv)
        status_var.set("")
        for tid in cards:
            if not by_id[tid].unavailable_reason(settings):
                cards[tid]["fire"].configure(state="normal")
                if cards[tid]["lane"].rest is None:       # queued but never reached
                    cards[tid]["lane"].clear()

    def stop_run_all():
        run_state["stop"] = True
        status_var.set("Stopping after the current trigger…")

    # ---- toolbar ---------------------------------------------------------
    run_all_btn = _gui_button(bar, "▶   Run all enabled", start_run_all, primary=True, anim=anim)
    run_all_btn.pack(side="left")
    stop_btn = _gui_button(bar, "■   Stop", stop_run_all, anim=anim)   # only while running
    manifest_btn = _gui_button(bar, "☰   Signal manifest",
                               lambda: open_manifest_dialog(root, triggers, settings),
                               anim=anim)
    manifest_btn.pack(side="left", padx=(8, 0))
    _gui_button(bar, "🎤   Presenter mode",
                lambda: open_presenter_picker(root, app, triggers, settings, profiles),
                anim=anim).pack(side="left", padx=(8, 0))
    _gui_button(bar, "⬇   Save report",
                lambda: open_report_dialog(root, app, triggers, settings),
                anim=anim).pack(side="left", padx=(8, 0))
    _gui_button(bar, "⟳   Updates", lambda: open_update_dialog(root),
                anim=anim).pack(side="right")
    status_var = tk.StringVar(value="")
    tk.Label(bar, textvariable=status_var, fg=GUI_DIM, bg=head_frost,
             font=(GUI_MONO, 9)).pack(side="left", padx=14)

    # ---- one card --------------------------------------------------------
    def _make_pane(parent, title, tid):
        """L3 detail pane: a toggle line + a recessed well that only appears once there
        is content and the presenter opens it. Returns (set_content, reset)."""
        frost = _bg_of(parent)
        state = {"open": False, "text": ""}
        btn = tk.Label(parent, fg=GUI_FAINT, bg=frost, font=(GUI_MONO, 9), cursor="hand2",
                       anchor="w")
        box = _well(parent)

        def _render():
            btn.configure(text=("▾  " if state["open"] else "▸  ") + title,
                          fg=(GUI_DIM if state["open"] else GUI_FAINT))
            if state["open"]:
                box.configure(state="normal")
                box.delete("1.0", "end")
                box.insert("1.0", state["text"] or "(no output)")
                box.configure(state="disabled")
                box.pack(fill="x", pady=(5, 0))
            else:
                box.pack_forget()

        def toggle(_e=None):
            state["open"] = not state["open"]
            _render()
            reflow(tid)
        btn.bind("<Button-1>", toggle)

        def set_content(text):
            state["text"] = text or ""
            if state["text"]:
                btn.pack(anchor="w", fill="x", pady=(9, 0))
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

    def build_card(t, fy):
        # Every card in a class shares one pane tone, sampled from the light at that
        # depth: the families read as families, and the glass still varies down the
        # window instead of stamping one flat colour 53 times.
        behind = _hx(*_backdrop_rgb(0.5, fy))
        unavailable = t.unavailable_reason(settings)
        disabled = bool(unavailable)
        gated_live = t.gated_disabled(settings)
        frost = _frost_at(0.5, fy, lift=0.055 if disabled else 0.145)
        sev = SEV_COLOR.get(t.severity, GUI_FAINT)

        frame = tk.Frame(stage, bg=frost)
        win = stage.create_window(-2000, 0, anchor="nw", window=frame)
        expand = {"open": False}

        # ---- L1: always-visible summary header (click to expand) ----------
        head_row = tk.Frame(frame, bg=frost, cursor="hand2")
        head_row.pack(fill="x")
        caret = tk.Label(head_row, text="▸", fg=GUI_FAINT, bg=frost, font=(GUI_MONO, 9))
        caret.pack(side="left", padx=(2, 8))
        bead = tk.Canvas(head_row, width=10, height=10, bg=frost, highlightthickness=0,
                         bd=0, takefocus=0)
        bead.create_oval(0, 0, 9, 9, fill=_mix(frost, sev, 0.35), outline="")
        bead.create_oval(2, 2, 7, 7, fill=sev, outline="")
        bead.pack(side="left", padx=(0, 9))
        title = tk.Label(head_row, text=t.label, fg=(GUI_FAINT if disabled else GUI_INK),
                         bg=frost, font=(GUI_FONT, 11, "bold"), anchor="w", justify="left")
        title.pack(side="left")
        if "hits_live_suspect_hosts" in t.flags:
            _chip_row(head_row, [("LIVE", GUI_WARN)], height=17).pack(side="left", padx=9)
        status = tk.Label(head_row, text=("disabled (live)" if gated_live
                                          else "not configured" if disabled else "not run"),
                          fg=(GUI_GOLD if disabled else GUI_FAINT), bg=frost,
                          font=(GUI_MONO, 9))
        status.pack(side="right", padx=(10, 2))
        lane = _Lane(head_row, anim, width=232, height=26, behind=frost,
                     on_emit=lambda: pulse.blip(GUI_ACCENT_LT, 0.85))
        if not disabled:
            lane.cv.pack(side="right", padx=(14, 0))

        # ---- L2: context + action, hidden until the row is expanded -------
        # NB: a widget's own -pady is a single distance; the (top, bottom) tuple form is
        # only valid on .pack() (see toggle_expand), never in a constructor.
        body_l2 = tk.Frame(frame, bg=frost)
        wraps = []

        chips = [(t.cls, GUI_ACCENT), (t.mode, GUI_DIM)]
        if t.threat_class:
            chips.append((t.threat_class, GUI_DIM))
        chips.append((t.severity, sev))
        wire_n = t.on_wire_count(settings)       # iprep fans out; see on_wire_count
        chips.append((f"{wire_n} signal" + ("" if wire_n == 1 else "s"), GUI_INFO))
        _chip_row(body_l2, chips).pack(anchor="w", pady=(10, 0))

        if t.expected_fire:
            lbl = _label(body_l2, t.expected_fire, GUI_DIM, (GUI_MONO, 9))
            lbl.pack(fill="x", pady=(10, 0))
            wraps.append(lbl)
        if t.talking_point:
            lbl = _label(body_l2, t.talking_point, GUI_FAINT, (GUI_FONT, 9))
            lbl.pack(fill="x", pady=(5, 0))
            wraps.append(lbl)
        hint = t.console_hint_text()
        if hint:
            lbl = _label(body_l2, "↳ " + hint, GUI_INFO, (GUI_FONT, 9))
            lbl.pack(fill="x", pady=(5, 0))
            wraps.append(lbl)

        actions = tk.Frame(body_l2, bg=frost)
        actions.pack(fill="x", pady=(12, 0))
        fire_btn = _gui_button(actions, "Fire", lambda tid=t.id: fire(tid), primary=True,
                               anim=anim)
        if disabled:
            fire_btn.configure(state="disabled",
                               text="Disabled (live)" if gated_live else "Not configured")
        fire_btn.pack(side="left")
        copy_btn = _gui_button(actions, "Copy verification key",
                               lambda tid=t.id: copy_text(cards[tid].get("verify_key"), tid),
                               anim=anim)
        # The presenter's own read of the customer's console. Deliberately a SEPARATE
        # record from what this host observed — the two are different kinds of evidence
        # and the report keeps them in different columns.
        confirm_btn = _gui_button(actions, CONFIRM_CYCLE_LABEL[CONFIRMED_UNSET],
                                  lambda tid=t.id: cycle_confirmed(tid), anim=anim)
        kv = tk.Label(actions, text="", fg=GUI_DIM, bg=frost, font=(GUI_MONO, 9))
        kv.pack(side="right", padx=(10, 2))

        reason = _label(body_l2, "", GUI_INK, (GUI_FONT, 9))
        wraps.append(reason)

        # ---- L3: detail panes, each disclosed on demand -------------------
        set_cmd, _r1 = _make_pane(body_l2, "command/payload details", t.id)
        set_flow, _r2 = _make_pane(body_l2, "5-tuple details", t.id)
        set_verify, _r3 = _make_pane(body_l2, "verification key (paste into the console)",
                                     t.id)
        panes = {"cmd": set_cmd, "flow": set_flow, "verify": set_verify}

        def set_pane(which, text):
            fn = panes.get(which)
            if fn:
                fn(text)

        if disabled:
            reason.configure(text=("Reaches live suspect infrastructure — enable "
                                   "enable_live_suspect_hosts in a controlled lab to run it."
                                   if gated_live else unavailable), fg=GUI_GOLD)
            reason.pack(anchor="w", fill="x", pady=(8, 0))

        def toggle_expand(_e=None):
            expand["open"] = not expand["open"]
            caret.configure(text="▾" if expand["open"] else "▸")
            if expand["open"]:
                body_l2.pack(fill="x", pady=(0, 4))
            else:
                body_l2.pack_forget()
            reflow(t.id)
            if expand["open"]:
                reveal(t.id)
        for w in (head_row, caret, bead, title, status):
            w.bind("<Button-1>", toggle_expand)
        bind_hover(frame, t.id)

        cards[t.id] = {"status": status, "reason": reason, "kv": kv, "fire": fire_btn,
                       "copy": copy_btn, "confirm": confirm_btn, "set_pane": set_pane,
                       "runs": 0, "verify_key": "", "seq": None, "lane": lane,
                       "confirmed": CONFIRMED_UNSET, "frame": frame, "win": win,
                       "frost": frost, "behind": behind, "sev": sev, "wraps": wraps,
                       "disabled": disabled, "y": 0, "h": 0, "tag": "pane-" + t.id,
                       "hover": 0.0, "hover_to": 0.0, "box": None}

    # ---- pointer response: the pane under the cursor lights its own edge ---
    def draw_pane(card):
        """Redraw one card's surface. The content frame covers the pane's middle, so
        what the pointer actually lights is the rim: the stroke picks up the trigger's
        severity colour and the pane starts throwing a little of it onto the backdrop."""
        box = card.get("box")
        if not box:
            return
        x0, top, x1, bottom = box
        k = card["hover"]
        try:
            stage.delete(card["tag"])
        except Exception:
            return
        tags = ("chrome", card["tag"], card.get("row", "row?"))
        _glass(stage, x0, top, x1, bottom, card["frost"], card["behind"], radius=15,
               shadow=4, glow=(card["sev"] if k > 0.02 else None), glow_k=k,
               stroke=_mix(_lift(card["frost"], 0.20 + 0.26 * k), card["sev"], 0.5 * k),
               tags=tags)
        rail = _round_pts(x0 + 4, top + 11, x0 + 7, bottom - 11, 1.5)
        stage.create_polygon(rail, smooth=True, splinesteps=4, outline="", tags=tags,
                             fill=(_mix(card["frost"], card["sev"], 0.45)
                                   if card["disabled"] else card["sev"]))

    def set_hover(tid, target):
        """Light or unlight one pane, in a single redraw.

        This used to fade over ~8 frames, which is fine for one card and ruinous while
        scrolling: cards streaming under a stationary pointer each started their own
        fade, and every frame of every fade redrew a whole glass stack. Measured, the
        Enter/Leave events themselves cost 0.27 ms per scroll tick and the redraws they
        triggered cost 1.84 ms. A rim that lights at once is not worse to look at."""
        card = cards.get(tid)
        if not card or card["hover"] == target or scroll_state["settling"]:
            return
        card["hover"] = card["hover_to"] = target
        draw_pane(card)

    def bind_hover(widget, tid):
        """Enter/Leave fire on every descendant, so a leave is only believed once the
        pointer is genuinely outside the card's rectangle."""
        for w in _descendants(widget):
            pane_owner[str(w)] = tid             # so a settled scroll can find the card

        def enter(_e=None):
            set_hover(tid, 1.0)

        def leave(_e=None):
            def settle():
                card = cards.get(tid)
                if not card:
                    return
                try:
                    px, py = root.winfo_pointerxy()
                    f = card["frame"]
                    fx, fy = f.winfo_rootx(), f.winfo_rooty()
                    inside = (fx <= px < fx + _num(f.winfo_width(), 0)
                              and fy <= py < fy + _num(f.winfo_height(), 0))
                except Exception:
                    inside = False
                if not inside:
                    set_hover(tid, 0.0)
            try:
                root.after(40, settle)
            except Exception:
                pass
        for w in _descendants(widget):
            try:
                w.bind("<Enter>", enter, add="+")
                w.bind("<Leave>", leave, add="+")
            except Exception:
                pass

    # ---- stack the cards on the stage ------------------------------------
    order, seen = [], set()
    for t in triggers:
        if t.cls not in seen:
            seen.add(t.cls)
            order.append(t.cls)
    # Every row — section heading or card — carries its own tag, so a single card's
    # change can shift everything below it with one canvas `move` per row instead of
    # re-laying the whole list out. Without a per-section tag the headings strand at
    # their old y while the cards slide, which is exactly the bug this invites.
    layout = []
    for si, cls in enumerate(order):
        members = [x for x in triggers if x.cls == cls]
        layout.append(["section", (CLASS_LABEL.get(cls, cls), len(members)),
                       "row%d" % len(layout)])
        fy = 0.10 + 0.74 * (si / max(1.0, len(order) - 1.0))
        for t in members:
            build_card(t, fy)
            card = cards[t.id]
            card["row"] = "row%d" % len(layout)
            card["index"] = len(layout)
            try:
                stage.addtag_withtag(card["row"], card["win"])
            except Exception:
                pass
            layout.append(["card", card, card["row"]])

    content = {"h": 0}                          # laid-out height, = the scroll region
    geom = {"x0": 0, "x1": 0, "w": 0}           # last full layout, reused by reflow()

    def relayout(_e=None):
        """Position every card on the stage and draw the glass under it.

        The frames are real widgets (so text, focus and clipboard all behave), but the
        surface they sit on is drawn — which is the only way to get a rounded, lit pane
        in Tk. Tk always paints embedded windows above canvas items, so the glass can be
        redrawn freely without ever covering the content."""
        w = _num(stage.winfo_width(), 0)
        if w < 200:
            w = _num(root.winfo_width(), 1140) - 4
        x0, x1 = SIDE, w - SIDE - 12
        inner = int(x1 - x0 - 2 * CARD_PAD)
        geom["x0"], geom["x1"], geom["w"] = x0, x1, w
        for row in layout:
            if row[0] != "card":
                continue
            obj = row[1]
            for lbl in obj["wraps"]:
                try:
                    lbl.configure(wraplength=max(200, inner - 20))
                except Exception:
                    pass
            try:
                stage.itemconfigure(obj["win"], width=inner)
            except Exception:
                pass
            obj["lane"].resize(232 if inner > 620 else 140)
        try:
            stage.update_idletasks()
        except Exception:
            pass
        try:
            stage.delete("chrome")
        except Exception:
            return
        y = 12
        for row in layout:
            kind, obj, tag = row
            if kind == "section":
                text, n = obj
                tags = ("chrome", tag)
                head_item = stage.create_text(x0 + 6, y + 16, anchor="w", text=text,
                                              fill=GUI_ACCENT, font=(GUI_MONO, 9, "bold"),
                                              tags=tags)
                item = stage.create_text(x1, y + 16, anchor="e", text=f"{n} triggers",
                                         fill=GUI_FAINT, font=(GUI_MONO, 9), tags=tags)
                try:
                    left = stage.bbox(item)[0] - 12
                    right = stage.bbox(head_item)[2] + 12
                except Exception:
                    left, right = x1 - 70, x0 + 6 + 7.2 * len(text)
                if left > right:
                    stage.create_line(right, y + 16, left, y + 16,
                                      fill=_lift(GUI_BG, 0.13), tags=tags)
                y += 34
                continue
            card = obj
            h = _num(card["frame"].winfo_reqheight(), 40)
            top, bottom = y, y + h + 2 * CARD_PAD
            card["box"] = (x0, top, x1, bottom)
            draw_pane(card)
            stage.coords(card["win"], x0 + CARD_PAD + 4, top + CARD_PAD)
            card["y"], card["h"] = top, bottom - top
            y = bottom + CARD_GAP
        content["h"] = y + 16
        try:
            stage.configure(scrollregion=(0, 0, w, content["h"]))
        except Exception:
            pass
        on_scrolled()

    def reflow(tid):
        """One card changed height — move the rest, don't rebuild them.

        A full relayout re-created 443 canvas items and re-measured all 53 cards to
        service a change in one of them; for a collapsed card, which is the default
        state, it re-created all of them to change nothing at all. This measures the one
        card that moved and slides every row below it by the difference."""
        card = cards.get(tid)
        if card is None or not card.get("box") or not geom["w"]:
            relayout()
            return
        try:
            stage.update_idletasks()             # required: reqheight must be fresh
        except Exception:
            pass
        x0, top, x1, bottom = card["box"]
        h = _num(card["frame"].winfo_reqheight(), 40)
        new_bottom = top + h + 2 * CARD_PAD
        dy = new_bottom - bottom
        card["box"] = (x0, top, x1, new_bottom)
        card["h"] = new_bottom - top
        draw_pane(card)
        if dy:
            for row in layout[card["index"] + 1:]:
                try:
                    stage.move(row[2], 0, dy)
                except Exception:
                    pass
                if row[0] == "card":
                    other = row[1]
                    ox0, otop, ox1, obottom = other["box"] or (x0, 0, x1, 0)
                    other["box"] = (ox0, otop + dy, ox1, obottom + dy)
                    other["y"] = otop + dy
            content["h"] += dy
            try:
                stage.configure(scrollregion=(0, 0, geom["w"], content["h"]))
            except Exception:
                pass
        on_scrolled()

    def reveal(tid):
        """Scroll just enough to bring a freshly expanded card into view — an expand
        that pushes its own actions off-screen is worse than no animation at all."""
        card = cards.get(tid)
        if not card:
            return
        try:
            top = stage.canvasy(0)
            vh = _num(stage.winfo_height(), 0)
            total = content["h"]                  # NOT bbox("all"): the backdrop image is
            if not vh or not total:               # pinned to the viewport and would skew it
                return
            bottom = card["y"] + card["h"] + 16
            if bottom > top + vh:
                target = min(card["y"] - 12, bottom - vh)
                stage.yview_moveto(max(0.0, target / float(total)))
        except Exception:
            pass

    # ---- resize ----------------------------------------------------------
    resize = {"job": None, "size": (0, 0)}

    def on_root_configure(event=None):
        if event is not None and getattr(event, "widget", None) is not root:
            return
        size = (_num(root.winfo_width(), 0), _num(root.winfo_height(), 0))
        if size == resize["size"] or size[0] < 100:
            return
        resize["size"] = size
        try:
            if resize["job"] is not None:
                root.after_cancel(resize["job"])
            resize["job"] = root.after(90, repaint_all)
        except Exception:
            repaint_all()

    def repaint_all():
        resize["job"] = None
        w = _num(root.winfo_width(), 1140)
        ensure_backdrop(w)                      # width only: the header strip is fixed
        paint_head(w)
        relayout()

    try:
        root.bind("<Configure>", on_root_configure)
    except Exception:
        pass

    # ---- stop decorating a window nobody is looking at --------------------
    focus_state = {"job": None}

    def _focus_check():
        focus_state["job"] = None
        try:                                     # None only when focus left the app
            anim.set_ambient(root.focus_displayof() is not None)
        except Exception:
            pass

    def on_focus(_e=None):
        # FocusOut also fires when focus moves to a child (the buttons take focus), so
        # settle first and then ask who actually holds it.
        try:
            if focus_state["job"] is not None:
                root.after_cancel(focus_state["job"])
            focus_state["job"] = root.after(120, _focus_check)
        except Exception:
            pass

    try:
        root.bind("<FocusIn>", on_focus, add="+")
        root.bind("<FocusOut>", on_focus, add="+")
    except Exception:
        pass

    def on_close():
        run_state["stop"] = True
        try:
            root.destroy()
        except tk.TclError:
            pass
    root.protocol("WM_DELETE_WINDOW", on_close)

    # Settle the geometry BEFORE the first paint. Without this, winfo_width() is still 1,
    # so the header painted itself 400px wide and relayout laid all 53 panes out at a
    # negative width — roughly twice as many canvas items created as the settled window
    # needs, and a visibly wrong frame on screen until the first <Configure> repaired it.
    try:
        root.update_idletasks()
    except tk.TclError:
        pass
    paint_head(_num(root.winfo_width(), 1140) or 1140)
    relayout()
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
                if not t.unavailable_reason(settings):
                    root.after(200, lambda tid=t.id: fire(tid))
                    break
        root.update_idletasks()
        root.update()
        repaint_all()
        root.after(int(os.environ.get("SECV_RENDER_MS", "300")), _finish)
    root.mainloop()


# ---------------------------------------------------------------------------
# presenter mode
# ---------------------------------------------------------------------------
def open_presenter_picker(root, app, triggers, settings, profiles):
    """Choose what to present: a curated profile, or everything enabled.

    Each option states its exact signal count up front, so the presenter commits to a
    number before the room sees any traffic."""
    existing = getattr(root, "_secv_presenter_picker", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    by_id = {t.id: t for t in triggers}
    dlg = _GlassDialog(root, f"{APP_NAME} — presenter mode", min_width=560, fy=0.35)
    root._secv_presenter_picker = dlg.win
    body = dlg.body

    _label(body, "What are we presenting?", GUI_INK, (GUI_FONT, 15, "bold")).pack(anchor="w")
    dlg.wrap(_label(body, "Each option runs in its own order and commits to a signal count.",
                    GUI_DIM, (GUI_FONT, 9)), 0).pack(fill="x", pady=(3, 12))

    def start(session):
        dlg.destroy()
        open_presenter_window(root, app, session, settings)

    def add_option(label, description, chosen):
        signals = sum(t.on_wire_count(settings) for t in chosen)
        tile = _Tile(body, pad=13, lift=0.07, glow=(GUI_ACCENT if chosen else None))
        tile.pack(fill="x", pady=4)
        head = tk.Frame(tile.body, bg=tile.fill)
        head.pack(fill="x")
        _label(head, label, GUI_INK, (GUI_FONT, 11, "bold")).pack(side="left")
        _label(head, f"{len(chosen)} triggers · {signals} signals", GUI_ACCENT,
               (GUI_MONO, 9), anchor="e").pack(side="right")
        if description:
            dlg.wrap(_label(tile.body, description, GUI_FAINT, (GUI_FONT, 9)),
                     60).pack(fill="x", pady=(3, 0))
        session = PresenterSession(chosen, settings, label=label, description=description)
        btn = _gui_button(tile.body, "Present", lambda s=session: start(s), primary=True)
        btn.pack(anchor="e", pady=(9, 0))
        if not chosen:
            btn.configure(state="disabled", text="Nothing enabled")
        tile.sync()

    for profile in (profiles or {}).values():
        chosen = [t for t in profile.triggers(by_id) if not t.gated_disabled(settings)]
        add_option(profile.label, profile.description, chosen)
    add_option("All enabled triggers", "The full catalog, in catalog order.",
               [t for t in triggers if not t.gated_disabled(settings)])

    _gui_button(body, "Cancel", dlg.destroy).pack(anchor="e", pady=(13, 0))
    dlg.show()


def open_presenter_window(root, app, session, settings):
    """Big-type, one-trigger-at-a-time presentation with a live scoreboard.

    The scoreboard tallies what THIS HOST observed and says so — it is never a claim
    about what the customer's stack did. The presenter still reads the verdict on the
    customer's console; this just keeps the story moving, the count honest, and puts a
    picture of the traffic on the wall while it is in flight."""
    existing = getattr(root, "_secv_presenter", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    dlg = _GlassDialog(root, f"{APP_NAME} — presenter", min_width=900, resizable=True, fy=0.5)
    win = dlg.win
    root._secv_presenter = win
    anim = _Anim(win)
    body = dlg.body
    frost = dlg.frost
    state = {"busy": False, "outcome": None, "reason": "", "reveal": 0.0, "shown": None}

    head = tk.Frame(body, bg=frost)
    head.pack(fill="x")
    _label(head, session.label, GUI_ACCENT, (GUI_FONT, 12, "bold")).pack(side="left")
    progress_var = tk.StringVar(value="")
    tk.Label(head, textvariable=progress_var, fg=GUI_DIM, bg=frost,
             font=(GUI_MONO, 10), anchor="e").pack(side="right")

    track = tk.Canvas(body, bg=frost, highlightthickness=0, bd=0, height=4)
    track.pack(fill="x", pady=(9, 0))

    def paint_track():
        try:
            track.delete("all")
            w = _num(track.winfo_width(), 0)
        except Exception:
            return
        if w < 20:
            return
        pos, total = session.progress()
        track.create_polygon(_round_pts(0, 0, w, 4, 2), smooth=True, splinesteps=4,
                             fill=_lift(frost, 0.09), outline="")
        if total:
            done = max(6.0, w * (pos / float(total)))
            track.create_polygon(_round_pts(0, 0, done, 4, 2), smooth=True, splinesteps=4,
                                 fill=GUI_ACCENT, outline="")
    track.bind("<Configure>", lambda e: paint_track())

    tile = _Tile(body, pad=20, lift=0.07)
    tile.pack(fill="x", pady=(13, 0))
    card = tile.body

    title_var = tk.StringVar(value="")
    dlg.wrap(tk.Label(card, textvariable=title_var, fg=GUI_INK, bg=tile.fill,
                      font=(GUI_FONT, 21, "bold"), anchor="w", justify="left"),
             90).pack(fill="x")
    expect_var = tk.StringVar(value="")
    dlg.wrap(tk.Label(card, textvariable=expect_var, fg=GUI_GOLD, bg=tile.fill,
                      font=(GUI_MONO, 11), anchor="w", justify="left"), 90).pack(fill="x", pady=(9, 0))
    talk_var = tk.StringVar(value="")
    dlg.wrap(tk.Label(card, textvariable=talk_var, fg=GUI_DIM, bg=tile.fill,
                      font=(GUI_FONT, 12), anchor="w", justify="left"), 90).pack(fill="x", pady=(10, 0))
    hint_var = tk.StringVar(value="")
    dlg.wrap(tk.Label(card, textvariable=hint_var, fg=GUI_INFO, bg=tile.fill,
                      font=(GUI_FONT, 10), anchor="w", justify="left"), 90).pack(fill="x", pady=(8, 0))

    # The stage: the same emission lane the cards use, at wall size.
    lane = _Lane(card, anim, width=760, height=74, behind=tile.fill)
    lane.cv.pack(fill="x", pady=(16, 2))

    result_var = tk.StringVar(value="")
    result_lbl = tk.Label(card, textvariable=result_var, fg=GUI_INK, bg=tile.fill,
                          font=(GUI_FONT, 25, "bold"), anchor="w")
    result_lbl.pack(fill="x", pady=(10, 0))
    reason_var = tk.StringVar(value="")
    dlg.wrap(tk.Label(card, textvariable=reason_var, fg=GUI_DIM, bg=tile.fill,
                      font=(GUI_FONT, 10), anchor="w", justify="left"), 90).pack(fill="x", pady=(4, 0))

    board_var = tk.StringVar(value="")
    tk.Label(body, textvariable=board_var, fg=GUI_INK, bg=frost, font=(GUI_MONO, 12),
             anchor="w", justify="left").pack(fill="x", pady=(14, 0))
    _label(body, "Observed locally by this host — the inline stack's console is "
                 "authoritative.", GUI_FAINT, (GUI_FONT, 9)).pack(anchor="w", pady=(2, 0))

    bar = tk.Frame(body, bg=frost)
    bar.pack(fill="x", pady=(14, 0))

    def render():
        pos, total = session.progress()
        progress_var.set(f"{pos} / {total}   ·   {session.summary_line()}")
        board_var.set(_presenter_board(session))
        paint_track()
        trigger = session.current
        if trigger is None:
            title_var.set("Done.")
            for var in (expect_var, talk_var, hint_var, result_var, reason_var):
                var.set("")
            lane.clear()
            fire_btn.configure(state="disabled", text="Finished")
            tile.sync()
            return
        title_var.set(trigger.label)
        expect_var.set(f"Expect: {trigger.expected_fire}" if trigger.expected_fire else "")
        talk_var.set(trigger.talking_point)
        hint_var.set("↳ " + trigger.console_hint_text() if trigger.console_hint_text() else "")
        seen = session.results.get(trigger.id)
        if seen != state["shown"]:
            state["shown"] = seen
            state["reveal"] = 0.0
            if seen:
                _reveal_result(seen)
            else:
                result_var.set("")
                lane.clear()
        result_var.set(seen.upper() if seen else "")
        reason_var.set(state.get("reason", "") if seen else "")
        wire = trigger.on_wire_count(settings)
        fire_btn.configure(state=("disabled" if state["busy"] else "normal"),
                           text=("Firing…" if state["busy"]
                                 else f"Fire  ({wire} signal" + ("" if wire == 1 else "s") + ")"))
        tile.sync()

    def _reveal_result(seen):
        """Let the verdict arrive rather than blink into existence — the word lights up
        as the lane resolves, so the room's eye follows the traffic to the answer."""
        colour = PRESENTER_STATE_FG.get(seen, GUI_INK)

        def frame(dt, _elapsed):
            state["reveal"] = min(1.0, state["reveal"] + dt * 3.6)
            try:
                result_lbl.configure(fg=_mix(tile.fill, colour, _ease(state["reveal"])))
            except Exception:
                return False
            return state["reveal"] < 1.0
        anim.add(frame)

    def poll():
        outcome = state.get("outcome")
        if outcome is not None:
            state["outcome"] = None
            state["busy"] = False
            tid, out = outcome
            session.record(tid, out.get("state", ERROR))
            state["reason"] = out.get("reason", "")
            ratio = out.get("ratio") or {}
            lane.resolve(out.get("state", ERROR), passes=ratio.get("reached"),
                         label=(f"{ratio['blocked']}/{ratio['total']} blocked" if ratio
                                else out.get("state", ERROR)))
            render()
        try:
            win.after(150, poll)
        except tk.TclError:
            pass

    def fire():
        trigger = session.current
        if trigger is None or state["busy"]:
            return
        state["busy"] = True
        state["reason"] = ""
        state["shown"] = None
        result_var.set("")
        lane.fire(trigger.on_wire_count(settings), label="in flight")
        render()

        def work():
            try:
                _t, out = app.run(trigger.id, {})
            except Exception as e:                  # a run thread must never die silently
                out = {"state": ERROR, "reason": f"{e.__class__.__name__}: {e}"}
            state["outcome"] = (trigger.id, out)
        threading.Thread(target=work, daemon=True).start()

    def step(delta):
        if state["busy"]:
            return
        session.goto(session.index + delta)
        state["reason"] = ""
        state["shown"] = None
        lane.clear()
        render()

    _gui_button(bar, "◀   Back", lambda: step(-1), anim=anim).pack(side="left")
    fire_btn = _gui_button(bar, "Fire", fire, primary=True, anim=anim)
    fire_btn.pack(side="left", padx=9)
    _gui_button(bar, "Next   ▶", lambda: step(1), anim=anim).pack(side="left")
    _gui_button(bar, "Close", dlg.destroy, anim=anim).pack(side="right")

    render()
    dlg.show(height=560)
    poll()


PRESENTER_STATE_FG = {ALLOWED: GUI_INFO, BLOCKED: GUI_ACCENT, ERROR: GUI_CRIT,
                      INVALID: GUI_GOLD, RATIO: GUI_WARN}


def _presenter_board(session):
    """The scoreboard line: overall tally, then per class."""
    board = session.scoreboard()
    parts = [f"{n} {s}" for s, n in sorted(board["states"].items())] or ["nothing fired yet"]
    lines = ["   ".join(parts)]
    for cls, slot in board["classes"].items():
        if not slot["fired"]:
            continue
        detail = " ".join(f"{n} {s}" for s, n in sorted(slot["states"].items()))
        lines.append(f"   {cls:<10} {slot['fired']}/{slot['total']}   {detail}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# evidence, manifest and update windows
# ---------------------------------------------------------------------------
def open_report_dialog(root, app, triggers, settings):
    """Write this session's evidence to local disk and say exactly where it went.

    Nothing is uploaded and no browser is launched on the user's behalf — the presenter
    decides what to do with the file. Writes an HTML leave-behind plus the raw JSON."""
    existing = getattr(root, "_secv_report_dialog", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    ledger = app.ledger
    dlg = _GlassDialog(root, f"{APP_NAME} — save report", min_width=560, fy=0.3)
    root._secv_report_dialog = dlg.win
    body = dlg.body

    if not ledger.records:
        _label(body, "Nothing to report yet", GUI_INK, (GUI_FONT, 14, "bold")).pack(anchor="w")
        _label(body, "Fire at least one trigger first.", GUI_DIM,
               (GUI_FONT, 10)).pack(anchor="w", pady=(5, 13))
        _gui_button(body, "Close", dlg.destroy).pack(anchor="e")
        dlg.show()
        return

    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    base = os.path.join(evidence_dir(settings), f"secvitals-{stamp}-{ledger.run_id}")
    written, failed = [], None
    try:
        written.append(export_ledger(ledger, base + ".html", triggers, settings))
        written.append(export_ledger(ledger, base + ".json", triggers, settings))
        written.append(export_ledger(ledger, base + ".csv", triggers, settings))
    except OSError as e:
        failed = str(e)

    chain_ok, bad_seq = ledger.verify_chain()
    _label(body, f"{len(ledger.records)} triggers · {ledger.signals_fired()} signals",
           GUI_ACCENT, (GUI_FONT, 15, "bold")).pack(anchor="w")
    if failed:
        dlg.wrap(_label(body, f"Could not write the report: {failed}", GUI_CRIT,
                        (GUI_FONT, 10)), 0).pack(fill="x", pady=(7, 0))
    else:
        _label(body, "Written to local disk (nothing was uploaded):", GUI_DIM,
               (GUI_FONT, 10)).pack(anchor="w", pady=(7, 4))
        tile = _Tile(body, pad=11, lift=0.05)
        tile.pack(fill="x")
        for path in written:
            dlg.wrap(tk.Label(tile.body, text=path, fg=GUI_INK, bg=tile.fill,
                              font=(GUI_MONO, 9), anchor="w", justify="left"),
                     70).pack(fill="x")
        tile.sync()
    _label(body, ("Evidence chain verified." if chain_ok
                  else f"Evidence chain BROKEN at record {bad_seq}."),
           (GUI_ACCENT if chain_ok else GUI_CRIT), (GUI_MONO, 9)).pack(anchor="w", pady=(9, 0))

    btns = tk.Frame(body, bg=dlg.frost)
    btns.pack(fill="x", pady=(15, 0))

    def copy_path():
        try:
            root.clipboard_clear()
            root.clipboard_append(written[0] if written else "")
        except tk.TclError:
            pass

    _gui_button(btns, "Close", dlg.destroy).pack(side="right")
    if written:
        _gui_button(btns, "Copy path", copy_path).pack(side="right", padx=(0, 8))
    dlg.show()


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
    text = format_signal_manifest(manifest, verbose=True)
    totals = manifest["totals"]

    dlg = _GlassDialog(root, f"{APP_NAME} — signal manifest", min_width=880, resizable=True,
                       fy=0.4)
    root._secv_manifest_dialog = dlg.win
    body = dlg.body

    _label(body, f"{totals['signals']} signals across {totals['triggers_enabled']} "
                 "enabled triggers", GUI_ACCENT, (GUI_FONT, 15, "bold")).pack(anchor="w")
    _label(body, "Nothing has been sent — this is the plan.", GUI_DIM,
           (GUI_FONT, 9)).pack(anchor="w", pady=(3, 10))

    box = _well(body, height=26)
    box.insert("1.0", text)
    box.configure(state="disabled")
    box.pack(fill="both", expand=True)

    btns = tk.Frame(body, bg=dlg.frost)
    btns.pack(fill="x", pady=(12, 0))

    def copy_all():
        try:
            root.clipboard_clear()
            root.clipboard_append(text)
        except tk.TclError:
            pass

    _gui_button(btns, "Close", dlg.destroy).pack(side="right")
    _gui_button(btns, "Copy", copy_all).pack(side="right", padx=(0, 8))
    dlg.show(width=880, height=540)


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

    dlg = _GlassDialog(root, f"{APP_NAME} update", min_width=460, fy=0.25)
    root._secv_update_dialog = dlg.win
    body = dlg.body

    _label(body, f"Installed version: {__version__}", GUI_INK,
           (GUI_FONT, 12, "bold")).pack(anchor="w")
    status_var = tk.StringVar(value="Checking …")
    dlg.wrap(tk.Label(body, textvariable=status_var, fg=GUI_DIM, bg=dlg.frost,
                      font=(GUI_FONT, 10), anchor="w", justify="left"),
             0).pack(fill="x", pady=(7, 14))

    btns = tk.Frame(body, bg=dlg.frost)
    btns.pack(fill="x")
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
    _gui_button(btns, "Close", dlg.destroy).pack(side="right")
    check_btn.pack(side="right", padx=(0, 8))

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
                install_btn.pack(side="right", padx=(0, 8))
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
            dlg.win.after(150, poll)
        except tk.TclError:
            pass

    dlg.show()
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


def export_ledger(ledger, path, triggers=None, settings=None):
    """Write run evidence to `path`; the file extension picks the format
    (.csv, .html/.htm, anything else = JSON). Local disk only."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        text = ledger.to_csv()
    elif ext in (".html", ".htm"):
        text = ledger.to_html(triggers, settings)
    else:
        text = ledger.to_json(triggers, settings)
    return write_evidence(path, text)


def format_scorecard(rows):
    """The reconciliation sheet as text: expected, observed, and the presenter's own
    attestation kept in three separate columns."""
    if not rows:
        return "No triggers have been fired yet."
    out = ["  #  TIME (UTC)            TRIGGER                 OBSERVED  CONFIRMED",
           "  " + "-" * 74]
    for r in rows:
        out.append("  {:<3}{:<22}{:<24}{:<10}{}".format(
            r.get("seq", ""), r.get("ts", ""), (r.get("id") or "")[:23],
            r.get("observed") or r.get("state") or "",
            _CONFIRMED_LABEL.get(r.get("confirmed"), r.get("confirmed") or "—")))
        expected = r.get("expected") or r.get("expected_fire") or ""
        if expected:
            out.append("     expected: " + expected[:96])
    return "\n".join(out)


def select_triggers(triggers, selector, settings, profile=None):
    """Resolve a `--run` selector into an ordered trigger list.

    With a `profile`, the profile's OWN order is used — that ordering is the demo
    narrative, and catalog order would destroy it. Gated triggers are still skipped.

    Otherwise: `all` (or empty) selects everything in catalog order, skipping
    live-suspect-gated triggers exactly as the window's "Run all enabled" does. A
    comma-separated list of trigger ids and/or class names selects those; an explicitly
    named trigger is NOT skipped, so asking for a gated one reports its disabled state
    instead of silently doing nothing. Raises ValueError on an unknown name."""
    if profile is not None:
        by_id = {t.id: t for t in triggers}
        return [t for t in profile.triggers(by_id) if not t.gated_disabled(settings)]
    if selector in (None, "", "all"):
        return [t for t in triggers if not t.unavailable_reason(settings)]
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


def run_headless(app, triggers, settings, selector="all", fmt="text", out=None,
                 export=None, profile=None):
    """Fire the selected triggers with no window and report honestly. Returns the
    process exit code (see HEADLESS_* above). With `export`, the run's evidence ledger
    is also written to that path (format chosen by its extension)."""
    out = sys.stdout if out is None else out
    try:
        chosen = select_triggers(triggers, selector, settings, profile)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return HEADLESS_USAGE
    if not chosen:
        print("error: that selection matched no runnable triggers", file=sys.stderr)
        return HEADLESS_USAGE

    planned = sum(t.on_wire_count(settings) for t in chosen)
    if fmt != "json":
        if profile is not None:
            print(f"Profile: {profile.label}", file=out)
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
        "demo_profile": (profile.name if profile is not None else None),
    }
    exported = None
    if export:
        try:
            exported = export_ledger(app.ledger, export, triggers, settings)
        except OSError as e:
            print(f"error: could not write {export}: {e}", file=sys.stderr)
            return HEADLESS_USAGE
    if fmt == "json":
        doc = {"summary": summary, "results": results}
        if exported:
            doc["export"] = exported
        json.dump(doc, out, indent=2)
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
        if exported:
            print(f"Evidence written to {exported}", file=out)
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
    p.add_argument("--profile", metavar="NAME",
                   help="scope --list / --dry-run / --run to a named demo profile from "
                        "settings.yaml, run in the profile's own order")
    p.add_argument("--profiles", action="store_true",
                   help="list the demo profiles defined in settings.yaml, then exit")
    p.add_argument("--export", metavar="FILE",
                   help="after --run, write the run evidence to FILE — the extension picks "
                        "the format (.json, .csv, .html). Written to local disk only")
    p.add_argument("--last-session", action="store_true",
                   help="print the reconciliation scorecard for the most recent run from "
                        "the local evidence log, without firing anything")
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
        profiles = load_profiles(settings, triggers)
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

    by_id = {t.id: t for t in triggers}
    if args.profiles:
        if args.format == "json":
            print(json.dumps([p.to_public(by_id, settings) for p in profiles.values()],
                             indent=2))
        else:
            print(format_profiles(profiles, by_id, settings))
        return 0

    profile = None
    if args.profile:
        profile = profiles.get(args.profile)
        if profile is None:
            known = ", ".join(sorted(profiles)) or "(none defined)"
            print(f"error: unknown profile {args.profile!r}. Available: {known}",
                  file=sys.stderr)
            return 2

    # Preview / headless paths: no window, and --list/--dry-run send nothing at all.
    if args.list_triggers or args.dry_run:
        scope = profile.triggers(by_id) if profile is not None else triggers
        manifest = signal_manifest(scope, settings)
        if profile is not None:
            manifest["demo_profile"] = profile.to_public(by_id, settings)
        if args.format == "json":
            print(json.dumps(manifest, indent=2))
        else:
            if profile is not None:
                print(f"Profile: {profile.label}"
                      + (f" — {profile.description}" if profile.description else ""))
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

    if args.last_session:
        path = os.path.join(evidence_dir(settings), "evidence.jsonl")
        records = last_session_records(path)
        if args.format == "json":
            print(json.dumps(records, indent=2, default=str))
        elif not records:
            print(f"No runs recorded yet in {path}.")
        else:
            print(f"Last session {records[0].get('run_id', '?')} — "
                  f"{len(records)} triggers, "
                  f"{sum(int(r.get('wire_requests') or 0) for r in records)} signals\n")
            print(format_scorecard(records))
        return 0

    app = App(settings, triggers, args.config_dir)
    planned = sum(t.on_wire_count(settings) for t in triggers
                  if not t.unavailable_reason(settings))
    log.info("%s %s — %d triggers (%d enabled, %d signals), native execution on %s",
             APP_NAME, __version__, len(triggers),
             sum(1 for t in triggers if not t.unavailable_reason(settings)), planned, sys.platform)

    if args.run:
        return run_headless(app, triggers, settings, args.run, args.format,
                            export=args.export, profile=profile)

    try:
        run_gui(settings, triggers, app, args.config_dir, profiles)
    except RuntimeError as e:
        log.error("%s", e)
        print(f"{APP_NAME} is a desktop app and needs a display.\n"
              "On Windows run it with pythonw/py; under headless Linux use Xvfb.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
