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

__version__ = "0.5.0"
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
        return bool(self.control_host)

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


@dataclasses.dataclass
class RunResult:
    subs: list = dataclasses.field(default_factory=list)
    duration_s: float = 0.0
    control_ok: bool = None    # egress control probe (dns/tcp only); None = not run
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
            subs.append(_run_curl(argv, trigger.timeout, stamp))
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
        res.control_ok = _tcp_probe(settings.control_host, settings.control_port,
                                    min(6.0, trigger.timeout))
    return res


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
            "class": r["class"], "severity": r["severity"],
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

    CSV_COLUMNS = ("seq", "ts", "run_id", "id", "label", "class", "runner", "severity",
                   "threat_class", "state", "reason", "rc", "http_code", "duration_s",
                   "wire_requests", "expected_fire", "confirmed", "verify_key", "hash")

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
               "<tr><th>#</th><th>Time (UTC)</th><th>Trigger</th><th>Expected to fire</th>"
               "<th>Observed locally</th><th>Confirmed on console</th><th>Signals</th></tr>")
    for row in ledger.scorecard():
        css = _STATE_CSS.get(row["observed"], "")
        out.append(
            f"<tr><td class='mono'>{row['seq']}</td><td class='mono'>{_esc(row['ts'])}</td>"
            f"<td><strong>{_esc(row['label'])}</strong><br><span class='mono' "
            f"style='color:#6f787c'>{_esc(row['id'])}</span></td>"
            f"<td>{_esc(row['expected'])}</td>"
            f"<td><span class='badge {css}'>{_esc(row['observed'])}</span><div class='note'>"
            f"{_esc(row['reason'])}</div></td>"
            f"<td>{_esc(_CONFIRMED_LABEL.get(row['confirmed'], row['confirmed']))}</td>"
            f"<td class='mono'>{_esc(row['signals'])}</td></tr>")
    out.append("</table></div><div class='note'>“Expected” is what the catalog says the "
               "signal should trip. “Observed locally” is this host's honest read. "
               "“Confirmed on console” is the presenter's own attestation — a human "
               "annotation, deliberately kept separate and outside the evidence chain.</div>")

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
        if not _tcp_probe(s.control_host, s.control_port, 6.0):
            return {"state": INVALID, "expected_fire": trigger.expected_fire,
                    "reason": (f"control probe to {s.control_host}:{s.control_port} failed — "
                               "egress is broken, so the whole test is invalid (not blocked)")}
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
            "id": t.id, "label": t.label, "class": t.cls, "runner": t.runner,
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
    return {
        "profile": "lab" if settings.enable_live_suspect_hosts else "default",
        "enable_live_suspect_hosts": settings.enable_live_suspect_hosts,
        "totals": {"triggers_enabled": enabled, "triggers_gated": gated,
                   "triggers_unconfigured": unconfigured,
                   "triggers_total": len(triggers), "signals": signals,
                   "signals_if_gate_enabled": signals_if_gate_on},
        "classes": [classes[k] for k in classes],
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
    out.append(f"TOTAL: {t['signals']} signals across {t['triggers_enabled']} enabled triggers")
    if t["triggers_gated"]:
        out.append(f"       {t['signals_if_gate_enabled']} signals if the live-suspect gate is enabled "
                   f"({t['triggers_total']} triggers)")
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

# The presenter's attestation cycles unset -> confirmed -> not-seen. It records what a
# human saw on the customer's console; it never changes this host's own observation.
CONFIRM_CYCLE = {CONFIRMED_UNSET: CONFIRMED_YES, CONFIRMED_YES: CONFIRMED_NO,
                 CONFIRMED_NO: CONFIRMED_UNSET}
CONFIRM_CYCLE_LABEL = {CONFIRMED_UNSET: "Console: not marked",
                       CONFIRMED_YES: "Console: confirmed \u2713",
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
        c["seq"] = out.get("seq")
        if c["seq"]:
            c["confirmed"] = CONFIRMED_UNSET
            c["confirm"].configure(text=CONFIRM_CYCLE_LABEL[CONFIRMED_UNSET],
                                   fg=CONFIRM_CYCLE_FG[CONFIRMED_UNSET])
            c["confirm"].pack(side="left", padx=6)
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
        ids = [t.id for t in triggers if not by_id[t.id].unavailable_reason(settings)]
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
            if not by_id[tid].unavailable_reason(settings):
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
    enabled_triggers = [t for t in triggers if not t.unavailable_reason(settings)]
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
    presenter_btn = _gui_button(
        bar, "🎤  Presenter mode",
        lambda: open_presenter_picker(root, app, triggers, settings, profiles))
    presenter_btn.pack(side="left", padx=6, pady=2)
    report_btn = _gui_button(bar, "⬇  Save report",
                             lambda: open_report_dialog(root, app, triggers, settings))
    report_btn.pack(side="left", padx=6, pady=2)
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
        unavailable = t.unavailable_reason(settings)
        disabled = bool(unavailable)
        gated_live = t.gated_disabled(settings)
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
        status = tk.Label(head, text=("disabled (live)" if gated_live
                                      else "not configured" if disabled else "not run"),
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
            fire_btn.configure(state="disabled",
                               text="Disabled (live)" if gated_live else "Not configured")
        fire_btn.pack(side="left")
        copy_btn = _gui_button(actions, "Copy verification key",
                               lambda tid=t.id: copy_text(cards[tid].get("verify_key"), tid))
        # The presenter's own read of the customer's console. Deliberately a SEPARATE
        # record from what this host observed — the two are different kinds of evidence
        # and the report keeps them in different columns.
        confirm_btn = _gui_button(actions, CONFIRM_CYCLE_LABEL[CONFIRMED_UNSET],
                                  lambda tid=t.id: cycle_confirmed(tid))
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
                                   "enable_live_suspect_hosts in a controlled lab to run it."
                                   if gated_live else unavailable),
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
                       "copy": copy_btn, "confirm": confirm_btn, "set_pane": set_pane,
                       "runs": 0, "verify_key": "", "seq": None,
                       "confirmed": CONFIRMED_UNSET}

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
                if not t.unavailable_reason(settings):
                    root.after(200, lambda tid=t.id: fire(tid))
                    break
        root.update_idletasks()
        root.update()
        root.after(int(os.environ.get("SECV_RENDER_MS", "300")), _finish)
    root.mainloop()


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
    dlg = tk.Toplevel(root)
    root._secv_presenter_picker = dlg
    dlg.title(f"{APP_NAME} — presenter mode")
    dlg.configure(bg=GUI_BG, padx=18, pady=14)
    dlg.transient(root)

    tk.Label(dlg, text="What are we presenting?", fg=GUI_INK, bg=GUI_BG,
             font=(GUI_FONT, 14, "bold")).pack(anchor="w")
    tk.Label(dlg, text="Each option runs in its own order and commits to a signal count.",
             fg=GUI_DIM, bg=GUI_BG, font=(GUI_FONT, 9)).pack(anchor="w", pady=(2, 12))

    def start(session):
        try:
            dlg.destroy()
        except tk.TclError:
            pass
        open_presenter_window(root, app, session, settings)

    def add_option(label, description, chosen, name=""):
        signals = sum(t.on_wire_count(settings) for t in chosen)
        row = tk.Frame(dlg, bg=GUI_SURFACE, padx=12, pady=10,
                       highlightbackground=GUI_GRID, highlightthickness=1)
        row.pack(fill="x", pady=3)
        head = tk.Frame(row, bg=GUI_SURFACE)
        head.pack(fill="x")
        tk.Label(head, text=label, fg=GUI_INK, bg=GUI_SURFACE,
                 font=(GUI_FONT, 11, "bold")).pack(side="left")
        tk.Label(head, text=f"{len(chosen)} triggers · {signals} signals", fg=GUI_ACCENT,
                 bg=GUI_SURFACE, font=(GUI_MONO, 9)).pack(side="right")
        if description:
            tk.Label(row, text=description, fg=GUI_FAINT, bg=GUI_SURFACE,
                     font=(GUI_FONT, 9), anchor="w", justify="left",
                     wraplength=520).pack(fill="x", pady=(2, 0))
        session = PresenterSession(chosen, settings, label=label, description=description)
        btn = _gui_button(row, "Present", lambda s=session: start(s), primary=True)
        btn.pack(anchor="e", pady=(8, 0))
        if not chosen:
            btn.configure(state="disabled", text="Nothing enabled")

    for profile in (profiles or {}).values():
        chosen = [t for t in profile.triggers(by_id) if not t.gated_disabled(settings)]
        add_option(profile.label, profile.description, chosen, profile.name)
    add_option("All enabled triggers", "The full catalog, in catalog order.",
               [t for t in triggers if not t.gated_disabled(settings)])

    _gui_button(dlg, "Cancel", dlg.destroy).pack(anchor="e", pady=(12, 0))


def open_presenter_window(root, app, session, settings):
    """Big-type, one-trigger-at-a-time presentation with a live scoreboard.

    The scoreboard tallies what THIS HOST observed and says so — it is never a claim
    about what the customer's stack did. The presenter still reads the verdict on the
    customer's console; this just keeps the story moving and the count honest."""
    existing = getattr(root, "_secv_presenter", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    win = tk.Toplevel(root)
    root._secv_presenter = win
    win.title(f"{APP_NAME} — presenter")
    win.configure(bg=GUI_BG, padx=28, pady=22)
    win.transient(root)
    state = {"busy": False, "outcome": None}

    head = tk.Frame(win, bg=GUI_BG)
    head.pack(fill="x")
    tk.Label(head, text=session.label, fg=GUI_ACCENT, bg=GUI_BG,
             font=(GUI_FONT, 12, "bold")).pack(side="left")
    progress_var = tk.StringVar(value="")
    tk.Label(head, textvariable=progress_var, fg=GUI_DIM, bg=GUI_BG,
             font=(GUI_MONO, 11)).pack(side="right")

    card = tk.Frame(win, bg=GUI_SURFACE, padx=24, pady=20,
                    highlightbackground=GUI_GRID, highlightthickness=1)
    card.pack(fill="both", expand=True, pady=(14, 0))

    title_var = tk.StringVar(value="")
    tk.Label(card, textvariable=title_var, fg=GUI_INK, bg=GUI_SURFACE,
             font=(GUI_FONT, 22, "bold"), anchor="w", justify="left",
             wraplength=780).pack(fill="x")
    expect_var = tk.StringVar(value="")
    tk.Label(card, textvariable=expect_var, fg=GUI_GOLD, bg=GUI_SURFACE,
             font=(GUI_MONO, 12), anchor="w", justify="left",
             wraplength=780).pack(fill="x", pady=(10, 0))
    talk_var = tk.StringVar(value="")
    tk.Label(card, textvariable=talk_var, fg=GUI_DIM, bg=GUI_SURFACE,
             font=(GUI_FONT, 13), anchor="w", justify="left",
             wraplength=780).pack(fill="x", pady=(12, 0))
    hint_var = tk.StringVar(value="")
    tk.Label(card, textvariable=hint_var, fg=GUI_INFO, bg=GUI_SURFACE,
             font=(GUI_FONT, 10), anchor="w", justify="left",
             wraplength=780).pack(fill="x", pady=(10, 0))

    result_var = tk.StringVar(value="")
    result_lbl = tk.Label(card, textvariable=result_var, fg=GUI_INK, bg=GUI_SURFACE,
                          font=(GUI_FONT, 26, "bold"), anchor="w")
    result_lbl.pack(fill="x", pady=(18, 0))
    reason_var = tk.StringVar(value="")
    tk.Label(card, textvariable=reason_var, fg=GUI_DIM, bg=GUI_SURFACE,
             font=(GUI_FONT, 10), anchor="w", justify="left",
             wraplength=780).pack(fill="x", pady=(4, 0))

    board_var = tk.StringVar(value="")
    tk.Label(win, textvariable=board_var, fg=GUI_INK, bg=GUI_BG, font=(GUI_MONO, 13),
             anchor="w", justify="left").pack(fill="x", pady=(16, 0))
    tk.Label(win, text="Observed locally by this host — the inline stack's console is "
                       "authoritative.", fg=GUI_FAINT, bg=GUI_BG,
             font=(GUI_FONT, 9)).pack(anchor="w")

    bar = tk.Frame(win, bg=GUI_BG)
    bar.pack(fill="x", pady=(16, 0))

    def render():
        pos, total = session.progress()
        progress_var.set(f"{pos} / {total}   ·   {session.summary_line()}")
        board_var.set(_presenter_board(session))
        trigger = session.current
        if trigger is None:
            title_var.set("Done.")
            expect_var.set("")
            talk_var.set("")
            hint_var.set("")
            result_var.set("")
            reason_var.set("")
            fire_btn.configure(state="disabled", text="Finished")
            return
        title_var.set(trigger.label)
        expect_var.set(f"Expect: {trigger.expected_fire}" if trigger.expected_fire else "")
        talk_var.set(trigger.talking_point)
        hint_var.set("↳ " + trigger.console_hint_text() if trigger.console_hint_text() else "")
        seen = session.results.get(trigger.id)
        result_var.set(seen.upper() if seen else "")
        result_lbl.configure(fg=PRESENTER_STATE_FG.get(seen, GUI_INK))
        reason_var.set(state.get("reason", "") if seen else "")
        wire = trigger.on_wire_count(settings)
        fire_btn.configure(state=("disabled" if state["busy"] else "normal"),
                           text=("Firing…" if state["busy"]
                                 else f"Fire  ({wire} signal" + ("" if wire == 1 else "s") + ")"))

    def poll():
        outcome = state.get("outcome")
        if outcome is not None:
            state["outcome"] = None
            state["busy"] = False
            tid, out = outcome
            session.record(tid, out.get("state", ERROR))
            state["reason"] = out.get("reason", "")
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
        result_var.set("")
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
        render()

    back_btn = _gui_button(bar, "◀  Back", lambda: step(-1))
    back_btn.pack(side="left")
    fire_btn = _gui_button(bar, "Fire", fire, primary=True)
    fire_btn.pack(side="left", padx=8)
    next_btn = _gui_button(bar, "Next  ▶", lambda: step(1))
    next_btn.pack(side="left")
    _gui_button(bar, "Close", win.destroy).pack(side="right")

    render()
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
    dlg = tk.Toplevel(root)
    root._secv_report_dialog = dlg
    dlg.title(f"{APP_NAME} — save report")
    dlg.configure(bg=GUI_BG, padx=18, pady=14)
    dlg.transient(root)

    if not ledger.records:
        tk.Label(dlg, text="Nothing to report yet", fg=GUI_INK, bg=GUI_BG,
                 font=(GUI_FONT, 13, "bold")).pack(anchor="w")
        tk.Label(dlg, text="Fire at least one trigger first.", fg=GUI_DIM, bg=GUI_BG,
                 font=(GUI_FONT, 10)).pack(anchor="w", pady=(4, 12))
        _gui_button(dlg, "Close", dlg.destroy).pack(anchor="e")
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
    tk.Label(dlg, text=f"{len(ledger.records)} triggers · {ledger.signals_fired()} signals",
             fg=GUI_ACCENT, bg=GUI_BG, font=(GUI_FONT, 14, "bold")).pack(anchor="w")
    if failed:
        tk.Label(dlg, text=f"Could not write the report: {failed}", fg=GUI_CRIT, bg=GUI_BG,
                 font=(GUI_FONT, 10), wraplength=520, justify="left").pack(anchor="w", pady=(6, 0))
    else:
        tk.Label(dlg, text="Written to local disk (nothing was uploaded):",
                 fg=GUI_DIM, bg=GUI_BG, font=(GUI_FONT, 10)).pack(anchor="w", pady=(6, 2))
        for path in written:
            tk.Label(dlg, text=path, fg=GUI_INK, bg=GUI_BG, font=(GUI_MONO, 9),
                     wraplength=560, justify="left").pack(anchor="w")
    tk.Label(dlg,
             text=("Evidence chain verified." if chain_ok
                   else f"Evidence chain BROKEN at record {bad_seq}."),
             fg=(GUI_ACCENT if chain_ok else GUI_CRIT), bg=GUI_BG,
             font=(GUI_MONO, 9)).pack(anchor="w", pady=(8, 0))

    btns = tk.Frame(dlg, bg=GUI_BG)
    btns.pack(anchor="e", fill="x", pady=(14, 0))

    def copy_path():
        try:
            root.clipboard_clear()
            root.clipboard_append(written[0] if written else "")
        except tk.TclError:
            pass

    _gui_button(btns, "Close", dlg.destroy).pack(side="right")
    if written:
        _gui_button(btns, "Copy path", copy_path).pack(side="right", padx=6)


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
