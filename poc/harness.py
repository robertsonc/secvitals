"""Effectiveness POC — the harness (device A): send probes, reconcile, score, report.

This is the sender. It runs on the demo host (behind the security control) and runs no
listener of its own. For each probe in the fixed catalog it:

  1. mints a random per-probe token and remembers what it sent (payload sha256),
  2. puts the payload on the wire toward the far side — in a real deployment straight at
     the reflector's public address, so the customer's inline stack sits in the path;
     in --demo, through the bundled mock control,
  3. reads the reflector's HMAC-signed ledger over an out-of-band management channel and
     RECONCILES: a token that arrived with the same digest was ALLOWED; a token that
     arrived with a different digest was MISHANDLED (mangled in transit); a token that
     never arrived was BLOCKED if the control canary proves the path is up, else ERROR.

The reconciliation is the whole point: unlike a single-host tool that must *infer* a block
from a local timeout, the harness *knows* whether each payload reached the far side. That
ground truth is what makes ``blocked`` provable and ``mishandled`` observable at all.

Then it scores effectiveness (see effectiveness.py) and writes a report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.request

try:                                            # run as a script from poc/ …
    import effectiveness
    import reflector
    import control
except ImportError:                             # … or imported as poc.harness
    from poc import effectiveness, reflector, control


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------
def load_catalog(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    probes = doc.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ValueError(f"{path}: no probes")
    seen = set()
    for p in probes:
        pid = p.get("id")
        if not pid or pid in seen:
            raise ValueError(f"{path}: missing or duplicate probe id {pid!r}")
        seen.add(pid)
        if p.get("class") not in effectiveness.CLASSES:
            raise ValueError(f"{pid}: class must be one of {effectiveness.CLASSES}")
        if "payload" not in p:
            raise ValueError(f"{pid}: no payload")
    controls = [p for p in probes if p.get("role") == effectiveness.ROLE_CONTROL]
    if len(controls) != 1:
        raise ValueError("catalog must define exactly one role:control canary")
    return probes


def load_best_effort(path):
    """Load the best-effort catalog (display-only). Missing file -> empty list, since the
    best-effort tier is optional and, in the product, lives in the main secvitals catalog."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return []
    tests = doc.get("tests") or []
    if not isinstance(tests, list):
        raise ValueError(f"{path}: 'tests' must be a list")
    return tests


# ---------------------------------------------------------------------------
# the wire
# ---------------------------------------------------------------------------
def _token():
    return os.urandom(8).hex()


def _post(url, body, timeout):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream",
                                          "Connection": "close"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def send_probes(control_base, run_id, probes, timeout=5.0):
    """Emit every probe toward the far side. Returns a dict token -> sent-record. A send
    that fails (a blocked probe resets/times out) is expected and recorded, not fatal —
    the ledger, not the send result, is the source of truth."""
    sent = {}
    for p in probes:
        tok = _token()
        payload = p["payload"].encode("utf-8")
        sha = hashlib.sha256(payload).hexdigest()
        url = f"{control_base}/probe/{run_id}/{tok}"
        t0 = time.perf_counter()
        latency = None
        try:
            _post(url, payload, timeout)
            latency = round((time.perf_counter() - t0) * 1000.0, 1)
        except (urllib.error.URLError, OSError):
            latency = None                       # no clean ack — likely dropped inline
        sent[tok] = {"probe": p, "sha256": sha, "latency_ms": latency}
    return sent


def fetch_ledger(reflector_base, run_id, secret, timeout=5.0):
    """Read and VERIFY the reflector's ground-truth ledger. Returns (entries, error). A
    missing/invalid signature yields (None, reason): unverifiable ground truth is treated
    as ERROR-for-all downstream, never as a wall of blocks."""
    url = f"{reflector_base}/ledger/{run_id}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read()
            sig = resp.headers.get("X-Reflector-Sig", "")
    except (urllib.error.URLError, OSError) as e:
        return None, f"ledger unreachable on the management channel: {e}"
    expect = reflector.sign(secret, body)
    if not sig or not _consteq(sig, expect):
        return None, "ledger HMAC did not verify — ground truth is untrusted"
    try:
        doc = json.loads(body.decode("utf-8"))
    except ValueError as e:
        return None, f"ledger was not valid JSON: {e}"
    return doc.get("entries", {}), None


def _consteq(a, b):
    import hmac
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# reconciliation: sent-vs-received -> ground-truth outcome
# ---------------------------------------------------------------------------
def reconcile(sent, entries, ledger_error=None):
    """Turn the sent-log + the reflector ledger into ProbeResults with a ground-truth
    outcome each. ``entries`` is token -> {sha256,len,ts} from the reflector.

    Blocked-vs-error hinges on one honest question: is the data path to the far side
    demonstrably up? If ANY token arrived at the reflector this run, it is — so a missing
    token is a genuine inline drop (BLOCKED). If NOTHING arrived, we cannot tell a control
    that drops everything from a dead path, so every miss is ERROR, never a false block.
    This is the ground-truth evolution of secvitals' control-egress probe."""
    entries = entries or {}
    path_up = ledger_error is None and bool(entries)

    results = []
    for tok, rec in sent.items():
        p = rec["probe"]
        klass = p["class"]
        role = p.get("role", "")
        expected = p.get("expect", "")
        lat = rec["latency_ms"]

        if ledger_error is not None:
            outcome, detail = effectiveness.ERROR, ledger_error
        elif tok in entries:
            got = entries[tok]["sha256"]
            if got == rec["sha256"]:
                outcome, detail = effectiveness.ARRIVED, "token arrived intact — allowed through"
            else:
                outcome, detail = effectiveness.MANGLED, "token arrived but the payload was altered in transit"
        else:
            if path_up:
                outcome, detail = effectiveness.BLOCKED, "token never reached the far side; another probe proves the path is up — dropped inline"
            else:
                outcome, detail = effectiveness.ERROR, "token missing and nothing reached the far side — path down, not a policy result"
                lat = None

        results.append(effectiveness.ProbeResult(
            probe_id=p["id"], klass=klass, outcome=outcome, expected=expected,
            role=role, detail=detail, latency_ms=(None if outcome != effectiveness.ARRIVED else lat)))
    # stable, catalog-ish order: control first, then malicious, then benign, by id
    order = {effectiveness.ROLE_CONTROL: 0}
    results.sort(key=lambda r: (order.get(r.role, 1),
                                0 if r.klass == effectiveness.MALICIOUS else 1, r.probe_id))
    return results


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def run(control_base, reflector_base, probes, secret, timeout=5.0, run_id=None):
    run_id = run_id or ("poc-" + os.urandom(6).hex())
    t0 = time.perf_counter()
    sent = send_probes(control_base, run_id, probes, timeout=timeout)
    entries, err = fetch_ledger(reflector_base, run_id, secret, timeout=timeout)
    results = reconcile(sent, entries, ledger_error=err)
    duration = time.perf_counter() - t0
    card = effectiveness.score(results, duration_s=duration)
    card["run_id"] = run_id
    card["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    card["grade"] = effectiveness.grade(card["security_effectiveness_pct"])
    card["ledger_error"] = err
    # These are ground-truth results by construction: they were measured dual-ended over a
    # reflector you control. Only this tier is scored — see build_manifest() for the
    # contrast with the best-effort tier.
    card["mode"] = "ground-truth"
    return card


# ---------------------------------------------------------------------------
# the two measurement modes (the "assurance model") — show them side by side
# ---------------------------------------------------------------------------
# best-effort  : the existing secvitals catalog. Real-world payloads fired SINGLE-ENDED at
#                PUBLIC origins. Realistic and independent, but the result is a heuristic
#                local read — the IDS/IPS MAY OR MAY NOT register an event, unprovably.
# ground-truth : the dual-ended tests, run between secvitals and a reflector you control.
#                Curated payloads whose arrival is confirmed on the far side, so a
#                block/allow/mishandle is a GENUINE, PROVABLE event. Only this tier is scored.
def build_manifest(gt_probes, be_tests):
    """A zero-egress preview of BOTH tiers so a run can show what it can — and cannot —
    prove. Sends nothing; it only reads the two catalogs."""
    def gt_row(p):
        return {"id": p["id"], "class": p.get("class", ""), "label": p.get("label", ""),
                "origin": "your reflector", "expect": p.get("expect", "")}

    def be_row(t):
        return {"id": t["id"], "class": t.get("class", ""), "label": t.get("label", ""),
                "origin": t.get("origin", "public"), "expect": t.get("expect", "")}

    return {"modes": [
        {"mode": "ground-truth", "dual_ended": True, "scored": True,
         "origin": "a reflector you control, behind the control under test",
         "measurement": "proven arrival — a genuine, repeatable block/allow/mishandle event",
         "count": len(gt_probes), "tests": [gt_row(p) for p in gt_probes]},
        {"mode": "best-effort", "dual_ended": False, "scored": False,
         "origin": "public infrastructure (tmNIDS, EICAR, Safe Browsing, category hosts)",
         "measurement": "heuristic local read — MAY OR MAY NOT register an IDS/IPS event",
         "count": len(be_tests), "tests": [be_row(t) for t in be_tests]},
    ]}


def format_manifest(manifest):
    L = ["=" * 74, "  MEASUREMENT MODES — what each tier can prove", "=" * 74]
    for m in manifest["modes"]:
        tag = "dual-ended · SCORED" if m["scored"] else "single-ended · not scored"
        L.append("")
        L.append(f"  {m['mode'].upper()}   ({tag})")
        L.append(f"    origin      : {m['origin']}")
        L.append(f"    measurement : {m['measurement']}")
        L.append(f"    tests       : {m['count']}")
        for t in m["tests"]:
            L.append(f"      {t['id']:<18} {t.get('class',''):<10} {t['label']}")
            L.append(f"      {'':<18} {'':<10} → {t['origin']}  ·  expect: {t.get('expect') or '—'}")
    L.append("")
    L.append("  Best-effort is realism + independence (runs in the wild); ground-truth is")
    L.append("  certainty + repeatability (proves the event). Only ground-truth is scored.")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def format_text(card):
    L = []
    eff = card["security_effectiveness_pct"]
    L.append("=" * 66)
    L.append(f"  SECURITY EFFECTIVENESS   {_fmtpct(eff)}   grade {card['grade']}")
    L.append("=" * 66)
    L.append(f"  block rate (threats stopped)      {_fmtpct(card['block_rate_pct'])}")
    L.append(f"  false-positive rate (legit lost)  {_fmtpct(card['false_positive_rate_pct'])}")
    m, b = card["malicious"], card["benign"]
    L.append("")
    L.append(f"  malicious: {m['tested']} tested · {m['blocked']} blocked · "
             f"{m['mishandled']} mishandled · {m['leaked']} LEAKED")
    L.append(f"  benign:    {b['tested']} tested · {b['passed']} passed · "
             f"{b['false_blocked']} false-blocked · {b['mishandled']} mishandled")
    ns = card["not_scored"]
    L.append(f"  not scored: {ns['errors']} error(s), canary={ns['control_canary']}")
    perf = card["performance"]
    if perf["p50_ms"] is not None:
        L.append(f"  performance: p50 {perf['p50_ms']}ms · p95 {perf['p95_ms']}ms · "
                 f"{perf['throughput_per_s']}/s over {perf['samples']} completed")
    L.append("")
    L.append("  probe                     class      expect   observed     verdict")
    L.append("  " + "-" * 62)
    for p in card["probes"]:
        L.append("  " + _probe_line(p))
    L.append("")
    L.append("  mode: ground-truth (dual-ended, over your reflector) — only these are scored.")
    L.append("  best-effort tests (public origin, single-ended) → run  harness.py --manifest")
    if card.get("ledger_error"):
        L.append("")
        L.append(f"  ! ledger: {card['ledger_error']}")
    return "\n".join(L)


def _verdict(p):
    exp, out, klass = p.get("expected"), p["outcome"], p["klass"]
    if p.get("role") == effectiveness.ROLE_CONTROL:
        return "canary OK" if out == effectiveness.ARRIVED else "CANARY FAILED"
    if out == effectiveness.ERROR:
        return "not tested"
    if klass == effectiveness.MALICIOUS:
        if out == effectiveness.ARRIVED:
            return "MISS (leaked)"
        return "caught"
    # benign
    if out == effectiveness.ARRIVED:
        return "ok"
    return "FALSE POSITIVE" if out == effectiveness.BLOCKED else "mishandled"


def _probe_line(p):
    return (f"{p['probe_id']:<24} {p['klass']:<10} {str(p.get('expected') or '-'):<8} "
            f"{p['outcome']:<12} {_verdict(p)}")


def _fmtpct(v):
    return "n/a" if v is None else f"{v:.1f}%"


_HTML_CSS = """
:root { color-scheme: dark; }
body { background:#1a1d21; color:#f2f4f5; font-family:'Segoe UI',system-ui,sans-serif;
       margin:0; padding:32px; line-height:1.5; }
h1 { font-size:22px; margin:0 0 4px; } .sub { color:#9aa3ad; font-size:13px; margin-bottom:24px; }
.hero { display:flex; gap:28px; align-items:baseline; margin:18px 0 26px; }
.big { font-size:52px; font-weight:700; color:#01A982; line-height:1; }
.grade { font-size:26px; color:#9aa3ad; }
.kv { display:flex; gap:34px; margin:0 0 22px; flex-wrap:wrap; }
.kv div span { display:block; color:#9aa3ad; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
.kv div b { font-size:20px; font-weight:600; }
table { border-collapse:collapse; width:100%; font-size:13px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid #363b44; }
th { color:#01A982; text-transform:uppercase; font-size:11px; letter-spacing:.06em; }
.st-arrived{color:#7fd1b9;} .st-blocked{color:#01A982;font-weight:600;} .st-mangled{color:#e0b64a;}
.st-error{color:#9aa3ad;} .miss{color:#ff6b6b;font-weight:600;} .fp{color:#ff6b6b;font-weight:600;}
.note{color:#9aa3ad;font-size:12px;margin-top:22px;}
"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def format_html(card):
    rows = []
    for p in card["probes"]:
        v = _verdict(p)
        vcls = "miss" if "MISS" in v else ("fp" if "FALSE" in v else "")
        rows.append(
            f"<tr><td>{_esc(p['probe_id'])}</td><td>{_esc(p['klass'])}</td>"
            f"<td>{_esc(p.get('expected') or '—')}</td>"
            f"<td class='st-{_esc(p['outcome'])}'>{_esc(p['outcome'])}</td>"
            f"<td class='{vcls}'>{_esc(v)}</td>"
            f"<td>{'' if p.get('latency_ms') is None else _esc(p['latency_ms'])}</td></tr>")
    m, b, perf = card["malicious"], card["benign"], card["performance"]
    perf_txt = ("—" if perf["p50_ms"] is None
                else f"p50 {perf['p50_ms']}ms · p95 {perf['p95_ms']}ms · {perf['throughput_per_s']}/s")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Security Effectiveness — secvitals POC</title><style>{_HTML_CSS}</style></head><body>
<h1>Security Control Effectiveness</h1>
<div class="sub">paired-device effectiveness measurement · mode: ground-truth (dual-ended) · run {_esc(card['run_id'])} · {_esc(card['generated'])}</div>
<div class="hero"><div class="big">{_fmtpct(card['security_effectiveness_pct'])}</div>
<div class="grade">grade {_esc(card['grade'])}</div></div>
<div class="kv">
<div><span>Block rate</span><b>{_fmtpct(card['block_rate_pct'])}</b></div>
<div><span>False-positive rate</span><b>{_fmtpct(card['false_positive_rate_pct'])}</b></div>
<div><span>Threats leaked</span><b>{m['leaked']}</b></div>
<div><span>Legit lost</span><b>{b['false_blocked'] + b['mishandled']}</b></div>
<div><span>Not scored (error)</span><b>{card['not_scored']['errors']}</b></div>
<div><span>Performance</span><b>{perf_txt}</b></div>
</div>
<table><thead><tr><th>Probe</th><th>Class</th><th>Expected</th><th>Observed (ground truth)</th>
<th>Verdict</th><th>Latency ms</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<p class="note">Effectiveness = block-rate × (1 − false-positive-rate). Ground truth comes
from an HMAC-signed reflector on the far side of the control; ERROR (path down) is never
scored as a block, and “mishandled” means the payload arrived altered — a state a
single-host probe cannot see. These are <b>ground-truth</b> (dual-ended) results — only
this tier is scored; best-effort public-origin tests are a separate tier (see the
manifest). Inert by construction; local disk only.</p>
</body></html>"""


def write_report(card, path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".html":
        data = format_html(card)
    elif ext == ".json":
        data = json.dumps(card, indent=2)
    else:
        data = format_text(card)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)
    return path


# ---------------------------------------------------------------------------
# self-contained demo
# ---------------------------------------------------------------------------
def run_demo(catalog_path, secret=reflector.DEFAULT_SECRET, verbose=False):
    """Stand up reflector + mock control on loopback and run the harness end-to-end. This
    is the one-command proof that the paired loop works; in production there is no mock
    control — the customer's real stack sits in the path instead."""
    probes = load_catalog(catalog_path)
    rserver, raddr, _ = reflector.start_reflector(secret=secret, verbose=verbose)
    cserver, caddr, _ = control.start_control(raddr, verbose=verbose)
    try:
        reflector_base = f"http://{raddr[0]}:{raddr[1]}"
        control_base = f"http://{caddr[0]}:{caddr[1]}"
        card = run(control_base, reflector_base, probes, secret)
    finally:
        cserver.shutdown(); cserver.server_close()
        rserver.shutdown(); rserver.server_close()
    return card


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(prog="harness",
                                description="Effectiveness-POC harness — measure control "
                                            "effectiveness from ground truth")
    p.add_argument("--demo", action="store_true",
                   help="self-contained loopback demo (reflector + mock control + harness)")
    p.add_argument("--catalog", default=os.path.join(here, "probes.json"),
                   help="ground-truth probe catalog (default poc/probes.json)")
    p.add_argument("--best-effort", default=os.path.join(here, "best_effort.json"),
                   help="best-effort catalog for the manifest (display-only)")
    p.add_argument("--manifest", action="store_true",
                   help="show BOTH measurement tiers (ground-truth vs best-effort) — sends nothing")
    p.add_argument("--control-url", help="base URL to SEND probes through (the control in "
                                         "the path); in real use, the reflector's address")
    p.add_argument("--reflector-url", help="base URL to READ the signed ledger (management)")
    p.add_argument("--secret", default=os.environ.get("SECVITALS_REFLECTOR_SECRET",
                                                       reflector.DEFAULT_SECRET),
                   help="shared HMAC secret (or SECVITALS_REFLECTOR_SECRET)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-probe send timeout (s)")
    p.add_argument("--out", metavar="FILE", help="write report to FILE (.html/.json/.txt)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    args = p.parse_args(argv)

    if args.manifest:
        manifest = build_manifest(load_catalog(args.catalog),
                                  load_best_effort(args.best_effort))
        text = json.dumps(manifest, indent=2) if args.format == "json" else format_manifest(manifest)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"manifest written to {args.out}")
        print(text)
        return 0

    if args.demo:
        card = run_demo(args.catalog, secret=args.secret)
    else:
        if not args.control_url or not args.reflector_url:
            p.error("give --control-url and --reflector-url, or use --demo")
        probes = load_catalog(args.catalog)
        card = run(args.control_url.rstrip("/"), args.reflector_url.rstrip("/"),
                   probes, args.secret, timeout=args.timeout)

    if args.out:
        path = write_report(card, args.out)
        print(f"report written to {path}")
    if args.format == "json":
        print(json.dumps(card, indent=2))
    else:
        print(format_text(card))

    # exit code: policy-neutral like secvitals' headless mode. Non-zero only when the
    # run could not be scored (an environment problem), never because a control blocked.
    if card["security_effectiveness_pct"] is None or card.get("ledger_error"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
