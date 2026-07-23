# Original tools — reference only (NOT executed by the app)

These are the scripts attached to the Security Vitals task, kept here verbatim for
**provenance and traceability**. The app does **not** run them. Their trigger
logic is reimplemented in Python and driven by the server-side catalog
(`catalog/*.yaml`); the classifier, caching, loopback server, and hardened update
path are new code.

| File | Ported into the app as | Notes |
|---|---|---|
| `run-ids-test.sh`, `run-ids-menu.sh` | tmNIDS runner + `ns-ids` catalog | Core kept: cached `tmNIDS -N`. `menu()` loop and `.cmd` launchers dropped. |
| `webcc-test.sh` | `ns-webcc` / `ns-iprep` catalog + 3-state classifier | Targets/ids ported; the "any nonzero rc = BLOCKED" classifier is **rewritten** (see `CONFIRMED.md` §5). `menu()` dropped. |
| `trigger_suricata.sh` | — | `testmyids` overlaps tmNIDS `-1`. The **`local` mode is excluded** (edits `local.rules`, restarts Suricata, needs privilege). |
| `Trigger-IDPS.ps1`, `Trigger-Suricata.ps1` | — | Windows ports of `trigger_suricata.sh`; same `local`-mode foot-gun. Not ported (app runs inside WSL). |

See `CONFIRMED.md` (repo root) for the full decision record.
