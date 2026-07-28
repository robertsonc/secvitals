"""The headline numbers in the docs must match what the catalog actually contains.

These figures are the product's central promise — "a known quantity of signals" — and
they are quoted in the README and the solution guide. They drift silently every time the
catalog grows, and a stale promise on stage is worse than no promise. Asserting them
here means the catalog and the claim can never disagree for long.

Deliberately narrow: this checks the load-bearing counts, not prose."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")
ROADMAP = os.path.join(HERE, "docs", "SOLUTION-AND-ROADMAP.md")
README = os.path.join(HERE, "README.md")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class TestDocsMatchCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = sv.load_settings(CONFIG)
        cls.triggers = sv.load_catalog(CONFIG, cls.settings)
        lab = sv.Settings(raw=dict(cls.settings.raw, enable_live_suspect_hosts=True))
        cls.default = sv.signal_manifest(cls.triggers, cls.settings)["totals"]
        cls.lab = sv.signal_manifest(cls.triggers, lab)["totals"]

    def test_readme_quotes_the_real_signal_counts(self):
        text = _read(README)
        self.assertIn(f"{self.default['signals']} signals across "
                      f"{self.default['triggers_enabled']} triggers", text)
        self.assertIn(f"{self.lab['signals']}\nacross {self.lab['triggers_enabled']}", text)

    def test_roadmap_quotes_the_real_signal_counts(self):
        text = _read(ROADMAP)
        self.assertIn(f"**{self.default['signals']} signals across "
                      f"{self.default['triggers_enabled']} triggers**", text)
        self.assertIn(f"**{self.lab['signals']} across {self.lab['triggers_enabled']}**", text)

    def test_roadmap_documents_every_trigger_exactly_once(self):
        """The full-catalog table is the auditable list; a trigger missing from it is a
        signal nobody reviewed, and a stale row is a signal that no longer exists."""
        rows = [ln for ln in _read(ROADMAP).splitlines() if re.match(r"^\| \d+[a-z]* \|", ln)]
        documented = [re.search(r"\| `([^`]+)`", ln).group(1) for ln in rows]
        catalog = [t.id for t in self.triggers]
        self.assertEqual(sorted(documented), sorted(catalog))
        self.assertEqual(len(documented), len(set(documented)), "duplicate rows")

    def test_roadmap_states_the_current_version(self):
        self.assertIn(f"version **{sv.__version__}**", _read(ROADMAP))

    def test_class_table_totals_agree_with_the_catalog(self):
        text = _read(ROADMAP)
        self.assertIn(f"**{len(self.triggers)}** |", text)          # class-table total row
        self.assertIn(f"all {len(self.triggers)} triggers", text)

    def test_live_suspect_count_is_stated_correctly(self):
        gated = [t for t in self.triggers if "hits_live_suspect_hosts" in t.flags]
        text = _read(ROADMAP)
        for t in gated:
            self.assertIn(f"`{t.id}`", text, f"{t.id} not named in the roadmap")
        self.assertEqual(len(gated), self.default["triggers_gated"])


if __name__ == "__main__":
    unittest.main()
