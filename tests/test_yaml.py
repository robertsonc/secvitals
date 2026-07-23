"""Tests for the vendored minimal YAML loader."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


class TestYaml(unittest.TestCase):
    def test_scalars(self):
        self.assertEqual(sv.yaml_load("x: 1")["x"], 1)
        self.assertEqual(sv.yaml_load("x: 1.5")["x"], 1.5)
        self.assertEqual(sv.yaml_load("x: true")["x"], True)
        self.assertEqual(sv.yaml_load("x: false")["x"], False)
        self.assertIsNone(sv.yaml_load("x: null")["x"])
        self.assertIsNone(sv.yaml_load("x: ~")["x"])
        self.assertEqual(sv.yaml_load('x: "hi"')["x"], "hi")
        self.assertEqual(sv.yaml_load("x: 'a''b'")["x"], "a'b")
        self.assertEqual(sv.yaml_load("x: plain words")["x"], "plain words")

    def test_url_colon_not_split(self):
        d = sv.yaml_load('u: "https://raw.example.com/a#b"')
        self.assertEqual(d["u"], "https://raw.example.com/a#b")
        d2 = sv.yaml_load("u: https://raw.example.com/x")
        self.assertEqual(d2["u"], "https://raw.example.com/x")

    def test_comment_stripping(self):
        d = sv.yaml_load("x: 1   # trailing comment\n# whole line\ny: 2")
        self.assertEqual(d, {"x": 1, "y": 2})
        # a '#' with no leading space is part of the scalar
        self.assertEqual(sv.yaml_load("x: a#b")["x"], "a#b")

    def test_flow_seq_and_map(self):
        d = sv.yaml_load("flags: [needs_internet, needs_et_ruleset]")
        self.assertEqual(d["flags"], ["needs_internet", "needs_et_ruleset"])
        d2 = sv.yaml_load('e: { rc: 0, body_contains: "uid=0" }')
        self.assertEqual(d2["e"], {"rc": 0, "body_contains": "uid=0"})
        d3 = sv.yaml_load("e: { rc_nonzero: true }")
        self.assertEqual(d3["e"], {"rc_nonzero": True})
        self.assertEqual(sv.yaml_load("e: []")["e"], [])
        self.assertEqual(sv.yaml_load("e: {}")["e"], {})

    def test_nested_mapping(self):
        text = "server:\n  host: 127.0.0.1\n  port: 8787\n  open_browser: true\n"
        d = sv.yaml_load(text)
        self.assertEqual(d["server"], {"host": "127.0.0.1", "port": 8787, "open_browser": True})

    def test_seq_of_maps(self):
        text = (
            "- id: a\n"
            "  argv: [\"tmNIDS\", \"-1\"]\n"
            "  flags: [needs_internet]\n"
            "- id: b\n"
            "  argv: [\"curl\", \"-s\"]\n"
        )
        d = sv.yaml_load(text)
        self.assertIsInstance(d, list)
        self.assertEqual(len(d), 2)
        self.assertEqual(d[0]["id"], "a")
        self.assertEqual(d[0]["argv"], ["tmNIDS", "-1"])
        self.assertEqual(d[0]["flags"], ["needs_internet"])
        self.assertEqual(d[1]["id"], "b")

    def test_nested_seq_under_key(self):
        text = "root:\n  items:\n    - one\n    - two\n  n: 2\n"
        d = sv.yaml_load(text)
        self.assertEqual(d["root"]["items"], ["one", "two"])
        self.assertEqual(d["root"]["n"], 2)

    def test_tabs_rejected(self):
        with self.assertRaises(sv.YamlError):
            sv.yaml_load("x:\n\ty: 1")

    def test_real_config_files(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        settings = sv.yaml_load_file(os.path.join(here, "config", "settings.yaml"))
        self.assertEqual(settings["server"]["host"], "127.0.0.1")
        self.assertEqual(settings["server"]["port"], 8787)
        self.assertFalse(settings["enable_live_suspect_hosts"])
        self.assertIn("raw.githubusercontent.com", settings["tmnids"]["url"])

        catalog = sv.yaml_load_file(os.path.join(here, "config", "catalog.yaml"))
        self.assertIsInstance(catalog, list)
        uid = catalog[0]
        self.assertEqual(uid["id"], "ns-uid")
        self.assertEqual(uid["argv"], ["tmNIDS", "-1"])
        self.assertEqual(uid["flags"], ["needs_internet", "needs_et_ruleset"])
        self.assertEqual(uid["expected_on_allow"], {"rc": 0, "body_contains": "uid=0"})
        self.assertEqual(uid["expected_on_block"], {"rc_nonzero": True})


if __name__ == "__main__":
    unittest.main()
