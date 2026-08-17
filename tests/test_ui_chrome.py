"""Invariants for the instrument-bench chrome.

The visual language is specified in DESIGN.md. These tests pin the load-bearing
copy and palette decisions so a "friendly" emoji or a decorative violet cannot
walk back onto a presenter-facing control."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


class TestUiChrome(unittest.TestCase):
    def test_toolbar_labels_are_words(self):
        labels = (sv.UI_RUN_ALL, sv.UI_STOP, sv.UI_MANIFEST,
                  sv.UI_PRESENTER, sv.UI_REPORT, sv.UI_UPDATES)
        for label in labels:
            self.assertTrue(label.isascii(), label)
            self.assertFalse(any(ord(ch) > 127 for ch in label), label)
            self.assertNotIn("🎤", label)
            self.assertNotIn("⬇", label)

    def test_confirm_labels_have_no_checkmark_emoji(self):
        for label in sv.CONFIRM_CYCLE_LABEL.values():
            self.assertNotIn("✓", label)
            self.assertTrue(label.startswith("Console:"))

    def test_class_labels_are_sentence_case(self):
        for label in sv.CLASS_LABEL.values():
            self.assertNotEqual(label, label.upper(), label)

    def test_blocked_is_the_brand_green(self):
        """Enforcement working is the success state of this product."""
        self.assertEqual(sv.STATE_COLOR[sv.BLOCKED], sv.GUI_ACCENT)
        self.assertEqual(sv.GUI_ACCENT, "#01A982")

    def test_palette_is_tinted_not_pure_black(self):
        self.assertNotEqual(sv.GUI_BG, "#000000")
        self.assertNotEqual(sv.GUI_BG, "#070a12")   # the old navy-night floor

    def test_allowed_is_not_electric_cyan(self):
        self.assertNotEqual(sv.STATE_COLOR[sv.ALLOWED], "#00B0E6")


if __name__ == "__main__":
    unittest.main()
