"""Tests for the opening geometry of the console window.

The bug this guards against (fixed in 0.8.1): `run_gui` opened at a hard-coded
1140x820. On a 1366x768 laptop — the single most common demo machine — that is taller
than the desktop, so the bottom of the trigger list was unreachable and the window sat
over the taskbar with no way to get to the Start button.

`_fit_to_work_area` is pure arithmetic over `winfo_screenwidth/height` plus, on Windows,
the real work-area rectangle. That makes it testable without a display, which matters:
the rest of the GUI needs an X server, so this logic would otherwise ship unverified.

The assertions below are deliberately written as *properties* — "the window fits on the
screen", "you can always shrink it to the size it opened at" — rather than a second copy
of the formula. Restating the implementation would pass no matter how wrong it got.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

WANT_W, WANT_H = 1140, 820      # what run_gui asks for
FLOOR_W, FLOOR_H = 560, 400     # below this the window is useless, so it stops shrinking

# Real screens people actually run the console on, plus the degenerate ends.
SCREENS = [
    ("1366x768 laptop", 1366, 768),     # the machine that motivated the fix
    ("1920x1080", 1920, 1080),
    ("2560x1440", 2560, 1440),
    ("3840x2160", 3840, 2160),
    ("1024x600 netbook", 1024, 600),
    ("800x600", 800, 600),
    ("320x240 absurd", 320, 240),
    ("1x1 degenerate", 1, 1),
]


class FakeRoot:
    """Just enough Tk root to drive the geometry maths, recording what it was told."""

    def __init__(self, w, h, fail=False):
        self._w, self._h = w, h
        self.fail = fail            # simulate a Tk that rejects geometry/minsize
        self.geometry_str = None
        self.minsize_args = None

    def winfo_screenwidth(self):
        return self._w

    def winfo_screenheight(self):
        return self._h

    def geometry(self, spec):
        if self.fail:
            raise RuntimeError("no display")
        self.geometry_str = spec

    def minsize(self, w, h):
        if self.fail:
            raise RuntimeError("no display")
        self.minsize_args = (w, h)


def parse_geometry(spec):
    """'1140x668+113+13' -> (1140, 668, 113, 13)"""
    size, _, rest = spec.partition("+")
    x, _, y = rest.partition("+")
    w, _, h = size.partition("x")
    return int(w), int(h), int(x), int(y)


class TestFitToWorkArea(unittest.TestCase):

    def test_never_larger_than_requested(self):
        """Fitting to the screen only ever shrinks. A 4K monitor does not get a
        bigger window than the layout was designed for."""
        for name, sw, sh in SCREENS:
            with self.subTest(name):
                w, h = sv._fit_to_work_area(FakeRoot(sw, sh), WANT_W, WANT_H)
                self.assertLessEqual(w, WANT_W)
                self.assertLessEqual(h, WANT_H)

    def test_large_screens_get_the_full_requested_size(self):
        """Anything with room to spare opens exactly as designed — the fit logic must
        not quietly shrink the window on machines that were never the problem."""
        for name, sw, sh in [s for s in SCREENS if s[1] >= 1920 and s[2] >= 1080]:
            with self.subTest(name):
                self.assertEqual(sv._fit_to_work_area(FakeRoot(sw, sh), WANT_W, WANT_H),
                                 (WANT_W, WANT_H))

    def test_window_fits_on_screen(self):
        """The actual bug: the whole window — position plus size — must land inside the
        screen. If the bottom edge falls past it, the card list is unreachable and the
        taskbar is covered."""
        for name, sw, sh in SCREENS:
            with self.subTest(name):
                root = FakeRoot(sw, sh)
                sv._fit_to_work_area(root, WANT_W, WANT_H)
                gw, gh, x, y = parse_geometry(root.geometry_str)
                # Degenerate screens hit the usability floor and will overflow; there is
                # no correct answer for a 1x1 desktop, and a too-small window beats a
                # zero-sized one. Real screens must fit.
                if sw >= FLOOR_W + 40 and sh >= FLOOR_H + 100:
                    self.assertLessEqual(x + gw, sw, f"{name}: right edge off screen")
                    self.assertLessEqual(y + gh, sh, f"{name}: bottom edge off screen")

    def test_1366x768_is_shorter_than_the_desktop(self):
        """The regression case, pinned explicitly: the window that used to open 820 tall
        on a 768-tall screen must now leave room for the panel."""
        root = FakeRoot(1366, 768)
        w, h = sv._fit_to_work_area(root, WANT_W, WANT_H)
        self.assertEqual(w, WANT_W)          # width was never the problem
        self.assertLess(h, WANT_H)           # height must have been reduced
        _, gh, _, y = parse_geometry(root.geometry_str)
        self.assertLessEqual(y + gh, 768 - 60)   # clear of the panel allowance

    def test_position_is_never_negative(self):
        """A negative offset puts the title bar off the top of the screen, where it
        cannot be grabbed to move the window."""
        for name, sw, sh in SCREENS:
            with self.subTest(name):
                root = FakeRoot(sw, sh)
                sv._fit_to_work_area(root, WANT_W, WANT_H)
                _, _, x, y = parse_geometry(root.geometry_str)
                self.assertGreaterEqual(x, 0)
                self.assertGreaterEqual(y, 0)

    def test_minsize_never_exceeds_the_opening_size(self):
        """A minimum larger than the opening size is the same bug wearing a different
        hat: Tk would force the window back up to the minimum, undoing the fit."""
        for name, sw, sh in SCREENS:
            with self.subTest(name):
                root = FakeRoot(sw, sh)
                w, h = sv._fit_to_work_area(root, WANT_W, WANT_H)
                mw, mh = root.minsize_args
                self.assertLessEqual(mw, w, f"{name}: min width {mw} > opening {w}")
                self.assertLessEqual(mh, h, f"{name}: min height {mh} > opening {h}")

    def test_floors_at_a_usable_size(self):
        """Shrinking has a lower bound — the window stops being useful long before it
        stops being positive, and a zero or negative dimension is a Tcl error."""
        for name, sw, sh in SCREENS:
            with self.subTest(name):
                w, h = sv._fit_to_work_area(FakeRoot(sw, sh), WANT_W, WANT_H)
                self.assertGreaterEqual(w, FLOOR_W)
                self.assertGreaterEqual(h, FLOOR_H)

    def test_reported_size_matches_the_geometry_set(self):
        """The return value is what the caller believes the window is; it must agree
        with what Tk was actually told."""
        for name, sw, sh in SCREENS:
            with self.subTest(name):
                root = FakeRoot(sw, sh)
                w, h = sv._fit_to_work_area(root, WANT_W, WANT_H)
                gw, gh, _, _ = parse_geometry(root.geometry_str)
                self.assertEqual((w, h), (gw, gh))

    def test_survives_a_root_that_rejects_geometry(self):
        """Headless and remote-display Tk can refuse these calls. Failing to place the
        window must not take the app down — it still has to return a usable size."""
        root = FakeRoot(1920, 1080, fail=True)
        w, h = sv._fit_to_work_area(root, WANT_W, WANT_H)
        self.assertEqual((w, h), (WANT_W, WANT_H))
        self.assertIsNone(root.geometry_str)

    def test_junk_screen_metrics_fall_back_to_the_requested_size(self):
        """`winfo_screenwidth` can return something non-numeric on a broken display
        connection. `_num` is what keeps that from becoming a TypeError mid-startup."""
        for bogus in (None, "", "not-a-number"):
            with self.subTest(repr(bogus)):
                class Junk(FakeRoot):
                    def winfo_screenwidth(self):
                        return bogus

                    def winfo_screenheight(self):
                        return bogus
                w, h = sv._fit_to_work_area(Junk(0, 0), WANT_W, WANT_H)
                self.assertGreaterEqual(w, FLOOR_W)
                self.assertGreaterEqual(h, FLOOR_H)


class TestWindowsWorkArea(unittest.TestCase):
    """On Windows the desktop-minus-taskbar rectangle is available exactly, so the fit
    should use it rather than the raw screen size. These run on any platform by faking
    `sys.platform` and the one ctypes call involved."""

    def setUp(self):
        self._platform = sys.platform
        self._had_windll = hasattr(sv.ctypes if hasattr(sv, "ctypes") else object, "windll")

    def tearDown(self):
        sys.platform = self._platform
        import ctypes
        if not self._had_windll and hasattr(ctypes, "windll"):
            del ctypes.windll

    def test_uses_the_work_area_not_the_full_screen(self):
        """A 1080-tall screen with a 40px taskbar has 1040 usable. The window must be
        placed against that, and offset by the work area's origin."""
        import ctypes

        class FakeUser32:
            def SystemParametersInfoW(self, action, uiparam, rect, winini):
                # The real call writes through a pointer; `ctypes.byref(x)` hands us a
                # CArgObject wrapping the struct, so unwrap it the same way the C side
                # would dereference it.
                target = getattr(rect, "_obj", rect)
                target.left, target.top = 0, 0
                target.right, target.bottom = 1366, 728
                return 1

        class FakeWindll:
            user32 = FakeUser32()

        sys.platform = "win32"
        ctypes.windll = FakeWindll()
        root = FakeRoot(1366, 768)          # raw screen is taller than the work area
        w, h = sv._fit_to_work_area(root, WANT_W, WANT_H)
        _, gh, _, y = parse_geometry(root.geometry_str)
        self.assertLessEqual(y + gh, 728, "window must fit the work area, not the screen")
        self.assertLessEqual(h, 728)

    def test_falls_back_when_the_windows_call_is_unavailable(self):
        """`ctypes.windll` does not exist off Windows, and the API can fail even on it.
        Either way the fit must degrade to the raw screen size, not raise."""
        sys.platform = "win32"
        import ctypes
        if hasattr(ctypes, "windll"):
            del ctypes.windll
        root = FakeRoot(1366, 768)
        w, h = sv._fit_to_work_area(root, WANT_W, WANT_H)
        self.assertGreaterEqual(w, FLOOR_W)
        self.assertGreaterEqual(h, FLOOR_H)
        self.assertIsNotNone(root.geometry_str)


# Must stay at the very bottom: unittest.main() calls sys.exit(), so any class defined
# below it is never reached when this file is run directly.
if __name__ == "__main__":
    unittest.main()
