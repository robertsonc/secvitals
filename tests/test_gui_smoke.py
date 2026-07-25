"""Headless smoke test for the Tkinter console build path.

The real GUI needs a display, so CI can't open a window — but most GUI-crashing bugs
are Tcl option errors raised the moment a widget is created (a bad colour, an illegal
screen distance, an unknown option), long before mainloop. Those kill the app under
`pythonw` with no console and no window.

This test drives `run_gui`'s full build (header, toolbar, one card per catalog trigger)
against a fake `tkinter` that mimics the one validation rule that actually bit us: a
widget's own `-padx`/`-pady`/`-borderwidth`/`-highlightthickness` is a SINGLE screen
distance — the `(near, far)` tuple form is legal only on `.pack()`/`.grid()`, never in a
constructor or `.configure()`. Passing a tuple there raises `TclError` on a real
interpreter. Regression guard for 0.1.1, where `tk.Frame(..., pady=(0, 10))` crashed the
window before it could appear.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeTclError(Exception):
    pass


# Options whose value must be a single screen distance on a widget (not a tuple).
_DISTANCE_OPTS = ("padx", "pady", "borderwidth", "bd", "highlightthickness", "width", "height")


def _validate(where, kw):
    for opt in _DISTANCE_OPTS:
        if opt in kw and isinstance(kw[opt], (tuple, list)):
            raise FakeTclError(
                f'bad screen distance "{kw[opt]}" for {where} option -{opt} '
                "(the (near, far) tuple form is only valid on .pack()/.grid())"
            )


class FakeWidget:
    """Records parent→child links so winfo_children() works; validates constructor and
    .configure() options the way real Tk does for screen distances. Geometry-manager
    calls (pack/grid/place) are intentionally permissive — tuples are legal there."""

    def __init__(self, parent=None, *args, **kw):
        self._children = []
        _validate("constructor", kw)
        if isinstance(parent, FakeWidget):
            parent._children.append(self)

    def configure(self, *args, **kw):
        _validate("configure", kw)
        return None

    config = configure

    def winfo_children(self):
        return list(self._children)

    def pack(self, *a, **k):
        return None

    grid = place = pack

    def __getattr__(self, name):          # every other widget/root method is a no-op
        # Private attributes must behave like a real widget's: absent until assigned,
        # so `getattr(root, "_secv_update_dialog", None)` returns None rather than a
        # truthy stub (which would make the dialogs' reuse guard skip the build).
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **k: None


def _install_fake_tkinter():
    mod = types.ModuleType("tkinter")
    for cls in ("Tk", "Frame", "Label", "Canvas", "Text", "Button",
                "Scrollbar", "StringVar", "Toplevel"):
        setattr(mod, cls, FakeWidget)
    mod.TclError = FakeTclError
    sys.modules["tkinter"] = mod
    return mod


class TestGuiBuildSmoke(unittest.TestCase):
    def setUp(self):
        self._saved = sys.modules.get("tkinter")
        _install_fake_tkinter()

    def tearDown(self):
        if self._saved is not None:
            sys.modules["tkinter"] = self._saved
        else:
            sys.modules.pop("tkinter", None)

    def test_validator_itself_is_real(self):
        # Guard against a false pass: the validator must reject a constructor tuple pad
        # and must NOT touch geometry-manager calls.
        with self.assertRaises(FakeTclError):
            FakeWidget(None, pady=(0, 10))
        FakeWidget(None, pady=8)                 # single distance is fine
        FakeWidget(None).pack(pady=(0, 10))      # tuple on pack is fine

    def test_run_gui_builds_every_card(self):
        import secvitals as sv
        settings = sv.load_settings("config")
        triggers = sv.load_catalog("config", settings)
        app = sv.App(settings, triggers, "config")
        self.assertGreater(len(triggers), 0)
        # Raises FakeTclError if any widget is built with an illegal option — which is
        # exactly how the real window failed to open before the fix.
        sv.run_gui(settings, triggers, app, "config")

    def test_manifest_dialog_builds(self):
        """The signal-manifest preview is a second window built from live catalog data;
        it must survive the same widget-option validation as the main window."""
        import secvitals as sv
        settings = sv.load_settings("config")
        triggers = sv.load_catalog("config", settings)
        app = sv.App(settings, triggers, "config")
        sv.run_gui(settings, triggers, app, "config")   # sets the module-level `tk`
        sv.open_manifest_dialog(FakeWidget(), triggers, settings)


if __name__ == "__main__":
    unittest.main()
