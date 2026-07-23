"""Server-level tests: loopback gate, keep-alive body draining, full request cycle."""
import http.client
import os
import re
import stat
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


class FakeCache:
    def __init__(self, path):
        self._path = path

    def ensure(self):
        return self._path


class TestLoopback(unittest.TestCase):
    def test_values(self):
        for ok in ("127.0.0.1", "localhost", "::1", "127.5.5.5"):
            self.assertTrue(sv._is_loopback(ok), ok)
        for bad in ("0.0.0.0", "10.0.0.1", "192.168.1.1", "8.8.8.8"):
            self.assertFalse(sv._is_loopback(bad), bad)


class TestServer(unittest.TestCase):
    def setUp(self):
        settings = sv.Settings(raw={"server": {"host": "127.0.0.1", "port": 0}})
        trig = sv.Trigger.from_dict(
            {"id": "ns-uid", "label": "Linux UID", "class": "ns-ids", "runner": "tmnids",
             "argv": ["tmNIDS", "-1"], "flags": ["needs_internet"],
             "expected_on_allow": {"rc": 0, "body_contains": "uid=0"},
             "expected_on_block": {"rc_nonzero": True}}, 30.0)
        self.app = sv.App(settings, [trig], ".")
        # stub tmNIDS so the test is hermetic (no network)
        fd, self.stub = tempfile.mkstemp(prefix="tmnids-stub-", suffix=".py")
        os.close(fd)
        with open(self.stub, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env python3\nprint('uid=0(root) gid=0(root) groups=0(root)')\n")
        os.chmod(self.stub, os.stat(self.stub).st_mode | stat.S_IEXEC)
        self.app.tmnids = FakeCache(self.stub)

        self.httpd = sv.ThreadingHTTPServer(("127.0.0.1", 0), sv.Handler)
        self.httpd.app = self.app
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if os.path.exists(self.stub):
            os.remove(self.stub)

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)

    def _token(self, conn):
        conn.request("GET", "/")
        html = conn.getresponse().read().decode("utf-8")
        return re.search(r'const TOKEN = "([^"]+)"', html).group(1)

    def test_status_and_catalog(self):
        c = self._conn()
        c.request("GET", "/api/status")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        r.read()   # drain before reusing the connection
        c.request("GET", "/api/catalog")
        body = c.getresponse().read().decode("utf-8")
        self.assertIn("ns-uid", body)
        self.assertNotIn("tmNIDS", body)   # argv template must not leak to the client
        c.close()

    def test_rejected_post_does_not_corrupt_keepalive(self):
        # This is the regression test for the unread-body bug.
        c = self._conn()
        c.request("POST", "/api/run", body=b'{"id":"ns-uid"}',
                  headers={"Content-Type": "application/json"})
        r1 = c.getresponse()
        r1.read()
        self.assertEqual(r1.status, 403)          # no token
        # Reuse the SAME connection — must still be healthy because the body was drained.
        c.request("GET", "/api/status")
        r2 = c.getresponse()
        self.assertEqual(r2.status, 200)
        self.assertIn(b'"ok": true', r2.read())
        c.close()

    def test_full_run_allowed_with_token(self):
        c = self._conn()
        token = self._token(c)
        c.request("POST", "/api/run", body=b'{"id":"ns-uid"}',
                  headers={"Content-Type": "application/json", "X-Secvitals-Token": token})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        data = r.read().decode("utf-8")
        self.assertIn('"state": "allowed"', data)
        c.close()

    def test_bad_host_rejected(self):
        c = self._conn()
        token = self._token(c)
        c.request("POST", "/api/run", body=b'{"id":"ns-uid"}',
                  headers={"Host": "evil.example", "Content-Type": "application/json",
                           "X-Secvitals-Token": token})
        self.assertEqual(c.getresponse().status, 421)
        c.close()


if __name__ == "__main__":
    unittest.main()
