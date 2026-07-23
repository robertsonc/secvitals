"""Tests for the hardened self-update: pure-stdlib RSA verify (interoperating with
openssl), manifest validation, version monotonicity, and fail-closed install."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None


def _canonical_manifest(version, sha256):
    return ('{"version":"%s","artifact":"secvitals.py","sha256":"%s"}' % (version, sha256)).encode()


@unittest.skipUnless(HAVE_OPENSSL, "openssl not available")
class TestSignedUpdate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="sv-update-")
        cls.priv = os.path.join(cls.dir, "priv.pem")
        cls.pub = os.path.join(cls.dir, "pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", cls.priv],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", cls.priv, "-pubout", "-out", cls.pub],
                       check=True, capture_output=True)
        with open(cls.pub, encoding="utf-8") as fh:
            cls.pubkey = fh.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _sign(self, message_bytes):
        msgf = os.path.join(self.dir, "m.bin")
        sigf = os.path.join(self.dir, "m.sig")
        with open(msgf, "wb") as fh:
            fh.write(message_bytes)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.priv, "-out", sigf, msgf],
                       check=True, capture_output=True)
        with open(sigf, "rb") as fh:
            return fh.read()

    def test_verify_roundtrip(self):
        msg = b"hello world"
        sig = self._sign(msg)
        self.assertTrue(sv.verify_rsa_sha256(self.pubkey, msg, sig))
        self.assertFalse(sv.verify_rsa_sha256(self.pubkey, msg + b"!", sig))
        self.assertFalse(sv.verify_rsa_sha256(self.pubkey, msg, sig[:-1] + bytes([sig[-1] ^ 1])))

    def test_verify_wrong_key(self):
        msg = b"payload"
        sig = self._sign(msg)
        other = sv.UPDATE_PUBKEY  # different modulus
        self.assertFalse(sv.verify_rsa_sha256(other, msg, sig))

    def _make_release(self, version, artifact_bytes=b"# SecVitals artifact\n", corrupt_sig=False,
                      wrong_sha=False):
        rel = tempfile.mkdtemp(prefix="sv-rel-", dir=self.dir)
        with open(os.path.join(rel, "secvitals.py"), "wb") as fh:
            fh.write(artifact_bytes)
        sha = hashlib.sha256(artifact_bytes).hexdigest()
        if wrong_sha:
            sha = "0" * 64
        manifest = _canonical_manifest(version, sha)
        with open(os.path.join(rel, "manifest.json"), "wb") as fh:
            fh.write(manifest)
        sig = self._sign(manifest)
        if corrupt_sig:
            sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        with open(os.path.join(rel, "manifest.json.sig"), "wb") as fh:
            fh.write(sig)
        return "file://" + os.path.join(rel, "manifest.json")

    def test_check_update_newer(self):
        url = self._make_release("9.9.9")
        m = sv.check_update(url, self.pubkey)
        self.assertIsNotNone(m)
        self.assertEqual(m["version"], "9.9.9")

    def test_check_update_not_newer_returns_none(self):
        url = self._make_release("0.0.1")
        self.assertIsNone(sv.check_update(url, self.pubkey))

    def test_check_update_bad_signature_fails_closed(self):
        url = self._make_release("9.9.9", corrupt_sig=True)
        with self.assertRaises(sv.UpdateError):
            sv.check_update(url, self.pubkey)

    def test_check_update_no_pubkey_fails_closed(self):
        url = self._make_release("9.9.9")
        with self.assertRaises(sv.UpdateError):
            sv.check_update(url, "")

    def test_install_happy_path(self):
        artifact = b"#!/usr/bin/env python3\n# Security Vitals updated artifact\nX = 1\n"
        url = self._make_release("9.9.9", artifact_bytes=artifact)
        m = sv.check_update(url, self.pubkey)
        target = os.path.join(self.dir, "install_target.py")
        with open(target, "wb") as fh:
            fh.write(b"# old version\n")
        out = sv.download_and_install(m, url, self.pubkey, target=target)
        self.assertEqual(out, target)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), artifact)
        self.assertTrue(os.path.exists(target + ".bak"))
        with open(target + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), b"# old version\n")

    def test_install_sha_mismatch_fails_closed(self):
        url = self._make_release("9.9.9", wrong_sha=True)
        # signature is valid over the (wrong-sha) manifest, so check passes; the artifact
        # hash check must then reject it.
        m = sv.check_update(url, self.pubkey)
        target = os.path.join(self.dir, "install_target2.py")
        with open(target, "wb") as fh:
            fh.write(b"# keep me\n")
        with self.assertRaises(sv.UpdateError):
            sv.download_and_install(m, url, self.pubkey, target=target)
        # the target must be untouched
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), b"# keep me\n")


class TestManifestParsing(unittest.TestCase):
    def test_valid(self):
        m = sv.parse_manifest(_canonical_manifest("1.2.3", "a" * 64))
        self.assertEqual(m["version"], "1.2.3")

    def test_missing_field(self):
        with self.assertRaises(sv.UpdateError):
            sv.parse_manifest(b'{"version":"1.0.0","artifact":"secvitals.py"}')

    def test_bad_sha(self):
        with self.assertRaises(sv.UpdateError):
            sv.parse_manifest(_canonical_manifest("1.0.0", "xyz"))

    def test_wrong_artifact(self):
        with self.assertRaises(sv.UpdateError):
            sv.parse_manifest(b'{"version":"1.0.0","artifact":"evil.py","sha256":"%s"}' % (b"a" * 64))

    def test_not_json(self):
        with self.assertRaises(sv.UpdateError):
            sv.parse_manifest(b"not json")

    def test_version_tuple(self):
        self.assertEqual(sv._version_tuple("1.2.3"), (1, 2, 3))
        self.assertEqual(sv._version_tuple("0.1.0"), (0, 1, 0))
        self.assertIsNone(sv._version_tuple("none"))
        self.assertLess(sv._version_tuple("0.1.0"), sv._version_tuple("0.2.0"))


if __name__ == "__main__":
    unittest.main()
