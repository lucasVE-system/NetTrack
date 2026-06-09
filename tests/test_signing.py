import importlib.util
import os
import tempfile
import unittest

import signing

_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "scripts", "sign_release.py")
_spec = importlib.util.spec_from_file_location("sign_release", _SCRIPT)
sign_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sign_release)


def _make_keypair(bits=768):
    """Small test keypair (768-bit keeps the test fast; real keys are 2048)."""
    e = signing.RELEASE_PUBKEY_E
    while True:
        p = sign_release._random_prime(bits // 2)
        q = sign_release._random_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        try:
            d = pow(e, -1, (p - 1) * (q - 1))
            return n, d
        except ValueError:
            continue


def _sign_file(path, n, d):
    em_len = (n.bit_length() + 7) // 8
    em = signing.emsa_pkcs1_v15(signing.file_sha256(path), em_len)
    return f"{pow(int.from_bytes(em, 'big'), d, n):x}"


class SigningRoundtripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n, cls.d = _make_keypair()
        cls.n_hex = f"{cls.n:x}"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.artifact = os.path.join(self._tmp.name, "artifact.bin")
        with open(self.artifact, "wb") as f:
            f.write(b"fake release binary contents" * 100)

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_signature_verifies(self):
        sig = _sign_file(self.artifact, self.n, self.d)
        self.assertTrue(signing.verify_signature(
            self.artifact, sig, pubkey_n=self.n_hex))

    def test_tampered_file_fails(self):
        sig = _sign_file(self.artifact, self.n, self.d)
        with open(self.artifact, "ab") as f:
            f.write(b"X")
        self.assertFalse(signing.verify_signature(
            self.artifact, sig, pubkey_n=self.n_hex))

    def test_wrong_key_fails(self):
        other_n, other_d = _make_keypair()
        sig = _sign_file(self.artifact, other_n, other_d)
        self.assertFalse(signing.verify_signature(
            self.artifact, sig, pubkey_n=self.n_hex))

    def test_garbage_signature_fails(self):
        for sig in ("", "zz-not-hex", "00", f"{self.n:x}"):  # incl. sig >= n
            self.assertFalse(signing.verify_signature(
                self.artifact, sig, pubkey_n=self.n_hex), repr(sig))

    def test_missing_file_fails(self):
        sig = _sign_file(self.artifact, self.n, self.d)
        self.assertFalse(signing.verify_signature(
            self.artifact + ".nope", sig, pubkey_n=self.n_hex))

    def test_embedded_production_key_is_set(self):
        # The shipped app must have a real 2048-bit public key embedded
        self.assertGreaterEqual(
            int(signing.RELEASE_PUBKEY_N, 16).bit_length(), 2040)

    def test_sign_script_roundtrip_via_keyfile(self):
        # End-to-end through the actual script 'sign' entry point
        keyfile = os.path.join(self._tmp.name, "release_key.json")
        import json
        with open(keyfile, "w") as f:
            json.dump({"n": self.n_hex, "d": f"{self.d:x}",
                       "e": signing.RELEASE_PUBKEY_E}, f)
        orig = sign_release.KEY_FILE
        sign_release.KEY_FILE = keyfile
        try:
            sign_release.sign(self.artifact)
        finally:
            sign_release.KEY_FILE = orig
        with open(self.artifact + ".sig") as f:
            sig = f.read().strip()
        self.assertTrue(signing.verify_signature(
            self.artifact, sig, pubkey_n=self.n_hex))


if __name__ == "__main__":
    unittest.main()
