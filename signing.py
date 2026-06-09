"""signing.py – release signature verification for the auto-updater.

Uses RSA-2048 + PKCS#1 v1.5 + SHA-256, implemented with plain integer math so
the app needs no third-party crypto dependency at runtime.

The PRIVATE key never ships with the app: it lives in release_key.json on the
maintainer's machine (gitignored). scripts/sign_release.py creates the keypair
and signs release artifacts; only the public key below is embedded.

Verification is the safe direction of PKCS#1 v1.5: we reconstruct the expected
encoded message ourselves and compare full byte strings, so there is no
signature parsing that could be tricked (no Bleichenbacher-style issues).
"""

from __future__ import annotations

import hashlib

# 2048-bit RSA public key used to verify release signatures (hex modulus).
# Regenerate with: python scripts/sign_release.py keygen
RELEASE_PUBKEY_N = "c786deeb6edd4962673197bf0a0e098202c84d4044bc519b2dfbf1a6796d5a30b02588128555e9bb4ef3ea0ca73bfb53f12322a90e7151363511d4353b1b03a4447bd64150ae9407b7ae5acd54ab86b8d2de4cc64e84e66efa1d753a650539d809fd8d7590fbd5dedc6e5bbd6178d0eb63ee601df4a3a4e8e70e22c9499991f07ac7ab14edf37bf3e8223a739b683bdf4b484d1b495b9a2fbd50fbf7177bf5d8a66a93508e308143006973da8c3e54026ee8144ad38a7fbc53a6c66b1df1638d9c4b3eae5fbb84951e661cd1dd421f979debe6473115591e7f71d53e9831ee169518f42d0ea74bccc18ba313f08e8eeefa88ddb2ff1f4d5eb2472f8aca4a59c7"
RELEASE_PUBKEY_E = 65537

# Set True once releases are published with .sig files. The updater will then
# REFUSE any release without a valid signature instead of falling back to the
# SHA256 sidecar (which an attacker with repo access could regenerate).
REQUIRE_SIGNATURE = False

# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017, section 9.2)
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def emsa_pkcs1_v15(digest: bytes, em_len: int) -> bytes:
    """EMSA-PKCS1-v1_5 encoding of a SHA-256 digest (RFC 8017 9.2)."""
    t = _SHA256_DIGESTINFO + digest
    if em_len < len(t) + 11:
        raise ValueError("key too small for SHA-256 PKCS#1 v1.5")
    ps = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def file_sha256(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def verify_signature(file_path: str, sig_hex: str,
                     pubkey_n: str = "", pubkey_e: int = 0) -> bool:
    """
    Verify an RSA PKCS#1 v1.5 / SHA-256 signature over a file.
    Returns False on any problem (bad key, bad signature, unreadable file).
    """
    try:
        n = int(pubkey_n or RELEASE_PUBKEY_N, 16)
        e = pubkey_e or RELEASE_PUBKEY_E
        sig = int(sig_hex.strip(), 16)
        if not (0 < sig < n):
            return False
        em_len = (n.bit_length() + 7) // 8
        em = pow(sig, e, n).to_bytes(em_len, "big")
        expected = emsa_pkcs1_v15(file_sha256(file_path), em_len)
        return em == expected
    except Exception:
        return False
