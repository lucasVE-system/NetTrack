"""sign_release.py – maintainer-side release signing for NetTrack.

The auto-updater verifies releases against the public key embedded in
signing.py. This script holds the other half of that scheme: it generates the
keypair and signs release artifacts with the PRIVATE key, which must stay on
the maintainer's machine (release_key.json is gitignored — back it up!).

Usage:
    python scripts/sign_release.py keygen
        Creates release_key.json next to this repo's root (refuses to
        overwrite) and prints the public modulus to paste into signing.py.

    python scripts/sign_release.py sign dist/NetTrack.exe
        Writes dist/NetTrack.exe.sig. Upload both files to the GitHub release.

Pure Python on purpose: no crypto dependency needed on the build machine.
"""

from __future__ import annotations

import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from signing import RELEASE_PUBKEY_E, emsa_pkcs1_v15, file_sha256  # noqa: E402

KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "release_key.json")

# Deterministic Miller-Rabin witnesses are not safe for adversarial inputs,
# so use many random rounds; for 1024-bit primes 40 rounds is far below a
# 2^-80 error probability.
_MR_ROUNDS = 40


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(_MR_ROUNDS):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    while True:
        # Force top two bits (so n = p*q has full size) and odd
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if candidate % RELEASE_PUBKEY_E != 1 and _is_probable_prime(candidate):
            return candidate


def keygen(bits: int = 2048) -> None:
    if os.path.exists(KEY_FILE):
        print(f"REFUSING to overwrite existing {KEY_FILE}")
        print("Delete it manually if you really want a new keypair "
              "(old releases will no longer verify).")
        sys.exit(1)

    print(f"Generating {bits}-bit RSA keypair (can take ~10s)...")
    e = RELEASE_PUBKEY_E
    while True:
        p = _random_prime(bits // 2)
        q = _random_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        lam = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, lam)
            break
        except ValueError:
            continue

    with open(KEY_FILE, "w") as f:
        json.dump({"n": f"{n:x}", "d": f"{d:x}", "e": e}, f, indent=2)
    print(f"Private key written to {KEY_FILE}")
    print("  -> KEEP THIS FILE SECRET and make an offline backup;")
    print("     losing it means future releases cannot be verified.\n")
    print("Paste this into signing.py as RELEASE_PUBKEY_N:")
    print(f'RELEASE_PUBKEY_N = "{n:x}"')


def sign(path: str) -> None:
    if not os.path.exists(KEY_FILE):
        print(f"No {KEY_FILE} — run 'keygen' first.")
        sys.exit(1)
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)

    with open(KEY_FILE) as f:
        key = json.load(f)
    n, d = int(key["n"], 16), int(key["d"], 16)
    em_len = (n.bit_length() + 7) // 8

    em = emsa_pkcs1_v15(file_sha256(path), em_len)
    sig = pow(int.from_bytes(em, "big"), d, n)

    sig_path = path + ".sig"
    with open(sig_path, "w") as f:
        f.write(f"{sig:x}\n")
    print(f"Signature written to {sig_path}")
    print("Upload it to the GitHub release together with the artifact.")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "keygen":
        keygen()
    elif len(sys.argv) >= 3 and sys.argv[1] == "sign":
        sign(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
