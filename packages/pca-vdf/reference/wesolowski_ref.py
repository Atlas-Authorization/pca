"""Independent Wesolowski VDF reference for @atlasauth/pca-vdf.

SELF-WRITTEN reference (no published test vectors exist for this package's hash-to-prime
transcript, and chiavdf is a class-group VDF, not an RSA-group one). It re-implements the
construction from its written specification using DIFFERENT code paths from the TypeScript:

  * y  = pow(x, 2**T, N)                  -- one big-exponent modpow, not T squarings
  * pi = pow(x, (2**T) // l, N)           -- direct floor division, not the running long-division
  * primality / modpow by gmpy2 (GMP 6.x) -- not the TypeScript Miller-Rabin
  * SHA-256 from hashlib                  -- not @noble/hashes

Needs: gmpy2==2.3.2 (GMP 6.3.0). Python 3.12.

Usage:
  wesolowski_ref.py vectors <out.json>      regenerate fixtures/wesolowski-reference-vectors.json
  wesolowski_ref.py eval    <in.json> <out.json>    [{N,x,T}] -> [{y,pi,l}]
  wesolowski_ref.py verify  <in.json> <out.json>    [{N,x,y,pi,T}] -> [{ok,reason}]
  wesolowski_ref.py isprime <in.json> <out.json>    ["n", ...] -> [bool]   (gmpy2 / GMP)
All big integers are decimal strings.
"""
import hashlib
import json
import math
import sys

import gmpy2

DOMAIN = b"atlas-pca/vdf/wesolowski/hash-to-prime/v1\x00"
CHALLENGE_PRIME_BITS = 256


def be(n):
    if n == 0:
        return b"\x00"
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, "big")


def lp(b):
    return len(b).to_bytes(4, "big") + b


def is_prime(n):
    return gmpy2.is_prime(gmpy2.mpz(n), 40)


def hash_to_prime(x, y, T, N, bits=CHALLENGE_PRIME_BITS):
    transcript = (
        DOMAIN
        + lp(be(x % N))
        + lp(be(y % N))
        + lp(be(T))
        + lp(be(N))
        + lp(bits.to_bytes(4, "big"))
    )
    seed = hashlib.sha256(transcript).digest()
    need = (bits + 7) // 8
    top = 1 << (bits - 1)
    mask = (1 << bits) - 1
    counter = 0
    while True:
        raw = b""
        block = 0
        while len(raw) < need:
            raw += hashlib.sha256(seed + counter.to_bytes(8, "big") + block.to_bytes(4, "big")).digest()
            block += 1
        cand = (int.from_bytes(raw[:need], "big") & mask) | top | 1
        if is_prime(cand):
            return cand
        counter += 1


def vdf_eval(N, x, T):
    y = int(gmpy2.powmod(x, gmpy2.mpz(1) << T, N))
    l = hash_to_prime(x, y, T, N)
    pi = int(gmpy2.powmod(x, (gmpy2.mpz(1) << T) // l, N))
    return y, pi, l


def is_unit(v, N):
    return 0 < v < N and math.gcd(v, N) == 1


def vdf_verify(N, x, y, pi, T):
    if N <= 3 or N % 2 == 0:
        return False, "bad-modulus"
    if T < 0:
        return False, "bad-steps"
    if not is_unit(y, N):
        return False, "non-canonical-y"
    if not is_unit(pi, N):
        return False, "non-canonical-pi"
    xr = x % N
    if not is_unit(xr, N) or xr == 1 or xr == N - 1:
        return False, "bad-input-x"
    l = hash_to_prime(x, y, T, N)
    r = pow(2, T, l)
    lhs = (int(gmpy2.powmod(pi, l, N)) * int(gmpy2.powmod(xr, r, N))) % N
    return (True, None) if lhs == y else (False, "equation-mismatch")


def s(n):
    return str(int(n))


def make_vectors(out):
    rsa2048 = int(open(__file__.rsplit("/", 2)[0] + "/fixtures/rsa-2048.json").read().split('"decimal": "')[1].split('"')[0])
    # A 512-bit modulus built from two fixed primes. TEST-ONLY: its factors are public (below).
    p512 = int(gmpy2.next_prime(gmpy2.mpz(3) ** 161))
    q512 = int(gmpy2.next_prime(gmpy2.mpz(7) ** 91))
    n512 = p512 * q512
    moduli = {"rsa-2048-challenge": rsa2048, "test-only-512": n512}
    positives = []
    xs = [2, 3, 123456789, (1 << 255) + 12345, rsa2048 // 3, rsa2048 - 2]
    for name, N in moduli.items():
        for i, x in enumerate(xs):
            for T in ([0, 1, 2, 255, 256, 257, 1000, 4096] if i < 3 else [3, 500, 20000]):
                if x % N in (0, 1, N - 1):
                    continue
                y, pi, l = vdf_eval(N, x, T)
                ok, why = vdf_verify(N, x, y, pi, T)
                assert ok, (name, x, T, why)
                positives.append({"modulus": name, "x": s(x), "T": T, "y": s(y), "pi": s(pi), "l": s(l)})
    negatives = []
    for name, N in moduli.items():
        x, T = 123456789, 1000
        y, pi, l = vdf_eval(N, x, T)

        def add(label, nx, ny, npi, nT, expect=None):
            ok, why = vdf_verify(N, nx, ny, npi, nT)
            assert not ok, label
            if expect:
                assert why == expect, (label, why)
            negatives.append({"modulus": name, "label": label, "x": s(nx), "y": s(ny), "pi": s(npi), "T": nT, "reason": why})

        add("y+1", x, y + 1, pi, T, "equation-mismatch")
        add("pi+1", x, y, pi + 1, T, "equation-mismatch")
        add("wrong T", x, y, pi, T + 1, "equation-mismatch")
        add("wrong x", x + 1, y, pi, T, "equation-mismatch")
        add("y=0 pi=0 (zero-work forgery)", x, 0, 0, T, "non-canonical-y")
        add("y=N pi=N", x, N, N, T, "non-canonical-y")
        add("y valid, pi=0", x, y, 0, T, "non-canonical-pi")
        add("y+N (non-canonical encoding of a valid y)", x, y + N, pi, T, "non-canonical-y")
        add("pi+N (non-canonical encoding of a valid pi)", x, y, pi + N, T, "non-canonical-pi")
        add("x=0", 0, y, pi, T, "bad-input-x")
        add("x=1", 1, y, pi, T, "bad-input-x")
        add("x=N-1", N - 1, y, pi, T, "bad-input-x")
        add("y=1 pi=1", x, 1, 1, T, "equation-mismatch")
    # Non-units need a known factor: only possible for the TEST-ONLY modulus.
    N = n512
    y, pi, l = vdf_eval(N, 123456789, 1000)
    for label, ny, npi, why in [("y is a multiple of p", p512, pi, "non-canonical-y"), ("pi is a multiple of q", y, q512, "non-canonical-pi")]:
        ok, got = vdf_verify(N, 123456789, ny, npi, 1000)
        assert not ok and got == why
        negatives.append({"modulus": "test-only-512", "label": label, "x": s(123456789), "y": s(ny), "pi": s(npi), "T": 1000, "reason": got})
    doc = {
        "provenance": {
            "kind": "SELF-WRITTEN independent reference vectors (NOT official / standard test vectors)",
            "why": "No published vectors exist for this package's hash-to-prime transcript; chiavdf is a class-group VDF.",
            "generator": "packages/pca-vdf/reference/wesolowski_ref.py vectors",
            "libraries": {"gmpy2": gmpy2.version(), "GMP": gmpy2.mp_version(), "python": sys.version.split()[0]},
            "transcript": "hash-to-prime v1: sha256(domain || lp(x) || lp(y) || lp(T) || lp(N) || lp(u32(256))), counter/block expansion, top+low bit set, first gmpy2.is_prime(.,40)",
        },
        "moduli": {
            "rsa-2048-challenge": "decimal in fixtures/rsa-2048.json",
            "test-only-512": {"N": s(n512), "p": s(p512), "q": s(q512), "note": "TEST ONLY: factors are public, so this modulus provides no delay"},
        },
        "positives": positives,
        "negatives": negatives,
    }
    with open(out, "w") as f:
        json.dump(doc, f, indent=1)


def main():
    cmd = sys.argv[1]
    if cmd == "vectors":
        make_vectors(sys.argv[2])
        return
    with open(sys.argv[2]) as f:
        req = json.load(f)
    out = []
    if cmd == "eval":
        for c in req:
            y, pi, l = vdf_eval(int(c["N"]), int(c["x"]), int(c["T"]))
            out.append({"y": s(y), "pi": s(pi), "l": s(l)})
    elif cmd == "isprime":
        out = [bool(is_prime(int(n))) for n in req]
    elif cmd == "verify":
        for c in req:
            ok, why = vdf_verify(int(c["N"]), int(c["x"]), int(c["y"]), int(c["pi"]), int(c["T"]))
            out.append({"ok": ok, "reason": why})
    else:
        raise SystemExit("unknown command")
    with open(sys.argv[3], "w") as f:
        json.dump(out, f)


main()
