"""Independent reference for the pca-abe differential tests (py_ecc, NOT @noble/curves).

Regenerate with:  uv run --with py_ecc==8.0.0 python gen_vectors.py > ../src/audit/vectors/abe-pyecc.json

Scheme: Bethencourt-Sahai-Waters CP-ABE (S&P 2007), type-3 pairing adaptation (see src/abe.ts).
For each case the reference draws alpha, beta, r, r_j, q (leaf share), s and recomputes, with py_ecc only:
  Q    = hash_to_G1(attr, DST)                       RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ (draft-09 form in py_ecc)
  h    = beta*g2        f = beta^-1 * g1             master public elements
  aG1  = alpha*g1                                    (cross-checks Y = e(g1,g2)^alpha across implementations)
  D    = ((alpha+r)/beta) * g1                       user key root
  Dj   = r*g1 + r_j*Q   (G1)     Dpj = r_j*g2 (G2)   attribute key components
  C0   = s*h (G2)       C = q*g2 (G2)    Cp = q*Q (G1)   ciphertext components
and asserts in py_ecc's own GT, before emitting:
  leaf:  e(Dj, C) == e(g1,g2)^(r*q) * e(Cp, Dpj)
  root:  e(D, C0) == e(g1,g2)^((alpha+r)*s)
Shamir vectors are also produced independently (Lagrange interpolation over Z_r in Python integers).
"""
import hashlib, json, random, sys
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.g2_primitives import G1_to_pubkey, G2_to_signature
from py_ecc.optimized_bls12_381 import G1, G2, multiply, pairing, curve_order, normalize, add
from py_ecc.optimized_bls12_381 import FQ12

DST = b"ATLAS-PCA-ABE:BSW07:H-G1:SHA256-SSWU-RO:v2"
rng = random.Random(0xA71A5)  # deterministic: the fixture is reproducible

def h2c(attr: str):
    return hash_to_G1(attr.encode("utf-8"), DST, hashlib.sha256)

def gt_pow(x, k):
    r = FQ12.one()
    b = x
    while k:
        if k & 1:
            r = r * b
        b = b * b
        k >>= 1
    return r

ATTRS = ["verb:read", "scope:finance", "holder:AAAA", "resource:/tickets/*", "café", "café", "а", "a", "x" * 300, "\U0001F510"]

def inv(x):
    return pow(x, -1, curve_order)

cases = []
e_gg = pairing(G2, G1)
for attr in ATTRS:
    alpha, beta, r, rj, q, sc = (rng.randrange(1, curve_order) for _ in range(6))
    Q = h2c(attr)
    h = multiply(G2, beta)
    f = multiply(G1, inv(beta))
    aG1 = multiply(G1, alpha)
    D = multiply(G1, (alpha + r) * inv(beta) % curve_order)
    Dj = add(multiply(G1, r), multiply(Q, rj))
    Dpj = multiply(G2, rj)
    C0 = multiply(h, sc)
    C = multiply(G2, q)
    Cp = multiply(Q, q)
    assert pairing(C, Dj) == gt_pow(e_gg, r * q % curve_order) * pairing(Dpj, Cp), "leaf equation failed in the reference"
    assert pairing(C0, D) == gt_pow(e_gg, (alpha + r) * sc % curve_order), "root equation failed in the reference"
    assert pairing(h, f) == e_gg
    cases.append({
        "attr": attr,
        "alpha": hex(alpha)[2:].zfill(64),
        "beta": hex(beta)[2:].zfill(64),
        "r": hex(r)[2:].zfill(64),
        "rj": hex(rj)[2:].zfill(64),
        "q": hex(q)[2:].zfill(64),
        "s": hex(sc)[2:].zfill(64),
        "Q": G1_to_pubkey(Q).hex(),
        "h": G2_to_signature(h).hex(),
        "f": G1_to_pubkey(f).hex(),
        "aG1": G1_to_pubkey(aG1).hex(),
        "D": G1_to_pubkey(D).hex(),
        "Dj": G1_to_pubkey(Dj).hex(),
        "Dpj": G2_to_signature(Dpj).hex(),
        "C0": G2_to_signature(C0).hex(),
        "C": G2_to_signature(C).hex(),
        "Cp": G1_to_pubkey(Cp).hex(),
        "equations_checked_in_reference": True,
    })

# Shamir over Z_r: fixed coefficients, all shares, secret = f(0)
def horner(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % curve_order
    return acc

def lagrange0(points):
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = num * xj % curve_order
                den = den * (xj - xi) % curve_order
        total = (total + yi * num * pow(den, -1, curve_order)) % curve_order
    return total

shamir = []
for (t, n) in [(1, 1), (2, 3), (3, 3), (3, 5), (4, 7)]:
    coeffs = [rng.randrange(0, curve_order) for _ in range(t)]
    shares = [(i, horner(coeffs, i)) for i in range(1, n + 1)]
    assert lagrange0(shares[:t]) == coeffs[0]
    shamir.append({"t": t, "n": n, "secret": hex(coeffs[0])[2:].zfill(64), "shares": [[i, hex(y)[2:].zfill(64)] for i, y in shares]})

json.dump({"generator": "py_ecc 8.0.0", "dst": DST.decode(), "cases": cases, "shamir": shamir}, sys.stdout, indent=1)
