"""Independent reference for the pca-abe differential tests (py_ecc, NOT @noble/curves).

Regenerate with:  uv run --with py_ecc==8.0.0 python gen_vectors_fame.py > ../src/audit/vectors/fame-pyecc.json

Scheme: FAME (Agrawal and Chase, CCS 2017, ePrint 2017/807), type-3 pairing, see src/fame.ts. For each policy the
reference draws every scalar, builds the span program with its OWN code (not the tree-Lagrange shortcut the
package uses to decrypt), recomputes the master key, a user key and a ciphertext with py_ecc only, then
DECRYPTS in py_ecc by solving sum_i w_i M_i = (1,0,..,0) with Gaussian elimination over Z_r, and asserts the recovered
KEM key equals T1^s1 * T2^s2 before emitting anything.
"""
import hashlib, json, random, sys
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.g2_primitives import G1_to_pubkey, G2_to_signature
from py_ecc.optimized_bls12_381 import G1, G2, multiply, add, neg, pairing, curve_order, Z1
from py_ecc.optimized_bls12_381 import FQ12

DST = b"ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1"
R = curve_order
rng = random.Random(0xFA3E5)


def h2c(msg):
    return hash_to_G1(msg, DST, hashlib.sha256)


def H_attr(y, l, t):
    a = y.encode("utf-8")
    return h2c(b"\x01" + len(a).to_bytes(4, "big") + a + bytes([l, t]))


def H_col(j, l, t):
    return h2c(b"\x02" + j.to_bytes(4, "big") + bytes([l, t]))


def gt_pow(x, k):
    k %= R
    r = FQ12.one()
    b = x
    while k:
        if k & 1:
            r = r * b
        b = b * b
        k >>= 1
    return r


def mul(P, k):
    k %= R
    return Z1 if k == 0 else multiply(P, k)


def inv(x):
    return pow(x, -1, R)


def sc():
    return rng.randrange(1, R)


def hx(n):
    return hex(n)[2:].zfill(64)


def g1h(P):
    return G1_to_pubkey(P).hex()


def g2h(P):
    return G2_to_signature(P).hex()


# ---- span program (independent code) ----
def msp(policy):
    rows = []
    state = {"n": 1}

    def walk(node, vec):
        if node[0] == "leaf":
            rows.append((node[1], vec))
            return
        _, t, kids = node
        base = state["n"]
        state["n"] += t - 1
        for i, kid in enumerate(kids, start=1):
            v = dict(vec)
            for k in range(1, t):
                v[base + k - 1] = pow(i, k, R)
            walk(kid, v)

    walk(policy, {0: 1})
    return rows, state["n"]


def solve(rows_vecs, ncols):
    """w with sum_i w_i * row_i = e1 over Z_r (Gauss-Jordan on the transposed system); None if unsatisfied."""
    m = len(rows_vecs)
    aug = [[rows_vecs[i].get(j, 0) % R for i in range(m)] + [1 if j == 0 else 0] for j in range(ncols)]
    piv = []
    r = 0
    for c in range(m):
        p = next((x for x in range(r, ncols) if aug[x][c] % R), None)
        if p is None:
            continue
        aug[r], aug[p] = aug[p], aug[r]
        iv = inv(aug[r][c])
        aug[r] = [v * iv % R for v in aug[r]]
        for x in range(ncols):
            if x != r and aug[x][c] % R:
                f = aug[x][c]
                aug[x] = [(a - f * b) % R for a, b in zip(aug[x], aug[r])]
        piv.append(c)
        r += 1
    if any(all(v == 0 for v in aug[x][:m]) and aug[x][m] % R for x in range(r, ncols)):
        return None
    w = [0] * m
    for k, c in enumerate(piv):
        w[c] = aug[k][m]
    return w


def leaf(a):
    return ("leaf", a)


CASES = [
    ("single", leaf("verb:read"), ["verb:read", "extra"]),
    ("and2", ("gate", 2, [leaf("holder:AAAA"), leaf("verb:read")]), ["verb:read", "holder:AAAA", "z"]),
    ("or2", ("gate", 1, [leaf("a"), leaf("b")]), ["b"]),
    ("2of3", ("gate", 2, [leaf("a"), leaf("b"), leaf("c")]), ["c", "a"]),
    ("3of5", ("gate", 3, [leaf(x) for x in "abcde"]), ["e", "b", "d"]),
    (
        "nested",
        ("gate", 2, [leaf("holder:x"), ("gate", 1, [leaf("verb:read"), leaf("verb:write")]), ("gate", 2, [leaf("café"), leaf("\U0001F510"), leaf("scope:/x*")])]),
        ["holder:x", "verb:write", "\U0001F510", "café"],
    ),
]

cases = []
e_gh = pairing(G2, G1)
for name, policy, attrs in CASES:
    a1, a2, b1, b2, d1, d2, d3 = (sc() for _ in range(7))
    r1, r2, sp, s1, s2 = (sc() for _ in range(5))
    sig = [sc() for _ in attrs]
    h1 = multiply(G2, a1)
    h2 = multiply(G2, a2)
    t1 = gt_pow(e_gh, d1 * a1 + d3)
    t2 = gt_pow(e_gh, d2 * a2 + d3)
    mskg = [multiply(G1, d) for d in (d1, d2, d3)]
    pw = [b1 * r1 % R, b2 * r2 % R, (r1 + r2) % R]
    k0 = [multiply(G2, p) for p in pw]
    a_inv = [inv(a1), inv(a2)]

    def term(oracle, t, sigma):
        s = Z1
        for l in range(3):
            s = add(s, mul(oracle(l, t), pw[l]))
        return multiply(add(s, multiply(G1, sigma)), a_inv[t])

    key = {}
    for y, sg in zip(attrs, sig):
        key[y] = [
            term(lambda l, t, y=y: H_attr(y, l, t), 0, sg),
            term(lambda l, t, y=y: H_attr(y, l, t), 1, sg),
            multiply(G1, (-sg) % R),
        ]
    kp = [
        add(term(lambda l, t: H_col(0, l, t), 0, sp), mskg[0]),
        add(term(lambda l, t: H_col(0, l, t), 1, sp), mskg[1]),
        add(multiply(G1, (-sp) % R), mskg[2]),
    ]
    rows, ncols = msp(policy)
    ct0 = [multiply(h1, s1), multiply(h2, s2), multiply(G2, (s1 + s2) % R)]

    def Q(j, l):
        return add(mul(H_col(j, l, 0), s1), mul(H_col(j, l, 1), s2))

    ct = []
    for (y, vec) in rows:
        row = []
        for l in range(3):
            acc = add(mul(H_attr(y, l, 0), s1), mul(H_attr(y, l, 1), s2))
            for j, m in vec.items():
                acc = add(acc, mul(Q(j, l), m))
            row.append(acc)
        ct.append(row)
    K = gt_pow(t1, s1) * gt_pow(t2, s2)
    own = [i for i, (y, _) in enumerate(rows) if y in key]
    w = solve([rows[i][1] for i in own], ncols)
    assert w is not None, name
    res = FQ12.one()
    for l in range(3):
        ctp = Z1
        kpp = kp[l]
        for wi, i in zip(w, own):
            ctp = add(ctp, mul(ct[i][l], wi))
            kpp = add(kpp, mul(key[rows[i][0]][l], wi))
        res = res * pairing(ct0[l], kpp) * pairing(k0[l], neg(ctp))
    assert res == K, "reference decryption failed for " + name

    def pol(n):
        return {"attr": n[1]} if n[0] == "leaf" else {"threshold": n[1], "of": [pol(k) for k in n[2]]}

    cases.append(
        {
            "name": name,
            "policy": pol(policy),
            "attrs": attrs,
            "scalars": {
                "a": [hx(a1), hx(a2)],
                "b": [hx(b1), hx(b2)],
                "d": [hx(d1), hx(d2), hx(d3)],
                "r": [hx(r1), hx(r2)],
                "sigma": [hx(x) for x in sig],
                "sigmaPrime": hx(sp),
                "s": [hx(s1), hx(s2)],
            },
            "h": [g2h(h1), g2h(h2)],
            "mskg": [g1h(x) for x in mskg],
            "k0": [g2h(x) for x in k0],
            "kp": [g1h(x) for x in kp],
            "key": {y: [g1h(x) for x in v] for y, v in key.items()},
            "ct0": [g2h(x) for x in ct0],
            "rows": [[g1h(x) for x in row] for row in ct],
            "decrypted_in_reference": True,
        }
    )
json.dump({"generator": "py_ecc 8.0.0", "dst": DST.decode(), "cases": cases}, sys.stdout, indent=1)
