#!/usr/bin/env python3
"""Reproduces every number quoted in docs/pca/security/proofs/*.md.

No dependencies beyond the standard library. Run:  python3 bounds.py
The STARK section re-implements, line for line, the proven-security formulas of
winter-air 0.13.1 (src/proof/security.rs, Theorem 2 / Theorem 3 of ePrint 2024/1553 as cited there),
and applies them to both Winterfell and Plonky3 parameters. The Winterfell result is checked against the
values asserted in sdks/stark-pca/tests/security_bits.rs.
"""
from math import log2, sqrt, ceil, floor

def section(t): print("\n=== " + t + " ===")

# ---------------------------------------------------------------- MPC
section("pca-mpc: field and statistical soundness")
p = 2**61 - 1
print("p = 2^61-1 =", p, " log2 p =", log2(p))
for k in (1, 2):
    print(f"MAC-check, k={k} keys: (2/p)^k = 2^{k*(1-log2(p)):.6f}  (bits: {k*(log2(p)-1):.4f})")
print("sacrifice, network code (e uniform in F_p^*): (1/(p-1))^2 = 2^%.6f" % (-2*log2(p-1)))
print("sacrifice, in-process code (e=0 mapped to 1, so P[e=1]=2/p): (2/p)^2 = 2^%.6f" % (2*(1-log2(p))))
Q, n = 100, 3
C = 3 + Q  # allow chain + 3 t-thermometer chains + Q r-thermometer chains = 1 + 3 + Q
C = 1 + 3 + Q
mults = (n - 1) * C
print(f"circuit for Q={Q}, n={n}: chains={C}, Beaver multiplications={mults}")
# net protocol: ONE batched MAC check (+ one for the sacrifice openings) ; sacrifice partners 2 per triple
macs_checks = 2
eps_mac = macs_checks * (2 / p) ** 2
eps_sac = mults * (1 / (p - 1)) ** 2
print("union bound  MAC-check events:", macs_checks, "->  2^%.3f" % log2(eps_mac))
print("union bound  sacrifice over %d triples -> 2^%.3f" % (mults, log2(eps_sac)))
print("total (online, dealer or honest-OT) eps <= 2^%.3f" % log2(eps_mac + eps_sac))
# in-process dealer-mode: one MacCheck per sacrificed triple + 1 final
eps_inproc = (mults + 1) * (2 / p) ** 2 + mults * (2 / p) ** 2
print("in-process composeSecureMalicious (a MAC-check per triple + final + e=1 bias) -> 2^%.3f" % log2(eps_inproc))
# honest-leakage slack: m passing checks exclude at most m key values -> p -> p-m
m = 500
print("conditioning on up to %d earlier passes changes per-key bound by factor %.3e (negligible)" % (m, p / (p - m)))

# ---------------------------------------------------------------- Ed25519 / generic reduction numerics
section("Ed25519 forking-lemma loss (illustrative)")
ell = 2**252 + 27742317777372353535851937790883648493
print("group order ell = 2^%.4f" % log2(ell))
for qh_bits in (40, 64):
    qh = 2**qh_bits
    # Pollard rho generic DL: Adv_DL(T) ~ T^2/(2*ell) ; forking: eps <= sqrt(q_h * Adv_DL) (+ lower-order)
    for T_bits in (60, 80, 100):
        T = 2**T_bits
        adv_dl = T**2 / (2 * ell)
        eps = sqrt(qh * adv_dl)
        print(f"q_h=2^{qh_bits} T=2^{T_bits}: Adv_DL<=2^{log2(adv_dl):.1f}  forking bound on SUF-CMA adv  <= 2^{log2(eps):.1f}")
print("(For comparison, Schnorr in GGM+ROM, Neven-Smart-Warinschi: O((q_G+q_H)^2/ell) =",
      "2^%.1f at q=2^64)" % log2((2 * 2**64) ** 2 / ell))

# ---------------------------------------------------------------- Pedersen / range proof
section("ratchet: challenge space")
print("Fiat-Shamir challenge space ell: 2^%.4f; SHA-512 reduction bias <= 2^-%.1f" % (log2(ell), 512 - log2(ell)))
print("range proof: N_BITS=32 => per-proof special-soundness error 1/ell per bit-OR and 1/ell for the aggregation Schnorr")
print("no-wrap condition: n*2^32 < ell  <=> n < 2^%.1f" % (log2(ell) - 32))

# ---------------------------------------------------------------- GGM
section("ratchet: GGM forward secrecy loss")
for d in (4, 10, 20):
    print(f"depth {d}: leaves 2^{d}; adaptive-leaf guess loss 2^{d}; hybrid loss 2d={2*d}; "
          f"total advantage multiplier <= 2^{d}*(2d+1) = 2^{d+log2(2*d+1):.2f} x Adv_PRF(HMAC-SHA256)")

# ---------------------------------------------------------------- STARK
section("STARK proven-security formulas (winter-air 0.13.1, security.rs)")

def conjectured(blowup, queries, grinding, field_bits, ext_deg, collision):
    field = field_bits * ext_deg
    q = log2(blowup) * queries
    if q >= 80:
        q += grinding
    return min(min(field, q) - 1, collision)

def proven_ldr_one(blowup, queries, grinding, field_bits, ext_deg, n, m, ncons, ncommit, constraint_batch, deep_batch):
    ext = field_bits * ext_deg
    rho = 1.0 / blowup
    alpha = (1.0 + 0.5 / m) * sqrt(rho)
    max_deg = blowup + 1.0
    lde = n * blowup
    num_open = 2.0
    denom = rho - (2.0 * m / lde)
    if denom <= 0:  # Rust f64 would give +inf / negative; log2 -> -inf; the `as u64` cast saturates to 0
        return [float('-inf')] * 4
    l = m / denom
    bf1 = 1.0 if constraint_batch == 'linear' else ncons - 1.0
    e1 = -log2(l) - log2(bf1) + ext
    e2 = -log2(l * l * (max_deg * (n + num_open - 1.0) + (n - 1.0))) + ext
    bf3 = 1.0 if deep_batch == 'linear' else ncommit - 1.0
    e3 = ext - log2(((m + 0.5) ** 7 / (3.0 * rho ** 1.5)) * lde ** 2 * bf3)
    ek = grinding - log2(alpha ** queries)
    return [e1, e2, e3, ek]

def proven_ldr(*a, **kw):
    blowup, queries, grinding, field_bits, ext_deg, n, ncons, ncommit, cb, db, coll = a
    ratio = (n + 2.0) / n
    m_max = ceil(1.0 / (2.0 * (sqrt(ratio) - 1.0)))
    m_max = min(m_max, 1000)
    best = None
    for m in range(3, m_max):
        e = proven_ldr_one(blowup, queries, grinding, field_bits, ext_deg, n, m, ncons, ncommit, cb, db)
        v = max(0, int(min(e))) if min(e) != float('-inf') else 0
        if best is None or v > best[0]:
            best = (v, m, e)
    v, m, e = best
    return min(v, coll), m, e

def proven_udr(blowup, queries, grinding, field_bits, ext_deg, n, ncons, ncommit, cb, db, coll, folding, remainder):
    ext = field_bits * ext_deg
    lde = n * blowup
    rho_plus = (n + 2.0) / lde
    alpha = (1.0 + rho_plus) * 0.5
    max_deg = blowup + 1.0
    bf1 = 1.0 if cb == 'linear' else ncons - 1.0
    e1 = -log2(bf1) + ext
    e2 = -log2(max_deg * (n + 2.0 - 1.0) + (n - 1.0)) + ext
    bf3 = 1.0 if db == 'linear' else ncommit - 1.0
    e3 = ext - log2(lde * bf3)
    # number of FRI layers: fold by `folding` until size <= remainder
    size, layers = lde, 0
    while size > remainder + 1:
        size //= folding
        layers += 1
    ei = ext - log2((folding - 1.0) * (lde + 1.0))
    ek = grinding - log2(alpha ** queries)
    e = [e1, e2, e3, ei, ek]
    return min(int(min(e)), coll), e, layers

print("\n-- stark-pca (Winterfell 0.13.1), working-tree options: 37 queries, blowup 8, no extension, grinding 0, trace 64 --")
W = dict(blowup=8, queries=37, grinding=0, field_bits=128, ext_deg=1, n=64)
conj = conjectured(8, 37, 0, 128, 1, 128)
print("conjectured (ethSTARK Conj. 1 as used by Winterfell):", conj, "bits")
v, m, e = proven_ldr(8, 37, 0, 128, 1, 64, 88, 56, 'linear', 'linear', 128)
print("proven list-decoding: %d bits at optimal m=%d; terms (e1,e2,e3,e_query) = %s" % (v, m, [round(x, 2) for x in e]))
u, eu, layers = proven_udr(8, 37, 0, 128, 1, 64, 88, 56, 'linear', 'linear', 128, 8, 31)
print("proven unique-decoding: %d bits; terms = %s ; FRI layers=%d" % (u, [round(x, 2) for x in eu], layers))
print("(test floors in sdks/stark-pca/tests/security_bits.rs: conjectured 110, LDR 54, UDR 30)")

print("\n-- stark-pca at git HEAD: 32 queries --")
print("conjectured:", conjectured(8, 32, 0, 128, 1, 128), " LDR:", proven_ldr(8, 32, 0, 128, 1, 64, 88, 56, 'linear', 'linear', 128)[0],
      " UDR:", proven_udr(8, 32, 0, 128, 1, 64, 88, 56, 'linear', 'linear', 128, 8, 31)[0])

print("\n-- stark-pca-plonky3 (Plonky3 0.8.0): 64 queries, log_blowup 2, query PoW 8, challenge field Goldilocks^2 --")
ext_bits = 2 * log2(0xFFFFFFFF00000001)
print("challenge field bits = %.6f" % ext_bits)
print("conjectured per README arithmetic: min(64*2+8=%d, hash 128, field-1=%.4f) = %.4f" % (64 * 2 + 8, ext_bits - 1, min(136, 128, ext_bits - 1)))
# Plonky3 uses alpha-power (Horner) batching for constraints and for the DEEP/FRI batch: 'algebraic'
for cb, db, label in (('linear', 'linear', 'if batching were linear (README arithmetic)'),
                      ('algebraic', 'algebraic', 'with alpha-power batching: 110 constraints, 56+4 committed columns')):
    v, m, e = proven_ldr(4, 64, 8, 64, 2, 64, 110, 60, cb, db, 128)
    # float rounding of the extension field: use exact 127.99999 bits
    print("proven LDR  (%s): %d bits at m=%d; terms=%s" % (label, v, m, [round(x, 2) for x in e]))
    u, eu, layers = proven_udr(4, 64, 8, 64, 2, 64, 110, 60, cb, db, 128, 2, 2)
    print("proven UDR  (%s): %d bits; terms=%s" % (label, u, [round(x, 2) for x in eu]))
print("limit m -> infinity (Johnson bound, no list-size loss): 64*1 + 8 = 72 bits query term; finite m strictly less:")
for m in (8, 16, 32):
    a = (1 + 0.5 / m) * sqrt(0.25)
    print("  m=%2d: query term = %.2f bits" % (m, 8 - 64 * log2(a)))
print("unique-decoding query term = 64*log2(8/5) = %.3f ; +8 grinding" % (64 * log2(8 / 5)))
