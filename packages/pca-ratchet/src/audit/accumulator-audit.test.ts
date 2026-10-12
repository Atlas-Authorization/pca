import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { b64u, unb64u } from '@atlasauth/pca';
import {
  type BudgetProof,
  N_BITS,
  addCommitments,
  commitRisk,
  openCommitment,
  proveBudget,
  proveRiskRange,
  verifyBoundedBudget,
  verifyBudget,
  verifyRiskRange,
} from '../accumulator';
import { G, H, L, ZERO, encodePoint, encodeScalar, decodeScalar, decodePoint, mod, mul, numberToBytesLE, randScalar } from '../group';
import { dudect } from './_dudect';

/**
 * Adversarial audit of the Pedersen commitment + bit-decomposition range proof (Mechanism 2).
 *
 * Sources: Pedersen, "Non-interactive and information-theoretic secure verifiable secret sharing" (1991);
 * Cramer-Damgard-Schoenmakers, "Proofs of partial knowledge" (CRYPTO 1994) for the OR proof; Schnorr (1991);
 * Fiat-Shamir (1986); bit-decomposition range proofs as in Camenisch-Chaabouni-shelat (2008) and Maxwell's
 * Confidential Transactions. DEVIATIONS are recorded in docs/pca/security/audit-abe-ratchet.md.
 */

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const hx = (b64: string): string => hex(unb64u(b64) as Uint8Array);
const V = JSON.parse(readFileSync(join(__dirname, 'vectors', 'ristretto-oracle.json'), 'utf8')) as {
  baseMultiples: string[];
  H: string;
  pedersen: { v: string; b: string; C: string }[];
  budget: { name: string; sum: string; bMax: string; proof: BudgetProof; oracle: string }[];
};

function honest(risks: bigint[], bMax: bigint): { cs: ReturnType<typeof commitRisk>[]; sum: string; proof: BudgetProof } {
  const cs = risks.map((r) => commitRisk(r));
  return { cs, sum: addCommitments(cs.map((c) => c.commitment)), proof: proveBudget(risks, cs.map((c) => c.blinding), bMax) };
}

describe('generators: independent derivation (nothing up my sleeve)', () => {
  it('G is the ristretto255 base point and equals the Rust (curve25519-dalek) encoding of 1*G', () => {
    expect(hex(G.toRawBytes())).toBe(V.baseMultiples[1]);
  });

  it('i*G for i = 0..15 matches the independent oracle', () => {
    V.baseMultiples.forEach((expected, i) => expect(hex(mul(G, BigInt(i)).toRawBytes())).toBe(expected));
  });

  it('H re-derived here from the published label (RFC 9496 hash-to-group over SHA-512) equals the module constant AND the Rust oracle', () => {
    const label = 'atlas-pca-ratchet/pedersen-generator-H/v1';
    const mine = RistrettoPoint.hashToCurve(sha512(new TextEncoder().encode(label)));
    expect(mine.equals(H)).toBe(true);
    expect(hex(H.toRawBytes())).toBe(V.H);
  });

  it('H is a valid, non-identity point different from G, -G and every small multiple of G (no cheap known discrete log)', () => {
    expect(H.equals(ZERO)).toBe(false);
    expect(H.equals(G)).toBe(false);
    const Hb = hex(H.toRawBytes());
    const Gneg = hex(G.negate().toRawBytes());
    expect(Hb).not.toBe(Gneg);
    let acc = ZERO;
    for (let i = 1; i <= 20000; i++) {
      acc = acc.add(G);
      if (acc.equals(H) || acc.negate().equals(H)) throw new Error(`H = ±${i}*G`);
    }
  });

  it('the group order is the ristretto255 prime l and every point is prime order (l*H = identity, (l-1)*H = -H)', () => {
    expect(L).toBe(2n ** 252n + 27742317777372353535851937790883648493n);
    expect(H.multiplyUnsafe(L - 1n).equals(H.negate())).toBe(true);
    expect(G.multiplyUnsafe(L - 1n).equals(G.negate())).toBe(true);
  });

  it('a different label gives a different generator (domain separation of the derivation)', () => {
    const other = RistrettoPoint.hashToCurve(sha512(new TextEncoder().encode('atlas-pca-ratchet/pedersen-generator-H/v2')));
    expect(other.equals(H)).toBe(false);
  });
});

describe('Pedersen commitments: differential, binding and hiding sanity', () => {
  it('commitments to 12 (value, blinding) pairs match the independent Rust oracle byte-for-byte', () => {
    for (const p of V.pedersen) {
      const b = Buffer.from(p.b, 'hex');
      let bs = 0n;
      for (let i = b.length - 1; i >= 0; i--) bs = (bs << 8n) | BigInt(b[i] as number);
      const c = commitRisk(BigInt(p.v), bs);
      expect(hx(c.commitment)).toBe(p.C);
    }
  });

  it('opens only to its own (value, blinding); not to a neighbouring value or blinding; blinding aliases mod l open identically', () => {
    const c = commitRisk(42n);
    expect(openCommitment(c.commitment, 42n, c.blinding)).toBe(true);
    expect(openCommitment(c.commitment, 43n, c.blinding)).toBe(false);
    expect(openCommitment(c.commitment, 41n, c.blinding)).toBe(false);
    expect(openCommitment(c.commitment, 42n, c.blinding + 1n)).toBe(false);
    expect(openCommitment(c.commitment, 42n, c.blinding + L)).toBe(true); // same field element
    expect(openCommitment('not-a-point', 42n, c.blinding)).toBe(false);
    expect(openCommitment(c.commitment, -1n, c.blinding)).toBe(false);
  });

  it('hiding sanity: equal values with fresh blindings give unrelated commitments; different values with equal blinding differ by exactly (v1-v2)*G', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) seen.add(commitRisk(7n).commitment);
    expect(seen.size).toBe(200);
    const b = randScalar();
    const c1 = decodePoint(commitRisk(100n, b).commitment);
    const c2 = decodePoint(commitRisk(60n, b).commitment);
    expect(c1.subtract(c2).equals(mul(G, 40n))).toBe(true);
  });

  it('[LIMITATION, asserted] re-using ONE blinding for two commitments leaks the value difference to anyone (so blindings must be fresh per action)', () => {
    const b = randScalar();
    const d = decodePoint(commitRisk(1000n, b).commitment).subtract(decodePoint(commitRisk(3n, b).commitment));
    // an observer brute-forces the difference over a small domain
    let found = -1n;
    for (let k = 0n; k < 2000n; k++) if (mul(G, k).equals(d)) found = k;
    expect(found).toBe(997n);
  });

  it('binding is exactly the hardness of dlog_G(H): with a generator whose dlog IS known, the same commitment opens two ways (control)', () => {
    const k = 123456789n;
    const Hbad = mul(G, k); // a "sleeve" generator
    const commit = (v: bigint, r: bigint) => mul(G, v).add(mul(Hbad, r));
    const c = commit(5n, 77n);
    // equivocate: open to 9 with r' = r - (9-5)/k
    const inv = (a: bigint): bigint => {
      let [r0, r1, s0, s1] = [L, mod(a), 0n, 1n];
      while (r1 !== 0n) {
        const q = r0 / r1;
        [r0, r1] = [r1, r0 - q * r1];
        [s0, s1] = [s1, s0 - q * s1];
      }
      return mod(s0);
    };
    const r2 = mod(77n - 4n * inv(k));
    expect(commit(9n, r2).equals(c)).toBe(true);
    // with the REAL H the same trick would need dlog_G(H); it fails for every guess we can afford
    for (let guess = 1n; guess < 500n; guess++) {
      expect(mul(G, 9n).add(mul(H, mod(77n - 4n * inv(guess)))).equals(mul(G, 5n).add(mul(H, 77n)))).toBe(false);
    }
  });

  it('the all-zero commitment (identity) is accepted as input but no honest blinding produces it; zero blinding is never drawn', () => {
    for (let i = 0; i < 500; i++) expect(randScalar()).not.toBe(0n);
    expect(commitRisk(0n, 0n).commitment).toBe(encodePoint(ZERO));
  });

  it('homomorphism (fast-check): sum of commitments opens to the sums', () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt({ min: 0n, max: 1_000_000n }), { minLength: 0, maxLength: 8 }), (vals) => {
        const cs = vals.map((v) => commitRisk(v));
        const sum = addCommitments(cs.map((c) => c.commitment));
        const sv = vals.reduce((a, b) => a + b, 0n);
        const sb = cs.reduce((a, c) => mod(a + c.blinding), 0n);
        return openCommitment(sum, sv, sb);
      }),
      { numRuns: 60 },
    );
  });
});

describe('differential: the independent Rust verifier agrees with ours on 15 budget cases', () => {
  for (const c of V.budget) {
    it(`${c.name}: oracle=${c.oracle}`, () => {
      expect(verifyBudget(c.sum, BigInt(c.bMax), c.proof)).toBe(c.oracle === '1');
    });
  }
});

describe('range-proof soundness attacks', () => {
  const base = honest([10n, 20n, 5n], 100n);

  it('out-of-range witness: an over-budget honest prover gets a well-formed proof that is rejected (sweeping the boundary)', () => {
    for (const total of [99n, 100n, 101n, 102n, 150n]) {
      const h = honest([total], 100n);
      expect(verifyBudget(h.sum, 100n, h.proof)).toBe(total <= 100n);
    }
  });

  it('slack boundary at 2^32: ceiling 2^32-1 with total 0 / 5 / 2^32-1 verifies; total 2^32 does not', () => {
    const top = (1n << 32n) - 1n;
    for (const t of [0n, 5n, top]) {
      const h = honest([t], top);
      expect(verifyBudget(h.sum, top, h.proof)).toBe(true);
    }
    const over = honest([top + 1n], top);
    expect(verifyBudget(over.sum, top, over.proof)).toBe(false);
  });

  it('negative total: a total larger than the ceiling by exactly 2^32 (slack = -2^32, whose low 32 bits are 0) is rejected', () => {
    const bMax = 50n;
    const h = honest([bMax + (1n << 32n)], bMax);
    expect(verifyBudget(h.sum, bMax, h.proof)).toBe(false);
    const h2 = honest([bMax + (1n << 32n) + 3n], bMax);
    expect(verifyBudget(h2.sum, bMax, h2.proof)).toBe(false);
  });

  it('NEGATIVE-RISK ATTACK: a commitment to l-50 ("-50") cancels real risk in the budget proof alone, but verifyBoundedBudget refuses it', () => {
    const real = commitRisk(100n);
    const bl = randScalar();
    const neg = mul(G, mod(-50n)).add(mul(H, bl)); // commits to the field element -50
    const negEnc = encodePoint(neg);
    const sum = addCommitments([real.commitment, negEnc]); // commits to 50 as a field element
    const proof = proveBudget([50n], [mod(real.blinding + bl)], 60n); // prover claims total 50 <= 60
    // the budget proof ON ITS OWN is satisfied (this is why it is documented as insufficient)
    expect(verifyBudget(sum, 60n, proof)).toBe(true);
    // the per-commitment range proofs are what close the hole: no valid range proof exists for the "negative" one
    let neg_range: ReturnType<typeof proveRiskRange> | undefined;
    try {
      neg_range = proveRiskRange(mod(-50n), bl);
    } catch {
      neg_range = undefined;
    }
    if (neg_range) expect(verifyRiskRange(negEnc, neg_range)).toBe(false);
    const rp = proveRiskRange(100n, real.blinding);
    expect(verifyRiskRange(real.commitment, rp)).toBe(true); // 100 is in range
    expect(verifyBoundedBudget([real.commitment, negEnc], [rp, neg_range ?? rp], 60n, proof)).toBe(false);
  });

  it('an honest bounded budget verifies end to end; swapping any range proof, dropping one, or adding a commitment fails', () => {
    const vals = [3n, 9n, 0n];
    const cs = vals.map((v) => commitRisk(v));
    const rps = cs.map((c, i) => proveRiskRange(vals[i] as bigint, c.blinding));
    const bp = proveBudget(vals, cs.map((c) => c.blinding), 20n);
    const encs = cs.map((c) => c.commitment);
    expect(verifyBoundedBudget(encs, rps, 20n, bp)).toBe(true);
    expect(verifyBoundedBudget(encs, [rps[1]!, rps[0]!, rps[2]!], 20n, bp)).toBe(false);
    expect(verifyBoundedBudget(encs, rps.slice(0, 2), 20n, bp)).toBe(false);
    expect(verifyBoundedBudget([...encs, commitRisk(1n).commitment], [...rps, rps[0]!], 20n, bp)).toBe(false);
    expect(verifyBoundedBudget(encs, rps, 11n, bp)).toBe(false);
  });

  it('challenge reuse / replay: a valid proof is bound to its bMax, its commitment sum and its own bit commitments', () => {
    expect(verifyBudget(base.sum, 100n, base.proof)).toBe(true);
    expect(verifyBudget(base.sum, 101n, base.proof)).toBe(false);
    expect(verifyBudget(base.sum, 99n, base.proof)).toBe(false);
    const other = honest([10n, 20n, 5n], 100n); // same totals, fresh blindings => different sum point
    expect(verifyBudget(other.sum, 100n, base.proof)).toBe(false);
    // replaying a proof for a DIFFERENT statement with the same ceiling
    const small = honest([1n], 100n);
    expect(verifyBudget(small.sum, 100n, base.proof)).toBe(false);
  });

  it('transcript binding: splicing the OR proofs / agg proof of one proof into another (same statement shape) fails', () => {
    const p2 = honest([10n, 20n, 5n], 100n).proof;
    const mixed: BudgetProof = { ...base.proof, or: p2.or };
    expect(verifyBudget(base.sum, 100n, mixed)).toBe(false);
    const mixed2: BudgetProof = { ...base.proof, agg: p2.agg };
    expect(verifyBudget(base.sum, 100n, mixed2)).toBe(false);
    const mixed3: BudgetProof = { ...base.proof, or: base.proof.or.map((o, i) => (i === 0 ? p2.or[0]! : o)) };
    expect(verifyBudget(base.sum, 100n, mixed3)).toBe(false);
  });

  it('domain separation: a per-commitment range proof cannot be replayed as a budget proof for a statement with the same slack point', () => {
    const c = commitRisk(37n);
    const rp = proveRiskRange(37n, c.blinding);
    expect(verifyRiskRange(c.commitment, rp)).toBe(true);
    // choose cSum so that V = ceiling*G - cSum equals the commitment c: cSum = ceiling*G - c
    const ceiling = 500n;
    const cSum = mul(G, ceiling).subtract(decodePoint(c.commitment));
    expect(verifyBudget(encodePoint(cSum), ceiling, rp)).toBe(false);
    // and the reverse direction
    const bud = honest([10n], 500n);
    expect(verifyRiskRange(encodePoint(mul(G, 500n).subtract(decodePoint(bud.sum))), bud.proof)).toBe(false);
  });

  it('the risk-range proof is bound to ITS commitment (cannot be moved to another commitment, even one with the same value)', () => {
    const a = commitRisk(5n);
    const b = commitRisk(5n);
    const rp = proveRiskRange(5n, a.blinding);
    expect(verifyRiskRange(a.commitment, rp)).toBe(true);
    expect(verifyRiskRange(b.commitment, rp)).toBe(false);
    expect(verifyRiskRange(encodePoint(ZERO), rp)).toBe(false);
  });

  it('a range proof for a value >= 2^32 cannot be produced honestly and a forged one is rejected', () => {
    const v = 1n << 32n;
    const c = commitRisk(v);
    expect(verifyRiskRange(c.commitment, proveRiskRange(v, c.blinding))).toBe(false);
    const c2 = commitRisk((1n << 32n) - 1n);
    expect(verifyRiskRange(c2.commitment, proveRiskRange((1n << 32n) - 1n, c2.blinding))).toBe(true);
  });

  it('forged bit commitment (bit = 2) with an otherwise valid shape is rejected, as is an identity bit commitment', () => {
    const p = structuredClone(base.proof);
    p.bitCommitments[4] = encodePoint(mul(G, 2n).add(mul(H, 5n)));
    expect(verifyBudget(base.sum, 100n, p)).toBe(false);
    const q = structuredClone(base.proof);
    q.bitCommitments[0] = encodePoint(ZERO);
    expect(verifyBudget(base.sum, 100n, q)).toBe(false);
  });

  it('simulated-OR forgery: giving every bit proof the SIMULATED branch still needs the hash to close, so random responses never verify', () => {
    const p = structuredClone(base.proof);
    for (const o of p.or) {
      o.e0 = encodeScalar(randScalar());
      o.e1 = encodeScalar(randScalar());
      o.z0 = encodeScalar(randScalar());
      o.z1 = encodeScalar(randScalar());
    }
    expect(verifyBudget(base.sum, 100n, p)).toBe(false);
  });

  it('malleability: every byte flip in a sample of encoded fields, non-canonical scalar aliases (s+l) and padded / standard-alphabet base64 are rejected', () => {
    const flip = (s: string, byte: number, bit: number): string => {
      const b = new Uint8Array(unb64u(s) as Uint8Array);
      b[byte] = (b[byte] as number) ^ (1 << bit);
      return b64u(b);
    };
    const fields: [string, (p: BudgetProof, f: (s: string) => string) => void][] = [
      ['bit commitment', (p, f) => (p.bitCommitments[9] = f(p.bitCommitments[9] as string))],
      ['e0', (p, f) => (p.or[11]!.e0 = f(p.or[11]!.e0))],
      ['e1', (p, f) => (p.or[11]!.e1 = f(p.or[11]!.e1))],
      ['z0', (p, f) => (p.or[11]!.z0 = f(p.or[11]!.z0))],
      ['z1', (p, f) => (p.or[11]!.z1 = f(p.or[11]!.z1))],
      ['agg a', (p, f) => (p.agg.a = f(p.agg.a))],
      ['agg z', (p, f) => (p.agg.z = f(p.agg.z))],
    ];
    for (const [name, set] of fields) {
      for (const [byte, bit] of [[0, 0], [5, 3], [15, 7], [30, 1]] as const) {
        const p = structuredClone(base.proof);
        set(p, (s) => flip(s, byte, bit));
        expect(verifyBudget(base.sum, 100n, p), `${name} byte ${byte} bit ${bit}`).toBe(false);
      }
    }
    for (const name of ['e0', 'e1', 'z0', 'z1'] as const) {
      const p = structuredClone(base.proof);
      const o = p.or[2]!;
      o[name] = b64u(numberToBytesLE((decodeScalar(o[name]) + L) % (1n << 256n), 32)); // s + l
      expect(verifyBudget(base.sum, 100n, p), `alias ${name}`).toBe(false);
    }
    const padded = structuredClone(base.proof);
    padded.agg.z = padded.agg.z + '=';
    expect(verifyBudget(base.sum, 100n, padded)).toBe(false);
    const std = structuredClone(base.proof);
    std.agg.a = Buffer.from(unb64u(std.agg.a) as Uint8Array).toString('base64');
    if (std.agg.a !== base.proof.agg.a) expect(verifyBudget(base.sum, 100n, std)).toBe(false);
  });

  it('structural abuse never throws and never verifies: wrong n, short/long arrays, non-objects, null fields, huge ceilings', () => {
    const bad: unknown[] = [
      null, undefined, 1, 'x', [], {}, { ...base.proof, n: 31 }, { ...base.proof, n: 33 }, { ...base.proof, or: base.proof.or.slice(1) },
      { ...base.proof, bitCommitments: base.proof.bitCommitments.concat('AA') }, { ...base.proof, agg: null }, { ...base.proof, agg: { a: 1, z: 2 } },
      { ...base.proof, or: base.proof.or.map(() => null) },
    ];
    for (const b of bad) expect(verifyBudget(base.sum, 100n, b as BudgetProof)).toBe(false);
    expect(verifyBudget('garbage', 100n, base.proof)).toBe(false);
    expect(verifyBudget(base.sum, -1n, base.proof)).toBe(false);
    expect(verifyBudget(base.sum, 1.5, base.proof)).toBe(false);
  });

  it('ceilings above 2^32-1 are clamped (a stronger statement), so a bigger ceiling never weakens the check', () => {
    const big = 1n << 100n;
    const ok = honest([10n], big);
    expect(verifyBudget(ok.sum, big, ok.proof)).toBe(true);
    // a total above the clamp is refused even though it is below the nominal ceiling
    const tooBig = honest([(1n << 32n) + 5n], big);
    expect(verifyBudget(tooBig.sum, big, tooBig.proof)).toBe(false);
  });
});

describe('nonce / blinding hygiene', () => {
  it('proofs are randomized: 100 proofs of one statement share no Schnorr commitment, no OR challenge and no bit commitment', () => {
    const risks = [4n, 4n];
    const blinds = [11n, 13n];
    const as = new Set<string>();
    const e0s = new Set<string>();
    const bc = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const p = proveBudget(risks, blinds, 50n);
      as.add(p.agg.a);
      e0s.add(p.or[0]!.e0);
      bc.add(p.bitCommitments[0]!);
    }
    expect(as.size).toBe(100);
    expect(e0s.size).toBe(100);
    expect(bc.size).toBe(100);
  });

  it('Schnorr nonce reuse would leak the witness (algebra shown on the verifier equation), which is why every proof draws a fresh nonce', () => {
    // z = k + e*w. Two proofs sharing k give w = (z1 - z2)/(e1 - e2). Demonstrated with explicit scalars.
    const k = randScalar();
    const w = randScalar();
    const e1 = randScalar();
    const e2 = randScalar();
    const z1 = mod(k + e1 * w);
    const z2 = mod(k + e2 * w);
    const inv = (a: bigint): bigint => {
      let r = 1n;
      let e = L - 2n;
      let b = mod(a);
      while (e > 0n) {
        if (e & 1n) r = mod(r * b);
        b = mod(b * b);
        e >>= 1n;
      }
      return r;
    };
    expect(mod((z1 - z2) * inv(e1 - e2))).toBe(w);
  });
});

describe('toy-group exhaustive soundness (algebra of the OR and aggregation checks)', () => {
  // The group is Z_q x Z_q written additively with G = (1,0) and H = (0,1): two generators with NO relation, which
  // is the idealisation of "dlog_G(H) is unknown". The verifier's checks are linear, so special soundness of the OR
  // proof can be checked over every transcript. This is the protocol algebra only, not computational binding.
  const q = 13;
  const m = (x: number): number => ((x % q) + q) % q;

  /** For bit commitment B = (v, s): the set of challenges e0+e1 reachable for each announcement (a0, a1), over ALL (e0,z0,e1,z1). */
  function challengesPerAnnouncement(v: number, s: number): Map<number, Set<number>> {
    const out = new Map<number, Set<number>>();
    for (let e0 = 0; e0 < q; e0++)
      for (let z0 = 0; z0 < q; z0++) {
        // a0 = z0*H - e0*B ; a1 = z1*H - e1*(B-G)
        const a0x = m(-e0 * v);
        const a0y = m(z0 - e0 * s);
        for (let e1 = 0; e1 < q; e1++)
          for (let z1 = 0; z1 < q; z1++) {
            const key = ((a0x * q + a0y) * q + m(-e1 * (v - 1))) * q + m(z1 - e1 * s);
            const set = out.get(key) ?? new Set<number>();
            set.add((e0 + e1) % q);
            out.set(key, set);
          }
      }
    return out;
  }

  it('v = 0 and v = 1 (honest bits): some announcement admits two challenges, so a witness is extractable (positive control)', () => {
    for (const v of [0, 1]) expect([...challengesPerAnnouncement(v, 5).values()].some((set) => set.size > 1)).toBe(true);
  });

  it('for EVERY B = (v, s) with v not in {0,1}, each announcement admits exactly ONE challenge: a cheating prover can answer at most one, so soundness error is 1/q per bit', () => {
    let checked = 0;
    for (let v = 2; v < q; v++) {
      for (let s = 0; s < q; s++) {
        for (const [, set] of challengesPerAnnouncement(v, s)) expect(set.size).toBe(1);
        checked++;
      }
    }
    expect(checked).toBe((q - 2) * q);
  });

  it('aggregation without wrap: with n bits and 2^n - 1 < q, the map bits -> sum_i 2^i b_i is injective mod q onto [0, 2^n), so a verified aggregate equals the slack exactly', () => {
    const n = 3; // 7 < 13
    const seen = new Map<number, number>();
    for (let bits = 0; bits < 1 << n; bits++) {
      const v = m(bits);
      expect(seen.has(v)).toBe(false);
      seen.set(v, bits);
    }
    // negative slack never lands in [0, 2^n): -k mod q = q-k > 2^n - 1 for k <= q - 2^n
    for (let k = 1; k <= q - (1 << n); k++) expect(m(-k)).toBeGreaterThan((1 << n) - 1);
    // control: with 2^n >= q the same check FAILS (wrap-around), which is why N_BITS * (#addends) must stay << l
    const n2 = 4; // 15 >= 13
    const seen2 = new Set<number>();
    let collided = false;
    for (let bits = 0; bits < 1 << n2; bits++) {
      const v = m(bits);
      if (seen2.has(v)) collided = true;
      seen2.add(v);
    }
    expect(collided).toBe(true);
  });

  it('real parameters: N_BITS addends of up to 2^N_BITS each fit in l with a large margin (no wrap for any realistic action count)', () => {
    expect(N_BITS).toBe(32);
    const maxActions = 1n << 64n;
    expect(maxActions * (1n << BigInt(N_BITS))).toBeLessThan(L);
  });
});

describe('property: honest proofs verify iff total <= min(ceiling, 2^32-1) (fast-check)', () => {
  it('accepts exactly the in-budget totals', () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt({ min: 0n, max: 5000n }), { minLength: 0, maxLength: 4 }),
        fc.bigInt({ min: 0n, max: 12000n }),
        (risks, bMax) => {
          const h = honest(risks, bMax);
          const total = risks.reduce((a, b) => a + b, 0n);
          return verifyBudget(h.sum, bMax, h.proof) === (total <= bMax);
        },
      ),
      { numRuns: 40 },
    );
  });
});

const HEAVY = process.env['PCA_AUDIT_TIMING'] === '1';
const SAMPLES = Number(process.env['PCA_AUDIT_TIMING_SAMPLES'] ?? 2000);

describe('timing harness validation (ratchet)', () => {
  it('negative control: identical work on both classes is not flagged', () => {
    const buf = new Uint8Array(64).fill(7);
    let acc = 0;
    const r = dudect('same-work', () => buf, (b) => { for (let i = 0; i < b.length; i++) acc = (acc + (b[i] ?? 0)) | 0; return acc; }, { samples: 3000, inner: 200 });
    expect(r.maxAbsT).toBeLessThan(20);
  });
});

describe.skipIf(!HEAVY)('secret-dependent operations (PCA_AUDIT_TIMING=1)', () => {
  it('mul(): zero scalar vs random scalar (the group helper masks the zero case)', () => {
    const r = dudect('mul(P,k)', (cls) => (cls === 0 ? 0n : randScalar()), (k) => mul(H, k), { samples: SAMPLES });
    console.log(JSON.stringify(r));
    expect(r.maxAbsT).toBeLessThan(30);
  });

  it('commitRisk: risk = 0 vs random risk', () => {
    const r = dudect('commitRisk', (cls) => (cls === 0 ? 0n : BigInt(Math.floor(Math.random() * 2 ** 31))), (v) => commitRisk(v), { samples: SAMPLES });
    console.log(JSON.stringify(r));
    expect(r.maxAbsT).toBeLessThan(30);
  });

  it('range proof: value 0 vs value 2^32-1 (Hamming weight 0 vs 32 of the secret bits)', () => {
    const r = dudect('proveRiskRange', (cls) => (cls === 0 ? 0n : (1n << 32n) - 1n), (v) => proveRiskRange(v, 5n), { samples: Math.min(SAMPLES, 400) });
    console.log(JSON.stringify(r));
    expect(r.maxAbsT).toBeLessThan(30);
  });
});
