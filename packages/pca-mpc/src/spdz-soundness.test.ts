/**
 * Audit residual limits 4 and 5a for the SPDZ layer (docs/pca/security/audit-crypto-packages.md):
 *
 *  (4) the MAC-check over the 61-bit field was ~2^-61 sound; every value now carries `MAC_KEYS = 2` MACs under
 *      independent global keys with independent challenge vectors, in the same batched check:
 *      error <= (2/p)^2 ~ 2^-120. The bound is checked analytically (the floor) AND empirically: the very same
 *      residual arithmetic (`macResiduals`) is run over deliberately tiny prime fields against a cheating-share
 *      attack, and the observed success rate must match the predicted (2/p - 1/p^2)^k within 4 sigma.
 *  (5a) a trusted dealer that hands out a wrong Beaver triple (c != a*b, with MACs computed on the wrong c so
 *      the triple is internally consistent) is detected by the sacrifice check and aborts the run.
 */
import { describe, expect, it } from 'vitest';
import { composeClear } from './compose';
import { FieldRng, PRIME, fmul } from './field';
import { splitMix64 } from './ot';
import type { DecisionVector } from './party';
import { reconstruct } from './sharing';
import {
  MAC_KEYS,
  MIN_MAC_SOUNDNESS_BITS,
  MacCheckAbort,
  SACRIFICE_PARTNERS,
  SpdzEngine,
  authShare,
  authValue,
  genTripleWithPartners,
  macResiduals,
  macSoundnessBits,
  sacrificeVerify,
  setupMac,
} from './spdz';
import { composeSecureMalicious } from './spdz-runner';

describe('(4) statistical soundness of the SPDZ MAC-check', () => {
  it('the default context carries 2 independent keys and at least 100 bits of soundness (floor), computed ~120', () => {
    const ctx = setupMac(3, new FieldRng(1n));
    expect(MAC_KEYS).toBeGreaterThanOrEqual(2);
    expect(1 + ctx.extraKeys.length).toBe(MAC_KEYS);
    const bits = macSoundnessBits(1 + ctx.extraKeys.length);
    expect(bits).toBeGreaterThanOrEqual(MIN_MAC_SOUNDNESS_BITS);
    expect(bits).toBeCloseTo(2 * (61 - 1), 3);
    // the keys are independent: distinct values and distinct share vectors
    expect(ctx.alpha).not.toBe(ctx.extraKeys[0]!.alpha);
    expect(ctx.alphaShares).not.toEqual(ctx.extraKeys[0]!.alphaShares);
  });

  it('a single-key context (~2^-60) is refused by the engine: fail closed below the floor', () => {
    const weak = setupMac(3, new FieldRng(2n), 1);
    expect(macSoundnessBits(1)).toBeLessThan(MIN_MAC_SOUNDNESS_BITS);
    expect(() => new SpdzEngine(weak)).toThrow(/soundness/);
    expect(() => setupMac(3, new FieldRng(2n), 0)).toThrow();
  });

  it('a forgery that is consistent under key 0 only (the old single-key attack) is caught by key 1, for every open and party', () => {
    for (let party = 0; party < 3; party++) {
      const rng = new FieldRng(BigInt(10 + party));
      const ctx = setupMac(3, rng);
      const delta = 4242n;
      // adversary knows alpha_0 (hypothetically even all of key 0) but not key 1
      const eng = new SpdzEngine(ctx, [{ openIndex: 0, party, valueDelta: delta, macKey: 0, macDelta: fmul(ctx.alpha, delta) }]);
      eng.open(authShare(5n, ctx, rng));
      expect(() => eng.macCheck(rng)).toThrow(MacCheckAbort);
    }
  });

  it('a forged MAC on key 1 ONLY is caught (every key is actually checked)', () => {
    const rng = new FieldRng(77n);
    const ctx = setupMac(3, rng);
    const eng = new SpdzEngine(ctx, [{ openIndex: 0, party: 1, macKey: 1, macDelta: 1n }]);
    eng.open(authShare(5n, ctx, rng));
    expect(() => eng.macCheck(rng)).toThrow(MacCheckAbort);
  });

  describe('bounded experiment on a deliberately tiny field (the real residual arithmetic, small modulus)', () => {
    /** Uniform value in [0, p) from a deterministic stream (rejection on 53 bits - exact uniformity). */
    const makeDraw = (seed: bigint, p: bigint) => {
      const next = splitMix64(seed);
      const limit = ((1n << 53n) / p) * p;
      return (): bigint => {
        for (;;) {
          const u = next() & ((1n << 53n) - 1n);
          if (u < limit) return u % p;
        }
      };
    };

    /**
     * One cheating-share attack on a single batched check over F_p with `keys` keys: n = 3 parties, 3 opens,
     * a cheating party 0 adds delta != 0 to its VALUE share of open 1 and a GUESSED MAC delta eps_l to its
     * key-l MAC share (the adversary does not know alpha, so eps_l is a uniform guess). Returns true iff the
     * batched check PASSES (the attack succeeds).
     */
    const attackOnce = (p: bigint, keys: number, draw: () => bigint): boolean => {
      const m = 3;
      const mod = (x: bigint): bigint => ((x % p) + p) % p;
      const alphaTotals = Array.from({ length: keys }, () => draw());
      const alphaShares = alphaTotals.map((a) => {
        const s = [draw(), draw()];
        s.push(mod(a - s[0]! - s[1]!));
        return s;
      });
      const opened = Array.from({ length: m }, () => ({ value: 0n, macShares: [] as bigint[][] }));
      for (let j = 0; j < m; j++) {
        const v = draw();
        const vs = [draw(), draw()];
        vs.push(mod(v - vs[0]! - vs[1]!));
        opened[j]!.value = v; // opened sum (honest)
        for (let l = 0; l < keys; l++) {
          const target = mod(alphaTotals[l]! * v);
          const ms = [draw(), draw()];
          ms.push(mod(target - ms[0]! - ms[1]!));
          opened[j]!.macShares.push(ms);
        }
      }
      // the cheat: party 0 lies about open 1
      const delta = 1n + (draw() % (p - 1n)); // non-zero
      opened[1]!.value = mod(opened[1]!.value + delta);
      for (let l = 0; l < keys; l++) {
        const eps = draw();
        opened[1]!.macShares[l]![0] = mod(opened[1]!.macShares[l]![0]! + eps);
      }
      const challenges = Array.from({ length: keys }, () => Array.from({ length: m }, () => draw()));
      const sigma = macResiduals(p, alphaShares, opened, challenges);
      return sigma.every((row) => mod(row.reduce((a, b) => a + b, 0n)) === 0n);
    };

    const predicted = (p: bigint, keys: number): number => (2 / Number(p) - 1 / (Number(p) * Number(p))) ** keys;

    const run = (p: bigint, keys: number, trials: number, seed: bigint): { observed: number; expected: number; sd: number } => {
      const draw = makeDraw(seed, p);
      let ok = 0;
      for (let t = 0; t < trials; t++) if (attackOnce(p, keys, draw)) ok++;
      const P = predicted(p, keys);
      return { observed: ok, expected: trials * P, sd: Math.sqrt(trials * P * (1 - P)) };
    };

    it('the residual core is exact: honest data passes with probability 1 over a tiny field', () => {
      const p = 251n;
      const draw = makeDraw(5n, p);
      // build honest data by hand: no cheat
      for (let t = 0; t < 200; t++) {
        const alpha = draw();
        const a0 = draw();
        const a1 = ((alpha - a0) % p + p) % p;
        const v = draw();
        const g0 = draw();
        const g1 = (((alpha * v - g0) % p) + p) % p;
        const sigma = macResiduals(p, [[a0, a1]], [{ value: v, macShares: [[g0, g1]] }], [[draw()]]);
        expect((sigma[0]![0]! + sigma[0]![1]!) % p).toBe(0n);
      }
    });

    it('1 key over a 16-bit prime: success rate ~ 2/p = 2^-15, matching the prediction within 4 sigma', () => {
      const p = 65521n; // largest prime below 2^16
      const r = run(p, 1, 2_000_000, 0x1111n);
      expect(r.expected).toBeGreaterThan(40);
      expect(Math.abs(r.observed - r.expected)).toBeLessThanOrEqual(4 * r.sd);
      expect(r.observed).toBeGreaterThan(0);
    }, 120_000);

    it('2 keys over an 8-bit prime: success rate ~ (2/p)^2, matching the prediction within 4 sigma; far below 1 key', () => {
      const p = 251n; // prime
      const two = run(p, 2, 1_000_000, 0x2222n);
      expect(two.expected).toBeGreaterThan(40);
      expect(Math.abs(two.observed - two.expected)).toBeLessThanOrEqual(4 * two.sd);
      const one = run(p, 1, 200_000, 0x3333n);
      expect(Math.abs(one.observed - one.expected)).toBeLessThanOrEqual(4 * one.sd);
      // amplification: the second key divides the success probability by ~p/2 (here ~125x)
      expect(one.observed / 200_000).toBeGreaterThan(50 * (two.observed / 1_000_000));
    }, 120_000);

    it('the analytic soundness-bits formula is a valid (conservative) lower bound for the exact tiny-field bits', () => {
      for (const [p, k] of [[251n, 1], [251n, 2], [65521n, 1], [65521n, 2], [PRIME, 2]] as const) {
        const exactBits = -Math.log2(predicted(p, k));
        expect(macSoundnessBits(k, p)).toBeLessThanOrEqual(exactBits + 1e-9);
        expect(exactBits - macSoundnessBits(k, p)).toBeLessThan(0.01);
      }
    });
  });
});

describe('(5a) a trusted dealer that lies about c is detected', () => {
  const V: DecisionVector[] = [
    { allow: 1, t: 1, rQuant: 3 },
    { allow: 1, t: 2, rQuant: 5 },
    { allow: 1, t: 1, rQuant: 1 },
  ];
  const Q = 8;

  it('an honest verified dealer: correct result, labelled trusted-dealer, triples certified', () => {
    const r = composeSecureMalicious(V, { Q, seed: 11n });
    expect(r.composed).toEqual(composeClear(V, Q));
    expect(r.offlineMode).toBe('trusted-dealer');
    expect(r.triplesVerified).toBe(true);
  });

  it('a dealer that gives a wrong product c = a*b + 1 aborts with MacCheckAbort (sacrifice), no output', () => {
    expect(() => composeSecureMalicious(V, { Q, seed: 12n, dealer: { fault: { keepCDelta: 1n } } })).toThrow(MacCheckAbort);
    expect(() => composeSecureMalicious(V, { Q, seed: 12n, dealer: { fault: { keepCDelta: 1n } } })).toThrow(/sacrifice FAILED/);
  });

  it('every kind of lie is caught: tiny, huge, p-1, and a lie in the partner or in only one of the partners', () => {
    for (const keepCDelta of [1n, 2n, PRIME - 1n, 123456789012345n]) {
      expect(() => composeSecureMalicious(V, { Q, seed: 13n, dealer: { fault: { keepCDelta } } })).toThrow(MacCheckAbort);
    }
    expect(() => composeSecureMalicious(V, { Q, seed: 14n, dealer: { fault: { partnerCDelta: [7n, undefined] } } })).toThrow(MacCheckAbort);
    expect(() => composeSecureMalicious(V, { Q, seed: 14n, dealer: { fault: { partnerCDelta: [undefined, 7n] } } })).toThrow(MacCheckAbort);
  });

  it('WITHOUT the verification the same lie slips through the MAC-check and corrupts the output (why it is needed)', () => {
    // true allow = 1 AND 0 = 0; the lie c = a*b + 1 turns the product into 0 + 1 = 1: a forged ALLOW
    const deny: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 3 },
      { allow: 0, t: 1, rQuant: 3 },
    ];
    expect(composeClear(deny, Q).allow).toBe(0);
    const wrong = composeSecureMalicious(deny, { Q, seed: 15n, dealer: { verifyTriples: false, fault: { keepCDelta: 1n } } });
    expect(wrong.macChecked).toBe(true); // the MACs are consistent with the lie
    expect(wrong.triplesVerified).toBe(false);
    expect(wrong.composed.allow).toBe(1); // silently wrong without the verification
    expect(() => composeSecureMalicious(deny, { Q, seed: 15n, dealer: { fault: { keepCDelta: 1n } } })).toThrow(MacCheckAbort);
  });

  it('sacrificeVerify certifies exactly the triples with c = a*b and drops nothing else', () => {
    const rng = new FieldRng(21n);
    const ctx = setupMac(3, rng);
    const batch = Array.from({ length: 10 }, () => genTripleWithPartners(ctx, rng));
    expect(batch[0]!.partners).toHaveLength(SACRIFICE_PARTNERS);
    const kept = sacrificeVerify(batch, ctx, rng);
    expect(kept).toHaveLength(10);
    for (const t of kept) {
      expect(reconstruct(t.c.value)).toBe(fmul(reconstruct(t.a.value), reconstruct(t.b.value)));
      expect(authValue(t.c)).toBe(fmul(authValue(t.a), authValue(t.b)));
    }
  });

  it('one bad triple hidden in a batch of 20 aborts the whole batch and emits nothing', () => {
    const rng = new FieldRng(22n);
    const ctx = setupMac(3, rng);
    const batch = Array.from({ length: 20 }, (_, i) => genTripleWithPartners(ctx, rng, SACRIFICE_PARTNERS, i === 13 ? { keepCDelta: 5n } : undefined));
    let out: unknown;
    expect(() => {
      out = sacrificeVerify(batch, ctx, rng);
    }).toThrow(MacCheckAbort);
    expect(out).toBeUndefined();
  });

  it('a forged opening during the sacrifice (a cheating party lying about rho or tau) is caught by the MAC-check', () => {
    for (const openIndex of [0, 1]) {
      for (const party of [0, 1, 2]) {
        const rng = new FieldRng(BigInt(30 + openIndex * 3 + party));
        const ctx = setupMac(3, rng);
        const batch = [genTripleWithPartners(ctx, rng)];
        expect(() => sacrificeVerify(batch, ctx, rng, [{ openIndex, party, valueDelta: 1n }])).toThrow(MacCheckAbort);
        expect(() => sacrificeVerify(batch, ctx, rng, [{ openIndex, party, macDelta: 1n, macKey: 1 }])).toThrow(MacCheckAbort);
      }
    }
  });

  it('a partner that does not share b, or a triple with no partners, is refused', () => {
    const rng = new FieldRng(40n);
    const ctx = setupMac(2, rng);
    const t = genTripleWithPartners(ctx, rng);
    const other = genTripleWithPartners(ctx, rng);
    expect(() => sacrificeVerify([{ keep: t.keep, partners: [other.keep] }], ctx, rng)).toThrow(MacCheckAbort);
    expect(() => sacrificeVerify([{ keep: t.keep, partners: [] }], ctx, rng)).toThrow(MacCheckAbort);
    expect(() => genTripleWithPartners(ctx, rng, 0)).toThrow();
  });

  it('dealing is fresh: two dealt triples (and their partners) differ', () => {
    const rng = new FieldRng(41n);
    const ctx = setupMac(2, rng);
    const a = genTripleWithPartners(ctx, rng);
    const b = genTripleWithPartners(ctx, rng);
    expect(authValue(a.keep.a)).not.toBe(authValue(b.keep.a));
    expect(authValue(a.partners[0]!.a)).not.toBe(authValue(a.partners[1]!.a));
  });
});
