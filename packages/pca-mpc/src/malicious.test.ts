/**
 * SPDZ malicious-security tests. Three themes, all REAL (the actual protocol runs; nothing mocked):
 *   (A) correctness still holds under HONEST parties: composeSecureMalicious == composeClear
 *       (and == the semi-honest runner's output);
 *   (B) a party that deviates in the ONLINE phase — wrong value at an open, forged MAC share, or an
 *       inconsistent Beaver opening — is CAUGHT by the MAC-check: the protocol ABORTS, no output;
 *   (C) the MAC-check never FALSE-aborts on honest runs (many random inputs), and abort is fail-closed.
 */

import { describe, expect, it } from 'vitest';
import { composeClear } from './compose';
import type { DecisionVector } from './party';
import { composeSecure } from './runner';
import { composeSecureMalicious } from './spdz-runner';
import {
  authShare,
  authValue,
  beaverMulAuth,
  type Deviation,
  genAuthTriple,
  MacCheckAbort,
  setupMac,
  SpdzEngine,
} from './spdz';
import { FieldRng, fmul } from './field';

/** Deterministic LCG so the random sweeps are reproducible. */
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

function randomVector(rnd: () => number, Q: number): DecisionVector {
  return {
    allow: rnd() < 0.5 ? 0 : 1,
    t: (1 + Math.floor(rnd() * 3)) as 1 | 2 | 3,
    rQuant: Math.floor(rnd() * (Q + 1)),
  };
}

// ===================================================================================================
describe('(A) SPDZ correctness under honest parties == cleartext composition', () => {
  it('matches composeClear over 200 random combos AND equals the semi-honest runner', () => {
    const rnd = lcg(0xc0ffee);
    const Q = 16;
    let runs = 0;
    for (let iter = 0; iter < 200; iter++) {
      const n = 1 + Math.floor(rnd() * 4); // 1..4 parties
      const vectors = Array.from({ length: n }, () => randomVector(rnd, Q));
      const expected = composeClear(vectors);
      const got = composeSecureMalicious(vectors, { Q, seed: BigInt(iter + 1) });
      expect(got.composed).toEqual(expected);
      expect(got.macChecked).toBe(true);
      // cross-check: the authenticated runner agrees with the semi-honest runner on honest inputs
      expect(got.composed).toEqual(composeSecure(vectors, { Q, seed: BigInt(iter + 1) }).composed);
      runs++;
    }
    expect(runs).toBe(200);
  });

  it('canonical 3-party user/org/regulator shape at full Q=100 (allow AND, t/r MAX)', () => {
    const Q = 100;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 12 },
      { allow: 1, t: 2, rQuant: 55 },
      { allow: 1, t: 1, rQuant: 30 },
    ];
    const got = composeSecureMalicious(vectors, { Q, seed: 7n });
    expect(got.composed).toEqual(composeClear(vectors));
    expect(got.composed).toEqual({ allow: 1, t: 2, rQuant: 55 });
  });

  it('single party (N=1): composes to its own vector, MAC-checked, 0 multiplications', () => {
    const got = composeSecureMalicious([{ allow: 1, t: 2, rQuant: 5 }], { Q: 8, seed: 1n });
    expect(got.composed).toEqual({ allow: 1, t: 2, rQuant: 5 });
    expect(got.multiplications).toBe(0);
    expect(got.macChecked).toBe(true);
  });

  it('is deterministic for a fixed seed', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 2, rQuant: 5 },
      { allow: 0, t: 3, rQuant: 9 },
    ];
    const a = composeSecureMalicious(vectors, { Q: 16, seed: 42n });
    const b = composeSecureMalicious(vectors, { Q: 16, seed: 42n });
    expect(a.composed).toEqual(b.composed);
    expect(a.opens).toBe(b.opens);
  });
});

// ===================================================================================================
describe('(B) a cheating party is CAUGHT by the MAC-check (abort, no silent wrong answer)', () => {
  const vectors: DecisionVector[] = [
    { allow: 1, t: 1, rQuant: 2 },
    { allow: 1, t: 2, rQuant: 4 },
    { allow: 1, t: 1, rQuant: 3 },
  ];
  const Q = 8;
  const seed = 2024n;

  it('baseline: the SAME inputs run HONESTLY produce the correct output (so only the cheat differs)', () => {
    const got = composeSecureMalicious(vectors, { Q, seed });
    expect(got.composed).toEqual(composeClear(vectors)); // { allow:1, t:2, rQuant:4 }
  });

  it('DEVIATION 1 — wrong VALUE share at an OUTPUT open => MacCheckAbort', () => {
    const honest = composeSecureMalicious(vectors, { Q, seed });
    const lastOpen = honest.opens - 1; // the final r-thermometer output open
    const dev: Deviation = { openIndex: lastOpen, party: 1, valueDelta: 1n };
    expect(() => composeSecureMalicious(vectors, { Q, seed, deviations: [dev] })).toThrow(MacCheckAbort);
  });

  it('DEVIATION 2 — forged MAC share (macDelta) at an open => MacCheckAbort', () => {
    const dev: Deviation = { openIndex: 0, party: 1, macDelta: 12345n };
    expect(() => composeSecureMalicious(vectors, { Q, seed, deviations: [dev] })).toThrow(MacCheckAbort);
  });

  it('DEVIATION 3 — inconsistent BEAVER opening (wrong d share at a multiplication) => MacCheckAbort', () => {
    // openIndex 0 is the first Beaver d-open (the first AND multiplication over the allow bits).
    const dev: Deviation = { openIndex: 0, party: 2, valueDelta: 7n };
    expect(() => composeSecureMalicious(vectors, { Q, seed, deviations: [dev] })).toThrow(MacCheckAbort);
  });

  it('a value-delta that would FLIP the decision is caught (no silent wrong answer)', () => {
    // allowOpen is the first OUTPUT open. Subtracting 1 from a party share would decode allow 1->0.
    const honest = composeSecureMalicious(vectors, { Q, seed });
    const allowOpenIndex = honest.opens - (1 + 3 + Q); // outputs are the last (1 + T_M + Q) opens
    const dev: Deviation = { openIndex: allowOpenIndex, party: 0, valueDelta: -1n };
    // Without a MAC this would silently return allow=0; with SPDZ it aborts instead.
    expect(() => composeSecureMalicious(vectors, { Q, seed, deviations: [dev] })).toThrow(MacCheckAbort);
  });

  it('SWEEP — a wrong value share at EVERY opening index is caught', () => {
    const honest = composeSecureMalicious(vectors, { Q, seed });
    let caught = 0;
    for (let idx = 0; idx < honest.opens; idx++) {
      const dev: Deviation = { openIndex: idx, party: 1, valueDelta: 3n };
      let aborted = false;
      try {
        composeSecureMalicious(vectors, { Q, seed, deviations: [dev] });
      } catch (e) {
        aborted = e instanceof MacCheckAbort;
      }
      if (aborted) caught++;
    }
    expect(caught).toBe(honest.opens); // every single open position is protected
    expect(honest.opens).toBeGreaterThan(10);
  });

  it('UNIT — a tampered Beaver opening yields a WRONG value but the MAC-check rejects it', () => {
    const rng = new FieldRng(99n);
    const ctx = setupMac(3, rng);
    const xv = 6n;
    const yv = 7n;
    const x = authShare(xv, ctx, rng);
    const y = authShare(yv, ctx, rng);
    const triple = genAuthTriple(ctx, rng);

    // Honest: open the product, MAC-check passes, value is exactly x*y.
    const honestEngine = new SpdzEngine(ctx);
    const z = beaverMulAuth(x, y, triple, ctx, honestEngine);
    const zOpen = honestEngine.open(z); // index 2 (after d=0, e=1)
    expect(zOpen).toBe(fmul(xv, yv));
    expect(authValue(z)).toBe(fmul(xv, yv));
    expect(() => honestEngine.macCheck(new FieldRng(1234n))).not.toThrow();

    // Malicious: a party corrupts the z-open (index 2). The opened value is now WRONG...
    const dev: Deviation = { openIndex: 2, party: 1, valueDelta: 100n };
    const badEngine = new SpdzEngine(ctx, [dev]);
    const z2 = beaverMulAuth(x, y, triple, ctx, badEngine);
    const badOpen = badEngine.open(z2);
    expect(badOpen).not.toBe(fmul(xv, yv)); // a naive protocol would accept this wrong product
    // ...but the MAC-check catches it.
    expect(() => badEngine.macCheck(new FieldRng(1234n))).toThrow(MacCheckAbort);
  });

  it('UNIT — a forged MAC share alone (value untouched) is caught', () => {
    const rng = new FieldRng(555n);
    const ctx = setupMac(2, rng);
    const x = authShare(42n, ctx, rng);
    const dev: Deviation = { openIndex: 0, party: 0, macDelta: 1n };
    const engine = new SpdzEngine(ctx, [dev]);
    const opened = engine.open(x);
    expect(opened).toBe(42n); // the value itself looks fine...
    expect(() => engine.macCheck(new FieldRng(7n))).toThrow(/MAC-check FAILED/); // ...but the MAC betrays it
  });
});

// ===================================================================================================
describe('(C) no false-abort on honest runs, and abort is fail-closed', () => {
  it('honest runs NEVER false-abort over 200 random combos', () => {
    const rnd = lcg(0xabcdef);
    const Q = 12;
    let ok = 0;
    for (let iter = 0; iter < 200; iter++) {
      const n = 1 + Math.floor(rnd() * 4);
      const vectors = Array.from({ length: n }, () => randomVector(rnd, Q));
      expect(() => {
        const got = composeSecureMalicious(vectors, { Q, seed: BigInt(iter * 7 + 1) });
        expect(got.composed).toEqual(composeClear(vectors));
        ok++;
      }).not.toThrow();
    }
    expect(ok).toBe(200);
  });

  it('honest MAC-check passes for many seeds (the residual is exactly 0)', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 3, rQuant: 5 },
      { allow: 0, t: 1, rQuant: 2 },
    ];
    for (let s = 1; s <= 50; s++) {
      expect(() => composeSecureMalicious(vectors, { Q: 8, seed: BigInt(s) })).not.toThrow();
    }
  });

  it('abort is FAIL-CLOSED: on detected cheating no result is produced', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 1 },
      { allow: 1, t: 1, rQuant: 1 },
    ];
    const honest = composeSecureMalicious(vectors, { Q: 8, seed: 3n });
    const dev: Deviation = { openIndex: honest.opens - 1, party: 0, valueDelta: 5n };
    let result: unknown = 'SENTINEL';
    try {
      result = composeSecureMalicious(vectors, { Q: 8, seed: 3n, deviations: [dev] });
    } catch (e) {
      expect(e).toBeInstanceOf(MacCheckAbort);
    }
    expect(result).toBe('SENTINEL'); // assignment never happened => no output leaked
  });

  it('composeSecureMalicious([]) fails closed (no parties)', () => {
    expect(() => composeSecureMalicious([], { Q: 8 })).toThrow(/no parties/i);
  });
});
