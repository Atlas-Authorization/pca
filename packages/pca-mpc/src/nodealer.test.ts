/**
 * No-dealer offline-phase tests (MASCOT-style, built on real OT) — all REAL, nothing mocked: the EC
 * base OT, the IKNP extension, and the Gilboa OT-multiplication actually run to produce the triples.
 *
 *   (A) the OT-based share multiplication is correct: Σz = (Σx)(Σy);
 *   (B) generated Beaver triples satisfy c = a·b and are correctly MAC'd with the DISTRIBUTED α, and no
 *       party holds any cleartext (a, b, c, or α) — everything is additively shared;
 *   (C) the online SPDZ phase consumes the NO-DEALER triples: honest runs equal `composeClear` over
 *       many random inputs (and equal the dealer runner), and a cheater is still CAUGHT (MAC-check
 *       aborts, no output);
 *   (D) determinism / fail-closed.
 *
 * The κ=128 Chou–Orlandi base OTs per party-pair are the one heavy cost, so tests SHARE a small set of
 * `NoDealerOffline` instances (one per party count) to amortize that setup; each draws fresh triples.
 */

import { describe, expect, it } from 'vitest';
import { fadd, fmul, FieldRng, mod } from './field';
import { reconstruct } from './sharing';
import { composeClear } from './compose';
import type { DecisionVector } from './party';
import { composeSecureMalicious } from './spdz-runner';
import { MacCheckAbort, type Deviation } from './spdz';
import { makeNoDealerOffline, NoDealerOffline } from './mascot';

/** Generous timeout: these tests run real elliptic-curve base OTs + OT extension. */
const T = 180_000;

/** One shared no-dealer offline per party count (base OTs amortized across every test that uses it). */
const sharedPool = new Map<number, NoDealerOffline>();
function shared(n: number): NoDealerOffline {
  let o = sharedPool.get(n);
  if (!o) {
    o = makeNoDealerOffline(n, 1000n + BigInt(n));
    sharedPool.set(n, o);
  }
  return o;
}

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
describe('(A) OT-based share multiplication (Gilboa) is correct, no dealer', () => {
  it('Σz = (Σx)(Σy) for random sharings across n = 2 and n = 3', () => {
    for (const n of [2, 3]) {
      const off = shared(n);
      const rng = new FieldRng(7n * BigInt(n));
      for (let trial = 0; trial < 3; trial++) {
        const x = Array.from({ length: n }, () => rng.next());
        const y = Array.from({ length: n }, () => rng.next());
        const z = off.otShareMultiply(x, y);
        expect(reconstruct(z)).toBe(fmul(reconstruct(x), reconstruct(y)));
      }
    }
  }, T);

  it('a single cross term x_i·y_j is additively shared between the two parties (Gilboa)', () => {
    // n=2, all of x on party 0 and all of y on party 1 ⇒ z reconstructs to x·y, and NEITHER party's
    // z-share equals the product (each is masked by the Gilboa randomness).
    const off = shared(2);
    const z = off.otShareMultiply([5n, 0n], [0n, 9n]);
    expect(reconstruct(z)).toBe(45n);
    expect(z[0]).not.toBe(45n);
    expect(z[1]).not.toBe(45n);
  }, T);
});

// ===================================================================================================
describe('(B) no-dealer authenticated Beaver triples: c = a·b, MAC-valid, nothing in the clear', () => {
  it("c = a·b and every component is MAC'd with the distributed α (n = 2, 3)", () => {
    for (const n of [2, 3]) {
      const off = shared(n);
      const alpha = off.macContext.alpha; // simulator-only; no party holds it
      for (let k = 0; k < 4; k++) {
        const tr = off.genAuthTriple();
        const a = reconstruct(tr.a.value);
        const b = reconstruct(tr.b.value);
        const c = reconstruct(tr.c.value);
        expect(c).toBe(fmul(a, b)); // Beaver relation
        expect(reconstruct(tr.a.mac)).toBe(fmul(alpha, a)); // SPDZ MACs Σγ = α·value
        expect(reconstruct(tr.b.mac)).toBe(fmul(alpha, b));
        expect(reconstruct(tr.c.mac)).toBe(fmul(alpha, c));
      }
    }
  }, T);

  it('the MAC key α is distributed: Σα_i = α and no single party holds α', () => {
    const off = shared(3);
    const ctx = off.macContext;
    let sum = 0n;
    for (const ai of off.alphaShares) sum = fadd(sum, ai);
    expect(sum).toBe(ctx.alpha);
    for (const ai of off.alphaShares) expect(ai).not.toBe(ctx.alpha);
    expect(off.alphaShares.length).toBe(3);
  }, T);

  it('no party holds the triple cleartext — each component is split into n shares, none the secret', () => {
    const off = shared(3);
    const tr = off.genAuthTriple();
    const a = reconstruct(tr.a.value);
    const c = reconstruct(tr.c.value);
    expect(tr.a.value.length).toBe(3);
    expect(tr.c.value.length).toBe(3);
    for (const s of tr.a.value) expect(s).not.toBe(a); // field-wide random shares
    for (const s of tr.c.value) expect(s).not.toBe(c);
    const macC = reconstruct(tr.c.mac);
    for (const g of tr.c.mac) expect(g).not.toBe(macC);
  }, T);

  it('authenticated INPUT sharing (no dealer): Σvalue = v and Σmac = α·v', () => {
    const off = shared(3);
    const alpha = off.macContext.alpha;
    for (const v of [0n, 1n, 123456789n]) {
      const inp = off.authInput(v, 1);
      expect(reconstruct(inp.value)).toBe(mod(v));
      expect(reconstruct(inp.mac)).toBe(fmul(alpha, mod(v)));
    }
  }, T);
});

// ===================================================================================================
describe('(C) the online SPDZ phase consumes NO-DEALER triples', () => {
  it('honest run == composeClear over many random inputs (1..3 parties, no-dealer triples)', () => {
    const rnd = lcg(0xd00d);
    const Q = 2;
    let runs = 0;
    for (let iter = 0; iter < 18; iter++) {
      const n = 1 + Math.floor(rnd() * 3); // 1..3 parties
      const vectors = Array.from({ length: n }, () => randomVector(rnd, Q));
      const got = composeSecureMalicious(vectors, { Q, seed: BigInt(iter + 1), offline: shared(n) });
      expect(got.composed).toEqual(composeClear(vectors));
      expect(got.macChecked).toBe(true);
      runs++;
    }
    expect(runs).toBe(18);
  }, T);

  it('agrees with the trusted-dealer malicious runner and the semi-honest cleartext', () => {
    const Q = 4;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 2 },
      { allow: 1, t: 3, rQuant: 1 },
    ];
    const noDealer = composeSecureMalicious(vectors, { Q, seed: 1n, offline: shared(2) });
    const dealer = composeSecureMalicious(vectors, { Q, seed: 1n });
    expect(noDealer.composed).toEqual(composeClear(vectors));
    expect(noDealer.composed).toEqual(dealer.composed);
  }, T);

  it('canonical 3-party user/org/regulator shape, no-dealer triples', () => {
    const Q = 8;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 2 },
      { allow: 1, t: 2, rQuant: 6 },
      { allow: 1, t: 1, rQuant: 3 },
    ];
    const got = composeSecureMalicious(vectors, { Q, seed: 1n, offline: shared(3) });
    expect(got.composed).toEqual(composeClear(vectors));
    expect(got.composed).toEqual({ allow: 1, t: 2, rQuant: 6 });
  }, T);

  it('single party (N=1) with no-dealer offline: no OT needed, composes to its own vector', () => {
    const off = shared(1);
    const got = composeSecureMalicious([{ allow: 1, t: 3, rQuant: 4 }], { Q: 8, seed: 1n, offline: off });
    expect(got.composed).toEqual({ allow: 1, t: 3, rQuant: 4 });
    expect(got.multiplications).toBe(0);
    expect(got.macChecked).toBe(true);
  }, T);

  it('a cheater is STILL caught with no-dealer triples (MAC-check aborts, no output)', () => {
    const Q = 4;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 1 },
      { allow: 1, t: 2, rQuant: 3 },
    ];
    const seed = 2026n;
    const honest = composeSecureMalicious(vectors, { Q, seed, offline: shared(2) });
    expect(honest.composed).toEqual(composeClear(vectors));

    // Deviate at the final output open: without a MAC this would silently flip the answer; SPDZ aborts.
    const dev: Deviation = { openIndex: honest.opens - 1, party: 1, valueDelta: 1n };
    let result: unknown = 'SENTINEL';
    expect(() => {
      result = composeSecureMalicious(vectors, { Q, seed, offline: shared(2), deviations: [dev] });
    }).toThrow(MacCheckAbort);
    expect(result).toBe('SENTINEL'); // fail-closed: no output produced

    // An inconsistent BEAVER opening (index 0 = the first authenticated multiplication) is caught too.
    const devBeaver: Deviation = { openIndex: 0, party: 0, valueDelta: 7n };
    expect(() =>
      composeSecureMalicious(vectors, { Q, seed, offline: shared(2), deviations: [devBeaver] }),
    ).toThrow(MacCheckAbort);
  }, T);
});

// ===================================================================================================
describe('(D) determinism and fail-closed', () => {
  it('is deterministic for a fixed offline seed (fresh instances, same seed ⇒ identical output)', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 2, rQuant: 2 },
      { allow: 0, t: 3, rQuant: 1 },
    ];
    const a = composeSecureMalicious(vectors, { Q: 3, seed: 9n, offline: makeNoDealerOffline(2, 5n) });
    const b = composeSecureMalicious(vectors, { Q: 3, seed: 9n, offline: makeNoDealerOffline(2, 5n) });
    expect(a.composed).toEqual(b.composed);
    expect(a.opens).toBe(b.opens);
  }, T);

  it('offline provider whose party count != number of vectors fails closed', () => {
    expect(() =>
      composeSecureMalicious([{ allow: 1, t: 1, rQuant: 0 }], { Q: 4, offline: shared(3) }),
    ).toThrow(/party count/i);
  }, T);

  it('honest no-dealer runs never false-abort (8 seeds)', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 3, rQuant: 2 },
      { allow: 1, t: 1, rQuant: 1 },
    ];
    const off = shared(2);
    for (let s = 1; s <= 8; s++) {
      expect(() => composeSecureMalicious(vectors, { Q: 3, seed: BigInt(s), offline: off })).not.toThrow();
    }
  }, T);
});
