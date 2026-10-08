/**
 * MALICIOUS-secure no-dealer offline tests — all REAL, nothing mocked. These are the tests for the
 * upgrade from a semi-honest offline to a malicious-with-abort offline:
 *
 *   (K) KOS correlation check on the IKNP OT extension — a CHEATING RECEIVER (tampered extension
 *       matrix `u`) is caught: the check fails → `MalOtAbort`. Honest extends never false-abort.
 *   (S) MASCOT sacrifice — a MALFORMED triple (a party corrupting a product share in the offline, i.e.
 *       a bad OT input, producing a self-MAC-consistent `c ≠ a·b`) is caught → `MacCheckAbort`, and NO
 *       triple is emitted. With the sacrifice OFF the same bad triple slips through (shows MACs alone
 *       do not catch it) — the sacrifice is what closes the gap.
 *   (I) input-consistency check — an input whose MAC does not match its value is caught → abort.
 *   (E) end-to-end — a malicious OFFLINE deviation makes `composeSecureMalicious` ABORT, never a wrong
 *       answer; honest runs still equal the cleartext composition and never false-abort.
 *   (G) GF(2^128) helper sanity (the field the KOS check lives in).
 *
 * The κ=128 Chou–Orlandi base OTs per party-pair are the one heavy cost, so where possible tests reuse
 * a small set of offline instances.
 */

import { describe, expect, it } from 'vitest';
import { fadd, fmul, FieldRng, mod } from './field';
import { reconstruct } from './sharing';
import { composeClear } from './compose';
import type { DecisionVector } from './party';
import { composeSecureMalicious } from './spdz-runner';
import { MacCheckAbort } from './spdz';
import { makeNoDealerOffline, NoDealerOffline } from './mascot';
import { KAPPA, MalOtAbort, OtChannel, otRandom, splitMix64 } from './ot';
import { gf128Add, gf128Mul, gf128MulByXi } from './gf128';

/** Generous timeout: these tests run real elliptic-curve base OTs + OT extension + KOS + sacrifice. */
const T = 180_000;

// ===================================================================================================
describe('(K) KOS correlation check catches a cheating OT-extension receiver', () => {
  it('a receiver who tampers the extension matrix u is caught (correlation check → abort), many seeds', () => {
    for (const seed of [1n, 2n, 3n, 7n, 42n, 101n, 777n, 2026n]) {
      const ch = new OtChannel(otRandom(splitMix64(seed)));
      const m = 61;
      const choiceBits = Array.from({ length: m }, (_, j) => j % 2);
      const msg0 = Array.from({ length: m }, (_, j) => BigInt(j));
      const msg1 = Array.from({ length: m }, (_, j) => BigInt(1_000 + j));
      // Malicious receiver: XOR a non-trivial delta into EVERY column of u (encodes inconsistent
      // choices). KOS catches this with probability 1 − 2^−128, i.e. deterministically here.
      ch.tamperU = (u) => {
        for (let i = 0; i < u.length; i++) u[i]! ^= 0b1011n;
      };
      expect(() => ch.extend(choiceBits, msg0, msg1)).toThrow(MalOtAbort);
    }
  }, T);

  it('honest extends NEVER false-abort — many rounds, sizes and choice patterns', () => {
    const ch = new OtChannel(otRandom(splitMix64(123456n)));
    for (let round = 0; round < 20; round++) {
      const m = [1, 5, 32, 61, 100][round % 5]!;
      const choiceBits = Array.from({ length: m }, (_, j) => (round * 3 + j * 7) % 2);
      const msg0 = Array.from({ length: m }, (_, j) => BigInt(j + round));
      const msg1 = Array.from({ length: m }, (_, j) => BigInt(900_000 + j + round));
      const { received } = ch.extend(choiceBits, msg0, msg1); // must not throw
      for (let j = 0; j < m; j++) {
        expect(received[j]).toBe(choiceBits[j] === 1 ? msg1[j] : msg0[j]); // and still correct
      }
    }
  }, T);

  it('a single-column tamper is caught exactly when that selector bit is 1 (KOS 1/2-per-column)', () => {
    // KOS soundness is amplified per deviating column; a lone column flip is masked iff s_i = 0. Over
    // many seeds we expect to see BOTH outcomes — demonstrating the check is really keyed to the
    // sender's secret selector s and not a trivial always-pass/always-fail.
    let caught = 0;
    const trials = 24;
    for (let seed = 1; seed <= trials; seed++) {
      const ch = new OtChannel(otRandom(splitMix64(BigInt(seed))));
      const m = 40;
      const choiceBits = Array.from({ length: m }, () => 0);
      const msg0 = Array.from({ length: m }, () => 0n);
      const msg1 = Array.from({ length: m }, () => 1n);
      ch.tamperU = (u) => {
        u[0]! ^= 1n;
      };
      try {
        ch.extend(choiceBits, msg0, msg1);
      } catch (e) {
        if (e instanceof MalOtAbort) caught++;
      }
    }
    expect(caught).toBeGreaterThan(0); // some s_0 = 1
    expect(caught).toBeLessThan(trials); // some s_0 = 0
  }, T);
});

// ===================================================================================================
describe('(S) MASCOT sacrifice catches a malformed triple (no bad triple emitted)', () => {
  it('a corrupted product share (bad OT input) in the offline is caught → MacCheckAbort, no triple', () => {
    for (const n of [2, 3]) {
      const off = makeNoDealerOffline(n, 500n + BigInt(n), {
        deviation: { productMul: 0, delta: 7n }, // corrupt the first delivered triple's c = a·b + 7
      });
      let result: unknown = 'SENTINEL';
      expect(() => {
        result = off.genAuthTriple();
      }).toThrow(MacCheckAbort);
      expect(result).toBe('SENTINEL'); // fail-closed: NO triple returned
    }
  }, T);

  it('WITHOUT the sacrifice, the same bad OT input slips through MAC-consistently (why we need it)', () => {
    // sacrifice:false reproduces the old semi-honest offline: the corrupted triple is emitted with
    // c = a·b + 7 but a perfectly consistent MAC (α·c). MACs ALONE cannot catch c != a·b — only the
    // sacrifice can. This is the gap the upgrade closes.
    const off = makeNoDealerOffline(2, 999n, {
      sacrifice: false,
      deviation: { productMul: 0, delta: 7n },
    });
    const alpha = off.macContext.alpha;
    const tr = off.genAuthTriple(); // does NOT throw
    const a = reconstruct(tr.a.value);
    const b = reconstruct(tr.b.value);
    const c = reconstruct(tr.c.value);
    expect(c).toBe(fadd(fmul(a, b), 7n)); // c is WRONG (= a·b + 7)
    expect(c).not.toBe(fmul(a, b));
    expect(reconstruct(tr.c.mac)).toBe(fmul(alpha, c)); // yet the MAC is CONSISTENT with the wrong c
  }, T);

  it('honest triples survive the sacrifice: c = a·b and MAC-valid under the distributed α', () => {
    for (const n of [2, 3]) {
      const off = makeNoDealerOffline(n, 1234n + BigInt(n));
      const alpha = off.macContext.alpha;
      for (let k = 0; k < 3; k++) {
        const tr = off.genAuthTriple();
        const a = reconstruct(tr.a.value);
        const b = reconstruct(tr.b.value);
        const c = reconstruct(tr.c.value);
        expect(c).toBe(fmul(a, b));
        expect(reconstruct(tr.c.mac)).toBe(fmul(alpha, c));
      }
    }
  }, T);
});

// ===================================================================================================
describe('(I) input-consistency check', () => {
  it('catches an input whose MAC does not match its value → abort', () => {
    const off = makeNoDealerOffline(3, 4242n);
    const honest = off.authInput(123456789n, 1);
    // Tamper: make the MAC inconsistent with the value (as a malicious authentication would).
    const tampered = { value: honest.value.slice(), mac: honest.mac.slice() };
    tampered.mac[0] = fadd(tampered.mac[0]!, 99n);
    expect(() => off.checkInputConsistency([tampered])).toThrow(MacCheckAbort);
  }, T);

  it('passes a batch of honest inputs (no false-abort), and is a no-op for an empty batch', () => {
    const off = makeNoDealerOffline(3, 4243n);
    const inputs = [off.authInput(0n, 0), off.authInput(1n, 1), off.authInput(987654321n, 2)];
    expect(() => off.checkInputConsistency(inputs)).not.toThrow();
    expect(() => off.checkInputConsistency([])).not.toThrow();
  }, T);
});

// ===================================================================================================
describe('(E) end-to-end: malicious offline deviation ABORTS; honest runs are correct', () => {
  it('a malicious offline deviation makes composeSecureMalicious abort, NOT a wrong answer', () => {
    const Q = 4;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 2 },
      { allow: 1, t: 3, rQuant: 1 },
    ];
    // Honest baseline (fresh malicious-secure offline) equals the cleartext composition.
    const honest = composeSecureMalicious(vectors, {
      Q,
      seed: 1n,
      offline: makeNoDealerOffline(2, 70n),
    });
    expect(honest.composed).toEqual(composeClear(vectors));

    // Now a party corrupts a product share in the offline → the sacrifice during triple generation
    // aborts → the whole composition aborts with NO output (never a silently wrong answer).
    const badOffline = makeNoDealerOffline(2, 70n, { deviation: { productMul: 0, delta: 3n } });
    let result: unknown = 'SENTINEL';
    expect(() => {
      result = composeSecureMalicious(vectors, { Q, seed: 1n, offline: badOffline });
    }).toThrow(MacCheckAbort);
    expect(result).toBe('SENTINEL'); // fail-closed
  }, T);

  it('honest malicious-secure offline == composeClear over several random inputs (no false-abort)', () => {
    const Q = 3;
    const pool = new Map<number, NoDealerOffline>();
    const shared = (n: number): NoDealerOffline => {
      let o = pool.get(n);
      if (!o) {
        o = makeNoDealerOffline(n, 8000n + BigInt(n));
        pool.set(n, o);
      }
      return o;
    };
    const rng = new FieldRng(0xfeedn);
    for (let iter = 0; iter < 8; iter++) {
      const n = 2 + (iter % 2); // 2 or 3 parties
      const vectors: DecisionVector[] = Array.from({ length: n }, () => ({
        allow: (rng.next() % 2n === 0n ? 0 : 1) as 0 | 1,
        t: (1 + Number(rng.next() % 3n)) as 1 | 2 | 3,
        rQuant: Number(rng.next() % BigInt(Q + 1)),
      }));
      const got = composeSecureMalicious(vectors, { Q, seed: BigInt(iter + 1), offline: shared(n) });
      expect(got.composed).toEqual(composeClear(vectors));
      expect(got.macChecked).toBe(true);
    }
  }, T);
});

// ===================================================================================================
describe('(G) GF(2^128) helper — the field the KOS check lives in', () => {
  const G = 1n; // multiplicative identity (x^0)
  const X = 2n; // the generator x

  it('multiplication is commutative, associative, has identity 1', () => {
    const a = 0x0123456789abcdef0fedcba987654321n;
    const b = 0xdeadbeefcafef00dba5eba11c0ffee77n;
    const c = 0x00112233445566778899aabbccddeeffn;
    expect(gf128Mul(a, b)).toBe(gf128Mul(b, a));
    expect(gf128Mul(a, G)).toBe(a);
    expect(gf128Mul(gf128Mul(a, b), c)).toBe(gf128Mul(a, gf128Mul(b, c)));
  });

  it('distributes over addition (XOR) and mulByXi == mul by x^i', () => {
    const a = 0x1111222233334444aaaabbbbccccddddn;
    const b = 0x5555666677778888eeeeffff00001111n;
    const c = 0x9999aaaabbbbccccddddeeeeffff0000n;
    // a·(b+c) == a·b + a·c
    expect(gf128Mul(a, gf128Add(b, c))).toBe(gf128Add(gf128Mul(a, b), gf128Mul(a, c)));
    // mulByXi(a, i) == a · x^i
    let xi = G;
    for (let i = 0; i < 20; i++) {
      expect(gf128MulByXi(a, i)).toBe(gf128Mul(a, xi));
      xi = gf128Mul(xi, X);
    }
  });

  it('reduction wraps at x^128 (x^127 · x == 0x87)', () => {
    const top = 1n << 127n; // x^127
    expect(gf128Mul(top, X)).toBe(0b10000111n); // x^128 ≡ x^7 + x^2 + x + 1
  });
});
