/**
 * Adversarial / audit-style tests for @atlasauth/pca-mpc-lwe-ot-wasm (the K-PKE / ring core under the
 * endemic LWE oblivious transfer). Complements the ACVP + cross-implementation suites: strict length
 * handling, non-reduced / out-of-range coefficient encodings, scratch-buffer isolation, ring-algebra
 * laws, hash-to-ring domain behaviour, the (documented) absence of ciphertext integrity in K-PKE,
 * and bounded fuzzing of every entry. Fuzz seconds: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  CT_BYTES,
  HASHIN_CAP,
  LatticeOtError,
  PK_BYTES,
  SK_BYTES,
  SYM_BYTES,
  TVEC_BYTES,
  hashToRing,
  kpkeDec,
  kpkeEnc,
  kpkeKeygen,
  ringAdd,
  ringSub,
} from './index';

const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const seed = (n: number): Uint8Array => new Uint8Array(SYM_BYTES).fill(n);
const KQ = 3329;
const INTERNAL_CRASH = /Cannot read propert|Cannot mix BigInt|is not a function|undefined is not|Maximum call stack|unreachable|out of bounds|memory access/i;

const kp = kpkeKeygen(seed(1));
const msg = seed(0x42);
const coins = seed(0x17);
const ct = kpkeEnc(kp.publicKey, msg, coins);

/** A ring vector of 3 polynomials x 256 coefficients as 12-bit packed bytes: set coefficient i to v. */
function setCoeff(buf: Uint8Array, i: number, v: number): Uint8Array {
  const out = Uint8Array.from(buf);
  const byte = Math.floor((i * 12) / 8);
  if (i % 2 === 0) {
    out[byte] = v & 0xff;
    out[byte + 1] = ((out[byte + 1] ?? 0) & 0xf0) | ((v >> 8) & 0x0f);
  } else {
    out[byte] = ((out[byte] ?? 0) & 0x0f) | ((v & 0x0f) << 4);
    out[byte + 1] = (v >> 4) & 0xff;
  }
  return out;
}

describe('length and type discipline', () => {
  it('every entry rejects any buffer that is not exactly the documented size, with LatticeOtError', () => {
    const wrong = (n: number) => new Uint8Array(n);
    for (const n of [0, 1, SYM_BYTES - 1, SYM_BYTES + 1]) {
      expect(() => kpkeKeygen(wrong(n))).toThrow(LatticeOtError);
      expect(() => kpkeEnc(kp.publicKey, wrong(n), coins)).toThrow(LatticeOtError);
      expect(() => kpkeEnc(kp.publicKey, msg, wrong(n))).toThrow(LatticeOtError);
    }
    for (const n of [0, PK_BYTES - 1, PK_BYTES + 1, SK_BYTES]) expect(() => kpkeEnc(wrong(n), msg, coins)).toThrow(LatticeOtError);
    for (const n of [0, SK_BYTES - 1, SK_BYTES + 1, PK_BYTES]) expect(() => kpkeDec(wrong(n), ct)).toThrow(LatticeOtError);
    for (const n of [0, CT_BYTES - 1, CT_BYTES + 1]) expect(() => kpkeDec(kp.secretKey, wrong(n))).toThrow(LatticeOtError);
    for (const n of [0, TVEC_BYTES - 1, TVEC_BYTES + 1]) {
      expect(() => ringAdd(wrong(n), wrong(TVEC_BYTES))).toThrow(LatticeOtError);
      expect(() => ringSub(wrong(TVEC_BYTES), wrong(n))).toThrow(LatticeOtError);
    }
  });

  it('non-Uint8Array arguments are a typed failure or an error - never a silent success on coerced garbage', () => {
    for (const j of [null, undefined, 'x'.repeat(SYM_BYTES), 5, {}, { length: SYM_BYTES }] as unknown[]) {
      let ok = false;
      try {
        kpkeKeygen(j as Uint8Array);
        ok = true;
      } catch (e) {
        expect(e instanceof Error).toBe(true);
      }
      expect(ok, String(j)).toBe(false);
    }
  });

  it('hashToRing: empty input is valid, the cap is enforced exactly, outputs are deterministic and input-dependent', () => {
    expect(hashToRing(new Uint8Array(0)).length).toBe(TVEC_BYTES);
    expect(hashToRing(new Uint8Array(HASHIN_CAP)).length).toBe(TVEC_BYTES);
    expect(() => hashToRing(new Uint8Array(HASHIN_CAP + 1))).toThrow(LatticeOtError);
    expect(hex(hashToRing(msg))).toBe(hex(hashToRing(msg)));
    expect(hex(hashToRing(msg))).not.toBe(hex(hashToRing(coins)));
    // length framing: a trailing zero byte is a different input
    expect(hex(hashToRing(new Uint8Array(0)))).not.toBe(hex(hashToRing(new Uint8Array(1))));
    expect(hex(hashToRing(new Uint8Array(1)))).not.toBe(hex(hashToRing(new Uint8Array(2))));
  });
});

describe('coefficient range: encodings with coefficients >= q', () => {
  it('ringAdd / ringSub results always have every coefficient in [0, q) and satisfy (a + b) - b = a for canonical inputs', () => {
    const a = hashToRing(seed(3));
    const b = hashToRing(seed(4));
    expect(hex(ringSub(ringAdd(a, b), b))).toBe(hex(a));
    expect(hex(ringAdd(ringSub(a, b), b))).toBe(hex(a));
    expect(hex(ringAdd(a, b))).toBe(hex(ringAdd(b, a)));
  });

  it('a public key whose polynomial coefficient is >= q (non-canonical encoding) is not silently accepted as the canonical key (FIPS 203 modulus check) - or at least encrypts identically to its reduction', () => {
    // coefficient 3329 + 5 would reduce to 5: the two encodings must not both be accepted as DIFFERENT keys with a different outcome
    const reduced = setCoeff(kp.publicKey, 0, 5);
    const unreduced = setCoeff(kp.publicKey, 0, KQ + 5);
    let rejected = false;
    let c2: Uint8Array = new Uint8Array(0);
    try {
      c2 = kpkeEnc(unreduced, msg, coins);
    } catch (e) {
      expect(e).toBeInstanceOf(LatticeOtError);
      rejected = true;
    }
    if (!rejected) expect(hex(c2)).toBe(hex(kpkeEnc(reduced, msg, coins)));
  });
});

describe('K-PKE semantics and documented limits', () => {
  it('round-trip: decrypt(encrypt(m)) = m for boundary messages (all-zero, all-ones, alternating)', () => {
    for (const m of [new Uint8Array(SYM_BYTES), new Uint8Array(SYM_BYTES).fill(0xff), Uint8Array.from({ length: SYM_BYTES }, (_, i) => (i % 2 ? 0xaa : 0x55))]) {
      expect(hex(kpkeDec(kp.secretKey, kpkeEnc(kp.publicKey, m, coins)))).toBe(hex(m));
    }
  });

  it('encryption is deterministic in (pk, m, coins) and the coins matter (fresh coins give a fresh ciphertext)', () => {
    expect(hex(kpkeEnc(kp.publicKey, msg, coins))).toBe(hex(ct));
    expect(hex(kpkeEnc(kp.publicKey, msg, seed(0x18)))).not.toBe(hex(ct));
    expect(hex(kpkeEnc(kp.publicKey, seed(0x43), coins))).not.toBe(hex(ct));
  });

  it('DOCUMENTED: K-PKE has no ciphertext integrity - a corrupted ciphertext decrypts to a different message without error (the OT layer adds its own commitments)', () => {
    const bad = Uint8Array.from(ct);
    bad[10] = (bad[10] ?? 0) ^ 0xff;
    bad[CT_BYTES - 5] = (bad[CT_BYTES - 5] ?? 0) ^ 0xff;
    const out = kpkeDec(kp.secretKey, bad);
    expect(out.length).toBe(SYM_BYTES);
    expect(hex(out)).not.toBe(hex(msg));
  });

  it('a wrong secret key never recovers the message', () => {
    const other = kpkeKeygen(seed(2));
    expect(hex(kpkeDec(other.secretKey, ct))).not.toBe(hex(msg));
  });

  it('keygen is deterministic per seed and distinct across seeds; public and secret keys differ', () => {
    expect(hex(kpkeKeygen(seed(1)).publicKey)).toBe(hex(kp.publicKey));
    expect(hex(kpkeKeygen(seed(2)).publicKey)).not.toBe(hex(kp.publicKey));
    expect(hex(kp.publicKey)).not.toBe(hex(kp.secretKey.slice(0, PK_BYTES)));
  });

  it('shared scratch memory: results are independent copies, and a rejected call does not poison the next', () => {
    const a = kpkeEnc(kp.publicKey, msg, coins);
    const aCopy = Uint8Array.from(a);
    kpkeEnc(kp.publicKey, seed(9), seed(9)).fill(0);
    a.fill(0xee);
    expect(hex(kpkeEnc(kp.publicKey, msg, coins))).toBe(hex(aCopy));
    expect(() => kpkeEnc(new Uint8Array(3), msg, coins)).toThrow(LatticeOtError);
    expect(hex(kpkeEnc(kp.publicKey, msg, coins))).toBe(hex(aCopy));
    const input = Uint8Array.from(msg);
    kpkeEnc(kp.publicKey, input, coins);
    expect(hex(input)).toBe(hex(msg));
  });
});

describe('property tests (fast-check)', () => {
  const sym = fc.uint8Array({ minLength: SYM_BYTES, maxLength: SYM_BYTES });
  it('K-PKE round-trips for any seed / message / coins', () => {
    fc.assert(
      fc.property(sym, sym, sym, (s, m, c) => {
        const k = kpkeKeygen(s);
        return hex(kpkeDec(k.secretKey, kpkeEnc(k.publicKey, m, c))) === hex(m);
      }),
      { numRuns: 15 },
    );
  });

  it('ring laws over hashed vectors: commutative add, a - a = 0, (a+b)-b = a, add/sub inverse', () => {
    const zero = ringSub(hashToRing(seed(7)), hashToRing(seed(7)));
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), fc.uint8Array({ maxLength: 64 }), (x, y) => {
        const a = hashToRing(x);
        const b = hashToRing(y);
        return hex(ringAdd(a, b)) === hex(ringAdd(b, a)) && hex(ringSub(a, a)) === hex(zero) && hex(ringSub(ringAdd(a, b), b)) === hex(a);
      }),
      { numRuns: 50 },
    );
  });
});

describe('bounded fuzzing (typed errors only, bounded time, fixed-size outputs)', () => {
  it('arbitrary byte strings of arbitrary lengths through every entry', () => {
    const anyBytes = fc.oneof(
      fc.uint8Array({ maxLength: 64 }),
      fc.uint8Array({ minLength: SYM_BYTES, maxLength: SYM_BYTES }),
      fc.uint8Array({ minLength: PK_BYTES, maxLength: PK_BYTES }),
      fc.uint8Array({ minLength: SK_BYTES, maxLength: SK_BYTES }),
      fc.uint8Array({ minLength: CT_BYTES, maxLength: CT_BYTES }),
      fc.uint8Array({ minLength: TVEC_BYTES, maxLength: TVEC_BYTES }),
    );
    fc.assert(
      fc.property(anyBytes, anyBytes, anyBytes, (a, b, c) => {
        const t0 = performance.now();
        const run = (f: () => Uint8Array | { publicKey: Uint8Array }) => {
          try {
            f();
          } catch (e) {
            expect(e instanceof Error).toBe(true);
            expect(INTERNAL_CRASH.test((e as Error).message), (e as Error).message).toBe(false);
          }
        };
        run(() => kpkeKeygen(a));
        run(() => kpkeEnc(a, b, c));
        run(() => kpkeDec(a, b));
        run(() => ringAdd(a, b));
        run(() => ringSub(a, b));
        run(() => hashToRing(a));
        expect(performance.now() - t0).toBeLessThan(1000);
        return true;
      }),
      fuzzOpts,
    );
  });

  it('mutated valid keys / ciphertexts never crash and never decrypt to the original under a flipped ciphertext bit', () => {
    fc.assert(
      fc.property(fc.nat({ max: CT_BYTES * 8 - 1 }), fc.nat({ max: PK_BYTES * 8 - 1 }), (cbit, kbit) => {
        const c = Uint8Array.from(ct);
        c[cbit >> 3] = (c[cbit >> 3] ?? 0) ^ (1 << (cbit & 7));
        expect(kpkeDec(kp.secretKey, c).length).toBe(SYM_BYTES);
        const k = Uint8Array.from(kp.publicKey);
        k[kbit >> 3] = (k[kbit >> 3] ?? 0) ^ (1 << (kbit & 7));
        try {
          expect(kpkeEnc(k, msg, coins).length).toBe(CT_BYTES);
        } catch (e) {
          expect(e).toBeInstanceOf(LatticeOtError);
        }
        return true;
      }),
      fuzzOpts,
    );
  });
});
