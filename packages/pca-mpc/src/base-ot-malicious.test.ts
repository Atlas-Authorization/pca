/**
 * MALICIOUS base-OT hardening tests (docs §7.1 item a/b/c) — the "no shortcuts" close of the OT stack.
 * These exercise the parts that upgrade the κ base OTs from semi-honest Chou–Orlandi to malicious
 * security against BOTH a cheating sender and a cheating receiver, plus the CSPRNG default:
 *   (P) POINT VALIDATION rejects off-curve, small-order (non-prime-order), and identity points;
 *   (Σ) the SCHNORR proof of knowledge of the sender's discrete log round-trips and rejects forgeries;
 *   (B) the MALICIOUS base OT catches a cheating SENDER (forged proof, wrong S, inconsistent ciphertext)
 *       and a cheating RECEIVER (off-curve / small-order R) → ABORT, and an honest run is correct;
 *   (C) randomness is the CSPRNG by DEFAULT; the deterministic SplitMix64 path is reachable ONLY behind
 *       an explicit test seed.
 */

import { describe, expect, it } from 'vitest';
import {
  add,
  assertInSubgroup,
  BASE,
  hasPrimeOrder,
  IDENTITY,
  isIdentity,
  isInSubgroup,
  isOnCurve,
  L,
  mul,
  mulBase,
  neg,
  type Point,
  PointValidationError,
  Q,
  schnorrProve,
  schnorrVerify,
} from './ec';
import {
  baseOT,
  BaseOtAbort,
  type BaseOtTamper,
  KAPPA,
  malBaseRandomOT,
  OtChannel,
  otRandom,
  splitMix64,
} from './ot';
import { fieldRandom, SecureFieldRng, secureOtRandom } from './csprng';
import { FieldRng, PRIME } from './field';

const SEED_BYTES = KAPPA / 8;
function seedBytes(fill: number): Uint8Array {
  const b = new Uint8Array(SEED_BYTES);
  b.fill(fill & 0xff);
  return b;
}

/** A genuine on-curve, NON-prime-order point: the 2-torsion point (0, −1). L is odd ⇒ [L]·P = P ≠ O. */
const SMALL_ORDER_POINT: Point = { X: 0n, Y: Q - 1n, Z: 1n, T: 0n };
/** An OFF-CURVE point: (1,1) satisfies the T-invariant but not the curve equation (1 + d ≠ 0). */
const OFF_CURVE_POINT: Point = { X: 1n, Y: 1n, Z: 1n, T: 1n };

// ===================================================================================================
describe('(P) point validation rejects off-curve / small-order / identity points', () => {
  it('isOnCurve accepts genuine subgroup points and rejects an off-curve point', () => {
    expect(isOnCurve(BASE)).toBe(true);
    expect(isOnCurve(mulBase(123456789n))).toBe(true);
    expect(isOnCurve(SMALL_ORDER_POINT)).toBe(true); // on the curve, just not prime-order
    expect(isOnCurve(OFF_CURVE_POINT)).toBe(false);
  });

  it('identity is detected and forbidden by assertInSubgroup', () => {
    expect(isIdentity(IDENTITY)).toBe(true);
    expect(isIdentity(BASE)).toBe(false);
    expect(() => assertInSubgroup(IDENTITY, 'id')).toThrow(PointValidationError);
    expect(() => assertInSubgroup(IDENTITY, 'id')).toThrow(/identity/);
  });

  it('hasPrimeOrder: true for base-point multiples, false for a small-order point', () => {
    expect(hasPrimeOrder(BASE)).toBe(true);
    expect(hasPrimeOrder(mulBase(987654321n))).toBe(true);
    expect(hasPrimeOrder(SMALL_ORDER_POINT)).toBe(false);
  });

  it('assertInSubgroup rejects an off-curve point (not on curve)', () => {
    expect(() => assertInSubgroup(OFF_CURVE_POINT, 'R')).toThrow(PointValidationError);
    expect(() => assertInSubgroup(OFF_CURVE_POINT, 'R')).toThrow(/not on curve/);
  });

  it('assertInSubgroup rejects a small-order / non-prime-order point (cofactor check)', () => {
    expect(() => assertInSubgroup(SMALL_ORDER_POINT, 'R')).toThrow(PointValidationError);
    expect(() => assertInSubgroup(SMALL_ORDER_POINT, 'R')).toThrow(/prime-order subgroup/);
  });

  it('isInSubgroup is true only for genuine non-identity prime-order points', () => {
    expect(isInSubgroup(BASE)).toBe(true);
    expect(isInSubgroup(mulBase(42n))).toBe(true);
    expect(isInSubgroup(IDENTITY)).toBe(false);
    expect(isInSubgroup(OFF_CURVE_POINT)).toBe(false);
    expect(isInSubgroup(SMALL_ORDER_POINT)).toBe(false);
  });
});

// ===================================================================================================
describe('(Σ) Schnorr proof of knowledge of the sender discrete log (S = y·B)', () => {
  const rnd = () => otRandom(splitMix64(7n)).scalar();

  it('an honest proof verifies', () => {
    const y = 0x1234567deadbeefn % L;
    const S = mulBase(y);
    const proof = schnorrProve(y, S, rnd);
    expect(schnorrVerify(S, proof)).toBe(true);
  });

  it('a forged proof (mauled z) is rejected', () => {
    const y = 0x99n;
    const S = mulBase(y);
    const proof = schnorrProve(y, S, rnd);
    expect(schnorrVerify(S, { U: proof.U, z: (proof.z + 1n) % L })).toBe(false);
  });

  it('a proof does not transfer to a different S', () => {
    const y = 0x55n;
    const S = mulBase(y);
    const proof = schnorrProve(y, S, rnd);
    expect(schnorrVerify(mulBase(y + 1n), proof)).toBe(false);
  });
});

// ===================================================================================================
describe('(B) malicious base OT: honest correctness + aborts on a cheating sender/receiver', () => {
  it('honest random OT: the receiver recovers exactly the chosen pad and not the other', () => {
    const choices = [0, 1, 1, 0, 1];
    const ro = malBaseRandomOT(choices, otRandom(splitMix64(11n)));
    for (let i = 0; i < choices.length; i++) {
      const ci = choices[i]!;
      expect(Buffer.from(ro.recvPads[i]!)).toEqual(Buffer.from(ro.senderPads[i]![ci]!));
      // The receiver must NOT obtain the unchosen pad.
      expect(Buffer.from(ro.recvPads[i]!)).not.toEqual(Buffer.from(ro.senderPads[i]![1 - ci]!));
    }
  });

  it('honest chosen-message base OT recovers m_c for every choice', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [seedBytes(1), seedBytes(2)],
      [seedBytes(3), seedBytes(4)],
      [seedBytes(5), seedBytes(6)],
    ];
    const r0 = baseOT(messages, [0, 1, 0], otRandom(splitMix64(21n)));
    expect(Buffer.from(r0.received[0]!)).toEqual(Buffer.from(messages[0]![0]));
    expect(Buffer.from(r0.received[1]!)).toEqual(Buffer.from(messages[1]![1]));
    expect(Buffer.from(r0.received[2]!)).toEqual(Buffer.from(messages[2]![0]));
    // The transcript now carries the sender's proof-of-knowledge and per-message commitments.
    expect(schnorrVerify(r0.transcript.S, r0.transcript.proof)).toBe(true);
    expect(r0.transcript.com.length).toBe(3);
  });

  it('cheating SENDER (forged Schnorr proof) → receiver aborts', () => {
    const tamper: BaseOtTamper = { tamperProof: (p) => ({ U: p.U, z: (p.z + 1n) % L }) };
    expect(() => malBaseRandomOT([0, 1], otRandom(splitMix64(31n)), tamper)).toThrow(BaseOtAbort);
  });

  it('cheating SENDER (wrong S, stale proof) → receiver aborts', () => {
    // Replace S with a different VALID subgroup point; the proof was for the original S, so it fails.
    const tamper: BaseOtTamper = { tamperS: (S) => add(S, BASE) };
    expect(() => malBaseRandomOT([0, 1], otRandom(splitMix64(32n)), tamper)).toThrow(BaseOtAbort);
  });

  it('cheating SENDER (ciphertext inconsistent with its commitment) → receiver aborts', () => {
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [seedBytes(1), seedBytes(2)],
      [seedBytes(3), seedBytes(4)],
    ];
    // Corrupt the CHOSEN ciphertext at index 0 (choice 0) so it no longer opens to the commitment.
    const tamper: BaseOtTamper = {
      tamperCiphertext: (ct) => {
        const e = ct[0]![0]!;
        e[0] = (e[0]! ^ 0x01) & 0xff;
      },
    };
    expect(() => baseOT(messages, [0, 1], otRandom(splitMix64(33n)), tamper)).toThrow(BaseOtAbort);
    expect(() => baseOT(messages, [0, 1], otRandom(splitMix64(33n)), tamper)).toThrow(
      /inconsistent with its commitment/,
    );
  });

  it('cheating RECEIVER (off-curve R) → sender rejects via point validation', () => {
    const tamper: BaseOtTamper = {
      tamperR: (R) => {
        R[0] = OFF_CURVE_POINT;
      },
    };
    expect(() => malBaseRandomOT([0, 1], otRandom(splitMix64(41n)), tamper)).toThrow(
      PointValidationError,
    );
  });

  it('cheating RECEIVER (small-order R) → sender rejects via the cofactor check', () => {
    const tamper: BaseOtTamper = {
      tamperR: (R) => {
        R[1] = SMALL_ORDER_POINT;
      },
    };
    expect(() => malBaseRandomOT([0, 1, 0], otRandom(splitMix64(42n)), tamper)).toThrow(
      /prime-order subgroup/,
    );
  });

  it('a mixed-order R (subgroup point + 2-torsion) is also rejected', () => {
    // R = x·B + (0,−1) is on the curve but has order 2L, so [L]·R = (0,−1) ≠ O → rejected.
    const tamper: BaseOtTamper = {
      tamperR: (R) => {
        R[0] = add(mulBase(777n), SMALL_ORDER_POINT);
      },
    };
    expect(() => malBaseRandomOT([1, 0], otRandom(splitMix64(43n)), tamper)).toThrow(
      PointValidationError,
    );
  });
});

// ===================================================================================================
describe('(C) randomness is the CSPRNG by default; SplitMix64 only behind an explicit test seed', () => {
  it('secureOtRandom draws non-zero scalars in [1, L) and is non-deterministic', () => {
    const r = secureOtRandom();
    const a = r.scalar();
    const b = r.scalar();
    expect(a).toBeGreaterThanOrEqual(1n);
    expect(a).toBeLessThan(L);
    expect(b).toBeGreaterThanOrEqual(1n);
    expect(b).toBeLessThan(L);
    expect(a).not.toBe(b); // two CSPRNG draws differ (collision prob ≈ 2^-252)
    expect(r.bytes(16).length).toBe(16);
  });

  it('SecureFieldRng yields field elements in [0, p) and is non-deterministic', () => {
    const a = new SecureFieldRng().next();
    const b = new SecureFieldRng().next();
    expect(a).toBeGreaterThanOrEqual(0n);
    expect(a).toBeLessThan(PRIME);
    expect(a).not.toBe(b);
  });

  it('fieldRandom(): CSPRNG by default, deterministic FieldRng only with a test seed', () => {
    expect(fieldRandom()).toBeInstanceOf(SecureFieldRng);
    const seeded = fieldRandom({ testSeed: 123n });
    expect(seeded).toBeInstanceOf(FieldRng);
    expect(seeded).not.toBeInstanceOf(SecureFieldRng);
    // Same explicit seed ⇒ identical stream; the default (CSPRNG) stream is NOT reproducible.
    expect(fieldRandom({ testSeed: 123n }).next()).toBe(fieldRandom({ testSeed: 123n }).next());
    expect(fieldRandom().next()).not.toBe(fieldRandom().next());
  });

  it('a default OtChannel (CSPRNG, no seed arg) runs a correct extension round', () => {
    const ch = new OtChannel(); // <-- no rng: uses secureOtRandom() by default
    const m = 24;
    const cb = Array.from({ length: m }, (_, j) => (j % 2) as 0 | 1);
    const msg0 = Array.from({ length: m }, (_, j) => BigInt(j));
    const msg1 = Array.from({ length: m }, (_, j) => BigInt(1000 + j));
    const { received } = ch.extend([...cb], msg0, msg1);
    for (let j = 0; j < m; j++) expect(received[j]).toBe(cb[j] === 1 ? msg1[j] : msg0[j]);
  });

  it('a seeded OtChannel is bit-reproducible; two default channels are not', () => {
    const run = (ch: OtChannel) =>
      ch.extend([1, 0, 1, 1], [1n, 2n, 3n, 4n], [10n, 20n, 30n, 40n]).uMatrix.join(',');
    const seededA = run(new OtChannel(otRandom(splitMix64(99n))));
    const seededB = run(new OtChannel(otRandom(splitMix64(99n))));
    expect(seededA).toBe(seededB); // deterministic under an explicit seed
    // Two independent default (CSPRNG) channels have different base-OT selectors.
    expect(new OtChannel().selector).not.toBe(new OtChannel().selector);
  });
});
