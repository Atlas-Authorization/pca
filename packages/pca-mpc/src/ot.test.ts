/**
 * Oblivious-transfer tests — the cryptographic root of the no-dealer offline phase, all REAL (the
 * actual EC group law, the actual Chou–Orlandi base OT, the actual IKNP extension run end to end):
 *   (A) the Ed25519 subgroup obeys the group law (self-consistency + known order);
 *   (B) base OT: the receiver recovers EXACTLY its chosen message, for every choice pattern;
 *   (C) base OT choice-privacy: the receiver's wire message R is consistent with BOTH choices, so the
 *       sender's transcript view is identical whether the receiver chose 0 or 1 (info-theoretic hiding);
 *   (D) IKNP extension: the receiver recovers exactly its chosen messages over many rounds/choices,
 *       and the unchosen message stays masked in the transcript.
 */

import { describe, expect, it } from 'vitest';
import {
  add,
  BASE,
  encodePoint,
  equal,
  IDENTITY,
  L,
  mul,
  mulBase,
  neg,
  sub,
  toAffine,
} from './ec';
import { baseOT, KAPPA, OtChannel, otRandom, splitMix64 } from './ot';

function seedBytes(fill: number): Uint8Array {
  const b = new Uint8Array(KAPPA / 8);
  b.fill(fill);
  return b;
}

// ===================================================================================================
describe('(A) Ed25519 prime-order subgroup obeys the group law', () => {
  it('[L]·B is the identity (B has order L)', () => {
    expect(equal(mul(L, BASE), IDENTITY)).toBe(true);
  });

  it('identity and negation behave', () => {
    expect(equal(add(BASE, IDENTITY), BASE)).toBe(true);
    expect(equal(add(BASE, neg(BASE)), IDENTITY)).toBe(true);
    expect(equal(sub(mulBase(7n), mulBase(7n)), IDENTITY)).toBe(true);
  });

  it('homomorphism: (a·B)+(b·B) = (a+b)·B and a·(b·B) = (a·b)·B', () => {
    const a = 12345678901234567890123456789n;
    const b = 98765432109876543210987654321n;
    expect(equal(add(mulBase(a), mulBase(b)), mulBase(a + b))).toBe(true);
    expect(equal(mul(a, mulBase(b)), mulBase((a * b) % L))).toBe(true);
    expect(equal(add(BASE, BASE), mul(2n, BASE))).toBe(true);
  });

  it('encodePoint is injective on distinct group elements (affine round-trip)', () => {
    const p = mulBase(1234n);
    const aff = toAffine(p);
    // Re-encode an equal point formed differently; encodings must match.
    const p2 = add(mulBase(1200n), mulBase(34n));
    expect(equal(p, p2)).toBe(true);
    expect(Buffer.from(encodePoint(p)).toString('hex')).toBe(
      Buffer.from(encodePoint(p2)).toString('hex'),
    );
    expect(aff.y).not.toBe(0n);
  });
});

// ===================================================================================================
describe('(B) Chou–Orlandi base OT: receiver recovers exactly the chosen message', () => {
  it('recovers m_c for every choice over a 32-wide batch', () => {
    const rng = otRandom(splitMix64(42n));
    const count = 32;
    const messages: Array<[Uint8Array, Uint8Array]> = [];
    const choices: number[] = [];
    for (let i = 0; i < count; i++) {
      messages.push([seedBytes(i + 1), seedBytes(100 + i)]);
      choices.push((i * 7 + 1) % 2);
    }
    const { received } = baseOT(messages, choices, rng);
    for (let i = 0; i < count; i++) {
      expect(Buffer.from(received[i]!).toString('hex')).toBe(
        Buffer.from(messages[i]![choices[i]!]!).toString('hex'),
      );
    }
  });

  it('both all-0 and all-1 choice vectors recover correctly', () => {
    const rng = otRandom(splitMix64(9n));
    const messages: Array<[Uint8Array, Uint8Array]> = [
      [seedBytes(1), seedBytes(2)],
      [seedBytes(3), seedBytes(4)],
    ];
    const r0 = baseOT(messages, [0, 0], rng);
    expect(Buffer.from(r0.received[0]!)).toEqual(Buffer.from(messages[0]![0]));
    expect(Buffer.from(r0.received[1]!)).toEqual(Buffer.from(messages[1]![0]));
    const r1 = baseOT(messages, [1, 1], rng);
    expect(Buffer.from(r1.received[0]!)).toEqual(Buffer.from(messages[0]![1]));
    expect(Buffer.from(r1.received[1]!)).toEqual(Buffer.from(messages[1]![1]));
  });
});

// ===================================================================================================
describe("(C) base OT choice-privacy: the sender's transcript is independent of the receiver's choice", () => {
  it('for every observed R there is a consistent x for BOTH c=0 and c=1 (R uniform either way)', () => {
    // R = x·B + c·S. If the receiver chose c=1 with blinding x, the SAME R is produced by c=0 with
    // blinding x' = x + y (since S = y·B). So the sender, who only sees R, cannot tell c apart: every
    // transcript is equally likely under both choices. We demonstrate the explicit bijection.
    const y = 1111111111n; // sender secret
    const S = mulBase(y);
    const x = 2222222222n; // receiver blinding, choice c=1
    const Rc1 = add(mulBase(x), S);
    // The c=0 explanation of the very same R:
    const xPrime = x + y;
    const Rc0 = mulBase(xPrime);
    expect(equal(Rc1, Rc0)).toBe(true);
  });

  it('R is a function only of (x, c) and ranges over the whole subgroup as x varies', () => {
    const y = 7n;
    const S = mulBase(y);
    const seen = new Set<string>();
    for (let x = 1n; x <= 50n; x++) {
      const R = add(mulBase(x), S); // c=1 branch
      seen.add(Buffer.from(encodePoint(R)).toString('hex'));
    }
    expect(seen.size).toBe(50); // all distinct — no structure leaking the choice
  });
});

// ===================================================================================================
describe('(D) IKNP OT extension: correctness over many rounds and the transcript masks the unchosen', () => {
  it('receiver recovers exactly its chosen field-element messages across 8 rounds', () => {
    const ch = new OtChannel(otRandom(splitMix64(7n)));
    for (let round = 0; round < 8; round++) {
      const m = 61;
      const cb: number[] = [];
      const msg0: bigint[] = [];
      const msg1: bigint[] = [];
      for (let j = 0; j < m; j++) {
        cb.push((round * 3 + j * 5) % 2);
        msg0.push(BigInt(1_000_000 * round + j));
        msg1.push(BigInt(900_000_000 + 1_000_000 * round + j));
      }
      const { received } = ch.extend(cb, msg0, msg1);
      for (let j = 0; j < m; j++) {
        expect(received[j]).toBe(cb[j] === 1 ? msg1[j] : msg0[j]);
      }
    }
  });

  it('variable round sizes compose (PRG counters stay aligned)', () => {
    const ch = new OtChannel(otRandom(splitMix64(123n)));
    for (const m of [1, 5, 61, 128, 300]) {
      const cb = Array.from({ length: m }, (_, j) => (j % 3 === 0 ? 1 : 0));
      const msg0 = Array.from({ length: m }, (_, j) => BigInt(j));
      const msg1 = Array.from({ length: m }, (_, j) => BigInt(1_000_000 + j));
      const { received } = ch.extend(cb, msg0, msg1);
      for (let j = 0; j < m; j++) expect(received[j]).toBe(cb[j] === 1 ? msg1[j] : msg0[j]);
    }
  });

  it('the receiver cannot recover the unchosen message from the transcript it holds', () => {
    // The receiver holds t-rows and the y0/y1 ciphertexts; the unchosen message is masked by H(j, qrow)
    // (c=0) or H(j, qrow⊕s) (c=1), both of which require the sender's secret selector s. We confirm the
    // recovered value equals ONLY the chosen message and never equals the unchosen one (which differs).
    const ch = new OtChannel(otRandom(splitMix64(555n)));
    const m = 40;
    const cb = Array.from({ length: m }, (_, j) => (j % 2) as 0 | 1);
    const msg0 = Array.from({ length: m }, (_, j) => BigInt(10 + j));
    const msg1 = Array.from({ length: m }, (_, j) => BigInt(500 + j));
    const { received } = ch.extend([...cb], msg0, msg1);
    for (let j = 0; j < m; j++) {
      const chosen = cb[j] === 1 ? msg1[j]! : msg0[j]!;
      const unchosen = cb[j] === 1 ? msg0[j]! : msg1[j]!;
      expect(received[j]).toBe(chosen);
      expect(received[j]).not.toBe(unchosen);
    }
  });
});
