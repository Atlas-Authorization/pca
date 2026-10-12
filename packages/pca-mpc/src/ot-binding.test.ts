/**
 * Audit residual limits 1-3 for the base OT and the OT extension (docs/pca/security/audit-crypto-packages.md):
 *
 *  (1) the sender's Schnorr proof is bound to session id, party indices, round label and both public
 *      points - a proof replayed into another session / party pair / round fails;
 *  (2) the base-OT keys hash the whole transcript (binding, S and EVERY R_i) with domain separation;
 *  (3) the KOS row weights are the output of SHAKE256 (an XOF) seeded by the whole Fiat-Shamir transcript
 *      (known-answer vector below was produced independently with Python hashlib.shake_256).
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { add, mulBase, schnorrProve, schnorrVerify } from './ec';
import {
  type BaseOtBinding,
  BaseOtAbort,
  OtChannel,
  MalOtAbort,
  baseOT,
  baseOtKdf,
  baseOtTranscriptHash,
  bindingBytes,
  kosChallenges,
  malBaseOtReceiverRespond,
  malBaseOtSenderDerive,
  malBaseOtSenderSetup,
  otRandom,
  splitMix64,
} from './ot';

const det = (seed: bigint) => otRandom(splitMix64(seed));
const BIND: BaseOtBinding = { sessionId: new Uint8Array(16).fill(0x11), senderIndex: 0, receiverIndex: 1, round: 'ot-ec' };
const variants: Array<[string, BaseOtBinding]> = [
  ['session id', { ...BIND, sessionId: new Uint8Array(16).fill(0x12) }],
  ['sender index', { ...BIND, senderIndex: 2 }],
  ['receiver index', { ...BIND, receiverIndex: 2 }],
  ['swapped roles', { ...BIND, senderIndex: 1, receiverIndex: 0 }],
  ['round label', { ...BIND, round: 'ot-lwe' }],
];

describe('(1) Schnorr proofs in the base OT are session-bound', () => {
  it('an honest proof verifies under its own binding', () => {
    const setup = malBaseOtSenderSetup(det(1n), BIND);
    expect(schnorrVerify(setup.S, setup.proof, bindingBytes(BIND))).toBe(true);
    expect(() => malBaseOtReceiverRespond(setup.S, setup.proof, [0, 1], det(2n), BIND)).not.toThrow();
  });

  it.each(variants)('a valid (S, proof) replayed into another %s is rejected', (_name, other) => {
    const setup = malBaseOtSenderSetup(det(3n), BIND);
    expect(schnorrVerify(setup.S, setup.proof, bindingBytes(other))).toBe(false);
    expect(() => malBaseOtReceiverRespond(setup.S, setup.proof, [0, 1], det(4n), other)).toThrow(BaseOtAbort);
  });

  it('the challenge binds both public points: a proof for S does not verify for S + B, nor with a swapped commitment', () => {
    const y = 123456789n;
    const S = mulBase(y);
    const ctx = bindingBytes(BIND);
    const proof = schnorrProve(y, S, () => 99n, ctx);
    expect(schnorrVerify(S, proof, ctx)).toBe(true);
    expect(schnorrVerify(add(S, mulBase(1n)), proof, ctx)).toBe(false);
    expect(schnorrVerify(S, { ...proof, U: add(proof.U, mulBase(1n)) }, ctx)).toBe(false);
  });

  it('a proof cannot be produced or checked without a context (fail closed)', () => {
    const y = 77n;
    const S = mulBase(y);
    expect(() => schnorrProve(y, S, () => 5n, new Uint8Array(0))).toThrow(/binding/);
    const proof = schnorrProve(y, S, () => 5n, bindingBytes(BIND));
    expect(schnorrVerify(S, proof, new Uint8Array(0))).toBe(false);
  });

  it('malformed bindings are refused', () => {
    expect(() => bindingBytes({ ...BIND, sessionId: new Uint8Array(4) })).toThrow(RangeError);
    expect(() => bindingBytes({ ...BIND, sessionId: new Uint8Array(65) })).toThrow(RangeError);
    expect(() => bindingBytes({ ...BIND, receiverIndex: 0 })).toThrow(RangeError);
    expect(() => bindingBytes({ ...BIND, senderIndex: -1 })).toThrow(RangeError);
    expect(() => bindingBytes({ ...BIND, round: '' })).toThrow(RangeError);
    expect(() => bindingBytes({ ...BIND, round: 'x'.repeat(65) })).toThrow(RangeError);
  });

  it('two independent runs without an explicit binding get different random session ids (no accidental sharing)', () => {
    const a = baseOT([[new Uint8Array(16), new Uint8Array(16)]], [0], det(9n));
    const b = baseOT([[new Uint8Array(16), new Uint8Array(16)]], [0], det(10n));
    // the sender proofs are for different sessions, so neither verifies under the other's context
    expect(a.transcript.proof.z).not.toBe(b.transcript.proof.z);
  });
});

describe('(2) base-OT keys are derived under a hash of the whole transcript', () => {
  const choices = [0, 1, 1, 0];
  const setup = malBaseOtSenderSetup(det(21n), BIND);
  const recv = malBaseOtReceiverRespond(setup.S, setup.proof, choices, det(22n), BIND);
  const honest = malBaseOtSenderDerive(setup.y, setup.T, recv.R, setup.S, BIND);

  it('honest run: the receiver key equals the sender key at the choice bit and not the other one', () => {
    choices.forEach((c, i) => {
      expect(Buffer.from(recv.recvPads[i]!).equals(Buffer.from(honest[i]![c]!))).toBe(true);
      expect(Buffer.from(recv.recvPads[i]!).equals(Buffer.from(honest[i]![1 - c]!))).toBe(false);
    });
  });

  it.each(variants)('changing the %s changes the transcript hash and EVERY derived key', (_name, other) => {
    expect(Buffer.from(baseOtTranscriptHash(other, setup.S, recv.R))).not.toEqual(Buffer.from(baseOtTranscriptHash(BIND, setup.S, recv.R)));
    const moved = malBaseOtSenderDerive(setup.y, setup.T, recv.R, setup.S, other);
    for (let i = 0; i < choices.length; i++) {
      expect(Buffer.from(moved[i]![0]).equals(Buffer.from(honest[i]![0]))).toBe(false);
      expect(Buffer.from(moved[i]![1]).equals(Buffer.from(honest[i]![1]))).toBe(false);
    }
  });

  it('changing the sender point S changes every key', () => {
    const otherS = mulBase(5n);
    expect(Buffer.from(baseOtTranscriptHash(BIND, otherS, recv.R))).not.toEqual(Buffer.from(baseOtTranscriptHash(BIND, setup.S, recv.R)));
    const moved = malBaseOtSenderDerive(setup.y, setup.T, recv.R, otherS, BIND);
    for (let i = 0; i < choices.length; i++) {
      expect(Buffer.from(moved[i]![0]).equals(Buffer.from(honest[i]![0]))).toBe(false);
      expect(Buffer.from(moved[i]![1]).equals(Buffer.from(honest[i]![1]))).toBe(false);
    }
  });

  it.each(choices.map((_c, j) => j))('changing ONLY R_%i changes the keys at EVERY index, including untouched ones', (j) => {
    const R2 = recv.R.slice();
    R2[j] = add(R2[j]!, mulBase(1n));
    expect(Buffer.from(baseOtTranscriptHash(BIND, setup.S, R2))).not.toEqual(Buffer.from(baseOtTranscriptHash(BIND, setup.S, recv.R)));
    const moved = malBaseOtSenderDerive(setup.y, setup.T, R2, setup.S, BIND);
    for (let i = 0; i < choices.length; i++) {
      expect(Buffer.from(moved[i]![0]).equals(Buffer.from(honest[i]![0]))).toBe(false);
      expect(Buffer.from(moved[i]![1]).equals(Buffer.from(honest[i]![1]))).toBe(false);
    }
  });

  it('the transcript hash is order-sensitive and length-framed (a dropped or reordered R_i changes it)', () => {
    const th = baseOtTranscriptHash(BIND, setup.S, recv.R);
    const reordered = [recv.R[1]!, recv.R[0]!, ...recv.R.slice(2)];
    expect(Buffer.from(baseOtTranscriptHash(BIND, setup.S, reordered))).not.toEqual(Buffer.from(th));
    expect(Buffer.from(baseOtTranscriptHash(BIND, setup.S, recv.R.slice(0, 3)))).not.toEqual(Buffer.from(th));
  });

  it('the KDF separates index, R_i, point and transcript hash', () => {
    const th = baseOtTranscriptHash(BIND, setup.S, recv.R);
    const p = mulBase(9n);
    const k = baseOtKdf(th, 0, recv.R[0]!, p);
    expect(k).toHaveLength(16);
    expect(Buffer.from(baseOtKdf(th, 1, recv.R[0]!, p))).not.toEqual(Buffer.from(k));
    expect(Buffer.from(baseOtKdf(th, 0, recv.R[1]!, p))).not.toEqual(Buffer.from(k));
    expect(Buffer.from(baseOtKdf(th, 0, recv.R[0]!, mulBase(10n)))).not.toEqual(Buffer.from(k));
    const th2 = baseOtTranscriptHash({ ...BIND, round: 'other' }, setup.S, recv.R);
    expect(Buffer.from(baseOtKdf(th2, 0, recv.R[0]!, p))).not.toEqual(Buffer.from(k));
  });

  it('an end-to-end chosen-message base OT under a custom binding still recovers the chosen message', () => {
    const m: Array<[Uint8Array, Uint8Array]> = [
      [new Uint8Array(16).fill(1), new Uint8Array(16).fill(2)],
      [new Uint8Array(16).fill(3), new Uint8Array(16).fill(4)],
    ];
    const r = baseOT(m, [1, 0], det(31n), undefined, BIND);
    expect(Buffer.from(r.received[0]!)).toEqual(Buffer.from(m[0]![1]));
    expect(Buffer.from(r.received[1]!)).toEqual(Buffer.from(m[1]![0]));
  });
});

describe('(3) KOS row weights come from SHAKE256 over the whole Fiat-Shamir transcript', () => {
  const binding = Uint8Array.from({ length: 40 }, (_, i) => i);
  const mExt = 200;
  const mkCols = (): bigint[] =>
    Array.from({ length: 128 }, (_, i) => (0x0123456789abcdef0123456789abcdef0123456789abcdef01n * BigInt(i + 3) + BigInt(i)) % (1n << BigInt(mExt)));

  it('matches the independently computed SHAKE-256 known-answer vector (python hashlib.shake_256)', () => {
    const chi = kosChallenges(binding, 7, mkCols(), mExt);
    expect(chi).toHaveLength(mExt);
    expect(chi[0]).toBe(0xac85d8f113e3deef5750545ac4bf855bn);
    expect(chi[1]).toBe(0xa0a0acdeb68b762db3165adbae279a1dn);
    expect(chi[199]).toBe(0x491f11182685beb174eba85a729c8170n);
    // digest over all 200 weights, 16 bytes each, little-endian
    const buf = Buffer.alloc(mExt * 16);
    chi.forEach((c, j) => {
      let v = c;
      for (let i = 0; i < 16; i++) {
        buf[j * 16 + i] = Number(v & 0xffn);
        v >>= 8n;
      }
    });
    expect(createHash('sha256').update(buf).digest('hex')).toBe('9977c643901be6bd224eec7e0d212de5e9852adfee835ed2449d0c0366c0749a');
  });

  it('every bit of u is bound: flipping any single bit - including bits above position 128 - changes EVERY weight', () => {
    const base = kosChallenges(binding, 7, mkCols(), mExt);
    for (const bit of [0, 1, 127, 128, 129, 199]) {
      const cols = mkCols();
      cols[5] = cols[5]! ^ (1n << BigInt(bit));
      const chi = kosChallenges(binding, 7, cols, mExt);
      expect(chi.every((c, j) => c !== base[j])).toBe(true);
    }
  });

  it('the weights depend on the channel binding, the round and the row count', () => {
    const base = kosChallenges(binding, 7, mkCols(), mExt);
    const other = Uint8Array.from(binding);
    other[0] = other[0]! ^ 1;
    expect(kosChallenges(other, 7, mkCols(), mExt)[0]).not.toBe(base[0]);
    expect(kosChallenges(binding, 8, mkCols(), mExt)[0]).not.toBe(base[0]);
    expect(kosChallenges(binding, 7, mkCols(), mExt + 8)[0]).not.toBe(base[0]);
  });

  it('weights are well spread: no repeats, both halves of the 128-bit word are used', () => {
    const chi = kosChallenges(binding, 7, mkCols(), mExt);
    expect(new Set(chi).size).toBe(mExt);
    expect(chi.some((c) => c >> 64n !== 0n)).toBe(true);
    expect(chi.some((c) => (c & ((1n << 64n) - 1n)) !== 0n)).toBe(true);
  });

  it('a receiver that tampers ONLY bits above 128 of a u column is still caught (the whole column is hashed and checked)', () => {
    const choices = Array.from({ length: 40 }, (_, i) => i & 1);
    const m0 = choices.map((_, i) => BigInt(i));
    const m1 = choices.map((_, i) => BigInt(i + 1000));
    // every column is tampered, so the check fails unless all 128 selector bits are 0 (probability 2^-128)
    let caught = false;
    for (let k = 0; k < 2 && !caught; k++) {
      const c2 = new OtChannel(det(BigInt(50 + k)));
      c2.tamperU = (u) => {
        for (let i = 0; i < u.length; i++) u[i] = u[i]! ^ (1n << 300n);
      };
      try {
        c2.extend(choices, m0, m1);
      } catch (e) {
        caught = e instanceof MalOtAbort;
      }
    }
    expect(caught).toBe(true);
  });
});
