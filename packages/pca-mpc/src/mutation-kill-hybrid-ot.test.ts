import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  HybridOtAbort, hybridBaseOT, hybridReceiverRecover, hybridSenderEncrypt, hybridSessionId, hybridTransferKey, withHybridBaseOt,
} from './hybrid-ot';
import { BASE, encodePoint, mulBase } from './ec';
import { otRandom, splitMix64 } from './ot';

const te = new TextEncoder();
const sha = (...c: Uint8Array[]): Uint8Array => {
  const h = createHash('sha256');
  for (const x of c) h.update(x);
  return new Uint8Array(h.digest());
};
const u32 = (x: number) => Uint8Array.of((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255);
const TK = te.encode('atlas-pca-mpc/hybrid-ot-transfer-key');
const TC = te.encode('atlas-pca-mpc/hybrid-ot-msg-commit');
const TS = te.encode('atlas-pca-mpc/hybrid-ot-sid');
const bytes = (n: number, s: number) => Uint8Array.from({ length: n }, (_, i) => (i * 7 + s) & 255);
const refKey = (sid: Uint8Array, index: number, slot: number, e: Uint8Array, k: Uint8Array, len: number): Uint8Array => {
  const out: number[] = [];
  for (let ctr = 0; out.length < len; ctr++) out.push(...sha(TK, sid, u32(index), Uint8Array.of(slot & 1), u32(ctr), e, k));
  return Uint8Array.from(out.slice(0, len));
};
const refCommit = (sid: Uint8Array, index: number, slot: number, m: Uint8Array, key: Uint8Array) =>
  sha(TC, sid, u32(index), Uint8Array.of(slot & 1), m, key);
const xor = (a: Uint8Array, b: Uint8Array) => Uint8Array.from(a, (x, i) => x ^ b[i]!);

describe('HybridOtAbort', () => {
  it('is a named Error', () => {
    const e = new HybridOtAbort('boom');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('HybridOtAbort');
    expect(e.message).toBe('boom');
  });
});

describe('hybridSessionId', () => {
  it('hashes tag, kem sid and the encoded EC point', () => {
    const kemSid = bytes(32, 1);
    const S = mulBase(5n);
    expect(hybridSessionId(kemSid, S)).toEqual(sha(TS, kemSid, encodePoint(S)));
    expect(hybridSessionId(kemSid, S)).not.toEqual(hybridSessionId(kemSid, BASE));
  });
});

describe('hybridTransferKey', () => {
  const sid = bytes(32, 3), e = bytes(32, 5), k = bytes(32, 9);
  it('is the counter-mode sha256 expansion for every length around block boundaries', () => {
    for (const len of [0, 1, 31, 32, 33, 64, 65, 100]) {
      const got = hybridTransferKey(sid, 2, 1, e, k, len);
      expect(got).toHaveLength(len);
      expect(got).toEqual(refKey(sid, 2, 1, e, k, len));
    }
  });
  it('binds index (big-endian u32), slot parity and both secrets', () => {
    const base = hybridTransferKey(sid, 0x01020304, 1, e, k, 40);
    expect(base).toEqual(refKey(sid, 0x01020304, 1, e, k, 40));
    expect(hybridTransferKey(sid, 0x01020304, 3, e, k, 40)).toEqual(base);
    expect(hybridTransferKey(sid, 0x01020304, 0, e, k, 40)).not.toEqual(base);
    expect(hybridTransferKey(sid, 0x01020304, 2, e, k, 40)).toEqual(hybridTransferKey(sid, 0x01020304, 0, e, k, 40));
    expect(hybridTransferKey(sid, 0x04030201, 1, e, k, 40)).not.toEqual(base);
    expect(hybridTransferKey(sid, 0x01020304, 1, bytes(32, 6), k, 40)).not.toEqual(base);
    expect(hybridTransferKey(sid, 0x01020304, 1, e, bytes(32, 10), 40)).not.toEqual(base);
    expect(hybridTransferKey(sid, 0xff000000, 1, e, k, 8)).toEqual(refKey(sid, 0xff000000, 1, e, k, 8));
  });
  it('bounds the length (0 and 1 MiB allowed, negatives / fractions / beyond refused)', () => {
    const msg = 'hybridTransferKey: length must be an integer in [0, 1 MiB]';
    expect(hybridTransferKey(sid, 0, 0, e, k, 0)).toHaveLength(0);
    expect(hybridTransferKey(sid, 0, 0, e, k, 1 << 20)).toHaveLength(1 << 20);
    for (const bad of [-1, (1 << 20) + 1, 1.5, NaN, Infinity]) {
      expect(() => hybridTransferKey(sid, 0, 0, e, k, bad)).toThrow(new RangeError(msg));
    }
  });
});

describe('hybridSenderEncrypt / hybridReceiverRecover', () => {
  const sid = bytes(32, 11);
  const msgs: Array<[Uint8Array, Uint8Array]> = [[bytes(5, 1), bytes(5, 2)], [bytes(40, 3), bytes(40, 4)]];
  const ec: Array<[Uint8Array, Uint8Array]> = [[bytes(32, 21), bytes(32, 22)], [bytes(32, 23), bytes(32, 24)]];
  const kem: Array<[Uint8Array, Uint8Array]> = [[bytes(32, 31), bytes(32, 32)], [bytes(32, 33), bytes(32, 34)]];

  it('encrypts each slot with its own key and commits to (msg, key) per index/slot', () => {
    const s = hybridSenderEncrypt(sid, msgs, ec, kem);
    for (let i = 0; i < 2; i++) {
      for (const j of [0, 1]) {
        const key = refKey(sid, i, j, ec[i]![j]!, kem[i]![j]!, msgs[i]![j]!.length);
        expect(s.encrypted[i]![j]).toEqual(xor(msgs[i]![j]!, key));
        expect(s.commitments[i]![j]).toEqual(refCommit(sid, i, j, msgs[i]![j]!, key));
      }
    }
    expect(hybridSenderEncrypt(sid, [], [], [])).toEqual({ encrypted: [], commitments: [] });
  });
  it('refuses length mismatches and unequal message pairs', () => {
    const m = 'hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch';
    expect(() => hybridSenderEncrypt(sid, msgs, ec.slice(0, 1), kem)).toThrow(m);
    expect(() => hybridSenderEncrypt(sid, msgs, ec, kem.slice(0, 1))).toThrow(m);
    expect(() => hybridSenderEncrypt(sid, msgs.slice(0, 1), ec, kem)).toThrow(m);
    expect(() => hybridSenderEncrypt(sid, [msgs[0]!, [bytes(3, 1), bytes(4, 1)]], ec, kem)).toThrow(
      'hybridSenderEncrypt (index 1): the two messages must be equal length',
    );
    expect(() => hybridSenderEncrypt(sid, [[bytes(3, 1), bytes(4, 1)], msgs[1]!], ec, kem)).toThrow(
      'hybridSenderEncrypt (index 0): the two messages must be equal length',
    );
  });
  it('the receiver recovers m_c (choice reduced mod 2) and aborts on any inconsistency', () => {
    const s = hybridSenderEncrypt(sid, msgs, ec, kem);
    const got = hybridReceiverRecover(sid, [1, 0], s, [ec[0]![1]!, ec[1]![0]!], [kem[0]![1]!, kem[1]![0]!]);
    expect(got).toEqual([msgs[0]![1], msgs[1]![0]]);
    const odd = hybridReceiverRecover(sid, [3, 2], s, [ec[0]![1]!, ec[1]![0]!], [kem[0]![1]!, kem[1]![0]!]);
    expect(odd).toEqual(got);
    expect(hybridReceiverRecover(sid, [], { encrypted: [], commitments: [] }, [], [])).toEqual([]);

    const lenMsg = 'hybridReceiverRecover: length mismatch';
    const ok = [ec[0]![1]!, ec[1]![0]!], okk = [kem[0]![1]!, kem[1]![0]!];
    expect(() => hybridReceiverRecover(sid, [1], s, ok, okk)).toThrow(lenMsg);
    expect(() => hybridReceiverRecover(sid, [1, 0], { ...s, encrypted: s.encrypted.slice(0, 1) }, ok, okk)).toThrow(lenMsg);
    expect(() => hybridReceiverRecover(sid, [1, 0], { ...s, commitments: s.commitments.slice(0, 1) }, ok, okk)).toThrow(lenMsg);
    expect(() => hybridReceiverRecover(sid, [1, 0], s, ok.slice(0, 1), okk)).toThrow(lenMsg);
    expect(() => hybridReceiverRecover(sid, [1, 0], s, ok, okk.slice(0, 1))).toThrow(lenMsg);

    // wrong pad => commitment mismatch => HybridOtAbort naming the index
    try {
      hybridReceiverRecover(sid, [1, 0], s, [ec[0]![1]!, bytes(32, 99)], okk);
      throw new Error('should abort');
    } catch (err) {
      expect(err).toBeInstanceOf(HybridOtAbort);
      expect((err as Error).message).toBe('hybrid base OT (index 1): sender ciphertext inconsistent with its commitment; aborting');
    }
    expect(() => hybridReceiverRecover(sid, [1, 0], s, [bytes(32, 98), ec[1]![0]!], okk)).toThrow(/index 0/);
    // a commitment of the wrong length aborts cleanly (no RangeError from timingSafeEqual)
    const short = { ...s, commitments: [[s.commitments[0]![0], s.commitments[0]![1]!.slice(0, 31)], s.commitments[1]!] as typeof s.commitments };
    expect(() => hybridReceiverRecover(sid, [1, 0], short, ok, okk)).toThrow(HybridOtAbort);
  });
});

describe('hybridBaseOT (real primitives)', () => {
  const messages: Array<[Uint8Array, Uint8Array]> = [[bytes(16, 1), bytes(16, 2)], [bytes(7, 3), bytes(7, 4)], [bytes(0, 0), bytes(0, 0)]];
  const choices = [1, 0, 1];
  it('transfers m_c with a self-consistent transcript', () => {
    const r = hybridBaseOT(messages, choices, otRandom(splitMix64(77n)));
    expect(r.received).toEqual([messages[0]![1], messages[1]![0], messages[2]![1]]);
    expect(r.transcript.sid).toEqual(hybridSessionId(r.transcript.kemSid, r.transcript.ecS));
    expect(r.transcript.encrypted.map((p) => p.map((x) => x.length))).toEqual([[16, 16], [7, 7], [0, 0]]);
    expect(r.transcript.commitments.every((p) => p.every((x) => x.length === 32))).toBe(true);
    expect(r.transcript.kemSid.length).toBeGreaterThan(0);
  });
  it('refuses messages/choices length mismatches', () => {
    expect(() => hybridBaseOT(messages, [1, 0], otRandom(splitMix64(1n)))).toThrow('hybridBaseOT: messages/choices length mismatch');
    expect(() => hybridBaseOT(messages.slice(0, 1), choices, otRandom(splitMix64(1n)))).toThrow('hybridBaseOT: messages/choices length mismatch');
  });
  it('tamperEncrypted runs on the sent ciphertexts and a corrupted one aborts', () => {
    let seen = 0;
    expect(() =>
      hybridBaseOT(messages, choices, otRandom(splitMix64(5n)), {
        tamperEncrypted: (enc) => {
          seen = enc.length;
          enc[1]![0] = enc[1]![0]!.map((b) => b ^ 1);
        },
      }),
    ).toThrow(HybridOtAbort);
    expect(seen).toBe(3);
    // corrupting the slot the receiver does NOT read is not detected
    const ok = hybridBaseOT(messages, choices, otRandom(splitMix64(5n)), { tamperEncrypted: (enc) => { enc[1]![1] = enc[1]![1]!.map((b) => b ^ 1); } });
    expect(ok.received[1]).toEqual(messages[1]![0]);
  });
  it('withHybridBaseOt exposes a baseOtFn returning only the received messages', () => {
    const cfg = withHybridBaseOt()!;
    expect(typeof cfg.baseOtFn).toBe('function');
    const out = cfg.baseOtFn!(messages, choices, otRandom(splitMix64(9n))) as { received: Uint8Array[] };
    expect(out.received).toEqual([messages[0]![1], messages[1]![0], messages[2]![1]]);
    expect(Object.keys(out)).toEqual(['received']);
  });
});
