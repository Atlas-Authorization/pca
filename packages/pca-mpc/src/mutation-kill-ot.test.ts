import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { BASE, L, encodePoint, mul, mulBase } from './ec';
import { gfToBig } from './otx';
import {
  BaseOtAbort, KAPPA, MalOtAbort, OtChannel, OtExtReceiver, OtExtSender, SSEC,
  baseOT, baseOtKdf, baseOtReceiverDecrypt, baseOtSenderEncrypt, baseOtTranscriptHash, bindingBytes, kosChallenges, kosChiWords,
  malBaseOtReceiverRespond, malBaseOtSenderDerive, malBaseOtSenderSetup, malBaseRandomOT, otRandom, randomBinding, splitMix64,
} from './ot';

const te = new TextEncoder();
const T = (s: string) => te.encode(s);
const sha = (...c: Uint8Array[]) => {
  const h = createHash('sha256');
  for (const x of c) h.update(x);
  return new Uint8Array(h.digest());
};
const u32 = (x: number) => Uint8Array.of((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255);
const b = (n: number, s = 0) => Uint8Array.from({ length: n }, (_, i) => (i * 13 + s) & 255);
const cat = (...a: Uint8Array[]) => Uint8Array.from(a.flatMap((x) => [...x]));
const rng = (s: bigint) => otRandom(splitMix64(s));
const errOf = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('did not throw'); };
const M64 = (1n << 64n) - 1n;

describe('abort classes and constants', () => {
  it('are named Errors', () => {
    const m = new MalOtAbort('x');
    expect(m).toBeInstanceOf(Error);
    expect(m.name).toBe('MalOtAbort');
    expect(m.message).toBe('x');
    const a = new BaseOtAbort('y');
    expect(a).toBeInstanceOf(Error);
    expect(a.name).toBe('BaseOtAbort');
    expect(a.message).toBe('y');
    expect(KAPPA).toBe(128);
    expect(SSEC).toBe(128);
  });
});

describe('splitMix64 / otRandom', () => {
  const ref = (seed: bigint) => {
    let s = seed & M64;
    return () => {
      s = (s + 0x9e3779b97f4a7c15n) & M64;
      let z = s;
      z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & M64;
      z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & M64;
      return (z ^ (z >> 31n)) & M64;
    };
  };
  it('matches the reference SplitMix64 stream and masks the seed to 64 bits', () => {
    const g = splitMix64(12345n), r = ref(12345n);
    for (let i = 0; i < 6; i++) expect(g()).toBe(r());
    const h = splitMix64((1n << 64n) + 5n), q = splitMix64(5n);
    for (let i = 0; i < 3; i++) expect(h()).toBe(q());
    const all1 = splitMix64(M64), r1 = ref(M64);
    expect(all1()).toBe(r1());
  });
  it('scalar assembles four words big-endian and reduces mod L', () => {
    const words = [M64, 1n << 63n, 12345n, M64 - 3n];
    let k = 0;
    const o = otRandom(() => words[k++]!);
    const want = ((words[0]! << 192n) | (words[1]! << 128n) | (words[2]! << 64n) | words[3]!) % L;
    expect(o.scalar()).toBe(want);
    expect(k).toBe(4);
  });
  it('scalar rejects zero up to 8 attempts then fails closed', () => {
    for (const zeros of [1, 7]) {
      let k = 0;
      const o = otRandom(() => (k++ < zeros * 4 ? 0n : 7n));
      expect(o.scalar()).toBe(((7n << 192n) | (7n << 128n) | (7n << 64n) | 7n) % L);
      expect(k).toBe(zeros * 4 + 4);
    }
    let k = 0;
    const o = otRandom(() => { k++; return 0n; });
    expect(errOf(() => o.scalar()).message).toBe('otRandom: entropy stream returned zero scalars repeatedly (RNG failure)');
    expect(k).toBe(32);
    // a value that is a multiple of L reduces to zero and is also rejected
    const lw = [(L >> 192n) & M64, (L >> 128n) & M64, (L >> 64n) & M64, L & M64];
    let j = 0;
    const o2 = otRandom(() => (j < 4 ? lw[j++]! : 9n));
    expect(o2.scalar()).toBe(((9n << 192n) | (9n << 128n) | (9n << 64n) | 9n) % L);
  });
  it('bytes emits each word little-endian and draws only as many words as needed', () => {
    let k = 0;
    const words = [0x0807060504030201n, 0x1817161514131211n];
    const o = otRandom(() => words[k++]!);
    expect([...o.bytes(0)]).toEqual([]);
    expect(k).toBe(0);
    expect([...o.bytes(8)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(k).toBe(1);
    k = 0;
    expect([...o.bytes(10)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12]);
    expect(k).toBe(2);
    k = 0;
    expect([...o.bytes(3)]).toEqual([1, 2, 3]);
    expect(k).toBe(1);
  });
});

describe('bindingBytes / randomBinding', () => {
  const ok = () => ({ sessionId: b(16), senderIndex: 3, receiverIndex: 9, round: 'round-x' });
  it('is the length-prefixed canonical encoding', () => {
    const v = ok();
    expect(bindingBytes(v)).toEqual(cat(T('atlas-pca-mpc/base-ot-binding'), u32(16), v.sessionId, u32(3), u32(9), u32(7), T('round-x')));
  });
  it('accepts the boundary values', () => {
    expect(() => bindingBytes({ ...ok(), sessionId: b(8) })).not.toThrow();
    expect(() => bindingBytes({ ...ok(), sessionId: b(64) })).not.toThrow();
    expect(() => bindingBytes({ ...ok(), senderIndex: 0, receiverIndex: 0xffffffff })).not.toThrow();
    expect(() => bindingBytes({ ...ok(), round: 'r' })).not.toThrow();
    expect(() => bindingBytes({ ...ok(), round: 'x'.repeat(64) })).not.toThrow();
  });
  it('rejects bad session ids, indexes and labels with precise messages', () => {
    const rej = (v: unknown, msg: string) => expect(errOf(() => bindingBytes(v as never))).toEqual(new RangeError(msg));
    rej({ ...ok(), sessionId: b(7) }, 'base-OT binding: sessionId must be 8..64 bytes');
    rej({ ...ok(), sessionId: b(65) }, 'base-OT binding: sessionId must be 8..64 bytes');
    rej({ ...ok(), sessionId: [...b(16)] }, 'base-OT binding: sessionId must be 8..64 bytes');
    rej({ ...ok(), senderIndex: -1 }, 'base-OT binding: senderIndex must be a uint32');
    rej({ ...ok(), senderIndex: 0x100000000 }, 'base-OT binding: senderIndex must be a uint32');
    rej({ ...ok(), senderIndex: 1.5 }, 'base-OT binding: senderIndex must be a uint32');
    rej({ ...ok(), receiverIndex: -1 }, 'base-OT binding: receiverIndex must be a uint32');
    rej({ ...ok(), receiverIndex: 0x100000000 }, 'base-OT binding: receiverIndex must be a uint32');
    rej({ ...ok(), receiverIndex: NaN }, 'base-OT binding: receiverIndex must be a uint32');
    rej({ ...ok(), receiverIndex: 3 }, 'base-OT binding: sender and receiver must be different parties');
    rej({ ...ok(), round: '' }, 'base-OT binding: round label must be 1..64 bytes');
    rej({ ...ok(), round: 'x'.repeat(65) }, 'base-OT binding: round label must be 1..64 bytes');
    rej({ ...ok(), round: 'é'.repeat(33) }, 'base-OT binding: round label must be 1..64 bytes');
  });
  it('randomBinding draws a 16 byte session id and defaults to parties 0 and 1', () => {
    const r = randomBinding(rng(1n), 'lbl');
    expect(r.sessionId).toEqual(rng(1n).bytes(16));
    expect(r.senderIndex).toBe(0);
    expect(r.receiverIndex).toBe(1);
    expect(r.round).toBe('lbl');
    const r2 = randomBinding(rng(1n), 'q', 4, 7);
    expect([r2.senderIndex, r2.receiverIndex]).toEqual([4, 7]);
  });
});

describe('transcript hash, KDF and KOS challenges', () => {
  const binding = { sessionId: b(16), senderIndex: 0, receiverIndex: 1, round: 'r' };
  it('baseOtTranscriptHash hashes the binding, S and every R in order with a count', () => {
    const S = mulBase(5n), R = [mulBase(6n), mulBase(7n)];
    expect(baseOtTranscriptHash(binding, S, R)).toEqual(
      sha(T('atlas-pca-mpc/base-ot-transcript'), bindingBytes(binding), encodePoint(S), u32(2), encodePoint(R[0]!), encodePoint(R[1]!)),
    );
    expect(baseOtTranscriptHash(binding, S, [R[1]!, R[0]!])).not.toEqual(baseOtTranscriptHash(binding, S, R));
  });
  it('baseOtKdf is the first 16 bytes of the domain-separated hash', () => {
    const th = b(32, 3), Ri = mulBase(8n), p = mulBase(9n);
    const got = baseOtKdf(th, 5, Ri, p);
    expect(got).toHaveLength(16);
    expect(got).toEqual(sha(T('atlas-pca-mpc/ot-kdf'), th, u32(5), encodePoint(Ri), encodePoint(p)).slice(0, 16));
  });
  it('kosChiWords / kosChallenges follow the SHAKE256 transcript definition', () => {
    const bind = b(20, 1), round = 3, mExt = 261, colBytes = Math.ceil(mExt / 8);
    const u = Array.from({ length: 4 }, (_, i) => (1n << BigInt(mExt - 1)) | BigInt(i * 77 + 1));
    const le = (v: bigint) => Uint8Array.from({ length: colBytes }, (_, i) => Number((v >> BigInt(8 * i)) & 255n));
    const xof = createHash('shake256', { outputLength: mExt * 16 });
    for (const part of [T('atlas-pca-mpc/ot-kos'), u32(bind.length), bind, u32(round), u32(mExt), u32(u.length), ...u.map(le)]) xof.update(part);
    const out = xof.digest();
    const want = new Uint32Array(mExt * 4);
    for (let i = 0; i < want.length; i++) want[i] = out.readUInt32LE(i * 4);
    const got = kosChiWords(bind, round, u, mExt);
    expect(got).toEqual(want);
    expect(kosChiWords(bind, round, u, mExt, u.map(le))).toEqual(want);
    const ch = kosChallenges(bind, round, u, mExt);
    expect(ch).toHaveLength(mExt);
    for (let j = 0; j < mExt; j++) expect(ch[j]).toBe(gfToBig(want.subarray(4 * j, 4 * j + 4)));
    expect(kosChiWords(bind, round + 1, u, mExt)).not.toEqual(want);
  });
});

describe('base OT steps', () => {
  const binding = { sessionId: b(16), senderIndex: 0, receiverIndex: 1, round: 'r' };
  it('random OT: sender pads cover both slots and the receiver pad is the chosen one', () => {
    const choices = [1, 0, 1, 1, 0];
    const r = malBaseRandomOT(choices, rng(2n), undefined, binding);
    expect(r.R).toHaveLength(5);
    expect(r.senderPads).toHaveLength(5);
    expect(r.recvPads).toHaveLength(5);
    choices.forEach((c, i) => {
      expect(r.recvPads[i]).toEqual(r.senderPads[i]![c]);
      expect(r.recvPads[i]).not.toEqual(r.senderPads[i]![1 - c]);
      expect(r.recvPads[i]).toHaveLength(16);
    });
  });
  it('the sender setup is y, S = yB, T = yS with a verifying proof', () => {
    const s = malBaseOtSenderSetup(rng(3n), binding);
    expect(s.S).toEqual(mulBase(s.y));
    expect(s.T).toEqual(mul(s.y, s.S));
    expect(malBaseOtReceiverRespond(s.S, s.proof, [0], rng(4n), binding).R).toHaveLength(1);
  });
  it('the receiver aborts on a proof for another context with the exact message', () => {
    const s = malBaseOtSenderSetup(rng(3n), binding);
    const e = errOf(() => malBaseOtReceiverRespond(s.S, s.proof, [0], rng(4n), { ...binding, round: 'other' }));
    expect(e).toBeInstanceOf(BaseOtAbort);
    expect(e.message).toBe('base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting');
  });
  it('the receiver point is x*B for choice 0 and x*B + S for choice 1', () => {
    const s = malBaseOtSenderSetup(rng(5n), binding);
    const r = rng(6n);
    const x0 = r.scalar(), x1 = r.scalar();
    const out = malBaseOtReceiverRespond(s.S, s.proof, [0, 1, 3], rng(6n), binding);
    expect(encodePoint(out.R[0]!)).toEqual(encodePoint(mulBase(x0)));
    expect(encodePoint(out.R[1]!)).not.toEqual(encodePoint(mulBase(x1)));
    const sd = malBaseOtSenderDerive(s.y, s.T, out.R, s.S, binding);
    expect(sd[0]![0]).toEqual(out.recvPads[0]);
    expect(sd[1]![1]).toEqual(out.recvPads[1]);
    expect(sd[2]![1]).toEqual(out.recvPads[2]);
  });
  it('baseOtSenderEncrypt checks shape and produces xor ciphertexts with per-slot commitments', () => {
    const msgs: Array<[Uint8Array, Uint8Array]> = [[b(16, 1), b(16, 2)], [b(3, 3), b(3, 4)]];
    const pads: Array<[Uint8Array, Uint8Array]> = [[b(16, 5), b(16, 6)], [b(16, 7), b(16, 8)]];
    expect(errOf(() => baseOtSenderEncrypt(msgs, pads.slice(1))).message).toBe('baseOT: messages/pads length mismatch');
    expect(errOf(() => baseOtSenderEncrypt([msgs[0]!], pads)).message).toBe('baseOT: messages/pads length mismatch');
    const wide: Array<[Uint8Array, Uint8Array]> = [msgs[0]!, [b(17), b(17)]];
    expect(errOf(() => baseOtSenderEncrypt(wide, pads))).toEqual(new RangeError('baseOT: message pair 1 must be equal length and at most 16 bytes (pad width)'));
    expect(errOf(() => baseOtSenderEncrypt([[b(17), b(4)], msgs[1]!], pads)).message).toContain('message pair 0 ');
    expect(errOf(() => baseOtSenderEncrypt([[b(4), b(17)], msgs[1]!], pads)).message).toContain('message pair 0 ');
    expect(errOf(() => baseOtSenderEncrypt([[b(4), b(5)], msgs[1]!], pads)).message).toContain('message pair 0 ');
    const { ct, com } = baseOtSenderEncrypt(msgs, pads);
    for (let i = 0; i < 2; i++) for (const bit of [0, 1]) {
      const m = msgs[i]![bit]!, p = pads[i]![bit]!;
      expect(ct[i]![bit]).toEqual(Uint8Array.from(m, (v, k) => v ^ p[k]!));
      expect(com[i]![bit]).toEqual(sha(T('atlas-pca-mpc/ot-msg-commit'), u32(i), Uint8Array.of(bit), m, p));
    }
  });
  it('baseOtReceiverDecrypt validates counts, shapes and commitments with precise aborts', () => {
    const choices = [1, 0];
    const msgs: Array<[Uint8Array, Uint8Array]> = [[b(16, 1), b(16, 2)], [b(16, 3), b(16, 4)]];
    const pads: Array<[Uint8Array, Uint8Array]> = [[b(16, 5), b(16, 6)], [b(16, 7), b(16, 8)]];
    const { ct, com } = baseOtSenderEncrypt(msgs, pads);
    const rp = [pads[0]![1], pads[1]![0]];
    expect(baseOtReceiverDecrypt(choices, rp, ct, com)).toEqual([msgs[0]![1], msgs[1]![0]]);
    const count = 'base OT: ciphertext/commitment count does not match the number of choices; aborting';
    expect(errOf(() => baseOtReceiverDecrypt(choices, rp, ct.slice(1), com)).message).toBe(count);
    expect(errOf(() => baseOtReceiverDecrypt(choices, rp, ct, com.slice(1))).message).toBe(count);
    expect(errOf(() => baseOtReceiverDecrypt(choices, rp.slice(1), ct, com)).message).toBe(count);
    const shape = (i: number) => `base OT (index ${i}): malformed ciphertext shape; aborting`;
    const unequal = ct.map((x) => [x[0], x[1]] as [Uint8Array, Uint8Array]);
    unequal[1] = [b(16), b(15)];
    const e1 = errOf(() => baseOtReceiverDecrypt(choices, rp, unequal, com));
    expect(e1).toBeInstanceOf(BaseOtAbort);
    expect(e1.message).toBe(shape(1));
    unequal[1] = [b(17), b(17)];
    expect(errOf(() => baseOtReceiverDecrypt(choices, rp, unequal, com)).message).toBe(shape(1));
    const flipped = ct.map((x) => [x[0].slice(), x[1].slice()] as [Uint8Array, Uint8Array]);
    flipped[1]![0]![0]! ^= 1;
    const e2 = errOf(() => baseOtReceiverDecrypt(choices, rp, flipped, com));
    expect(e2).toBeInstanceOf(BaseOtAbort);
    expect(e2.message).toBe('base OT (index 1): sender ciphertext inconsistent with its commitment; aborting');
    // only the chosen slot is checked
    flipped[1]![0]![0]! ^= 1;
    flipped[1]![1]![0]! ^= 1;
    expect(baseOtReceiverDecrypt(choices, rp, flipped, com)).toEqual([msgs[0]![1], msgs[1]![0]]);
  });
  it('baseOT delivers the chosen messages, exposes the transcript and honours tamper hooks', () => {
    const msgs: Array<[Uint8Array, Uint8Array]> = [[b(16, 1), b(16, 2)], [b(8, 3), b(8, 4)], [b(0), b(0)]];
    const r = baseOT(msgs, [1, 0, 1], rng(7n));
    expect(r.received).toEqual([msgs[0]![1], msgs[1]![0], msgs[2]![1]]);
    expect(r.transcript.R).toHaveLength(3);
    expect(r.transcript.ct).toHaveLength(3);
    expect(r.transcript.com).toHaveLength(3);
    expect(r.transcript.S).toBeDefined();
    expect(r.transcript.proof).toBeDefined();
    expect(errOf(() => baseOT(msgs, [1, 0], rng(7n))).message).toBe('baseOT: messages/choices length mismatch');
    expect(errOf(() => baseOT(msgs.slice(1), [1, 0, 1], rng(7n))).message).toBe('baseOT: messages/choices length mismatch');
    expect(errOf(() => baseOT(msgs, [1, 0, 1], rng(7n), { tamperCiphertext: (ct) => { ct[0]![1] = b(16, 9); } })).message)
      .toBe('base OT (index 0): sender ciphertext inconsistent with its commitment; aborting');
    expect(baseOT(msgs, [1, 0, 1], rng(7n), {}).received).toEqual(r.received);
    expect(errOf(() => baseOT(msgs, [1, 0, 1], rng(7n), { tamperR: (R) => { R[1] = { ...R[1]!, X: R[1]!.X + 1n }; } }))).toBeInstanceOf(Error);
    expect(errOf(() => baseOT(msgs, [1, 0, 1], rng(7n), { tamperS: () => BASE, tamperProof: (p) => p }))).toBeInstanceOf(Error);
  });
});

// ------------------------------------------------------------------------------- OT extension roles

const pair = (seed: bigint) => {
  const r = rng(seed);
  const kos = bindingBytes({ sessionId: b(16, 1), senderIndex: 0, receiverIndex: 1, round: 'iknp-kos' });
  const recv = new OtExtReceiver(r, kos);
  const send = new OtExtSender(r, kos);
  const messages = recv.makeSeeds();
  const s = send.makeSelector();
  send.setSeeds(s.map((bit, i) => messages[i]![bit]!));
  return { recv, send, s, messages };
};
const bitsOf = (n: number, seed: number) => Array.from({ length: n }, (_, i) => ((i * 7 + seed) % 5) & 1);
const vals = (n: number, seed: bigint) => Array.from({ length: n }, (_, i) => (BigInt(i + 1) * 0x9e3779b97f4a7c15n + seed) & M64);
const run = (p: ReturnType<typeof pair>, c: number[], m0: bigint[], m1: bigint[]) => {
  const { msg, pending } = p.recv.begin(c);
  const { y0, y1 } = p.send.respond(msg, m0, m1);
  return p.recv.finish(pending, y0, y1);
};

describe('OtExtReceiver / OtExtSender', () => {
  it('multi-round extension delivers exactly the chosen message (counters and tweak offsets advance in step)', () => {
    const p = pair(41n);
    for (const [m, seed] of [[1, 0], [100, 1], [300, 2], [33, 3], [64, 4]] as const) {
      const c = bitsOf(m, seed);
      const m0 = vals(m, BigInt(seed)), m1 = vals(m, BigInt(seed) + 99n);
      expect(run(p, c, m0, m1)).toEqual(c.map((bit, j) => (bit ? m1[j] : m0[j])));
    }
  });
  it('is gated on the base OT and validates the seeds', () => {
    const r = rng(1n);
    const kos = b(20);
    const recv = new OtExtReceiver(r, kos), send = new OtExtSender(r, kos);
    expect(recv.ready).toBe(false);
    expect(send.ready).toBe(false);
    expect(errOf(() => recv.begin([0])).message).toBe('OtExtReceiver: base OT not done');
    expect(errOf(() => send.respond({ u: [], x: 0n, tComb: 0n }, [], [])).message).toBe('OtExtSender: base OT not done');
    expect(errOf(() => send.setSeeds([])).message).toBe('OtExtSender: wrong base-OT output size');
    const seeds = recv.makeSeeds();
    expect(recv.ready).toBe(true);
    expect(seeds).toHaveLength(KAPPA);
    for (const [k0, k1] of seeds) { expect(k0).toHaveLength(16); expect(k1).not.toEqual(k0); }
    expect(errOf(() => send.setSeeds(seeds.map((x) => x[0]))).message).toBe('OtExtSender: wrong base-OT output size');
    const s = send.makeSelector();
    expect(s).toHaveLength(KAPPA);
    expect(s.every((x) => x === 0 || x === 1)).toBe(true);
    expect(s.some((x) => x === 1) && s.some((x) => x === 0)).toBe(true);
    s[0] = 1 - s[0]!;
    expect(send.makeSelector()).not.toBe(s);
    expect(errOf(() => send.setSeeds(seeds.slice(1).map((x) => x[0]))).message).toBe('OtExtSender: wrong base-OT output size');
    send.setSeeds(seeds.map((x) => x[0]));
    expect(send.ready).toBe(true);
  });
  it('the selector is the little-endian packing of the base-OT choice bits', () => {
    const p = pair(42n);
    let want = 0n;
    p.s.forEach((bit, i) => { want |= BigInt(bit) << BigInt(i); });
    expect(p.send.selector).toBe(want);
    const copy = p.send.makeSelector();
    copy[0] = copy[0]! ^ 1;
    expect(p.send.selector).toBe(want);
  });
  it('rejects bad choice bits and messages with precise range errors', () => {
    const p = pair(43n);
    expect(errOf(() => p.recv.begin([0, 2, 1]))).toEqual(new RangeError('OtChannel.extend: choice bit 1 must be 0 or 1'));
    expect(errOf(() => p.recv.begin([0, 1, -1]))).toEqual(new RangeError('OtChannel.extend: choice bit 2 must be 0 or 1'));
    const { msg } = p.recv.begin([0, 1]);
    const bad = (m0: unknown[], m1: unknown[], j: number) =>
      expect(errOf(() => p.send.respond(msg, m0 as bigint[], m1 as bigint[]))).toEqual(
        new RangeError(`OtChannel.extend: message ${j} must be a bigint in [0, 2^64) (the pad is 64 bits wide)`),
      );
    bad([1n, -1n], [1n, 1n], 1);
    bad([1n, 1n], [1n, -1n], 1);
    bad([1n, M64 + 1n], [1n, 1n], 1);
    bad([1n, 1n], [1n, M64 + 1n], 1);
    bad([1, 1n], [1n, 1n], 0);
    bad([1n, 1n], ['1', 1n], 0);
  });
  it('accepts the extreme 64-bit messages', () => {
    const p = pair(44n);
    expect(run(p, [0, 1], [0n, M64], [M64, 0n])).toEqual([0n, 0n]);
  });
  it('rejects length mismatches on both sides', () => {
    const p = pair(45n);
    const { msg, pending } = p.recv.begin([0, 1]);
    expect(errOf(() => p.send.respond(msg, [1n, 2n], [1n])).message).toBe('OtChannel.extend: length mismatch');
    const q = pair(45n);
    const r2 = q.recv.begin([0, 1]);
    const { y0, y1 } = q.send.respond(r2.msg, [1n, 2n], [3n, 4n]);
    const mm = 'OT extension: ciphertext count does not match the number of rows; aborting';
    expect(errOf(() => q.recv.finish(r2.pending, y0.slice(1), y1)).message).toBe(mm);
    expect(errOf(() => q.recv.finish(r2.pending, y0, y1.slice(1))).message).toBe(mm);
    void pending;
  });
  it('the sender aborts on structurally malformed receiver messages, naming the round', () => {
    const p = pair(46n);
    run(p, [1], [5n], [6n]);
    const abortOf = (f: () => unknown) => { const e = errOf(f); expect(e).toBeInstanceOf(MalOtAbort); return e.message; };
    const fresh = () => p.recv.begin([0, 1]).msg;
    const cols = `a cheating OT-extension receiver was detected; aborting`;
    let msg = fresh();
    expect(abortOf(() => p.send.respond({ ...msg, u: msg.u.slice(1) }, [1n, 2n], [3n, 4n]))).toBe(`KOS check (round 1): wrong number of u columns; ${cols}`);
    msg = fresh();
    expect(abortOf(() => p.send.respond({ ...msg, u: [...msg.u, 0n] }, [1n, 2n], [3n, 4n]))).toBe(`KOS check (round 2): wrong number of u columns; ${cols}`);
    msg = fresh();
    expect(abortOf(() => p.send.respond({ ...msg, u: 'x' as never }, [1n, 2n], [3n, 4n]))).toBe(`KOS check (round 3): wrong number of u columns; ${cols}`);
    const limit = 1n << BigInt(2 + KAPPA + SSEC);
    for (const [bad, label] of [[-1n, 'neg'], [limit, 'limit'], [limit + 5n, 'over'], [5 as never, 'num']] as const) {
      msg = fresh();
      const u = msg.u.slice();
      u[77] = bad as bigint;
      const round = p.recv ? undefined : undefined;
      void round; void label;
      const m = abortOf(() => p.send.respond({ ...msg, u }, [1n, 2n], [3n, 4n]));
      expect(m).toMatch(/^KOS check \(round \d+\): malformed u column 77; a cheating OT-extension receiver was detected; aborting$/);
    }
    const lim128 = 1n << 128n;
    for (const patch of [{ x: -1n }, { x: lim128 }, { tComb: -1n }, { tComb: lim128 }, { x: 1 as never }, { tComb: '1' as never }]) {
      msg = fresh();
      const m = abortOf(() => p.send.respond({ ...msg, ...patch }, [1n, 2n], [3n, 4n]));
      expect(m).toMatch(/^KOS check \(round \d+\): malformed \(x, t\); a cheating OT-extension receiver was detected; aborting$/);
    }
  });
  it('detects a tampered KOS pair or column, and still accepts the extreme in-range values structurally', () => {
    const p = pair(47n);
    let { msg } = p.recv.begin([0, 1, 1]);
    const failed = (round: number) => `KOS correlation check FAILED (round ${round}): a cheating OT-extension receiver was detected; aborting`;
    expect(errOf(() => p.send.respond({ ...msg, x: msg.x ^ 1n }, [1n, 2n, 3n], [4n, 5n, 6n])).message).toBe(failed(0));
    ({ msg } = p.recv.begin([0, 1, 1]));
    expect(errOf(() => p.send.respond({ ...msg, tComb: msg.tComb ^ 1n }, [1n, 2n, 3n], [4n, 5n, 6n])).message).toBe(failed(1));
    ({ msg } = p.recv.begin([0, 1, 1]));
    const u = msg.u.slice();
    u[3] = u[3]! ^ 1n;
    expect(errOf(() => p.send.respond({ ...msg, u }, [1n, 2n, 3n], [4n, 5n, 6n])).message).toBe(failed(2));
    const hi = msg.u.slice();
    hi[3] = hi[3]! ^ (1n << BigInt(3 + KAPPA + SSEC - 1));
    ({ msg } = p.recv.begin([0, 1, 1]));
    const top = msg.u.slice();
    top[5] = top[5]! ^ (1n << BigInt(3 + KAPPA + SSEC - 1));
    expect(errOf(() => p.send.respond({ ...msg, u: top }, [1n, 2n, 3n], [4n, 5n, 6n])).message).toBe(failed(3));
  });
  it('the receiver hook lets a tampered matrix through to the sender, and a malformed one is sent with a zero pair', () => {
    const p = pair(48n);
    p.recv.tamperU = (u) => { u[0] = -1n; };
    const { msg } = p.recv.begin([0, 1]);
    expect(msg.x).toBe(0n);
    expect(msg.tComb).toBe(0n);
    expect(msg.u[0]).toBe(-1n);
    const q = pair(48n);
    q.recv.tamperU = (u, round) => { for (let i = 0; i < u.length; i++) u[i] = u[i]! ^ BigInt(round + 1); };
    const r = q.recv.begin([0, 1]);
    expect(r.msg.x).not.toBe(0n);
    expect(errOf(() => q.send.respond(r.msg, [1n, 2n], [3n, 4n]))).toBeInstanceOf(MalOtAbort);
    const big = pair(48n);
    big.recv.tamperU = (u) => { u[1] = 1n << BigInt(2 + KAPPA + SSEC); };
    expect(big.recv.begin([0, 1]).msg.x).toBe(0n);
    const e = pair(48n);
    e.recv.tamperU = (u) => { (u as unknown[])[4] = 'x'; };
    expect(e.recv.begin([0, 1]).msg.tComb).toBe(0n);
  });
});

describe('OtChannel', () => {
  const fake = (messages: Array<[Uint8Array, Uint8Array]>, choices: number[]) => ({ received: messages.map((m, i) => m[choices[i]!]!) });
  it('extends over a custom base OT without setting the EC transcript', () => {
    let calls = 0, sizes = 0;
    const ch = new OtChannel(rng(51n), { baseOtFn: (m, c) => { calls++; sizes = m.length + c.length; return fake(m, c); } });
    const c = bitsOf(70, 1), m0 = vals(70, 1n), m1 = vals(70, 2n);
    const out = ch.extend(c, m0, m1);
    expect(out.received).toEqual(c.map((bit, j) => (bit ? m1[j] : m0[j])));
    expect(out.uMatrix).toHaveLength(KAPPA);
    expect(calls).toBe(1);
    expect(sizes).toBe(2 * KAPPA);
    expect(ch.baseTranscript).toBeUndefined();
    ch.extend([1], [3n], [4n]);
    expect(calls).toBe(1);
  });
  it('validates lengths and returns nothing for an empty round', () => {
    const ch = new OtChannel(rng(52n), { baseOtFn: fake });
    expect(errOf(() => ch.extend([0, 1], [1n], [2n, 3n])).message).toBe('OtChannel.extend: length mismatch');
    expect(errOf(() => ch.extend([0, 1], [1n, 2n], [3n])).message).toBe('OtChannel.extend: length mismatch');
    expect(ch.extend([], [], [])).toEqual({ received: [], uMatrix: [] });
    expect(errOf(() => ch.extend([2], [1n], [2n]))).toBeInstanceOf(RangeError);
  });
  it('the selector getter triggers setup and is stable', () => {
    const ch = new OtChannel(rng(53n), { baseOtFn: fake });
    const s = ch.selector;
    expect(s).toBeGreaterThan(0n);
    expect(ch.selector).toBe(s);
  });
  it('a tampered u matrix is caught by the KOS check', () => {
    const ch = new OtChannel(rng(54n), { baseOtFn: fake });
    ch.tamperU = (u) => { u[7] = u[7]! ^ 1n; };
    expect(errOf(() => ch.extend([0, 1, 0], [1n, 2n, 3n], [4n, 5n, 6n]))).toBeInstanceOf(MalOtAbort);
  });
  it('the default EC setup runs the real base OT under the given binding', () => {
    const ch = new OtChannel(rng(55n), { binding: { sessionId: b(16, 9), senderIndex: 2, receiverIndex: 5 } });
    const out = ch.extend([1, 0], [10n, 20n], [30n, 40n]);
    expect(out.received).toEqual([30n, 20n]);
    expect(ch.baseTranscript!.R).toHaveLength(KAPPA);
    const again = new OtChannel(rng(55n), { binding: { sessionId: b(16, 9), senderIndex: 2, receiverIndex: 5 } });
    expect(again.extend([1, 0], [10n, 20n], [30n, 40n]).uMatrix).toEqual(out.uMatrix);
    const other = new OtChannel(rng(55n), { binding: { sessionId: b(16, 10), senderIndex: 2, receiverIndex: 5 } });
    other.extend([1, 0], [10n, 20n], [30n, 40n]);
    expect(other.baseTranscript!.ct).not.toEqual(out.uMatrix && again.baseTranscript!.ct);
  });
});

// ------------------------------------------------------------------------------- round 2

import { IDENTITY } from './ec';
import { maskTail, prgColumn } from './otx';

describe('round 2: kosChiWords column override', () => {
  it('hashes the supplied column bytes instead of re-deriving them from u', () => {
    const bind = b(20, 1), round = 2, mExt = 40, colBytes = 5;
    const u = [1n, 2n, 3n];
    const other = [b(colBytes, 1), b(colBytes, 2), b(colBytes, 3)];
    const xof = createHash('shake256', { outputLength: mExt * 16 });
    for (const part of [T('atlas-pca-mpc/ot-kos'), u32(bind.length), bind, u32(round), u32(mExt), u32(u.length), ...other]) xof.update(part);
    const out = xof.digest();
    const want = new Uint32Array(mExt * 4);
    for (let i = 0; i < want.length; i++) want[i] = out.readUInt32LE(i * 4);
    expect(kosChiWords(bind, round, u, mExt, other)).toEqual(want);
    expect(kosChiWords(bind, round, u, mExt)).not.toEqual(want);
  });
});

describe('round 2: base OT checks', () => {
  const binding = { sessionId: b(16), senderIndex: 0, receiverIndex: 1, round: 'r' };
  it('a commitment of the wrong length is an inconsistency abort, not a crash', () => {
    const msgs: Array<[Uint8Array, Uint8Array]> = [[b(16, 1), b(16, 2)]];
    const pads: Array<[Uint8Array, Uint8Array]> = [[b(16, 5), b(16, 6)]];
    const { ct, com } = baseOtSenderEncrypt(msgs, pads);
    const short: Array<[Uint8Array, Uint8Array]> = [[com[0]![0].slice(1), com[0]![1].slice(1)]];
    const e = errOf(() => baseOtReceiverDecrypt([1], [pads[0]![1]], ct, short));
    expect(e).toBeInstanceOf(BaseOtAbort);
    expect(e.message).toBe('base OT (index 0): sender ciphertext inconsistent with its commitment; aborting');
    const long: Array<[Uint8Array, Uint8Array]> = [[b(33), b(33)]];
    expect(errOf(() => baseOtReceiverDecrypt([0], [pads[0]![0]], ct, long))).toBeInstanceOf(BaseOtAbort);
  });
  it('point validation names the offending party and index', () => {
    const s = malBaseOtSenderSetup(rng(61n), binding);
    expect(errOf(() => malBaseOtReceiverRespond(IDENTITY, s.proof, [0], rng(62n), binding)).message).toContain('base-OT S (received by receiver)');
    const out = malBaseOtReceiverRespond(s.S, s.proof, [0, 1], rng(62n), binding);
    expect(errOf(() => malBaseOtSenderDerive(s.y, s.T, [out.R[0]!, IDENTITY], s.S, binding)).message).toContain('base-OT R_1 (received by sender)');
  });
});

describe('round 2: extension receiver internals', () => {
  it('the wire u hides bvec = choice bits followed by the random check bits', () => {
    for (const m of [5, 40]) {
      const seed = 70n + BigInt(m);
      const p = pair(seed);
      const c = bitsOf(m, 2);
      const { msg } = p.recv.begin(c);
      const mExt = m + KAPPA + SSEC, W = (mExt + 31) >>> 5, colBytes = Math.ceil(mExt / 8);
      const r2 = rng(seed);
      for (let i = 0; i < 2 * KAPPA; i++) r2.bytes(16);
      for (let i = 0; i < KAPPA; i++) r2.bytes(1);
      const padBytes = r2.bytes(KAPPA + SSEC);
      const t0 = prgColumn(p.messages[3]![0], 0, W), g0 = prgColumn(p.messages[3]![1], 0, W);
      maskTail(t0, mExt);
      maskTail(g0, mExt);
      const bv = new Uint32Array(W);
      let uw = msg.u[3]!;
      for (let w = 0; w < W; w++) { bv[w] = (Number(uw & 0xffffffffn) ^ t0[w]! ^ g0[w]!) >>> 0; uw >>= 32n; }
      for (let j = 0; j < mExt; j++) {
        const bit = (bv[j >>> 5]! >>> (j & 31)) & 1;
        const want = j < m ? c[j]! : padBytes[j - m]! & 1;
        expect(bit).toBe(want);
      }
      expect(bv.length * 32 >= mExt).toBe(true);
      void colBytes;
    }
  });
  it('begin snapshots the choice bits, so later caller mutation cannot change the result', () => {
    const p = pair(71n);
    const c = [1, 0, 1, 1];
    const m0 = [1n, 2n, 3n, 4n], m1 = [5n, 6n, 7n, 8n];
    const { msg, pending } = p.recv.begin(c);
    const { y0, y1 } = p.send.respond(msg, m0, m1);
    c.fill(0);
    expect(p.recv.finish(pending, y0, y1)).toEqual([5n, 2n, 7n, 8n]);
  });
  it('a zero column is a valid structure on the wire (only the KOS check can reject it)', () => {
    const p = pair(72n);
    p.recv.tamperU = (u) => { u[0] = 0n; };
    const { msg } = p.recv.begin([0, 1]);
    expect(msg.x).not.toBe(0n);
    expect(msg.tComb).not.toBe(0n);
    const q = pair(72n);
    const r = q.recv.begin([0, 1]);
    const zeroed = r.msg.u.slice();
    zeroed[5] = 0n;
    expect(errOf(() => q.send.respond({ ...r.msg, u: zeroed }, [1n, 2n], [3n, 4n])).message).toMatch(/^KOS correlation check FAILED/);
    const z = pair(73n);
    const zr = z.recv.begin([0, 1]);
    expect(errOf(() => z.send.respond({ ...zr.msg, x: 0n }, [1n, 2n], [3n, 4n])).message).toMatch(/^KOS correlation check FAILED/);
    const w = pair(73n);
    const wr = w.recv.begin([0, 1]);
    expect(errOf(() => w.send.respond({ ...wr.msg, tComb: 0n }, [1n, 2n], [3n, 4n])).message).toMatch(/^KOS correlation check FAILED/);
  });
  it('makeSelector returns a copy: editing it cannot desynchronise the sender', () => {
    const r = rng(74n);
    const kos = b(20, 2);
    const recv = new OtExtReceiver(r, kos), send = new OtExtSender(r, kos);
    const messages = recv.makeSeeds();
    const s = send.makeSelector();
    const seeds = s.map((bit, i) => messages[i]![bit]!);
    s.fill(0);
    send.setSeeds(seeds);
    const { msg, pending } = recv.begin([1, 0]);
    const { y0, y1 } = send.respond(msg, [1n, 2n], [3n, 4n]);
    expect(recv.finish(pending, y0, y1)).toEqual([3n, 2n]);
  });
  it('a rejected extend leaves the channel state untouched', () => {
    const ch = new OtChannel(rng(75n), { baseOtFn: fakeBase });
    expect(errOf(() => ch.extend([0, 1], [1n, -1n], [3n, 4n]))).toBeInstanceOf(RangeError);
    expect(ch.extend([0, 1], [1n, 2n], [3n, 4n]).received).toEqual([1n, 4n]);
    expect(errOf(() => ch.extend([0, 1], [1n, 2n], [3n, M64 + 1n]))).toBeInstanceOf(RangeError);
    expect(ch.extend([1, 1], [1n, 2n], [3n, 4n]).received).toEqual([3n, 4n]);
  });
});

function fakeBase(messages: Array<[Uint8Array, Uint8Array]>, choices: number[]) {
  return { received: messages.map((m, i) => m[choices[i]!]!) };
}
