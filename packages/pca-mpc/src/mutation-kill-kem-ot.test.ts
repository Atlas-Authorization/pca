import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  KEM_OT_SECRET_BYTES, KemBaseOtAbort, kemBaseOT, kemBaseOtMal, kemBaseOtMalCommit, kemBaseOtMalOpen, kemBaseOtMalRandom,
  kemBaseOtMalRandomRecover, kemBaseOtMalRandomSend, kemBaseOtMalRecover, kemBaseOtMalSend, kemBaseOtMalSenderNonce, kemBaseOtOpen,
  kemBaseOtReceive, kemBaseOtSend, kemOtPad, withKemBaseOt, withKemBaseOtMal,
} from './kem-ot';
import { otRandom, splitMix64 } from './ot';

const rng = (s: bigint) => otRandom(splitMix64(s));
const te = new TextEncoder();
const sha = (...c: Uint8Array[]) => {
  const h = createHash('sha256');
  for (const x of c) h.update(x);
  return new Uint8Array(h.digest());
};
const u32 = (x: number) => Uint8Array.of((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255);
const b = (n: number, s = 0) => Uint8Array.from({ length: n }, (_, i) => (i * 13 + s) & 255);
const xor = (x: Uint8Array, y: Uint8Array) => Uint8Array.from(x, (v, i) => v ^ y[i]!);
const T = (s: string) => te.encode(s);
const expand = (mk: (ctr: number) => Uint8Array, len: number) => {
  const out: number[] = [];
  for (let ctr = 0; out.length < len; ctr++) out.push(...mk(ctr));
  return Uint8Array.from(out.slice(0, len));
};
const msgs = (): Array<[Uint8Array, Uint8Array]> => [[b(40, 1), b(40, 2)], [b(5, 3), b(5, 4)], [b(33, 5), b(33, 6)]];
const errOf = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('did not throw'); };

describe('KemBaseOtAbort / kemOtPad', () => {
  it('is a named Error', () => {
    const e = new KemBaseOtAbort('m');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('KemBaseOtAbort');
    expect(e.message).toBe('m');
  });
  it('is the counter-mode sha256 expansion around block boundaries', () => {
    const ss = b(32, 7);
    for (const len of [0, 1, 5, 31, 32, 33, 40, 64, 65, 100]) {
      const got = kemOtPad(0x01020304, 1, ss, len);
      expect(got).toHaveLength(len);
      expect(got).toEqual(expand((ctr) => sha(T('atlas-pca-mpc/kem-ot-pad'), u32(0x01020304), Uint8Array.of(1), u32(ctr), ss), len));
    }
    expect(kemOtPad(2, 3, ss, 40)).toEqual(kemOtPad(2, 1, ss, 40));
    expect(kemOtPad(2, 2, ss, 40)).toEqual(kemOtPad(2, 0, ss, 40));
    expect(kemOtPad(2, 0, ss, 40)).not.toEqual(kemOtPad(2, 1, ss, 40));
  });
  it('bounds the length to an integer in [0, 1 MiB]', () => {
    const msg = 'kemOtPad: length must be an integer in [0, 1 MiB]';
    for (const len of [-1, 1.5, NaN, Infinity, (1 << 20) + 1]) expect(() => kemOtPad(0, 0, b(32), len)).toThrow(new RangeError(msg));
    expect(kemOtPad(0, 0, b(32), 0)).toHaveLength(0);
    expect(kemOtPad(0, 0, b(32), 1 << 20)).toHaveLength(1 << 20);
  });
});

describe('plain KEM base OT', () => {
  it('places distinct public keys on the wire for either choice', () => {
    const { message } = kemBaseOtReceive([0, 1, 0, 1], rng(1n));
    expect(message.publicKeys).toHaveLength(4);
    for (const [p0, p1] of message.publicKeys) expect(p0).not.toEqual(p1);
  });
  it('rejects mismatched lengths with precise messages', () => {
    const { message, state } = kemBaseOtReceive([0, 1, 0], rng(2n));
    expect(errOf(() => kemBaseOtSend(msgs().slice(1), message, rng(3n))).message).toBe('kemBaseOtSend: messages/publicKeys length mismatch');
    expect(errOf(() => kemBaseOtSend([...msgs(), msgs()[0]!], message, rng(3n))).message).toBe('kemBaseOtSend: messages/publicKeys length mismatch');
    const bad = msgs();
    bad[1] = [b(4), b(5)];
    expect(errOf(() => kemBaseOtSend(bad, message, rng(3n))).message).toBe('kemBaseOtSend (index 1): the two messages must be equal length');
    const sm = kemBaseOtSend(msgs(), message, rng(3n));
    const o = 'kemBaseOtOpen: transcript/state length mismatch';
    expect(errOf(() => kemBaseOtOpen(state, { ...sm, ciphertexts: sm.ciphertexts.slice(1) })).message).toBe(o);
    expect(errOf(() => kemBaseOtOpen(state, { ...sm, encrypted: sm.encrypted.slice(1) })).message).toBe(o);
    expect(errOf(() => kemBaseOtOpen(state, { ...sm, encrypted: [...sm.encrypted, sm.encrypted[0]!] })).message).toBe(o);
    expect(errOf(() => kemBaseOT(msgs(), [0, 1], rng(4n))).message).toBe('kemBaseOT: messages/choices length mismatch');
    expect(errOf(() => kemBaseOT(msgs().slice(1), [0, 1, 1], rng(4n))).message).toBe('kemBaseOT: messages/choices length mismatch');
  });
  it('delivers the chosen message and exposes the transcript', () => {
    const r = kemBaseOT(msgs(), [1, 0, 1], rng(5n));
    expect(r.received).toEqual([msgs()[0]![1], msgs()[1]![0], msgs()[2]![1]]);
    expect(r.transcript.publicKeys).toHaveLength(3);
    expect(r.transcript.ciphertexts).toHaveLength(3);
    expect(r.transcript.encrypted.map((e) => e[0].length)).toEqual([40, 5, 33]);
  });
  it('wires into the OT channel as baseOtFn', () => {
    const w = withKemBaseOt();
    expect(w).toEqual({ baseOtFn: kemBaseOT });
  });
});

describe('committed KEM base OT', () => {
  const chain = (choices: number[], m = msgs().slice(0, choices.length)) => {
    const r = rng(11n);
    const { message: commit, state } = kemBaseOtMalCommit(choices, r);
    const nonce = kemBaseOtMalSenderNonce(r);
    const opening = kemBaseOtMalOpen(state);
    return { r, commit, state, nonce, opening, m };
  };
  it('commits to the ordered keys with distinct placement and a per-index RO commitment', () => {
    const { commit, state } = chain([0, 1, 1]);
    expect(commit.rn).toHaveLength(32);
    expect(commit.commitments).toHaveLength(3);
    state.publicKeys.forEach(([p0, p1], i) => {
      expect(p0).not.toEqual(p1);
      expect(commit.commitments[i]).toEqual(sha(T('atlas-pca-mpc/kem-ot-commit'), commit.rn, u32(i), p0, p1));
    });
  });
  it('opens copies of the committed keys', () => {
    const { state, opening } = chain([0, 1]);
    expect(opening.publicKeys).toEqual(state.publicKeys);
    expect(opening.publicKeys[0]).not.toBe(state.publicKeys[0]);
  });
  it('pads each slot under (sid, com, index, slot, ss) and the receiver recovers only its choice', () => {
    const { r, commit, state, nonce, opening, m } = chain([1, 0, 1]);
    const sm = kemBaseOtMalSend(m, commit, nonce, opening, r);
    const sid = sha(T('atlas-pca-mpc/kem-ot-sid'), commit.rn, nonce.sn);
    for (let i = 0; i < 3; i++) {
      const c = [1, 0, 1][i]!;
      const ss = ml_kem768.decapsulate(sm.ciphertexts[i]![c]!, state.secretKeys[i]!);
      const pad = expand((ctr) => sha(T('atlas-pca-mpc/kem-ot-mal-pad'), sid, commit.commitments[i]!, u32(i), Uint8Array.of(c), u32(ctr), ss), m[i]![c]!.length);
      expect(sm.encrypted[i]![c]).toEqual(xor(m[i]![c]!, pad));
    }
    expect(kemBaseOtMalRecover(state, nonce, sm)).toEqual([m[0]![1], m[1]![0], m[2]![1]]);
    expect(kemBaseOtMalRecover(state, nonce, sm, {})).toEqual([m[0]![1], m[1]![0], m[2]![1]]);
  });
  it('rejects mismatched lengths with precise messages', () => {
    const { r, commit, state, nonce, opening, m } = chain([1, 0, 1]);
    const s = 'kemBaseOtMalSend: messages/commitments/publicKeys length mismatch';
    expect(errOf(() => kemBaseOtMalSend(m.slice(1), commit, nonce, opening, r)).message).toBe(s);
    expect(errOf(() => kemBaseOtMalSend(m, { ...commit, commitments: commit.commitments.slice(1) }, nonce, opening, r)).message).toBe(s);
    expect(errOf(() => kemBaseOtMalSend(m, commit, nonce, { publicKeys: opening.publicKeys.slice(1) }, r)).message).toBe(s);
    const bad = m.map((x) => [x[0], x[1]] as [Uint8Array, Uint8Array]);
    bad[2] = [b(3), b(4)];
    expect(errOf(() => kemBaseOtMalSend(bad, commit, nonce, opening, r)).message).toBe('kemBaseOtMalSend (index 2): the two messages must be equal length');
    const sm = kemBaseOtMalSend(m, commit, nonce, opening, r);
    const o = 'kemBaseOtMalRecover: transcript/state length mismatch';
    expect(errOf(() => kemBaseOtMalRecover(state, nonce, { ...sm, ciphertexts: sm.ciphertexts.slice(1) })).message).toBe(o);
    expect(errOf(() => kemBaseOtMalRecover(state, nonce, { ...sm, encrypted: sm.encrypted.slice(1) })).message).toBe(o);
    expect(errOf(() => kemBaseOtMalRecover(state, nonce, { ...sm, encrypted: [...sm.encrypted, sm.encrypted[0]!] })).message).toBe(o);
    expect(errOf(() => kemBaseOtMal(m, [0, 1], rng(1n))).message).toBe('kemBaseOtMal: messages/choices length mismatch');
    expect(errOf(() => kemBaseOtMal(m.slice(1), [0, 1, 1], rng(1n))).message).toBe('kemBaseOtMal: messages/choices length mismatch');
  });
  it('aborts at the first index whose opened key differs from its commitment', () => {
    const flip = { tamperOpenedKeys: (pks: Array<[Uint8Array, Uint8Array]>) => { const k = pks[1]![0].slice(); k[0]! ^= 1; pks[1]![0] = k; } };
    const e = errOf(() => kemBaseOtMal(msgs(), [0, 1, 0], rng(21n), flip));
    expect(e).toBeInstanceOf(KemBaseOtAbort);
    expect(e.message).toBe("kem base OT (index 1): opened public keys do not match the receiver's commitment; aborting");
    expect(kemBaseOtMal(msgs(), [0, 1, 0], rng(21n), {}).received).toEqual([msgs()[0]![0], msgs()[1]![1], msgs()[2]![0]]);
  });
  it('a receiver binding a different sid cannot unmask', () => {
    const t = { tamperReceiverSid: (s: Uint8Array) => { const x = s.slice(); x[0]! ^= 1; return x; } };
    const r = kemBaseOtMal(msgs(), [0, 1, 0], rng(22n), t);
    expect(r.received[0]).not.toEqual(msgs()[0]![0]);
  });
  it('exposes the full transcript and works as a BaseOtFn', () => {
    const r = kemBaseOtMal(msgs(), [1, 1, 0], rng(23n));
    expect(r.received).toEqual([msgs()[0]![1], msgs()[1]![1], msgs()[2]![0]]);
    expect(r.transcript.rn).toHaveLength(32);
    expect(r.transcript.sn).toHaveLength(32);
    expect(r.transcript.commitments).toHaveLength(3);
    expect(r.transcript.publicKeys).toHaveLength(3);
    expect(r.transcript.ciphertexts).toHaveLength(3);
    expect(r.transcript.encrypted.map((e) => e[1].length)).toEqual([40, 5, 33]);
    const w = withKemBaseOtMal();
    expect(typeof w!.baseOtFn).toBe('function');
    expect(w!.baseOtFn!(msgs(), [0, 1, 1], rng(24n)).received).toEqual([msgs()[0]![0], msgs()[1]![1], msgs()[2]![1]]);
  });
});

describe('committed KEM random OT', () => {
  it('derives session-bound 32 byte secrets per slot, the receiver learning only its choice', () => {
    expect(KEM_OT_SECRET_BYTES).toBe(32);
    const choices = [1, 0, 1];
    const r = rng(31n);
    const { message: commit, state } = kemBaseOtMalCommit(choices, r);
    const nonce = kemBaseOtMalSenderNonce(r);
    const opening = kemBaseOtMalOpen(state);
    const sm = kemBaseOtMalRandomSend(commit, nonce, opening, r);
    expect(sm.ciphertexts).toHaveLength(3);
    expect(sm.senderSecrets).toHaveLength(3);
    const sid = sha(T('atlas-pca-mpc/kem-ot-sid'), commit.rn, nonce.sn);
    const secret = (i: number, slot: number, ss: Uint8Array) =>
      sha(T('atlas-pca-mpc/kem-ot-mal-secret'), sid, commit.commitments[i]!, u32(i), Uint8Array.of(slot), ss).slice(0, 32);
    const recv = kemBaseOtMalRandomRecover(state, nonce, sm);
    expect(recv).toHaveLength(3);
    for (let i = 0; i < 3; i++) {
      const c = choices[i]!;
      const ss = ml_kem768.decapsulate(sm.ciphertexts[i]![c]!, state.secretKeys[i]!);
      expect(sm.senderSecrets[i]![c]).toEqual(secret(i, c, ss));
      expect(sm.senderSecrets[i]![c]).toHaveLength(32);
      expect(recv[i]).toEqual(sm.senderSecrets[i]![c]);
      expect(sm.senderSecrets[i]![1 - c]).not.toEqual(recv[i]);
    }
    expect(kemBaseOtMalRandomRecover(state, nonce, sm, {})).toEqual(recv);
    const tampered = kemBaseOtMalRandomRecover(state, nonce, sm, { tamperReceiverSid: (s) => { const x = s.slice(); x[0]! ^= 1; return x; } });
    expect(tampered).toHaveLength(3);
    expect(tampered[0]).not.toEqual(recv[0]);
  });
  it('rejects mismatched lengths with precise messages', () => {
    const r = rng(32n);
    const { message: commit, state } = kemBaseOtMalCommit([0, 1], r);
    const nonce = kemBaseOtMalSenderNonce(r);
    const opening = kemBaseOtMalOpen(state);
    expect(errOf(() => kemBaseOtMalRandomSend({ ...commit, commitments: commit.commitments.slice(1) }, nonce, opening, r)).message)
      .toBe('kemBaseOtMalRandomSend: commitments/publicKeys length mismatch');
    expect(errOf(() => kemBaseOtMalRandomSend(commit, nonce, { publicKeys: opening.publicKeys.slice(1) }, r)).message)
      .toBe('kemBaseOtMalRandomSend: commitments/publicKeys length mismatch');
    const sm = kemBaseOtMalRandomSend(commit, nonce, opening, r);
    const m = 'kemBaseOtMalRandomRecover: transcript/state length mismatch';
    expect(errOf(() => kemBaseOtMalRandomRecover(state, nonce, { ...sm, ciphertexts: sm.ciphertexts.slice(1) })).message).toBe(m);
    expect(errOf(() => kemBaseOtMalRandomRecover(state, nonce, { ...sm, ciphertexts: [...sm.ciphertexts, sm.ciphertexts[0]!] })).message).toBe(m);
  });
  it('aborts when an opened key does not match its commitment', () => {
    const flip = { tamperOpenedKeys: (pks: Array<[Uint8Array, Uint8Array]>) => { const k = pks[1]![1].slice(); k[3]! ^= 1; pks[1]![1] = k; } };
    const e = errOf(() => kemBaseOtMalRandom([0, 1, 1], rng(33n), flip));
    expect(e).toBeInstanceOf(KemBaseOtAbort);
    expect(e.message).toBe("kem base OT (index 1): opened public keys do not match the receiver's commitment; aborting");
  });
  it('runs end to end and exposes the transcript, with or without hooks', () => {
    const choices = [0, 1, 1, 0];
    for (const hooks of [undefined, {}]) {
      const r = kemBaseOtMalRandom(choices, rng(34n), hooks);
      expect(r.senderSecrets).toHaveLength(4);
      expect(r.recvSecrets).toHaveLength(4);
      choices.forEach((c, i) => expect(r.recvSecrets[i]).toEqual(r.senderSecrets[i]![c]));
      expect(r.sid).toEqual(sha(T('atlas-pca-mpc/kem-ot-sid'), r.transcript.rn, r.transcript.sn));
      expect(r.transcript.rn).toHaveLength(32);
      expect(r.transcript.sn).toHaveLength(32);
      expect(r.transcript.commitments).toHaveLength(4);
      expect(r.transcript.publicKeys).toHaveLength(4);
      expect(r.transcript.ciphertexts).toHaveLength(4);
    }
    const t = kemBaseOtMalRandom(choices, rng(34n), { tamperReceiverSid: (s) => { const x = s.slice(); x[1]! ^= 1; return x; } });
    expect(t.recvSecrets[0]).not.toEqual(t.senderSecrets[0]![0]);
  });
});
