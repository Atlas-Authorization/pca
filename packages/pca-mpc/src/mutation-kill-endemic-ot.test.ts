import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  CT_BYTES, EndemicLweOtAbort, PK_BYTES, SYM_BYTES, TVEC_BYTES,
  endemicLweBaseOT, endemicLweBaseOtFn, endemicLweBaseOtRandom, endemicLwePad, endemicLweReceive, endemicLweRecoverRandom,
  endemicLweSendRandom, endemicSessionId, withEndemicLweBaseOt,
} from './endemic-ot';
import { otRandom, splitMix64 } from './ot';

const rng = (s: bigint) => otRandom(splitMix64(s));
const te = new TextEncoder();
const sha = (...c: Uint8Array[]) => {
  const h = createHash('sha256');
  for (const x of c) h.update(x);
  return new Uint8Array(h.digest());
};
const u32 = (x: number) => Uint8Array.of((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255);
const TAG_PAD = te.encode('atlas-pca-mpc/endemic-lwe-ot-pad');
const refPad = (sid: Uint8Array, i: number, slot: number, payload: Uint8Array, len: number) => {
  const out: number[] = [];
  for (let ctr = 0; out.length < len; ctr++) out.push(...sha(TAG_PAD, sid, u32(i), Uint8Array.of(slot & 1), u32(ctr), payload));
  return Uint8Array.from(out.slice(0, len));
};
const b = (n: number, s = 0) => Uint8Array.from({ length: n }, (_, i) => (i * 13 + s) & 255);

describe('EndemicLweOtAbort', () => {
  it('is a named Error', () => {
    const e = new EndemicLweOtAbort('x');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('EndemicLweOtAbort');
    expect(e.message).toBe('x');
  });
});

describe('endemicLwePad', () => {
  it('is the counter-mode sha256 expansion for lengths around block boundaries', () => {
    const sid = endemicSessionId(b(32, 1));
    const payload = b(32, 9);
    for (const len of [0, 1, 5, 31, 32, 33, 40, 64, 65, 100]) {
      const got = endemicLwePad(sid, 3, 1, payload, len);
      expect(got).toHaveLength(len);
      expect(got).toEqual(refPad(sid, 3, 1, payload, len));
    }
    expect(endemicLwePad(sid, 3, 3, payload, 40)).toEqual(endemicLwePad(sid, 3, 1, payload, 40));
    expect(endemicLwePad(sid, 3, 2, payload, 40)).toEqual(endemicLwePad(sid, 3, 0, payload, 40));
    expect(endemicLwePad(sid, 3, 0, payload, 40)).not.toEqual(endemicLwePad(sid, 3, 1, payload, 40));
  });
});

describe('endemicLweReceive', () => {
  it('produces exactly one point pair and rho per choice, sized from the lattice core', () => {
    const { message, state } = endemicLweReceive([0, 1, 1], rng(1n));
    expect(message.rn).toHaveLength(SYM_BYTES);
    expect(message.points).toHaveLength(3);
    expect(message.rhos).toHaveLength(3);
    expect(state.choices).toEqual([0, 1, 1]);
    expect(state.secretKeys).toHaveLength(3);
    for (const [p0, p1] of message.points) { expect(p0).toHaveLength(TVEC_BYTES); expect(p1).toHaveLength(TVEC_BYTES); }
    expect(endemicLweReceive([], rng(1n)).message.points).toHaveLength(0);
  });
});

describe('endemicLweSendRandom validation', () => {
  const good = () => endemicLweReceive([0, 1], rng(2n)).message;
  const abort = (m: unknown, msg: string) => {
    let err: unknown;
    try { endemicLweSendRandom(m as never, rng(3n)); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(EndemicLweOtAbort);
    expect((err as Error).message).toBe(msg);
  };
  it('accepts a well formed message and the empty message', () => {
    expect(endemicLweSendRandom(good(), rng(3n)).ciphertexts).toHaveLength(2);
    const e = endemicLweSendRandom({ rn: b(SYM_BYTES), points: [], rhos: [] }, rng(3n));
    expect(e.ciphertexts).toEqual([]);
    expect(e.senderPads).toEqual([]);
  });
  it('rejects a malformed session nonce', () => {
    const g = good();
    abort({ ...g, rn: [...g.rn] }, 'endemic LWE OT: malformed session nonce');
    abort({ ...g, rn: g.rn.slice(1) }, 'endemic LWE OT: malformed session nonce');
    abort({ ...g, rn: new Uint8Array(SYM_BYTES + 1) }, 'endemic LWE OT: malformed session nonce');
  });
  it('rejects non-array or mismatched points/rhos', () => {
    const g = good();
    abort({ ...g, points: { length: 2 } }, 'endemic LWE OT: points/rhos length mismatch');
    abort({ ...g, rhos: { length: 2 } }, 'endemic LWE OT: points/rhos length mismatch');
    abort({ ...g, points: { length: 2 }, rhos: { length: 2 } }, 'endemic LWE OT: points/rhos length mismatch');
    abort({ ...g, rhos: g.rhos.slice(1) }, 'endemic LWE OT: points/rhos length mismatch');
    abort({ ...g, points: g.points.slice(1) }, 'endemic LWE OT: points/rhos length mismatch');
  });
  it('rejects each malformed point pair at its index', () => {
    const g = good();
    const withPt = (pt: unknown, idx = 1) => ({ ...g, points: g.points.map((p, i) => (i === idx ? pt : p)) });
    const msg = (i: number) => `endemic LWE OT: malformed point pair at index ${i}`;
    const ok = g.points[1]!;
    abort(withPt('nope'), msg(1));
    abort(withPt([ok[0]]), msg(1));
    abort(withPt([ok[0], ok[1], ok[1]]), msg(1));
    abort(withPt([[...ok[0]], ok[1]]), msg(1));
    abort(withPt([ok[0], [...ok[1]]]), msg(1));
    abort(withPt([ok[0].slice(1), ok[1]]), msg(1));
    abort(withPt([ok[0], ok[1].slice(1)]), msg(1));
    abort(withPt([new Uint8Array(TVEC_BYTES + 1), ok[1]]), msg(1));
    abort(withPt([ok[0], new Uint8Array(TVEC_BYTES + 1)]), msg(1));
    abort(withPt(undefined, 0), msg(0));
  });
  it('rejects each malformed rho at its index', () => {
    const g = good();
    const withRho = (rho: unknown) => ({ ...g, rhos: g.rhos.map((r, i) => (i === 1 ? rho : r)) });
    const msg = 'endemic LWE OT: malformed rho at index 1';
    abort(withRho([...g.rhos[1]!]), msg);
    abort(withRho(g.rhos[1]!.slice(1)), msg);
    abort(withRho(new Uint8Array(PK_BYTES - TVEC_BYTES + 1)), msg);
  });
  it('applies a tamper hook to the ciphertexts after the pads are fixed', () => {
    const m = good();
    const plain = endemicLweSendRandom(m, rng(5n));
    const t = endemicLweSendRandom(m, rng(5n), { tamperCiphertexts: (c) => { c[0]![1] = new Uint8Array(3); } });
    expect(t.ciphertexts[0]![1]).toEqual(new Uint8Array(3));
    expect(t.ciphertexts[0]![0]).toEqual(plain.ciphertexts[0]![0]);
    expect(t.senderPads).toEqual(plain.senderPads);
    expect(endemicLweSendRandom(m, rng(5n), {}).ciphertexts).toEqual(plain.ciphertexts);
  });
});

describe('endemicLweRecoverRandom validation', () => {
  const run = () => {
    const { message, state } = endemicLweReceive([1, 0], rng(7n));
    return { state, sm: endemicLweSendRandom(message, rng(8n)) };
  };
  const abort = (st: never, sm: unknown, msg: string) => {
    let err: unknown;
    try { endemicLweRecoverRandom(st, sm as never); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(EndemicLweOtAbort);
    expect((err as Error).message).toBe(msg);
  };
  it('recovers the chosen pads and checks nothing else', () => {
    const { state, sm } = run();
    const pads = endemicLweRecoverRandom(state, sm);
    expect(pads).toEqual([sm.senderPads[0]![1], sm.senderPads[1]![0]]);
  });
  it('rejects a wrong ciphertext count or a non-array', () => {
    const { state, sm } = run();
    const msg = 'endemic LWE OT: ciphertext count does not match the transfer count';
    abort(state as never, { ciphertexts: sm.ciphertexts.slice(1) }, msg);
    abort(state as never, { ciphertexts: [...sm.ciphertexts, sm.ciphertexts[0]] }, msg);
    abort(state as never, { ciphertexts: { length: 2 } }, msg);
    abort(state as never, {}, msg);
  });
  it('rejects each malformed ciphertext pair at its index', () => {
    const { state, sm } = run();
    const msg = 'endemic LWE OT: malformed ciphertext pair at index 1';
    const ok = sm.ciphertexts[1]!;
    const withCt = (ct: unknown) => ({ ciphertexts: sm.ciphertexts.map((c, i) => (i === 1 ? ct : c)) });
    abort(state as never, withCt('x'), msg);
    abort(state as never, withCt([[...ok[0]], ok[1]]), msg);
    abort(state as never, withCt([ok[0], [...ok[1]]]), msg);
    abort(state as never, withCt([ok[0].slice(1), ok[1]]), msg);
    abort(state as never, withCt([ok[0], ok[1].slice(1)]), msg);
    abort(state as never, withCt([new Uint8Array(CT_BYTES + 1), ok[1]]), msg);
    abort(state as never, withCt([ok[0], new Uint8Array(CT_BYTES + 1)]), msg);
    abort(state as never, { ciphertexts: [undefined, ok] }, 'endemic LWE OT: malformed ciphertext pair at index 0');
  });
});

describe('endemicLweBaseOtRandom', () => {
  it('returns pads consistent with the session id and pairs the receiver pad to its choice', () => {
    const r = endemicLweBaseOtRandom([1, 0, 1], rng(11n));
    expect(r.recvPads).toEqual([r.senderPads[0]![1], r.senderPads[1]![0], r.senderPads[2]![1]]);
    expect(r.sid).toEqual(endemicSessionId(r.message.rn));
    expect(r.ciphertexts).toHaveLength(3);
  });
});

describe('endemicLweBaseOT', () => {
  const msgs: Array<[Uint8Array, Uint8Array]> = [[b(40, 1), b(40, 2)], [b(5, 3), b(5, 4)], [b(33, 5), b(33, 6)]];
  it('delivers the chosen message and exposes the full transcript', () => {
    const choices = [1, 0, 1];
    const r = endemicLweBaseOT(msgs, choices, rng(21n));
    expect(r.received).toEqual([msgs[0]![1], msgs[1]![0], msgs[2]![1]]);
    const replay = endemicLweReceive(choices, rng(21n)).message;
    expect(r.transcript.rn).toEqual(replay.rn);
    expect(r.transcript.points).toEqual(replay.points);
    expect(r.transcript.rhos).toEqual(replay.rhos);
    expect(r.transcript.ciphertexts).toHaveLength(3);
    expect(r.transcript.encrypted.map((e) => e[0].length)).toEqual([40, 5, 33]);
    expect(r.transcript.commitments.every((c) => c[0].length === 32 && c[1].length === 32)).toBe(true);
  });
  it('rejects mismatched messages/choices and unequal message pair lengths', () => {
    expect(() => endemicLweBaseOT(msgs, [0], rng(1n))).toThrow('endemicLweBaseOT: messages/choices length mismatch');
    expect(() => endemicLweBaseOT([msgs[0]!, [b(4), b(5)]], [0, 1], rng(1n))).toThrow(
      'endemicLweBaseOT (index 1): the two messages must be equal length',
    );
  });
  it('aborts with the index when the chosen ciphertext is tampered, but not the other one', () => {
    const tamperChosen = (idx: number, slot: number) => ({
      tamperCiphertexts: (c: Array<[Uint8Array, Uint8Array]>) => { const x = c[idx]![slot]!.slice(); x[0]! ^= 1; c[idx]![slot] = x; },
    });
    let err: unknown;
    try { endemicLweBaseOT(msgs, [1, 0, 1], rng(22n), tamperChosen(2, 1)); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(EndemicLweOtAbort);
    expect((err as Error).message).toBe('endemic base OT (index 2): sender ciphertext inconsistent with its commitment; aborting');
    expect(endemicLweBaseOT(msgs, [1, 0, 1], rng(22n), tamperChosen(2, 0)).received[2]).toEqual(msgs[2]![1]);
  });
  it('works as a BaseOtFn and through withEndemicLweBaseOt', () => {
    const r = endemicLweBaseOtFn(msgs, [0, 1, 0], rng(23n));
    expect(r.received).toEqual([msgs[0]![0], msgs[1]![1], msgs[2]![0]]);
    expect(withEndemicLweBaseOt()).toEqual({ baseOtFn: endemicLweBaseOtFn });
  });
});
