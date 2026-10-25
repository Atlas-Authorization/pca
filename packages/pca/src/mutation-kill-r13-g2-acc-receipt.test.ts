/**
 * r13 mutation kills for intent-acc.ts (group g2): reservation receipts, the sequencer key set, tracked key-set state
 * and verifyReceiptAgainstHolder. Every refusal is pinned by its exact text (shape checks) or by an exact boolean against
 * a baseline that verifies, so each guard is shown to be the one deciding.
 */
import { describe, expect, it } from 'vitest';
import {
  ACC_RECEIPT_DOMAIN,
  ACC_RECEIPT_REF_DOMAIN,
  ACC_RESERVE_DOMAIN,
  SEQUENCER_KEYS_DOMAIN,
  SEQUENCER_KEYS_REF_DOMAIN,
  accReceiptDigest as accReceiptDigest_,
  pcactnReservationDigest as pcactnReservationDigest_,
  accReceiptCoreDigest as accReceiptCoreDigest_,
  accReceiptShapeError as accReceiptShapeError_,
  sequencerKeySetDigest as sequencerKeySetDigest_,
  sequencerKeySetShapeError as sequencerKeySetShapeError_,
  signAccReceipt as signAccReceipt_,
  signSequencerKeySet as signSequencerKeySet_,
  trackedKeySetError as trackedKeySetError_,
  verifyAccReceiptSignature as verifyAccReceiptSignature_,
  verifyReceiptAgainstHolder as verifyReceiptAgainstHolder_,
  verifySequencerKeySet as verifySequencerKeySet_,
  type AccReceipt,
  type AccReceiptBody,
  type SequencerKeySet,
  type SequencerKeySetBody,
} from './intent-acc';
import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf, sign, verify } from './keys';
import { mlDsa65Keygen, suitePqPublicKey } from './pq';

// ---- exact outcomes: every call of the module under test is settled, so a thrown error is an outcome compared with
// toEqual (an assertion), never an uncaught error. A throw comes back as { ok: false, error: { name, message } }.
type Settled = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const failed = (e: unknown): Settled => ({ ok: false, error: { name: e instanceof Error ? e.name : typeof e, message: e instanceof Error ? e.message : String(e) } });
const settle = (f: () => unknown): Settled => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return failed(e);
  }
};
const sv = <F extends (...a: never[]) => unknown>(f: F): F =>
  ((...a: Parameters<F>) => {
    const r = settle(() => f(...a));
    return r.ok ? r.value : r;
  }) as unknown as F;
const thrown = (message: string, name = 'Error') => ({ ok: false, error: { name, message } });
const accReceiptCoreDigest = sv(accReceiptCoreDigest_);
const accReceiptDigest = sv(accReceiptDigest_);
const pcactnReservationDigest = sv(pcactnReservationDigest_);
const accReceiptShapeError = sv(accReceiptShapeError_);
const sequencerKeySetDigest = sv(sequencerKeySetDigest_);
const sequencerKeySetShapeError = sv(sequencerKeySetShapeError_);
const signAccReceipt = sv(signAccReceipt_);
const signSequencerKeySet = sv(signSequencerKeySet_);
const trackedKeySetError = sv(trackedKeySetError_);
const verifyAccReceiptSignature = sv(verifyAccReceiptSignature_);
const verifyReceiptAgainstHolder = sv(verifyReceiptAgainstHolder_);
const verifySequencerKeySet = sv(verifySequencerKeySet_);

const seed = (l: string) => sha256(utf8(`r13-g2-receipt/${l}`));
const key = (l: string) => {
  const sk = seed(l);
  return { sk, pub: b64u(publicKeyOf(sk)) };
};
const seqRoot = key('root');
const seqKey = key('signing');
const stranger = key('stranger');
const ML = mlDsa65Keygen(seed('ml'));
const ML2 = mlDsa65Keygen(seed('ml2'));
const MLPK = suitePqPublicKey('ml-dsa-65', { mlDsa: ML })!;
const ML2PK = suitePqPublicKey('ml-dsa-65', { mlDsa: ML2 })!;
const H32 = b64u(seed('head'));
const S32 = b64u(seed('session'));
const D32 = b64u(seed('digest'));
const NOW = 1_800_000_000_000;

const body = (o: Partial<AccReceiptBody> = {}): AccReceiptBody => ({ v: 1, kind: 'pca-acc-receipt', session: S32, acc: 'trip', seq: 1, pre: 0, delta: 5, post: 5, pcactn_digest: D32, aud: 'aud.example', issued_at: NOW - 1_000, expires_at: NOW + 60_000, kid: 's1', ledger: { index: 0, head: H32 }, ...o });
const RC = signAccReceipt(body(), seqKey.sk);
const ksBody = (o: Partial<SequencerKeySetBody> = {}): SequencerKeySetBody => ({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 100, keys: [{ kid: 's1', pk: seqKey.pub, not_before: NOW - 10_000 }], ...o });
const KS = signSequencerKeySet(ksBody(), seqRoot.sk);
const HOLDER = { kind: 'sequenced' as const, uri: 'https://seq.example', root: seqRoot.pub };
const vr = (r: unknown, keySets: unknown = [KS], now = NOW, f = {}) => verifyReceiptAgainstHolder(r as AccReceipt, HOLDER, keySets as unknown[], now, f);
const rshape = (o: Record<string, unknown>) => accReceiptShapeError({ ...RC, ...o });
const kshape = (o: Record<string, unknown>) => sequencerKeySetShapeError({ ...KS, ...o });
const entry = (o: Record<string, unknown>) => kshape({ keys: [{ kid: 's1', pk: seqKey.pub, not_before: 0, ...o }] });

describe('accReceiptShapeError', () => {
  it('accepts signed receipts (ed25519 and PQ) and a reordered ledger', () => {
    expect(accReceiptShapeError(RC)).toBeNull();
    expect(rshape({ ledger: { head: H32, index: 3 } })).toBeNull();
    expect(rshape({ seq: 1, pre: 0, delta: 0, post: 0, expires_at: RC.issued_at + 900_000 })).toBeNull();
    expect(accReceiptShapeError(signAccReceipt(body(), seqKey.sk, { alg: 'ml-dsa-65', mlDsa: ML }))).toBeNull();
    expect(rshape({ alg: 'ed25519' })).toBeNull();
  });
  it('refuses each malformed member with the exact text', () => {
    for (const x of [null, [], 'r', Object.create(RC)]) expect(accReceiptShapeError(x)).toBe('receipt is not an object');
    expect(rshape({ x: 1 })).toBe("receipt: unknown member 'x'");
    expect(rshape({ v: 2 })).toBe('not a pca-acc-receipt v1');
    expect(rshape({ kind: 'pca-acc' })).toBe('not a pca-acc-receipt v1');
    expect(rshape({ session: 'abc' })).toBe('receipt.session is not canonical base64url (32 bytes)');
    for (const acc of [['trip'], 'a-b', '', 5]) expect(rshape({ acc })).toBe('receipt.acc is not an accumulator id');
    for (const seq of [0, 1.5, '1', -1]) expect(rshape({ seq })).toBe('receipt.seq must be a safe integer >= 1');
    for (const k of ['pre', 'delta', 'post']) for (const v of [-1, 1.5, '1']) expect(rshape({ [k]: v })).toBe('receipt pre / delta / post must be non-negative safe integers');
    expect(rshape({ pcactn_digest: 'abc' })).toBe('receipt.pcactn_digest is not canonical base64url (32 bytes)');
    for (const aud of ['', 5, null]) expect(rshape({ aud })).toBe('receipt.aud must be a non-empty string');
    expect(rshape({ issued_at: -1 })).toBe('receipt.issued_at / expires_at must be non-negative safe integers');
    expect(rshape({ expires_at: 1.5 })).toBe('receipt.issued_at / expires_at must be non-negative safe integers');
    const life = 'receipt.expires_at must be within 900000 ms after issued_at';
    expect(rshape({ expires_at: RC.issued_at })).toBeNull();
    expect(rshape({ expires_at: RC.issued_at - 1 })).toBe(life);
    expect(rshape({ expires_at: RC.issued_at + 900_001 })).toBe(life);
    for (const kid of [['s1'], 'a b', '', 'k'.repeat(65)]) expect(rshape({ kid })).toBe('receipt.kid must match [A-Za-z0-9_.:-]{1,64}');
    for (const ledger of [null, [], { index: 0 }, { head: H32 }, { index: 0, head: H32, x: 1 }, { index: -1, head: H32 }, { index: 0.5, head: H32 }, { index: 0, head: 'abc' }]) expect(rshape({ ledger })).toBe('receipt.ledger must be {index, head}');
    expect(rshape({ signer: 'abc' })).toBe('receipt.signer is not canonical base64url (32 bytes)');
    expect(rshape({ alg: 'x-suite' })).toBe("receipt.alg: unsupported_suite: 'x-suite'");
    expect(rshape({ alg: 5 })).toBe('receipt.alg: alg must be a string');
    const edPq = 'an ed25519 receipt must not carry pq_pk / pq_sig';
    expect(rshape({ pq_pk: MLPK })).toBe(edPq);
    expect(rshape({ pq_sig: 'x' })).toBe(edPq);
    expect(rshape({ alg: 'ed25519', pq_sig: 'x' })).toBe(edPq);
    for (const sig of [5, undefined, null]) expect(rshape({ sig })).toBe('receipt.sig must be a string');
  });
  it('signAccReceipt refuses to sign a malformed body', () => {
    expect(signAccReceipt(body({ seq: 0 }), seqKey.sk)).toEqual(thrown('signAccReceipt: receipt.seq must be a safe integer >= 1'));
  });
});

describe('verifyAccReceiptSignature', () => {
  it('verifies under the expected signer only, and never throws', () => {
    expect(verifyAccReceiptSignature(RC, seqKey.pub)).toBe(true);
    expect(verifyAccReceiptSignature(RC, stranger.pub)).toBe(false);
    expect(verifyAccReceiptSignature({ ...RC, x: 1 } as never, seqKey.pub)).toBe(false); // extra member: not covered by the signature, refused by shape
    expect(verifyAccReceiptSignature({ ...RC, post: 6 }, seqKey.pub)).toBe(false);
    expect(verifyAccReceiptSignature(null as never, seqKey.pub)).toBe(false);
    const pq = signAccReceipt(body(), seqKey.sk, { alg: 'ml-dsa-65', mlDsa: ML });
    expect(verifyAccReceiptSignature(pq, seqKey.pub, { pqPins: { [seqKey.pub]: MLPK } })).toBe(true);
    expect(verifyAccReceiptSignature(pq, seqKey.pub)).toBe(false);
    const throwing = {
      get pqPins(): never {
        throw new Error('boom');
      },
    };
    expect(verifyAccReceiptSignature(pq, seqKey.pub, throwing as never)).toBe(false);
  });
});

describe('domains and content addresses', () => {
  const msgOf = (domain: string, b: unknown) => {
    const d = utf8(domain);
    const c = canonicalBytesStrict(b);
    const m = new Uint8Array(d.length + c.length);
    m.set(d);
    m.set(c, d.length);
    return m;
  };
  it('the domain constants', () => {
    expect([ACC_RECEIPT_DOMAIN, ACC_RECEIPT_REF_DOMAIN, ACC_RESERVE_DOMAIN, SEQUENCER_KEYS_DOMAIN, SEQUENCER_KEYS_REF_DOMAIN]).toEqual(['atlas-pca/acc-receipt/v1\0', 'atlas-pca/acc-receipt-ref/v1', 'atlas-pca/acc-reserve/v1', 'atlas-pca/sequencer-keys/v1\0', 'atlas-pca/sequencer-keys-ref/v1']);
  });
  it('a receipt and a key set sign the domain-prefixed canonical body (checked independently)', () => {
    const verifies = (signed: unknown, signer: Uint8Array, domain: string) =>
      settle(() => {
        const { sig, ...b } = signed as { sig: string };
        return verify(publicKeyOf(signer), msgOf(domain, b), decodeB64uStrict(sig)!);
      });
    expect(verifies(RC, seqKey.sk, 'atlas-pca/acc-receipt/v1\0')).toEqual({ ok: true, value: true });
    expect(verifies(KS, seqRoot.sk, 'atlas-pca/sequencer-keys/v1\0')).toEqual({ ok: true, value: true });
  });
  it('content addresses', () => {
    expect(accReceiptDigest(RC)).toBe(hashCanonical({ d: 'atlas-pca/acc-receipt-ref/v1', r: RC }));
    expect(sequencerKeySetDigest(KS)).toBe(hashCanonical({ d: 'atlas-pca/sequencer-keys-ref/v1', k: KS }));
    const p = { v: 1, aud: 'a', sig: 's', pq_sig: 'q', threshold: { t: 1 }, intent_session: { x: 1 }, nonce: 'n' };
    expect(pcactnReservationDigest(p)).toBe(hashCanonical({ d: 'atlas-pca/acc-reserve/v1', b: { v: 1, aud: 'a', nonce: 'n' } }));
  });
});

describe('accReceiptCoreDigest', () => {
  it('is the domain-separated digest of the core fields only', () => {
    const core = { v: RC.v, kind: RC.kind, session: RC.session, acc: RC.acc, seq: RC.seq, pre: RC.pre, delta: RC.delta, post: RC.post, pcactn_digest: RC.pcactn_digest, aud: RC.aud, issued_at: RC.issued_at, expires_at: RC.expires_at };
    expect(accReceiptCoreDigest(RC)).toBe(hashCanonical({ d: 'atlas-pca/acc-receipt-core/v1', r: core }));
    expect(accReceiptCoreDigest({ ...RC, kid: 'other', ledger: { index: 9, head: S32 } } as never)).toBe(accReceiptCoreDigest(RC));
    expect(accReceiptCoreDigest({ ...RC, post: 6 })).not.toBe(accReceiptCoreDigest(RC));
  });
});

describe('sequencerKeySetShapeError', () => {
  it('accepts signed key sets and the boundary members', () => {
    expect(sequencerKeySetShapeError(KS)).toBeNull();
    expect(kshape({ keys: Array.from({ length: 256 }, (_, i) => ({ kid: `k${i}`, pk: seqKey.pub, not_before: 0 })) })).toBeNull();
    expect(entry({ not_after: 0 })).toBeNull();
    expect(entry({ not_before: 5, not_after: 5 })).toBeNull();
    expect(entry({ alg: 'ml-dsa-65', pq_pk: MLPK })).toBeNull();
    expect(kshape({ version: 1, issued_at: 0 })).toBeNull();
    expect(kshape({ alg: 'ed25519' })).toBeNull();
    expect(sequencerKeySetShapeError(signSequencerKeySet(ksBody(), seqRoot.sk, { alg: 'ml-dsa-65', mlDsa: ML }))).toBeNull();
  });
  it('refuses each malformed member with the exact text', () => {
    for (const x of [null, [], 'k', Object.create(KS)]) expect(sequencerKeySetShapeError(x)).toBe('key set is not an object');
    expect(kshape({ x: 1 })).toBe("key set: unknown member 'x'");
    expect(kshape({ v: 2 })).toBe('not a pca-sequencer-keys v1');
    expect(kshape({ kind: 'keys' })).toBe('not a pca-sequencer-keys v1');
    expect(kshape({ sequencer: 'abc' })).toBe('sequencer is not canonical base64url (32 bytes)');
    for (const version of [0, 1.5, '1', -1]) expect(kshape({ version })).toBe('version must be a safe integer >= 1');
    for (const issued_at of [-1, 1.5]) expect(kshape({ issued_at })).toBe('issued_at must be a non-negative safe integer');
    for (const keys of [[], 'k', { length: 1 }, Array.from({ length: 257 }, (_, i) => ({ kid: `k${i}`, pk: seqKey.pub, not_before: 0 }))]) expect(kshape({ keys })).toBe('keys must be 1..256 entries');
    const shapeMsg = 'keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}';
    expect(kshape({ keys: [null] })).toBe(shapeMsg);
    expect(kshape({ keys: [[]] })).toBe(shapeMsg);
    expect(entry({ x: 1 })).toBe(shapeMsg);
    const kidMsg = 'key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct';
    for (const kid of [['s1'], 'a b', '', 5]) expect(entry({ kid })).toBe(kidMsg);
    expect(kshape({ keys: [{ kid: 'd', pk: seqKey.pub, not_before: 0 }, { kid: 'd', pk: stranger.pub, not_before: 0 }] })).toBe(kidMsg);
    expect(entry({ pk: 'abc' })).toBe('key pk is not canonical base64url (32 bytes)');
    expect(entry({ alg: 'x-suite' })).toBe("key alg: unsupported_suite: 'x-suite'");
    expect(entry({ pq_pk: '!!' })).toBe('key pq_pk is not canonical base64url');
    const val = 'key validity must be 0 <= not_before <= not_after';
    for (const o of [{ not_before: -1 }, { not_before: 1.5 }, { not_before: 5, not_after: 4 }, { not_after: 1.5 }, { not_after: -1 }, { not_after: null }]) expect(entry(o)).toBe(val);
    expect(kshape({ alg: 'x-suite' })).toBe("alg: unsupported_suite: 'x-suite'");
    const edPq = 'an ed25519 key set must not carry pq_pk / pq_sig';
    expect(kshape({ pq_pk: MLPK })).toBe(edPq);
    expect(kshape({ pq_sig: 'x' })).toBe(edPq);
    expect(kshape({ alg: 'ed25519', pq_pk: MLPK })).toBe(edPq);
    for (const sig of [5, undefined]) expect(kshape({ sig })).toBe('sig must be a string');
  });
  it('signSequencerKeySet refuses to sign a malformed body', () => {
    expect(signSequencerKeySet(ksBody({ version: 0 }), seqRoot.sk)).toEqual(thrown('signSequencerKeySet: version must be a safe integer >= 1'));
  });
});

/** A key set signed by `signer` that names `sequencer` (possibly another key) as its root: the `sequencer` binding test. */
const crafted = (sequencer: string, signer = seqRoot): SequencerKeySet => {
  const b = { v: 1, kind: 'pca-sequencer-keys', sequencer, version: 1, issued_at: NOW - 100, keys: [{ kid: 's1', pk: seqKey.pub, not_before: NOW - 10_000 }] };
  const dom = utf8('atlas-pca/sequencer-keys/v1\0');
  const c = canonicalBytesStrict(b);
  const msg = new Uint8Array(dom.length + c.length);
  msg.set(dom);
  msg.set(c, dom.length);
  return { ...b, sig: b64u(sign(signer.sk, msg)) } as SequencerKeySet;
};

describe('verifySequencerKeySet', () => {
  it('verifies under the pinned root only', () => {
    expect(verifySequencerKeySet(KS, seqRoot.pub)).toBe(true);
    expect(verifySequencerKeySet(KS, stranger.pub)).toBe(false);
    expect(verifySequencerKeySet({ ...KS, x: 1 }, seqRoot.pub)).toBe(false);
    expect(verifySequencerKeySet(crafted(seqRoot.pub), seqRoot.pub)).toBe(true); // the crafting is faithful
    expect(verifySequencerKeySet(crafted(stranger.pub), seqRoot.pub)).toBe(false); // signed by the root, names another sequencer
  });
  it('a PQ key set needs the root PQ pin', () => {
    const pq = signSequencerKeySet(ksBody(), seqRoot.sk, { alg: 'ml-dsa-65', mlDsa: ML });
    expect(verifySequencerKeySet(pq, seqRoot.pub, MLPK)).toBe(true);
    expect(verifySequencerKeySet(pq, seqRoot.pub)).toBe(false);
    expect(verifySequencerKeySet(pq, seqRoot.pub, ML2PK)).toBe(false);
  });
  it('never throws', () => {
    let reads = 0;
    const p = new Proxy({ ...KS }, {
      get(t, k, r) {
        if (k === 'sig' && ++reads > 1) throw new Error('boom');
        return Reflect.get(t, k, r);
      },
    });
    expect(verifySequencerKeySet(p, seqRoot.pub)).toBe(false);
    expect(reads).toBe(2);
  });
});

describe('trackedKeySetError', () => {
  const D = sequencerKeySetDigest(KS);
  it('accepts {version, digest}', () => {
    expect(trackedKeySetError({ version: 1, digest: D })).toBeNull();
    expect(trackedKeySetError({ digest: D, version: 7 })).toBeNull();
  });
  it('refuses with the exact text', () => {
    for (const t of [null, [], 3, 'x', undefined]) expect(trackedKeySetError(t)).toBe('a tracked key set must be an object {version, digest}');
    expect(trackedKeySetError({ version: 1, digest: D, extra: 1 })).toBe("a tracked key set has the unknown member 'extra'");
    for (const version of [0, -1, 1.5, '1', undefined]) expect(trackedKeySetError({ version, digest: D })).toBe('a tracked key set version must be a safe integer >= 1');
    for (const digest of ['abc', 5, undefined, b64u(new Uint8Array(31))]) expect(trackedKeySetError({ version: 1, digest })).toBe('a tracked key set digest must be canonical base64url (32 bytes)');
  });
});

describe('verifyReceiptAgainstHolder', () => {
  it('baseline verifies', () => {
    expect(vr(RC)).toBe(true);
  });
  it('fails closed on a misconfigured verifier', () => {
    expect(vr(RC, [KS], 1.5)).toBe(false);
    expect(vr(RC, [KS], NOW, { maxReceiptAgeMs: -1 })).toBe(false);
    expect(vr(RC, [KS], NOW, { maxKeySetAgeMs: -1 })).toBe(false);
    expect(vr(RC, [KS], NOW, { maxKeySetAgeMs: 1.5 })).toBe(false);
    expect(vr(RC, [KS], NOW, { tracked: { version: 0, digest: sequencerKeySetDigest(KS) } })).toBe(false);
    expect(vr(RC, [KS], NOW, { minKeySetVersion: -1 })).toBe(false);
    expect(vr(RC, [KS], NOW, { minKeySetVersion: 1.5 })).toBe(false);
    expect(vr(RC, [KS], NOW, { minKeySetVersion: 1, maxReceiptAgeMs: 1_000, maxKeySetAgeMs: 100 })).toBe(true);
    // values that would pass every later comparison: only the configuration guard refuses them
    expect(vr(RC, [KS], NOW + 0.5)).toBe(false);
    expect(vr(RC, [KS], NOW, { maxReceiptAgeMs: Number.POSITIVE_INFINITY })).toBe(false);
    expect(vr(RC, [KS], NOW, { maxReceiptAgeMs: 5_000.5 })).toBe(false);
    expect(vr(RC, [KS], NOW, { maxKeySetAgeMs: Number.POSITIVE_INFINITY })).toBe(false);
    expect(vr(RC, [KS], NOW, { maxKeySetAgeMs: 5_000.5 })).toBe(false);
  });
  it('fails closed on non-array key sets and a malformed receipt (never throws)', () => {
    expect(vr(RC, new Set([KS]))).toBe(false);
    expect(vr(RC, [])).toBe(false);
    expect(vr(null)).toBe(false);
    expect(vr({ ...RC, x: 1 })).toBe(false);
  });
  it('receipt time bounds are inclusive', () => {
    expect(vr(signAccReceipt(body({ issued_at: NOW + 60_000, expires_at: NOW + 61_000 }), seqKey.sk))).toBe(true);
    expect(vr(signAccReceipt(body({ issued_at: NOW + 60_001, expires_at: NOW + 61_000 }), seqKey.sk))).toBe(false);
    expect(vr(RC, [KS], NOW, { maxReceiptAgeMs: 1_000 })).toBe(true);
    expect(vr(RC, [KS], NOW, { maxReceiptAgeMs: 999 })).toBe(false);
  });
  it('key-set time bounds are inclusive', () => {
    const fut = (issued_at: number) => signSequencerKeySet(ksBody({ issued_at }), seqRoot.sk);
    expect(vr(RC, [fut(NOW + 60_000)])).toBe(true);
    expect(vr(RC, [fut(NOW + 60_001)])).toBe(false);
    expect(vr(RC, [KS], NOW, { maxKeySetAgeMs: 100 })).toBe(true);
    expect(vr(RC, [KS], NOW, { maxKeySetAgeMs: 99 })).toBe(false);
  });
  it('version floor and tracked state', () => {
    const KS2 = signSequencerKeySet(ksBody({ version: 2 }), seqRoot.sk);
    expect(vr(RC, [KS], NOW, { minKeySetVersion: 2 })).toBe(false);
    expect(vr(RC, [KS2], NOW, { minKeySetVersion: 2 })).toBe(true);
    expect(vr(RC, [KS, KS2], NOW, { minKeySetVersion: 2 })).toBe(true);
    const D1 = sequencerKeySetDigest(KS);
    expect(vr(RC, [KS], NOW, { tracked: { version: 1, digest: D1 } })).toBe(true);
    expect(vr(RC, [KS], NOW, { tracked: { version: 1, digest: H32 } })).toBe(false);
    expect(vr(RC, [KS], NOW, { tracked: { version: 2, digest: D1 } })).toBe(false);
    expect(vr(RC, [KS2], NOW, { tracked: { version: 1, digest: D1 } })).toBe(true);
  });
  it('the key entry: kid, signer, not_before, not_after, suite', () => {
    const withKeys = (keys: SequencerKeySetBody['keys']) => [signSequencerKeySet(ksBody({ keys }), seqRoot.sk)];
    expect(vr(signAccReceipt(body({ kid: 'zz' }), seqKey.sk))).toBe(false);
    expect(vr(signAccReceipt(body(), stranger.sk))).toBe(false);
    expect(vr(RC, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: NOW - 1_000 }]))).toBe(true);
    expect(vr(RC, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: NOW - 999 }]))).toBe(false);
    // not_after: the receipt must be issued by then, and the key must not have retired more than the skew ago
    const ret = (not_after: number) => withKeys([{ kid: 's1', pk: seqKey.pub, not_before: NOW - 100_000, not_after }]);
    const at = (issued_at: number) => signAccReceipt(body({ issued_at, expires_at: issued_at + 60_000 }), seqKey.sk);
    expect(vr(at(NOW - 60_000), ret(NOW - 60_000))).toBe(true);
    expect(vr(at(NOW - 60_000), ret(NOW - 60_001))).toBe(false);
    expect(vr(at(NOW - 59_999), ret(NOW - 60_000))).toBe(false);
    expect(vr(at(NOW - 70_000), ret(NOW - 60_001))).toBe(false);
    expect(vr(RC, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: 0, alg: 'ed25519' }]))).toBe(true);
    // the entry's suite must equal the receipt's: an ed25519 receipt under a PQ entry is refused even though it verifies
    expect(vr(RC, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: 0, alg: 'ml-dsa-65', pq_pk: MLPK }]))).toBe(false);
    const pq = signAccReceipt(body(), seqKey.sk, { alg: 'ml-dsa-65', mlDsa: ML });
    expect(vr(pq, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: 0, alg: 'ml-dsa-65', pq_pk: MLPK }]))).toBe(true);
    expect(vr(pq, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: 0, alg: 'ml-dsa-65', pq_pk: ML2PK }]))).toBe(false);
    expect(vr(pq, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: 0, alg: 'ml-dsa-65' }]))).toBe(false);
    expect(vr(pq, withKeys([{ kid: 's1', pk: seqKey.pub, not_before: 0 }]))).toBe(false);
  });
  it('a bad signature, or a set not under the root, is refused; a later set can still verify', () => {
    expect(vr({ ...RC, post: 6, delta: 6 })).toBe(false);
    const other = signSequencerKeySet(ksBody(), stranger.sk);
    expect(vr(RC, [other])).toBe(false);
    expect(vr(RC, [other, KS])).toBe(true);
    expect(vr(RC, [{ ...KS, x: 1 }, KS])).toBe(true);
  });
  it('a PQ root needs its pinned PQ key', () => {
    const pqKs = signSequencerKeySet(ksBody(), seqRoot.sk, { alg: 'ml-dsa-65', mlDsa: ML });
    expect(verifyReceiptAgainstHolder(RC, { ...HOLDER, root_alg: 'ml-dsa-65', root_pq_pk: MLPK }, [pqKs], NOW)).toBe(true);
    expect(verifyReceiptAgainstHolder(RC, HOLDER, [pqKs], NOW)).toBe(false);
  });
});
