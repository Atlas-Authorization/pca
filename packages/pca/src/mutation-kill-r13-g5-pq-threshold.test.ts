/**
 * 0.4.2 r13 mutation kills (g5): pq-threshold.ts. Exact verdict objects (reason, detail, at) for every refusal,
 * array-with-properties containers (an Array is never a record), 1 / 256 / 257 signer bounds, t / k bounds with
 * non-integers, canonical sort order (hybrid entries order by their Ed25519 key), the message prefix, every catch
 * (a throwing getter), the epoch guard through verifyRotationChain, and isRotationFork's individual conjuncts.
 * Set-construction tests use well-formed key bytes only (construction never verifies a key); signing uses ML-DSA-65.
 */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict, sha384, utf8 } from './hash';
import { generateKeyPair } from './keys';
import { SIG_SUITES, encodeMlDsaPublicKey, mlDsa65Keygen, type SigAlg, type SuiteSecretKeys } from './pq';
import {
  assembleQuorumProof,
  buildQuorumSet,
  buildRotationCert,
  isRotationFork,
  loadQuorumSet,
  quorumActionDigest,
  quorumMessage,
  quorumProofSize,
  rotationActionDigest,
  signQuorumShare,
  signRotationShare,
  verifyQuorum,
  verifyQuorumApproval,
  verifyRotationChain,
  type QuorumSet,
  type QuorumSignerInput,
} from './pq-threshold';

const BAD = { ok: false, reason: 'bad-set' };
const MAL = { ok: false, reason: 'malformed' };
const bytes = (n: number, i: number, salt = 0) => {
  const b = new Uint8Array(n).fill(salt);
  b[0] = i & 0xff;
  b[1] = (i >> 8) & 0xff;
  return b;
};
const pkOf = (alg: SigAlg, i: number, salt = 7) => b64u(bytes(SIG_SUITES[alg].pqPkBytes, i, salt));
const ed = (i: number) => b64u(bytes(32, i, 3));
const ml = (i: number): QuorumSignerInput => ({ alg: 'ml-dsa-65', keys: { mlDsaPub: pkOf('ml-dsa-65', i) } });
const slh = (i: number): QuorumSignerInput => ({ alg: 'slh-dsa-sha2-128f', keys: { slhDsaPub: pkOf('slh-dsa-sha2-128f', i) } });
/** A built set, asserted (an AssertionError, never a bare throw, when construction is refused). */
const okSet = (r: ReturnType<typeof buildQuorumSet>): QuorumSet => {
  expect(r).toMatchObject({ ok: true });
  return (r as { set: QuorumSet }).set;
};
/** Capture a call's outcome: a throw becomes a compared value (an assertion failure), never an uncaught error. */
const settle = (f: () => unknown) => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? { name: e.name, message: e.message } : String(e) };
  }
};
const val = (f: () => unknown) => {
  const r = settle(f);
  return r.ok ? r.value : r;
};

let ctr = 11;
interface Party { input: QuorumSignerInput; secrets: SuiteSecretKeys }
const party = (hybrid = false): Party => {
  const k = mlDsa65Keygen(new Uint8Array(32).fill(ctr++));
  if (!hybrid) return { input: { alg: 'ml-dsa-65', keys: { mlDsaPub: encodeMlDsaPublicKey(k.publicKey) } }, secrets: { mlDsa: k } };
  const e = generateKeyPair();
  return { input: { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: b64u(e.publicKey), mlDsaPub: encodeMlDsaPublicKey(k.publicKey) } }, secrets: { edSecret: e.secretKey, mlDsa: k } };
};
const realWorld = (parties: Party[], t: number) => {
  const set = okSet(buildQuorumSet(parties.map((p) => p.input), t));
  const sec = set.signers.map((e) => {
    const p = parties.find((q) => q.input.keys.mlDsaPub === e.pq);
    expect(p).toBeDefined();
    return p!.secrets;
  });
  return { set, sec };
};
const P = [party(), party(), party(), party(true)];
/** The signing world, built lazily inside a test (so a refused construction is an assertion in that test). */
let memo: { W: ReturnType<typeof realWorld>; H: number; PURE: number[]; ACTION: string } | undefined;
const g = () => {
  if (memo === undefined) {
    const W = realWorld(P, 2);
    const H = W.set.signers.findIndex((e) => e.alg === 'hybrid-ed25519-ml-dsa-65');
    expect(H).toBeGreaterThanOrEqual(0);
    const ACTION = quorumActionDigest(utf8('transfer 100'));
    expect(ACTION).toBe(b64u(sha384(utf8('transfer 100'))));
    memo = { W, H, PURE: [0, 1, 2, 3].filter((i) => i !== H), ACTION };
  }
  return memo;
};
const share = (i: number, epoch = 0, action?: string) => signQuorumShare(g().W.set, i, epoch, action ?? g().ACTION, g().W.sec[i]!);
const proofOf = (idx: number[]) => assembleQuorumProof(g().W.set, idx.map((i) => share(i)));
const vq = (over: Record<string, unknown> = {}) =>
  val(() => verifyQuorum({ set: g().W.set, proof: proofOf([g().PURE[0]!, g().PURE[1]!]), epoch: 0, actionDigest: g().ACTION, ...over } as never));

describe('buildQuorumSet: exact bad-set verdicts and bounds', () => {
  it('signers container and entries', () => {
    expect(buildQuorumSet('x' as never, 1)).toEqual(BAD);
    expect(buildQuorumSet(new Set([ml(1)]) as never, 1)).toEqual(BAD);
    expect(okSet(buildQuorumSet([ml(1)], 1)).signers.length).toBe(1);
    expect(buildQuorumSet([null as never], 1)).toEqual(BAD);
    expect(buildQuorumSet([Object.assign([], ml(1)) as never], 1)).toEqual(BAD);
    expect(buildQuorumSet([{ alg: 'ml-dsa-65', keys: Object.assign([], { mlDsaPub: pkOf('ml-dsa-65', 1) }) } as never], 1)).toEqual(BAD);
    expect(buildQuorumSet([{ alg: 'ml-dsa-65', keys: null } as never], 1)).toEqual(BAD);
    expect(buildQuorumSet([{ alg: 'nope', keys: {} } as never], 1)).toEqual(BAD);
    expect(buildQuorumSet([{ alg: 'ml-dsa-65', keys: { mlDsaPub: 'short' } }], 1)).toEqual(BAD);
  });
  it('a throwing getter is caught as bad-set', () => {
    const s = { alg: 'ml-dsa-65' } as Record<string, unknown>;
    Object.defineProperty(s, 'keys', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(buildQuorumSet([s as never], 1)).toEqual(BAD);
  });
  it('pq key per suite: ml-dsa-87, slh-dsa-256s, fn-dsa-512 / 1024', () => {
    expect(okSet(buildQuorumSet([{ alg: 'ml-dsa-87', keys: { mlDsa87Pub: pkOf('ml-dsa-87', 1) } }], 1)).signers[0]).toEqual({ alg: 'ml-dsa-87', pq: pkOf('ml-dsa-87', 1) });
    expect(okSet(buildQuorumSet([{ alg: 'slh-dsa-sha2-256s', keys: { slhDsa256sPub: pkOf('slh-dsa-sha2-256s', 1) } }], 1)).signers[0]).toEqual({ alg: 'slh-dsa-sha2-256s', pq: pkOf('slh-dsa-sha2-256s', 1) });
    expect(okSet(buildQuorumSet([{ alg: 'fn-dsa-512', keys: { fnDsa512Pub: pkOf('fn-dsa-512', 1) } }], 1)).signers[0]).toEqual({ alg: 'fn-dsa-512', pq: pkOf('fn-dsa-512', 1) });
    expect(okSet(buildQuorumSet([{ alg: 'fn-dsa-1024', keys: { fnDsa1024Pub: pkOf('fn-dsa-1024', 1) } }], 1)).signers[0]).toEqual({ alg: 'fn-dsa-1024', pq: pkOf('fn-dsa-1024', 1) });
  });
  it('a non-PQ suite is refused even with a zero-length PQ component', () => {
    expect(buildQuorumSet([{ alg: 'ed25519', keys: { edPub: ed(1), slhDsa256sPub: '' } } as never], 1)).toEqual(BAD);
    expect(loadQuorumSet({ t: 1, minHashBased: 0, signers: [{ alg: 'ed25519', ed: ed(1), pq: '' }], id: 'x' })).toEqual(BAD);
  });
  it('hybrid needs a 32-byte ed key; a pure suite must carry none', () => {
    expect(okSet(buildQuorumSet([{ alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: ed(1), mlDsaPub: pkOf('ml-dsa-65', 1) } }], 1)).signers[0]).toEqual({ alg: 'hybrid-ed25519-ml-dsa-65', ed: ed(1), pq: pkOf('ml-dsa-65', 1) });
    expect(buildQuorumSet([{ alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: 'short', mlDsaPub: pkOf('ml-dsa-65', 1) } }], 1)).toEqual(BAD);
    expect(buildQuorumSet([{ alg: 'ml-dsa-65', keys: { edPub: ed(1), mlDsaPub: pkOf('ml-dsa-65', 1) } }], 1)).toEqual(BAD);
  });
  it('n in 1..256', () => {
    expect(buildQuorumSet([], 1)).toEqual(BAD);
    const many = (n: number) => Array.from({ length: n }, (_, i) => ml(i));
    expect(okSet(buildQuorumSet(many(256), 1)).signers.length).toBe(256);
    expect(buildQuorumSet(many(257), 1)).toEqual(BAD);
  });
  it('t in 1..n (safe integer); k in 0..t (safe integer) and backed by hash-based signers', () => {
    expect(buildQuorumSet([ml(1), ml(2)], 1.5)).toEqual(BAD);
    expect(buildQuorumSet([ml(1), ml(2)], '1' as never)).toEqual(BAD);
    expect(buildQuorumSet([ml(1), ml(2)], 0)).toEqual(BAD);
    expect(buildQuorumSet([ml(1), ml(2)], 3)).toEqual(BAD);
    expect(okSet(buildQuorumSet([ml(1), ml(2)], 2)).t).toBe(2);
    expect(buildQuorumSet([slh(1)], 1, 0.5)).toEqual(BAD);
    expect(buildQuorumSet([slh(1)], 1, '0' as never)).toEqual(BAD);
    expect(buildQuorumSet([slh(1)], 1, -1)).toEqual(BAD);
    expect(buildQuorumSet([slh(1), slh(2)], 1, 2)).toEqual(BAD);
    expect(okSet(buildQuorumSet([slh(1)], 1, 1)).minHashBased).toBe(1);
    expect(buildQuorumSet([ml(1), slh(2)], 2, 2)).toEqual(BAD);
  });
  it('distinct key components', () => {
    expect(buildQuorumSet([ml(1), ml(1)], 1)).toEqual(BAD);
    const h = (e: number, p: number): QuorumSignerInput => ({ alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: ed(e), mlDsaPub: pkOf('ml-dsa-65', p) } });
    expect(buildQuorumSet([h(1, 1), h(1, 2)], 1)).toEqual(BAD);
  });
  it('the set id is sha384 over the set-domain body', () => {
    const st = okSet(buildQuorumSet([ml(2), ml(1)], 2));
    const body = { d: 'atlas-pca/pq-quorum-set/v1', t: 2, k: 0, s: st.signers.map((e) => ({ a: e.alg, e: e.ed ?? null, p: e.pq })) };
    expect(st.id).toBe(b64u(sha384(canonicalBytesStrict(body))));
  });
  it('canonical order: by suite, then (hybrids) by Ed25519 key, then by PQ key; the id is order-independent', () => {
    const s = okSet(buildQuorumSet([ml(3), ml(1), ml(2)], 1));
    expect(s.signers.map((e) => e.pq)).toEqual([pkOf('ml-dsa-65', 1), pkOf('ml-dsa-65', 2), pkOf('ml-dsa-65', 3)]);
    expect(okSet(buildQuorumSet([ml(2), ml(3), ml(1)], 1)).id).toBe(s.id);
    // ed order (1 < 2) disagrees with pq order (9 > 8)
    const A: QuorumSignerInput = { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: b64u(new Uint8Array(32).fill(1)), mlDsaPub: b64u(new Uint8Array(SIG_SUITES['ml-dsa-65'].pqPkBytes).fill(9)) } };
    const B: QuorumSignerInput = { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: b64u(new Uint8Array(32).fill(2)), mlDsaPub: b64u(new Uint8Array(SIG_SUITES['ml-dsa-65'].pqPkBytes).fill(8)) } };
    for (const order of [[A, B], [B, A]]) expect(okSet(buildQuorumSet(order, 1)).signers.map((e) => e.ed)).toEqual([A.keys.edPub, B.keys.edPub]);
  });
});

describe('loadQuorumSet: exact verdicts', () => {
  const S3 = () => okSet(buildQuorumSet([ml(1), ml(2), ml(3)], 2));
  const wire = (over: Record<string, unknown> = {}) => ({ ...JSON.parse(JSON.stringify(S3())), ...over });
  it('round trip', () => {
    expect(loadQuorumSet(wire())).toEqual({ ok: true, set: S3() });
  });
  it('containers: an Array (even with the members) is not a set; signers must be an array; id a string', () => {
    expect(loadQuorumSet(null)).toEqual(BAD);
    expect(loadQuorumSet(Object.assign([], wire()))).toEqual(BAD);
    expect(loadQuorumSet(wire({ signers: 'x' }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ id: 5 }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ signers: [null] }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ signers: S3().signers.map((e) => Object.assign([], e)) }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ signers: [{ alg: 'ml-dsa-65', pq: 'short' }] }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ signers: [{ alg: 'nope', pq: pkOf('ml-dsa-65', 1) }] }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ t: 9 }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ id: 'x' }))).toEqual(BAD);
  });
  it('wire order must be canonical even when only two entries are swapped', () => {
    const [a, b, c] = S3().signers;
    expect(loadQuorumSet(wire({ signers: [a, c, b] }))).toEqual(BAD);
    expect(loadQuorumSet(wire({ signers: [c, b, a] }))).toEqual(BAD);
  });
  it('a throwing getter is caught as bad-set', () => {
    const x = wire();
    Object.defineProperty(x, 'signers', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(loadQuorumSet(x)).toEqual(BAD);
  });
});

describe('quorumMessage / signQuorumShare / quorumProofSize', () => {
  it('message = domain prefix || sha384(canonical{set_id, epoch, action})', () => {
    const pre = utf8('atlas-pca/pq-quorum-msg/v1\0');
    const want = [...Array.from(pre), ...Array.from(sha384(canonicalBytesStrict({ set_id: 'S', epoch: 3, action: 'A' })))];
    expect(val(() => Array.from(quorumMessage('S', 3, 'A')))).toEqual(want);
    expect(want.length).toBe(pre.length + 48);
    expect(val(() => quorumActionDigest(utf8('x')))).toBe(b64u(sha384(utf8('x'))));
    expect(val(() => rotationActionDigest('S', 1))).toBe(b64u(sha384(canonicalBytesStrict({ kind: 'pq-quorum-rotation', to_set_id: 'S', to_epoch: 1 }))));
  });
  it('signQuorumShare: a RangeError for an unknown index; pq_sig only for hybrids', () => {
    expect(settle(() => share(99))).toEqual({ ok: false, error: { name: 'RangeError', message: 'signQuorumShare: no such signer index' } });
    expect(settle(() => Object.keys(share(g().PURE[0]!)))).toEqual({ ok: true, value: ['i', 'sig'] });
    expect(settle(() => Object.keys(share(g().H)))).toEqual({ ok: true, value: ['i', 'sig', 'pq_sig'] });
  });
  it('chosenBytes counts an unknown index as 0', () => {
    const one = SIG_SUITES['ml-dsa-65'].sigBytes + SIG_SUITES['ml-dsa-65'].pqSigBytes;
    const hyb = SIG_SUITES['hybrid-ed25519-ml-dsa-65'].sigBytes + SIG_SUITES['hybrid-ed25519-ml-dsa-65'].pqSigBytes;
    expect(val(() => quorumProofSize(g().W.set, [g().PURE[0]!, 99]))).toEqual({ minBytes: 2 * one, maxBytes: Math.max(2 * one, one + hyb), t: 2, compact: false, chosenBytes: one });
    expect(val(() => quorumProofSize(g().W.set))).toEqual({ minBytes: 2 * one, maxBytes: Math.max(2 * one, one + hyb), t: 2, compact: false });
  });
});

describe('verifyQuorum: exact verdicts', () => {
  it('success; signers sorted ascending whatever the proof order', () => {
    const [a, b, c] = g().PURE as [number, number, number];
    for (const order of [[c, a, b], [b, c, a], [c, b, a], [a, b, c]]) {
      expect(val(() => verifyQuorum({ set: g().W.set, proof: proofOf(order), epoch: 0, actionDigest: g().ACTION }))).toEqual({ ok: true, signers: [a, b, c].sort((x, y) => x - y), count: 3, hashBased: 0 });
    }
    expect(vq()).toEqual({ ok: true, signers: [g().PURE[0], g().PURE[1]], count: 2, hashBased: 0 });
  });
  it('input container', () => {
    expect(val(() => verifyQuorum(null as never))).toEqual(MAL);
    expect(val(() => verifyQuorum(Object.assign([], { set: g().W.set, proof: proofOf([g().PURE[0]!, g().PURE[1]!]), epoch: 0, actionDigest: g().ACTION }) as never))).toEqual(MAL);
    // an internal throw (a throwing getter) is caught as malformed
    const boom = {} as Record<string, unknown>;
    Object.defineProperty(boom, 'set', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(val(() => verifyQuorum(boom as never))).toEqual(MAL);
  });
  it('set, pin, epoch, digest', () => {
    expect(vq({ set: { ...g().W.set, id: 'x' } })).toEqual(BAD);
    expect(vq({ expectedSetId: 'x' })).toEqual({ ok: false, reason: 'set-mismatch' });
    expect(vq({ epoch: -1 })).toEqual(MAL);
    expect(vq({ epoch: 1.5 })).toEqual(MAL);
    expect(vq({ actionDigest: 5 })).toEqual(MAL);
  });
  it('proof container', () => {
    const p = proofOf([g().PURE[0]!, g().PURE[1]!]);
    expect(vq({ proof: null })).toEqual(MAL);
    expect(vq({ proof: Object.assign([], p) })).toEqual(MAL);
    expect(vq({ proof: { ...p, set_id: 5 } })).toEqual(MAL);
    expect(vq({ proof: { ...p, sigs: 'x' } })).toEqual(MAL);
    expect(vq({ proof: { ...p, set_id: 'other' } })).toEqual({ ok: false, reason: 'set-mismatch' });
  });
  it('shares: container, sig type, index range', () => {
    const s0 = share(g().PURE[0]!);
    const s1 = share(g().PURE[1]!);
    const with0 = (x: unknown) => vq({ proof: { set_id: g().W.set.id, sigs: [x, s1] } });
    expect(with0(null)).toEqual(MAL);
    expect(with0(Object.assign([], s0))).toEqual(MAL);
    expect(with0({ ...s0, sig: 5 })).toEqual(MAL);
    const unk = { ok: false, reason: 'unknown-signer' };
    expect(with0({ ...s0, i: '0' })).toEqual(unk);
    expect(with0({ ...s0, i: 0.5 })).toEqual(unk);
    expect(with0({ ...s0, i: -1 })).toEqual(unk);
    expect(with0({ ...s0, i: 4 })).toEqual(unk);
    expect(with0({ ...s0, i: 5 })).toEqual(unk);
  });
  it('hybrid pq_sig presence must match the suite', () => {
    const h = share(g().H);
    const { pq_sig: _p, ...noPq } = h;
    expect(vq({ proof: { set_id: g().W.set.id, sigs: [share(g().PURE[0]!), noPq] } })).toEqual({ ok: false, reason: 'bad-signature', detail: g().H });
    expect(vq({ proof: { set_id: g().W.set.id, sigs: [share(g().PURE[0]!), h] } })).toEqual({ ok: true, signers: [g().PURE[0], g().H].sort((a, b) => a! - b!), count: 2, hashBased: 0 });
  });
  it('requireHashBased that is not a safe integer is malformed', () => {
    expect(vq({ requireHashBased: Number.NaN })).toEqual(MAL);
    expect(vq({ requireHashBased: 1.5 })).toEqual(MAL);
    expect(vq({ requireHashBased: Number.POSITIVE_INFINITY })).toEqual(MAL);
    expect(vq({ requireHashBased: -3 })).toMatchObject({ ok: true });
    expect(vq({ requireHashBased: 1 })).toEqual({ ok: false, reason: 'diversity-unmet' });
  });
});

describe('verifyQuorumApproval', () => {
  it('only a Uint8Array message; a throwing option getter is false', () => {
    const proof = proofOf([g().PURE[0]!, g().PURE[1]!]);
    expect(val(() => verifyQuorumApproval(g().W.set, proof, utf8('transfer 100'), 0))).toBe(true);
    expect(val(() => verifyQuorumApproval(g().W.set, proof, 'transfer 100' as never, 0))).toBe(false);
    const opts = {} as Record<string, unknown>;
    Object.defineProperty(opts, 'expectedSetId', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(val(() => verifyQuorumApproval(g().W.set, proof, utf8('transfer 100'), 0, opts as never))).toBe(false);
  });
});

describe('verifyRotationChain: exact verdicts', () => {
  const FP = party();
  let rmemo: { F: ReturnType<typeof realWorld>; T: QuorumSet } | undefined;
  const rw = () => (rmemo ??= { F: realWorld([FP], 1), T: okSet(buildQuorumSet([ml(41)], 1)) });
  const cert = () => buildRotationCert(rw().F.set, 0, rw().T, [signRotationShare(rw().F.set, 0, 0, rw().T, rw().F.sec[0]!)]);
  it('one valid step', () => {
    expect(val(() => verifyRotationChain(rw().F.set, 0, [cert()]))).toEqual({ ok: true, set: rw().T, epoch: 1, length: 1 });
    expect(val(() => verifyRotationChain(rw().F.set, 5, []))).toEqual({ ok: true, set: rw().F.set, epoch: 5, length: 0 });
  });
  it('the genesis epoch must be a non-negative safe integer', () => {
    for (const e of [-1, 1.5, '5', Number.NaN, Number.POSITIVE_INFINITY]) expect(val(() => verifyRotationChain(rw().F.set, e as never, []))).toEqual({ ok: false, reason: 'bad-set', at: -1 });
    expect(val(() => verifyRotationChain({ ...rw().F.set, id: 'x' }, 0, []))).toEqual({ ok: false, reason: 'bad-set', at: -1 });
  });
  it('chain container and length', () => {
    expect(val(() => verifyRotationChain(rw().F.set, 0, 'x'))).toEqual({ ok: false, reason: 'malformed', at: -1 });
    expect(val(() => verifyRotationChain(rw().F.set, 0, Array(1025).fill(null)))).toEqual({ ok: false, reason: 'chain-too-long', at: -1 });
    expect(val(() => verifyRotationChain(rw().F.set, 0, Array(1024).fill(null)))).toEqual({ ok: false, reason: 'malformed', at: 0 });
  });
  it('per-cert shape', () => {
    const c = val(cert) as Record<string, unknown>;
    const m0 = { ok: false, reason: 'malformed', at: 0 };
    expect(val(() => verifyRotationChain(rw().F.set, 0, [Object.assign([], c)]))).toEqual(m0);
    expect(val(() => verifyRotationChain(rw().F.set, 0, [{ ...c, from_set_id: 5 }]))).toEqual(m0);
    expect(val(() => verifyRotationChain(rw().F.set, 0, [{ ...c, from_epoch: -1 }]))).toEqual(m0);
    expect(val(() => verifyRotationChain(rw().F.set, 0, [{ ...c, to_epoch: 1.5 }]))).toEqual(m0);
    expect(val(() => verifyRotationChain(rw().F.set, 0, [{ ...c, from_set_id: 'other' }]))).toEqual({ ok: false, reason: 'chain-broken', at: 0 });
    expect(val(() => verifyRotationChain(rw().F.set, 0, [{ ...c, to_set: { ...rw().T, id: 'x' } }]))).toEqual({ ok: false, reason: 'bad-rotation', at: 0 });
    expect(val(() => verifyRotationChain(rw().F.set, 0, [{ ...c, to_set: rw().F.set }]))).toEqual({ ok: false, reason: 'bad-rotation', at: 0 });
  });
  it('a throwing getter is caught as malformed at -1', () => {
    const c = { ...(val(cert) as object) } as Record<string, unknown>;
    Object.defineProperty(c, 'from_set_id', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(val(() => verifyRotationChain(rw().F.set, 0, [c]))).toEqual({ ok: false, reason: 'malformed', at: -1 });
  });
});

describe('isRotationFork', () => {
  const a = { from_set_id: 'S', from_epoch: 0, to_set: { id: 'A' } };
  const b = { from_set_id: 'S', from_epoch: 0, to_set: { id: 'B' } };
  it('each conjunct', () => {
    expect(val(() => isRotationFork(a, b))).toBe(true);
    expect(val(() => isRotationFork(null, b))).toBe(false);
    expect(val(() => isRotationFork(a, null))).toBe(false);
    expect(val(() => isRotationFork(a, a))).toBe(false);
    expect(val(() => isRotationFork(a, { ...b, from_set_id: 'S2' }))).toBe(false);
    expect(val(() => isRotationFork(a, { ...b, from_epoch: 1 }))).toBe(false);
    expect(val(() => isRotationFork({ ...a, to_set: { id: 5 } }, b))).toBe(false);
    expect(val(() => isRotationFork(a, { ...b, to_set: { id: 5 } }))).toBe(false);
    expect(val(() => isRotationFork({ ...a, to_set: null }, b))).toBe(false);
    expect(val(() => isRotationFork({ from_set_id: 'S', from_epoch: 0 }, b))).toBe(false);
    expect(val(() => isRotationFork('x', b))).toBe(false);
    expect(val(() => isRotationFork(a, 7))).toBe(false);
  });
});
