import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import {
  type SigAlg,
  type SuiteSecretKeys,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeSlhDsaPublicKey,
  mlDsa65Keygen,
  mlDsa87Keygen,
  slhDsa128fKeygen,
} from './pq';
import {
  type QuorumSet,
  type QuorumShare,
  type QuorumSignerInput,
  assembleQuorumProof,
  buildQuorumSet,
  buildRotationCert,
  isRotationFork,
  loadQuorumSet,
  quorumActionDigest,
  quorumProofSize,
  signQuorumShare,
  signRotationShare,
  verifyQuorum,
  verifyQuorumApproval,
  verifyRotationChain,
} from './pq-threshold';

let ctr = 1;
const seed = (n: number): Uint8Array => new Uint8Array(n).fill(ctr++ & 0xff);

interface Party {
  input: QuorumSignerInput;
  secrets: SuiteSecretKeys;
}

function party(alg: SigAlg): Party {
  const ed = generateKeyPair();
  switch (alg) {
    case 'ml-dsa-65': {
      const k = mlDsa65Keygen(seed(32));
      return { input: { alg, keys: { mlDsaPub: encodeMlDsaPublicKey(k.publicKey) } }, secrets: { mlDsa: k } };
    }
    case 'ml-dsa-87': {
      const k = mlDsa87Keygen(seed(32));
      return { input: { alg, keys: { mlDsa87Pub: encodeMlDsa87PublicKey(k.publicKey) } }, secrets: { mlDsa87: k } };
    }
    case 'slh-dsa-sha2-128f': {
      const k = slhDsa128fKeygen(seed(48));
      return { input: { alg, keys: { slhDsaPub: encodeSlhDsaPublicKey(k.publicKey) } }, secrets: { slhDsa: k } };
    }
    case 'hybrid-ed25519-ml-dsa-65': {
      const k = mlDsa65Keygen(seed(32));
      return { input: { alg, keys: { edPub: b64u(ed.publicKey), mlDsaPub: encodeMlDsaPublicKey(k.publicKey) } }, secrets: { edSecret: ed.secretKey, mlDsa: k } };
    }
    default:
      throw new Error(`test party: ${alg}`);
  }
}

interface World {
  set: QuorumSet;
  /** secrets by sorted index */
  sec: SuiteSecretKeys[];
}

function world(parties: Party[], t: number, k = 0): World {
  const r = buildQuorumSet(parties.map((p) => p.input), t, k);
  if (!r.ok) throw new Error('set');
  const sec = r.set.signers.map((e) => {
    const p = parties.find((q) => (q.input.keys.mlDsaPub ?? q.input.keys.mlDsa87Pub ?? q.input.keys.slhDsaPub) === e.pq);
    return p!.secrets;
  });
  return { set: r.set, sec };
}

const ACTION = quorumActionDigest(new TextEncoder().encode('transfer 100'));
const shares = (w: World, idx: number[], epoch = 0, action = ACTION): QuorumShare[] => idx.map((i) => signQuorumShare(w.set, i, epoch, action, w.sec[i]!));
const verify = (w: World, idx: number[], over: Partial<Parameters<typeof verifyQuorum>[0]> = {}) =>
  verifyQuorum({ set: w.set, proof: assembleQuorumProof(w.set, shares(w, idx)), epoch: 0, actionDigest: ACTION, ...over });

const mixed = world([party('ml-dsa-65'), party('ml-dsa-87'), party('slh-dsa-sha2-128f'), party('hybrid-ed25519-ml-dsa-65')], 3);

describe('pq-threshold: suite mixes', () => {
  it.each([
    ['ml-dsa-65', 0],
    ['ml-dsa-87', 1],
    ['slh-dsa-sha2-128f', 2],
    ['hybrid-ed25519-ml-dsa-65', 3],
  ] as const)('%s signer counts', (alg, _) => {
    const idx = mixed.set.signers.map((e, i) => (e.alg === alg ? i : -1)).filter((i) => i >= 0);
    expect(idx.length).toBe(1);
    const others = [0, 1, 2, 3].filter((i) => i !== idx[0]).slice(0, 2);
    expect(verify(mixed, [idx[0]!, ...others]).ok).toBe(true);
  });
  it('exactly t passes, more than t passes, t-1 fails', () => {
    expect(verify(mixed, [0, 1, 2])).toMatchObject({ ok: true, count: 3 });
    expect(verify(mixed, [0, 1, 2, 3])).toMatchObject({ ok: true, count: 4 });
    expect(verify(mixed, [0, 1])).toEqual({ ok: false, reason: 'below-threshold' });
    expect(verify(mixed, [])).toEqual({ ok: false, reason: 'below-threshold' });
  });
  it('boolean approval adapter', () => {
    const msg = new TextEncoder().encode('transfer 100');
    const proof = assembleQuorumProof(mixed.set, shares(mixed, [0, 1, 2]));
    expect(verifyQuorumApproval(mixed.set, proof, msg, 0)).toBe(true);
    expect(verifyQuorumApproval(mixed.set, proof, new TextEncoder().encode('transfer 101'), 0)).toBe(false);
    expect(verifyQuorumApproval(mixed.set, proof, msg, 0, { expectedSetId: 'x' })).toBe(false);
  });
});

describe('pq-threshold: set commitment and distinctness', () => {
  it('set id binds keys, suites, t, diversity; order-independent', () => {
    const a = party('ml-dsa-65');
    const b = party('ml-dsa-65');
    const s1 = buildQuorumSet([a.input, b.input], 2);
    const s2 = buildQuorumSet([b.input, a.input], 2);
    const s3 = buildQuorumSet([a.input, b.input], 1);
    if (!s1.ok || !s2.ok || !s3.ok) throw new Error('x');
    expect(s1.set.id).toBe(s2.set.id);
    expect(s1.set.id).not.toBe(s3.set.id);
  });
  it('rejects two entries sharing a key, shared ed key, bad t/k, non-PQ suite', () => {
    const a = party('ml-dsa-65');
    expect(buildQuorumSet([a.input, a.input], 1).ok).toBe(false);
    const h1 = party('hybrid-ed25519-ml-dsa-65');
    const h2 = party('hybrid-ed25519-ml-dsa-65');
    const shareEd: QuorumSignerInput = { alg: h2.input.alg, keys: { ...h2.input.keys, edPub: h1.input.keys.edPub } };
    expect(buildQuorumSet([h1.input, shareEd], 1).ok).toBe(false);
    const b = party('ml-dsa-65');
    expect(buildQuorumSet([a.input, b.input], 0).ok).toBe(false);
    expect(buildQuorumSet([a.input, b.input], 3).ok).toBe(false);
    expect(buildQuorumSet([a.input, b.input], 2, 1).ok).toBe(false); // no hash-based signer exists
    expect(buildQuorumSet([{ alg: 'ed25519', keys: { edPub: a.input.keys.mlDsaPub } }], 1).ok).toBe(false);
    expect(buildQuorumSet([], 1).ok).toBe(false);
  });
  it('duplicate signature / duplicate index rejected, no double count', () => {
    const s = shares(mixed, [0, 1]);
    const dup = [...s, s[0]!];
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, dup), epoch: 0, actionDigest: ACTION })).toMatchObject({ ok: false, reason: 'duplicate-signer' });
  });
  it('loadQuorumSet rejects forged id, tampered t, reordered signers', () => {
    expect(loadQuorumSet(JSON.parse(JSON.stringify(mixed.set))).ok).toBe(true);
    expect(loadQuorumSet({ ...mixed.set, t: 1 }).ok).toBe(false);
    expect(loadQuorumSet({ ...mixed.set, id: 'AAAA' }).ok).toBe(false);
    expect(loadQuorumSet({ ...mixed.set, signers: [...mixed.set.signers].reverse() }).ok).toBe(false);
  });
});

describe('pq-threshold: binding', () => {
  it('forged signer (signature by a non-member key under a member index) rejected', () => {
    const outsider = party('ml-dsa-65');
    // index 0 may not be an ml-dsa-65 entry; force a matching alg slot
    const i65 = mixed.set.signers.findIndex((e) => e.alg === 'ml-dsa-65');
    const forged = { ...signQuorumShare(mixed.set, i65, 0, ACTION, outsider.secrets) };
    const others = shares(mixed, [0, 1, 2, 3].filter((i) => i !== i65).slice(0, 2));
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, [forged, ...others]), epoch: 0, actionDigest: ACTION })).toMatchObject({ ok: false, reason: 'bad-signature' });
  });
  it('wrong set, wrong epoch, wrong message', () => {
    const other = world([party('ml-dsa-65'), party('ml-dsa-65')], 1);
    const proof = assembleQuorumProof(mixed.set, shares(mixed, [0, 1, 2]));
    expect(verifyQuorum({ set: other.set, proof, epoch: 0, actionDigest: ACTION })).toEqual({ ok: false, reason: 'set-mismatch' });
    expect(verify(mixed, [0, 1, 2], { expectedSetId: other.set.id })).toEqual({ ok: false, reason: 'set-mismatch' });
    expect(verify(mixed, [0, 1, 2], { epoch: 1 })).toMatchObject({ ok: false, reason: 'bad-signature' });
    expect(verify(mixed, [0, 1, 2], { actionDigest: quorumActionDigest(new Uint8Array([1])) })).toMatchObject({ ok: false, reason: 'bad-signature' });
  });
  it('an extra invalid signature rejects the proof; out-of-range / too many signers', () => {
    const s = shares(mixed, [0, 1, 2]);
    s[2] = { ...s[2]!, sig: s[0]!.sig };
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, s), epoch: 0, actionDigest: ACTION }).ok).toBe(false);
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, [{ i: 99, sig: 'x' }]), epoch: 0, actionDigest: ACTION })).toMatchObject({ reason: 'unknown-signer' });
    const five = Array.from({ length: 5 }, () => shares(mixed, [0])[0]!);
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, five), epoch: 0, actionDigest: ACTION })).toMatchObject({ reason: 'too-many-signatures' });
  });
  it('hybrid share missing pq_sig, or pure share carrying one, rejected', () => {
    const iH = mixed.set.signers.findIndex((e) => e.alg === 'hybrid-ed25519-ml-dsa-65');
    const s = shares(mixed, [0, 1, 2, 3]);
    const noPq = s.map((x) => (x.i === iH ? { i: x.i, sig: x.sig } : x));
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, noPq), epoch: 0, actionDigest: ACTION }).ok).toBe(false);
    const withPq = s.map((x) => (x.i !== iH ? { ...x, pq_sig: s.find((y) => y.i === iH)!.pq_sig } : x));
    expect(verifyQuorum({ set: mixed.set, proof: assembleQuorumProof(mixed.set, withPq), epoch: 0, actionDigest: ACTION }).ok).toBe(false);
  });
});

describe('pq-threshold: assumption diversity', () => {
  const w = world([party('ml-dsa-65'), party('ml-dsa-65'), party('slh-dsa-sha2-128f')], 2, 1);
  const lat = w.set.signers.map((e, i) => (e.alg === 'ml-dsa-65' ? i : -1)).filter((i) => i >= 0);
  const hb = w.set.signers.findIndex((e) => e.alg === 'slh-dsa-sha2-128f');
  it('lattice-only quorum fails when k=1 committed', () => {
    expect(verify(w, lat)).toEqual({ ok: false, reason: 'diversity-unmet' });
  });
  it('quorum with a hash-based signer passes', () => {
    expect(verify(w, [lat[0]!, hb])).toMatchObject({ ok: true, hashBased: 1 });
  });
  it('verifier-side requireHashBased tightens a k=0 set', () => {
    const nonHash = mixed.set.signers.map((e, i) => (e.alg === 'slh-dsa-sha2-128f' ? -1 : i)).filter((i) => i >= 0);
    expect(verify(mixed, nonHash).ok).toBe(true);
    expect(verify(mixed, nonHash, { requireHashBased: 1 })).toEqual({ ok: false, reason: 'diversity-unmet' });
  });
  it('k cannot be stripped: it is part of the set id', () => {
    const s0 = buildQuorumSet(w.set.signers.map((e) => ({ alg: e.alg, keys: e.alg === 'slh-dsa-sha2-128f' ? { slhDsaPub: e.pq } : { mlDsaPub: e.pq } })), 2, 0);
    if (!s0.ok) throw new Error('x');
    expect(s0.set.id).not.toBe(w.set.id);
  });
});

describe('pq-threshold: rotation', () => {
  const w0 = world([party('ml-dsa-65'), party('ml-dsa-65'), party('ml-dsa-87')], 2);
  const w1 = world([party('ml-dsa-87'), party('ml-dsa-65')], 2);
  const w2 = world([party('slh-dsa-sha2-128f'), party('ml-dsa-65')], 1);
  const rot = (from: World, to: World, epoch: number, idx = [0, 1]) =>
    buildRotationCert(from.set, epoch, to.set, idx.map((i) => signRotationShare(from.set, i, epoch, to.set, from.sec[i]!)));

  it('valid two-step chain', () => {
    const r = verifyRotationChain(w0.set, 0, [rot(w0, w1, 0), rot(w1, w2, 1)]);
    expect(r).toMatchObject({ ok: true, epoch: 2, length: 2 });
    if (r.ok) expect(r.set.id).toBe(w2.set.id);
  });
  it('empty chain returns genesis', () => {
    expect(verifyRotationChain(w0.set, 5, [])).toMatchObject({ ok: true, epoch: 5 });
  });
  it('below-threshold rotation, wrong signer set, broken link', () => {
    expect(verifyRotationChain(w0.set, 0, [rot(w0, w1, 0, [0])])).toMatchObject({ ok: false, reason: 'below-threshold', at: 0 });
    expect(verifyRotationChain(w0.set, 0, [rot(w1, w2, 0)])).toMatchObject({ ok: false, reason: 'chain-broken' });
    expect(verifyRotationChain(w0.set, 0, [rot(w0, w1, 0), rot(w0, w2, 1)])).toMatchObject({ ok: false, reason: 'chain-broken', at: 1 });
  });
  it('non-monotone / skipped epoch', () => {
    const c = rot(w0, w1, 0);
    expect(verifyRotationChain(w0.set, 0, [{ ...c, to_epoch: 5 }])).toMatchObject({ ok: false, reason: 'non-monotone-epoch' });
    expect(verifyRotationChain(w0.set, 1, [c])).toMatchObject({ ok: false, reason: 'non-monotone-epoch' });
    expect(verifyRotationChain(w0.set, 0, [{ ...c, from_epoch: 3 }])).toMatchObject({ ok: false });
  });
  it('rotation signature cannot be redirected to another successor', () => {
    const c = rot(w0, w1, 0);
    expect(verifyRotationChain(w0.set, 0, [{ ...c, to_set: w2.set }])).toMatchObject({ ok: false, reason: 'bad-signature' });
  });
  it('fork detection and no-op rotation', () => {
    const a = rot(w0, w1, 0);
    const b = rot(w0, w2, 0);
    expect(isRotationFork(a, b)).toBe(true);
    expect(isRotationFork(a, a)).toBe(false);
    expect(verifyRotationChain(w0.set, 0, [rot(w0, w0, 0)])).toMatchObject({ ok: false, reason: 'bad-rotation' });
  });
});

describe('pq-threshold: size accounting', () => {
  it('is linear in t and never claims compactness', () => {
    const r = quorumProofSize(mixed.set, [0, 1, 2]);
    expect(r.compact).toBe(false);
    expect(r.t).toBe(3);
    expect(r.minBytes).toBeLessThanOrEqual(r.maxBytes);
    expect(r.chosenBytes).toBeGreaterThanOrEqual(r.minBytes);
    expect(r.chosenBytes).toBeLessThanOrEqual(r.maxBytes);
    // ml-dsa-65 3309 + ml-dsa-87 4627 + slh 17088 + hybrid (64+3309)
    expect(quorumProofSize(mixed.set).maxBytes).toBe(17088 + 4627 + 3373);
  });
});

describe('pq-threshold: malformed inputs never throw', () => {
  const junk: unknown[] = [undefined, null, 0, 'x', [], {}, { set: 1 }, { set: mixed.set }, { set: mixed.set, proof: null, epoch: 0, actionDigest: ACTION },
    { set: mixed.set, proof: { set_id: mixed.set.id, sigs: [null, 1, {}, { i: 'a' }, { i: 0, sig: 5 }] }, epoch: 0, actionDigest: ACTION },
    { set: mixed.set, proof: { set_id: mixed.set.id, sigs: [] }, epoch: -1, actionDigest: ACTION },
    { set: mixed.set, proof: { set_id: mixed.set.id, sigs: [] }, epoch: 1.5, actionDigest: ACTION },
    { set: mixed.set, proof: { set_id: mixed.set.id, sigs: [] }, epoch: 0, actionDigest: 5 },
    { set: mixed.set, proof: { set_id: mixed.set.id, sigs: 'nope' }, epoch: 0, actionDigest: ACTION },
    { set: { signers: [{ alg: 'bogus' }], t: 1, id: 'x' }, proof: {}, epoch: 0, actionDigest: ACTION }];
  it('verifyQuorum', () => {
    for (const j of junk) {
      const r = verifyQuorum(j as never);
      expect(r.ok).toBe(false);
    }
  });
  it('loadQuorumSet / buildQuorumSet / chain / approval', () => {
    for (const j of junk) {
      expect(loadQuorumSet(j).ok).toBe(false);
      expect(buildQuorumSet(j as never, j as never).ok).toBe(false);
      expect(verifyRotationChain(j, 0, j).ok).toBe(false);
      expect(verifyQuorumApproval(j, j, j as never, j as never)).toBe(false);
      expect(isRotationFork(j, j)).toBe(false);
    }
    expect(verifyRotationChain(mixed.set, 0, [null, 3, {}]).ok).toBe(false);
  });
  it('randomized mutation of a valid proof never throws and never verifies', () => {
    const proof = JSON.parse(JSON.stringify(assembleQuorumProof(mixed.set, shares(mixed, [0, 1, 2])))) as { sigs: Array<Record<string, unknown>> };
    for (let n = 0; n < 60; n++) {
      const p = JSON.parse(JSON.stringify(proof)) as typeof proof;
      const s = p.sigs[n % 3]!;
      const key = n % 2 === 0 ? 'sig' : 'i';
      s[key] = [null, 7, 'AAAA', {}, -1, 1e9, []][n % 7];
      const r = verifyQuorum({ set: mixed.set, proof: p, epoch: 0, actionDigest: ACTION });
      expect(r.ok).toBe(false);
    }
  });
});
