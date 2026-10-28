/** Mutation kills for @atlasauth/pca-pq-threshold: exact refusal reasons for the group descriptor and the hybrid verdicts. */

import { describe, expect, it } from 'vitest';
import {
  sha256,
  DEFAULT_RISK_POLICY,
  type PlanNode,
  attenuate,
  b64u,
  buildPCActn,
  canonicalBytes,
  encodeKey,
  generateKeyPair,
  mintGrant,
  mlDsa65Keygen,
  thresholdMessage,
} from '@atlasauth/pca';
import { frostTrustedDealerKeygen } from '@atlasauth/pca/ext/frost';
import {
  MAX_GROUP_SIZE, MAX_PQ_SIGNER_ENTRIES, HYBRID_ARTIFACT_VERSION, createHybridThresholdVerifier, foldHybridStepUp, hybridThresholdSign, issueGroupDescriptor,
  signerSetCommitment, verifyGroupDescriptor, verifyHybridStepUp, verifyHybridThreshold,
} from './index';

const NOW = Date.now();
const err = (f: () => unknown): Error => { try { f(); } catch (e) { return e as Error; } throw new Error('no throw'); };
const AUTH = generateKeyPair();
const pq = [mlDsa65Keygen(new Uint8Array(32).fill(1)), mlDsa65Keygen(new Uint8Array(32).fill(2))];
const pqPks = pq.map((k) => k.publicKey);

function loop() {
  const P = generateKeyPair(), A = generateKeyPair();
  const { grant } = mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g', envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } });
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
  const pcactn = buildPCActn({ aud: 'aud', now: NOW, grant, chain: [grant, c1], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0.9, inputs: {} } });
  return { grant, pcactn };
}
const { grant, pcactn } = loop();
const msg = thresholdMessage(pcactn);
const dealt = (t: number, n: number) => {
  const kg = frostTrustedDealerKeygen(t, n);
  return { kg, desc: issueGroupDescriptor({ authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t, participants: kg.participantShares }) };
};
const base = { pqPublicKeys: pqPks, pqT: 1, trustedAuthorities: [AUTH.publicKey] };
const one = [{ keyPair: pq[0]! }];
const pk32 = (i: number) => b64u(new Uint8Array(32).fill(i));
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

describe('signerSetCommitment', () => {
  it('is sha256(domain || canonical sorted rows) and order-insensitive', () => {
    const rows = [{ id: 1, pk: pk32(1) }, { id: 2, pk: pk32(2) }];
    const d = new TextEncoder().encode('atlas-pca-pq-threshold/signer-set/v1\0');
    const body = canonicalBytes(rows);
    const m = new Uint8Array(d.length + body.length); m.set(d); m.set(body, d.length);
    const expected = b64u(sha256(m));
    expect(signerSetCommitment([{ identifier: 2, publicKey: pk32(2) }, { identifier: 1, publicKey: pk32(1) }])).toBe(expected);
    expect(signerSetCommitment([{ identifier: 1, publicKey: new Uint8Array(32).fill(1) }, { identifier: 2, publicKey: pk32(2) }])).toBe(expected);
  });
  it('bounds and messages', () => {
    const lim = `signerSetCommitment: need 1..${MAX_GROUP_SIZE} participants`;
    expect(err(() => signerSetCommitment([])).message).toBe(lim);
    expect(err(() => signerSetCommitment(null as never)).message).toBe(lim);
    const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ identifier: i + 1, publicKey: pk32(1) }));
    expect(err(() => signerSetCommitment(mk(MAX_GROUP_SIZE + 1))).message).toBe(lim);
    expect(() => signerSetCommitment(mk(MAX_GROUP_SIZE))).not.toThrow();
    const ids = 'signerSetCommitment: participant identifiers must be positive safe integers';
    for (const id of [0, -1, 1.5, 2 ** 60, NaN, '1' as never]) expect(err(() => signerSetCommitment([{ identifier: id as number, publicKey: pk32(1) }])).message).toBe(ids);
    expect(() => signerSetCommitment([{ identifier: 1, publicKey: pk32(1) }])).not.toThrow();
    const share = 'signerSetCommitment: verification share is not a canonical b64u(32) value';
    for (const pk of ['nope', new Uint8Array(31), b64u(new Uint8Array(33)), pk32(1) + '=']) expect(err(() => signerSetCommitment([{ identifier: 1, publicKey: pk }])).message).toBe(share);
    expect(err(() => signerSetCommitment([{ identifier: 3, publicKey: pk32(1) }, { identifier: 3, publicKey: pk32(2) }])).message).toBe('signerSetCommitment: duplicate participant identifier');
    expect(err(() => signerSetCommitment([{ identifier: 1, publicKey: pk32(1) }, { identifier: 2, publicKey: pk32(1) }, { identifier: 2, publicKey: pk32(2) }])).message).toBe('signerSetCommitment: duplicate participant identifier');
  });
});

describe('issueGroupDescriptor', () => {
  const { kg } = dealt(2, 3);
  const args = { authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t: 2, participants: kg.participantShares };
  it('refusals carry their own message; t == n is allowed', () => {
    expect(err(() => issueGroupDescriptor({ ...args, t: 4 })).message).toBe('issueGroupDescriptor: need 1 <= t <= n (t=4, n=3)');
    expect(err(() => issueGroupDescriptor({ ...args, t: 0 })).message).toBe('issueGroupDescriptor: need 1 <= t <= n (t=0, n=3)');
    expect(err(() => issueGroupDescriptor({ ...args, t: 1.5 })).message).toBe('issueGroupDescriptor: need 1 <= t <= n (t=1.5, n=3)');
    expect(issueGroupDescriptor({ ...args, t: 3 }).descriptor.t).toBe(3);
    expect(err(() => issueGroupDescriptor({ ...args, groupPublicKey: 'nope' })).message).toBe('issueGroupDescriptor: group public key is not canonical b64u(32)');
    const bad = 'issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key';
    expect(err(() => issueGroupDescriptor({ ...args, authoritySecretKey: new Uint8Array(3) })).message).toBe(bad);
    expect(err(() => issueGroupDescriptor({ ...args, authoritySecretKey: 'x'.repeat(32) as never })).message).toBe(bad);
    expect(err(() => issueGroupDescriptor({ ...args, authoritySecretKey: new Uint8Array(33) })).message).toBe(bad);
  });
  it('descriptor content', () => {
    const d = issueGroupDescriptor(args);
    expect(d.descriptor).toEqual({ v: 1, suite: 'frost-ed25519', groupPublicKey: b64u(kg.groupPublicKey), t: 2, n: 3, signerSetCommitment: signerSetCommitment(kg.participantShares) });
    expect(d.authority).toBe(b64u(AUTH.publicKey));
  });
});

describe('verifyGroupDescriptor: every refusal has its own reason', () => {
  const { kg, desc } = dealt(2, 3);
  const exp = { trustedAuthorities: [AUTH.publicKey], groupKey: kg.groupPublicKey, t: 2 };
  const V = (s: unknown, e: object = {}) => verifyGroupDescriptor(s, { ...exp, ...e } as never);
  const F = (reason: string) => ({ ok: false, reason });
  const mut = (f: (d: any) => void) => { const c = clone(desc) as any; f(c); return c; };
  it('accepts the honest descriptor in both key spellings', () => {
    expect(V(desc)).toEqual({ ok: true, descriptor: desc.descriptor });
    expect(V(desc, { trustedAuthorities: [b64u(AUTH.publicKey)], groupKey: b64u(kg.groupPublicKey) }).ok).toBe(true);
    expect(V(desc, { signerSetCommitment: desc.descriptor.signerSetCommitment }).ok).toBe(true);
  });
  it.each([[null], [undefined], [5], ['x'], [true]])('not an object: %j', (s) => {
    expect(V(s)).toEqual(F('no signed group descriptor: the threshold is unattested'));
  });
  it('malformed envelope', () => {
    for (const s of [{}, { descriptor: null, authority: 'a', sig: 's' }, { descriptor: 'x', authority: 'a', sig: 's' }, mut((d) => { d.authority = 5; }), mut((d) => { d.sig = 5; })]) {
      expect(V(s)).toEqual(F('malformed group descriptor'));
    }
  });
  it('unsupported version or suite, each alone', () => {
    expect(V(mut((d) => { d.descriptor.v = 2; }))).toEqual(F('unsupported group descriptor version or suite'));
    expect(V(mut((d) => { d.descriptor.suite = 'x'; }))).toEqual(F('unsupported group descriptor version or suite'));
  });
  it('key / commitment must be strings', () => {
    expect(V(mut((d) => { d.descriptor.groupPublicKey = 5; }))).toEqual(F('malformed group descriptor'));
    expect(V(mut((d) => { d.descriptor.signerSetCommitment = 5; }))).toEqual(F('malformed group descriptor'));
  });
  it('t / n must satisfy 1 <= t <= n <= MAX', () => {
    const bad = 'malformed group descriptor: need 1 <= t <= n';
    for (const [t, n] of [[0, 3], [-1, 3], [1.5, 3], [2, 1.5], [3, 2], [2, 1025], ['2', 3], [2, '3']] as const) {
      expect(V(mut((d) => { d.descriptor.t = t; d.descriptor.n = n; }))).toEqual(F(bad));
    }
    // n == t and n == MAX_GROUP_SIZE pass the shape check (they then fail later, never with the shape reason)
    expect((V(mut((d) => { d.descriptor.t = 3; d.descriptor.n = 3; })) as { reason: string }).reason).not.toBe(bad);
    expect((V(mut((d) => { d.descriptor.t = 2; d.descriptor.n = MAX_GROUP_SIZE; })) as { reason: string }).reason).not.toBe(bad);
    expect((V(mut((d) => { d.descriptor.t = 1; d.descriptor.n = 1; })) as { reason: string }).reason).not.toBe(bad);
  });
  it('authority must be pinned, canonical and sign the exact descriptor', () => {
    expect(V(desc, { trustedAuthorities: [] })).toEqual(F('group descriptor authority is not trusted'));
    expect(V(desc, { trustedAuthorities: [generateKeyPair().publicKey] })).toEqual(F('group descriptor authority is not trusted'));
    expect(V(mut((d) => { d.authority = 'bad'; }), { trustedAuthorities: ['bad'] })).toEqual(F('malformed authority key or signature'));
    expect(V(mut((d) => { d.sig = 'AAAA'; }))).toEqual(F('malformed authority key or signature'));
    expect(V(mut((d) => { d.authority = b64u(new Uint8Array(33)); }), { trustedAuthorities: [b64u(new Uint8Array(33))] })).toEqual(F('malformed authority key or signature'));
    expect(V(mut((d) => { d.sig = b64u(new Uint8Array(63)); }))).toEqual(F('malformed authority key or signature'));
    expect(V(mut((d) => { d.descriptor.signerSetCommitment = pk32(9); }))).toEqual(F('group descriptor signature does not verify'));
  });
  it('group key, required t and signer set are pinned', () => {
    expect(V(desc, { groupKey: dealt(2, 3).kg.groupPublicKey })).toEqual(F('group descriptor is for a different group key'));
    for (const t of [0, -1, 1.5, NaN]) expect(V(desc, { t })).toEqual(F('required t must be a positive integer'));
    expect(V(desc, { t: 3 })).toEqual(F('group was set up as 2-of-3 but 3 is required: the threshold is not bound to this key'));
    expect(V(desc, { t: 1 })).toEqual(F('group was set up as 2-of-3 but 1 is required: the threshold is not bound to this key'));
    expect(V(desc, { signerSetCommitment: pk32(7) })).toEqual(F('group descriptor is for a different signer set'));
  });
  it('a throwing verifier input fails closed with a fixed message', () => {
    expect(V(desc, { trustedAuthorities: undefined })).toEqual(F('group descriptor could not be verified (malformed)'));
    expect(V(desc, { trustedAuthorities: 5 })).toEqual(F('group descriptor could not be verified (malformed)'));
  });
});

describe('hybridThresholdSign', () => {
  const { kg } = dealt(2, 3);
  const q = kg.participantShares.slice(0, 2);
  it('artifact shape and defaults', () => {
    const a = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: q, t: 2 }, pqSigners: [{ keyPair: pq[0]! }, { keyPair: pq[1]! }] });
    expect(a.v).toBe(HYBRID_ARTIFACT_VERSION);
    expect(a.digest).toBe(b64u(sha256(msg)));
    expect(a.frost).toMatchObject({ alg: 'frost-ed25519', group_pk: b64u(kg.groupPublicKey), t: 2, quorum: 2 });
    expect(a.pq.alg).toBe('ml-dsa-65');
    expect(a.pq.pqT).toBe(2);
    expect(a.pq.signers).toHaveLength(2);
    const b = hybridThresholdSign(pcactn, { frost: { groupPublicKey: b64u(kg.groupPublicKey), quorum: kg.participantShares, t: 2 }, pqSigners: [{ keyPair: pq[0]! }, { keyPair: pq[1]! }], pqT: 1 });
    expect(b.pq.pqT).toBe(1);
    expect(b.frost.quorum).toBe(3);
  });
  it('refusals', () => {
    const f = (o: object) => () => hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: q, t: 2 }, pqSigners: one, ...o } as never);
    expect(err(f({ frost: { groupPublicKey: kg.groupPublicKey, quorum: q, t: 0 } })).message).toBe('hybridThresholdSign: frost.t must be a positive integer (got 0)');
    expect(err(f({ frost: { groupPublicKey: kg.groupPublicKey, quorum: q, t: 1.5 } })).message).toBe('hybridThresholdSign: frost.t must be a positive integer (got 1.5)');
    expect(err(f({ frost: { groupPublicKey: kg.groupPublicKey, quorum: q, t: 3 } })).message).toBe('hybridThresholdSign: FROST quorum of 2 is below the threshold t=3');
    expect(err(f({ pqSigners: [] })).message).toBe('hybridThresholdSign: at least one ML-DSA co-signer is required');
    expect(err(f({ frost: { groupPublicKey: new Uint8Array(31), quorum: q, t: 2 } })).message).toBe('hybridThresholdSign: FROST group public key must be 32 bytes');
    expect(err(f({ frost: { groupPublicKey: 'nope', quorum: q, t: 2 } })).message).toBe('hybridThresholdSign: FROST group public key is not canonical b64u(32)');
    expect(err(f({ frost: { groupPublicKey: b64u(new Uint8Array(33)), quorum: q, t: 2 } })).message).toBe('hybridThresholdSign: FROST group public key is not canonical b64u(32)');
    expect(() => f({})()).not.toThrow();
  });
  it('the declared t is the cryptographic threshold: a quorum above t is accepted, below is refused by frostCosign', () => {
    expect(() => hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares, t: 2 }, pqSigners: one })).not.toThrow();
    expect(() => hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 1), t: 1 }, pqSigners: one })).toThrow();
  });
});

describe('verifyHybridThreshold: precise verdicts', () => {
  const { kg, desc } = dealt(2, 3);
  const art = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 2), t: 2 }, pqSigners: [{ keyPair: pq[0]! }, { keyPair: pq[1]! }], pqT: 2 });
  const o = { ...base, groupKey: kg.groupPublicKey, t: 2, pqT: 2, groupDescriptor: desc };
  const V = (a: unknown, e: object = {}, act: unknown = pcactn) => verifyHybridThreshold(act as never, a as never, { ...o, ...e } as never);
  const art2 = (f: (a: any) => void) => { const c = clone(art) as any; f(c); return c; };
  it('accepts, with an exact verdict', () => {
    expect(V(art)).toStrictEqual({ ok: true, frost: true, pq: { ok: true, count: 2, need: 2 } });
  });
  it('frost-side reasons, in precedence order', () => {
    for (const t of [0, -1, 1.5, NaN]) expect(V(art, { t })).toMatchObject({ ok: false, frost: false, reason: 't must be a positive integer' });
    expect(V(art, { groupKey: 'nope' })).toMatchObject({ ok: false, frost: false, reason: 'trusted FROST group key is not a canonical b64u(32) point' });
    for (const bad of [undefined, null, 5, art2((a) => { a.frost = null; }), art2((a) => { a.frost = 5; }), art2((a) => { a.frost.alg = 'x'; })]) {
      expect(V(bad)).toMatchObject({ ok: false, frost: false, reason: 'malformed or missing FROST part' });
    }
    expect(V(art, { groupDescriptor: null })).toMatchObject({ ok: false, frost: false, reason: 'no signed group descriptor: the threshold is unattested' });
    // a failing descriptor is reported before the declared-threshold downgrade check
    expect(V(art2((a) => { a.frost.t = 1; }), { groupDescriptor: null }).reason).toBe('no signed group descriptor: the threshold is unattested');
    expect(V(art2((a) => { a.frost.t = 1; }))).toMatchObject({ frost: false, reason: 'FROST declared threshold 1 is below the required t=2 (downgrade)' });
    expect(V(art2((a) => { a.frost.t = 1.5; }))).toMatchObject({ frost: false, reason: 'FROST declared threshold 1.5 is below the required t=2 (downgrade)' });
    expect(V(art2((a) => { a.frost.t = 'x'; }))).toMatchObject({ frost: false, reason: 'FROST declared threshold x is below the required t=2 (downgrade)' });
    expect(V(art2((a) => { a.frost.t = 2; })).frost).toBe(true);
    expect(V(art2((a) => { a.frost.t = 3; })).frost).toBe(true);
    const badSig = 'FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)';
    for (const sig of [b64u(new Uint8Array(64)), 'x', 5, undefined]) expect(V(art2((a) => { a.frost.sig = sig; }))).toMatchObject({ ok: false, frost: false, reason: badSig });
  });
  it('the artifact cannot name its own group key', () => {
    const other = dealt(2, 3);
    const forged = hybridThresholdSign(pcactn, { frost: { groupPublicKey: other.kg.groupPublicKey, quorum: other.kg.participantShares.slice(0, 2), t: 2 }, pqSigners: one });
    expect(V(forged)).toMatchObject({ frost: false });
  });
  it('pq-side reasons and counting', () => {
    for (const pqT of [0, -1, 1.5, NaN]) {
      const v = V(art, { pqT });
      expect(v.pq).toEqual({ ok: false, count: 0, need: pqT, reason: 'pqT must be a positive integer' });
      expect(v.reason).toBe('pqT must be a positive integer');
    }
    for (const bad of [undefined, null, 5, 'x']) {
      expect(V(art2((a) => { a.pq = bad; })).pq).toEqual({ ok: false, count: 0, need: 2, reason: 'malformed pq block' });
    }
    expect(V(art2((a) => { a.pq.alg = 'x'; })).pq.reason).toBe('malformed pq block');
    expect(V(art2((a) => { a.pq.signers = 'x'; })).pq.reason).toBe('malformed pq block');
    expect(V(art2((a) => { delete a.pq.signers; })).pq.reason).toBe('malformed pq block');
    const short = (c: number, n: number) => `post-quantum quorum short: ${c} of ${n} required ML-DSA co-signatures`;
    const one1 = art2((a) => { a.pq.signers = [a.pq.signers[0]]; });
    expect(V(one1).pq).toEqual({ ok: false, count: 1, need: 2, reason: short(1, 2) });
    expect(V(one1)).toMatchObject({ ok: false, frost: true, reason: short(1, 2) });
    expect(V(one1, { pqT: 1 })).toEqual({ ok: true, frost: true, pq: { ok: true, count: 1, need: 1 } });
    // entries that are not objects / lack strings are skipped, not fatal
    const junk = art2((a) => { a.pq.signers = [null, 5, 'x', {}, { pk: 5, sig: 'x' }, { pk: 'x', sig: 5 }, ...a.pq.signers]; });
    expect(V(junk).pq).toEqual({ ok: true, count: 2, need: 2 });
    // a trusted key carrying a non-string signature is skipped, not fatal
    const badSig = art2((a) => { a.pq.signers = [{ pk: a.pq.signers[0].pk, sig: 5 }, { pk: a.pq.signers[0].pk, sig: undefined }, ...a.pq.signers]; });
    expect(V(badSig).pq).toEqual({ ok: true, count: 2, need: 2 });
    // a duplicated key counts once
    const dup = art2((a) => { a.pq.signers = [a.pq.signers[0], a.pq.signers[0]]; });
    expect(V(dup).pq).toEqual({ ok: false, count: 1, need: 2, reason: short(1, 2) });
    // a key outside the trusted pool does not count; a malformed pool entry is ignored
    expect(V(art, { pqPublicKeys: [pqPks[0], 'garbage', 5] }).pq).toEqual({ ok: false, count: 1, need: 2, reason: short(1, 2) });
    expect(V(art, { pqPublicKeys: [b64u(pqPks[0]!), b64u(pqPks[1]!)] }).pq.ok).toBe(true);
    // a signature over another action does not count
    const other = loop().pcactn;
    expect(V(art, {}, other).pq.count).toBe(0);
    // entry cap
    const filler = Array.from({ length: MAX_PQ_SIGNER_ENTRIES }, () => ({ pk: 'x', sig: 'x' }));
    const late = art2((a) => { a.pq.signers = [...filler, ...a.pq.signers]; });
    expect(V(late).pq.count).toBe(0);
    const edge = art2((a) => { a.pq.signers = [...filler.slice(1), ...a.pq.signers]; });
    expect(V(edge).pq.count).toBe(1);
  });
  it('pq failure is reported when frost passes; frost failure wins when both fail', () => {
    const both = art2((a) => { a.frost.sig = b64u(new Uint8Array(64)); a.pq.signers = []; });
    expect(V(both)).toMatchObject({ ok: false, frost: false, reason: 'FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)' });
    expect(V(both).pq.ok).toBe(false);
  });
  it('malformed action or options fail closed with the fixed verdict', () => {
    const reason = 'malformed action or verifier options';
    expect(V(art, {}, null)).toEqual({ ok: false, frost: false, pq: { ok: false, count: 0, need: 0, reason }, reason });
    expect(V(art, { pqPublicKeys: null })).toEqual({ ok: false, frost: false, pq: { ok: false, count: 0, need: 0, reason }, reason });
  });
  it('signer-set pin is forwarded', () => {
    expect(V(art, { signerSetCommitment: desc.descriptor.signerSetCommitment }).ok).toBe(true);
    expect(V(art, { signerSetCommitment: pk32(3) }).reason).toBe('group descriptor is for a different signer set');
  });
});

describe('step-up folding and the PCActn hook', () => {
  const { kg, desc } = dealt(2, 3);
  const art = hybridThresholdSign(pcactn, { frost: { groupPublicKey: kg.groupPublicKey, quorum: kg.participantShares.slice(0, 2), t: 2 }, pqSigners: one, pqT: 1 });
  const hookOpts = { groupKey: kg.groupPublicKey, pqPublicKeys: pqPks, t: 2, pqT: 1, pqBlock: art.pq, groupDescriptor: desc, trustedAuthorities: [AUTH.publicKey] };
  it('fold adds exactly one guardian share carrying the group key and keeps existing shares', () => {
    const stepUp = foldHybridStepUp(pcactn, art);
    expect(stepUp.pq).toBe(art.pq);
    expect(stepUp.pcactn.threshold?.shares).toEqual([{ role: 'guardian', publicKey: art.frost.group_pk, sig: art.frost.sig }]);
    const prior = { role: 'principal', publicKey: 'p', sig: 's' };
    const withPrior = foldHybridStepUp({ ...pcactn, threshold: { shares: [prior] } } as never, art);
    expect(withPrior.pcactn.threshold?.shares).toHaveLength(2);
    expect(withPrior.pcactn.threshold?.shares[0]).toEqual(prior);
    const odd = foldHybridStepUp({ ...pcactn, threshold: { shares: 'x' } } as never, art);
    expect(odd.pcactn.threshold?.shares).toHaveLength(1);
  });
  it('hook reasons', () => {
    const stepUp = foldHybridStepUp(pcactn, art);
    const ctx = (p: unknown) => ({ pcactn: p, grant, nowEpoch: 1 }) as never;
    const H = (e: object = {}) => createHybridThresholdVerifier({ ...hookOpts, ...e } as never);
    expect(H()(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: true });
    expect(H({ groupDescriptor: null })(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: false, reason: 'no signed group descriptor: the threshold is unattested' });
    expect(H({ groupKey: 'nope' })(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: false, reason: 'group descriptor is for a different group key' });
    expect(H()(ctx(pcactn))).toEqual({ enforced: true, ok: false, reason: 'no FROST aggregate for the trusted group key in the step-up' });
    const mk = (shares: unknown[]) => ({ ...stepUp.pcactn, threshold: { shares } });
    const good = stepUp.pcactn.threshold!.shares[0]!;
    const noise = [null, 5, { publicKey: good.publicKey, sig: 5 }, { publicKey: 'other', sig: good.sig }];
    expect(H()(ctx(mk([...noise, good])))).toEqual({ enforced: true, ok: true });
    expect(H()(ctx(mk(noise)))).toEqual({ enforced: true, ok: false, reason: 'no FROST aggregate for the trusted group key in the step-up' });
    const bad = { ...good, sig: b64u(new Uint8Array(64)) };
    expect(H()(ctx(mk([bad])))).toEqual({ enforced: true, ok: false, reason: 'FROST aggregate does not verify under the trusted group key (quorum short or forged)' });
    expect(H({ pqBlock: { ...art.pq, signers: [] } })(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: false, reason: 'post-quantum quorum short: 0 of 1 required ML-DSA co-signatures' });
    expect(H({ pqBlock: undefined, pqT: 1 })(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: false, reason: 'malformed pq block' });
    expect(H({ signerSetCommitment: pk32(5) })(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: false, reason: 'group descriptor is for a different signer set' });
    expect(H({ signerSetCommitment: desc.descriptor.signerSetCommitment })(ctx(stepUp.pcactn))).toEqual({ enforced: true, ok: true });
  });
  it('verifyHybridStepUp runs the full PCActn verification and forwards every pin', async () => {
    const stepUp = foldHybridStepUp(pcactn, art);
    const v = { grant, groupKey: kg.groupPublicKey, pqPublicKeys: pqPks, t: 2, pqT: 1, groupDescriptor: desc, trustedAuthorities: [AUTH.publicKey], audience: 'aud', nowEpoch: NOW };
    const r = await verifyHybridStepUp(stepUp, v);
    expect(r.allow).toBe(true);
    expect(r.reason).toBeUndefined();
    expect(r.pq).toEqual({ ok: true, count: 1, need: 1 });
    const wrongAud = await verifyHybridStepUp(stepUp, { ...v, audience: 'other' });
    expect(wrongAud.allow).toBe(false);
    expect(wrongAud.reason).toBe(wrongAud.core.reason);
    expect(wrongAud.reason).toBeTruthy();
    const pinned = await verifyHybridStepUp(stepUp, { ...v, signerSetCommitment: pk32(4) });
    expect(pinned.allow).toBe(false);
    expect((await verifyHybridStepUp(stepUp, { ...v, signerSetCommitment: desc.descriptor.signerSetCommitment })).allow).toBe(true);
    const shortPq = await verifyHybridStepUp({ ...stepUp, pq: { ...stepUp.pq, signers: [] } }, v);
    expect(shortPq.allow).toBe(false);
    expect(shortPq.pq.count).toBe(0);
  });
});
