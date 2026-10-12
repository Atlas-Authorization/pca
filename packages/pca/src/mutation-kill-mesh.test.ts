/**
 * Mutation-kill tests for mesh.ts (part 1): caveat algebra, head advance, witness, domain, proof assembly, size and
 * latency models, the A2A federation primitives (budget tree, cross reference) and the worked example. Inputs carry VALID
 * signatures wherever a guard must fire on its own; reason strings that reach callers are asserted exactly.
 */
import { describe, expect, it } from 'vitest';
import { type Capability, mintRoot } from './capability';
import { b64u, canonicalBytes, hashCanonical, utf8 } from './hash';
import { encodeKey, generateKeyPair, publicKeyOf, sign, verifyB64u } from './keys';
import { safetyBound } from './risk';
import {
  allocateSub,
  anchorCrossReference,
  assembleMeshProof,
  buildMeshExample,
  checkHeadAdvance,
  type CosignedHead,
  createFederatedBudget,
  type CrossReference,
  crossReferenceCommit,
  demonstrateForkRejection,
  effectiveAuthority,
  type FederatedBudgetState,
  federatedSafetyBound,
  keyRevocationId,
  type MeshAction,
  MeshDomain,
  type MeshHead,
  MeshWitness,
  meshActionDigest,
  meshProofSize,
  revocationLatencyBound,
  signMeshAction,
  spendFederated,
  translatedEffectiveAuthority,
  verifyCrossReference,
} from './mesh';

const kp = () => generateKeyPair();
const pubOf = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const cat = (a: Uint8Array, b: Uint8Array) => {
  const m = new Uint8Array(a.length + b.length);
  m.set(a);
  m.set(b, a.length);
  return m;
};
const HEAD_DOM = 'atlas-pca/mesh-head/v1\0';
const human = kp();
let capN = 0;
const mkCap = (): Capability =>
  mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(human.secretKey), caveats: [{ type: 'scope', actions: [`a${capN++}`] }] });

// ---------------------------------------------------------------------------------------------
describe('effectiveAuthority', () => {
  it('no caveats: only an empty prefix list', () => {
    expect(effectiveAuthority([])).toEqual({ prefixes: [] });
  });
  it('unknown caveat type fails closed with the exact message', () => {
    expect(effectiveAuthority([{ type: 'mystery' }])).toEqual({ error: 'unknown caveat type "mystery" (fail closed)' });
    expect(effectiveAuthority([{ type: 'toString' }])).toEqual({ error: 'unknown caveat type "toString" (fail closed)' });
  });
  it('scope: first caveat is sorted + de-duplicated, later ones intersect preserving the earlier order', () => {
    expect((effectiveAuthority([{ type: 'scope', actions: ['c', 'a', 'b', 'a'] }]) as { actions: string[] }).actions).toEqual(['a', 'b', 'c']);
    expect((effectiveAuthority([{ type: 'scope', actions: ['a', 'b', 'c'] }, { type: 'scope', actions: ['c', 'b'] }]) as { actions: string[] }).actions).toEqual(['b', 'c']);
    expect((effectiveAuthority([{ type: 'scope', actions: ['a', 'b'] }, { type: 'scope', actions: ['x'] }]) as { actions: string[] }).actions).toEqual([]);
  });
  it('audience: same sort/dedupe/intersect semantics', () => {
    expect((effectiveAuthority([{ type: 'audience', domains: ['z', 'm', 'z'] }]) as { audience: string[] }).audience).toEqual(['m', 'z']);
    expect((effectiveAuthority([{ type: 'audience', domains: ['a', 'b', 'c'] }, { type: 'audience', domains: ['c', 'a'] }]) as { audience: string[] }).audience).toEqual(['a', 'c']);
  });
  it('max_amount / expires / max_hops take the minimum in either order', () => {
    for (const [a, b] of [[10, 5], [5, 10]] as const) {
      expect(effectiveAuthority([{ type: 'max_amount', max: a }, { type: 'max_amount', max: b }])).toEqual({ prefixes: [], maxAmount: 5 });
      expect(effectiveAuthority([{ type: 'expires', at: a }, { type: 'expires', at: b }])).toEqual({ prefixes: [], expiresAt: 5 });
      expect(effectiveAuthority([{ type: 'max_hops', n: a }, { type: 'max_hops', n: b }])).toEqual({ prefixes: [], maxHops: 5 });
    }
    expect(effectiveAuthority([{ type: 'max_hops', n: 3 }])).toEqual({ prefixes: [], maxHops: 3 });
    expect(effectiveAuthority([{ type: 'max_amount', max: 0 }])).toEqual({ prefixes: [], maxAmount: 0 });
  });
  it('resource prefixes accumulate in order', () => {
    expect(effectiveAuthority([{ type: 'resource', prefix: '/a' }, { type: 'resource', prefix: '/a/b' }])).toEqual({ prefixes: ['/a', '/a/b'] });
  });
  it('malformed caveats: exact error per caveat type and per sub-condition', () => {
    expect(effectiveAuthority([{ type: 'scope', actions: 'a' } as never])).toEqual({ error: 'malformed scope caveat' });
    expect(effectiveAuthority([{ type: 'scope', actions: ['a', 1] } as never])).toEqual({ error: 'malformed scope caveat' });
    expect(effectiveAuthority([{ type: 'scope' } as never])).toEqual({ error: 'malformed scope caveat' });
    expect(effectiveAuthority([{ type: 'resource', prefix: 5 } as never])).toEqual({ error: 'malformed resource caveat' });
    for (const bad of ['5', NaN, Infinity, undefined]) {
      expect(effectiveAuthority([{ type: 'max_amount', max: bad } as never])).toEqual({ error: 'malformed max_amount caveat' });
      expect(effectiveAuthority([{ type: 'expires', at: bad } as never])).toEqual({ error: 'malformed expires caveat' });
      expect(effectiveAuthority([{ type: 'max_hops', n: bad } as never])).toEqual({ error: 'malformed max_hops caveat' });
    }
    expect(effectiveAuthority([{ type: 'audience', domains: 'x' } as never])).toEqual({ error: 'malformed audience caveat' });
    expect(effectiveAuthority([{ type: 'audience', domains: ['x', 2] } as never])).toEqual({ error: 'malformed audience caveat' });
    expect(effectiveAuthority([{ type: 'audience' } as never])).toEqual({ error: 'malformed audience caveat' });
  });
  it('a malformed caveat after valid ones still fails the whole conjunction', () => {
    expect(effectiveAuthority([{ type: 'max_amount', max: 1 }, { type: 'expires', at: 'x' } as never])).toEqual({ error: 'malformed expires caveat' });
  });
  it('translatedEffectiveAuthority: wraps the conjunction; malformed shapes give the exact error', () => {
    const tc = (caveats: unknown) => ({ caveats }) as never;
    expect(translatedEffectiveAuthority(tc([{ type: 'max_amount', max: 3 }]))).toEqual({ prefixes: [], maxAmount: 3 });
    expect(translatedEffectiveAuthority(null as never)).toEqual({ error: 'malformed translated capability' });
    expect(translatedEffectiveAuthority([] as never)).toEqual({ error: 'malformed translated capability' });
    expect(translatedEffectiveAuthority(tc('x'))).toEqual({ error: 'malformed translated capability' });
    expect(translatedEffectiveAuthority(tc([null]))).toEqual({ error: 'malformed translated capability' });
    expect(translatedEffectiveAuthority(tc([{ max: 1 }]))).toEqual({ error: 'malformed translated capability' });
    expect(translatedEffectiveAuthority(tc([{ type: 5 }]))).toEqual({ error: 'malformed translated capability' });
    expect(translatedEffectiveAuthority(tc([[]]))).toEqual({ error: 'malformed translated capability' });
  });
});

// ---------------------------------------------------------------------------------------------
describe('keyRevocationId', () => {
  it('is "key:" + the key', () => {
    expect(keyRevocationId('abc')).toBe('key:abc');
  });
});

// ---------------------------------------------------------------------------------------------
describe('checkHeadAdvance', () => {
  const dom = kp();
  const D = new MeshDomain('d', dom.secretKey);
  const W = new MeshWitness(kp().secretKey);
  const H: MeshHead = { domain: 'dom', size: 1, root: 'r1', rev_root: 'rr', rev_size: 0, timestamp: 5 };
  const adv = (n: Partial<MeshHead>, p: Partial<MeshHead> = {}, proof?: unknown) => checkHeadAdvance({ ...H, ...p }, { ...H, ...n }, proof as never);

  it('identical heads advance (nothing to complain about)', () => {
    expect(adv({})).toBeUndefined();
  });
  it('validHead: every field is checked on both prev and next, each alone', () => {
    const bad: Record<string, unknown>[] = [
      { domain: 5 },
      { root: 5 },
      { rev_root: 5 },
      { size: -1 },
      { size: 1.5 },
      { size: '1' },
      { size: NaN },
      { size: 2 ** 53 },
      { rev_size: -1 },
      { rev_size: 0.5 },
      { rev_size: '0' },
      { rev_size: 2 ** 53 },
      { timestamp: NaN },
      { timestamp: Infinity },
      { timestamp: '5' },
      { size: 0 }, // size 0 requires root ''
      { root: '' }, // empty root requires size 0
    ];
    for (const b of bad) {
      expect(adv(b), JSON.stringify(b)).toBe('malformed head');
      expect(adv({}, b), JSON.stringify(b)).toBe('malformed head');
    }
    for (const nonRec of [null, undefined, 5, 'x', [] as unknown[]]) {
      expect(checkHeadAdvance(nonRec as never, H)).toBe('malformed head');
      expect(checkHeadAdvance(H, nonRec as never)).toBe('malformed head');
    }
  });
  it('validHead: zero sizes, a zero rev_size and a negative / zero timestamp are legal', () => {
    const empty = { domain: 'dom', size: 0, root: '', rev_root: 'rr', rev_size: 0, timestamp: 0 };
    expect(checkHeadAdvance(empty, empty)).toBeUndefined();
    expect(checkHeadAdvance(empty, { ...empty, timestamp: -3 })).toBeUndefined();
  });
  it('different domain', () => {
    expect(adv({ domain: 'other' })).toBe('head is for a different domain');
  });
  it('rollback: log size or revocation size shrinking', () => {
    expect(adv({ size: 1 }, { size: 2, root: 'r2' })).toBe('head rolls back');
    expect(adv({ rev_size: 0 }, { rev_size: 1 })).toBe('head rolls back');
    expect(adv({ rev_size: 1, rev_root: 'x' }, { rev_size: 1 })).toBe('equivocation (revocation set)'); // equal rev size is NOT a rollback
  });
  it('equal log size must have the identical root', () => {
    expect(adv({ root: 'other' })).toBe('equivocation (same size, different log)');
  });
  it('equal revocation size must have the identical revocation root; a larger one may differ', () => {
    expect(adv({ rev_root: 'zz' })).toBe('equivocation (revocation set)');
    expect(adv({ rev_root: 'zz', rev_size: 1 })).toBeUndefined();
  });
  it('a larger log needs a consistency proof of exactly (prev.size -> next.size)', () => {
    const a = mkCap();
    const b = mkCap();
    D.record(a);
    const h1 = D.publishHead([W], 10).head;
    D.record(b);
    const h2 = D.publishHead([W], 20).head;
    const good = D.consistencyProof(h1.size, h2.size);
    expect(checkHeadAdvance(h1, h2, good)).toBeUndefined();
    const need = 'consistency proof required for a larger head';
    expect(checkHeadAdvance(h1, h2)).toBe(need);
    expect(checkHeadAdvance(h1, h2, null as never)).toBe(need);
    expect(checkHeadAdvance(h1, h2, [] as never)).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, oldSize: good.oldSize + 1 })).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, newSize: good.newSize + 1 })).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, oldSize: -1 })).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, newSize: 1.5 })).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, path: 'x' as never })).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, path: [1 as never] })).toBe(need);
    expect(checkHeadAdvance(h1, h2, { ...good, path: Array(129).fill('A') })).toBe(need);
    // 128 entries is within the cap: it is judged by the consistency check, not the shape check
    const notConsistent = 'head is not consistent with the previous head (fork or rewrite)';
    expect(checkHeadAdvance(h1, h2, { ...good, path: Array(128).fill('A') })).toBe(notConsistent);
    expect(checkHeadAdvance(h1, h2, { ...good, path: ['A'] })).toBe(notConsistent);
    // the revocation equivocation rule still applies after a good proof
    expect(checkHeadAdvance(h1, { ...h2, rev_root: 'bogus' }, good)).toBe('equivocation (revocation set)');
  });
});

// ---------------------------------------------------------------------------------------------
describe('MeshWitness', () => {
  const signedHead = (secret: Uint8Array, h: MeshHead): CosignedHead => ({ head: h, sig: b64u(sign(secret, cat(utf8(HEAD_DOM), canonicalBytes(h)))), cosigs: [] });
  const emptyRev = (): { rev_root: string; rev_size: number } => {
    const d = new MeshDomain('x', kp().secretKey);
    const h = d.publishHead([], 1).head;
    return { rev_root: h.rev_root, rev_size: h.rev_size };
  };
  const mkHead = (domain: string, over: Partial<MeshHead> = {}): MeshHead => ({ domain, size: 0, root: '', ...emptyRev(), timestamp: 100, ...over });

  it('cosign: malformed requests', () => {
    const w = new MeshWitness(kp().secretKey);
    const dk = kp();
    const d = pubOf(dk.secretKey);
    const ch = signedHead(dk.secretKey, mkHead(d));
    const m = 'witness: malformed head';
    expect(() => w.cosign(undefined as never)).toThrow(m);
    expect(() => w.cosign(null as never)).toThrow(m);
    expect(() => w.cosign({ rev_ids: [] } as never)).toThrow(m);
    expect(() => w.cosign({ head: { head: { ...ch.head, size: -1 }, sig: ch.sig, cosigs: [] }, rev_ids: [] })).toThrow(m);
    expect(() => w.cosign({ head: { head: ch.head, sig: 5 as never, cosigs: [] }, rev_ids: [] })).toThrow(m);
    expect(() => w.cosign({ head: { head: ch.head, sig: undefined as never, cosigs: [] }, rev_ids: [] })).toThrow(m);
    expect(() => w.cosign({ head: ch, rev_ids: [] })).not.toThrow();
  });
  it('cosign: signature, clock and revocation-list checks (exact messages and boundaries)', () => {
    const dk = kp();
    const d = pubOf(dk.secretKey);
    const ch = signedHead(dk.secretKey, mkHead(d));
    const w = new MeshWitness(kp().secretKey);
    expect(() => w.cosign({ head: { ...ch, sig: signedHead(kp().secretKey, ch.head).sig }, rev_ids: [] })).toThrow('witness: head not signed by its domain');
    // clock: default skew 60 s, boundary inclusive
    const clocked = new MeshWitness(kp().secretKey, { clock: () => 100 - 60_000 });
    expect(() => clocked.cosign({ head: ch, rev_ids: [] })).not.toThrow();
    const clocked2 = new MeshWitness(kp().secretKey, { clock: () => 100 - 60_001 });
    expect(() => clocked2.cosign({ head: ch, rev_ids: [] })).toThrow('witness: head timestamp is in the future');
    const custom = new MeshWitness(kp().secretKey, { clock: () => 90, maxClockSkewMs: 10 });
    expect(() => custom.cosign({ head: ch, rev_ids: [] })).not.toThrow();
    const custom2 = new MeshWitness(kp().secretKey, { clock: () => 89, maxClockSkewMs: 10 });
    expect(() => custom2.cosign({ head: ch, rev_ids: [] })).toThrow('witness: head timestamp is in the future');
    const zero = new MeshWitness(kp().secretKey, { clock: () => 99, maxClockSkewMs: 0 });
    expect(() => zero.cosign({ head: ch, rev_ids: [] })).toThrow('witness: head timestamp is in the future');
    // revocation list shape
    const lm = 'witness: malformed revocation list';
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: ch, rev_ids: 'x' as never })).toThrow(lm);
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: ch, rev_ids: undefined as never })).toThrow(lm);
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: ch, rev_ids: [1 as never] })).toThrow(lm);
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: ch, rev_ids: new Array(1_000_001) as never })).toThrow(lm);
    // the list must reproduce BOTH the size and the root of the head
    const dd = new MeshDomain('r', dk.secretKey);
    dd.revoke('id1');
    const hr = dd.publishHead([], 100).head;
    const base = { domain: d, size: 0, root: '', timestamp: 100 };
    const mism = 'witness: revocation list does not match head';
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: signedHead(dk.secretKey, { ...base, rev_root: hr.rev_root, rev_size: 1 }), rev_ids: ['id1'] })).not.toThrow();
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: signedHead(dk.secretKey, { ...base, rev_root: hr.rev_root, rev_size: 1 }), rev_ids: ['id2'] })).toThrow(mism);
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: signedHead(dk.secretKey, { ...base, rev_root: hr.rev_root, rev_size: 2 }), rev_ids: ['id1'] })).toThrow(mism);
    expect(() => new MeshWitness(kp().secretKey).cosign({ head: signedHead(dk.secretKey, { ...base, rev_root: mkHead(d).rev_root, rev_size: 1 }), rev_ids: ['id1'] })).toThrow(mism);
  });
  it('cosign: the cosignature is over the COSIG-domain message; witness id is its public key', () => {
    const sk = kp().secretKey;
    const w = new MeshWitness(sk);
    expect(w.id).toBe(pubOf(sk));
    const dk = kp();
    const ch = signedHead(dk.secretKey, mkHead(pubOf(dk.secretKey)));
    const c = w.cosign({ head: ch, rev_ids: [] });
    expect(c.witness).toBe(w.id);
    expect(verifyB64u(w.id, cat(utf8('atlas-pca/mesh-cosig/v1\0'), canonicalBytes(ch.head)), c.sig)).toBe(true);
    expect(verifyB64u(w.id, cat(utf8(HEAD_DOM), canonicalBytes(ch.head)), c.sig)).toBe(false);
  });
  it('cosign: successor rules - reasons are prefixed, state is only committed on success', () => {
    const dk = kp();
    const d = pubOf(dk.secretKey);
    const w = new MeshWitness(kp().secretKey);
    const dom = new MeshDomain('x', dk.secretKey);
    dom.record(mkCap());
    const h1 = dom.publishHead([w], 100);
    expect(w.lastSeen(d)).toEqual(h1.head);
    // rollback (smaller head) is refused with the checkHeadAdvance reason
    const older = signedHead(dk.secretKey, mkHead(d, { timestamp: 200 }));
    expect(() => w.cosign({ head: older, rev_ids: [] })).toThrow('witness: head rolls back');
    expect(w.lastSeen(d)).toEqual(h1.head);
    // equal head with an EQUAL timestamp is accepted; an earlier one is a timestamp regression
    const same = signedHead(dk.secretKey, h1.head);
    expect(() => w.cosign({ head: same, rev_ids: [] })).not.toThrow();
    const regress = signedHead(dk.secretKey, { ...h1.head, timestamp: 99 });
    expect(() => w.cosign({ head: regress, rev_ids: [] })).toThrow('witness: timestamp regresses');
    expect(w.lastSeen(d)!.timestamp).toBe(100);
  });
  it('cosign: a later list must be a superset of the previously cosigned revocations', () => {
    const dk = kp();
    const w = new MeshWitness(kp().secretKey);
    const d1 = new MeshDomain('x', dk.secretKey);
    d1.revoke('a');
    d1.publishHead([w], 10);
    // a different history with the same key: revokes b and c but NOT a
    const d2 = new MeshDomain('x', dk.secretKey);
    d2.revoke('b');
    d2.revoke('c');
    expect(() => d2.publishHead([w], 20)).toThrow('witness: revocation set drops a previously cosigned revocation');
    const d3 = new MeshDomain('x', dk.secretKey);
    d3.revoke('a');
    d3.revoke('b');
    expect(() => d3.publishHead([w], 20)).not.toThrow();
  });
  it('lastSeen returns a copy, undefined for an unknown domain', () => {
    const dk = kp();
    const w = new MeshWitness(kp().secretKey);
    expect(w.lastSeen('nope')).toBeUndefined();
    const d = new MeshDomain('x', dk.secretKey);
    const h = d.publishHead([w], 5);
    const s = w.lastSeen(d.id)!;
    s.timestamp = 999;
    expect(w.lastSeen(d.id)).toEqual(h.head);
  });
  it('exportState is deterministic (sorted by domain), deep-copied, with the revocation ids', () => {
    const w = new MeshWitness(kp().secretKey);
    const doms = [0, 1, 2, 3].map(() => new MeshDomain('x', kp().secretKey));
    doms[0]!.revoke('q');
    doms[0]!.revoke('p');
    for (const d of [doms[2]!, doms[0]!, doms[3]!, doms[1]!]) d.publishHead([w], 7);
    const st = w.exportState();
    const ids = doms.map((d) => d.id).sort();
    expect(st.seen.map((s) => s.head.domain)).toEqual(ids);
    expect(st.seen.find((s) => s.head.domain === doms[0]!.id)!.rev_ids).toEqual(['p', 'q']);
    st.seen[0]!.head.timestamp = 12345;
    st.seen.find((s) => s.head.domain === doms[0]!.id)!.rev_ids.push('zzz');
    const again = w.exportState();
    expect(again.seen[0]!.head.timestamp).toBe(7);
    expect(again.seen.find((s) => s.head.domain === doms[0]!.id)!.rev_ids).toEqual(['p', 'q']);
    expect(new MeshWitness(kp().secretKey).exportState()).toEqual({ seen: [] });
  });
  it('importState round-trips, replaces (not merges) memory, and validates every record', () => {
    const w = new MeshWitness(kp().secretKey);
    const d1 = new MeshDomain('x', kp().secretKey);
    d1.revoke('a');
    d1.publishHead([w], 5);
    const st = w.exportState();
    const w2 = new MeshWitness(kp().secretKey);
    const other = new MeshDomain('y', kp().secretKey);
    other.publishHead([w2], 3);
    w2.importState(st);
    expect(w2.exportState()).toEqual(st);
    expect(w2.lastSeen(other.id)).toBeUndefined(); // old memory is cleared
    expect(w2.lastSeen(d1.id)).toEqual(w.lastSeen(d1.id));
    const m = 'witness: malformed state';
    const rec = st.seen[0]!;
    expect(() => w2.importState({ seen: [null as never] })).toThrow(m);
    expect(() => w2.importState({ seen: [{ head: { ...rec.head, size: -1 }, rev_ids: rec.rev_ids }] })).toThrow(m);
    expect(() => w2.importState({ seen: [{ head: rec.head, rev_ids: 'a' as never }] })).toThrow(m);
    expect(() => w2.importState({ seen: [{ head: rec.head, rev_ids: [1 as never] }] })).toThrow(m);
    expect(() => w2.importState({ seen: [{ head: rec.head, rev_ids: ['b'] }] })).toThrow(m); // root mismatch, same size
    expect(() => w2.importState({ seen: [{ head: { ...rec.head, rev_size: 2 }, rev_ids: rec.rev_ids }] })).toThrow(m); // size mismatch, same root
    // a failed import leaves the previous memory intact
    expect(w2.lastSeen(d1.id)).toEqual(w.lastSeen(d1.id));
    // empty / absent state clears memory without throwing
    expect(() => w2.importState({} as never)).not.toThrow();
    expect(w2.exportState()).toEqual({ seen: [] });
    w2.importState(st);
    expect(() => w2.importState(undefined as never)).not.toThrow();
    expect(w2.exportState()).toEqual({ seen: [] });
  });
});

// ---------------------------------------------------------------------------------------------
describe('MeshDomain', () => {
  it('enroll: a binding signed over the BINDING-domain message', () => {
    const sk = kp().secretKey;
    const d = new MeshDomain('n', sk);
    expect(d.name).toBe('n');
    expect(d.id).toBe(pubOf(sk));
    const b = d.enroll('agent', 'role');
    expect(b).toMatchObject({ agent: 'agent', domain: d.id, role: 'role' });
    expect(verifyB64u(d.id, cat(utf8('atlas-pca/mesh-binding/v1\0'), canonicalBytes({ agent: 'agent', domain: d.id, role: 'role' })), b.sig)).toBe(true);
  });
  it('record is idempotent and returns the log index', () => {
    const d = new MeshDomain('n', kp().secretKey);
    const a = mkCap();
    const b = mkCap();
    expect(d.record(a)).toBe(0);
    expect(d.record(b)).toBe(1);
    expect(d.record(a)).toBe(0);
    expect(d.record(b)).toBe(1);
    expect(d.publishHead([], 1).head.size).toBe(2);
  });
  it('publishHead: head fields, domain signature over the HEAD-domain message, empty log has root ""', () => {
    const d = new MeshDomain('n', kp().secretKey);
    const e = d.publishHead([], 42);
    expect(e.head).toMatchObject({ domain: d.id, size: 0, root: '', rev_size: 0, timestamp: 42 });
    expect(e.cosigs).toEqual([]);
    expect(verifyB64u(d.id, cat(utf8(HEAD_DOM), canonicalBytes(e.head)), e.sig)).toBe(true);
    d.record(mkCap());
    d.revoke('zz');
    const h = d.publishHead([], 43).head;
    expect(h.size).toBe(1);
    expect(h.root).not.toBe('');
    expect(h.rev_size).toBe(1);
    expect(h.rev_root).not.toBe(e.head.rev_root);
  });
  it('publishHead hands each witness the right consistency proof / revocation list (or none)', () => {
    const d = new MeshDomain('n', kp().secretKey);
    const seen: { req: { consistency?: unknown; rev_ids: string[] } }[] = [];
    let last: MeshHead | undefined;
    const spy = {
      lastSeen: () => last,
      cosign: (req: { head: CosignedHead; consistency?: unknown; rev_ids: string[] }) => {
        seen.push({ req });
        return { witness: 'spy', sig: 's' };
      },
    } as unknown as MeshWitness;
    d.record(mkCap());
    d.revoke('r1');
    d.publishHead([spy], 1);
    expect(seen[0]!.req.consistency).toBeUndefined(); // first sight: none
    expect(seen[0]!.req.rev_ids).toEqual(['r1']);
    last = { domain: d.id, size: 1, root: 'x', rev_root: 'y', rev_size: 1, timestamp: 1 };
    d.publishHead([spy], 2); // same size: no proof
    expect(seen[1]!.req.consistency).toBeUndefined();
    d.record(mkCap());
    d.publishHead([spy], 3); // larger: a real proof from the witness's last size
    expect(seen[2]!.req.consistency).toEqual(d.consistencyProof(1, 2));
    last = { ...last, size: 5 };
    d.publishHead([spy], 4); // smaller than the witness has seen: refused downstream, but no proof is fabricated from a larger size
    expect(seen[3]!.req.consistency).toEqual({ oldSize: 5, newSize: 2, path: [] });
  });
  it('publishHead: every witness must cosign unless a threshold tolerates refusals; failures are reported as the first error', () => {
    const dk = kp();
    const d = new MeshDomain('n', dk.secretKey);
    const good = new MeshWitness(kp().secretKey);
    const strict = new MeshWitness(kp().secretKey);
    // strict has already seen a LARGER history of the same domain key
    const big = new MeshDomain('n', dk.secretKey);
    big.record(mkCap());
    big.record(mkCap());
    big.publishHead([strict], 1);
    expect(() => d.publishHead([good, strict], 2)).toThrow('witness: head rolls back');
    const h = d.publishHead([good, strict], 2, { threshold: 1 });
    expect(h.cosigs.map((c) => c.witness)).toEqual([good.id]);
    expect(() => d.publishHead([good, strict], 2, { threshold: 2 })).toThrow('witness: head rolls back');
    expect(() => d.publishHead([good], 2, { threshold: 2 })).toThrow('publishHead: not enough witnesses');
    expect(() => d.publishHead([good], 2, { threshold: 1 })).not.toThrow();
    expect(() => d.publishHead([], 2, { threshold: 0 })).not.toThrow();
    // two refusals: the FIRST error is reported
    const s2 = new MeshWitness(kp().secretKey);
    const bad = new MeshDomain('n', dk.secretKey);
    bad.record(mkCap());
    bad.record(mkCap());
    bad.record(mkCap());
    bad.publishHead([s2], 1);
    expect(() => d.publishHead([strict, s2], 2)).toThrow('witness: head rolls back');
  });
  it('a failed publish records nothing: evidence for that head is unavailable', () => {
    const dk = kp();
    const d = new MeshDomain('n', dk.secretKey);
    const strict = new MeshWitness(kp().secretKey);
    const big = new MeshDomain('n', dk.secretKey);
    big.record(mkCap());
    big.record(mkCap());
    big.publishHead([strict], 1);
    const c = mkCap();
    d.record(c);
    expect(() => d.publishHead([strict], 2)).toThrow();
    const ok = d.publishHead([], 2);
    expect(() => d.evidence(c, { ...ok, sig: 'other' })).toThrow('evidence: unknown head');
  });
  it('consistencyProof defaults newSize to the current log length; pinProof is bound to a published head', () => {
    const d = new MeshDomain('n', kp().secretKey);
    const w = new MeshWitness(kp().secretKey);
    for (let i = 0; i < 3; i++) d.record(mkCap());
    const h3 = d.publishHead([w], 1);
    d.record(mkCap());
    expect(d.consistencyProof(2)).toEqual(d.consistencyProof(2, 4));
    expect(d.consistencyProof(2)).not.toEqual(d.consistencyProof(2, 3));
    const pin: MeshHead = { ...h3.head, size: 2 };
    const pp = d.pinProof(pin, h3);
    expect(pp.domain).toBe(d.id);
    expect(pp.proof).toEqual(d.consistencyProof(2, 3));
    expect(() => d.pinProof(pin, { ...h3, sig: 'unknown' })).toThrow('pinProof: unknown head');
  });
  it('evidence: snapshot isolation, binding passthrough, exact errors', () => {
    const d = new MeshDomain('n', kp().secretKey);
    const a = mkCap();
    const late = mkCap();
    d.record(a);
    const h = d.publishHead([], 1);
    d.record(late);
    d.revoke(a.id); // after the head: the snapshot still shows a unrevoked
    const ev = d.evidence(a, h);
    expect(ev.domain).toBe(d.id);
    expect(ev.head).toBe(h);
    expect('binding' in ev).toBe(false);
    expect(ev.inclusion.index).toBe(0);
    expect(ev.revocation.cap.size).toBe(0);
    expect(ev.revocation.issuer_key.size).toBe(0);
    const b = d.enroll('x', 'y');
    expect(d.evidence(a, h, b).binding).toBe(b);
    expect(() => d.evidence(late, h)).toThrow('evidence: capability not in this head');
    expect(() => d.evidence(a, { ...h, sig: 'zzz' })).toThrow('evidence: unknown head');
    // revocation of the issuer key as of a later head
    d.revoke(keyRevocationId(late.issuer));
    const h2 = d.publishHead([], 2);
    expect(() => d.evidence(late, h2)).toThrow();
  });
});

// ---------------------------------------------------------------------------------------------
describe('assembleMeshProof / meshProofSize', () => {
  /** A domain with revocations '!' and '~' so every capability id is bracketed by the same two leaves. */
  const bracketed = () => {
    const ws = [new MeshWitness(kp().secretKey), new MeshWitness(kp().secretKey)];
    const d = new MeshDomain('n', kp().secretKey);
    d.revoke('!');
    d.revoke('~');
    const caps: Capability[] = [];
    // a real chain: root (human->k1), c1 (k1->k2)
    const k1 = kp();
    const k2 = kp();
    const root = mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(k1.secretKey), caveats: [{ type: 'scope', actions: ['x'] }] });
    caps.push(root);
    d.record(root);
    return { ws, d, caps, k1, k2, root };
  };

  it('shared head: cosignatures merge by witness, de-duplicated, without aliasing the input', () => {
    const { ws, d, root } = bracketed();
    const h = d.publishHead(ws, 1);
    const e = d.evidence(root, h);
    const only0: CosignedHead = { ...h, cosigs: [h.cosigs[0]!] };
    const only1: CosignedHead = { ...h, cosigs: [h.cosigs[1]!] };
    const action: MeshAction = { type: 'x', resource: '/', service_domain: d.id, nonce: 'n', at: 1 };
    const p = assembleMeshProof({ chain: [root], hops: [{ ...e, head: only0 }, { ...e, head: only1 }, { ...e, head: only0 }, { ...e, head: h }], action, leafSecret: kp().secretKey });
    expect(p.heads).toHaveLength(1);
    expect(p.heads[0]!.cosigs.map((c) => c.witness).sort()).toEqual(ws.map((w) => w.id).sort());
    expect(p.hops.map((x) => x.head)).toEqual([0, 0, 0, 0]);
    expect(only0.cosigs).toHaveLength(1); // the input head object is untouched
    expect(only1.cosigs).toHaveLength(1);
  });
  it('different heads (different signature OR different body) get different table entries', () => {
    const { ws, d, root } = bracketed();
    const h1 = d.publishHead(ws, 1);
    const h2 = d.publishHead(ws, 2);
    const action: MeshAction = { type: 'x', resource: '/', service_domain: d.id, nonce: 'n', at: 1 };
    const p = assembleMeshProof({ chain: [root], hops: [d.evidence(root, h1), d.evidence(root, h2)], action, leafSecret: kp().secretKey });
    expect(p.heads).toHaveLength(2);
    expect(p.hops.map((x) => x.head)).toEqual([0, 1]);
    // same signature string but a different head body must not be merged (key covers both)
    const p2 = assembleMeshProof({ chain: [root], hops: [d.evidence(root, h1), { ...d.evidence(root, h1), head: { ...h1, head: { ...h1.head, timestamp: 99 } } }], action, leafSecret: kp().secretKey });
    expect(p2.heads).toHaveLength(2);
    // the same body under a different signature is also distinct
    const p3 = assembleMeshProof({ chain: [root], hops: [d.evidence(root, h1), { ...d.evidence(root, h1), head: { ...h1, sig: 'other' } }], action, leafSecret: kp().secretKey });
    expect(p3.heads).toHaveLength(2);
  });
  it('bracketing leaves are carried once and referenced by index; empty set has no lo/hi keys', () => {
    const { ws, d, root, k1, k2 } = bracketed();
    const c1 = mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(k2.secretKey), caveats: [{ type: 'scope', actions: ['y'] }] });
    d.record(c1);
    const h = d.publishHead(ws, 1);
    const action: MeshAction = { type: 'x', resource: '/', service_domain: d.id, nonce: 'n', at: 1 };
    const p = assembleMeshProof({ chain: [root], hops: [d.evidence(root, h), d.evidence(c1, h)], action, leafSecret: k1.secretKey });
    expect(p.rev_leaves).toHaveLength(2);
    expect(p.rev_leaves.map((l) => l.id).sort()).toEqual(['!', '~']);
    for (const hop of p.hops) for (const nm of [hop.revocation.cap, hop.revocation.issuer_key]) {
      expect(nm.size).toBe(2);
      expect(p.rev_leaves[nm.lo!]!.id).toBe('!');
      expect(p.rev_leaves[nm.hi!]!.id).toBe('~');
    }
    // size accounting uses the expanded proofs
    const sz = meshProofSize(p);
    expect(sz.uncompacted_bytes).toBeGreaterThan(sz.total_bytes - sz.rev_leaves_bytes - 1000);
    const empty = new MeshDomain('e', kp().secretKey);
    empty.record(root);
    const he = empty.publishHead(ws, 1);
    const pe = assembleMeshProof({ chain: [root], hops: [empty.evidence(root, he)], action, leafSecret: k1.secretKey });
    expect(pe.rev_leaves).toEqual([]);
    expect(Object.keys(pe.hops[0]!.revocation.cap)).toEqual(['size']);
    expect(Object.keys(pe.hops[0]!.revocation.issuer_key)).toEqual(['size']);
  });
  it('a one-sided bracket (id above the maximum / below the minimum) carries only that leaf', () => {
    const ws = [new MeshWitness(kp().secretKey)];
    const d = new MeshDomain('n', kp().secretKey);
    d.revoke('!');
    const k1 = kp();
    const root = mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(k1.secretKey), caveats: [] });
    d.record(root);
    const h = d.publishHead(ws, 1);
    const p = assembleMeshProof({ chain: [root], hops: [d.evidence(root, h)], action: { type: 'x', resource: '/', service_domain: d.id, nonce: 'n', at: 1 }, leafSecret: k1.secretKey });
    expect(Object.keys(p.hops[0]!.revocation.cap).sort()).toEqual(['lo', 'size']);
    const d2 = new MeshDomain('n', kp().secretKey);
    d2.revoke('~');
    d2.record(root);
    const h2 = d2.publishHead(ws, 1);
    const p2 = assembleMeshProof({ chain: [root], hops: [d2.evidence(root, h2)], action: { type: 'x', resource: '/', service_domain: d2.id, nonce: 'n', at: 1 }, leafSecret: k1.secretKey });
    expect(Object.keys(p2.hops[0]!.revocation.cap).sort()).toEqual(['hi', 'size']);
  });
  it('pin_proofs: present only when non-empty; binding only when given; action_sig is the tip holder\'s', () => {
    const { ws, d, root, k1 } = bracketed();
    const h = d.publishHead(ws, 1);
    const action: MeshAction = { type: 'x', resource: '/', service_domain: d.id, nonce: 'n', at: 1 };
    const a = { chain: [root], hops: [d.evidence(root, h)], action, leafSecret: k1.secretKey };
    expect('pin_proofs' in assembleMeshProof(a)).toBe(false);
    expect('pin_proofs' in assembleMeshProof({ ...a, pinProofs: [] })).toBe(false);
    const pp = [{ domain: d.id, proof: { oldSize: 1, newSize: 1, path: [] } }];
    expect(assembleMeshProof({ ...a, pinProofs: pp }).pin_proofs).toEqual(pp);
    const bnd = d.enroll('k', 'r');
    expect('binding' in assembleMeshProof(a).hops[0]!).toBe(false);
    expect(assembleMeshProof({ ...a, hops: [d.evidence(root, h, bnd)] }).hops[0]!.binding).toEqual(bnd);
    const p = assembleMeshProof(a);
    expect(p.action_sig).toBe(signMeshAction([root], action, k1.secretKey));
    expect(p.action).toBe(action);
  });
  it('meshProofSize: every figure is the canonical byte length of the matching part; the v0 layout is larger', () => {
    const ex = buildMeshExample();
    const s = meshProofSize(ex.proof);
    const bl = (x: unknown) => canonicalBytes(x).length;
    expect(s.total_bytes).toBe(bl(ex.proof));
    expect(s.chain_bytes).toBe(bl(ex.proof.chain));
    expect(s.heads_bytes).toBe(bl(ex.proof.heads));
    expect(s.rev_leaves_bytes).toBe(bl(ex.proof.rev_leaves));
    expect(s.hops_bytes).toBe(bl(ex.proof.hops));
    expect(s.uncompacted_bytes).toBe(
      bl(ex.proof.chain) + bl(ex.proof.action) + bl(ex.proof.action_sig) + ex.proof.hops.reduce((n, h) => n + bl({ ...h, head: ex.proof.heads[h.head], revocation: h.revocation }), 0),
    );
    // hop 0 and 1 share a head: expanding it per hop costs more than the table
    expect(s.uncompacted_bytes).toBeGreaterThan(s.chain_bytes + s.hops_bytes);
  });
  it('meshProofSize expands lo/hi indices (including index 0) back into inline leaves', () => {
    const ws = [new MeshWitness(kp().secretKey)];
    const d = new MeshDomain('n', kp().secretKey);
    d.revoke('!');
    d.revoke('~');
    const k1 = kp();
    const root = mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(k1.secretKey), caveats: [] });
    d.record(root);
    const h = d.publishHead(ws, 1);
    const p = assembleMeshProof({ chain: [root], hops: [d.evidence(root, h)], action: { type: 'x', resource: '/', service_domain: d.id, nonce: 'n', at: 1 }, leafSecret: k1.secretKey });
    expect(p.hops[0]!.revocation.cap.lo).toBe(0);
    const bl = (x: unknown) => canonicalBytes(x).length;
    const exp = (c: { size: number; lo?: number; hi?: number }) => ({ size: c.size, ...(c.lo !== undefined ? { lo: p.rev_leaves[c.lo] } : {}), ...(c.hi !== undefined ? { hi: p.rev_leaves[c.hi] } : {}) });
    const hop = p.hops[0]!;
    const want = bl(p.chain) + bl(p.action) + bl(p.action_sig) + bl({ ...hop, head: p.heads[hop.head], revocation: { cap: exp(hop.revocation.cap), issuer_key: exp(hop.revocation.issuer_key) } });
    expect(meshProofSize(p).uncompacted_bytes).toBe(want);
    // an out-of-range index expands to nothing
    const broken = { ...p, hops: [{ ...hop, revocation: { cap: { size: 2, lo: 7, hi: 8 }, issuer_key: { size: 2 } } }] };
    const wantBroken = bl(p.chain) + bl(p.action) + bl(p.action_sig) + bl({ ...broken.hops[0], head: p.heads[hop.head], revocation: { cap: { size: 2 }, issuer_key: { size: 2 } } });
    expect(meshProofSize(broken).uncompacted_bytes).toBe(wantBroken);
  });
});

// ---------------------------------------------------------------------------------------------
describe('revocationLatencyBound', () => {
  const INF = { published_ms: Infinity, unpinned_ms: Infinity, pinned_ms: Infinity, honest_provers_viable: false };
  it('exact figures', () => {
    expect(revocationLatencyBound({ maxHeadAgeMs: 1000, headIntervalMs: 100, maxClockSkewMs: 50, pinRefreshMs: 300 })).toEqual({ published_ms: 100, unpinned_ms: 1050, pinned_ms: 300, honest_provers_viable: true });
    expect(revocationLatencyBound({ maxHeadAgeMs: 1000, headIntervalMs: 100, maxClockSkewMs: 50, pinRefreshMs: 5000 }).pinned_ms).toBe(1050);
    expect(revocationLatencyBound({ maxHeadAgeMs: 1000, headIntervalMs: 100 })).toEqual({ published_ms: 100, unpinned_ms: 1000, pinned_ms: 1000, honest_provers_viable: true });
  });
  it('honest provers are viable only when interval + skew is STRICTLY below the head age', () => {
    expect(revocationLatencyBound({ maxHeadAgeMs: 100, headIntervalMs: 60, maxClockSkewMs: 40 }).honest_provers_viable).toBe(false);
    expect(revocationLatencyBound({ maxHeadAgeMs: 100, headIntervalMs: 60, maxClockSkewMs: 39 }).honest_provers_viable).toBe(true);
    expect(revocationLatencyBound({ maxHeadAgeMs: 100, headIntervalMs: 101 }).honest_provers_viable).toBe(false);
  });
  it('zero is a legal value everywhere', () => {
    expect(revocationLatencyBound({ maxHeadAgeMs: 0, headIntervalMs: 0, maxClockSkewMs: 0, pinRefreshMs: 0 })).toEqual({ published_ms: 0, unpinned_ms: 0, pinned_ms: 0, honest_provers_viable: false });
  });
  it('any non-finite / negative / mistyped input yields the unusable bound', () => {
    const ok = { maxHeadAgeMs: 10, headIntervalMs: 1 };
    for (const bad of [-1, NaN, Infinity, '5']) {
      expect(revocationLatencyBound({ ...ok, maxHeadAgeMs: bad as never })).toEqual(INF);
      expect(revocationLatencyBound({ ...ok, headIntervalMs: bad as never })).toEqual(INF);
      expect(revocationLatencyBound({ ...ok, maxClockSkewMs: bad as never })).toEqual(INF);
      expect(revocationLatencyBound({ ...ok, pinRefreshMs: bad as never })).toEqual(INF);
    }
    expect(revocationLatencyBound(undefined as never)).toEqual(INF);
    expect(revocationLatencyBound(null as never)).toEqual(INF);
    expect(revocationLatencyBound({ headIntervalMs: 1 } as never)).toEqual(INF);
    expect(revocationLatencyBound({ maxHeadAgeMs: 1 } as never)).toEqual(INF);
  });
});

// ---------------------------------------------------------------------------------------------
describe('worked example + fork demonstration', () => {
  it('deterministic names and structure', () => {
    const ex = buildMeshExample();
    expect([ex.domains.A.name, ex.domains.B.name, ex.domains.C.name]).toEqual(['org-A', 'org-B', 'org-C']);
    expect(ex.bindings.orchestrator.role).toBe('orchestrator');
    expect(ex.bindings.tool.role).toBe('tool-agent');
    expect(ex.bindings.service.role).toBe('service-agent');
    expect(ex.trust.threshold).toBe(2);
    expect(ex.witnesses).toHaveLength(3);
    expect(ex.heads.A0.head.size).toBe(1);
    expect(ex.heads.A.head.size).toBe(2);
    expect(ex.proof.action).toEqual({ type: 'payments.refund', resource: '/orders/42/line/1', amount: 25, service_domain: ex.domains.C.id, nonce: 'n-0001', at: ex.trust.now });
    expect(buildMeshExample(5_000_000).trust.now).toBe(5_000_000);
    expect(ex.chain[0]!.caveats).toEqual([
      { type: 'scope', actions: ['payments.refund', 'payments.read', 'orders.read'] },
      { type: 'resource', prefix: '/orders/' },
      { type: 'max_amount', max: 500 },
      { type: 'expires', at: ex.trust.now + 3_600_000 },
      { type: 'audience', domains: [ex.domains.C.id] },
    ]);
    expect(ex.chain[1]!.caveats.slice(5)).toEqual([{ type: 'scope', actions: ['payments.refund', 'payments.read'] }, { type: 'max_amount', max: 100 }]);
    expect(ex.chain[2]!.caveats.slice(7)).toEqual([{ type: 'resource', prefix: '/orders/42' }, { type: 'max_hops', n: 4 }]);
    expect(ex.chain[3]!.caveats.slice(9)).toEqual([{ type: 'scope', actions: ['payments.refund'] }, { type: 'max_amount', max: 50 }]);
    expect(ex.heads.A0.head.timestamp).toBe(ex.trust.now - 2_000);
    expect(ex.heads.A.head.timestamp).toBe(ex.trust.now - 1_000);
    expect(ex.heads.B.head.timestamp).toBe(ex.trust.now - 1_000);
    expect(ex.heads.C.head.timestamp).toBe(ex.trust.now - 1_000);
  });
  it('golden: the whole example is byte-stable (seed labels, names, roles are all part of it)', () => {
    const ex = buildMeshExample();
    expect(hashCanonical({ proof: ex.proof, trust: ex.trust, bindings: ex.bindings })).toBe('ZBVcOYM1ZFaWYYg4LHirQF6IW_SHFSJZZDl2iT0pgvA');
  });
  it('demonstrateForkRejection', () => {
    expect(demonstrateForkRejection()).toEqual({
      honest_extension_cosigned: true,
      fork_larger_than_prior: true,
      size_only_check_would_accept: true,
      fork_rejected: true,
      fork_reason: 'witness: head is not consistent with the previous head (fork or rewrite)',
    });
  });
});

// ---------------------------------------------------------------------------------------------
describe('federated budget', () => {
  const root = () => (createFederatedBudget({ rootId: 'r', rootDomain: 'dr', B0: 10, kappa: 2, bMax: 10 }) as { ok: true; state: FederatedBudgetState }).state;
  const alloc = (s: FederatedBudgetState, id: string, parent: string, a: number, domain = 'd-' + id) => {
    const r = allocateSub(s, { id, domain, parent, alloc: a });
    if (!r.ok) throw new Error(r.reason);
    return r.state;
  };

  it('createFederatedBudget: exact state and exact refusals in check order', () => {
    expect(createFederatedBudget({ rootId: 'r', rootDomain: 'dr', B0: 5, kappa: 2, bMax: 10 })).toEqual({ ok: true, state: { nodes: { r: { domain: 'dr', B: 5 } }, root: 'r', kappa: 2, bMax: 10 } });
    const a = { rootId: 'r', rootDomain: 'dr', B0: 5, kappa: 2, bMax: 10 };
    const no = (over: Record<string, unknown>) => createFederatedBudget({ ...a, ...over } as never);
    expect(createFederatedBudget(null as never)).toEqual({ ok: false, reason: 'malformed root' });
    expect(no({ rootId: 5 })).toEqual({ ok: false, reason: 'malformed root' });
    expect(no({ rootDomain: 5 })).toEqual({ ok: false, reason: 'malformed root' });
    for (const k of [0, -1, NaN, Infinity, '2']) expect(no({ kappa: k })).toEqual({ ok: false, reason: 'kappa must be finite and > 0' });
    for (const b of [-1, NaN, Infinity, '2']) expect(no({ bMax: b })).toEqual({ ok: false, reason: 'bMax must be finite and >= 0' });
    for (const b of [-1, NaN, Infinity, '2']) expect(no({ B0: b })).toEqual({ ok: false, reason: 'B0 must be finite and >= 0' });
    expect(no({ B0: 11 })).toEqual({ ok: false, reason: 'B0 exceeds bMax' });
    expect(no({ kappa: 0, bMax: -1, B0: -1 })).toEqual({ ok: false, reason: 'kappa must be finite and > 0' });
    expect(no({ bMax: -1, B0: -1 })).toEqual({ ok: false, reason: 'bMax must be finite and >= 0' });
    expect(no({ B0: -1 })).toEqual({ ok: false, reason: 'B0 must be finite and >= 0' });
    expect(no({ B0: 10 }).ok).toBe(true);
    expect(no({ B0: 0, bMax: 0 }).ok).toBe(true);
    expect(no({ B0: 0 }).ok).toBe(true);
    expect(no({ kappa: 1e-9 }).ok).toBe(true);
  });
  it('allocateSub: exact node, parent unchanged, input state unchanged', () => {
    const s = root();
    const before = JSON.stringify(s);
    const r = allocateSub(s, { id: 'a', domain: 'da', parent: 'r', alloc: 4 });
    expect(r).toEqual({ ok: true, state: { ...s, nodes: { r: { domain: 'dr', B: 10 }, a: { domain: 'da', parent: 'r', B: 4 } } } });
    expect(JSON.stringify(s)).toBe(before);
    expect(allocateSub(s, { id: 'a', domain: 'da', parent: 'r', alloc: 10 }).ok).toBe(true); // alloc == parent remaining
  });
  it('allocateSub: exact refusals', () => {
    const s = alloc(root(), 'a', 'r', 4);
    const al = (args: unknown, st: unknown = s) => allocateSub(st as never, args as never);
    expect(al({ id: 'x', domain: 'd', parent: 'r', alloc: 1 }, null)).toEqual({ ok: false, reason: 'malformed budget state' });
    for (const bad of [null, { domain: 'd', parent: 'r', alloc: 1 }, { id: 'x', parent: 'r', alloc: 1 }, { id: 'x', domain: 'd', alloc: 1 }, { id: 5, domain: 'd', parent: 'r' }, { id: 'x', domain: 5, parent: 'r' }, { id: 'x', domain: 'd', parent: 5 }]) {
      expect(al(bad)).toEqual({ ok: false, reason: 'malformed allocation' });
    }
    expect(al({ id: 'r', domain: 'd', parent: 'r', alloc: 1 })).toEqual({ ok: false, reason: 'node id already exists' });
    expect(al({ id: 'a', domain: 'd', parent: 'nope', alloc: 1 })).toEqual({ ok: false, reason: 'node id already exists' });
    expect(al({ id: 'x', domain: 'd', parent: 'nope', alloc: 1 })).toEqual({ ok: false, reason: 'unknown parent' });
    expect(al({ id: 'x', domain: 'd', parent: 'a', alloc: 5 })).toEqual({ ok: false, reason: 'allocation exceeds parent remaining budget' });
    expect(al({ id: 'x', domain: 'd', parent: 'a', alloc: -1 })).toEqual({ ok: false, reason: 'allocation must be finite and >= 0' });
    expect(al({ id: 'x', domain: 'd', parent: 'a', alloc: NaN })).toEqual({ ok: false, reason: 'allocation must be finite and >= 0' });
    expect(al({ id: 'x', domain: 'd', parent: 'a', alloc: 4 }).ok).toBe(true);
    expect(al({ id: 'x', domain: 'd', parent: 'a', alloc: 0 }).ok).toBe(true);
  });
  it('validBudgetState (seen through spend and allocate): each defect alone is "malformed budget state"', () => {
    const good = alloc(root(), 'a', 'r', 4);
    const mut = (f: (s: Record<string, any>) => void) => {
      const s = JSON.parse(JSON.stringify(good));
      f(s);
      return s;
    };
    const defects: unknown[] = [
      null,
      'x',
      [],
      mut((s) => (s.nodes = [])),
      mut((s) => (s.nodes = null)),
      mut((s) => (s.root = 5)),
      mut((s) => (s.kappa = '2')),
      mut((s) => (s.kappa = NaN)),
      mut((s) => (s.kappa = Infinity)),
      mut((s) => (s.kappa = 0)),
      mut((s) => (s.kappa = -1)),
      mut((s) => (s.bMax = '1')),
      mut((s) => (s.bMax = NaN)),
      mut((s) => (s.bMax = -1)),
      mut((s) => (s.root = 'ghost')),
      mut((s) => (s.nodes.a = null)),
      mut((s) => (s.nodes.a = [])),
      mut((s) => (s.nodes.a.domain = 5)),
      mut((s) => (s.nodes.a.B = '1')),
      mut((s) => (s.nodes.a.B = NaN)),
      mut((s) => (s.nodes.a.B = Infinity)),
      mut((s) => (s.nodes.a.B = -1)),
      mut((s) => (s.nodes.a.parent = 5)),
    ];
    for (const d of defects) {
      expect(spendFederated(d as never, 'a', 0), JSON.stringify(d)).toEqual({ ok: false, reason: 'malformed budget state' });
      expect(allocateSub(d as never, { id: 'z', domain: 'd', parent: 'a', alloc: 0 }), JSON.stringify(d)).toEqual({ ok: false, reason: 'malformed budget state' });
    }
    // boundaries that must stay legal
    for (const f of [(s: Record<string, any>) => (s.bMax = 0), (s: Record<string, any>) => (s.nodes.a.B = 0), (s: Record<string, any>) => (s.kappa = 0.001)]) {
      expect(spendFederated(mut(f) as never, 'a', 0).ok).toBe(true);
    }
    // a parentless node other than the root is "not rooted", not malformed
    expect(spendFederated(mut((s) => delete s.nodes.a.parent) as never, 'a', 0)).toEqual({ ok: false, reason: 'node is not rooted at the budget root' });
  });
  it('spendFederated: input validation', () => {
    const s = root();
    expect(spendFederated(s, 5 as never, 1)).toEqual({ ok: false, reason: 'malformed node id' });
    expect(spendFederated(s, undefined as never, 1)).toEqual({ ok: false, reason: 'malformed node id' });
    for (const c of [-1, NaN, Infinity, '1']) expect(spendFederated(s, 'r', c as never)).toEqual({ ok: false, reason: 'spend must be finite and >= 0' });
    expect(spendFederated(s, 'r', 0)).toEqual({ ok: true, state: s });
    expect(spendFederated(s, 'nope', 1)).toEqual({ ok: false, reason: 'unknown node' });
  });
  it('spending at the root: insufficient / exact / partial', () => {
    const s = root();
    expect(spendFederated(s, 'r', 10.5)).toEqual({ ok: false, reason: 'root budget insufficient' });
    const r10 = spendFederated(s, 'r', 10) as { ok: true; state: FederatedBudgetState };
    expect(r10.state.nodes.r).toEqual({ domain: 'dr', B: 0 });
    const r4 = spendFederated(alloc(s, 'a', 'r', 5), 'r', 4) as { ok: true; state: FederatedBudgetState };
    expect(r4.state.nodes).toEqual({ r: { domain: 'dr', B: 6 }, a: { domain: 'd-a', parent: 'r', B: 5 } });
  });
  it('spending at a child of the root debits child and root once; other nodes and the input are untouched', () => {
    const s = alloc(alloc(root(), 'a', 'r', 6), 'z', 'r', 2);
    const before = JSON.stringify(s);
    const r = spendFederated(s, 'a', 3) as { ok: true; state: FederatedBudgetState };
    expect(r.state.nodes).toEqual({ r: { domain: 'dr', B: 7 }, a: { domain: 'd-a', parent: 'r', B: 3 }, z: { domain: 'd-z', parent: 'r', B: 2 } });
    expect(r.state.root).toBe('r');
    expect(r.state.kappa).toBe(2);
    expect(r.state.bMax).toBe(10);
    expect(JSON.stringify(s)).toBe(before);
    // exactly equal to the sub budget is allowed
    expect(spendFederated(s, 'a', 6).ok).toBe(true);
    expect(spendFederated(s, 'a', 6.5)).toEqual({ ok: false, reason: 'sub-agent budget insufficient' });
  });
  it('the root running out is reported as the parent', () => {
    let s = alloc(root(), 'a', 'r', 8);
    s = (spendFederated(s, 'r', 5) as { ok: true; state: FederatedBudgetState }).state; // root 5, a still ceiling 8
    expect(spendFederated(s, 'a', 6)).toEqual({ ok: false, reason: 'parent budget insufficient' });
    expect(spendFederated(s, 'a', 5).ok).toBe(true);
  });
  it('deep spend debits every strict-interior ancestor and the root exactly once; the first insufficient ancestor is named', () => {
    let s = alloc(root(), 'a', 'r', 9);
    s = alloc(s, 'b', 'a', 8);
    s = alloc(s, 'c', 'b', 7);
    const r = spendFederated(s, 'c', 2) as { ok: true; state: FederatedBudgetState };
    expect(Object.fromEntries(Object.entries(r.state.nodes).map(([k, v]) => [k, v.B]))).toEqual({ r: 8, a: 7, b: 6, c: 5 });
    // drain the middle: spend at b leaves a, b low
    let t = (spendFederated(s, 'b', 6) as { ok: true; state: FederatedBudgetState }).state; // r4 a3 b2 c7
    expect(spendFederated(t, 'c', 3)).toEqual({ ok: false, reason: 'ancestor "b" budget insufficient' }); // b=2 first (closest to the spender)
    t = (spendFederated(t, 'b', 2) as { ok: true; state: FederatedBudgetState }).state; // r2 a1 b0 c7
    expect(spendFederated(t, 'c', 1)).toEqual({ ok: false, reason: 'ancestor "b" budget insufficient' });
    // ancestors exactly covering the spend are fine
    const eq = alloc(alloc(alloc(root(), 'a', 'r', 5), 'b', 'a', 5), 'c', 'b', 5);
    const done = spendFederated(eq, 'c', 5) as { ok: true; state: FederatedBudgetState };
    expect(done.ok).toBe(true);
    expect(Object.fromEntries(Object.entries(done.state.nodes).map(([k, v]) => [k, v.B]))).toEqual({ r: 5, a: 0, b: 0, c: 0 });
  });
  it('malformed trees: cycles, depth bound, dangling parent, orphan', () => {
    const base = root();
    const cyc = { ...base, nodes: { ...base.nodes, x: { domain: 'd', parent: 'y', B: 1 }, y: { domain: 'd', parent: 'x', B: 1 } } };
    expect(spendFederated(cyc, 'x', 0)).toEqual({ ok: false, reason: 'cycle in budget tree' });
    const self = { ...base, nodes: { ...base.nodes, x: { domain: 'd', parent: 'x', B: 1 } } };
    expect(spendFederated(self, 'x', 0)).toEqual({ ok: false, reason: 'cycle in budget tree' });
    const dangling = { ...base, nodes: { ...base.nodes, p: { domain: 'd', parent: 'ghost', B: 1 } } };
    expect(spendFederated(dangling, 'p', 0)).toEqual({ ok: false, reason: 'unknown node' });
    const orphan = { ...base, nodes: { ...base.nodes, o: { domain: 'd', B: 1 } } };
    expect(spendFederated(orphan, 'o', 0)).toEqual({ ok: false, reason: 'node is not rooted at the budget root' });
    // depth: 64 nodes on the path is allowed, 65 is not
    const nodes: Record<string, { domain: string; parent?: string; B: number }> = { n0: { domain: 'd', B: 1 } };
    for (let i = 1; i <= 64; i++) nodes[`n${i}`] = { domain: 'd', parent: `n${i - 1}`, B: 1 };
    const deep = { nodes, root: 'n0', kappa: 1, bMax: 1 };
    expect(spendFederated(deep, 'n63', 0).ok).toBe(true);
    expect(spendFederated(deep, 'n64', 0)).toEqual({ ok: false, reason: 'budget tree too deep' });
  });
  it('federatedSafetyBound: bMax / kappa, and 0 for anything unusable', () => {
    expect(federatedSafetyBound({ bMax: 10, kappa: 2 })).toBe(5);
    expect(federatedSafetyBound({ bMax: 10, kappa: 2 })).toBe(safetyBound({ bMax: 10, kappa: 2 }));
    expect(federatedSafetyBound({ bMax: 0, kappa: 2 })).toBe(0);
    expect(federatedSafetyBound({ bMax: -5, kappa: 2 })).toBe(0);
    expect(federatedSafetyBound({ bMax: 10, kappa: 0 })).toBe(0);
    for (const bad of [null, undefined, 5, 'x', []]) expect(federatedSafetyBound(bad as never)).toBe(0);
    expect(federatedSafetyBound({ bMax: NaN, kappa: 2 })).toBe(0);
    expect(federatedSafetyBound({ bMax: Infinity, kappa: 2 })).toBe(0);
    expect(federatedSafetyBound({ bMax: 10, kappa: NaN })).toBe(0);
    expect(federatedSafetyBound({ bMax: 10, kappa: Infinity })).toBe(0);
    expect(federatedSafetyBound({ bMax: '10', kappa: 2 } as never)).toBe(0);
    expect(federatedSafetyBound({ bMax: 10, kappa: '2' } as never)).toBe(0);
  });
});

// ---------------------------------------------------------------------------------------------
describe('cross reference', () => {
  const A = kp();
  const B = kp();
  const xr = (): CrossReference => ({ action_digest: 'dg', fromGuardian: pubOf(A.secretKey), toGuardian: pubOf(B.secretKey), nonce: 'n', at: 7 });
  const anchors = (x = xr()) => {
    const c = crossReferenceCommit(x);
    return { from: anchorCrossReference(A.secretKey, c, 1), to: anchorCrossReference(B.secretKey, c, 2) };
  };

  it('meshActionDigest / crossReferenceCommit are the domain-separated canonical hashes', () => {
    const a: MeshAction = { type: 't', resource: '/r', service_domain: 'sd', nonce: 'n', at: 1 };
    expect(meshActionDigest(a)).toBe(hashCanonical({ v: 'atlas-pca/mesh-action-digest/v1\0', action: a }));
    const x = xr();
    expect(crossReferenceCommit(x)).toBe(hashCanonical({ v: 'atlas-pca/mesh-xref/v1', action_digest: 'dg', from: x.fromGuardian, to: x.toGuardian, nonce: 'n', at: 7 }));
    for (const over of [{ action_digest: 'x' }, { fromGuardian: 'x' }, { toGuardian: 'x' }, { nonce: 'x' }, { at: 8 }]) expect(crossReferenceCommit({ ...x, ...over })).not.toBe(crossReferenceCommit(x));
  });
  it('anchorCrossReference: domain key, fields and signature over the XANCHOR-domain message', () => {
    const an = anchorCrossReference(A.secretKey, 'cm', 9);
    expect(an).toMatchObject({ domain: pubOf(A.secretKey), commit: 'cm', seq: 9 });
    expect(verifyB64u(an.domain, cat(utf8('atlas-pca/mesh-xanchor/v1\0'), canonicalBytes({ commit: 'cm', seq: 9 })), an.sig)).toBe(true);
  });
  it('verifies two agreeing anchors', () => {
    const x = xr();
    expect(verifyCrossReference(x, anchors(x))).toEqual({ ok: true, commit: crossReferenceCommit(x) });
  });
  it('malformed cross-reference: each field alone', () => {
    const x = xr();
    const a = anchors(x);
    const m = { ok: false, reason: 'malformed cross-reference' };
    for (const bad of [null, 'x', [], { ...x, action_digest: 5 }, { ...x, fromGuardian: 5 }, { ...x, toGuardian: 5 }, { ...x, nonce: 5 }, { ...x, at: NaN }, { ...x, at: '7' }, { ...x, at: Infinity }]) {
      expect(verifyCrossReference(bad as never, a), JSON.stringify(bad)).toEqual(m);
    }
  });
  it('malformed anchors: each anchor field alone, on each side', () => {
    const x = xr();
    const a = anchors(x);
    const m = { ok: false, reason: 'malformed anchors' };
    expect(verifyCrossReference(x, null as never)).toEqual(m);
    expect(verifyCrossReference(x, [] as never)).toEqual(m);
    for (const side of ['from', 'to'] as const) {
      for (const bad of [null, 'x', { ...a[side], domain: 5 }, { ...a[side], commit: 5 }, { ...a[side], seq: -1 }, { ...a[side], seq: 1.5 }, { ...a[side], seq: '1' }, { ...a[side], sig: 5 }]) {
        expect(verifyCrossReference(x, { ...a, [side]: bad } as never), side + JSON.stringify(bad)).toEqual(m);
      }
      expect(verifyCrossReference(x, { ...a, [side]: { ...a[side], seq: 0 } } as never)).toMatchObject({ ok: false, reason: expect.stringMatching(/anchor signature invalid/) }); // seq 0 is well formed (signature then fails)
    }
  });
  it('semantic refusals with exact reasons, in order', () => {
    const x = xr();
    const a = anchors(x);
    expect(verifyCrossReference({ ...x, toGuardian: x.fromGuardian }, a)).toEqual({ ok: false, reason: 'cross-reference must span two distinct domains' });
    expect(verifyCrossReference(x, { ...a, from: anchorCrossReference(B.secretKey, crossReferenceCommit(x), 1) })).toEqual({ ok: false, reason: 'source anchor domain does not match the cross-reference' });
    expect(verifyCrossReference(x, { ...a, to: anchorCrossReference(A.secretKey, crossReferenceCommit(x), 1) })).toEqual({ ok: false, reason: 'target anchor domain does not match the cross-reference' });
    expect(verifyCrossReference(x, { ...a, from: anchorCrossReference(A.secretKey, 'different', 1) })).toEqual({ ok: false, reason: 'source anchor commits a different action' });
    expect(verifyCrossReference(x, { ...a, to: anchorCrossReference(B.secretKey, 'different', 1) })).toEqual({ ok: false, reason: 'target anchor commits a different action' });
    expect(verifyCrossReference(x, { ...a, from: { ...a.from, seq: a.from.seq + 1 } })).toEqual({ ok: false, reason: 'source anchor signature invalid' });
    expect(verifyCrossReference(x, { ...a, to: { ...a.to, seq: a.to.seq + 1 } })).toEqual({ ok: false, reason: 'target anchor signature invalid' });
    expect(verifyCrossReference(x, { ...a, from: { ...a.from, sig: a.to.sig } })).toEqual({ ok: false, reason: 'source anchor signature invalid' });
    // a signature over a bare {commit, seq} without the domain prefix is rejected
    const bare = b64u(sign(A.secretKey, canonicalBytes({ commit: a.from.commit, seq: a.from.seq })));
    expect(verifyCrossReference(x, { ...a, from: { ...a.from, sig: bare } })).toEqual({ ok: false, reason: 'source anchor signature invalid' });
  });
});
