/**
 * Mutation-kill tests for mesh.ts (part 2): checkCosignedHead, verifyMeshProof (trust validation, shapes, per-hop checks,
 * action admission) and the A2A translated-capability verifier. Each guard is reached with a proof whose OTHER parts are valid.
 */
import { describe, expect, it } from 'vitest';
import { type Capability, type Caveat, capHash, delegate, mintRoot } from './capability';
import { b64u, canonicalBytes, hashCanonical, utf8 } from './hash';
import { encodeKey, generateKeyPair, publicKeyOf, sign, verifyB64u } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import {
  assembleMeshProof,
  buildMeshExample,
  checkCosignedHead,
  type CosignedHead,
  DEFAULT_MAX_CHAIN_LENGTH,
  DEFAULT_MAX_CLOCK_SKEW_MS,
  DEFAULT_MAX_HEAD_AGE_MS,
  type MeshAction,
  MeshDomain,
  type MeshHead,
  type MeshProof,
  type MeshTrust,
  MeshWitness,
  signMeshAction,
  translateCapability,
  type TranslatedCapability,
  verifyMeshProof,
  verifyTranslatedCapability,
} from './mesh';

const kp = () => generateKeyPair();
const pubOf = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const cat = (a: Uint8Array, b: Uint8Array) => {
  const m = new Uint8Array(a.length + b.length);
  m.set(a);
  m.set(b, a.length);
  return m;
};
const HEAD_DOM = utf8('atlas-pca/mesh-head/v1\0');
const COSIG_DOM = utf8('atlas-pca/mesh-cosig/v1\0');
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
/** The deliberate ill-typed-input boundary: hands a value of the wrong shape to a typed slot so the verifier sees it. */
const malformed = <T>(v: unknown): T => v as T;

// ---------------------------------------------------------------------------------------------
// checkCosignedHead
// ---------------------------------------------------------------------------------------------
describe('checkCosignedHead', () => {
  const NOW = 1_000_000;
  const dk = kp();
  const D = pubOf(dk.secretKey);
  const ws = [kp(), kp(), kp()];
  const W = ws.map((w) => pubOf(w.secretKey));
  const trust = (over: Partial<MeshTrust> = {}): MeshTrust => ({ humanPrincipal: 'h', witnesses: [W[0]!, W[1]!], threshold: 2, now: NOW, allowedDomains: [D], rootDomain: D, ...over });
  const head = (over: Partial<MeshHead> = {}): MeshHead => ({ domain: D, size: 0, root: '', rev_root: 'rr', rev_size: 0, timestamp: NOW - 1000, ...over });
  const cosig = (w: { secretKey: Uint8Array }, h: MeshHead) => ({ witness: pubOf(w.secretKey), sig: b64u(sign(w.secretKey, cat(COSIG_DOM, canonicalBytes(h)))) });
  const ch = (h: MeshHead = head(), cos = [cosig(ws[0]!, h), cosig(ws[1]!, h)]): CosignedHead => ({ head: h, sig: b64u(sign(dk.secretKey, cat(HEAD_DOM, canonicalBytes(h)))), cosigs: cos });

  it('accepts a fresh, domain-signed, k-cosigned head', () => {
    expect(checkCosignedHead(ch(), D, trust())).toBeUndefined();
  });
  it('wrong expected domain / unusable container -> "head is for a different domain"', () => {
    const m = 'head is for a different domain';
    expect(checkCosignedHead(ch(), 'other', trust())).toBe(m);
    expect(checkCosignedHead(null as never, D, trust())).toBe(m);
    expect(checkCosignedHead({} as never, D, trust())).toBe(m);
    expect(checkCosignedHead({ head: 5 } as never, D, trust())).toBe(m);
    expect(checkCosignedHead({ head: [] } as never, D, trust())).toBe(m);
    expect(checkCosignedHead({ head: null } as never, D, trust())).toBe(m);
  });
  it('malformed head: shape, or a non-string signature - each alone', () => {
    const good = ch();
    expect(checkCosignedHead({ ...good, head: { ...good.head, size: -1 } }, D, trust())).toBe('malformed head');
    expect(checkCosignedHead({ ...good, head: { ...good.head, root: 'x' } }, D, trust())).toBe('malformed head'); // size 0 requires root ''
    expect(checkCosignedHead({ ...good, sig: 5 as never }, D, trust())).toBe('malformed head');
    expect(checkCosignedHead({ ...good, sig: undefined as never }, D, trust())).toBe('malformed head');
  });
  it('domain signature', () => {
    const good = ch();
    expect(checkCosignedHead({ ...good, sig: ch(head({ timestamp: NOW - 5 })).sig }, D, trust())).toBe('head not signed by its domain key');
    // signed with the cosignature domain prefix instead
    const wrong = b64u(sign(dk.secretKey, cat(COSIG_DOM, canonicalBytes(good.head))));
    expect(checkCosignedHead({ ...good, sig: wrong }, D, trust())).toBe('head not signed by its domain key');
  });
  it('cosig container: must be an array of at most 256', () => {
    const good = ch();
    expect(checkCosignedHead({ ...good, cosigs: 'x' as never }, D, trust())).toBe('malformed head');
    expect(checkCosignedHead({ ...good, cosigs: undefined as never }, D, trust())).toBe('malformed head');
    const filler = { witness: W[0]!, sig: 'x' };
    const real = good.cosigs;
    expect(checkCosignedHead({ ...good, cosigs: [...Array(254).fill(filler), ...real] }, D, trust())).toBeUndefined(); // 256 exactly
    expect(checkCosignedHead({ ...good, cosigs: [...Array(255).fill(filler), ...real] }, D, trust())).toBe('malformed head'); // 257
  });
  it('counts only DISTINCT, PINNED, VALIDLY signed cosignatures; exact "have/need" message', () => {
    const h = head();
    const c0 = cosig(ws[0]!, h);
    const c1 = cosig(ws[1]!, h);
    const c2 = cosig(ws[2]!, h); // valid but NOT pinned
    const msg = (n: number, k = 2) => `head has ${n}/${k} trusted witness cosignatures`;
    expect(checkCosignedHead(ch(h, [c0]), D, trust())).toBe(msg(1));
    expect(checkCosignedHead(ch(h, []), D, trust())).toBe(msg(0));
    expect(checkCosignedHead(ch(h, [c0, c0]), D, trust())).toBe(msg(1)); // duplicates count once
    expect(checkCosignedHead(ch(h, [c0, c2]), D, trust())).toBe(msg(1)); // unpinned
    expect(checkCosignedHead(ch(h, [c2]), D, trust({ threshold: 1 }))).toBe(msg(0, 1));
    expect(checkCosignedHead(ch(h, [{ ...c1, sig: c0.sig }, c0]), D, trust())).toBe(msg(1)); // wrong signature
    expect(checkCosignedHead(ch(h, [{ witness: c1.witness, sig: b64u(sign(ws[1]!.secretKey, cat(HEAD_DOM, canonicalBytes(h)))) }, c0]), D, trust())).toBe(msg(1)); // HEAD-domain signature by a witness
    // junk entries are skipped, not fatal
    expect(checkCosignedHead(ch(h, [null as never, c0, 5 as never, c1]), D, trust())).toBeUndefined();
    expect(checkCosignedHead(ch(h, [{ witness: 5, sig: c0.sig } as never, c0, c1]), D, trust())).toBeUndefined();
    expect(checkCosignedHead(ch(h, [{ witness: c0.witness, sig: 5 } as never, c1]), D, trust({ threshold: 2 }))).toBe(msg(1));
    expect(checkCosignedHead(ch(h, [c0, c1]), D, trust({ threshold: 1 }))).toBeUndefined();
    // a cosignature over a DIFFERENT head does not count
    expect(checkCosignedHead(ch(h, [cosig(ws[0]!, head({ timestamp: NOW - 2 })), c1]), D, trust())).toBe(msg(1));
  });
  it('future-dated / stale boundaries with the documented defaults', () => {
    expect(DEFAULT_MAX_CLOCK_SKEW_MS).toBe(60_000);
    expect(DEFAULT_MAX_HEAD_AGE_MS).toBe(300_000);
    expect(DEFAULT_MAX_CHAIN_LENGTH).toBe(64);
    const at = (ts: number, t: Partial<MeshTrust> = {}) => checkCosignedHead(ch(head({ timestamp: ts })), D, trust(t));
    expect(at(NOW + 60_000)).toBeUndefined();
    expect(at(NOW + 60_001)).toBe('head timestamp is in the future');
    expect(at(NOW + 10, { maxClockSkewMs: 10 })).toBeUndefined();
    expect(at(NOW + 11, { maxClockSkewMs: 10 })).toBe('head timestamp is in the future');
    expect(at(NOW + 1, { maxClockSkewMs: 0 })).toBe('head timestamp is in the future');
    expect(at(NOW - 300_000)).toBeUndefined();
    expect(at(NOW - 300_001)).toBe('head is stale');
    expect(at(NOW - 50, { maxHeadAgeMs: 50 })).toBeUndefined();
    expect(at(NOW - 51, { maxHeadAgeMs: 50 })).toBe('head is stale');
    expect(at(NOW - 1, { maxHeadAgeMs: 0 })).toBe('head is stale');
    expect(at(NOW, { maxHeadAgeMs: 0 })).toBeUndefined();
  });
  it('pins: rollback / equivocation are reported with the "(vs pinned head)" suffix; a proof is used for a larger head', () => {
    const h = head();
    const pinned = (p: MeshHead) => trust({ pinnedHeads: { [D]: p } });
    expect(checkCosignedHead(ch(h), D, pinned({ ...h, size: 1, root: 'r' }))).toBe('head rolls back (vs pinned head)');
    expect(checkCosignedHead(ch(h), D, pinned({ ...h, rev_root: 'zz' }))).toBe('equivocation (revocation set) (vs pinned head)');
    expect(checkCosignedHead(ch(h), D, pinned(h))).toBeUndefined();
    expect(checkCosignedHead(ch(h), D, trust({ pinnedHeads: {} }))).toBeUndefined();
    expect(checkCosignedHead(ch(h), D, trust({ pinnedHeads: { other: { ...h, size: 5, root: 'r' } } }))).toBeUndefined();
    // larger head than the pin: the proof is required
    const dom = new MeshDomain('x', dk.secretKey);
    const a = mintRoot({ principalSecret: dk.secretKey, principalPublic: D, holder: D, caveats: [{ type: 'scope', actions: ['a'] }] });
    const b = mintRoot({ principalSecret: dk.secretKey, principalPublic: D, holder: D, caveats: [{ type: 'scope', actions: ['b'] }] });
    dom.record(a);
    const w = new MeshWitness(ws[0]!.secretKey);
    const w2 = new MeshWitness(ws[1]!.secretKey);
    const h1 = dom.publishHead([w, w2], NOW - 1000);
    dom.record(b);
    const h2 = dom.publishHead([w, w2], NOW - 500);
    const t = trust({ pinnedHeads: { [D]: h1.head } });
    expect(checkCosignedHead(h2, D, t)).toBe('consistency proof required for a larger head (vs pinned head)');
    expect(checkCosignedHead(h2, D, t, dom.consistencyProof(1, 2))).toBeUndefined();
  });
  it('never throws: hostile containers are "malformed head"', () => {
    const good = ch();
    expect(checkCosignedHead({ ...good, cosigs: [{ witness: W[0]!, get sig(): string { throw new Error('boom'); } }] } as never, D, trust())).toBe('malformed head');
    expect(checkCosignedHead(good, D, { ...trust(), witnesses: 5 as never })).toBe('malformed head');
  });
});

// ---------------------------------------------------------------------------------------------
// verifyMeshProof on the worked example
// ---------------------------------------------------------------------------------------------
describe('verifyMeshProof: trust configuration', () => {
  const ex = buildMeshExample();
  const v = (t: unknown) => verifyMeshProof(ex.proof, t as MeshTrust);
  const T = ex.trust;
  const bad = (reason: string) => ({ ok: false, reason, trace: [] });

  it('the example verifies and the trace is exact', () => {
    const r = verifyMeshProof(ex.proof, T);
    expect(r.ok).toBe(true);
    expect('reason' in r).toBe(false);
    expect('hop' in r).toBe(false);
    expect(r.root_principal).toBe(ex.chain[0]!.issuer);
    expect(r.leaf).toBe(ex.chain[3]!.holder);
    expect(r.trace.map((h) => [h.hop, h.domain, h.issuer, h.holder, h.crosses_boundary])).toEqual(
      ex.chain.map((c, i) => [i, [ex.domains.A, ex.domains.A, ex.domains.B, ex.domains.C][i]!.id, c.issuer, c.holder, [false, true, true, false][i]]),
    );
    expect(r.trace[3]!.effective).toEqual({ prefixes: ['/orders/', '/orders/42'], actions: ['payments.refund'], maxAmount: 50, expiresAt: T.now + 3_600_000, audience: [ex.domains.C.id], maxHops: 4 });
  });
  it('invalid trust shapes', () => {
    expect(v(null)).toEqual(bad('invalid trust configuration'));
    expect(v('x')).toEqual(bad('invalid trust configuration'));
    expect(v([])).toEqual(bad('invalid trust configuration'));
    expect(v({ ...T, humanPrincipal: 5 })).toEqual(bad('invalid trust configuration'));
    expect(v({ ...T, witnesses: 'x' })).toEqual(bad('invalid trust configuration'));
    expect(v({ ...T, witnesses: [...T.witnesses, 5] })).toEqual(bad('invalid trust configuration'));
  });
  it('threshold must be an integer in 1..distinct witnesses', () => {
    const m = bad('invalid trust configuration: threshold');
    for (const th of [0, -1, 1.5, '2', NaN, 4]) expect(v({ ...T, threshold: th })).toEqual(m);
    expect(v({ ...T, threshold: 3 }).ok).toBe(true);
    expect(v({ ...T, threshold: 1 }).ok).toBe(true);
    const w = T.witnesses;
    expect(v({ ...T, witnesses: [w[0], w[0], w[1]], threshold: 3 })).toEqual(m); // duplicates are not distinct
    expect(v({ ...T, witnesses: [w[0], w[0], w[1]], threshold: 2 }).ok).toBe(true);
  });
  it('now must be a finite number', () => {
    for (const n of [NaN, Infinity, '1', undefined]) expect(v({ ...T, now: n })).toEqual(bad('invalid trust configuration: now'));
  });
  it('the optional durations: finite, >= 0 (0 is legal)', () => {
    for (const k of ['maxHeadAgeMs', 'maxClockSkewMs', 'maxActionAgeMs']) {
      for (const x of [-1, NaN, Infinity, '5']) expect(v({ ...T, [k]: x }), `${k}=${String(x)}`).toEqual(bad(`invalid trust configuration: ${k}`));
    }
    expect(v({ ...T, maxHeadAgeMs: 10 ** 9, maxClockSkewMs: 0, maxActionAgeMs: 0 }).ok).toBe(true);
  });
  it('maxChainLength: positive integer; also bounds the chain', () => {
    for (const x of [0, -1, 1.5, '4', NaN]) expect(v({ ...T, maxChainLength: x })).toEqual(bad('invalid trust configuration: maxChainLength'));
    expect(v({ ...T, maxChainLength: 4 }).ok).toBe(true);
    const r = v({ ...T, maxChainLength: 3 });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('chain length out of bounds');
  });
  it('allowedDomains / rootDomain / issuerDomains / pinnedHeads', () => {
    const m = bad('invalid trust configuration: allowedDomains is required');
    for (const x of [undefined, 'x', [], [5], { length: 1 }]) expect(v({ ...T, allowedDomains: x })).toEqual(m);
    const r = bad('invalid trust configuration: rootDomain is required and must be in allowedDomains');
    expect(v({ ...T, rootDomain: undefined })).toEqual(r);
    expect(v({ ...T, rootDomain: 5 })).toEqual(r);
    expect(v({ ...T, rootDomain: 'elsewhere' })).toEqual(r);
    expect(v({ ...T, allowedDomains: [ex.domains.B.id, ex.domains.C.id] })).toEqual(r);
    const im = bad('invalid trust configuration: issuerDomains');
    for (const x of ['x', [], null, 5, { k: 5 }, { k: ex.domains.A.id, j: 5 }]) expect(v({ ...T, issuerDomains: x }), JSON.stringify(x)).toEqual(im);
    expect(v({ ...T, issuerDomains: {} }).ok).toBe(true);
    const pm = bad('invalid trust configuration: pinnedHeads');
    for (const x of ['x', [], null, 5]) expect(v({ ...T, pinnedHeads: x })).toEqual(pm);
    expect(v({ ...T, pinnedHeads: {} }).ok).toBe(true);
  });
});

describe('verifyMeshProof: proof shapes', () => {
  const ex = buildMeshExample();
  const T = ex.trust;
  const run = (mut: (p: MeshProof & Record<string, any>) => void, t: MeshTrust = T) => {
    const p = clone(ex.proof) as MeshProof & Record<string, any>;
    mut(p);
    return verifyMeshProof(p, t);
  };
  const reason = (r: { ok: boolean; reason?: string; hop?: number }) => [r.reason, r.hop];

  it('top level', () => {
    for (const k of ['chain', 'hops', 'heads', 'rev_leaves']) {
      expect(reason(run((p) => (p[k] = 'x'))), k).toEqual(['malformed proof', undefined]);
      expect(reason(run((p) => delete p[k])), k).toEqual(['malformed proof', undefined]);
    }
    for (const bad of [null, 5, 'x', []]) expect(reason(verifyMeshProof(bad as never, T))).toEqual(['malformed proof', undefined]);
  });
  it('action: shape of every field, and the signature must be a string', () => {
    const m = ['malformed action', undefined];
    expect(reason(run((p) => (p.action_sig = malformed(5))))).toEqual(m);
    expect(reason(run((p) => Reflect.deleteProperty(p, 'action_sig')))).toEqual(m);
    for (const bad of [null, 'x', [], { ...ex.proof.action, type: 5 }, { ...ex.proof.action, resource: 5 }, { ...ex.proof.action, service_domain: 5 }, { ...ex.proof.action, nonce: 5 }, { ...ex.proof.action, at: '1' }, { ...ex.proof.action, at: NaN }, { ...ex.proof.action, at: Infinity }, { ...ex.proof.action, amount: '5' }, { ...ex.proof.action, amount: NaN }, { ...ex.proof.action, amount: Infinity }]) {
      expect(reason(run((p) => (p.action = malformed(bad)))), JSON.stringify(bad)).toEqual(m);
    }
    const noAmount: MeshAction = { ...ex.proof.action };
    delete noAmount.amount;
    expect(run((p) => (p.action = noAmount)).reason).not.toBe('malformed action'); // amount is optional
  });
  it('pin_proofs shape', () => {
    const m = ['malformed pin proofs', undefined];
    const okp = { domain: 'x', proof: { oldSize: 0, newSize: 0, path: [] } };
    expect(reason(run((p) => (p.pin_proofs = malformed('x'))))).toEqual(m);
    expect(reason(run((p) => (p.pin_proofs = malformed(null))))).toEqual(m);
    expect(reason(run((p) => (p.pin_proofs = [malformed(null)])))).toEqual(m);
    expect(reason(run((p) => (p.pin_proofs = [{ ...okp, domain: malformed(5) }])))).toEqual(m);
    expect(reason(run((p) => (p.pin_proofs = [{ domain: 'x', proof: { oldSize: -1, newSize: 0, path: [] } }])))).toEqual(m);
    expect(reason(run((p) => (p.pin_proofs = [{ domain: 'x', proof: { oldSize: 0, newSize: 0, path: [malformed(1)] } }])))).toEqual(m);
    expect(reason(run((p) => (p.pin_proofs = Array(257).fill(okp))))).toEqual(m);
    expect(run((p) => (p.pin_proofs = Array(256).fill(okp))).ok).toBe(true);
    expect(run((p) => (p.pin_proofs = [])).ok).toBe(true);
  });
  it('chain length bounds (default 64, explicit, and empty)', () => {
    const m = ['chain length out of bounds', undefined];
    expect(reason(run((p) => (p.chain = [])))).toEqual(m);
    expect(reason(run((p) => (p.chain = Array(65).fill(p.chain[0]))))).toEqual(m);
    expect(run((p) => (p.chain = Array(64).fill(p.chain[0]))).reason).not.toBe('chain length out of bounds');
    expect(reason(run((p) => (p.chain = Array(5).fill(p.chain[0])), { ...T, maxChainLength: 4 }))).toEqual(m);
    expect(run((p) => (p.chain = Array(4).fill(p.chain[0])), { ...T, maxChainLength: 4 }).reason).not.toBe('chain length out of bounds');
    expect(run((p) => (p.chain = Array(65).fill(p.chain[0])), { ...T, maxChainLength: 100 }).reason).not.toBe('chain length out of bounds');
  });
  it('evidence tables may not exceed the chain; counts must line up', () => {
    const m = ['evidence tables exceed chain size', undefined];
    expect(reason(run((p) => (p.heads = [...p.heads, ...p.heads, p.heads[0]!])))).toEqual(m); // 7 heads for 4 hops... (> chain length)
    expect(reason(run((p) => (p.heads = [...p.heads, p.heads[0]!, p.heads[0]!])))).toEqual(m); // 5 > 4
    const leaf = { id: 'x', proof: { index: 0, size: 1, path: [] } };
    expect(run((p) => (p.rev_leaves = Array(9).fill(leaf))).reason).toBe('evidence tables exceed chain size'); // > 2 * 4
    expect(run((p) => (p.rev_leaves = Array(8).fill(leaf))).ok).toBe(true);
    expect(reason(run((p) => p.hops.pop()))).toEqual(['hop evidence count does not match chain length', undefined]);
    expect(reason(run((p) => p.hops.push(p.hops[0]!)))).toEqual(['hop evidence count does not match chain length', undefined]);
  });
  it('chain verification failures are prefixed "chain: "', () => {
    const r = run((p) => (p.chain[1]!.sig = p.chain[0]!.sig));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^chain: /);
    expect(r.trace).toEqual([]);
    expect(verifyMeshProof(ex.proof, { ...T, humanPrincipal: pubOf(kp().secretKey) }).reason).toMatch(/^chain: /);
  });
  it('revocation leaves must be well formed (each field alone); an unreferenced extra leaf is otherwise harmless', () => {
    const m = ['malformed revocation leaves', undefined];
    const good = { id: 'x', proof: { index: 0, size: 1, path: [] } };
    expect(run((p) => (p.rev_leaves = [good])).ok).toBe(true);
    for (const bad of [null, 'x', [], { proof: good.proof }, { id: 5, proof: good.proof }, { id: 'x' }, { id: 'x', proof: null }, { id: 'x', proof: { ...good.proof, index: -1 } }, { id: 'x', proof: { ...good.proof, index: 0.5 } }, { id: 'x', proof: { ...good.proof, size: -1 } }, { id: 'x', proof: { ...good.proof, size: 1.5 } }, { id: 'x', proof: { ...good.proof, path: 'a' } }, { id: 'x', proof: { ...good.proof, path: undefined } }, { id: 'x', proof: { ...good.proof, path: Array(129).fill({}) } }]) {
      expect(reason(run((p) => (p.rev_leaves = [good, malformed(bad)]))), JSON.stringify(bad)).toEqual(m);
    }
    expect(run((p) => (p.rev_leaves = [{ id: 'x', proof: { ...good.proof, path: Array(128).fill({}) } }])).ok).toBe(true); // 128 is within the cap
    expect(run((p) => (p.rev_leaves = [{ id: 'x', proof: { index: 0, size: 0, path: [] } }])).ok).toBe(true); // zero sizes are numbers
  });
  it('every head in the table must be referenced; indexes must exist', () => {
    expect(reason(run((p) => (p.heads.push(p.heads[0]!))))).toEqual(['unreferenced or missing head in evidence table', undefined]);
    expect(reason(run((p) => { p.hops[0]!.head = 3; p.hops[1]!.head = 3; }))).toEqual(['malformed hop evidence', 0]); // table has 3 entries: index 3 does not exist
    expect(reason(run((p) => (p.hops[2]!.head = 7)))).toEqual(['malformed hop evidence', 2]); // 7 is a nat, so the table still counts 3 distinct
    expect(reason(run((p) => (p.hops[2]!.head = 1.5)))).toEqual(['unreferenced or missing head in evidence table', undefined]);
  });
  it('per-hop evidence shape, each field alone, with the hop index', () => {
    const m = (i: number) => ['malformed hop evidence', i];
    expect(reason(run((p) => (p.hops[1] = null as never)))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1] = 'x' as never)))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1] = [] as never)))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1]!.domain = malformed(5))))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1]!.head = 1.5)))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1]!.head = malformed('0'))))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1]!.head = -1)))).toEqual(m(1));
    expect(reason(run((p) => Reflect.deleteProperty(p.hops[1]!, 'revocation')))).toEqual(m(1));
    expect(reason(run((p) => (p.hops[1]!.revocation = malformed([]))))).toEqual(m(1));
  });
});

describe('verifyMeshProof: per-hop checks', () => {
  const ex = buildMeshExample();
  const T = ex.trust;
  const A = ex.domains.A.id;
  const B = ex.domains.B.id;
  const run = (mut: (p: MeshProof & Record<string, any>) => void, t: Partial<MeshTrust> = {}) => {
    const p = clone(ex.proof) as MeshProof & Record<string, any>;
    mut(p);
    return verifyMeshProof(p, { ...T, ...t });
  };
  const reason = (r: { reason?: string; hop?: number }) => [r.reason, r.hop];

  it('allowedDomains is enforced per hop; hop 0 must come from the root domain', () => {
    expect(reason(run(() => undefined, { allowedDomains: [A, ex.domains.C.id] }))).toEqual(['issuing domain not allowed by policy', 2]);
    expect(reason(run(() => undefined, { rootDomain: B }))).toEqual(['root capability must be anchored in the pinned root domain', 0]);
  });
  it('issuerDomains pins hops >= 1 only, and only for issuers that are present', () => {
    const humanPub = ex.chain[0]!.issuer;
    const tool = ex.chain[2]!.issuer;
    expect(run(() => undefined, { issuerDomains: { [humanPub]: 'nowhere' } }).ok).toBe(true); // hop 0 issuer is anchored by trust, not by the pin
    expect(run(() => undefined, { issuerDomains: {} }).ok).toBe(true);
    expect(run(() => undefined, { issuerDomains: { [tool]: B } }).ok).toBe(true);
    expect(reason(run(() => undefined, { issuerDomains: { [tool]: A } }))).toEqual(['issuer key is pinned to a different domain', 2]);
    expect(reason(run(() => undefined, { issuerDomains: { [ex.chain[1]!.issuer]: B } }))).toEqual(['issuer key is pinned to a different domain', 1]);
    expect(run(() => undefined, { issuerDomains: { constructor: 'x', toString: 'y' } }).ok).toBe(true);
  });
  it('the evidence head must be for the hop domain', () => {
    expect(reason(run((p) => { const t = p.hops[2]!.head; p.hops[2]!.head = p.hops[3]!.head; p.hops[3]!.head = t; }))).toEqual(['source-domain anchor: head is for a different domain', 2]);
    expect(reason(run((p) => (p.heads[p.hops[2]!.head]!.head = malformed(5))))).toEqual(['source-domain anchor: head is for a different domain', 2]);
    expect(reason(run((p) => (p.heads[p.hops[2]!.head] = malformed(null))))).toEqual(['malformed proof', undefined]);
  });
  it('head failures are surfaced with the "source-domain anchor: " prefix and the hop index', () => {
    expect(reason(run(() => undefined, { now: T.now + 400_000 }))).toEqual(['source-domain anchor: head is stale', 0]);
    expect(reason(run((p) => (p.heads[p.hops[3]!.head]!.cosigs = [])))).toEqual(['source-domain anchor: head has 0/2 trusted witness cosignatures', 3]);
    expect(reason(run((p) => (p.heads[p.hops[3]!.head]!.sig = p.heads[p.hops[2]!.head]!.sig)))).toEqual(['source-domain anchor: head not signed by its domain key', 3]);
  });
  it('a failing head is judged once and every hop sharing it fails the same way', () => {
    expect(reason(run((p) => (p.heads[p.hops[0]!.head]!.cosigs = [])))).toEqual(['source-domain anchor: head has 0/2 trusted witness cosignatures', 0]);
  });
  it('pins: the pin proof for the right domain is used', () => {
    const pin = ex.heads.A0.head;
    const t = { pinnedHeads: { [A]: pin } };
    const good = ex.domains.A.consistencyProof(1, 2);
    const junk = { oldSize: 0, newSize: 0, path: [] };
    expect(reason(run(() => undefined, t))).toEqual(['source-domain anchor: consistency proof required for a larger head (vs pinned head)', 0]);
    expect(run((p) => (p.pin_proofs = [{ domain: A, proof: good }]), t).ok).toBe(true);
    expect(run((p) => (p.pin_proofs = [{ domain: B, proof: junk }, { domain: A, proof: good }]), t).ok).toBe(true); // finds by domain, not first
    expect(reason(run((p) => (p.pin_proofs = [{ domain: B, proof: good }]), t))).toEqual(['source-domain anchor: consistency proof required for a larger head (vs pinned head)', 0]);
    expect(reason(run((p) => (p.pin_proofs = [{ domain: A, proof: junk }, { domain: A, proof: good }]), t))[0]).toBe('source-domain anchor: consistency proof required for a larger head (vs pinned head)'); // first match wins
  });
  it('inclusion: each defect alone -> "hop not included in the issuing domain log"', () => {
    const m = (i: number) => ['hop not included in the issuing domain log', i];
    const inc = (p: MeshProof & Record<string, any>, i: number) => p.hops[i]!.inclusion;
    expect(reason(run((p) => (p.hops[2]!.inclusion = malformed(null))))).toEqual(m(2));
    expect(reason(run((p) => (p.hops[2]!.inclusion = malformed([]))))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 2).index = -1)))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 2).index = 0.5)))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 2).size = inc(p, 2).size + 1)))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 2).size = -1)))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 2).path = malformed('x'))))).toEqual(m(2));
    expect(reason(run((p) => Reflect.deleteProperty(inc(p, 2), 'path')))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 2).path = Array(129).fill('A'))))).toEqual(m(2));
    expect(reason(run((p) => (inc(p, 1).index = 0)))).toEqual(m(1)); // wrong leaf position
    expect(reason(run((p) => (p.hops[1]!.inclusion = p.hops[0]!.inclusion)))).toEqual(m(1));
  });
  it('domain binding: hop 0 needs none; later hops need a valid one, each defect alone', () => {
    const mis = (i: number) => ['missing or mismatched domain binding for issuer', i];
    expect(run((p) => (p.hops[0]!.binding = malformed({ junk: true }))).ok).toBe(true);
    expect(reason(run((p) => delete p.hops[1]!.binding))).toEqual(mis(1));
    expect(reason(run((p) => (p.hops[1]!.binding = malformed(null))))).toEqual(mis(1));
    expect(reason(run((p) => (p.hops[1]!.binding = malformed([]))))).toEqual(mis(1));
    expect(reason(run((p) => (p.hops[2]!.binding!.role = malformed(5))))).toEqual(mis(2));
    expect(reason(run((p) => (p.hops[2]!.binding!.sig = malformed(5))))).toEqual(mis(2));
    expect(reason(run((p) => (p.hops[2]!.binding!.agent = ex.chain[1]!.issuer)))).toEqual(mis(2));
    expect(reason(run((p) => (p.hops[2]!.binding!.domain = A)))).toEqual(mis(2));
    expect(reason(run((p) => (p.hops[2]!.binding!.role = 'something-else')))).toEqual(['domain binding signature invalid', 2]);
    expect(reason(run((p) => (p.hops[2]!.binding!.sig = ex.bindings.orchestrator.sig)))).toEqual(['domain binding signature invalid', 2]);
    // signed by a different key than the issuing domain
    const forged = { agent: ex.chain[2]!.issuer, domain: B, role: 'tool-agent', sig: b64u(sign(kp().secretKey, utf8('x'))) };
    expect(reason(run((p) => (p.hops[2]!.binding = forged)))).toEqual(['domain binding signature invalid', 2]);
  });
  it('revocation proofs: capability and issuer key are checked separately, with their own reasons', () => {
    const capRev = (i: number) => ['capability revoked (or revocation proof invalid)', i];
    const keyRev = (i: number) => ['issuer key revoked (or revocation proof invalid)', i];
    expect(reason(run((p) => (p.hops[1]!.revocation.cap = { size: 5 })))).toEqual(capRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.issuer_key = { size: 5 })))).toEqual(keyRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.cap = malformed(null))))).toEqual(capRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.issuer_key = malformed(null))))).toEqual(keyRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.cap = malformed('x'))))).toEqual(capRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.cap = { size: -1 })))).toEqual(capRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.cap = { size: 0.5 })))).toEqual(capRev(1));
    expect(reason(run((p) => (p.hops[1]!.revocation.issuer_key = { size: malformed('0') })))).toEqual(keyRev(1));
    // bracket indices must point into the leaf table (index == length is out of range; negative / fractional are not indices)
    expect(p0(run, 'lo', 0)).toEqual(capRev(1));
    expect(p0(run, 'hi', 0)).toEqual(capRev(1));
    expect(p0(run, 'lo', -1)).toEqual(capRev(1));
    expect(p0(run, 'hi', 1.5)).toEqual(capRev(1));
    expect(p0(run, 'lo', '0')).toEqual(capRev(1));
    // both defects: the capability is reported first
    expect(reason(run((p) => { p.hops[1]!.revocation.cap = { size: 5 }; p.hops[1]!.revocation.issuer_key = { size: 5 }; }))).toEqual(capRev(1));
  });
  it('the trace of a failed verification holds the hops that passed', () => {
    const r = run((p) => (p.hops[2]!.revocation.cap = { size: 5 }));
    expect(r.trace.map((h) => h.hop)).toEqual([0, 1]);
    expect(r.hop).toBe(2);
  });
});

function p0(run: (m: (p: any) => void) => { reason?: string; hop?: number }, side: string, ix: unknown) {
  const r = run((p) => (p.hops[1].revocation.cap = { size: 0, [side]: ix }));
  return [r.reason, r.hop];
}

// ---------------------------------------------------------------------------------------------
// single-domain scenarios
// ---------------------------------------------------------------------------------------------
interface Scenario {
  proof: MeshProof;
  trust: MeshTrust;
  chain: Capability[];
  D: MeshDomain;
  leaf: { secretKey: Uint8Array };
  now: number;
  resign: (a: Partial<MeshAction>) => MeshProof;
}
const NOW = 1_800_000_000_000;
function scenario(rootCaveats: Caveat[], steps: Caveat[][] = [], opts: { rootSuite?: Parameters<typeof mintRoot>[0]['suite']; pqPins?: Record<string, string> } = {}): Scenario {
  const human = kp();
  const holders = [kp(), ...steps.map(() => kp())];
  const D = new MeshDomain('D', kp().secretKey);
  const ws = [new MeshWitness(kp().secretKey), new MeshWitness(kp().secretKey)];
  const chain: Capability[] = [mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(holders[0]!.secretKey), caveats: rootCaveats, ...(opts.rootSuite ? { suite: opts.rootSuite } : {}) })];
  steps.forEach((cv, i) => chain.push(delegate(chain[i]!, pubOf(holders[i + 1]!.secretKey), cv, holders[i]!.secretKey)));
  for (const c of chain) D.record(c);
  const head = D.publishHead(ws, NOW - 1000);
  const hops = chain.map((c, i) => D.evidence(c, head, i === 0 ? undefined : D.enroll(c.issuer, 'r')));
  const leaf = holders[holders.length - 1]!;
  const action: MeshAction = { type: 't', resource: '/r/1', amount: 5, service_domain: D.id, nonce: 'n', at: NOW };
  const proof = assembleMeshProof({ chain, hops, action, leafSecret: leaf.secretKey });
  const trust: MeshTrust = { humanPrincipal: pubOf(human.secretKey), witnesses: ws.map((w) => w.id), threshold: 2, now: NOW, allowedDomains: [D.id], rootDomain: D.id, ...(opts.pqPins ? { pqPins: opts.pqPins } : {}) };
  const resign = (a: Partial<MeshAction>): MeshProof => {
    const na = { ...action, ...a } as MeshAction;
    for (const k of Object.keys(na)) if ((na as unknown as Record<string, unknown>)[k] === undefined) delete (na as unknown as Record<string, unknown>)[k];
    return { ...proof, action: na, action_sig: signMeshAction(chain, na, leaf.secretKey) };
  };
  return { proof, trust, chain, D, leaf, now: NOW, resign };
}

describe('verifyMeshProof: admission of the leaf action', () => {
  const adm = (caveats: Caveat[], a: Partial<MeshAction> = {}, steps: Caveat[][] = [], t: Partial<MeshTrust> = {}) => {
    const s = scenario(caveats, steps);
    return verifyMeshProof(s.resign(a), { ...s.trust, ...t });
  };
  const denied = (d: string) => ({ ok: false, reason: `action not admitted: ${d}` });
  const pick = (r: { ok: boolean; reason?: string }) => ({ ok: r.ok, ...(r.reason ? { reason: r.reason } : {}) });

  it('no caveats admits anything well formed (every constraint is optional)', () => {
    expect(adm([]).ok).toBe(true);
    expect(adm([], { amount: undefined }).ok).toBe(true);
  });
  it('scope', () => {
    expect(adm([{ type: 'scope', actions: ['t'] }]).ok).toBe(true);
    expect(pick(adm([{ type: 'scope', actions: ['u', 'v'] }]))).toEqual(denied('action "t" not in scope'));
    expect(pick(adm([{ type: 'scope', actions: [] }]))).toEqual(denied('action "t" not in scope'));
  });
  it('resource prefixes: all must hold; the first violated one is named', () => {
    expect(adm([{ type: 'resource', prefix: '/r' }, { type: 'resource', prefix: '/r/1' }]).ok).toBe(true);
    expect(pick(adm([{ type: 'resource', prefix: '/q' }]))).toEqual(denied('resource "/r/1" outside prefix "/q"'));
    expect(pick(adm([{ type: 'resource', prefix: '/r' }, { type: 'resource', prefix: '/r/2' }]))).toEqual(denied('resource "/r/1" outside prefix "/r/2"'));
  });
  it('amount ceiling: inclusive, and a missing amount is refused', () => {
    expect(adm([{ type: 'max_amount', max: 5 }]).ok).toBe(true);
    expect(pick(adm([{ type: 'max_amount', max: 4.99 }]))).toEqual(denied('amount exceeds ceiling 4.99'));
    expect(pick(adm([{ type: 'max_amount', max: 100 }], { amount: undefined }))).toEqual(denied('amount exceeds ceiling 100'));
    expect(adm([{ type: 'max_amount', max: 0 }], { amount: 0 }).ok).toBe(true);
    expect(adm([{ type: 'scope', actions: ['t'] }], { amount: undefined }).ok).toBe(true); // no ceiling: amount optional
  });
  it('expiry: inclusive of the expiry instant', () => {
    expect(adm([{ type: 'expires', at: NOW }]).ok).toBe(true);
    expect(pick(adm([{ type: 'expires', at: NOW - 1 }]))).toEqual(denied('capability expired'));
  });
  it('audience', () => {
    const s = scenario([]);
    expect(adm([{ type: 'audience', domains: ['x', s.D.id] }], { service_domain: 'x' }).ok).toBe(true);
    expect(pick(adm([{ type: 'audience', domains: ['x'] }]))).toEqual(denied('service domain not in audience'));
    expect(pick(adm([{ type: 'audience', domains: [] }]))).toEqual(denied('service domain not in audience'));
  });
  it('max_hops: the chain length may equal the cap but not exceed it', () => {
    expect(adm([], {}, [[{ type: 'max_hops', n: 2 }]]).ok).toBe(true);
    expect(pick(adm([], {}, [[{ type: 'max_hops', n: 1 }]]))).toEqual(denied('chain exceeds max_hops 1'));
    expect(pick(adm([{ type: 'max_hops', n: 1 }], {}, [[]]))).toEqual(denied('chain exceeds max_hops 1'));
    expect(adm([{ type: 'max_hops', n: 1 }]).ok).toBe(true);
  });
  it('check order: scope, resource, amount, expiry, audience, hops', () => {
    const all: Caveat[] = [{ type: 'scope', actions: ['u'] }, { type: 'resource', prefix: '/q' }, { type: 'max_amount', max: 1 }, { type: 'expires', at: NOW - 1 }, { type: 'audience', domains: ['x'] }, { type: 'max_hops', n: 1 }];
    const drop = (n: number) => all.slice(n);
    const base = { ok: false } as const;
    expect(adm(drop(0), {}, [[]]).reason).toBe('action not admitted: action "t" not in scope');
    expect(adm(drop(1), {}, [[]]).reason).toBe('action not admitted: resource "/r/1" outside prefix "/q"');
    expect(adm(drop(2), {}, [[]]).reason).toBe('action not admitted: amount exceeds ceiling 1');
    expect(adm(drop(3), {}, [[]]).reason).toBe('action not admitted: capability expired');
    expect(adm(drop(4), {}, [[]]).reason).toBe('action not admitted: service domain not in audience');
    expect(adm(drop(5), {}, [[]]).reason).toBe('action not admitted: chain exceeds max_hops 1');
    expect(base.ok).toBe(false);
  });
  it('malformed / unknown caveats in the chain fail closed at their hop with the effectiveAuthority message', () => {
    const r = adm([{ type: 'max_amount', max: 'x' } as never]);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('malformed max_amount caveat');
    expect(r.hop).toBe(0);
    const r2 = adm([], {}, [[{ type: 'mystery' }]]);
    expect(r2.reason).toBe('unknown caveat type "mystery" (fail closed)');
    expect(r2.hop).toBe(1);
    expect(r2.trace).toHaveLength(1);
  });
  it('crosses_boundary on the LAST hop compares the action target with the hop domain', () => {
    const s = scenario([]);
    const same = verifyMeshProof(s.proof, s.trust);
    expect(same.trace[0]!.crosses_boundary).toBe(false);
    const other = verifyMeshProof(s.resign({ service_domain: 'elsewhere' }), s.trust);
    expect(other.ok).toBe(true);
    expect(other.trace[0]!.crosses_boundary).toBe(true);
  });
  it('action freshness and signature', () => {
    const s = scenario([]);
    const v = (a: Partial<MeshAction>, t: Partial<MeshTrust> = {}) => verifyMeshProof(s.resign(a), { ...s.trust, ...t });
    expect(v({ at: NOW + 60_000 }).ok).toBe(true);
    expect(v({ at: NOW + 60_001 }).reason).toBe('action timestamp is in the future');
    expect(v({ at: NOW + 5 }, { maxClockSkewMs: 5 }).ok).toBe(true);
    expect(v({ at: NOW + 6 }, { maxClockSkewMs: 5 }).reason).toBe('action timestamp is in the future');
    expect(v({ at: NOW + 1 }, { maxClockSkewMs: 0 }).reason).toBe('action timestamp is in the future');
    expect(v({ at: NOW - 10 }, { maxActionAgeMs: 10 }).ok).toBe(true);
    expect(v({ at: NOW - 11 }, { maxActionAgeMs: 10 }).reason).toBe('action is stale');
    expect(v({ at: NOW - 1 }, { maxActionAgeMs: 0 }).reason).toBe('action is stale');
    expect(v({ at: NOW }, { maxActionAgeMs: 0 }).ok).toBe(true);
    expect(v({ at: NOW - 10 ** 9 }).ok).toBe(true); // no age cap configured
    const bad = { ...s.resign({}), action_sig: b64u(sign(kp().secretKey, utf8('x'))) };
    expect(verifyMeshProof(bad, s.trust).reason).toBe('action not signed by the chain tip holder');
    // the signature is bound to the tip: signed over the action alone is rejected
    const bare = { ...s.proof, action_sig: b64u(sign(s.leaf.secretKey, cat(utf8('atlas-pca/mesh-action/v1\0'), canonicalBytes({ action: s.proof.action })))) };
    expect(verifyMeshProof(bare, s.trust).reason).toBe('action not signed by the chain tip holder');
    expect(verifyB64u(s.chain[0]!.holder, utf8('x'), 'x')).toBe(false);
  });
  it('failures carry no "hop" key unless a hop is meant', () => {
    const s = scenario([]);
    const r = verifyMeshProof(s.resign({ at: NOW + 10 ** 6 }), s.trust);
    expect(r.ok).toBe(false);
    expect('hop' in r).toBe(false);
    expect(r.trace).toHaveLength(1);
  });
  it('a 16-hop chain (the chain verifier\'s own cap) verifies; maxChainLength cuts it earlier', () => {
    const s = scenario([], Array.from({ length: 15 }, () => []));
    expect(s.proof.chain).toHaveLength(16);
    expect(verifyMeshProof(s.proof, s.trust).ok).toBe(true);
    expect(verifyMeshProof(s.proof, { ...s.trust, maxChainLength: 16 }).ok).toBe(true);
    expect(verifyMeshProof(s.proof, { ...s.trust, maxChainLength: 15 }).reason).toBe('chain length out of bounds');
    const long = scenario([], Array.from({ length: 16 }, () => []));
    expect(verifyMeshProof(long.proof, long.trust).reason).toBe('chain: chain too long (max 16 hops)');
  });
});

// ---------------------------------------------------------------------------------------------
// PQ pins flow through every chain verification
// ---------------------------------------------------------------------------------------------
describe('pqPins (hybrid roots)', () => {
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
  const pin = encodeMlDsaPublicKey(ml.publicKey);
  const suite = { alg: 'hybrid-ed25519-ml-dsa-65' as const, mlDsa: ml };

  it('verifyMeshProof: refused without a pin, accepted with the issuer pin', () => {
    const s = scenario([{ type: 'scope', actions: ['t'] }], [], { rootSuite: suite });
    const human = s.trust.humanPrincipal;
    const without = verifyMeshProof(s.proof, s.trust);
    expect(without.ok).toBe(false);
    expect(without.reason).toMatch(/^chain: /);
    expect(verifyMeshProof(s.proof, { ...s.trust, pqPins: { [human]: pin } }).ok).toBe(true);
  });
  it('translateCapability / verifyTranslatedCapability forward the pins', () => {
    const s = scenario([{ type: 'scope', actions: ['t'] }], [], { rootSuite: suite });
    const human = s.trust.humanPrincipal;
    const bridge = kp().secretKey;
    const args = { fromGuardian: 'A', toGuardian: 'B', bridgeSecret: bridge, issued_at: 1 };
    expect(() => translateCapability(s.chain, args)).toThrow(/^translateCapability: invalid source chain: /);
    const tc = translateCapability(s.chain, { ...args, pqPins: { [human]: pin } });
    const without = verifyTranslatedCapability(tc);
    expect(without.ok).toBe(false);
    expect(without.reason).toMatch(/^source chain: /);
    expect(verifyTranslatedCapability(tc, { pqPins: { [human]: pin } }).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// translated capabilities
// ---------------------------------------------------------------------------------------------
describe('translateCapability / verifyTranslatedCapability', () => {
  const human = kp();
  const holder = kp();
  const bridge = kp();
  const A = 'guardian-A';
  const B = 'guardian-B';
  const srcCaveats: Caveat[] = [{ type: 'scope', actions: ['x', 'y'] }, { type: 'max_amount', max: 100 }];
  const root = (caveats: Caveat[] = srcCaveats) => mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(holder.secretKey), caveats });
  const mk = (extra?: Caveat[], caveats?: Caveat[], over: Record<string, unknown> = {}) =>
    translateCapability([root(caveats)], { fromGuardian: A, toGuardian: B, bridgeSecret: bridge.secretKey, issued_at: 1000, ...(extra ? { additionalCaveats: extra } : {}), ...over } as never);
  const xcapMsg = (tc: TranslatedCapability) =>
    cat(utf8('atlas-pca/mesh-xcap/v1\0'), canonicalBytes({ v: 'atlas-pca/mesh-xcap/v1', from: tc.fromGuardian, to: tc.toGuardian, source_tip: tc.source_tip, caveats: tc.caveats, issued_at: tc.issued_at }));
  const resign = (tc: TranslatedCapability, over: Partial<TranslatedCapability>): TranslatedCapability => {
    const n = { ...tc, ...over };
    return { ...n, sig: b64u(sign(bridge.secretKey, xcapMsg(n))) };
  };
  const vt = (tc: unknown, o = {}) => verifyTranslatedCapability(tc as TranslatedCapability, o);

  it('translateCapability: exact output, deep-copied caveats, signed over the xcap message', () => {
    const r = root();
    const tc = translateCapability([r], { fromGuardian: A, toGuardian: B, bridgeSecret: bridge.secretKey, issued_at: 1000, additionalCaveats: [{ type: 'max_amount', max: 10 }] });
    expect(tc.source).toEqual([r]);
    expect(tc).toMatchObject({ fromGuardian: A, toGuardian: B, bridge: pubOf(bridge.secretKey), source_tip: capHash(r), issued_at: 1000 });
    expect(tc.caveats).toEqual([...srcCaveats, { type: 'max_amount', max: 10 }]);
    expect(verifyB64u(tc.bridge, xcapMsg(tc), tc.sig)).toBe(true);
    // caveats are copies
    tc.caveats[0] = { type: 'scope', actions: ['hacked'] };
    expect(r.caveats[0]).toEqual(srcCaveats[0]);
    const extra: Caveat[] = [{ type: 'max_amount', max: 10 }];
    const tc2 = translateCapability([r], { fromGuardian: A, toGuardian: B, bridgeSecret: bridge.secretKey, issued_at: 1, additionalCaveats: extra });
    tc2.caveats[2]!.max = 999;
    expect(extra[0]!.max).toBe(10);
    expect(mk().caveats).toEqual(srcCaveats);
    expect(mk([]).caveats).toEqual(srcCaveats);
  });
  it('translateCapability: refuses an invalid chain and non-caveat additions', () => {
    expect(() => translateCapability([], { fromGuardian: A, toGuardian: B, bridgeSecret: bridge.secretKey, issued_at: 1 })).toThrow(/^translateCapability: invalid source chain: /);
    const m = 'translateCapability: additionalCaveats must be an array of caveats';
    for (const bad of ['x', {}, [null], [{}], [{ type: 5 }], [[]], [{ type: 'a' }, 'b']]) expect(() => mk(bad as never), JSON.stringify(bad)).toThrow(m);
    expect(() => mk([{ type: 'whatever' }])).not.toThrow();
    // the chain is checked first
    expect(() => translateCapability([], { fromGuardian: A, toGuardian: B, bridgeSecret: bridge.secretKey, issued_at: 1, additionalCaveats: 'x' as never })).toThrow(/invalid source chain/);
  });
  it('verifies and reports the translated authority', () => {
    const tc = mk([{ type: 'max_amount', max: 10 }, { type: 'expires', at: 5000 }]);
    expect(vt(tc)).toEqual({ ok: true, from: A, to: B, bridge: pubOf(bridge.secretKey), effective: { prefixes: [], actions: ['x', 'y'], maxAmount: 10, expiresAt: 5000 } });
    expect(vt(tc, { fromGuardian: A, toGuardian: B, bridge: tc.bridge, rootIssuer: pubOf(human.secretKey) }).ok).toBe(true);
  });
  it('shape: each field alone -> "malformed translated capability"', () => {
    const tc = mk();
    const m = { ok: false, reason: 'malformed translated capability' };
    for (const bad of [null, 'x', [], { ...tc, source: 'x' }, { ...tc, fromGuardian: 5 }, { ...tc, toGuardian: 5 }, { ...tc, bridge: 5 }, { ...tc, source_tip: 5 }, { ...tc, sig: 5 }, { ...tc, issued_at: '1' }, { ...tc, issued_at: NaN }, { ...tc, issued_at: Infinity }, { ...tc, caveats: 'x' }, { ...tc, caveats: [{}] }, { ...tc, caveats: [null] }]) {
      expect(vt(bad), JSON.stringify(bad)).toEqual(m);
    }
    expect(vt({ ...tc, issued_at: 0 }).reason).not.toBe('malformed translated capability');
  });
  it('source chain and pins', () => {
    const tc = mk();
    expect(vt({ ...tc, source: [] }).reason).toMatch(/^source chain: /);
    expect(vt(tc, { rootIssuer: pubOf(kp().secretKey) }).reason).toMatch(/^source chain: /);
    expect(vt(tc, { fromGuardian: 'x' })).toEqual({ ok: false, reason: 'source guardian mismatch' });
    expect(vt(tc, { toGuardian: 'x' })).toEqual({ ok: false, reason: 'target guardian mismatch' });
    expect(vt(tc, { bridge: 'x' })).toEqual({ ok: false, reason: 'bridge key mismatch' });
    const same = resign(tc, { toGuardian: A });
    expect(vt(same)).toEqual({ ok: false, reason: 'translation does not cross a domain boundary' });
    expect(vt(resign(tc, { fromGuardian: '' , toGuardian: '' }))).toEqual({ ok: false, reason: 'translation does not cross a domain boundary' });
  });
  it('source_tip binding, append-only prefix (with the offending index) and bridge signature', () => {
    const tc = mk([{ type: 'max_amount', max: 10 }]);
    expect(vt({ ...tc, source_tip: 'x' })).toEqual({ ok: false, reason: 'source_tip does not match the source chain tip' });
    expect(vt(resign(tc, { caveats: tc.caveats.slice(2) }))).toEqual({ ok: false, reason: 'translation drops a source caveat (widening)' });
    expect(vt(resign(tc, { caveats: [] }))).toEqual({ ok: false, reason: 'translation drops a source caveat (widening)' });
    expect(vt(resign(tc, { caveats: tc.caveats.slice(1) }))).toEqual({ ok: false, reason: 'translation altered or reordered source caveat 0 (widening)' });
    expect(vt(resign(tc, { caveats: [{ type: 'scope', actions: ['x', 'y', 'z'] }, ...tc.caveats.slice(1)] }))).toEqual({ ok: false, reason: 'translation altered or reordered source caveat 0 (widening)' });
    expect(vt(resign(tc, { caveats: [tc.caveats[0]!, { type: 'max_amount', max: 1000 }, tc.caveats[2]!] }))).toEqual({ ok: false, reason: 'translation altered or reordered source caveat 1 (widening)' });
    expect(vt(resign(tc, { caveats: [tc.caveats[1]!, tc.caveats[0]!, tc.caveats[2]!] }))).toEqual({ ok: false, reason: 'translation altered or reordered source caveat 0 (widening)' });
    expect(vt({ ...tc, issued_at: tc.issued_at + 1 })).toEqual({ ok: false, reason: 'translation not signed by the declared bridge key' });
    expect(vt({ ...tc, bridge: pubOf(kp().secretKey) })).toEqual({ ok: false, reason: 'translation not signed by the declared bridge key' });
    expect(vt({ ...tc, fromGuardian: 'z' })).toEqual({ ok: false, reason: 'translation not signed by the declared bridge key' });
    expect(vt({ ...tc, caveats: [...tc.caveats, { type: 'max_amount', max: 1 }] })).toEqual({ ok: false, reason: 'translation not signed by the declared bridge key' });
    // signature without the xcap domain prefix is rejected
    const bare = { ...tc, sig: b64u(sign(bridge.secretKey, canonicalBytes({ v: 'atlas-pca/mesh-xcap/v1', from: A, to: B, source_tip: tc.source_tip, caveats: tc.caveats, issued_at: tc.issued_at }))) };
    expect(vt(bare)).toEqual({ ok: false, reason: 'translation not signed by the declared bridge key' });
  });
  it('unknown / malformed caveats fail closed on either side, with their own wording', () => {
    const srcBad = mk(undefined, [{ type: 'mystery' }]);
    expect(vt(srcBad)).toEqual({ ok: false, reason: 'source caveats: unknown caveat type "mystery" (fail closed)' });
    const srcBad2 = mk(undefined, [{ type: 'max_amount', max: 'x' } as never]);
    expect(vt(srcBad2)).toEqual({ ok: false, reason: 'source caveats: malformed max_amount caveat' });
    expect(vt(mk([{ type: 'mystery' }]))).toEqual({ ok: false, reason: 'unknown caveat type "mystery" (fail closed)' });
    expect(vt(mk([{ type: 'expires', at: 'x' } as never]))).toEqual({ ok: false, reason: 'malformed expires caveat' });
  });
  it('expiry: only when `now` is given and the translated authority has an expiry; inclusive of the instant', () => {
    const tc = mk([{ type: 'expires', at: 5000 }]);
    expect(vt(tc, { now: 5000 }).ok).toBe(true);
    expect(vt(tc, { now: 5001 })).toEqual({ ok: false, reason: 'translated capability expired' });
    expect(vt(tc, { now: 0 }).ok).toBe(true);
    expect(vt(tc, {}).ok).toBe(true);
    expect(vt(tc, { now: 10 ** 12 }).reason).toBe('translated capability expired');
    expect(vt(mk(), { now: 10 ** 12 }).ok).toBe(true); // no expiry caveat anywhere
    // an expiry inherited from the source chain tip counts too, and the earlier of two wins
    const srcExp = mk(undefined, [{ type: 'expires', at: 700 }]);
    expect(vt(srcExp, { now: 701 }).reason).toBe('translated capability expired');
    const both = mk([{ type: 'expires', at: 300 }], [{ type: 'expires', at: 700 }]);
    expect(vt(both, { now: 301 }).reason).toBe('translated capability expired');
    expect(vt(both, { now: 300 }).ok).toBe(true);
  });
  it('never throws on hostile structure', () => {
    const tc = mk();
    expect(vt({ ...tc, source: [null] })).toMatchObject({ ok: false });
    expect(vt({ ...tc, source: [{ ...tc.source[0]!, caveats: 5 }] })).toMatchObject({ ok: false });
    expect(hashCanonical(tc.caveats)).toBeTruthy();
  });
});
