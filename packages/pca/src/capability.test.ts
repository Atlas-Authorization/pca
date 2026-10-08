import { describe, expect, it } from 'vitest';
import {
  allocationsMonotone,
  attenuate,
  budgetAllocCaveat,
  budgetAllocNodes,
  capHash,
  delegate,
  MAX_CHAIN_DEPTH,
  mintRoot,
  verifyChain,
  type Capability,
} from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { b64u, hashCanonical, sha256, utf8 } from './hash';

function setup() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const S = generateKeyPair();
  const root = mintRoot({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    caveats: [{ type: 'ttl', secs: 3600 }, { type: 'rate', perHour: 10 }],
  });
  return { P, A, S, root };
}

describe('capability chain', () => {
  it('mint -> attenuate -> delegate verifies', () => {
    const { P, A, S, root } = setup();
    const c1 = attenuate(root, [{ type: 'resource', prefix: '/acct' }], A.secretKey);
    const c2 = delegate(c1, encodeKey(S.publicKey), [{ type: 'depth', max: 0 }], A.secretKey);
    expect(c2.caveats).toHaveLength(4);
    expect(c2.holder).toBe(encodeKey(S.publicKey));
    expect(verifyChain([root, c1, c2], encodeKey(P.publicKey))).toEqual({ ok: true });
    expect(verifyChain([root])).toEqual({ ok: true });
  });
  it('wrong expected root issuer rejected', () => {
    const { root } = setup();
    expect(verifyChain([root], encodeKey(generateKeyPair().publicKey)).ok).toBe(false);
  });
  it('re-signed child that DROPS a parent caveat is rejected', () => {
    const { A, root } = setup();
    const good = attenuate(root, [], A.secretKey);
    const body = { issuer: good.issuer, holder: good.holder, caveats: good.caveats.slice(1), parent: good.parent! };
    const forged = forge(body, A.secretKey);
    const r = verifyChain([root, forged]);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/drops/);
  });
  it('REORDERED caveats rejected', () => {
    const { A, root } = setup();
    const good = attenuate(root, [{ type: 'x' }], A.secretKey);
    const caveats = [good.caveats[1]!, good.caveats[0]!, good.caveats[2]!];
    const r = verifyChain([root, forge({ issuer: good.issuer, holder: good.holder, caveats, parent: good.parent! }, A.secretKey)]);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/altered or reordered/);
  });
  it('LOOSENED (edited) caveat rejected', () => {
    const { A, root } = setup();
    const good = attenuate(root, [], A.secretKey);
    const caveats = [{ type: 'ttl', secs: 999999 }, good.caveats[1]!];
    const r = verifyChain([root, forge({ issuer: good.issuer, holder: good.holder, caveats, parent: good.parent! }, A.secretKey)]);
    expect(r.ok).toBe(false);
  });
  it('mutating caveats after signing breaks the digest', () => {
    const { A, root } = setup();
    const c = attenuate(root, [{ type: 'x' }], A.secretKey);
    const t: Capability = { ...c, caveats: [...c.caveats.slice(0, 2), { type: 'y' }] };
    expect(verifyChain([root, t]).ok).toBe(false);
  });
  it('hop signed by the wrong key is rejected', () => {
    const { root } = setup();
    const evil = generateKeyPair();
    const c = attenuate(root, [], evil.secretKey);
    const r = verifyChain([root, c]);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/bad signature/);
  });
  it('issuer not equal to parent holder rejected (binding continuity)', () => {
    const { root, A } = setup();
    const evil = generateKeyPair();
    const c = forge({ issuer: encodeKey(evil.publicKey), holder: root.holder, caveats: root.caveats, parent: capHash(root) }, evil.secretKey);
    expect(verifyChain([root, c])).toMatchObject({ ok: false });
    expect(A).toBeDefined();
  });
  it('broken parent link rejected', () => {
    const { P, A, root } = setup();
    const other = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
    const c = attenuate(other, [], A.secretKey);
    const r = verifyChain([root, c]);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/parent link/);
  });
  it('empty chain and rooted-with-parent rejected', () => {
    const { A, root } = setup();
    expect(verifyChain([]).ok).toBe(false);
    expect(verifyChain([attenuate(root, [], A.secretKey)]).ok).toBe(false);
  });
});

// Re-sign an arbitrary body with the real signing scheme (simulates a malicious but key-holding hop).
import { sign } from './keys';
function forge(body: { issuer: string; holder: string; caveats: unknown[]; parent: string }, secret: Uint8Array): Capability {
  const digest = hashCanonical({ issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent });
  const d = sha256(utf8('x')); void d;
  const p = utf8('atlas-pca/cap/v1\0');
  const raw = Buffer.from(digest, 'base64url');
  const m = new Uint8Array(p.length + raw.length);
  m.set(p);
  m.set(raw, p.length);
  return { id: digest, issuer: body.issuer, holder: body.holder, caveats: body.caveats as Capability['caveats'], parent: body.parent, body_digest: digest, sig: b64u(sign(secret, m)) };
}

describe('capability chain hardening (P5-3)', () => {
  it('rejects chains deeper than MAX_CHAIN_DEPTH before any signature work, accepts exactly the max', () => {
    const { A, root } = setup();
    const chain: Capability[] = [root];
    for (let i = 1; i < MAX_CHAIN_DEPTH; i++) chain.push(attenuate(chain[i - 1]!, [], A.secretKey));
    expect(verifyChain(chain).ok).toBe(true);
    chain.push(attenuate(chain[chain.length - 1]!, [], A.secretKey));
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/too long/);
  });

  it('rejects wrongly-typed hops instead of throwing', () => {
    const { A, root } = setup();
    const child = attenuate(root, [{ type: 'x' }], A.secretKey);
    const mut = (patch: Record<string, unknown>) => verifyChain([root, { ...child, ...patch } as unknown as Capability]);
    expect(mut({ caveats: 'nope' }).ok).toBe(false);
    expect(mut({ caveats: [null] }).ok).toBe(false);
    expect(mut({ caveats: [{ nottype: 1 }] }).ok).toBe(false);
    expect(mut({ sig: 5 }).ok).toBe(false);
    expect(mut({ parent: 7 }).ok).toBe(false);
    expect(verifyChain([null as unknown as Capability]).ok).toBe(false);
    expect(verifyChain([root, child]).ok).toBe(true);
  });
});

describe('per-child budget subtree: carried allocation caveat (monotone / lineage)', () => {
  it('allocationsMonotone: non-increasing passes, a widening and a malformed limit are rejected', () => {
    expect(allocationsMonotone([]).ok).toBe(true); // no allocations => single-pool path
    expect(allocationsMonotone([{ type: 'expires', at: 1 }]).ok).toBe(true); // unrelated caveats ignored
    expect(allocationsMonotone([budgetAllocCaveat(10), budgetAllocCaveat(10), budgetAllocCaveat(4)]).ok).toBe(true);
    const widen = allocationsMonotone([budgetAllocCaveat(5), budgetAllocCaveat(7)]);
    expect(widen.ok).toBe(false);
    expect(widen.reason).toMatch(/widens/);
    expect(allocationsMonotone([budgetAllocCaveat(Number.NaN)]).ok).toBe(false);
    expect(allocationsMonotone([budgetAllocCaveat(-1)]).ok).toBe(false);
  });

  it('verifyChain accepts a child allocating <= its parent and REJECTS a child that widens', () => {
    const { P, A, S, root } = setup();
    const pPub = encodeKey(P.publicKey);
    // root -> task (alloc 10) -> sub (alloc 4): monotone, verifies.
    const task = delegate(root, encodeKey(A.publicKey), [budgetAllocCaveat(10)], A.secretKey);
    const sub = delegate(task, encodeKey(S.publicKey), [budgetAllocCaveat(4)], A.secretKey);
    expect(verifyChain([root, task, sub], pPub)).toEqual({ ok: true });
    // a sibling sub that tries to allocate MORE than the parent carried (10) is rejected by chain verify.
    const widen = delegate(task, encodeKey(S.publicKey), [budgetAllocCaveat(11)], A.secretKey);
    const r = verifyChain([root, task, widen], pPub);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/widens/);
  });

  it('budgetAllocNodes: extracts one node per allocation, in root->leaf order, with monotone limits + stable keys', () => {
    const { A, S, root } = setup();
    const task = delegate(root, encodeKey(A.publicKey), [budgetAllocCaveat(10)], A.secretKey);
    const sub = delegate(task, encodeKey(S.publicKey), [budgetAllocCaveat(4)], A.secretKey);
    const nodes = budgetAllocNodes([root, task, sub]);
    expect(nodes.map((n) => n.limit)).toEqual([10, 4]);
    expect(nodes.map((n) => n.depth)).toEqual([1, 2]); // introduced at hops 1 and 2
    expect(nodes[0]!.holder).toBe(encodeKey(A.publicKey));
    expect(nodes[1]!.holder).toBe(encodeKey(S.publicKey));
    expect(new Set(nodes.map((n) => n.nodePath)).size).toBe(2); // distinct, content-addressed keys
    // a chain with no allocation caveat yields no nodes (the backward-compatible single-pool path).
    const plain = delegate(root, encodeKey(S.publicKey), [{ type: 'expires', at: Date.now() + 1000 }], A.secretKey);
    expect(budgetAllocNodes([root, plain])).toEqual([]);
  });
});
