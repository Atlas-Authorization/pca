/**
 * r13 mutation kills for capability.ts module-level constants (static mutants; each test re-evaluates the module):
 * the capability signature domain (checked by an independent Ed25519 verification), BUDGET_ALLOC_CAVEAT, the budget
 * node path domain, CAVEAT_LIMIT_REASON, and the toRes adapter verifyChain feeds to the verified chain walk.
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, hashCanonical, unb64u, utf8 } from './hash';
import { generateKeyPair, verifyB64u } from './keys';

async function fresh() {
  vi.resetModules();
  return import('./capability');
}
const P = generateKeyPair();
const A = generateKeyPair();
const B = generateKeyPair();

describe('capability.ts constants (fresh module)', () => {
  it('a root is signed over utf8("atlas-pca/cap/v1\\0") || body digest', async () => {
    const m = await fresh();
    const root = m.mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: [] });
    expect(root.body_digest).toBe(hashCanonical({ issuer: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: [], parent: null }));
    const d = unb64u(root.body_digest);
    const pfx = utf8('atlas-pca/cap/v1\0');
    const msg = new Uint8Array(pfx.length + d.length);
    msg.set(pfx);
    msg.set(d, pfx.length);
    expect(verifyB64u(b64u(P.publicKey), msg, root.sig)).toBe(true);
  });
  it('budget allocation caveats and node paths', async () => {
    const m = await fresh();
    expect(m.BUDGET_ALLOC_CAVEAT).toBe('budget_alloc');
    const root = m.mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: [] });
    const child = m.attenuate(root, [{ type: 'budget_alloc', limit: 5 } as never], A.secretKey);
    const nodes = m.budgetAllocNodes([root, child]);
    expect(nodes).toEqual([{ nodePath: hashCanonical({ d: 'atlas-pca/budget-node/v1', cap: child.id, i: 0 }), capId: child.id, holder: child.holder, depth: 1, caveatIndex: 0, limit: 5 }]);
  });
  it('the caveat limit reason', async () => {
    const m = await fresh();
    expect(m.CAVEAT_LIMIT_REASON).toBe('chain exceeds caveat limit (max 256 per hop, 1024 per chain)');
  });
  it('verifyChain accepts a good chain and names a bad signature', async () => {
    const m = await fresh();
    const root = m.mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: [] });
    expect(m.verifyChain([root], b64u(P.publicKey))).toEqual({ ok: true });
    const forged = m.attenuate(root, [], B.secretKey);
    const r = m.verifyChain([root, forged], b64u(P.publicKey));
    expect(r.ok).toBe(false);
    expect(typeof r.reason).toBe('string');
    expect(r.reason!.length).toBeGreaterThan(0);
  });
});
