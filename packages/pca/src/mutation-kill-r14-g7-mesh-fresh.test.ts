/**
 * r14 static-mutant kills for mesh.ts (fresh module). Every domain-separated signature (head, cosignature, binding,
 * action, translated capability, cross-reference anchor) is checked with a plain Ed25519 verify over
 * utf8(domain) || canonical(body); the action digest against hashCanonical; plus DEFAULT_MAX_HEAD_AGE_MS, the known
 * caveat types of effectiveAuthority, the `own` helper (federated budget), `bytes` (proof size) and isCaveatArray.
 */
import { describe, expect, it, vi } from 'vitest';
import { capHash } from './capability';
import { canonicalBytes, hashCanonical, utf8 } from './hash';
import { verifyB64u } from './keys';

async function fresh() {
  vi.resetModules();
  return import('./mesh');
}
const msg = (domain: string, body: unknown) => {
  const b = canonicalBytes(body);
  const p = utf8(domain);
  const m = new Uint8Array(p.length + b.length);
  m.set(p);
  m.set(b, p.length);
  return m;
};
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};

describe('mesh.ts statics (fresh module)', () => {
  it('head, cosignature, binding and action signatures use their documented domains', async () => {
    const m = await fresh();
    const ex = m.buildMeshExample();
    const ch = ex.heads.A;
    expect(verifyB64u(ch.head.domain, msg('atlas-pca/mesh-head/v1\0', ch.head), ch.sig)).toBe(true);
    const c = ch.cosigs[0]!;
    expect(verifyB64u(c.witness, msg('atlas-pca/mesh-cosig/v1\0', ch.head), c.sig)).toBe(true);
    const b = ex.bindings.tool;
    expect(verifyB64u(b.domain, msg('atlas-pca/mesh-binding/v1\0', { agent: b.agent, domain: b.domain, role: b.role }), b.sig)).toBe(true);
    const tip = ex.chain[ex.chain.length - 1]!;
    expect(verifyB64u(tip.holder, msg('atlas-pca/mesh-action/v1\0', { action: ex.proof.action, tip: capHash(tip) }), ex.proof.action_sig)).toBe(true);
  });
  it('a translated capability and a cross-reference anchor use theirs; the action digest too', async () => {
    const m = await fresh();
    const ex = m.buildMeshExample();
    const r = settle(() => m.translateCapability(ex.chain, { fromGuardian: 'A', toGuardian: 'B', bridgeSecret: new Uint8Array(32).fill(6), issued_at: 5, additionalCaveats: [{ type: 'max_hops', n: 1 } as never] }));
    expect(r.ok).toBe(true);
    const tc = (r as { value: ReturnType<typeof m.translateCapability> }).value;
    const body = { v: 'atlas-pca/mesh-xcap/v1', from: 'A', to: 'B', source_tip: tc.source_tip, caveats: tc.caveats, issued_at: 5 };
    expect(verifyB64u(tc.bridge, msg('atlas-pca/mesh-xcap/v1\0', body), tc.sig)).toBe(true);
    const an = m.anchorCrossReference(new Uint8Array(32).fill(8), 'c0mmit', 3);
    expect(verifyB64u(an.domain, msg('atlas-pca/mesh-xanchor/v1\0', { commit: 'c0mmit', seq: 3 }), an.sig)).toBe(true);
    expect(m.meshActionDigest(ex.proof.action)).toBe(hashCanonical({ v: 'atlas-pca/mesh-action-digest/v1\0', action: ex.proof.action }));
  });
  it('DEFAULT_MAX_HEAD_AGE_MS, known caveat types, proof size', async () => {
    const m = await fresh();
    expect(m.DEFAULT_MAX_HEAD_AGE_MS).toBe(300_000);
    const all = [
      { type: 'scope', actions: ['a'] }, { type: 'resource', prefix: '/x' }, { type: 'max_amount', max: 5 },
      { type: 'expires', at: 9 }, { type: 'audience', domains: ['d'] }, { type: 'max_hops', n: 2 },
    ];
    expect(m.effectiveAuthority(all as never)).toEqual({ actions: ['a'], prefixes: ['/x'], maxAmount: 5, expiresAt: 9, audience: ['d'], maxHops: 2 });
    expect(m.effectiveAuthority([{ type: 'nope' }] as never)).toEqual({ error: 'unknown caveat type "nope" (fail closed)' });
    const ex = m.buildMeshExample();
    expect(m.meshProofSize(ex.proof).total_bytes).toBe(canonicalBytes(ex.proof).length);
  });
  it('the federated budget reads own nodes', async () => {
    const m = await fresh();
    const s = m.createFederatedBudget({ rootId: 'root', rootDomain: 'A', B0: 1, kappa: 1, bMax: 1 });
    expect(s.ok).toBe(true);
    const st = (s as { state: Parameters<typeof m.allocateSub>[0] }).state;
    const a = m.allocateSub(st, { id: 'kid', domain: 'B', parent: 'root', alloc: 0.5 });
    expect(a.ok).toBe(true);
    expect(m.allocateSub(st, { id: 'kid2', domain: 'B', parent: 'toString', alloc: 0.1 })).toEqual({ ok: false, reason: 'unknown parent' });
  });
});
