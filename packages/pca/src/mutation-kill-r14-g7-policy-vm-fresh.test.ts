/**
 * r14 static-mutant kills for policy-vm.ts (fresh module): WORST (missing risk inputs are named and assumed worst) and
 * FAST_PATH_ELIGIBLE_CLASSES (reversible / rate_limited / costly may take the optimistic path; others may not).
 */
import { describe, expect, it, vi } from 'vitest';

async function load() {
  vi.resetModules();
  const vm = await import('./policy-vm');
  const env = await import('./envelope');
  const keys = await import('./keys');
  const risk = await import('./risk');
  return { vm, env, keys, risk };
}
const NOW = 1_800_000_000_000;
function input(m: Awaited<ReturnType<typeof load>>, rc: string | undefined, r: Record<string, number>) {
  const P = m.keys.generateKeyPair();
  const A = m.keys.generateKeyPair();
  const grant = m.env.mintGrant({
    principalSecret: P.secretKey, principalPublic: m.keys.encodeKey(P.publicKey), holder: m.keys.encodeKey(A.publicKey), goal: 'g',
    envelope: { predicates: [{ verb: 'read', resource: '*' }] as never, caveats: [] as never, agent_binding: {}, risk_policy: m.risk.DEFAULT_RISK_POLICY },
  }).grant;
  return { grant, action: { action: { verb: 'read', resource: '/r', ...(rc ? { reversibility_class: rc } : {}) } } as never, risk: r as never, budget: { B: 1, tau: NOW, asOf: NOW }, now: NOW };
}
const LOW = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };

describe('policy-vm.ts statics (fresh module)', () => {
  it('missing risk inputs are listed and scored as the worst case', async () => {
    const m = await load();
    const d = m.vm.decide(input(m, 'reversible', { age: 0 }));
    expect(d.reasons).toContain('risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence');
    expect(d.r).toBe(m.risk.riskScore({ semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 0 }, m.risk.DEFAULT_RISK_POLICY.weights));
  });
  it('only the recognised non-irreversible classes may take the optimistic path', async () => {
    const m = await load();
    const opt = (rc: string | undefined) => m.vm.decide(input(m, rc, LOW)).requiredThreshold.optimisticAllowed;
    expect(['reversible', 'rate_limited', 'costly', 'irreversible', 'other', undefined].map(opt)).toEqual([true, true, true, false, false, false]);
  });
});
