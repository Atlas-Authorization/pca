/**
 * Negative controls: every property below must FAIL against a core that has been broken on purpose. Each case swaps
 * one function of `@atlasauth/pca` for a faulty one and asserts that the matching invariant reports a counterexample.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.resetModules();
  vi.doUnmock('@atlasauth/pca');
});

async function withBroken(patch: (real: Record<string, unknown>) => Record<string, unknown>) {
  vi.resetModules();
  vi.doMock('@atlasauth/pca', async (orig) => {
    const real = (await orig()) as Record<string, unknown>;
    return { ...real, ...patch(real) };
  });
  return (await import('./properties')) as typeof import('./properties');
}

const fails = (p: { run: (n: number, s: number) => void }) => expect(() => p.run(300, 7)).toThrow();
const inv = (m: typeof import('./properties'), name: string) => m.INVARIANTS.find((i) => i.name === name)!;

describe('each invariant fails against a core that is broken on purpose', () => {
  it('admission-soundness: an admit that lets everything through unmetered', async () => {
    const m = await withBroken(() => ({ admit: () => ({ admit: true, needStepUp: false, t: 1, metered: false }) }));
    fails(inv(m, 'admission-soundness'));
  });
  it('fail-closed:unknown-caveat-type: an evaluator that accepts what it does not know', async () => {
    const m = await withBroken(() => ({ evaluateCaveats: () => ({ ok: true, failed: [] }) }));
    fails(inv(m, 'fail-closed:unknown-caveat-type'));
  });
  it('forbid-monotone: a decision procedure that lets a permit beat a forbid', async () => {
    const m = await withBroken((real) => ({
      decideClauses: (cl: { kind: string }[], ctx: unknown, o: unknown) => (real.decideClauses as (...a: unknown[]) => unknown)(cl.filter((c) => c.kind !== 'forbid'), ctx, o),
    }));
    fails(inv(m, 'forbid-monotone'));
  });
  it('fail-closed:forged-chain-rejected: a verifier that accepts every chain', async () => {
    const m = await withBroken(() => ({ verifyChain: () => ({ ok: true }) }));
    fails(inv(m, 'fail-closed:forged-chain-rejected'));
  });
  it('fail-closed:garbage-chain-rejected: a verifier that accepts every chain', async () => {
    const m = await withBroken(() => ({ verifyChain: () => ({ ok: true }) }));
    fails(inv(m, 'fail-closed:garbage-chain-rejected'));
  });
  it('determinism: a risk score that is not a function of its inputs', async () => {
    const m = await withBroken((real) => ({ riskScore: (...a: unknown[]) => (real.riskScore as (...x: unknown[]) => number)(...a) + Math.random() * 1e-3 }));
    fails(inv(m, 'determinism'));
  });
  it('risk-wellformed-and-monotone: a risk score that goes down when inputs get worse', async () => {
    const m = await withBroken((real) => ({ riskScore: (i: Record<string, number>, w: unknown) => 1 - (real.riskScore as (a: unknown, b: unknown) => number)(i, w) }));
    fails(inv(m, 'risk-wellformed-and-monotone'));
  });
  it('fail-closed:undecidable-leaf: a leaf evaluator that treats "unknown" as true', async () => {
    const m = await withBroken(() => ({ evaluateConditionTri: () => 'true', evaluateCondition: () => true }));
    fails(inv(m, 'fail-closed:undecidable-leaf'));
  });
  it('attenuation-monotonicity: a delegate that drops the parent caveats (widens authority)', async () => {
    const m = await withBroken((real) => ({
      delegate: (...a: unknown[]) => ({ ...(real.delegate as (...x: unknown[]) => Record<string, unknown>)(...a), caveats: [] }),
    }));
    fails(inv(m, 'attenuation-monotonicity'));
  });
  it('attenuation-monotonicity: a chain verifier that rejects a legally built chain', async () => {
    const m = await withBroken(() => ({ verifyChain: () => ({ ok: false }) }));
    fails(inv(m, 'attenuation-monotonicity'));
  });
  it('cumulative-budget-bound: an admit that ignores the remaining budget', async () => {
    const m = await withBroken(() => ({ admit: () => ({ admit: true, needStepUp: false, t: 1, metered: true }) }));
    fails(inv(m, 'cumulative-budget-bound'));
  });
  it('fail-closed:undecidable-groups: a tri-state evaluator that says true for everything', async () => {
    const m = await withBroken(() => ({ evaluateConditionTri: () => 'true' }));
    fails(inv(m, 'fail-closed:undecidable-groups'));
  });
  it('fail-closed:member-of-cycle-safe: an evaluator that never reaches a target through the cycle', async () => {
    const m = await withBroken(() => ({ evaluateConditionTri: () => 'false' }));
    fails(inv(m, 'fail-closed:member-of-cycle-safe'));
  });
  it('every registered invariant has a negative control above (a new invariant without one fails here)', async () => {
    const m = await withBroken(() => ({}));
    const covered = new Set([
      'admission-soundness', 'fail-closed:unknown-caveat-type', 'fail-closed:forged-chain-rejected', 'fail-closed:garbage-chain-rejected',
      'determinism', 'risk-wellformed-and-monotone', 'fail-closed:undecidable-leaf', 'attenuation-monotonicity', 'cumulative-budget-bound',
      'fail-closed:undecidable-groups', 'fail-closed:member-of-cycle-safe', 'forbid-monotone',
    ]);
    expect(m.INVARIANTS.map((i) => i.name).sort()).toEqual([...covered].sort());
  });
  it('the unbroken core passes the same cases (the control for the controls)', async () => {
    const m = await withBroken(() => ({}));
    for (const name of ['admission-soundness', 'fail-closed:unknown-caveat-type', 'fail-closed:forged-chain-rejected', 'fail-closed:garbage-chain-rejected', 'determinism', 'risk-wellformed-and-monotone', 'fail-closed:undecidable-leaf', 'attenuation-monotonicity', 'cumulative-budget-bound', 'fail-closed:undecidable-groups', 'fail-closed:member-of-cycle-safe', 'forbid-monotone']) {
      expect(() => inv(m, name).run(300, 7), name).not.toThrow();
    }
  });
});
