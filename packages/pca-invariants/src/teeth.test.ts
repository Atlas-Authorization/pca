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
  it('the unbroken core passes the same cases (the control for the controls)', async () => {
    const m = await withBroken(() => ({}));
    for (const name of ['admission-soundness', 'fail-closed:unknown-caveat-type', 'fail-closed:forged-chain-rejected', 'fail-closed:garbage-chain-rejected', 'determinism', 'risk-wellformed-and-monotone', 'fail-closed:undecidable-leaf']) {
      expect(() => inv(m, name).run(300, 7), name).not.toThrow();
    }
  });
});
