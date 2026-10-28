/** Differential tests for the approvals.ts mutants listed as equivalent: the behaviour the mutant would introduce is shown to be identical. */
import { describe, expect, it } from 'vitest';
import { buildGoalLineage, classApprovalCovers, approveClass, reviewAction } from './approvals';
import { agent, type Agent } from './facade';
import { generateKeyPair } from './keys';
import { goalCommitOf } from './envelope';

const real = agent({ principal: generateKeyPair(), goal: 'g', permissions: { s: ['p'] }, limits: {}, aud: 'a', now: 0 });
const mk = (spec: Record<string, unknown>): Agent => ({ ...real, policy: { ...real.policy, actions: [spec] } }) as unknown as Agent;

describe('equivalence: approvals', () => {
  it('EQ-APR-1 amountField undefined looks up params["undefined"], which the key summary prints identically', () => {
    const d = buildGoalLineage(mk({ verb: 'v', blastRadius: 0.1 }), 'v', 'r', { undefined: 5 }).chain[2]!.detail;
    expect(d).toBe('undefined=5');
  });
  it('EQ-APR-2 an empty commitment is never opened by any (goal, salt)', () => {
    for (const salt of ['', 'S', 'x'.repeat(64)]) expect(goalCommitOf('g', salt)).not.toBe('');
  });
  it('EQ-APR-3 a numeric salt has no length, so it is rejected by the length test as well', () => {
    expect((5 as unknown as string).length > 0).toBe(false);
  });
  it('EQ-APR-4 a bare "*" resource pattern behaves as the prefix-"*" rule (empty prefix) does', () => {
    const star = approveClass(['a'], { ttlMs: 10, by: 'x', now: 0, resource: '*' });
    for (const r of ['', 'a', 'acct:1']) expect(classApprovalCovers(star, 'a', r, 1)).toBe(true);
    expect(''.startsWith('*'.slice(0, -1))).toBe(true);
  });
  it('EQ-APR-5 opts.goal undefined passes {goal: undefined}, which buildGoalLineage treats as absent', () => {
    const a = { ...real, dryRun: () => ({ allowed: true, t: 2 }) } as unknown as Agent;
    const r = reviewAction(a, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 1 });
    expect(r.kind === 'step_up' && 'goal' in r.request.lineage).toBe(false);
    expect('goal' in buildGoalLineage(real, 'v', 'r', undefined, { goal: undefined })).toBe(false);
  });
});
