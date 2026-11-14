import { describe, expect, it } from 'vitest';
import type { ActionContext, Capability, Envelope, PCActn, PolicyDecision } from '@atlasauth/pca';
import { DecisionExplanation, explainDecision, type CaveatOutcome } from './index';

const PC = {} as unknown as PCActn;
const dec = (over: object = {}): PolicyDecision =>
  ({
    admit: false,
    needStepUp: true,
    releaseGuardianShare: true,
    r: 0.4,
    requiredThreshold: { t: 2, proof: 'standard', optimisticAllowed: false },
    budget: { B: 0.5, tau: 0, asOf: 0 },
    reasons: ['kept-reason'],
    ...over,
  }) as unknown as PolicyDecision;
const envOf = (over: object = {}): Envelope =>
  ({ predicates: [{ verb: 'v' }], caveats: [], agent_binding: {}, risk_policy: { theta1: 0.2, theta2: 0.6, kappa: 2 }, ...over }) as unknown as Envelope;
const cap = (id: string, caveats: unknown[] | undefined): Capability => ({ id, issuer: 'I'.repeat(43), holder: 'H'.repeat(43), caveats }) as unknown as Capability;
const act = (verb = 'a', resource = 'r'): ActionContext => ({ action: { verb, resource } }) as unknown as ActionContext;
const EXPIRES = { type: 'expires', at: 1000 };

describe('fix line rendering', () => {
  const base = explainDecision(PC, dec());
  const CAVEAT_FIX = '              ↳ fix:'; // the decision's own fix line is indented differently
  const render = (caveats: CaveatOutcome[]): string => new DecisionExplanation({ ...base, caveats }).toText();
  it('prints a fix only for an unsatisfied caveat that has a remedy', () => {
    const mk = (satisfied: boolean, remedy?: string): CaveatOutcome => ({ type: 't', satisfied, value: {}, detail: 'd', delegated: false, ...(remedy ? { remedy } : {}) });
    expect(render([mk(false, 'do this')])).toContain('  caveat ✗  : d\n              ↳ fix: do this');
    expect(render([mk(true, 'do this')])).not.toContain(CAVEAT_FIX);
    expect(render([mk(false)])).not.toContain(CAVEAT_FIX);
    expect(render([mk(true)])).not.toContain(CAVEAT_FIX);
  });
});

describe('chain shapes that must not abort the explanation', () => {
  it('an empty chain keeps the envelope caveats and the decision reasons', () => {
    const ex = explainDecision(PC, dec(), { envelope: envOf({ caveats: [EXPIRES] }), context: { action: act('v'), chain: [] } });
    expect(ex.reasons).toEqual(['kept-reason']);
    expect(ex.caveats.map((c) => [c.type, c.delegated])).toEqual([['expires', false]]);
  });
  it('a hole at the leaf of a multi-hop chain keeps the envelope caveats and the decision reasons', () => {
    const chain = [cap('r', []), cap('m', []), undefined] as unknown as Capability[];
    const ex = explainDecision(PC, dec(), { envelope: envOf({ caveats: [EXPIRES] }), context: { action: act('v'), chain } });
    expect(ex.reasons).toEqual(['kept-reason']);
    expect(ex.caveats.map((c) => [c.type, c.delegated])).toEqual([['expires', false]]);
    expect(ex.grant.capabilityId).toBe('r');
  });
});
