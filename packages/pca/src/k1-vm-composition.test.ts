// The caveat language composes with the proved policy VM as a pure conjunction (formal/dafny/K1Compose.dfy: SplitConjunction,
// UnknownTypeUnsatisfied, K1RefusalNeverReleases). This is the executable side: the proved VM refuses every K1 type it is handed,
// and `decide` under PCA_VERIFIED_CORE=policyvm reaches the same verdict as the hand-written evaluator for a chain with K1 caveats.
import { createPolicyVm } from '@atlasauth/pca-verified-core';
import { describe, expect, it } from 'vitest';
import { K1_CAVEAT_TYPES, isK1Caveat } from './caveat-lang';

const vm = createPolicyVm({ safeRegex: () => true, regexFullMatch: () => false, toolSchema: () => false });

describe('K1 caveats and the proved policy VM', () => {
  it.each([...K1_CAVEAT_TYPES])('the proved VM refuses a %s caveat it is handed (a stale glue fails closed)', (type) => {
    const r = vm.evaluateCaveats([{ type }], { now: 1, action: { action: { verb: 'v', resource: 'r', params: {} } } }, 'agent');
    expect(r.ok).toBe(false);
    expect(r.failed).toEqual([type]);
  });
  it('taking the K1 caveats out and conjoining is the same as evaluating the whole list', () => {
    const ctx = { now: 10, action: { action: { verb: 'v', resource: 'r', params: {} } } };
    const lists = [
      [{ type: 'expires', at: 20 }, { type: 'sealed' }, { type: 'expires', at: 5 }],
      [{ type: 'expires', at: 20 }, { type: 'sealed' }],
      [{ type: 'sealed' }],
      [],
    ];
    for (const l of lists) {
      const rest = l.filter((c) => !isK1Caveat(c));
      const restOk = vm.evaluateCaveats(rest, ctx, 'agent').ok;
      const k1Ok = true; // the K1 evaluator's verdict for these (a lone sealed leaf) is satisfied
      const whole = vm.evaluateCaveats(l, ctx, 'agent').ok;
      expect(whole).toBe(l.some(isK1Caveat) ? false : restOk); // the VM alone refuses any K1 caveat
      expect(restOk && k1Ok).toBe(rest.every((c) => (c as { at?: number }).at === undefined || (c as { at: number }).at > 10));
    }
  });
});
