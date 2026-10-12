import { describe, expect, it } from 'vitest';
import { evaluatePredicates, predicateMatches, evaluateConditionTri } from './predicates';
import { withRegexBudget, chargeRegex, MAX_REGEX_EVALUATIONS_PER_DOCUMENT, MAX_REGEX_STEPS_PER_DOCUMENT, RegexBudget } from './regex-budget';
import { compileSafeRegex } from './safe-regex';

const heavy = '.*' + '[^]{64}'.repeat(24) + '.*'; // R4-05 PoC shape: 1543 NFA instructions, admitted per pattern
const act = (resource: string) => ({ action: { verb: 'read', resource } }) as never;

describe('R4-05 per-document regex budget', () => {
  it('a 150-predicate envelope of admitted heavy patterns is cut off well under the PoC cost (deterministic step accounting)', () => {
    const preds = Array.from({ length: 152 }, () => ({ verb: '*', resource: 're:' + heavy }));
    const subject = 'a'.repeat(512);
    const perEval = compileSafeRegex(heavy)!.program.length * (subject.length + 1); // worst-case NFA steps of ONE evaluation
    const poc = preds.length * perEval; // what the PoC paid with no document budget
    // The document budget is chained to an outer request budget, so its charges are observable (steps are charged BEFORE matching).
    const rb = RegexBudget.request();
    const r = rb.run(() => evaluatePredicates(preds as never, act(subject)));
    expect(r.allowed).toBe(false);
    expect(rb.steps).toBeLessThanOrEqual(MAX_REGEX_STEPS_PER_DOCUMENT);
    expect(rb.steps % perEval).toBe(0);
    expect(rb.steps / perEval).toBe(Math.floor(MAX_REGEX_STEPS_PER_DOCUMENT / perEval)); // exactly the evaluations one document affords
    expect(rb.steps * 10).toBeLessThan(poc); // an order of magnitude under the PoC cost
  });
  it('fails closed: a matching predicate placed AFTER the budget is spent is not allowed', () => {
    const preds = [
      ...Array.from({ length: 100 }, () => ({ verb: '*', resource: 're:' + heavy })),
      { verb: '*', resource: 're:a+' },
    ];
    expect(evaluatePredicates(preds as never, act('a'.repeat(100))).allowed).toBe(false);
  });
  it('a cap on the number of regex evaluations holds even for tiny patterns', () => {
    const n = MAX_REGEX_EVALUATIONS_PER_DOCUMENT;
    const preds = [...Array.from({ length: n }, () => ({ verb: '*', resource: 're:b' })), { verb: '*', resource: 're:a' }];
    expect(evaluatePredicates(preds as never, act('a')).allowed).toBe(false);
    expect(evaluatePredicates(preds.slice(-1) as never, act('a')).allowed).toBe(true);
  });
  it('ordinary policies are unaffected', () => {
    const preds = [{ verb: 'read', resource: 're:/acct/[^/]+/items/\\d+' }];
    expect(evaluatePredicates(preds as never, act('/acct/x/items/42')).allowed).toBe(true);
  });
  it('matches-conditions share the same document budget as resource patterns', () => {
    const where = Array.from({ length: 100 }, () => ({ field: 'action.resource', op: 'matches', value: heavy }));
    const ok = predicateMatches({ verb: '*', where: [{ any_of: where }] } as never, act('a'.repeat(512)));
    expect(ok).toBe(false);
    expect(evaluateConditionTri({ all_of: where } as never, act('a'.repeat(512)))).not.toBe('true');
  });
  it('scopes nest and reset: a spent scope does not leak into the next one', () => {
    withRegexBudget(() => {
      for (let i = 0; i < 100; i++) chargeRegex(heavy, 512);
      expect(chargeRegex('a', 1)).toBe(false);
    });
    expect(withRegexBudget(() => chargeRegex('a', 1))).toBe(true);
  });
});
