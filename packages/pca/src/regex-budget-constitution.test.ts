import { describe, expect, it } from 'vitest';
import { checkAndAdvance, checkProhibitions, emptyState, type Constitution } from './prohibitions';
import { checkContract } from './contracts';
import { RegexBudget, setRegexBudgetProvider, chargeRegex, regexRefusals, withRegexBudget, REGEX_REQUEST_SCALE, MAX_REGEX_EVALUATIONS_PER_DOCUMENT } from './regex-budget';

const heavy = '.*' + '[^]{64}'.repeat(24) + '.*';
const act = (resource: string) => ({ action: { verb: 'read', resource }, env: {} }) as never;
const constitutionOf = (n: number, re: string): Constitution =>
  ({ version: 1, principal: 'P'.repeat(43), invariants: Array.from({ length: n }, (_, i) => ({ id: `n${i}`, kind: 'never', when: { verb: '*', resource: 're:' + re } })) }) as never;

describe('R5-API-01 constitution evaluation shares one document regex budget', () => {
  it('256 heavy invariants: cost is capped to one document (PoC: 182 ms checkProhibitions, 417 ms checkAndAdvance unbounded)', () => {
    const c = constitutionOf(256, heavy);
    const a = act('a'.repeat(512));
    checkProhibitions(a, c, emptyState(1)); // warm
    const rb = RegexBudget.request();
    const r = rb.run(() => checkProhibitions(a, c, emptyState(1)));
    // deterministic cost bound (timing is machine-dependent): the whole constitution charged at most ONE document's steps
    expect(rb.steps).toBeLessThanOrEqual(5_000_000);
    expect(rb.evaluations).toBeLessThanOrEqual(MAX_REGEX_EVALUATIONS_PER_DOCUMENT);
    expect(r.ok).toBe(false);
    // the budget cut the constitution off (far fewer evaluations were charged than there are invariants) and the work is a
    // pure function of the input
    expect(rb.evaluations).toBeGreaterThan(0);
    expect(rb.evaluations).toBeLessThan(c.invariants.length);
    const rb2 = RegexBudget.request();
    rb2.run(() => checkProhibitions(a, c, emptyState(1)));
    expect([rb2.steps, rb2.evaluations, rb2.chars]).toEqual([rb.steps, rb.evaluations, rb.chars]);
    // checkAndAdvance evaluates the constitution ONCE for both the evidence and the decision: exactly one document
    const rb3 = RegexBudget.request();
    rb3.run(() => checkAndAdvance(true, a, c, emptyState(1)));
    expect(rb3.steps).toBe(rb.steps);
    expect(rb3.evaluations).toBe(rb.evaluations);
  });
  it('fail closed: a veto whose regex is REFUSED by the budget still applies', () => {
    // 64 harmless non-matching regex invariants burn the evaluation budget; the 65th would match "secret" but is refused.
    const inv = Array.from({ length: MAX_REGEX_EVALUATIONS_PER_DOCUMENT }, (_, i) => ({ id: `b${i}`, kind: 'never', when: { verb: '*', resource: 're:zzz' } }));
    inv.push({ id: 'veto', kind: 'never', when: { verb: '*', resource: 're:secret' } });
    const r = checkProhibitions(act('secret'), { version: 1, principal: 'P'.repeat(43), invariants: inv } as never, emptyState(1));
    expect(r.violated).toContain('veto');
    // and a non-matching action also trips the refused veto (cannot decide => veto), never silently passes
    const r2 = checkProhibitions(act('public'), { version: 1, principal: 'P'.repeat(43), invariants: inv } as never, emptyState(1));
    expect(r2.violated).toContain('veto');
  });
  it('ordinary constitutions are unaffected and deterministic', () => {
    const c = constitutionOf(3, '/secret/.*');
    expect(checkProhibitions(act('/pub/x'), c, emptyState(1)).ok).toBe(true);
    expect(checkProhibitions(act('/secret/x'), c, emptyState(1)).ok).toBe(false);
    const r1 = checkAndAdvance(true, act('/pub/x'), c, emptyState(1));
    const r2 = checkAndAdvance(true, act('/pub/x'), c, emptyState(1));
    expect(r1.allow).toBe(true);
    expect(r2.evidence).toEqual(r1.evidence);
  });
  it('a contract (embedded constitution + clauses) is one document', () => {
    const inv = Array.from({ length: 200 }, (_, i) => ({ id: `c${i}`, kind: 'never', when: { verb: '*', resource: 're:' + heavy } }));
    const rb = RegexBudget.request();
    const r = rb.run(() => checkContract(act('a'.repeat(512)), { version: 1, principal: 'P'.repeat(43), invariants: inv, clauses: [] } as never, emptyState(1)));
    expect(r.ok).toBe(false);
    expect(rb.steps).toBeLessThanOrEqual(5_000_000); // ONE document's steps, not 200 x
  });
});

describe('R5-API-01 request-scoped budget object', () => {
  it('documents inside a request budget share its (scaled) cap', () => {
    const rb = RegexBudget.request();
    const c = constitutionOf(64, 'a');
    let refusedAny = 0;
    rb.run(() => {
      for (let i = 0; i < REGEX_REQUEST_SCALE + 2; i++) {
        checkProhibitions(act('b'), c, emptyState(1));
        refusedAny = rb.refusals;
      }
    });
    expect(rb.evaluations).toBeGreaterThan(MAX_REGEX_EVALUATIONS_PER_DOCUMENT * REGEX_REQUEST_SCALE);
    expect(refusedAny).toBeGreaterThan(0);
  });
  it('outside every scope an evaluation is still budgeted (never unbudgeted)', () => {
    expect(chargeRegex('a', 1)).toBe(true);
    expect(chargeRegex('(', 1)).toBe(false); // uncompilable is refused
    expect(regexRefusals()).toBe(0);
  });
  it('document scopes are fresh per call and join when nested', () => {
    withRegexBudget(() => {
      for (let i = 0; i < 100; i++) chargeRegex('a', 1);
      expect(chargeRegex('a', 1)).toBe(false);
      withRegexBudget(() => expect(chargeRegex('a', 1)).toBe(false)); // joined, still spent
    });
    expect(withRegexBudget(() => chargeRegex('a', 1))).toBe(true);
  });
});

describe('R5-API-01 ambient (server) request budget provider', () => {
  it('documents opened with no explicit scope chain to the provider budget', () => {
    const rb = RegexBudget.request();
    setRegexBudgetProvider(() => rb);
    try {
      checkProhibitions(act('b'), constitutionOf(2, 'a'), emptyState(1));
      expect(rb.evaluations).toBe(2);
      chargeRegex('a', 1); // outside any document scope: still charged to the request budget
      expect(rb.evaluations).toBe(3);
    } finally {
      setRegexBudgetProvider(null);
    }
  });
});
