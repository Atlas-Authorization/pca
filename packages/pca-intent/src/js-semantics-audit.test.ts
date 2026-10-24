/**
 * Regression for the 2026-10-12 JavaScript-semantics audit: per-verb null masses are looked up and recorded as OWN keys,
 * so a verb spelled like an Object.prototype member is an ordinary verb (the conformance README states the same rule for
 * the intent names a verifier reads, the `*-proto-*` vectors of rules 16-18, and in general under "Host-language
 * strictness"). Before, a `nullMass` record without such a verb returned the inherited member
 * (`toString` -> a function, `__proto__` -> Object.prototype), the learner's prior became NaN and construction threw, and
 * an Intent Map could not record a `__proto__` verb at all (the assignment only touched the prototype).
 */
import { describe, expect, it } from 'vitest';
import type { Predicate } from '@atlasauth/pca';
import { createLearner, deriveOmega, emitIntentMap, mapLearnerOptions, type IntentSlots } from './index';

const policyFor = (verb: string) => ({
  predicates: [{ verb, resource: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 200 }, { field: 'action.params.amount', op: 'gte', value: 0 }] }] as Predicate[],
  caveats: [],
});
const slotsFor = (verb: string): IntentSlots => ({ verbs: [verb], constraints: [{ path: 'action.params.amount', max: 200, unit: 'USD' }] });

describe('null mass per verb: own keys only', () => {
  it('a verb named toString, absent from the nullMass record, takes the default 0.2 and is recorded as an own key', () => {
    const omega = deriveOmega({ policies: [policyFor('toString')], slots: slotsFor('toString') });
    const m = emitIntentMap(createLearner(omega, { nullMass: { other: 0.1 } }), 'ref-1');
    expect(Object.keys(m.learner.null_mass_ppm)).toEqual(['toString']);
    expect(Object.getOwnPropertyDescriptor(m.learner.null_mass_ppm, 'toString')?.value).toBe(200_000);
  });
  it('a recorded __proto__ verb survives the map -> learner-options round trip as an own key', () => {
    const omega = deriveOmega({ policies: [policyFor('stripe.refund')], slots: slotsFor('stripe.refund') });
    const m = emitIntentMap(createLearner(omega), 'ref-1');
    const withProto = { ...m, learner: { ...m.learner, null_mass_ppm: JSON.parse('{"__proto__": 50000, "stripe.refund": 200000}') as Record<string, number> } };
    const nm = mapLearnerOptions(withProto).nullMass as Record<string, number>;
    expect(Object.keys(nm)).toEqual(['__proto__', 'stripe.refund']);
    expect(Object.getOwnPropertyDescriptor(nm, '__proto__')?.value).toBe(0.05);
    expect(Object.getPrototypeOf(nm)).toBe(Object.prototype);
  });
});
