import { describe, expect, it } from 'vitest';
import { validatePolicyAgainstSchema, verbShapes, type ActionDefLike, type PolicyInput, type VerbShape } from './index';
import { refund, refundShape } from './k2-fixtures';

const schema: VerbShape[] = [refundShape, { verb: 'stripe.list', params: { limit: { type: 'integer', min: 1, max: 100 } } }];
const codes = (p: PolicyInput, extra = {}) => validatePolicyAgainstSchema(p, schema, extra).findings.map((f) => `${f.severity}:${f.code}`).filter((c) => c !== 'warn:unbounded-money'); // money ceilings are asserted in their own test

describe('validatePolicyAgainstSchema', () => {
  it('a clean policy has no findings', () => {
    expect(validatePolicyAgainstSchema({ predicates: [refund(500)] }, schema)).toEqual({ ok: true, findings: [] });
  });

  it('an undeclared verb and an undeclared parameter are errors', () => {
    expect(codes({ predicates: [{ verb: 'stripe.payout' }] })).toEqual(['error:undeclared-verb']);
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amout', op: 'lte', value: 5 }] }] })).toEqual(['error:undeclared-param']);
  });

  it('a wildcard verb is checked against every verb; a parameter missing from some is a warning', () => {
    expect(codes({ predicates: [{ verb: '*', where: [{ field: 'action.params.amount', op: 'lte', value: 5 }] }] })).toEqual(['warn:undeclared-param']);
  });

  it('type mismatches', () => {
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: '500' }] }] })).toEqual(['error:type-mismatch']);
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.reason', op: 'eq', value: 5 }] }] })).toEqual(['error:type-mismatch']);
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.reason', op: 'lte', value: 'a' }] }] })).toEqual(['warn:ordering-on-string']);
  });

  it('enum values the schema does not have', () => {
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.reason', op: 'eq', value: 'chargeback' }] }] })).toEqual(['error:value-not-in-enum']);
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.reason', op: 'in', value: ['fraud', 'chargeback'] }] }] })).toEqual(['warn:value-not-in-enum']);
  });

  it('bounds the schema makes impossible or redundant', () => {
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'gt', value: 100000 }] }] })).toEqual(['error:out-of-range']);
    expect(codes({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lt', value: 0 }] }] })).toEqual(['error:out-of-range']);
    expect(codes({ predicates: [refund(100000)] })).toEqual(['info:redundant-bound']);
    expect(codes({ predicates: [refund(100001)] })).toEqual(['info:redundant-bound']);
    expect(codes({ predicates: [refund(99999)] })).toEqual([]);
  });

  it('an unsatisfiable predicate is flagged, as is a money verb with no ceiling', () => {
    const dead: PolicyInput = { predicates: [{ verb: 'stripe.list', where: [{ field: 'action.params.limit', op: 'gte', value: 50 }, { field: 'action.params.limit', op: 'lte', value: 10 }] }] };
    expect(codes(dead)).toEqual(['warn:unreachable-predicate']);
    expect(validatePolicyAgainstSchema({ predicates: [{ verb: 'stripe.refund' }] }, schema).findings.map((f) => f.code)).toEqual(['unbounded-money']);
  });

  it('rule 20: a unit-bearing parameter needs the matching unit tag', () => {
    const withUnit: VerbShape[] = [{ verb: 'stripe.refund', params: { amount: { type: 'integer', semantic: 'money.amount', unit: 'usd_cents' } } }];
    const p = refund(500);
    const run = (units?: Record<string, { kind: string; currency?: string; exponent?: number }>) =>
      validatePolicyAgainstSchema({ predicates: [p] }, withUnit, { units, schemaUnits: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } } }).findings.map((f) => f.code);
    expect(run({})).toEqual(['unit-missing']);
    expect(run({ 'action.params.amount': { kind: 'money', currency: 'EUR', exponent: 2 } })).toEqual(['unit-mismatch']);
    expect(run({ 'action.params.amount': { kind: 'money', currency: 'USD', exponent: 0 } })).toEqual(['unit-mismatch']);
    expect(run({ 'action.params.amount': { kind: 'money', currency: 'USD', exponent: 2 } })).toEqual([]);
    expect(run(undefined)).toEqual([]); // a grant without a units map is not checked here
  });

  it('prohibitions on an undeclared verb are a warning, not an error', () => {
    expect(codes({ predicates: [refund()], vetoes: [{ id: 'x', kind: 'deny', when: { verb: 'stripe.nope' } }] })).toEqual(['warn:undeclared-verb']);
  });

  it('accepts ActionDefs and lists schema verbs nothing grants', () => {
    const defs: ActionDefLike[] = [{ id: 'stripe.refund', params: refundShape.params }, { verb: 'stripe.void', params: {} }];
    expect(verbShapes(defs).map((s) => s.verb)).toEqual(['stripe.refund', 'stripe.void']);
    const r = validatePolicyAgainstSchema({ predicates: [refund(500)] }, defs, { listUngranted: true });
    expect(r.findings).toEqual([{ code: 'verb-not-granted', severity: 'info', where: 'stripe.void', message: "the schema declares 'stripe.void' but no predicate grants it" }]);
  });

  it('reads a signed action schema', () => {
    const doc = { v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1', units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } }, verbs: [{ verb: 'stripe.refund', kind: 'write', params: { amount: { type: 'integer', semantic: 'money.amount', sensitivity: 'material', unit: 'usd_cents', max: 1000 } } }], sig: { alg: 'ed25519', kid: 'k', value: 'x' } };
    const r = validatePolicyAgainstSchema({ predicates: [refund(5000)] }, doc as never, { units: { 'action.params.amount': { kind: 'money', currency: 'USD', exponent: 2 } } });
    expect(r.findings.map((f) => f.code)).toEqual(['redundant-bound']);
  });
});
