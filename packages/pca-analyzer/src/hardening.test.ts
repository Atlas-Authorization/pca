import { describe, expect, it } from 'vitest';
import type { Predicate } from '@atlasauth/pca';
import { alwaysAllows, alwaysDenies, disjoint, equivalent, reachable, subsumes } from './index';

const P = (where: Predicate['where'], verb: Predicate['verb'] = '*'): Predicate => ({ verb, resource: '*', where });

describe('ordering against a non-numeric operand is not decided exactly', () => {
  // Regression: `subject.role >= " "` is true for "admin" (the evaluator orders strings), but the analyzer enumerated only
  // numeric thresholds, found nothing, and "proved" the policy always denies.
  const strGte = [P([{ field: 'subject.role', op: 'gte', value: ' ' }])];
  it('alwaysDenies fails safe instead of proving a denial', () => {
    const r = alwaysDenies({ predicates: strGte });
    expect(r.alwaysDenies).toBe(false);
  });
  it('reachable fails safe', () => {
    const r = reachable({ predicates: strGte }, { verb: 'read', resource: '/x' });
    expect(r.reachable).toBe(true);
    expect(r.approximate).toBe(true);
  });
  it.each(['lt', 'lte', 'gt', 'gte'] as const)('%s with a string, boolean or array operand', (op) => {
    for (const value of ['b', true, ['x'], null]) {
      const r = alwaysDenies({ predicates: [P([{ field: 'subject.role', op, value } as never])] });
      expect(r.alwaysDenies, `${op} ${JSON.stringify(value)}`).toBe(false);
    }
  });
  it('a numeric threshold is still decided exactly', () => {
    expect(alwaysDenies({ predicates: [P([{ field: 'action.params.amount', op: 'gte', value: 100 }, { field: 'action.params.amount', op: 'lte', value: 10 }])] }).alwaysDenies).toBe(true);
    expect(alwaysDenies({ predicates: [P([{ field: 'action.params.amount', op: 'gte', value: 1 }])] }).alwaysDenies).toBe(false);
  });
  it('subsumes and disjoint never claim the safe answer on it', () => {
    const wide = [P(undefined)];
    expect(subsumes({ predicates: strGte }, { predicates: wide }).subsumes).toBe(false);
    expect(disjoint({ predicates: strGte }, { predicates: wide }).disjoint).toBe(false);
    expect(equivalent({ predicates: strGte }, { predicates: wide }).equivalent).toBe(false);
  });
});

describe('a value that is not a policy is an empty policy, and nothing throws', () => {
  it.each([[null], [undefined], [5], ['x'], [{}], [{ predicates: 'x' }], [{ predicates: null }]])('%j', (p) => {
    expect(alwaysDenies(p as never).alwaysDenies).toBe(true);
    expect(reachable(p as never, { verb: 'a', resource: 'b' }).reachable).toBe(false);
    expect(alwaysAllows(p as never, 'a').alwaysAllows).toBe(false);
  });
  it('an empty policy subsumes nothing but is subsumed by everything', () => {
    const wide = { predicates: [P(undefined)] };
    expect(subsumes(null as never, wide).subsumes).toBe(false);
    expect(subsumes(wide, null as never).subsumes).toBe(true);
  });
});

describe('the grid bound cannot be disabled', () => {
  const many = { predicates: Array.from({ length: 12 }, (_, i) => P([{ field: `action.params.f${i}`, op: 'in', value: ['a', 'b', 'c', 'd'] }, { field: `action.params.g${i}`, op: 'eq', value: i }])) };
  it.each([[-5], [Number.NaN], ['9' as never], [undefined]])('maxCombinations %j falls back to the default bound', (maxCombinations) => {
    const t = Date.now();
    const r = alwaysDenies(many, undefined, { maxCombinations });
    expect(Date.now() - t).toBeLessThan(10_000);
    expect(typeof r.alwaysDenies).toBe('boolean');
  });
  it('a bound of 0 makes every grid overflow, and the answer fails safe', () => {
    const r = alwaysDenies(many, undefined, { maxCombinations: 0 });
    expect([r.alwaysDenies, r.approximate]).toEqual([false, true]);
  });
  it('a grid larger than the bound fails safe', () => {
    const r = alwaysDenies(many, undefined, { maxCombinations: 10 });
    expect(r.alwaysDenies).toBe(false);
    expect(r.approximate).toBe(true);
  });
});
