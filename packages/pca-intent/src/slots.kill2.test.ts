import { describe, expect, it } from 'vitest';
import { slotsToPolicy } from './slots';

const P = 'action.params.amount';

describe('slotsToPolicy: every constraint kind, exactly', () => {
  it('min, max, oneOf, prefixOneOf and noneOf compile to their literal conditions in order', () => {
    const noneOf = ['z'];
    const pol = slotsToPolicy({
      verbs: ['v.a'],
      constraints: [{ path: P, min: 0, max: 9, oneOf: ['a', 'b'], noneOf }],
    });
    expect(pol).toEqual({
      predicates: [
        {
          verb: 'v.a',
          resource: '*',
          where: [
            { field: P, op: 'gte', value: 0 },
            { field: P, op: 'lte', value: 9 },
            { field: P, op: 'in', value: ['a', 'b'] },
            { field: P, op: 'nin', value: ['z'] },
          ],
        },
      ],
      caveats: [],
    });
    const w = pol.predicates[0]!.where as { value: unknown }[];
    expect(w[3]!.value).not.toBe(noneOf);
  });
  it('a lone prefix is a leaf; oneOf plus prefixes is an any_of in that order; a lone prefix list of two is any_of', () => {
    expect(slotsToPolicy({ verbs: ['v'], constraints: [{ path: 'action.resource', prefixOneOf: ['/a/'] }] }).predicates[0]!.where).toEqual([
      { field: 'action.resource', op: 'prefix', value: '/a/' },
    ]);
    expect(slotsToPolicy({ verbs: ['v'], constraints: [{ path: 'action.resource', prefixOneOf: ['/a/', '/b/'] }] }).predicates[0]!.where).toEqual([
      { any_of: [{ field: 'action.resource', op: 'prefix', value: '/a/' }, { field: 'action.resource', op: 'prefix', value: '/b/' }] },
    ]);
    expect(slotsToPolicy({ verbs: ['v'], constraints: [{ path: 'action.resource', oneOf: ['/x'], prefixOneOf: ['/a/'] }] }).predicates[0]!.where).toEqual([
      { any_of: [{ field: 'action.resource', op: 'in', value: ['/x'] }, { field: 'action.resource', op: 'prefix', value: '/a/' }] },
    ]);
  });
  it('min 0 still counts (not just truthy), and an empty noneOf adds nothing', () => {
    expect(slotsToPolicy({ verbs: ['v'], constraints: [{ path: P, min: 0, noneOf: [] }] }).predicates[0]!.where).toEqual([{ field: P, op: 'gte', value: 0 }]);
    expect(slotsToPolicy({ verbs: ['v'], constraints: [{ path: P, noneOf: [] }] }).predicates).toEqual([{ verb: 'v', resource: '*' }]);
  });
  it('a verb-scoped constraint applies only to its verb; an unscoped one to every verb', () => {
    const pol = slotsToPolicy({
      verbs: ['v.a', 'v.b'],
      constraints: [{ verb: 'v.a', path: P, max: 1 }, { path: P, min: 5 }],
    });
    expect(pol.predicates).toEqual([
      { verb: 'v.a', resource: '*', where: [{ field: P, op: 'lte', value: 1 }, { field: P, op: 'gte', value: 5 }] },
      { verb: 'v.b', resource: '*', where: [{ field: P, op: 'gte', value: 5 }] },
    ]);
  });
});
