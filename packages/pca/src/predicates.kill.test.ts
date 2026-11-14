import { describe, expect, it } from 'vitest';
import { evaluatePredicates, namedUnmetLimitReason, type ActionContext, type Condition, type Predicate } from './predicates';

const ctx = (params: Record<string, unknown> = {}, extra: Partial<ActionContext> = {}): ActionContext => ({ action: { verb: 'v', resource: '/r', params }, ...extra });
const pred = (...where: unknown[]): Predicate[] => [{ verb: 'v', resource: '*', where: where as Condition[] }];
const leaf = (field: string, op: string, value?: unknown) => ({ field: `action.params.${field}`, op, value }) as unknown as Condition;
const why = (where: unknown, c: ActionContext = ctx({ x: 6, a: 1, b: 2, c: 3 })) => {
  const r = evaluatePredicates(pred(where), c);
  expect(r.allowed).toBe(false);
  return r.reason;
};
const NS = ' not satisfied for v on /r';

describe('limit wording per operator', () => {
  const cases: Array<[string, unknown, unknown, string]> = [
    ['eq', 5, 6, 'x == 5'],
    ['ne', 5, 5, 'x != 5'],
    ['lt', 5, 5, 'x < 5'],
    ['lte', 5, 6, 'x <= 5'],
    ['gt', 5, 5, 'x > 5'],
    ['gte', 5, 4, 'x >= 5'],
    ['in', [1, 2], 3, 'x in [1, 2]'],
    ['nin', [1, 2], 1, 'x not in [1, 2]'],
    ['prefix', 'ab', 'zz', 'x starts with "ab"'],
    ['like', 'a*', 'zz', 'x like "a*"'],
    ['matches', 'a+', 'zz', 'x matches "a+"'],
    ['is_a', 'User', 'Group::1', 'x is a "User"'],
  ];
  for (const [op, value, x, text] of cases) {
    it(`names ${op}`, () => {
      expect(why(leaf('x', op, value), ctx({ x }))).toBe(text + NS);
    });
  }
  it('names member_of', () => {
    const c = { field: 'action.params.x', op: 'member_of', value: 'g1', collection: 'env.parents' } as unknown as Condition;
    expect(why(c, ctx({ x: 'n1' }))).toBe('x member of "g1"' + NS);
  });
  it('names a reference operand by its path, and a non-string reference as <ref>', () => {
    expect(why({ field: 'action.params.x', op: 'eq', ref: 'env.limit' }, ctx({ x: 6 }, { env: { limit: 7 } }))).toBe('x == env.limit' + NS);
    expect(why({ field: 'action.params.x', op: 'eq', ref: 5 }, ctx({ x: 6 }))).toBe('x == <ref>' + NS);
  });
});

describe('limit wording for odd conditions', () => {
  it('a non-object condition is <condition>', () => {
    for (const bad of [null, 5, 'str', true]) expect(why(bad)).toBe('<condition>' + NS);
  });
  it('a non-string field is <field>, an unknown or non-string op is <condition>', () => {
    expect(why({ field: 5, op: 'eq', value: 1 })).toBe('<field> == 1' + NS);
    expect(why({ field: 'action.params.x', op: ['eq'], value: 1 })).toBe('x <condition>' + NS);
    expect(why({ field: 'action.params.x', op: 'bogus', value: 1 })).toBe('x <condition>' + NS);
  });
  it('a group with a non-array member list is <condition>, whatever its kind', () => {
    expect(why({ all_of: 'x' })).toBe('<condition>' + NS);
    expect(why({ any_of: 'x' })).toBe('<condition>' + NS);
  });
});

describe('limit wording for groups', () => {
  const a = leaf('a', 'eq', 9);
  const b = leaf('b', 'eq', 9);
  const c = leaf('c', 'eq', 9);
  it('an any_of lists its members separated by "; "', () => {
    expect(why({ any_of: [a, b] })).toBe('any of (a == 9; b == 9)' + NS);
  });
  it('nested groups are written out to two levels and then elided', () => {
    expect(why({ any_of: [{ all_of: [a, c] }] })).toBe('any of (all of (a == 9; c == 9))' + NS);
    expect(why({ any_of: [{ all_of: [{ any_of: [a] }] }] })).toBe('any of (all of ((...)))' + NS);
  });
  it('a negation is written as not (...) and is elided at depth two', () => {
    const t = leaf('a', 'eq', 1);
    expect(why({ not: t })).toBe('not (a == 1)' + NS);
    expect(why({ not: { not: { not: t } } })).toBe('not (not ((...)))' + NS);
  });
  it('shows at most eight members of a group', () => {
    const nine = Array.from({ length: 9 }, (_, i) => leaf(`k${i}`, 'eq', 9));
    const eight = Array.from({ length: 8 }, (_, i) => `k${i} == 9`).join('; ');
    expect(why({ any_of: nine }, ctx({}))).toBe(`any of (${eight})` + NS);
    expect(why({ any_of: [{ all_of: nine }] }, ctx({}))).toBe(`any of (all of (${eight}))` + NS);
  });
  it('an all_of points at its first unmet child, but only to a bounded depth', () => {
    expect(why({ all_of: [leaf('a', 'eq', 1), b, c] })).toBe('b == 9' + NS);
    const x = leaf('b', 'eq', 9);
    const deep = { all_of: [{ all_of: [{ all_of: [{ all_of: [{ all_of: [x] }] }] }] }] };
    expect(why(deep)).toBe('all of (b == 9)' + NS);
  });
});

describe('named-limit scope', () => {
  const unmet = leaf('x', 'lte', 5);
  it('is undefined without a context action, and for non-string verbs or resources', () => {
    expect(namedUnmetLimitReason(pred(unmet), undefined as never)).toBeUndefined();
    expect(namedUnmetLimitReason(pred(unmet), {} as never)).toBeUndefined();
    expect(namedUnmetLimitReason([{ verb: '*', resource: '*', where: [unmet] }], { action: { verb: 5, resource: '/r', params: { x: 6 } } } as never)).toBeUndefined();
    expect(namedUnmetLimitReason([{ verb: '*', resource: '*', where: [unmet] }], { action: { verb: 'v', resource: 7, params: { x: 6 } } } as never)).toBeUndefined();
  });
  it('is the exact sentence when a limit is unmet, and undefined when none is', () => {
    expect(namedUnmetLimitReason(pred(unmet), ctx({ x: 6 }))).toBe('x <= 5 not satisfied for v on /r');
    expect(namedUnmetLimitReason(pred(unmet), ctx({ x: 5 }))).toBeUndefined();
  });
  it('ignores a predicate that is a function carrying the right members', () => {
    const fn = Object.assign(() => 1, { verb: '*', resource: '*', where: [unmet] });
    expect(namedUnmetLimitReason([fn as unknown as Predicate], ctx({ x: 6 }))).toBeUndefined();
  });
  it('a denial without a context action still reads as no predicate permits', () => {
    expect(evaluatePredicates([{ verb: 'v', resource: 'r' }], {} as never)).toEqual({ allowed: false, reason: 'no predicate permits undefined on undefined' });
  });
});
