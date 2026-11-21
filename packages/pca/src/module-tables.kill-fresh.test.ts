/**
 * Module-load tables re-evaluated per test (vi.resetModules + dynamic import): the reversibility class ranks and the
 * operator spellings used in limit-naming denial reasons.
 */
import { describe, expect, it, vi } from 'vitest';

describe('reversibility class ranks (fresh module)', () => {
  it('the table and classRank: known classes by tier, anything else most restrictive', async () => {
    vi.resetModules();
    const r = await import('./reversibility');
    expect(r.CLASS_RANK).toEqual({ reversible: 0, rate_limited: 1, costly: 1, irreversible: 2 });
    expect([r.classRank('reversible'), r.classRank('rate_limited'), r.classRank('costly'), r.classRank('irreversible')]).toEqual([0, 1, 1, 2]);
    expect([r.classRank('unknown'), r.classRank(undefined), r.classRank(1), r.classRank('constructor')]).toEqual([2, 2, 2, 2]);
  });
});

describe('operator spellings in denial reasons (fresh module)', () => {
  it('every operator is spelled with its own text', async () => {
    vi.resetModules();
    const p = await import('./predicates');
    const why = (op: string, value: unknown) =>
      p.evaluatePredicates([{ verb: 'pay', resource: 'acct/*', where: [{ field: 'action.params.a', op, value } as never] }], { action: { verb: 'pay', resource: 'acct/1', params: {} } }).reason;
    const s = ' not satisfied for pay on acct/1';
    expect(why('eq', 1)).toBe(`a == 1${s}`);
    expect(why('ne', true)).toBe(`a != true${s}`);
    expect(why('lt', 1)).toBe(`a < 1${s}`);
    expect(why('lte', 1)).toBe(`a <= 1${s}`);
    expect(why('gt', 1)).toBe(`a > 1${s}`);
    expect(why('gte', 1)).toBe(`a >= 1${s}`);
    expect(why('in', ['x'])).toBe(`a in ["x"]${s}`);
    expect(why('nin', ['x'])).toBe(`a not in ["x"]${s}`);
    expect(why('prefix', 'p/')).toBe(`a starts with "p/"${s}`);
    expect(why('like', 'x*')).toBe(`a like "x*"${s}`);
    expect(why('matches', '^x')).toBe(`a matches "^x"${s}`);
    expect(why('is_a', 'T')).toBe(`a is a "T"${s}`);
    expect(why('member_of', 'g')).toBe(`a member of "g"${s}`);
  });
});
