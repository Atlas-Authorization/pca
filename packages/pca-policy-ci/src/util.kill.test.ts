import { describe, expect, it } from 'vitest';
import type { Caveat } from '@atlasauth/pca';
import type { AnalyzerAction } from './deps';
import { describeAction, hasCaveatOfType, isDangerousVerb, isWildcardResource, num, uniq, verbsOf } from './util';

describe('verbsOf', () => {
  it('wraps a string, filters an array to its strings, and refuses anything else', () => {
    expect(verbsOf('a.b')).toEqual(['a.b']);
    expect(verbsOf(['a', 'b'])).toEqual(['a', 'b']);
    expect(verbsOf(['a', 1, null, 'b'] as never)).toEqual(['a', 'b']);
    expect(verbsOf([1, 2] as never)).toEqual([]);
    expect(verbsOf(undefined as never)).toEqual([]);
    expect(verbsOf(7 as never)).toEqual([]);
    expect(verbsOf({} as never)).toEqual([]);
  });
});

describe('num', () => {
  it('returns finite numbers only', () => {
    expect(num(5)).toBe(5);
    expect(num(0)).toBe(0);
    expect(num(-1.5)).toBe(-1.5);
    expect(num(Number.NaN)).toBeUndefined();
    expect(num(Number.POSITIVE_INFINITY)).toBeUndefined();
    expect(num(Number.NEGATIVE_INFINITY)).toBeUndefined();
    expect(num('5')).toBeUndefined();
    expect(num(null)).toBeUndefined();
    expect(num(undefined)).toBeUndefined();
  });
});

describe('isDangerousVerb', () => {
  it('matches case-insensitively by substring in either direction of case', () => {
    expect(isDangerousVerb('DB.Delete', ['delete'])).toBe(true);
    expect(isDangerousVerb('db.delete', ['DELETE'])).toBe(true);
    expect(isDangerousVerb('db.read', ['delete'])).toBe(false);
    expect(isDangerousVerb('db.delete', [])).toBe(false);
  });
});

describe('isWildcardResource', () => {
  it('admits only an omitted resource or exactly *', () => {
    expect(isWildcardResource(undefined)).toBe(true);
    expect(isWildcardResource('*')).toBe(true);
    expect(isWildcardResource('')).toBe(false);
    expect(isWildcardResource('/a/*')).toBe(false);
    expect(isWildcardResource('**')).toBe(false);
  });
});

describe('hasCaveatOfType', () => {
  it('finds a matching type and tolerates malformed members', () => {
    const cv = (t: unknown): Caveat => ({ type: t }) as Caveat;
    expect(hasCaveatOfType([cv('expires')], ['expires'])).toBe(true);
    expect(hasCaveatOfType([cv('rate'), cv('expires')], ['expires', 'x'])).toBe(true);
    expect(hasCaveatOfType([cv('rate')], ['expires'])).toBe(false);
    expect(hasCaveatOfType([], ['expires'])).toBe(false);
    expect(hasCaveatOfType([cv(5)], ['5'])).toBe(false);
    expect(hasCaveatOfType([{} as Caveat], ['expires'])).toBe(false);
    expect(() => hasCaveatOfType([null as never], ['expires'])).not.toThrow();
    expect(hasCaveatOfType([null as never], ['expires'])).toBe(false);
    expect(() => hasCaveatOfType([undefined as never], ['expires'])).not.toThrow();
    expect(hasCaveatOfType([undefined as never, 'expires' as never], ['expires'])).toBe(false);
  });
});

describe('describeAction', () => {
  const base: AnalyzerAction = { verb: 'pay', resource: '/acct/1' };
  it('renders verb and resource', () => {
    expect(describeAction(base)).toBe('pay /acct/1');
  });
  it('appends non-empty params as JSON, skips empty or missing params', () => {
    expect(describeAction({ ...base, params: { amount: 5 } })).toBe('pay /acct/1 {"amount":5}');
    expect(describeAction({ ...base, params: {} })).toBe('pay /acct/1');
  });
  it('appends the reversibility class in brackets when present', () => {
    expect(describeAction({ ...base, reversibilityClass: 'irreversible' })).toBe('pay /acct/1 [irreversible]');
    expect(describeAction({ ...base, params: { a: 1 }, reversibilityClass: 'reversible' })).toBe('pay /acct/1 {"a":1} [reversible]');
  });
});

describe('uniq', () => {
  it('keeps the first occurrence, in order', () => {
    expect(uniq([])).toEqual([]);
    expect(uniq(['a', 'b', 'a', 'c', 'b'])).toEqual(['a', 'b', 'c']);
    expect(uniq(['x', 'x', 'x'])).toEqual(['x']);
  });
});
