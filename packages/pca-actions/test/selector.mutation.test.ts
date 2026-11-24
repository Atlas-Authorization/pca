import { describe, expect, it } from 'vitest';
import { allowSelectorError, policyDecision, selectorHasNot, selectorMatches, selectorMatchesFor, type Selector, type TraitPolicy } from '../src';

const t = (id: string): Selector => ({ k: 'trait', id });
const cl = (...ids: string[]): ReadonlySet<string> => new Set(ids);

describe('selectorMatches', () => {
  it('trait', () => {
    expect(selectorMatches(t('a'), cl('a'))).toBe(true);
    expect(selectorMatches(t('a'), cl('b'))).toBe(false);
  });
  it('all_of needs every id (and is true for none)', () => {
    const s = (...ids: string[]): Selector => ({ k: 'all_of', ids });
    expect(selectorMatches(s('a', 'b'), cl('a', 'b', 'c'))).toBe(true);
    expect(selectorMatches(s('a', 'b'), cl('a'))).toBe(false);
    expect(selectorMatches(s('a'), cl('a'))).toBe(true);
    expect(selectorMatches(s('a'), cl())).toBe(false);
    expect(selectorMatches(s(), cl())).toBe(true);
  });
  it('any_of needs at least one id (and is false for none)', () => {
    const s = (...ids: string[]): Selector => ({ k: 'any_of', ids });
    expect(selectorMatches(s('a', 'b'), cl('a'))).toBe(true);
    expect(selectorMatches(s('a', 'b'), cl('b'))).toBe(true);
    expect(selectorMatches(s('a', 'b'), cl('c'))).toBe(false);
    expect(selectorMatches(s('a'), cl())).toBe(false);
    expect(selectorMatches(s(), cl('a'))).toBe(false);
  });
  it('not negates', () => {
    expect(selectorMatches({ k: 'not', s: t('a') }, cl())).toBe(true);
    expect(selectorMatches({ k: 'not', s: t('a') }, cl('a'))).toBe(false);
    expect(selectorMatches({ k: 'not', s: { k: 'not', s: t('a') } }, cl('a'))).toBe(true);
  });
  it('and is the conjunction', () => {
    const s: Selector = { k: 'and', a: t('a'), b: t('b') };
    expect(selectorMatches(s, cl('a', 'b'))).toBe(true);
    expect(selectorMatches(s, cl('a'))).toBe(false);
    expect(selectorMatches(s, cl('b'))).toBe(false);
    expect(selectorMatches(s, cl())).toBe(false);
  });
});

describe('selectorMatchesFor', () => {
  it('an unconfirmed action matches every prohibit and no allow, whatever the selector says', () => {
    expect(selectorMatchesFor(t('a'), 'prohibit', cl(), false)).toBe(true);
    expect(selectorMatchesFor({ k: 'not', s: t('a') }, 'prohibit', cl('a'), false)).toBe(true);
    expect(selectorMatchesFor(t('a'), 'allow', cl('a'), false)).toBe(false);
  });
  it('a confirmed action is matched by its closure', () => {
    expect(selectorMatchesFor(t('a'), 'prohibit', cl(), true)).toBe(false);
    expect(selectorMatchesFor(t('a'), 'allow', cl('a'), true)).toBe(true);
  });
});

describe('selectorHasNot', () => {
  it('finds a negation anywhere under and, and nowhere else', () => {
    const n: Selector = { k: 'not', s: t('a') };
    expect(selectorHasNot(n)).toBe(true);
    expect(selectorHasNot({ k: 'and', a: t('a'), b: n })).toBe(true);
    expect(selectorHasNot({ k: 'and', a: n, b: t('a') })).toBe(true);
    expect(selectorHasNot({ k: 'and', a: t('a'), b: { k: 'and', a: t('b'), b: n } })).toBe(true);
    expect(selectorHasNot({ k: 'and', a: t('a'), b: t('b') })).toBe(false);
    expect(selectorHasNot(t('a'))).toBe(false);
    expect(selectorHasNot({ k: 'all_of', ids: ['a'] })).toBe(false);
    expect(selectorHasNot({ k: 'any_of', ids: ['a'] })).toBe(false);
  });
});

describe('allowSelectorError', () => {
  const NOT = 'an allow selector must not use negation: the absence of a trait is never a safety claim';
  const ANY = 'any_of in an allow selector requires the grant to be pinned to a pack digest';
  const any: Selector = { k: 'any_of', ids: ['a', 'b'] };
  it('refuses negation, pinned or not', () => {
    expect(allowSelectorError({ k: 'not', s: t('a') }, true)).toBe(NOT);
    expect(allowSelectorError({ k: 'and', a: t('a'), b: { k: 'not', s: t('b') } }, false)).toBe(NOT);
  });
  it('refuses any_of unless pinned, at any depth under and', () => {
    expect(allowSelectorError(any, false)).toBe(ANY);
    expect(allowSelectorError({ k: 'and', a: t('a'), b: any }, false)).toBe(ANY);
    expect(allowSelectorError({ k: 'and', a: any, b: t('a') }, false)).toBe(ANY);
    expect(allowSelectorError({ k: 'and', a: t('a'), b: { k: 'and', a: t('b'), b: any } }, false)).toBe(ANY);
    expect(allowSelectorError(any, true)).toBeNull();
    expect(allowSelectorError({ k: 'and', a: t('a'), b: any }, true)).toBeNull();
  });
  it('accepts positive selectors without any_of', () => {
    expect(allowSelectorError(t('a'), false)).toBeNull();
    expect(allowSelectorError({ k: 'and', a: t('a'), b: t('b') }, false)).toBeNull();
    expect(allowSelectorError({ k: 'all_of', ids: ['a'] }, false)).toBeNull();
  });
});

describe('policyDecision', () => {
  const base: TraitPolicy = { pinned: ['v.one'], allow: [t('a')], prohibit: [t('bad')] };
  it('a matching prohibit denies, even outside the pinned set under escalate', () => {
    expect(policyDecision(base, 'v.one', cl('a', 'bad'), true)).toBe('deny');
    expect(policyDecision({ ...base, on_new_action: 'escalate' }, 'v.new', cl('bad'), true)).toBe('deny');
  });
  it('an unconfirmed action is denied by any prohibit selector, even one that does not match its closure', () => {
    expect(policyDecision({ ...base, on_new_action: 'escalate' }, 'v.new', cl('a'), false)).toBe('deny');
    expect(policyDecision({ ...base, on_new_action: 'escalate' }, 'v.new', cl('a'), true)).toBe('escalate');
    expect(policyDecision(base, 'v.one', cl('a'), false)).toBe('deny');
  });
  it('an unpinned verb is denied or escalated, never allowed', () => {
    expect(policyDecision(base, 'v.new', cl('a'), true)).toBe('deny');
    expect(policyDecision({ ...base, on_new_action: 'deny' }, 'v.new', cl('a'), true)).toBe('deny');
    expect(policyDecision({ ...base, on_new_action: 'escalate' }, 'v.new', cl('a'), true)).toBe('escalate');
  });
  it('a pinned verb is allowed by a matching allow and denied otherwise', () => {
    expect(policyDecision(base, 'v.one', cl('a'), true)).toBe('allow');
    expect(policyDecision(base, 'v.one', cl('c'), true)).toBe('deny');
    expect(policyDecision({ ...base, allow: [] }, 'v.one', cl('a'), true)).toBe('deny');
  });
});
