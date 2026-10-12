// R6-CORE-07: the proved `re:` entry point must charge a DOCUMENT regex budget exactly like predicates.ts resourceMatches,
// otherwise a document with many `re:` predicates is bounded only per match (the 64-evaluation document cap is lost).
import { describe, expect, it } from 'vitest';
import { MAX_REGEX_EVALUATIONS_PER_DOCUMENT, RegexBudget } from '../../pca/src/regex-budget';
import { reMatchesVerified } from '../src/ext-regex';

describe('reMatchesVerified document budget (R6-CORE-07)', () => {
  it('70 re: predicates in one document: the match at #69 is refused, as in production', () => {
    const doc = new RegexBudget();
    const results: boolean[] = [];
    for (let i = 0; i < 70; i++) results.push(reMatchesVerified(i === 68 ? 'acct/[0-9]+' : `nomatch${i}`, 'acct/42', doc));
    expect(results.filter(Boolean)).toEqual([]);
    expect(doc.refusals).toBeGreaterThan(0);
  });
  it('within the cap it matches, and charges one evaluation per call', () => {
    const doc = new RegexBudget();
    expect(reMatchesVerified('acct/[0-9]+', 'acct/42', doc)).toBe(true);
    expect(doc.evaluations).toBe(1);
    for (let i = 1; i < MAX_REGEX_EVALUATIONS_PER_DOCUMENT; i++) reMatchesVerified('x', 'y', doc);
    expect(doc.evaluations).toBe(MAX_REGEX_EVALUATIONS_PER_DOCUMENT);
    expect(reMatchesVerified('acct/[0-9]+', 'acct/42', doc)).toBe(false);
  });
  it('patterns refused before matching (too long, unsafe, subject too long) are not charged, as in production', () => {
    const doc = new RegexBudget();
    expect(reMatchesVerified('a'.repeat(201), 'a', doc)).toBe(false);
    expect(reMatchesVerified('a', 'a'.repeat(513), doc)).toBe(false);
    expect(reMatchesVerified('(a+)+b', 'aab', doc)).toBe(false);
    expect(doc.evaluations).toBe(0);
  });
  it('cannot be called without a budget', () => {
    expect(() => (reMatchesVerified as (a: string, b: string) => boolean)('a', 'a')).toThrow(/budget/);
    expect(() => reMatchesVerified('a', 'a', null as never)).toThrow(/budget/);
  });
});
