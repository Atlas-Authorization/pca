/**
 * Mutation-kill tests for regex-budget.ts: exact accounting (evaluations / chars / steps / refusals), every cap on both
 * sides of its boundary at document and request scale, scope joining, and the cache source walk. Modules are imported
 * statically (NO vi.resetModules: re-evaluating safe-regex.ts inside a test would make its module-level tables count as
 * covered by these tests only, hiding them from the suites that do test them).
 */
import { describe, expect, it } from 'vitest';
import * as budgetMod from './regex-budget';
import * as cacheMod from './regex-cache';

async function fresh() {
  return { ...budgetMod, ...cacheMod };
}

describe('RegexBudget accounting', () => {
  it('defaults to a top-level document budget', async () => {
    const { RegexBudget } = await fresh();
    const b = new RegexBudget();
    expect(b.isDocument).toBe(true);
    expect(b.parentBudget).toBeNull();
    const c = new RegexBudget(1, b);
    expect(c.parentBudget).toBe(b);
  });
  it('an uncompilable pattern is refused and counted as ONE refusal', async () => {
    const { RegexBudget } = await fresh();
    const b = new RegexBudget();
    expect(b.charge('(', 1)).toBe(false);
    expect(b.refusals).toBe(1);
    expect(b.evaluations).toBe(0);
  });
  it('chars add the source length; steps add program length x (subject length + 1)', async () => {
    const { RegexBudget } = await fresh();
    const b = new RegexBudget();
    expect(b.charge('abc', 0)).toBe(true);
    expect(b.chars).toBe(3);
    const l = b.steps; // program length of 'abc' x 1
    expect(l).toBeGreaterThan(0);
    expect(b.charge('abc', 9)).toBe(true);
    expect(b.steps).toBe(l + l * 10);
    expect(b.chars).toBe(6);
    expect(b.evaluations).toBe(2);
  });
  it('document source-size cap is inclusive (8192), then refuses', async () => {
    const { RegexBudget, MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT } = await fresh();
    const b = new RegexBudget();
    const p = 'a'.repeat(256);
    for (let i = 0; i < MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT / 256; i++) expect(b.charge(p, 0), String(i)).toBe(true);
    expect(b.chars).toBe(MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT);
    expect(b.charge('a', 0)).toBe(false);
  });
  it('request scale multiplies the evaluation and source-size caps', async () => {
    const { RegexBudget, MAX_REGEX_EVALUATIONS_PER_DOCUMENT, REGEX_REQUEST_SCALE } = await fresh();
    const r = RegexBudget.request();
    for (let i = 0; i < MAX_REGEX_EVALUATIONS_PER_DOCUMENT * REGEX_REQUEST_SCALE; i++) expect(r.charge('a', 0), String(i)).toBe(true);
    expect(r.charge('a', 0)).toBe(false);
    const r2 = RegexBudget.request();
    const p = 'a'.repeat(256);
    for (let i = 0; i < 9; i++) expect(r2.charge(p, 0), String(i)).toBe(true); // 2304 chars: over 8192/4, under 8192*4
  });
  it('the step cap is inclusive at exactly 5,000,000', async () => {
    const { RegexBudget, MAX_REGEX_STEPS_PER_DOCUMENT } = await fresh();
    let done = false;
    for (let n = 1; n <= 12 && !done; n++) {
      const src = 'a'.repeat(n);
      const probe = new RegexBudget();
      probe.charge(src, 0);
      const len = probe.steps;
      if (MAX_REGEX_STEPS_PER_DOCUMENT % len !== 0) continue;
      const subject = MAX_REGEX_STEPS_PER_DOCUMENT / len - 1;
      const b = new RegexBudget();
      expect(b.charge(src, subject)).toBe(true);
      expect(b.steps).toBe(MAX_REGEX_STEPS_PER_DOCUMENT);
      const c = new RegexBudget();
      expect(c.charge(src, subject + 1)).toBe(false);
      done = true;
    }
    expect(done).toBe(true);
  });
});

describe('scopes', () => {
  it('an explicit budget is used', async () => {
    const { RegexBudget, withRegexBudget, chargeRegex } = await fresh();
    const b = new RegexBudget();
    expect(withRegexBudget(() => chargeRegex('a', 0), b)).toBe(true);
    expect(b.evaluations).toBe(1);
  });
  it('a nested document scope JOINS the open document budget (refusals seen inside)', async () => {
    const { RegexBudget, withRegexBudget, chargeRegex, regexRefusals } = await fresh();
    const b = new RegexBudget();
    expect(
      b.run(() => {
        chargeRegex('(', 0);
        return withRegexBudget(() => regexRefusals());
      }),
    ).toBe(1);
    expect(
      withRegexBudget(() => {
        chargeRegex('(', 0);
        return withRegexBudget(() => regexRefusals());
      }),
    ).toBe(1);
  });
});

describe('regex cache source of the current budget', () => {
  it('a document budget inside a request budget uses the request source', async () => {
    const { RegexBudget, withRegexBudget, regexCacheGet, regexCacheStats } = await fresh();
    RegexBudget.request('S').run(() => withRegexBudget(() => regexCacheGet('k1', () => 1, () => 1)));
    expect(regexCacheStats().bySource['S']).toBe(1);
  });
  it('outside any scope the ambient request budget supplies the source', async () => {
    const { RegexBudget, setRegexBudgetProvider, regexCacheGet, regexCacheStats } = await fresh();
    const amb = RegexBudget.request('amb');
    setRegexBudgetProvider(() => amb);
    regexCacheGet('k2', () => 1, () => 1);
    setRegexBudgetProvider(null);
    regexCacheGet('k3', () => 1, () => 1);
    expect(regexCacheStats().bySource['amb']).toBe(1);
    expect(cacheMod.regexCacheHas('k3')).toBe(true);
  });
});

describe('request budgets and parents', () => {
  it('a request budget is not a document scope', async () => {
    const { RegexBudget } = await fresh();
    expect(RegexBudget.request().isDocument).toBe(false);
    expect(RegexBudget.request('s').source).toBe('s');
  });
  it('a document budget also charges its parent, and is refused when the parent is exhausted', async () => {
    const { RegexBudget, MAX_REGEX_EVALUATIONS_PER_DOCUMENT, REGEX_REQUEST_SCALE } = await fresh();
    const parent = RegexBudget.request();
    const child = new RegexBudget(1, parent);
    expect(child.charge('a', 0)).toBe(true);
    expect(parent.evaluations).toBe(1);
    const full = RegexBudget.request();
    for (let i = 0; i < MAX_REGEX_EVALUATIONS_PER_DOCUMENT * REGEX_REQUEST_SCALE; i++) full.charge('a', 0);
    const late = new RegexBudget(1, full);
    expect(late.charge('a', 0)).toBe(false);
    expect(late.refusals).toBe(1);
  });
  it('a cap refusal counts one refusal and poisons the evaluation counter to cap*scale + 1', async () => {
    const { RegexBudget, MAX_REGEX_EVALUATIONS_PER_DOCUMENT, REGEX_REQUEST_SCALE, MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT } = await fresh();
    const r = RegexBudget.request();
    const p = 'a'.repeat(256);
    let n = 0;
    while (r.charge(p, 0)) n++;
    expect(n).toBe((MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT * REGEX_REQUEST_SCALE) / 256);
    expect(r.refusals).toBe(1);
    expect(r.evaluations).toBe(MAX_REGEX_EVALUATIONS_PER_DOCUMENT * REGEX_REQUEST_SCALE + 1);
  });
  it('the step cap scales with the request scale', async () => {
    const { RegexBudget, MAX_REGEX_STEPS_PER_DOCUMENT } = await fresh();
    const probe = new RegexBudget();
    probe.charge('a', 0);
    const len = probe.steps;
    const subject = Math.floor((2 * MAX_REGEX_STEPS_PER_DOCUMENT) / len) - 1; // ~2 documents' worth of steps
    expect(new RegexBudget().charge('a', subject)).toBe(false);
    expect(RegexBudget.request().charge('a', subject)).toBe(true);
  });
});

