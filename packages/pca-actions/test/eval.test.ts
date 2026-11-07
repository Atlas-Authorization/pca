// The suggestion measurement: corpus invariants (the real-spec set is what the floors are about), the hold-out split, the statistics and
// the floor check. The full measurement runs in CI as `scripts/eval-suggest.ts`.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { evalSuggest, floorFailures, parseCorpusJsonl, parseHandTsv, realSplit, type CorpusEntry, type EvalReport, type Floors } from '../src/import/eval';
import type { SuggestRules } from '../src';

const dir = join(__dirname, '..', 'corpus');
const real = parseCorpusJsonl(readFileSync(join(dir, 'real.jsonl'), 'utf8'));

describe('the real-spec corpus', () => {
  it('has at least 150 labeled positives for each of the five core traits, from at least 40 distinct public specifications', () => {
    const n = (t: string): number => real.filter((e) => e.labels.includes(t)).length;
    for (const t of ['money_moving', 'destructive', 'external_communication', 'privilege_change', 'code_execution']) expect(n(t), t).toBeGreaterThanOrEqual(150);
    expect(new Set(real.map((e) => e.spec)).size).toBeGreaterThanOrEqual(40);
    expect(real.length).toBeGreaterThanOrEqual(9000);
  });
  it('carries no vendor prose: names, methods, paths, parameter names and types, and labels only', () => {
    for (const e of real) {
      expect(e.src).toBe('real');
      expect(e.description).toBe('');
      expect(Object.keys(e).sort()).toEqual(['description', 'id', 'kind', 'labels', 'method', 'name', 'params', 'path', 'spec', 'src']);
      for (const p of e.params) expect(p).toMatch(/^[^:]+:(string|integer|boolean|array|number)$/);
    }
  });
  it('has unique ids and distinct operations within a spec, sorted labels from the closed set', () => {
    expect(new Set(real.map((e) => e.id)).size).toBe(real.length);
    const ok = new Set(['money_moving', 'destructive', 'external_communication', 'privilege_change', 'code_execution', 'public_exposure', 'financial_data_read', 'scheduled']);
    for (const e of real) { expect(e.labels).toEqual([...e.labels].sort()); for (const l of e.labels) expect(ok.has(l)).toBe(true); }
    const seen = new Set<string>();
    for (const e of real) { const k = `${e.spec}|${e.method}|${e.path}`; expect(seen.has(k), k).toBe(false); seen.add(k); }
  });
});

describe('the hold-out split', () => {
  it('is a fixed function of the specification name, roughly even, and puts each spec wholly on one side', () => {
    expect(realSplit('stripe')).toBe(realSplit('stripe'));
    const sides = new Map<string, Set<string>>();
    for (const e of real) { const s = sides.get(e.spec!) ?? new Set(); s.add(realSplit(e.spec)); sides.set(e.spec!, s); }
    for (const s of sides.values()) expect(s.size).toBe(1);
    const hold = [...sides.values()].filter((s) => s.has('holdout')).length;
    expect(hold).toBeGreaterThan(sides.size * 0.3);
    expect(hold).toBeLessThan(sides.size * 0.7);
    expect(realSplit('stripe')).toBe('tune');
    expect(realSplit('discord')).toBe('holdout');
  });
});

describe('evalSuggest', () => {
  const slice: CorpusEntry[] = [
    ...real.filter((e) => e.spec === 'stripe').slice(0, 120),
    ...real.filter((e) => e.spec === 'discord').slice(0, 60),
    ...parseHandTsv(readFileSync(join(dir, 'hand.tsv'), 'utf8')).slice(0, 40),
  ];
  const r = evalSuggest(slice);
  it('imports every entry and reports by source with the real set split into tune and hold-out', () => {
    expect(r.entries).toBe(slice.length);
    expect(r.mapped).toBe(slice.length);
    expect(Object.keys(r.by_source).sort()).toEqual(['hand', 'real', 'real/holdout', 'real/tune']);
    expect(r.by_source['real']!.entries).toBe(180);
    expect(r.by_source['real/holdout']!.entries).toBe(60);
    expect(r.by_source['real/tune']!.entries).toBe(120);
  });
  it('counts true and false positives and negatives exactly, and bounds recall below its point estimate', () => {
    for (const s of r.flagged) {
      expect(s.tp + s.fn).toBe(s.positives);
      expect(s.tp + s.fp).toBe(s.predicted);
      if (s.recall !== null) { expect(Math.abs(s.recall - s.tp / s.positives)).toBeLessThan(1e-12); expect(s.recall_lower!).toBeLessThanOrEqual(s.recall + 1e-12); }
    }
    const refund = r.flagged.find((s) => s.trait === 'money_moving')!;
    expect(refund.positives).toBeGreaterThan(5);
  });
  it('the rules are the only variable: a rule set that matches nothing flags fewer of the labeled positives', () => {
    const none: SuggestRules = { v: 1, kind: 'pca-suggest-rules', version: '0.0.1', rules: [{ id: 'SR-001', match: { name_tokens: ['zzzz'] }, adds: ['pca.bulk'], note: 'x' }] };
    const dest = (x: EvalReport): number => x.flagged.find((t) => t.trait === 'destructive')!.tp;
    expect(dest(evalSuggest(slice, { rules: none }))).toBeLessThan(dest(r));
  });
});

describe('floorFailures', () => {
  const stat = (trait: string, positives: number, recall_lower: number | null) => ({ trait, positives, predicted: 10, tp: 0, fp: 0, fn: 0, precision: null, recall: null, recall_lower, precision_lower: null });
  const rep = (hold: number, lower: number | null, positives = 200): EvalReport => ({
    alpha: 0.05, entries: 100, mapped: 100, rules_version: '1', flagged: [], suggested: [],
    by_source: { 'real/holdout': { entries: hold, flagged: [stat('money_moving', positives, lower)] }, syn: { entries: 10, flagged: [stat('money_moving', 50, 0.97)] } },
  });
  const f: Floors = { v: 2, alpha: 0.05, real: { min_entries: 50, min_positives: { money_moving: 100 }, recall_lower: { money_moving: 0.6 } }, regression: { recall_lower: { money_moving: 0.9 } } };
  it('passes at the floor and names each way of failing', () => {
    expect(floorFailures(rep(60, 0.6), f)).toEqual([]);
    expect(floorFailures(rep(60, 0.59), f)).toEqual(['money_moving: hold-out recall lower bound 59.0% is below the recorded floor 60.0%']);
    expect(floorFailures(rep(10, 0.7), f)).toEqual(['the real-spec hold-out has 10 operations, fewer than the required 50']);
    expect(floorFailures(rep(60, 0.7, 40), f)).toEqual(['money_moving: 40 real labeled positives, fewer than the 100 the floor needs']);
    expect(floorFailures(rep(60, null), f)).toEqual(['money_moving: hold-out recall lower bound - is below the recorded floor 60.0%']);
    const low = rep(60, 0.7);
    low.by_source['syn']!.flagged[0]!.recall_lower = 0.8;
    expect(floorFailures(low, f)).toEqual(['money_moving: regression-set recall lower bound 80.0% is below 90.0%']);
    expect(floorFailures({ ...rep(60, 0.7), mapped: 99 }, f)).toEqual(['1 corpus operations were not imported']);
  });
  it('the recorded floors file is well formed and each floored trait has the positives it names', () => {
    const rec = JSON.parse(readFileSync(join(dir, 'recall-floors.json'), 'utf8')) as Floors;
    expect(rec.v).toBe(2);
    for (const [t, floor] of Object.entries(rec.real.recall_lower)) { expect(floor).toBeGreaterThan(0); expect(floor).toBeLessThan(1); expect(rec.real.min_positives[t]).toBeGreaterThanOrEqual(10); }
  });
});
