// The suggestion measurement against the real importer and the real suggestion engine (nothing replaced): which traits are scored, how a
// custom trait id is named, and the floor check at a floor of zero and with several traits in a report.
import { describe, expect, it } from 'vitest';
import { BOTTOM, CORE_REGISTRY, SUGGEST_RULES_KIND, extendRegistry, type SuggestRules } from '../src';
import { evalSuggest, floorFailures, type CorpusEntry, type EvalReport, type Floors, type TraitStat } from '../src/import/eval';

const E = (o: Partial<CorpusEntry> & { id: string }): CorpusEntry => ({ src: 'hand', kind: 'mcp', name: o.id, params: [], labels: [], description: 'd', ...o });

describe('evalSuggest', () => {
  it('never scores the unreviewed or irreversible traits, even when an entry is labeled with them', () => {
    const r = evalSuggest([E({ id: 'a', name: 'send_email', labels: ['unreviewed', 'irreversible', 'comm'] })]);
    const names = [...r.flagged, ...r.suggested].map((s) => s.trait);
    expect(names).not.toContain('unreviewed');
    expect(names).not.toContain('irreversible');
  });
  it('names a custom trait by its whole id: only an id that starts with pca. loses that prefix', () => {
    const registry = extendRegistry(CORE_REGISTRY, [{ id: 'xpca.foo', implies: [], floor: BOTTOM, card_phrase: 'a custom trait' }]);
    const rules: SuggestRules = { v: 1, kind: SUGGEST_RULES_KIND, version: '9.0.0', rules: [{ id: 'SR-901', match: { methods: ['DELETE'] }, adds: ['xpca.foo'], note: 'a delete' }] };
    const r = evalSuggest([E({ id: 'd', kind: 'openapi', name: 'dropIt', method: 'delete', path: '/things', labels: ['xpca.foo'] })], { rules, registry });
    const pick = (l: TraitStat[]) => l.find((s) => s.trait === 'xpca.foo');
    expect(pick(r.flagged)).toMatchObject({ positives: 1, predicted: 1, tp: 1 });
    expect(pick(r.suggested)).toMatchObject({ positives: 1, predicted: 1, tp: 1 });
  });
  it('lists the scored traits in name order, not registry order (a custom trait registered after the core ones sorts first)', () => {
    const registry = extendRegistry(CORE_REGISTRY, [{ id: 'aaa.custom', implies: [], floor: BOTTOM, card_phrase: 'a custom trait' }]);
    const r = evalSuggest([E({ id: 'a', name: 'send_email', labels: ['aaa.custom', 'bulk'] })], { registry });
    const names = r.flagged.map((s) => s.trait);
    expect(names[0]).toBe('aaa.custom');
    expect(names).toContain('bulk');
    expect(names).toEqual([...names].sort());
  });
});

describe('floorFailures', () => {
  const st = (trait: string, positives: number, recall_lower: number | null): TraitStat => ({ trait, positives, predicted: 10, tp: 0, fp: 0, fn: 0, precision: null, recall: null, recall_lower, precision_lower: null });
  const rep = (hold: TraitStat[], syn: TraitStat[]): EvalReport => ({
    alpha: 0.05, entries: 10, mapped: 10, rules_version: '1', flagged: [], suggested: [],
    by_source: { 'real/holdout': { entries: 10, flagged: hold }, syn: { entries: 10, flagged: syn } },
  });
  const floors = (real: Record<string, number>, regression: Record<string, number>): Floors => ({ v: 2, alpha: 0.05, real: { min_entries: 1, min_positives: {}, recall_lower: real }, regression: { recall_lower: regression } });

  it('a recall bound that is not known fails even a floor of zero', () => {
    expect(floorFailures(rep([st('money_moving', 5, null)], [st('money_moving', 5, null)]), floors({ money_moving: 0 }, { money_moving: 0 }))).toEqual([
      'money_moving: hold-out recall lower bound - is below the recorded floor 0.0%',
      'money_moving: regression-set recall lower bound - is below 0.0%',
    ]);
  });
  it('each floored trait is read from its own row of the regression set', () => {
    expect(floorFailures(rep([], [st('bulk', 5, 0.1), st('money_moving', 5, 0.95)]), floors({}, { money_moving: 0.9 }))).toEqual([]);
  });
});
