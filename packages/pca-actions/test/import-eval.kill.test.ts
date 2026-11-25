// Further behaviour tests for the suggestion measurement: trait-name selection and ordering, group keys and drafts without bindings.
// The importer, the suggestion engine and the hint reader are replaced by fakes so every expected value is exact.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { importActions } from '../src/import/pipeline';
import { applySuggestion, suggestWithRules } from '../src/import/suggest';
import { hintTraits } from '../src/effective';
import { CORE_REGISTRY } from '../src/core-traits';
import type { Registry, TraitDef } from '../src/traits';
import { evalSuggest, importCorpus, type CorpusEntry } from '../src/import/eval';

vi.mock('../src/import/pipeline', () => ({ importActions: vi.fn() }));
vi.mock('../src/import/suggest', async (orig) => ({ ...(await orig<Record<string, unknown>>()), suggestWithRules: vi.fn(), applySuggestion: vi.fn() }));
vi.mock('../src/effective', async (orig) => ({ ...(await orig<Record<string, unknown>>()), hintTraits: vi.fn() }));

const imp = vi.mocked(importActions);
const E = (o: Partial<CorpusEntry> & { id: string }): CorpusEntry => ({ src: 'hand', kind: 'mcp', name: o.id, params: [], labels: [], description: '', ...o });

beforeEach(() => { vi.clearAllMocks(); imp.mockReset(); });

describe('importCorpus: grouping and matching', () => {
  it('keeps an entry without a specification apart from an entry whose specification has any other text', () => {
    imp.mockReturnValue({ defs: [], todo: [] } as never);
    importCorpus([E({ id: 'a' }), E({ id: 'b', spec: 'Stryker was here!' })]);
    expect(imp.mock.calls.map((c) => (c[1] as { name: string }[]).map((t) => t.name))).toEqual([['a'], ['b']]);
  });

  it('matches a draft that carries no bindings at all to an entry with an empty name', () => {
    const d = {};
    imp.mockReturnValue({ defs: [d], todo: [] } as never);
    const r = importCorpus([E({ id: 'x', name: '' })]);
    expect(r.defs.get('x')).toBe(d);
  });
});

describe('evalSuggest: which traits are scored, and in what order', () => {
  const ids = ['pca.z', 'pca.m', 'org.pca.q', 'unreviewed', 'pca.a', 'pca.unreviewed', 'pca.irreversible', 'irreversible'];
  const template = CORE_REGISTRY.traits.get('pca.bulk')!; // a real trait definition, re-keyed: the ids below are test-only and never pass through extendRegistry (which reserves `pca.`)
  const registry: Registry = { traits: new Map(ids.map((id): [string, TraitDef] => [id, { ...template, id, implies: [] }])) };

  it('leaves out the two held-back core traits, keeps a trait that only ends in their name, strips only a leading prefix, and sorts', () => {
    const hints = ['pca.z', 'org.pca.q', 'pca.unreviewed', 'pca.irreversible'];
    imp.mockReturnValue({ defs: [{ bindings: { mcp: { tool: 'e1' } }, hints }], todo: [] } as never);
    vi.mocked(suggestWithRules).mockReturnValue({ traits: [], fired: [] } as never);
    vi.mocked(applySuggestion).mockImplementation(((d: unknown) => d) as never);
    vi.mocked(hintTraits).mockImplementation(((d: { hints: string[] }) => d.hints) as never);
    const r = evalSuggest([E({ id: 'e1', labels: ['z', 'org.pca.q', 'unreviewed', 'irreversible', 'm'] })], { registry });
    expect(r.flagged.map((s) => [s.trait, s.tp, s.fp, s.fn])).toEqual([
      ['irreversible', 1, 0, 0],
      ['m', 0, 0, 1],
      ['org.pca.q', 1, 0, 0],
      ['unreviewed', 0, 0, 1],
      ['z', 1, 0, 0],
    ]);
  });
});
