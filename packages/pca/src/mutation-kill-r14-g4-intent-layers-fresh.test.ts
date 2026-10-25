/**
 * r14 static mutants of intent-layers.ts: LAYER_CEILINGS and the module-level helpers (isPlain, closedTo, isLayerPolicy,
 * layerAdmits, own), checked on a re-evaluated module (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';
import type { LayerPolicy } from './intent-layers';
import type { ActionContext } from './predicates';

async function fresh() {
  vi.resetModules();
  return import('./intent-layers');
}
const cap = (max: number): LayerPolicy => ({ predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: max }] }] });
const ctx = (total: number): ActionContext => ({ action: { verb: 'air.book', resource: 'r', params: { total } } });
const outside = (k: string) => ({ status: 'fail', layer: k, reason: `layers: the action is outside the ${k} ceiling (a ceiling is never a question)` });

describe('intent-layers (fresh module)', () => {
  it('LAYER_CEILINGS is org, site, std in that order', async () => {
    const l = await fresh();
    expect(l.LAYER_CEILINGS).toEqual(['org', 'site', 'std']);
  });
  it('each ceiling is read, named and enforced; inside every ceiling passes', async () => {
    const l = await fresh();
    for (const k of ['org', 'site', 'std']) expect(l.decideLayerCeilings({ [k]: cap(1) }, ctx(5))).toEqual(outside(k));
    expect(l.decideLayerCeilings({ org: cap(10), site: cap(10), std: cap(10) }, ctx(5))).toEqual({ status: 'pass' });
  });
  it('isLayerPolicy, isPlain and closedTo: well-formed layers are accepted, malformed ones refused', async () => {
    const l = await fresh();
    expect(l.isLayerPolicy(cap(1))).toBe(true);
    expect(l.isLayerPolicy({ predicates: [], x: 1 })).toBe(false);
    expect(l.isLayerPolicy([])).toBe(false);
    expect(l.decideLayerCeilings({ org: { predicates: 'x' } as never }, ctx(5))).toEqual({ status: 'fail', layer: 'org', reason: 'layers: the org ceiling is malformed (null or not {predicates: [...]})' });
  });
  it('decideLayers: admits by task index, vetoes by denied, asks otherwise', async () => {
    const l = await fresh();
    expect(l.decideLayers({ task: [cap(1), cap(10)] }, ctx(5))).toEqual({ decision: 'admit', by: 1 });
    expect(l.decideLayers({ task: [cap(10)], denied: [cap(10)] }, ctx(5))).toEqual({ decision: 'intent_denied' });
    expect(l.decideLayers({ task: [cap(1)] }, ctx(5))).toEqual({ decision: 'intent_required' });
    expect(l.decideLayers({ org: cap(1), task: [cap(10)] }, ctx(5))).toEqual({ decision: 'ceiling', layer: 'org' });
  });
});
