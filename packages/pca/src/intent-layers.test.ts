import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { decideLayerCeilings, decideLayers, type LayerPolicy } from './intent-layers';
import type { ActionContext } from './predicates';

// Intent Layer v2 milestone V5, verifier side: the `layers` check (deny anywhere wins, T18).

const cap = (max: number): LayerPolicy => ({ predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: max }] }] });
const ctx = (total: number, world?: Record<string, unknown>): ActionContext => ({ action: { verb: 'air.book', resource: 'r', params: { total } }, ...(world ? { env: { world } } : {}) });

describe('decideLayerCeilings', () => {
  it('names the first ceiling that denies, in the order org, site, std; absent layers are Ω̃', () => {
    expect(decideLayerCeilings({ org: cap(500), site: cap(400), std: cap(300) }, ctx(600))).toMatchObject({ status: 'fail', layer: 'org' });
    expect(decideLayerCeilings({ org: cap(500), site: cap(400), std: cap(300) }, ctx(450))).toMatchObject({ status: 'fail', layer: 'site' });
    expect(decideLayerCeilings({ std: cap(300) }, ctx(350))).toMatchObject({ status: 'fail', layer: 'std' });
    expect(decideLayerCeilings({}, ctx(10_000))).toEqual({ status: 'pass' });
  });

  it('layers read verifier-computed env paths like any predicate', () => {
    const org: LayerPolicy = { predicates: [{ verb: 'air.book', where: [{ field: 'env.world.fraud_flag', op: 'eq', value: 0 }] }] };
    expect(decideLayerCeilings({ org }, ctx(1, { fraud_flag: 0 })).status).toBe('pass');
    expect(decideLayerCeilings({ org }, ctx(1, { fraud_flag: 1 })).status).toBe('fail');
    expect(decideLayerCeilings({ org }, ctx(1)).status).toBe('fail'); // missing fact: fail closed
  });

  it('a malformed layer admits nothing (fail closed)', () => {
    expect(decideLayerCeilings({ org: {} as LayerPolicy }, ctx(1)).status).toBe('fail');
    expect(decideLayerCeilings({ org: { predicates: [] } }, ctx(1)).status).toBe('fail');
  });
});

describe('absent vs null (README "absent vs null")', () => {
  const bad = (x: unknown) => x as LayerPolicy;
  it('a ceiling present with null or a non-layer value is malformed and fails, naming it; absent is Ω̃', () => {
    expect(decideLayerCeilings({ org: bad(null) }, ctx(1))).toMatchObject({ status: 'fail', layer: 'org' });
    expect(decideLayerCeilings({ site: bad({ predicates: null }) }, ctx(1))).toMatchObject({ status: 'fail', layer: 'site' });
    expect(decideLayerCeilings({ std: bad([]) }, ctx(1))).toMatchObject({ status: 'fail', layer: 'std' });
    expect(decideLayerCeilings(null as unknown as Record<string, never>, ctx(1)).status).toBe('fail');
    expect(decideLayerCeilings({}, ctx(1))).toEqual({ status: 'pass' });
  });
  it('a null or non-array denied / task, or a malformed entry, is intent_denied (never a question, never an admission)', () => {
    expect(decideLayers({ task: [cap(100)], denied: bad(null) as unknown as LayerPolicy[] }, ctx(50))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task: null as unknown as LayerPolicy[] }, ctx(50))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task: [bad(null), cap(100)] }, ctx(50))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({} as never, ctx(50))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task: [cap(100)] }, ctx(50))).toEqual({ decision: 'admit', by: 0 });
  });
});

describe('decideLayers', () => {
  it('ceiling, then denied regions, then the task union, else intent_required', () => {
    const g = { org: cap(500), task: [cap(100), cap(200)], denied: [{ predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'eq' as const, value: 150 }] }] }] };
    expect(decideLayers(g, ctx(600))).toEqual({ decision: 'ceiling', layer: 'org' });
    expect(decideLayers(g, ctx(150))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers(g, ctx(90))).toEqual({ decision: 'admit', by: 0 });
    expect(decideLayers(g, ctx(190))).toEqual({ decision: 'admit', by: 1 });
    expect(decideLayers(g, ctx(300))).toEqual({ decision: 'intent_required' });
  });

  it('T18: whatever the task layer and the deltas admit, an admitted action is inside every ceiling', () => {
    const maybe = fc.option(fc.integer({ min: 0, max: 1000 }), { nil: null });
    fc.assert(
      fc.property(maybe, maybe, maybe, fc.array(fc.integer({ min: 0, max: 1000 }), { maxLength: 5 }), fc.integer({ min: 0, max: 1000 }), (o, s, d, task, total) => {
        const g = { ...(o === null ? {} : { org: cap(o) }), ...(s === null ? {} : { site: cap(s) }), ...(d === null ? {} : { std: cap(d) }), task: task.map(cap) };
        const r = decideLayers(g, ctx(total));
        if (r.decision !== 'admit') return true;
        return [o, s, d].every((c) => c === null || total <= c);
      }),
    );
  });
});

describe('closed and typed layers', () => {
  it('an unknown member of the layers object, a grant or a layer is malformed', () => {
    expect(decideLayerCeilings({ org: cap(500), extra: cap(1) } as never, ctx(1))).toMatchObject({ status: 'fail', layer: 'org' });
    expect(decideLayerCeilings({ site: { ...cap(500), note: 'x' } as never }, ctx(1))).toMatchObject({ status: 'fail', layer: 'site' });
    expect(decideLayers({ task: [cap(100)], extra: [] } as never, ctx(50))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task: [{ ...cap(100), caveats: [] } as never] }, ctx(50))).toEqual({ decision: 'intent_denied' });
  });
});
