/* eslint-disable @typescript-eslint/no-explicit-any */
// Mutation-kill tests for src/ext-taint.ts: the typed adapter over the proved taint decisions. Differential against the production
// implementation over an adversarial corpus, plus pinned reasons / call orders / numeric boundaries.
import { describe, expect, it } from 'vitest';
import { computeTaint, joinLabel, joinLabels, labelRank as prodRank, taintValue as prodValue } from './support/legacy/taint';
import {
  BOTTOM,
  TAINT_LEVELS,
  TOP,
  combineTaintRank,
  computeTaintVerified,
  isTaintLevel,
  joinLabelVerified,
  joinLabelsVerified,
  labelRank,
  taintGateVerified,
  taintValue,
  type TaintLabel,
} from '../src/ext-taint';

const labels: TaintLabel[] = [];
for (const k of TAINT_LEVELS) {
  labels.push({ kind: k });
  if (k === 'tool' || k === 'agent') labels.push({ kind: k, id: 'x' }, { kind: k, id: 'y' }, { kind: k, id: '' });
}

describe('labels', () => {
  it('constants, ranks, values and kind recognition', () => {
    expect(BOTTOM).toEqual({ kind: 'trusted' });
    expect(TOP).toEqual({ kind: 'agent' });
    expect([...TAINT_LEVELS]).toEqual(['trusted', 'first_party', 'tool', 'web', 'agent']);
    for (const l of labels) {
      expect(labelRank(l)).toBe(prodRank(l as any));
      expect(taintValue(l)).toBe(prodValue(l as any));
    }
    // unknown / inherited kinds rank WORST in both (Taint.UnknownKindRanksWorst), never NaN
    for (const k of ['constructor', '__proto__', 'toString', 5, undefined]) {
      expect(labelRank({ kind: k } as any)).toBe(4);
      expect(labelRank({ kind: k } as any)).toBe(prodRank({ kind: k } as any));
      expect(taintValue({ kind: k } as any)).toBe(prodValue({ kind: k } as any));
    }
    expect(taintValue({ kind: 'trusted' })).toBe(0);
    expect(taintValue({ kind: 'tool' })).toBe(0.5);
    expect(taintValue({ kind: 'agent' })).toBe(1);
    for (const k of TAINT_LEVELS) expect(isTaintLevel(k)).toBe(true);
    for (const k of ['constructor', '__proto__', 'toString', 'hasOwnProperty', '', 'Trusted', 5, null, undefined, {}, ['tool']]) expect(isTaintLevel(k)).toBe(false);
  });
  it('join agrees with production for every ordered pair (kinds and ids)', () => {
    for (const a of labels) for (const b of labels) expect(joinLabelVerified(a, b)).toEqual(joinLabel(a as any, b as any));
  });
  it('join / joinLabels reject unknown kinds with the documented TypeError, whichever argument is bad', () => {
    const bad: any[] = [null, undefined, {}, { kind: 'constructor' }, { kind: 5 }];
    for (const x of bad) {
      expect(() => joinLabelVerified(x, { kind: 'web' })).toThrow(new TypeError('taint: unknown label kind'));
      expect(() => joinLabelVerified({ kind: 'web' }, x)).toThrow(new TypeError('taint: unknown label kind'));
      expect(() => joinLabelsVerified([{ kind: 'web' }, x])).toThrow(new TypeError('taint: unknown label kind'));
      expect(() => joinLabelsVerified([x])).toThrow(TypeError);
    }
    expect(() => joinLabelVerified(null as any, null as any)).toThrow('taint: unknown label kind');
  });
  it('joinLabels: empty lineage is TOP; folds agree with production, order independent; every label is consumed', () => {
    expect(joinLabelsVerified([])).toEqual({ kind: 'agent' });
    expect(joinLabelsVerified([{ kind: 'trusted' }])).toEqual({ kind: 'trusted' });
    expect(joinLabelsVerified([{ kind: 'trusted' }, { kind: 'first_party' }])).toEqual({ kind: 'first_party' });
    expect(joinLabelsVerified([{ kind: 'trusted' }, { kind: 'trusted' }, { kind: 'web' }])).toEqual({ kind: 'web' });
    for (const a of labels) for (const b of labels) for (const c of [labels[0]!, labels[3]!, labels[5]!]) {
      expect(joinLabelsVerified([a, b, c])).toEqual(joinLabels([a, b, c] as any));
      expect(joinLabelsVerified([c, b, a])).toEqual(joinLabels([c, b, a] as any));
    }
  });
  it('combineTaintRank is max', () => {
    for (let a = 0; a <= 4; a++) for (let b = 0; b <= 4; b++) expect(combineTaintRank(a, b)).toBe(Math.max(a, b));
  });
});

type Reg = Record<string, any>;
const ctxOf = (reg: Reg, graph?: Record<string, unknown>, calls?: string[]) => ({
  registry: { lookup: (d: string) => { calls?.push(`r:${d}`); return reg[d]; } },
  ...(graph ? { resourceGraph: { node: (id: string) => { calls?.push(`g:${id}`); return graph[id]; } } } : {}),
});

describe('computeTaintVerified', () => {
  const reg: Reg = { a: { kind: 'trusted' }, b: { kind: 'first_party' }, c: { kind: 'tool', id: 'T' }, d: { kind: 'web' }, e: { kind: 'agent', id: 'A' }, bad: { kind: 'constructor' }, bad2: { kind: 5 }, nul: null };
  const graph = { g1: { x: 1 }, g2: 0 };
  const provs: any[] = [
    undefined, null, [], 'str', 5, true, {}, { trusted_refs: undefined }, { trusted_refs: null }, { trusted_refs: 'x' }, { trusted_refs: {} }, { trusted_refs: [] },
    { trusted_refs: [''] }, { trusted_refs: [1] }, { trusted_refs: [null] }, { trusted_refs: ['a', ''] }, { trusted_refs: ['a', 3] }, { trusted_refs: ['a'] },
    { trusted_refs: ['a', 'b'] }, { trusted_refs: ['a', 'b', 'c', 'd', 'e'] }, { trusted_refs: ['c', 'c'] }, { trusted_refs: ['e', 'c'] }, { trusted_refs: ['zz'] },
    { trusted_refs: ['bad'] }, { trusted_refs: ['bad2'] }, { trusted_refs: ['nul'] }, { trusted_refs: ['g1'] }, { trusted_refs: ['g2'] }, { trusted_refs: ['a', 'g1'] },
    { trusted_refs: ['x'.repeat(128)] }, { trusted_refs: ['x'.repeat(129)] }, { trusted_refs: ['x'.repeat(129), 'x'.repeat(129)] },
    { trusted_refs: ['a', 'b'], other: 1 },
  ];
  const norm = (r: any) => JSON.parse(JSON.stringify(r));

  it('agrees with production on the whole adversarial corpus (result, registry and graph call order)', () => {
    for (const p of provs) {
      const c1: string[] = [], c2: string[] = [];
      const got = computeTaintVerified(p, ctxOf({ ...reg, ['x'.repeat(128)]: { kind: 'web' } }, graph, c1));
      const exp = computeTaint(p, ctxOf({ ...reg, ['x'.repeat(128)]: { kind: 'web' } }, graph, c2) as any);
      // production's NaN case for 'constructor'/numeric kinds is the one documented deviation: those refs are simply not vouched
      if (JSON.stringify(p)?.includes('bad')) continue;
      expect(norm(got), JSON.stringify(p)).toEqual(norm(exp));
      expect(c1, JSON.stringify(p)).toEqual(c2);
    }
  });
  it('a registry label with a non-own kind is NOT vouched (Taint.UnknownKindIsNotVouching, same as production), falling through to the graph', () => {
    const calls: string[] = [];
    const r = computeTaintVerified({ trusted_refs: ['bad'] }, ctxOf(reg, { bad: { n: 1 } }, calls));
    expect(r.valid).toBe(true);
    expect(r.refs).toEqual([{ ref: 'bad', label: { kind: 'first_party' } }]);
    expect(calls).toEqual(['r:bad', 'g:bad']);
    expect(computeTaintVerified({ trusted_refs: ['bad'] }, ctxOf(reg)).refs).toEqual([{ ref: 'bad', label: { kind: 'agent', id: 'bad' } }]);
    expect(computeTaintVerified({ trusted_refs: ['nul'] }, ctxOf(reg)).refs).toEqual([{ ref: 'nul', label: { kind: 'agent', id: 'nul' } }]);
    expect(computeTaintVerified({ trusted_refs: ['bad2'] }, ctxOf(reg)).taint).toBe(1);
  });
  it('invalid results carry the exact reason, TOP label, taint 1 and no refs', () => {
    const norm = (r: any) => JSON.parse(JSON.stringify(r));
    const inv = (r: any, reason: string) => expect(r).toEqual({ taint: 1, label: { kind: 'agent' }, refs: [], valid: false, reason });
    inv(computeTaintVerified({ trusted_refs: ['a'] }, undefined as any), 'taint: no trusted-input registry');
    inv(computeTaintVerified({ trusted_refs: ['a'] }, {} as any), 'taint: no trusted-input registry');
    inv(computeTaintVerified({ trusted_refs: ['a'] }, { registry: {} } as any), 'taint: no trusted-input registry');
    inv(computeTaintVerified({ trusted_refs: ['a'] }, { registry: { lookup: 5 } } as any), 'taint: no trusted-input registry');
    inv(computeTaintVerified({ trusted_refs: ['a'] }, null as any), 'taint: no trusted-input registry');
    for (const p of [null, undefined, [], 'str', 5, true]) inv(computeTaintVerified(p, ctxOf(reg)), 'taint: provenance is absent or malformed');
    for (const p of [{ trusted_refs: 'x' }, { trusted_refs: {} }, { trusted_refs: null }, { trusted_refs: 3 }]) inv(computeTaintVerified(p, ctxOf(reg)), 'taint: trusted_refs must be an array');
    for (const p of [{ trusted_refs: [''] }, { trusted_refs: [1] }, { trusted_refs: ['a', null] }, { trusted_refs: ['a', ''] }]) inv(computeTaintVerified(p, ctxOf(reg)), 'taint: trusted_refs must be non-empty strings');
    for (const p of [{}, { trusted_refs: undefined }]) expect(computeTaintVerified(p, ctxOf(reg))).toEqual(norm(computeTaint(p, ctxOf(reg) as any)));
    // an object without a registry is a registry failure, an array-valued provenance is malformed (not "no refs")
    inv(computeTaintVerified([], ctxOf(reg)), 'taint: provenance is absent or malformed');
  });
  it('a sparse trusted_refs array (holes) fails closed; a bad element stops the scan before the registry is touched', () => {
    const calls: string[] = [];
    // eslint-disable-next-line no-sparse-arrays
    const r = computeTaintVerified({ trusted_refs: ['a', , 'b'] }, ctxOf(reg, undefined, calls));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('taint: trusted_refs must be non-empty strings');
    expect(calls).toEqual([]);
    const c2: string[] = [];
    expect(computeTaintVerified({ trusted_refs: ['a', 7, 'b'] }, ctxOf(reg, undefined, c2)).valid).toBe(false);
    expect(c2).toEqual([]);
  });
  it('empty trusted_refs is valid and worst-case free: label TOP? no - the empty lineage joins to TOP with taint 1 but valid', () => {
    expect(computeTaintVerified({ trusted_refs: [] }, ctxOf(reg))).toEqual(norm(computeTaint({ trusted_refs: [] }, ctxOf(reg) as any)));
  });
  it('registry is consulted in order, the graph only for unvouched refs, and a throwing graph is the worst case', () => {
    const calls: string[] = [];
    const r = computeTaintVerified({ trusted_refs: ['a', 'zz', 'g1'] }, ctxOf(reg, { g1: true }, calls));
    expect(calls).toEqual(['r:a', 'r:zz', 'g:zz', 'r:g1', 'g:g1']);
    expect(r.refs.map((x) => x.label.kind)).toEqual(['trusted', 'agent', 'first_party']);
    const throwing = { registry: { lookup: () => undefined }, resourceGraph: { node: () => { throw new Error('graph down'); } } };
    expect(computeTaintVerified({ trusted_refs: ['q'] }, throwing).refs).toEqual([{ ref: 'q', label: { kind: 'agent', id: 'q' } }]);
    const throwingReg = { registry: { lookup: () => { throw new Error('reg down'); } } };
    expect(computeTaintVerified({ trusted_refs: ['q'] }, throwingReg)).toEqual({ taint: 1, label: { kind: 'agent' }, refs: [], valid: false, reason: 'taint: evaluation error (fail closed): reg down' });
    expect(computeTaintVerified({ trusted_refs: ['q'] }, { registry: { lookup: () => { throw 'str'; } } }).reason).toBe('taint: evaluation error (fail closed): unknown');
  });
  it('ids: refs longer than 128 chars are not interned, 128 is; id equality drives the join', () => {
    const long = 'x'.repeat(129);
    const a = computeTaintVerified({ trusted_refs: [long, long] }, ctxOf({ [long]: { kind: 'tool', id: 'T' } }));
    const b = computeTaint({ trusted_refs: [long, long] }, ctxOf({ [long]: { kind: 'tool', id: 'T' } }) as any);
    expect(norm(a)).toEqual(norm(b));
    const same = computeTaintVerified({ trusted_refs: ['c', 'c'] }, ctxOf(reg));
    expect(same.label).toEqual({ kind: 'tool', id: 'T' });
    const diff = computeTaintVerified({ trusted_refs: ['c', 'e'] }, ctxOf(reg));
    expect(norm(diff)).toEqual(norm(computeTaint({ trusted_refs: ['c', 'e'] }, ctxOf(reg) as any)));
  });
  it('result shape: taint is rank/4, refs keep order and original strings', () => {
    const r = computeTaintVerified({ trusted_refs: ['a', 'b', 'd'] }, ctxOf(reg));
    expect(r.valid).toBe(true);
    expect(r.taint).toBe(0.75);
    expect(r.label).toEqual({ kind: 'web' });
    expect(r.refs).toEqual([{ ref: 'a', label: { kind: 'trusted' } }, { ref: 'b', label: { kind: 'first_party' } }, { ref: 'd', label: { kind: 'web' } }]);
    expect(r.reason).toBeUndefined();
    expect(computeTaintVerified({ trusted_refs: ['a'] }, ctxOf(reg)).taint).toBe(0);
    expect(computeTaintVerified({ trusted_refs: ['a', 'b'] }, ctxOf(reg)).taint).toBe(0.25);
    expect(computeTaintVerified({ trusted_refs: ['a', 'c'] }, ctxOf(reg)).taint).toBe(0.5);
  });
});

describe('taintGateVerified', () => {
  const reg: Reg = { a: { kind: 'trusted' }, b: { kind: 'first_party' }, c: { kind: 'tool' }, d: { kind: 'web' } };
  const prov = (...refs: string[]) => ({ trusted_refs: refs });
  it('passes iff the computed rank is within the largest allowed rank, over a maxTaint grid', () => {
    const maxes = [0, 0.1, 0.24, 0.25, 0.26, 0.49, 0.5, 0.74, 0.75, 0.99, 1, 1.5, 100, Number.POSITIVE_INFINITY];
    for (const [ref, rank] of [['a', 0], ['b', 1], ['c', 2], ['d', 3], ['zz', 4]] as const) {
      for (const m of maxes) {
        const g = taintGateVerified(prov(ref), ctxOf(reg), m);
        expect(g.ok, `${ref} max ${m}`).toBe(rank / 4 <= m);
      }
    }
  });
  it('exceed message names the computed taint and the policy max exactly', () => {
    expect(taintGateVerified(prov('d'), ctxOf(reg), 0.5)).toEqual({ ok: false, reason: 'information-flow taint 0.75 exceeds policy max 0.5' });
    expect(taintGateVerified(prov('zz'), ctxOf(reg), 0)).toEqual({ ok: false, reason: 'information-flow taint 1 exceeds policy max 0' });
    expect(taintGateVerified(prov('a'), ctxOf(reg), 0)).toEqual({ ok: true });
  });
  it('misconfigured maxTaint (negative, NaN) fails closed with the dedicated reason; 0 is fine', () => {
    const msg = 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)';
    expect(taintGateVerified(prov('a'), ctxOf(reg), -0.0001)).toEqual({ ok: false, reason: msg });
    expect(taintGateVerified(prov('a'), ctxOf(reg), -1)).toEqual({ ok: false, reason: msg });
    expect(taintGateVerified(prov('a'), ctxOf(reg), Number.NaN)).toEqual({ ok: false, reason: msg });
    expect(taintGateVerified(prov('a'), ctxOf(reg), 0).ok).toBe(true);
  });
  it('an invalid lineage reports the computeTaint reason, before any threshold comparison', () => {
    expect(taintGateVerified(null, ctxOf(reg), 1)).toEqual({ ok: false, reason: 'taint: provenance is absent or malformed' });
    expect(taintGateVerified({ trusted_refs: 'x' }, ctxOf(reg), 1)).toEqual({ ok: false, reason: 'taint: trusted_refs must be an array' });
    expect(taintGateVerified({ trusted_refs: [''] }, ctxOf(reg), 1)).toEqual({ ok: false, reason: 'taint: trusted_refs must be non-empty strings' });
    expect(taintGateVerified(prov('a'), undefined as any, 1)).toEqual({ ok: false, reason: 'taint: no trusted-input registry' });
    // an invalid lineage is denied even at an effectively-unbounded max, and a misconfigured max does not mask it
    expect(taintGateVerified(null, ctxOf(reg), Number.POSITIVE_INFINITY).ok).toBe(false);
    expect(taintGateVerified(null, ctxOf(reg), -1)).toEqual({ ok: false, reason: 'taint: provenance is absent or malformed' });
  });
  it('an exception from the registry is a fail-closed deny carrying its message', () => {
    const ctx = { registry: { lookup: () => { throw new Error('boom'); } } };
    expect(taintGateVerified(prov('a'), ctx, 1)).toEqual({ ok: false, reason: 'taint: evaluation error (fail closed): boom' });
  });
});

describe('ext-taint glue edges', () => {
  it('labelRank of a null / undefined label is the worst rank, not a TypeError', () => {
    expect(labelRank(null as any)).toBe(4);
    expect(labelRank(undefined as any)).toBe(4);
    expect(taintValue(null as any)).toBe(1);
  });
  it('a non-Error thrown by the registry is reported as "unknown"', () => {
    const ctx = { registry: { lookup: () => { throw 'str'; } } };
    expect(computeTaintVerified({ trusted_refs: ['q'] }, ctx as any)).toEqual({ taint: 1, label: { kind: 'agent' }, refs: [], valid: false, reason: 'taint: evaluation error (fail closed): unknown' });
  });
  it('without a registry the provenance is never inspected (a revoked proxy is not touched)', () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    expect(computeTaintVerified(proxy, {} as any)).toEqual({ taint: 1, label: { kind: 'agent' }, refs: [], valid: false, reason: 'taint: no trusted-input registry' });
    // with a registry the same provenance is an evaluation error (Array.isArray throws on a revoked proxy)
    const r = computeTaintVerified(proxy, { registry: { lookup: () => undefined } });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/^taint: evaluation error \(fail closed\): /);
  });
  it('a maxTaint that cannot be compared (a Symbol) is a fail-closed gate error carrying the message', () => {
    const g = taintGateVerified({ trusted_refs: ['a'] }, { registry: { lookup: () => ({ kind: 'trusted' }) } }, Symbol('m') as any);
    expect(g.ok).toBe(false);
    expect((g as any).reason).toBe('taint gate error (fail closed): Cannot convert a Symbol value to a number');
  });
});
