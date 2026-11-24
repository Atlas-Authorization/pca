import { describe, expect, it } from 'vitest';
import type { Dim, HarmModel, Omega } from '@atlasauth/pca-intent';
import { binEnt, CLARIFY_REASONS, informationGain, MAX_CANDIDATES, parseClarifyRequest, planClarification, type ClarifyPlanInput } from './index';

const QTY = 'action.params.qty';
const cand = (qty: unknown = 3) => ({ verb: 'cart.add', values: { [QTY]: qty } });
const bad = (body: unknown) => {
  const r = parseClarifyRequest(body);
  if (r.ok) throw new Error('expected a refusal');
  return r.error;
};

describe('parseClarifyRequest', () => {
  it('accepts a well-formed request and returns it normalized', () => {
    const body = { candidates: [{ verb: 'cart.add', values: { [QTY]: 3, 'action.resource': 'shop/x', 'action.params.note': 'hi' } }], reason: 'other' };
    expect(parseClarifyRequest(body)).toEqual({ ok: true, request: { candidates: body.candidates, reason: 'other' } });
  });
  it('refuses a body that is not an object', () => {
    for (const b of [null, 'x', 5, [], undefined]) expect(bad(b)).toBe('body must be an object');
  });
  it('refuses unknown members (no text)', () => {
    expect(bad({ candidates: [cand()], reason: 'other', text: 'hi' })).toBe('unknown member "text" (clarifications carry no text)');
  });
  it('refuses an unknown reason, naming the closed enum', () => {
    const msg = `reason must be one of ${CLARIFY_REASONS.join(', ')}`;
    for (const reason of ['urgent', 5, undefined]) expect(bad({ candidates: [cand()], reason })).toBe(msg);
    expect(msg).toContain('ambiguous_parameter, multiple_options');
  });
  it('bounds the candidate count to 1..8', () => {
    const msg = `candidates must be 1..${MAX_CANDIDATES} structured actions`;
    expect(MAX_CANDIDATES).toBe(8);
    for (const candidates of [[], Array.from({ length: 9 }, () => cand()), 'x', undefined, {}]) expect(bad({ candidates, reason: 'other' })).toBe(msg);
    expect(parseClarifyRequest({ candidates: Array.from({ length: 8 }, () => cand()), reason: 'other' }).ok).toBe(true);
    expect(parseClarifyRequest({ candidates: [cand()], reason: 'other' }).ok).toBe(true);
  });
  it('refuses a candidate that is not an object, with its index', () => {
    for (const c of [null, 'x', 5, []]) expect(bad({ candidates: [cand(), c], reason: 'other' })).toBe('candidates[1] must be an object');
  });
  it('refuses unknown members of a candidate', () => {
    expect(bad({ candidates: [{ ...cand(), label: 'cheap' }], reason: 'other' })).toBe('candidates[0] has an unknown member "label"');
  });
  it('requires a non-empty verb of at most 128 characters', () => {
    const msg = 'candidates[0].verb must be a non-empty string';
    for (const verb of ['', 5, null, undefined, 'v'.repeat(129)]) expect(bad({ candidates: [{ verb, values: {} }], reason: 'other' })).toBe(msg);
    expect(parseClarifyRequest({ candidates: [{ verb: 'v'.repeat(128), values: {} }], reason: 'other' }).ok).toBe(true);
  });
  it('requires an object of values, at most 64 of them', () => {
    for (const values of [undefined, null, 'x', [], 5]) expect(bad({ candidates: [{ verb: 'v', values }], reason: 'other' })).toBe('candidates[0].values must be an object');
    const many = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`action.params.p${i}`, i]));
    expect(bad({ candidates: [{ verb: 'v', values: many(65) }], reason: 'other' })).toBe('candidates[0] has too many values');
    expect(parseClarifyRequest({ candidates: [{ verb: 'v', values: many(64) }], reason: 'other' }).ok).toBe(true);
  });
  it('refuses malformed paths before anything else about the value', () => {
    for (const p of ['bad path', '1x', 'action..x', 'a-b']) expect(bad({ candidates: [{ verb: 'v', values: { [p]: 1 } }], reason: 'other' })).toBe('candidates[0] has a malformed path');
  });
  it('lets the agent name only the action: action.resource and action.params.*', () => {
    const msg = 'candidates[0].values may only name action.params.* or action.resource';
    for (const p of ['env.acc.spend.post', 'action', 'resource', 'action.paramsx.y']) expect(bad({ candidates: [{ verb: 'v', values: { [p]: 1 } }], reason: 'other' })).toBe(msg);
    expect(parseClarifyRequest({ candidates: [{ verb: 'v', values: { 'action.resource': 'r' } }], reason: 'other' }).ok).toBe(true);
  });
  it('numbers must be safe integers; strings at most 256 characters; nothing else', () => {
    const num = `candidates[0].values.${QTY} must be a safe integer`;
    for (const v of [1.5, -0, 2 ** 53, Number.NaN, Infinity]) expect(bad({ candidates: [cand(v)], reason: 'other' })).toBe(num);
    expect(parseClarifyRequest({ candidates: [cand(-5)], reason: 'other' }).ok).toBe(true);
    const other = `candidates[0].values.${QTY} must be a string (≤ 256) or an integer`;
    for (const v of [true, null, {}, [], 'x'.repeat(257)]) expect(bad({ candidates: [cand(v)], reason: 'other' })).toBe(other);
    expect(parseClarifyRequest({ candidates: [cand('x'.repeat(256))], reason: 'other' }).ok).toBe(true);
    expect(parseClarifyRequest({ candidates: [cand('')], reason: 'other' }).ok).toBe(true);
  });
});

describe('informationGain', () => {
  it('is the entropy of the answer minus the noise entropy, under asymmetric noise', () => {
    expect(informationGain(0.5, 0, 0)).toBeCloseTo(1, 12);
    expect(informationGain(0.3, 0.1, 0.2)).toBeCloseTo(binEnt(0.3 * 0.8 + 0.7 * 0.1) - (0.3 * binEnt(0.2) + 0.7 * binEnt(0.1)), 12);
    expect(informationGain(0.3, 0.1, 0.2)).toBeCloseTo(0.3482981, 6);
    expect(informationGain(0.8, 0.05, 0.3)).toBeCloseTo(binEnt(0.8 * 0.7 + 0.2 * 0.05) - (0.8 * binEnt(0.3) + 0.2 * binEnt(0.05)), 12);
  });
});

describe('planClarification', () => {
  const KEYS = ['a', 'b', 'c', 'd', 'e'];
  const dim: Dim = { kind: 'cat', path: 'action.params.k', values: KEYS.map((value) => ({ kind: 'exact' as const, value })) };
  const OM: Omega = { v: 1, approximate: [], verbs: [{ verb: 'pick', reversibility: 'reversible', weight: 1, dims: [dim] }] };
  const harmOf = (h: Record<string, number>): HarmModel => ({ verb: () => 1, dim: (_d, x) => h[String(x)] ?? 1 });
  const at = (k: string) => ({ verb: 'pick', values: { 'action.params.k': k } });
  const plan = (
    keys: string[],
    o: { p?: Record<string, number>; h?: Record<string, number>; veto?: string[]; out?: string[]; asked?: string[] } = {},
  ) => {
    const idx = (i: readonly number[]) => KEYS[i[0]!]!;
    const input: ClarifyPlanInput = {
      omega: OM,
      view: {
        p: (_v, i) => o.p?.[idx(i)] ?? 0.5,
        vetoed: (_v, i) => (o.veto ?? []).includes(idx(i)),
        outsideCeiling: (_v, i) => (o.out ?? []).includes(idx(i)),
      },
      candidates: keys.map(at),
      asked: new Set(o.asked ?? []),
      etaPos: 0,
      etaNeg: 0,
      harm: harmOf(o.h ?? {}),
    };
    return planClarification(input);
  };

  it('classifies each candidate: outside, denied (ceiling, veto, p <= 0), admitted, asked, uncertain', () => {
    const r = plan(['a', 'b', 'c', 'd', 'e', 'zz'], { out: ['a'], veto: ['b'], p: { c: 0, d: 1 }, asked: ['pick|4'] });
    expect(r.verdicts).toEqual([
      { index: 0, verdict: 'denied' },
      { index: 1, verdict: 'denied' },
      { index: 2, verdict: 'denied' },
      { index: 3, verdict: 'admitted' },
      { index: 4, verdict: 'asked' },
      { index: 5, verdict: 'outside' },
    ]);
    expect(r.ask).toBeNull();
  });
  it('a ceiling-only cell and a veto-only cell are each denied', () => {
    expect(plan(['a'], { out: ['a'] }).verdicts).toEqual([{ index: 0, verdict: 'denied' }]);
    expect(plan(['a'], { veto: ['a'] }).verdicts).toEqual([{ index: 0, verdict: 'denied' }]);
  });
  it('asks the cell with the greatest information gain', () => {
    const r = plan(['b', 'a'], { p: { a: 0.5, b: 0.2 }, h: { b: 9, a: 1 } });
    expect(r.ask).toEqual({ index: 1, verb: 'pick', idx: [0], p: 0.5, ig: informationGain(0.5, 0, 0) });
    expect(plan(['a', 'b'], { p: { a: 0.5, b: 0.2 }, h: { b: 9, a: 1 } }).ask).toMatchObject({ index: 0, idx: [0] });
    expect(plan(['a', 'b'], { p: { a: 0.2, b: 0.5 }, h: { a: 9, b: 1 } }).ask).toMatchObject({ index: 1, idx: [1] });
  });
  it('ties on gain go to the larger risk weight (mass times harm)', () => {
    expect(plan(['a', 'b'], { h: { a: 1, b: 3 } }).ask).toMatchObject({ index: 1, idx: [1] });
    expect(plan(['b', 'a'], { h: { a: 1, b: 3 } }).ask).toMatchObject({ index: 0, idx: [1] });
    expect(plan(['a', 'b', 'c'], { h: { a: 1, b: 3, c: 2 } }).ask).toMatchObject({ index: 1, idx: [1] });
  });
  it('then to the lower cell index, whatever the candidate order', () => {
    expect(plan(['a', 'b'], { h: { a: 2, b: 2 } }).ask).toMatchObject({ index: 0, idx: [0] });
    expect(plan(['b', 'a'], { h: { a: 2, b: 2 } }).ask).toMatchObject({ index: 1, idx: [0] });
    expect(plan(['c', 'a', 'b'], { h: { a: 2, b: 2, c: 2 } }).ask).toMatchObject({ index: 1, idx: [0] });
  });
  it('a lower-weight cell with a lower index does not displace a heavier one', () => {
    expect(plan(['b', 'a'], { h: { a: 1, b: 5 } }).ask).toMatchObject({ index: 0, idx: [1] });
  });
  it('repeated candidates for one cell are all uncertain and the first is asked', () => {
    const r = plan(['b', 'b', 'a'], { h: { a: 1, b: 3 } });
    expect(r.verdicts.map((v) => v.verdict)).toEqual(['uncertain', 'uncertain', 'uncertain']);
    expect(r.ask).toMatchObject({ index: 0, idx: [1] });
  });
  it('equal gain, weight and flat index across verbs keeps the earlier candidate', () => {
    const twin: Omega = { v: 1, approximate: [], verbs: [{ ...OM.verbs[0]!, weight: 0.5 }, { ...OM.verbs[0]!, verb: 'pick2', weight: 0.5 }] };
    const r = planClarification({
      omega: twin,
      view: { p: () => 0.5, vetoed: () => false, outsideCeiling: () => false },
      candidates: [at('a'), { verb: 'pick2', values: { 'action.params.k': 'a' } }],
      asked: new Set<string>(),
      etaPos: 0,
      etaNeg: 0,
      harm: harmOf({}),
    });
    expect(r.ask).toMatchObject({ index: 0, verb: 'pick', idx: [0] });
  });
});
