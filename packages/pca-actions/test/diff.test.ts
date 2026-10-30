import { conformAction } from '@atlasauth/pca/ext/intent';
import { describe, expect, it } from 'vitest';
import { confirmed, testReview } from './reviewed';
import { BUILTIN_DEFS, CORE_REGISTRY, DECISION_RANK, effective, floorDecision, leq, diffDefs, toSchemaVerb, validateDef, CAVEAT_KINDS, CONTEXT_KEYS, type ActionDef, type CaveatKind } from '../src';
import { rng, genDef } from './vectors-gen';
import { mutate, sampleCalls } from './mutate';
import { runs } from './runs';

const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const patch = (d: ActionDef, f: (x: Record<string, any>) => void): ActionDef => {
  const c = clone(d) as unknown as Record<string, any>;
  f(c);
  expect(validateDef(c)).toBeNull();
  return c as ActionDef;
};
const cls = (a: ActionDef, b: ActionDef) => diffDefs(a, b).class;

describe('semantic diff: classes', () => {
  it('only text changed is equal', () => {
    const r = diffDefs(refund, patch(refund, (x) => { x.title = 'Refund a payment'; x.description = 'New wording.'; }));
    expect(r.class).toBe('equal');
    expect(r.reasons).toEqual(['text: title, description or compensates changed']);
  });
  it('an identical definition is equal with no reasons', () => {
    expect(diffDefs(refund, clone(refund))).toEqual({ class: 'equal', reasons: [] });
  });
  it('tightening a bound is narrow, loosening it is widen', () => {
    expect(cls(refund, patch(refund, (x) => { x.params.amount.max = 5000; }))).toBe('narrow');
    expect(cls(refund, patch(refund, (x) => { x.params.amount.max = 999_999_999_999; }))).toBe('widen');
    expect(cls(refund, patch(refund, (x) => { x.params.amount.min = 100; }))).toBe('narrow');
    expect(cls(refund, patch(refund, (x) => { x.params.amount.min = 0; }))).toBe('widen');
  });
  it('a lowered reversibility, blast or idempotency is widen', () => {
    expect(cls(refund, patch(refund, (x) => { x.reversibility = 'reversible'; }))).toBe('widen');
    expect(cls(refund, patch(refund, (x) => { x.blast = { radius: 'one' }; }))).not.toBe('narrow');
    expect(cls(refund, patch(refund, (x) => { delete x.idempotency; delete x.params.idempotency_key; }))).not.toBe('narrow');
  });
  it('a trait added is narrow, a trait removed is widen', () => {
    const base = patch(refund, (x) => { x.traits = ['pca.pii_access']; });
    expect(cls(refund, base)).toBe('narrow');
    expect(cls(base, refund)).toBe('widen');
  });
  it('confirmed -> unconfirmed only tightens; unconfirmed -> confirmed (fewer traits) is a widening unless a verifier-checked confirmation says otherwise', () => {
    const c = confirmed(refund);
    const edited = { ...patch(refund, (x) => { x.title = 'Refund a payment'; }), review: { state: 'authored' as const } };
    const o = testReview();
    // the edit changes the digest: the old attestation is stale, so the new version is unconfirmed (top) - narrow, never widen
    const down = diffDefs(c, edited, CORE_REGISTRY, o);
    expect(down.class).toBe('narrow');
    expect(down.reasons).toEqual(expect.arrayContaining(['confirmation: narrow', 'effective.traits: narrow', 'text: title, description or compensates changed']));
    const up = diffDefs(edited, confirmed(edited), CORE_REGISTRY, o);
    expect(up.class).toBe('widen');
    expect(up.reasons).toContain('confirmation: widen');
    // without a verifier nothing is confirmed: neither side lowers the other
    expect(diffDefs(c, edited, CORE_REGISTRY).class).toBe('equal');
  });
  it('a new optional parameter is widen; a new required one and a removed required one are incomparable', () => {
    expect(cls(refund, patch(refund, (x) => { x.params.note = { type: 'string', max_len: 64, required: false }; }))).toBe('widen');
    expect(cls(refund, patch(refund, (x) => { x.params.note = { type: 'string', max_len: 64 }; }))).toBe('incomparable');
    expect(cls(refund, patch(refund, (x) => { delete x.params.charge; }))).toBe('incomparable');
  });
  it('removing an optional parameter is narrow; required to optional is widen; optional to required is narrow', () => {
    const opt = patch(refund, (x) => { x.params.note = { type: 'string', max_len: 64, required: false }; });
    expect(cls(opt, refund)).toBe('narrow');
    expect(cls(refund, patch(refund, (x) => { x.params.charge.required = false; }))).toBe('widen');
    expect(cls(opt, patch(opt, (x) => { x.params.note.required = true; }))).toBe('narrow');
  });
  it('an enum value added is widen, removed is narrow', () => {
    const e = patch(refund, (x) => { x.params.reason = { type: 'string', values: ['duplicate', 'fraud'], max_len: 16 }; });
    expect(cls(e, patch(e, (x) => { x.params.reason.values.push('other'); }))).toBe('widen');
    expect(cls(e, patch(e, (x) => { x.params.reason.values = ['fraud']; }))).toBe('narrow');
  });
  it('max_len and max_items raised are widen', () => {
    const a = patch(refund, (x) => { x.params.memo = { type: 'string', max_len: 100 }; x.params.ids = { type: 'array', items: 'string', max_items: 4 }; });
    expect(cls(a, patch(a, (x) => { x.params.memo.max_len = 200; }))).toBe('widen');
    expect(cls(a, patch(a, (x) => { x.params.ids.max_items = 8; }))).toBe('widen');
    expect(cls(a, patch(a, (x) => { x.params.ids.max_items = 2; }))).toBe('narrow');
  });
  it('sensitivity lowered and provenance loosened are widen; the inverse is narrow', () => {
    const a = patch(refund, (x) => { x.params.memo = { type: 'string', max_len: 100, sensitivity: 'material', provenance_min: 'tool' }; });
    expect(cls(a, patch(a, (x) => { x.params.memo.sensitivity = 'free'; }))).toBe('widen');
    expect(cls(a, patch(a, (x) => { x.params.memo.sensitivity = 'critical'; }))).toBe('narrow');
    expect(cls(a, patch(a, (x) => { x.params.memo.provenance_min = 'agent'; }))).toBe('widen');
    expect(cls(a, patch(a, (x) => { x.params.memo.provenance_min = 'first_party'; }))).toBe('narrow');
  });
  it('a changed unit, role or binding is incomparable', () => {
    expect(cls(refund, patch(refund, (x) => { x.params.amount.unit = { kind: 'money', ccy: 'EUR', exp: 2 }; }))).toBe('incomparable');
    expect(cls(refund, patch(refund, (x) => { x.bindings = { mcp: { tool: 'other_tool' } }; }))).toBe('incomparable');
  });
  it('a resource id pattern that is not contained in the old one is widen; a contained one is narrow', () => {
    const wide = patch(refund, (x) => { x.resource.id = { prefix: 'ch_', class: 'alnum', len: [8, 64] }; });
    const narrower = patch(wide, (x) => { x.resource.id = { prefix: 'ch_', class: 'hex', len: [8, 32] }; });
    expect(cls(wide, narrower)).toBe('narrow');
    expect(cls(narrower, wide)).toBe('widen');
  });
  it('effects removed is widen, a wider scope is widen, new aliases are widen', () => {
    const two = patch(refund, (x) => { x.effects = ['pay', 'send']; });
    expect(cls(two, refund)).toBe('widen');
    expect(cls(refund, two)).toBe('narrow');
    // a wider scope widens the resource but also implies pca.bulk (a restriction): no order, so never free
    expect(cls(refund, patch(refund, (x) => { x.resource.scope = 'set'; }))).toBe('incomparable');
    expect(cls(refund, patch(refund, (x) => { x.aliases = [...x.aliases, 'give_money_back']; }))).toBe('widen');
  });
  it('one dimension widening while another narrows is incomparable', () => {
    expect(cls(refund, patch(refund, (x) => { x.params.amount.max = 5000; x.params.amount.min = 0; }))).toBe('incomparable');
  });
  it('two different verbs cannot be diffed', () => {
    expect(() => diffDefs(refund, BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!)).toThrow(/diff compares two versions of one verb/);
  });
});

type Classify = (a: ActionDef, b: ActionDef) => string;

/** The first (old, new, why) for which `classify` says equal/narrow but the new definition is more permissive; null if none in `n` mutants. */
function findViolation(classify: Classify, seed: number, n: number): { checked: number; free: number; violation: string | null } {
  const r = rng(seed);
  let free = 0;
  let checked = 0;
  for (let i = 0; i < n; i++) {
    const base = genDef(r, i);
    if (validateDef(base) !== null) continue;
    const m = mutate(base, r);
    if (m === null) continue;
    checked++;
    const c = classify(base, m);
    if (c !== 'equal' && c !== 'narrow') continue;
    free++;
    const eo = effective(base, CORE_REGISTRY).hint.eff;
    const en = effective(m, CORE_REGISTRY).hint.eff;
    if (!leq(eo, en)) return { checked, free, violation: 'the effective profile fell' };
    const so = { verbs: [toSchemaVerb(base, CORE_REGISTRY).verb] };
    const sn = { verbs: [toSchemaVerb(m, CORE_REGISTRY).verb] };
    for (const call of sampleCalls([base, m], r, 40)) {
      if (conformAction(sn, m.verb, call).ok && !conformAction(so, base.verb, call).ok) return { checked, free, violation: `a call the new def accepts is refused by the old one: ${JSON.stringify(call)}` };
    }
    for (let k = 0; k < 4; k++) {
      const g = { caveats: r.sub(CAVEAT_KINDS) as CaveatKind[], max_esc: r.int(0, 3), preauth_esc: r.int(0, 3) };
      const ctx = { context: r.sub(CONTEXT_KEYS) };
      if (DECISION_RANK[floorDecision(g, ctx, en)] > DECISION_RANK[floorDecision(g, ctx, eo)]) return { checked, free, violation: 'FloorDecision rose' };
    }
  }
  return { checked, free, violation: null };
}

describe('semantic diff: soundness oracle', () => {
  it('equal/narrow implies the new definition accepts only calls the old one accepts and never lowers the floors', () => {
    const n = runs(100_000);
    const res = findViolation((a, b) => diffDefs(a, b).class, 0xd1ff04, n);
    expect(res.violation).toBeNull();
    expect(res.checked).toBeGreaterThan(Math.floor(n * 0.4));
    expect(res.free).toBeGreaterThan(0);
  });
  // negative controls: classifiers with a deliberate hole are caught by the same oracle
  it('negative control: a classifier that ignores parameters is caught', () => {
    const blind: Classify = (a, b) => (diffDefs({ ...a, params: {} }, { ...b, params: {} }).class);
    expect(findViolation(blind, 0xd1ff05, 4000).violation).not.toBeNull();
  });
  it('negative control: a classifier that calls every change narrow is caught', () => {
    expect(findViolation(() => 'narrow', 0xd1ff06, 2000).violation).not.toBeNull();
  });
  it('negative control: a classifier that ignores the effective profile is caught', () => {
    const noProfile: Classify = (a, b) => (diffDefs({ ...a, effects: ['read'], traits: [], reversibility: 'reversible' }, { ...b, effects: ['read'], traits: [], reversibility: 'reversible' }).class);
    expect(findViolation(noProfile, 0xd1ff07, 4000).violation).not.toBeNull();
  });
});
