// Exact behaviour of the def normal form that the other tests leave open: sensitivity floors, the worst reversibility of a
// value-dependent declaration, the per-param defaults and the side-effect order.
import { describe, expect, it } from 'vitest';
import { effectiveParamSensitivity, normalize, sensitivityFloor, worstReversibility, type ActionDef, type ParamDef, type ReversibilityDecl } from '../src';

const def = (over: Partial<ActionDef> = {}): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: 'a.b.c', title: 'T', effects: ['read'], resource: { type: 'a.b', id: '*', scope: 'one' }, params: {}, review: { state: 'authored' }, ...over,
});
const P = (type: string, extra: object = {}): ParamDef => ({ type, ...extra }) as ParamDef;

describe('sensitivityFloor', () => {
  it.each([
    ['nothing', {}, 'free'],
    ['a critical role', { role: 'money.amount' }, 'critical'],
    ['a material role', { role: 'person.name' }, 'material'],
    ['an unknown role', { role: 'x.acme.thing' }, 'free'],
    ['a role named like an object member', { role: 'constructor' }, 'free'],
    ['a material tag', { tags: ['pii'] }, 'material'],
    ['a critical tag', { tags: ['secret'] }, 'critical'],
    ['a critical tag after a material one', { tags: ['pii', 'secret'] }, 'critical'],
    ['an unknown tag', { tags: ['nonsense'] }, 'free'],
    ['an unknown tag before a critical one', { tags: ['nonsense', 'secret'] }, 'critical'],
    ['an unknown tag after a critical one', { tags: ['secret', 'nonsense'] }, 'critical'],
    ['an unknown tag after a material one', { tags: ['pii', 'nonsense'] }, 'material'],
    ['a tag named like an object member', { tags: ['toString'] }, 'free'],
    ['a material role and a critical tag', { role: 'person.name', tags: ['secret'] }, 'critical'],
    ['a critical role and a material tag', { role: 'money.amount', tags: ['pii'] }, 'critical'],
  ])('%s', (_l, p, want) => {
    expect(sensitivityFloor(p as never)).toBe(want);
  });
});

describe('effectiveParamSensitivity: the declared value, raised to the floor', () => {
  it.each([
    ['nothing declared, no floor', {}, 'free'],
    ['nothing declared, a material floor', { tags: ['pii'] }, 'material'],
    ['free declared under a material floor', { tags: ['pii'], sensitivity: 'free' }, 'material'],
    ['critical declared over a material floor', { tags: ['pii'], sensitivity: 'critical' }, 'critical'],
    ['material declared over no floor', { sensitivity: 'material' }, 'material'],
    ['material declared under a critical floor', { role: 'money.amount', sensitivity: 'material' }, 'critical'],
  ])('%s', (_l, p, want) => {
    expect(effectiveParamSensitivity(p as never)).toBe(want);
  });
});

describe('worstReversibility', () => {
  const w = (r: ReversibilityDecl, params: Record<string, ParamDef>) => worstReversibility(r, params);
  it('a plain class is itself', () => expect(w('rate_limited', {})).toBe('rate_limited'));
  it('a boolean map that names both spellings covers the domain: the default is ignored', () => {
    const f = { f: P('boolean') };
    expect(w({ by: 'f', map: { true: 'reversible', false: 'reversible' }, default: 'irreversible' }, f)).toBe('reversible');
    expect(w({ by: 'f', map: { true: 'reversible', false: 'rate_limited' }, default: 'irreversible' }, f)).toBe('rate_limited');
    expect(w({ by: 'f', map: { true: 'irreversible', false: 'reversible' } }, f)).toBe('irreversible');
  });
  it('a boolean map that misses a spelling falls back to the default, or to irreversible', () => {
    const f = { f: P('boolean') };
    expect(w({ by: 'f', map: { true: 'reversible' }, default: 'irreversible' }, f)).toBe('irreversible');
    expect(w({ by: 'f', map: { false: 'reversible' }, default: 'irreversible' }, f)).toBe('irreversible');
    expect(w({ by: 'f', map: { true: 'reversible' }, default: 'rate_limited' }, f)).toBe('rate_limited');
    expect(w({ by: 'f', map: { true: 'reversible' } }, f)).toBe('irreversible');
  });
  it('a string enum is covered when every value is mapped', () => {
    const f = { f: P('string', { values: ['a', 'b'] }) };
    expect(w({ by: 'f', map: { a: 'reversible', b: 'reversible' }, default: 'irreversible' }, f)).toBe('reversible');
    expect(w({ by: 'f', map: { a: 'reversible', b: 'rate_limited' }, default: 'irreversible' }, f)).toBe('rate_limited');
    expect(w({ by: 'f', map: { a: 'irreversible', b: 'reversible' } }, f)).toBe('irreversible');
  });
  it('a string enum with an unmapped value is not covered, even when some value is mapped', () => {
    const f = { f: P('string', { values: ['a', 'b'] }) };
    expect(w({ by: 'f', map: { a: 'reversible' }, default: 'irreversible' }, f)).toBe('irreversible');
    expect(w({ by: 'f', map: { a: 'reversible' }, default: 'rate_limited' }, f)).toBe('rate_limited');
    expect(w({ by: 'f', map: { a: 'reversible' } }, f)).toBe('irreversible');
  });
  it('a param whose domain is open (a string without values, any other type, or no such param) is never covered', () => {
    const map = { a: 'reversible' } as const;
    expect(w({ by: 'f', map, default: 'rate_limited' }, { f: P('string') })).toBe('rate_limited');
    expect(w({ by: 'f', map }, { f: P('string') })).toBe('irreversible');
    expect(w({ by: 'f', map }, { f: P('integer') })).toBe('irreversible');
    expect(w({ by: 'f', map }, { f: P('integer', { values: ['a'] }) })).toBe('irreversible');
    expect(w({ by: 'f', map }, {})).toBe('irreversible');
    expect(w({ by: 'f', map, default: 'rate_limited' }, {})).toBe('rate_limited');
  });
});

describe('normalize: params', () => {
  const norm = (params: Record<string, ParamDef>) => normalize(def({ params })).params;
  it('fills required (true by default, false kept) and the effective sensitivity, and sorts the param names', () => {
    const out = normalize(def({ params: { z: P('string', { required: false }), a: P('string', { tags: ['pii'] }) } })).params;
    expect(Object.keys(out)).toEqual(['a', 'z']);
    expect(out.a).toStrictEqual({ type: 'string', tags: ['pii'], required: true, sensitivity: 'material' });
    expect(out.z).toStrictEqual({ type: 'string', required: false, sensitivity: 'free' });
  });
  it('sorts and dedupes the tags', () => {
    expect(norm({ x: P('string', { tags: ['sql', 'pii', 'sql'] }) }).x!.tags).toEqual(['pii', 'sql']);
  });
  it('copies the values rather than sharing the array', () => {
    const values = ['b', 'a'];
    const out = norm({ x: P('string', { values }) }).x!;
    expect(out.values).toEqual(['b', 'a']);
    expect(out.values).not.toBe(values);
  });
  it('sorts and dedupes a declared accumulates', () => {
    expect(norm({ x: P('integer', { accumulates: ['b', 'a', 'b'] }) }).x!.accumulates).toEqual(['a', 'b']);
  });
  it('a money amount accumulates by its lower-cased currency; nothing else does', () => {
    const amount = (extra: object) => norm({ x: P('integer', { role: 'money.amount', ...extra }) }).x!;
    expect(amount({ unit: { kind: 'money', ccy: 'USD', exp: 2 } }).accumulates).toEqual(['money.usd']);
    expect(amount({ unit: { kind: 'money', ccy: 'USD', exp: 2 }, accumulates: ['b', 'a'] }).accumulates).toEqual(['a', 'b']);
    expect('accumulates' in amount({})).toBe(false);
    expect('accumulates' in amount({ unit: { kind: 'money', ccy: { from: 'c' }, exp: 2 } })).toBe(false);
    expect('accumulates' in amount({ unit: { kind: 'count', ccy: 'USD' } })).toBe(false);
    const other = norm({ x: P('integer', { role: 'money.fee', unit: { kind: 'money', ccy: 'USD', exp: 2 } }) }).x!;
    expect('accumulates' in other).toBe(false);
  });
});

describe('normalize: reversibility and side effects', () => {
  it('a value-dependent reversibility is copied, and an absent default stays absent', () => {
    const r = { by: 'f', map: { x: 'reversible' as const } };
    const n = normalize(def({ reversibility: r })).reversibility;
    expect(n).toStrictEqual({ by: 'f', map: { x: 'reversible' } });
    expect(n).not.toBe(r);
    expect((n as { map: object }).map).not.toBe(r.map);
    expect(normalize(def({ reversibility: { ...r, default: 'rate_limited' } })).reversibility).toStrictEqual({ by: 'f', map: { x: 'reversible' }, default: 'rate_limited' });
  });
  it('side effects are ordered by target, then kind, and keep only those two members', () => {
    const se = [
      { target: 'b', kind: 'send' }, { target: 'a', kind: 'update' }, { target: 'b', kind: 'create' },
      { target: 'a', kind: 'create' }, { target: 'c', kind: 'create' }, { target: 'a', kind: 'send', extra: 1 },
    ];
    const want = [
      { target: 'a', kind: 'create' }, { target: 'a', kind: 'send' }, { target: 'a', kind: 'update' },
      { target: 'b', kind: 'create' }, { target: 'b', kind: 'send' }, { target: 'c', kind: 'create' },
    ];
    expect(normalize(def({ side_effects: se as never })).side_effects).toStrictEqual(want);
    expect(normalize(def({ side_effects: [...se].reverse() as never })).side_effects).toStrictEqual(want);
    expect(normalize(def({ side_effects: [se[0], se[1]] as never })).side_effects).toStrictEqual([{ target: 'a', kind: 'update' }, { target: 'b', kind: 'send' }]);
    expect(normalize(def({ side_effects: [se[1], se[0]] as never })).side_effects).toStrictEqual([{ target: 'a', kind: 'update' }, { target: 'b', kind: 'send' }]);
    expect(normalize(def({ side_effects: [se[2], se[3]] as never })).side_effects).toStrictEqual([{ target: 'a', kind: 'create' }, { target: 'b', kind: 'create' }]);
    expect(normalize(def()).side_effects).toEqual([]);
  });
});
