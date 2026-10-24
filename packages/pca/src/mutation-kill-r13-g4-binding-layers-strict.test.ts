/**
 * r13 mutation kills for intent-binding.ts, intent-layers.ts and intent-strict.ts: exact wire reasons, the root-grant
 * lookup on non-grants, every fail-closed catch (reached with a getter that throws or an input only the strict encoder
 * refuses), and the strictness helpers on primitives and null (where a dropped `typeof` / null guard would throw or
 * read a string's own index). Fixtures are built inside the tests.
 */
import { describe, expect, it } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { decideIntentBinding, intentGoalCommit, rootGoalCommit, validateIntentWire, type EnvelopeIntent } from './intent-binding';
import { decideLayerCeilings, decideLayers, type LayerPolicy, type LayeredGrant } from './intent-layers';
import { isPlainObject, isSafeInt, isSafeNonNeg, ownGet, ownHas } from './intent-strict';
import type { ActionContext } from './predicates';

const D32 = (l: string) => b64u(sha256(utf8('r13-g4-binding/' + l)));
const INTENT = (): EnvelopeIntent => ({ ref: D32('ref'), map_digest: D32('map'), goal_salt: 'c2FsdA', fidelity_ppm: 950_000, residual_risk_ppm: 12_000 });

describe('validateIntentWire exact reasons', () => {
  it('non-objects, including undefined and null', () => {
    for (const v of [undefined, null, 5, 'x', [], true]) expect(validateIntentWire(v)).toBe("'intent' must be an object");
  });
  it('each member', () => {
    expect(validateIntentWire(INTENT())).toBeNull();
    expect(validateIntentWire({ ...INTENT(), ref: 'x' })).toBe("'intent.ref' is not canonical base64url (32 bytes)");
    expect(validateIntentWire({ ...INTENT(), map_digest: 'x' })).toBe("'intent.map_digest' is not canonical base64url (32 bytes)");
    for (const f of [-1, 1_000_001, 1.5, '5']) expect(validateIntentWire({ ...INTENT(), fidelity_ppm: f })).toBe("'intent.fidelity_ppm' must be a safe integer in [0, 1000000]");
  });
});

describe('rootGoalCommit on non-grants', () => {
  it('null for anything that is not an object with a caveats array', () => {
    for (const g of [undefined, null, 5, 'g', [], {}, { caveats: 'x' }, { caveats: {} }, { caveats: null }]) expect(rootGoalCommit(g)).toBeNull();
    expect(rootGoalCommit({ caveats: [{ type: 'envelope', goal_commit: 'gc' }] })).toBe('gc');
  });
});

describe('decideIntentBinding catch', () => {
  it('a goal salt the strict encoder refuses fails closed with the encoder reason', () => {
    const i = { ...INTENT(), goal_salt: '\uD800' };
    expect(decideIntentBinding(i, { caveats: [{ type: 'envelope', goal_commit: intentGoalCommit(INTENT()) }] })).toEqual({
      status: 'fail',
      reason: 'intent binding error (fail closed): canonicalize: lone surrogate in string',
    });
  });
});

const cap = (max: number): LayerPolicy => ({ predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: max }] }] });
const ctx = (total: number): ActionContext => ({ action: { verb: 'air.book', resource: 'r', params: { total } } });
const throwing = (k: string) => Object.defineProperty({}, k, { enumerable: true, get: () => { throw new Error('boom'); } });

describe('decideLayerCeilings exact outcomes', () => {
  it('an unknown member', () => {
    expect(decideLayerCeilings({ org: cap(10), bogus: 1 } as never, ctx(1))).toEqual({ status: 'fail', layer: 'org', reason: 'layers: unknown member (the layers object is {org?, site?, std?})' });
  });
  it('a non-object layers member', () => {
    for (const l of [null, undefined, 5, [], 'x']) {
      expect(decideLayerCeilings(l as never, ctx(1))).toEqual({ status: 'fail', layer: 'org', reason: 'layers: the layers member is malformed (not an object)' });
    }
  });
  it('a malformed ceiling is named', () => {
    expect(decideLayerCeilings({ site: null as never }, ctx(1))).toEqual({ status: 'fail', layer: 'site', reason: 'layers: the site ceiling is malformed (null or not {predicates: [...]})' });
    expect(decideLayerCeilings({ org: cap(10), std: { predicates: [], x: 1 } as never }, ctx(1))).toEqual({ status: 'fail', layer: 'std', reason: 'layers: the std ceiling is malformed (null or not {predicates: [...]})' });
  });
  it('an evaluation error fails closed, reported as org', () => {
    expect(decideLayerCeilings(throwing('site') as never, ctx(1))).toEqual({ status: 'fail', layer: 'org', reason: 'layers: evaluation error (fail closed): boom' });
  });
});

describe('decideLayers: malformed denied / task never admit', () => {
  it('a malformed denied entry that would not match is still intent_denied (not an admission)', () => {
    const task = [cap(100)];
    expect(decideLayers({ task, denied: [cap(0)] }, ctx(5))).toEqual({ decision: 'admit', by: 0 });
    expect(decideLayers({ task, denied: [{ ...cap(0), extra: 1 } as never] }, ctx(5))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task, denied: [cap(0), { predicates: 'x' } as never] }, ctx(5))).toEqual({ decision: 'intent_denied' });
  });
  it('a task list with one malformed entry is intent_denied even when an earlier entry admits', () => {
    expect(decideLayers({ task: [cap(100), { predicates: 'x' } as never] }, ctx(5))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task: [cap(100), cap(1)] }, ctx(5))).toEqual({ decision: 'admit', by: 0 });
    expect(decideLayers({ task: [cap(1), cap(100)] }, ctx(5))).toEqual({ decision: 'admit', by: 1 });
    expect(decideLayers({ task: [cap(1)] }, ctx(5))).toEqual({ decision: 'intent_required' });
  });
  it('a throwing member fails closed as intent_denied', () => {
    expect(decideLayers(throwing('task') as unknown as LayeredGrant, ctx(5))).toEqual({ decision: 'intent_denied' });
  });
});

describe('intent-strict helpers on primitives and null', () => {
  it('isSafeInt / isSafeNonNeg', () => {
    expect([1, 0, -1, 1.5, -0, '1', NaN, 2 ** 53].map(isSafeInt)).toEqual([true, true, true, false, false, false, false, false]);
    expect([1, 0, -1, -0].map(isSafeNonNeg)).toEqual([true, true, false, false]);
  });
  it('isPlainObject never throws on undefined / primitives', () => {
    expect([undefined, null, 5, 's', true, [], new Date(0), {}, Object.create(null)].map(isPlainObject)).toEqual([false, false, false, false, false, false, false, true, true]);
  });
  it('ownGet', () => {
    expect(ownGet(null, 'a')).toBeUndefined();
    expect(ownGet(undefined, 'a')).toBeUndefined();
    expect(ownGet('abc', '0')).toBeUndefined();
    expect(ownGet({ a: 1 }, 'a')).toBe(1);
    expect(ownGet(Object.defineProperty({}, 'a', { get: () => 1 }), 'a')).toBeUndefined();
  });
  it('ownHas', () => {
    expect(ownHas(null, 'a')).toBe(false);
    expect(ownHas(undefined, 'a')).toBe(false);
    expect(ownHas('abc', '0')).toBe(false);
    expect(ownHas('abc', 'length')).toBe(false);
    expect(ownHas(5, 'a')).toBe(false);
    expect(ownHas({ a: undefined }, 'a')).toBe(true);
    expect(ownHas({}, 'toString')).toBe(false);
  });
});
