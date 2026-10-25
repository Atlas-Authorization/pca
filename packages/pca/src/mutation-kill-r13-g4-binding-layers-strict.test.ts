/**
 * r13 mutation kills for intent-binding.ts, intent-layers.ts and intent-strict.ts: exact wire reasons, the root-grant
 * lookup on non-grants, every fail-closed catch (reached with a getter that throws or an input only the strict encoder
 * refuses), and the strictness helpers on primitives and null (where a dropped `typeof` / null guard would throw or
 * read a string's own index). Fixtures are built inside the tests.
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { decideIntentBinding, intentGoal, intentGoalCommit, intentPolicyActive, parseIntentGoal, rootGoalCommit, validateIntentWire, type EnvelopeIntent } from './intent-binding';
import { decideLayerCeilings, decideLayers, type LayerPolicy, type LayeredGrant } from './intent-layers';
import { freeRecord, isPlainObject, isSafeInt, isSafeNonNeg, ownGet, ownHas, suiteCapabilityError } from './intent-strict';
import type { ActionContext } from './predicates';

/** The value, or 'THREW: <message>' (so a mutant that makes a total function throw fails an assertion). */
const val = <T>(f: () => T): T | string => {
  try {
    return f();
  } catch (e) {
    return `THREW: ${(e as Error).message}`;
  }
};
const D32 = (l: string) => b64u(sha256(utf8('r13-g4-binding/' + l)));
const INTENT = (): EnvelopeIntent => ({ ref: D32('ref'), map_digest: D32('map'), goal_salt: 'c2FsdA', fidelity_ppm: 950_000, residual_risk_ppm: 12_000 });

describe('validateIntentWire exact reasons', () => {
  it('non-objects, including undefined and null', () => {
    for (const v of [undefined, null, 5, 'x', [], true]) expect(val(() => validateIntentWire(v))).toBe("'intent' must be an object");
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
    for (const g of [undefined, null, 5, 'g', [], {}, { caveats: 'x' }, { caveats: {} }, { caveats: null }]) expect(val(() => rootGoalCommit(g))).toBeNull();
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
      expect(val(() => decideLayerCeilings(l as never, ctx(1)))).toEqual({ status: 'fail', layer: 'org', reason: 'layers: the layers member is malformed (not an object)' });
    }
  });
  it('a malformed ceiling is named', () => {
    expect(decideLayerCeilings({ site: null as never }, ctx(1))).toEqual({ status: 'fail', layer: 'site', reason: 'layers: the site ceiling is malformed (null or not {predicates: [...]})' });
    expect(decideLayerCeilings({ org: cap(10), std: { predicates: [], x: 1 } as never }, ctx(1))).toEqual({ status: 'fail', layer: 'std', reason: 'layers: the std ceiling is malformed (null or not {predicates: [...]})' });
  });
  it('an action outside a ceiling names it', () => {
    expect(decideLayerCeilings({ org: cap(100), site: cap(10) }, ctx(20))).toEqual({ status: 'fail', layer: 'site', reason: 'layers: the action is outside the site ceiling (a ceiling is never a question)' });
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
    expect([undefined, null, 5, 's', true, [], new Date(0), {}, Object.create(null)].map((v) => val(() => isPlainObject(v)))).toEqual([false, false, false, false, false, false, false, true, true]);
  });
  it('ownGet', () => {
    expect(val(() => ownGet(null, 'a'))).toBeUndefined();
    expect(val(() => ownGet(undefined, 'a'))).toBeUndefined();
    expect(val(() => ownGet('abc', '0'))).toBeUndefined();
    expect(ownGet({ a: 1 }, 'a')).toBe(1);
    expect(ownGet(Object.defineProperty({}, 'a', { get: () => 1 }), 'a')).toBeUndefined();
  });
  it('ownHas', () => {
    expect(val(() => ownHas(null, 'a'))).toBe(false);
    expect(val(() => ownHas(undefined, 'a'))).toBe(false);
    expect(val(() => ownHas('abc', '0'))).toBe(false);
    expect(val(() => ownHas('abc', 'length'))).toBe(false);
    expect(val(() => ownHas(5, 'a'))).toBe(false);
    expect(ownHas({ a: undefined }, 'a')).toBe(true);
    expect(ownHas({}, 'toString')).toBe(false);
  });
});

/** The outcome of a call, compared with toEqual: a throw becomes { ok: false, error: { name, message } }. */
const settle = <T>(f: () => T): { ok: true; value: T } | { ok: false; error: { name: string; message: string } } => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: { name: (e as Error).name, message: (e as Error).message } };
  }
};

describe('intent-binding goals (fresh module for the constants)', () => {
  it('the published goal prefixes and fields', async () => {
    vi.resetModules();
    const b = await import('./intent-binding');
    expect([b.INTENT_GOAL_PREFIX, b.INTENT_GOAL_V2_PREFIX, b.INTENT_GOAL_V2C_PREFIX, b.INTENT_GOAL_COMMIT_DOMAIN, b.PPM_ONE, b.MAX_INTENT_GOAL_SALT_LEN]).toEqual([
      'pca-intent:v1:',
      'pca-intent:v2:',
      'pca-intent:v2c:',
      'atlas-pca/goal/v1\0',
      1_000_000,
      128,
    ]);
    expect(b.ENVELOPE_INTENT_FIELDS).toEqual(['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm']);
  });
  it('intentGoal / parseIntentGoal', () => {
    expect(settle(() => intentGoal('r'))).toEqual({ ok: true, value: 'pca-intent:v1:r' });
    expect(settle(() => intentGoal('r', 'm'))).toEqual({ ok: true, value: 'pca-intent:v1:r:m' });
    expect(settle(() => intentGoal('r', ''))).toEqual({ ok: true, value: 'pca-intent:v1:r' });
    for (const g of [5, null, undefined, 'x', 'pca-intent:v1:', 'pca-intent:v1:a:b:c']) expect(settle(() => parseIntentGoal(g as string))).toEqual({ ok: true, value: null });
    expect(settle(() => parseIntentGoal('pca-intent:v1:a'))).toEqual({ ok: true, value: { intentRef: 'a' } });
    expect(settle(() => parseIntentGoal('pca-intent:v1:a:b'))).toEqual({ ok: true, value: { intentRef: 'a', mapDigest: 'b' } });
  });
  it('intentGoalCommit: v1, v2 session and v2c committed-map goals', () => {
    const i = INTENT();
    const h = (goal: string) => hashCanonical({ d: 'atlas-pca/goal/v1\0', goal, salt: i.goal_salt });
    expect(intentGoalCommit(i)).toBe(h(`pca-intent:v1:${i.ref}:${i.map_digest}`));
    expect(intentGoalCommit(i, 'S')).toBe(h(`pca-intent:v2:S:${i.map_digest}`));
    expect(intentGoalCommit(i, 'S', 'plain')).toBe(h(`pca-intent:v2:S:${i.map_digest}`));
    expect(intentGoalCommit(i, 'S', 'commit')).toBe(h(`pca-intent:v2c:S:${i.map_digest}`));
    expect(intentGoalCommit(i, undefined, 'commit')).toBe(h(`pca-intent:v1:${i.ref}:${i.map_digest}`));
  });
  it('intentPolicyActive', () => {
    for (const [p, v] of [[undefined, false], [{}, false], [{ require: false }, false], [{ require: true }, true], [{ min_fidelity_ppm: 0 }, true], [{ max_residual_risk_ppm: 0 }, true]] as const) {
      expect(settle(() => intentPolicyActive(p as never))).toEqual({ ok: true, value: v });
    }
  });
  it('the goal_salt and residual_risk_ppm wire reasons', () => {
    for (const goal_salt of ['', 5, 'x'.repeat(129)]) expect(validateIntentWire({ ...INTENT(), goal_salt })).toBe("'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)");
    for (const r of [-1, 1.5, '5']) expect(validateIntentWire({ ...INTENT(), residual_risk_ppm: r })).toBe("'intent.residual_risk_ppm' must be a non-negative safe integer");
  });
});

describe('intent-strict exports (fresh module for the constants)', () => {
  it('RESERVED_NAMES and UNSUPPORTED_SUITE', async () => {
    vi.resetModules();
    const s = await import('./intent-strict');
    expect([...s.RESERVED_NAMES].sort()).toEqual(['__proto__', 'constructor', 'prototype']);
    expect(s.UNSUPPORTED_SUITE).toBe('unsupported_suite');
    expect(s.suiteCapabilityError('x', () => false)).toBe("unsupported_suite: 'x'");
  });
  it('ownGet reads data properties only, including a falsy value', () => {
    expect(settle(() => ownGet({ a: 0 }, 'a'))).toEqual({ ok: true, value: 0 });
    expect(settle(() => ownGet({}, 'a'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => ownGet({}, 'toString'))).toEqual({ ok: true, value: undefined });
    expect(settle(() => ownGet(Object.defineProperty({}, 'a', { get: () => 7 }), 'a'))).toEqual({ ok: true, value: undefined });
  });
  it('freeRecord is prototype-free', () => {
    const r = freeRecord<number>();
    expect(Object.getPrototypeOf(r)).toBeNull();
    expect(r.toString).toBeUndefined();
  });
  it('suiteCapabilityError', () => {
    const impl = (a: string) => a === 'ed25519';
    expect(settle(() => suiteCapabilityError(undefined, impl))).toEqual({ ok: true, value: null });
    expect(settle(() => suiteCapabilityError('ed25519', impl))).toEqual({ ok: true, value: null });
    expect(settle(() => suiteCapabilityError('mystery', impl))).toEqual({ ok: true, value: "unsupported_suite: 'mystery'" });
    for (const a of [5, null, {}]) expect(settle(() => suiteCapabilityError(a, impl))).toEqual({ ok: true, value: 'alg must be a string' });
  });
});
