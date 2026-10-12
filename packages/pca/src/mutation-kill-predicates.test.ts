/**
 * Mutation-kill tests for predicates.ts: exact Tri values for every leaf-op outcome, the params-availability guards,
 * resolvePath edge cases, glob / is_a / member_of internals, every boundary of the numeric limits, the cost accounting of
 * isSafeRegexSource, resource matching, and every built-in caveat (boundaries, fail-closed paths).
 */
import { describe, expect, it } from 'vitest';
import { compileSafeRegex } from './safe-regex';
import {
  envelopeCaveatEvaluator,
  evaluateCaveats,
  evaluateCondition,
  evaluateConditionTri,
  evaluatePredicates,
  isGroupCondition,
  isLeafCondition,
  isSafeRegexSource,
  MAX_LIKE_PATTERN_LEN,
  MAX_MATCHES_PATTERN_LEN,
  MAX_MEMBER_CLOSURE_NODES,
  MAX_PATTERN_SUBJECT_LEN,
  MAX_RE_RESOURCE_LEN,
  predicateMatches,
  resolvePath,
  REVERSIBILITY_ORDER,
  type ActionContext,
  type CaveatContext,
  type Condition,
  type Predicate,
} from './predicates';

const ctxOf = (o: Record<string, unknown> = {}): ActionContext => ({ action: { verb: 'v', resource: '/r' }, ...o }) as ActionContext;
const withParams = (params: unknown, extra: Record<string, unknown> = {}): ActionContext => ({ action: { verb: 'v', resource: '/r', params }, ...extra }) as ActionContext;
const tri = (c: unknown, ctx: ActionContext = ctxOf()) => evaluateConditionTri(c as Condition, ctx);

describe('type guards', () => {
  it('isGroupCondition: only objects with all_of / any_of / not; never throws on primitives', () => {
    expect(isGroupCondition({ all_of: [] })).toBe(true);
    expect(isGroupCondition({ any_of: [] })).toBe(true);
    expect(isGroupCondition({ not: {} } as never)).toBe(true);
    expect(isGroupCondition({ field: 'a', op: 'eq' })).toBe(false);
    for (const bad of [null, undefined, 5, 'all_of', true, [], ['all_of']]) expect(isGroupCondition(bad as never)).toBe(false);
  });
  it('isLeafCondition: object, not a group, string field', () => {
    expect(isLeafCondition({ field: 'a', op: 'eq' })).toBe(true);
    expect(isLeafCondition({ field: '', op: 'eq' })).toBe(true);
    expect(isLeafCondition({ field: 5 } as never)).toBe(false);
    expect(isLeafCondition({} as never)).toBe(false);
    expect(isLeafCondition({ field: 'a', not: {} } as never)).toBe(false);
    expect(isLeafCondition({ field: 'a', all_of: [] } as never)).toBe(false);
    expect(isLeafCondition({ field: 'a', any_of: [] } as never)).toBe(false);
    for (const bad of [null, undefined, 5, 'field', [], [{ field: 'a' }]]) expect(isLeafCondition(bad as never)).toBe(false);
  });
});

describe('resolvePath', () => {
  const ctx = {
    action: { verb: 'v', resource: '/r', params: { a: { b: [10, { c: 'deep' }, null] }, n: null, z: 0, e: '', f: false, 'x.y': 1 } },
    subject: { id: 's1' },
    env: { list: ['p', 'q'] },
  } as unknown as ActionContext;
  it('found / value for scalars incl. falsy and null leaves', () => {
    expect(resolvePath(ctx, 'action.verb')).toStrictEqual({ found: true, value: 'v' });
    expect(resolvePath(ctx, 'subject.id')).toStrictEqual({ found: true, value: 's1' });
    expect(resolvePath(ctx, 'action.params.z')).toStrictEqual({ found: true, value: 0 });
    expect(resolvePath(ctx, 'action.params.e')).toStrictEqual({ found: true, value: '' });
    expect(resolvePath(ctx, 'action.params.f')).toStrictEqual({ found: true, value: false });
    expect(resolvePath(ctx, 'action.params.n')).toStrictEqual({ found: true, value: null });
    expect(resolvePath(ctx, 'action.params.a.b.1.c')).toStrictEqual({ found: true, value: 'deep' });
    expect(resolvePath(ctx, 'action.params.a.b.2')).toStrictEqual({ found: true, value: null });
    expect(resolvePath(ctx, 'env.list.0')).toStrictEqual({ found: true, value: 'p' });
    expect(resolvePath(ctx, 'env.list.1')).toStrictEqual({ found: true, value: 'q' });
  });
  it('a root alone resolves to the root object; unknown roots / bad paths are not found (exactly {found:false})', () => {
    expect(resolvePath(ctx, 'subject')).toStrictEqual({ found: true, value: { id: 's1' } });
    for (const p of ['', 'nope', 'actionx', 'Action.verb', 'toString', '__proto__', 'constructor.name']) expect(resolvePath(ctx, p)).toStrictEqual({ found: false });
    for (const p of [undefined, null, 5, {}, ['action']]) expect(resolvePath(ctx, p)).toStrictEqual({ found: false });
    // root present as a key but undefined
    expect(resolvePath({ action: { verb: 'v', resource: 'r' } } as ActionContext, 'subject.id')).toStrictEqual({ found: false });
    expect(resolvePath({ action: { verb: 'v', resource: 'r' }, subject: undefined } as ActionContext, 'subject')).toStrictEqual({ found: false });
    expect(resolvePath(null as unknown as ActionContext, 'action.verb')).toStrictEqual({ found: false });
  });
  it('own properties only, forbidden segments, descent into non-objects', () => {
    for (const p of ['action.params.__proto__', 'action.params.constructor', 'action.params.prototype', 'action.__proto__.x', 'action.params.toString', 'action.params.hasOwnProperty']) {
      expect(resolvePath(ctx, p)).toStrictEqual({ found: false });
    }
    expect(resolvePath(ctx, 'action.verb.length')).toStrictEqual({ found: false }); // string is not an object
    expect(resolvePath(ctx, 'action.params.z.x')).toStrictEqual({ found: false });
    expect(resolvePath(ctx, 'action.params.n.x')).toStrictEqual({ found: false }); // null
    expect(resolvePath(ctx, 'action.params.missing')).toStrictEqual({ found: false });
    expect(resolvePath(ctx, 'action.params.a.b.1.nope')).toStrictEqual({ found: false });
    const inherited = { action: Object.assign(Object.create({ inheritedKey: 1 }), { verb: 'v', resource: 'r' }) } as ActionContext;
    expect(resolvePath(inherited, 'action.inheritedKey')).toStrictEqual({ found: false });
    // a key that holds undefined is not found
    expect(resolvePath({ action: { verb: 'v', resource: 'r', params: { u: undefined } } } as ActionContext, 'action.params.u')).toStrictEqual({ found: false });
  });
  it('array indices: canonical decimal only, in range only', () => {
    for (const p of ['env.list.01', 'env.list.-1', 'env.list.x', 'env.list.1.5', 'env.list.', 'env.list. 0', 'env.list.0x1', 'env.list.length', 'env.list.2', 'env.list.99', 'env.list.00']) {
      expect(resolvePath(ctx, p)).toStrictEqual({ found: false });
    }
    expect(resolvePath(ctx, 'env.list.0').found).toBe(true);
    const big = { action: { verb: 'v', resource: 'r', params: { l: Array.from({ length: 12 }, (_, i) => i * 10) } } } as unknown as ActionContext;
    expect(resolvePath(big, 'action.params.l.10')).toStrictEqual({ found: true, value: 100 });
    expect(resolvePath(big, 'action.params.l.11')).toStrictEqual({ found: true, value: 110 });
    expect(resolvePath(big, 'action.params.l.12')).toStrictEqual({ found: false });
    expect(resolvePath(big, 'action.params.l.1a')).toStrictEqual({ found: false });
    expect(resolvePath(big, 'action.params.l.a1')).toStrictEqual({ found: false });
    const holes = { action: { verb: 'v', resource: 'r', params: { l: [1, undefined, 3] } } } as unknown as ActionContext;
    expect(resolvePath(holes, 'action.params.l.1')).toStrictEqual({ found: false });
    expect(resolvePath(holes, 'action.params.l.2')).toStrictEqual({ found: true, value: 3 });
  });
  it('keys containing dots are unreachable (segments split on ".")', () => {
    expect(resolvePath(ctx, 'action.params.x.y')).toStrictEqual({ found: false });
  });
});

describe('leaf evaluation: exact Tri values', () => {
  const c = ctxOf({ subject: { role: 'admin', n: 5, s: 'abc', arr: ['a', 'b'], o: { x: 1, y: 2 }, nul: null, t: true } });
  it('malformed leaves are unknown (not false)', () => {
    expect(tri(null)).toBe('unknown');
    expect(tri(undefined)).toBe('unknown');
    expect(tri(5)).toBe('unknown');
    expect(tri('x')).toBe('unknown');
    expect(tri({ field: 'subject.role', op: 'eq' })).toBe('unknown'); // no value
    expect(tri({ field: 'subject.role' })).toBe('unknown');
    expect(tri({ field: 5, op: 'eq', value: 1 })).toBe('unknown');
    expect(tri({ field: '', op: 'eq', value: 1 }, c)).toBe('unknown');
    expect(tri({ field: '', op: 'exists' }, c)).toBe('unknown');
    expect(tri({ field: '', op: 'exists', value: false }, c)).toBe('unknown');
    expect(tri({ field: { length: 3, startsWith: () => false }, op: 'exists', value: false }, c)).toBe('unknown');
    expect(tri({ field: 'subject.role', op: 5, value: 1 }, c)).toBe('unknown');
    expect(tri({ field: 'subject.role', op: 'zz', value: 'admin' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.role', op: undefined, value: 'admin' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.nope', op: 'eq', value: 1 }, c)).toBe('unknown');
    expect(tri({ field: 'subject.role', op: 'eq', value: undefined }, c)).toBe('unknown');
  });
  it('eq / ne use canonical deep equality (key order irrelevant, array order relevant, type strict)', () => {
    expect(tri({ field: 'subject.role', op: 'eq', value: 'admin' }, c)).toBe('true');
    expect(tri({ field: 'subject.role', op: 'eq', value: 'user' }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'ne', value: 'admin' }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'ne', value: 'user' }, c)).toBe('true');
    expect(tri({ field: 'subject.n', op: 'eq', value: '5' }, c)).toBe('false');
    expect(tri({ field: 'subject.n', op: 'eq', value: 5 }, c)).toBe('true');
    expect(tri({ field: 'subject.o', op: 'eq', value: { y: 2, x: 1 } }, c)).toBe('true');
    expect(tri({ field: 'subject.arr', op: 'eq', value: ['b', 'a'] }, c)).toBe('false');
    expect(tri({ field: 'subject.arr', op: 'eq', value: ['a', 'b'] }, c)).toBe('true');
    expect(tri({ field: 'subject.nul', op: 'eq', value: null }, c)).toBe('true');
    expect(tri({ field: 'subject.t', op: 'eq', value: true }, c)).toBe('true');
    expect(tri({ field: 'subject.t', op: 'eq', value: 1 }, c)).toBe('false');
  });
  it('an uncanonicalizable operand/field compares unequal (eq false, ne true), never throws', () => {
    const nan = ctxOf({ subject: { x: NaN, f: () => 1 } });
    expect(tri({ field: 'subject.x', op: 'eq', value: NaN }, nan)).toBe('false');
    expect(tri({ field: 'subject.x', op: 'ne', value: NaN }, nan)).toBe('true');
    expect(tri({ field: 'subject.f', op: 'eq', value: 1 }, nan)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'eq', value: Infinity }, c)).toBe('false');
    expect(tri({ field: 'subject.x', op: 'in', value: [NaN] }, nan)).toBe('false');
    expect(tri({ field: 'subject.x', op: 'nin', value: [NaN] }, nan)).toBe('true');
  });
  it('in / nin: operand must be an array', () => {
    expect(tri({ field: 'subject.role', op: 'in', value: ['user', 'admin'] }, c)).toBe('true');
    expect(tri({ field: 'subject.role', op: 'in', value: ['user'] }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'in', value: [] }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'in', value: 'admin' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.role', op: 'in', value: { 0: 'admin' } }, c)).toBe('unknown');
    expect(tri({ field: 'subject.role', op: 'nin', value: ['user', 'admin'] }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'nin', value: ['user'] }, c)).toBe('true');
    expect(tri({ field: 'subject.role', op: 'nin', value: [] }, c)).toBe('true');
    expect(tri({ field: 'subject.role', op: 'nin', value: 'user' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.o', op: 'in', value: [{ y: 2, x: 1 }] }, c)).toBe('true');
  });
  it.each([
    ['lt', [-1, 0, 1], ['true', 'false', 'false']],
    ['lte', [-1, 0, 1], ['true', 'true', 'false']],
    ['gt', [-1, 0, 1], ['false', 'false', 'true']],
    ['gte', [-1, 0, 1], ['false', 'true', 'true']],
  ] as Array<[string, number[], string[]]>)('%s over numbers and strings (subject n=5, s="abc")', (op, rel, want) => {
    // n=5 vs operand 6 (v<operand => -1), 5 (0), 4 (+1)
    const operands = [6, 5, 4];
    operands.forEach((o, i) => expect(tri({ field: 'subject.n', op, value: o }, c), `${op} num ${rel[i]}`).toBe(want[i]));
    const strs = ['abd', 'abc', 'abb'];
    strs.forEach((o, i) => expect(tri({ field: 'subject.s', op, value: o }, c), `${op} str ${rel[i]}`).toBe(want[i]));
  });
  it('ordering operands must be comparable: same-type finite numbers or two strings, else unknown', () => {
    for (const op of ['lt', 'lte', 'gt', 'gte']) {
      expect(tri({ field: 'subject.n', op, value: '5' }, c)).toBe('unknown');
      expect(tri({ field: 'subject.s', op, value: 5 }, c)).toBe('unknown');
      expect(tri({ field: 'subject.t', op, value: false }, c)).toBe('unknown');
      expect(tri({ field: 'subject.t', op, value: true }, c)).toBe('unknown');
      expect(tri({ field: 'subject.nul', op, value: null }, c)).toBe('unknown');
      expect(tri({ field: 'subject.o', op, value: { x: 1, y: 2 } }, c)).toBe('unknown');
      expect(tri({ field: 'subject.arr', op, value: ['a', 'b'] }, c)).toBe('unknown');
      expect(tri({ field: 'subject.n', op, value: Infinity }, c)).toBe('unknown');
      expect(tri({ field: 'subject.n', op, value: -Infinity }, c)).toBe('unknown');
      expect(tri({ field: 'subject.n', op, value: NaN }, c)).toBe('unknown');
      expect(tri({ field: 'subject.inf', op, value: 1 }, ctxOf({ subject: { inf: Infinity } }))).toBe('unknown');
      expect(tri({ field: 'subject.inf', op, value: 1 }, ctxOf({ subject: { inf: NaN } }))).toBe('unknown');
      expect(tri({ field: 'subject.x', op, value: 1 }, ctxOf({ subject: { x: undefined } }))).toBe('unknown');
    }
  });
  it('string ordering is UTF-8 / code point order; lone surrogates have no order', () => {
    const astral = '\u{10000}';
    const bmp = '￿';
    const cc = ctxOf({ subject: { a: astral, b: bmp, lone: '\ud800', ok: 'x' } });
    expect(tri({ field: 'subject.a', op: 'gt', value: bmp }, cc)).toBe('true'); // UTF-16 order would say false
    expect(tri({ field: 'subject.b', op: 'lt', value: astral }, cc)).toBe('true');
    for (const op of ['lt', 'lte', 'gt', 'gte', 'eq']) {
      if (op !== 'eq') {
        expect(tri({ field: 'subject.lone', op, value: 'x' }, cc)).toBe('unknown');
        expect(tri({ field: 'subject.ok', op, value: '\ud800' }, cc)).toBe('unknown');
        expect(tri({ field: 'subject.lone', op, value: '\ud800' }, cc)).toBe('unknown');
        expect(tri({ field: 'subject.ok', op, value: '\udc00x' }, cc)).toBe('unknown');
      }
    }
    // a valid surrogate PAIR is fine
    expect(tri({ field: 'subject.a', op: 'gte', value: astral }, cc)).toBe('true');
    expect(tri({ field: 'subject.ok', op: 'lt', value: 'a\u{1f600}' }, cc)).toBe('false');
  });
  it('prefix', () => {
    expect(tri({ field: 'subject.s', op: 'prefix', value: 'ab' }, c)).toBe('true');
    expect(tri({ field: 'subject.s', op: 'prefix', value: 'abc' }, c)).toBe('true');
    expect(tri({ field: 'subject.s', op: 'prefix', value: '' }, c)).toBe('true');
    expect(tri({ field: 'subject.s', op: 'prefix', value: 'abcd' }, c)).toBe('false');
    expect(tri({ field: 'subject.s', op: 'prefix', value: 'bc' }, c)).toBe('false');
    expect(tri({ field: 'subject.s', op: 'prefix', value: 5 }, c)).toBe('unknown');
    expect(tri({ field: 'subject.n', op: 'prefix', value: '5' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.n', op: 'prefix', value: 5 }, c)).toBe('unknown');
  });
  it('exists: value:false means must be absent; anything else means present', () => {
    expect(tri({ field: 'subject.role', op: 'exists' }, c)).toBe('true');
    expect(tri({ field: 'subject.nope', op: 'exists' }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'exists', value: true }, c)).toBe('true');
    expect(tri({ field: 'subject.nope', op: 'exists', value: true }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'exists', value: false }, c)).toBe('false');
    expect(tri({ field: 'subject.nope', op: 'exists', value: false }, c)).toBe('true');
    expect(tri({ field: 'subject.role', op: 'exists', value: 0 }, c)).toBe('true'); // 0 !== false
    expect(tri({ field: 'subject.nope', op: 'exists', value: 0 }, c)).toBe('false');
    expect(tri({ field: 'subject.role', op: 'exists', value: '' }, c)).toBe('true');
    expect(tri({ field: 'subject.nul', op: 'exists' }, c)).toBe('true'); // null is present
    expect(tri({ field: 'subject.nul', op: 'exists', value: false }, c)).toBe('false');
  });
  it('ref: operand taken from another path; a missing ref is unknown; ref wins over value', () => {
    const r = ctxOf({ subject: { a: 'x', b: 'x', c: 'y' }, env: { cur: 'x' } });
    expect(tri({ field: 'subject.a', op: 'eq', ref: 'env.cur' }, r)).toBe('true');
    expect(tri({ field: 'subject.c', op: 'eq', ref: 'env.cur' }, r)).toBe('false');
    expect(tri({ field: 'subject.c', op: 'ne', ref: 'env.cur' }, r)).toBe('true');
    expect(tri({ field: 'subject.a', op: 'eq', ref: 'env.nope' }, r)).toBe('unknown');
    expect(tri({ field: 'subject.a', op: 'eq', ref: 'env.cur', value: 'zzz' }, r)).toBe('true');
    expect(tri({ field: 'subject.a', op: 'eq', ref: 'env.nope', value: 'x' }, r)).toBe('unknown');
    expect(tri({ field: 'subject.a', op: 'eq', ref: undefined, value: 'x' }, r)).toBe('true');
    expect(tri({ field: 'subject.a', op: 'eq', ref: 'subject.b' }, r)).toBe('true');
  });
});

describe('params availability guards', () => {
  const E = { field: 'action.params.x', op: 'exists', value: false };
  it('a params-rooted FIELD is unknown when params are missing / null / not an object (never vacuously true)', () => {
    for (const p of [undefined, null, 'str', 5, true]) {
      expect(tri(E, withParams(p))).toBe('unknown');
      expect(tri({ field: 'action.params', op: 'exists', value: false }, withParams(p))).toBe('unknown');
      expect(tri({ field: 'action.params.x', op: 'nin', value: ['a'] }, withParams(p))).toBe('unknown');
    }
    expect(tri({ field: 'action.params.x', op: 'exists', value: false }, ctxOf())).toBe('unknown');
    expect(tri({ field: 'action.params', op: 'exists', value: false }, ctxOf())).toBe('unknown');
    expect(tri({ field: 'action.params.x', op: 'exists', value: false }, null as unknown as ActionContext)).toBe('unknown');
    expect(tri({ field: 'action.params.x', op: 'exists', value: false }, {} as ActionContext)).toBe('unknown');
  });
  it('with real params the same conditions decide', () => {
    expect(tri(E, withParams({}))).toBe('true');
    expect(tri(E, withParams({ x: 1 }))).toBe('false');
    expect(tri({ field: 'action.params', op: 'exists', value: false }, withParams({}))).toBe('false');
    expect(tri({ field: 'action.params', op: 'exists' }, withParams({}))).toBe('true');
    expect(tri({ field: 'action.params', op: 'exists' }, withParams([]))).toBe('true'); // an array is an object
    expect(tri({ field: 'action.params.0', op: 'eq', value: 'a' }, withParams(['a']))).toBe('true');
  });
  it('fields that merely START with "action.params" (no dot) are not params-rooted', () => {
    expect(tri({ field: 'action.paramsX', op: 'exists', value: false }, ctxOf())).toBe('true');
    expect(tri({ field: 'action.parameters', op: 'exists', value: false }, ctxOf())).toBe('true');
    expect(tri({ field: 'subject.x', op: 'exists', value: false }, ctxOf())).toBe('true');
    expect(tri({ field: 'env.action.params.x', op: 'exists', value: false }, ctxOf())).toBe('true');
  });
  it('a params-rooted REF is unknown when params are unavailable, but resolves when they are', () => {
    const f = { field: 'env.a', op: 'eq', ref: 'action.params' };
    expect(tri(f, withParams(null, { env: { a: null } }))).toBe('unknown');
    expect(tri(f, withParams('str', { env: { a: 'str' } }))).toBe('unknown');
    expect(tri(f, withParams(7, { env: { a: 7 } }))).toBe('unknown');
    expect(tri(f, withParams({ k: 1 }, { env: { a: { k: 1 } } }))).toBe('true');
    const g = { field: 'env.a', op: 'eq', ref: 'action.params.k' };
    expect(tri(g, withParams({ k: 1 }, { env: { a: 1 } }))).toBe('true');
    expect(tri(g, withParams({ k: 2 }, { env: { a: 1 } }))).toBe('false');
    expect(tri(g, withParams(undefined, { env: { a: 1 } }))).toBe('unknown');
    expect(tri(g, withParams('s', { env: { a: 1 } }))).toBe('unknown');
    // a non-params ref is not affected by missing params
    expect(tri({ field: 'env.a', op: 'eq', ref: 'env.b' }, ctxOf({ env: { a: 1, b: 1 } }))).toBe('true');
    expect(tri({ field: 'env.a', op: 'eq', ref: 'env.b' }, withParams(null, { env: { a: 1, b: 1 } }))).toBe('true');
    expect(tri({ field: 'env.a', op: 'eq', ref: 'env.b' }, withParams(undefined, { env: { a: 1, b: 1 } }))).toBe('true');
    expect(tri({ field: 'env.a', op: 'eq', ref: 'actionparams' }, withParams(undefined, { env: { a: 1 } }))).toBe('unknown');
    // non-string ref is ignored by the guard (then used as a path => not found)
    expect(tri({ field: 'env.a', op: 'eq', ref: 5 as unknown as string, value: 1 }, ctxOf({ env: { a: 1 } }))).toBe('unknown');
  });
});

describe('like (glob)', () => {
  const like = (v: unknown, g: unknown) => tri({ field: 'subject.v', op: 'like', value: g }, ctxOf({ subject: { v } }));
  it('semantics', () => {
    expect(like('hello', 'hello')).toBe('true');
    expect(like('hello', 'h*o')).toBe('true');
    expect(like('hello', 'h*')).toBe('true');
    expect(like('hello', '*')).toBe('true');
    expect(like('', '*')).toBe('true');
    expect(like('', '')).toBe('true');
    expect(like('a', '')).toBe('false');
    expect(like('', 'a')).toBe('false');
    expect(like('hello', 'h?llo')).toBe('true');
    expect(like('hello', 'h??lo')).toBe('true');
    expect(like('hello', 'h?lo')).toBe('false');
    expect(like('hello', '?????')).toBe('true');
    expect(like('hello', '????')).toBe('false');
    expect(like('hello', '??????')).toBe('false');
    expect(like('hello', 'x*')).toBe('false');
    expect(like('hello', '*x')).toBe('false');
    expect(like('hello', 'hell')).toBe('false');
    expect(like('hell', 'hello')).toBe('false');
    expect(like('hello', '*l*o')).toBe('true');
    expect(like('hello', '*e*l*o')).toBe('true');
    expect(like('hello', '*o*')).toBe('true');
    expect(like('hello', 'he**llo')).toBe('true');
    expect(like('hello', '**')).toBe('true');
    expect(like('hello', '*?')).toBe('true');
    expect(like('', '*?')).toBe('false');
    expect(like('hello', '?*')).toBe('true');
    expect(like('abcabc', '*abc')).toBe('true');
    expect(like('abcabd', '*abc')).toBe('false');
    expect(like('aXbXc', 'a*b*c')).toBe('true');
    expect(like('aXbXd', 'a*b*c')).toBe('false');
    expect(like('mississippi', 'm*iss*ppi')).toBe('true');
    expect(like('mississippi', '*ss*ss*')).toBe('true');
    expect(like('aaaa', '*a*a*a*b')).toBe('false');
    expect(like('a'.repeat(500), '*a*a*a*b')).toBe('false'); // would be catastrophic with a backtracking regex
    expect(like('line\nbreak', 'line?break')).toBe('true');
    expect(like('line\nbreak', 'line*break')).toBe('true');
    expect(like('a b', 'a?b')).toBe('true');
    expect(like('\u{1f600}', '?')).toBe('false'); // ? is ONE code unit
    expect(like('\u{1f600}', '??')).toBe('true');
  });
  it('backslash escapes the next char; dangling backslash is unknown', () => {
    expect(like('a*b', 'a\\*b')).toBe('true');
    expect(like('aXb', 'a\\*b')).toBe('false');
    expect(like('a?b', 'a\\?b')).toBe('true');
    expect(like('aXb', 'a\\?b')).toBe('false');
    expect(like('a\\b', 'a\\\\b')).toBe('true');
    expect(like('ab', 'a\\b')).toBe('true');
    expect(like('a', 'a\\')).toBe('unknown');
    expect(like('', '\\')).toBe('unknown');
    expect(like('a', '\\')).toBe('unknown');
    expect(like('a*', '*\\*')).toBe('true');
    expect(like('a', '*\\*')).toBe('false');
    expect(like('**', '\\**')).toBe('true');
  });
  it('operands must be strings; length limits are inclusive at the boundary', () => {
    expect(MAX_LIKE_PATTERN_LEN).toBe(512);
    expect(MAX_PATTERN_SUBJECT_LEN).toBe(512);
    expect(like(5, '*')).toBe('unknown');
    expect(like('a', 5)).toBe('unknown');
    expect(like(5, 5)).toBe('unknown');
    expect(like(null, '*')).toBe('unknown');
    expect(like('a'.repeat(512), '*')).toBe('true');
    expect(like('a'.repeat(513), '*')).toBe('unknown');
    expect(like('a', '*'.repeat(512))).toBe('true');
    expect(like('a', '*'.repeat(513))).toBe('unknown');
    expect(like('a'.repeat(512), 'a'.repeat(512))).toBe('true');
    expect(like('a'.repeat(512), 'a'.repeat(511) + 'b')).toBe('false');
  });
});

describe('matches (linear-time regex subset)', () => {
  const m = (v: unknown, re: unknown) => tri({ field: 'subject.v', op: 'matches', value: re }, ctxOf({ subject: { v } }));
  it('full-match semantics with exact Tri values', () => {
    expect(m('abc', 'abc')).toBe('true');
    expect(m('abcd', 'abc')).toBe('false');
    expect(m('xabc', 'abc')).toBe('false');
    expect(m('abc', 'a.c')).toBe('true');
    expect(m('/acct/9/items/42', '/acct/[^/]+/items/\\d+')).toBe('true');
    expect(m('/acct/9/items/x', '/acct/[^/]+/items/\\d+')).toBe('false');
    expect(m('GET /x', '(?:GET|POST) /x')).toBe('true');
    expect(m('PUT /x', '(?:GET|POST) /x')).toBe('false');
    expect(m('', '')).toBe('true');
    expect(m('', 'a*')).toBe('true');
    expect(m('a', 5)).toBe('unknown');
    expect(m(5, 'a')).toBe('unknown');
  });
  it('unsafe or unsupported patterns are unknown (never run)', () => {
    for (const re of ['(a+)+', '(a*)*', '(a|aa)+', '\\1', '(?=a)', '(?<n>a)', 'a{', '(a', 'a)', '[a', '\\b', 'a**']) expect(m('aa', re)).toBe('unknown');
  });
  it('limits: pattern <= 200, subject <= 512 (inclusive)', () => {
    expect(MAX_MATCHES_PATTERN_LEN).toBe(200);
    expect(m('a'.repeat(200), 'a'.repeat(200))).toBe('true');
    expect(m('a'.repeat(200), 'a'.repeat(201))).toBe('unknown');
    expect(m('a', 'a'.repeat(201))).toBe('unknown');
    expect(m('a', 'a'.repeat(200))).toBe('false');
    expect(m('a'.repeat(512), 'a*')).toBe('true');
    expect(m('a'.repeat(513), 'a*')).toBe('unknown');
    expect(m('a'.repeat(512), '.*')).toBe('true');
    expect(m('a'.repeat(513), '.*')).toBe('unknown');
    // either limit alone is enough to refuse
    expect(m('a'.repeat(513), 'a'.repeat(201))).toBe('unknown');
    expect(m('a'.repeat(513), 'a')).toBe('unknown');
  });
});

describe('is_a', () => {
  const isa = (v: unknown, t: unknown) => tri({ field: 'subject.v', op: 'is_a', value: t }, ctxOf({ subject: { v } }));
  it('strings: exact type or "Type::id" prefix, not a bare prefix', () => {
    expect(isa('User', 'User')).toBe('true');
    expect(isa('User::alice', 'User')).toBe('true');
    expect(isa('Users::alice', 'User')).toBe('false');
    expect(isa('Username', 'User')).toBe('false');
    expect(isa('User:alice', 'User')).toBe('false');
    expect(isa('XUser::a', 'User')).toBe('false');
    expect(isa('Group::alice', 'User')).toBe('false');
    expect(isa('', 'User')).toBe('false');
    expect(isa('User::', 'User')).toBe('true');
  });
  it('objects: own `type` string and/or `tags` array; undecidable => unknown', () => {
    expect(isa({ type: 'User' }, 'User')).toBe('true');
    expect(isa({ type: 'User::admin' }, 'User')).toBe('true');
    expect(isa({ type: 'Users' }, 'User')).toBe('false');
    expect(isa({ type: 'Username' }, 'User')).toBe('false');
    expect(isa({ type: 'Group' }, 'User')).toBe('false');
    expect(isa({ tags: ['User'] }, 'User')).toBe('true');
    expect(isa({ tags: ['Group', 'User'] }, 'User')).toBe('true');
    expect(isa({ tags: ['Group'] }, 'User')).toBe('false');
    expect(isa({ tags: [] }, 'User')).toBe('false');
    expect(isa({ tags: ['User::x'] }, 'User')).toBe('false'); // tags are exact
    expect(isa({ type: 'Group', tags: ['User'] }, 'User')).toBe('true');
    expect(isa({ type: 'User', tags: ['Group'] }, 'User')).toBe('true');
    expect(isa({ type: 'Group', tags: ['Other'] }, 'User')).toBe('false');
    expect(isa({}, 'User')).toBe('unknown');
    expect(isa({ other: 1 }, 'User')).toBe('unknown');
    expect(isa({ type: 5 }, 'User')).toBe('unknown');
    expect(isa({ type: 5, tags: ['User'] }, 'User')).toBe('true');
    expect(isa({ type: 'User', tags: 'abc' }, 'User')).toBe('true');
    expect(isa({ type: 5, tags: 'abc' }, 'User')).toBe('unknown');
    expect(isa({ tags: 'User' }, 'User')).toBe('unknown');
    expect(isa({ tags: { 0: 'User' } }, 'User')).toBe('unknown');
    expect(isa({ type: null }, 'User')).toBe('unknown');
    expect(isa(Object.create({ type: 'User' }), 'User')).toBe('unknown'); // inherited `type` is ignored
    expect(isa(Object.create({ tags: ['User'] }), 'User')).toBe('unknown');
    expect(isa(['User'], 'User')).toBe('unknown');
    expect(isa(5, 'User')).toBe('unknown');
    expect(isa(true, 'User')).toBe('unknown');
    expect(isa(null, 'User')).toBe('unknown');
  });
  it('the type operand must be a non-empty string', () => {
    expect(isa('User', '')).toBe('unknown');
    expect(isa('User', 5)).toBe('unknown');
    expect(isa('User', ['User'])).toBe('unknown');
    expect(isa({ type: 'x' }, '')).toBe('unknown');
  });
});

describe('member_of (bounded reflexive transitive closure)', () => {
  const mo = (v: unknown, target: unknown, coll: unknown, extra: Record<string, unknown> = {}, ctxExtra: Record<string, unknown> = {}) =>
    tri({ field: 'subject.v', op: 'member_of', value: target, collection: 'env.g', ...extra }, ctxOf({ subject: { v }, env: { g: coll }, ...ctxExtra }));
  const G = { alice: ['dev', 'ops'], dev: 'eng', ops: ['eng', 'oncall'], eng: ['all'], solo: [] };
  it('reflexive, transitive, string and array parents', () => {
    expect(mo('alice', 'alice', G)).toBe('true');
    expect(mo('alice', 'dev', G)).toBe('true');
    expect(mo('alice', 'eng', G)).toBe('true');
    expect(mo('alice', 'all', G)).toBe('true');
    expect(mo('alice', 'oncall', G)).toBe('true');
    expect(mo('alice', 'nobody', G)).toBe('false');
    expect(mo('solo', 'all', G)).toBe('false');
    expect(mo('dev', 'alice', G)).toBe('false');
    expect(mo('orphan', 'orphan', G)).toBe('true');
    expect(mo('orphan', 'dev', G)).toBe('false');
    expect(mo('alice', ['nobody', 'oncall'], G)).toBe('true');
    expect(mo('alice', ['nobody', 'none'], G)).toBe('false');
    expect(mo('alice', ['nobody', 5, 'all'], G)).toBe('true');
    expect(mo('alice', ['nobody', 5], G)).toBe('false');
    expect(mo('x', 'Stryker was here', G)).toBe('false');
    expect(mo('orphan', ['Stryker was here'], G)).toBe('false');
    expect(mo('bad', 'zzz', { bad: [5, null, 'good', {}], good: 'zzz' })).toBe('true');
    expect(mo('bad', 'x', { bad: 5 })).toBe('false');
    expect(mo('bad', 'x', { bad: { x: 1 } })).toBe('false');
    expect(mo('bad', 'x', { bad: [5, null, {}, ['x']] })).toBe('false'); // non-string members are dropped, nested arrays too
  });
  it('non-string array members are dropped, not followed', () => {
    expect(mo('a', 'g', { a: [5], '5': 'g' })).toBe('false');
    expect(mo('a', 'g', { a: [['b']], b: 'g' })).toBe('false');
    expect(mo('a', 'g', { a: [null], null: 'g' })).toBe('false');
    expect(mo('a', 'g', { a: [true], true: 'g' })).toBe('false');
  });
  it('cycles terminate', () => {
    expect(mo('a', 'c', { a: 'b', b: 'c', c: 'a' })).toBe('true');
    expect(mo('a', 'z', { a: 'b', b: 'c', c: 'a' })).toBe('false');
    expect(mo('a', 'z', { a: 'a' })).toBe('false');
  });
  it('proto-pollution keys are never followed (own "__proto__" from JSON included)', () => {
    const poisoned = JSON.parse('{"__proto__":["admin"],"constructor":["admin"],"prototype":["admin"],"ok":["__proto__","constructor","prototype"]}');
    expect(mo('__proto__', 'admin', poisoned)).toBe('false');
    expect(mo('constructor', 'admin', poisoned)).toBe('false');
    expect(mo('prototype', 'admin', poisoned)).toBe('false');
    expect(mo('ok', 'admin', poisoned)).toBe('false');
    expect(mo('ok', '__proto__', poisoned)).toBe('true');
    expect(mo('toString', 'x', { a: 'x' })).toBe('false');
    expect(mo('hasOwnProperty', 'x', {})).toBe('false');
    // inherited adjacency entries do not exist
    expect(mo('a', 'g', Object.create({ a: ['g'] }))).toBe('false');
  });
  it('the closure is capped at MAX_MEMBER_CLOSURE_NODES dequeued nodes', () => {
    expect(MAX_MEMBER_CLOSURE_NODES).toBe(10_000);
    const chain: Record<string, string> = {};
    for (let i = 0; i < 10_050; i++) chain['n' + i] = 'n' + (i + 1);
    expect(mo('n0', 'n10000', chain)).toBe('true');
    expect(mo('n0', 'n10001', chain)).toBe('false');
    expect(mo('n0', 'n10049', chain)).toBe('false');
    expect(mo('n0', 'n9999', chain)).toBe('true');
    expect(mo('n5', 'n10005', chain)).toBe('true');
    expect(mo('n5', 'n10006', chain)).toBe('false');
  });
  it('fails closed (unknown) on every missing piece', () => {
    expect(mo(5, 'g', G)).toBe('unknown'); // field must be a string
    expect(mo(['alice'], 'g', G)).toBe('unknown');
    expect(mo('alice', 'g', undefined)).toBe('unknown'); // collection value absent
    expect(mo('alice', 'g', 'str')).toBe('unknown');
    expect(mo('alice', 'g', ['alice'])).toBe('unknown'); // an array is not an adjacency map
    expect(mo('alice', 'g', null)).toBe('unknown');
    expect(mo('alice', 'g', G, { collection: undefined })).toBe('unknown');
    expect(mo('alice', 'g', G, { collection: '' })).toBe('unknown');
    expect(mo('alice', 'g', G, { collection: 5 })).toBe('unknown');
    expect(mo('alice', 'g', G, { collection: 'env.nope' })).toBe('unknown');
    expect(mo('alice', undefined, G)).toBe('unknown'); // no value
    expect(mo('alice', 5, G)).toBe('unknown');
    expect(mo('alice', [], G)).toBe('unknown');
    expect(mo('alice', [5], G)).toBe('unknown');
    expect(mo('alice', {}, G)).toBe('unknown');
    expect(mo('alice', null, G)).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'member_of', collection: 'env.g' }, ctxOf({ subject: { v: 'alice' }, env: { g: G } }))).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'member_of', value: undefined, collection: 'env.g' }, ctxOf({ subject: { v: 'alice' }, env: { g: G } }))).toBe('unknown');
    expect(tri({ field: 'subject.nope', op: 'member_of', value: 'dev', collection: 'env.g' }, ctxOf({ env: { g: G } }))).toBe('unknown');
  });
  it('target group from `ref`; an unresolved ref is unknown even when `value` is present', () => {
    const c = ctxOf({ subject: { v: 'alice' }, env: { g: G, want: 'eng', wants: ['nobody', 'all'], bad: 5 } });
    expect(tri({ field: 'subject.v', op: 'member_of', ref: 'env.want', collection: 'env.g' }, c)).toBe('true');
    expect(tri({ field: 'subject.v', op: 'member_of', ref: 'env.wants', collection: 'env.g' }, c)).toBe('true');
    expect(tri({ field: 'subject.v', op: 'member_of', ref: 'env.nope', collection: 'env.g' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'member_of', ref: 'env.nope', value: 'eng', collection: 'env.g' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'member_of', ref: 'env.bad', collection: 'env.g' }, c)).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'member_of', ref: 'env.want', value: 'nobody', collection: 'env.g' }, c)).toBe('true');
  });
  it('the collection path may itself be params-rooted and then needs params', () => {
    const c = withParams({ g: G }, { subject: { v: 'alice' } });
    expect(tri({ field: 'subject.v', op: 'member_of', value: 'eng', collection: 'action.params.g' }, c)).toBe('true');
    expect(tri({ field: 'subject.v', op: 'member_of', value: 'eng', collection: 'action.params.g' }, withParams(undefined, { subject: { v: 'alice' } }))).toBe('unknown');
  });
});

describe('boolean groupings (three-valued)', () => {
  const T = { field: 'subject.a', op: 'eq', value: 1 };
  const F = { field: 'subject.a', op: 'eq', value: 2 };
  const U = { field: 'subject.nope', op: 'eq', value: 2 };
  const c = ctxOf({ subject: { a: 1 } });
  it('all_of: any false wins; else any unknown => unknown; else true; empty/non-array => unknown', () => {
    expect(tri({ all_of: [T, T] }, c)).toBe('true');
    expect(tri({ all_of: [T, F] }, c)).toBe('false');
    expect(tri({ all_of: [F, T] }, c)).toBe('false');
    expect(tri({ all_of: [T, U] }, c)).toBe('unknown');
    expect(tri({ all_of: [U, T] }, c)).toBe('unknown');
    expect(tri({ all_of: [U, F] }, c)).toBe('false'); // a later false beats an earlier unknown
    expect(tri({ all_of: [F, U] }, c)).toBe('false');
    expect(tri({ all_of: [U] }, c)).toBe('unknown');
    expect(tri({ all_of: [] }, c)).toBe('unknown');
    expect(tri({ all_of: 'x' }, c)).toBe('unknown');
    expect(tri({ all_of: undefined }, c)).toBe('unknown');
    expect(tri({ all_of: {} }, c)).toBe('unknown');
  });
  it('any_of: any true wins; else any unknown => unknown; else false; empty/non-array => unknown', () => {
    expect(tri({ any_of: [F, F] }, c)).toBe('false');
    expect(tri({ any_of: [F] }, c)).toBe('false');
    expect(tri({ any_of: [F, T] }, c)).toBe('true');
    expect(tri({ any_of: [T, F] }, c)).toBe('true');
    expect(tri({ any_of: [U, T] }, c)).toBe('true'); // a later true beats an earlier unknown
    expect(tri({ any_of: [T, U] }, c)).toBe('true');
    expect(tri({ any_of: [F, U] }, c)).toBe('unknown');
    expect(tri({ any_of: [U, F] }, c)).toBe('unknown');
    expect(tri({ any_of: [U] }, c)).toBe('unknown');
    expect(tri({ any_of: [] }, c)).toBe('unknown');
    expect(tri({ any_of: 'x' }, c)).toBe('unknown');
    expect(tri({ any_of: null }, c)).toBe('unknown');
  });
  it('not inverts decided values and keeps unknown', () => {
    expect(tri({ not: T }, c)).toBe('false');
    expect(tri({ not: F }, c)).toBe('true');
    expect(tri({ not: U }, c)).toBe('unknown');
    expect(tri({ not: { not: T } }, c)).toBe('true');
    expect(tri({ not: { not: U } }, c)).toBe('unknown');
    expect(tri({ not: null }, c)).toBe('unknown');
    expect(tri({ not: 5 }, c)).toBe('unknown');
    expect(tri({ not: undefined }, c)).toBe('unknown');
  });
  it('nesting', () => {
    expect(tri({ all_of: [{ any_of: [F, T] }, { not: F }] }, c)).toBe('true');
    expect(tri({ any_of: [{ all_of: [T, F] }, { not: T }] }, c)).toBe('false');
  });
  it('all_of takes precedence over any_of over not when several keys are present', () => {
    expect(tri({ all_of: [T], any_of: [F], not: F }, c)).toBe('true');
    expect(tri({ any_of: [F], not: F }, c)).toBe('false');
  });
  it('evaluateCondition is exactly `=== "true"`', () => {
    expect(evaluateCondition(T as Condition, c)).toBe(true);
    expect(evaluateCondition(F as Condition, c)).toBe(false);
    expect(evaluateCondition(U as Condition, c)).toBe(false);
    expect(evaluateCondition({ not: U } as Condition, c)).toBe(false);
    expect(evaluateCondition(null as unknown as Condition, c)).toBe(false);
  });
  it('a hostile condition (throwing traps) is unknown, not an exception', () => {
    const hostile = new Proxy({}, { has() { throw new Error('boom'); }, get() { throw new Error('boom'); } });
    expect(tri(hostile, c)).toBe('unknown');
    expect(evaluateCondition(hostile as Condition, c)).toBe(false);
    const throwingField = { get field(): string { throw new Error('boom'); }, op: 'eq', value: 1 };
    expect(tri(throwingField, c)).toBe('unknown');
  });
});

describe('predicateMatches / evaluatePredicates', () => {
  const ctx = (verb = 'read', resource = '/a/b', extra: Record<string, unknown> = {}): ActionContext => ({ action: { verb, resource }, ...extra }) as ActionContext;
  it('verb: exact, "*", list; non-string verb matches nothing; non-string list members are skipped', () => {
    expect(predicateMatches({ verb: 'read' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: 'write' }, ctx())).toBe(false);
    expect(predicateMatches({ verb: '*' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: ['x', 'read'] }, ctx())).toBe(true);
    expect(predicateMatches({ verb: ['x', 'y'] }, ctx())).toBe(false);
    expect(predicateMatches({ verb: ['x', '*'] }, ctx())).toBe(true);
    expect(predicateMatches({ verb: [] }, ctx())).toBe(false);
    expect(predicateMatches({ verb: [5, 'read'] as never }, ctx())).toBe(true);
    expect(predicateMatches({ verb: [5] as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 5 as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: undefined as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: null as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: { 0: 'read' } as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'Read' }, ctx())).toBe(false);
  });
  it('resource: omitted/exact/"*"/prefix*/non-string', () => {
    expect(predicateMatches({ verb: 'read' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '*' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '/a/b' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '/a' }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: '/a/b/c' }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: '/a/*' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '/a/b*' }, ctx())).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '/a/bc*' }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: '/x/*' }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: '/a/b*' }, ctx('read', '/a/b'))).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '/a/b*' }, ctx('read', '/a/bzzz'))).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: 'ab' }, ctx('read', 'abc'))).toBe(false); // exact, not a prefix
    expect(predicateMatches({ verb: 'read', resource: 'abc' }, ctx('read', 'ab'))).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: '' }, ctx('read', ''))).toBe(true);
    expect(predicateMatches({ verb: 'read', resource: '' }, ctx('read', 'x'))).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: 5 as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: null as never }, ctx())).toBe(false);
    expect(predicateMatches({ verb: 'read', resource: ['/a/b'] as never }, ctx())).toBe(false);
  });
  it('re: resources use the safe engine; limits at 200 / 512; unsafe or unsupported => no match', () => {
    const re = (src: string, resource: string) => predicateMatches({ verb: 'read', resource: 're:' + src }, ctx('read', resource));
    expect(MAX_RE_RESOURCE_LEN).toBe(512);
    expect(re('/a/[a-z]+', '/a/bc')).toBe(true);
    expect(re('/a/[a-z]+', '/a/b1')).toBe(false);
    expect(re('/a', '/a/b')).toBe(false); // full match only
    expect(re('', '')).toBe(true);
    expect(re('', 'x')).toBe(false);
    expect(re('a'.repeat(200), 'a'.repeat(200))).toBe(true);
    expect(re('a'.repeat(201), 'a'.repeat(201))).toBe(false);
    expect(re('a*', 'a'.repeat(512))).toBe(true);
    expect(re('a*', 'a'.repeat(513))).toBe(false);
    expect(re('.*', 'a'.repeat(513))).toBe(false);
    expect(re('(a+)+', 'aaa')).toBe(false); // nested quantifier: unsafe
    expect(re('\\1', 'a')).toBe(false);
    expect(re('(?=a)a', 'a')).toBe(false);
    expect(re('a{', 'a{')).toBe(false);
    // `re:` is a regex even when it ends with '*'
    expect(re('a*', 'aaa')).toBe(true);
    expect(re('a*', 'b')).toBe(false);
  });
  it('where: an array of conditions that must ALL be true; non-array => no match', () => {
    const c = ctx('read', '/a/b', { subject: { r: 'admin' } });
    expect(predicateMatches({ verb: 'read', where: [] }, c)).toBe(true);
    expect(predicateMatches({ verb: 'read', where: [{ field: 'subject.r', op: 'eq', value: 'admin' }] }, c)).toBe(true);
    expect(predicateMatches({ verb: 'read', where: [{ field: 'subject.r', op: 'eq', value: 'admin' }, { field: 'subject.r', op: 'eq', value: 'x' }] }, c)).toBe(false);
    expect(predicateMatches({ verb: 'read', where: [{ field: 'subject.r', op: 'eq', value: 'x' }, { field: 'subject.r', op: 'eq', value: 'admin' }] }, c)).toBe(false);
    expect(predicateMatches({ verb: 'read', where: [{ field: 'subject.nope', op: 'eq', value: 'x' }] }, c)).toBe(false);
    expect(predicateMatches({ verb: 'read', where: { field: 'subject.r', op: 'eq', value: 'admin' } as never }, c)).toBe(false);
    expect(predicateMatches({ verb: 'read', where: 'x' as never }, c)).toBe(false);
    expect(predicateMatches({ verb: 'read', where: null as never }, c)).toBe(false);
    expect(predicateMatches({ verb: 'read', where: undefined }, c)).toBe(true);
  });
  it('malformed predicate / context fail closed', () => {
    for (const p of [null, undefined, 5, 'read', true]) expect(predicateMatches(p as never, ctx())).toBe(false);
    expect(predicateMatches([] as never, ctx())).toBe(false);
    expect(predicateMatches({ verb: '*' }, null as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, undefined as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, {} as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, { action: null } as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, { action: { verb: 5, resource: '/a' } } as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, { action: { verb: 'read', resource: 5 } } as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, { action: { verb: 'read' } } as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, { action: { resource: '/a' } } as never)).toBe(false);
    expect(predicateMatches({ verb: '*' }, { action: { verb: '', resource: '' } } as never)).toBe(true);
    const hostile = { get verb(): string { throw new Error('boom'); }, resource: '*' } as unknown as Predicate;
    expect(predicateMatches(hostile, ctx())).toBe(false);
  });
  it('evaluatePredicates: default deny, first match wins and is returned by identity, exact reasons', () => {
    expect(evaluatePredicates([], ctx())).toStrictEqual({ allowed: false, reason: 'envelope grants no predicates' });
    expect(evaluatePredicates(undefined as never, ctx())).toStrictEqual({ allowed: false, reason: 'envelope grants no predicates' });
    expect(evaluatePredicates('x' as never, ctx())).toStrictEqual({ allowed: false, reason: 'envelope grants no predicates' });
    expect(evaluatePredicates({ 0: { verb: '*' }, length: 1 } as never, ctx())).toStrictEqual({ allowed: false, reason: 'envelope grants no predicates' });
    const p1: Predicate = { verb: 'write' };
    const p2: Predicate = { verb: 'read' };
    const p3: Predicate = { verb: '*' };
    const r = evaluatePredicates([p1, p2, p3], ctx());
    expect(r.allowed).toBe(true);
    expect(r.matched).toBe(p2);
    expect(r.reason).toBeUndefined();
    expect('reason' in r).toBe(false);
    expect(evaluatePredicates([p1], ctx())).toStrictEqual({ allowed: false, reason: 'no predicate permits read on /a/b' });
    expect(evaluatePredicates([p1, null as never], ctx('x', 'y'))).toStrictEqual({ allowed: false, reason: 'no predicate permits x on y' });
    expect(evaluatePredicates([p1], { action: {} } as never)).toStrictEqual({ allowed: false, reason: 'no predicate permits undefined on undefined' });
    expect(evaluatePredicates([p1], null as never)).toStrictEqual({ allowed: false, reason: 'no predicate permits undefined on undefined' });
  });
  it('evaluatePredicates never throws: an unprintable verb in the denial message fails closed', () => {
    const nasty = { action: { verb: { toString() { throw new Error('boom'); } }, resource: '/r' } } as never;
    expect(evaluatePredicates([{ verb: 'x' }], nasty)).toStrictEqual({ allowed: false, reason: 'predicate evaluation error (fail closed)' });
  });
});

describe('isSafeRegexSource: accepted subset', () => {
  it.each([
    '',
    'abc',
    '/acct/[^/]+/items/\\d+',
    '(?:GET|POST) /x',
    'a+?',
    'a+?b',
    'a*?b',
    'a??',
    'a{2}?',
    'a{1,3}?b',
    '\\(a\\)',
    '\\[a\\]',
    '\\|a',
    'a\\+',
    '[(]',
    '[)]',
    '[|]',
    '[*]',
    '[+]',
    '[\\](]',
    '[\\]]',
    '[\\\\]',
    '[^(]',
    '[^]',
    '[]',
    '[^](a)',
    '[a-z]+',
    '\\d+',
    '\\0',
    '\\0a',
    '(a)',
    '(a)+',
    '(?:a)+',
    '(?:ab)+',
    '(?:a)?',
    '(a|b)',
    '(?:a|b)c',
    'a{10}',
    'a{0}',
    'a{1,}',
    'a{2,}',
    'a{10,}',
    'a{12,34}',
    'a{64}',
    'a{1,64}',
    'a{0,64}',
    '.{64}',
    'a{0064}',
    'a+b*',
    'a+b+',
    'a|b|c',
    ('a|'.repeat(22) + 'a'),
    ('a?'.repeat(22)),
    ('a{1,2}'.repeat(22)),
    'a+b*c{1,64}',
    'a{1,2}'.repeat(11) + 'b+',
    'a?'.repeat(6) + 'b+c+',
    'a{1,2}b{1,2}c{1,2}d{1,2}e{1,2}f{1,2}g{1,2}h{1,2}i{1,2}j{1,2}k{1,2}l{1,2}m{1,2}n{1,2}o{1,2}p{1,2}q{1,2}r{1,2}s{1,2}t{1,2}u{1,2}v{1,2}',
    'a{2,5}b{2,5}c{2,5}d{2,5}',
    'a{2,5}b{2,5}c{2,5}d{2,5}e{2,5}f{2,5}',
  ])('%s', (src) => {
    expect(isSafeRegexSource(src), src).toBe(true);
  });
});

describe('isSafeRegexSource: refused', () => {
  it.each([
    ['nested quantifier', '(a+)+'],
    ['nested quantifier', '(a*)*'],
    ['nested quantifier', '(a?)+'],
    ['nested quantifier', '(a{2})+'],
    ['nested quantifier', '(a+){2}'],
    ['nested quantifier', '(.*a){10}'],
    ['nested quantifier', '(?:a+)*'],
    ['nested via inner group', '(?:(?:a+))+'],
    ['nested via inner group', '(?:(?:a|b))+'],
    ['nested via inner group', '(?:x(?:a+))+'],
    ['nested via inner group', '(?:x(?:a|b)y)*'],
    ['alternation under quantifier', '(a|aa)+'],
    ['alternation under quantifier', '(?:a|b)+'],
    ['alternation under quantifier', '(a|b)*'],
    ['alternation under quantifier', '(a|b){2}'],
    ['alternation under quantifier', '(a|b)?'],
    ['backreference', '\\1'],
    ['backreference', '(a)\\1'],
    ['backreference', '\\9'],
    ['backreference', '\\k<n>'],
    ['backreference', '\\5'],
    ['lookahead', '(?=a)'],
    ['lookahead', '(?!a)'],
    ['lookbehind', '(?<=a)'],
    ['named group', '(?<n>a)'],
    ['(? without colon', '(?a)'],
    ['(? at end', 'a(?'],
    ['unbalanced', '(a'],
    ['unbalanced', 'a)'],
    ['unbalanced', ')('],
    ['unbalanced', '((a)'],
    ['unterminated class', '[a'],
    ['unterminated class', '[^a'],
    ['unterminated class', '[\\]'],
    ['unterminated class', '['],
    ['unterminated class', '[^'],
    ['class swallowed the paren (JS class semantics)', '[^](a+)+]'],
    ['trailing backslash', 'a\\'],
    ['trailing backslash', '\\'],
    ['quantifier with nothing before', '*a'],
    ['quantifier with nothing before', '+a'],
    ['quantifier with nothing before', '?a'],
    ['quantifier after open paren', '(*a)'],
    ['quantifier after open paren', '(?:*a)'],
    ['quantifier after alternation', 'a|*'],
    ['quantifier after alternation', 'a|+b'],
    ['quantifier after quantifier', 'a**'],
    ['quantifier after quantifier', 'a+*'],
    ['quantifier after quantifier', 'a{2}*'],
    ['quantifier after quantifier', 'a*{2}'],
    ['quantifier after lazy quantifier', 'a+??'],
    ['malformed brace', 'a{'],
    ['malformed brace', 'a{x}'],
    ['malformed brace', 'a{,2}'],
    ['malformed brace', 'a{2'],
    ['malformed brace', 'a{2,'],
    ['malformed brace', '{2}'],
    ['malformed brace', 'a{ 2}'],
    ['range out of order', 'a{2,1}'],
    ['range out of order', 'a{5,4}'],
    ['bounded repeat too large', 'a{65}'],
    ['bounded repeat too large', 'a{1,65}'],
    ['bounded repeat too large', 'a{0,65}'],
    ['bounded repeat too large', 'a{100}'],
    ['bounded repeat too large', 'a{65,70}'],
    ['bounded repeat too large', 'a{65,}'],
    ['three unbounded', 'a+b+c+'],
    ['three unbounded', 'a*b*c*'],
    ['three unbounded', 'a+b{1,}c*'],
    ['four unbounded', 'a+b+c+d+'],
    ['cost 23: 23 alternations', 'a|'.repeat(23) + 'a'],
    ['cost 23: 23 optionals', 'a?'.repeat(23)],
    ['cost 23: 23 two-way repeats', 'a{1,2}'.repeat(23)],
    ['cost 23: 22 + 1', 'a+b*c{1,64}d?'],
    ['cost 23: 22 + 1 alt', 'a+b*c{1,64}|d'],
    ['cost 24: three-way repeats', 'a{1,3}'.repeat(12)],
    ['cost: exponential sequenced choice', 'a?'.repeat(30) + 'a'.repeat(30) + 'b'],
    ['cost: alternation sequence', '(?:a|aa){20}b'],
    ['cost: wide variable repeat x4', 'a{0,64}b{0,64}c{0,64}d{0,64}'],
    ['cost: bounded 12 times (2 bits each = 24)', 'a{2,5}'.repeat(12)],
    ['cost: five wide', 'a{1,4}'.repeat(12)],
    ['cost: three 4-way repeats', 'a{1,4}'.repeat(12)],
  ] as Array<[string, string]>)('%s: %s', (_why, src) => {
    expect(isSafeRegexSource(src), src).toBe(false);
  });
  it('accepted syntactically but not compilable by the linear engine => refused', () => {
    expect(isSafeRegexSource('a{x')).toBe(false);
    expect(isSafeRegexSource('\\p')).toBe(false);
    expect(isSafeRegexSource('\\b')).toBe(false);
    expect(isSafeRegexSource('\\_')).toBe(false);
    expect(isSafeRegexSource('(?:a)\\u12')).toBe(false);
    expect(isSafeRegexSource('[b-a]')).toBe(false);
    expect(isSafeRegexSource('^*')).toBe(false);
    expect(isSafeRegexSource('a'.repeat(5000))).toBe(false);
  });
  it('cost accounting is exact: a bounded {m,n} costs ceil(log2(n-m+1)), {n} costs 0, ? costs 1, | costs 1, unbounded costs 8', () => {
    // 22 bits exactly passes; 23 fails — built from different constructs
    expect(isSafeRegexSource('a+b+' + 'c?'.repeat(6))).toBe(true); // 8+8+6
    expect(isSafeRegexSource('a+b+' + 'c?'.repeat(7))).toBe(false); // 23
    expect(isSafeRegexSource('a+b+' + 'c|'.repeat(5) + 'c')).toBe(true); // 8+8+5 = 21 (then +... ok)
    expect(isSafeRegexSource('a+b+' + 'c|'.repeat(6) + 'c')).toBe(true); // 22
    expect(isSafeRegexSource('a+b+' + 'c|'.repeat(7) + 'c')).toBe(false); // 23
    expect(isSafeRegexSource('a+' + 'b{1,64}'.repeat(2) + 'c{1,4}')).toBe(true); // 8 + 6 + 6 + 2 = 22
    expect(isSafeRegexSource('a+' + 'b{1,64}'.repeat(2) + 'c{1,4}d?')).toBe(false); // 23
    expect(isSafeRegexSource('a+b{1,64}b{1,64}c{1,5}')).toBe(false); // ceil(log2 5)=3 => 8+6+6+3 = 23
    expect(isSafeRegexSource('a+b{1,64}b{1,64}c{1,3}')).toBe(true); // ceil(log2 3)=2 => 22
    expect(isSafeRegexSource('a+b{1,64}b{1,64}c{1,2}')).toBe(true); // 1 => 21
    expect(isSafeRegexSource('a{3}'.repeat(40))).toBe(true); // {n} is free
    expect(isSafeRegexSource('a{64}'.repeat(40))).toBe(true);
    expect(isSafeRegexSource('a{7,7}'.repeat(40))).toBe(true); // one option: free
    expect(isSafeRegexSource('a{1,2}'.repeat(22))).toBe(true); // 2 options => 1 bit
    expect(isSafeRegexSource('a{1,2}'.repeat(23))).toBe(false);
    expect(isSafeRegexSource('a{1,3}'.repeat(11))).toBe(true); // 3 options => 2 bits => 22
    expect(isSafeRegexSource('a{1,3}'.repeat(12))).toBe(false);
    expect(isSafeRegexSource('a{2,5}'.repeat(7))).toBe(true); // 4 options => 2 bits => 14; as unbounded it would be 56
    expect(isSafeRegexSource('a{2,5}'.repeat(11))).toBe(true); // 22
    expect(isSafeRegexSource('a{2,5}'.repeat(12))).toBe(false);
    expect(isSafeRegexSource('a{0,1}'.repeat(22))).toBe(true);
    expect(isSafeRegexSource('a{0,1}'.repeat(23))).toBe(false);
    expect(isSafeRegexSource('a{2,}b{2,}')).toBe(true); // 16
    expect(isSafeRegexSource('a{2,}b{2,}c?c?c?c?c?c?')).toBe(true); // 22
    expect(isSafeRegexSource('a{2,}b{2,}c?c?c?c?c?c?c?')).toBe(false);
  });
});

describe('envelopeCaveatEvaluator', () => {
  const NOW = 1_700_000_000_000;
  const ev = (caveat: unknown, ctx: unknown = { now: NOW }) => envelopeCaveatEvaluator(caveat as never, ctx);
  it('guards: caveat and ctx must be objects, now must be finite', () => {
    expect(ev({ type: 'expires', at: NOW + 1 })).toBe(true);
    for (const bad of [null, undefined, 5, 'x']) expect(ev(bad)).toBe(false);
    for (const bad of [null, undefined, 5, 'x']) expect(envelopeCaveatEvaluator({ type: 'expires', at: NOW + 1 } as never, bad)).toBe(false);
    for (const now of [undefined, null, NaN, Infinity, -Infinity, '1', {}]) expect(ev({ type: 'expires', at: NOW + 1 }, { now })).toBe(false);
    expect(ev({ type: 'delegation_depth', max: 5 }, { now: NaN, delegationDepth: 0 })).toBe(false);
    expect(ev({ type: 'budget_alloc', limit: 5 }, { now: Infinity })).toBe(false);
    expect(ev({ type: 'budget_alloc', limit: 5 }, {})).toBe(false);
    expect(ev({ type: 'zzz' })).toBe(false);
    expect(ev({})).toBe(false);
    expect(ev({ type: 5 })).toBe(false);
  });
  it('expires: now < at (strict), at must be finite', () => {
    expect(ev({ type: 'expires', at: NOW + 1 })).toBe(true);
    expect(ev({ type: 'expires', at: NOW })).toBe(false);
    expect(ev({ type: 'expires', at: NOW - 1 })).toBe(false);
    expect(ev({ type: 'expires', at: NaN })).toBe(false);
    expect(ev({ type: 'expires', at: Infinity })).toBe(false);
    expect(ev({ type: 'expires', at: '9999999999999' })).toBe(false);
    expect(ev({ type: 'expires' })).toBe(false);
  });
  it('not_before: now >= at (inclusive)', () => {
    expect(ev({ type: 'not_before', at: NOW })).toBe(true);
    expect(ev({ type: 'not_before', at: NOW - 1 })).toBe(true);
    expect(ev({ type: 'not_before', at: NOW + 1 })).toBe(false);
    expect(ev({ type: 'not_before', at: -Infinity })).toBe(false);
    expect(ev({ type: 'not_before', at: 'x' })).toBe(false);
    expect(ev({ type: 'not_before' })).toBe(false);
  });
  it('rate: admitted actions in (now - per_secs, now] must be < max', () => {
    const rate = (max: unknown, per_secs: unknown, recent: unknown) => ev({ type: 'rate', max, per_secs }, { now: NOW, recentActionTimes: recent });
    expect(rate(2, 10, [])).toBe(true);
    expect(rate(2, 10, [NOW - 1000])).toBe(true);
    expect(rate(2, 10, [NOW - 1000, NOW - 2000])).toBe(false); // already max in window
    expect(rate(3, 10, [NOW - 1000, NOW - 2000])).toBe(true);
    // lower bound is exclusive: t === now - per_secs*1000 is OUTSIDE the window
    expect(rate(1, 10, [NOW - 10_000])).toBe(true);
    expect(rate(1, 10, [NOW - 9_999])).toBe(false);
    expect(rate(1, 10, [NOW - 10_001])).toBe(true);
    // upper bound inclusive: t === now counts; the future does not
    expect(rate(1, 10, [NOW])).toBe(false);
    expect(rate(1, 10, [NOW + 1])).toBe(true);
    expect(rate(1, 10, [NOW + 1000, NOW + 2000])).toBe(true);
    // max 0 forbids everything
    expect(rate(0, 10, [])).toBe(false);
    // non-finite times are ignored
    expect(rate(1, 10, [NaN, Infinity, '5' as never, null as never, undefined as never])).toBe(true);
    expect(rate(1, 10, [NaN, NOW - 1])).toBe(false);
    // malformed params / data fail closed
    expect(rate(2, 0, [])).toBe(false);
    expect(rate(2, -5, [])).toBe(false);
    expect(rate(2, NaN, [])).toBe(false);
    expect(rate(2, Infinity, [])).toBe(false);
    expect(rate(2, '10', [])).toBe(false);
    expect(rate(NaN, 10, [])).toBe(false);
    expect(rate(Infinity, 10, [])).toBe(false);
    expect(rate('2', 10, [])).toBe(false);
    expect(rate(undefined, 10, [])).toBe(false);
    expect(rate(2, undefined, [])).toBe(false);
    expect(rate(2, 10, undefined)).toBe(false);
    expect(rate(2, 10, null)).toBe(false);
    expect(rate(2, 10, 'x')).toBe(false);
    expect(rate(2, 10, { length: 0 })).toBe(false);
    // fractional per_secs is allowed (> 0)
    expect(rate(1, 0.5, [NOW - 400])).toBe(false);
    expect(rate(1, 0.5, [NOW - 600])).toBe(true);
  });
  it('max_blast_radius: blastRadius <= max', () => {
    const br = (max: unknown, blastRadius: unknown) => ev({ type: 'max_blast_radius', max }, { now: NOW, blastRadius });
    expect(br(0.5, 0.5)).toBe(true);
    expect(br(0.5, 0.4)).toBe(true);
    expect(br(0.5, 0.51)).toBe(false);
    expect(br(0, 0)).toBe(true);
    expect(br(0.5, NaN)).toBe(false);
    expect(br(0.5, undefined)).toBe(false);
    expect(br(0.5, '0.1')).toBe(false);
    expect(br(0.5, Infinity)).toBe(false);
    expect(br(NaN, 0.1)).toBe(false);
    expect(br(Infinity, 0.1)).toBe(false);
    expect(br(undefined, 0.1)).toBe(false);
    expect(br('1', 0.1)).toBe(false);
    expect(br(-Infinity, -Infinity)).toBe(false);
  });
  it('reversibility_max: current class no more severe than the limit; unknown classes fail', () => {
    expect(REVERSIBILITY_ORDER).toEqual(['reversible', 'rate_limited', 'irreversible']);
    const rv = (cls: unknown, cur: unknown) => ev({ type: 'reversibility_max', class: cls }, { now: NOW, reversibilityClass: cur });
    for (const [lim, cur, want] of [
      ['reversible', 'reversible', true],
      ['reversible', 'rate_limited', false],
      ['reversible', 'irreversible', false],
      ['rate_limited', 'reversible', true],
      ['rate_limited', 'rate_limited', true],
      ['rate_limited', 'irreversible', false],
      ['irreversible', 'reversible', true],
      ['irreversible', 'rate_limited', true],
      ['irreversible', 'irreversible', true],
    ] as Array<[string, string, boolean]>) expect(rv(lim, cur), `${lim}/${cur}`).toBe(want);
    expect(rv('bogus', 'reversible')).toBe(false);
    expect(rv('reversible', 'bogus')).toBe(false);
    expect(rv('reversible', undefined)).toBe(false);
    expect(rv(undefined, 'reversible')).toBe(false);
    expect(rv(undefined, undefined)).toBe(false);
    expect(rv('irreversible', null)).toBe(false);
    expect(rv('', '')).toBe(false);
    expect(rv('Reversible', 'reversible')).toBe(false);
  });
  it('delegation_depth: delegationDepth <= max', () => {
    const dd = (max: unknown, d: unknown) => ev({ type: 'delegation_depth', max }, { now: NOW, delegationDepth: d });
    expect(dd(2, 2)).toBe(true);
    expect(dd(2, 1)).toBe(true);
    expect(dd(2, 0)).toBe(true);
    expect(dd(2, 3)).toBe(false);
    expect(dd(0, 0)).toBe(true);
    expect(dd(0, 1)).toBe(false);
    expect(dd(2, undefined)).toBe(false);
    expect(dd(2, NaN)).toBe(false);
    expect(dd(2, '1')).toBe(false);
    expect(dd(NaN, 1)).toBe(false);
    expect(dd(undefined, 1)).toBe(false);
    expect(dd(Infinity, 1)).toBe(false);
  });
  it('budget_alloc: satisfied iff limit is a finite number >= 0', () => {
    const ba = (limit: unknown) => ev({ type: 'budget_alloc', limit });
    expect(ba(0)).toBe(true);
    expect(ba(1)).toBe(true);
    expect(ba(1e9)).toBe(true);
    expect(ba(0.5)).toBe(true);
    expect(ba(-1)).toBe(false);
    expect(ba(-0.0001)).toBe(false);
    expect(ba(NaN)).toBe(false);
    expect(ba(Infinity)).toBe(false);
    expect(ba('5')).toBe(false);
    expect(ba(undefined)).toBe(false);
    expect(ba(null)).toBe(false);
    expect(ev({ type: 'budget_alloc' })).toBe(false);
  });
  it('a throwing getter fails closed', () => {
    const hostile = { type: 'expires', get at(): number { throw new Error('boom'); } };
    expect(ev(hostile)).toBe(false);
    const hostileCtx = { get now(): number { throw new Error('boom'); } };
    expect(ev({ type: 'expires', at: NOW + 1 }, hostileCtx)).toBe(false);
  });
});

describe('evaluateCaveats', () => {
  const NOW = 1_700_000_000_000;
  const ctx: CaveatContext = { now: NOW, blastRadius: 0.1, reversibilityClass: 'reversible', delegationDepth: 1, recentActionTimes: [] };
  it('ok iff every caveat holds; failed lists unsatisfied types in order', () => {
    expect(evaluateCaveats([], ctx)).toStrictEqual({ ok: true, failed: [] });
    expect(evaluateCaveats([{ type: 'expires', at: NOW + 5 }, { type: 'not_before', at: NOW }], ctx)).toStrictEqual({ ok: true, failed: [] });
    expect(evaluateCaveats([{ type: 'expires', at: NOW - 5 }, { type: 'not_before', at: NOW }, { type: 'max_blast_radius', max: 0.01 }], ctx)).toStrictEqual({ ok: false, failed: ['expires', 'max_blast_radius'] });
    expect(evaluateCaveats([{ type: 'nonsense' } as never], ctx)).toStrictEqual({ ok: false, failed: ['nonsense'] });
    expect(evaluateCaveats([{ type: 'delegation_depth', max: 0 }, { type: 'delegation_depth', max: 0 }], ctx)).toStrictEqual({ ok: false, failed: ['delegation_depth', 'delegation_depth'] });
  });
  it('a malformed caveats list fails with the marker', () => {
    for (const bad of [undefined, null, 'x', 5, {}, { length: 1 }]) expect(evaluateCaveats(bad as never, ctx)).toStrictEqual({ ok: false, failed: ['<malformed caveats>'] });
  });
  it('a caveat without a string type is reported as <malformed>', () => {
    for (const cv of [null, undefined, 5, {}, { type: 5 }, { type: null }, 'x']) {
      expect(evaluateCaveats([cv as never], ctx), JSON.stringify(cv)).toStrictEqual({ ok: false, failed: ['<malformed>'] });
    }
    expect(evaluateCaveats([{ type: '' } as never], ctx)).toStrictEqual({ ok: false, failed: [''] });
  });
  it('custom evaluator replaces the built-in; its exceptions count as unsatisfied; truthiness is respected', () => {
    const calls: unknown[][] = [];
    const all = (cv: unknown, c: unknown): boolean => {
      calls.push([cv, c]);
      return true;
    };
    expect(evaluateCaveats([{ type: 'whatever' }], ctx, all as never)).toStrictEqual({ ok: true, failed: [] });
    expect(calls.length).toBe(1);
    expect(calls[0]![1]).toBe(ctx);
    const boom = (): boolean => {
      throw new Error('boom');
    };
    expect(evaluateCaveats([{ type: 'a' }, { type: 'b' }], ctx, boom)).toStrictEqual({ ok: false, failed: ['a', 'b'] });
    const alt = (cv: { type: string }): boolean => cv.type === 'good';
    expect(evaluateCaveats([{ type: 'good' }, { type: 'bad' }, { type: 'good' }], ctx, alt)).toStrictEqual({ ok: false, failed: ['bad'] });
    // every caveat is evaluated (no short-circuit)
    let n = 0;
    evaluateCaveats([{ type: 'x' }, { type: 'y' }, { type: 'z' }], ctx, () => (n++, false));
    expect(n).toBe(3);
  });
});

describe('survivor kills (round 2)', () => {
  const subj = (v: unknown, extra: Record<string, unknown> = {}) => ctxOf({ subject: { v }, ...extra });
  it('is_a: an ARRAY carrying an own "type" property is not a typed record (no decidable type)', () => {
    const arr = Object.assign([], { type: 'foo' });
    expect(tri({ field: 'subject.v', op: 'is_a', value: 'foo' }, subj(arr))).toBe('unknown');
    const arr2 = Object.assign([], { tags: ['foo'] });
    expect(tri({ field: 'subject.v', op: 'is_a', value: 'foo' }, subj(arr2))).toBe('unknown');
  });
  it('member_of: a node with no adjacency entry has no neighbours (no phantom node)', () => {
    const c = { field: 'subject.v', op: 'member_of', collection: 'env.g', value: 'Stryker was here' };
    expect(tri(c, subj('solo', { env: { g: { a: ['b'] } } }))).toBe('false');
    expect(tri(c, subj('constructor', { env: { g: { a: ['b'] } } }))).toBe('false');
  });
  it('member_of: an adjacency value that is neither a string nor an array contributes no neighbours', () => {
    const c = { field: 'subject.v', op: 'member_of', collection: 'env.g', value: 'Stryker was here' };
    for (const raw of [5, true, null, { x: 1 }]) expect(tri(c, subj('a', { env: { g: { a: raw } } }))).toBe('false');
    expect(tri({ ...c, value: 'b' }, subj('a', { env: { g: { a: 'b' } } }))).toBe('true');
    expect(tri({ ...c, value: 'b' }, subj('a', { env: { g: { a: ['x', 5, 'b'] } } }))).toBe('true');
  });
  it('member_of: closure stops when the queue is empty (no phantom "undefined" node expansion)', () => {
    const c = { field: 'subject.v', op: 'member_of', collection: 'env.g', value: 'zzz' };
    expect(tri(c, subj('a', { env: { g: { a: [], undefined: ['zzz'] } } }))).toBe('false');
    expect(tri({ ...c, value: 'a' }, subj('a', { env: { g: {} } }))).toBe('true');
  });
  it('member_of: a node is expanded once - diamonds do not exhaust the node budget', () => {
    const g: Record<string, string[]> = {};
    for (let k = 0; k < 20; k++) {
      g[`n${k}`] = [`m${k}a`, `m${k}b`];
      g[`m${k}a`] = [`n${k + 1}`];
      g[`m${k}b`] = [`n${k + 1}`];
    }
    const c = { field: 'subject.v', op: 'member_of', collection: 'env.g', value: 'n20' };
    expect(tri(c, subj('n0', { env: { g } }))).toBe('true');
    // and a cycle terminates with the right verdict
    expect(tri({ ...c, value: 'q' }, subj('a', { env: { g: { a: ['b', 'a'], b: ['a'] } } }))).toBe('false');
  });
  it('a params-rooted ref is "unknown" when params are unavailable, even for exists (which ignores ref otherwise)', () => {
    const noParams = ctxOf({ subject: { id: 's' } });
    expect(tri({ field: 'subject.id', op: 'exists', ref: 'action.params.x' }, noParams)).toBe('unknown');
    expect(tri({ field: 'subject.id', op: 'exists', ref: 'action.params' }, noParams)).toBe('unknown');
    expect(tri({ field: 'subject.id', op: 'exists', ref: 'subject.id' }, noParams)).toBe('true');
    expect(tri({ field: 'subject.id', op: 'exists', ref: 'zaction.params.x' }, noParams)).toBe('true');
  });
  it('prefix / like / matches: a non-string operand (or subject) is "unknown", never coerced', () => {
    expect(tri({ field: 'subject.v', op: 'prefix', value: 5 }, subj('5abc'))).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'prefix', value: ['5'] }, subj('5abc'))).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'prefix', value: 'a' }, subj({ startsWith: () => true }))).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'like', value: 5 }, subj(''))).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'matches', value: 5 }, subj(''))).toBe('unknown');
    expect(tri({ field: 'subject.v', op: 'matches', value: ['a'] }, subj('a'))).toBe('unknown');
  });
  it('like: stars expand (kind of the collapsed star token matters)', () => {
    expect(tri({ field: 'subject.v', op: 'like', value: 'a*' }, subj('abc'))).toBe('true');
    expect(tri({ field: 'subject.v', op: 'like', value: 'a**c' }, subj('abbc'))).toBe('true');
    expect(tri({ field: 'subject.v', op: 'like', value: '*b*' }, subj('abc'))).toBe('true');
    expect(tri({ field: 'subject.v', op: 'like', value: '*b*' }, subj('acc'))).toBe('false');
  });
  it('predicate where must be an array: an empty string where is not "no conditions"', () => {
    const base = { verb: 'v', resource: '/r' };
    expect(predicateMatches({ ...base, where: '' } as never, ctxOf())).toBe(false);
    expect(predicateMatches({ ...base, where: [] } as never, ctxOf())).toBe(true);
    expect(predicateMatches({ ...base, where: 0 } as never, ctxOf())).toBe(false);
  });
  it('isSafeRegexSource: a literal "]" directly before a class does not confuse the class scan', () => {
    expect(isSafeRegexSource('][a]')).toBe(true);
    expect(isSafeRegexSource('a][b]')).toBe(true);
    expect(isSafeRegexSource('[a]][b]')).toBe(true);
  });
});

describe('survivor kills (round 3): regex budget and step cap in matches', () => {
  const ctxV = (v: string) => ctxOf({ subject: { v } });
  it('per-document regex evaluation budget: the 65th matches evaluation is refused (unknown), the 64th is not', () => {
    const cond = { field: 'subject.v', op: 'matches', value: 'a+' };
    const mk = (n: number) => ({ all_of: Array.from({ length: n }, () => cond) });
    expect(tri(mk(64), ctxV('aaa'))).toBe('true');
    expect(tri(mk(65), ctxV('aaa'))).toBe('unknown');
    const mkAny = (n: number) => ({ any_of: [...Array.from({ length: n }, () => ({ field: 'subject.v', op: 'matches', value: 'b+' })), { field: 'subject.v', op: 'eq', value: 'aaa' }] });
    expect(tri(mkAny(64), ctxV('aaa'))).toBe('true');
  });
  it('a pattern whose NFA x subject exceeds the match step cap is "unknown" (engine returns null), not false', () => {
    const big = '(?:' + 'a'.repeat(63) + '){64}';
    expect(compileSafeRegex(big)).not.toBeNull();
    expect(isSafeRegexSource(big)).toBe(true);
    expect(tri({ field: 'subject.v', op: 'matches', value: big }, ctxV('a'.repeat(512)))).toBe('unknown');
    // a small subject is evaluated normally
    expect(tri({ field: 'subject.v', op: 'matches', value: big }, ctxV('a'.repeat(100)))).toBe('false');
  });
});

describe('survivor kills (round 4): hostile shapes where a guard is observable', () => {
  const fnWith = (props: Record<string, unknown>) => Object.assign(() => undefined, props);
  const caveatCtx = { now: 50 } as CaveatContext;

  it('member_of: an INHERITED "value" is not an operand (own property only)', () => {
    const inherited = Object.assign(Object.create({ value: 'g' }), { field: 'subject.v', op: 'member_of', collection: 'env.adj' });
    const ctx = ctxOf({ subject: { v: 'a' }, env: { adj: { a: 'g' } } });
    expect(tri({ field: 'subject.v', op: 'member_of', collection: 'env.adj', value: 'g' }, ctx)).toBe('true');
    expect(tri(inherited, ctx)).toBe('unknown');
  });

  it('a function-typed condition is not an object condition (unknown), even carrying a valid leaf shape', () => {
    const leaf = { field: 'action.verb', op: 'eq', value: 'v' };
    expect(tri(leaf)).toBe('true');
    expect(tri(fnWith(leaf))).toBe('unknown');
    expect(evaluateCondition(fnWith(leaf) as never, ctxOf())).toBe(false);
  });

  it('a function-typed predicate never matches, even with verb/resource "*"', () => {
    expect(predicateMatches({ verb: '*', resource: '*' }, ctxOf())).toBe(true);
    expect(predicateMatches(fnWith({ verb: '*', resource: '*' }) as never, ctxOf())).toBe(false);
  });

  it('a non-string resource pattern never matches, even an object that quacks like a glob', () => {
    const quack = { startsWith: () => false, endsWith: () => true, slice: () => '' };
    expect(predicateMatches({ verb: 'v', resource: quack } as never, ctxOf())).toBe(false);
    expect(predicateMatches({ verb: 'v', resource: '*' }, ctxOf())).toBe(true);
  });

  it('resource re: patterns are charged to the per-document regex budget: the 65th evaluation is refused', () => {
    const miss: Predicate = { verb: '*', resource: 're:b' };
    const hit: Predicate = { verb: '*', resource: 're:a' };
    const ctx = { action: { verb: 'v', resource: 'a' } } as ActionContext;
    expect(evaluatePredicates([...Array.from({ length: 63 }, () => miss), hit], ctx).allowed).toBe(true);
    expect(evaluatePredicates([...Array.from({ length: 64 }, () => miss), hit], ctx).allowed).toBe(false);
  });

  it('caveats: a function-typed caveat or context is refused, however well-formed', () => {
    const cv = { type: 'expires', at: 100 };
    expect(envelopeCaveatEvaluator(cv as never, caveatCtx)).toBe(true);
    expect(envelopeCaveatEvaluator(fnWith(cv) as never, caveatCtx)).toBe(false);
    expect(envelopeCaveatEvaluator(cv as never, fnWith({ now: 50 }))).toBe(false);
    expect(envelopeCaveatEvaluator(null as never, caveatCtx)).toBe(false);
    expect(envelopeCaveatEvaluator(cv as never, null)).toBe(false);
  });

  it('rate: recentActionTimes must be a real array (a duck-typed filter() is refused)', () => {
    const cv = { type: 'rate', max: 5, per_secs: 60 };
    expect(envelopeCaveatEvaluator(cv as never, { now: 1000, recentActionTimes: [] } as CaveatContext)).toBe(true);
    expect(envelopeCaveatEvaluator(cv as never, { now: 1000, recentActionTimes: { filter: () => [] } } as never)).toBe(false);
  });

  it('isSafeRegexSource: bounded repeat cap is 64 for {n} and {m,n}; {n,} is unbounded and still accepted', () => {
    expect(isSafeRegexSource('a{64}')).toBe(true);
    expect(isSafeRegexSource('a{65}')).toBe(false);
    expect(isSafeRegexSource('a{100}')).toBe(false);
    expect(isSafeRegexSource('a{1,64}')).toBe(true);
    expect(isSafeRegexSource('a{1,65}')).toBe(false);
    expect(isSafeRegexSource('a{3}')).toBe(true);
    expect(isSafeRegexSource('a{2,}')).toBe(true);
    expect(isSafeRegexSource('a*')).toBe(true);
    expect(isSafeRegexSource('a+b+')).toBe(true);
    expect(isSafeRegexSource('a+b+c+')).toBe(false);
  });
});
