/* eslint-disable @typescript-eslint/no-explicit-any */
// Differential tests: the PROVED predicate / caveat / Policy-VM core (formal/dafny/PolicyVm.dfy via src/ext-policyvm.ts)
// against the production TypeScript (packages/pca/src/predicates.ts, agent-native.ts, policy-vm.ts, risk.ts).
// Scale with PVM_N (random cases per family; default is modest for the Mac, the cloud run uses millions in total).
import { describe, expect, it } from 'vitest';
import * as prod from '../../pca/src/predicates';
import { safeRegexFullMatch } from '../../pca/src/safe-regex';
import { agentNativeCaveatEvaluator, toolSchemaEvaluator } from '../../pca/src/agent-native';
import { decide, type DecideInput } from './support/legacy/policy-vm';
import { admit as prodAdmit, escalateThreshold as prodEscalate, requiredThreshold as prodRequired, cost as prodCost } from '../../pca/src/risk';
import {
  admitVerified,
  createPolicyVm,
  decideCoreVerified,
  escalateThresholdVerified,
  ratToDouble,
  requiredThresholdVerified,
  toRat,
} from '../src/ext-policyvm';
import { decideVerified } from './support/policyvm-decide';
import { loadCorpus } from './support/corpus';

const N = Number(process.env.PVM_N ?? 4000);
const SEED = Number(process.env.PVM_SEED ?? 1);

const vm = createPolicyVm({ safeRegex: prod.isSafeRegexSource, regexFullMatch: safeRegexFullMatch, toolSchema: toolSchemaEvaluator as any });

// ---------------------------------------------------------------- deterministic PRNG + generators
class R {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0 || 1;
  }
  f(): number {
    // mulberry32
    this.s = (this.s + 0x6d2b79f5) >>> 0;
    let t = this.s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  i(n: number): number {
    return Math.floor(this.f() * n);
  }
  p<T>(xs: readonly T[]): T {
    return xs[this.i(xs.length)]!;
  }
  b(pr = 0.5): boolean {
    return this.f() < pr;
  }
}

const STR_POOL = [
  '', 'a', 'b', 'abc', 'ab', 'aab', 'ba', 'abcabc', 'a*', '*a', 'a?c', '/acct/1', '/acct/2/items/7', '/acct/', '/acct/*', 'GET', 'POST', 'DELETE', '*',
  'Type', 'Type::7', 'Type::', 'x::y', 'user', 'user::42', 'admin', 'é', 'é', '\u{1F600}', '￿', '\u{10000}', '\ud800', '\udc00', 'a\ud800', '𐀀',
  '__proto__', 'constructor', 'prototype', 'toString', '10', '2', '02', 'reversible', 'rate_limited', 'irreversible', 'costly', 're:.*', 're:/acct/[^/]+', 're:(a+)+',
  'a.b', 'x'.repeat(513), 'y'.repeat(200), 'a'.repeat(300), '\\', 'a\\*', '\\*', '*a*a*b', 'aaaaaaaaaaaaaaaaaaaab', 'predicates', 'tool_schema', 'expires',
];
const NUM_POOL = [0, -0, 1, -1, 2, 3, 10, 1.5, 0.1, 0.2, 0.30000000000000004, 1e21, 1e-7, 123456789.123, 2 ** 53, -(2 ** 53), 5e-324, 1.7976931348623157e308, NaN, Infinity, -Infinity, 1700000000000, 1700000060000];
const KEY_POOL = ['a', 'b', 'c', 'type', 'tags', 'x', 'y', 'params', 'session', 'device', 'id', 'name', '0', '1', 'length', '__proto__', 'constructor', 'prototype', 'k\ud800', 'k\ud801', 'é', '\u{10000}', 'z', ''];
const OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists', 'like', 'matches', 'is_a', 'member_of'];
const MATCH_PATTERNS = ['a+', '[a-c]+', '/acct/[^/]+', '(a+)+', '(?=x)', '\\1', 'a{2,3}', '.*', 'ab|cd', '', '(', '[', 'x*y*z*', '\\d+', '[^]', '(a|aa)+b', 'a*a*a*a*b', 'é+'];

function setProp(o: any, k: string, v: unknown): void {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}
function scalar(r: R): unknown {
  const c = r.i(10);
  if (c < 3) return r.p(STR_POOL);
  if (c < 6) return r.p(NUM_POOL);
  if (c === 6) return r.b();
  if (c === 7) return null;
  if (c === 8) return undefined;
  return r.p(STR_POOL);
}
function value(r: R, d: number): unknown {
  const c = r.i(d > 2 ? 6 : 10);
  if (c < 6) return scalar(r);
  if (c < 8) {
    const n = r.i(4);
    return Array.from({ length: n }, () => value(r, d + 1));
  }
  const o: any = r.b(0.1) ? Object.create(null) : {};
  const n = r.i(5);
  for (let i = 0; i < n; i++) setProp(o, r.p(KEY_POOL), value(r, d + 1));
  return o;
}
function strList(r: R): string[] {
  return Array.from({ length: r.i(4) }, () => r.p(STR_POOL));
}
function adjacency(r: R): any {
  const o: any = {};
  const nodes = ['a', 'b', 'c', 'x', 'y', 'user', 'admin', '__proto__', 'z'];
  for (let i = 0; i < r.i(7); i++) setProp(o, r.p(nodes), r.b(0.4) ? r.p(nodes) : r.b(0.8) ? Array.from({ length: r.i(3) }, () => (r.b(0.9) ? r.p(nodes) : (r.p(NUM_POOL) as any))) : value(r, 2));
  return o;
}
function context(r: R): any {
  const ctx: any = {};
  if (r.b(0.95)) {
    const a: any = { verb: r.b(0.95) ? r.p(['GET', 'POST', 'DELETE', 'read', 'a']) : r.p(NUM_POOL), resource: r.b(0.95) ? r.p(['/acct/1', '/acct/2/items/7', '/x', 'a', 'abc', '', 'é']) : r.p(NUM_POOL) };
    if (r.b(0.85)) a.params = r.b(0.9) ? value(r, 1) : r.p([null, 5, 'p', [] as any]);
    if (r.b(0.9) && a.params && typeof a.params === 'object' && !Array.isArray(a.params)) {
      setProp(a.params, 'x', scalar(r));
      setProp(a.params, 'session', value(r, 2));
      setProp(a.params, 'tags', strList(r));
      // 0.4.1 max_spend: the spend it reads (own amount + optional own currency)
      if (r.b(0.6)) setProp(a.params, 'amount', r.b(0.85) ? r.p([0, 1, 50, 99.5, 100, 100.5, 1e6, -1, -0, NaN, Infinity]) : scalar(r));
      if (r.b(0.3)) setProp(a.params, 'currency', r.p(['usd', 'USD', 'Usd', 'eur', null, undefined, 5]));
    }
    if (r.b(0.3)) a.reversibility_class = r.p(['reversible', 'rate_limited', 'irreversible', 'costly', 5]);
    ctx.action = a;
  }
  if (r.b(0.7)) ctx.subject = value(r, 1);
  if (r.b(0.7)) {
    const e: any = value(r, 1);
    ctx.env = e && typeof e === 'object' ? e : {};
    if (typeof ctx.env === 'object' && !Array.isArray(ctx.env)) {
      setProp(ctx.env, 'groups', adjacency(r));
      setProp(ctx.env, 'current_device', scalar(r));
      setProp(ctx.env, 'g', r.b() ? strList(r) : r.p(STR_POOL));
    }
  }
  if (r.b(0.2)) ctx.toolBinding = r.p(STR_POOL);
  if (r.b(0.03)) return r.p([null, 5, 'str', [] as any, undefined]);
  return ctx;
}
function paths(ctx: any, limit = 40): string[] {
  const out: string[] = [];
  const walk = (v: any, p: string, d: number): void => {
    if (out.length > limit) return;
    out.push(p);
    if (d > 3 || v === null || typeof v !== 'object') return;
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${p}.${i}`, d + 1));
    else for (const k of Object.keys(v)) walk(v[k], `${p}.${k}`, d + 1);
  };
  if (ctx && typeof ctx === 'object') for (const k of Object.keys(ctx)) walk(ctx[k], k, 0);
  return out;
}
function pathOf(r: R, ps: string[]): unknown {
  const c = r.i(14);
  if (c < 9 && ps.length) return r.p(ps);
  if (c === 9) return r.p(['action.params.x', 'action.params', 'action.verb', 'env.groups', 'env.g', 'subject.id', 'action.params.session.device', 'action.params.tags']);
  if (c === 10) return r.p(['', 'nope', 'action.', 'action..x', '.action', 'action.__proto__', 'env.constructor', 'action.params.__proto__.x', 'action.params.0', 'action.params.01', 'action.params.-1', 'action.params.1e3']);
  if (c === 11) return r.p([5, null, undefined, {}, []]);
  return ps.length ? r.p(ps) : 'action.verb';
}
function leaf(r: R, ctx: any, ps: string[]): any {
  const c: any = {};
  if (r.b(0.97)) c.field = pathOf(r, ps);
  c.op = r.b(0.96) ? r.p(OPS) : r.p(['bogus', 5, null, 'EQ', '']);
  const op = c.op;
  const useRef = r.b(0.18);
  if (useRef) c.ref = pathOf(r, ps);
  else if (r.b(0.93)) {
    if (op === 'in' || op === 'nin') c.value = r.b(0.9) ? Array.from({ length: r.i(4) }, () => scalar(r)) : value(r, 1);
    else if (op === 'like') c.value = r.p(['a*', '*a', 'a?c', '*a*a*b', '\\', 'a\\*', '*', '', '?', '**a**', 'abc', '/acct/*', 'x'.repeat(520), r.p(STR_POOL)]);
    else if (op === 'matches') c.value = r.p(MATCH_PATTERNS);
    else if (op === 'member_of') c.value = r.b(0.7) ? r.p(['a', 'b', 'admin', 'x', '__proto__', 'zz']) : r.b() ? strList(r) : value(r, 1);
    else if (op === 'is_a') c.value = r.p(['Type', 'user', 'admin', 'x', '', 5, 'Type::7']);
    else if (op === 'exists') c.value = r.p([true, false, 0, null, 'x', undefined]);
    else c.value = r.b(0.85) ? scalar(r) : value(r, 1);
  }
  if (op === 'member_of' || r.b(0.03)) c.collection = r.b(0.8) ? r.p(['env.groups', 'env.g', 'action.params', 'subject', ...ps.slice(0, 3)]) : pathOf(r, ps);
  if (r.b(0.02)) c.extra = 1;
  return c;
}
function cond(r: R, ctx: any, ps: string[], d: number): any {
  const c = r.i(20);
  if (d > 3 || c < 12) return leaf(r, ctx, ps);
  if (c < 15) return { all_of: r.b(0.9) ? Array.from({ length: r.i(4) }, () => cond(r, ctx, ps, d + 1)) : r.p([null, 5, 'x', {}, []]) };
  if (c < 17) return { any_of: r.b(0.9) ? Array.from({ length: r.i(4) }, () => cond(r, ctx, ps, d + 1)) : r.p([null, 5, 'x', {}, []]) };
  if (c < 19) return { not: r.b(0.95) ? cond(r, ctx, ps, d + 1) : r.p([null, 5, undefined, [], {}]) };
  const m = r.i(6);
  if (m === 0) return r.p([null, 5, 'str', undefined, true, [] as any]);
  if (m === 1) return { all_of: [cond(r, ctx, ps, d + 1)], any_of: [cond(r, ctx, ps, d + 1)] };
  if (m === 2) return { not: cond(r, ctx, ps, d + 1), all_of: [cond(r, ctx, ps, d + 1)] };
  if (m === 3) return [leaf(r, ctx, ps)];
  if (m === 4) return { all_of: undefined };
  return { not: undefined };
}
function predicate(r: R, ctx: any, ps: string[]): any {
  const p: any = {};
  if (r.b(0.95)) p.verb = r.b(0.6) ? r.p(['GET', 'POST', '*', 'read', 'DELETE']) : r.b(0.8) ? Array.from({ length: r.i(4) }, () => r.p(['GET', 'POST', '*', 5, null, 'a'] as any[])) : r.p([5, null, {}]);
  if (r.b(0.85)) p.resource = r.p(['*', '/acct/*', '/acct/1', 're:/acct/[^/]+', 're:.*', 're:(a+)+', 're:/acct/[^/]+/items/\\d+', '', 'a*', 're:' + 'a'.repeat(201), 'abc', 5, null, 'é*']);
  if (r.b(0.75)) p.where = r.b(0.94) ? Array.from({ length: r.i(4) }, () => cond(r, ctx, ps, 1)) : r.p([null, 5, {}, 'x']);
  if (r.b(0.02)) return r.p([null, 5, 'x', [] as any, undefined]);
  return p;
}

// ---------------------------------------------------------------- helpers
const same = (a: unknown, b: unknown, what: string): void => {
  expect(b, what).toEqual(a);
};

// 0.5 (B6): production names the unmet `where` limit ("<limit> not satisfied for V on R"); the verified kernel only says
// "no predicate permits V on R". The verdict is what is proved; the wording is compared in the plain form.
const plain = (r: string | undefined) => (r === undefined ? r : r.replace(/^.*? not satisfied for (.+)$/s, 'no predicate permits $1'));
const plainJson = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'string' ? plain(x) : x));

describe('PolicyVm differential: condition evaluator (random + exhaustive)', () => {
  it('resolvePath agrees on every path of random contexts, plus junk paths', () => {
    const r = new R(SEED * 7 + 1);
    let n = 0;
    for (let i = 0; i < N; i++) {
      const ctx = context(r);
      const ps = paths(ctx);
      for (let j = 0; j < 6; j++) {
        const p = pathOf(r, ps);
        const a = prod.resolvePath(ctx, p);
        const b = vm.resolvePath(ctx, p);
        if (a.found !== b.found) throw new Error(`resolvePath ${JSON.stringify(p)} prod=${a.found} verified=${b.found}`);
        if (a.found && !Object.is(a.value, b.value)) throw new Error('resolvePath value differs');
        n++;
      }
    }
    expect(n).toBeGreaterThan(1000);
  });

  it('evaluateConditionTri: random conditions x random contexts', () => {
    const r = new R(SEED * 13 + 2);
    const tally: Record<string, number> = { true: 0, false: 0, unknown: 0 };
    for (let i = 0; i < N * 3; i++) {
      const ctx = context(r);
      const ps = paths(ctx);
      const c = cond(r, ctx, ps, 0);
      const a = prod.evaluateConditionTri(c, ctx);
      const b = vm.evaluateConditionTri(c, ctx);
      if (a !== b) throw new Error(`Tri differs prod=${a} verified=${b}\ncond=${JSON.stringify(c)}\nctx=${JSON.stringify(ctx)}`);
      tally[a]!++;
      if (i % 5 === 0) expect(vm.evaluateCondition(c, ctx)).toBe(prod.evaluateCondition(c, ctx));
    }
    // the generator must reach all three verdicts, many times
    expect(tally['true']!).toBeGreaterThan(N / 10);
    expect(tally['false']!).toBeGreaterThan(N / 10);
    expect(tally['unknown']!).toBeGreaterThan(N / 10);
  });

  it('exhaustive: every op x every path x a pool of operands on a fixed context', () => {
    const ctx: any = {
      action: { verb: 'GET', resource: '/acct/1', params: { x: 'abc', n: 2, f: 1.5, neg: -1, s: 'é', arr: ['a', 'b'], t: { type: 'user::1', tags: ['admin', 3] }, nul: null, big: 2 ** 53, o: { a: 1, b: [1, 2] } } },
      subject: { id: 'u1', type: 'Type::7' },
      env: { groups: { a: 'b', b: ['c', 'admin'], c: [], x: 'x' }, g: ['admin'], current_device: 'd1', lp: '\ud800' },
    };
    const ps = paths(ctx, 200);
    const operands: unknown[] = ['abc', 'a*', '?bc', 'ab', 'é', '\u{10000}', '￿', 2, 1.5, -1, 0, NaN, null, true, ['a', 'b'], [], ['abc', 2], { a: 1, b: [1, 2] }, { b: [1, 2], a: 1 }, 'admin', ['admin'], 'Type', 'user', 'a+', '[abc]+', 'x::y', '\ud800'];
    let n = 0;
    for (const field of [...ps, 'nope', '', 'action.params.zz']) {
      for (const op of OPS) {
        for (const v of operands) {
          const c: any = { field, op, value: v };
          if (op === 'member_of') c.collection = 'env.groups';
          const a = prod.evaluateConditionTri(c, ctx);
          const b = vm.evaluateConditionTri(c, ctx);
          if (a !== b) throw new Error(`exhaustive leaf differs ${JSON.stringify(c)} prod=${a} verified=${b}`);
          n++;
        }
        const cr: any = { field, op, ref: 'action.params.x' };
        if (op === 'member_of') cr.collection = 'env.groups';
        expect(vm.evaluateConditionTri(cr, ctx)).toBe(prod.evaluateConditionTri(cr, ctx));
        n++;
      }
    }
    expect(n).toBeGreaterThan(5000);
  });

  it('exhaustive small ASTs: every group shape over 6 leaves, depth <= 2', () => {
    const ctx: any = { action: { verb: 'GET', resource: '/a', params: { x: 1, y: 'a' } }, env: {} };
    const leaves: any[] = [
      { field: 'action.params.x', op: 'eq', value: 1 }, // true
      { field: 'action.params.x', op: 'eq', value: 2 }, // false
      { field: 'action.params.zz', op: 'eq', value: 2 }, // unknown
      { field: 'action.params.y', op: 'prefix', value: 'a' }, // true
      { field: 'action.params.y', op: 'gt', value: 5 }, // unknown (type mismatch)
      { field: 'action.params.x', op: 'lt', value: 5 }, // true
    ];
    const level1: any[] = [...leaves];
    for (const a of leaves) level1.push({ not: a });
    for (const k of ['all_of', 'any_of']) {
      level1.push({ [k]: [] });
      for (const a of leaves) {
        level1.push({ [k]: [a] });
        for (const b of leaves) {
          level1.push({ [k]: [a, b] });
          for (const c of leaves) level1.push({ [k]: [a, b, c] });
        }
      }
    }
    let n = 0;
    const verdicts = new Set<string>();
    for (const c of level1) {
      const a = prod.evaluateConditionTri(c, ctx);
      expect(vm.evaluateConditionTri(c, ctx)).toBe(a);
      verdicts.add(a);
      n++;
    }
    for (const x of level1.filter((_, i) => i % 7 === 0)) {
      for (const k of ['all_of', 'any_of']) {
        for (const y of level1.filter((_, i) => i % 11 === 0)) {
          const c = { [k]: [x, { not: y }] };
          expect(vm.evaluateConditionTri(c, ctx)).toBe(prod.evaluateConditionTri(c, ctx));
          n++;
        }
      }
      const c = { not: { not: x } };
      expect(vm.evaluateConditionTri(c, ctx)).toBe(prod.evaluateConditionTri(c, ctx));
      n++;
    }
    expect(verdicts.size).toBe(3);
    expect(n).toBeGreaterThan(3000);
  });

  it('visited nodes never exceed the size of the condition tree (resource bound), on random conditions', () => {
    const r = new R(SEED * 17 + 3);
    const size = (c: any): number => {
      if (c === null || typeof c !== 'object') return 1;
      if (Array.isArray(c)) return 1 + c.reduce((s: number, x: any) => s + size(x), 0);
      return 1 + Object.keys(c).reduce((s, k) => s + size(c[k]), 0);
    };
    for (let i = 0; i < N; i++) {
      const ctx = context(r);
      const c = cond(r, ctx, paths(ctx), 0);
      const { visited } = vm.evaluateConditionCounted(c, ctx);
      expect(visited).toBeLessThanOrEqual(size(c));
    }
  });
});

describe('PolicyVm differential: predicates', () => {
  it('predicateMatches / evaluatePredicates agree (verdict, matched identity, reason)', () => {
    const r = new R(SEED * 19 + 4);
    let allowed = 0;
    let denied = 0;
    for (let i = 0; i < N * 2; i++) {
      const ctx = context(r);
      const ps = paths(ctx);
      const list: any = r.b(0.97) ? Array.from({ length: r.i(4) }, () => predicate(r, ctx, ps)) : r.p([null, 5, {}, 'x']);
      const a = prod.evaluatePredicates(list, ctx);
      const b = vm.evaluatePredicates(list, ctx);
      if (a.allowed !== b.allowed || plain(a.reason) !== plain(b.reason) || a.matched !== b.matched) throw new Error(`evaluatePredicates differs\nprod=${JSON.stringify(a)}\nverified=${JSON.stringify(b)}\nlist=${JSON.stringify(list)}\nctx=${JSON.stringify(ctx)}`);
      if (a.allowed) allowed++;
      else denied++;
      if (Array.isArray(list)) for (const p of list) expect(vm.predicateMatches(p, ctx)).toBe(prod.predicateMatches(p, ctx));
    }
    expect(allowed).toBeGreaterThan(N / 50);
    expect(denied).toBeGreaterThan(N / 10);
  });
});

// ---------------------------------------------------------------- caveats
const CAV_TYPES = ['expires', 'not_before', 'rate', 'max_blast_radius', 'reversibility_max', 'delegation_depth', 'budget_alloc', 'predicates', 'tool_schema', 'envelope', 'bogus', 'max_spend', 'note', 'intent_session'];
function caveat(r: R, ctx: any, ps: string[]): any {
  const t = r.b(0.97) ? r.p(CAV_TYPES) : r.p([5, null, undefined, {}, [], 'toString'] as any[]);
  const c: any = { type: t };
  const num = (): unknown => (r.b(0.85) ? r.p([0, 1, 2, 3, 0.5, 0.25, 1700000000000, 1700000000001, 1699999999999, 60, 3600, -1, 1e308, NaN, Infinity, -0]) : scalar(r));
  switch (t) {
    case 'expires':
    case 'not_before':
      c.at = num();
      break;
    case 'rate':
      c.max = num();
      c.per_secs = num();
      break;
    case 'max_blast_radius':
    case 'delegation_depth':
      c.max = num();
      break;
    case 'reversibility_max':
      c.class = r.b(0.9) ? r.p(['reversible', 'rate_limited', 'irreversible', 'costly', ['irreversible'], [['reversible']], ['a', 'b'], [], null, undefined, 5, {}]) : scalar(r);
      break;
    case 'budget_alloc':
      c.limit = num();
      break;
    case 'max_spend':
      if (r.b(0.9)) c.usd = r.b(0.7) ? r.p([0, 1, 50, 100, 1e6, -1, NaN]) : num();
      break;
    case 'predicates':
      c.allow = r.b(0.93) ? Array.from({ length: r.i(3) }, () => predicate(r, ctx, ps)) : r.p([null, 5, {}, 'x']);
      break;
    case 'intent_session':
      Object.assign(c, sessionCaveat(r));
      break;
    case 'tool_schema':
      c.tool = r.p(['GET', 'POST', 'a']);
      c.schema = r.b() ? { props: {}, required: [] } : r.p([null, 5]);
      break;
    default:
      break;
  }
  if (r.b(0.02)) return r.p([null, 5, 'x', [] as any, undefined]);
  return c;
}
// Intent Layer v2 (rule 13) session caveat members: mostly well-formed, with every way of being malformed (including `seq: -0`, which
// both the TypeScript isNonNeg and the model's SessionSeqOk refuse: the extraction boundary carries the -0 flag).
const B32 = ['A'.repeat(43), 'A'.repeat(42) + 'E', 'abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE', 'z'.repeat(42) + 'w'];
const BAD32 = ['A'.repeat(42), 'A'.repeat(44), 'A'.repeat(42) + 'B', 'A'.repeat(42) + '=', 'A'.repeat(42) + '+', 'A'.repeat(41) + '/A', '', 5, null, ['A'.repeat(43)]];
function sessionCaveat(r: R): Record<string, unknown> {
  const b32 = (): unknown => (r.b(0.85) ? r.p(B32) : r.p(BAD32));
  const seq = r.b(0.8) ? r.p([0, 1, 2, 2147483647]) : r.p([2147483648, -1, -0, 1.5, NaN, Infinity, '1', null, 2 ** 53]);
  const out: Record<string, unknown> = { session: b32(), root: b32(), seq };
  const wantPrev = r.b(0.85) ? seq !== 0 : seq === 0;
  if (wantPrev) out.prev = b32();
  if (r.b(0.05)) out.prev = undefined;
  if (r.b(0.05)) delete out[r.p(['session', 'root', 'seq'])];
  if (r.b(0.05)) out[r.p(['extra', 'Type', 'note'])] = 1;
  return out;
}
const NOW = 1700000000000;
function cavContext(r: R, ctx: any): any {
  const c: any = {};
  if (r.b(0.95)) c.now = r.b(0.9) ? NOW + r.p([0, 1, -1, 1000, -1000, 60000]) : r.p([NaN, Infinity, '5', null, undefined, -0, 0]);
  if (r.b(0.8)) c.blastRadius = r.p([0, 0.1, 0.5, 1, 0.3, NaN, '0.1', undefined]);
  if (r.b(0.8)) c.reversibilityClass = r.p(['reversible', 'rate_limited', 'irreversible', 'costly', ['reversible'], undefined, 5, null]);
  if (r.b(0.8)) c.delegationDepth = r.p([0, 1, 2, 3, -1, 1.5, NaN, '1']);
  if (r.b(0.8)) c.recentActionTimes = r.b(0.9) ? Array.from({ length: r.i(6) }, () => NOW - r.i(70000) + (r.b(0.05) ? r.p([0.5, -0.5]) : 0)).concat(r.b(0.1) ? [NaN, 'x' as any, Infinity] : []) : r.p([null, 5, {}]);
  if (r.b(0.9)) c.action = ctx;
  if (r.b(0.5)) c.toolCall = { tool: 'GET', args: {} };
  if (r.b(0.02)) return r.p([null, 5, 'x', [] as any, undefined]);
  return c;
}

describe('PolicyVm differential: intent_session caveat (rule 13)', () => {
  const ctx = { now: NOW, action: { action: { verb: 'v', resource: 'r' } } };
  const ok = { type: 'intent_session', session: B32[0], root: B32[1], seq: 0 };
  it('a well-formed caveat is satisfied, a malformed one is not, and the proved evaluators agree with production', () => {
    const cases: unknown[] = [
      ok,
      { ...ok, seq: 3, prev: B32[2] },
      { ...ok, seq: 2147483647, prev: B32[3] },
      { ...ok, seq: 1 },
      { ...ok, prev: B32[2] },
      { ...ok, seq: 2147483648, prev: B32[2] },
      { ...ok, seq: 1.5, prev: B32[2] },
      { ...ok, seq: -1 },
      { ...ok, seq: -0 },
      { ...ok, session: BAD32[2] },
      { ...ok, root: BAD32[0] },
      { ...ok, seq: 2, prev: BAD32[4] },
      { ...ok, extra: 1 },
      { ...ok, prev: undefined },
      Object.assign(Object.create(null), ok),
      Object.assign(Object.create({ inherited: 1 }), ok),
      [ok],
    ];
    const verdicts = cases.map((cv) => {
      const a = prod.envelopeCaveatEvaluator(cv as any, ctx);
      expect(vm.envelopeCaveatEvaluator(cv, ctx)).toBe(a);
      expect(vm.agentNativeCaveatEvaluator(cv, ctx)).toBe(agentNativeCaveatEvaluator(cv as any, ctx));
      return a;
    });
    expect(verdicts).toEqual([true, true, true, false, false, false, false, false, false, false, false, false, false, true, true, false, false]);
    // negative zero: refused by both (and +0 accepted by both), in either evaluator
    expect(prod.envelopeCaveatEvaluator({ ...ok, seq: -0 } as any, ctx)).toBe(false);
    expect(vm.envelopeCaveatEvaluator({ ...ok, seq: -0 }, ctx)).toBe(false);
    expect(vm.agentNativeCaveatEvaluator({ ...ok, seq: -0 }, ctx)).toBe(false);
    expect(vm.envelopeCaveatEvaluator({ ...ok, seq: 0 }, ctx)).toBe(true);
    // -0 elsewhere still compares as 0 (eq / lte / expires), exactly like the TypeScript
    expect(vm.envelopeCaveatEvaluator({ type: 'delegation_depth', max: -0 }, { ...ctx, delegationDepth: 0 })).toBe(prod.envelopeCaveatEvaluator({ type: 'delegation_depth', max: -0 } as any, { ...ctx, delegationDepth: 0 } as any));
    // no clock: unsatisfied like every stock caveat
    expect(vm.envelopeCaveatEvaluator(ok, { action: ctx.action })).toBe(false);
    expect(prod.envelopeCaveatEvaluator(ok as any, { action: ctx.action } as any)).toBe(false);
  });
  it('random session caveats agree (envelope and agent-native evaluators)', () => {
    const r = new R(SEED * 31 + 13);
    let sat = 0;
    for (let i = 0; i < N * 3; i++) {
      const cv = { type: 'intent_session', ...sessionCaveat(r) };
      const a = prod.envelopeCaveatEvaluator(cv as any, ctx);
      const b = vm.envelopeCaveatEvaluator(cv, ctx);
      if (a !== b) throw new Error(`intent_session differs prod=${a} verified=${b} cv=${JSON.stringify(cv)}`);
      if (agentNativeCaveatEvaluator(cv as any, ctx) !== vm.agentNativeCaveatEvaluator(cv, ctx)) throw new Error(`agent differs cv=${JSON.stringify(cv)}`);
      if (a) sat++;
    }
    expect(sat).toBeGreaterThan(N / 2);
    expect(sat).toBeLessThan(N * 3);
  });
});

describe('PolicyVm differential: caveats', () => {
  it('envelopeCaveatEvaluator and agentNativeCaveatEvaluator agree on every single caveat', () => {
    const r = new R(SEED * 23 + 5);
    let t = 0;
    let f = 0;
    for (let i = 0; i < N * 3; i++) {
      const actx = context(r);
      const ps = paths(actx);
      const cv = caveat(r, actx, ps);
      const cx = cavContext(r, actx);
      const a = prod.envelopeCaveatEvaluator(cv, cx);
      const b = vm.envelopeCaveatEvaluator(cv, cx);
      if (a !== b) throw new Error(`envelope differs prod=${a} verified=${b}\ncv=${JSON.stringify(cv)}\ncx=${JSON.stringify(cx)}`);
      const a2 = agentNativeCaveatEvaluator(cv, cx);
      const b2 = vm.agentNativeCaveatEvaluator(cv, cx);
      if (a2 !== b2) throw new Error(`agent differs prod=${a2} verified=${b2}\ncv=${JSON.stringify(cv)}\ncx=${JSON.stringify(cx)}`);
      if (a) t++;
      else f++;
    }
    expect(t).toBeGreaterThan(N / 20);
    expect(f).toBeGreaterThan(N / 5);
  });

  it('evaluateCaveats lists agree (ok + failed names), both evaluators; not-an-array fails closed', () => {
    const r = new R(SEED * 29 + 6);
    for (let i = 0; i < N; i++) {
      const actx = context(r);
      const ps = paths(actx);
      const cs: any = r.b(0.97) ? Array.from({ length: r.i(6) }, () => caveat(r, actx, ps)) : r.p([null, 5, {}, 'x', undefined]);
      const cx = cavContext(r, actx);
      same(prod.evaluateCaveats(cs, cx), vm.evaluateCaveats(cs, cx), 'envelope list');
      same(prod.evaluateCaveats(cs, cx, agentNativeCaveatEvaluator), vm.evaluateCaveats(cs, cx, 'agent'), 'agent list');
    }
  });

  it('the conformance corpus: every caveat list in every vector (grant + chain hops) evaluates identically', () => {
    const { core, adversarial } = loadCorpus();
    let lists = 0;
    for (const v of [...core, ...adversarial]) {
      const sets: unknown[] = [v.grant?.caveats];
      const chain = v.pcactn?.cap_chain;
      if (Array.isArray(chain)) for (const h of chain) sets.push(h?.caveats);
      for (const cs of sets) {
        const cx = { now: v.context?.now };
        same(prod.evaluateCaveats(cs as any, cx as any), vm.evaluateCaveats(cs, cx), `corpus ${v.name}`);
        same(prod.evaluateCaveats(cs as any, cx as any, agentNativeCaveatEvaluator), vm.evaluateCaveats(cs, cx, 'agent'), `corpus agent ${v.name}`);
        lists++;
      }
    }
    expect(lists).toBeGreaterThan(4000);
  });
});

describe('PolicyVm differential: thresholds / admission / escalation kernels', () => {
  const TH: Array<[number, number]> = [[0.25, 0.6], [0, 0], [0.5, 0.5], [0, 1], [1, 1], [0.1, 0.9], [0.33, 0.66]];
  const RS = [0, 0.1, 0.25, 0.2500000000000001, 0.24999999999999997, 0.33, 0.5, 0.6, 0.6000000000000001, 0.99, 1, 1.5, -1, NaN, Infinity, -Infinity, 0.66];
  it('requiredThreshold x escalateThreshold x admit: exhaustive grid', () => {
    let n = 0;
    for (const [t1, t2] of TH)
      for (const r of RS)
        for (const irr of [false, true]) {
          const a = prodRequired(r, { theta1: t1, theta2: t2 }, { irreversible: irr });
          const b = requiredThresholdVerified(r, t1, t2, irr);
          expect(b).toEqual(a);
          for (const minT of [1, 2, 3] as const) {
            expect(escalateThresholdVerified(b, minT)).toEqual(prodEscalate(a, minT));
            n++;
          }
          for (const B of [0, 0.1, 0.25, 0.5, 1, NaN, 0.2500000000000001]) {
            for (const kappa of [1, 0.5, 2, 0, -1, NaN]) {
              const pol: any = { theta1: t1, theta2: t2, kappa };
              const pa = prodAdmit(r, { B, tau: 0 }, pol);
              const t = prodRequired(r, pol).t;
              const pb = admitVerified(t, B >= prodCost(r, kappa));
              expect(pb).toEqual(pa);
              n++;
            }
          }
        }
    expect(n).toBeGreaterThan(2000);
  });
  it('the exact-rational encoding of doubles round-trips', () => {
    const r = new R(SEED);
    for (const x of NUM_POOL.filter(Number.isFinite)) expect(Object.is(ratToDouble(toRat(x)) + 0, x + 0)).toBe(true);
    for (let i = 0; i < 5000; i++) {
      const x = (r.f() - 0.5) * 2 ** r.i(200) * (r.b(0.3) ? 1e-300 : 1);
      if (Number.isFinite(x)) expect(ratToDouble(toRat(x))).toBe(x);
    }
  });
});

describe('PolicyVm differential: decide() with the verified kernels', () => {
  function policy(r: R): any {
    const th1 = r.p([0.25, 0.1, 0, 0.5]);
    return {
      weights: { alpha: r.p([0.25, 0, 1]), beta: 0.2, gamma: r.p([0.2, 0, 3]), delta: 0.2, epsilon: 0.1, zeta: 0.05 },
      theta1: th1,
      theta2: r.p([th1, 0.6, 1, th1 + 0.1]),
      kappa: r.p([1, 0.5, 2, 0.1]),
      lambda: r.p([0.0005, 0, 1]),
      rho: 0.5,
      bMax: 1,
    };
  }
  function gen(r: R): DecideInput {
    const actx = context(r);
    const ps = paths(actx);
    const a = actx && typeof actx === 'object' ? actx : { action: { verb: 'GET', resource: '/acct/1' } };
    const preds = Array.from({ length: r.i(4) }, () => predicate(r, a, ps));
    if (r.b(0.5)) preds.push({ verb: '*', resource: '*' });
    const caveats = Array.from({ length: r.i(4) }, () => caveat(r, a, ps));
    if (r.b(0.5)) caveats.push({ type: 'expires', at: NOW + 1000 });
    const envCv: any = { type: 'envelope', goal_commit: 'g', predicates: preds, caveats, agent_binding: {}, risk_policy: policy(r) };
    if (r.b(0.01)) delete envCv.goal_commit;
    // 0.4.1: caveats on the root OUTSIDE the envelope (before and after it, incl. a second envelope) are evaluated like hop caveats
    const rootPre = r.b(0.15) ? [caveat(r, a, ps)] : [];
    const rootPost = Array.from({ length: r.b(0.4) ? 1 + r.i(2) : 0 }, () => (r.b(0.2) ? r.p([{ type: 'note' }, { ...envCv }]) : caveat(r, a, ps)));
    const grant: any = { id: 'x', issuer: 'i', holder: 'h', caveats: [...rootPre, envCv, ...rootPost], body_digest: '', sig: '' };
    const input: any = {
      grant,
      action: a,
      risk: r.b(0.9) ? Object.fromEntries(['semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age'].filter(() => r.b(0.7)).map((k) => [k, r.p([0, 0.1, 0.5, 1, 0.9, NaN, 2, -1])])) : {},
      budget: { B: r.p([0, 0.1, 0.5, 1, 0.01, NaN]), tau: NOW - r.p([0, 1000, 3600000, 7200000]), ...(r.b(0.3) ? { asOf: NOW - 5 } : {}) },
      now: r.b(0.97) ? NOW : r.p([NaN, Infinity]),
      chainVerified: true,
    };
    if (r.b(0.4)) input.rFloor = r.p([0, 0.3, 0.9, 1, 2, -1, NaN, 'x']);
    if (r.b(0.2)) input.ageHorizonMs = r.p([0, 1000, 3600000, -5, NaN]);
    if (r.b(0.3)) input.caveatContext = { delegationDepth: r.p([0, 1, 5]), recentActionTimes: [NOW - 10, NOW - 20], ...(r.b(0.3) ? { reversibilityClass: r.p(['irreversible', 'reversible']) } : {}) };
    if (r.b(0.3)) {
      const n = 1 + r.i(3);
      const hop = (k: number) => ({ ...grant, caveats: [...grant.caveats, ...Array.from({ length: k }, () => caveat(r, a, ps))] });
      input.chain = r.b(0.95) ? Array.from({ length: n }, (_, i) => hop(i)) : r.p([[], 5, 'x']);
    }
    if (r.b(0.25)) input.plan = [{ id: 'n1', verb: 'GET', resource: '/acct/1', reversibility_class: r.p(['reversible', 'irreversible', 'costly']) }, { id: 'n2', verb: 'POST', resource: '/x' }];
    return input as DecideInput;
  }
  it('decide() === decideVerified() on random inputs (release, threshold, admit, step-up, reasons, budget)', () => {
    const r = new R(SEED * 31 + 7);
    const kinds = { release: 0, admit: 0, stepUp: 0, denied: 0 };
    for (let i = 0; i < N; i++) {
      const input = gen(r);
      const a = decide(input);
      const b = decideVerified(input, vm);
      if (plainJson(a) !== plainJson(b)) throw new Error(`decide differs\nprod=${JSON.stringify(a)}\nverified=${JSON.stringify(b)}\ninput=${JSON.stringify(input)}`);
      if (a.releaseGuardianShare) kinds.release++;
      else kinds.denied++;
      if (a.admit) kinds.admit++;
      if (a.needStepUp) kinds.stepUp++;
    }
    expect(kinds.release).toBeGreaterThan(N / 50);
    expect(kinds.denied).toBeGreaterThan(N / 50);
    expect(kinds.admit).toBeGreaterThan(0);
    expect(kinds.stepUp).toBeGreaterThan(N / 50);
  });
  it('decideCoreVerified truth table (release iff all four hold; no release => step-up, no admit, no debit)', () => {
    for (let m = 0; m < 16; m++) {
      const [p, c, d, ch] = [!!(m & 1), !!(m & 2), !!(m & 4), !!(m & 8)];
      for (const t of [1, 2, 3] as const)
        for (const cover of [true, false]) {
          const adm = admitVerified(t, cover);
          const rt = requiredThresholdVerified(t === 1 ? 0.1 : t === 2 ? 0.4 : 0.9, 0.25, 0.6, false);
          const o = decideCoreVerified(p, c, d, ch, rt, adm);
          expect(o.release).toBe(p && c && d && ch);
          if (!o.release) {
            expect(o.admit).toBe(false);
            expect(o.needStepUp).toBe(true);
            expect(o.debit).toBe(false);
          }
        }
    }
  });
});


describe('PolicyVm differential: exotic JS values', () => {
  class Box {
    type = 'Box::1';
    constructor(public v: unknown) {}
  }
  it('non-plain objects, functions, bigint, symbols, undefined members behave identically', () => {
    const exotic: unknown[] = [new Date(0), new Map([[1, 2]]), new Box(1), () => 1, 10n, Symbol('s'), undefined, [undefined, 1], { u: undefined, n: 1 }, Object.create(null), new Set([1]), /re/, new Error('e'), Object.assign(Object.create({ inherited: 1 }), { own: 2 })];
    let n = 0;
    for (const e of exotic) {
      for (const fieldVal of exotic) {
        const ctx: any = { action: { verb: 'GET', resource: '/a', params: { f: fieldVal, o: e } }, env: { m: e, groups: e } };
        for (const op of OPS) {
          for (const mode of ['value', 'ref']) {
            const c: any = { field: 'action.params.f', op };
            if (mode === 'value') c.value = e;
            else c.ref = 'action.params.o';
            if (op === 'member_of') c.collection = 'env.groups';
            const a = prod.evaluateConditionTri(c, ctx);
            let b: string;
            try {
              b = vm.evaluateConditionTri(c, ctx);
            } catch (err: any) {
              if (err?.name === 'PolicyVmUnsupported') continue;
              throw err;
            }
            if (a !== b) throw new Error(`exotic differs op=${op} mode=${mode} prod=${a} verified=${b}`);
            n++;
          }
        }
      }
    }
    expect(n).toBeGreaterThan(1000);
  });
});

describe('production findings (PoC) - FIXED in production', () => {
  it('F1 (fixed): deepEq is key-order insensitive also for object keys containing different lone surrogates (compareUtf8 tie-break by code unit)', () => {
    const mk = (pairs: Array<[string, number]>): any => {
      const o: any = {};
      for (const [k, v] of pairs) setProp(o, k, v);
      return o;
    };
    const a = mk([['\ud800', 1], ['\ud801', 2]]);
    const b = mk([['\ud801', 2], ['\ud800', 1]]);
    const ctx = { action: { params: { v: a } } };
    const c = { field: 'action.params.v', op: 'eq', value: b };
    expect(prod.evaluateConditionTri(c as any, ctx as any)).toBe('true');
    expect(vm.evaluateConditionTri(c, ctx)).toBe('true'); // proved: CmpStr tie-break + DeepEqObjPerm
    const a2 = mk([['x', 1], ['y', 2]]);
    const b2 = mk([['y', 2], ['x', 1]]);
    expect(prod.evaluateConditionTri({ field: 'action.params.v', op: 'eq', value: b2 } as any, { action: { params: { v: a2 } } } as any)).toBe('true');
  });
  it('nested key-order insensitivity (PolicyVm.DeepEqDeepPerm): lone-surrogate / U+FFFD / astral keys permuted at EVERY level of a depth-4 value', () => {
    const KEYS = ['\ud800', '\ud801', '\udc00', '\ufffd', 'a', '\u{10000}', 'k\ud800', 'k\ud801'];
    let seed = 12345;
    const rnd = (n: number) => { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return seed % n; };
    const shuffle = <T,>(xs: T[]): T[] => { const a = xs.slice(); for (let i = a.length - 1; i > 0; i--) { const j = rnd(i + 1); [a[i], a[j]] = [a[j]!, a[i]!]; } return a; };
    // a value tree as ordered [key, child] lists; build() materialises it with a given (per-level) key order
    type T = { leaf: unknown } | { arr: T[] } | { obj: Array<[string, T]> };
    const gen = (d: number): T => {
      if (d === 0) return { leaf: rnd(3) === 0 ? KEYS[rnd(KEYS.length)] : rnd(4) };
      if (rnd(4) === 0) return { arr: Array.from({ length: 1 + rnd(2) }, () => gen(d - 1)) };
      const ks = shuffle(KEYS).slice(0, 2 + rnd(4));
      return { obj: ks.map((k) => [k, gen(d - 1)] as [string, T]) };
    };
    const build = (t: T, permute: boolean): unknown => {
      if ('leaf' in t) return t.leaf;
      if ('arr' in t) return t.arr.map((c) => build(c, permute));
      const o: any = {};
      for (const [k, c] of permute ? shuffle(t.obj) : t.obj) setProp(o, k, build(c, permute));
      return o;
    };
    let eqs = 0;
    for (let n = 0; n < 60; n++) {
      const t = gen(4);
      const a = build(t, false);
      const b = build(t, true); // same map at every depth, entries permuted at every level
      const ctx = { action: { params: { v: a } } };
      for (const op of ['eq', 'ne', 'in', 'nin'] as const) {
        const c = { field: 'action.params.v', op, value: op === 'in' || op === 'nin' ? [0, b] : b };
        const want = op === 'eq' || op === 'in' ? 'true' : 'false';
        expect(prod.evaluateConditionTri(c as any, ctx as any)).toBe(want);
        expect(vm.evaluateConditionTri(c, ctx)).toBe(want);
      }
      // and a value that differs in one deep leaf is NOT equal in either
      const t2 = JSON.parse(JSON.stringify(t)) as T;
      let cur: any = t2;
      while (!('leaf' in cur)) cur = 'arr' in cur ? cur.arr[0] : cur.obj[0][1];
      cur.leaf = 'different-leaf';
      const c2 = { field: 'action.params.v', op: 'eq', value: build(t2, true) };
      expect(prod.evaluateConditionTri(c2 as any, ctx as any)).toBe(vm.evaluateConditionTri(c2, ctx));
      if (prod.evaluateConditionTri(c2 as any, ctx as any) === 'false') eqs++;
    }
    expect(eqs).toBeGreaterThan(40);
  });
  it('F2 (fixed): reversibility_max type-checks `class`: an array is no longer coerced with String()', () => {
    const cx = { now: 1, reversibilityClass: 'irreversible' };
    expect(prod.envelopeCaveatEvaluator({ type: 'reversibility_max', class: 'irreversible' } as any, cx)).toBe(true);
    expect(prod.envelopeCaveatEvaluator({ type: 'reversibility_max', class: ['irreversible'] } as any, cx)).toBe(false);
    expect(vm.envelopeCaveatEvaluator({ type: 'reversibility_max', class: ['irreversible'] }, cx)).toBe(false);
    expect(prod.envelopeCaveatEvaluator({ type: 'reversibility_max', class: ['irreversible', 'x'] } as any, cx)).toBe(false);
  });
});
