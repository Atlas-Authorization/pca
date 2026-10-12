import { describe, expect, it } from 'vitest';
import type { Condition, Predicate } from '@atlasauth/pca';
import {
  DEFAULT_MAX_COMBINATIONS,
  admits,
  admitsAction,
  collectProbes,
  normalizePolicy,
  productSize,
  repToAction,
  representatives,
  search,
  toModel,
  type Probes,
  type Rep,
} from './enumerate';
import { FRESH_STRING } from './field';

const FV = '\u0000atlas-analyzer::fresh-verb\u0000';
const FR = '\u0000atlas-analyzer::fresh-resource\u0000';
const cond = (field: string, op: string, value?: unknown, extra: object = {}) => ({ field, op, value, ...extra }) as unknown as Condition;
const pred = (verb: string | string[], resource: string | undefined, where?: Condition[]) => ({ verb, resource, ...(where ? { where } : {}) }) as unknown as Predicate;

describe('normalizePolicy / toModel', () => {
  it('shapes', () => {
    expect(DEFAULT_MAX_COMBINATIONS).toBe(200_000);
    expect(normalizePolicy({ predicates: 'x' as never })).toEqual({ predicates: [], caveats: [] });
    expect(normalizePolicy({ predicates: [], caveats: 'x' as never })).toEqual({ predicates: [], caveats: [] });
    const p = [pred('a', '*')];
    const cv = [{ type: 'expires', at: 1 }] as never;
    const n = normalizePolicy({ predicates: p, caveats: cv });
    expect(n.predicates).toBe(p);
    expect(n.caveats).toBe(cv);
    expect(normalizePolicy({ predicates: p }).caveats).toEqual([]);
  });
  it('toModel carries caveat analysis', () => {
    const m = toModel({ predicates: [pred('a', '*')], caveats: [{ type: 'reversibility_max', class: 'rate_limited' }] as never });
    expect(m.caveatSat).toBe(true);
    expect(m.revCap).toBe(1);
    expect(m.caveatReason).toBeUndefined();
    expect(m.undecidable).toEqual([]);
    const bad = toModel({ predicates: [], caveats: [{ type: 'zzz' }] as never });
    expect(bad.caveatSat).toBe(false);
    expect(bad.caveatReason).toBe("unknown caveat type 'zzz' (fail closed)");
  });
});

describe('undecidable detection', () => {
  const und = (predicates: Predicate[]) => toModel({ predicates }).undecidable;
  it('regex resource', () => {
    expect(und([pred('a', 're:x+')])).toEqual(['re: regex resource matcher — resource dimension cannot be soundly enumerated']);
    expect(und([pred('a', 'r')])).toEqual([]);
    expect(und([pred('a', undefined)])).toEqual([]);
  });
  it('leaf reasons', () => {
    expect(und([pred('a', '*', [cond('action.params.x', 'eq', 1, { ref: 'env.y' })])])).toEqual([
      'cross-field `ref` condition — the relation between two fields is not resolved',
    ]);
    expect(und([pred('a', '*', [cond('action.params', 'exists')])])).toEqual([
      'condition on the whole `action.params` object is not enumerated precisely',
    ]);
    for (const op of ['like', 'matches', 'is_a', 'member_of']) {
      expect(und([pred('a', '*', [cond('action.params.x', op, 's')])])).toEqual([
        `\`${op}\` condition — matched by over-approximation, not enumerated exactly`,
      ]);
    }
    expect(und([pred('a', '*', [cond('action.params.x', 'eq', 's')])])).toEqual([]);
    expect(und([pred('a', '*', [cond('action.params.x', 'prefix', 's')])])).toEqual([]);
  });
  it('groups recurse (all_of, any_of, not) and dedupe', () => {
    const l = cond('action.params.x', 'like', 's');
    const msg = ['`like` condition — matched by over-approximation, not enumerated exactly'];
    expect(und([pred('a', '*', [{ all_of: [l, l] } as never])])).toEqual(msg);
    expect(und([pred('a', '*', [{ any_of: [l] } as never])])).toEqual(msg);
    expect(und([pred('a', '*', [{ not: l } as never])])).toEqual(msg);
    expect(und([pred('a', '*', [{ not: { not: l } } as never])])).toEqual(msg);
    // non-array groups: ignored (no throw)
    expect(und([pred('a', '*', [{ all_of: 'x' } as never])])).toEqual([]);
    expect(und([pred('a', '*', [{ any_of: 'x' } as never])])).toEqual([]);
    // all_of present but not an array falls through to any_of
    expect(und([pred('a', '*', [{ all_of: 'x', any_of: [l] } as never])])).toEqual(msg);
    // all_of array wins over any_of
    expect(und([pred('a', '*', [{ all_of: [cond('f', 'eq', 1)], any_of: [l] } as never])])).toEqual([]);
    // any_of present but not an array falls through to not
    expect(und([pred('a', '*', [{ any_of: 'x', not: l } as never])])).toEqual(msg);
    // any_of beats not
    expect(und([pred('a', '*', [{ any_of: [cond('f', 'eq', 1)], not: l } as never])])).toEqual([]);
  });
  it('junk is tolerated', () => {
    expect(und([null as never, 'x' as never, pred('a', '*', [null as never, 5 as never, {} as never])])).toEqual([]);
    expect(und([{ verb: 'a', where: 'zzz' } as never])).toEqual([]);
  });
  it('multiple reasons keep insertion order', () => {
    const r = und([
      pred('a', 're:x', [cond('action.params.x', 'like', 's'), cond('action.params', 'eq', 1, { ref: 'env.q' })]),
    ]);
    expect(r[0]).toBe('re: regex resource matcher — resource dimension cannot be soundly enumerated');
    expect(r[1]).toBe('`like` condition — matched by over-approximation, not enumerated exactly');
    expect(r).toHaveLength(4);
  });
});

describe('collectProbes exact', () => {
  const cp = (predicateSets: Predicate[][], extra: object = {}) => collectProbes({ predicateSets, varyReversibility: false, ...extra });
  it('verbs: strings, arrays, wildcard, extras', () => {
    expect(cp([[pred('a.b', '*'), pred(['c', '*', 5 as never, 'd'], '*'), pred('*', '*')]]).verbs).toEqual(['a.b', 'c', 'd', FV]);
    expect(cp([[pred('a', '*')]], { extraVerbs: ['z'] }).verbs).toEqual(['z', 'a', FV]);
    expect(cp([[pred(5 as never, '*')]]).verbs).toEqual([FV]);
  });
  it('resources: exact, prefix, regex, wildcard, undefined', () => {
    expect(cp([[pred('a', '/x/*'), pred('a', '/y'), pred('a', 're:q'), pred('a', '*'), pred('a', undefined)]]).resources).toEqual([
      '/x/',
      '/x/x',
      '/y',
      FR,
    ]);
    expect(cp([[]], { extraResources: ['r*', 'plain', '*', 're:z'] }).resources).toEqual(['r', 'rx', 'plain', FR]);
  });
  it('verb/resource conditions feed literals, not fields', () => {
    const pr = cp([
      [
        pred('*', '*', [
          cond('action.verb', 'eq', 'v1'),
          cond('action.verb', 'ne', 'v2'),
          cond('action.verb', 'prefix', 'v3'),
          cond('action.verb', 'like', 'v4'),
          cond('action.verb', 'is_a', 'v5'),
          cond('action.verb', 'in', ['v6', 7, 'v7']),
          cond('action.verb', 'nin', ['v8']),
          cond('action.verb', 'matches', 'v9'),
          cond('action.verb', 'eq', 5),
          cond('action.verb', 'in', 'notarray'),
          cond('action.resource', 'eq', '/r1'),
          cond('action.resource', 'prefix', '/p/'),
          cond('action.resource', 'in', ['/r2', 4, '/r3*']),
          cond('action.resource', 'eq', 5),
        ]),
      ],
    ]);
    expect(pr.verbs).toEqual(['v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', FV]);
    expect(pr.resources).toEqual(['/r1', '/p/', '/p/x', '/r2', '/r3', '/r3x', FR]);
    expect(pr.fields).toEqual([]);
  });
  it('field conds bucketed per path, groups flattened, junk skipped', () => {
    const pr = cp([
      [
        pred('a', '*', [
          cond('action.params.n', 'gte', 1),
          { all_of: [cond('action.params.n', 'lte', 3), { any_of: [cond('subject.role', 'eq', 'admin')] }] } as never,
          { not: cond('env.zone', 'eq', 'eu') } as never,
          null as never,
          7 as never,
          {} as never,
          { all_of: 'x' } as never,
        ]),
      ],
      [null as never, pred('b', '*', [cond('action.params.n', 'eq', 2)])],
    ]);
    expect(pr.fields.map((f) => f.path)).toEqual(['action.params.n', 'subject.role', 'env.zone']);
    expect(pr.fields[0]?.values.slice(0, -1)).toEqual([2, 0, 1, 1.5, 2.5, 3, 4, FRESH_STRING]);
    expect(pr.fields[0]?.values).toHaveLength(9);
    expect(pr.fields[1]?.values).toEqual(['admin', FRESH_STRING, expect.anything()]);
    expect(typeof (pr.fields[1]?.values[2])).toBe('symbol');
    expect(pr.fields[2]?.values.slice(0, 2)).toEqual(['eu', FRESH_STRING]);
  });
  it('extraFieldConditions get their path stamped', () => {
    const pr = cp([[]], {
      extraFieldConditions: [
        { path: 'action.params.amount', cond: { field: 'ignored', op: 'lte', value: 10 } },
        { path: 'action.params.amount', cond: { field: 'ignored', op: 'gte', value: 0 } },
      ],
    });
    expect(pr.fields).toHaveLength(1);
    expect(pr.fields[0]?.path).toBe('action.params.amount');
    expect(pr.fields[0]?.values.slice(0, -1)).toEqual([-1, 0, 5, 10, 11, FRESH_STRING]);
  });
  it('revClasses', () => {
    expect(cp([[]]).revClasses).toEqual([undefined]);
    expect(collectProbes({ predicateSets: [], varyReversibility: true }).revClasses).toEqual(['reversible', 'rate_limited', 'irreversible']);
  });
});

describe('productSize / representatives / search', () => {
  const A = Symbol('a');
  void A;
  const pr = (verbs: string[], resources: string[], revClasses: (string | undefined)[], fields: { path: string; values: unknown[] }[]): Probes => ({
    verbs,
    resources,
    revClasses,
    fields,
  });
  it('productSize multiplies all', () => {
    expect(productSize(pr(['a', 'b'], ['x', 'y', 'z'], [undefined], []))).toBe(6);
    expect(productSize(pr(['a'], ['x'], ['r', 's', 't'], [{ path: 'p', values: [1, 2] }, { path: 'q', values: [1, 2, 3, 4, 5] }]))).toBe(30);
    expect(productSize(pr(['a', 'b'], ['x'], ['r', 's'], [{ path: 'p', values: [1, 2, 3] }]))).toBe(12);
  });
  it('representatives order: verb > resource > rev > fields (last field fastest)', () => {
    const out = [...representatives(pr(['v1', 'v2'], ['r1', 'r2'], [undefined, 'reversible'], [{ path: 'a', values: [1, 2] }, { path: 'b', values: ['x', 'y'] }]))];
    expect(out).toHaveLength(32);
    expect(out[0]).toEqual({ verb: 'v1', resource: 'r1', revClass: undefined, assignments: new Map<string, unknown>([['a', 1], ['b', 'x']]) });
    expect(out[1]?.assignments).toEqual(new Map<string, unknown>([['a', 1], ['b', 'y']]));
    expect(out[2]?.assignments).toEqual(new Map<string, unknown>([['a', 2], ['b', 'x']]));
    expect(out[4]?.revClass).toBe('reversible');
    expect(out[8]?.resource).toBe('r2');
    expect(out[16]?.verb).toBe('v2');
  });
  it('absent value removes the assignment; no stale leakage', () => {
    // ABSENT symbol is only obtainable via collectProbes
    const probes = collectProbes({ predicateSets: [[pred('a', '*', [cond('action.params.n', 'eq', 1)])]], varyReversibility: false });
    const reps = [...representatives({ ...probes, verbs: ['a'], resources: ['r'] })];
    const maps = reps.map((r) => [...r.assignments.entries()]);
    expect(maps[0]).toEqual([['action.params.n', 1]]);
    expect(maps[maps.length - 1]).toEqual([]);
    expect(reps.every((r) => r.assignments instanceof Map)).toBe(true);
    // yielded maps are snapshots
    expect(reps[0]?.assignments.get('action.params.n')).toBe(1);
  });
  it('no fields yields one rep per combination with empty assignments', () => {
    const out = [...representatives(pr(['a'], ['b'], [undefined], []))];
    expect(out).toEqual([{ verb: 'a', resource: 'b', revClass: undefined, assignments: new Map() }]);
  });
  it('empty field list values yields nothing', () => {
    expect([...representatives(pr(['a'], ['b'], [undefined], [{ path: 'p', values: [] }]))]).toEqual([]);
  });
  it('search: hit, no hit, overflow boundary', () => {
    const p = pr(['a', 'b', 'c'], ['r'], [undefined], []);
    expect(search(p, (r) => r.verb === 'b', 3)).toEqual({ hit: expect.objectContaining({ verb: 'b' }), overflow: false });
    expect(search(p, () => false, 3)).toEqual({ overflow: false });
    expect(search(p, () => true, 2)).toEqual({ overflow: true });
    let calls = 0;
    search(p, () => { calls++; return false; }, 3);
    expect(calls).toBe(3);
  });
});

describe('admits / admitsAction / repToAction', () => {
  const rep = (verb: string, resource: string, revClass: string | undefined, a: [string, unknown][] = []): Rep => ({ verb, resource, revClass, assignments: new Map(a) });
  const m = (predicates: Predicate[], caveats: unknown[] = []) => toModel({ predicates, caveats: caveats as never });

  it('caveat gate and reversibility', () => {
    const P = [pred('a', '*')];
    expect(admits(m(P), rep('a', 'r', undefined))).toBe(true);
    expect(admits(m(P, [{ type: 'zzz' }]), rep('a', 'r', undefined))).toBe(false);
    const cap = m(P, [{ type: 'reversibility_max', class: 'rate_limited' }]);
    expect(admits(cap, rep('a', 'r', undefined))).toBe(false);
    expect(admits(cap, rep('a', 'r', 'reversible'))).toBe(true);
    expect(admits(cap, rep('a', 'r', 'rate_limited'))).toBe(true);
    expect(admits(cap, rep('a', 'r', 'irreversible'))).toBe(false);
    expect(admits(cap, rep('a', 'r', 'bogus'))).toBe(false);
    const cap0 = m(P, [{ type: 'reversibility_max', class: 'reversible' }]);
    expect(admits(cap0, rep('a', 'r', 'reversible'))).toBe(true);
    expect(admits(cap0, rep('a', 'r', 'rate_limited'))).toBe(false);
  });
  it('contexts: params/subject/env/action extras reach the evaluator', () => {
    const mm = m([
      pred('a', '*', [
        cond('action.params.n', 'eq', 5),
        cond('subject.role', 'eq', 'admin'),
        cond('env.zone.name', 'eq', 'eu'),
        cond('action.extra', 'eq', 'e'),
        cond('action.deep.k', 'eq', 'd'),
        cond('action.reversibility_class', 'eq', 'reversible'),
      ]),
    ]);
    const all: [string, unknown][] = [
      ['action.params.n', 5],
      ['subject.role', 'admin'],
      ['env.zone.name', 'eu'],
      ['action.extra', 'e'],
      ['action.deep.k', 'd'],
    ];
    expect(admits(mm, rep('a', 'r', 'reversible', all))).toBe(true);
    for (let i = 0; i < all.length; i++) {
      expect(admits(mm, rep('a', 'r', 'reversible', all.filter((_, j) => j !== i)))).toBe(false);
    }
    expect(admits(mm, rep('a', 'r', undefined, all))).toBe(false);
  });
  it('verb and resource fixed from rep, assignments to them are ignored', () => {
    const mm = m([pred('a', 'r')]);
    expect(admits(mm, rep('a', 'r', undefined, [['action.verb', 'zzz'], ['action.resource', 'zzz']]))).toBe(true);
    expect(admits(mm, rep('b', 'r', undefined, [['action.verb', 'a']]))).toBe(false);
  });
  it('unaddressable roots / short paths ignored; whole params leaf leaves params empty', () => {
    const mm = m([pred('a', '*', [cond('action.params.n', 'exists', true)])]);
    expect(admits(mm, rep('a', 'r', undefined, [['action.params', 5]]))).toBe(false);
    expect(admits(mm, rep('a', 'r', undefined, [['action', 5], ['other.params.n', 1], ['x', 1]]))).toBe(false);
    expect(admits(mm, rep('a', 'r', undefined, [['action.params.n', 1]]))).toBe(true);
  });
  it('insert: a leaf later overwritten by a branch and vice versa', () => {
    const mm = m([pred('a', '*', [cond('action.params.a.b', 'eq', 1)])]);
    expect(admits(mm, rep('a', 'r', undefined, [['action.params.a.b', 1]]))).toBe(true);
    // a leaf at params.a, then a deeper path replaces it with a branch
    expect(admits(mm, rep('a', 'r', undefined, [['action.params.a', 9], ['action.params.a.b', 1]]))).toBe(true);
    // a branch at params.a.b? then leaf at params.a overwrites it
    expect(admits(mm, rep('a', 'r', undefined, [['action.params.a.b', 1], ['action.params.a', 9]]))).toBe(false);
  });
  it('subject/env empty roots default to empty objects', () => {
    const mm = m([pred('a', '*', [cond('subject.x', 'exists', false), cond('env.y', 'exists', false)])]);
    expect(admits(mm, rep('a', 'r', undefined))).toBe(true);
  });

  it('repToAction', () => {
    expect(repToAction(rep('v', 'r', undefined))).toEqual({ verb: 'v', resource: 'r', params: {} });
    const a = repToAction(rep('v', 'r', 'rate_limited', [['action.params.n', 3], ['subject.s', 1], ['env.e.f', 2], ['action.extra', 1]]));
    expect(a).toEqual({ verb: 'v', resource: 'r', params: { n: 3 }, reversibilityClass: 'rate_limited', subject: { s: 1 }, env: { e: { f: 2 } } });
    expect(Object.keys(repToAction(rep('v', 'r', undefined, [['subject.s', 1]])))).toEqual(['verb', 'resource', 'params', 'subject']);
    expect('subject' in repToAction(rep('v', 'r', undefined, [['env.e', 1]]))).toBe(false);
    expect('env' in repToAction(rep('v', 'r', undefined, [['subject.e', 1]]))).toBe(false);
  });

  it('admitsAction', () => {
    const mm = m([pred('a', '*', [cond('action.params.n', 'gt', 1), cond('subject.s', 'eq', 1), cond('env.e', 'eq', 2)])]);
    expect(admitsAction(mm, { verb: 'a', resource: 'r', params: { n: 2 }, subject: { s: 1 }, env: { e: 2 } })).toBe(true);
    expect(admitsAction(mm, { verb: 'a', resource: 'r', params: { n: 1 }, subject: { s: 1 }, env: { e: 2 } })).toBe(false);
    expect(admitsAction(mm, { verb: 'a', resource: 'r', params: { n: 2 }, env: { e: 2 } })).toBe(false);
    expect(admitsAction(mm, { verb: 'a', resource: 'r', params: { n: 2 }, subject: { s: 1 } })).toBe(false);
    expect(admitsAction(mm, { verb: 'a', resource: 'r', subject: { s: 1 }, env: { e: 2 } })).toBe(false);
    expect(admitsAction(m([pred('a', '*')]), { verb: 'a', resource: 'r' })).toBe(true);
    expect(admitsAction(m([pred('a', '*')], [{ type: 'zzz' }]), { verb: 'a', resource: 'r' })).toBe(false);
    const cap = m([pred('a', '*', [cond('action.reversibility_class', 'eq', 'reversible')])], [{ type: 'reversibility_max', class: 'rate_limited' }]);
    expect(admitsAction(cap, { verb: 'a', resource: 'r' })).toBe(false);
    expect(admitsAction(cap, { verb: 'a', resource: 'r', reversibilityClass: 'reversible' })).toBe(true);
    expect(admitsAction(cap, { verb: 'a', resource: 'r', reversibilityClass: 'irreversible' })).toBe(false);
    // class reaches the evaluator even without a cap
    const nocap = m([pred('a', '*', [cond('action.reversibility_class', 'eq', 'irreversible')])]);
    expect(admitsAction(nocap, { verb: 'a', resource: 'r', reversibilityClass: 'irreversible' })).toBe(true);
    expect(admitsAction(nocap, { verb: 'a', resource: 'r' })).toBe(false);
    // input not mutated / aliased
    const params = { n: 2 };
    admitsAction(mm, { verb: 'a', resource: 'r', params, subject: { s: 1 }, env: { e: 2 } });
    expect(params).toEqual({ n: 2 });
  });
});
