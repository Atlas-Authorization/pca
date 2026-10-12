import { describe, expect, it } from 'vitest';
import type { Caveat, Condition, Predicate } from '@atlasauth/pca';
import { analyzeCaveats } from './caveats';
import { admits, collectProbes, productSize, representatives, toModel, type Rep } from './enumerate';
import { fieldProbes } from './field';
import { admitsConcrete, alwaysAllows, alwaysDenies, intentConformance, reachable } from './index';

const cond = (field: string, op: string, value?: unknown, extra: object = {}) => ({ field, op, value, ...extra }) as unknown as Condition;
const pred = (verb: string | string[], resource: string | undefined, where?: Condition[]) => ({ verb, resource, ...(where ? { where } : {}) }) as unknown as Predicate;
const pol = (predicates: Predicate[], caveats: unknown[] = []) => ({ predicates, caveats: caveats as never });
const LIKE = cond('action.params.s', 'like', 'x');
const REF = cond('action.params.n', 'eq', 1, { ref: 'env.y' });
const LIKE_MSG = '`like` condition — matched by over-approximation, not enumerated exactly';
const REF_MSG = 'cross-field `ref` condition — the relation between two fields is not resolved';
const rep = (verb: string, resource: string, revClass: string | undefined, a: [string, unknown][] = []): Rep => ({ verb, resource, revClass, assignments: new Map(a) });

describe('caveats: function-typed caveat objects are malformed', () => {
  it('rejects a callable carrying a valid type', () => {
    const fn = Object.assign(() => 0, { type: 'expires', at: 1 });
    expect(analyzeCaveats([fn as unknown as Caveat])).toEqual({ sat: false, reason: 'malformed caveat (not an object with a string type)' });
  });
});

describe('fieldProbes: unserializable values keep distinct identities per type', () => {
  it('bigint and circular object both survive', () => {
    const circ: Record<string, unknown> = {};
    circ['self'] = circ;
    const L = (v: unknown) => cond('x', 'eq', v);
    const out = fieldProbes([L(10n), L(circ), L(11n)]);
    expect(out.slice(0, 2)).toEqual([10n, circ]);
    expect(out).toHaveLength(3);
  });
});

describe('enumerate: structural guards', () => {
  const und = (predicates: Predicate[]) => toModel({ predicates }).undecidable;
  it('a non-group, non-leaf object still contributes nothing', () => {
    expect(und([pred('a', '*', [{ field: 5, op: 'like', ref: 'x' } as unknown as Condition])])).toEqual([]);
    expect(und([pred('a', '*', [{ op: 'like', value: 's' } as unknown as Condition])])).toEqual([]);
  });
  it('callable predicates are ignored', () => {
    const fnPred = Object.assign(() => 0, { verb: 'zz', resource: 're:x', where: [cond('f', 'like', 's')] }) as unknown as Predicate;
    expect(und([fnPred])).toEqual([]);
    const pr = collectProbes({ predicateSets: [[fnPred]], varyReversibility: false });
    expect(pr.verbs).toEqual(['\u0000atlas-analyzer::fresh-verb\u0000']);
    expect(pr.fields).toEqual([]);
  });
  it('group conditions with non-array members are ignored without throwing', () => {
    expect(und([pred('a', '*', [{ all_of: 5 } as unknown as Condition])])).toEqual([]);
    expect(und([pred('a', '*', [{ any_of: 5 } as unknown as Condition])])).toEqual([]);
    expect(und([pred('a', '*', [{ all_of: {} } as unknown as Condition])])).toEqual([]);
    const pr = collectProbes({
      predicateSets: [[pred('a', '*', [{ all_of: 5 } as unknown as Condition, { any_of: 5 } as unknown as Condition, { all_of: { length: 1, 0: cond('q.r', 'eq', 1) } } as unknown as Condition])]],
      varyReversibility: false,
    });
    expect(pr.fields).toEqual([]);
  });
  it('verb conditions only read literals from the string-valued ops', () => {
    for (const op of ['gt', 'gte', 'lt', 'lte', 'matches', 'member_of', 'exists']) {
      const pr = collectProbes({ predicateSets: [[pred('*', '*', [cond('action.verb', op, ['x', 'y'])])]], varyReversibility: false });
      expect(pr.verbs).toEqual(['\u0000atlas-analyzer::fresh-verb\u0000']);
    }
    const ok = collectProbes({ predicateSets: [[pred('*', '*', [cond('action.verb', 'nin', ['x'])])]], varyReversibility: false });
    expect(ok.verbs[0]).toBe('x');
    const notArr = collectProbes({ predicateSets: [[pred('*', '*', [cond('action.verb', 'in', 'x')])]], varyReversibility: false });
    expect(notArr.verbs).toHaveLength(1);
  });
  it('resource prefix with a non-string value adds nothing', () => {
    const pr = collectProbes({ predicateSets: [[pred('*', '*', [cond('action.resource', 'prefix', 5)])]], varyReversibility: false });
    expect(pr.resources).toEqual(['\u0000atlas-analyzer::fresh-resource\u0000']);
    const arr = collectProbes({ predicateSets: [[pred('*', '*', [cond('action.resource', 'prefix', ['a'])])]], varyReversibility: false });
    expect(arr.resources).toEqual(['a', '\u0000atlas-analyzer::fresh-resource\u0000']);
  });
  it('a whole-params leaf assignment does not replace the params object', () => {
    const m = toModel({ predicates: [pred('a', '*', [cond('action.params', 'eq', 5)])] });
    expect(admits(m, rep('a', 'r', undefined, [['action.params', 5]]))).toBe(false);
    const m2 = toModel({ predicates: [pred('a', '*', [cond('action.params.n', 'eq', 5)])] });
    expect(admits(m2, rep('a', 'r', undefined, [['action.params', 5], ['action.params.n', 5]]))).toBe(true);
  });
  it('a whole-params leaf assignment leaves an evaluable (empty) params object', () => {
    const m = toModel({ predicates: [pred('a', '*', [{ not: cond('action.params', 'eq', 5) } as unknown as Condition])] });
    expect(admits(m, rep('a', 'r', undefined, [['action.params', 5]]))).toBe(true);
    expect(admits(m, rep('a', 'r', undefined))).toBe(true);
  });
  it('an absent reversibility class stays absent from the evaluated action', () => {
    const present = toModel({ predicates: [pred('a', '*', [cond('action.reversibility_class', 'exists', true)])] });
    const absent = toModel({ predicates: [pred('a', '*', [cond('action.reversibility_class', 'exists', false)])] });
    expect(admits(present, rep('a', 'r', undefined))).toBe(false);
    expect(admits(present, rep('a', 'r', 'reversible'))).toBe(true);
    expect(admits(absent, rep('a', 'r', undefined))).toBe(true);
    expect(admits(absent, rep('a', 'r', 'reversible'))).toBe(false);
  });
  it('representatives never leak a stale assignment between siblings', () => {
    const probes = collectProbes({
      predicateSets: [[pred('a', '*', [cond('action.params.n', 'eq', 1), cond('action.params.m', 'eq', 2)])]],
      varyReversibility: false,
    });
    const seen = new Set<string>();
    for (const r of representatives({ ...probes, verbs: ['a'], resources: ['r'] })) seen.add(JSON.stringify([...r.assignments.entries()]));
    expect(seen.size).toBe(productSize({ ...probes, verbs: ['a'], resources: ['r'] }));
  });
});

describe('index: remaining branches', () => {
  it('an unknown reversibility class is refused with its own reason', () => {
    const p = pol([pred('a', '*')], [{ type: 'reversibility_max', class: 'irreversible' }]);
    expect(reachable(p, { verb: 'a', resource: 'r', reversibilityClass: 'bogus' })).toEqual({
      reachable: false,
      reason: "reversibility class 'bogus' exceeds the caveat cap",
    });
  });
  it('fail-safe reasons list every undecidable feature, joined with "; "', () => {
    const p = pol([pred('a', '*', [LIKE, REF])]);
    const joined = `${LIKE_MSG}; ${REF_MSG}`;
    expect(reachable(p, { verb: 'a', resource: 'r', params: { s: 'no', n: 0 } }).reason).toBe(
      `over-approximated (${joined}); could not construct a witness but cannot prove unreachable`,
    );
    expect(alwaysDenies(pol([pred('a', 're:q', [LIKE, REF])]))).toMatchObject({ alwaysDenies: false, approximate: true });
    const both = pol([pred('a', '*', [LIKE, REF, cond('action.params.t', 'gt', 1), cond('action.params.t', 'lt', 0)])]);
    expect(alwaysDenies(both).reason).toBe(`over-approximated (${joined}); cannot prove vacuity`);
    expect(alwaysAllows(pol([pred('a', '*'), pred('a', '*', [LIKE, REF])]), 'a').reason).toBe(`over-approximated (${joined}); cannot prove totality`);
  });
  it('witness merging keeps provided params and omits absent subject/env', () => {
    const p = pol([pred('a', '*', [cond('action.params.n', 'gt', 10)])]);
    const r = reachable(p, { verb: 'a', resource: 'r', params: { extra: 1 } });
    expect(r.reachable).toBe(true);
    expect(r.witness?.params?.['extra']).toBe(1);
    expect((r.witness?.params?.['n'] as number) > 10).toBe(true);
    expect(Object.keys(r.witness ?? {}).sort()).toEqual(['params', 'resource', 'verb']);
    const noParams = reachable(pol([pred('a', '*', [cond('subject.role', 'eq', 'x')])]), { verb: 'a', resource: 'r' });
    expect(noParams.witness?.params).toEqual({});
    expect(Object.keys(noParams.witness ?? {}).sort()).toEqual(['params', 'resource', 'subject', 'verb']);
    const envOnly = reachable(pol([pred('a', '*', [cond('env.z', 'eq', 1)])]), { verb: 'a', resource: 'r' });
    expect(Object.keys(envOnly.witness ?? {}).sort()).toEqual(['env', 'params', 'resource', 'verb']);
  });
  it('only action.params.* paths are pinned by provided params', () => {
    const path = 'subject.abcdefghijklmnopq';
    const key = path.slice(14);
    expect(key).toBe('ghijklmnopq');
    const p = pol([pred('a', '*', [cond(path, 'eq', 'good')])]);
    expect(reachable(p, { verb: 'a', resource: 'r', params: { [key]: 'bad' } }).reachable).toBe(true);
    expect(reachable(pol([pred('a', '*', [cond('action.params.q', 'eq', 'good')])]), { verb: 'a', resource: 'r', params: { q: 'bad' } }).reachable).toBe(false);
  });
  it('a custom grid bound applies to alwaysAllows', () => {
    const p = pol([pred('a', '*', [cond('action.params.n', 'gt', 1)])]);
    expect(alwaysAllows(p, 'a', { maxCombinations: 1 }).approximate).toBe(true);
    expect(alwaysAllows(p, 'a').approximate).toBeUndefined();
  });
  it('intentConformance: unsat caveats conform even with undecidable features', () => {
    expect(intentConformance(pol([pred('a', '*', [LIKE])], [{ type: 'zzz' }]), { verbs: ['a'], resourceScopes: ['re:q'] })).toEqual({
      conforms: true,
      violations: [],
    });
  });
  it('intentConformance: wildcard intent verb is not probed as a literal verb', () => {
    const r = intentConformance(pol([pred('*', '*')]), { verbs: ['*'], maxAmount: 10 });
    expect(r.violations.length).toBeGreaterThan(0);
    expect(r.violations.every((v) => v.action.verb === '\u0000atlas-analyzer::fresh-verb\u0000')).toBe(true);
  });
  it('intentConformance: intent verbs are probed so violations name them', () => {
    const r = intentConformance(pol([pred('*', '*')]), { verbs: ['x'], maxAmount: 10 });
    const verbs = new Set(r.violations.map((v) => v.action.verb));
    expect(verbs.has('x')).toBe(true);
    const xOver = r.violations.find((v) => v.action.verb === 'x' && v.kinds.includes('over-amount'));
    expect(xOver?.kinds).toEqual(['over-amount']);
  });
  it('intentConformance: grid bound multiplies verbs by resources', () => {
    const p = pol([pred('a', '*')]);
    const intent = { verbs: ['a'], resourceScopes: ['/r1', '/r2*'] };
    const size = productSize(collectProbes({ predicateSets: [p.predicates], extraVerbs: ['a'], extraResources: intent.resourceScopes, varyReversibility: false }));
    expect(size).toBe(2 * 4);
    expect(intentConformance(p, intent, { maxCombinations: size }).approximate).toBeUndefined();
    expect(intentConformance(p, intent, { maxCombinations: size - 1 }).approximate).toBe(true);
    expect(intentConformance(p, intent, { maxCombinations: 1 }).approximate).toBe(true);
  });
  it('intentConformance: amounts are only inspected when maxAmount is set', () => {
    const neg = pol([pred('pay', '*', [cond('action.params.amount', 'lt', -1)])]);
    expect(intentConformance(neg, { verbs: ['pay'] })).toEqual({ conforms: true, violations: [] });
    const withMax = intentConformance(neg, { verbs: ['pay'], maxAmount: 5 });
    expect(withMax.violations.some((v) => v.kinds.includes('under-amount'))).toBe(true);
  });
  it('intentConformance: only finite numbers count as amounts', () => {
    const arr = pol([pred('pay', '*', [cond('action.params.amount', 'eq', [200])])]);
    expect(intentConformance(arr, { verbs: ['pay'], maxAmount: 100 }).conforms).toBe(true);
    const inf = pol([pred('pay', '*', [cond('action.params.amount', 'in', [Infinity, NaN])])]);
    expect(intentConformance(inf, { verbs: ['pay'], maxAmount: 100 }).conforms).toBe(true);
    const wide = pol([
      pred('pay', '*', [
        {
          any_of: [
            { all_of: [cond('action.params.amount', 'gte', 0), cond('action.params.amount', 'lte', 100)] },
            { all_of: [cond('action.params.amount', 'nin', [Infinity]), cond('action.params.amount', 'gt', 1e308)] },
            { all_of: [cond('action.params.amount', 'nin', [-Infinity]), cond('action.params.amount', 'lt', -1e308)] },
          ],
        } as unknown as Condition,
      ]),
    ]);
    const wr = intentConformance(wide, { verbs: ['pay'], maxAmount: 100 });
    expect(wr).toEqual({ conforms: true, violations: [] });
    // non-finite amounts that the policy does admit are not amounts: they are never reported
    const open = pol([pred('pay', '*', [cond('action.params.amount', 'ne', Infinity), cond('action.params.amount', 'ne', -Infinity)])]);
    expect(admitsConcrete(open, { verb: 'pay', resource: 'r', params: { amount: Infinity } })).toBe(true);
    expect(admitsConcrete(open, { verb: 'pay', resource: 'r', params: { amount: -Infinity } })).toBe(true);
    const or = intentConformance(open, { verbs: ['pay'], maxAmount: 100 });
    const amounts = or.violations.map((v) => v.action.params?.['amount']);
    expect(amounts).toContain(101);
    expect(amounts).toContain(-1);
    expect(amounts).not.toContain(Infinity);
    expect(amounts).not.toContain(-Infinity);
    const str = pol([pred('pay', '*', [cond('action.params.amount', 'eq', '500')])]);
    expect(intentConformance(str, { verbs: ['pay'], maxAmount: 100 }).conforms).toBe(true);
  });
  it('intentConformance: regex scope limits (pattern length, subject length, safety)', () => {
    const long = 'a'.repeat(201);
    expect(intentConformance(pol([pred('x', long)]), { verbs: ['x'], resourceScopes: ['re:' + long] }).violations[0]?.kinds).toEqual(['off-scope']);
    const ok200 = 'a'.repeat(200);
    expect(intentConformance(pol([pred('x', ok200)]), { verbs: ['x'], resourceScopes: ['re:' + ok200] }).violations).toHaveLength(0);
    const at512 = 'a'.repeat(512);
    const over = 'a'.repeat(513);
    expect(intentConformance(pol([pred('x', at512)]), { verbs: ['x'], resourceScopes: ['re:a+'] }).violations).toHaveLength(0);
    expect(intentConformance(pol([pred('x', over)]), { verbs: ['x'], resourceScopes: ['re:a+'] }).violations[0]?.kinds).toEqual(['off-scope']);
    expect(intentConformance(pol([pred('x', 'ab')]), { verbs: ['x'], resourceScopes: ['re:(a+)+$'] }).violations[0]?.kinds).toEqual(['off-scope']);
    expect(intentConformance(pol([pred('x', 'ab')]), { verbs: ['x'], resourceScopes: ['re:a+b'] }).violations).toHaveLength(0);
  });
});
