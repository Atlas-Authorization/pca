import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_RISK_POLICY, type Caveat, type Condition, type Predicate } from '@atlasauth/pca';

type Handler = ((...a: unknown[]) => unknown) | undefined;
const h = vi.hoisted(() => ({
  reachable: undefined as Handler,
  alwaysAllows: undefined as Handler,
  alwaysDenies: undefined as Handler,
  subsumes: undefined as Handler,
}));

vi.mock('./deps', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./deps')>();
  return {
    ...actual,
    reachable: vi.fn((...a: Parameters<typeof actual.reachable>) => (h.reachable ? h.reachable(...a) : actual.reachable(...a)) as ReturnType<typeof actual.reachable>),
    alwaysAllows: vi.fn((...a: Parameters<typeof actual.alwaysAllows>) => (h.alwaysAllows ? h.alwaysAllows(...a) : actual.alwaysAllows(...a)) as ReturnType<typeof actual.alwaysAllows>),
    alwaysDenies: vi.fn((...a: Parameters<typeof actual.alwaysDenies>) => (h.alwaysDenies ? h.alwaysDenies(...a) : actual.alwaysDenies(...a)) as ReturnType<typeof actual.alwaysDenies>),
    subsumes: vi.fn((...a: Parameters<typeof actual.subsumes>) => (h.subsumes ? h.subsumes(...a) : actual.subsumes(...a)) as ReturnType<typeof actual.subsumes>),
  };
});

import { alwaysAllows, alwaysDenies, reachable } from './deps';
import type { NormalizedPolicy } from './normalize';
import {
  ruleDangerousReachability,
  ruleMissingSafetyFloor,
  ruleOverBroadGrant,
  rulePrivilegeEscalation,
  ruleRedundantCaveat,
} from './rules';
import { DEFAULT_DANGEROUS_VERBS, type Finding } from './types';

beforeEach(() => {
  h.reachable = undefined;
  h.alwaysAllows = undefined;
  h.alwaysDenies = undefined;
  h.subsumes = undefined;
  vi.mocked(reachable).mockClear();
  vi.mocked(alwaysAllows).mockClear();
  vi.mocked(alwaysDenies).mockClear();
});

const pol = (predicates: unknown[], caveats: Caveat[] = [], riskPolicy?: typeof DEFAULT_RISK_POLICY): NormalizedPolicy => ({
  predicates: predicates as Predicate[],
  caveats,
  kind: 'bare',
  ...(riskPolicy !== undefined ? { riskPolicy } : {}),
});
const cv = (type: string, rest: Record<string, unknown> = {}): Caveat => ({ type, ...rest }) as Caveat;
const LEAF: Condition = { field: 'action.params.n', op: 'lte', value: 10 };
const F = (rule: Finding['rule'], severity: Finding['severity'], message: string, where?: string): Finding =>
  where === undefined ? { rule, severity, message } : { rule, severity, message, where };
const OB = (severity: Finding['severity'], message: string, where?: string) => F('over-broad-grant', severity, message, where);
const RC = (severity: Finding['severity'], message: string, where?: string) => F('redundant-caveat', severity, message, where);
const DR = (severity: Finding['severity'], message: string) => F('dangerous-reachability', severity, message);
const SF = (message: string) => F('missing-safety-floor', 'warn', message);
const NARROWING = 'max_blast_radius/rate/reversibility_max/budget_alloc/delegation_depth';
const DANGEROUS = DEFAULT_DANGEROUS_VERBS;
const OPTS = { maxCombinations: 7 };
const notAllEvery = () => ({ alwaysAllows: false });

describe('over-broad grant: wildcard verb and resource', () => {
  it('a wildcard verb is one error and never probed as a concrete verb', () => {
    h.alwaysAllows = notAllEvery;
    expect(ruleOverBroadGrant(pol([{ verb: '*', resource: '/x' }]), DANGEROUS, OPTS)).toStrictEqual([
      OB('error', `predicate grants a WILDCARD verb '*' — authority over any action`, 'predicates[0]'),
    ]);
    expect(ruleOverBroadGrant(pol([{ verb: '*' }]), DANGEROUS, OPTS)).toStrictEqual([
      OB('error', `predicate grants a WILDCARD verb '*' — authority over any action`, 'predicates[0]'),
    ]);
    expect(vi.mocked(alwaysAllows)).not.toHaveBeenCalled();
  });

  it('a wildcard resource with a dangerous verb is an error naming the dangerous verbs only', () => {
    h.alwaysAllows = notAllEvery;
    const p = pol([{ verb: ['db.read', 'db.delete', 'acct.transfer'], resource: '*', where: [LEAF] }]);
    expect(ruleOverBroadGrant(p, DANGEROUS, OPTS)).toStrictEqual([
      OB('error', `dangerous verb(s) ["db.delete","acct.transfer"] granted on a WILDCARD resource ('*')`, 'predicates[0]'),
    ]);
  });

  it('an omitted resource is a wildcard too', () => {
    h.alwaysAllows = notAllEvery;
    expect(ruleOverBroadGrant(pol([{ verb: 'db.delete', where: [LEAF] }]), DANGEROUS, OPTS)).toStrictEqual([
      OB('error', `dangerous verb(s) ["db.delete"] granted on a WILDCARD resource ('*')`, 'predicates[0]'),
    ]);
  });

  it('a wildcard resource with only safe verbs is a warning', () => {
    h.alwaysAllows = notAllEvery;
    expect(ruleOverBroadGrant(pol([{ verb: 'db.read', resource: '*' }]), DANGEROUS, OPTS)).toStrictEqual([
      OB('warn', `predicate matches ANY resource ('*') — consider a resource prefix`, 'predicates[0]'),
    ]);
    // a verb that is not a string leaves no verbs, so there is nothing dangerous and no wildcard verb either
    expect(ruleOverBroadGrant(pol([{ verb: 5, resource: '*' }]), DANGEROUS, OPTS)).toStrictEqual([
      OB('warn', `predicate matches ANY resource ('*') — consider a resource prefix`, 'predicates[0]'),
    ]);
  });

  it('a specific resource with a safe verb adds no resource finding', () => {
    h.alwaysAllows = notAllEvery;
    const out = ruleOverBroadGrant(pol([{ verb: 'db.read', resource: '/a/*' }]), DANGEROUS, OPTS);
    expect(out).toStrictEqual([]);
  });

  it('a custom dangerous list can name * itself, and * is still never reported as an unnarrowed dangerous verb', () => {
    h.alwaysAllows = notAllEvery;
    expect(ruleOverBroadGrant(pol([{ verb: '*' }]), ['*'], OPTS)).toStrictEqual([
      OB('error', `predicate grants a WILDCARD verb '*' — authority over any action`, 'predicates[0]'),
      OB('error', `dangerous verb(s) ["*"] granted on a WILDCARD resource ('*')`, 'predicates[0]'),
    ]);
  });

  it('reports the index of each predicate', () => {
    h.alwaysAllows = notAllEvery;
    const out = ruleOverBroadGrant(pol([{ verb: 'db.read', resource: '/x', where: [LEAF] }, { verb: 'db.read', resource: '*' }]), DANGEROUS, OPTS);
    expect(out).toStrictEqual([OB('warn', `predicate matches ANY resource ('*') — consider a resource prefix`, 'predicates[1]')]);
  });
});

describe('over-broad grant: dangerous verb with no narrowing', () => {
  const msg = (v: string) => `dangerous verb '${v}' is granted with NO narrowing \`where\` and no scope-narrowing caveat (${NARROWING})`;
  const dangerous = (extra: object = {}, caveats: Caveat[] = []) => ruleOverBroadGrant(pol([{ verb: 'acct.transfer', resource: '/acct/1', ...extra }], caveats), DANGEROUS, OPTS);

  it('is an error with the full message and the predicate location', () => {
    h.alwaysAllows = notAllEvery;
    expect(dangerous()).toStrictEqual([OB('error', msg('acct.transfer'), 'predicates[0]')]);
  });
  it('an empty or malformed where does not narrow', () => {
    h.alwaysAllows = notAllEvery;
    expect(dangerous({ where: [] })).toStrictEqual([OB('error', msg('acct.transfer'), 'predicates[0]')]);
    expect(dangerous({ where: 'nonsense' })).toStrictEqual([OB('error', msg('acct.transfer'), 'predicates[0]')]);
  });
  it('a non-empty where narrows', () => {
    h.alwaysAllows = notAllEvery;
    expect(dangerous({ where: [LEAF] })).toStrictEqual([]);
  });
  it('a scope-narrowing caveat narrows; an unrelated caveat does not', () => {
    h.alwaysAllows = notAllEvery;
    for (const t of ['max_blast_radius', 'rate', 'reversibility_max', 'budget_alloc', 'delegation_depth']) expect(dangerous({}, [cv(t)])).toStrictEqual([]);
    expect(dangerous({}, [cv('expires', { at: 1 })])).toStrictEqual([OB('error', msg('acct.transfer'), 'predicates[0]')]);
  });
  it('a safe verb with no narrowing is fine', () => {
    h.alwaysAllows = notAllEvery;
    expect(ruleOverBroadGrant(pol([{ verb: 'docs.read', resource: '/docs/1' }]), DANGEROUS, OPTS)).toStrictEqual([]);
  });
  it('one finding per dangerous verb', () => {
    h.alwaysAllows = notAllEvery;
    const out = ruleOverBroadGrant(pol([{ verb: ['db.drop', 'docs.read', 'db.purge'], resource: '/x' }]), DANGEROUS, OPTS);
    expect(out).toStrictEqual([OB('error', msg('db.drop'), 'predicates[0]'), OB('error', msg('db.purge'), 'predicates[0]')]);
  });
});

describe('over-broad grant: proven always-allow', () => {
  const total = (v: string) => `grants EVERY action of '${v}' — the authority has no effective constraint (always-allow)`;
  it('probes each distinct concrete verb once with the policy and the analyzer options', () => {
    h.alwaysAllows = notAllEvery;
    const caveats = [cv('expires', { at: 5 })];
    const p = pol([{ verb: ['a.b', 'c.d'], resource: '/x', where: [LEAF] }, { verb: 'a.b', resource: '/y', where: [LEAF] }, { verb: '*', resource: '/z', where: [LEAF] }], caveats);
    ruleOverBroadGrant(p, DANGEROUS, OPTS);
    const calls = vi.mocked(alwaysAllows).mock.calls;
    expect(calls.map((c) => c[1])).toEqual(['a.b', 'c.d']);
    expect(calls[0]![0]).toStrictEqual({ predicates: p.predicates, caveats });
    expect(calls[0]![2]).toBe(OPTS);
  });
  it('a proven total verb is an error with no location', () => {
    h.alwaysAllows = (_i, v) => ({ alwaysAllows: v === 'c.d' });
    const out = ruleOverBroadGrant(pol([{ verb: ['a.b', 'c.d'], resource: '/x', where: [LEAF] }]), DANGEROUS, OPTS);
    expect(out).toStrictEqual([OB('error', total('c.d'))]);
  });
  it('an approximate verdict is never an error', () => {
    h.alwaysAllows = () => ({ alwaysAllows: true, approximate: true });
    expect(ruleOverBroadGrant(pol([{ verb: 'a.b', resource: '/x', where: [LEAF] }]), DANGEROUS, OPTS)).toStrictEqual([]);
    h.alwaysAllows = () => ({ alwaysAllows: true, approximate: false });
    expect(ruleOverBroadGrant(pol([{ verb: 'a.b', resource: '/x', where: [LEAF] }]), DANGEROUS, OPTS)).toStrictEqual([OB('error', total('a.b'))]);
    h.alwaysAllows = () => ({ alwaysAllows: false, approximate: false });
    expect(ruleOverBroadGrant(pol([{ verb: 'a.b', resource: '/x', where: [LEAF] }]), DANGEROUS, OPTS)).toStrictEqual([]);
  });
});

describe('malformed predicates are skipped, not crashed on', () => {
  it('null, undefined and non-object predicates produce nothing and are never probed', () => {
    h.alwaysAllows = () => ({ alwaysAllows: true });
    for (const bad of [null, undefined, 'x', 5, true]) {
      expect(() => ruleOverBroadGrant(pol([bad]), DANGEROUS, OPTS)).not.toThrow();
      expect(ruleOverBroadGrant(pol([bad]), DANGEROUS, OPTS)).toStrictEqual([]);
    }
    expect(vi.mocked(alwaysAllows)).not.toHaveBeenCalled();
  });
});

describe('privilege escalation', () => {
  const hop = (id: string) => pol([{ verb: id, resource: '/x', where: [LEAF] }], [cv('expires', { at: 9 })]);
  it('compares each parent with its child, in order, with the analyzer options', () => {
    const seen: unknown[][] = [];
    h.subsumes = (...a) => {
      seen.push(a);
      return { subsumes: true };
    };
    const hops = [hop('a'), hop('b'), hop('c')];
    expect(rulePrivilegeEscalation(hops, OPTS)).toStrictEqual([]);
    expect(seen).toHaveLength(2);
    expect(seen[0]).toStrictEqual([{ predicates: hops[0]!.predicates, caveats: hops[0]!.caveats }, { predicates: hops[1]!.predicates, caveats: hops[1]!.caveats }, OPTS]);
    expect((seen[1]![1] as { predicates: unknown }).predicates).toBe(hops[2]!.predicates);
    expect(seen[0]![2]).toBe(OPTS);
  });
  it('a single hop and an empty chain are clean', () => {
    h.subsumes = () => {
      throw new Error('must not be called');
    };
    expect(rulePrivilegeEscalation([hop('a')], OPTS)).toStrictEqual([]);
    expect(rulePrivilegeEscalation([], OPTS)).toStrictEqual([]);
  });
  it('skips a missing hop on either side instead of failing', () => {
    h.subsumes = () => ({ subsumes: true });
    const sparse: NormalizedPolicy[] = [hop('a')];
    sparse[2] = hop('c');
    expect(() => rulePrivilegeEscalation(sparse, OPTS)).not.toThrow();
    expect(rulePrivilegeEscalation(sparse, OPTS)).toStrictEqual([]);
  });
  it('an undecidable hop is a warning with its reason', () => {
    h.subsumes = () => ({ subsumes: false, approximate: true, reason: 'regex resource' });
    expect(rulePrivilegeEscalation([hop('a'), hop('b')], OPTS)).toStrictEqual([
      F('privilege-escalation', 'warn', 'could not prove hop 1 attenuation (undecidable: regex resource) — attenuation not verified', 'hop[1]'),
    ]);
    h.subsumes = () => ({ subsumes: false, approximate: true });
    expect(rulePrivilegeEscalation([hop('a'), hop('b'), hop('c')], OPTS)).toStrictEqual([
      F('privilege-escalation', 'warn', 'could not prove hop 1 attenuation (undecidable) — attenuation not verified', 'hop[1]'),
      F('privilege-escalation', 'warn', 'could not prove hop 2 attenuation (undecidable) — attenuation not verified', 'hop[2]'),
    ]);
  });
  it('a proven escalation is an error naming the counterexample when there is one', () => {
    const base = 'delegation hop 1 ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)';
    h.subsumes = () => ({ subsumes: false, counterexample: { verb: 'pay', resource: '/acct/1', params: { amount: 5 } } });
    expect(rulePrivilegeEscalation([hop('a'), hop('b')], OPTS)).toStrictEqual([
      F('privilege-escalation', 'error', `${base} — child admits 'pay /acct/1 {"amount":5}' which its parent denies`, 'hop[1]'),
    ]);
    h.subsumes = () => ({ subsumes: false });
    expect(rulePrivilegeEscalation([hop('a'), hop('b')], OPTS)).toStrictEqual([F('privilege-escalation', 'error', base, 'hop[1]')]);
  });
  it('a subsuming hop is clean even when the verdict is approximate', () => {
    h.subsumes = () => ({ subsumes: true, approximate: true });
    expect(rulePrivilegeEscalation([hop('a'), hop('b')], OPTS)).toStrictEqual([]);
  });
});

describe('redundant caveat: exact duplicates', () => {
  it('flags the later copy, naming the first', () => {
    const e = cv('expires', { at: 5 });
    expect(ruleRedundantCaveat(pol([], [e, cv('rate', { max: 1 }), { ...e }, { ...e }]))).toStrictEqual([
      RC('warn', `caveat 2 ('expires') is an exact duplicate of caveat 0 — dead policy`, 'caveats[2]'),
      RC('warn', `caveat 3 ('expires') is an exact duplicate of caveat 0 — dead policy`, 'caveats[3]'),
    ]);
  });
  it('distinct caveats are not duplicates', () => {
    expect(ruleRedundantCaveat(pol([], [cv('rate', { max: 1 }), cv('rate', { max: 2 }), cv('budget', { max: 1 })]))).toStrictEqual([]);
  });
  it('caveats that cannot be serialized are compared by type', () => {
    const a = cv('x', { n: 1n });
    const b = cv('y', { n: 1n });
    expect(ruleRedundantCaveat(pol([], [a, b]))).toStrictEqual([]);
    expect(ruleRedundantCaveat(pol([], [a, cv('x', { n: 2n })]))).toStrictEqual([
      RC('warn', `caveat 1 ('x') is an exact duplicate of caveat 0 — dead policy`, 'caveats[1]'),
    ]);
  });
  it('null, undefined and non-object caveats are ignored', () => {
    for (const bad of [null, undefined, 'x', 7]) {
      const list = [bad, bad, cv('expires', { at: 1 }), bad] as unknown as Caveat[];
      expect(() => ruleRedundantCaveat(pol([], list))).not.toThrow();
      expect(ruleRedundantCaveat(pol([], list))).toStrictEqual([]);
    }
  });
});

describe('redundant caveat: a stricter caveat of the same type dominates', () => {
  it('keeps the earliest expiry, the latest not_before, and the smallest bound for the rest', () => {
    const caveats = [
      cv('expires', { at: 30 }),
      cv('expires', { at: 10 }),
      cv('not_before', { at: 5 }),
      cv('not_before', { at: 9 }),
      cv('max_blast_radius', { max: 0.5 }),
      cv('max_blast_radius', { max: 0.1 }),
      cv('delegation_depth', { max: 3 }),
      cv('delegation_depth', { max: 2 }),
      cv('budget_alloc', { limit: 100 }),
      cv('budget_alloc', { limit: 50 }),
    ];
    expect(ruleRedundantCaveat(pol([], caveats))).toStrictEqual([
      RC('warn', `caveat 0 ('expires' at=30) is subsumed by a stricter 'expires' (at=10) — it can never bite`, 'caveats[0]'),
      RC('warn', `caveat 2 ('not_before' at=5) is subsumed by a stricter 'not_before' (at=9) — it can never bite`, 'caveats[2]'),
      RC('warn', `caveat 4 ('max_blast_radius' max=0.5) is subsumed by a stricter 'max_blast_radius' (max=0.1) — it can never bite`, 'caveats[4]'),
      RC('warn', `caveat 6 ('delegation_depth' max=3) is subsumed by a stricter 'delegation_depth' (max=2) — it can never bite`, 'caveats[6]'),
      RC('warn', `caveat 8 ('budget_alloc' limit=100) is subsumed by a stricter 'budget_alloc' (limit=50) — it can never bite`, 'caveats[8]'),
    ]);
  });
  it('the binding caveat itself is never flagged, and equal values are only a duplicate', () => {
    const out = ruleRedundantCaveat(pol([], [cv('expires', { at: 10 }), cv('expires', { at: 10 })]));
    expect(out).toStrictEqual([RC('warn', `caveat 1 ('expires') is an exact duplicate of caveat 0 — dead policy`, 'caveats[1]')]);
    const equalButDifferent = ruleRedundantCaveat(pol([], [cv('expires', { at: 10 }), cv('expires', { at: 10, note: 'x' })]));
    expect(equalButDifferent).toStrictEqual([]);
  });
  it('a single caveat, other types, and caveats without a numeric bound are left alone', () => {
    expect(ruleRedundantCaveat(pol([], [cv('expires', { at: 10 })]))).toStrictEqual([]);
    expect(ruleRedundantCaveat(pol([], [cv('expires', { at: 10 }), cv('rate', { max: 5 })]))).toStrictEqual([]);
    expect(ruleRedundantCaveat(pol([], [cv('expires', { at: 10 }), cv('expires')]))).toStrictEqual([]);
    expect(ruleRedundantCaveat(pol([], [cv('expires', { at: 10 }), cv('expires', { at: '5' }), cv('expires', { at: Number.NaN })]))).toStrictEqual([]);
    expect(ruleRedundantCaveat(pol([], [cv('expires'), cv('expires', { at: 10 })]))).toStrictEqual([]);
  });
  it('a bound field shared with another caveat type does not make the types compete', () => {
    expect(ruleRedundantCaveat(pol([], [cv('max_blast_radius', { max: 0.5 }), cv('rate', { max: 5 }), cv('delegation_depth', { max: 1 })]))).toStrictEqual([]);
  });
  it('a different type with a smaller value does not dominate', () => {
    expect(ruleRedundantCaveat(pol([], [cv('expires', { at: 10 }), cv('not_before', { at: 1 }), cv('expires', { at: 10, x: 1 })]))).toStrictEqual([]);
  });
});

describe('redundant caveat: predicates', () => {
  it('an unsatisfiable numeric where is dead policy', () => {
    const dead = { verb: 'a.b', resource: '/x', where: [{ field: 'action.params.n', op: 'gte', value: 100 }, { field: 'action.params.n', op: 'lte', value: 10 }] };
    expect(ruleRedundantCaveat(pol([{ verb: 'a.b', resource: '/x', where: [LEAF] }, dead]))).toStrictEqual([
      RC('warn', 'predicate 1 can never match — its numeric `where` constraints are unsatisfiable (dead policy)', 'predicates[1]'),
    ]);
  });
  it('bounds on different fields are not a contradiction', () => {
    const where = [{ field: 'action.params.a', op: 'gte', value: 100 }, { field: 'action.params.b', op: 'lte', value: 10 }];
    expect(ruleRedundantCaveat(pol([{ verb: 'a.b', resource: '/x', where }]))).toStrictEqual([]);
  });
  it('a bound that does not tighten the field is info, located on its condition', () => {
    const where = [LEAF, { field: 'action.params.n', op: 'lte', value: 100 }];
    expect(ruleRedundantCaveat(pol([{ verb: 'a.b', resource: '/x', where: [] }, { verb: 'a.b', resource: '/x', where }]))).toStrictEqual([
      RC('info', `condition on 'action.params.n' (lte 100) does not tighten the authority — redundant with the other bounds on this field`, 'predicates[1].where[1]'),
    ]);
  });
  it('two copies of the same bound are both redundant with each other', () => {
    const where = [LEAF, { ...LEAF }];
    const out = ruleRedundantCaveat(pol([{ verb: 'a.b', where }]));
    expect(out.map((f) => f.where)).toEqual(['predicates[0].where[0]', 'predicates[0].where[1]']);
    expect(out.every((f) => f.severity === 'info')).toBe(true);
  });
  const only = (where: unknown[]) => ruleRedundantCaveat(pol([{ verb: 'a.b', resource: '/x', where }])).map((f) => f.where);
  it('compares each end of the interval on its own: value and inclusiveness', () => {
    const c = (op: string, value: number, field = 'action.params.n') => ({ field, op, value });
    expect(only([c('gt', 5), c('gt', 3)])).toEqual(['predicates[0].where[1]']);
    expect(only([c('gt', 5), c('gte', 5)])).toEqual(['predicates[0].where[1]']);
    expect(only([c('lt', 3), c('lt', 5)])).toEqual(['predicates[0].where[1]']);
    expect(only([c('lt', 5), c('lte', 5)])).toEqual(['predicates[0].where[1]']);
    expect(only([c('gte', 1), c('lte', 10), c('lte', 20)])).toEqual(['predicates[0].where[2]']);
    expect(only([c('gte', 1), c('lte', 10)])).toEqual([]);
  });
  it('each field is judged on its own', () => {
    const c = (field: string, op: string, value: number) => ({ field, op, value });
    expect(only([c('action.params.a', 'lte', 10), c('action.params.b', 'lte', 100)])).toEqual([]);
    expect(only([c('action.params.a', 'lte', 10), c('action.params.b', 'lte', 100), c('action.params.b', 'lte', 200)])).toEqual(['predicates[0].where[2]']);
  });
  it('ignores conditions that are not plain numeric bounds', () => {
    const base = { field: 'action.params.n', op: 'lte', value: 10 };
    expect(only([base, { field: 'action.params.n', op: 'ne', value: 5 }])).toEqual([]);
    expect(only([base, { field: 'action.params.n', op: 'lte', value: 'x' }])).toEqual([]);
    expect(only([base, { field: 'action.params.n', op: 'lte', value: 100, ref: 'action.params.m' }])).toEqual([]);
    expect(only([{ op: 'lte', value: 10 }, { op: 'lte', value: 100 }])).toEqual([]);
    expect(only([base, { all_of: [{ field: 'action.params.n', op: 'lte', value: 100 }] }])).toEqual([]);
  });
  it('malformed predicates and a non-array where are skipped', () => {
    for (const bad of [null, undefined, 'x', 7]) {
      expect(() => ruleRedundantCaveat(pol([bad]))).not.toThrow();
      expect(ruleRedundantCaveat(pol([bad]))).toStrictEqual([]);
    }
    expect(ruleRedundantCaveat(pol([{ verb: 'a.b', where: 'nonsense' }]))).toStrictEqual([]);
  });
});

describe('dangerous reachability', () => {
  const P = (extra: object = {}) => [{ verb: 'db.delete', resource: '/t/*', where: [LEAF], ...extra }];
  const W = { verb: 'db.delete', resource: '/t/1', params: { n: 1 } };
  const WTXT = 'db.delete /t/1 {"n":1}';

  it('probes every distinct dangerous concrete verb for totality of denial, with the policy and options', () => {
    h.alwaysDenies = () => ({ alwaysDenies: true });
    const caveats = [cv('expires', { at: 5 })];
    const p = pol([{ verb: ['db.delete', 'docs.read', '*', 'db.delete'], resource: '/x', where: [LEAF] }, { verb: 'acct.transfer', resource: '/y', where: [LEAF] }], caveats);
    expect(ruleDangerousReachability(p, DANGEROUS, [], OPTS)).toStrictEqual([]);
    const calls = vi.mocked(alwaysDenies).mock.calls;
    expect(calls.map((c) => c[1])).toEqual(['db.delete', 'acct.transfer']);
    expect(calls[0]![0]).toStrictEqual({ predicates: p.predicates, caveats });
    expect(calls[0]![2]).toBe(OPTS);
    expect(vi.mocked(reachable)).not.toHaveBeenCalled();
  });

  it('a provably reachable dangerous verb with no gate is an error naming the witness action', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false, witness: W });
    expect(ruleDangerousReachability(pol(P()), DANGEROUS, [], OPTS)).toStrictEqual([
      DR('error', `dangerous action '${WTXT}' is REACHABLE with no budget / rate / step-up gate`),
    ]);
  });

  it('with no witness the verb itself is named', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false });
    expect(ruleDangerousReachability(pol(P()), DANGEROUS, [], OPTS)).toStrictEqual([
      DR('error', `dangerous action 'db.delete' is REACHABLE with no budget / rate / step-up gate`),
    ]);
  });

  it('a verb that is always denied, or whose verdict is approximate, is not reported as reachable', () => {
    h.alwaysDenies = () => ({ alwaysDenies: true });
    expect(ruleDangerousReachability(pol(P()), DANGEROUS, [], OPTS)).toStrictEqual([]);
    h.alwaysDenies = () => ({ alwaysDenies: true, approximate: true });
    expect(ruleDangerousReachability(pol(P()), DANGEROUS, [], OPTS)).toStrictEqual([
      DR('warn', `could not decide reachability of dangerous verb 'db.delete' (undecidable)`),
    ]);
  });

  it('an approximate verdict is a warning that quotes the reason', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false, approximate: true, reason: 'grid too large', witness: W });
    expect(ruleDangerousReachability(pol(P()), DANGEROUS, [], OPTS)).toStrictEqual([
      DR('warn', `could not decide reachability of dangerous verb 'db.delete' (undecidable: grid too large)`),
    ]);
  });

  it('an explicit approximate=false does not hide a proven verdict', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false, approximate: false, witness: W });
    expect(ruleDangerousReachability(pol(P()), DANGEROUS, [], OPTS)).toStrictEqual([
      DR('error', `dangerous action '${WTXT}' is REACHABLE with no budget / rate / step-up gate`),
    ]);
  });

  it('a budget, rate or blast-radius caveat downgrades a proven verdict to info and names the gates', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false, witness: W });
    const gated = (caveats: Caveat[], rp?: typeof DEFAULT_RISK_POLICY) => ruleDangerousReachability(pol(P(), caveats, rp), DANGEROUS, [], OPTS);
    expect(gated([cv('rate'), cv('expires', { at: 1 }), cv('max_blast_radius')])).toStrictEqual([DR('info', `dangerous action '${WTXT}' is reachable but gated by rate/max_blast_radius`)]);
    expect(gated([cv('budget_alloc')])).toStrictEqual([DR('info', `dangerous action '${WTXT}' is reachable but gated by budget_alloc`)]);
    expect(gated([cv('expires', { at: 1 }), cv('reversibility_max')])).toStrictEqual([DR('error', `dangerous action '${WTXT}' is REACHABLE with no budget / rate / step-up gate`)]);
  });

  it('a risk step-up threshold below 1 is a gate; 1 and above, or a non-finite value, is not', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false, witness: W });
    const withTheta = (theta2: number, caveats: Caveat[] = []) => ruleDangerousReachability(pol(P(), caveats, { ...DEFAULT_RISK_POLICY, theta2 }), DANGEROUS, [], OPTS);
    expect(withTheta(0.5)).toStrictEqual([DR('info', `dangerous action '${WTXT}' is reachable but gated by risk step-up (theta2 < 1)`)]);
    expect(withTheta(0.999)).toStrictEqual([DR('info', `dangerous action '${WTXT}' is reachable but gated by risk step-up (theta2 < 1)`)]);
    expect(withTheta(0.5, [cv('rate')])).toStrictEqual([DR('info', `dangerous action '${WTXT}' is reachable but gated by rate, risk step-up (theta2 < 1)`)]);
    for (const t of [1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(withTheta(t)[0]?.severity).toBe('error');
    }
  });

  it('explicit targets with a resource are probed for reachability of that exact action, after the derived ones', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false, witness: W });
    h.reachable = () => ({ reachable: true });
    const p = pol(P());
    const out = ruleDangerousReachability(p, DANGEROUS, [{ verb: 'x.y', resource: '/r' }], OPTS);
    expect(out).toStrictEqual([
      DR('error', `dangerous action '${WTXT}' is REACHABLE with no budget / rate / step-up gate`),
      DR('error', `dangerous action 'x.y /r' is REACHABLE with no budget / rate / step-up gate`),
    ]);
    const calls = vi.mocked(reachable).mock.calls;
    expect(calls).toHaveLength(1);
    expect(calls[0]![0]).toStrictEqual({ predicates: p.predicates, caveats: [] });
    expect(calls[0]![1]).toStrictEqual({ verb: 'x.y', resource: '/r' });
    expect(calls[0]![2]).toBe(OPTS);
    expect(vi.mocked(alwaysDenies).mock.calls.map((c) => c[1])).toEqual(['db.delete']);
  });

  it('a target with no resource is probed by verb only, even when the verb is not otherwise dangerous', () => {
    h.alwaysDenies = () => ({ alwaysDenies: false });
    const out = ruleDangerousReachability(pol([{ verb: 'docs.read', resource: '/x', where: [LEAF] }]), DANGEROUS, [{ verb: 'docs.read' }], OPTS);
    expect(out).toStrictEqual([DR('error', `dangerous action 'docs.read' is REACHABLE with no budget / rate / step-up gate`)]);
    expect(vi.mocked(reachable)).not.toHaveBeenCalled();
  });

  it('reachability verdicts: unreachable is silent, approximate is a warning, proven respects the gate', () => {
    const t = [{ verb: 'x.y', resource: '/r' }];
    const safe = pol([{ verb: 'docs.read', resource: '/x', where: [LEAF] }]);
    h.reachable = () => ({ reachable: false });
    expect(ruleDangerousReachability(safe, DANGEROUS, t, OPTS)).toStrictEqual([]);
    h.reachable = () => ({ reachable: false, approximate: true });
    expect(ruleDangerousReachability(safe, DANGEROUS, t, OPTS)).toStrictEqual([DR('warn', `could not decide reachability of dangerous verb 'x.y' (undecidable)`)]);
    h.reachable = () => ({ reachable: true, approximate: true, reason: 'regex' });
    expect(ruleDangerousReachability(safe, DANGEROUS, t, OPTS)).toStrictEqual([DR('warn', `could not decide reachability of dangerous verb 'x.y' (undecidable: regex)`)]);
    h.reachable = () => ({ reachable: true, approximate: false });
    expect(ruleDangerousReachability(safe, DANGEROUS, t, OPTS)).toStrictEqual([DR('error', `dangerous action 'x.y /r' is REACHABLE with no budget / rate / step-up gate`)]);
    h.reachable = () => ({ reachable: true });
    expect(ruleDangerousReachability(pol(safe.predicates, [cv('rate')]), DANGEROUS, t, OPTS)).toStrictEqual([DR('info', `dangerous action 'x.y /r' is reachable but gated by rate`)]);
  });

  it('a policy with no dangerous verb and no targets is clean without any probe', () => {
    expect(ruleDangerousReachability(pol([{ verb: 'docs.read', resource: '/x' }]), DANGEROUS, [], OPTS)).toStrictEqual([]);
    expect(vi.mocked(alwaysDenies)).not.toHaveBeenCalled();
  });
});

describe('missing safety floor', () => {
  const both = { requireExpiry: true, requireScopeGate: true };
  const EXPIRY = SF('grant has no `expires` caveat — the authority never expires');
  const GATE = SF('non-trivial grant has no blast-radius / rate / budget gate (max_blast_radius/rate/budget_alloc)');
  const safeP = { verb: 'docs.read', resource: '/docs/x', where: [LEAF] };
  const run = (predicates: unknown[], caveats: Caveat[] = [], cfg = both) => ruleMissingSafetyFloor(pol(predicates, caveats), cfg, DANGEROUS);

  it('a policy that grants nothing needs no floor', () => {
    expect(run([])).toStrictEqual([]);
  });
  it('a missing expiry is a warning; an expiry satisfies it', () => {
    expect(run([safeP])).toStrictEqual([EXPIRY]);
    expect(run([safeP], [cv('expires', { at: 1 })])).toStrictEqual([]);
    expect(run([safeP], [], { requireExpiry: false, requireScopeGate: true })).toStrictEqual([]);
  });
  it('a non-trivial grant needs a blast-radius, rate or budget gate', () => {
    const exp = [cv('expires', { at: 1 })];
    const open = { verb: 'docs.read', resource: '/docs/x' };
    expect(run([open], exp)).toStrictEqual([GATE]);
    expect(run([open], [...exp, cv('max_blast_radius')])).toStrictEqual([]);
    expect(run([open], [...exp, cv('rate')])).toStrictEqual([]);
    expect(run([open], [...exp, cv('budget_alloc')])).toStrictEqual([]);
    expect(run([open], [...exp, cv('reversibility_max')])).toStrictEqual([GATE]);
    expect(run([open])).toStrictEqual([EXPIRY, GATE]);
    expect(run([open], exp, { requireExpiry: true, requireScopeGate: false })).toStrictEqual([]);
    expect(run([open], [], { requireExpiry: false, requireScopeGate: false })).toStrictEqual([]);
  });
  it('a tightly constrained grant is not non-trivial', () => {
    expect(run([safeP], [cv('expires', { at: 1 })])).toStrictEqual([]);
  });
  it('each of the four reasons alone makes a grant non-trivial', () => {
    const exp = [cv('expires', { at: 1 })];
    expect(run([{ ...safeP, verb: '*' }], exp)).toStrictEqual([GATE]);
    expect(run([{ ...safeP, verb: 'db.delete' }], exp)).toStrictEqual([GATE]);
    expect(run([{ ...safeP, verb: ['docs.read', 'db.purge'] }], exp)).toStrictEqual([GATE]);
    expect(run([{ ...safeP, resource: '*' }], exp)).toStrictEqual([GATE]);
    expect(run([{ verb: 'docs.read', resource: '/docs/x' }], exp)).toStrictEqual([GATE]);
    expect(run([{ ...safeP, where: [] }], exp)).toStrictEqual([GATE]);
    expect(run([{ ...safeP, where: 'x' }], exp)).toStrictEqual([GATE]);
    expect(run([{ verb: 'docs.read', where: [LEAF] }], exp)).toStrictEqual([GATE]);
  });
  it('one non-trivial predicate among tight ones is enough', () => {
    const exp = [cv('expires', { at: 1 })];
    expect(run([safeP, { verb: 'db.delete', resource: '/x', where: [LEAF] }], exp)).toStrictEqual([GATE]);
    expect(run([{ verb: 'db.delete', resource: '/x', where: [LEAF] }, safeP], exp)).toStrictEqual([GATE]);
  });
  it('malformed predicates are never non-trivial and never crash', () => {
    const exp = [cv('expires', { at: 1 })];
    for (const bad of [null, undefined, 'x', 7]) {
      expect(() => run([bad], exp)).not.toThrow();
      expect(run([bad], exp)).toStrictEqual([]);
      expect(run([bad, safeP], exp)).toStrictEqual([]);
    }
  });
  it('honours a custom dangerous list', () => {
    const exp = [cv('expires', { at: 1 })];
    expect(ruleMissingSafetyFloor(pol([{ ...safeP, verb: 'docs.read' }]), both, ['read'])).toStrictEqual([EXPIRY, GATE]);
    expect(ruleMissingSafetyFloor(pol([{ ...safeP, verb: 'db.delete' }], exp), both, ['read'])).toStrictEqual([]);
  });
});
