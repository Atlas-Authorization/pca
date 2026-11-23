import { describe, expect, it } from 'vitest';
import type { Condition, Predicate } from '@atlasauth/pca';
import { coverage, coverageGate, permitId, toModel, witnessOf, type AnalyzerAction, type CoverageReport, type Mutant, type PolicyInput } from './index';

const leaf = (field: string, op: string, value?: unknown, extra: object = {}) => ({ field, op, value, ...extra }) as unknown as Condition;
const pred = (verb: string, where?: Condition[], resource?: string) => ({ verb, ...(resource !== undefined ? { resource } : {}), ...(where ? { where } : {}) }) as unknown as Predicate;
const act = (verb: string, params?: Record<string, unknown>, resource = '/r'): AnalyzerAction => ({ verb, resource, ...(params ? { params } : {}) });
const N = (op: string, v: unknown) => leaf('action.params.n', op, v);
const M = (op: string, v: unknown) => leaf('action.params.m', op, v);
const DEAD = (): Condition[] => [N('gte', 10), N('lte', 1)];
const REF = () => leaf('action.params.n', 'lt', 5, { ref: 'env.y' });

const ids = (r: CoverageReport): string[] => r.mutants.survivors.map((s: Mutant) => s.id);
const shape = (r: CoverageReport) => r.mutants.survivors.map((s: Mutant) => ({ id: s.id, description: s.description }));
const without = (all: string[], gone: string[]): string[] => all.filter((x) => !gone.includes(x));

describe('permitId', () => {
  it('names a permit by index', () => {
    expect(permitId(0)).toBe('permit[0]');
    expect(permitId(12)).toBe('permit[12]');
  });
});

describe('witnessOf: the clause that decided', () => {
  const a = (risk: number): AnalyzerAction => act('a', { risk });
  const risk = (op: string, v: number) => leaf('action.params.risk', op, v);

  it('a deny prohibition beats an earlier approval prohibition', () => {
    const m = toModel({
      predicates: [pred('a')],
      vetoes: [
        { id: 'ap', kind: 'approval', when: pred('a') },
        { id: 'dn', kind: 'deny', when: pred('a', [leaf('action.params.block', 'eq', 1)]) },
      ],
    });
    expect(witnessOf(m, act('a', { block: 1 }))).toEqual({ decision: 'deny', winner: { kind: 'veto', id: 'dn' }, also: ['permit[0]', 'ap'] });
    expect(witnessOf(m, act('a', { block: 0 }))).toEqual({ decision: 'escalate', winner: { kind: 'veto', id: 'ap' }, also: ['permit[0]'] });
  });

  it('tighten rules: only rules that hold or cannot be decided are listed; the deny rule decides a deny', () => {
    const m = toModel({
      predicates: [pred('a')],
      tighten: [
        { id: 't1', when: risk('gt', 5), signal: 'escalate' },
        { id: 't2', when: risk('gt', 8), signal: 'deny' },
        { id: 't3', when: { all_of: [] }, signal: 'escalate' },
      ],
    });
    expect(witnessOf(m, a(1))).toEqual({ decision: 'escalate', winner: { kind: 'tighten', id: 't3' }, also: ['permit[0]'] });
    expect(witnessOf(m, a(6))).toEqual({ decision: 'escalate', winner: { kind: 'tighten', id: 't1' }, also: ['permit[0]', 't3'] });
    expect(witnessOf(m, a(9))).toEqual({ decision: 'deny', winner: { kind: 'tighten', id: 't2' }, also: ['permit[0]', 't1', 't3'] });
  });

  it('a reversibility cap that denies is attributed to the caveats', () => {
    const m = toModel({ predicates: [pred('a')], caveats: [{ type: 'reversibility_max', class: 'reversible' }] as never });
    expect(witnessOf(m, { verb: 'a', resource: '/r', reversibilityClass: 'irreversible' })).toEqual({ decision: 'deny', winner: { kind: 'caveat', id: 'caveats' }, also: ['permit[0]'] });
  });

  it('an unsatisfiable caveat set is the winner even when no permit matches', () => {
    const m = toModel({ predicates: [pred('a')], caveats: [{ type: 'rate', max: 0, per_secs: 1 }] as never });
    expect(witnessOf(m, act('zz'))).toEqual({ decision: 'deny', winner: { kind: 'caveat', id: 'caveats' }, also: [] });
    expect(witnessOf(m, act('a'))).toEqual({ decision: 'deny', winner: { kind: 'caveat', id: 'caveats' }, also: ['permit[0]'] });
  });

  it('an escalation that comes only from an ancestor has no clause id', () => {
    const m = toModel({ predicates: [pred('a')], meet: [{ predicates: [pred('a')], tighten: [{ id: 'up', when: risk('gt', 5), signal: 'escalate' }] }] });
    expect(witnessOf(m, a(9))).toEqual({ decision: 'escalate', winner: { kind: 'tighten', id: null }, also: ['permit[0]'] });
  });
});

describe('coverage: clauses, counts and scores', () => {
  const p2: PolicyInput = {
    predicates: [pred('a')],
    tighten: [
      { id: 't1', when: leaf('action.params.risk', 'gt', 5), signal: 'escalate' },
      { id: 't2', when: leaf('action.params.risk', 'gt', 8), signal: 'deny' },
      { id: 't3', when: { all_of: [] }, signal: 'escalate' },
    ],
  };

  it('counts matched and decisive per clause, with tighten rules as clauses', () => {
    const r = coverage(p2, [act('a', { risk: 1 }), act('a', { risk: 9 })]);
    expect(r.traffic).toBe(2);
    expect(r.clauses).toEqual([
      { id: 'permit[0]', kind: 'permit', matched: 2, decisive: 0, reachable: true },
      { id: 't1', kind: 'tighten', matched: 1, decisive: 0, reachable: 'unknown' },
      { id: 't2', kind: 'tighten', matched: 1, decisive: 1, reachable: 'unknown' },
      { id: 't3', kind: 'tighten', matched: 2, decisive: 1, reachable: 'unknown' },
    ]);
    expect(r.neverMatched).toEqual([]);
    expect(r.neverDecisive).toEqual(['permit[0]', 't1']);
    expect(r.untested).toEqual([]);
    expect(r.unreachable).toEqual([]);
    expect(r.score.clauses).toBe(0.5);
    expect(r.boundaries).toEqual([
      { path: 'action.params.risk', threshold: 5, below: false, at: false, above: false },
      { path: 'action.params.risk', threshold: 8, below: false, at: false, above: true },
    ]);
  });

  it('reachability per clause kind: decided, dead, and over-approximated', () => {
    const like = leaf('action.params.s', 'like', 'x*');
    const p: PolicyInput = {
      predicates: [pred('a'), pred('d', DEAD()), pred('l', [...DEAD(), like])],
      vetoes: [
        { id: 'v-dead', kind: 'deny', when: pred('a', DEAD()) },
        { id: 'v-live', kind: 'deny', when: pred('a', undefined, '/f') },
        { id: 'v-like', kind: 'deny', when: pred('a', [...DEAD(), like]) },
      ],
      tighten: [{ id: 't1', when: leaf('action.params.risk', 'gt', 5), signal: 'escalate' }],
    };
    const r = coverage(p, [], { maxMutants: 0 });
    expect(r.clauses.map((c) => [c.id, c.kind, c.reachable])).toEqual([
      ['permit[0]', 'permit', true],
      ['permit[1]', 'permit', false],
      ['permit[2]', 'permit', 'unknown'],
      ['v-dead', 'veto', false],
      ['v-live', 'veto', true],
      ['v-like', 'veto', 'unknown'],
      ['t1', 'tighten', 'unknown'],
    ]);
    expect(r.unreachable).toEqual(['permit[1]', 'v-dead']);
    expect(r.untested).toEqual(['permit[0]', 'permit[2]', 'v-live', 'v-like', 't1']);
  });

  it('an unreachable clause is left out of the clause score and the untested list', () => {
    const r = coverage({ predicates: [pred('a'), pred('d', DEAD())] }, [act('a')], { maxMutants: 0 });
    expect(r.clauses.map((c) => [c.id, c.matched, c.decisive, c.reachable])).toEqual([['permit[0]', 1, 1, true], ['permit[1]', 0, 0, false]]);
    expect(r.score.clauses).toBe(1);
    expect(r.neverMatched).toEqual(['permit[1]']);
    expect(r.neverDecisive).toEqual(['permit[1]']);
    expect(r.untested).toEqual([]);
    expect(r.unreachable).toEqual(['permit[1]']);
  });

  it('an empty policy scores 1 on every ratio', () => {
    expect(coverage({ predicates: [] }, []).score).toEqual({ clauses: 1, boundaries: 1, mutation: 1 });
  });

  it('a mutant proven equivalent is removed from the mutation denominator', () => {
    const p: PolicyInput = { predicates: [pred('v', [N('lte', 5), N('lte', 9)])] };
    const traffic = [5, 6, 4, 9, 10, 8].map((n) => act('v', { n }));
    const r = coverage(p, traffic);
    expect(r.mutants.equivalent).toBeGreaterThan(0);
    expect(r.mutants.survivors).toEqual([]);
    expect(r.mutants.killed).toBe(r.mutants.total - r.mutants.equivalent);
    expect(r.score.mutation).toBe(1);
  });
});

describe('coverage: boundaries', () => {
  const one: PolicyInput = { predicates: [pred('v', [N('lt', 10)])] };
  const row = (r: CoverageReport) => r.boundaries.map((b) => [b.threshold, b.below, b.at, b.above]);

  it('below, at and above are exact neighbours of the threshold, from numeric traffic only', () => {
    const run = (ns: unknown[], o = {}) => row(coverage(one, ns.map((n) => act('v', { n })), { maxMutants: 0, ...o }));
    expect(run([10])).toEqual([[10, false, true, false]]);
    expect(run([9])).toEqual([[10, true, false, false]]);
    expect(run([11])).toEqual([[10, false, false, true]]);
    expect(run([8, 12, '9', '11', '10', null])).toEqual([[10, false, false, false]]);
    expect(run([7, 13], { epsilon: 3 })).toEqual([[10, true, false, true]]);
    expect(run([6, 14], { epsilon: 3 })).toEqual([[10, false, false, false]]);
    expect(row(coverage(one, [{ verb: 'v', resource: '/r' }], { maxMutants: 0 }))).toEqual([[10, false, false, false]]);
  });

  it('the boundary score counts only boundaries hit on all three sides', () => {
    const p: PolicyInput = { predicates: [pred('v', ['a', 'b', 'c', 'd'].map((f) => leaf(`action.params.${f}`, 'lt', 10)))] };
    const traffic = [{ a: 10 }, { a: 9 }, { b: 10 }, { b: 11 }, { c: 9 }, { c: 11 }, { d: 9 }, { d: 10 }, { d: 11 }].map((x) => act('v', x));
    const r = coverage(p, traffic, { maxMutants: 0 });
    expect(r.boundaries.map((b) => [b.path, b.below, b.at, b.above])).toEqual([
      ['action.params.a', true, true, false],
      ['action.params.b', false, true, true],
      ['action.params.c', true, false, true],
      ['action.params.d', true, true, true],
    ]);
    expect(r.score.boundaries).toBe(0.25);
  });

  it('collects numeric parameter paths through groups, every comparison op, and prohibition thresholds', () => {
    const p: PolicyInput = {
      predicates: [
        pred('v0', [{ all_of: [leaf('action.params.zlt', 'lt', 1), { any_of: [leaf('action.params.zlte', 'lte', 2), { not: leaf('action.params.zgt', 'gt', 3) }] }] } as Condition]),
        pred('v1', [leaf('action.params.zgte', 'gte', 4), leaf('action.params.zeq', 'eq', 5), leaf('action.params.zin', 'in', [6, 7]), leaf('action.params.znin', 'nin', [8])]),
        pred('v2', [leaf('action.params.zne', 'ne', 9), leaf('action.params.zpre', 'prefix', 'ab'), leaf('subject.sx', 'lt', 10), leaf('foo.action.params.', 'lt', 11)]),
      ],
      vetoes: [{ id: 'ov', kind: 'approval', when: pred('v0'), over: { path: 'env.amt', threshold: 12 } }],
    };
    const r = coverage(p, [], { maxMutants: 0 });
    expect(r.boundaries).toEqual(
      [
        ['action.params.zeq', 5],
        ['action.params.zgt', 3],
        ['action.params.zgte', 4],
        ['action.params.zin', 6],
        ['action.params.zin', 7],
        ['action.params.zlt', 1],
        ['action.params.zlte', 2],
        ['action.params.znin', 8],
        ['env.amt', 12],
      ].map(([path, threshold]) => ({ path, threshold, below: false, at: false, above: false })),
    );
  });

  it('paths come out sorted whatever order the policy names them in', () => {
    const p: PolicyInput = { predicates: [pred('v', [leaf('action.params.z', 'lt', 1), leaf('action.params.a', 'lt', 2)])] };
    expect(coverage(p, [], { maxMutants: 0 }).boundaries.map((b) => b.path)).toEqual(['action.params.a', 'action.params.z']);
  });
});

describe('coverage: mutation operators', () => {
  const OPS: PolicyInput = {
    predicates: [
      pred('v0', [N('lt', 7)]),
      pred('v1', [N('lte', 7)]),
      pred('v2', [N('gt', 7)]),
      pred('v3', [N('gte', 7)]),
      pred('v4', [N('eq', 7)]),
      pred('v5', [N('ne', 7)]),
      pred('v6', [N('in', [1, 2])]),
      pred('v7', [N('nin', [1, 2])]),
      pred('v8', [leaf('action.params.s', 'prefix', 'ab')]),
      pred('v9', [leaf('action.params.s', 'eq', 'abc')]),
      pred('v10', [REF()]),
    ],
  };
  const m = (i: number, what: string) => ({ id: `permit[${i}].where[0]:${what}`, description: `permit[${i}]: ${what}` });
  const dropP = (i: number) => ({ id: `drop-permit[${i}]`, description: `drop permit[${i}]` });
  const dropC = (i: number) => ({ id: `permit[${i}].where[0]:drop`, description: `permit[${i}]: drop condition 0` });
  const numeric = (i: number, op: string, flip: string) => [dropP(i), m(i, `n ${op} 7 -> 8`), m(i, `n ${op} 7 -> 6`), m(i, `n ${op} -> ${flip}`), dropC(i)];
  const flipOnly = (i: number, name: string, op: string, flip: string) => [dropP(i), m(i, `${name} ${op} -> ${flip}`), dropC(i)];

  it('generates the exact mutants for every comparison op', () => {
    const r = coverage(OPS, [], { maxMutants: 1000 });
    expect(shape(r)).toEqual([
      ...numeric(0, 'lt', 'lte'),
      ...numeric(1, 'lte', 'lt'),
      ...numeric(2, 'gt', 'gte'),
      ...numeric(3, 'gte', 'gt'),
      ...numeric(4, 'eq', 'ne'),
      ...flipOnly(5, 'n', 'ne', 'eq'),
      ...flipOnly(6, 'n', 'in', 'nin'),
      ...flipOnly(7, 'n', 'nin', 'in'),
      dropP(8),
      dropC(8),
      ...flipOnly(9, 's', 'eq', 'ne'),
      dropP(10),
      dropC(10),
    ]);
    expect(r.mutants.total).toBe(r.mutants.survivors.length);
    expect(r.mutants.killed).toBe(0);
    expect(r.mutants.equivalent).toBe(0);
  });

  it('a non-finite threshold cannot be digested, so the policy is refused rather than mutated', () => {
    expect(() => coverage({ predicates: [pred('v', [N('lt', Infinity)])] }, [], { maxMutants: 1000 })).toThrow('canonicalize: non-finite number');
  });

  it('the epsilon option sets the numeric step', () => {
    const r = coverage({ predicates: [pred('v', [N('lt', 10)])] }, [], { epsilon: 5 });
    expect(ids(r)).toEqual(['drop-permit[0]', 'permit[0].where[0]:n lt 10 -> 15', 'permit[0].where[0]:n lt 10 -> 5', 'permit[0].where[0]:n lt -> lte', 'permit[0].where[0]:drop']);
  });

  it('names a parameter condition by the parameter, stripping only a leading action.params.', () => {
    const p: PolicyInput = { predicates: [pred('rx', [leaf('env.action.params.q', 'lt', 3)]), pred('r', [REF()])] };
    expect(ids(coverage(p, [], { maxMutants: 1000 }))).toEqual([
      'drop-permit[0]',
      'permit[0].where[0]:env.action.params.q lt 3 -> 4',
      'permit[0].where[0]:env.action.params.q lt 3 -> 2',
      'permit[0].where[0]:env.action.params.q lt -> lte',
      'permit[0].where[0]:drop',
      'drop-permit[1]',
      'permit[1].where[0]:drop',
    ]);
  });

  it('mutates nested groups with the path to the changed child', () => {
    const where = [
      {
        all_of: [N('lt', 10), { any_of: [M('gte', 5), { not: leaf('action.params.k', 'eq', 'x') }] }],
      } as Condition,
    ];
    const r = coverage({ predicates: [pred('v', where), pred('r', [REF()])] }, [], { maxMutants: 1000 });
    const g = (what: string) => ({ id: `permit[0].where[0]:${what}`, description: `permit[0]: ${what}` });
    expect(shape(r)).toEqual([
      dropP(0),
      g('all_of[0] n lt 10 -> 11'),
      g('all_of[0] n lt 10 -> 9'),
      g('all_of[0] n lt -> lte'),
      g('all_of[1] any_of[0] m gte 5 -> 6'),
      g('all_of[1] any_of[0] m gte 5 -> 4'),
      g('all_of[1] any_of[0] m gte -> gt'),
      g('all_of[1] any_of[1] not(k eq -> ne)'),
      dropC(0),
      dropP(1),
      dropC(1),
    ]);
  });

  it('a condition that is not a plain comparison yields no variants, and cannot break the walk', () => {
    const p: PolicyInput = { predicates: [pred('z', [null as never]), pred('y', [{} as Condition]), pred('x', [5 as never]), pred('r', [REF()])] };
    const r = coverage(p, [], { maxMutants: 1000 });
    expect(r.mutants.total).toBe(8);
    expect(ids(r).filter((i) => i.includes('undefined'))).toEqual([]);
  });

  it('a predicate with no conditions only has its drop mutant', () => {
    const r = coverage({ predicates: [pred('v'), pred('r', [REF()])] }, [], { maxMutants: 1000 });
    expect(ids(r)).toEqual(['drop-permit[0]', 'drop-permit[1]', 'permit[1].where[0]:drop']);
  });

  it('a cross-field reference condition gets no value or operator variants', () => {
    const r = coverage({ predicates: [pred('v', [REF()])] }, [], { maxMutants: 1000 });
    expect(ids(r)).toEqual(['drop-permit[0]', 'permit[0].where[0]:drop']);
  });

  it('caps the number of mutants (200 by default)', () => {
    const p: PolicyInput = { predicates: Array.from({ length: 41 }, (_, i) => pred(`v${i}`, [N('lt', 5)])) };
    expect(coverage(p, []).mutants.total).toBe(200);
    expect(coverage(p, [], { maxMutants: 3 }).mutants.total).toBe(3);
    expect(coverage(p, [], { maxMutants: 0 }).mutants.total).toBe(0);
    expect(coverage(p, [], { maxMutants: 1000 }).mutants.total).toBe(205);
  });
});

describe('coverage: which traffic kills which mutant', () => {
  const outcome = (policy: PolicyInput, traffic: AnalyzerAction[]) => {
    const r = coverage(policy, traffic, { maxMutants: 1000 });
    return { killed: r.mutants.killed, equivalent: r.mutants.equivalent, survivors: ids(r) };
  };
  const at = (n: number, m?: number): AnalyzerAction => act('v', m === undefined ? { n } : { n, m });

  it('all_of: each child is replaced in place', () => {
    const p: PolicyInput = { predicates: [pred('v', [{ all_of: [N('lt', 10), M('lt', 20)] } as Condition])] };
    const w = (s: string) => `permit[0].where[0]:${s}`;
    const ALL = ['drop-permit[0]', w('all_of[0] n lt 10 -> 11'), w('all_of[0] n lt 10 -> 9'), w('all_of[0] n lt -> lte'), w('all_of[1] m lt 20 -> 21'), w('all_of[1] m lt 20 -> 19'), w('all_of[1] m lt -> lte'), w('drop')];
    const table: Array<[AnalyzerAction, string[]]> = [
      [at(5, 100), [w('drop')]],
      [at(10, 0), [w('all_of[0] n lt 10 -> 11'), w('all_of[0] n lt -> lte'), w('drop')]],
      [at(0, 20), [w('all_of[1] m lt 20 -> 21'), w('all_of[1] m lt -> lte'), w('drop')]],
      [at(9, 0), ['drop-permit[0]', w('all_of[0] n lt 10 -> 9')]],
      [at(0, 19), ['drop-permit[0]', w('all_of[1] m lt 20 -> 19')]],
    ];
    for (const [a, killed] of table) expect(outcome(p, [a])).toEqual({ killed: killed.length, equivalent: 0, survivors: without(ALL, killed) });
  });

  it('any_of: each child is replaced in place', () => {
    const p: PolicyInput = { predicates: [pred('v', [{ any_of: [N('gt', 10), M('gt', 20)] } as Condition])] };
    const w = (s: string) => `permit[0].where[0]:${s}`;
    const ALL = ['drop-permit[0]', w('any_of[0] n gt 10 -> 11'), w('any_of[0] n gt 10 -> 9'), w('any_of[0] n gt -> gte'), w('any_of[1] m gt 20 -> 21'), w('any_of[1] m gt 20 -> 19'), w('any_of[1] m gt -> gte'), w('drop')];
    const table: Array<[AnalyzerAction, string[]]> = [
      [at(0, 0), [w('drop')]],
      [at(10, 0), [w('any_of[0] n gt 10 -> 9'), w('any_of[0] n gt -> gte'), w('drop')]],
      [at(11, 0), ['drop-permit[0]', w('any_of[0] n gt 10 -> 11')]],
      [at(0, 20), [w('any_of[1] m gt 20 -> 19'), w('any_of[1] m gt -> gte'), w('drop')]],
      [at(0, 21), ['drop-permit[0]', w('any_of[1] m gt 20 -> 21')]],
    ];
    for (const [a, killed] of table) expect(outcome(p, [a])).toEqual({ killed: killed.length, equivalent: 0, survivors: without(ALL, killed) });
  });

  it('not: the negated condition is mutated inside the negation', () => {
    const p: PolicyInput = { predicates: [pred('v', [{ not: N('gte', 10) } as Condition])] };
    const w = (s: string) => `permit[0].where[0]:${s}`;
    const ALL = ['drop-permit[0]', w('not(n gte 10 -> 11)'), w('not(n gte 10 -> 9)'), w('not(n gte -> gt)'), w('drop')];
    expect(outcome(p, [at(10)])).toEqual({ killed: 3, equivalent: 0, survivors: ['drop-permit[0]', w('not(n gte 10 -> 9)')] });
    expect(outcome(p, [at(9)])).toEqual({ killed: 2, equivalent: 0, survivors: without(ALL, ['drop-permit[0]', w('not(n gte 10 -> 9)')]) });
  });

  it('a permit with several conditions: a mutant changes or drops exactly one of them', () => {
    const p: PolicyInput = { predicates: [pred('v', [N('lt', 10), M('lt', 20)])] };
    const w = (j: number, s: string) => `permit[0].where[${j}]:${s}`;
    const ALL = ['drop-permit[0]', w(0, 'n lt 10 -> 11'), w(0, 'n lt 10 -> 9'), w(0, 'n lt -> lte'), w(0, 'drop'), w(1, 'm lt 20 -> 21'), w(1, 'm lt 20 -> 19'), w(1, 'm lt -> lte'), w(1, 'drop')];
    const table: Array<[AnalyzerAction, string[]]> = [
      [at(50, 5), [w(0, 'drop')]],
      [at(5, 20), [w(1, 'm lt 20 -> 21'), w(1, 'm lt -> lte'), w(1, 'drop')]],
      [at(10, 0), [w(0, 'n lt 10 -> 11'), w(0, 'n lt -> lte'), w(0, 'drop')]],
      [at(9, 19), ['drop-permit[0]', w(0, 'n lt 10 -> 9'), w(1, 'm lt 20 -> 19')]],
    ];
    for (const [a, killed] of table) expect(outcome(p, [a])).toEqual({ killed: killed.length, equivalent: 0, survivors: without(ALL, killed) });
  });

  it('with several permits a mutant only touches its own permit', () => {
    const p: PolicyInput = { predicates: [pred('a', [N('lt', 10)]), pred('b', [N('lt', 10)])] };
    const w = (i: number, s: string) => `permit[${i}].where[0]:${s}`;
    const ALL = ['drop-permit[0]', w(0, 'n lt 10 -> 11'), w(0, 'n lt 10 -> 9'), w(0, 'n lt -> lte'), w(0, 'drop'), 'drop-permit[1]', w(1, 'n lt 10 -> 11'), w(1, 'n lt 10 -> 9'), w(1, 'n lt -> lte'), w(1, 'drop')];
    const table: Array<[AnalyzerAction, string[]]> = [
      [act('a', { n: 10 }), [w(0, 'n lt 10 -> 11'), w(0, 'n lt -> lte'), w(0, 'drop')]],
      [act('a', { n: 5 }), ['drop-permit[0]']],
      [act('b', { n: 10 }), [w(1, 'n lt 10 -> 11'), w(1, 'n lt -> lte'), w(1, 'drop')]],
      [act('b', { n: 5 }), ['drop-permit[1]']],
    ];
    for (const [a, killed] of table) expect(outcome(p, [a])).toEqual({ killed: killed.length, equivalent: 0, survivors: without(ALL, killed) });
  });

  it('prohibitions: dropping one, and raising a threshold by one step', () => {
    const p: PolicyInput = {
      predicates: [pred('v'), pred('r', [REF()])],
      vetoes: [
        { id: 'frozen', kind: 'deny', when: pred('v', undefined, '/f') },
        { id: 'big', kind: 'approval', when: pred('v'), over: { path: 'action.params.n', threshold: 300 } },
      ],
    };
    const ALL = ['drop-permit[0]', 'drop-permit[1]', 'permit[1].where[0]:drop', 'drop-veto:frozen', 'drop-veto:big', 'veto:big:threshold+'];
    const r0 = coverage(p, [], { maxMutants: 1000 });
    expect(shape(r0)).toEqual([
      { id: 'drop-permit[0]', description: 'drop permit[0]' },
      { id: 'drop-permit[1]', description: 'drop permit[1]' },
      { id: 'permit[1].where[0]:drop', description: 'permit[1]: drop condition 0' },
      { id: 'drop-veto:frozen', description: 'drop prohibition frozen' },
      { id: 'drop-veto:big', description: 'drop prohibition big' },
      { id: 'veto:big:threshold+', description: 'raise the big threshold by 1' },
    ]);
    expect(outcome(p, [act('v', { n: 300 }, '/ok')])).toEqual({ killed: 1, equivalent: 0, survivors: without(ALL, ['drop-permit[0]']) });
    expect(outcome(p, [act('v', { n: 301 }, '/ok')])).toEqual({ killed: 3, equivalent: 0, survivors: without(ALL, ['drop-permit[0]', 'drop-veto:big', 'veto:big:threshold+']) });
    expect(outcome(p, [act('v', { n: 300 }, '/f')])).toEqual({ killed: 1, equivalent: 0, survivors: without(ALL, ['drop-veto:frozen']) });
  });

  it('an approval prohibition that is only dropped is equivalent for admission', () => {
    const p: PolicyInput = {
      predicates: [pred('v')],
      vetoes: [
        { id: 'frozen', kind: 'deny', when: pred('v', undefined, '/f') },
        { id: 'big', kind: 'approval', when: pred('v'), over: { path: 'action.params.n', threshold: 300 } },
      ],
    };
    expect(outcome(p, [])).toEqual({ killed: 0, equivalent: 2, survivors: ['drop-permit[0]', 'drop-veto:frozen'] });
    expect(outcome(p, [act('v', { n: 300 }, '/ok')])).toEqual({ killed: 1, equivalent: 2, survivors: ['drop-veto:frozen'] });
    expect(outcome(p, [act('v', { n: 300 }, '/f')])).toEqual({ killed: 1, equivalent: 2, survivors: ['drop-permit[0]'] });
  });

  it('tighten rules: dropping one', () => {
    const p: PolicyInput = {
      predicates: [pred('v'), pred('r', [REF()])],
      tighten: [
        { id: 't1', when: leaf('action.params.risk', 'gt', 5), signal: 'escalate' },
        { id: 't2', when: leaf('action.params.risk', 'gt', 8), signal: 'deny' },
      ],
    };
    const ALL = ['drop-permit[0]', 'drop-permit[1]', 'permit[1].where[0]:drop', 'drop-tighten:t1', 'drop-tighten:t2'];
    expect(shape(coverage(p, [], { maxMutants: 1000 })).slice(3)).toEqual([
      { id: 'drop-tighten:t1', description: 'drop tighten rule t1' },
      { id: 'drop-tighten:t2', description: 'drop tighten rule t2' },
    ]);
    const risk = (risk: number) => act('v', { risk });
    expect(outcome(p, [risk(9)])).toEqual({ killed: 1, equivalent: 0, survivors: without(ALL, ['drop-tighten:t2']) });
    expect(outcome(p, [risk(6)])).toEqual({ killed: 2, equivalent: 0, survivors: without(ALL, ['drop-permit[0]', 'drop-tighten:t1']) });
    expect(outcome(p, [risk(1)])).toEqual({ killed: 1, equivalent: 0, survivors: without(ALL, ['drop-permit[0]']) });
  });
});

describe('coverageGate', () => {
  const survivors: Mutant[] = [1, 2, 3].map((i) => ({ id: `m${i}`, description: `d${i}` }));
  const report = (score: CoverageReport['score'], unreachable: string[] = []): CoverageReport => ({
    traffic: 0,
    policyDigest: 'd',
    clauses: [],
    neverMatched: [],
    neverDecisive: [],
    untested: [],
    unreachable,
    boundaries: [],
    mutants: { total: 5, killed: 1, equivalent: 0, survivors },
    score,
  });

  it('reports every failed threshold with its exact message', () => {
    const g = coverageGate(report({ clauses: 0.5, boundaries: 0.25, mutation: 0.2 }, ['a', 'b']), { clauses: 0.9, boundaries: 0.5, mutation: 0.8, maxSurvivors: 1 });
    expect(g).toEqual({
      ok: false,
      reasons: ['clause coverage 0.50 < 0.9', 'boundary coverage 0.25 < 0.5', 'mutation score 0.20 < 0.8', '3 surviving mutants > 1', 'unreachable clauses: a, b'],
    });
  });

  it('each threshold fails on its own, and passes at the limit', () => {
    const s = { clauses: 0.5, boundaries: 0.25, mutation: 0.2 };
    expect(coverageGate(report(s), { boundaries: 0.5 }).reasons).toEqual(['boundary coverage 0.25 < 0.5']);
    expect(coverageGate(report(s), { mutation: 0.8 }).reasons).toEqual(['mutation score 0.20 < 0.8']);
    expect(coverageGate(report(s), { maxSurvivors: 2 }).reasons).toEqual(['3 surviving mutants > 2']);
    expect(coverageGate(report(s), { clauses: 0.5, boundaries: 0.25, mutation: 0.2, maxSurvivors: 3 })).toEqual({ ok: true, reasons: [] });
    expect(coverageGate(report(s))).toEqual({ ok: true, reasons: [] });
    expect(coverageGate(report({ clauses: 0, boundaries: 0, mutation: 0 }), {})).toEqual({ ok: true, reasons: [] });
  });
});
