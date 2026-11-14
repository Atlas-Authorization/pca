import { describe, expect, it } from 'vitest';
import type { AccumulatorDecl, IntentEvent, MonitorDecl, UnsignedActionSchema } from '@atlasauth/pca/ext/intent';
import {
  accDimPath,
  augmentOmega,
  defaultAccumulators,
  describeAccCell,
  dimKindOf,
  liftAction,
  liftedCell,
  monDimPath,
  stepTrajectory,
  trajectoryHarmRange,
  type CatDim,
  type Dim,
  type NumDim,
  type Omega,
  type Psi,
  type VerbSpace,
} from './index';

const HOLDER = { kind: 'site_local' } as const;
const acc = (over: Partial<AccumulatorDecl> & { id: string }): AccumulatorDecl => ({ agg: 'count', sel: { verbs: [] }, win: { kind: 'task' }, key: null, holder: HOLDER, ...over });
const mon = (over: Partial<MonitorDecl> & { id: string }): MonitorDecl => ({ kind: 'never', p: { verb: 'a' }, ...over });
const cat = (path: string): CatDim => ({ kind: 'cat', path, values: [{ kind: 'exact', value: 'x' }, { kind: 'other', value: '⊥' }] });
const num = (path: string, hi = 10, cuts: number[] = []): NumDim => ({ kind: 'num', path, lo: 0, hi, cuts, dist: 'uniform' });
const vsOf = (verb: string, dims: Dim[]): VerbSpace => ({ verb, reversibility: 'reversible', weight: 1, dims });
const omegaOf = (...verbs: VerbSpace[]): Omega => ({ v: 1, approximate: [], verbs });
const pathsOf = (o: Omega, verb: string): string[] => o.verbs.find((v) => v.verb === verb)!.dims.map((d) => d.path);

describe('dimKindOf', () => {
  it('names the kind of every path family, matching by prefix only', () => {
    expect(dimKindOf('action.params.x')).toBe('param');
    expect(dimKindOf('env.acc.x.post')).toBe('acc');
    expect(dimKindOf('env.mon.x.state')).toBe('mon');
    expect(dimKindOf('env.canon.x')).toBe('canon');
    expect(dimKindOf('env.world.x')).toBe('world');
    expect(dimKindOf('env.rel.x')).toBe('rel');
    expect(dimKindOf('env.prov.x')).toBe('prov');
    expect(dimKindOf('env.class.x')).toBe('class');
    expect(dimKindOf('env.hour')).toBe('other');
    expect(dimKindOf('action.resource')).toBe('other');
  });

  it('does not match a family name that only appears at the end of the path', () => {
    for (const fam of ['env.canon.', 'env.world.', 'env.rel.', 'env.prov.', 'env.class.']) expect(dimKindOf(`zz.${fam}`)).toBe('other');
  });
});

describe('augmentOmega', () => {
  it('copies approximate, replaces earlier accumulator and monitor dimensions and keeps the dimensions sorted', () => {
    const base: Omega = {
      v: 1,
      approximate: ['regex'],
      verbs: [vsOf('v', [cat('subject.z'), num('action.params.amount'), num(accDimPath('old')), cat(monDimPath('old'))])],
    };
    const o = augmentOmega(base, { accumulators: [acc({ id: 'spend', agg: 'sum', domain_max: 100 })], monitors: [mon({ id: 'm' })] });
    expect(o.approximate).toEqual(['regex']);
    expect(o.approximate).not.toBe(base.approximate);
    expect(o.verbs).toEqual([
      {
        verb: 'v',
        reversibility: 'reversible',
        weight: 1,
        dims: [
          num('action.params.amount'),
          { kind: 'num', path: 'env.acc.spend.post', lo: 0, hi: 100, cuts: [], dist: 'loguniform' },
          { kind: 'cat', path: 'env.mon.m.state', values: [{ kind: 'exact', value: 'clean' }, { kind: 'exact', value: 'seen' }] },
          cat('subject.z'),
        ],
      },
    ]);
  });

  it('keeps only the safe-integer cuts inside [0, A], de-duplicated and sorted, and tolerates absent cut tables', () => {
    const base = omegaOf(vsOf('v', []));
    const psi: Psi = { accumulators: [acc({ id: 'a', domain_max: 100 }), acc({ id: 'b', domain_max: 7 })], monitors: [] };
    const o = augmentOmega(base, psi, { cuts: { a: [50, 0, 100, 100, 7.5, -1, 101, 10, Number.NaN, 2 ** 60] } });
    const dims = o.verbs[0]!.dims as NumDim[];
    expect(dims.map((d) => [d.path, d.cuts])).toEqual([
      ['env.acc.a.post', [0, 10, 50, 100]],
      ['env.acc.b.post', []],
    ]);
    expect(augmentOmega(base, psi, {}).verbs[0]!.dims.map((d) => d.path)).toEqual(['env.acc.a.post', 'env.acc.b.post']);
    expect(augmentOmega(base, psi).verbs[0]!.dims.map((d) => d.path)).toEqual(['env.acc.a.post', 'env.acc.b.post']);
  });

  it('adds every non-wallet accumulator to every verb unless the scope is selected', () => {
    const base = omegaOf(vsOf('book', []), vsOf('tip', []), vsOf('pay', []));
    const psi: Psi = {
      accumulators: [
        acc({ id: 'u', agg: 'sum', sel: { accumulates_into: 'usd' }, domain_max: 1000 }),
        acc({ id: 'p', sel: { verbs: ['pay'] }, domain_max: 50 }),
        acc({ id: 'e', sel: { event: 'question' }, domain_max: 9 }),
        acc({ id: 'q', sel: { event: 'intent_required' }, cap: 6, holder: { kind: 'wallet' } }),
      ],
      monitors: [],
    };
    for (const opts of [undefined, {}, { scope: 'all' as const }]) {
      const o = augmentOmega(base, psi, opts);
      for (const verb of ['book', 'tip', 'pay']) expect(pathsOf(o, verb)).toEqual(['env.acc.e.post', 'env.acc.p.post', 'env.acc.u.post']);
    }
  });

  it('with the selected scope, an accumulator is a dimension only of the verbs it selects', () => {
    const base = omegaOf(vsOf('book', []), vsOf('tip', []), vsOf('pay', []));
    const schema: UnsignedActionSchema = {
      v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1',
      verbs: [
        { verb: 'tip', kind: 'write', params: { 'action.params.amount': { type: 'integer', semantic: 'money.amount', sensitivity: 'free' } } },
        { verb: 'book', kind: 'write', params: { 'action.params.total': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['usd'] } } },
      ],
    };
    const psi: Psi = {
      accumulators: [
        acc({ id: 'u', agg: 'sum', sel: { accumulates_into: 'usd' }, domain_max: 1000 }),
        acc({ id: 'p', sel: { verbs: ['pay'] }, domain_max: 50 }),
        acc({ id: 'e', sel: { event: 'question' }, domain_max: 9 }),
        acc({ id: 'q', sel: { event: 'intent_required' }, cap: 6, holder: { kind: 'wallet' } }),
      ],
      monitors: [],
    };
    const o = augmentOmega(base, psi, { scope: 'selected', schema: { verbs: schema.verbs } });
    expect(pathsOf(o, 'book')).toEqual(['env.acc.u.post']);
    expect(pathsOf(o, 'tip')).toEqual([]);
    expect(pathsOf(o, 'pay')).toEqual(['env.acc.p.post']);
    // without a schema nothing is selected through accumulates_into
    const bare = augmentOmega(base, psi, { scope: 'selected' });
    expect(pathsOf(bare, 'book')).toEqual([]);
    expect(pathsOf(bare, 'pay')).toEqual(['env.acc.p.post']);
  });

  it('with the selected scope, an accumulator without accumulates_into never selects through the schema', () => {
    const base = omegaOf(vsOf('book', []));
    // a schema entry whose unit list holds an undefined slot must not match a selector that names no unit
    const holes = [undefined] as unknown as string[];
    const verbs: UnsignedActionSchema['verbs'] = [
      { verb: 'book', kind: 'write', params: { 'action.params.total': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', accumulates_into: holes } } },
    ];
    const psi: Psi = { accumulators: [acc({ id: 'p', sel: { verbs: ['pay'] }, domain_max: 50 })], monitors: [] };
    expect(pathsOf(augmentOmega(base, psi, { scope: 'selected', schema: { verbs } }), 'book')).toEqual([]);
  });

  it('adds a monitor to every verb, or with the selected scope only to the verbs of its guarded predicate', () => {
    const base = omegaOf(vsOf('book', []), vsOf('tip', []), vsOf('pay', []));
    const psi: Psi = {
      accumulators: [],
      monitors: [
        mon({ id: 'm1', kind: 'requires_prior', p: { verb: 'a' }, q: { verb: 'pay' } }),
        mon({ id: 'm2', kind: 'requires_prior', p: { verb: 'a' }, q: { verb: ['tip', 'book'] } }),
        mon({ id: 'm3', kind: 'precedes', p: { verb: 'a' }, q: { verb: '*' } }),
        mon({ id: 'm4', kind: 'never', p: { verb: 'a' } }),
      ],
    };
    const all = augmentOmega(base, psi);
    for (const verb of ['book', 'tip', 'pay']) expect(pathsOf(all, verb)).toEqual(['env.mon.m1.state', 'env.mon.m2.state', 'env.mon.m3.state', 'env.mon.m4.state']);
    const sel = augmentOmega(base, psi, { scope: 'selected' });
    expect(pathsOf(sel, 'book')).toEqual(['env.mon.m2.state', 'env.mon.m3.state', 'env.mon.m4.state']);
    expect(pathsOf(sel, 'tip')).toEqual(['env.mon.m2.state', 'env.mon.m3.state', 'env.mon.m4.state']);
    expect(pathsOf(sel, 'pay')).toEqual(['env.mon.m1.state', 'env.mon.m3.state', 'env.mon.m4.state']);
    expect(sel.verbs[2]!.dims[0]).toEqual({ kind: 'cat', path: 'env.mon.m1.state', values: [{ kind: 'exact', value: 'unmet' }, { kind: 'exact', value: 'met' }] });
  });
});

// ---- lifting an action -----------------------------------------------------------------------------------------

const SCHEMA: UnsignedActionSchema = {
  v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1',
  verbs: [
    { verb: 'pay', kind: 'write', params: { 'action.params.other': { type: 'integer', semantic: 'count.items', sensitivity: 'free' } } },
    {
      verb: 'book',
      kind: 'write',
      params: {
        'action.params.flag': { type: 'boolean', semantic: 'flag.any', sensitivity: 'material' },
        'action.params.tags': { type: 'set', semantic: 'tag.any', sensitivity: 'material', values: ['a', 'b'] },
        'action.params.absent': { type: 'boolean', semantic: 'flag.any', sensitivity: 'material' },
      },
    },
  ],
};
const PSI: Psi = {
  accumulators: [
    acc({ id: 'cnt', agg: 'count', sel: { verbs: ['pay'] }, domain_max: 100 }),
    acc({ id: 'total', agg: 'sum', val: 'action.params.n', sel: { verbs: ['book'] }, domain_max: 1000 }),
  ],
  monitors: [mon({ id: 'm0', kind: 'never', p: { verb: 'zzz' } }), mon({ id: 'm1', kind: 'never', p: { verb: 'pay' } })],
};
const HISTORY: IntentEvent[] = [
  { id: 'e1', verb: 'book', resource: 'r', params: { n: 3 }, t: 1, status: 'committed' },
  { id: 'e2', verb: 'pay', resource: 'r', params: {}, t: 2, status: 'reserved' },
];
const BOOK_DIMS: Dim[] = [
  num('action.params.n'),
  cat('action.params.name'),
  cat('action.params.skip'),
  num('action.params.missing'),
  cat('env.canon.flag'),
  cat('env.canon.tags'),
  cat('env.canon.undeclared'),
  cat('env.canon.absent'),
  num(accDimPath('total')),
  num(accDimPath('cnt')),
  num(accDimPath('ghost')),
  cat(monDimPath('m1')),
  cat(monDimPath('m0')),
  cat(monDimPath('ghost')),
  cat('action.resource'),
  cat('env.world.x'),
];
const OT = omegaOf(vsOf('pay', [cat('action.resource'), cat('env.world.x')]), vsOf('book', BOOK_DIMS));

describe('liftAction', () => {
  it('reads every dimension kind from the action and the history', () => {
    const cand = { verb: 'book', resource: 'res/1', params: { n: 4, name: 'bob', skip: true, flag: true, tags: ['b', 'a'], undeclared: 1 }, t: 3 };
    const lifted = liftAction(OT, PSI, HISTORY, cand, SCHEMA);
    expect(lifted).toStrictEqual({
      verb: 'book',
      values: {
        'action.params.n': 4,
        'action.params.name': 'bob',
        'env.canon.flag': 'true',
        'env.canon.tags': '["a","b"]',
        [accDimPath('total')]: 7,
        [accDimPath('cnt')]: 1,
        [monDimPath('m1')]: 'seen',
        [monDimPath('m0')]: 'clean',
        'action.resource': 'res/1',
      },
    });
  });

  it('renders a false boolean and leaves canon dimensions out without a schema declaration', () => {
    const cand = { verb: 'book', resource: 'r', params: { n: 1, flag: false, absent: false }, t: 3 };
    const withSchema = liftAction(OT, PSI, HISTORY, cand, SCHEMA)!;
    expect(withSchema.values['env.canon.flag']).toBe('false');
    expect(withSchema.values['env.canon.absent']).toBe('false');
    const noSchema = liftAction(OT, PSI, HISTORY, cand)!;
    expect(Object.keys(noSchema.values).filter((k) => k.startsWith('env.canon.'))).toEqual([]);
  });

  it('is null for a verb outside the augmented space', () => {
    expect(liftAction(OT, PSI, HISTORY, { verb: 'nope', resource: 'r', params: {}, t: 3 }, SCHEMA)).toBeNull();
  });

  it('uses the declaration of the candidate verb, not the first one', () => {
    const cand = { verb: 'book', resource: 'r', params: { n: 1, flag: true }, t: 3 };
    expect(liftAction(OT, PSI, HISTORY, cand, SCHEMA)!.values['env.canon.flag']).toBe('true');
  });

  it('reads each parameter value once, from an own property', () => {
    let calls = 0;
    // reports an own property on the first query and none on the second
    const flaky = () => {
      calls = 0;
      return new Proxy({}, { getOwnPropertyDescriptor: () => (calls++ % 2 === 0 ? { value: 5, enumerable: true, configurable: true } : undefined) }) as Record<string, unknown>;
    };
    const o = omegaOf(vsOf('book', [num('action.params.n'), cat('env.canon.flag')]));
    expect(liftAction(o, { accumulators: [], monitors: [] }, [], { verb: 'book', resource: 'r', params: flaky(), t: 1 })!.values).toStrictEqual({});
    expect(liftAction(o, { accumulators: [], monitors: [] }, [], { verb: 'book', resource: 'r', params: flaky(), t: 1 }, SCHEMA)!.values).toStrictEqual({ 'env.canon.flag': 'false' });
    const onlyCanon = omegaOf(vsOf('book', [cat('env.canon.flag')]));
    expect(liftAction(onlyCanon, { accumulators: [], monitors: [] }, [], { verb: 'book', resource: 'r', params: flaky(), t: 1 }, SCHEMA)!.values).toStrictEqual({ 'env.canon.flag': 'false' });
  });
});

describe('liftedCell and stepTrajectory', () => {
  const O = omegaOf(vsOf('pay', [num('action.params.n', 10, [5])]), vsOf('book', [num('action.params.n', 10, [5])]));
  const e1: IntentEvent = { id: 'e1', verb: 'book', resource: 'r', params: { n: 1 }, t: 1, status: 'committed' };
  const cand = (n: number) => ({ id: 'c1', verb: 'book', resource: 'r', params: { n }, t: 9 });
  const psi: Psi = { accumulators: [], monitors: [] };

  it('liftedCell finds the verb space and the cell, or fails closed', () => {
    const r = liftedCell(O, { verb: 'book', values: { 'action.params.n': 7 } })!;
    expect(r.vs).toBe(O.verbs[1]);
    expect(r.cell).toEqual([2]);
    expect(liftedCell(O, { verb: 'nope', values: {} })).toBeNull();
    expect(liftedCell(O, { verb: 'book', values: { 'action.params.n': 99 } })).toBeNull();
  });

  it('admits a step the grant accepts and appends a reserved event', () => {
    const calls: [string, number[]][] = [];
    const r = stepTrajectory(O, psi, [e1], cand(3), (v, c) => (calls.push([v, c]), true));
    expect(r.admitted).toBe(true);
    expect(r.lifted).toEqual({ verb: 'book', values: { 'action.params.n': 3 } });
    expect(r.history).toEqual([e1, { id: 'c1', verb: 'book', resource: 'r', params: { n: 3 }, t: 9, status: 'reserved' }]);
    expect(calls).toEqual([['book', [0]]]);
  });

  it('leaves the history unchanged (as a copy) when the grant refuses', () => {
    const history = [e1];
    const r = stepTrajectory(O, psi, history, cand(7), () => false);
    expect(r.admitted).toBe(false);
    expect(r.history).toEqual([e1]);
    expect(r.history).not.toBe(history);
  });

  it('never asks the grant about a point outside the space, or about an unknown verb', () => {
    let asked = 0;
    const inGrant = () => (asked++, true);
    const outside = stepTrajectory(O, psi, [e1], cand(99), inGrant);
    expect(outside.admitted).toBe(false);
    expect(outside.lifted).toEqual({ verb: 'book', values: { 'action.params.n': 99 } });
    expect(outside.history).toEqual([e1]);
    const unknown = stepTrajectory(O, psi, [e1], { ...cand(3), verb: 'nope' }, inGrant);
    expect(unknown.admitted).toBe(false);
    expect(unknown.lifted).toBeNull();
    expect(unknown.history).toEqual([e1]);
    expect(asked).toBe(0);
  });
});

describe('defaultAccumulators', () => {
  const site = { kind: 'site_local' };
  const money = (extra: { accumulates_into?: string[] } = {}) => ({ type: 'integer' as const, semantic: 'money.amount', sensitivity: 'critical' as const, ...extra });
  const schema: UnsignedActionSchema = {
    v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1',
    verbs: [
      { verb: 'z.pay', kind: 'write', params: { 'action.params.total': money({ accumulates_into: ['b.x', 'a.y'] }) } },
      {
        verb: 'z.untagged',
        kind: 'write',
        params: {
          'action.params.amt': money(),
          'action.params.count': { type: 'integer', semantic: 'count.items', sensitivity: 'free' },
          'action.params.note': { type: 'string', semantic: 'money.amount', sensitivity: 'free' },
          'action.params.tagged': money({ accumulates_into: ['a.y'] }),
        },
      },
      { verb: 'a.untagged', kind: 'write', params: { 'action.params.fee': money() } },
      { verb: 'm.untagged', kind: 'write', params: { 'action.params.fee': money() } },
    ],
  };

  it('adds unit sums in unit order, untagged money sums in verb-and-path order, and the question counter', () => {
    expect(defaultAccumulators(schema, { spendDomainMax: 500 })).toEqual([
      { id: 'spend_a_y', agg: 'sum', unit: 'a.y', sel: { accumulates_into: 'a.y' }, win: { kind: 'task' }, key: null, domain_max: 500, holder: site },
      { id: 'spend_b_x', agg: 'sum', unit: 'b.x', sel: { accumulates_into: 'b.x' }, win: { kind: 'task' }, key: null, domain_max: 500, holder: site },
      { id: 'spend_a_untagged_fee', agg: 'sum', val: 'action.params.fee', sel: { verbs: ['a.untagged'] }, win: { kind: 'task' }, key: null, domain_max: 500, holder: site },
      { id: 'spend_m_untagged_fee', agg: 'sum', val: 'action.params.fee', sel: { verbs: ['m.untagged'] }, win: { kind: 'task' }, key: null, domain_max: 500, holder: site },
      { id: 'spend_z_untagged_amt', agg: 'sum', val: 'action.params.amt', sel: { verbs: ['z.untagged'] }, win: { kind: 'task' }, key: null, domain_max: 500, holder: site },
      { id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' } },
    ]);
  });

  it('takes the question cap and the holder from the options', () => {
    const out = defaultAccumulators({ verbs: [] }, { spendDomainMax: 5, questionCap: 3, holder: { kind: 'wallet' } });
    expect(out).toEqual([{ id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 3, holder: { kind: 'wallet' } }]);
  });

  it('truncates long unit and verb names so the ids stay within the id limit', () => {
    const long: UnsignedActionSchema = {
      v: 1, kind: 'pca-action-schema', site: 's', aud: 'a', version: '1',
      verbs: [
        { verb: 'k', kind: 'write', params: { 'action.params.total': money({ accumulates_into: ['u'.repeat(60)] }) } },
        { verb: 'v'.repeat(60), kind: 'write', params: { ['action.params.' + 'p'.repeat(40)]: money() } },
      ],
    };
    const ids = defaultAccumulators(long, { spendDomainMax: 1 }).map((a) => a.id);
    expect(ids).toEqual(['spend_' + 'u'.repeat(58), 'spend_' + 'v'.repeat(58), 'questions']);
  });
});

describe('describeAccCell and trajectoryHarmRange', () => {
  const d = num(accDimPath('spend'), 200, [100]);

  it('renders a single-value cell as exactly and a range as between', () => {
    expect(describeAccCell(d, 1, 'total')).toBe('total: exactly 100');
    expect(describeAccCell(d, 0, 'total')).toBe('total: between 0 and 99');
  });

  it('adds the action amount when given, even zero, and formats amounts with the given function', () => {
    expect(describeAccCell(d, 2, 'total', 0)).toBe('total: between 101 and 200 (this action: 0)');
    expect(describeAccCell(d, 1, 'total', 30, (x) => `$${x}`)).toBe('total: exactly $100 (this action: $30)');
  });

  it('rejects a cell that does not exist', () => {
    expect(() => describeAccCell(d, 3, 'total')).toThrow(new Error('describeAccCell: no such cell'));
  });

  it('multiplies the two bounds and refuses anything that is not a non-negative integer length and a non-negative harm', () => {
    expect(trajectoryHarmRange(8, 10)).toBe(80);
    expect(trajectoryHarmRange(0, 5)).toBe(0);
    expect(trajectoryHarmRange(3, 0)).toBe(0);
    const bad = new Error('trajectoryHarmRange: bad arguments');
    expect(() => trajectoryHarmRange(-1, 1)).toThrow(bad);
    expect(() => trajectoryHarmRange(1.5, 1)).toThrow(bad);
    expect(() => trajectoryHarmRange(2, -1)).toThrow(bad);
    expect(() => trajectoryHarmRange(2, Number.NaN)).toThrow(bad);
    expect(() => trajectoryHarmRange(Number.NaN, 2)).toThrow(bad);
  });
});
