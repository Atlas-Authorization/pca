import { describe, expect, it } from 'vitest';
import { buildSpace, cellKey, cells, mkAct, type Case, type Space } from '../src/examples';
import type { Bound, Cond, Grant, Op, Prohibit, Term, Ty, Value } from '../src/ir';
import { CNT, USD, baseGoal, ctrue, usd } from './fixtures';

const OTH = '\u0000other';
const par = (path: string, ty: Ty): Term => ({ k: 'param', path, ty });
const lit = (v: Value): Term => ({ k: 'lit', v });
const cmp = (op: Op, l: Term, r: Term): Cond => ({ k: 'cmp', op, l, r });
const sv = (s: string): Value => ({ k: 's', s });
const usdV = (n: number): Value => ({ k: 'q', q: usd(n) });
const cntV = (n: number): Value => ({ k: 'q', q: { u: CNT, n } });
const amount = par('amount', { k: 'q', u: USD });
const who = par('who', { k: 's' });

describe('buildSpace: the exact Space of a goal', () => {
  const grants: Grant[] = [
    { gid: 'g1', verb: 'zv', res: { k: 'oneof', ids: ['r2', 'r1'] }, cond: { k: 'and', a: { k: 'and', a: cmp('lte', amount, lit(usdV(10))), b: cmp('gte', amount, lit(usdV(9))) }, b: cmp('lte', amount, lit(usdV(100))) } },
    { gid: 'g2', verb: 'av', res: { k: 'all_of', parts: [{ k: 'exact', id: 'rx' }, { k: 'related', rel: 'B', anchor: 'a' }, { k: 'related', rel: 'C', anchor: 'm' }, { k: 'related', rel: 'A', anchor: 'z' }] }, cond: ctrue },
    { gid: 'g3', verb: 'mv', res: { k: 'any', reason: 'r' }, cond: { k: 'and', a: cmp('eq', who, lit(sv('sb'))), b: cmp('eq', lit(sv('sa')), who) } },
  ];
  const prohibits: Prohibit[] = [
    { pid: 'p1', target: { k: 'verb', verb: 'pv' }, res: { k: 'exact', id: 'rp' }, cond: cmp('eq', par('pp', { k: 's' }), lit(sv('pz'))) },
    { pid: 'p2', target: { k: 'effect', cls: 'money_out' }, res: { k: 'any', reason: 'r' }, cond: ctrue },
  ];
  const bound = (bid: string, agg: Bound['agg'], value: Term, cap: Bound['cap']): Bound => ({ bid, sel: { k: 'gids', gids: ['g1'] }, agg, value, key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap, onExceed: 'deny' });
  const bounds: Bound[] = [
    bound('b1', 'sum', par('tot', { k: 'q', u: USD }), usd(50)),
    bound('b2', 'count', par('cntP', { k: 'q', u: CNT }), { u: CNT, n: 3 }),
    bound('b3', 'sum', lit(sv('z')), { u: CNT, n: 7 }),
  ];
  const goal = baseGoal({ grants, prohibits, bounds, escalateOn: [cmp('ne', par('esc', { k: 's' }), lit(sv('e1')))] });

  it('collects sorted verbs and resources, sorted relations, numerically sorted quantity groups and sorted discrete literals from grants, prohibits, escalation and sum bounds only', () => {
    const sp = buildSpace([goal], ['ev']);
    expect(sp.verbs).toEqual(['av', 'ev', 'mv', 'pv', 'zv']);
    expect(sp.resources).toEqual(['r1', 'r2', 'rp', 'rx']);
    expect(sp.rels).toEqual([{ rel: 'A', anchor: 'z' }, { rel: 'B', anchor: 'a' }, { rel: 'C', anchor: 'm' }]);
    expect(sp.q).toEqual(new Map([['amount', new Map([['money:USD', [9, 10, 100]]])], ['tot', new Map([['money:USD', [50]]])]]));
    expect(sp.d).toEqual(new Map([['who', ['s:sa', 's:sb']], ['pp', ['s:pz']], ['esc', ['s:e1']]]));
    expect([...sp.q.keys()].sort()).toEqual(['amount', 'tot']);
  });

  it('keeps two relation selectors whose concatenations collide apart, in discovery order', () => {
    const g = baseGoal({ grants: [{ gid: 'g1', verb: 'x', res: { k: 'all_of', parts: [{ k: 'related', rel: 'ab', anchor: 'c' }, { k: 'related', rel: 'a', anchor: 'bc' }] }, cond: ctrue }] });
    expect(buildSpace([g]).rels).toEqual([{ rel: 'ab', anchor: 'c' }, { rel: 'a', anchor: 'bc' }]);
  });
});

describe('cellKey: the exact canonical cell string', () => {
  const sp: Space = {
    verbs: ['v1'], resources: ['r1'], rels: [{ rel: 'R', anchor: 'A' }, { rel: 'S', anchor: 'A' }],
    q: new Map([['amt', new Map([['money:USD', [10, 20]]])], ['cnt', new Map([['count', [5]]])]]),
    d: new Map([['who', ['s:a']]]),
  };
  const c = (verb: string, res: string, params: Record<string, Value>, rm: [string[], string[]]): Case => ({
    act: mkAct(verb, res, params),
    rels: [{ rel: 'R', anchor: 'A', members: rm[0] }, { rel: 'S', anchor: 'A', members: rm[1] }],
  });

  it('writes literal hits, positions between literals, relation bits, and known verb and resource', () => {
    expect(cellKey(sp, c('v1', 'r1', { amt: usdV(10), cnt: cntV(7), who: sv('a') }, [['r1'], []])))
      .toBe('{"l":[1,0],"p":{"amt":"money:USD=0","cnt":"count@1","who":"s:a"},"r":"r1","v":"v1"}');
  });

  it('writes an unknown verb and resource as a wildcard, the second relation bit, and values between literals', () => {
    expect(cellKey(sp, c('zz', 'rr', { amt: usdV(15), cnt: cntV(5), who: sv('q') }, [[], ['rr']])))
      .toBe('{"l":[0,1],"p":{"amt":"money:USD@1","cnt":"count=0","who":"other"},"r":"*","v":"*"}');
  });

  it('writes the position below the first literal, on the last literal, and above all literals', () => {
    expect(cellKey(sp, c('v1', 'r1', { amt: usdV(5) }, [[], []]))).toBe('{"l":[0,0],"p":{"amt":"money:USD@0","cnt":"missing","who":"missing"},"r":"r1","v":"v1"}');
    expect(cellKey(sp, c('v1', 'r1', { amt: usdV(20) }, [[], []]))).toBe('{"l":[0,0],"p":{"amt":"money:USD=1","cnt":"missing","who":"missing"},"r":"r1","v":"v1"}');
    expect(cellKey(sp, c('v1', 'r1', { amt: usdV(25) }, [[], []]))).toBe('{"l":[0,0],"p":{"amt":"money:USD@2","cnt":"missing","who":"missing"},"r":"r1","v":"v1"}');
  });

  it('writes a unit mismatch and a literal set as unit and missing', () => {
    const eur: Value = { k: 'q', q: { u: { k: 'money', ccy: 'EUR' }, n: 1 } };
    expect(cellKey(sp, c('v1', 'r1', { amt: eur, cnt: { k: 'set', items: [] } }, [[], []])))
      .toBe('{"l":[0,0],"p":{"amt":"unit","cnt":"missing","who":"missing"},"r":"r1","v":"v1"}');
  });

  it('writes a string on a quantity-only parameter and a quantity on a discrete-only parameter as unit', () => {
    expect(cellKey(sp, c('v1', 'r1', { amt: sv('a'), cnt: cntV(100), who: cntV(3) }, [[], []])))
      .toBe('{"l":[0,0],"p":{"amt":"unit","cnt":"count@1","who":"unit"},"r":"r1","v":"v1"}');
  });
});

describe('cells: the exact options of each parameter', () => {
  const only = (q: Map<string, Map<string, number[]>>, d: Map<string, string[]>): Space => ({ verbs: [], resources: [], rels: [], q, d });
  const optsOf = (sp: Space): (Value | undefined)[] => cells(sp).cases.map((x) => x.act.params['p']);
  const mon = (n: number): Value => ({ k: 'q', q: { u: { k: 'money', ccy: 'USD' }, n } });

  it('offers absent, each literal with its neighbours, and a unit-mismatch money for a money group', () => {
    const ZZZ: Value = { k: 'q', q: { u: { k: 'money', ccy: 'ZZZ' }, n: 0 } };
    expect(optsOf(only(new Map([['p', new Map([['money:USD', [100]]])]]), new Map()))).toEqual([undefined, mon(99), mon(100), mon(101), ZZZ]);
  });

  it('offers a negative neighbour only for instants and keeps zero for the others', () => {
    const o = optsOf(only(new Map([['p', new Map([['count', [0]], ['instant', [0]]])]]), new Map()));
    expect(o).toEqual([undefined, cntV(0), cntV(1), { k: 'q', q: { u: { k: 'instant' }, n: -1 } }, { k: 'q', q: { u: { k: 'instant' }, n: 0 } }, { k: 'q', q: { u: { k: 'instant' }, n: 1 } }]);
  });

  it('offers no string option for a quantity-only parameter', () => {
    expect(optsOf(only(new Map([['p', new Map([['count', [5]]])]]), new Map()))).toEqual([undefined, cntV(4), cntV(5), cntV(6)]);
  });

  it('offers each discrete literal in order and then the other-string for a discrete parameter', () => {
    expect(optsOf(only(new Map(), new Map([['p', ['s:b', 's:a']]])))).toEqual([undefined, sv('b'), sv('a'), sv(OTH)]);
  });

  it('removes duplicate options: a grid of exactly 40000 cells stays complete', () => {
    const verbs = Array.from({ length: 32 }, (_, i) => `v${i}`);
    const d = new Map<string, string[]>(['d0', 'd1', 'd2', 'd3'].map((p): [string, string[]] => [p, ['s:a', 's:b', 's:c']]));
    // two empty money groups both add the unit-mismatch money: the parameter has 2 options, not 3
    const q = new Map([['p', new Map([['money:USD', [] as number[]], ['money:EUR', [] as number[]]])]]);
    const r = cells({ verbs, resources: [], rels: [], q, d }, { verbs });
    // 32 verbs * 1 resource * 1 relation mask * 5^4 discrete options * 2 = 40000
    expect(r.complete).toBe(true);
    expect(r.cases).toHaveLength(40_000);
  }, 120_000);
});
