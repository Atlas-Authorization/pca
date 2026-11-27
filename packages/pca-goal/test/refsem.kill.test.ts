import { describe, expect, it } from 'vitest';
import type { Act, Adm, Bound, Cond, Goal, Hist, Op, Ontology, ResSel, Term, Value } from '../src/ir';
import { refExplain } from '../src/refsem';

const U = { k: 'count' } as const;
const q = (n: number): Value => ({ k: 'q', q: { u: U, n } });
const lit = (v: Value): Term => ({ k: 'lit', v });
const param = (path: string): Term => ({ k: 'param', path, ty: { k: 'q', u: U } });
const ont: Ontology = { verbs: [{ verb: 'v', cls: 'c', params: [] }], rels: [] };
const act = (o: Partial<Act> = {}): Act => ({ verb: 'v', res: 'r', params: {}, t: 100, sess: 's', prin: 'p', org: 'o', agent: 'a1', depth: 0, ...o });
const none: Hist = { adms: [], last: -1, aggs: {} };
const goal = (o: Partial<Goal> = {}): Goal => ({
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [],
  grants: [{ gid: 'g', verb: 'v', res: { k: 'any', reason: 'x' }, cond: { k: 'true' } }], prohibits: [],
  bounds: [], validity: { notBefore: 0, notAfter: 1_000_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g'] },
  escalateOn: [], wildcardAck: [], holes: [], ...o,
});
const decide = (g: Goal, a: Act = act(), h: Hist = none): 0 | 1 | 2 => refExplain(g, ont, a, h).d;
const withCond = (cond: Cond): Goal => goal({ grants: [{ gid: 'g', verb: 'v', res: { k: 'any', reason: 'x' }, cond }] });
const cmp = (op: Op, l: Term, r: Term): Cond => ({ k: 'cmp', op, l, r });
const adm = (a: Act): Adm => ({ gid: 'g', act: a });
const hist = (...acts: Act[]): Hist => ({ adms: acts.map(adm), last: -1, aggs: {} });
const bound = (o: Partial<Bound>): Bound => ({
  bid: 'b', sel: { k: 'gids', gids: ['g'] }, agg: 'count', value: param('amt'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' },
  cap: { u: U, n: 1 }, onExceed: 'deny', ...o,
});
const withBound = (o: Partial<Bound>): Goal => goal({ bounds: [bound(o)] });

describe('refsem kills: comparison operators', () => {
  it('every operator decides exactly the integer comparison, on all orderings', () => {
    const ops: Array<[Op, (x: number, y: number) => boolean]> = [
      ['eq', (x, y) => x === y], ['ne', (x, y) => x !== y], ['lt', (x, y) => x < y],
      ['gte', (x, y) => x >= y], ['gt', (x, y) => x > y], ['lte', (x, y) => x <= y],
    ];
    for (const [op, f] of ops) {
      for (const [x, y] of [[1, 2], [2, 2], [3, 2]] as const) {
        expect(decide(withCond(cmp(op, lit(q(x)), lit(q(y))))), `${op} ${x} ${y}`).toBe(f(x, y) ? 2 : 0);
      }
    }
  });
  it('in and nin test set membership', () => {
    const set: Value = { k: 'set', items: [q(1), q(2)] };
    expect(decide(withCond(cmp('in', lit(q(2)), lit(set))))).toBe(2);
    expect(decide(withCond(cmp('in', lit(q(3)), lit(set))))).toBe(0);
    expect(decide(withCond(cmp('nin', lit(q(3)), lit(set))))).toBe(2);
    expect(decide(withCond(cmp('nin', lit(q(2)), lit(set))))).toBe(0);
  });
  it('comparing a quantity with text is unknown, not a crash', () => {
    expect(decide(withCond(cmp('eq', lit(q(1)), lit({ k: 's', s: 'a' }))))).toBe(1);
    expect(decide(withCond(cmp('lt', lit(q(1)), lit({ k: 's', s: 'a' }))))).toBe(1);
    expect(decide(withCond(cmp('lt', lit({ k: 's', s: 'a' }), lit(q(1)))))).toBe(1);
  });
  it('a history aggregate term reads as a quantity of its bound', () => {
    const c = withCond(cmp('lte', { k: 'hist', bid: 'b1', u: U }, lit(q(5))));
    expect(decide(c, act(), { adms: [], last: -1, aggs: { b1: { u: U, n: 3 } } })).toBe(2);
    expect(decide(c, act(), { adms: [], last: -1, aggs: { b1: { u: U, n: 9 } } })).toBe(0);
    expect(decide(c, act(), none)).toBe(1);
  });
});

describe('refsem kills: resources, validity, depth', () => {
  it('a related selector with no matching relation admits nothing, even a resource named like a placeholder', () => {
    const res: ResSel = { k: 'related', rel: 'none', anchor: 'x' };
    const g = goal({ grants: [{ gid: 'g', verb: 'v', res, cond: { k: 'true' } }] });
    expect(decide(g, act({ res: 'Stryker was here' }))).toBe(0);
  });
  it('maxIdle: denied past the idle window, allowed at it, never judged without a previous action', () => {
    const g = goal({ validity: { notBefore: 0, notAfter: 1_000_000, maxIdle: 50 } });
    const at = (last: number): 0 | 1 | 2 => decide(g, act({ t: 100 }), { adms: [], last, aggs: {} });
    expect(at(0)).toBe(0); // last = 0 is a real time, 100 idle
    expect(at(49)).toBe(0);
    expect(at(50)).toBe(2); // exactly maxIdle: not past it
    expect(at(60)).toBe(2);
    expect(at(-1)).toBe(2);
  });
  it('a delegation depth past maxDepth is denied', () => {
    expect(decide(goal(), act({ depth: 1 }))).toBe(2);
    expect(decide(goal(), act({ depth: 2 }))).toBe(0);
  });
  it('a negative delegation depth is denied, even for a grant the delegate may touch', () => {
    expect(decide(goal(), act({ depth: -1 }))).toBe(0);
  });
  it('validity is the closed interval [notBefore, notAfter]', () => {
    const g = goal({ validity: { notBefore: 50, notAfter: 200, maxIdle: 0 } });
    expect(decide(g, act({ t: 49 }))).toBe(0);
    expect(decide(g, act({ t: 50 }))).toBe(2);
    expect(decide(g, act({ t: 200 }))).toBe(2);
    expect(decide(g, act({ t: 201 }))).toBe(0);
  });
});

describe('refsem kills: bounds', () => {
  const amtAct = (n: number, o: Partial<Act> = {}): Act => act({ params: { amt: q(n) }, ...o });
  it('max bound: the largest of history and the action decides, equal to the cap passes', () => {
    const g = withBound({ agg: 'max', value: param('amt'), cap: { u: U, n: 5 } });
    expect(decide(g, amtAct(10))).toBe(0);
    expect(decide(g, amtAct(5))).toBe(2);
    expect(decide(g, amtAct(1), hist(amtAct(10, { t: 90 })))).toBe(0);
    expect(decide(g, amtAct(1), hist(amtAct(1, { t: 90 })))).toBe(2);
    expect(decide(g, amtAct(5), hist(amtAct(4, { t: 90 })))).toBe(2);
  });
  it('sum bound over the same history', () => {
    const g = withBound({ agg: 'sum', value: param('amt'), cap: { u: U, n: 5 } });
    expect(decide(g, amtAct(3), hist(amtAct(3, { t: 90 })))).toBe(0);
    expect(decide(g, amtAct(3), hist(amtAct(2, { t: 90 })))).toBe(2);
  });
  it('distinct bound counts distinct values of the key, the action included', () => {
    const g = withBound({ agg: 'distinct', key: 'k', cap: { u: U, n: 1 } });
    const s = (v: string): Act => act({ params: { k: { k: 's', s: v } } });
    expect(decide(g, s('x'))).toBe(2); // one value, cap one
    expect(decide(g, s('x'), hist(s('x')))).toBe(2); // the same value twice is still one
    expect(decide(g, s('x'), hist(s('y')))).toBe(0); // two values
    expect(decide(g, act())).toBe(1); // the action has no such parameter: unknown
    expect(decide(g, s('x'), hist(act({ t: 90 })))).toBe(1); // a past action has none
  });
  it('a bound on a class the verb is not in, naming no grant of the action, is not applied', () => {
    const g = goal({
      grants: [{ gid: 'Stryker was here', verb: 'v', res: { k: 'any', reason: 'x' }, cond: { k: 'true' } }],
      deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['Stryker was here'] },
      bounds: [bound({ sel: { k: 'effect', cls: 'other' }, cap: { u: U, n: 0 } })],
    });
    expect(decide(g)).toBe(2);
  });
  it('a gids bound selects by gid only: never by verb, whatever else the selector carries', () => {
    const sel = { k: 'gids', gids: ['zz'], cls: 'c' } as unknown as Bound['sel'];
    expect(decide(goal({ bounds: [bound({ sel, cap: { u: U, n: 0 } })] }))).toBe(2);
    const g = goal({
      grants: [{ gid: 'g', verb: 'Stryker was here', res: { k: 'any', reason: 'x' }, cond: { k: 'true' } }],
      bounds: [bound({ sel: { k: 'gids', gids: ['zz'] }, cap: { u: U, n: 0 } })],
    });
    expect(decide(g, act({ verb: 'Stryker was here' }))).toBe(2);
  });
  it('an exceeded escalate bound escalates, an exceeded deny bound denies', () => {
    expect(decide(withBound({ agg: 'count', cap: { u: U, n: 0 }, onExceed: 'escalate' }))).toBe(1);
    expect(decide(withBound({ agg: 'count', cap: { u: U, n: 0 }, onExceed: 'deny' }))).toBe(0);
  });
});

describe('refsem kills: bound scope', () => {
  const g = (scope: Bound['scope']): Goal => withBound({ scope });
  const prior = (o: Partial<Act>): Hist => hist(act({ t: 90, ...o }));
  it('session', () => {
    expect(decide(g({ k: 'session' }), act(), prior({}))).toBe(0);
    expect(decide(g({ k: 'session' }), act(), prior({ sess: 'other' }))).toBe(2);
  });
  it('principal ignores the org', () => {
    expect(decide(g({ k: 'principal' }), act(), prior({ prin: 'other' }))).toBe(2);
    expect(decide(g({ k: 'principal' }), act(), prior({ org: 'other' }))).toBe(0);
    expect(decide(g({ k: 'principal' }), act(), prior({ sess: 'other' }))).toBe(0);
  });
  it('org ignores the principal', () => {
    expect(decide(g({ k: 'org' }), act(), prior({ org: 'other' }))).toBe(2);
    expect(decide(g({ k: 'org' }), act(), prior({ prin: 'other' }))).toBe(0);
    expect(decide(g({ k: 'org' }), act(), prior({ sess: 'other' }))).toBe(0);
  });
  it('fleet needs both agents in the fleet', () => {
    const f = g({ k: 'fleet', agents: ['a1', 'a2'] });
    expect(decide(f, act({ agent: 'a1' }), prior({ agent: 'a2' }))).toBe(0);
    expect(decide(f, act({ agent: 'a1' }), prior({ agent: 'zz' }))).toBe(2);
    expect(decide(f, act({ agent: 'zz' }), prior({ agent: 'a1' }))).toBe(2);
    expect(decide(f, act({ agent: 'zz' }), prior({ agent: 'zz' }))).toBe(2);
  });
});

describe('refsem kills: bound window', () => {
  const g = (window: Bound['window']): Goal => withBound({ window });
  const prior = (t: number): Hist => hist(act({ t }));
  it('task counts every earlier action', () => {
    expect(decide(g({ k: 'task' }), act(), prior(1))).toBe(0);
  });
  it('sliding: the window is (t - ms, t]', () => {
    const w = g({ k: 'sliding', ms: 50 });
    expect(decide(w, act({ t: 100 }), prior(50))).toBe(2); // exactly ms ago: out
    expect(decide(w, act({ t: 100 }), prior(51))).toBe(0);
    expect(decide(w, act({ t: 100 }), prior(100))).toBe(0); // same instant: in
  });
  it('period: same period index counts, a zero-length period counts nothing', () => {
    const w = g({ k: 'period', ms: 100, t0: 30 });
    expect(decide(w, act({ t: 110 }), prior(95))).toBe(0); // (110-30)/100 and (95-30)/100 are both 0
    expect(decide(w, act({ t: 130 }), prior(95))).toBe(2); // 1 vs 0
    expect(decide(g({ k: 'period', ms: 0, t0: 0 }), act({ t: 100 }), prior(100))).toBe(2);
  });
});

