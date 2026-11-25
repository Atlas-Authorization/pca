import { describe, expect, it } from 'vitest';
import { EMPTY_HIST, buildSpace, decideCase, mkAct, rankOf, replay, type Space } from '../src/examples';
import type { Bound, Cond, Goal, Prohibit, Term, Value } from '../src/ir';
import { CNT, ONT, baseGoal, ctrue, usd } from './fixtures';

const sv = (s: string): Value => ({ k: 's', s });
const cntLit = (n: number): Term => ({ k: 'lit', v: { k: 'q', q: { u: CNT, n } } });
const par = (path: string): Term => ({ k: 'param', path, ty: { k: 's' } });
const cmp = (op: 'eq' | 'lt' | 'in', l: Term, r: Term): Cond => ({ k: 'cmp', op, l, r });
const lit = (v: Value): Term => ({ k: 'lit', v });
const amount = (n: number): Value => ({ k: 'q', q: usd(n) });

describe('rankOf and mkAct', () => {
  it('ranks allow 0, escalate 1, deny 2', () => {
    expect(rankOf('allow')).toBe(0);
    expect(rankOf('escalate')).toBe(1);
    expect(rankOf('deny')).toBe(2);
  });

  it('builds the fixed envelope: time 0, session s, principal p, org o, agent a, depth 0, overridable', () => {
    expect(mkAct('v', 'r')).toEqual({ verb: 'v', res: 'r', params: {}, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 });
    expect(mkAct('v', 'r', {}, { sess: 'x', depth: 1 })).toEqual({ verb: 'v', res: 'r', params: {}, t: 0, sess: 'x', prin: 'p', org: 'o', agent: 'a', depth: 1 });
  });
});

describe('decideCase: prohibited', () => {
  const act = mkAct('pay.read', 'x');
  const withProhibit = (cond: Cond): Goal => {
    const p: Prohibit = { pid: 'p1', target: { k: 'verb', verb: 'pay.read' }, res: { k: 'any', reason: 'r' }, cond };
    return baseGoal({ prohibits: [p] });
  };

  it('is false when no prohibition applies', () => {
    expect(decideCase(baseGoal(), ONT, { act })).toEqual({ decision: 'allow', witness: 'g2', prohibited: false });
  });
  it('is true when a prohibition fires (deny, no witness)', () => {
    expect(decideCase(withProhibit(ctrue), ONT, { act })).toEqual({ decision: 'deny', witness: null, prohibited: true });
  });
  it('is true when a prohibition is unknown (escalate, no witness)', () => {
    const unknown = cmp('eq', par('customer'), lit(sv('C1')));
    expect(decideCase(withProhibit(unknown), ONT, { act })).toEqual({ decision: 'escalate', witness: null, prohibited: true });
  });
});

describe('replay', () => {
  it('starts from the empty history', () => {
    expect(replay(baseGoal(), ONT, [], ONT.rels)).toEqual({ adms: [], last: -1, aggs: {} });
    expect(EMPTY_HIST).toEqual({ adms: [], last: -1, aggs: {} });
  });

  it('records only admitted actions, so a denied action never counts toward a cumulative limit', () => {
    const b: Bound = {
      bid: 'b1', sel: { k: 'effect', cls: 'money_out' }, agg: 'count', value: cntLit(0), key: '',
      window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: CNT, n: 1 }, onExceed: 'deny',
    };
    const g = baseGoal({ bounds: [b] });
    const refund = (n: number, t: number) => mkAct('pay.refund', 'ch_1', { amount: amount(n) }, { t });
    const a1 = refund(9000, 1); // denied by the grant condition (amount over 5000)
    const a2 = refund(100, 2); // admitted: the only counted refund
    const a3 = refund(100, 3); // denied by the bound (second counted refund)
    const a4 = mkAct('pay.read', 'x', {}, { t: 4 }); // admitted under g2, outside the bound
    const a5 = mkAct('pay.wire', 'x', {}, { t: 5 }); // no grant: denied
    expect(replay(g, ONT, [a1], ONT.rels)).toEqual({ adms: [], last: -1, aggs: {} });
    expect(replay(g, ONT, [a1, a2], ONT.rels)).toEqual({ adms: [{ gid: 'g1', act: a2 }], last: 2, aggs: {} });
    expect(replay(g, ONT, [a1, a2, a3, a4, a5], ONT.rels)).toEqual({ adms: [{ gid: 'g1', act: a2 }, { gid: 'g2', act: a4 }], last: 4, aggs: {} });
  });

  it('does not record an escalated action', () => {
    const b: Bound = {
      bid: 'b1', sel: { k: 'gids', gids: ['g2'] }, agg: 'count', value: cntLit(0), key: '',
      window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: CNT, n: 1 }, onExceed: 'escalate',
    };
    const a1 = mkAct('pay.read', 'x', {}, { t: 1 });
    const a2 = mkAct('pay.read', 'x', {}, { t: 2 });
    const a3 = mkAct('pay.read', 'x', {}, { t: 3 });
    expect(replay(baseGoal({ bounds: [b] }), ONT, [a1, a2, a3], ONT.rels)).toEqual({ adms: [{ gid: 'g2', act: a1 }], last: 1, aggs: {} });
  });
});

describe('buildSpace: literal walk', () => {
  it('finds literals on the left of a comparison, under or and not, and has no verbs by default', () => {
    const cond: Cond = {
      k: 'or',
      a: cmp('lt', cntLit(5), par('n')),
      b: { k: 'not', c: cmp('eq', par('m'), lit(sv('x'))) },
    };
    const g = baseGoal({ grants: [{ gid: 'g1', verb: 'v1', res: { k: 'exact', id: 'r1' }, cond }], wildcardAck: [] });
    const want: Space = {
      verbs: ['v1'], resources: ['r1'], rels: [],
      q: new Map([['n', new Map([['count', [5]]])]]),
      d: new Map([['m', ['s:x']]]),
    };
    expect(buildSpace([g])).toEqual(want);
  });

  it('ignores comparisons that do not pair one parameter with one literal, and nested sets', () => {
    const hist: Term = { k: 'hist', bid: 'b', u: CNT };
    const nested: Value = { k: 'set', items: [sv('a'), { k: 'set', items: [sv('b')] }] };
    const escalateOn: Cond[] = [
      cmp('eq', cntLit(7), lit(sv('z'))),
      cmp('eq', par('p1'), par('p2')),
      cmp('eq', par('p1'), hist),
      cmp('eq', hist, cntLit(3)),
      cmp('in', par('k'), lit(nested)),
    ];
    const g = baseGoal({ grants: [], escalateOn, wildcardAck: [] });
    expect(buildSpace([g])).toEqual({ verbs: [], resources: [], rels: [], q: new Map(), d: new Map([['k', ['s:a']]]) });
  });
});
