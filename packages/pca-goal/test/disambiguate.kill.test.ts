import { describe, expect, it } from 'vitest';
import { disagreementMass, disambiguate, questions, type Question, type Reading } from '../src/disambiguate';
import { mkAct } from '../src/examples';
import type { Bound, Cond, Goal, Grant, Hole, Ontology, Prohibit } from '../src/ir';
import { ctrue, lteAmt } from './fixtures';

const shell: Goal = {
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [], grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 1_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [],
};
const goal = (over: Partial<Goal>): Goal => ({ ...shell, ...over });
const grant = (gid: string, verb: string, cond: Cond = ctrue): Grant => ({ gid, verb, res: { k: 'any', reason: 'r' }, cond });
const rd = (id: string, g: Goal): Reading => ({ id, family: 'f', deterministic: true, goal: g, notes: [] });
const eqAmt = (n: number): Cond => { const c = lteAmt(n); return c.k === 'cmp' ? { ...c, op: 'eq' } : c; };
const hole = (hid: string, q: string): Hole => ({ hid, q, domain: [], affects: [], global: false });
const countBound = (n: number): Bound => ({
  bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: { u: { k: 'count' }, n: 1 } } }, key: '',
  window: { k: 'task' }, scope: { k: 'principal' }, cap: { u: { k: 'count' }, n }, onExceed: 'deny',
});
const OTHER = '\u0000other-resource';
const ontOf = (verbs: [string, string][]): Ontology => ({ verbs: verbs.map(([verb, cls]) => ({ verb, cls, params: [] })), rels: [] });

describe('question text, ranking by risk and mass, allow / notAllow sets', () => {
  const ont = ontOf([['v.read', 'read'], ['v.rev', 'reversible'], ['v.ext', 'external_send'], ['v.irr', 'irreversible'], ['v.odd', 'odd']]); // v.ghost is not declared
  const verbs = ['v.read', 'v.rev', 'v.ext', 'v.irr', 'v.odd', 'v.ghost'];
  const readings = [rd('r1', goal({ grants: verbs.map((v, i) => grant(`g${i}`, v)) })), rd('r2', goal({}))];
  it('scores by the effect class of the verb (unknown class and unknown verb are the riskiest); ties break by id', () => {
    const qs = questions(readings, { ont });
    expect(qs.map((q) => [q.act.verb, q.score])).toStrictEqual([['v.ghost', 10], ['v.irr', 10], ['v.odd', 10], ['v.ext', 8], ['v.rev', 2], ['v.read', 1]]);
  });
  it('the mass of an action multiplies the score', () => {
    const qs = questions(readings, { ont, massOf: () => 4 });
    expect(qs.map((q) => [q.act.verb, q.score])).toStrictEqual([['v.ghost', 40], ['v.irr', 40], ['v.odd', 40], ['v.ext', 32], ['v.rev', 8], ['v.read', 4]]);
  });
  it('a question lists the readings that allow and those that do not, and reads as the action alone when no history is needed', () => {
    const q = questions(readings, { ont }).find((x) => x.act.verb === 'v.read') as Question;
    expect(q.allow).toStrictEqual(['r1']);
    expect(q.notAllow).toStrictEqual(['r2']);
    expect(q.text).toBe(`Should this be allowed: v.read on ${OTHER}?`);
    expect(q.prior).toStrictEqual([]);
    expect(q.id).toBe(JSON.stringify([mkAct('v.read', OTHER), 0]));
  });
});

describe('cap-sequence witnesses', () => {
  const ont = ontOf([['pay.refund', 'reversible'], ['pay.read', 'read']]);
  const prohibit: Prohibit = { pid: 'p1', target: { k: 'effect', cls: 'read' }, res: { k: 'any', reason: 'r' }, cond: ctrue };
  const capped = (n: number): Goal => goal({ grants: [grant('g1', 'pay.refund')], prohibits: [prohibit], bounds: [countBound(n)] });
  const readings = [rd('r1', capped(1)), rd('r2', capped(2)), rd('r3', capped(1))];
  it('the one question is the second identical action, asked once although two readings produce it', () => {
    const qs = questions(readings, { ont });
    expect(qs).toHaveLength(1);
    const q = qs[0] as Question;
    const act = mkAct('pay.refund', OTHER);
    expect(q.id).toBe(JSON.stringify([act, 1]));
    expect(q.act).toStrictEqual(act);
    expect(q.prior).toStrictEqual([act]);
    expect(q.rels).toStrictEqual([]);
    expect(q.allow).toStrictEqual(['r2']);
    expect(q.notAllow).toStrictEqual(['r1', 'r3']);
    expect(q.text).toBe(`Should this be allowed: pay.refund on ${OTHER} (after 1 earlier identical action(s))?`);
    expect(q.score).toBeCloseTo(1.8365916681, 8); // H2(1/3) x risk(reversible) = 0.9182958340544896 x 2
  });
});

describe('witnesses come only from decision cells and cap sequences', () => {
  const ont = ontOf([['pay.refund', 'read']]);
  const readings = [rd('r1', goal({ grants: [grant('g1', 'pay.refund')] })), rd('r2', goal({ grants: [grant('g1', 'pay.refund', eqAmt(1000))] }))];
  const amountOf = (q: Question): string => {
    const v = q.act.params['amount'];
    if (v === undefined) return 'missing';
    return v.k === 'q' && v.q.u.k === 'money' ? `${v.q.u.ccy}:${v.q.n}` : 'other';
  };
  it('tied questions are ordered by id, and no extreme-amount probe is asked', () => {
    // cell representatives: amount missing, 999, 1001 and a foreign currency split the readings (1000 does not); ids compare as text
    expect(questions(readings, { ont }).map(amountOf)).toStrictEqual(['USD:1001', 'USD:999', 'ZZZ:0', 'missing']);
  });
});

describe('disagreement mass', () => {
  const ont = ontOf([['v.a', 'read'], ['v.b', 'read']]);
  const pair = (h1: Hole[], h2: Hole[]): Reading[] => [rd('r1', goal({ grants: [grant('g1', 'v.a')], holes: h1 })), rd('r2', goal({ grants: [grant('g2', 'v.b')], holes: h2 }))];
  it('is the fraction of witness cells the readings split on', () => {
    expect(disagreementMass(pair([], []), ont)).toBeCloseTo(2 / 3, 12); // v.a and v.b split, the other verb does not, of three cells
  });

  const exhausted = async (h1: Hole[], h2: Hole[]) => {
    let asks = 0;
    const res = await disambiguate(pair(h1, h2), () => { asks++; return 'allow'; }, { ont, budget: 0 });
    return { res, asks };
  };
  const budget: Hole = { hid: 'budget', q: 'Question budget exhausted with disagreement left.', domain: [], affects: [], global: true };
  it('a zero budget asks nothing and keeps one budget hole', async () => {
    const { res, asks } = await exhausted([], []);
    expect(asks).toBe(0);
    expect(res.status).toBe('budget_exhausted');
    expect(res.asked).toStrictEqual([]);
    expect(res.remaining).toStrictEqual(['r1', 'r2']);
    expect(res.residualMass).toBeCloseTo(2 / 3, 12);
    expect(res.goal.holes).toStrictEqual([budget]);
  });
  it('holes stay in id order: the budget hole goes before a later id', async () => {
    expect((await exhausted([hole('z', 'zq')], [])).res.goal.holes).toStrictEqual([budget, hole('z', 'zq')]);
  });
  it('holes stay in id order: earlier ids are not reversed', async () => {
    expect((await exhausted([hole('a', 'aq')], [hole('b', 'bq')])).res.goal.holes).toStrictEqual([hole('a', 'aq'), hole('b', 'bq'), budget]);
  });
  it('a reading hole with the same id keeps its place before the budget hole', async () => {
    expect((await exhausted([hole('budget', 'mine')], [])).res.goal.holes).toStrictEqual([hole('budget', 'mine'), budget]);
  });
});
