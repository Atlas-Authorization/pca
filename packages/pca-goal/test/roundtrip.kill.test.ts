import { describe, expect, it } from 'vitest';
import type { Cond, Goal, Op, Term, Unit } from '../src/ir';
import type { EffectClass, IntentOntology } from '../src/ontology';
import { renderCard } from '../src/card';
import { MUTATION_KINDS, cardRoundTrips, deterministicExplainer, lexicalComparator, measureDetection, mutateGoal, roundTrip, type Comparator, type Explainer, type MutationKind } from '../src/roundtrip';

const USD: Unit = { k: 'money', ccy: 'USD' };
const CNT: Unit = { k: 'count' };
const DUR: Unit = { k: 'duration' };
const RATIO: Unit = { k: 'ratio' };

const goal = (over: Partial<Goal> = {}): Goal => ({
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [],
  grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 9, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [], ...over,
});
const ont = (verbs: { id: string; effect: EffectClass }[]): IntentOntology => ({
  id: 't', version: 1, domain: 'd', types: [{ id: 'customer', id_prefix: 'cus_' }], units: {}, relations: [],
  verbs: verbs.map((v) => ({ id: v.id, effect: v.effect, resource_type: 'x', params: {} })), aliases: {}, templates: [],
});
const amountParam: Term = { k: 'param', path: 'amount', ty: { k: 'q', u: USD } };
const qlit = (n: number, u: Unit): Term => ({ k: 'lit', v: { k: 'q', q: { u, n } } });
const cmp = (op: Op, r: Term): Cond => ({ k: 'cmp', op, l: amountParam, r });
const must = (g: Goal | undefined): Goal => {
  if (!g) throw new Error('expected a mutation');
  return g;
};
const anyRes = { k: 'any', reason: 'r' } as const;
const tru: Cond = { k: 'true' };

describe('cardRoundTrips', () => {
  it('is true for a plain goal and false when the goal carries something the tape cannot hold', () => {
    const g = goal({ grants: [{ gid: 'g1', verb: 'v', res: anyRes, cond: tru }], wildcardAck: ['g1'] });
    expect(cardRoundTrips(g)).toBe(true);
    expect(cardRoundTrips(Object.assign(goal(), { extra: 1 }))).toBe(false);
  });
});

describe('roundTrip', () => {
  const lines = (g: Goal): string[] => renderCard(g).lines;
  const g = goal({ grants: [{ gid: 'g1', verb: 'v', res: anyRes, cond: tru }] });
  const same: Comparator = { id: 'c', family: 'f', async equivalent() { return { equivalent: true }; } };
  const differ: Comparator = { id: 'c', family: 'f', async equivalent() { return { equivalent: false }; } };
  const ex: Explainer = { id: 'e', async explain() { return 'x'; } };

  it('the explainer sees the card lines and the comparator sees the goal text and the explanation', async () => {
    let seenLines: string[] = [];
    let seen: [string, string] = ['', ''];
    const explainer: Explainer = { id: 'e', async explain(l) { seenLines = l; return 'EXPL'; } };
    const comparator: Comparator = { id: 'c', family: 'f', async equivalent(t, e) { seen = [t, e]; return { equivalent: true }; } };
    expect(await roundTrip(g, 'TEXT', explainer, comparator)).toBe('ok');
    expect(seenLines).toEqual(lines(g));
    expect(seen).toEqual(['TEXT', 'EXPL']);
  });
  it('escalates when the comparator disagrees, or when either side throws', async () => {
    expect(await roundTrip(g, 't', ex, same)).toBe('ok');
    expect(await roundTrip(g, 't', ex, differ)).toBe('escalate');
    const boomE: Explainer = { id: 'e', async explain() { throw new Error('x'); } };
    const boomC: Comparator = { id: 'c', family: 'f', async equivalent() { throw new Error('x'); } };
    expect(await roundTrip(g, 't', boomE, same)).toBe('escalate');
    expect(await roundTrip(g, 't', ex, boomC)).toBe('escalate');
  });
});

describe('offline reference pair', () => {
  const o = ont([]);
  const cmpr = lexicalComparator(o);
  it('identity and joining', async () => {
    expect(deterministicExplainer.id).toBe('card-prose');
    expect(await deterministicExplainer.explain(['a', 'b'])).toBe('a\nb');
    expect(cmpr.id).toBe('lexical');
    expect(cmpr.family).toBe('rule');
  });
  it('compares ids as a sorted set with an unambiguous separator', async () => {
    expect(await cmpr.equivalent('cus_2 cus_1 cus_1', 'cus_1 cus_2')).toEqual({ equivalent: true });
    expect(await cmpr.equivalent('cus_1 cus_2', 'cus_1')).toEqual({ equivalent: false, reason: 'ids differ' });
    expect(await cmpr.equivalent('cus_1', 'cus_1 cus_2')).toEqual({ equivalent: false, reason: 'ids differ' });
    expect(await cmpr.equivalent('cus_1 cus_2', 'cus_1cus_2')).toEqual({ equivalent: false, reason: 'ids differ' });
  });
  it('amounts: stated, invented and missing', async () => {
    const text = 'refund cus_1 up to $50.00';
    expect(await cmpr.equivalent(text, 'cus_1 at most 5000 USD minor units')).toEqual({ equivalent: true });
    expect(await cmpr.equivalent(text, 'cus_1 at most 9999 USD minor units')).toEqual({ equivalent: false, reason: 'amount USD 9999 not stated by the principal' });
    expect(await cmpr.equivalent(text, 'cus_1 at most 5000 EUR minor units')).toEqual({ equivalent: false, reason: 'amount EUR 5000 not stated by the principal' });
    expect(await cmpr.equivalent(text, 'cus_1 only')).toEqual({ equivalent: false, reason: 'no amount in the policy' });
    expect(await cmpr.equivalent('refund cus_1', 'cus_1 only')).toEqual({ equivalent: true });
  });
});

describe('mutateGoal', () => {
  const o = ont([{ id: 'r.read', effect: 'read' }, { id: 'a.send', effect: 'external_send' }, { id: 'b.pay', effect: 'irreversible' }, { id: 'c.del', effect: 'reversible' }]);
  const bound = (bid: string, cap: { u: Unit; n: number }): Goal['bounds'][number] => ({ bid, sel: { k: 'effect', cls: 'c' }, agg: 'count', value: qlit(1, CNT), key: '', window: { k: 'task' }, scope: { k: 'session' }, cap, onExceed: 'deny' });
  const proh = (pid: string): Goal['prohibits'][number] => ({ pid, target: { k: 'verb', verb: 'b.pay' }, res: anyRes, cond: tru });
  const plain: Goal['grants'] = [{ gid: 'g1', verb: 'a.send', res: anyRes, cond: tru }];

  it('widen_cap scales a money or count cap by ten and leaves other units', () => {
    expect(must(mutateGoal(goal({ grants: plain, bounds: [bound('b1', { u: USD, n: 100 }), bound('b2', { u: USD, n: 5 })] }), 'widen_cap', o)).bounds.map((b) => b.cap)).toEqual([{ u: USD, n: 1000 }, { u: USD, n: 5 }]);
    expect(must(mutateGoal(goal({ bounds: [bound('b1', { u: CNT, n: 3 })] }), 'widen_cap', o)).bounds[0]!.cap).toEqual({ u: CNT, n: 30 });
    expect(must(mutateGoal(goal({ bounds: [bound('b1', { u: DUR, n: 7 })] }), 'widen_cap', o)).bounds[0]!.cap).toEqual({ u: DUR, n: 7 });
    expect(must(mutateGoal(goal({ bounds: [bound('b1', { u: RATIO, n: 7 })] }), 'widen_cap', o)).bounds[0]!.cap).toEqual({ u: RATIO, n: 7 });
    expect(mutateGoal(goal({ grants: plain }), 'widen_cap', o)).toBeUndefined();
  });

  it('widen_where scales only the upper-bound literals of the first grant that has any, recursing through and / or', () => {
    const grants: Goal['grants'] = [
      { gid: 'gA', verb: 'a.send', res: anyRes, cond: { k: 'not', c: cmp('lte', qlit(100, USD)) } },
      { gid: 'gB', verb: 'a.send', res: anyRes, cond: cmp('lte', { k: 'param', path: 'limit', ty: { k: 'q', u: USD } }) },
      { gid: 'gC', verb: 'a.send', res: anyRes, cond: cmp('lte', { k: 'lit', v: { k: 's', s: 'x' } }) },
      { gid: 'gD', verb: 'a.send', res: anyRes, cond: cmp('lte', qlit(7, RATIO)) },
      { gid: 'gE', verb: 'a.send', res: anyRes, cond: tru },
      { gid: 'gF', verb: 'a.send', res: anyRes, cond: { k: 'and', a: { k: 'or', a: cmp('lt', qlit(100, USD)), b: cmp('gt', qlit(200, USD)) }, b: { k: 'and', a: cmp('lte', qlit(3, CNT)), b: cmp('eq', qlit(5, USD)) } } },
      { gid: 'gG', verb: 'a.send', res: anyRes, cond: cmp('lte', qlit(1, USD)) },
    ];
    const g = goal({ grants });
    const before = JSON.stringify(g);
    const out = must(mutateGoal(g, 'widen_where', o));
    expect(JSON.stringify(g)).toBe(before);
    expect(out.grants.slice(0, 5)).toEqual(grants.slice(0, 5));
    expect(out.grants[5]!.cond).toEqual({ k: 'and', a: { k: 'or', a: cmp('lt', qlit(1000, USD)), b: cmp('gt', qlit(200, USD)) }, b: { k: 'and', a: cmp('lte', qlit(30, CNT)), b: cmp('eq', qlit(5, USD)) } });
    expect(out.grants[6]).toEqual(grants[6]);
    expect(mutateGoal(goal({ grants: grants.slice(0, 5) }), 'widen_where', o)).toBeUndefined();
    expect(mutateGoal(goal(), 'widen_where', o)).toBeUndefined();
    expect(must(mutateGoal(goal({ grants: [grants[6]!] }), 'widen_where', o)).grants[0]!.cond).toEqual(cmp('lte', qlit(10, USD)));
  });

  it('drop_prohibit pops the last prohibit only', () => {
    const g = goal({ prohibits: [proh('p1'), proh('p2')], bounds: [bound('b1', { u: USD, n: 1 })] });
    const out = must(mutateGoal(g, 'drop_prohibit', o));
    expect(out.prohibits.map((p) => p.pid)).toEqual(['p1']);
    expect(out.bounds).toEqual(g.bounds);
    expect(mutateGoal(goal({ bounds: g.bounds }), 'drop_prohibit', o)).toBeUndefined();
    expect(must(mutateGoal(goal({ prohibits: [proh('p1')] }), 'drop_prohibit', o)).prohibits).toEqual([]);
  });

  it('drop_bound pops the last bound only', () => {
    const g = goal({ prohibits: [proh('p1')], bounds: [bound('b1', { u: USD, n: 1 }), bound('b2', { u: USD, n: 2 })] });
    const out = must(mutateGoal(g, 'drop_bound', o));
    expect(out.bounds.map((b) => b.bid)).toEqual(['b1']);
    expect(out.prohibits).toEqual(g.prohibits);
    expect(mutateGoal(goal({ prohibits: g.prohibits }), 'drop_bound', o)).toBeUndefined();
    expect(must(mutateGoal(goal({ bounds: [bound('b1', { u: USD, n: 1 })] }), 'drop_bound', o)).bounds).toEqual([]);
  });

  it('swap_resource changes the first exact resource id and nothing else', () => {
    const g = goal({ grants: [{ gid: 'g1', verb: 'a.send', res: anyRes, cond: tru }, { gid: 'g2', verb: 'a.send', res: { k: 'exact', id: 'ch_1' }, cond: tru }, { gid: 'g3', verb: 'a.send', res: { k: 'exact', id: 'ch_2' }, cond: tru }] });
    const out = must(mutateGoal(g, 'swap_resource', o));
    expect(out.grants.map((x) => x.res)).toEqual([anyRes, { k: 'exact', id: 'ch_19' }, { k: 'exact', id: 'ch_2' }]);
    expect(out.wildcardAck).toEqual([]);
    expect(mutateGoal(goal({ grants: plain }), 'swap_resource', o)).toBeUndefined();
  });

  it('add_grant injects the first unused, non-read, non-prohibited verb, acknowledged as a wildcard', () => {
    const g = goal({ grants: plain, prohibits: [proh('p1'), { pid: 'p2', target: { k: 'effect', cls: 'reversible' }, res: anyRes, cond: tru }] });
    const out = must(mutateGoal(g, 'add_grant', o));
    expect(out.grants).toEqual([plain[0]!, { gid: 'injected', verb: 'c.del', res: { k: 'any', reason: 'injected' }, cond: { k: 'true' } }]);
    expect(out.wildcardAck).toEqual(['injected']);
    expect(out.prohibits).toEqual(g.prohibits);
    expect(mutateGoal(goal(), 'add_grant', ont([{ id: 'r.read', effect: 'read' }]))).toBeUndefined();
    expect(mutateGoal(goal({ grants: plain }), 'add_grant', ont([{ id: 'a.send', effect: 'external_send' }]))).toBeUndefined();
    expect(mutateGoal(goal({ prohibits: [proh('p1')] }), 'add_grant', ont([{ id: 'b.pay', effect: 'irreversible' }]))).toBeUndefined();
  });
});

describe('measureDetection', () => {
  const o = ont([{ id: 'r.read', effect: 'read' }, { id: 'c.del', effect: 'reversible' }]);
  const full = goal({
    grants: [{ gid: 'g1', verb: 'a.send', res: { k: 'exact', id: 'ch_1' }, cond: cmp('lte', qlit(100, USD)) }],
    prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'b.pay' }, res: anyRes, cond: tru }],
    bounds: [{ bid: 'b1', sel: { k: 'effect', cls: 'c' }, agg: 'count', value: qlit(1, CNT), key: '', window: { k: 'task' }, scope: { k: 'session' }, cap: { u: USD, n: 100 }, onExceed: 'deny' }],
  });
  const flagging: Comparator = { id: 'c', family: 'f', async equivalent(text) { return { equivalent: text !== 'flag' }; } };

  it('counts applied and detected per kind, and the rate is detected over applied', async () => {
    const reps = await measureDetection([{ goal: full, text: 'ok' }, { goal: full, text: 'flag' }], o, deterministicExplainer, flagging);
    expect(reps).toEqual(MUTATION_KINDS.map((kind: MutationKind) => ({ kind, applied: 2, detected: 1, rate: 0.5 })));
  });
  it('a mutation that does not apply is not counted', async () => {
    const reps = await measureDetection([{ goal: goal(), text: 'flag' }], ont([{ id: 'r.read', effect: 'read' }]), deterministicExplainer, flagging);
    expect(reps).toEqual(MUTATION_KINDS.map((kind: MutationKind) => ({ kind, applied: 0, detected: 0, rate: 0 })));
  });
});
