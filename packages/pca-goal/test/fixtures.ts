// Seeded, deterministic generators over the IR grammar (no dependency: a 32-bit LCG).
import type { Act, Bound, Cond, Goal, Grant, Hist, Ontology, Prohibit, Quantity, Unit } from '../src/ir';

export const USD: Unit = { k: 'money', ccy: 'USD' };
export const EUR: Unit = { k: 'money', ccy: 'EUR' };
export const CNT: Unit = { k: 'count' };
export const usd = (n: number): Quantity => ({ u: USD, n });

export const ONT: Ontology = {
  verbs: [
    { verb: 'pay.refund', cls: 'money_out', params: [{ path: 'amount', ty: { k: 'q', u: USD } }, { path: 'customer', ty: { k: 's' } }] },
    { verb: 'pay.transfer', cls: 'money_out', params: [{ path: 'amount', ty: { k: 'q', u: USD } }] },
    { verb: 'pay.read', cls: 'read', params: [] },
    { verb: 'mail.send', cls: 'external_send', params: [{ path: 'to', ty: { k: 's' } }] },
  ],
  rels: [{ rel: 'charges_of', anchor: 'C1', members: ['ch_1', 'ch_2', 'ch_3'] }],
};

export class Rng {
  constructor(private s: number) {}
  next(): number { this.s = (Math.imul(this.s, 1664525) + 1013904223) >>> 0; return this.s; }
  int(n: number): number { return this.next() % n; }
  pick<T>(xs: readonly T[]): T { return xs[this.int(xs.length)]!; }
  bool(): boolean { return this.int(2) === 1; }
}

const amt = { k: 'param', path: 'amount', ty: { k: 'q', u: USD } } as const;
export const lteAmt = (n: number): Cond => ({ k: 'cmp', op: 'lte', l: amt, r: { k: 'lit', v: { k: 'q', q: usd(n) } } });
export const ctrue: Cond = { k: 'true' };

export function baseGoal(over: Partial<Goal> = {}): Goal {
  return {
    v: 1, principal: 'P1', ontDigest: 'ont1', nlDigest: 'nl1', sources: [],
    grants: [
      { gid: 'g1', verb: 'pay.refund', res: { k: 'related', rel: 'charges_of', anchor: 'C1' }, cond: lteAmt(5000) },
      { gid: 'g2', verb: 'pay.read', res: { k: 'any', reason: 'read anything' }, cond: ctrue },
    ],
    prohibits: [], bounds: [],
    validity: { notBefore: 0, notAfter: 1_000_000, maxIdle: 0 },
    deleg: { maxDepth: 2, narrowOnly: true, mayTouch: ['g1'] },
    escalateOn: [], wildcardAck: ['g2'], holes: [], ...over,
  };
}

export function randCond(r: Rng, depth = 0): Cond {
  const k = depth > 1 ? r.int(2) : r.int(5);
  if (k === 0) return ctrue;
  if (k === 1) {
    const op = r.pick(['eq', 'ne', 'lt', 'lte', 'gt', 'gte'] as const);
    const u = r.int(5) === 0 ? EUR : USD; // sometimes an ill-typed comparison: the typechecker must reject it, never coerce
    return { k: 'cmp', op, l: amt, r: { k: 'lit', v: { k: 'q', q: { u, n: r.int(10) * 1000 } } } };
  }
  if (k === 2) return { k: 'and', a: randCond(r, depth + 1), b: randCond(r, depth + 1) };
  if (k === 3) return { k: 'or', a: randCond(r, depth + 1), b: randCond(r, depth + 1) };
  return { k: 'not', c: randCond(r, depth + 1) };
}

export function randAct(r: Rng, t = r.int(1_200_000)): Act {
  const verb = r.pick(['pay.refund', 'pay.transfer', 'pay.read', 'mail.send', 'pay.wire'] as const);
  const params: Act['params'] = {};
  if (r.int(8) !== 0) params.amount = { k: 'q', q: r.int(7) === 0 ? { u: EUR, n: r.int(9000) } : usd(r.int(9) * 1000 + r.pick([0, 0, 1, -1] as const) + 1) };
  if (r.bool()) params.customer = { k: 's', s: r.pick(['C1', 'C2'] as const) };
  return { verb, res: r.pick(['ch_1', 'ch_2', 'ch_9', 'x'] as const), params, t, sess: r.pick(['s1', 's2'] as const), prin: 'P1', org: 'O', agent: r.pick(['a1', 'a2'] as const), depth: r.int(4) === 0 ? 1 : 0 };
}
export function randHist(r: Rng, g: Goal): Hist {
  const n = r.int(5);
  const adms = Array.from({ length: n }, () => ({ gid: r.pick(g.grants.length ? g.grants.map((x) => x.gid) : ['g1']), act: randAct(r, r.int(1_000_000)) }));
  return { adms, last: n ? r.int(1_000_000) : -1, aggs: {} };
}
export function randGoal(r: Rng): Goal {
  const grants: Grant[] = [
    { gid: 'g1', verb: 'pay.refund', res: r.int(4) === 0 ? { k: 'all_of', parts: [{ k: 'related', rel: 'charges_of', anchor: 'C1' }, { k: 'oneof', ids: ['ch_1', 'ch_9'] }] } : r.bool() ? { k: 'related', rel: 'charges_of', anchor: 'C1' } : { k: 'oneof', ids: ['ch_1', 'ch_9'] }, cond: randCond(r) },
    { gid: 'g2', verb: 'pay.transfer', res: { k: 'any', reason: 'r' }, cond: randCond(r) },
    { gid: 'g3', verb: 'pay.read', res: { k: 'exact', id: 'x' }, cond: ctrue },
  ].slice(0, 1 + r.int(3)) as Grant[];
  const prohibits: Prohibit[] = r.bool() ? [{ pid: 'p1', target: r.bool() ? { k: 'effect', cls: 'money_out' } : { k: 'verb', verb: 'mail.send' }, res: { k: 'any', reason: 'r' }, cond: randCond(r) }] : [];
  const bounds: Bound[] = r.bool() ? [{
    bid: 'b1', sel: r.bool() ? { k: 'gids', gids: ['g1'] } : { k: 'effect', cls: 'money_out' }, agg: r.pick(['count', 'sum'] as const),
    value: amt, key: '', window: r.pick([{ k: 'lifetime' }, { k: 'sliding', ms: 300_000 }, { k: 'period', ms: 200_000, t0: 0 }] as const),
    scope: r.pick([{ k: 'session' }, { k: 'principal' }] as const), cap: { u: USD, n: 0 }, onExceed: r.pick(['deny', 'escalate'] as const),
  }] : [];
  for (const b of bounds) b.cap = b.agg === 'count' ? { u: CNT, n: 1 + r.int(3) } : usd(1000 * (1 + r.int(9)));
  return baseGoal({ grants, prohibits, bounds, wildcardAck: ['g2'], escalateOn: r.int(4) === 0 ? [randCond(r)] : [] });
}
