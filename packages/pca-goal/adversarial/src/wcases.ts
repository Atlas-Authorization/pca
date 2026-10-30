// Hand-authored weakness cases (W1..W23, IR level). Expected outcomes are HAND-LABELLED (`want`), not oracle-derived; building the
// corpus throws if the oracle disagrees with a label. They ship as vectors (kind 'w') so every language runner checks them too.
import type { Act, Adm, Bound, Cond, Decision, Goal, Quantity, Scope, Value, Window } from './types.ts';
import { DOMAINS, eurU, usdU, vq, vs } from './domains.ts';
import { BASE_T, act, andAll, ctrue, emptyGoal, lit, mkCase, mkHist, param, type Case, type Probe } from './gen.ts';
import { decide } from './oracle.ts';

const [PAY, EMAIL] = [DOMAINS[0]!, DOMAINS[1]!];
export const usd = (n: number): Value => vq(usdU, n);
const eur = (n: number): Value => vq(eurU, n);
const cnt = (n: number): Value => vq({ k: 'count' }, n);
export { act };
const lte = (path: string, v: Value): Cond => ({ k: 'cmp', op: 'lte', l: param(path), r: lit(v) });
const gt = (path: string, v: Value): Cond => ({ k: 'cmp', op: 'gt', l: param(path), r: lit(v) });
const goal = (dom: typeof PAY, f: (g: Goal) => void): Goal => { const g = emptyGoal(dom); f(g); return g; };
type WP = { a: Act; h?: Adm[]; want: Decision; gid?: string };
type WCase = { w: string; name: string; dom: typeof PAY; goal: Goal; compile?: string[]; probes: WP[] };
const ent = (a: Act, gid = 'g1'): Adm => ({ gid, act: a });
const refundGoal = (f: (g: Goal) => void = () => {}): Goal => goal(PAY, (g) => {
  g.grants = [{ gid: 'g1', verb: 'refund', res: { k: 'oneof', ids: ['ch_1', 'ch_2'] }, cond: lte('amount', usd(20000)) }];
  f(g);
});
const q1 = (n: number): Quantity => ({ u: { k: 'count' }, n });
const sumBound = (window: Window, scope: Scope, cap = 20000, onExceed: 'deny' | 'escalate' = 'deny'): Bound =>
  ({ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'sum', value: param('amount'), key: '', window, scope, cap: { u: usdU, n: cap }, onExceed });
const countBound = (bid: string, window: Window, n: number): Bound => ({ bid, sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: lit({ k: 'q', q: q1(1) }), key: '', window, scope: { k: 'session' }, cap: q1(n), onExceed: 'deny' });
const DAY = 86_400_000;
const r = (amt: number, t = BASE_T, over: Partial<Act> = {}) => act('refund', 'ch_1', { amount: usd(amt) }, t, over);

export const WCASES: WCase[] = [
  { w: 'W5', name: 'sliding day window is exactly 24h, cap exact', dom: PAY, goal: refundGoal((g) => g.bounds.push(sumBound({ k: 'sliding', ms: DAY }, { k: 'principal' }))),
    probes: [
      { a: r(5000), h: [ent(r(15000, BASE_T - 1000))], want: 'allow', gid: 'g1' },
      { a: r(5001), h: [ent(r(15000, BASE_T - 1000))], want: 'deny' },
      { a: r(5000), h: [ent(r(15000, BASE_T - DAY))], want: 'allow', gid: 'g1' }, // exactly 24h ago is outside (t > a.t - ms)
      { a: r(5000), h: [ent(r(15000, BASE_T - DAY + 1))], want: 'allow', gid: 'g1' },
      { a: r(5001), h: [ent(r(15000, BASE_T - DAY + 1))], want: 'deny' },
    ] },
  { w: 'W5', name: 'period window resets at the period edge (explicit t0)', dom: PAY, goal: refundGoal((g) => g.bounds.push(sumBound({ k: 'period', ms: DAY, t0: BASE_T - 1000 }, { k: 'principal' }))),
    probes: [
      { a: r(5000, BASE_T + 10), h: [ent(r(15000, BASE_T - 500))], want: 'allow', gid: 'g1' },
      { a: r(5001, BASE_T + 10), h: [ent(r(15000, BASE_T - 500))], want: 'deny' },
      { a: r(20000, BASE_T + DAY), h: [ent(r(20000, BASE_T + DAY - 2000))], want: 'allow', gid: 'g1' }, // next period
    ] },
  { w: 'W6', name: 'a sum bound over a param no verb declares compiles but is never Allow: the aggregate is Unknown, so every admission escalates (fail closed)', dom: PAY,
    goal: refundGoal((g) => g.bounds.push({ ...sumBound({ k: 'lifetime' }, { k: 'session' }), value: { k: 'param', path: 'amount_cents', ty: { k: 'q', u: usdU } } })),
    probes: [{ a: r(100), want: 'escalate' }, { a: r(30000), want: 'deny' }] },
  { w: 'W7', name: 'adding a second count limit keeps the first (no rate-caveat drop)', dom: PAY,
    goal: refundGoal((g) => g.bounds.push(countBound('b1', { k: 'sliding', ms: 60_000 }, 2), countBound('b2', { k: 'lifetime' }, 5))),
    probes: [
      { a: r(100, BASE_T), h: [ent(r(100, BASE_T - 1000))], want: 'allow', gid: 'g1' },
      { a: r(100, BASE_T), h: [ent(r(100, BASE_T - 1000)), ent(r(100, BASE_T - 2000))], want: 'deny' }, // b1 exceeded (the candidate counts)
      { a: r(100, BASE_T), h: [1, 2, 3, 4, 5].map((i) => ent(r(100, BASE_T - 100_000 * i))), want: 'deny' }, // b2 exceeded
    ] },
  { w: 'W7', name: 'a dollar cap does not drop the escalation tier (escalate_on stays); a true trigger caps the decision at escalate, never above', dom: PAY,
    goal: refundGoal((g) => { g.bounds.push(sumBound({ k: 'lifetime' }, { k: 'session' }, 50000)); g.escalateOn.push(gt('amount', usd(10000))); }),
    probes: [{ a: r(100), want: 'allow', gid: 'g1' }, { a: r(15000), want: 'escalate' }, { a: r(30000), want: 'deny' }, { a: act('delete_customer', 'cust:C1'), want: 'deny' }] },
  { w: 'W8', name: 'salami split across sessions under a principal-scope cap', dom: PAY,
    goal: refundGoal((g) => g.bounds.push(sumBound({ k: 'lifetime' }, { k: 'principal' }, 5000))),
    probes: [
      { a: r(1900, BASE_T, { sess: 's3' }), h: [ent(r(1900, BASE_T - 3, { sess: 's1' })), ent(r(1900, BASE_T - 2, { sess: 's2' }))], want: 'deny' },
      { a: r(1200, BASE_T, { sess: 's3' }), h: [ent(r(1900, BASE_T - 3, { sess: 's1' })), ent(r(1900, BASE_T - 2, { sess: 's2' }))], want: 'allow', gid: 'g1' },
    ] },
  { w: 'W8', name: 'control: the same history under a session-scope cap is NOT shared (why principal scope exists)', dom: PAY,
    goal: refundGoal((g) => g.bounds.push(sumBound({ k: 'lifetime' }, { k: 'session' }, 5000))),
    probes: [{ a: r(1900, BASE_T, { sess: 's3' }), h: [ent(r(1900, BASE_T - 3, { sess: 's1' })), ent(r(1900, BASE_T - 2, { sess: 's2' }))], want: 'allow', gid: 'g1' }] },
  { w: 'W9', name: 'org and fleet scopes share one cap across principals and agents', dom: PAY,
    goal: refundGoal((g) => g.bounds.push(sumBound({ k: 'lifetime' }, { k: 'org' }, 3000), { ...sumBound({ k: 'lifetime' }, { k: 'fleet', agents: ['a2', 'a3'] }, 2500), bid: 'b2' })),
    probes: [
      { a: r(1500, BASE_T, { prin: 'pr1' }), h: [ent(r(1600, BASE_T - 2, { prin: 'pr2', agent: 'a9' }))], want: 'deny' }, // org cap 3000: 1600+1500
      { a: r(1300, BASE_T, { prin: 'pr1' }), h: [ent(r(1600, BASE_T - 2, { prin: 'pr2', agent: 'a9' }))], want: 'allow', gid: 'g1' },
      { a: r(1300, BASE_T, { agent: 'a3' }), h: [ent(r(1300, BASE_T - 2, { agent: 'a2' }))], want: 'deny' }, // fleet {a2,a3}: 1300+1300 > 2500
      { a: r(1200, BASE_T, { agent: 'a3' }), h: [ent(r(1300, BASE_T - 2, { agent: 'a2' }))], want: 'allow', gid: 'g1' },
      { a: r(1300, BASE_T, { agent: 'a1' }), h: [ent(r(1300, BASE_T - 2, { agent: 'a2' }))], want: 'allow', gid: 'g1' }, // candidate outside the fleet: nothing of the fleet counts
    ] },
  { w: 'W10', name: 'delegate acts only under a gid the delegation names; depth capped', dom: PAY,
    goal: refundGoal((g) => {
      g.grants.push({ gid: 'g2', verb: 'read_charge', res: { k: 'any', reason: 'read' }, cond: ctrue });
      g.wildcardAck.push('g2'); g.deleg = { maxDepth: 2, narrowOnly: true, mayTouch: ['g2'] };
    }),
    probes: [
      { a: act('read_charge', 'ch_1', {}, BASE_T, { depth: 1 }), want: 'allow', gid: 'g2' },
      { a: act('refund', 'ch_1', { amount: usd(100) }, BASE_T, { depth: 1 }), want: 'deny' },
      { a: act('read_charge', 'ch_1', {}, BASE_T, { depth: 3 }), want: 'deny' },
      { a: act('refund', 'ch_1', { amount: usd(100) }, BASE_T, { depth: 0 }), want: 'allow', gid: 'g1' },
    ] },
  { w: 'W22', name: 'goal says no sub-agents (max_depth 0)', dom: PAY, goal: refundGoal((g) => { g.deleg = { maxDepth: 0, narrowOnly: true, mayTouch: [] }; }),
    probes: [{ a: r(100), want: 'allow', gid: 'g1' }, { a: r(100, BASE_T, { depth: 1 }), want: 'deny' }] },
  { w: 'W22', name: 'idle expiry: maxIdle 0 is off; a gap longer than maxIdle since the last admitted action denies', dom: PAY,
    goal: refundGoal((g) => { g.validity = { ...g.validity, maxIdle: 3600_000 }; }),
    probes: [
      { a: r(100, BASE_T + 3600_000), h: [ent(r(100, BASE_T))], want: 'allow', gid: 'g1' },
      { a: r(100, BASE_T + 3600_001), h: [ent(r(100, BASE_T))], want: 'deny' },
      { a: r(100, BASE_T + 99_999_999), want: 'allow', gid: 'g1' }, // no history: nothing to be idle since
    ] },
  { w: 'W12', name: 'ambiguous goal is a draft with a hole: dependent grant dropped, never allowed', dom: PAY,
    goal: refundGoal((g) => {
      g.grants.push({ gid: 'g2', verb: 'delete_customer', res: { k: 'exact', id: 'cust:C1' }, cond: ctrue });
      g.holes.push({ hid: 'h1', q: 'Should deleting customers be allowed?', domain: ['yes', 'no'], affects: ['g2'], global: false });
    }),
    probes: [{ a: act('delete_customer', 'cust:C1'), want: 'deny' }, { a: r(100), want: 'allow', gid: 'g1' }] },
  { w: 'W12', name: 'a global hole drops every grant', dom: PAY,
    goal: refundGoal((g) => { g.holes.push({ hid: 'h1', q: 'Which customer?', domain: [], affects: [], global: true }); }),
    probes: [{ a: r(100), want: 'deny' }] },
  { w: 'W13', name: 'prohibition by effect class catches every verb of the class (no synonym escapes)', dom: EMAIL,
    goal: goal(EMAIL, (g) => {
      g.grants = [{ gid: 'g1', verb: 'archive', res: { k: 'any', reason: 'mail' }, cond: ctrue }, { gid: 'g2', verb: 'bulk_remove', res: { k: 'any', reason: 'mail' }, cond: ctrue }, { gid: 'g3', verb: 'delete', res: { k: 'any', reason: 'mail' }, cond: ctrue }, { gid: 'g4', verb: 'trash', res: { k: 'any', reason: 'mail' }, cond: ctrue }];
      g.wildcardAck = ['g1', 'g2', 'g3', 'g4'];
      g.prohibits = [{ pid: 'x1', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'any', reason: 'never' }, cond: ctrue }];
    }),
    probes: [{ a: act('archive', 't1'), want: 'allow', gid: 'g1' }, { a: act('bulk_remove', 't1'), want: 'deny' }, { a: act('delete', 't1'), want: 'deny' }, { a: act('trash', 't1'), want: 'deny' }] },
  { w: 'W13', name: 'a prohibition whose condition is Unknown escalates (never allows, never silently ignored)', dom: PAY,
    goal: refundGoal((g) => { g.prohibits = [{ pid: 'x1', target: { k: 'verb', verb: 'refund' }, res: { k: 'any', reason: 'ban' }, cond: gt('amount', usd(10000)) }]; }),
    probes: [{ a: r(100), want: 'allow', gid: 'g1' }, { a: r(15000), want: 'deny' }, { a: act('refund', 'ch_1', {}), want: 'escalate' }] },
  { w: 'W18', name: 'currency and unit confusion: EUR amount never satisfies a USD ceiling; minor units exact', dom: PAY,
    goal: refundGoal(() => {}),
    probes: [
      { a: act('refund', 'ch_1', { amount: eur(100) }), want: 'escalate' }, // mixed unit => Unknown => escalate, never allow
      { a: act('refund', 'ch_1', { amount: usd(20000) }), want: 'allow', gid: 'g1' }, // $200.00 exactly
      { a: act('refund', 'ch_1', { amount: usd(20001) }), want: 'deny' },
      { a: act('refund', 'ch_1', { amount: cnt(100) }), want: 'escalate' },
    ] },
  { w: 'W18', name: 'ill-typed: a USD ceiling on a param the ontology declares in EUR', dom: { ...PAY, ontology: { ...PAY.ontology, verbs: PAY.ontology.verbs.map((v) => ({ ...v, params: v.params.map((p) => (p.path === 'amount' ? { path: 'amount', ty: { k: 'q' as const, u: eurU } } : p)) })) } },
    compile: ['ill_typed_grant'], goal: refundGoal(() => {}), probes: [] },
  { w: 'W19', name: 'unicode identity: ids are compared byte-exact (NFD, homoglyph, zero-width are different ids)', dom: PAY,
    goal: goal(PAY, (g) => { g.grants = [{ gid: 'g1', verb: 'read_charge', res: { k: 'oneof', ids: ['cust:C1', 'cust:Café'] }, cond: ctrue }]; }),
    probes: [
      { a: act('read_charge', 'cust:C1'), want: 'allow', gid: 'g1' },
      { a: act('read_charge', 'cust:Café'), want: 'allow', gid: 'g1' }, // NFC
      { a: act('read_charge', 'cust:Café'), want: 'deny' }, // NFD is a different id
      { a: act('read_charge', 'cust:С' + '1'), want: 'deny' }, // Cyrillic Es
      { a: act('read_charge', 'cust:C1​'), want: 'deny' }, // zero-width space
    ] },
  { w: 'W21', name: 'unknown condition value escalates, never allows', dom: PAY, goal: refundGoal(() => {}),
    probes: [{ a: act('refund', 'ch_1', {}), want: 'escalate' }, { a: act('refund', 'ch_9', { amount: usd(1) }), want: 'deny' }] },
  { w: 'W23', name: 'resource scope: related set resolves; this customer only', dom: PAY,
    goal: goal(PAY, (g) => { g.grants = [{ gid: 'g1', verb: 'refund', res: { k: 'related', rel: 'charges_of', anchor: 'cust:C1' }, cond: ctrue }]; }),
    probes: [{ a: act('refund', 'ch_2', {}), want: 'allow', gid: 'g1' }, { a: act('refund', 'ch_4', {}), want: 'deny' }] },
  { w: 'W23', name: 'all_of is the intersection of its parts (the N-version meet narrows, never widens)', dom: PAY,
    goal: goal(PAY, (g) => { g.grants = [{ gid: 'g1', verb: 'refund', res: { k: 'all_of', parts: [{ k: 'related', rel: 'charges_of', anchor: 'cust:C1' }, { k: 'oneof', ids: ['ch_1', 'ch_4'] }] }, cond: ctrue }]; }),
    probes: [{ a: act('refund', 'ch_1', {}), want: 'allow', gid: 'g1' }, { a: act('refund', 'ch_2', {}), want: 'deny' }, { a: act('refund', 'ch_4', {}), want: 'deny' }] },
  { w: 'W23', name: 'wildcard resource without wildcard_ack is a compile error', dom: PAY, compile: ['ill_typed_grant'],
    goal: goal(PAY, (g) => { g.grants = [{ gid: 'g1', verb: 'refund', res: { k: 'any', reason: 'x' }, cond: ctrue }]; }), probes: [] },
  { w: 'W23', name: 'clauses out of canonical order are a compile error (G-T5: one order, one digest)', dom: PAY, compile: ['not_canonical_order'],
    goal: goal(PAY, (g) => { g.grants = [{ gid: 'g2', verb: 'read_charge', res: { k: 'exact', id: 'ch_1' }, cond: ctrue }, { gid: 'g1', verb: 'read_charge', res: { k: 'exact', id: 'ch_2' }, cond: ctrue }]; }), probes: [] },
];
void andAll; void vs;

export function wCorpus(): Case[] {
  return WCASES.map((c, i) => {
    const probes: Probe[] = c.probes.map((p) => {
      const h = mkHist(p.h ?? []);
      const expect = decide(c.goal, c.dom.ontology, p.a, h);
      if (expect.decision !== p.want || (p.gid && expect.witness?.gid !== p.gid)) throw new Error(`${c.w} "${c.name}": oracle says ${JSON.stringify(expect)}, label says ${p.want}/${p.gid}`);
      return { action: p.a, history: h, expect };
    });
    const k = mkCase({ id: `w-${c.w.toLowerCase()}-${String(i).padStart(2, '0')}`, kind: 'w', domain: c.dom.name, seed: 0, w: c.w, note: c.name, ontology: c.dom.ontology, goal: c.goal, probes, equiv: [] });
    if (c.compile && JSON.stringify(k.compile.reasons) !== JSON.stringify(c.compile)) throw new Error(`${c.w} "${c.name}": compile reasons ${k.compile.reasons}`);
    if (!c.compile && !k.compile.ok) throw new Error(`${c.w} "${c.name}": unexpected compile errors ${k.compile.reasons}`);
    return k;
  });
}
