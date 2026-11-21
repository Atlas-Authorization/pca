// Oracle: @atlasauth/pca-goal roundtrip.ts (card tape round trip, widening mutations, explainer+comparator detector).
// PORTING: cardRoundTrips(g) -> GoalRoundTrip.cardRoundTrips; mutateGoal(g, kind, ontology) -> GoalRoundTrip.mutateGoal (null = undefined);
//   roundTrip(goal, text, explainer, comparator) / measureDetection(cases, ontology, explainer, comparator) -> GoalRoundTrip.roundTrip / measureDetection,
//   with injected functions chosen by mode name: explainer card (deterministicExplain) | throw;
//   comparator ok (always equivalent) | no | throw | contains:<s> (equivalent iff the explanation contains s).
import * as R0 from '../../../packages/pca-goal/src/roundtrip';
import { Oracle, refWrite } from './lib.mjs';
const R: any = (R0 as any).default ?? R0;
const o = new Oracle('goal-roundtrip', 'tools/pca-audit/oracles/goal-roundtrip.mts', 'TS-reference oracle for pca-goal roundtrip.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const USD = { k: 'money', ccy: 'USD' }, CNT = { k: 'count' };
const qn = (u: any, v: number) => ({ u, n: v });
const lq = (u: any, v: number) => ({ k: 'lit', v: { k: 'q', q: qn(u, v) } });
const pq = (path: string, u: any = USD) => ({ k: 'param', path, ty: { k: 'q', u } });
const ps = (path: string) => ({ k: 'param', path, ty: { k: 's' } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const base = (over: any) => ({ v: 1, principal: 'alice', ontDigest: 'o', nlDigest: 'n', sources: ['s1'], grants: [], prohibits: [], bounds: [], validity: { notBefore: 0, notAfter: 100000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g1'] }, escalateOn: [], wildcardAck: [], holes: [], ...over });
const ONTO = { id: 'x', version: 1, domain: 'd', types: [], units: {}, relations: [], aliases: {}, templates: [], verbs: [{ id: 'pay', effect: 'irreversible', resource_type: 't', params: {} }, { id: 'read', effect: 'read', resource_type: 't', params: {} }, { id: 'send', effect: 'external_send', resource_type: 't', params: {} }, { id: 'wipe', effect: 'irreversible', resource_type: 't', params: {} }] };
const sumB = { bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'sum', value: pq('amount'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: qn(USD, 500), onExceed: 'deny' };
const cntB = { bid: 'b2', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: lq(CNT, 1), key: '', window: { k: 'task' }, scope: { k: 'org' }, cap: qn(CNT, 3), onExceed: 'escalate' };
const durB = { bid: 'b3', sel: { k: 'effect', cls: 'read' }, agg: 'max', value: pq('amount'), key: '', window: { k: 'lifetime' }, scope: { k: 'org' }, cap: { u: { k: 'duration' }, n: 7 }, onExceed: 'deny' };
const GA = base({
  grants: [{ gid: 'g1', verb: 'pay', res: { k: 'exact', id: 'acct:a' }, cond: { k: 'and', a: cmp('lte', pq('amount'), lq(USD, 100)), b: { k: 'or', a: cmp('lt', pq('n', CNT), lq(CNT, 5)), b: cmp('gt', pq('amount'), lq(USD, 7)) } } }, { gid: 'g2', verb: 'read', res: { k: 'oneof', ids: ['d1', 'd2'] }, cond: { k: 'true' } }],
  prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'wipe' }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } }, { pid: 'p2', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'oneof', ids: ['v'] }, cond: { k: 'true' } }],
  bounds: [sumB, cntB], escalateOn: [cmp('gt', pq('amount'), lq(USD, 40))],
});
const GB = base({ grants: [{ gid: 'g1', verb: 'read', res: { k: 'any', reason: 'r' }, cond: cmp('lte', ps('x'), { k: 'lit', v: { k: 's', s: 'z' } }) }], wildcardAck: ['g1'], holes: [{ hid: 'h', q: 'q', domain: ['a'], affects: [], global: true }] });
const GC = base({ grants: [{ gid: 'g1', verb: 'send', res: { k: 'related', rel: 'team', anchor: 'alice' }, cond: { k: 'not', c: cmp('lte', pq('amount'), lq(USD, 9)) } }], bounds: [durB], prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'pay' }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } }] });
const GD = base({ grants: [{ gid: 'g1', verb: 'pay', res: { k: 'exact', id: 'acct:z' }, cond: { k: 'true' } }, { gid: 'g2', verb: 'send', res: { k: 'all_of', parts: [{ k: 'exact', id: 'a' }, { k: 'oneof', ids: ['a', 'b'] }] }, cond: cmp('lte', pq('amount', { k: 'ratio' }), lq({ k: 'ratio' }, 4)) }] });
const GE = base({});
const GOALS = [GA, GB, GC, GD, GE];
for (const g of GOALS) await run('cardRoundTrips', R.cardRoundTrips, [g]);
await run('cardRoundTrips', R.cardRoundTrips, [{ ...GA, extra: 1 }]);
await run('cardRoundTrips', R.cardRoundTrips, [{ ...GA, deleg: { ...GA.deleg, narrowOnly: 1 } }]);
await run('cardRoundTrips', R.cardRoundTrips, [{ ...GA, v: 1.5 }]);
for (const g of GOALS) for (const kind of R.MUTATION_KINDS) await run('mutateGoal', (gg: any, k: string, ont: any) => R.mutateGoal(gg, k, ont) ?? null, [g, kind, ONTO]);
await run('mutateGoal', (gg: any, k: string, ont: any) => R.mutateGoal(gg, k, ont) ?? null, [GA, 'bogus', ONTO]);
await run('mutateGoal', (gg: any, k: string, ont: any) => R.mutateGoal(gg, k, ont) ?? null, [GE, 'add_grant', { ...ONTO, verbs: [{ id: 'read', effect: 'read', resource_type: 't', params: {} }] }]);
await run('mutateGoal', (gg: any, k: string, ont: any) => R.mutateGoal(gg, k, ont) ?? null, [GE, 'add_grant', { ...ONTO, verbs: [] }]);
const explainerOf = (m: string) => ({ id: m, async explain(p: string[]) { if (m === 'throw') throw new Error('boom'); return p.join('\n'); } });
const comparatorOf = (m: string) => ({ id: m, family: 'f', async equivalent(_t: string, e: string) { if (m === 'throw') throw new Error('boom'); if (m === 'ok') return { equivalent: true }; if (m === 'no') return { equivalent: false, reason: 'x' }; return { equivalent: e.includes(m.slice(9)) }; } });
const rtF = (g: any, text: string, ex: string, cm: string) => R.roundTrip(g, text, explainerOf(ex), comparatorOf(cm));
for (const g of [GA, GB, GE]) for (const ex of ['card', 'throw']) for (const cm of ['ok', 'no', 'throw', 'contains:ALLOW "g1"', 'contains:zzz']) await run('roundTrip', rtF, [g, 'text', ex, cm]);
const mdF = (cases: any, ont: any, ex: string, cm: string) => R.measureDetection(cases, ont, explainerOf(ex), comparatorOf(cm));
const cases = GOALS.map((g, i) => ({ goal: g, text: 'text ' + i }));
for (const cm of ['ok', 'no', 'throw', 'contains:ALLOW "g1"', 'contains:exactly "acct:a"']) await run('measureDetection', mdF, [cases, ONTO, 'card', cm]);
await run('measureDetection', mdF, [[], ONTO, 'card', 'ok']);
await run('measureDetection', mdF, [cases, ONTO, 'throw', 'ok']);
refWrite(o, 'goal-roundtrip');
