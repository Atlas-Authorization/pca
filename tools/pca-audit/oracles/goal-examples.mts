// Oracle: @atlasauth/pca-goal examples.ts (decision cells, boundary examples, goal tests, policy pin). Deterministic; Ed25519 via seeds.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   buildSpace(goals, extraVerbs) -> GoalExamples.buildSpace(...).toJson()   (Maps become objects)
//   cellKey(goals, extraVerbs, case) -> GoalExamples.cellKey(buildSpace(goals, extraVerbs), case)
//   cells(goals, extraVerbs, verbsOrNull) -> GoalExamples.cells(buildSpace(..), verbs)  => {cases, complete}
//   decideCase(g, ont, c) / replay(g, ont, acts, rels) / allowWitness(g, grantIndex, ont) / boundaryExamples(g, ont, extra, verbs) / reviewSet(ex, cap)
//   testsDigest(tests) / makeGoalTests(g, confirmed) / signGoalTestsSeed(set, seedB64u) / checkGoalTests(signed, pins, mode, g, ont)
//   (mode: ref = decideCase of g, allow, deny, ask) / signPinSeed(pin, seedB64u) / checkPin(pin, pins, cur)
import * as E0 from '../../../packages/pca-goal/src/examples';
import * as D0 from '../../../packages/pca-goal/src/digests';
import * as S0 from '../../../packages/pca-goal/src/sign';
import { Oracle, refWrite, seed } from './lib.mjs';
const E: any = (E0 as any).default ?? E0;
const D: any = (D0 as any).default ?? D0;
const S: any = (S0 as any).default ?? S0;
const o = new Oracle('goal-examples', 'tools/pca-audit/oracles/goal-examples.mts', 'TS-reference oracle for pca-goal examples.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const USD = { k: 'money', ccy: 'USD' }, CNT = { k: 'count' };
const qn = (u: any, v: number) => ({ u, n: v });
const lq = (u: any, v: number) => ({ k: 'lit', v: { k: 'q', q: qn(u, v) } });
const ls = (s: string) => ({ k: 'lit', v: { k: 's', s } });
const pq = (path: string, u: any = USD) => ({ k: 'param', path, ty: { k: 'q', u } });
const ps = (path: string) => ({ k: 'param', path, ty: { k: 's' } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const base = (over: any) => ({ v: 1, principal: 'alice', ontDigest: 'ont1', nlDigest: 'nl1', sources: [], grants: [], prohibits: [], bounds: [], validity: { notBefore: 0, notAfter: 100000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g1', 'g2'] }, escalateOn: [], wildcardAck: [], holes: [], ...over });
const ONT = { verbs: [{ verb: 'pay', cls: 'irreversible', params: [{ path: 'amount', ty: { k: 'q', u: USD } }, { path: 'to', ty: { k: 's' } }] }, { verb: 'read', cls: 'read', params: [] }, { verb: 'wipe', cls: 'irreversible', params: [] }], rels: [{ rel: 'team', anchor: 'alice', members: ['m1'] }] };
const GA = base({
  grants: [{ gid: 'g1', verb: 'pay', res: { k: 'oneof', ids: ['acct:a', 'acct:b'] }, cond: { k: 'and', a: cmp('lte', pq('amount'), lq(USD, 50)), b: cmp('in', ps('to'), { k: 'lit', v: { k: 'set', items: [{ k: 's', s: 'x' }, { k: 's', s: 'y' }] } }) } }],
  bounds: [{ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'sum', value: pq('amount'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: qn(USD, 100), onExceed: 'deny' }],
});
const GB = base({
  grants: [{ gid: 'g1', verb: 'read', res: { k: 'related', rel: 'team', anchor: 'alice' }, cond: { k: 'true' } }, { gid: 'g2', verb: 'pay', res: { k: 'exact', id: 'acct:a' }, cond: cmp('gte', pq('amount'), lq(USD, 5)) }],
  prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'wipe' }, res: { k: 'any', reason: 'never' }, cond: { k: 'true' } }],
  bounds: [{ bid: 'b1', sel: { k: 'gids', gids: ['g2'] }, agg: 'count', value: lq(CNT, 1), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: qn(CNT, 2), onExceed: 'escalate' }],
  escalateOn: [cmp('gt', pq('amount'), lq(USD, 40))],
});
const GC = base({ grants: [{ gid: 'g1', verb: 'read', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }], wildcardAck: ['g1'] });
const GD = base({ grants: [] });
const GE = base({
  grants: [{ gid: 'g1', verb: 'pay', res: { k: 'all_of', parts: [{ k: 'oneof', ids: ['acct:a', 'acct:b'] }, { k: 'exact', id: 'acct:a' }] }, cond: { k: 'or', a: cmp('lt', pq('amount'), lq(USD, 10)), b: { k: 'not', c: cmp('ne', ps('to'), ls('z')) } } }],
  bounds: [{ bid: 'b1', sel: { k: 'effect', cls: 'irreversible' }, agg: 'max', value: pq('amount'), key: '', window: { k: 'task' }, scope: { k: 'org' }, cap: qn(USD, 8), onExceed: 'deny' }],
});
const GF = base({ grants: [{ gid: 'g1', verb: 'pay', res: { k: 'exact', id: 'acct:a' }, cond: cmp('lte', pq('amount', { k: 'instant' }), lq({ k: 'instant' }, 7)) }] });
const GOALS = [GA, GB, GC, GD, GE, GF];
const mkAct = (verb: string, res: string, params: any = {}, over: any = {}) => ({ verb, res, params, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0, ...over });
const sval = (s: string) => ({ k: 's', s });
const qval = (u: any, v: number) => ({ k: 'q', q: qn(u, v) });

const spaceJson = (goals: any[], extra: string[]) => E.buildSpace(goals, extra);
for (const [i, g] of GOALS.entries()) await run('buildSpace', spaceJson, [[g], []]);
await run('buildSpace', spaceJson, [[GA, GB], ['extra', 'pay']]);
await run('buildSpace', spaceJson, [[], []]);
await run('buildSpace', spaceJson, [[GA, GE, GF], []]);
const cellKeyF = (goals: any[], extra: string[], c: any) => E.cellKey(E.buildSpace(goals, extra), c);
const cellsF = (goals: any[], extra: string[], verbs: any) => E.cells(E.buildSpace(goals, extra), verbs === null ? {} : { verbs });
for (const [i, g] of GOALS.entries()) {
  await run('cells', cellsF, [[g], [], null]);
}
await run('cells', cellsF, [[GA, GB], ['read'], null]);
await run('cells', cellsF, [[GA], [], ['pay']]);
await run('cells', cellsF, [[GA, GB, GE], [], null]);
const cs: any[] = [
  { act: mkAct('pay', 'acct:a', { amount: qval(USD, 50), to: sval('x') }), rels: [] },
  { act: mkAct('pay', 'acct:a', { amount: qval(USD, 51), to: sval('q') }), rels: [] },
  { act: mkAct('pay', 'acct:z', { amount: qval(CNT, 1) }), rels: [] },
  { act: mkAct('read', 'm1', {}), rels: [{ rel: 'team', anchor: 'alice', members: ['m1'] }] },
  { act: mkAct('read', 'm1', {}), rels: [{ rel: 'team', anchor: 'alice', members: [] }] },
  { act: mkAct('read', 'm1', {}), rels: [] },
  { act: mkAct('nope', 'zz', { zz: sval('a') }), rels: [] },
];
for (const g of [[GA], [GB], [GA, GB]]) for (const c of cs) await run('cellKey', cellKeyF, [g, [], c]);
// decideCase / replay
for (const g of [GA, GB, GC, GE]) for (const c of cs) {
  await run('decideCase', E.decideCase, [g, ONT, c]);
  await run('decideCase', E.decideCase, [g, ONT, { act: c.act }]);
}
for (const g of [GA, GB]) {
  const acts = [mkAct('pay', 'acct:a', { amount: qval(USD, 50), to: sval('x') }, { t: 1 }), mkAct('pay', 'acct:a', { amount: qval(USD, 50), to: sval('y') }, { t: 2 }), mkAct('pay', 'acct:a', { amount: qval(USD, 50), to: sval('x') }, { t: 3 }), mkAct('pay', 'acct:b', { amount: qval(USD, 60) }, { t: 4 }), mkAct('read', 'm1', {}, { t: 5 })];
  await run('replay', E.replay, [g, ONT, acts, []]);
  await run('replay', E.replay, [g, ONT, acts, [{ rel: 'team', anchor: 'alice', members: ['m1'] }]]);
}
// allowWitness
for (const g of [GA, GB, GC, GE, GF]) for (let i = 0; i < g.grants.length; i++) await run('allowWitness', (gg: any, idx: number, ont: any) => E.allowWitness(gg, gg.grants[idx], ont) ?? null, [g, i, ONT]);
// boundaryExamples
for (const g of [GA, GB, GC, GD, GE, GF]) await run('boundaryExamples', (gg: any, ont: any, extra: any, verbs: any) => E.boundaryExamples(gg, { ont, ...(extra ? { extra } : {}), ...(verbs ? { verbs } : {}) }), [g, ONT, null, null]);
await run('boundaryExamples', (gg: any, ont: any, extra: any, verbs: any) => E.boundaryExamples(gg, { ont, ...(extra ? { extra } : {}), ...(verbs ? { verbs } : {}) }), [GC, ONT, [GA], ['wipe']]);
// reviewSet
const exs: any[] = E.boundaryExamples(GB, { ont: ONT }).examples;
for (const cap of [0, 1, 3, 7, 1000]) await run('reviewSet', E.reviewSet, [exs, cap]);
// tests digest / make / check / pin
const tests = exs.slice(0, 6).map((e: any, i: number) => ({ id: e.id, act: e.act, hist: e.hist, rels: e.rels, answer: ['allow', 'deny', 'ask'][i % 3] }));
await run('testsDigest', E.testsDigest, [tests]);
await run('testsDigest', E.testsDigest, [[...tests].reverse()]);
await run('testsDigest', E.testsDigest, [[]]);
const confirmed = exs.slice(0, 5).map((e: any, i: number) => ({ example: e, answer: ['allow', 'deny', 'ask'][i % 3] }));
await run('makeGoalTests', E.makeGoalTests, [GB, confirmed]);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const sd = (l: string) => seed('goal-examples/' + l);
const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const set: any = E.makeGoalTests(GB, exs.slice(0, 8).map((e: any) => ({ example: e, answer: e.decision === 'allow' ? 'allow' : e.decision === 'deny' ? 'deny' : 'ask' })));
await run('signGoalTestsSeed', (s: any, sb: string) => E.signGoalTests(s, fromB64(sb)), [set, b64(sd('a'))]);
const signed: any = E.signGoalTests(set, sd('a'));
const pk = S.signerId(sd('a')), pk2 = S.signerId(sd('b'));
const checkF = (sg: any, pins: any, mode: string, g: any, ont: any) => E.checkGoalTests(sg, pins, mode === 'ref' ? (t: any) => E.decideCase(g, ont, t).decision : () => (mode === 'allow' ? 'allow' : mode === 'deny' ? 'deny' : 'escalate'));
for (const mode of ['ref', 'allow', 'deny', 'ask']) {
  await run('checkGoalTests', checkF, [signed, [pk], mode, GB, ONT]);
  await run('checkGoalTests', checkF, [signed, [pk2], mode, GB, ONT]);
}
await run('checkGoalTests', checkF, [signed, [pk], 'ref', GA, ONT]);
await run('checkGoalTests', checkF, [{ ...signed, payload: { ...signed.payload, tests_digest: 'x' } }, [pk], 'ref', GB, ONT]);
const policyDigest = 'pd1';
const pin: any = { goal_digest: D.goalDigest(GB), policy_digest: policyDigest, tests_digest: set.tests_digest, ontology_digest: GB.ontDigest };
await run('signPinSeed', (p: any, sb: string) => E.signPin(p, fromB64(sb)), [pin, b64(sd('a'))]);
const sp: any = E.signPin(pin, sd('a'));
const cur = { goal: GB, policy_digest: policyDigest, tests: set };
for (const [nm, p, pins, c] of [
  ['ok', sp, [pk], cur], ['wrong-pin', sp, [pk2], cur], ['goal', sp, [pk], { ...cur, goal: GA }], ['policy', sp, [pk], { ...cur, policy_digest: 'other' }],
  ['tests', sp, [pk], { ...cur, tests: { ...set, tests_digest: 'zz' } }], ['tests-edit', sp, [pk], { ...cur, tests: { ...set, tests: set.tests.slice(1) } }],
  ['ont', sp, [pk], { ...cur, goal: { ...GB, ontDigest: 'o2' } }],
] as any[]) await run('checkPin', E.checkPin, [p, pins, c]);
refWrite(o, 'goal-examples');
