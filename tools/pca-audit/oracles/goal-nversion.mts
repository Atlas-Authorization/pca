// Oracle: @atlasauth/pca-goal nversion.ts (semantic meet of readings, panel check) and disambiguate.ts (questions, halving). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value; scores are doubles, compared exactly):
//   meet(goals) -> GoalNVersion.meet; meetGrants(a, b) -> GoalNVersion.meetGrants; checkPanel(readings) -> GoalNVersion.checkPanel
//   nVersion(readings, ont, massThreshold|null) -> GoalNVersion.nVersion(readings, new Opts(ont), threshold)
//   questions(readings, ont) -> GoalDisambiguate.questions; disagreementMass(readings, ont); allowsWitness(goal, ont, w)
//   disambiguate(readings, ont, mode, budget|null) -> GoalDisambiguate.disambiguate (mode: allow | deny | truth:<i> = answer as reading i would)
import * as N0 from '../../../packages/pca-goal/src/nversion';
import * as D0 from '../../../packages/pca-goal/src/disambiguate';
import { Oracle, refWrite } from './lib.mjs';
const N: any = (N0 as any).default ?? N0;
const D: any = (D0 as any).default ?? D0;
const o = new Oracle('goal-nversion', 'tools/pca-audit/oracles/goal-nversion.mts', 'TS-reference oracle for pca-goal nversion and disambiguate.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const USD = { k: 'money', ccy: 'USD' }, CNT = { k: 'count' };
const qn = (u: any, v: number) => ({ u, n: v });
const lq = (u: any, v: number) => ({ k: 'lit', v: { k: 'q', q: qn(u, v) } });
const pq = (path: string, u: any = USD) => ({ k: 'param', path, ty: { k: 'q', u } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const base = (over: any) => ({ v: 1, principal: 'alice', ontDigest: 'ont1', nlDigest: 'nl1', sources: ['chat'], grants: [], prohibits: [], bounds: [], validity: { notBefore: 0, notAfter: 100000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g1', 'g2'] }, escalateOn: [], wildcardAck: [], holes: [], ...over });
const ONT = { verbs: [{ verb: 'pay', cls: 'irreversible', params: [{ path: 'amount', ty: { k: 'q', u: USD } }] }, { verb: 'read', cls: 'read', params: [] }, { verb: 'wipe', cls: 'irreversible', params: [] }], rels: [] };
const pay = (cap: number, ids: string[], gid = 'g1') => ({ gid, verb: 'pay', res: { k: 'oneof', ids }, cond: cmp('lte', pq('amount'), lq(USD, cap)) });
const sumB = (gid: string, cap: number, bid = 'b1', onExceed = 'deny') => ({ bid, sel: { k: 'gids', gids: [gid] }, agg: 'sum', value: pq('amount'), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: qn(USD, cap), onExceed });
const R1 = base({ grants: [pay(50, ['acct:a', 'acct:b'])], bounds: [sumB('g1', 100)] });
const R2 = base({ grants: [pay(100, ['acct:a'])], bounds: [sumB('g1', 150, 'b1', 'escalate')], sources: ['mail'] });
const R3 = base({ grants: [pay(20, ['acct:a', 'acct:b']), { gid: 'g2', verb: 'read', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }], wildcardAck: ['g2'], prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'wipe' }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } }] });
const R4 = base({ grants: [{ gid: 'g1', verb: 'read', res: { k: 'related', rel: 'team', anchor: 'alice' }, cond: { k: 'true' } }], prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'wipe' }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } }, { pid: 'p2', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'oneof', ids: ['v'] }, cond: { k: 'true' } }], validity: { notBefore: 5, notAfter: 9000, maxIdle: 300 }, deleg: { maxDepth: 3, narrowOnly: true, mayTouch: ['g1'] }, holes: [{ hid: 'h1', q: 'q', domain: ['a'], affects: ['g1'], global: false }], escalateOn: [cmp('gt', pq('amount'), lq(USD, 30))] });
const R5 = base({ grants: [pay(50, ['acct:a', 'acct:b']), { gid: 'g2', verb: 'pay', res: { k: 'all_of', parts: [{ k: 'exact', id: 'acct:a' }, { k: 'oneof', ids: ['acct:a', 'acct:z'] }] }, cond: { k: 'true' } }], bounds: [sumB('g1', 100), { bid: 'b2', sel: { k: 'gids', gids: ['g2'] }, agg: 'count', value: lq(CNT, 1), key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: qn(CNT, 2), onExceed: 'deny' }], holes: [{ hid: 'h1', q: 'q', domain: ['a'], affects: ['g2'], global: true }], validity: { notBefore: 0, notAfter: 50000, maxIdle: 100 } });
const R6 = base({ principal: 'bob' });
const R7 = base({ grants: [pay(50, ['acct:a', 'acct:b'])], bounds: [sumB('g1', 100)] });
const rd = (id: string, family: string, deterministic: boolean, goal: any) => ({ id, family, deterministic, goal, notes: [] });
const READ = [rd('t', 'rule', true, R1), rd('a', 'x', false, R2), rd('b', 'y', false, R3), rd('c', 'z', false, R5), rd('d', 'x', false, R7), rd('e', 'q', false, R4)];

for (const gs of [[R1], [R1, R2], [R1, R3], [R2, R1], [R1, R2, R3], [R1, R5], [R3, R4], [R1, R7], [R1, R5, R2], [R4, R5], [R1, R1]]) await run('meet', N.meet, [gs]);
await run('meet', N.meet, [[]]);
await run('meet', N.meet, [[R1, R6]]);
await run('meet', N.meet, [[R1, { ...R2, nlDigest: 'other' }]]);
for (const [a, b] of [[R1, R2], [R1, R3], [R3, R5], [R4, R1], [R1, R1]]) await run('meetGrants', N.meetGrants, [a.grants, b.grants]);
for (const rs of [READ, READ.slice(0, 3), READ.slice(0, 2), [READ[0], READ[0], READ[0]], [READ[1], READ[2], READ[3]], [READ[0], { ...READ[1], deterministic: 1 }, READ[2]], []]) await run('checkPanel', N.checkPanel, [rs]);
const sets: any[][] = [[READ[0], READ[1]], [READ[0], READ[1], READ[2]], [READ[0], READ[3]], [READ[0], READ[4]], [READ[0], READ[1], READ[3]], [READ[2], READ[5]].map((r) => r), [READ[1], READ[3], READ[0], READ[2]]];
for (const rs of sets) {
  await run('disagreementMass', D.disagreementMass, [rs, ONT]);
  await run('questions', (r: any, ont: any) => D.questions(r, { ont }), [rs, ONT]);
  await run('nVersion', (r: any, ont: any, th: any) => N.nVersion(r, { ont, ...(th === null ? {} : { massThreshold: th }) }), [rs, ONT, null]);
  await run('nVersion', (r: any, ont: any, th: any) => N.nVersion(r, { ont, ...(th === null ? {} : { massThreshold: th }) }), [rs, ONT, 0.5]);
}
// R2/R6 differ in principal: readings must share principal
await run('nVersion', (r: any, ont: any) => N.nVersion(r, { ont }), [[READ[0], rd('x', 'x', false, R6)], ONT]);
const w1 = { act: { verb: 'pay', res: 'acct:a', params: { amount: { k: 'q', q: qn(USD, 40) } }, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 }, prior: [], rels: [] };
const w2 = { ...w1, prior: [w1.act, w1.act, w1.act] };
for (const g of [R1, R2, R3, R5]) for (const w of [w1, w2]) await run('allowsWitness', D.allowsWitness, [g, ONT, w]);
const discF = async (readings: any[], ont: any, mode: string, budget: any) => D.disambiguate(readings, (q: any) => mode === 'allow' ? 'allow' : mode === 'deny' ? 'deny' : (D.allowsWitness(readings[Number(mode.slice(6))].goal, ont, q) ? 'allow' : 'deny'), { ont, ...(budget === null ? {} : { budget }) });
for (const rs of sets) for (const mode of ['allow', 'deny', 'truth:0', 'truth:1']) await run('disambiguate', discF, [rs, ONT, mode, null]);
await run('disambiguate', discF, [sets[1], ONT, 'truth:2', 1]);
await run('disambiguate', discF, [sets[6], ONT, 'truth:3', 1]);
await run('disambiguate', discF, [sets[6], ONT, 'allow', 0]);
refWrite(o, 'goal-nversion');
