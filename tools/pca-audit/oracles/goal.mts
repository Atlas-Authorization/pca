// Oracle: @atlasauth/pca-goal pure core: token-tape codec, digests, normalize, fmt, card, reference semantics, binding, signing envelope.
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value):
//   encodeGoal(goal) / encodeOntology(o) / encodeAct(a) / encodeHist(h) -> GoalCodec.*  (a tape is [[tag, n|s], ...], tag in k|i|s)
//   decodeGoal(tape) -> GoalCodec.decodeGoal; decodePolicy(tape) -> GoalCodec.decodePolicy (a throw requires a throw)
//   goalDigest/nlDigest/modelSetDigest/approvalDigest -> GoalDigests.*; canonicalizeGoal / stable -> GoalNormalize.*
//   fmtMoney/fmtQuantity/fmtValue/fmtAct -> GoalFmt.*; renderCard(goal) -> GoalCard.renderCard ({lines, warnings})
//   refDecide / refExplain(goal, ont, act, hist) -> GoalRefsem.*; canonicalPolicy / policyDigest -> GoalCompiler.*
//   actionDigest / bindDecision / guardExecute / claimGate / goalCommit / openCommit -> GoalBinding.*
//   signPayloadSeed(kind, payload, seedB64u) -> GoalSign.signPayload(kind, payload, seed); verifyPayload(signed, kind, pins) -> GoalSign.verifyPayload
//   signGoalArtifactSeed(kind, body, seedB64u) -> GoalSign.signGoalArtifact(kind, body, seed); verifyGoalArtifact(kind, a, field, pins)
// Ed25519 only (deterministic). Seeds derive from seed(label); no key material is stored.
import * as C0 from '../../../packages/pca-goal/src/codec';
import * as D0 from '../../../packages/pca-goal/src/digests';
import * as N0 from '../../../packages/pca-goal/src/normalize';
import * as F0 from '../../../packages/pca-goal/src/fmt';
import * as CD0 from '../../../packages/pca-goal/src/card';
import * as R0 from '../../../packages/pca-goal/src/refsem';
import * as B0 from '../../../packages/pca-goal/src/binding';
import * as S0 from '../../../packages/pca-goal/src/sign';
import { Oracle, refWrite, rng, seed, variants } from './lib.mjs';
const C: any = (C0 as any).default ?? C0;
const D: any = (D0 as any).default ?? D0;
const N: any = (N0 as any).default ?? N0;
const F: any = (F0 as any).default ?? F0;
const CD: any = (CD0 as any).default ?? CD0;
const R: any = (R0 as any).default ?? R0;
const B: any = (B0 as any).default ?? B0;
const S: any = (S0 as any).default ?? S0;

const o = new Oracle('goal', 'tools/pca-audit/oracles/goal.mts', 'TS-reference oracle for the pca-goal pure core.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const unwrap = (x: any): any => (x && x.default && !x.encodeGoal && !x.goalDigest ? x.default : x);

const USD = { k: 'money', ccy: 'USD' };
const CNT = { k: 'count' };
const qn = (u: any, v: number) => ({ u, n: v });
const lq = (u: any, v: number) => ({ k: 'lit', v: { k: 'q', q: qn(u, v) } });
const ls = (s: string) => ({ k: 'lit', v: { k: 's', s } });
const pq = (path: string, u: any = USD) => ({ k: 'param', path, ty: { k: 'q', u } });
const ps = (path: string) => ({ k: 'param', path, ty: { k: 's' } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const mk = (over: any = {}) => ({
  v: 1, principal: 'alice', ontDigest: 'ont1', nlDigest: 'nl1', sources: ['chat:1'],
  grants: [{ gid: 'g1', verb: 'pay', res: { k: 'oneof', ids: ['acct:a', 'acct:b'] }, cond: { k: 'and', a: cmp('lte', pq('amount'), lq(USD, 50000)), b: cmp('in', ps('to'), { k: 'lit', v: { k: 'set', items: [{ k: 's', s: 'x' }, { k: 'q', q: qn(CNT, 3) }] } }) } },
    { gid: 'g2', verb: 'read', res: { k: 'any', reason: 'all docs' }, cond: { k: 'true' } },
    { gid: 'g3', verb: 'send', res: { k: 'all_of', parts: [{ k: 'related', rel: 'team', anchor: 'alice' }, { k: 'oneof', ids: ['m1', 'm2'] }, { k: 'exact', id: 'm1' }] }, cond: { k: 'not', c: { k: 'or', a: cmp('gt', pq('n', CNT), lq(CNT, 2)), b: cmp('ne', ps('k'), ls('z')) } } }],
  prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'wipe' }, res: { k: 'any', reason: 'never' }, cond: { k: 'true' } },
    { pid: 'p2', target: { k: 'effect', cls: 'irreversible' }, res: { k: 'oneof', ids: ['vault'] }, cond: cmp('gte', pq('amount'), lq(USD, 1)) }],
  bounds: [{ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'sum', value: pq('amount'), key: '', window: { k: 'sliding', ms: 86400000 }, scope: { k: 'session' }, cap: qn(USD, 100000), onExceed: 'deny' },
    { bid: 'b2', sel: { k: 'effect', cls: 'read' }, agg: 'count', value: lq(CNT, 1), key: '', window: { k: 'period', ms: 1000, t0: 5 }, scope: { k: 'fleet', agents: ['a', 'b'] }, cap: qn(CNT, 3), onExceed: 'escalate' },
    { bid: 'b3', sel: { k: 'gids', gids: ['g1', 'g3'] }, agg: 'distinct', value: lq(CNT, 1), key: 'to', window: { k: 'lifetime' }, scope: { k: 'org' }, cap: qn(CNT, 2), onExceed: 'deny' },
    { bid: 'b4', sel: { k: 'gids', gids: ['g1'] }, agg: 'max', value: pq('amount'), key: '', window: { k: 'task' }, scope: { k: 'principal' }, cap: qn(USD, 9000), onExceed: 'escalate' }],
  validity: { notBefore: 0, notAfter: 2000000, maxIdle: 5000 }, deleg: { maxDepth: 2, narrowOnly: true, mayTouch: ['g1', 'g2'] },
  escalateOn: [cmp('gt', pq('amount'), lq(USD, 20000))], wildcardAck: ['g2'],
  holes: [{ hid: 'h1', q: 'which account?', domain: ['a', 'b'], affects: ['g1'], global: false }],
  ...over,
});
const GOALS: any[] = [
  mk(),
  mk({ holes: [], wildcardAck: [], escalateOn: [] }),
  mk({ grants: [], prohibits: [], bounds: [], holes: [], sources: [], deleg: { maxDepth: 0, narrowOnly: false, mayTouch: [] } }),
  mk({ validity: { notBefore: 5, notAfter: 9007199254740991, maxIdle: 0 }, principal: 'é   "q"\\', nlDigest: '' }),
];
const ONT = { verbs: [{ verb: 'pay', cls: 'irreversible', params: [{ path: 'amount', ty: { k: 'q', u: USD } }, { path: 'to', ty: { k: 's' } }] }, { verb: 'wipe', cls: 'irreversible', params: [] }, { verb: 'read', cls: 'read', params: [] }, { verb: 'send', cls: 'external_send', params: [{ path: 'n', ty: { k: 'q', u: CNT } }, { path: 'k', ty: { k: 's' } }] }],
  rels: [{ rel: 'team', anchor: 'alice', members: ['m1', 'm3'] }] };
const sval = (s: string) => ({ k: 's', s });
const qval = (u: any, v: number) => ({ k: 'q', q: qn(u, v) });
const mkAct = (verb: string, res: string, params: any = {}, over: any = {}) => ({ verb, res, params, t: 100, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0, ...over });
const HIST0 = { adms: [], last: -1, aggs: {} };

// ---- codec
for (const g of GOALS) { await run('encodeGoal', C.encodeGoal, [g]); await run('decodeGoal', C.decodeGoal, [C.encodeGoal(g)]); }
await run('encodeOntology', C.encodeOntology, [ONT]);
await run('encodeOntology', C.encodeOntology, [{ verbs: [], rels: [] }]);
const acts = [mkAct('pay', 'acct:a', { amount: qval(USD, 100), to: sval('x') }), mkAct('read', 'doc', {}), mkAct('send', 'm1', { n: qval(CNT, 3), k: sval('z') }, { t: 5000, depth: 1 })];
for (const a of acts) await run('encodeAct', C.encodeAct, [a]);
const H1 = { adms: [{ gid: 'g1', act: acts[0] }, { gid: 'g2', act: acts[1] }], last: 100, aggs: { b1: qn(USD, 100), b0: qn(CNT, 1) } };
await run('encodeHist', C.encodeHist, [HIST0]);
await run('encodeHist', C.encodeHist, [H1]);
for (const [name, v] of variants(GOALS[0], { maxPaths: 25, hostile: [null, 1.5, '', {}] })) await run('encodeGoal', C.encodeGoal, [v]);
for (const [name, v] of variants(acts[0], { maxPaths: 40, hostile: [null, 1.5, 2 ** 53, '', {}, []] })) await run('encodeAct', C.encodeAct, [v]);
for (const [name, v] of variants(H1, { maxPaths: 50, hostile: [null, 1.5, 2 ** 53, '', {}, []] })) await run('encodeHist', C.encodeHist, [v]);
for (const [name, v] of variants(ONT, { maxPaths: 50, hostile: [null, 1.5, '', {}, []] })) await run('encodeOntology', C.encodeOntology, [v]);
// decode: truncations, trailing tokens, bad tags
const T0: any[] = C.encodeGoal(GOALS[0]) as any;
for (let i = 0; i < T0.length; i += 3) await run('decodeGoal', C.decodeGoal, [T0.slice(0, i)]);
await run('decodeGoal', C.decodeGoal, [[...T0, ['i', 0]]]);
for (let i = 0; i < T0.length; i += 4) await run('decodeGoal', C.decodeGoal, [T0.map((t: any, j: number) => (j === i ? [t[0] === 'k' ? 'i' : 'k', t[1]] : t))]);
for (let i = 0; i < T0.length; i += 7) await run('decodeGoal', C.decodeGoal, [T0.map((t: any, j: number) => (j === i ? [t[0], typeof t[1] === 'number' ? t[1] + 1 : t[1] + 'x'] : t))]);
await run('decodeGoal', C.decodeGoal, [[]]);
await run('decodeGoal', C.decodeGoal, [[['k', 480]]]);
// decodePolicy over hand-built policy tapes
const K = (x: number) => ['k', x], I = (x: number) => ['i', x], Sx = (x: string) => ['s', x];
const polTape = [K(650), I(1), K(620), Sx('g1'), Sx('pay'), K(631), I(1), Sx('r1'), K(602), K(351), K(340), Sx('amount'), K(310), K(300), Sx('USD'), K(341), K(330), K(300), Sx('USD'), I(5),
  I(1), K(640), Sx('p1'), I(2), Sx('wipe'), Sx('x'), K(630), K(601),
  I(1), K(610), Sx('b1'), I(1), Sx('g1'), I(0), K(450), K(401), K(341), K(330), K(301), I(1), Sx(''), K(421), I(1000), K(430), K(301), I(3), K(440),
  I(1), K(604), K(600), K(603), K(601), K(600), K(460), I(0), I(10), I(0), K(461), I(2), I(1), I(1), Sx('g1')];
await run('decodePolicy', C.decodePolicy, [polTape]);
for (let i = 0; i < polTape.length; i += 5) await run('decodePolicy', C.decodePolicy, [polTape.slice(0, i)]);
await run('decodePolicy', C.decodePolicy, [[...polTape, I(1)]]);
await run('decodePolicy', C.decodePolicy, [polTape.map((t: any, j: number) => (j === 0 ? K(651) : t))]);
await run('decodePolicy', C.decodePolicy, [polTape.map((t: any, j: number) => (j === 2 ? K(621) : t))]);

// ---- digests / normalize
for (const g of GOALS) await run('goalDigest', D.goalDigest, [g]);
for (const [name, v] of variants(GOALS[1], { maxPaths: 15, hostile: [null, 1.5, 2 ** 53, '', 'x'] })) await run('goalDigest', D.goalDigest, [v]);
for (const t of ['', 'pay bob 5 dollars', 'é\u0000"', 'long '.repeat(100)]) await run('nlDigest', D.nlDigest, [t]);
for (const m of [[], ['a'], ['b', 'a', 'b'], ['é', 'z', 'Z', '😀', '￿']]) await run('modelSetDigest', D.modelSetDigest, [m]);
for (const b of [{}, { a: 'x', b: 5 }, { goal_digest: 'g', exp: 100, tests_digest: 't' }, { a: 1.5 }, { a: 2 ** 53 }]) await run('approvalDigest', D.approvalDigest, [b]);
const shuffled = mk({ grants: [...mk().grants].reverse(), prohibits: [...mk().prohibits].reverse(), bounds: [...mk().bounds].reverse(), wildcardAck: ['g3', 'g1', 'g3'], deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['z', 'a', 'z', 'é'] }, holes: [{ hid: 'h2', q: 'q', domain: [], affects: [], global: true }, { hid: 'h1', q: 'q', domain: [], affects: [], global: true }] });
await run('canonicalizeGoal', N.canonicalizeGoal, [shuffled]);
for (const g of GOALS) await run('canonicalizeGoal', N.canonicalizeGoal, [g]);
await run('canonicalizeGoal', N.canonicalizeGoal, [mk({ grants: [{ gid: 'b', verb: 'v', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }, { gid: 'B', verb: 'v', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }, { gid: 'b', verb: 'w', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }] })]);
for (const v of [null, 1, 'x', [], {}, { b: 1, a: [2, { d: 1, c: null }] }, { 'é': 1, 'z': 2, 'Z': 3 }]) await run('stable', N.stable, [v]);

// ---- fmt
for (const [c, m] of [['USD', 12345], ['USD', 5], ['USD', 0], ['JPY', 500], ['EUR', 100], ['XYZ', 77], ['KRW', 0], ['GBP', -5], ['CAD', 10]]) await run('fmtMoney', F.fmtMoney, [c, m]);
for (const u of [USD, CNT, { k: 'duration' }, { k: 'instant' }, { k: 'bytes' }, { k: 'ratio' }, { k: 'money', ccy: 'ZZZ' }]) await run('fmtQuantity', F.fmtQuantity, [qn(u, 4200)]);
for (const v of [sval('a"b'), qval(USD, 250), { k: 'set', items: [sval('x'), qval(CNT, 2)] }, { k: 'set', items: [] }]) await run('fmtValue', F.fmtValue, [v]);
for (const a of acts) await run('fmtAct', F.fmtAct, [a]);

// ---- card
for (const g of GOALS) await run('renderCard', CD.renderCard, [g]);
for (const [name, v] of variants(GOALS[0], { maxPaths: 40, hostile: [null] })) if (!name.endsWith(' deleted') && !name.includes('/k ')) await run('renderCard', CD.renderCard, [v]);
for (const c of [{ k: 'true' }, cmp('lt', pq('a'), ls('b')), cmp('nin', ps('a'), lq(CNT, 1))]) await run('renderCond', CD.cond, [c]);

// ---- reference semantics
const r = rng(0x60a1);
const verbs = ['pay', 'wipe', 'read', 'send', 'nope'];
const resS = ['acct:a', 'acct:b', 'acct:c', 'vault', 'm1', 'm2', 'm3', 'doc'];
const randAct = (t: number): any => {
  const params: any = {};
  if (r.next() < 0.8) params.amount = qval(r.pick([USD, USD, USD, CNT]), r.pick([0, 1, 49999, 50000, 50001, 9000, 9001, 20000, 20001, 100000]));
  if (r.next() < 0.7) params.to = r.pick([sval('x'), sval('y'), qval(CNT, 3), qval(CNT, 4)]);
  if (r.next() < 0.6) params.n = qval(CNT, r.int(0, 4));
  if (r.next() < 0.5) params.k = sval(r.pick(['z', 'w']));
  return mkAct(r.pick(verbs), r.pick(resS), params, { t, sess: r.pick(['s', 's', 't']), prin: r.pick(['p', 'p', 'q']), org: r.pick(['o', 'o', 'z']), agent: r.pick(['a', 'b', 'c']), depth: r.pick([0, 0, 0, 1, 2, 3, -1]) });
};
const goalsR = [GOALS[0], GOALS[1], GOALS[3], mk({ holes: [], deleg: { maxDepth: 3, narrowOnly: false, mayTouch: ['g1', 'g2', 'g3'] }, validity: { notBefore: 0, notAfter: 2000000, maxIdle: 0 } })];
for (let i = 0; i < 220; i++) {
  const g = goalsR[i % goalsR.length];
  const t0 = r.pick([100, 1000, 1999, 3000, 90000, 2000001, 99999999]);
  const adms: any[] = [];
  const nh = r.int(0, 5);
  let last = -1;
  const aggs: any = {};
  for (let j = 0; j < nh; j++) { const a = randAct(t0 - r.int(0, 3000)); adms.push({ gid: r.pick(['g1', 'g2', 'g3', 'g9']), act: a }); last = Math.max(last, a.t); }
  if (r.next() < 0.5) aggs.b1 = qn(r.pick([USD, CNT]), r.int(0, 100000));
  const h = { adms, last: nh && r.next() < 0.8 ? last : -1, aggs };
  const a = randAct(t0);
  await run('refExplain', R.refExplain, [g, ONT, a, h]);
  if (i % 4 === 0) await run('refDecide', R.refDecide, [g, ONT, a, h]);
}
// hand-built boundary acts: decisions at each cap edge
for (const amt of [0, 49999, 50000, 50001]) for (const to of [sval('x'), qval(CNT, 3), sval('no')]) {
  await run('refExplain', R.refExplain, [GOALS[1], ONT, mkAct('pay', 'acct:a', { amount: qval(USD, amt), to }), HIST0]);
}
for (const [name, v] of variants(mkAct('pay', 'acct:a', { amount: qval(USD, 100), to: sval('x') }), { maxPaths: 80, hostile: [null, 1.5, {}] })) if (!name.endsWith(' deleted')) await run('refExplain', R.refExplain, [GOALS[1], ONT, v, HIST0]);
// distinct / max / sum bounds with histories
const adm = (gid: string, p: any, t: number) => ({ gid, act: mkAct('pay', 'acct:a', p, { t }) });
for (const cap of [1, 2, 3]) {
  const gd = mk({ holes: [], escalateOn: [], bounds: [{ bid: 'bd', sel: { k: 'gids', gids: ['g1'] }, agg: 'distinct', value: lq(CNT, 1), key: 'to', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: qn(CNT, cap), onExceed: 'deny' }] });
  const hh = { adms: [adm('g1', { to: sval('a') }, 1), adm('g1', { to: sval('b') }, 2), adm('g1', { to: sval('a') }, 3)], last: 3, aggs: {} };
  await run('refExplain', R.refExplain, [gd, ONT, mkAct('pay', 'acct:a', { amount: qval(USD, 5), to: sval('c') }, { t: 4 }), hh]);
  await run('refExplain', R.refExplain, [gd, ONT, mkAct('pay', 'acct:a', { amount: qval(USD, 5), to: sval('a') }, { t: 4 }), hh]);
  await run('refExplain', R.refExplain, [gd, ONT, mkAct('pay', 'acct:a', { amount: qval(USD, 5) }, { t: 4 }), hh]);
}

// ---- policy digest
import * as CP0 from '../../../packages/pca-goal/src/compiler';
const CP: any = (CP0 as any).default ?? CP0;
const POLS = [{ preds: [], prohs: [], ceils: [], escs: [], validity: { notBefore: 0, notAfter: 5, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g1'] } }, { z: 1, a: { 'é': 2, b: [] } }, { b: 1, a: [2, 'é', { z: null, y: true }] }];
for (const p of POLS) {
  await run('canonicalPolicy', CP.canonicalPolicy, [p]);
  await run('policyDigest', CP.policyDigest, [p]);
}

// ---- binding
for (const a of acts) { await run('actionDigest', B.actionDigest, [a]); for (const d of ['allow', 'deny', 'escalate']) await run('bindDecision', B.bindDecision, [a, d]); }
for (const a of acts) for (const b of acts) for (const d of ['allow', 'deny', 'escalate']) await run('guardExecute', B.guardExecute, [B.bindDecision(a, d as any), b]);
await run('guardExecute', B.guardExecute, [{ decision: 'allow', action_digest: 5 }, acts[0]]);
await run('guardExecute', B.guardExecute, [{ decision: 'allow' }, acts[0]]);
await run('guardExecute', B.guardExecute, [null, acts[0]]);
for (const base of ['allow', 'escalate', 'deny']) for (const [min, rep] of [[500000, 400000], [500000, 500000], [500000, 600000], [500000, null], [500000, 0]]) {
  await run('claimGate', (b: any, m: number, rp: any) => B.claimGate(b, m, 0, rp === null ? undefined : rp), [base, min, rep]);
}
for (const [a, b, c] of [['g', 'p', 's'], ['', '', ''], ['é', 'p:q', 's:t']]) {
  await run('goalCommit', B.goalCommit, [a, b, c]);
  await run('openCommit', B.openCommit, [B.goalCommit(a, b, c), a, b, c]);
  await run('openCommit', B.openCommit, [B.goalCommit(a, b, c), a, b, c + 'x']);
}

// ---- signing envelope (Ed25519, seeds derived from labels)
const sd = (l: string): Uint8Array => seed('goal/' + l);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const signPayloadSeed = (kind: string, payload: any, seedB64: string) => S.signPayload(kind, payload, new Uint8Array(Buffer.from(seedB64, 'base64url')));
const signGoalArtifactSeed = (kind: string, body: any, seedB64: string) => S.signGoalArtifact(kind, body, new Uint8Array(Buffer.from(seedB64, 'base64url')));
const idOf = (l: string) => S.signerId(sd(l));
for (const kind of ['goal-tests', 'policy-pin', 'ontology']) await run('signPayloadSeed', signPayloadSeed, [kind, { a: 1, b: ['x'] }, b64(sd('s1'))]);
await run('signPayloadSeed', signPayloadSeed, ['k', { a: 1.5 }, b64(sd('s1'))]);
await run('signPayloadSeed', signPayloadSeed, ['k', { a: 2 ** 53 }, b64(sd('s1'))]);
await run('signGoalArtifactSeed', signGoalArtifactSeed, ['approval', { signer: idOf('s1'), x: 1 }, b64(sd('s1'))]);
await run('signGoalArtifactSeed', signGoalArtifactSeed, ['approval', { signer: idOf('s1'), x: 1e21 }, b64(sd('s1'))]);
for (const l of ['s1', 's2']) await run('signerId', (sb: string) => S.signerId(new Uint8Array(Buffer.from(sb, 'base64url'))), [b64(sd(l))]);
for (const k of ['a', 'goal-tests']) await run('goalDomain', S.goalDomain, [k]);
{
  const sp: any = S.signPayload('goal-tests', { t: [1, 2] }, sd('s1'));
  const pk1 = idOf('s1'), pk2 = idOf('s2');
  const cases: [string, any, string, any[]][] = [
    ['ok', sp, 'goal-tests', [pk1]], ['wrong-pin', sp, 'goal-tests', [pk2]], ['no-pins', sp, 'goal-tests', []], ['wrong-kind', sp, 'policy-pin', [pk1]],
    ['obj-pin', sp, 'goal-tests', [{ pk: pk1 }]], ['obj-pin-pq', sp, 'goal-tests', [{ pk: pk1, pq_pk: 'x' }]], ['two-pins', sp, 'goal-tests', [pk2, pk1]],
    ['tampered', { ...sp, payload: { t: [1, 3] } }, 'goal-tests', [pk1]], ['tampered-sig', { ...sp, sig: sp.sig.slice(0, -2) + 'AA' }, 'goal-tests', [pk1]],
    ['no-sig', (({ sig, ...x }: any) => x)(sp), 'goal-tests', [pk1]], ['v2', { ...sp, v: 2 }, 'goal-tests', [pk1]], ['null', null, 'goal-tests', [pk1]], ['array', [], 'goal-tests', [pk1]],
    ['alg-ed', { ...sp, alg: 'ed25519' }, 'goal-tests', [pk1]], ['alg-bad', { ...sp, alg: 'nope' }, 'goal-tests', [pk1]], ['alg-num', { ...sp, alg: 5 }, 'goal-tests', [pk1]],
    ['pq-pk-on-ed', { ...sp, pq_pk: 'abc' }, 'goal-tests', [pk1]], ['pq-sig-num', { ...sp, pq_sig: 5 }, 'goal-tests', [pk1]], ['signer-num', { ...sp, signer: 5 }, 'goal-tests', [pk1]],
  ];
  for (const [nm, art, kind, pins] of cases) await run('verifyPayload', S.verifyPayload, [art, kind, pins]);
  const ga: any = S.signGoalArtifact('approval', { signer: pk1, who: 'me' }, sd('s1'));
  for (const [nm, art, kind, pins] of cases) await run('verifyGoalArtifact', (k: string, a: any, f: string, p: any) => S.verifyGoalArtifact(k, a, f, p), [kind === 'goal-tests' ? 'approval' : 'ledger', kind === 'goal-tests' ? { ...(art ?? {}), ...(art && typeof art === 'object' && !Array.isArray(art) ? {} : {}) } : ga, 'signer', pins]);
  for (const k of ['approval', 'other']) for (const pins of [[pk1], [pk2], []]) await run('verifyGoalArtifact', S.verifyGoalArtifact, [k, ga, 'signer', pins]);
  await run('verifyGoalArtifact', S.verifyGoalArtifact, ['approval', ga, 'who', [pk1]]);
  await run('verifyGoalArtifact', S.verifyGoalArtifact, ['approval', { ...ga, x: 1 }, 'signer', [pk1]]);
}
refWrite(o, 'goal');
