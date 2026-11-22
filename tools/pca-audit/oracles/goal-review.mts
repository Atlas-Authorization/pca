// Oracle: @atlasauth/pca-goal review.ts (policy card, semantic diff, signed goal approval and its loader) with an injected STUB kernel
// (the proved compiler is not carried natively). Stub kernel, by name kmode:
//   compile(goal, ont) = no grants ? {ok:false, reasons:['empty']} : {ok:true, policy:{gids:[...grant ids], n:#grants}}
//   policyDigest(p) = hashCanonical({d:'stub-policy', p}); analyze(p) = p.n >= 5 ? ['too many'] : []
//   decide(goal, ont, act, hist) = some grant has act.verb ? 'allow' : 'deny'
//   newlyAllowed(prev, next, ont, limit) = {witnesses: acts of the grants of next whose gid is not in prev, complete: true}
//   kmode 'full' = all of the above; 'nodecide' = no decide; 'nonewly' = no newlyAllowed; 'throwcompile' = compile throws; 'throwdigest' = policyDigest throws
// PORTING (fn(args) -> native entry point, comparison rule; all compare by JSON value; ReviewError carries code):
//   effectiveLimits(o) -> GoalReview.effectiveLimits; renderPolicyCard(goal, tests, opts{limits?, allowHoles?}) -> GoalReview.renderPolicyCard; cardDigest(card); cardToText(card)
//   diffGoals(prev, next, opts{limits?, ontology?, kmode}) -> GoalReview.diffGoals(prev, next, kernel(kmode), limits, ontology); diffToText(d)
//   approveGoalSeed(sub, seedB64u, opts{now, ttlMs?, limits?, base?, kmode}) -> GoalReview.approveGoal(sub, seed, ApproveOptions); a throw requires a throw
//   loadApprovedGoal(sub, approval, opts{reviewers, ontology_digest?, now, limits?, kmode}) -> GoalReview.loadApprovedGoal (never throws)
import * as RV0 from '../../../packages/pca-goal/src/review';
import * as O0 from '../../../packages/pca-goal/src/ontology';
import * as OS0 from '../../../packages/pca-goal/src/ontologies/index';
import * as S0 from '../../../packages/pca-goal/src/sign';
import * as P0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';
const hashCanonical: any = ((P0 as any).default ?? P0).hashCanonical;
const RV: any = (RV0 as any).default ?? RV0;
const O: any = (O0 as any).default ?? O0;
const OS: any = (OS0 as any).default ?? OS0;
const S: any = (S0 as any).default ?? S0;
const o = new Oracle('goal-review', 'tools/pca-audit/oracles/goal-review.mts', 'TS-reference oracle for pca-goal review.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const sd = (l: string) => seed('goal-review/' + l);
const T0 = 1_800_000_000_000;

const stub = (mode: string): any => {
  const k: any = {
    compile: (g: any) => { if (mode === 'throwcompile') throw new Error('boom'); return g.grants.length === 0 ? { ok: false, reasons: ['empty'] } : { ok: true, policy: { gids: g.grants.map((x: any) => x.gid), n: g.grants.length } }; },
    policyDigest: (p: any) => { if (mode === 'throwdigest') throw new Error('boom'); return hashCanonical({ d: 'stub-policy', p }); },
    analyze: (p: any) => (p.n >= 5 ? ['too many'] : []),
    decide: (g: any, _ont: any, act: any) => (g.grants.some((x: any) => x.verb === act.verb) ? 'allow' : 'deny'),
    newlyAllowed: (prev: any, next: any) => ({ witnesses: next.grants.filter((x: any) => !prev.grants.some((y: any) => y.gid === x.gid)).map((x: any) => ({ verb: x.verb, res: 'r', params: {}, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 })), complete: true }),
  };
  if (mode === 'nodecide') delete k.decide;
  if (mode === 'nonewly') delete k.newlyAllowed;
  return k;
};

// ---- goals (through the template instantiation: nlDigest matches the instruction)
const mk = (name: string, tid: string, slots: any, nl: string) => O.instantiateTemplate(OS.ALL_ONTOLOGIES[name], tid, slots, { principal: 'p1', nl });
const subOf = (name: string, goal: any, instruction: string, extra: any = {}) => ({ goal, ontology: O.ontologyForGoal(OS.ALL_ONTOLOGIES[name], goal), instruction, model_set: ['m-a', 'm-b'], ...extra });
const pay = OS.ALL_ONTOLOGIES.payments, code = OS.ALL_ONTOLOGIES.code_repos, mail = OS.ALL_ONTOLOGIES.email;
const ex = (name: string, tid: string) => OS.ALL_ONTOLOGIES[name].templates.find((t: any) => t.id === tid).example;
const NL = 'do the thing';
const g1 = mk('payments', 'refund_duplicate', ex('payments', 'refund_duplicate'), NL);
const g2 = mk('code_repos', 'fix_on_branch', ex('code_repos', 'fix_on_branch'), NL);
const g3 = mk('email', 'reply_to_thread', ex('email', 'reply_to_thread'), NL);
const g4 = mk('payments', 'refund_customer_charges', ex('payments', 'refund_customer_charges'), NL);
const gHole = mk('payments', 'refund_duplicate', {}, NL);
const gWild = (ack: boolean) => ({ ...clone(g2), grants: [{ gid: 'w', verb: 'read_repo', res: { k: 'any', reason: 'everything' }, cond: { k: 'true' } }], wildcardAck: ack ? ['w'] : [], nlDigest: S ? mk('code_repos', 'read_only_repo', ex('code_repos', 'read_only_repo'), NL).nlDigest : '' });
const GOALS: any[][] = [['payments', g1], ['code_repos', g2], ['email', g3], ['payments', g4], ['payments', gHole], ['code_repos', gWild(true)], ['code_repos', gWild(false)]];
const TESTS = [
  { id: 't1', act: { verb: 'refund', res: 'ch_1', params: { amount: { k: 'q', q: { u: { k: 'money', ccy: 'USD' }, n: 5 } } }, t: 1, sess: 's', prin: 'p1', org: 'o', agent: 'a', depth: 0 }, hist: { adms: [], last: -1, aggs: {} }, answer: 'allow' },
  { id: 't2', act: { verb: 'nuke', res: 'x', params: {}, t: 1, sess: 's', prin: 'p1', org: 'o', agent: 'a', depth: 0 }, hist: { adms: [{ act: { verb: 'refund', res: 'c', params: {}, t: 0, sess: 's', prin: 'p1', org: 'o', agent: 'a', depth: 0 }, dec: 'allow' }], last: 0, aggs: {} }, answer: 'deny', rels: [] },
  { id: 't3', act: { verb: 'refund', res: 'ch_2', params: {}, t: 1, sess: 's', prin: 'p1', org: 'o', agent: 'a', depth: 0 }, hist: { adms: [], last: -1, aggs: {} }, answer: 'ask' },
];

// ---- limits, cards
for (const l of [undefined, {}, { max_grants: 1 }, { max_grants: 99 }, { max_grants: -1 }, { max_grants: 1.5 }, { max_grants: '5' }, { max_card_bytes: 100, max_witnesses: 0 }, { bogus: 1 }, null]) await run('effectiveLimits', (x: any) => RV.effectiveLimits(x ?? undefined), [l ?? null]);
const cards: any[] = [];
for (const [name, g] of GOALS) {
  for (const tests of [[], TESTS.slice(0, 1), TESTS]) for (const opts of [{}, { allowHoles: true }, { limits: { max_card_lines: 3 } }, { limits: { max_card_bytes: 200 } }, { limits: { max_grants: 0 } }]) {
    await run('renderPolicyCard', (gg: any, tt: any, oo: any) => RV.renderPolicyCard(gg, tt, oo), [g, tests, opts]);
  }
  try { const c = RV.renderPolicyCard(g, TESTS, { allowHoles: true }); cards.push(c); } catch { /* refused goal */ }
}
for (const bad of [null, 5, [], {}, { ...g1, grants: 5 }, { ...g1, validity: [] }, { ...g1, deleg: null }, { ...g1, escalateOn: undefined }, { ...g1, grants: [{ gid: 'x' }] }, { ...g1, grants: [{ gid: 'x', verb: 'v', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }] },
  { ...g1, wildcardAck: 'x' }, { ...g1, principal: 1.5 }, { ...g1, bounds: [{ bid: 'b', weird: 1 }] }, { ...g1, escalateOn: [{ k: 'zzz' }] }]) await run('renderPolicyCard', (gg: any, tt: any, oo: any) => RV.renderPolicyCard(gg, tt, oo), [bad, [], {}]);
{
  const big = clone(g1); big.grants = Array.from({ length: 33 }, (_, i) => ({ ...g1.grants[0], gid: 'g' + String(i).padStart(2, '0') }));
  await run('renderPolicyCard', (gg: any, tt: any, oo: any) => RV.renderPolicyCard(gg, tt, oo), [big, [], {}]);
  await run('renderPolicyCard', (gg: any, tt: any, oo: any) => RV.renderPolicyCard(gg, tt, oo), [g1, Array.from({ length: 41 }, (_, i) => ({ ...TESTS[0], id: 't' + i })), {}]);
}
for (const c of cards) { await run('cardDigest', RV.cardDigest, [c]); await run('cardToText', RV.cardToText, [c]); }

// ---- diff
const widened = (g: any, f: (x: any) => void) => { const c = clone(g); f(c); return c; };
const DIFFS: [any, any][] = [
  [g1, g1],
  [g1, widened(g1, (x) => { x.bounds[0].cap.n *= 2; })], [g1, widened(g1, (x) => { x.bounds[0].cap.n = Math.floor(x.bounds[0].cap.n / 2); })], [g1, widened(g1, (x) => { x.bounds = []; })],
  [g1, widened(g1, (x) => { x.prohibits = []; })], [g1, widened(g1, (x) => { x.grants.push({ gid: 'zz', verb: 'transfer', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }); })],
  [g1, widened(g1, (x) => { x.grants.pop(); })], [g1, widened(g1, (x) => { x.principal = 'someone'; x.ontDigest = 'other'; x.nlDigest = 'nl2'; x.wildcardAck = ['zz']; })],
  [g1, widened(g1, (x) => { x.validity.notAfter = 5; })], [g1, widened(g1, (x) => { x.validity.maxIdle = 5; x.validity.notBefore = 0; })], [g1, widened(g1, (x) => { x.validity.maxIdle = 0; x.validity.notAfter *= 2; })], [g1, widened(g1, (x) => { x.deleg = { maxDepth: 5, narrowOnly: false, mayTouch: ['zz'] }; })],
  [g1, widened(g1, (x) => { x.deleg.maxDepth = 0; })], [g1, widened(g1, (x) => { x.escalateOn.push({ k: 'true' }); })], [g1, widened(g1, (x) => { x.grants[0].cond = { k: 'and', a: x.grants[0].cond, b: { k: 'cmp', op: 'eq', l: { k: 'lit', v: { k: 's', s: 'a' } }, r: { k: 'lit', v: { k: 's', s: 'a' } } } }; })],
  [g1, widened(g1, (x) => { x.grants[0].cond = { k: 'true' }; })], [g1, widened(g1, (x) => { x.grants[0].res = { k: 'any', reason: 'r' }; })], [g1, widened(g1, (x) => { x.prohibits[0].res = { k: 'oneof', ids: ['a'] }; })],
  [g1, widened(g1, (x) => { x.bounds[0].window = { k: 'task' }; })], [g1, widened(g1, (x) => { x.bounds[0].cap.u = { k: 'count' }; })],
  [g2, g1], [g2, g3], [gHole, g1],
];
{
  const many = clone(g1); many.grants = Array.from({ length: 14 }, (_, i) => ({ ...g1.grants[0], gid: 'm' + String(i).padStart(2, '0') }));
  DIFFS.push([g1, many]);
  const prevMany = clone(g1); prevMany.grants = Array.from({ length: 31 }, (_, i) => ({ ...g1.grants[0], gid: 'a' + String(i).padStart(2, '0') }));
  const nextMany = clone(g1); nextMany.grants = Array.from({ length: 31 }, (_, i) => ({ ...g1.grants[0], gid: 'b' + String(i).padStart(2, '0') }));
  DIFFS.push([prevMany, nextMany]);
}
const dOut: any[] = [];
for (const [a, b] of DIFFS) {
  for (const opts of [{ kmode: 'full' }, { kmode: 'none' }, { kmode: 'full', ontology: O.ontologyForGoal(pay, a) }, { kmode: 'nonewly', ontology: O.ontologyForGoal(pay, a) }, { kmode: 'full', limits: { max_diff_changes: 2, max_diff_widenings: 1, max_witnesses: 1 }, ontology: O.ontologyForGoal(pay, a) }]) {
    await run('diffGoals', (p: any, nx: any, op: any) => RV.diffGoals(p, nx, op.kmode === 'none' ? undefined : stub(op.kmode), { ...(op.limits ? { limits: op.limits } : {}), ...(op.ontology ? { ontology: op.ontology } : {}) }), [a, b, opts]);
  }
  try { dOut.push(RV.diffGoals(a, b, stub('full'), { ontology: O.ontologyForGoal(pay, a) })); } catch { /* over the caps */ }
}
for (const d of dOut) await run('diffToText', RV.diffToText, [d]);

// ---- approval and loading
const REV = b64(sd('rev')), REV2 = b64(sd('rev2'));
const revId = S.signerId(sd('rev')), rev2Id = S.signerId(sd('rev2'));
const approve = (sub: any, seedB64: string, op: any) => RV.approveGoal(sub, new Uint8Array(Buffer.from(seedB64, 'base64url')), { kernel: stub(op.kmode), now: op.now, ...(op.ttlMs !== undefined ? { ttlMs: op.ttlMs } : {}), ...(op.limits ? { limits: op.limits } : {}), ...(op.base ? { base: op.base } : {}) });
const load = (sub: any, ap: any, op: any) => RV.loadApprovedGoal(sub, ap, { kernel: stub(op.kmode), reviewers: op.reviewers, now: op.now, ...(op.ontology_digest !== undefined ? { ontology_digest: op.ontology_digest } : {}), ...(op.limits ? { limits: op.limits } : {}) });
const SUBS: any[] = [];
for (const [name, g] of GOALS) { SUBS.push(subOf(name, g, NL), subOf(name, g, NL, { tests: TESTS.slice(0, 1) })); }
SUBS.push(subOf('payments', g1, NL, { tests: TESTS }), subOf('payments', g1, NL, { tests: [TESTS[1]] }), subOf('payments', g1, 'other text'), subOf('payments', g1, NL, { model_set: [] }), subOf('payments', g1, NL, { model_set: ['b', 'a', 'b'] }));
const OPT = { kmode: 'full', now: T0 };
for (const sub of SUBS) {
  for (const op of [OPT, { ...OPT, kmode: 'nodecide' }, { ...OPT, kmode: 'throwcompile' }, { ...OPT, kmode: 'throwdigest' }]) await run('approveGoalSeed', approve, [sub, REV, op]);
}
for (const op of [{ ...OPT, ttlMs: 0 }, { ...OPT, ttlMs: -5 }, { ...OPT, ttlMs: 86_400_001 }, { ...OPT, ttlMs: 86_400_000 }, { ...OPT, now: 1.5 }, { ...OPT, now: 2 ** 53 }, { ...OPT, limits: { max_grants: 1 } }, { ...OPT, base: g1 }, { ...OPT, base: g2 }, { ...OPT, base: widened(g1, (x) => { x.grants = []; x.prohibits = []; }), limits: { max_diff_changes: 0 } }])
  await run('approveGoalSeed', approve, [SUBS[0], REV, op]);
for (const bad of [null, 5, {}, { ...SUBS[0], goal: null }, { ...SUBS[0], ontology: [] }, { ...SUBS[0], instruction: 5 }, { ...SUBS[0], model_set: 'x' }, { ...SUBS[0], model_set: [1] }, { ...SUBS[0], tests: null }, { ...SUBS[0], tests: 'x' }]) await run('approveGoalSeed', approve, [bad, REV, OPT]);

const okSubs = SUBS.filter((s) => { try { approve(s, REV, OPT); return true; } catch { return false; } });
const LO = { kmode: 'full', now: T0 + 1000, reviewers: [revId] };
for (const sub of okSubs) {
  const ap = approve(sub, REV, OPT);
  await run('loadApprovedGoal', load, [sub, ap, LO]);
  await run('loadApprovedGoal', load, [sub, ap, { ...LO, kmode: 'nodecide' }]);
}
const sub0 = okSubs[0], ap0 = approve(sub0, REV, OPT);
const subT = okSubs.find((s) => (s.tests ?? []).length > 0)!, apT = approve(subT, REV, OPT);
for (const op of [{ ...LO, reviewers: [] }, { ...LO, reviewers: [rev2Id] }, { ...LO, reviewers: [{ pk: revId }] }, { ...LO, reviewers: [{ pk: revId, pq_pk: 'x' }] }, { ...LO, reviewers: 'x' }, { ...LO, now: T0 - 1 }, { ...LO, now: T0 + 3_600_000 }, { ...LO, now: T0 + 3_599_999 }, { ...LO, ontology_digest: sub0.goal.ontDigest }, { ...LO, ontology_digest: 'other' }, { ...LO, limits: { max_grants: 0 } }, { ...LO, kmode: 'throwcompile' }])
  await run('loadApprovedGoal', load, [sub0, ap0, op]);
for (const f of ['v', 'goal_digest', 'policy_digest', 'card_digest', 'ontology_digest', 'tests_digest', 'nl_digest', 'model_set_digest', 'reviewer', 'approved_at', 'expires_at', 'sig']) {
  await run('loadApprovedGoal', load, [sub0, { ...ap0, [f]: typeof ap0[f] === 'number' ? ap0[f] + 1 : f === 'v' ? 2 : 'x' + String(ap0[f]).slice(1) }, LO]);
  await run('loadApprovedGoal', load, [sub0, (({ [f]: _x, ...r }: any) => r)(ap0), LO]);
}
for (const [label, mutSub] of [['instruction', { ...sub0, instruction: 'x' }], ['model_set', { ...sub0, model_set: ['z'] }], ['goal', { ...sub0, goal: { ...sub0.goal, principal: 'evil' } }], ['tests', { ...subT, tests: [] }], ['tests2', { ...subT, tests: [TESTS[1]] }], ['ontology', { ...sub0, ontology: { verbs: [], rels: [] } }]] as const) await run('loadApprovedGoal', load, [mutSub, label.startsWith('tests') ? apT : ap0, LO]);
for (const bad of [null, 5, [], { ...ap0, sig: 5 }, { ...ap0, approved_at: 1.5 }, { ...ap0, approved_at: -0 }, { ...ap0, alg: 'nope' }, { ...ap0, alg: 'ed25519' }, { ...ap0, pq_pk: 'x' }]) await run('loadApprovedGoal', load, [sub0, bad, LO]);
await run('loadApprovedGoal', load, [null, ap0, LO]);
await run('loadApprovedGoal', load, [{ ...sub0, tests: 5 }, ap0, LO]);
{
  const long = approve(sub0, REV, { ...OPT, ttlMs: 86_400_000 });
  await run('loadApprovedGoal', load, [sub0, long, LO]);
  await run('loadApprovedGoal', load, [sub0, { ...long, expires_at: long.expires_at + 1 }, LO]);
  const other = approve(sub0, REV2, OPT);
  await run('loadApprovedGoal', load, [sub0, other, { ...LO, reviewers: [rev2Id, revId] }]);
  await run('loadApprovedGoal', load, [sub0, { ...other, reviewer: revId }, LO]);
}
refWrite(o, 'goal-review');
