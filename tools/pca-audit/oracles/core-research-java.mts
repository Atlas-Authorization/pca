// Oracle: the research-tier pure modules session.ts, console.ts (with the immune.ts read side it uses), dlp.ts, policy-sim.ts and
// reputation-evidence.ts, TS reference. Written for the Java lane; reusable by any native. Ed25519 only; keys from seed(label); clocks are arguments.
// PORTING (fn(args) -> native entry point, comparison rule: JSON value; a reference throw means the native throws):
//   evaluateDlp(policy, ctx) / defaultDlpPolicy(opts)
//   assess(state) / observe(state, obs) / validateImmuneState(x) -> string|null / updateBaseline(b, r) / baselineStd(b)  (immune.ts, with the default config)
//   buildConsole(events) / anomalies(view) / eventFromPCActn(p, outcome, at|null) / freezeAgent(set, agent) / unfreezeAgent(set, agent) / isFrozen(set, agent)
//   session(ops): ["agent", A, specLabel] -> holder public id    ["start", S, A] ["mk", S, [A..], goalCommit|null] (a hand-built session; null = the first member's)
//                 ["add", S2, S, holderLabel|null, [caveat..]|null] -> {member id}    ["agents", S] ["depth", S] ["shares", S] ["goal", S] ["console", S, events]
//                 an op that throws records {"$err": "Error"}. An agent spec is {principal, holder, goal, goalSalt, permissions, now} (seeds "research/<label>").
//   simulate(spec, actions, opts) / lintPolicy(spec, opts): spec = {permissions, limits?, budgetModel?, riskPolicy?, now} compiled with the facade's compilePolicy; opts {start?}
//   disputesFromSettlements(records, guardianPub, subjectMap, pin|null): subjectOf = own-key lookup in the map (absent = unknown); guardian "@g" = the seed's public key
import { Oracle, refWrite, seed, rng, jsonOut } from './lib.mjs';
const { b64u }: any = await import('../../../packages/pca/src/hash.ts');
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
const { agent }: any = await import('../../../packages/pca/src/facade.ts');
const { compilePolicy }: any = await import('../../../packages/pca/src/facade.ts');
const D: any = await import('../../../packages/pca/src/dlp.ts');
const I: any = await import('../../../packages/pca/src/immune.ts');
const C: any = await import('../../../packages/pca/src/console.ts');
const S: any = await import('../../../packages/pca/src/session.ts');
const PS: any = await import('../../../packages/pca/src/policy-sim.ts');
const RE: any = await import('../../../packages/pca/src/reputation-evidence.ts');
const BS: any = await import('../../../packages/pca/src/bond-settlement.ts');

const o = new Oracle('core-research-java', 'tools/pca-audit/oracles/core-research-java.mts', 'TS-reference oracle for the research-tier session, console, dlp, policy-sim and reputation-evidence modules.');
const sd = (l: string) => seed('research/' + l);
const T0 = 1_800_000_000_000;

// ------------------------------------------------------------------------------------------------ dlp
const dc = (name: any, resource: any, max: any, extra: any = {}) => ({ name, resource, ...(max === undefined ? {} : { maxTaintForAuto: max }), ...extra });
const POLICIES: any[] = [
  { classes: [] }, { classes: [], defaultMaxTaintForAuto: 1 }, { classes: [dc('pii', 'customer:*', 0, { hardDenyAbove: 2 })] },
  { classes: [dc('pii', 'customer:*', 0, { hardDenyAbove: 2 }), dc('secrets', 'secret:*', 0, { hardDenyAbove: 0 }), dc('any', '*', 3)], defaultMaxTaintForAuto: 5 },
  { classes: [dc('a', 'x:*', 2), dc('b', 'x:*', 1), dc('c', 'x:*', 3)] }, { classes: [dc('b', 'x:*', 1), dc('a', 'x:*', 2)] }, { classes: [dc('long', 'x:y:*', 4), dc('short', 'x:*', 1), dc('exact', 'x:y:z', 2)] },
  { classes: [dc('open', 'x:*', undefined), dc('shut', 'x:*', 1)] }, { classes: [dc('shut', 'x:*', 1), dc('open', 'x:*', undefined)] }, { classes: [dc('bad', 'x:*', 'high')] }, { classes: [dc('bad', 'x:*', null)] },
  { classes: [dc('bad', 'x:*', 1, { hardDenyAbove: 'z' })] }, { classes: [dc('bad', 'x:*', 'high'), dc('good', 'x:*', 1)] }, { classes: [], defaultMaxTaintForAuto: 'x' }, { classes: [dc('v', 'x:*', 1, { verbs: ['send'] })] },
  { classes: [dc('v', 'x:*', 1, { verbs: [] }), dc('w', 'x:*', 0, { verbs: ['send', 'read'] })] }, { classes: [dc('nv', 'x:*', 1, { verbs: '' })] }, { classes: [dc('sv', 'x:*', 1, { verbs: 'sendread' })] },
  { classes: [dc(undefined, 'x:*', 1)] }, { classes: [dc(5, 'x:*', 1, { hardDenyAbove: 3 })] }, { classes: [dc('inf', 'x:*', 1e308, { hardDenyAbove: 1e308 })] }, { classes: [dc('neg', 'x:*', -1)] }, { classes: [dc('big', 'x:*', 1e21)] },
  { classes: [dc('frac', 'x:*', 0.1 + 0.2, { hardDenyAbove: 1.5 })] }, {}, { classes: null }, { classes: 'x' }, null, [], { classes: [null] }, { classes: [5] }, { classes: [{}] }, { classes: [{ resource: 5, maxTaintForAuto: 1 }] },
  { classes: [dc('star', '*', 2), dc('pre', 'x*', 1)] }, { classes: [dc('emptyPrefix', '', 1)] }, { classes: [dc('é', 'é*', 0)] },
];
const CTX = (verb: any, resource: any, taint: any) => ({ verb, resource, taint });
const ctxs: any[] = [];
for (const res of ['x:y:z', 'x:y:w', 'x:q', 'customer:1', 'secret:k', 'other', '', 'éa']) for (const t of [0, 1, 2, 3, 4, 5, 10, -1, 1e308, 1.5, 0.30000000000000004, null, '5', 'x', true, {}, [], 1e21]) ctxs.push(CTX('send', res, t));
ctxs.push(CTX('read', 'x:q', 1), CTX('other', 'x:q', 2), CTX(undefined, 'x:q', 1), CTX('send', undefined, 1), CTX('send', 5, 1), { verb: 'send', resource: 'x:q' }, { verb: 'send', resource: 'x:q', taint: 0, trustedRefs: ['a'] });
let k = 0;
for (const p of POLICIES) for (const c of ctxs) await o.run('evaluateDlp', 'd' + k++, D.evaluateDlp, [p, c]);
for (const opts of [{}, { piiResource: 'p:*' }, { secretsResource: 's:*' }, { piiResource: 'p:*', secretsResource: 's:*' }, { piiResource: '' }, { piiResource: 5 }, { secretsResource: null }, undefined, {}]) await o.run('defaultDlpPolicy', 'o' + k++, D.defaultDlpPolicy, [opts ?? null].map((x) => x ?? undefined));

// ------------------------------------------------------------------------------------------------ immune read side + console
const R = rng(1234);
const baselines: any[] = [{ n: 0, mean: 0, m2: 0 }, { n: 1, mean: 0.5, m2: 0 }, { n: 5, mean: 0.2, m2: 0.04 }, { n: 100, mean: 0.5, m2: 1.5 }, { n: 7, mean: 0.1, m2: 0 }];
for (const b of baselines) for (const r of [0, 0.5, 1, -1, 2, 0.1, 0.30000000000000004]) await o.run('updateBaseline', `ub${k++}`, I.updateBaseline, [b, r]);
for (const b of baselines) await o.run('baselineStd', `bs${k++}`, I.baselineStd, [b]);
const states: any[] = [I.INITIAL_IMMUNE_STATE];
for (let i = 0; i < 40; i++) {
  let s = I.INITIAL_IMMUNE_STATE;
  const n = R.int(1, 25), kind = i % 4;
  let at = T0;
  for (let j = 0; j < n; j++) {
    at += R.int(0, 5) * 600_000;
    const hot = kind >= 2 && j > n / 2;
    s = I.observe(s, { r: hot ? 0.6 + R.next() * 0.4 : R.next() * 0.3, at, stepUp: kind === 1 ? R.next() < 0.8 : hot && R.next() < 0.7, denied: kind === 3 && R.next() < 0.5 });
  }
  states.push(JSON.parse(JSON.stringify(s)));
}
for (const s of states) await o.run('assess', `a${k++}`, I.assess, [s]);
const badStates: any[] = [null, 5, 'x', {}, { baseline: null }, { baseline: { n: 1.5, mean: 0, m2: 0 }, ewma: 0, stepUps: 0, denies: 0, lastAt: 0, seeded: true }, { ...states[3], seeded: 'yes' }, { ...states[3], ewma: 2 }, { ...states[3], lastAt: -1 },
  { ...states[3], stepUps: -1 }, { ...states[3], denies: 2e9 }, { ...states[3], baseline: { ...states[3].baseline, n: -0 } }, { ...states[3], baseline: { ...states[3].baseline, mean: 1.5 } }, { ...states[3], baseline: { ...states[3].baseline, m2: -1 } }, { ...states[3], lastAt: '5' }, []];
for (const s of badStates) { await o.run('assess', `a${k++}`, I.assess, [s]); await o.run('validateImmuneState', `v${k++}`, I.validateImmuneState, [s]); }
for (const s of states.slice(0, 12)) await o.run('validateImmuneState', `v${k++}`, I.validateImmuneState, [s]);
const obss: any[] = [{ r: 0.5, at: T0 }, { r: 2, at: T0 + 5 }, { r: -1, at: T0 - 5 }, { r: 0.2, at: T0 + 3_600_000, stepUp: true }, { r: 0.9, at: T0 + 7_200_000, denied: true }, { r: 0.4 }, { r: 'x', at: T0 }, { r: 0.4, at: null }, { r: 0.4, at: T0, stepUp: true, denied: true }];
for (const s of states.slice(0, 14)) for (const ob of obss) await o.run('observe', `o${k++}`, I.observe, [s, ob]);

const AG = ['agent-a', 'agent-b', 'agent-c', 'é-agent', 'agent-d'];
function genEvents(seedN: number, n: number): any[] {
  const g = rng(seedN);
  const evs: any[] = [];
  let at = T0;
  for (let i = 0; i < n; i++) {
    at += g.int(0, 4) * 90_000 - (g.next() < 0.1 ? 200_000 : 0);
    const ag = g.pick(AG);
    const heavy = ag === 'agent-b';
    const outcome = g.pick(heavy ? ['step_up', 'step_up', 'deny', 'auto', 'executed'] : ['auto', 'auto', 'auto', 'executed', 'step_up', 'deny', 'other']);
    evs.push({ at, agent: ag, verb: g.pick(['stripe.refund', 'gmail.send', 'github.read']), resource: g.pick(['a', 'b', 'c:1']), outcome, ...(g.next() < 0.85 ? { r: heavy ? 0.5 + g.next() * 0.5 : g.next() * 0.4 } : {}), ...(g.next() < 0.3 ? { taint: g.int(0, 4) } : {}), ...(g.next() < 0.2 ? { digest: 'd' + i, goalCommit: 'g' } : {}) });
  }
  return evs;
}
const CE: any[] = [[], [{ at: T0, agent: 'a', verb: 'v', resource: 'r', outcome: 'auto' }], genEvents(1, 5), genEvents(2, 20), genEvents(3, 60), genEvents(4, 150), genEvents(5, 300)];
const hostile = [null, 5, 'x', [], {}, { at: 'x', agent: 'a' }, { at: T0, agent: '' }, { at: T0, agent: 5 }, { at: null, agent: 'a' }, { agent: 'a' }, { at: T0 }, { at: T0, agent: 'a', outcome: 'weird' }, { at: T0, agent: 'a', outcome: 'auto', r: null }, { at: T0, agent: 'a', outcome: 'deny', r: 3 }, { at: -5, agent: 'a', outcome: 'step_up', r: -2 }, { at: 1e15, agent: 'b' }];
CE.push(hostile, [...genEvents(7, 12), ...hostile], hostile.map((h) => [h, { at: T0, agent: 'z', outcome: 'auto' }]).flat());
CE.push(genEvents(8, 40).map((e: any) => ({ ...e, agent: 'solo' })), genEvents(9, 40).map((e: any) => ({ ...e, at: T0 })), genEvents(10, 30).map((e: any, i: number) => ({ ...e, at: T0 + i * 3_600_000 * 2, outcome: 'deny', r: 1 })));
for (const evs of CE) await o.run('buildConsole', `bc${k++}`, C.buildConsole, [evs]);
for (const evs of CE.slice(1, 8)) await o.run('anomalies', `an${k++}`, (e: any) => C.anomalies(C.buildConsole(e)), [evs]);
const mkP = (extra: any = {}) => ({ iat: T0, cap_chain: [{ id: 'c0', holder: 'root' }, { id: 'c1', holder: 'leaf-holder' }], action: { verb: 'stripe.refund', resource: 'ch_1', params_digest: 'x' }, risk_claim: { r: 0.4 }, provenance: { taint_level: 2 }, ...extra });
for (const [p, out, at] of [[mkP(), 'auto', null], [mkP(), 'deny', 5], [mkP({ risk_claim: undefined }), 'step_up', null], [mkP({ provenance: undefined }), 'executed', 0], [mkP({ cap_chain: [] }), 'auto', null], [mkP({ cap_chain: [{ id: 'x' }] }), 'auto', null],
  [mkP({ cap_chain: undefined }), 'auto', null], [mkP({ iat: undefined }), 'auto', null], [mkP({ risk_claim: { r: 1e21 } }), 'auto', null], [mkP({ extra: { n: [1, 2.5, 'é'] } }), 'auto', 7], [mkP({ action: { verb: 'v' } }), 'auto', null], [mkP({ action: undefined }), 'auto', null]] as any[]) {
  await o.run('eventFromPCActn', `ev${k++}`, (pp: any, oc: string, a: any) => C.eventFromPCActn(pp, oc, a === null ? undefined : a), [p, out, at]);
}
const FS: any[] = [{ frozen: [] }, { frozen: ['b'] }, { frozen: ['a', 'c'] }, { frozen: ['é', 'z', 'a'] }, { frozen: ['b', 'a'] }, {}, null, { frozen: 'x' }, { frozen: [1, 2] }];
for (const f of FS) for (const a of ['a', 'b', 'é', '', 'Z', 5, null, 'aa']) {
  await o.run('freezeAgent', `fz${k++}`, C.freezeAgent, [f, a]);
  await o.run('unfreezeAgent', `uf${k++}`, C.unfreezeAgent, [f, a]);
  await o.run('isFrozen', `if${k++}`, C.isFrozen, [f, a]);
}

// ------------------------------------------------------------------------------------------------ session
const goalA = { principal: 'p', holder: 'ha', goal: 'ship the release', goalSalt: 'AAECAwQFBgcICQoLDA0ODw', permissions: { github: ['read', 'merge_pr'] }, now: 0 };
const goalB = { principal: 'p', holder: 'hb', goal: 'a different goal', goalSalt: 'AAECAwQFBgcICQoLDA0ODw', permissions: { github: ['read'] }, now: 0 };
const goalC = { principal: 'p2', holder: 'hc', goal: 'ship the release', goalSalt: 'AAECAwQFBgcICQoLDA0ODw', permissions: { github: ['read'] }, now: 0 };
const kdesc = (spec: any) => { const p = sd(spec.principal), h = sd(spec.holder); return { principal: { secretKey: p, publicKey: publicKeyOf(p) }, holder: { secretKey: h, publicKey: publicKeyOf(h) } }; };
async function runSession(ops: any[]): Promise<any[]> {
  const ags = new Map<string, any>(), sess = new Map<string, any>();
  const out: any[] = [];
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'agent': { const sp = op[2]; const ks = kdesc(sp); const a = agent({ ...ks, goal: sp.goal, goalSalt: sp.goalSalt, permissions: sp.permissions, now: sp.now }); ags.set(op[1], a); v = b64u(a.holder.publicKey); break; }
        case 'start': sess.set(op[1], S.startSession(ags.get(op[2]))); v = sess.get(op[1]).goalCommit; break;
        case 'mk': { const ms = op[2].map((n: string) => ags.get(n)); sess.set(op[1], { root: ms[0], members: ms, goalCommit: op[3] === null ? (ms[0] ? (await import('../../../packages/pca/src/envelope.ts') as any).readEnvelope(ms[0].grant)?.goal_commit ?? '' : '') : op[3] }); v = sess.get(op[1]).goalCommit; break; }
        case 'add': {
          const r = S.addMember(sess.get(op[2]), { ...(op[3] === null ? {} : { holder: { secretKey: sd(op[3]), publicKey: publicKeyOf(sd(op[3])) } }), ...(op[4] === null ? {} : { addedCaveats: op[4] }) });
          sess.set(op[1], r.session); v = b64u(r.member.holder.publicKey); break;
        }
        case 'agents': v = S.sessionAgents(sess.get(op[1])); break;
        case 'depth': v = S.sessionDepth(sess.get(op[1])); break;
        case 'shares': v = S.sharesGoal(sess.get(op[1])); break;
        case 'goal': v = sess.get(op[1]).goalCommit; break;
        case 'console': v = S.sessionConsole(sess.get(op[1]), op[2]); break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch { out.push({ $err: 'Error' }); }
  }
  return out;
}
const sessEvents = (ids: string[]) => ids.flatMap((id, i) => [{ at: T0 + i * 1000, agent: id, verb: 'v', resource: 'r', outcome: 'auto', r: 0.1 }, { at: T0 + i * 1000 + 5, agent: id, verb: 'v', resource: 'r', outcome: 'step_up', r: 0.7 }]);
const addN = (n: number, from: string) => Array.from({ length: n }, (_, i) => ['add', 'T' + (i + 1), i === 0 ? from : 'T' + i, 'm' + i, null]);
const sessCases: Array<[string, any[]]> = [
  ['basic', [['agent', 'A', goalA], ['start', 'S0', 'A'], ['depth', 'S0'], ['shares', 'S0'], ['agents', 'S0'], ['add', 'S1', 'S0', 'h1', null], ['add', 'S2', 'S1', 'h2', [{ type: 'max_blast_radius', max: 0.5 }]], ['depth', 'S2'], ['agents', 'S2'], ['shares', 'S2'], ['goal', 'S2']]],
  ['console', [['agent', 'A', goalA], ['start', 'S0', 'A'], ['add', 'S1', 'S0', 'h1', null], ['add', 'S2', 'S1', 'h2', null], ['agents', 'S2'],
    ['console', 'S2', sessEvents(['x', 'y'])], ['console', 'S0', []], ['console', 'S1', [null]], ['console', 'S0', [5, 'x', {}]]]],
  ['mixed-goals', [['agent', 'A', goalA], ['agent', 'B', goalB], ['agent', 'C', goalC], ['mk', 'S1', ['A', 'B'], null], ['shares', 'S1'], ['mk', 'S2', ['A', 'C'], null], ['shares', 'S2'], ['mk', 'S3', ['A', 'A'], null], ['shares', 'S3'], ['mk', 'S4', ['A', 'B'], ''], ['shares', 'S4'], ['mk', 'S5', ['A'], 'nope'], ['shares', 'S5'], ['depth', 'S1'], ['depth', 'S5'], ['mk', 'S6', [], ''], ['depth', 'S6'], ['shares', 'S6']]],
  ['depth-limit', [['agent', 'A', goalA], ['start', 'T0', 'A'], ...Array.from({ length: 34 }, (_, i) => ['add', 'T' + (i + 1), 'T' + i, 'm' + i, null]), ['depth', 'T31'], ['depth', 'T32'], ['depth', 'T33'], ['shares', 'T32'], ['agents', 'T3']]],
  ['bad-ops', [['agent', 'A', goalA], ['start', 'S0', 'A'], ['add', 'S1', 'S9', null, null], ['add', 'S1', 'S0', 'h1', 'x'], ['agents', 'S9'], ['console', 'S0', 'x'], ['console', 'S0', null]]],
];
for (const [name, ops] of sessCases) await o.run('session', name, runSession, [ops]);

// ------------------------------------------------------------------------------------------------ policy sim
const specs: any[] = [
  { permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 },
  { permissions: { stripe: ['payout', 'refund', 'charge'], gmail: ['send', 'draft'], github: ['read', 'merge_pr'] }, limits: { payout: '$100/day', refund: '$50/h', send: '5/hour', charge: '$20/m', read: '9/s', merge_pr: '5/w' }, riskPolicy: { theta1: 0.2, theta2: 0.5 }, now: 1000 },
  { permissions: { github: ['read', 'merge_pr', 'delete_repo'], gmail: ['draft'] }, budgetModel: 'risk', riskPolicy: { theta1: 0.1, theta2: 0.4 }, now: 5 },
  { permissions: { stripe: ['refund'], zz: ['thing'], 'stripe ': ['x'] }, limits: { refund: '$10', thing: '1/d', nope: '5', 'stripe.refund': '$9' }, now: 0 },
  { permissions: { github: ['read'] }, riskPolicy: { theta2: 1 }, now: 0 },
  { permissions: { stripe: ['payout', 'refund'], github: ['delete_repo'] }, limits: { payout: '$100000' }, riskPolicy: { bMax: 1000, kappa: 1, theta2: 1 }, now: 0 },
  { permissions: { github: ['read'] }, riskPolicy: { lambda: 0.5, bMax: 3 }, budgetModel: 'risk', now: 0 },
  { permissions: {}, now: 0 },
  { permissions: { stripe: ['issue_refund', 'bill'], gmail: ['send_email'] }, limits: { issue_refund: '$5' }, now: 0 },
];
const sact = (verb: string, resource: string, params?: any, at?: any) => ({ verb, resource, ...(params !== undefined ? { params } : {}), ...(at !== undefined ? { at } : {}) });
function genActions(seedN: number, n: number, timed: boolean): any[] {
  const g = rng(seedN);
  const verbs = ['stripe.payout', 'stripe.refund', 'stripe.charge', 'gmail.send', 'gmail.draft', 'github.read', 'github.merge_pr', 'github.delete_repo', 'zz.thing', 'nope.x', 'stripe.issue_refund'];
  const out: any[] = [];
  let at = T0;
  for (let i = 0; i < n; i++) {
    at += g.int(0, 3) * 20_000;
    out.push(sact(g.pick(verbs), g.pick(['acct:1', 'org/repo', 'x@y.z', '']), g.next() < 0.7 ? { amount: g.pick([1, 10, 25, 50, 99, 100, 250, 1000, 99999, 0, -3, '30', null]) } : g.next() < 0.5 ? {} : undefined, timed ? (g.next() < 0.1 ? undefined : at) : undefined));
  }
  return out;
}
const simSets: any[] = [[], genActions(11, 8, true), genActions(12, 25, true), genActions(13, 25, false), genActions(14, 60, true), genActions(15, 40, true).reverse(),
  [sact('stripe.payout', 'a', { amount: 10 }, 'x'), sact('stripe.payout', 'a', { amount: 10 }, null), sact('stripe.payout', 'a', { amount: 10 }, 5), sact('stripe.payout', 'a', { amount: 10 })]];
for (const [si, s] of specs.entries()) {
  for (const [ai, acts] of simSets.entries()) {
    for (const start of [null, 0, T0]) await o.run('simulate', `s${si}-${ai}-${start}`, (sp: any, aa: any, op: any) => PS.simulate(compilePolicy(sp), aa, op === null ? {} : { start: op }), [s, acts, start]);
  }
  await o.run('lintPolicy', `l${si}`, (sp: any) => PS.lintPolicy(compilePolicy(sp)), [s]);
}

// ------------------------------------------------------------------------------------------------ reputation evidence
const GS = sd('guardian');
const GPUB = b64u(publicKeyOf(GS));
const planner = new BS.BondSettlementPlanner({ guardianSecret: GS });
const jj = (x: any) => JSON.parse(JSON.stringify(x));
const view = (bonds: any = {}) => ({ bond: (id: string) => bonds[id], balanceOf: () => 1000, openTotals: () => ({ count: 0, sum: 0 }) });
const recs: any[] = [];
for (const [i, amt] of [10, 40, 2.5, 100].entries()) {
  const id = 'bond-' + i;
  recs.push(jj(planner.planOpen(view(), { claimId: id, amount: amt, depositor: 'alice', now: T0 + i }).record));
  recs.push(jj(planner.planRelease(view({ [id]: { claimId: id, amount: amt, depositor: 'alice', status: 'open' } }), { claimId: id, now: T0 + 100 + i }).record));
  try {
    recs.push(jj(planner.planSlashOnRevocation(view({ [id]: { claimId: id, amount: amt, depositor: 'alice', status: 'open' } }), { claimId: id, claim: { bond_ref: id, pcactn_digest: 'dg' + i }, revokedCapId: 'cap-' + i, treasury: 'treasury', challengerAccount: 'chal', now: T0 + 200 + i }).record));
  } catch (e) { console.log('slash plan failed', (e as Error).message); }
}
const subj = Object.fromEntries([0, 1, 2].map((i) => ['bond-' + i, 'subject-' + i]));
const tam = (r: any, f: any) => ({ ...r, ...f });
const recSets: any[] = [recs, recs.slice(0, 3), [], [recs[0]], recs.slice().reverse(), [...recs, tam(recs[1], { amount: 999 }), tam(recs[2], { sig: 'AAAA' }), null, 5, {}, { claimId: 5 }, tam(recs[1], { claimId: 'unknown' })], [recs[1], recs[1], recs[1]]];
for (const [i, rs] of recSets.entries()) for (const [gname, g] of [['@g', GPUB], ['other', b64u(publicKeyOf(sd('other')))]] as const) for (const [sname, sm] of [['subj', subj], ['none', {}], ['all', Object.fromEntries(Array.from({ length: 4 }, (_, j) => ['bond-' + j, 'sub' + j]))]] as const) {
  await o.run('disputesFromSettlements', `d${i}-${gname}-${sname}`, (rr: any, gk: string, m: any, pn: any) => RE.disputesFromSettlements(rr, gk === '@g' ? GPUB : gk, (id: string) => (Object.hasOwn(m, id) ? m[id] : undefined), pn === null ? undefined : pn), [rs, g === GPUB ? '@g' : g, sm, null]);
}
refWrite(o, 'core-research-java');
