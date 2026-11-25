// Oracle: the agent-facing half of approvals.ts (reviewAction, buildGoalLineage, describeGoalLineage, batchReview, timeBox), TS reference.
// Written for the Java lane; reusable by any native. Ed25519 only; keys come from seed(label); every clock is an argument.
// An "agent spec" is {principal, holder, goal, goalSalt, permissions, limits?, riskPolicy?, budgetModel?, now, aud?}: both sides build
// the facade agent from it (principal / holder = seed labels under "approvals/"). The grant carries a random provenance pin, so a grant
// is never compared; only review results (which never include it) and deterministic Ed25519 attenuations are.
// PORTING (fn(args) -> native entry point, comparison rule; results compared by JSON value, a reference throw = the native throws):
//   reviewAction(spec, verb, resource, params|null, opts)  -> Approvals.reviewAction(agent, ...) ; opts {now?, goal?, standing?, renderer?: "ok"|"throw"|"badshape", insecure?: bool}
//       renderer "ok" returns {v:1, kind:"pca-approval-render", verb, def_digest: 43 x "A", unreviewed: true, fields:[{id:"resource",class:"param",value:resource}]};
//       "throw" throws Error("boom"); "badshape" returns {v:2}. params null = undefined.
//   buildGoalLineage(spec, verb, resource, params|null, {goal?})
//   describeGoalLineage(lineage)  (lineage objects as produced above, plus hostile ones)
//   batchReview(spec, calls[{verb,resource,params?}], opts)
//   timeBox(parent, holderSeedLabel, ttlMs, now) -> the attenuated capability (Ed25519 is deterministic: compared in full)
import { Oracle, refWrite, seed } from './lib.mjs';
const { b64u }: any = await import('../../../packages/pca/src/hash.ts');
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
const { mintRoot }: any = await import('../../../packages/pca/src/capability.ts');
const { agent }: any = await import('../../../packages/pca/src/facade.ts');
const { reviewAction, buildGoalLineage, describeGoalLineage, batchReview, timeBox }: any = await import('../../../packages/pca/src/approvals.ts');

const o = new Oracle('core-approvals-java', 'tools/pca-audit/oracles/core-approvals-java.mts', 'TS-reference oracle for the facade half of approvals.');
const keyOf = (l: string) => seed('approvals/' + l);

const agents = new Map<string, any>();
function build(spec: any): any {
  const k = JSON.stringify(spec);
  let a = agents.get(k);
  if (!a) {
    const p = keyOf(spec.principal), h = keyOf(spec.holder);
    a = agent({
      principal: { secretKey: p, publicKey: publicKeyOf(p) }, holder: { secretKey: h, publicKey: publicKeyOf(h) }, goal: spec.goal,
      goalSalt: spec.goalSalt, permissions: spec.permissions, ...(spec.limits ? { limits: spec.limits } : {}),
      ...(spec.riskPolicy ? { riskPolicy: spec.riskPolicy } : {}), ...(spec.budgetModel ? { budgetModel: spec.budgetModel } : {}), now: spec.now, ...(spec.aud ? { aud: spec.aud } : {}),
    });
    agents.set(k, a);
  }
  return a;
}
const rendererOf = (mode: string) => (verb: string, resource: string) => {
  if (mode === 'throw') throw new Error('boom');
  if (mode === 'badshape') return { v: 2 } as any;
  return { v: 1, kind: 'pca-approval-render', verb, def_digest: 'A'.repeat(43), unreviewed: true, fields: [{ id: 'resource', class: 'param', value: resource }] } as any;
};
const optsOf = (op: any) => {
  const r: any = {};
  if (op?.now !== undefined && op.now !== null) r.now = op.now;
  if (op?.goal !== undefined && op.goal !== null) r.goal = op.goal;
  if (op?.standing) r.standing = op.standing;
  if (op?.renderer) r.renderer = rendererOf(op.renderer);
  if (op?.insecure) r.insecureUnboundApproval = true;
  return r;
};
const prm = (p: any) => (p === null ? undefined : p);

const SALT = 'AAECAwQFBgcICQoLDA0ODw';
const pay = { principal: 'p', holder: 'h', goal: 'process October payouts', goalSalt: SALT, permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 };
const multi = {
  principal: 'p', holder: 'h2', goal: 'run the shop “day”', goalSalt: SALT, now: 1000,
  permissions: { stripe: ['payout', 'refund', 'charge'], gmail: ['send', 'draft'], github: ['read', 'merge_pr'], zz: ['thing'] },
  limits: { payout: '$100/day', refund: '$50/h', send: '5/hour', charge: '$20/m', read: '9/s', merge_pr: '5/w', thing: '3/mo' },
  riskPolicy: { theta1: 0.2, theta2: 0.5 },
};
const frac = { ...multi, goalSalt: 'BAECAwQFBgcICQoLDA0ODw', limits: { payout: '$100.5/min', refund: '$7.5/weeks', send: '1/d', charge: '$2/mo', read: '4/second' } };
const risk = { principal: 'p', holder: 'h3', goal: 'g', goalSalt: SALT, permissions: { github: ['read', 'merge_pr', 'delete_repo'], gmail: ['draft'] }, budgetModel: 'risk', riskPolicy: { theta1: 0.1, theta2: 0.4 }, now: 5 };
const nosalt = { ...pay, goal: 'ünï ☃ goal', permissions: { stripe: ['payout', 'refund'] }, limits: { payout: '$100', refund: '$10/d' } };
const specs: any[] = [pay, multi, frac, risk, nosalt];

const paramsSet: Array<[string, any]> = [
  ['none', null], ['empty', {}], ['amt0', { amount: 0 }], ['amt10', { amount: 10 }], ['amt50', { amount: 50 }], ['amt80', { amount: 80 }], ['amt99.5', { amount: 99.5 }], ['amt100', { amount: 100 }],
  ['amt500', { amount: 500 }], ['amt-1', { amount: -1 }], ['amtStr', { amount: '25' }], ['amtNull', { amount: null }], ['amtObj', { amount: { a: 1 } }], ['amtArr', { amount: [1, null, 'x', [2, 3]] }],
  ['amtBool', { amount: true }], ['amt1e21', { amount: 1e21 }], ['amtFloat', { amount: 0.1 }],
  ['many', { a: 1, b: 'two', c: { d: 3, e: [1, 2] }, d: [1, 2, 3], e: null, f: true, g: 'g' }],
  ['intkeys', { b: 1, 2: 'two', a: 2, 1: 'one', 10: { z: 1, 1: 2 } }],
  ['nested', { to: { name: 'x', n: [1, 2, { q: null }] }, memo: 'hé "q" \\ \n' }],
  ['unicode', { note: 'snow ☃ \u{1F600}', k: 'a\u0001b' }],
  ['fieldAmountOther', { amount: 5, extra: 'x' }], ['fiveKeys', { a: 1, b: 2, c: 3, d: 4, e: 5 }], ['emptyStr', { x: '' }],
];
const targets: Array<[any, string, string]> = [];
for (const s of [pay, nosalt]) for (const [v, r] of [['stripe.payout', 'acct:1'], ['stripe.refund', 'charge:1'], ['gmail.send', 'x@y.z'], ['stripe.payout', '']] as const) targets.push([s, v, r]);
for (const s of [multi, frac]) for (const [v, r] of [['stripe.payout', 'acct:1'], ['stripe.refund', 'ch_1'], ['stripe.charge', 'cus_9'], ['gmail.send', 'a@b.c'], ['gmail.draft', 'd'], ['github.read', 'org/repo'], ['github.merge_pr', 'org/repo#4'], ['zz.thing', 'q'], ['stripe.refund.x', 'r'], ['nope', 'r']] as const) targets.push([s, v, r]);
for (const [v, r] of [['github.read', 'r'], ['github.merge_pr', 'r'], ['github.delete_repo', 'r'], ['gmail.draft', 'd'], ['gmail.send', 'd']] as const) targets.push([risk, v, r]);

let n = 0;
const standingFor = (verbs: string[], resource: string | undefined, at: number, ttl: number) => ({ id: 'id' + n, verbs, ...(resource !== undefined ? { resource } : {}), grantedAt: at, ttlMs: ttl, by: 'me' });
const optSets: any[] = [
  { insecure: true, now: 1 }, { insecure: true, now: 1, goal: 'process October payouts' }, { insecure: true, now: 1700000000000, goal: 'other “goal”' }, { renderer: 'ok', now: 2 },
  { renderer: 'ok', now: 2, goal: 'process October payouts', insecure: true }, { renderer: 'throw', now: 3 }, { renderer: 'badshape', now: 3 }, { now: 4 }, { insecure: true, now: 7 }, // every option set pins the clock: request.id embeds requestedAt
  { insecure: true, now: 5, standing: [standingFor(['stripe.payout'], undefined, 0, 100)] },
  { insecure: true, now: 5, standing: [standingFor(['stripe.payout', 'stripe.refund'], 'acct:*', 0, 100)] },
  { insecure: true, now: 500, standing: [standingFor(['stripe.payout'], '*', 0, 100)] },
  { renderer: 'ok', now: 6, standing: [standingFor(['gmail.send'], undefined, 0, 1000)] },
];
for (const [s, v, r] of targets) {
  for (const [pn, p] of paramsSet) {
    const sel = optSets[n++ % optSets.length];
    await o.run('reviewAction', `${s.holder}-${v}-${r}-${pn}-${n}`, (spec: any, verb: string, res: string, params: any, op: any) => reviewAction(build(spec), verb, res, prm(params), optsOf(op)), [s, v, r, p, sel]);
  }
}
// a representative cross product for the lineage builder
n = 0;
for (const [s, v, r] of targets) for (const [pn, p] of paramsSet.filter((_, i) => i % 3 === 0)) {
  for (const goal of [undefined, 'process October payouts', 'run the shop “day”', 'wrong goal', '']) {
    const op: any = goal === undefined ? {} : { goal };
    await o.run('buildGoalLineage', `${s.holder}-${v}-${r}-${pn}-${goal ?? 'u'}-${n++}`, (spec: any, verb: string, res: string, params: any, op2: any) => buildGoalLineage(build(spec), verb, res, prm(params), op2), [s, v, r, p, op]);
  }
}
// describeGoalLineage over real lineages and hostile shapes
const lins: any[] = [];
for (const [s, v, r] of targets.slice(0, 12)) lins.push(buildGoalLineage(build(s), v, r, { amount: 5 }, { goal: 'process October payouts' }), buildGoalLineage(build(s), v, r, undefined));
lins.push({ chain: [] }, { chain: [{ kind: 'goal', label: 'a' }] }, { chain: [{ kind: 'goal', label: 'a', detail: '' }, { kind: 'action', label: 'b', detail: 'd' }] }, { chain: [{ label: 'é', detail: '☃' }] });
let li = 0;
for (const l of lins) await o.run('describeGoalLineage', 'l' + li++, describeGoalLineage as any, [JSON.parse(JSON.stringify(l))]);
for (const bad of [null, {}, { chain: null }, { chain: 'x' }, { chain: [null] }, { chain: [{}] }, { chain: [{ label: 5 }] }]) await o.run('describeGoalLineage', 'bad' + li++, describeGoalLineage as any, [bad]);
// batches
const calls = (s: any) => [{ verb: 'stripe.payout', resource: 'a', params: { amount: 10 } }, { verb: 'stripe.payout', resource: 'a', params: { amount: 80 } }, { verb: 'stripe.payout', resource: 'a', params: { amount: 500 } }, { verb: 'nope', resource: 'z' }, { verb: 'stripe.payout', resource: 'b', params: null }];
let bi = 0;
for (const s of [pay, multi, nosalt]) for (const op of optSets) {
  await o.run('batchReview', `b${bi++}`, (spec: any, cs: any, op2: any) => batchReview(build(spec), cs.map((c: any) => ({ verb: c.verb, resource: c.resource, ...(c.params ? { params: c.params } : {}) })), optsOf(op2)), [s, calls(s), op]);
}
await o.run('batchReview', 'empty', (spec: any, cs: any, op2: any) => batchReview(build(spec), cs, optsOf(op2)), [pay, [], { insecure: true }]);
// timeBox
for (const [label, cav] of [['root', []], ['scope', [{ type: 'scope', actions: ['a.b'] }]], ['two', [{ type: 'scope', actions: ['a'] }, { type: 'expires', at: 99 }]]] as const) {
  const pub = b64u(publicKeyOf(keyOf('tb-holder'))), ppub = b64u(publicKeyOf(keyOf('tb-principal')));
  const parent = mintRoot({ principalSecret: keyOf('tb-principal'), principalPublic: ppub, holder: pub, caveats: cav as any });
  for (const [ttl, now] of [[1000, 0], [3_600_000, 1_800_000_000_000], [0, 5], [-5, 5], [1.5, 10], [86_400_000, 1e12], [1e15, 1e15], [1e300, 1e300]]) {
    await o.run('timeBox', `${label}-${ttl}-${now}`, (cap: any, hl: string, t: number, nw: number) => timeBox(cap, keyOf(hl), t, nw), [JSON.parse(JSON.stringify(parent)), 'tb-holder', ttl, now]);
  }
}
refWrite(o, 'core-approvals-java');
