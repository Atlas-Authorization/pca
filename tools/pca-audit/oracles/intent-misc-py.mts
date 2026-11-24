// Oracle (python lane): @atlasauth/pca-intent pieces without a dedicated corpus: statement.ts, compilers.ts (pure parts), schema.ts,
// provenance.ts, classifier.ts (pure parts), trajectory.ts, frames.ts, jit.ts (pure parts). Deterministic (fixed seeds, no clocks).
// PORTING (fn(args) -> native entry point; JSON value equality, a throwing reference requires a native throw):
//   signIntent(s, seedB64u) / verifyIntent(s, opts?) / intentRef(s)
//   parseSlotsJSON(raw) / slotsPrompt(text) / runCompilers(input, specs) (specs: {kind: captured|fixed|throws, id, family, policy?}) / analyzeDisagreement(outputs, opts) / committeeAnchors(outputs, lambda) / panelFlags(report)
//   deriveOmegaFromSchema(opts) / canonValue(decl, x)
//   provenanceBanner(level, what?) / provenanceFriction(base, sensitivity, level) / regretReport(cases, scale?) (a case's admits = values.ok == 1, utility = values.u)
//   calibrateConfusion(samples, labels, delta?) / confusionDigest(cal) / publishedErrorRate(cal) / classifierCardNote(id, cal) / classifierRisk(m) / labelSound(m) / labelSoundBound(m, hMax)
//   dimKindOf(path) / describeAccCell(d, i, label, thisAction?) / trajectoryHarmRange(n, h) / defaultAccumulators(schema, opts) / augmentOmega(omega, psi, opts) / liftAction(omega, psi, history, cand, schema?) / stepTrajectory(omega, psi, history, cand, allowedCells, schema?)
//   stateDigest(v) / snapshotState(values, keep?) / writeSetOf(spec, action) / checkFrame(spec, action, pre, post, opts?)
//   cellCoords(vs, cell) / cellFromCoords(vs, coords) / intentRequiredBody(input)
import * as ST0 from '../../../packages/pca-intent/src/statement';
import * as CO0 from '../../../packages/pca-intent/src/compilers';
import * as SC0 from '../../../packages/pca-intent/src/schema';
import * as PV0 from '../../../packages/pca-intent/src/provenance';
import * as CL0 from '../../../packages/pca-intent/src/classifier';
import * as TR0 from '../../../packages/pca-intent/src/trajectory';
import * as FR0 from '../../../packages/pca-intent/src/frames';
import * as JI0 from '../../../packages/pca-intent/src/jit';
import * as O0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const ST: any = (ST0 as any).default ?? ST0;
const CO: any = (CO0 as any).default ?? CO0;
const SC: any = (SC0 as any).default ?? SC0;
const PV: any = (PV0 as any).default ?? PV0;
const CL: any = (CL0 as any).default ?? CL0;
const TR: any = (TR0 as any).default ?? TR0;
const FR: any = (FR0 as any).default ?? FR0;
const JI: any = (JI0 as any).default ?? JI0;
const O: any = (O0 as any).default ?? O0;
const o = new Oracle('intent-misc', 'tools/pca-audit/oracles/intent-misc-py.mts', 'TS-reference oracle for intent statement, compilers, schema, provenance, classifier, trajectory, frames and jit pure parts.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const unseed = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const S = (l: string) => Buffer.from(seed('intent-misc/' + l)).toString('base64url');

// ---- statement ----
const SEED_A = S('a'); const SEED_B = S('b');
const stmt: any = { v: 1, text: 'refund up to 250 USD', slots: { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', max: 250 }] }, sources: [{ kind: 'conversation', uri: 'chat://1', digest: S('d1') }, { kind: 'ticket', digest: S('d2') }], created_at: 1700000000000, nonce: 'n-1' };
const signed = ST.signIntent(stmt, unseed(SEED_A));
await run('signIntent', (s: any, sd: string) => ST.signIntent(s, unseed(sd)), [stmt, SEED_A]);
await run('signIntent', (s: any, sd: string) => ST.signIntent(s, unseed(sd)), [{ ...stmt, principal: signed.principal }, SEED_A]);
await run('signIntent', (s: any, sd: string) => ST.signIntent(s, unseed(sd)), [{ ...stmt, principal: signed.principal }, SEED_B]);
for (const bad of [{ ...stmt, text: '' }, { ...stmt, v: 2 }, { ...stmt, slots: [] }, { ...stmt, sources: 'x' }, { ...stmt, sources: [{ kind: 'nope', digest: S('d1') }] }, { ...stmt, sources: [{ kind: 'form', digest: 'x' }] }, { ...stmt, sources: [{ kind: 'form', uri: 5, digest: S('d1') }] }, { ...stmt, created_at: -1 }, { ...stmt, created_at: 1.5 }, { ...stmt, nonce: '' }, { ...stmt, extra: 1 }])
  await run('signIntent', (s: any, sd: string) => ST.signIntent(s, unseed(sd)), [bad, SEED_A]);
await run('intentRef', ST.intentRef, [signed]);
await run('intentRef', ST.intentRef, [{ ...signed, sig: 'zzz', alg: 'ml-dsa-65' }]);
await run('intentRef', ST.intentRef, [stmt]);
await run('verifyIntent', ST.verifyIntent, [signed]);
await run('verifyIntent', ST.verifyIntent, [signed, { expectedSigner: signed.principal }]);
await run('verifyIntent', ST.verifyIntent, [signed, { expectedSigner: S('x') }]);
await run('verifyIntent', ST.verifyIntent, [{ ...signed, alg: 'ml-dsa-65' }]);
await run('verifyIntent', ST.verifyIntent, [{ ...signed, alg: 'nope' }]);
await run('verifyIntent', ST.verifyIntent, [{ ...signed, pq_pk: 'x' }]);
await run('verifyIntent', ST.verifyIntent, [{ ...signed, sig: S('q') }]);
for (const [, v] of variants(signed, { hostile: [null, 0, 1, '', 'x', [], {}, true, -1], maxPaths: 300 })) {
  try { const r = ST.verifyIntent(JSON.parse(JSON.stringify(v))); if (JSON.stringify(r).includes('malformed intent statement')) continue; } catch {}
  await run('verifyIntent', ST.verifyIntent, [v]);
}

// ---- compilers ----
for (const raw of ['{"verbs":["stripe.refund"],"constraints":[{"path":"action.params.amount","max":100}]}', '```json\n{"verbs":["stripe.refund","nope.x",5],"constraints":[{"verb":"stripe.refund","path":"action.params.amount","max":100.5,"min":1},{"path":"bad.path","max":1},{"path":"env.hour","min":9,"max":17}]}\n```',
  'not json', '', '[]', '5', 'null', '{}', '{"verbs":["gmail.send"],"constraints":[null,5,{"path":"action.params.to","oneOf":["a","b"],"noneOf":[],"prefixOneOf":[1]},{"verb":"stripe.refund","path":"action.params.x","max":1},{"verb":5,"path":"action.params.x","max":1},{"path":"action.params.to"},{"verb":"gmail.send","path":"action.params.to"},{"verb":"gmail.send","path":"action.resource","prefixOneOf":["/a/"]}]}',
  '  {"verbs":["stripe.refund","stripe.refund"],"constraints":[{"path":"action.params.amount","max":1e2,"min":"5"}]} trailing', '{"verbs":"x","constraints":"y"}', '{"verbs":["stripe.refund"],"constraints":[{"path":"action.params.amount","max":NaN}]}', 'prefix {"verbs":[]} and {"verbs":["files.read"]}'])
  await run('parseSlotsJSON', (r: string) => CO.parseSlotsJSON(r), [raw]);
for (const t of ['refund the customer', '', 'ünï "quoted" \n text']) await run('slotsPrompt', (x: string) => CO.slotsPrompt(x), [t]);
const mk = (spec: any) => spec.kind === 'captured' ? CO.capturedSlotsCompiler(spec.id) : spec.kind === 'throws' ? { id: spec.id, family: spec.family, compile() { throw new Error('boom'); } } : CO.fixedCompiler(spec.id, spec.family, () => spec.policy);
const sl1 = { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', max: 250 }] };
const specsets: any[][] = [[{ kind: 'captured', id: 'cap' }], [{ kind: 'fixed', id: 'f1', family: 'rule', policy: { predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 250 }] }], caveats: [{ type: 'reversibility_max', class: 'irreversible' }, { type: 'expires', at: 5 }] } }, { kind: 'throws', id: 't', family: 'rule' }],
  [{ kind: 'fixed', id: 'f2', family: 'rule', policy: 5 }, { kind: 'fixed', id: 'f3', family: 'x', policy: null }]];
for (const inp of [{ text: 'refund', slots: sl1 }, { text: 'refund' }]) for (const sp of specsets) await run('runCompilers', (i: any, s: any[]) => CO.runCompilers(i, s.map(mk)), [inp, sp]);
const A = (amt: number) => ({ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: amt }] }], caveats: [] });
const outs: any[] = [
  { compiler: 'a', family: 'm1', policy: A(250), notes: [] }, { compiler: 'b', family: 'm2', policy: A(500), notes: [] }, { compiler: 'c', family: 'm1', policy: { predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 250 }, { field: 'action.params.currency', op: 'in', value: ['usd'] }] }, { verb: 'gmail.send' }], caveats: [] }, notes: ['x'] },
  { compiler: 'd', family: 'm3', policy: { predicates: [], caveats: [] }, notes: [] }];
for (const subset of [[0], [0, 1], [0, 2], [1, 2, 3], [0, 0].slice(0, 1), []]) for (const opts of [{}, { slots: sl1 }, { slots: sl1, riskWeighted: true }, { slots: sl1, limit: 3 }]) {
  await run('analyzeDisagreement', (os: any[], op: any) => CO.analyzeDisagreement(os, op), [subset.map((i) => outs[i]), opts]);
  const rep = CO.analyzeDisagreement(subset.map((i) => outs[i]), opts);
  await run('panelFlags', CO.panelFlags, [rep]);
}
for (const lam of [0.5, 2]) await run('committeeAnchors', CO.committeeAnchors, [outs, lam]);

// ---- schema ----
const P = (type: string, semantic: string, sensitivity: string, extra: any = {}) => ({ type, semantic, sensitivity, ...extra });
const schema: any = { verbs: [
  { verb: 'shop.buy', kind: 'write', reversibility: 'irreversible', params: { 'action.params.total': P('integer', 'money.amount', 'critical', { min: 0, max: 5000 }), 'action.params.note': P('string', 'text.message', 'free', { max_len: 100 }), 'action.params.gift': P('boolean', 'flag.gift', 'material'), 'action.params.tags': P('set', 'label.tag', 'material', { values: ['a', 'b', 'c'] }), 'action.params.ship': P('string', 'place.address', 'material', { values: ['home', 'office'], default: 'home', principal_neutral_default: true }), 'action.params.qty': P('integer', 'count.items', 'material', { default: 1, principal_neutral_default: true }) } },
  { verb: 'shop.view', kind: 'read', params: { 'action.params.id': P('string', 'id.item', 'free') } },
  { verb: 'shop.cancel', kind: 'write', reversibility_by: { param: 'action.params.refund', map: { true: 'reversible', false: 'irreversible' } }, params: { 'action.params.refund': P('boolean', 'flag.refund', 'material') } },
  { verb: 'shop.pay', kind: 'write', params: { 'action.params.payee': P('string', 'party.payee', 'free'), 'action.params.amt': P('integer', 'money.amount', 'free') } }] };
const sl2 = { verbs: ['shop.buy'], constraints: [{ path: 'action.params.total', max: 300 }, { path: 'action.params.ship', oneOf: ['home'] }] };
const pol = { predicates: [{ verb: 'shop.buy', where: [{ field: 'action.params.total', op: 'lte', value: 100 }] }] };
for (const opts of [{ schema }, { schema, slots: sl2 }, { schema, slots: sl2, policies: [pol] }, { schema, verbs: ['shop.buy', 'shop.nope'] }, { schema, verbs: ['shop.cancel', 'shop.pay'] }, { schema, confirmed: { 'action.params.total': [50], 'action.params.gift': [true], 'action.params.tags': [['b', 'a']], 'action.params.ship': ['office'] } },
  { schema, domains: { 'action.params.total': { lo: 10, hi: 20 } } }, { schema, floor: { prefixes: ['count.'], exact: [] } }, { schema: { verbs: [] } }, { schema, slots: { verbs: ['shop.view'], constraints: [] } }]) await run('deriveOmegaFromSchema', (x: any) => SC.deriveOmegaFromSchema(x), [opts]);
for (const [d, x] of [[P('boolean', 'x', 'material'), true], [P('boolean', 'x', 'material'), 0], [P('set', 'x', 'material'), ['b', 'a', 'é', '😀', 'Z']], [P('set', 'x', 'material'), []], [P('array', 'x', 'material'), [1, 2]], [P('string', 'x', 'material'), 'q"']] as any[]) await run('canonValue', SC.canonValue, [d, x]);

// ---- provenance ----
for (const l of ['trusted', 'first_party', 'tool', 'web', 'agent', 'bogus']) { await run('provenanceBanner', (a: string) => PV.provenanceBanner(a), [l]); await run('provenanceBanner', (a: string, b: string) => PV.provenanceBanner(a, b), [l, 'recipient']); for (const b of ['tap', 'hold', 'typed', 'device', 'zzz']) for (const s of ['material', 'critical']) await run('provenanceFriction', PV.provenanceFriction, [b, s, l]); }
const oc = (u: number, ok: number) => ({ verb: 'v', values: { u, ok } });
const cases = [{ feasible: [oc(1, 1), oc(5, 1), oc(9, 0)], chosen: oc(1, 1) }, { feasible: [oc(1, 1), oc(5, 1)], chosen: oc(5, 1) }, { feasible: [oc(2, 0)], chosen: oc(2, 0) }, { feasible: [], chosen: oc(1, 1) }, { feasible: [oc(3, 1), oc(0.5, 1)], chosen: oc(0.5, 1) }];
const cvt = (cs: any[]) => cs.map((c) => ({ ...c, admits: (x: any) => x.values.ok === 1, utility: (x: any) => x.values.u }));
for (const sc of [undefined, 1, 2, 0, -1]) await run('regretReport', (cs: any[], s: any) => (s === undefined ? PV.regretReport(cvt(cs)) : PV.regretReport(cvt(cs), s)), sc === undefined ? [cases] : [cases, sc]);
await run('regretReport', (cs: any[]) => PV.regretReport(cvt(cs)), [[]]);

// ---- classifier ----
const labs = ['spam', 'ham', 'other'];
const samp = (t: string, p: string, k: number) => Array.from({ length: k }, () => ({ truth: t, predicted: p }));
const sets: any[] = [[...samp('spam', 'spam', 40), ...samp('spam', 'ham', 2), ...samp('ham', 'ham', 50), ...samp('ham', 'spam', 5), ...samp('other', 'other', 10)], [], samp('spam', 'spam', 3), [{ truth: 'x', predicted: 'spam' }], [...samp('spam', 'ham', 1), ...samp('ham', 'spam', 1)]];
const cals: any[] = [];
for (const ss of sets) for (const dg of [undefined, 0.05, 0.2]) { await run('calibrateConfusion', (s: any, l: any, d: any) => (d === undefined ? CL.calibrateConfusion(s, l) : CL.calibrateConfusion(s, l, d)), dg === undefined ? [ss, labs] : [ss, labs, dg]); try { cals.push(CL.calibrateConfusion(ss, labs, dg)); } catch {} }
for (const bad of [[[], [], 0.05], [[], labs, 0], [[], labs, 1], [[], ['b', 'a', 'a'], 0.5]]) await run('calibrateConfusion', (s: any, l: any, d: any) => CL.calibrateConfusion(s, l, d), bad);
for (const c of cals) { await run('confusionDigest', CL.confusionDigest, [c]); await run('publishedErrorRate', CL.publishedErrorRate, [c]); await run('classifierCardNote', CL.classifierCardNote, ['clf', c]); }
const arr = { mu: [[0.2, 0.1], [0.3, 0.4]], a: [[1, 0], [1, 1]], h: [[1, 5], [2, 3]], inG: [[true, false], [true, true]], g: [[0.9, 0.2], [0.1, 0.8]] };
const arr2 = { ...arr, a: [[1, 1], [1, 1]] }; const arr3 = { ...arr, inG: [[false, false], [false, false]] }; const arr4 = { ...arr, a: [[0, 0], [0, 0]], g: [[1, 1], [1, 1]] };
for (const m of [arr, arr2, arr3, arr4]) { await run('classifierRisk', CL.classifierRisk, [m]); await run('labelSound', CL.labelSound, [m]); await run('labelSoundBound', CL.labelSoundBound, [m, 7]); }

// ---- trajectory ----
for (const p of ['action.params.x', 'env.acc.s.post', 'env.mon.m.state', 'env.canon.g', 'env.world.w', 'env.rel.r', 'env.prov.p', 'env.class.c', 'action.resource', '']) await run('dimKindOf', TR.dimKindOf, [p]);
const accDim: any = { kind: 'num', path: 'env.acc.s.post', lo: 0, hi: 1000, cuts: [100, 500], dist: 'loguniform' };
for (const i of [0, 1, 2, 3, 4, 5, -1]) await run('describeAccCell', (d: any, k: number, l: string) => TR.describeAccCell(d, k, l), [accDim, i, 'trip total']);
await run('describeAccCell', (d: any, k: number, l: string, t: number) => TR.describeAccCell(d, k, l, t), [accDim, 1, 'trip total', 42]);
for (const [a, b] of [[10, 5], [0, 5], [10, 0], [-1, 5], [1.5, 2], [10, -1], [2 ** 53, 1]]) await run('trajectoryHarmRange', TR.trajectoryHarmRange, [a, b]);
await run('defaultAccumulators', (s: any, x: any) => TR.defaultAccumulators(s, x), [schema, { spendDomainMax: 10000 }]);
const sch2: any = { verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.amount': P('integer', 'money.amount', 'critical', { accumulates_into: ['usd', 'eur x'] }), 'action.params.fee': P('integer', 'money.amount', 'material') } }, { verb: 'a.c', kind: 'write', params: { 'action.params.pay': P('integer', 'money.amount', 'material', { accumulates_into: ['usd'] }) } }] };
for (const x of [{ spendDomainMax: 500, questionCap: 3 }, { spendDomainMax: 500, holder: { kind: 'wallet' } }]) await run('defaultAccumulators', (s: any, y: any) => TR.defaultAccumulators(s, y), [sch2, x]);
const base0 = { id: 's', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
const psi: any = { accumulators: [{ ...base0, agg: 'sum', val: 'action.params.total', domain_max: 1000 }, { ...base0, id: 'w', agg: 'count', holder: { kind: 'wallet' } }, { ...base0, id: 'q', sel: { verbs: ['shop.view'] }, agg: 'count', domain_max: 50 }], monitors: [{ id: 'm', kind: 'requires_prior', p: { verb: 'shop.verify', resource: '*' }, q: { verb: 'shop.buy', resource: '*' } }, { id: 'n', kind: 'never', p: { verb: 'shop.bad', resource: '*' } }] };
const omegaB = O.deriveOmega({ policies: [{ predicates: [{ verb: 'shop.buy', where: [{ field: 'action.params.total', op: 'lte', value: 300 }] }, { verb: 'shop.view' }] }] });
const augs: any[] = [];
for (const opts of [{}, { cuts: { s: [50, 300, 5, 1001, 1.5, -1] } }, { scope: 'selected' }, { scope: 'selected', cuts: { s: [10] }, schema }, { scope: 'all', cuts: { q: [3] } }]) { await run('augmentOmega', (om: any, p: any, x: any) => TR.augmentOmega(om, p, x), [omegaB, psi, opts]); try { augs.push(TR.augmentOmega(omegaB, psi, opts)); } catch {} }
await run('augmentOmega', (om: any, p: any, x: any) => TR.augmentOmega(om, p, x), [omegaB, { accumulators: [{ ...base0, agg: 'sum', val: 'action.params.total' }], monitors: [] }, {}]);
const hist: any[] = [{ id: 'h1', verb: 'shop.buy', resource: 'r', params: { total: 120 }, t: 10, status: 'committed' }, { id: 'h2', verb: 'shop.verify', resource: 'r', params: {}, t: 20, status: 'committed' }];
const cands: any[] = [{ verb: 'shop.buy', resource: 'r', params: { total: 50 }, t: 100 }, { verb: 'shop.buy', resource: 'r', params: { total: 5000 }, t: 100 }, { verb: 'shop.buy', resource: 'r', params: {}, t: 100 }, { verb: 'shop.view', resource: 'r', params: { total: 'x' }, t: 100 }, { verb: 'shop.nope', resource: 'r', params: {}, t: 100 }, { verb: 'shop.buy', resource: 'r', params: { total: true }, t: 100 }];
for (const om of augs.slice(0, 3)) for (const h of [[], hist]) for (const c of cands) await run('liftAction', (a: any, p: any, hh: any, cc: any) => TR.liftAction(a, p, hh, cc), [om, psi, h, c]);
for (const c of cands.slice(0, 3)) for (const al of [[[0, 0, 0]], 'all', 'none']) await run('stepTrajectory', (a: any, p: any, hh: any, cc: any, allow: any) => { const r = TR.stepTrajectory(a, p, hh, { ...cc, id: 'new' }, (verb: string, cell: number[]) => allow === 'all' ? true : allow === 'none' ? false : allow.some((x: number[]) => x.join() === cell.join()), undefined); return r; }, [augs[0], psi, hist, c, al]);

// ---- frames ----
for (const v of [1, 'a', null, { a: [1, 2] }, [1, { b: 2 }], true, 1.5, '']) await run('stateDigest', FR.stateDigest, [v]);
await run('snapshotState', (v: any) => FR.snapshotState(v), [{ 'a.b': 1, c: { d: 2 }, e: null }]);
await run('snapshotState', (v: any, k: any) => FR.snapshotState(v, k), [{ 'a.b': 1, c: 'x' }, false]);
const spec: any = { state: ['acct.email', 'acct.cards', 'loyalty.points', 'bookings.count'], writes: { 'shop.buy': ['loyalty.points', 'bookings.count'], 'acct.update': { param: 'action.params.field', map: { email: ['acct.email'], cards: ['acct.cards'] }, default: [] }, 'acct.nop': { param: 'field', map: {} } }, post: [{ id: 'buy.count', verb: 'shop.buy', deltas: [{ path: 'bookings.count', by: 1 }] }, { id: 'buy.eff', verb: 'shop.buy', where: [{ field: 'env.effect.amount', op: 'lte', ref: 'action.params.total' }] }, { id: 'buy.pts', verb: 'shop.buy', deltas: [{ path: 'loyalty.points', by: 10 }], where: [{ field: 'env.post.loyalty.points', op: 'gte', ref: 'env.pre.loyalty.points' }] }] };
const vals0 = { 'acct.email': 'a@x', 'acct.cards': ['v'], 'loyalty.points': 100, 'bookings.count': 2 };
const pre = FR.snapshotState(vals0); const preNoVal = FR.snapshotState(vals0, false);
const posts: Record<string, any> = { same: pre, mail: FR.snapshotState({ ...vals0, 'acct.email': 'b@x' }), buy: FR.snapshotState({ ...vals0, 'loyalty.points': 110, 'bookings.count': 3 }), buyBad: FR.snapshotState({ ...vals0, 'loyalty.points': 105, 'bookings.count': 5 }), cards: FR.snapshotState({ ...vals0, 'acct.cards': [] }), missing: FR.snapshotState({ 'acct.email': 'a@x' }), noval: preNoVal, empty: {} };
for (const [pn, ps] of Object.entries(posts)) for (const a of [{ verb: 'shop.buy', resource: 'r', params: { total: 50 } }, { verb: 'acct.update', resource: 'r', params: { field: 'email' } }, { verb: 'acct.update', resource: 'r', params: { field: 'zzz' } }, { verb: 'other.verb', resource: 'r' }]) for (const op of [{}, { effect: { amount: 40 } }, { effect: { amount: 90 } }, { attributions: [{ var: 'acct.email', actor: 'admin' }], self: 'agent' }, { attributions: [{ var: 'acct.email', actor: 'agent' }], self: 'agent' }])
  await run('checkFrame', (s: any, aa: any, p0: any, p1: any, x: any) => FR.checkFrame(s, aa, p0, p1, x), [spec, a, pn === 'noval' ? preNoVal : pre, ps, op]);
for (const sp of [null, {}, { state: 5 }, { state: [], writes: {} }]) await run('checkFrame', (s: any) => FR.checkFrame(s, { verb: 'v', resource: 'r' }, {}, {}), [sp]);
for (const a of [{ verb: 'acct.update', params: { field: 'email' } }, { verb: 'acct.update', params: { field: 5 } }, { verb: 'acct.update', params: { field: true } }, { verb: 'acct.update', params: { field: 'cards' } }, { verb: 'acct.update' }, { verb: 'acct.nop', params: {} }, { verb: 'shop.buy' }, { verb: 'nope' }, { verb: 'acct.update', params: { action: { params: { field: 'email' } } } }]) await run('writeSetOf', FR.writeSetOf, [spec, a]);

// ---- jit ----
const vsJ: any = O.deriveOmega({ policies: [{ predicates: [{ verb: 'stripe.refund', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }, { field: 'action.params.to', op: 'in', value: ['a', 'b'] }] }] }] }).verbs[0];
const totalJ = O.verbCellCount(vsJ);
for (let f = 0; f < totalJ; f++) {
  const cell = O.decodeCell(vsJ, f);
  await run('cellCoords', JI.cellCoords, [vsJ, cell]);
  const co = JI.cellCoords(vsJ, cell);
  await run('cellFromCoords', JI.cellFromCoords, [vsJ, co]);
}
for (const bad of [{}, { 'action.params.amount': [1, 2], 'action.params.to': ['a'] }, { 'action.params.amount': ['x', 'x'], 'action.params.to': ['a'] }, { 'action.params.amount': [1, 1], 'action.params.to': ['zzz'] }, { 'action.params.amount': [1, 1], 'action.params.to': ['a', 'b'] }, { 'action.params.amount': [1, 1], 'action.params.other': ['a'] }, { 'action.params.amount': [1, 1] }]) await run('cellFromCoords', JI.cellFromCoords, [vsJ, bad]);
const pcact: any = { action: { verb: 'stripe.refund', resource: 'r', params_digest: S('pd'), reversibility_class: 'irreversible' }, other: 1 };
for (const cell of [[0, 0], [1, 1], [0, 2]]) await run('intentRequiredBody', (i: any) => JI.intentRequiredBody(i), [{ session: S('s'), mapDigest: S('m'), schemaDigest: S('sc'), pcactn: pcact, vs: vsJ, cell, questionId: 'q1', friction: 'tap', deliveredTo: 'wallet', expiresAt: 1900000000000 }]);
refWrite(o, 'intent-misc');
