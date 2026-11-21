// Oracle: forecast() of packages/pca/src/budget-forecast.ts (recommendPolicy and autonomyBoundOf are already in ref-core-sweep-java; this adds forecast
// and replays the two with a few more edges so the module has one corpus). Writes out/ref-budget-forecast.json.gz. No keys, no clock.
// PORTING (results compared by JSON value; a reference throw = the native throws)
//   forecast [spec, plan, start|null, catalogActions|null] -> {steps:[{verb,resource,outcome,r,budgetAfter}], firstStepUpAt?, autonomousRisk, forcesCosign, cosignsNeeded, endBudget}
//     spec = {permissions, limits?, budgetModel?, riskPolicy?, now}: compiled with the facade's compilePolicy (same fixtures as the policy-sim cases of ref-core-research-java);
//     start null = option absent; catalogActions null = the default catalog, else an array of defineAction specs forming buildCatalog(actions) (verbs unknown to it fail closed).
//     plan = [{verb, resource, params?, at?}]
//   recommendPolicy [targetActions, perActionRisk, kappa|null]   -> {kappa, bMax, autonomousBound, rationale}
//   autonomyBoundOf [{bMax, kappa}]                              -> number
import { Oracle, refWrite, rng } from './lib.mjs';
import { adder, nul } from './foundation.mjs';
const { compilePolicy }: any = await import('../../../packages/pca/src/facade.ts');
const BF: any = await import('../../../packages/pca/src/budget-forecast.ts');
const CAT: any = await import('../../../packages/pca/src/catalog.ts');
const o = new Oracle('budget-forecast', 'tools/pca-audit/oracles/budget-forecast.mts', 'TS-reference oracle for packages/pca/src/budget-forecast.ts.');
const REF: Record<string, (...a: any[]) => any> = {
  forecast: (sp, plan, start, ca) => BF.forecast(compilePolicy(sp), plan, { ...(start === null ? {} : { start }), ...(ca === null ? {} : { catalog: CAT.buildCatalog(ca.map((a: any) => CAT.defineAction(a))) }) }),
  recommendPolicy: (n, r, k) => BF.recommendPolicy(n, r, k === null ? {} : { kappa: k }),
  autonomyBoundOf: (p) => BF.autonomyBoundOf(p),
};
const add = adder(o, REF);
const T0 = 1_800_000_000_000;
const specs: any[] = [
  { permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 },
  { permissions: { stripe: ['payout', 'refund', 'charge'], gmail: ['send', 'draft'], github: ['read', 'merge_pr'] }, limits: { payout: '$100/day', refund: '$50/h', send: '5/hour' }, riskPolicy: { theta1: 0.2, theta2: 0.5 }, now: 1000 },
  { permissions: { github: ['read', 'merge_pr', 'delete_repo'], gmail: ['draft'] }, budgetModel: 'risk', riskPolicy: { theta1: 0.1, theta2: 0.4 }, now: 5 },
  { permissions: { stripe: ['refund'], zz: ['thing'] }, limits: { refund: '$10', thing: '1/d' }, now: 0 },
  { permissions: { github: ['read'] }, riskPolicy: { lambda: 0.5, bMax: 3 }, budgetModel: 'risk', now: 0 },
  { permissions: {}, now: 0 },
];
const sact = (verb: string, resource: string, params?: any, at?: any) => ({ verb, resource, ...(params !== undefined ? { params } : {}), ...(at !== undefined ? { at } : {}) });
function gen(seedN: number, n: number): any[] {
  const g = rng(seedN); const verbs = ['stripe.payout', 'stripe.refund', 'stripe.charge', 'gmail.send', 'gmail.draft', 'github.read', 'github.merge_pr', 'github.delete_repo', 'zz.thing', 'nope.x'];
  let at = T0; const out: any[] = [];
  for (let i = 0; i < n; i++) { at += g.int(0, 3) * 20_000; out.push(sact(g.pick(verbs), g.pick(['acct:1', 'org/repo', '']), g.next() < 0.7 ? { amount: g.pick([1, 10, 25, 50, 99, 100, 250, 99999, 0, -3, '30', null]) } : undefined, g.next() < 0.1 ? undefined : at)); }
  return out;
}
const plans: any[] = [[], gen(21, 6), gen(22, 20), gen(23, 40), [sact('github.read', 'a')], [sact('stripe.payout', 'a', { amount: 10 }, 'x'), sact('stripe.payout', 'a', { amount: 10 }, null)]];
for (const [si, s] of specs.entries()) for (const [pi, p] of plans.entries()) for (const st of [null, 0, 0.5, T0]) await add('forecast', `s${si}-p${pi}-${st}`, [s, p, st, null]);
const CUSTOM = [{ connector: 'zz', action: 'thing', reversibility: 'irreversible', blastRadius: 0.95, description: 'x' }, { connector: 'github', action: 'read', reversibility: 'reversible', blastRadius: 0.01, description: 'x' }];
for (const [si, s] of specs.slice(0, 5).entries()) await add('forecast', `custom-cat-${si}`, [s, plans[2], null, CUSTOM]);
await add('forecast', 'empty-cat', [specs[1], plans[1], null, []]);
for (const n of [0, 1, 10, 100, 12.5, -5, 1e6, 0.001, 3e20, { $num: 'NaN' }, { $num: 'Infinity' }, '3', null]) for (const r of [0, 1e-9, 1e-6, 0.25, 0.333, 0.5, 1, 2, -1, { $num: 'NaN' }, { $num: 'Infinity' }, { $num: '-Infinity' }]) await add('recommendPolicy', `n${JSON.stringify(n)}/r${JSON.stringify(r)}`, [n, r, null]);
for (const k of [0.5, 2, 3.7, 0, -1, 1e-9, 100, { $num: 'NaN' }, { $num: 'Infinity' }, '2']) await add('recommendPolicy', `kappa${JSON.stringify(k)}`, [10, 0.1, k]);
for (const p of [{ bMax: 10, kappa: 2 }, { bMax: 0, kappa: 1 }, { bMax: -4, kappa: 2 }, { bMax: 10, kappa: 0 }, { bMax: 10, kappa: -1 }, { bMax: 7, kappa: 3 }, { bMax: 1e9, kappa: 1e-3 }, { bMax: 5, kappa: 'x' }, { bMax: 5 }, { bMax: { $num: 'NaN' }, kappa: 1 }]) await add('autonomyBoundOf', JSON.stringify(p), [p]);
refWrite(o, 'budget-forecast');
