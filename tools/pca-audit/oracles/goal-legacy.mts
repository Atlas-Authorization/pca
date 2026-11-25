// Oracle: @atlasauth/pca-goal legacy.ts (liftLegacy: the facade's {permissions, limits} lifted to a Goal and IR ontology; default catalog).
// PORTING: liftLegacy(permissions, limits|null, principal, notAfter|null, notBefore|null, nlDigest|null) ->
//   GoalLegacy.liftLegacy(permissions, limits, null /*default catalog*/, principal, notAfter, notBefore, nlDigest) = {goal, ontology}; a throw requires a throw.
import * as L0 from '../../../packages/pca-goal/src/legacy';
import { Oracle, refWrite } from './lib.mjs';
const L: any = (L0 as any).default ?? L0;
const o = new Oracle('goal-legacy', 'tools/pca-audit/oracles/goal-legacy.mts', 'TS-reference oracle for pca-goal legacy.');
let n = 0;
const lift = (permissions: any, limits: any, principal: string, notAfter: any, notBefore: any, nl: any) =>
  L.liftLegacy({ permissions, ...(limits ? { limits } : {}), principal, ...(notAfter !== null ? { notAfter } : {}), ...(notBefore !== null ? { notBefore } : {}), ...(nl !== null ? { nlDigest: nl } : {}) });
const run = (permissions: any, limits: any = null, principal = 'alice', notAfter: any = null, notBefore: any = null, nl: any = null) => o.run('liftLegacy', String(n++), lift, [permissions, limits, principal, notAfter, notBefore, nl]);

const PERMS: any[] = [
  { stripe: ['charge'] }, { stripe: ['charge', 'refund', 'payout'] }, { gmail: ['send', 'draft', 'delete'] }, { github: ['read', 'create_pr', 'merge_pr'] }, { slack: ['post_message', 'read'] },
  { calendar: ['create_event', 'delete_event'] }, { stripe: ['bill'] }, { stripe: ['refund', 'refund'] }, { foo: ['bar'] }, { foo: ['bar', 'baz'], stripe: ['charge'] }, { 'a.b': ['c'] },
  { stripe: [] }, {}, { stripe: 'charge' }, { stripe: ['charge', 5] }, { stripe: ['charge'], gmail: ['send'], github: ['read'] }, { zzz: ['a'], aaa: ['b'] }, { stripe: ['create_customer'] },
];
for (const p of PERMS) await run(p);
await run({ stripe: ['charge'] }, null, 'é', 1000, 5, 'nl');
await run({ stripe: ['charge'] }, null, '', 9007199254740991, 0, '');
const LIMITS = ['$500/day', '$500', '$0', '$0.005', '$1.005', '$1.115', '$20.50/hour', '$ 20 / h', '$20/min', '$20/week', '$20/month', '$20/sec', '$20/s', '$20/year', '$20/constructor', '$20/Day', '10', '10/hour', '0', '0/day', '5/s', '1.5', '2.0', '100000000000000000000', '$90071992547409.91', '$99999999999999999', '$0.1', '$0.29', '$4.35', '', ' ', 'abc', '$', '/day', '-5', '$-5', '5/', '$5/ day', ' $5 ', '$5\n', 'x'.repeat(65), '$' + '1'.repeat(40), 5, null, true, [], {}];
for (const lim of LIMITS) {
  await run({ stripe: ['charge'] }, { 'stripe.charge': lim });
  await run({ gmail: ['send'] }, { 'gmail.send': lim });
}
await run({ stripe: ['charge', 'refund'], gmail: ['send'] }, { 'stripe.charge': '$500/day', refund: '$20', send: '10/hour' });
await run({ stripe: ['charge', 'refund'], gmail: ['send'] }, { charge: '$1', 'stripe.refund': '$2', 'gmail.send': '3' });
await run({ stripe: ['charge'] }, { 'stripe.charge': null, charge: '$5/day' });
await run({ stripe: ['charge'] }, { 'stripe.charge': '$5/day', charge: null });
await run({ stripe: ['charge'] }, { charge: null });
await run({ stripe: ['charge'] }, { 'stripe.charge': null });
await run({ stripe: ['charge'] }, { bill: '$7' });
await run({ stripe: ['charge'] }, { unrelated: '$7' });
await run({ stripe: ['bill'] }, { 'stripe.charge': '$7/day' });
await run({ foo: ['bar'] }, { 'foo.bar': '$3' });
await run({ foo: ['bar'] }, { 'foo.bar': '3/day', bar: '$3' });
await run({ stripe: ['charge'], gmail: ['send'] }, { 'stripe.charge': '$5', 'gmail.send': '$5' });
refWrite(o, 'goal-legacy');
