// Oracle: @atlasauth/pca-actions test-runner.ts. Writes out/ref-actions-test-runner.json.gz.
// PORTING table (core trait registry; the YAML round trip of the digest property is the identity on the value in Java: yamlLoader = null)
//   decideExample(d, ex, defs)          -> ActionTestRunner.decideExample(d, ex, CORE, defs): {got, why}
//   runDefTests(defs, propLimit|null)   -> ActionTestRunner.runDefTests(defs, CORE, propLimit, null): {examples, props, ok}
//   testText(report)                    -> ActionTestRunner.testText(report)
import * as TR0 from '../../../packages/pca-actions/src/test-runner.ts';
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import { Oracle, refWrite, clone } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const TR = un(TR0), BI = un(B0), DM = un(DM0), CT = un(CT0);
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-test-runner', 'tools/pca-audit/oracles/actions-test-runner.mts', 'TS-reference oracle for the pca-actions example and property runner.');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const find = (v: string) => ALL.find((d) => d.verb === v);

const PAY = mut(find('stripe.charge'), (d) => {
  d.verb = 'acme.pay.send';
  d.examples = [
    { params: { customer: 'cus_12345678', amount: 2500, idempotency_key: 'k_1' }, expect: 'escalate' },
    { params: { customer: 'cus_12345678', amount: 2500, idempotency_key: 'k_1' }, under: { allow: { verb: 'acme.pay.send', where: { amount: { max: 5000 } } } }, expect: 'escalate' },
    { params: { customer: 'cus_12345678', amount: 9000, idempotency_key: 'k_1' }, under: { allow: [{ trait: 'money_moving', where: { amount: { max: 5000 } } }] }, expect: 'escalate' },
    { params: { customer: 'cus_12345678', amount: 100 }, expect: 'deny' },
    { params: { customer: 'cus_12345678', amount: 0, idempotency_key: 'k_1' }, expect: 'deny' },
    { params: { customer: 'cus_12345678', amount: 100, idempotency_key: 'k_1' }, under: { allow: { verb: 'acme.pay.send', caveats: ['amount_cap', 'count_cap', 'window'], context: ['idempotency', 'fresh_revocation'] } }, expect: 'allow' },
  ];
});
const MAIL = mut(find('gmail.send'), (d) => {
  d.verb = 'acme.mail.send';
  d.examples = [
    { params: { to: 'a@example.com', subject: 's', body: 'b', idempotency_key: 'k' }, expect: 'escalate' },
    { params: { to: 'a@example.com', subject: 's', body: 'b', idempotency_key: 'k' }, under: { allow: { trait: 'external_communication', where: { 'to.domain': ['example.com'] }, caveats: ['rate_cap'] } }, expect: 'escalate' },
    { params: { to: 'a@EXAMPLE.com', subject: 's', body: 'b', idempotency_key: 'k' }, under: { allow: { verb: 'acme.mail.send', where: { 'to.domain': ['example.com'] } } }, expect: 'escalate' },
    { params: { to: 'a@evil.com', subject: 's', body: 'b', idempotency_key: 'k' }, under: { allow: { verb: 'acme.mail.send', where: { 'to.domain': ['example.com'] } } }, expect: 'escalate' },
    { params: { to: 'a@example.com', subject: 's', body: 'b', idempotency_key: 'k' }, under: { allow: { verb: 'acme.mail.send', where: { to: ['a@example.com'] } } }, expect: 'escalate' },
    { params: { to: 'a@example.com' }, expect: 'deny' },
  ];
});
const BAD_UNDER: [string, any][] = [
  ['under array', []], ['under extra key', { allow: { verb: 'x.y' }, zz: 1 }], ['selector none', { allow: {} }], ['selector both', { allow: { verb: 'x.y', trait: 'destructive' } }], ['selector unknown key', { allow: { verb: 'x.y', zz: 1 } }],
  ['where not object', { allow: { verb: 'acme.pay.send', where: [] } }], ['caveats bad', { allow: { verb: 'acme.pay.send', caveats: ['nope'] } }], ['caveats not list', { allow: { verb: 'acme.pay.send', caveats: 'amount_cap' } }],
  ['selector number', { allow: 5 }], ['where cond string', { allow: { verb: 'acme.pay.send', where: { amount: 'x' } } }], ['where unknown param', { allow: { verb: 'acme.pay.send', where: { nope: ['x'] } } }],
  ['where list on int', { allow: { verb: 'acme.pay.send', where: { amount: ['x'] } } }], ['where min', { allow: { verb: 'acme.pay.send', where: { amount: { min: 5000 } } } }], ['where max min', { allow: { verb: 'acme.pay.send', where: { amount: { min: 1, max: 5000 } } } }],
  ['other verb', { allow: { verb: 'x.y' } }], ['trait full id', { allow: { trait: 'pca.money_moving' } }], ['trait other', { allow: { trait: 'destructive' } }], ['id where', { allow: { verb: 'acme.pay.send', where: { customer: ['cus_12345678'] } } }],
  ['null under', null], ['string under', 'x'],
];
for (const [n, u] of BAD_UNDER) {
  await o.run('decideExample', n, (d: any, ex: any, defs: any) => TR.decideExample(d, ex, CORE, defs), [PAY, { params: { customer: 'cus_12345678', amount: 2500, idempotency_key: 'k_1' }, under: u, expect: 'escalate' }, [PAY]]);
}
for (const [i, ex] of PAY.examples.entries()) await o.run('decideExample', `pay ${i}`, (d: any, e: any, defs: any) => TR.decideExample(d, e, CORE, defs), [PAY, ex, [PAY, MAIL]]);
for (const [i, ex] of MAIL.examples.entries()) await o.run('decideExample', `mail ${i}`, (d: any, e: any, defs: any) => TR.decideExample(d, e, CORE, defs), [MAIL, ex, [PAY, MAIL]]);
await o.run('decideExample', 'unconformant params', (d: any, ex: any, defs: any) => TR.decideExample(d, ex, CORE, defs), [PAY, { params: { zzz: 1 }, expect: 'deny' }, [PAY]]);
await o.run('decideExample', 'delete builtin', (d: any, ex: any, defs: any) => TR.decideExample(d, ex, CORE, defs), [find('gmail.delete'), find('gmail.delete').examples[0], [find('gmail.delete')]]);

const RD = (n: string, defs: any[], limit: any = null) => o.run('runDefTests', n, (d: any, l: any) => TR.runDefTests(d, CORE, l === null ? {} : { propLimit: l }), [defs, limit]);
await RD('pay', [PAY]);
await RD('pay+mail', [PAY, MAIL]);
await RD('builtins with examples', BI.BUILTIN_DEFS.filter((d: any) => d.examples).map((d: any) => clone(d)));
await RD('builtin read', [find('github.read'), find('http.get')]);
await RD('domain', DM.DOMAIN_DEFS.slice(0, 6).map((d: any) => clone(d)));
await RD('limit 4', [PAY, MAIL], 4);
await RD('limit 1', [MAIL], 1);
await RD('traits many', [mut(MAIL, (d) => (d.traits = ['pca.external_communication', 'pca.pii_access', 'pca.regulated_data', 'pca.data_export']))], 256);
await RD('empty', []);
await RD('failing example', [mut(PAY, (d) => (d.examples = [{ params: { customer: 'cus_12345678', amount: 2500, idempotency_key: 'k_1' }, expect: 'allow' }]))]);
for (const [n, defs] of [['pay', [PAY]], ['failing', [mut(PAY, (d) => (d.examples = [{ params: { customer: 'cus_12345678', amount: 2500, idempotency_key: 'k_1' }, expect: 'allow' }]))]], ['empty', []]] as [string, any[]][]) {
  const rep = TR.runDefTests(defs, CORE);
  await o.run('testText', n, (r: any) => TR.testText(r), [rep]);
}
refWrite(o, 'actions-test-runner');
