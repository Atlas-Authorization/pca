// Oracle (extra, Java lane): @atlasauth/pca-ap2 verifyPcaBinding (the PCA side of an AP2 payment chain: grant, terms, constraints,
// the closed mandate's PCActn through the core verifier, the risk and threshold rule, the policy decision on the server-held mandate).
// The open token is a fixed, unsigned-looking SD-JWT hop (verifyPcaBinding only reads its hash, taken as `openHash`); the agent P-256
// key is derived from a label. Everything is deterministic (Ed25519 PCActns, fixed clock).
//
// PORTING: verifyPcaBinding(input) -> Ap2.verifyPcaBinding(VerifyPcaBindingInput); the result {ok:false, reason} | {ok:true, pcactn, grant, terms}
// is compared by JSON value; a missing mandate or missing charge history is a throw ({"$throws", code}).
// input = {open, closed, openHash, expectedPrincipal, pqPins?, audience, now?, mandate, recentChargeTimes?, hooks?, enforce?}; hooks are
// constant descriptors {threshold?: H, ...}, H = {enforced: false} | {enforced: true, ok, reason?, t?}; enforce = {freshness: {maxAgeMs, ...}}.
// Writes out/ref-ap2-java-extra.json.gz.
import { createECDH, createHash } from 'node:crypto';
import * as M0 from '@atlasauth/pca-ap2';
import * as C0 from '@atlasauth/pca';
import * as P0 from '@atlasauth/pca-payments';
import { Oracle, refWrite, seed } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const C: any = (C0 as any).default ?? C0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('ap2-java-extra', 'tools/pca-audit/oracles/ap2-java-extra.mts', 'TS-reference oracle for ap2 verifyPcaBinding (Java lane).');
const T0 = 1_800_000_000_000;
const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const J = (x: any) => JSON.parse(JSON.stringify(x));
const pk = (x: Uint8Array) => C.encodeKey(C.publicKeyOf(x));
const principal = seed('ap2x-principal'), agentSeed = seed('ap2x-agent');
const ecdh = createECDH('prime256v1');
ecdh.setPrivateKey(createHash('sha256').update('atlas-pca-conformance/ap2x/agent-p256').digest());
const pub = ecdh.getPublicKey();
const AGENT_JWK = { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
const MERCH = { id: 'merchant_1', name: 'Demo Merchant', website: 'https://demo-merchant.example' };
const token = (payload: any) => `${b64u(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' })))}.${b64u(Buffer.from(JSON.stringify(payload)))}.${b64u(Buffer.alloc(64, 7))}~`;
const OPEN = token({ iss: 'issuer', vct: 'mandate.payment.open.1', iat: 1 });
const OPEN2 = token({ iss: 'issuer', vct: 'mandate.payment.open.1', iat: 2 });
const openHash = M.sdHashOf(M.parseSdJwtHop(OPEN));
const mandateFor = (over: any = {}) => J(P.buildPaymentMandate({
  principalSecret: principal, principalPublic: pk(principal), agentPublic: pk(agentSeed), merchants: ['merchant_1'], categories: [], currency: 'USD', perTransactionCap: 50000,
  autoApproveThreshold: 5000, cumulativeCap: 100000, periodMs: 7_200_000, periodStart: T0, maxTransactionsPerPeriod: 5, goalSalt: 'c2FsdC0wMDAx', now: T0, ...over,
}));
const MAN: Record<string, any> = { base: mandateFor(), cats: mandateFor({ categories: ['5734'] }), noMax: mandateFor({ maxTransactionsPerPeriod: undefined }), small: mandateFor({ perTransactionCap: 5000, cumulativeCap: 5000, autoApproveThreshold: 100 }) };
MAN.drained = { ...MAN.base, budget: { ...MAN.base.budget, B: 0 } };
MAN.other = mandateFor({ merchants: ['merchant_2'] });
const openClaims = (m: any, over: any = {}) => J({ x_pca: M.pcaOpenClaim(m), cnf: { jwk: AGENT_JWK }, constraints: M.paymentConstraintsFromTerms(m.terms, [MERCH], 'ref'), exp: Math.floor(T0 / 1000) + 3600, ...over });
const bind = (m: any, a: any = {}) => M.buildPcaPaymentBinding({
  mandate: m, open: OPEN, agentJwk: AGENT_JWK, agentSecret: agentSeed, audience: 'atlas-instance', counter: 1, transactionId: 'tx_1', payee: MERCH,
  amount: { amount: 4000, currency: 'USD' }, instrumentId: 'spt_1', now: T0, ...a,
});
const closedClaims = (m: any, a: any = {}, over: any = {}) => J({
  transaction_id: 'tx_1', payee: MERCH, payment_amount: a.amount ?? { amount: 4000, currency: 'USD' }, payment_instrument: { id: 'spt_1', type: 'card' }, x_pca: bind(m, a), ...over,
});
const H_OK = { enforced: true, ok: true }, H_T = (t: number) => ({ enforced: true, ok: true, t }), H_BAD = { enforced: true, ok: false, reason: 'nope' };
const hooksOf = (h: any) => h === undefined ? undefined : Object.fromEntries(Object.entries(h).map(([k, v]) => [k, async () => v]));
const verify = async (i: any) => M.verifyPcaBinding({ ...i, hooks: hooksOf(i.hooks) });
const mk = (over: any = {}, mandKey = 'base', a: any = {}) => {
  const m = MAN[mandKey];
  return { open: openClaims(m), closed: closedClaims(m, a), openHash, expectedPrincipal: pk(principal), audience: 'atlas-instance', now: T0 + 1000, mandate: m, recentChargeTimes: [], ...over };
};
let n = 0;
const add = (name: string, i: any) => o.run('verifyPcaBinding', `${name}#${n++}`, verify, [i]);
const A = (amount: number, currency = 'USD') => ({ amount: { amount, currency } });

await add('basic', mk());
for (const amt of [1, 100, 4000, 5000, 5001, 20000, 30000, 50000, 50001]) {
  await add(`amt${amt}/nohook`, mk({}, 'base', A(amt)));
  for (const [hn, h] of [['t1', { threshold: H_T(1) }], ['t2', { threshold: H_T(2) }], ['t3', { threshold: H_T(3) }], ['ok', { threshold: H_OK }], ['bad', { threshold: H_BAD }]] as any[])
    await add(`amt${amt}/${hn}`, mk({ hooks: h }, 'base', A(amt)));
}
for (const mk2 of Object.keys(MAN)) for (const amt of [4000, 60000]) await add(`mandate/${mk2}/${amt}`, mk({ mandate: MAN[mk2] }, 'base', A(amt)));
await add('cats ok', mk({}, 'cats', { category: '5734' }));
await add('cats missing', mk({}, 'cats'));
await add('cats wrong', mk({}, 'cats', { category: 'x' }));
await add('now late', mk({ now: T0 + 3 * 3_600_000 }));
await add('now early', mk({ now: T0 - 120_000 }));
await add('no now', mk({ now: undefined }));
await add('aud other', mk({ audience: 'other' }));
await add('principal other', mk({ expectedPrincipal: pk(seed('ap2x-other')) }));
await add('pins', mk({ pqPins: {} }));
await add('pins mismatch', mk({ pqPins: { [pk(principal)]: 'AAAA' } }));
await add('openHash other', mk({ openHash: M.sdHashOf(M.parseSdJwtHop(OPEN2)) }));
await add('openHash bad', mk({ openHash: 'x' }));
for (const rc of [undefined, [], [T0], [T0, T0, T0, T0, T0], [T0, 'x'], 'x', null]) await add(`history/${JSON.stringify(rc)}`, mk({ recentChargeTimes: rc }));
await add('history noMax', mk({ recentChargeTimes: undefined }, 'noMax'));
await add('mandate missing', mk({ mandate: undefined }));
await add('mandate null', mk({ mandate: null }));
await add('mandate other grant', mk({ mandate: MAN.other }));
await add('enforce freshness', mk({ enforce: { freshness: { maxAgeMs: 1000 } } }));
// open / closed mutations
const mutOpen: [string, (x: any) => void][] = [
  ['no x_pca', (x) => { delete x.x_pca; }], ['x_pca v2', (x) => { x.x_pca.v = 2; }], ['no grant', (x) => { delete x.x_pca.grant; }], ['no terms', (x) => { delete x.x_pca.terms; }],
  ['terms cap', (x) => { x.x_pca.terms.perTransactionCap = 99999; }], ['terms merchants', (x) => { x.x_pca.terms.merchants = ['merchant_1', 'evil']; }], ['terms currency', (x) => { x.x_pca.terms.currency = 'EUR'; }],
  ['grant sig', (x) => { x.x_pca.grant.sig = 'AAAA'; }], ['grant issuer', (x) => { x.x_pca.grant.issuer = pk(seed('ap2x-other')); }], ['no constraints', (x) => { x.constraints = []; }],
  ['range max', (x) => { x.constraints[0].max = 99999; }], ['range cur', (x) => { x.constraints[0].currency = 'EUR'; }], ['payees extra', (x) => { x.constraints[1].allowed.push({ id: 'evil' }); }],
  ['no payees', (x) => { x.constraints = x.constraints.filter((c: any) => c.type !== 'payment.allowed_payees'); }], ['budget big', (x) => { x.constraints[3].max = 99999; }],
  ['no budget', (x) => { x.constraints = x.constraints.filter((c: any) => c.type !== 'payment.budget'); }], ['recurrence', (x) => { x.constraints[4].max_occurrences = 99; }],
  ['no recurrence', (x) => { x.constraints = x.constraints.filter((c: any) => c.type !== 'payment.agent_recurrence'); }], ['exp far', (x) => { x.exp = 99999999999; }], ['no exp', (x) => { delete x.exp; }],
  ['other agent key', (x) => { x.cnf.jwk = { ...x.cnf.jwk, x: x.cnf.jwk.y }; }], ['no cnf', (x) => { delete x.cnf; }],
];
for (const [name, f] of mutOpen) { const i = mk(); f(i.open); await add(`open/${name}`, i); }
const mutClosed: [string, (x: any) => void][] = [
  ['no x_pca', (x) => { delete x.x_pca; }], ['x_pca v2', (x) => { x.x_pca.v = 2; }], ['charge amount', (x) => { x.x_pca.charge.amount = 3999; }], ['charge currency', (x) => { x.x_pca.charge.currency = 'EUR'; }],
  ['pay amount', (x) => { x.payment_amount.amount = 4001; }], ['payee', (x) => { x.payee = { id: 'merchant_2' }; }], ['instrument', (x) => { x.payment_instrument.id = 'other'; }], ['tx', (x) => { x.transaction_id = 'tx_2'; }],
  ['pcactn sig', (x) => { x.x_pca.pcactn.sig = 'AAAA'; }], ['pcactn nonce', (x) => { x.x_pca.pcactn.nonce = 'n'; }], ['pcactn verb', (x) => { x.x_pca.pcactn.action.verb = 'refund'; }],
  ['pcactn params', (x) => { x.x_pca.pcactn.action.params_digest = 'AAAA'; }], ['risk low', (x) => { x.x_pca.pcactn.risk_claim.r = 0; }], ['risk str', (x) => { x.x_pca.pcactn.risk_claim.r = 'x'; }],
  ['no risk', (x) => { delete x.x_pca.pcactn.risk_claim; }], ['no pcactn', (x) => { delete x.x_pca.pcactn; }], ['category', (x) => { x.x_pca.charge.category = 'zz'; }],
];
for (const [name, f] of mutClosed) { const i = mk(); f(i.closed); await add(`closed/${name}`, i); }
console.log('cases', o.cases.length);
refWrite(o, 'ap2-java-extra');
