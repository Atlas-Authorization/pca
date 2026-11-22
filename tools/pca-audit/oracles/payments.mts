// Oracle: @atlasauth/pca-payments (mandate, charge decision, charge action, spend rails, Shared Payment Token limits, Stripe Issuing
// adapter, agent network tokens). Deterministic: keys derive from seeds, fixed clocks (T0), fixed goal salt. Bytes travel as {"$bytes": b64url}.
// The policy decision (`decide`) is the core PCA engine: authorizeCharge cases carry the reference's recorded decision as the LAST argument,
// which a native feeds back through its decider, so the native assembly (decide input, refusals, exact money arithmetic, budget threading)
// is compared case by case; chargeDecideInput compares the decide input itself.
// PORTING (fn(args) -> native entry point, comparison rule; everything compared by JSON value):
//   isPlainId(x)                                   -> isPlainId
//   mandatePredicates(terms) / mandateCaveats(terms) / mandateRiskPolicy(terms, replenish) -> same names
//   autoSpendBound({policy})                       -> autoSpendBound (number)
//   buildPaymentMandate(params)                    -> buildPaymentMandate (params.principalSecret = 32-byte Ed25519 seed)
//   chargeActionContext / chargeParams(mandate, charge); chargePlanNode(mandate, charge, id)
//   chargeToPCActn(mandate, charge, opts)          -> chargeToPCActn (opts.signerSecret = Ed25519 seed; Ed25519 signatures are deterministic)
//   isMinorUnits(x)
//   chargeDecideInput(mandate, charge, now, grant) -> chargeDecideInput
//   authorizeCharge(mandate, charge, grant, rec)   -> authorizeCharge with the decider returning `rec` (the reference decide() result); a native
//                                                    that refuses before deciding (MandateGrantError) must throw
//   settleCharge(mandate, decision); applyHumanCosign(mandate, now, opts) -> applyHumanCosign(mandate, now, opts.full === true)
//   sharedPaymentTokenLimits(mandate, now); railLimits(mandate, now, opts); categoriesFromTraits(traits); reconcileSettlement(approved, s)
//   verifyStripeSignature(rawBody, header, secret, nowSec, tolerance|null: null = the default tolerance); signStripePayload(rawBody, secret, tSec); stripeCardParams(limits, names, cardholder, metadata?)
//   stripeAuthorizationFromEvent(event); stripeSettlementFromTransaction(txn)
//   stripeIssuingWebhook(rawBody, signature, secret, nowSec, approved)  the authorize callback returns {approved}; result {status, headers, body}
//   looksLikePan(s); tokenRefError(ref); bindingMessage(binding) (bytes); bindNetworkToken(opts); verifyNetworkTokenBinding(b, expect)
//   controlsFromLimits(limits, grant); settlementMetadata(binding, digest); reconcileNetworkSettlement(expected, record)
//   chargeWithNetworkToken(binding, mandate, charge, opts)
// Not generated (async / time based; covered by native unit tests): authorizeChargeAtomic, applyHumanCosignAtomic, createRailAuthorizer, the partner adapters.
import * as C0 from '@atlasauth/pca';
import * as P0 from '@atlasauth/pca-payments';
import * as S0 from '../../../packages/pca-payments/src/rails-stripe';
import { Oracle, refWrite, seed, variants } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const P: any = (P0 as any).default ?? P0;
const S: any = (S0 as any).default ?? S0;
const { publicKeyOf, encodeKey, decide, hashCanonical } = C;
const o = new Oracle('payments', 'tools/pca-audit/oracles/payments.mts', 'TS-reference oracle for @atlasauth/pca-payments.');
const T0 = 1_800_000_000_000;
const sk = { principal: seed('pay-principal'), agent: seed('pay-agent'), other: seed('pay-other') };
const pk = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const b64 = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const unb = (x: any): any => {
  if (Array.isArray(x)) return x.map(unb);
  if (x !== null && typeof x === 'object') {
    const k = Object.keys(x);
    if (k.length === 1 && k[0] === '$bytes') return new Uint8Array(Buffer.from(x.$bytes, 'base64url'));
    return Object.fromEntries(k.map((key) => [key, unb(x[key])]));
  }
  return x;
};
const J = (x: any) => JSON.parse(JSON.stringify(x));
const lite = (m: any) => ({ terms: m.terms, policy: m.policy, budget: m.budget });
let n = 0;
const run = (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, `${name}#${n++}`, (...a: any[]) => ref(...unb(a)), args);

// ---- mandate params ---------------------------------------------------------------------------------------------------------
const base: any = {
  principalSecret: b64(sk.principal), principalPublic: pk(sk.principal), agentPublic: pk(sk.agent), merchants: ['openai', 'aws'], categories: ['5734', '5817'],
  currency: 'USD', perTransactionCap: 500, autoApproveThreshold: 200, cumulativeCap: 1000, periodMs: 30 * 86_400_000, periodStart: T0, maxTransactionsPerPeriod: 5,
  replenishPerCosign: 400, goal: 'buy compute', goalSalt: 'c2FsdC0wMDAx', now: T0,
};
const paramSets: Record<string, any> = {
  base,
  minimal: { principalSecret: base.principalSecret, principalPublic: base.principalPublic, agentPublic: base.agentPublic, merchants: ['m1'], currency: 'EUR', perTransactionCap: 100, autoApproveThreshold: 0, cumulativeCap: 100, goalSalt: 'c2FsdC0wMDAy', now: T0 },
  defaultGoal: { ...base, goal: undefined },
  noPeriodStart: { ...base, periodStart: undefined },
  fractionalLegacy: { ...base, strictMinorUnits: false, perTransactionCap: 100, autoApproveThreshold: 25, cumulativeCap: 250.5, replenishPerCosign: 33.5 },
  fractionalLegacyBad: { ...base, strictMinorUnits: false, perTransactionCap: 99.5, autoApproveThreshold: 10.25, cumulativeCap: 250.75, replenishPerCosign: 33.5 },
  fractionalStrict: { ...base, perTransactionCap: 99.5 },
  yEqX: { ...base, autoApproveThreshold: 500 },
  capEqX: { ...base, cumulativeCap: 500 },
  yGtX: { ...base, autoApproveThreshold: 501 },
  capLtX: { ...base, cumulativeCap: 499 },
  starMerchant: { ...base, merchants: ['open*'] },
  ctlMerchant: { ...base, merchants: ['a\u0007b'] },
  delMerchant: { ...base, merchants: ['a\u007fb'] },
  emptyMerchants: { ...base, merchants: [] },
  emptyCats: { ...base, categories: [] },
  unicodeMerchant: { ...base, merchants: ['café', '😀'] },
  zeroRep: { ...base, replenishPerCosign: 0 },
  nullRep: { ...base, replenishPerCosign: null },
  nullCats: { ...base, categories: null },
  noMaxTx: { ...base, maxTransactionsPerPeriod: undefined },
  bigPeriod: { ...base, periodMs: 1 },
  roundHalf: { ...base, periodMs: 1500, maxTransactionsPerPeriod: 2 },
  roundHalf2: { ...base, periodMs: 2500, maxTransactionsPerPeriod: 2 },
};
for (const [k, v] of Object.entries(paramSets)) await run('buildPaymentMandate', `set/${k}`, P.buildPaymentMandate as any, [v]);
const skipVar = (name: string) => /^\/(principalSecret|principalPublic|agentPublic|goalSalt|now)/.test(name);
for (const [name, v] of variants(base, { depth: 3, maxPaths: 14 })) {
  if (skipVar(name)) continue;
  await run('buildPaymentMandate', `var/${name}`, P.buildPaymentMandate as any, [v]);
}

// ---- mandates under test -----------------------------------------------------------------------------------------------------
const mand: Record<string, any> = {};
for (const k of ['base', 'minimal', 'defaultGoal', 'fractionalLegacy', 'capEqX', 'yEqX', 'emptyCats']) mand[k] = J(P.buildPaymentMandate(unb(paramSets[k])));
const otherGrant = J(P.buildPaymentMandate(unb({ ...base, merchants: ['zzz'] }))).grant;

for (const [k, m] of Object.entries(mand)) {
  const t = m.terms;
  await run('mandatePredicates', `terms/${k}`, P.mandatePredicates as any, [t]);
  await run('mandateCaveats', `terms/${k}`, P.mandateCaveats as any, [t]);
  await run('mandateRiskPolicy', `terms/${k}`, P.mandateRiskPolicy as any, [t, 123]);
  await run('autoSpendBound', `m/${k}`, P.autoSpendBound as any, [lite(m)]);
}
for (const [name, v] of variants(mand.base.terms, { depth: 3, maxPaths: 9 })) {
  await run('mandatePredicates', `var/${name}`, P.mandatePredicates as any, [v]);
  await run('mandateCaveats', `var/${name}`, P.mandateCaveats as any, [v]);
  await run('mandateRiskPolicy', `var/${name}`, P.mandateRiskPolicy as any, [v, 400]);
}
for (const rep of [0, 1, 1000, 0.5, null]) await run('mandateRiskPolicy', `rep/${String(rep)}`, P.mandateRiskPolicy as any, [mand.base.terms, rep]);
for (const pol of [{ kappa: 500, bMax: 1000 }, { kappa: 0, bMax: 1000 }, { kappa: -1, bMax: 10 }, { kappa: 3, bMax: -5 }, { kappa: 7, bMax: 100 }, { kappa: 0.3, bMax: 0.9 }, { kappa: 1, bMax: 1e15 }]) await run('autoSpendBound', `p/${JSON.stringify(pol)}`, P.autoSpendBound as any, [{ policy: pol }]);
for (const x of [0, 1, 5, 2 ** 53 - 1, 2 ** 53, -0, -1, 1.5, '1', null, true, [], {}, 1e21]) await run('isMinorUnits', `x/${JSON.stringify(x)}${Object.is(x, -0) ? 'neg0' : ''}`, P.isMinorUnits as any, [x]);
for (const x of ['a', '', 'a*', '*', 'a\u0000', 'a\u001f', 'a ', 'a\u007f', 'é', 5, null, ['a'], {}]) await run('isPlainId', `x/${JSON.stringify(x)}`, P.isPlainId as any, [x]);

// ---- charges --------------------------------------------------------------------------------------------------------------------
const ch = (over: any = {}): any => ({ merchant: 'openai', amount: 50, category: '5734', currency: 'USD', now: T0 + 1000, recentChargeTimes: [], ...over });
const amounts: any[] = [0, 1, 50, 199, 200, 201, 300, 499, 500, 501, 1000, 1001, -1, 1.5, 0.1, 2 ** 53, 2 ** 53 - 1, '50', null, true, [], -0, 1e21, undefined];
const charges: any[] = [ch(), ...amounts.map((a) => ch({ amount: a })),
  ch({ merchant: 'aws' }), ch({ merchant: 'nope' }), ch({ merchant: '' }), ch({ merchant: '*' }), ch({ merchant: 'open*' }), ch({ merchant: 5 }), ch({ merchant: null }), ch({ merchant: undefined }),
  ch({ category: '5817' }), ch({ category: 'x' }), ch({ category: undefined }), ch({ category: null }), ch({ category: 5 }), ch({ currency: 'EUR' }), ch({ currency: 'usd' }), ch({ currency: undefined }), ch({ currency: null }), ch({ currency: 5 }),
  ch({ now: T0 + 31 * 86_400_000 }), ch({ now: T0 - 1 }), ch({ now: T0 }), ch({ now: T0 + 30 * 86_400_000 }), ch({ now: T0 + 30 * 86_400_000 - 1 }),
  ch({ recentChargeTimes: [] }), ch({ recentChargeTimes: [T0, T0, T0, T0, T0] }), ch({ recentChargeTimes: [T0, T0, T0, T0] }), ch({ recentChargeTimes: [T0 - 40 * 86_400_000] }), ch({ recentChargeTimes: 'x' }),
  ch({ amount: 200, currency: 'EUR' }), ch({ amount: 300, category: 'x' }),
];
const varCharges: any[] = [];
for (const [name, v] of variants(ch(), { depth: 1, maxPaths: 12 })) if (v !== null && typeof v === 'object' && !Array.isArray(v)) varCharges.push(v);
const recDecision = (m: any, c: any, g: any) => {
  try {
    return J(decide(P.chargeDecideInput(unb(J(m ?? null)), unb(J(c)), c.now ?? T0 + 1000, unb(J(g ?? null)))));
  } catch { return null; }
};
for (const [i, c] of varCharges.entries()) {
  await run('chargeActionContext', `var/${i}`, P.chargeActionContext as any, [lite(mand.base), J(c)]);
  await run('chargeParams', `var/${i}`, P.chargeParams as any, [lite(mand.base), J(c)]);
}
for (const [mk, m] of Object.entries(mand)) {
  for (const [i, c] of charges.entries()) {
    const cc = J(c);
    if (mk !== 'base' && i > 5) continue;
    await run('chargeActionContext', `${mk}/${i}`, P.chargeActionContext as any, [lite(m), cc]);
    if (mk === 'base') await run('chargeParams', `${mk}/${i}`, P.chargeParams as any, [lite(m), cc]);
    if (mk === 'base' && i < 12) await run('chargePlanNode', `${mk}/${i}`, P.chargePlanNode as any, [lite(m), cc, `n${i}`]);
    await run('chargeDecideInput', `${mk}/${i}`, P.chargeDecideInput as any, [m, cc, cc.now ?? T0 + 1000, m.grant]);
    if (!Number.isFinite(cc.now)) continue;
    const rec = recDecision(m, cc, m.grant);
    await run('authorizeCharge', `${mk}/${i}`, ((mm: any, c2: any, g: any, _r: any) => P.authorizeCharge(mm, c2, g)) as any, [m, cc, m.grant, rec]);
  }
}
// budget states, grants and tampering
const m0 = mand.base;
const budgets: any[] = [{ B: 1000, tau: T0, asOf: T0 }, { B: 40, tau: T0, asOf: T0 }, { B: 50, tau: T0, asOf: T0 }, { B: 0, tau: T0, asOf: T0 }, { B: 5000, tau: T0, asOf: T0 }, { B: -5, tau: T0, asOf: T0 },
  { B: 49.5, tau: T0, asOf: T0 }, { B: 100.5, tau: T0, asOf: T0 }, { B: '1000', tau: T0 }, { B: null }, {}, null, 'x', { B: 1000 }, { B: 1000, tau: T0 - 3_600_000 }, { B: 1000, tau: T0, asOf: T0 - 100_000 }];
for (const [i, b] of budgets.entries()) for (const [j, a] of [1, 50, 300, 999].entries()) {
  const m = { ...m0, budget: b };
  const c = ch({ amount: a });
  await run('authorizeCharge', `budget/${i}/${j}`, ((mm: any, c2: any, g: any, _r: any) => P.authorizeCharge(mm, c2, g)) as any, [m, c, m.grant, recDecision(m, c, m.grant)]);
  if (j === 1 && i % 2 === 0) await run('chargeDecideInput', `budget/${i}/${j}`, P.chargeDecideInput as any, [m, c, T0 + 1000, m.grant]);
}
const tampered: Record<string, any> = {
  nullGrant: [m0, ch(), null], undefGrant: [m0, ch(), undefined], stringGrant: [m0, ch(), 'g'], otherGrant: [m0, ch(), otherGrant],
  grantNoCaveats: [{ ...m0, grant: { ...m0.grant, caveats: [] } }, ch(), { ...m0.grant, caveats: [] }],
  noGrantInMandate: [{ ...m0, grant: undefined }, ch(), m0.grant], noTerms: [{ ...m0, terms: undefined }, ch(), m0.grant], noPolicy: [{ ...m0, policy: undefined }, ch(), m0.grant],
  nullTerms: [{ ...m0, terms: null }, ch(), m0.grant], zeroTerms: [{ ...m0, terms: 0 }, ch(), m0.grant],
  capTerms: [{ ...m0, terms: { ...m0.terms, perTransactionCap: 9999 } }, ch(), m0.grant], merchTerms: [{ ...m0, terms: { ...m0.terms, merchants: ['openai', 'aws', 'evil'] } }, ch(), m0.grant],
  catTerms: [{ ...m0, terms: { ...m0.terms, categories: [] } }, ch(), m0.grant], periodTerms: [{ ...m0, terms: { ...m0.terms, periodEnd: T0 * 2 } }, ch(), m0.grant],
  policyBmax: [{ ...m0, policy: { ...m0.policy, bMax: 1e9 } }, ch(), m0.grant], policyTheta: [{ ...m0, policy: { ...m0.policy, theta1: 1, theta2: 1 } }, ch(), m0.grant],
  mandateNull: [null, ch(), m0.grant], mandateStr: ['x', ch(), m0.grant], mandateNoBudget: [{ ...m0, budget: undefined }, ch(), m0.grant],
};
for (const [k, [m, c, g]] of Object.entries(tampered)) {
  await run('authorizeCharge', `tamper/${k}`, ((mm: any, c2: any, gg: any, _r: any) => P.authorizeCharge(mm, c2, gg)) as any, [m, c, g, recDecision(m, c, g)]);
  await run('chargeDecideInput', `tamper/${k}`, P.chargeDecideInput as any, [m, c, T0 + 1000, g]);
}
// chargeToPCActn / chargeWithNetworkToken
const act = (over: any = {}) => ({ signerSecret: b64(sk.agent), aud: 'inst_1', counter: 3, now: T0 + 500, ...over });
const actOpts: any[] = [act(), act({ nodeId: 'custom' }), act({ counter: 0 }), act({ aud: '' }), act({ aud: undefined }), act({ now: undefined, iat: undefined }), act({ chain: undefined })];
for (const [i, op] of actOpts.entries()) {
  if (op.now === undefined) continue;
  for (const [j, c] of [ch(), ch({ amount: 0 }), ch({ amount: 1.5 }), ch({ amount: -1 }), ch({ amount: 500 }), ch({ category: undefined }), ch({ merchant: 'aws', amount: 7 })].entries())
    await run('chargeToPCActn', `${i}/${j}`, P.chargeToPCActn as any, [m0, c, op]);
}
await run('chargeToPCActn', 'minimal', P.chargeToPCActn as any, [mand.minimal, { merchant: 'm1', amount: 100, currency: 'EUR' }, act()]);

// settle / cosign
const dec = (m: any, c: any) => J(P.authorizeCharge(unb(m), unb(c), unb(m.grant)));
for (const [i, a] of [50, 300, 501].entries()) await run('settleCharge', `d/${i}`, P.settleCharge as any, [lite(m0), dec(m0, ch({ amount: a }))]);
for (const [i, b] of budgets.entries()) for (const [j, op] of [undefined, {}, { full: true }, { full: false }, { full: 'yes' }].entries()) for (const now of [T0, T0 + 5])
  await run('applyHumanCosign', `${i}/${j}/${now}`, ((m: any, nw: any, o2: any) => P.applyHumanCosign(m, nw, o2)) as any, [{ ...lite(m0), budget: b }, now, op]);
await run('applyHumanCosign', 'low-policy', P.applyHumanCosign as any, [{ ...lite(m0), policy: { ...m0.policy, rho: 50, bMax: 300 }, budget: { B: 280, tau: 1, asOf: 1 } }, T0, {}]);

// ---- rails ------------------------------------------------------------------------------------------------------------------------------
const rmands = [mand.base, mand.minimal, mand.emptyCats, mand.fractionalLegacy, mand.capEqX];
const nowsR = [T0, T0 + 1, T0 + 30 * 86_400_000 - 1, T0 + 30 * 86_400_000, T0 + 40 * 86_400_000, 0, -1];
for (const [i, m] of rmands.entries()) for (const [j, nw] of nowsR.entries()) {
  await run('sharedPaymentTokenLimits', `${i}/${j}`, P.sharedPaymentTokenLimits as any, [lite(m), nw]);
  for (const [k, op] of [undefined, {}, { allowAnyCategory: true }, { actionTraits: ['mcc.c5734'] }, { actionTraits: ['mcc.c9999'] }, { actionTraits: ['mcc.c5734', 'mcc.c5817', 'x'], allowAnyCategory: true }, { actionTraits: ['mcc.c5734x', 'mcc.c57'] }].entries())
    await run('railLimits', `${i}/${j}/${k}`, P.railLimits as any, [lite(m), nw, op]);
}
for (const bud of [0, 0.5, 1, 99, 199.9, 200, 250, 1e9, -3, null, 'x']) for (const [i, m] of [mand.base, mand.minimal].entries())
  { await run('sharedPaymentTokenLimits', `bud/${i}/${String(bud)}`, P.sharedPaymentTokenLimits as any, [{ ...lite(m), budget: { ...m.budget, B: bud } }, T0]); await run('railLimits', `bud/${i}/${String(bud)}`, P.railLimits as any, [{ ...lite(m), budget: { ...m.budget, B: bud } }, T0, { allowAnyCategory: true }]); }
for (const tr of [[], ['mcc.c1234'], ['mcc.c1234', 'mcc.c1234', 'mcc.c0001'], ['mcc.c123'], ['mcc.c12345'], ['xmcc.c1234'], ['mcc.c1234\n'], ['mcc.c١٢٣٤'], ['mcc.C1234'], [5, null, 'mcc.c4444']]) await run('categoriesFromTraits', `${JSON.stringify(tr)}`, P.categoriesFromTraits as any, [tr]);
const appr = { id: 'auth_1', amount: 500, currency: 'USD', merchantId: 'm1' };
const sett = { authorizationId: 'auth_1', amount: 500, currency: 'usd', merchantId: 'm1', captures: 1 };
for (const [i, s] of [sett, { ...sett, amount: 499 }, { ...sett, amount: 501 }, { ...sett, authorizationId: 'x' }, { ...sett, currency: 'EUR' }, { ...sett, merchantId: 'm2' }, { ...sett, merchantId: undefined }, { ...sett, captures: 2 }, { ...sett, captures: 0 },
  { ...sett, amount: 501, currency: 'EUR', merchantId: 'q', authorizationId: 'z', captures: 3 }, { ...sett, amount: '501' }, { ...sett, currency: 5 }].entries()) await run('reconcileSettlement', `${i}`, P.reconcileSettlement as any, [appr, s]);

// ---- Stripe -------------------------------------------------------------------------------------------------------------------------------
const SEC = 'whsec_test_secret';
const body = '{"id":"evt_1","type":"issuing_authorization.request"}';
const goodHdr = S.signStripePayload(body, SEC, 1_800_000_000);
const hdrCases: [string, any][] = [
  ['good', goodHdr], ['undefined', undefined], ['empty', ''], ['no-t', goodHdr.replace(/^t=\d+,/, '')], ['no-v1', 't=1800000000'], ['v1-upper', goodHdr.replace(/v1=(.*)$/, (_m, h) => 'v1=' + h.toUpperCase())],
  ['v1-short', goodHdr.slice(0, -2)], ['v1-long', goodHdr + '0'], ['two-v1-first-bad', goodHdr.replace('v1=', 'v1=' + '0'.repeat(64) + ',v1=')], ['two-v1-last-bad', goodHdr + ',v1=' + '0'.repeat(64)],
  ['spaces', ' t = 1800000000 , v1 = ' + goodHdr.split('v1=')[1] + ' '], ['t-twice', 't=1,' + goodHdr], ['t-twice-last', goodHdr + ',t=1'], ['t-neg', goodHdr.replace('t=1800000000', 't=-1800000000')], ['t-frac', goodHdr.replace('t=1800000000', 't=1800000000.5')],
  ['t-13', goodHdr.replace('t=1800000000', 't=1800000000123')], ['t-lead0', goodHdr.replace('t=1800000000', 't=01800000000')], ['v0', goodHdr.replace('v1=', 'v0=')], ['no-eq', 'garbage'], ['nbsp', ' ' + goodHdr], ['bom-keys', '﻿' + goodHdr],
  ['other-secret', S.signStripePayload(body, 'other', 1_800_000_000)], ['other-body', S.signStripePayload(body + ' ', SEC, 1_800_000_000)], ['future', S.signStripePayload(body, SEC, 1_800_000_000 + 301)], ['trailing-comma', goodHdr + ','],
];
for (const [name, h] of hdrCases) for (const [nowSec, tol] of [[1_800_000_000, undefined], [1_800_000_300, undefined], [1_800_000_301, undefined], [1_799_999_699, undefined], [1_799_999_700, undefined], [1_800_000_100, 100], [1_800_000_101, 100], [1_800_000_000, 0], [1_800_000_000, -5]] as any[])
  await run('verifyStripeSignature', `${name}/${nowSec}/${tol}`, (rb: any, hd: any, sc: any, ns: any, tl: any) => (tl === null ? S.verifyStripeSignature(rb, hd, sc, ns) : S.verifyStripeSignature(rb, hd, sc, ns, tl)), [body, h, SEC, nowSec, tol]);
for (const [i, sc] of ['', 'a', SEC, 5, null, undefined, 'é', 'x'.repeat(200)].entries()) await run('verifyStripeSignature', `secret/${i}`, S.verifyStripeSignature as any, [body, S.signStripePayload(body, typeof sc === 'string' ? sc : 'z', 1_800_000_000), sc, 1_800_000_000]);
for (const [i, b2] of ['', '{}', 'café € 😀', 'a'.repeat(5000), 'line\nbreak'].entries()) {
  await run('signStripePayload', `b/${i}`, S.signStripePayload as any, [b2, SEC, 1_800_000_000]);
  await run('verifyStripeSignature', `b/${i}`, S.verifyStripeSignature as any, [b2, S.signStripePayload(b2, SEC, 1_800_000_000), SEC, 1_800_000_010]);
}
for (const t of [0, 1, 1_800_000_000, 99_999_999_999]) await run('signStripePayload', `t/${t}`, S.signStripePayload as any, [body, SEC, t]);
const lim = { currency: 'USD', perAuthorizationMax: 500, totalMax: 1000, categories: ['5734', '5817'], merchants: ['m1'], expiresAt: 1 };
const names = { '5734': 'computer_software_stores', '5817': 'digital_goods_applications' };
for (const [i, a] of ([[lim, names, 'ich_1', undefined], [lim, names, 'ich_1', { k: 'v', 'a b': 'c' }], [{ ...lim, categories: [] }, names, 'ich_2', undefined], [{ ...lim, categories: ['9999'] }, names, 'ich_1', undefined],
  [{ ...lim, currency: 'EUR', perAuthorizationMax: 1, totalMax: 1e9 }, names, 'ich_3', {}], [{ ...lim, categories: ['5734', '5817', '5734'] }, names, 'c', undefined], [{ ...lim, totalMax: 0.5 }, names, 'c', undefined]] as any[]).entries())
  await run('stripeCardParams', `${i}`, (l: any, nm: any, c: any, md: any) => S.stripeCardParams(l, { categoryNames: nm, cardholder: c, ...(md !== undefined ? { metadata: md } : {}) }), a);
const evt = (over: any = {}) => ({ id: 'evt_1', type: 'issuing_authorization.request', data: { object: { id: 'iauth_1', card: { id: 'ic_1' }, pending_request: { amount: 500, currency: 'usd' }, merchant_data: { network_id: 'm1', category_code: '5734' } } }, ...over });
const evCases: any[] = [evt(), evt({ type: 'other' }), evt({ type: undefined }), null, 'x', 5, [], {}, { type: 'issuing_authorization.request' }, { type: 'issuing_authorization.request', data: {} }, { type: 'issuing_authorization.request', data: { object: [] } }];
const mutate = (f: (a: any) => void) => { const e = J(evt()); f(e.data.object); return e; };
evCases.push(mutate((a) => delete a.id), mutate((a) => (a.id = 5)), mutate((a) => delete a.card), mutate((a) => (a.card = { id: 5 })), mutate((a) => delete a.pending_request), mutate((a) => (a.pending_request.amount = '5')),
  mutate((a) => (a.pending_request.amount = 0)), mutate((a) => (a.pending_request.amount = -5)), mutate((a) => (a.pending_request.amount = 1.5)), mutate((a) => delete a.pending_request.currency), mutate((a) => (a.pending_request.currency = 5)),
  mutate((a) => delete a.merchant_data), mutate((a) => (a.merchant_data = { network_id: '' })), mutate((a) => (a.merchant_data = { network_id: 5, category_code: 5 })), mutate((a) => (a.merchant_data = { category_code: '' })),
  mutate((a) => (a.merchant_data = [])), mutate((a) => (a.merchant_data = null)));
for (const [i, e] of evCases.entries()) {
  await run('stripeAuthorizationFromEvent', `${i}`, S.stripeAuthorizationFromEvent as any, [e]);
  for (const approved of [true, false, null, 'yes']) {
    const raw = JSON.stringify(e);
    await run('stripeIssuingWebhook', `${i}/${approved}`, async (rb: any, sg: any, sc: any, ns: any, ap: any) => S.createStripeIssuingWebhook({ secret: sc, nowSec: () => ns, authorize: async () => ({ approved: ap, reasons: [] }) as any })({ rawBody: rb, signature: sg }), [raw, S.signStripePayload(raw, SEC, 1_800_000_000), SEC, 1_800_000_000, approved]);
  }
}
for (const [i, a] of ([['{', undefined], ['{', 'sig'], ['not json', 'sig'], ['{}', 'sig'], ['[]', 'sig'], ['null', 'sig'], ['"x"', 'sig'], ['5', 'sig']] as any[]).entries()) {
  const sig = a[1] === 'sig' ? S.signStripePayload(a[0], SEC, 1_800_000_000) : a[1];
  await run('stripeIssuingWebhook', `raw/${i}`, async (rb: any, sg: any, sc: any, ns: any, ap: any) => S.createStripeIssuingWebhook({ secret: sc, nowSec: () => ns, authorize: async () => ({ approved: ap, reasons: [] }) as any })({ rawBody: rb, signature: sg }), [a[0], sig, SEC, 1_800_000_000, true]);
}
await run('stripeIssuingWebhook', 'stale', async (rb: any, sg: any, sc: any, ns: any, ap: any) => S.createStripeIssuingWebhook({ secret: sc, nowSec: () => ns, authorize: async () => ({ approved: ap, reasons: [] }) as any })({ rawBody: rb, signature: sg }), [JSON.stringify(evt()), S.signStripePayload(JSON.stringify(evt()), SEC, 1_800_000_000), SEC, 1_800_001_000, true]);
const txn = (over: any = {}) => ({ type: 'capture', authorization: 'iauth_1', amount: -500, currency: 'usd', merchant_data: { network_id: 'm1' }, ...over });
for (const [i, t] of [txn(), txn({ type: 'refund' }), txn({ authorization: 5 }), txn({ authorization: undefined }), txn({ amount: '5' }), txn({ amount: 0 }), txn({ amount: 500 }), txn({ amount: -1.5 }), txn({ currency: 5 }), txn({ merchant_data: undefined }), txn({ merchant_data: { network_id: 5 } }),
  txn({ merchant_data: { network_id: '' } }), null, 'x', [], {}].entries()) await run('stripeSettlementFromTransaction', `${i}`, S.stripeSettlementFromTransaction as any, [t]);

// ---- network tokens ---------------------------------------------------------------------------------------------------------------------------
const NONCE = 'nonce-0123456789abcdef';
const grant = m0.grant;
const bo = (over: any = {}) => ({ provider: 'visa_ic', tokenRef: 'tok_abcdef123456', grant, issuerNonce: NONCE, holderSecret: b64(sk.agent), holderPublic: b64(publicKeyOf(sk.agent)), ...over });
const refs = ['tok_abcdef123456', 'short', 'tok_ab', 'x'.repeat(8), 'x'.repeat(128), 'x'.repeat(129), '4111111111111111', 'a4111111111111111b', '4111-1111-1111-1111', '4111 1111 1111 1111', 'tok_4111111111111111', '41111111111111119', '411111111111111',
  'abcdefgh-4111111111111111', 'abc_4242424242424242_x', '4242424242424242', '1234567890123456', '1234567890123', '12345678901234567890', '0000000000000000', 'ref.with:allowed-chars_1', 'has space1', 'ünïcode1234', '', 'tok\n12345678', 'tok_abcdef123456\n'];
for (const r of refs) { await run('tokenRefError', `${JSON.stringify(r)}`, P.tokenRefError as any, [r]); await run('looksLikePan', `${JSON.stringify(r)}`, P.looksLikePan as any, [r]); }
for (const r of [5, null, undefined, {}, []]) await run('tokenRefError', `t/${JSON.stringify(r)}`, P.tokenRefError as any, [r]);
for (const s of ['4111 1111 1111 1111', '4111 1111 1111 1111', '4111 1111111111111', '4111-\t1111-1111-1111', 'a 4111111111111111 b', '411111111111 1111', 'call 4111111111111111 now 4111111111111111', '0000 0000 0000 000', '99999999999999999999', '﻿4111111111111111', '41111111111111112']) await run('looksLikePan', `s/${JSON.stringify(s)}`, P.looksLikePan as any, [s]);
const bindings: Record<string, any> = {};
for (const [i, over] of [{}, { provider: 'mastercard_agent_pay' }, { tokenRef: 'tok_other_123456' }, { issuerNonce: 'n'.repeat(16) }, { issuerNonce: 'short' }, { tokenRef: '4111111111111111' }, { tokenRef: 'x' }, { grant: { a: 1 } }, { grant: null }, { holderSecret: b64(sk.other), holderPublic: b64(publicKeyOf(sk.other)) }, { provider: '' }, { provider: 5 }].entries()) {
  await run('bindNetworkToken', `${i}`, P.bindNetworkToken as any, [bo(over)]);
  try { bindings[String(i)] = J(P.bindNetworkToken(unb(bo(over)))); } catch { /* refused */ }
}
const good = bindings['0'];
const exp = (over: any = {}) => ({ grant, holder: pk(sk.agent), issuerNonce: NONCE, ...over });
const bcases: [string, any, any][] = [['good', good, exp()], ['provider', good, exp({ provider: 'visa_ic' })], ['provider-bad', good, exp({ provider: 'mastercard_agent_pay' })], ['holder', good, exp({ holder: pk(sk.other) })], ['nonce', good, exp({ issuerNonce: 'x'.repeat(16) })],
  ['grant', good, exp({ grant: { a: 1 } })], ['no-grant', good, { holder: pk(sk.agent), issuerNonce: NONCE }], ['null', null, exp()], ['str', 'x', exp()], ['arr', [], exp()], ['empty', {}, exp()], ['kind', { ...good, kind: 'other' }, exp()],
  ['ref', { ...good, token_ref: 'tok_other_123456' }, exp()], ['ref-pan', { ...good, token_ref: '4111111111111111' }, exp()], ['proof-flip', { ...good, binding_proof: good.binding_proof.slice(0, 10) + (good.binding_proof[10] === 'A' ? 'B' : 'A') + good.binding_proof.slice(11) }, exp()],
  ['proof-short', { ...good, binding_proof: good.binding_proof.slice(0, 20) }, exp()], ['proof-pad', { ...good, binding_proof: good.binding_proof + '=' }, exp()], ['proof-missing', { ...good, binding_proof: undefined }, exp()], ['proof-num', { ...good, binding_proof: 5 }, exp()],
  ['holder-b', { ...good, holder: pk(sk.other) }, exp({ holder: pk(sk.other) })], ['grant-digest', { ...good, grant_digest: 'x' }, exp()], ['nonce-b', { ...good, issuer_nonce: 'y'.repeat(16) }, exp()], ['provider-empty', { ...good, provider: '' }, exp()],
  ['provider-num', { ...good, provider: 5 }, exp()], ['extra', { ...good, extra: 1 }, exp()], ['expect-null', good, null]];
for (const [name, b, e] of bcases) {
  await run('verifyNetworkTokenBinding', name, P.verifyNetworkTokenBinding as any, [b, e ?? {}]);
  if (b && typeof b === 'object' && !Array.isArray(b) && typeof b.provider === 'string') await run('bindingMessage', name, P.bindingMessage as any, [b]);
}
for (const [name, v] of variants(good, { depth: 2 })) await run('verifyNetworkTokenBinding', `var/${name}`, P.verifyNetworkTokenBinding as any, [v, exp()]);
const limits = { currency: 'USD', perAuthorizationMax: 200, totalMax: 1000, categories: ['5734'], merchants: ['openai', 'aws'], expiresAt: 1_802_592_000_000 };
for (const [i, l] of [limits, { ...limits, expiresAt: undefined }, { ...limits, categories: [] }].entries()) await run('controlsFromLimits', `${i}`, P.controlsFromLimits as any, [l, grant]);
for (const d of ['', 'abc', hashCanonical({ x: 1 })]) await run('settlementMetadata', `${d.slice(0, 6)}`, P.settlementMetadata as any, [good, d]);
const dg = hashCanonical(grant);
const recd = (over: any = {}) => ({ metadata: { pca_grant: dg, pca_pcactn: 'pd', pca_token_ref: 'tok_abcdef123456', ...over } });
const ex = (over: any = {}) => ({ grantDigest: dg, pcactnDigest: 'pd', tokenRef: 'tok_abcdef123456', ...over });
for (const [i, a] of ([[ex(), recd()], [ex(), recd({ pca_grant: 'x' })], [ex(), recd({ pca_pcactn: 'x' })], [ex(), recd({ pca_token_ref: 'x' })], [ex(), recd({ pca_pcactn: undefined })], [ex(), recd({ pca_pcactn: '' })], [ex({ pcactnDigest: '' }), recd({ pca_pcactn: '' })], [ex({ pcactnDigest: '' }), recd()],
  [ex(), {}], [ex(), null], [ex(), undefined], [ex(), { metadata: null }], [ex(), { metadata: 'x' }], [ex(), { metadata: [] }], [ex(), recd({ pca_pcactn: 5 })], [ex(), recd({ pca_grant: undefined, pca_token_ref: undefined })],
  [ex({ grantDigest: undefined }), recd({ pca_grant: undefined })], [ex({ pcactnDigest: 5 }), recd({ pca_pcactn: 'x' })], [ex({ pcactnDigest: 5 }), recd()]] as any[]).entries()) await run('reconcileNetworkSettlement', `${i}`, P.reconcileNetworkSettlement as any, a);
const bcw = bindings['0'];
for (const [i, c] of [ch(), ch({ amount: 0 }), ch({ amount: 1.5 }), ch({ merchant: 'aws', amount: 9 }), ch({ category: undefined })].entries()) {
  await run('chargeWithNetworkToken', `${i}`, P.chargeWithNetworkToken as any, [bcw, m0, c, act()]);
  await run('chargeWithNetworkToken', `${i}/other-grant`, P.chargeWithNetworkToken as any, [{ ...bcw, grant_digest: 'x' }, m0, c, act()]);
  await run('chargeWithNetworkToken', `${i}/bad-ref`, P.chargeWithNetworkToken as any, [{ ...bcw, token_ref: '4111111111111111' }, m0, c, act()]);
}

// results holding NaN / Infinity ({"$num"}) cannot be carried as JSON numbers by a native: dropped
const before = o.cases.length;
o.cases = o.cases.filter((c: any) => !JSON.stringify(c.out).includes('"$num"'));
console.log('dropped', before - o.cases.length, 'non-finite results');
if (process.env.SIZES) { const bm = o.cases.filter((c: any) => c.fn === 'buildPaymentMandate'); console.log(bm.length, bm.slice(0, 3).map((c: any) => JSON.stringify(c).length), bm.map((c: any) => c.name).slice(20, 30)); const by: any = {}; for (const c of o.cases) by[c.fn] = (by[c.fn] ?? 0) + JSON.stringify(c).length; console.log(by); }
refWrite(o, 'payments');
