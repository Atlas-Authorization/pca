/** Mutation-kill suite for pca.ts: every refusal reason, each condition on its own, the threshold-hook bookkeeping. */
import { beforeEach, describe, expect, it } from 'vitest';
import { encodeMlDsaPublicKey, mlDsa65Keygen, buildPCActn, encodeKey, generateKeyPair, mintGrant, mintRoot, paramsDigest, hashCanonical, type PCActn } from '@atlasauth/pca';
import { authorizeCharge, buildPaymentMandate, chargeParams, chargePlanNode, mandateCaveats, mandatePredicates, type PaymentMandate } from '@atlasauth/pca-payments';
import {
  buildPcaPaymentBinding,
  jwkThumbprint,
  paymentConstraintsFromTerms,
  openCheckoutMandateFromPca,
  openPaymentMandateFromPca,
  pcaBindingNonce,
  pcaOpenClaim,
  riskRatio,
  sdHashOf,
  parseSdJwtHop,
  verifyPcaBinding,
  type VerifyPcaBindingInput,
  generateAp2KeyPair,
  type JsonObject,
  type OpenPaymentMandateClaims,
  type PaymentMandateClaims,
} from './index';
import { MERCHANT, NOW_MS, NOW_S, makeScenario, verifyScenario, type Scenario } from './testkit';

const pubOf = (k: { publicKey: Uint8Array }): string => encodeKey(k.publicKey);
const asRec = (v: unknown): Record<string, unknown> => v as Record<string, unknown>;

function verified(s: Scenario) {
  const r = verifyScenario(s);
  if (!r.ok) throw new Error(r.reason);
  return { open: structuredClone(r.payment.open), closed: structuredClone(r.payment.closed), openHash: r.payment.openHash };
}
const input = (s: Scenario, over: Record<string, unknown> = {}) => ({
  ...verified(s),
  expectedPrincipal: pubOf(s.principal),
  audience: s.pcaAudience,
  now: NOW_MS + 60_000,
  // the verifier's own mandate state and charge history (the policy decision always runs on them)
  mandate: s.pca,
  recentChargeTimes: [],
  ...over,
});
type In = ReturnType<typeof input> & Pick<VerifyPcaBindingInput, 'pqPins'>;
const reason = async (i: In): Promise<string> => {
  const r = await verifyPcaBinding(i as never);
  return r.ok ? 'ACCEPTED' : r.reason;
};
const find = (o: OpenPaymentMandateClaims, t: string) => asRec(o.constraints.find((c) => c.type === t));
const xp = (m: { x_pca?: unknown }) => asRec(m.x_pca);

describe('open-mandate x_pca claim shape', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  it('null, array, wrong version, missing grant/terms are all "no x_pca grant"', async () => {
    const want = 'open mandate carries no x_pca grant';
    for (const bad of [null, [], 'x', { v: 2, grant: {}, terms: {} }, { v: 1, terms: {} }, { v: 1, grant: {} }, { v: 1, grant: [], terms: {} }, { v: 1, grant: {}, terms: [] }, { v: 1, grant: null, terms: {} }]) {
      const i = input(s);
      (i.open as { x_pca?: unknown }).x_pca = bad;
      expect(await reason(i), JSON.stringify(bad)).toBe(want);
    }
  });
  it('the unmutated flow with the live mandate is accepted', async () => {
    expect(await reason(input(s, { mandate: s.pca }))).toBe('ACCEPTED');
  });
  it('pcaOpenClaim shape', () => {
    const c = pcaOpenClaim(s.pca);
    expect(Object.keys(c).sort()).toEqual(['grant', 'terms', 'v']);
    expect(c.v).toBe(1);
  });
});

describe('constraintsWithinTerms: each constraint on its own', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  const tamper = async (mut: (o: OpenPaymentMandateClaims) => void): Promise<string> => {
    const i = input(s);
    mut(i.open);
    return reason(i);
  };
  it('constraint order does not matter (found by type)', async () => {
    expect(await tamper((o) => { o.constraints = [...o.constraints].reverse(); })).toBe('ACCEPTED');
    expect(await tamper((o) => { o.constraints = [find(o, 'payment.budget'), find(o, 'payment.agent_recurrence'), find(o, 'payment.allowed_payees'), find(o, 'payment.reference'), find(o, 'payment.amount_range')] as never; })).toBe('ACCEPTED');
  });
  it('missing amount_range', async () => {
    expect(await tamper((o) => { o.constraints = o.constraints.filter((c) => c.type !== 'payment.amount_range'); })).toBe('open mandate has no amount_range to compare with the PCA per-transaction cap');
  });
  it('amount_range currency / max boundary', async () => {
    expect(await tamper((o) => { find(o, 'payment.amount_range').currency = 'EUR'; })).toBe('amount_range currency differs from the PCA terms');
    expect(await tamper((o) => { find(o, 'payment.amount_range').max = 50_000; })).toBe('ACCEPTED');
    expect(await tamper((o) => { find(o, 'payment.amount_range').max = 50_001; })).toBe('amount_range.max 50001 exceeds the PCA per-transaction cap 50000');
  });
  it('allowed_payees: one outsider among allowed ones is refused; a missing list is refused', async () => {
    expect(await tamper((o) => { (find(o, 'payment.allowed_payees').allowed as unknown[]).push({ id: 'merchant_2', name: 'Other' }); })).toBe('allowed_payees names a merchant outside the PCA allowlist');
    expect(await tamper((o) => { o.constraints = o.constraints.filter((c) => c.type !== 'payment.allowed_payees'); })).toBe('open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side');
  });
  it('budget: missing, currency, max boundary', async () => {
    expect(await tamper((o) => { o.constraints = o.constraints.filter((c) => c.type !== 'payment.budget'); })).toBe('open mandate has no budget to compare with the PCA cumulative cap');
    expect(await tamper((o) => { find(o, 'payment.budget').currency = 'EUR'; })).toBe('budget exceeds the PCA cumulative cap');
    expect(await tamper((o) => { find(o, 'payment.budget').max = 1000; })).toBe('ACCEPTED');
    expect(await tamper((o) => { find(o, 'payment.budget').max = 1000.01; })).toBe('budget exceeds the PCA cumulative cap');
  });
  it('recurrence: missing, no max, over max, equal max', async () => {
    const want = 'max_occurrences is missing or exceeds the PCA transaction limit';
    expect(await tamper((o) => { o.constraints = o.constraints.filter((c) => c.type !== 'payment.agent_recurrence'); })).toBe(want);
    expect(await tamper((o) => { delete find(o, 'payment.agent_recurrence').max_occurrences; })).toBe(want);
    expect(await tamper((o) => { find(o, 'payment.agent_recurrence').max_occurrences = 6; })).toBe(want);
    expect(await tamper((o) => { find(o, 'payment.agent_recurrence').max_occurrences = 5; })).toBe('ACCEPTED');
    expect(await tamper((o) => { find(o, 'payment.agent_recurrence').max_occurrences = 1; })).toBe('ACCEPTED');
  });
  it('period: missing exp and exp past the period end are refused, equal is fine', async () => {
    const end = Math.floor((NOW_MS + 24 * 3_600_000) / 1000);
    expect(await tamper((o) => { delete o.exp; })).toBe('open mandate outlives the PCA period');
    expect(await tamper((o) => { o.exp = end + 1; })).toBe('open mandate outlives the PCA period');
    expect(await tamper((o) => { o.exp = end; })).toBe('ACCEPTED');
  });
});

describe('terms without a period / velocity limit', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario({ mandateOver: { periodMs: undefined, maxTransactionsPerPeriod: undefined }, exp: NOW_S + 3600 });
  });
  it('is accepted: no recurrence cap or expiry is required of the AP2 side', async () => {
    expect(await reason(input(s))).toBe('ACCEPTED');
  });
  it('an open mandate without exp is still fine when the terms have no period end', async () => {
    const i = input(s);
    delete i.open.exp;
    expect(await reason(i)).toBe('ACCEPTED');
  });
  it('open mandate issuance requires the explicit exp', () => {
    expect(s.pca.terms.periodEnd).toBeUndefined();
    expect(s.pca.terms.maxTransactionsPerPeriod).toBeUndefined();
    const rec = paymentConstraintsFromTerms(s.pca.terms, [MERCHANT], 'R').find((c) => c.type === 'payment.agent_recurrence');
    expect(rec).toStrictEqual({ type: 'payment.agent_recurrence', frequency: 'ON_DEMAND' });
  });
});

describe('grant envelope / risk policy consistency', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  it('terms periodStart / cap tamper: envelope and risk policy reasons', async () => {
    const a = input(s);
    asRec(asRec(a.open.x_pca).terms).periodStart = 1;
    expect(await reason(a)).toBe('x_pca terms do not match the grant envelope');
    const b = input(s);
    asRec(asRec(b.open.x_pca).terms).perTransactionCap = 400;
    expect(await reason(b)).toBe('x_pca terms do not match the grant envelope');
    const c = input(s);
    asRec(asRec(c.open.x_pca).terms).cumulativeCap = 2000;
    expect(await reason(c)).toBe('x_pca terms do not match the grant risk policy');
  });
  const regrant = (risk: Record<string, unknown>) => {
    const i = input(s);
    const terms = s.pca.terms;
    const { grant } = mintGrant({
      principalSecret: s.principal.secretKey,
      principalPublic: pubOf(s.principal),
      holder: pubOf(s.agentEd),
      goal: 'g',
      envelope: { predicates: mandatePredicates(terms), caveats: mandateCaveats(terms), agent_binding: {}, risk_policy: { ...s.pca.policy, ...risk } },
    });
    asRec(i.open.x_pca).grant = JSON.parse(JSON.stringify(grant));
    return i;
  };
  it('a principal-signed grant whose kappa or bMax differs from the terms is refused', async () => {
    expect(await reason(regrant({}))).not.toBe('ACCEPTED'); // PCActn was signed under the other grant
    expect(await reason(regrant({ kappa: 400 }))).toBe('x_pca terms do not match the grant risk policy');
    expect(await reason(regrant({ bMax: 2000 }))).toBe('x_pca terms do not match the grant risk policy');
    expect(await reason(regrant({ kappa: 400, bMax: 2000 }))).toBe('x_pca terms do not match the grant risk policy');
  });
  it('a grant without an envelope is refused', async () => {
    const i = input(s);
    const grantRec = asRec(asRec(i.open.x_pca).grant);
    const root = mintRoot({
      principalSecret: s.principal.secretKey,
      principalPublic: pubOf(s.principal),
      holder: pubOf(s.agentEd),
      caveats: [],
    });
    void grantRec;
    asRec(i.open.x_pca).grant = JSON.parse(JSON.stringify(root));
    expect(await reason(i)).toBe('PCA grant has no envelope');
  });
  it('a grant that fails chain verification names the reason', async () => {
    const i = input(s, { expectedPrincipal: pubOf(generateKeyPair()) });
    const r = await reason(i);
    expect(r.startsWith('PCA grant: ')).toBe(true);
    expect(r.length).toBeGreaterThan('PCA grant: '.length);
  });
});

describe('closed mandate x_pca claim shape and charge', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  it('shape errors', async () => {
    const want = 'closed mandate carries no x_pca PCActn';
    const good = xp(verified(s).closed);
    for (const bad of [null, [], { ...good, v: 2 }, { v: 1, charge: good.charge }, { v: 1, pcactn: good.pcactn }, { ...good, pcactn: [] }, { ...good, charge: null }]) {
      const i = input(s);
      (i.closed as { x_pca?: unknown }).x_pca = bad;
      expect(await reason(i), JSON.stringify(bad)).toBe(want);
    }
  });
  it('charge currency and amount are each compared with the payment amount', async () => {
    const want = 'x_pca charge differs from the mandate payment_amount';
    const a = input(s);
    asRec(xp(a.closed).charge).currency = 'EUR';
    expect(await reason(a)).toBe(want);
    const b = input(s);
    asRec(xp(b.closed).charge).amount = 40.01;
    expect(await reason(b)).toBe(want);
    const c = input(s);
    asRec(xp(c.closed).charge).amount = '40';
    expect(await reason(c)).toBe(want);
  });
  it('a charge carrying a category the PCActn did not commit to fails the params digest', async () => {
    const i = input(s);
    asRec(xp(i.closed).charge).category = 'extra';
    expect(await reason(i)).toBe('PCActn params do not commit to the x_pca charge');
  });
  it('PCActn for another merchant than the payee is refused (action resource)', async () => {
    const two = makeScenario({ mandateOver: { merchants: ['merchant_1', 'merchant_2'] }, extraMerchants: [{ ...MERCHANT, id: 'merchant_2', name: 'Two' }] });
    const i = input(two);
    xp(i.closed).pcactn = buildPcaPaymentBinding({
      mandate: two.pca, open: two.openPayment, agentJwk: two.agent.publicJwk, agentSecret: two.agentEd.secretKey, audience: two.pcaAudience, counter: 7,
      transactionId: i.closed.transaction_id, payee: { ...MERCHANT, id: 'merchant_2' }, amount: { amount: two.amountMinor, currency: 'USD' }, instrumentId: 'card_4242', now: NOW_MS + 10_000,
    }).pcactn;
    expect(await reason(i)).toBe('PCActn action is not a charge at this payee');
  });
});

describe('categories', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario({ mandateOver: { categories: ['food', 'travel'] }, category: 'food' });
  });
  it('accepted with an allowed category (digest includes it), also with the live mandate', async () => {
    expect(await reason(input(s))).toBe('ACCEPTED');
    expect(await reason(input(s, { mandate: s.pca }))).toBe('ACCEPTED');
  });
  it('missing, wrong, or non-string category is refused with the category reason', async () => {
    const want = 'x_pca charge lacks an allowed category';
    for (const c of [undefined, 'fuel', 5, null, ['food']]) {
      const i = input(s);
      const ch = asRec(xp(i.closed).charge);
      if (c === undefined) delete ch.category;
      else ch.category = c;
      expect(await reason(i), String(c)).toBe(want);
    }
  });
  it('a non-string category in the signed terms never satisfies the check', async () => {
    const terms = { ...s.pca.terms, categories: [5 as unknown as string] };
    const { grant } = mintGrant({
      principalSecret: s.principal.secretKey, principalPublic: pubOf(s.principal), holder: pubOf(s.agentEd), goal: 'g',
      envelope: { predicates: mandatePredicates(terms), caveats: mandateCaveats(terms), agent_binding: {}, risk_policy: s.pca.policy },
    });
    const i = input(s);
    asRec(i.open.x_pca).grant = JSON.parse(JSON.stringify(grant));
    asRec(i.open.x_pca).terms = JSON.parse(JSON.stringify(terms));
    asRec(xp(i.closed).charge).category = 5;
    expect(await reason(i)).toBe('x_pca charge lacks an allowed category');
  });
});

describe('threshold hook bookkeeping (R2-09)', () => {
  let s: Scenario; // 120 USD above Y: needs t = 3
  beforeEach(() => {
    s = makeScenario({ quantity: 1, unitPrice: 12_000 });
  });
  const hookRes = (r: Record<string, unknown>) => ({ threshold: () => r as never });
  it('without any hook: exact reason', async () => {
    expect(await reason(input(s))).toBe('this charge needs a threshold of 3 (human co-sign); supply hooks.threshold to verify it');
    expect(await reason(input(s, { hooks: {} }))).toBe('this charge needs a threshold of 3 (human co-sign); supply hooks.threshold to verify it');
  });
  it('only an ENFORCED, ok result reporting a numeric t counts', async () => {
    const unreported = 'this charge needs a threshold of 3 but the threshold hook enforced t=unreported; build it with createThresholdVerifier({ t: 3 })';
    expect(await reason(input(s, { hooks: hookRes({ enforced: true, ok: true }) }))).toBe(unreported);
    expect(await reason(input(s, { hooks: hookRes({ enforced: false, t: 3 }) }))).toBe(unreported);
    expect(await reason(input(s, { hooks: hookRes({ enforced: false, ok: true, t: 3 }) }))).toBe(unreported);
    expect(await reason(input(s, { hooks: hookRes({ enforced: true, ok: true, t: '3' }) }))).toBe(unreported);
  });
  it('a failing hook is a PCActn rejection', async () => {
    expect(await reason(input(s, { hooks: hookRes({ enforced: true, ok: false, t: 3, reason: 'no quorum' }) }))).toBe('PCActn: threshold: no quorum');
  });
  it('enforced t must reach the needed t (boundary)', async () => {
    expect(await reason(input(s, { hooks: hookRes({ enforced: true, ok: true, t: 2 }) }))).toBe('this charge needs a threshold of 3 but the threshold hook enforced t=2; build it with createThresholdVerifier({ t: 3 })');
    expect(await reason(input(s, { hooks: hookRes({ enforced: true, ok: true, t: 3 }) }))).toBe('ACCEPTED');
    expect(await reason(input(s, { hooks: hookRes({ enforced: true, ok: true, t: 4 }) }))).toBe('ACCEPTED');
  });
  it('other hooks are passed through to the core', async () => {
    const calls: string[] = [];
    const hooks = { threshold: () => ({ enforced: true, ok: true, t: 3 }) as never, revocation: () => { calls.push('rev'); return { enforced: true, ok: false, reason: 'revoked' } as never; } };
    expect(await reason(input(s, { hooks }))).toBe('PCActn: revocation: revoked');
    expect(calls).toEqual(['rev']);
  });
  it('enforce options are passed through to the core', async () => {
    const small = makeScenario();
    expect(await reason(input(small, { enforce: { attestation: { required: true } } }))).toMatch(/^PCActn: .*attestation/);
  });
});

describe('live PCA mandate state', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  it('a different mandate than the one in the open mandate', async () => {
    const other = makeScenario();
    expect(await reason(input(s, { mandate: other.pca }))).toBe('the supplied PCA mandate is not the one in the open mandate');
  });
  it('deny from the live decision lists the reasons joined by "; "', async () => {
    const recent = [NOW_MS + 1, NOW_MS + 2, NOW_MS + 3, NOW_MS + 4, NOW_MS + 5];
    const r = await reason(input(s, { mandate: s.pca, recentChargeTimes: recent }));
    expect(r).toBe('PCA denies this charge: caveat(s) not satisfied: rate');
    const empty: PaymentMandate = { ...s.pca, budget: { ...s.pca.budget, B: 0 } };
    expect(await reason(input(s, { mandate: empty, recentChargeTimes: recent }))).toBe(
      'PCA denies this charge: caveat(s) not satisfied: rate; trust budget depleted: human recharge required',
    );
  });
  it('recentChargeTimes default to none', async () => {
    const one = makeScenario({ mandateOver: { maxTransactionsPerPeriod: 1 } });
    expect(await reason(input(one, { mandate: one.pca }))).toBe('ACCEPTED');
  });
  it('budget exhausted: step-up needed although the risk is low', async () => {
    const poor: PaymentMandate = { ...s.pca, budget: { ...s.pca.budget, B: 1 } };
    const direct = authorizeCharge(poor, { merchant: 'merchant_1', amount: 4000, currency: 'USD', now: NOW_MS + 60_000, recentChargeTimes: [] }, poor.grant);
    expect(direct.outcome).toBe('step_up');
    expect(await reason(input(s, { mandate: poor }))).toBe('PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced');
    const hook = (t: number | undefined) => ({ threshold: () => ({ enforced: true, ok: true, ...(t !== undefined ? { t } : {}) }) as never });
    expect(await reason(input(s, { mandate: poor, hooks: hook(1) }))).toBe('PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced');
    expect(await reason(input(s, { mandate: poor, hooks: hook(undefined) }))).toBe('PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced');
    expect(await reason(input(s, { mandate: poor, hooks: hook(2) }))).toBe('ACCEPTED');
    expect(await reason(input(s, { mandate: poor, hooks: hook(3) }))).toBe('ACCEPTED');
  });
  it('the category is part of the live decision', async () => {
    const c = makeScenario({ mandateOver: { categories: ['food'] }, category: 'food' });
    expect(await reason(input(c, { mandate: c.pca }))).toBe('ACCEPTED');
  });
  it('now is forwarded to the live decision (expired period)', async () => {
    const r = await reason(input(s, { mandate: s.pca, now: NOW_MS + 25 * 3_600_000 }));
    expect(r).not.toBe('ACCEPTED');
  });
});

describe('risk claim, understated or exactly at tolerance', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  function rebind(i: In, risk: unknown, amountOverride?: { amount: number; currency: string }, payee = MERCHANT, verb = 'charge') {
    const closed = i.closed as PaymentMandateClaims;
    const amount = amountOverride ?? closed.payment_amount;
    const major = amount.amount; // minor units
    const charge = { merchant: payee.id, amount: major, currency: amount.currency };
    const facts = {
      transactionId: closed.transaction_id, payeeId: payee.id, amount: amount.amount, currency: amount.currency, instrumentId: closed.payment_instrument.id,
      openHash: i.openHash, agentJkt: jwkThumbprint(i.open.cnf.jwk),
    };
    const nodeId = `ap2:${closed.transaction_id}`;
    const node = { ...chargePlanNode(s.pca, charge, nodeId), verb };
    const built = buildPCActn({
      grant: s.pca.grant, chain: [s.pca.grant], plan: [node], nodeId, params: chargeParams(s.pca, charge), counter: 9,
      signerSecret: s.agentEd.secretKey, aud: s.pcaAudience, nonce: pcaBindingNonce(facts), riskClaim: { r: risk as number, inputs: { ...chargeParams(s.pca, charge), blastRadius: risk as number } }, now: NOW_MS + 10_000,
    });
    closed.payment_amount = amount;
    closed.payee = payee;
    closed.x_pca = { v: 1, charge: { amount: major, currency: amount.currency }, pcactn: JSON.parse(JSON.stringify(built)) } as JsonObject;
  }
  it('understated risk is refused with its own reason; the exact and the tolerated values are accepted', async () => {
    const real = riskRatio(40, 500);
    expect(real).toBe(0.08);
    const ok = input(s);
    rebind(ok, real);
    expect(await reason(ok)).toBe('ACCEPTED');
    const tol = input(s);
    rebind(tol, real - 1e-9);
    expect(await reason(tol)).toBe('ACCEPTED');
    const low = input(s);
    rebind(low, real - 2e-9);
    expect(await reason(low)).toBe('PCActn understates the risk of this charge');
    const zero = input(s);
    rebind(zero, 0);
    expect(await reason(zero)).toBe('PCActn understates the risk of this charge');
  });
  it('a charge at exactly the per-transaction cap is accepted (with the t=3 threshold enforced)', async () => {
    const cap = makeScenario({ quantity: 1, unitPrice: 50_000 });
    const hooks = { threshold: () => ({ enforced: true, ok: true, t: 3 }) as never };
    expect(await reason(input(cap, { hooks }))).toBe('ACCEPTED');
  });
  it('a validly signed PCActn for another verb, another payee or another currency is refused', async () => {
    const a = input(s);
    rebind(a, 0.08, undefined, MERCHANT, 'transfer');
    expect(await reason(a)).toBe('PCActn action is not a charge at this payee');
    const b = input(s);
    rebind(b, 0.08, undefined, { ...MERCHANT, id: 'merchant_9' });
    expect(await reason(b)).toBe('payment currency or payee is outside the PCA terms');
    const c = input(s);
    rebind(c, 0.08, { amount: 4000, currency: 'EUR' });
    expect(await reason(c)).toBe('payment currency or payee is outside the PCA terms');
  });
  it('an unexpected exception is reported as the failure reason', async () => {
    const i = input(s);
    delete (i.closed as { payment_amount?: unknown }).payment_amount;
    expect(await reason(i)).toMatch(/^Cannot read propert/);
  });
  it('a charge above the per-transaction cap is refused', async () => {
    const i = input(s);
    rebind(i, 1, { amount: 50_001, currency: 'USD' });
    const r = await reason(i);
    expect(r).not.toBe('ACCEPTED');
    expect(r).toBe('payment exceeds the PCA per-transaction cap');
  });
});

describe('riskRatio and constraint builders', () => {
  it('cap of zero or negative means full risk; exact ratios', () => {
    expect(riskRatio(5, 0)).toBe(1);
    expect(riskRatio(0, 0)).toBe(1);
    expect(riskRatio(0, -1)).toBe(1);
    expect(riskRatio(5, 10)).toBe(0.5);
    expect(riskRatio(-5, 10)).toBe(0);
  });
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const mk = (over: Record<string, unknown> = {}) =>
    buildPaymentMandate({
      principalSecret: principal.secretKey, principalPublic: pubOf(principal), agentPublic: pubOf(agent), merchants: ['merchant_1'], currency: 'USD',
      perTransactionCap: 50_000, autoApproveThreshold: 5_000, cumulativeCap: 100_000, now: NOW_MS, ...over,
    });
  it('constraint list shape incl. optional max_occurrences and inexact cap', () => {
    const c = paymentConstraintsFromTerms(mk({ maxTransactionsPerPeriod: 3 }).terms, [MERCHANT], 'REF');
    expect(c.map((x) => x.type)).toEqual(['payment.amount_range', 'payment.allowed_payees', 'payment.reference', 'payment.budget', 'payment.agent_recurrence']);
    expect(c[4]).toEqual({ type: 'payment.agent_recurrence', frequency: 'ON_DEMAND', max_occurrences: 3 });
    expect(paymentConstraintsFromTerms(mk().terms, [MERCHANT], 'REF')[4]).toStrictEqual({ type: 'payment.agent_recurrence', frequency: 'ON_DEMAND' });
    // 29 / 100 * 100 is 28.999999999999996 in floating point: the cap is converted exactly (nudged), not refused
    const odd = paymentConstraintsFromTerms(mk({ perTransactionCap: 29, autoApproveThreshold: 29, cumulativeCap: 29 }).terms, [MERCHANT], 'R').find((x) => x.type === 'payment.budget') as { max: number };
    expect(Math.trunc(odd.max * 100)).toBe(29);
  });
  it('merchant descriptors are matched by id', () => {
    const other = { id: 'merchant_0', name: 'Zero' };
    const c = paymentConstraintsFromTerms(mk({ merchants: ['merchant_1'] }).terms, [other, MERCHANT], 'REF');
    expect(asRec(c[1]).allowed).toEqual([MERCHANT]);
    expect(() => paymentConstraintsFromTerms(mk().terms, [other], 'REF')).toThrow('no merchant descriptor supplied for PCA merchant merchant_1');
  });
  it('salt is forwarded into the issued mandates and exp errors are exact', () => {
    const issuer = generateAp2KeyPair('k');
    const a = generateAp2KeyPair();
    const m = mk({ periodMs: 3_600_000 });
    const mkTok = (salt?: () => string) =>
      openPaymentMandateFromPca(m, { issuer: { privateKey: issuer.privateKey, kid: 'k' }, agentJwk: a.publicJwk, merchants: [MERCHANT], iat: NOW_S, checkoutReference: 'R', ...(salt ? { salt } : {}) });
    let n = 0;
    const salted = mkTok(() => `fixed-salt-${++n}`);
    expect(Buffer.from(parseSdJwtHop(salted).disclosures.map((d) => d).join(''), 'utf8').length).toBeGreaterThan(0);
    expect(parseSdJwtHop(salted).disclosures.some((d) => Buffer.from(d, 'base64url').toString().includes('fixed-salt-1'))).toBe(true);
    const chk = openCheckoutMandateFromPca(m, {
      issuer: { privateKey: issuer.privateKey, kid: 'k' }, agentJwk: a.publicJwk, merchants: [MERCHANT], iat: NOW_S, lineItems: [{ id: 'l', acceptable_items: [{ id: 'a', title: 'A' }], quantity: 1 }],
      salt: () => 'chk-salt',
    });
    expect(parseSdJwtHop(chk).disclosures.some((d) => Buffer.from(d, 'base64url').toString().includes('chk-salt'))).toBe(true);
    expect(() => openPaymentMandateFromPca(m, { issuer: { privateKey: issuer.privateKey }, agentJwk: a.publicJwk, merchants: [MERCHANT], iat: NOW_S, exp: NOW_S + 3601, checkoutReference: 'R' })).toThrow('exp must not exceed the PCA period end');
    expect(() => openPaymentMandateFromPca(mk(), { issuer: { privateKey: issuer.privateKey }, agentJwk: a.publicJwk, merchants: [MERCHANT], iat: NOW_S, checkoutReference: 'R' })).toThrow('exp is required when the PCA terms have no period end');
  });
});

describe('buildPcaPaymentBinding output', () => {
  let s: Scenario;
  beforeEach(() => {
    s = makeScenario();
  });
  it('charge block, version and node id', () => {
    const b = buildPcaPaymentBinding({
      mandate: s.pca, open: s.openPayment, agentJwk: s.agent.publicJwk, agentSecret: s.agentEd.secretKey, audience: s.pcaAudience, counter: 3,
      transactionId: 'T1', payee: MERCHANT, amount: { amount: 4000, currency: 'USD' }, instrumentId: 'card_4242', now: NOW_MS + 10_000,
    });
    expect(b.v).toBe(1);
    expect(b.charge).toStrictEqual({ amount: 4000, currency: 'USD' });
    const p = b.pcactn as unknown as PCActn;
    expect(p.nonce).toBe(pcaBindingNonce({ transactionId: 'T1', payeeId: 'merchant_1', amount: 4000, currency: 'USD', instrumentId: 'card_4242', openHash: sdHashOf(parseSdJwtHop(s.openPayment)), agentJkt: jwkThumbprint(s.agent.publicJwk) }));
    expect(p.risk_claim.r).toBe(0.08);
    expect(p.risk_claim.inputs).toMatchObject({ blastRadius: 0.08 });
    expect(JSON.stringify(p.plan)).toContain('ap2:T1');
    expect(p.action.params_digest).toBe(paramsDigest({ amount: 4000, currency: 'USD' }));
    const withCat = buildPcaPaymentBinding({
      mandate: makeScenario({ mandateOver: { categories: ['food'] } }).pca, open: s.openPayment, agentJwk: s.agent.publicJwk, agentSecret: s.agentEd.secretKey, audience: s.pcaAudience, counter: 3,
      transactionId: 'T1', payee: MERCHANT, amount: { amount: 4000, currency: 'USD' }, instrumentId: 'card_4242', category: 'food', now: NOW_MS + 10_000,
    });
    expect(withCat.charge).toStrictEqual({ amount: 4000, currency: 'USD', category: 'food' });
    void hashCanonical;
    void generateAp2KeyPair;
  });
  it('now is honoured by the PCActn iat', () => {
    const mk = (now?: number) =>
      buildPcaPaymentBinding({
        mandate: s.pca, open: s.openPayment, agentJwk: s.agent.publicJwk, agentSecret: s.agentEd.secretKey, audience: s.pcaAudience, counter: 3,
        transactionId: 'T1', payee: MERCHANT, amount: { amount: 4000, currency: 'USD' }, instrumentId: 'card_4242', ...(now !== undefined ? { now } : {}),
      });
    expect((mk(NOW_MS + 5000).pcactn as unknown as PCActn).iat).toBe(NOW_MS + 5000);
  });
});

describe('pqPins are forwarded to the grant verification', () => {
  it('a pin for the root issuer lets the grant step pass', async () => {
    const s = makeScenario();
    const atk = generateKeyPair();
    const i = input(s);
    const real = asRec(asRec(i.open.x_pca).grant) as unknown as { holder: string; caveats: never[] };
    const root = mintRoot({
      principalSecret: atk.secretKey, principalPublic: pubOf(s.principal), holder: real.holder, caveats: real.caveats,
      suite: { alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(3)) },
    });
    asRec(i.open.x_pca).grant = root as unknown as JsonObject;
    const unpinned = await reason(i);
    expect(unpinned).toMatch(/needs a PQ key pinned/);
    const pinned = await reason({ ...i, pqPins: { [pubOf(s.principal)]: encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(3)).publicKey) } });
    expect(pinned).not.toMatch(/^PCA grant: /);
  });
});
