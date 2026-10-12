import { describe, expect, it } from 'vitest';
import { encodeKey, encodeMlDsaPublicKey, generateKeyPair, mintRoot, mlDsa65Keygen } from '@atlasauth/pca';
import { buildPaymentMandate } from '@atlasauth/pca-payments';
import {
  buildPcaPaymentBinding,
  generateAp2KeyPair,
  openPaymentMandateFromPca,
  paymentConstraintsFromTerms,
  riskRatio,
  verifyPcaBinding,
  type OpenPaymentMandateClaims,
  type PaymentMandateClaims,
  type JsonObject,
} from './index';
import { MERCHANT, NOW_MS, NOW_S, createThresholdVerifier, makeScenario, verifyScenario, type Scenario } from './testkit';

const pubOf = (k: { publicKey: Uint8Array }): string => encodeKey(k.publicKey);

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
const asRec = (v: unknown): Record<string, unknown> => v as Record<string, unknown>;

describe('PCA binding of the AP2 purchase', () => {
  const s = makeScenario();

  it('accepts: principal-signed grant, terms consistent, PCActn valid and committing to this exact AP2 charge', async () => {
    const r = await verifyPcaBinding(input(s, { mandate: s.pca }));
    expect(r.ok, r.ok ? '' : r.reason).toBe(true);
    if (r.ok) {
      expect(r.pcactn.action).toMatchObject({ verb: 'charge', resource: 'merchant:merchant_1' });
      expect(r.terms.perTransactionCap).toBe(500);
    }
  });

  it('the grant and the PCActn travel inside the mandates as the namespaced x_pca claim', () => {
    const { open, closed } = verified(s);
    expect(Object.keys(asRec(open.x_pca)).sort()).toEqual(['grant', 'terms', 'v']);
    expect(Object.keys(asRec(closed.x_pca)).sort()).toEqual(['charge', 'pcactn', 'v']);
    expect(asRec(asRec(closed.x_pca).pcactn).nonce).toMatch(/^ap2:/);
  });

  it('refuses a grant not signed by the expected principal, and a wrong PCA audience', async () => {
    const stranger = generateKeyPair();
    expect((await verifyPcaBinding(input(s, { expectedPrincipal: pubOf(stranger) }))).ok).toBe(false);
    const r = await verifyPcaBinding(input(s, { audience: 'https://pca.example/instance/2' }));
    expect(!r.ok && r.reason).toMatch(/audience/);
  });

  it('refuses x_pca terms that do not match the grant envelope or risk policy', async () => {
    const i = input(s);
    asRec(asRec(i.open.x_pca).terms).perTransactionCap = 5000;
    const r = await verifyPcaBinding(i);
    expect(!r.ok && r.reason).toMatch(/do not match the grant/);
    const j = input(s);
    asRec(asRec(j.open.x_pca).terms).merchants = ['merchant_1', 'merchant_2'];
    expect((await verifyPcaBinding(j)).ok).toBe(false);
  });

  it('refuses an open mandate whose AP2 constraints are wider than the PCA terms', async () => {
    const tamper = async (mut: (o: OpenPaymentMandateClaims) => void): Promise<string> => {
      const i = input(s);
      mut(i.open);
      const r = await verifyPcaBinding(i);
      return r.ok ? 'ACCEPTED' : r.reason;
    };
    const find = (o: OpenPaymentMandateClaims, t: string) => asRec(o.constraints.find((c) => c.type === t));
    expect(await tamper((o) => { find(o, 'payment.amount_range').max = 50_001; })).toMatch(/exceeds the PCA per-transaction cap/);
    expect(await tamper((o) => { find(o, 'payment.budget').max = 1001; })).toMatch(/budget exceeds/);
    expect(await tamper((o) => { asRec((find(o, 'payment.allowed_payees').allowed as unknown[])[0]).id = 'merchant_2'; })).toMatch(/outside the PCA allowlist/);
    expect(await tamper((o) => { find(o, 'payment.agent_recurrence').max_occurrences = 6; })).toMatch(/max_occurrences/);
    expect(await tamper((o) => { delete find(o, 'payment.agent_recurrence').max_occurrences; })).toMatch(/max_occurrences/);
    expect(await tamper((o) => { o.constraints = o.constraints.filter((c) => c.type !== 'payment.budget'); })).toMatch(/no budget/);
    expect(await tamper((o) => { o.constraints = o.constraints.filter((c) => c.type !== 'payment.allowed_payees'); })).toMatch(/no allowed_payees/);
    expect(await tamper((o) => { o.exp = (o.exp as number) + 7 * 86_400; })).toMatch(/outlives the PCA period/);
  });

  it('refuses a PCActn that does not commit to this AP2 charge', async () => {
    const other = makeScenario();
    // a perfectly valid PCActn from a different purchase, spliced into this closed mandate
    const i = input(s);
    i.closed.x_pca = asRec(verified(other).closed.x_pca) as JsonObject;
    expect((await verifyPcaBinding(i)).ok).toBe(false);

    // same grant, same agent, but bound to another transaction id
    const rebound = buildPcaPaymentBinding({
      mandate: s.pca, open: s.openPayment, agentJwk: s.agent.publicJwk, agentSecret: s.agentEd.secretKey, audience: s.pcaAudience, counter: 2,
      transactionId: 'another-transaction', payee: MERCHANT, amount: { amount: s.amountMinor, currency: 'USD' }, instrumentId: 'card_4242', now: NOW_MS + 10_000,
    });
    const j = input(s);
    j.closed.x_pca = rebound;
    const r = await verifyPcaBinding(j);
    expect(!r.ok && r.reason).toMatch(/nonce does not bind/);
  });

  it('refuses the same PCActn presented under a different AP2 agent key or a different open mandate', async () => {
    const i = input(s);
    i.open.cnf = { jwk: generateAp2KeyPair().publicJwk };
    expect(((await verifyPcaBinding(i)) as { reason?: string }).reason).toMatch(/nonce does not bind/);
    const j = input(s, { openHash: 'a-different-open-mandate-hash' });
    expect(((await verifyPcaBinding(j)) as { reason?: string }).reason).toMatch(/nonce does not bind/);
  });

  it('refuses when the AP2 amount, payee or instrument no longer matches what the PCActn committed', async () => {
    const amount = input(s);
    amount.closed.payment_amount = { amount: s.amountMinor + 1, currency: 'USD' };
    expect(((await verifyPcaBinding(amount)) as { reason?: string }).reason).toMatch(/differs from the mandate payment_amount/);
    const payee = input(s);
    payee.closed.payee = { ...MERCHANT, id: 'merchant_2' };
    expect((await verifyPcaBinding(payee)).ok).toBe(false);
    const instr = input(s);
    instr.closed.payment_instrument = { id: 'card_9999', type: 'card' };
    expect(((await verifyPcaBinding(instr)) as { reason?: string }).reason).toMatch(/nonce does not bind/);
  });

  it('refuses an expired PCActn and a missing x_pca', async () => {
    const r = await verifyPcaBinding(input(s, { now: NOW_MS + 10 * 3_600_000 }));
    expect(!r.ok && r.reason).toMatch(/PCActn/);
    const none = input(s);
    delete (none.closed as PaymentMandateClaims).x_pca;
    expect(((await verifyPcaBinding(none)) as { reason?: string }).reason).toMatch(/no x_pca PCActn/);
    const noOpen = input(s);
    delete (noOpen.open as OpenPaymentMandateClaims).x_pca;
    expect(((await verifyPcaBinding(noOpen)) as { reason?: string }).reason).toMatch(/no x_pca grant/);
  });
});

describe('human co-sign (PCA step-up) on a charge above the auto-approve threshold', () => {
  const s = makeScenario({ quantity: 1, unitPrice: 12_000 }); // 120 USD > Y = 50 USD
  const bad = makeScenario({ quantity: 1, unitPrice: 12_000 });

  it('without a threshold verifier the verifier refuses to accept it silently', async () => {
    const r = await verifyPcaBinding(input(s));
    expect(!r.ok && r.reason).toMatch(/needs a threshold of 3/);
  });

  it('with the principal + guardian co-sign and a threshold verifier it is accepted', async () => {
    const withCosign = makeScenario({ quantity: 1, unitPrice: 12_000, cosign: true });
    const hooks = { threshold: createThresholdVerifier({ signerSet: withCosign.signerSet, t: 3 }) };
    const r = await verifyPcaBinding(input(withCosign, { hooks, mandate: withCosign.pca }));
    expect(r.ok, r.ok ? '' : r.reason).toBe(true);
  });

  it('a co-sign by the wrong key, or none at all, is refused by the threshold verifier', async () => {
    const hooks = { threshold: createThresholdVerifier({ signerSet: bad.signerSet, t: 3 }) };
    const r = await verifyPcaBinding(input(bad, { hooks }));
    expect(r.ok).toBe(false);
    const forged = makeScenario({ quantity: 1, unitPrice: 12_000, cosign: true });
    const stranger = makeScenario({ quantity: 1, unitPrice: 12_000, cosign: true });
    const r2 = await verifyPcaBinding(input(forged, { hooks: { threshold: createThresholdVerifier({ signerSet: stranger.signerSet, t: 3 }) } }));
    expect(r2.ok).toBe(false);
  });

  it('R2-09: a threshold hook built for t=1 cannot satisfy a charge that needs t=3', async () => {
    const withCosign = makeScenario({ quantity: 1, unitPrice: 12_000, cosign: true });
    const hooks = { threshold: createThresholdVerifier({ signerSet: withCosign.signerSet, t: 1 }) };
    const r = await verifyPcaBinding(input(withCosign, { hooks }));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/enforced t=1|threshold/);
  });

  it('with the live PCA mandate, a step-up charge whose PCActn has no threshold field is refused', async () => {
    const hooks = { threshold: createThresholdVerifier({ signerSet: s.signerSet, t: 1 }) };
    const r = await verifyPcaBinding(input(s, { hooks, mandate: s.pca }));
    expect(!r.ok && r.reason).toMatch(/co-sign|enforced t=1/);
  });
});

describe('risk claim', () => {
  it('rounds up to 12 decimals so ratios like 1/3 are signable, and never rounds down', () => {
    expect(riskRatio(100, 300)).toBeGreaterThanOrEqual(1 / 3);
    expect(String(riskRatio(100, 300)).length).toBeLessThanOrEqual(15);
    expect(riskRatio(300, 300)).toBe(1);
    expect(riskRatio(400, 300)).toBe(1);
    expect(riskRatio(0, 300)).toBe(0);
    expect(riskRatio(75, 100)).toBe(0.75);
  });

  it('an agent that understates its own risk is refused', async () => {
    const s = makeScenario();
    const i = input(s);
    asRec(asRec(i.closed.x_pca).pcactn).risk_claim = { r: 0, inputs: {} }; // 40 of 500 is r = 0.08
    const r = await verifyPcaBinding(i);
    expect(r.ok).toBe(false); // the signature no longer covers the edited body, or the understatement is caught
  });
});

describe('terms to AP2 constraints', () => {
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const mk = (over: Record<string, unknown> = {}) =>
    buildPaymentMandate({
      principalSecret: principal.secretKey, principalPublic: pubOf(principal), agentPublic: pubOf(agent), merchants: ['merchant_1'], currency: 'USD',
      perTransactionCap: 500, autoApproveThreshold: 50, cumulativeCap: 1000, now: NOW_MS, ...over,
    });

  it('produces integer minor-unit ranges and a major-unit budget the official SDK reads identically', () => {
    const c = paymentConstraintsFromTerms(mk().terms, [MERCHANT], 'REF');
    expect(c).toContainEqual({ type: 'payment.amount_range', currency: 'USD', min: 0, max: 50_000 });
    expect(c).toContainEqual({ type: 'payment.budget', currency: 'USD', max: 1000 });
    expect(c).toContainEqual({ type: 'payment.reference', conditional_transaction_id: 'REF' });
  });

  it('refuses what cannot be expressed: unknown merchant, JPY budget, inexact caps, no expiry', () => {
    expect(() => paymentConstraintsFromTerms(mk().terms, [], 'REF')).toThrow(/no merchant descriptor/);
    expect(() => paymentConstraintsFromTerms(mk({ currency: 'JPY' }).terms, [MERCHANT], 'REF')).toThrow(/unsupported/);
    const a = generateAp2KeyPair();
    const issuer = generateAp2KeyPair('k');
    expect(() => openPaymentMandateFromPca(mk(), { issuer: { privateKey: issuer.privateKey, kid: 'k' }, agentJwk: a.publicJwk, merchants: [MERCHANT], iat: NOW_S, checkoutReference: 'R' })).toThrow(/exp is required/);
    expect(() => openPaymentMandateFromPca(mk({ periodMs: 3_600_000 }), { issuer: { privateKey: issuer.privateKey, kid: 'k' }, agentJwk: a.publicJwk, merchants: [MERCHANT], iat: NOW_S, exp: NOW_S + 7200, checkoutReference: 'R' })).toThrow(/must not exceed/);
  });
});

// R3-01: the grant in the open mandate is a ROOT capability; a pure-PQ root must verify under the principal's pin, never its own pq_pk.
describe('R3-01: forged pure-PQ x_pca grant', () => {
  const s = makeScenario();
  const forged = () => {
    const atk = generateKeyPair();
    const base = verified(s);
    const real = asRec(asRec(base.open.x_pca).grant) as unknown as { holder: string; caveats: never[] };
    const root = mintRoot({
      principalSecret: atk.secretKey,
      principalPublic: pubOf(s.principal),
      holder: real.holder,
      caveats: real.caveats,
      suite: { alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(new Uint8Array(32).fill(3)) },
    });
    const open = structuredClone(base.open) as OpenPaymentMandateClaims;
    (open.x_pca as Record<string, unknown>).grant = root as unknown as JsonObject;
    return { ...base, open };
  };

  it('is refused at the grant step (the forger signed under its own ML-DSA key and named the principal)', async () => {
    const r = await verifyPcaBinding(input(s, forged()));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/PCA grant:.*pinned/);
    // still refused when the real principal has pinned ITS key (the attacker's key is not the pin)
    const r2 = await verifyPcaBinding(input(s, { ...forged(), pqPins: { [pubOf(s.principal)]: encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(4)).publicKey) } }));
    expect(!r2.ok && r2.reason).toMatch(/PCA grant:/);
  });
});
