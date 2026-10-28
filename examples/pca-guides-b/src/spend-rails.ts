/**
 * Put the spending limits on the card too. A virtual card carries the same limits as the mandate, and every card
 * authorization is answered by the same decision the agent's own charge would get. The card network is a second line of defence:
 * it never allows what the mandate would refuse, and it declines on a step-up, a timeout or any error.
 *
 * Stripe is faked here: the "events" are plain objects shaped like Stripe's Issuing authorization requests and signed with a
 * local test secret, so the script runs offline.
 *
 * Run it:  npm run spend-rails      (exits nonzero if any outcome is not the expected one)
 */
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate, createRailAuthorizer, railLimits, reconcileSettlement } from '@atlasauth/pca-payments';
import { createStripeIssuingWebhook, signStripePayload, stripeCardParams, stripeSettlementFromTransaction } from '@atlasauth/pca-payments/stripe-issuing';
import { memoryChargeBudgetStore } from '@atlasauth/pca-payments/testing';
import { expectOutcome, finish } from './check.js';

const NOW = 1_800_000_000_000;
const SECRET = 'example-signing-secret'; // the webhook signing secret you would get from your Stripe dashboard
const MERCHANT = '1234567890';

// Amounts are integer minor units (cents): the person lets the agent spend $5 at a time, $10 in total, then asks again.
const principal = generateKeyPair();
const agent = generateKeyPair();
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: [MERCHANT],
  categories: ['5734', '5817'], // software stores, digital goods
  currency: 'USD',
  perTransactionCap: 800,
  autoApproveThreshold: 500,
  cumulativeCap: 1000,
  periodMs: 86_400_000,
  now: NOW,
});

// 1. The card's limits are a copy of the mandate's.
const limits = railLimits(mandate, NOW);
expectOutcome('card limits', [limits.perAuthorizationMax, limits.totalMax, limits.categories], [500, 1000, ['5734', '5817']]);
const card = stripeCardParams(limits, {
  cardholder: 'ich_example',
  categoryNames: { '5734': 'computer_software_stores', '5817': 'digital_goods_applications' },
});
expectOutcome('Stripe card: per-authorization limit', [card['spending_controls[spending_limits][0][amount]'], card['spending_controls[spending_limits][0][interval]']], ['500', 'per_authorization']);
expectOutcome('Stripe card: lifetime limit', [card['spending_controls[spending_limits][1][amount]'], card['spending_controls[spending_limits][1][interval]']], ['1000', 'all_time']);

// 2. The webhook for authorization requests.
const request = (authId: string, o: { amount?: number; mcc?: string; merchant?: string; card?: string } = {}): string =>
  JSON.stringify({
    type: 'issuing_authorization.request',
    data: {
      object: {
        id: authId,
        card: { id: o.card ?? 'ic_example_1' },
        merchant_data: { network_id: o.merchant ?? MERCHANT, category_code: o.mcc ?? '5734' },
        pending_request: { amount: o.amount ?? 400, currency: 'usd' },
      },
    },
  });

function makeHook(onStepUp?: (id: string) => void) {
  const authorize = createRailAuthorizer({
    instruments: (cardId) => (cardId === 'ic_example_1' ? { mandate, grant: mandate.grant } : undefined),
    store: memoryChargeBudgetStore(), // production: a durable store with a conditional write
    now: () => NOW,
    onStepUp: (x) => { onStepUp?.(x.id); },
  });
  const hook = createStripeIssuingWebhook({ secret: SECRET, authorize, nowSec: () => Math.floor(NOW / 1000) });
  const post = async (body: string, signature = signStripePayload(body, SECRET, Math.floor(NOW / 1000))) => {
    const r = await hook({ rawBody: body, signature });
    return [r.status, r.status === 200 ? (JSON.parse(r.body) as { approved?: boolean }).approved : undefined] as const;
  };
  return { post };
}

const stepUps: string[] = [];
const a = makeHook((id) => stepUps.push(id));
expectOutcome('$4 at the listed merchant', await a.post(request('iauth_1')), [200, true]);
expectOutcome('$6: over the $5 line, a person must decide', await a.post(request('iauth_2', { amount: 600 })), [200, false]);
expectOutcome('the principal was told about the step-up', stepUps, ['iauth_2']);
expectOutcome('$9: over the $8 ceiling', await a.post(request('iauth_3', { amount: 900 })), [200, false]);
expectOutcome('another merchant', await a.post(request('iauth_4', { merchant: '9999999999' })), [200, false]);
expectOutcome('a gambling category', await a.post(request('iauth_5', { mcc: '7995' })), [200, false]);
expectOutcome('a card the mandate does not know', await a.post(request('iauth_6', { card: 'ic_other' })), [200, false]);
const unsigned = request('iauth_7');
expectOutcome('a forged signature: nothing is decided', await a.post(unsigned, signStripePayload(unsigned, 'not-the-secret', Math.floor(NOW / 1000))), [400, undefined]);

// 3. The $10 total is spent atomically: the third $4 does not fit.
const b = makeHook();
const answers = [await b.post(request('iauth_8')), await b.post(request('iauth_9')), await b.post(request('iauth_10'))];
expectOutcome('three $4 charges against $10', answers.map((r) => r[1]), [true, true, false]);

// 4. Settlement: what the network captured must fit what was approved.
const approved = { id: 'iauth_8', amount: 400, currency: 'usd', merchantId: MERCHANT };
const capture = (cents: number) => stripeSettlementFromTransaction({ type: 'capture', authorization: 'iauth_8', amount: -cents, currency: 'usd', merchant_data: { network_id: MERCHANT } });
const exact = capture(400);
const over = capture(450);
expectOutcome('captured exactly $4', exact === undefined ? 'unreadable' : reconcileSettlement(approved, exact), { ok: true });
expectOutcome('captured $4.50: freeze the grant', over === undefined ? 'unreadable' : reconcileSettlement(approved, over), { ok: false, reasons: ['settled_more_than_approved'], action: 'freeze_grant' });

finish();
