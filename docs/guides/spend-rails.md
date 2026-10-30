---
title: Spend rails, a virtual card with the same limits
order: 16
---

# Spend rails: a virtual card with the same limits

**Problem.** You let an agent pay for things. A [payment mandate](./agent-payments-and-approvals.md) decides each charge the agent asks for, but the agent still needs money to spend, and a card number is ambient authority: anyone who has it can charge it for anything.

**Fix.** Issue a virtual card whose limits are a copy of the mandate's, and answer every real-time authorization request from the card network with the same decision the mandate would give. The card network is a second line of defence. It never approves what the mandate would refuse. It declines on a step-up, a timeout or any error.

```bash
npm install @atlasauth/pca @atlasauth/pca-payments
```

> Nothing on this page calls Stripe or a card network. The Stripe adapter turns documented event shapes into decisions, and the example below feeds it hand-made events signed with a local secret. To go live you add your own Stripe account, create the card, and point the Issuing authorization webhook at your handler.

## 1. Start from a mandate

Amounts are integer minor units (cents).

```ts
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate } from '@atlasauth/pca-payments';

const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['1234567890'],       // the merchant ids the card network reports
  categories: ['5734', '5817'],    // merchant category codes
  currency: 'USD',
  perTransactionCap: 800,          // one charge above this is denied
  autoApproveThreshold: 500,       // above this a person decides
  cumulativeCap: 1000,             // the agent's own spend before a person refills it
  periodMs: 86_400_000,
});
```

## 2. Mint the card from the limits

```ts
import { railLimits } from '@atlasauth/pca-payments';
import { stripeCardParams } from '@atlasauth/pca-payments/stripe-issuing';

const limits = railLimits(mandate, Date.now());
// { currency: 'USD', perAuthorizationMax: 500, totalMax: 1000, categories: ['5734', '5817'], merchants: [...], expiresAt }

const params = stripeCardParams(limits, {
  cardholder: 'ich_example',
  categoryNames: { '5734': 'computer_software_stores', '5817': 'digital_goods_applications' },
});
// POST these form fields to Stripe's card-creation endpoint with your own client
```

`railLimits` throws instead of producing a card that would be wider than the grant:

- no autonomous spend left means no card (a bigger card would need a person's co-sign);
- a mandate with no category list and no category traits is refused unless you pass `allowAnyCategory: true`;
- action traits of the form `mcc.c5734` only narrow the categories, and an empty intersection throws.

`stripeCardParams` also throws if you forget the Stripe name for one of the categories.

## 3. Answer authorization requests

```ts
import { createRailAuthorizer } from '@atlasauth/pca-payments';
import { createStripeIssuingWebhook } from '@atlasauth/pca-payments/stripe-issuing';
import { memoryChargeBudgetStore } from '@atlasauth/pca-payments/testing';

const authorize = createRailAuthorizer({
  instruments: (cardId) => (cardId === 'ic_example_1' ? { mandate, grant: mandate.grant } : undefined), // your own lookup
  store: memoryChargeBudgetStore(),   // production: a durable store with a conditional write
  onStepUp: (a) => notifyPrincipal(a), // a person cannot approve at a card terminal; tell them instead
});

const handler = createStripeIssuingWebhook({ secret: signingSecret, authorize });

// in your HTTP route, with the RAW body (not parsed JSON):
const reply = await handler({ rawBody, signature: req.headers['stripe-signature'] });
// reply = { status, headers, body }: send all three back as they are
```

The webhook handler:

- verifies the signature (with a five-minute tolerance) and answers `400` to a bad one, so nothing is decided;
- answers `200 {"approved": true}` only when the mandate says `auto`, and `200 {"approved": false}` for everything else;
- never sends an `amount`, so it never changes the held amount;
- sets the `Stripe-Version` header Stripe requires.

Set the timeout behavior of your Stripe endpoint to **decline**. The authorizer also gives up on its own after 1.5 seconds (`latencyBudgetMs`) and declines, because Stripe waits two.

The cumulative budget is spent atomically per authorization. If a decision finishes after the timeout it may have debited the budget without sending an approval. That under-spends, which is the safe direction. A person refills it with a co-sign.

## 4. Check what settled

Approving is not the end. When the capture arrives, compare it with what you approved:

```ts
import { reconcileSettlement } from '@atlasauth/pca-payments';
import { stripeSettlementFromTransaction } from '@atlasauth/pca-payments/stripe-issuing';

const settled = stripeSettlementFromTransaction(transactionEvent.data.object); // undefined if it is not a capture
if (settled) {
  const r = reconcileSettlement({ id: 'iauth_8', amount: 400, currency: 'usd', merchantId: '1234567890' }, settled);
  // { ok: true }  or  { ok: false, reasons: ['settled_more_than_approved'], action: 'freeze_grant' }
}
```

Any excess, another merchant or currency, or a second capture comes back as `freeze_grant`. You apply it: freeze the grant, escalate the rest of that scope, tell the principal.

## Expected output

The companion script (`npm run spend-rails` in the `pca-guides-b` examples):

```
ok   card limits -> [500,1000,["5734","5817"]]
ok   $4 at the listed merchant -> [200,true]
ok   $6: over the $5 line, a person must decide -> [200,false]
ok   the principal was told about the step-up -> ["iauth_2"]
ok   another merchant -> [200,false]
ok   a forged signature: nothing is decided -> [400,null]
ok   three $4 charges against $10 -> [true,true,false]
ok   captured $4.50: freeze the grant -> {"action":"freeze_grant","ok":false,"reasons":["settled_more_than_approved"]}

All outcomes as expected.
```

## When it declines

| Reason in the verdict | Meaning |
|---|---|
| `step_up_required` | Over the auto-approve line, or the autonomous budget is used up. A person has to decide |
| `instrument_unknown` | Your `instruments` lookup does not know this card |
| `merchant_unknown` | The request carries no merchant id (the allowlist is written in merchant ids, never display names) |
| `amount_not_positive_minor_units` | Not a positive integer |
| `latency_budget_exceeded` | Not decided in time |
| `authorizer_error` | Your lookup threw; the answer is a decline |

A denied charge also carries the mandate's own reasons (wrong merchant, wrong category, wrong currency, over the ceiling). See the decisions in [Agent payments](./agent-payments-and-approvals.md).

## Next

- Decide charges the agent makes itself, without a card: [Agent payments, risk-priced approvals and wallet permissions](./agent-payments-and-approvals.md).
- Keep an API key out of the agent's hands as well: [Keep API credentials away from the agent](./token-vault-proxy.md).
- Add a second approver for large amounts: [Golden paths](./golden-paths.md).
