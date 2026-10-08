# @atlasauth/pca-payments

Reference prototype: a payment mandate (merchant/category allowlist, per-transaction + cumulative caps, auto-approve threshold Y, hard ceiling X, bonded refunds) expressed as a PCA Root Intent Grant — PCA as the authorization layer for agentic payments (AP2 / x402).

## Install

```sh
npm i @atlasauth/pca-payments
```

Depends on the core `@atlasauth/pca` (installed transitively).

## Usage

```ts
import { buildPaymentMandate, authorizeCharge, settleCharge } from '@atlasauth/pca-payments';

// Encode the mandate as a PCA Root Intent Grant + initial trust budget.
const mandate = buildPaymentMandate({
  principalSecret, principalPublic, agentPublic,
  merchants: ['acme'],
  currency: 'USD',
  perTransactionCap: 200,     // X — hard ceiling on one charge
  autoApproveThreshold: 50,   // Y — at/under ⇒ autonomous, over ⇒ human co-sign
  cumulativeCap: 1000,        // total autonomous spend between co-signs
});

// Run a charge through the PCA decision (pure; never throws).
const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 40, currency: 'USD' });
// decision.outcome: 'auto' | 'step_up' | 'deny'

const next = settleCharge(mandate, decision); // thread the debited budget to the next charge
```

This computes a mandate decision and the derived trust budget; it does not authorize on its own. The resource server's verifier remains the authority at run time.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
