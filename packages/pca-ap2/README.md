# @atlasauth/pca-ap2

AP2 (Agent Payments Protocol) wire-compatibility for PCA. AP2 — donated to the FIDO Alliance, v0.2 shape (2026-04-28) — models agentic payments as a chain of signed Verifiable Digital Credentials: **IntentMandate → CartMandate → PaymentMandate**. That chain is a near-isomorphism of PCA's attenuating capability chain, so this package bridges the two.

**PCA governs. AP2 is the payment-mandate wire. x402 / Stripe Shared Payment Tokens settle. Compose them.**

- **PCA** (`@atlasauth/pca`, `@atlasauth/pca-payments`) = the authority / budget layer: who may spend, how much, until when, and when a human must co-sign.
- **AP2** = the Intent→Cart→Payment VDC chain other parties verify.
- **x402 / Stripe SPT** = the settlement rails that actually move value, fed by PCA's governance.

This is a bridge, not a replacement.

## ⚠️ Verify against the AP2 schemas before production

AP2 is a moving target and its mandate field-level signing roles differ between secondary sources (e.g. whether a cart is co-signed by both merchant and user, and whether the step is called "Cart" or "Checkout"), and it layers over UCP (`ucp.dev`), whose dated releases move the payment token between `payment_data.token` and `payment.instruments[*].credential.token`. This package models the v0.2 Intent/Cart/Payment chain **to the best public understanding** and **must be validated against the AP2 repository `schemas/` and the official spec at [ap2-protocol.org](https://ap2-protocol.org) before any production wire use.** PCA-native terms that AP2 has no field for are carried in a namespaced `x_pca` extension (so the chain round-trips back to PCA terms); those fields are non-standard by construction.

## Usage

```ts
import { buildPaymentMandate, authorizeCharge } from '@atlasauth/pca-payments';
import {
  toAP2IntentMandate, toAP2CartMandate, toAP2PaymentMandate,
  chainMandates, fromAP2Mandate, x402Settlement, stripeSptSettlement,
} from '@atlasauth/pca-ap2';

// 1. A PCA payment mandate (the authority layer).
const mandate = buildPaymentMandate({
  principalSecret, principalPublic, agentPublic,
  merchants: ['acme'], currency: 'USD',
  perTransactionCap: 500, autoApproveThreshold: 50, cumulativeCap: 1000,
});

// 2. Map it down the AP2 VDC chain (each step narrows, never amplifies).
const intent = toAP2IntentMandate(mandate, { issuerPublic, issuerSecret });        // user signs
const cart   = toAP2CartMandate(intent,
  { merchant: 'acme', items: [{ name: 'Seat', quantity: 1, unit_price: { currency: 'USD', value: 120 } }] },
  { issuerPublic: merchantPublic, issuerSecret: merchantSecret });                 // merchant signs

// The human-present signal maps from the PCA decision: tier-3 human step-up ⇒ human_present = true.
const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 120, currency: 'USD' });
const payment = toAP2PaymentMandate(cart, {
  issuerPublic: payerPublic, issuerSecret: payerSecret,
  paymentMethod: { type: 'card' }, pcaTier: decision.t, intent,
});

// 3. Assemble + verify the chain is a non-amplifying narrowing (mirrors PCA attenuation).
const chain = chainMandates(intent, cart, payment);
chain.verify(); // { ok: true, reasons: [] }

// 4. Parse back toward PCA terms.
fromAP2Mandate(intent); // { type: 'IntentMandate', merchants: ['acme'], perTransactionCap: 500, ... }

// 5. Hand the verified payment mandate to a settlement rail (structural; no network here).
x402Settlement.settle(payment, { resourceUrl, payTo, network: 'base' });
stripeSptSettlement.settle(payment, { payTo: 'acct_merchant' });
```

### Human-present mapping

| PCA decision                                  | AP2 `human_present` |
| --------------------------------------------- | ------------------- |
| tier 1 — autonomous (amount ≤ Y, budget OK)   | `false` (human-not-present) |
| tier 3 — human step-up / co-sign required     | `true` (human-present) |

### Settlement backends

`x402Settlement` and `stripeSptSettlement` implement `SettlementBackend` and are **structural only** — they turn a (presumed-verified) Payment Mandate into the rail's wire shape (x402's HTTP-402 challenge + `X-PAYMENT` header; Stripe's Shared-Payment-Token charge in minor units). They perform no network I/O; they are the hooks a real integration fills in, fed by PCA's governance decision.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
