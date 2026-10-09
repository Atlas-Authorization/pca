# @atlasauth/pca-ap2

A mandate chain for Proof-Carrying Authority (PCA) modelled on AP2 (Agent Payments Protocol, FIDO Alliance). AP2 models agentic payments as a chain of mandates: an intent, then a checkout, then a payment. That chain closely mirrors PCA's attenuating capability chain, and this package maps one onto the other as signed credentials named IntentMandate, CartMandate and PaymentMandate. These credentials are a PCA rendition of the concepts and are not the SD-JWT mandate format that the current AP2 schemas define (see Status).

PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the mandate wire other parties verify. Settlement rails (x402, Stripe Shared Payment Tokens) move the value, fed by PCA's decision. This is a bridge, not a replacement.

## Install

```sh
npm i @atlasauth/pca-ap2
```

Depends on `@atlasauth/pca` and `@atlasauth/pca-payments` (installed transitively; you will usually import `buildPaymentMandate` from the latter).

## Usage

```ts
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { buildPaymentMandate, authorizeCharge } from '@atlasauth/pca-payments';
import {
  toAP2IntentMandate, toAP2CartMandate, toAP2PaymentMandate,
  chainMandates, fromAP2Mandate, x402Settlement, stripeSptSettlement,
} from '@atlasauth/pca-ap2';

const principal = generateKeyPair(), merchantKey = generateKeyPair();
const payerKey = generateKeyPair(), agentKey = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

// 1. A PCA payment mandate (the authority layer).
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey, principalPublic: pub(principal), agentPublic: pub(agentKey),
  merchants: ['acme'], currency: 'USD',
  perTransactionCap: 500, autoApproveThreshold: 50, cumulativeCap: 1000,
});

// 2. Map it down the AP2 chain; each step narrows, never widens.
const intent = toAP2IntentMandate(mandate, { issuerPublic: pub(principal), issuerSecret: principal.secretKey });
const cart = toAP2CartMandate(
  intent,
  { merchant: 'acme', items: [{ sku: 'seat', name: 'Seat', quantity: 1, unit_price: { currency: 'USD', value: 120 } }] },
  { issuerPublic: pub(merchantKey), issuerSecret: merchantKey.secretKey },
);
const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 120, currency: 'USD' }); // step-up, t = 3
const payment = toAP2PaymentMandate(cart, {
  issuerPublic: pub(payerKey), issuerSecret: payerKey.secretKey,
  paymentMethod: { type: 'card' }, pcaTier: decision.t, intent,
});

// 3. Verify the chain is a non-amplifying narrowing.
chainMandates(intent, cart, payment).verify(); // { ok: true, reasons: [] }

// 4. Parse back toward PCA terms.
fromAP2Mandate(intent); // { type: 'IntentMandate', merchants: ['acme'], perTransactionCap: 500, ... }

// 5. Build the rail's wire shape from the payment mandate (structural, no network).
x402Settlement.settle(payment, { resourceUrl: 'https://api.example.com/report', payTo: '0xabc', network: 'base' });
stripeSptSettlement.settle(payment, { payTo: 'acct_merchant' });
```

### Human-present mapping

| PCA decision | AP2 `human_present` |
| --- | --- |
| tier 1: autonomous (within the auto-approve threshold and budget) | `false` |
| tier 3: human step-up or co-sign required | `true` |

## API

- Mapping: `toAP2IntentMandate`, `toAP2CartMandate`, `toAP2PaymentMandate`, `fromAP2Mandate`.
- Signing and chain: `signMandate`, `verifyMandate`, `mandateHash`, `chainMandates`, `verifyAP2Chain`.
- Settlement hooks: `x402Settlement`, `stripeSptSettlement` (the `SettlementBackend` interface).

## Status

Experimental, and **not wire-compatible with the current AP2 specification**. The official AP2 JSON Schemas (github.com/google-agentic-commerce/AP2 at commit e1ea56d, 2026-04-29) define SD-JWT mandates (`mandate.checkout.1`, `mandate.payment.1` and the open variants) with integer minor-unit amounts. This package emits Ed25519-signed, W3C-style credentials with decimal amounts, so its output fails those schemas (the tests pin exactly which required claims are missing). Use it to express a PCA grant as an Intent, Cart and Payment chain between parties that both use this package; do not present its output to an AP2 verifier. PCA-specific terms that AP2 has no field for are carried in a namespaced, non-standard `x_pca` extension.

Validated: the official schemas and the example payloads from the AP2 documentation are committed with source URLs and sha256 and checked with Ajv (the documented closed and open payment mandates validate, and the encoded SD-JWT examples are internally consistent). The chain's own signature, hash-binding and non-amplifying-narrowing checks are covered by the package tests.

The settlement backends are structural only: they turn a payment mandate into an x402 HTTP-402 challenge or a Stripe Shared-Payment-Token charge shape (minor units) and perform no network I/O. The x402 output is checked against the x402 v1 specification (field set, atomic-unit `maxAmountRequired`, `maxTimeoutSeconds`, standard-base64 `X-PAYMENT`); the `X-PAYMENT` payload is a placeholder envelope, not a signed authorization, and `asset` should be supplied as the token contract address. The Stripe shape has no official vector behind it. Settlement backends assume the mandate has already been verified. The cryptography is unaudited.

## License

MIT - see LICENSE
