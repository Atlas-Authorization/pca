# @atlasauth/pca-payments

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

**Experimental prototype.** A payment mandate (merchant and category allowlists, per-transaction and cumulative caps, an auto-approve threshold, a hard ceiling, and bonded refunds) expressed as a Proof-Carrying Authority (PCA) Root Intent Grant, for agentic payments. A charge at or under the auto-approve threshold is autonomous; above it needs a human co-sign; off-allowlist, wrong-currency or over-ceiling charges are denied.

## Install

```sh
npm i @atlasauth/pca-payments
```

Depends on `@atlasauth/pca`.

## Usage

```ts
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { buildPaymentMandate, authorizeCharge, settleCharge } from '@atlasauth/pca-payments';

const principal = generateKeyPair();
const agent = generateKeyPair();

// Encode the mandate as a PCA Root Intent Grant + initial trust budget.
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['acme'],
  currency: 'USD',
  perTransactionCap: 200,     // X — hard ceiling on one charge
  autoApproveThreshold: 50,   // Y — at/under ⇒ autonomous, over ⇒ human co-sign
  cumulativeCap: 1000,        // total autonomous spend between co-signs
});

const storedGrant = mandate.grant; // built here; a server loads it from its own store by the grant id
// Run a charge through the PCA decision against the grant YOU verified or stored (never the one a request carries).
// A mandate whose grant, terms or policy differ from that grant throws MandateGrantError (code
// 'mandate_grant_mismatch' / 'mandate_terms_mismatch'; 'verified_grant_required' without one).
const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 40, currency: 'USD' }, storedGrant);
// decision.outcome: 'auto' | 'step_up' | 'deny'

const next = settleCharge(mandate, decision); // thread the debited budget to the next charge
```

`chargeToPCActn(mandate, charge, { signerSecret, aud, counter })` builds the signed PCActn for a charge, and `openChargeBond` opens an optimistic bonded claim for dispute and refund handling. `applyHumanCosign` restores the autonomous budget after a human co-sign.

## Status

Experimental. `authorizeCharge` computes a mandate decision and the derived trust budget; it does not authorize on its own, and the resource server's verifier remains the authority at run time. Amounts are integer minor units: `authorizeCharge` denies a fractional, negative, NaN or unsafe amount (reason `amount_not_integer_minor_units`) and `chargeToPCActn` throws; pass `strictMinorUnits: true` to `buildPaymentMandate` to require integer terms too. The charge must be built by your server from its own order, never from a value the agent supplies. For a cumulative cap that holds across processes and concurrent charges, use `authorizeChargeAtomic` with a durable `ChargeBudgetStore` (an atomic compare-and-set; a missing store throws `ChargeStoreError`); `@atlasauth/pca-payments/testing` has a single-process reference store for tests. Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca); its cryptography has not been independently audited.

## License

MIT - see LICENSE
