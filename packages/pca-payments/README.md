# @atlasauth/pca-payments

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

// Run a charge through the PCA decision (pure; never throws).
const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 40, currency: 'USD' });
// decision.outcome: 'auto' | 'step_up' | 'deny'

const next = settleCharge(mandate, decision); // thread the debited budget to the next charge
```

`chargeToPCActn(mandate, charge, { signerSecret, aud, counter })` builds the signed PCActn for a charge, and `openChargeBond` opens an optimistic bonded claim for dispute and refund handling. `applyHumanCosign` restores the autonomous budget after a human co-sign.

## Status

Experimental. `authorizeCharge` computes a mandate decision and the derived trust budget; it does not authorize on its own, and the resource server's verifier remains the authority at run time. Use integer minor units for amounts in production to avoid float drift. Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca); its cryptography has not been independently audited.

## License

MIT - see LICENSE
