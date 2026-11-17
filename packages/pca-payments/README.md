# @atlasauth/pca-payments

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A payment mandate (merchant and category allowlists, per-transaction and cumulative caps, an auto-approve threshold, a hard ceiling, and bonded refunds) expressed as a Proof-Carrying Authority (PCA) Root Intent Grant, for agentic payments. A charge at or under the auto-approve threshold is autonomous; above it needs a human co-sign; off-allowlist, wrong-currency or over-ceiling charges are denied.

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
  perTransactionCap: 20_000,     // X, hard ceiling on one charge (integer minor units: USD 200.00)
  autoApproveThreshold: 5_000,   // Y, at/under = autonomous, over = human co-sign
  cumulativeCap: 100_000,        // total autonomous spend between co-signs
});

const storedGrant = mandate.grant; // built here; a server loads it from its own store by the grant id
// Run a charge through the PCA decision against the grant YOU verified or stored (never the one a request carries).
// A mandate whose grant, terms or policy differ from that grant throws MandateGrantError (code
// 'mandate_grant_mismatch' / 'mandate_terms_mismatch'; 'verified_grant_required' without one).
const decision = authorizeCharge(mandate, { merchant: 'acme', amount: 4_000, currency: 'USD' }, storedGrant);
// decision.outcome: 'auto' | 'step_up' | 'deny'

const next = settleCharge(mandate, decision); // thread the debited budget to the next charge
```

`sharedPaymentTokenLimits(mandate, now)` gives the `usage_limits` of a Stripe Shared Payment Token that fits what the mandate lets an agent spend without a co-sign (threshold, remaining budget, period).

`chargeToPCActn(mandate, charge, { signerSecret, aud, counter })` builds the signed PCActn for a charge, and `openChargeBond` opens an optimistic bonded claim for dispute and refund handling. `applyHumanCosign` restores the autonomous budget after a human co-sign.

## Failure modes

| Missing or wrong | Result |
|---|---|
| No verified grant, or a mandate whose grant, terms or policy are not that grant's | `authorizeCharge` throws `MandateGrantError` (`verified_grant_required`, `mandate_grant_mismatch`, `mandate_terms_mismatch`) |
| Fractional, negative, NaN, unsafe or non-number amount | `deny`, reason `amount_not_integer_minor_units`, nothing debited |
| Merchant not a plain id (empty, contains `*`, not a string) | `deny`, reason `merchant_invalid` |
| Merchant, category or currency off the allowlist; amount above the ceiling X; mandate expired | `deny` |
| Amount above the auto-approve threshold Y, or the cumulative budget cannot cover it | `step_up` (human co-sign), budget unchanged |
| Fractional or non-safe-integer mandate term | `buildPaymentMandate` throws (pass `strictMinorUnits: false` only for a legacy mandate) |
| Merchant id containing `*` or a control character | `buildPaymentMandate` throws |
| No store, or a store without `get` and `compareAndSet` | `ChargeStoreError` |
| Store returns a malformed record (bad version, budget not three finite numbers) | `ChargeStoreError` |
| Stored balance above the signed `bMax` or negative | clamped to `[0, bMax]` before deciding |
| Persistent compare-and-set contention | `deny`, reason `budget_store_conflict`; a co-sign throws instead of being dropped |

## Limits

- Amounts are integer minor units of the mandate currency. There is no currency conversion: a charge in another currency is denied.
- `authorizeCharge` computes a decision and the next budget; it does not move money, and the resource server's verifier remains the authority.
- The cumulative cap holds across processes and concurrent charges only through `authorizeChargeAtomic` with a durable store whose `compareAndSet` is a single conditional write. The single-process store in `/testing` is for tests.
- Build the charge from your own order on the server, never from a value the agent supplies.

## Status

Production. `authorizeCharge` computes a mandate decision and the derived trust budget; it does not authorize on its own, and the resource server's verifier remains the authority at run time. Amounts are integer minor units: `authorizeCharge` denies a fractional, negative, NaN or unsafe amount (reason `amount_not_integer_minor_units`) and `chargeToPCActn` throws; pass `strictMinorUnits: true` to `buildPaymentMandate` to require integer terms too. The charge must be built by your server from its own order, never from a value the agent supplies. For a cumulative cap that holds across processes and concurrent charges, use `authorizeChargeAtomic` with a durable `ChargeBudgetStore` (an atomic compare-and-set; a missing store throws `ChargeStoreError`); `@atlasauth/pca-payments/testing` has a single-process reference store for tests. Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca); its cryptography has not been independently audited.

## License

MIT - see LICENSE
