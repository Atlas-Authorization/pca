# @atlasauth/pca-ap2

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a Proof-Carrying Authority (PCA) grant.

AP2 models agentic payments as a chain of mandates: an open mandate signed by the user's trusted surface that delegates to an agent key and carries constraints, then a closed mandate signed by the agent that settles one concrete purchase. This package issues and verifies the checkout and payment mandates (`mandate.checkout.1`, `mandate.checkout.open.1`, `mandate.payment.1`, `mandate.payment.open.1`) in the SD-JWT format defined by the official AP2 JSON Schemas: integer minor-unit amounts, selective disclosure, ES256 (P-256) keys, and a key-binding JWT at each hop.

PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. The AP2 mandates are the wire other parties verify, and each one carries PCA's proof of the grant (open mandate) or of the individual charge (closed payment mandate). Settlement rails (x402, Stripe Shared Payment Tokens) move the value.

## Install

```sh
npm i @atlasauth/pca-ap2
```

Depends on `@atlasauth/pca` and `@atlasauth/pca-payments` (installed transitively; you will usually build the PCA payment mandate with `buildPaymentMandate` from the latter).

## What it provides

- **Issue**: `issueOpenPaymentMandate`, `issueOpenCheckoutMandate`, `presentClosedCheckout`, `presentClosedPayment`; or from a PCA mandate directly, `openPaymentMandateFromPca` and `openCheckoutMandateFromPca`.
- **Verify**: `verifyCheckoutChain`, `verifyPaymentChain`, and `verifyPurchase` (checkout and payment verified together: the payment must reference the open checkout, settle the closed checkout's `checkout_hash`, and match the quoted payee, currency and total). A verifier must name its own audience and nonce.
- **Constraints**: `checkPaymentConstraints` and `checkCheckoutConstraints` evaluate amount ranges, allowed payees, budgets, recurrence, references and acceptable line items from the disclosed claims. A disclosure the agent withholds cannot widen an open mandate.
- **PCA binding**: `buildPcaPaymentBinding` and `verifyPcaBinding`.
- **Low level**: SD-JWT parsing and strict disclosure processing (`parseSdJwtHop`, `processDisclosures`, `splitChain`), schema-level validators (`paymentMandateProblems` and the three siblings), and `toMinorUnits` / `fromMinorUnits`.
- **Settlement shapes**: `x402Settlement`, `stripeSptSettlement` (the `SettlementBackend` interface).

## PCA binding

The PCA proof travels inside the mandate as a namespaced `x_pca` claim, so it is covered by the issuer's or agent's signature and by the next hop's `sd_hash`:

| Mandate | `x_pca` | Meaning |
| --- | --- | --- |
| open (checkout or payment) | `{ v, grant, terms }` | the principal-signed PCA grant and the terms it was minted from |
| closed payment | `{ v, charge, pcactn }` | the agent-signed PCA action proof that authorises exactly this charge |

The PCActn's signed nonce commits to the transaction id, payee, amount, instrument, the open mandate's `sd_hash` and the thumbprint of the agent's AP2 key, so replaying the proof under another mandate, charge or agent key fails. The official schemas do not forbid additional mandate claims and the reference SDK ignores unknown ones; both are tested, so `x_pca` does not affect schema validity or reference verification. Verifiers that do not know PCA simply ignore it. A charge above the auto-approve threshold carries a threshold co-signature in the PCActn.

`verifyPcaBinding` checks the grant signature and expected principal, that the `x_pca` terms agree with the grant envelope and with the AP2 constraints (AP2 constraints wider than the PCA terms are refused), the PCActn chain and signature, and the commitment above. When the charge's risk needs a threshold of t > 1, the `hooks.threshold` verifier must report that it enforced at least that `t` (build it with `createThresholdVerifier({ signerSet, t })`); a hook built for a smaller `t` is refused, as in the core verifier (breaking).

**The policy decision always runs on the verifier's own state (breaking).** `mandate` (the PCA mandate state you hold, with its live budget) is required, and `recentChargeTimes` (from your own records) is required when the mandate limits the charge count; otherwise `verifyPcaBinding` throws `PcaBindingError` (`mandate_required` / `charge_history_required`). The mandate must be bound to the verified grant (`authorizeCharge` refuses a different grant or terms), so the cumulative budget and the charge-count rate limit are always enforced.

## Status

Experimental. Single use and cumulative spend: `redeemPurchase(checkout, payment, options, ledger)` verifies a purchase and redeems it once, taking the usage context from a durable `PurchaseLedger` (an atomic `reserve` / `release`; a missing or failing ledger denies) instead of a caller-supplied one. A usage context with a NaN, negative or fractional counter is refused by the budget and recurrence constraints. `@atlasauth/pca-ap2/testing` has a single-process reference ledger for tests.

 Mandates are checked against the official AP2 JSON Schemas and documentation at github.com/google-agentic-commerce/AP2, commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (2026-04-29; still the head of `main` when this package was last updated). The schemas and example payloads are committed with source URLs and sha256.

What is verified, and how:

- Every mandate this package issues validates against the official schemas (Ajv, JSON Schema 2020-12).
- The six encoded SD-JWT examples in the AP2 documentation are parsed and re-serialised byte for byte; their disclosure digests, `sd_hash`, `checkout_hash`, `transaction_id` and payment reference recompute to the published values, and the closed hops' ES256 signatures (made by Google's reference code) verify under the open mandate's `cnf.jwk` with this verifier. The documentation never publishes the issuer key, so the documented open mandates' root signatures cannot be checked.
- Cross-implementation, in both directions: purchases issued here are accepted by Google's official AP2 Python SDK (`MandateClient`, payment and checkout chains) and by the independent `@sd-jwt/core` library; purchases issued by the official SDK are verified here with the real root signature.
- The documentation's decoded JSON blocks differ from its encoded tokens; the encoded tokens are treated as the source of truth.
- Adversarial tests: an exhaustive single-character mutation of a valid purchase is never accepted, structure fuzzing never throws or accepts, and withheld disclosures cannot widen an open mandate. Where this package is stricter than the reference SDK (for example acceptable-items, quantities and budgets) the tests say so.

Limits: only the P-256/ES256 and SHA-2 `_sd_alg` paths are implemented. Payment budgets are converted from major units the way the AP2 SDK does (a fixed x100), so they are refused for currencies whose exponent is not 2. Issuer key trust (`kid` / `x5c` resolution) is the caller's job. The cryptography is unaudited.

The settlement backends are structural only: they turn a payment mandate into an x402 HTTP-402 challenge or a Stripe Shared-Payment-Token charge shape and perform no network I/O. The x402 output is checked against the x402 v1 specification (field set, atomic-unit `maxAmountRequired`, `maxTimeoutSeconds`, standard-base64 `X-PAYMENT`); the `X-PAYMENT` payload is a placeholder envelope, not a signed authorization, and `asset` should be supplied as the token contract address. The Stripe shape has no official vector behind it. Settlement backends assume the mandate has already been verified.

## License

MIT - see LICENSE
