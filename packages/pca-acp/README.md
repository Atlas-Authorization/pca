# @atlasauth/pca-acp

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Agentic Commerce Protocol (ACP) and x402 adapter for Proof-Carrying Authority (PCA). It mints an ACP-style delegated one-time payment token (a JWS bound to session, merchant, amount, currency and expiry) from a PCActn, and provides an x402 (HTTP 402) facilitator hook that only settles when the token and its backing proof verify.

The PCActn's capability caveats gate issuance: minting is refused (`AcpAuthorityError`) if the requested amount, currency, merchant, category or human-present modality exceeds what the proof authorizes, or if the token would outlive the proof. The token carries the proof by reference (its digest), never its contents. For the AP2 Intent/Cart/Payment chain see `@atlasauth/pca-ap2`.

## Install

```sh
npm i @atlasauth/pca-acp
```

Depends on `@atlasauth/pca` and `jose` (installed transitively).

## Usage

```ts
import {
  spendCapCaveat, merchantAllowCaveat,
  mintDelegatedPaymentToken, verifyDelegatedPaymentToken,
  x402Challenge, x402Settle, acpX402Verifier,
} from '@atlasauth/pca-acp';

// `grant` carries payment caveats, e.g. mintRoot({ ..., caveats: [spendCapCaveat(500, 'USD'),
// merchantAllowCaveat(['acme'])] }); `pcActn` is a PCActn built from it with @atlasauth/pca.

const token = await mintDelegatedPaymentToken(pcActn, {
  amount: 100, currency: 'USD', merchant: 'acme', session: 'sess-1',
  expiresAt: Date.now() + 10 * 60_000,
  paymentMethod: { type: 'shared_payment_token', token: 'spt_abc' },
  signingKey: privateKey,                 // jose KeyLike, Uint8Array or JWK; default alg EdDSA
});
// minting 900 against the 500 cap throws AcpAuthorityError

// Settlement: check the token binding and re-verify the backing proof.
await verifyDelegatedPaymentToken(token, {
  expectedMerchant: 'acme', amount: 100, expectedCurrency: 'USD', verifyKey: publicKey,
  singleUse,                              // atomic claim(jti, expiresAtMs) store: required (strict by default)
  pcActn, grant, audience: 'my-rs',       // optional full proof re-verification
}); // { ok: true, claims, pcaResult }

// x402: answer with a 402 challenge, then gate settlement on the proof-bound token.
const challenge = x402Challenge('/api/report', { amount: 100, currency: 'USDC', payTo: '0xabc' }); // payTo and currency are required
const result = await x402Settle({ token, merchant: 'acme', amount: 100 }, {
  verify: acpX402Verifier({ verifyKey: publicKey, expectedMerchant: 'acme', amount: 100, expectedCurrency: 'USD', singleUse, pcActn, grant, audience: 'my-rs' }),
  settle: async (payload, claims) => ({ charged: claims.amount }),   // your facilitator call
}); // { settled: true, status: 200, receipt } or { settled: false, status: 402, reason }
```

`acpX402Verifier` is strict by default: it needs `expectedMerchant`, `amount`, `expectedCurrency` and `singleUse` from your own order data and never reads the client payload's merchant or amount. Pass `strict: false` only in a test.

## API

- Caveats: `spendCapCaveat`, `merchantAllowCaveat`, `merchantCategoryCaveat`, `humanPresentCaveat`, `extractPaymentAuthority`, `checkPaymentAuthority`, `AcpAuthorityError`.
- Tokens: `mintDelegatedPaymentToken`, `verifyDelegatedPaymentToken`.
- x402: `x402Challenge`, `x402Settle`, `acpX402Verifier`.
- ACP: `toAcpAllowance` maps verified claims to the `allowance` object of a delegate_payment request.
- x402 v2 transport: `readPaymentSignature`, `x402PaymentSignatureHeaders`, `x402SettlementResponse`, `decodePaymentSignatureHeader`, `decodePaymentResponseHeader`.
- x402 v2: `x402ChallengeV2`, `encodePaymentRequiredHeader`, `decodePaymentRequiredHeader`, `x402Negotiate`, `normalizeX402Payload`, `x402AcceptedMatches`, `paymentRequiredV2Problems`.
- Stripe Shared Payment Tokens: `parseStripeSpt`, `stripeSptProblems`, `stripeSptUsable`, `stripeSptWithinClaims`, `stripeUsageLimitsFor`.

## Failure modes

| Missing or wrong | Result |
|---|---|
| Mint request above the proof's spend cap, off its currency, merchant or category allowlist, or `humanPresent` missing | `mintDelegatedPaymentToken` throws `AcpAuthorityError` |
| Fractional, zero, negative or unsafe amount | refused at mint, settlement, caveat and x402 challenge |
| Expiry in the past, or after the proof's `exp`; no session id | `AcpAuthorityError` |
| Malformed payment caveat on the proof | `AcpAuthorityError` (fail closed) |
| Token spelling not canonical, bad signature, wrong key or algorithm | `{ ok: false, reason }` before any claim is read |
| Merchant, amount, currency, session mismatch or expired token | `{ ok: false, reason }` |
| No `singleUse` store or no `expectedCurrency` (strict, the default) | `{ ok: false }` with the exact reason |
| Token already redeemed, or the store throws | `{ ok: false }`; a token whose settlement call then fails stays spent |
| `grant` without the `pcActn` to re-verify | `{ ok: false }` |
| `pcActn` digest differs, or the bound proof fails the core verifier | `{ ok: false }` |
| x402 challenge without `payTo` or `currency`, or a bad amount or timeout | `x402Challenge` throws `TypeError` |
| x402 verifier admits without claims | `settled: false`, status 402 |
| Allowance claim not expressible in ACP (currency not three letters, merchant over 256 characters, bad expiry) | `toAcpAllowance` throws `AcpAuthorityError` |

## Limits

- The delegated token's claims are this package's own signed envelope; Stripe's Shared Payment Token object is read and checked separately (see Shared Payment Tokens above). `toAcpAllowance` produces the `allowance` object of the ACP delegate_payment request as specified; the card payment method object is yours to supply.
- x402 v1 (`x402Challenge`) and v2 (`x402ChallengeV2`) are both implemented and negotiated with `x402Negotiate` (highest common version; no overlap means no challenge). v2 follows the x402 specification v2 (github.com/coinbase/x402, `specs/x402-specification-v2.md`): CAIP-2 `network`, atomic string `amount`, `resource` info, base64 `PAYMENT-REQUIRED` header. In a v2 payload the delegated token is `payload.token` and the echoed `accepted` must be exactly one of the requirements you offered (`offered` option of `acpX402Verifier`). The HTTP transport (x402 transport specification v2, `specs/transports-v2/http.md`) is implemented on the decoded objects: `encodePaymentSignatureHeader` / `decodePaymentSignatureHeader` / `readPaymentSignature` (a missing `PAYMENT-SIGNATURE` is 402, a malformed one 400), `encodePaymentResponseHeader` / `decodePaymentResponseHeader` / `x402SettlementResponse` (200 with `success: true`, or 402 with `success: false`, an `errorReason` and an empty transaction), and `X402_HTTP_STATUS`. Each header is the base64 of a JSON object, validated in both directions.
- Shared Payment Tokens follow the Stripe API reference object `shared_payment.granted_token` (docs.stripe.com/api/shared-payment/granted-token/object). The checks are local and never call Stripe; the vectors are the reference's example object and the x402 specification's examples.
- No network I/O: verification and settlement are injected. The single-use store must be an atomic, durable conditional write.
- Issuer key trust (`kid` or `x5c` resolution) is the caller's job.

## Status

Production. Amounts are integer minor units everywhere. The cryptography of the underlying PCA core has not been independently audited. Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca).

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the delegated payment token: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
