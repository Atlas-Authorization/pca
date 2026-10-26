# @atlasauth/pca-acp

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
  expectedMerchant: 'acme', amount: 100, verifyKey: publicKey,
  pcActn, grant, audience: 'my-rs',       // optional full proof re-verification
}); // { ok: true, claims, pcaResult }

// x402: answer with a 402 challenge, then gate settlement on the proof-bound token.
const challenge = x402Challenge('/api/report', { amount: 100, currency: 'USDC', payTo: '0xabc' });
const result = await x402Settle({ token, merchant: 'acme', amount: 100 }, {
  verify: acpX402Verifier({ verifyKey: publicKey, pcActn, grant, audience: 'my-rs' }),
  settle: async (payload, claims) => ({ charged: claims.amount }),   // your facilitator call
}); // { settled: true, status: 200, receipt } or { settled: false, status: 402, reason }
```

Pass `expectedMerchant` and `amount` to `acpX402Verifier` from your own order data when you can; by default it reads them from the client's payload.

## API

- Caveats: `spendCapCaveat`, `merchantAllowCaveat`, `merchantCategoryCaveat`, `humanPresentCaveat`, `extractPaymentAuthority`, `checkPaymentAuthority`, `AcpAuthorityError`.
- Tokens: `mintDelegatedPaymentToken`, `verifyDelegatedPaymentToken`.
- x402: `x402Challenge`, `x402Settle`, `acpX402Verifier`.

## Status

Experimental. Amounts are integer minor units everywhere (mint, settlement, spend-cap caveats and the x402 challenge refuse fractional, negative, NaN and unsafe values). Pass `singleUse` (an atomic `claim(jti, expiresAtMs)` store) to redeem a token exactly once, and `strict: true` to require the store, an expected currency and, for the x402 verifier, a server-supplied merchant and amount (the client payload's own merchant and amount are then never read). The claim is made only after every other check passes and a failing store denies; a token whose settlement call then fails stays spent. Without `strict`, single use is opt-in and the payload fields are the fallback.

Spec pins: ACP delegated-token claims are this package's own structural envelope (not Stripe's Shared Payment Token wire format), and the x402 challenge follows the v1 `accepts` field names (`scheme`, `network`, `maxAmountRequired`, `resource`, `payTo`, `asset`, `mimeType`); x402 v2 and the current ACP schemas have not been checked against this code, so validate them before wire use. The x402 helpers perform no network I/O; verification and settlement are injected. The cryptography is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the delegated payment token: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
