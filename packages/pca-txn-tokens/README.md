# @atlasauth/pca-txn-tokens

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

OAuth-standards **chain-of-custody profile** for Proof-Carrying Authority. It projects a PCA attenuating
capability chain into the delegation idiom enterprise agent-auth infrastructure already reads — RFC 8693
nested `act` claims carried inside a Transaction Token — so a resource server (or SIEM, audit pipeline,
or policy engine) can see **who invoked whom** across an agent swarm over a plain signed JWT.

## Honest framing

This is a **bridge, not a replacement**. The cryptographic authority for an action remains the PCActn's
signed, hash-linked, attenuating capability chain (`@atlasauth/pca`): every hop is signed by the key the
parent is bound to, caveats are append-only, and widening is impossible by construction. A verifier
(see `@atlasauth/pca`) checks **that**, default-deny.

The Transaction Token minted here is the **interop envelope** around the chain of custody and the action.
It is **not** a bearer credential and does **not** authorize anything on its own — it lets standards-native
tooling consume the delegation chain. Compose, don't replace: the PCActn's signed capability chain stays
the credential.

## Specs

- **RFC 8693** — OAuth 2.0 Token Exchange. §4.1 defines the nestable `act` (actor) claim; we map one
  `act` level per PCA delegation hop, descending the chain of custody.
  <https://www.rfc-editor.org/rfc/rfc8693>
- **draft-ietf-oauth-transaction-tokens** — Transaction Tokens: a short-lived, signed, immutable token
  (typ `txn_token+jwt`) carrying an invariant request context through a call chain.
  <https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/>
- **Its agent extension** — putting the delegated-agent call chain into the Transaction Token's `act`
  claim so agent-auth infra reads the custody chain natively. Here, the PCA capability chain **is** that
  call chain, and the PCA action is the transaction context (`tctx`).

## Install

```sh
npm i @atlasauth/pca-txn-tokens
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import {
  subActChain,
  toTransactionToken,
  fromTransactionToken,
  actDepth,
} from '@atlasauth/pca-txn-tokens';

// A PCA agent + a two-level sub-delegation (principal -> a -> sub1 -> sub2).
const a = agent({
  principal: generateKeyPair(),
  goal: 'reconcile refunds for October',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: 'https://api.acme.com',
});
const leaf = a.subAgent().subAgent();

// 1) Pure projection to RFC 8693 nested sub/act (no signing).
const custody = subActChain(leaf.chain);
// custody.sub           = root principal (chain[0].issuer)
// custody.act.sub       = chain[0].holder
// custody.act.act.sub   = chain[1].holder, ... descending the chain
actDepth(custody); // === leaf.chain.length

// 2) Mint a signed Transaction Token (EdDSA / Ed25519). issuerKey: a raw 32-byte
//    Ed25519 secret seed (KeyPair.secretKey) or a pre-imported `jose` key.
const tts = generateKeyPair(); // Transaction Token Service signing key
const jwt = await toTransactionToken({
  chain: leaf.chain,
  action: { verb: 'stripe.refund', resource: 'charge:ch_123', aud: 'https://api.acme.com' },
  issuerKey: tts.secretKey,
  issuer: 'https://tts.acme.com',
  ttlSec: 120, // optional, default 120
});

// 3) Verify + parse (throws on bad signature / wrong key / expiry / malformed claims).
const { chain, action, claims } = await fromTransactionToken(jwt, tts.publicKey);
// chain  = the reconstructed sub/act chain of custody
// action = { verb, resource, aud } (the tctx)
// claims = the full verified JWT claim set (iss/sub/aud/iat/exp/jti/act/tctx)
```

## API

| Export | Signature | Notes |
| --- | --- | --- |
| `subActChain` | `(chain: CapabilityChain) => SubActClaim` | Pure. `sub` = root principal; one nested `act` per delegation hop. |
| `toTransactionToken` | `(args) => Promise<string>` | Signs an EdDSA `txn_token+jwt`. `issuerKey`: raw Ed25519 seed or `jose` key. |
| `fromTransactionToken` | `(jwt, verifyKey) => Promise<{ chain, action, claims }>` | Verifies + parses. `verifyKey`: raw Ed25519 public key or `jose` key. |
| `actDepth` | `(claim: SubActClaim) => number` | Delegation depth = number of nested `act` levels. |

Signing is EdDSA (Ed25519) via [`jose`](https://github.com/panva/jose). Ed25519 key material interops
with `@atlasauth/pca` key pairs directly (32-byte secret seed / 32-byte public key).

## Draft-11 profile

The default output is this package's original profile (header `typ` `txn_token+jwt`). For tokens that follow draft-ietf-oauth-transaction-tokens-11, ask for it explicitly:

```ts
const jwt = await toTransactionToken({
  chain: leaf.chain,
  action: { verb: 'stripe.refund', resource: 'charge:ch_123', aud: 'https://api.acme.com' },
  issuerKey: tts.secretKey,
  issuer: 'https://tts.acme.com',
  profile: 'draft-11',
  scope: 'refund',                 // required
  reqWl: 'gateway.acme.com',       // required: the workload that asked for the token
  trustDomain: 'acme.com',         // goes in `aud` (defaults to action.aud)
});

const { chain, action, claims } = await fromTransactionToken(jwt, tts.publicKey, {
  profile: 'draft-11',
  audience: 'acme.com',            // required: the trust domain you serve
  seenTxn: (txn, exp) => store.hasOrAdd(txn, exp), // optional replay hook
});
```

In this profile the header `typ` is `txntoken+jwt`; `iat`, `aud`, `exp`, `txn`, `sub`, `scope` and `req_wl` are required; `aud` must contain the audience you pass; there is no `jti`. The `tctx` object carries the PCA action (`verb`, `resource`, `aud`); a `tctx` of any other shape is refused. The `act` claim is this package's extension: the draft defines none.

## RFC 8693 chains

`subActChain` descends in delegation order (root holder outermost). RFC 8693 section 4.1 puts the most recent actor outermost. `toRfc8693Act(claim)` converts to the RFC order for consumers that expect it; `fromTransactionToken` returns whatever nesting the token carries, so an RFC-ordered `act` round-trips unchanged.

## Failure modes

Every row throws; nothing returns a partial result.

| Situation | Result |
| --- | --- |
| non-canonical token spelling | refused before any verification |
| signature invalid, wrong key, tampered payload | `signature verification failed` |
| `alg` other than EdDSA (including `none`, HS256, ES256) | `"alg" (Algorithm) Header Parameter value not allowed` |
| header `typ` not the profile's value (including no `typ`) | `unexpected "typ" JWT header value` |
| `exp` missing (both profiles) or in the past | `missing required "exp" claim` / `"exp" claim timestamp check failed` |
| `nbf` in the future | `"nbf" claim timestamp check failed` |
| any draft-11 required claim missing | `missing required "<claim>" claim` |
| `txn`, `scope` or `req_wl` empty or not a string (draft-11) | refused |
| `aud` does not contain `opts.audience` | `unexpected "aud" claim value` |
| `draft-11` without `opts.audience` | `TypeError` |
| `sub` missing; `tctx` missing or malformed; `act` malformed at any depth | refused |
| `seenTxn` reports a repeat, has no identifier to check, or throws | refused |
| minting without `scope` / `reqWl` / a trust domain (draft-11), empty issuer, bad ttl, key not 32 bytes | throws |

## Limits

- Pinned to draft-ietf-oauth-transaction-tokens-11 (30 July 2026) for the `draft-11` profile, and to RFC 8693 section 4.1 for `act`. The draft is still an Internet-Draft and will change; the pin names the revision the tests reproduce. The default profile is unchanged from earlier releases.
- A Transaction Token is not a bearer credential here and is not replay resistant on its own (the draft says the same); keep the lifetime short and use `seenTxn` where instances share a store.
- Ed25519 (EdDSA) only.
- `fromTransactionToken` never decides authority: verify the PCActn's capability chain separately.

## Status

The Transaction Tokens draft is still evolving IETF work; the `tctx` shape here follows the PCA action (`verb`, `resource`, `aud`). The cryptography in the PCA stack has
not been independently audited.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the Transaction Token: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
