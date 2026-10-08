# @atlasauth/pca-txn-tokens

OAuth-standards **chain-of-custody profile** for Proof-Carrying Authority. It projects a PCA attenuating
capability chain into the delegation idiom enterprise agent-auth infrastructure already reads — RFC 8693
nested `act` claims carried inside a Transaction Token — so a resource server (or SIEM, audit pipeline,
or policy engine) can see **who invoked whom** across an agent swarm over a plain signed JWT.

## Honest framing

This is a **bridge, not a replacement**. The cryptographic authority for an action remains the PCActn's
signed, hash-linked, attenuating capability chain (`@atlasauth/pca`): every hop is signed by the key the
parent is bound to, caveats are append-only, and widening is impossible by construction. A verifier
(`@atlasauth/backend` `requirePCA` / the adjudicator) checks **that**, default-deny.

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
