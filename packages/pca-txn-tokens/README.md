# @atlasauth/pca-txn-tokens

> Maturity: **production** (supported for production use), pinned to draft-ietf-oauth-transaction-tokens-11. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
  (typ `txntoken+jwt` in revision 11) carrying an invariant request context through a call chain.
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
  profile: 'legacy',
  ttlSec: 120, // optional, default 120
});

// 3) Verify + parse (throws on bad signature / wrong key / expiry / malformed claims).
const { chain, action, tctx, claims } = await fromTransactionToken(jwt, tts.publicKey, {
  profile: 'legacy',
  replayCheck: 'unchecked', // or seenTxn: (id, exp) => store.hasOrAdd(id, exp)
});
// chain  = the reconstructed sub/act chain of custody
// action = { verb, resource, aud } (the PCA action in tctx)
// tctx   = the transaction context object as signed
// claims = the full verified JWT claim set (iss/sub/aud/iat/exp/jti/act/tctx)
```

The example above uses the `legacy` profile, which is this package's original shape. New code should use the default `draft-11` profile, shown in the next section.

## API

| Export | Signature | Notes |
| --- | --- | --- |
| `subActChain` | `(chain: CapabilityChain) => SubActClaim` | Pure. `sub` = root principal; one nested `act` per delegation hop. |
| `toTransactionToken` | `(args) => Promise<string>` | Signs an EdDSA `txn_token+jwt`. `issuerKey`: raw Ed25519 seed or `jose` key. |
| `fromTransactionToken` | `(jwt, verifyKey, opts?) => Promise<{ chain, action, tctx, claims }>` | Verifies + parses. `verifyKey`: raw Ed25519 public key or `jose` key. `action` is `undefined` for a free-form draft `tctx`. |
| `toRfc8693Act` | `(claim: SubActClaim) => SubActClaim` | Converts this profile's `act` order to the RFC order. |
| `TxnTokenError` | class, `code` = `replay_store_required` | Thrown when the verifier has no replay store and no explicit opt-out. |
| `actDepth` | `(claim: SubActClaim) => number` | Delegation depth = number of nested `act` levels. |

Signing is EdDSA (Ed25519) via [`jose`](https://github.com/panva/jose). Ed25519 key material interops
with `@atlasauth/pca` key pairs directly (32-byte secret seed / 32-byte public key).

## Draft-11 profile (the default)

`draft-11` follows draft-ietf-oauth-transaction-tokens-11 and is what you get when you pass no `profile`. The original shape is still available with `profile: 'legacy'`.

```ts
const jwt = await toTransactionToken({
  chain: leaf.chain,
  action: { verb: 'stripe.refund', resource: 'charge:ch_123', aud: 'https://api.acme.com' },
  issuerKey: tts.secretKey,
  issuer: 'https://tts.acme.com',
  scope: 'refund',                 // required
  reqWl: 'gateway.acme.com',       // required: the workload that asked for the token
  trustDomain: 'acme.com',         // goes in `aud` (defaults to action.aud)
});

const { chain, action, tctx } = await fromTransactionToken(jwt, tts.publicKey, {
  audience: 'acme.com',            // required: the trust domain you serve
  seenTxn: (txn, exp) => store.hasOrAdd(txn, exp), // required unless replayCheck: 'unchecked'
});
```

In this profile the header `typ` is `txntoken+jwt`; `iat`, `aud`, `exp`, `txn`, `sub`, `scope` and `req_wl` are required; `aud` must contain the audience you pass; there is no `jti`. The `act` claim is this package's extension: the draft defines none.

**Free-form `tctx`.** The draft's transaction context is a free-form JSON object (its Figure 4 example carries `action`, `ticker`, `quantity` and a nested `customer_type`), and `rctx` is a second free-form object. The verifier accepts any JSON object as `tctx` and returns it unchanged as `tctx`; `action` is then `undefined`. The names `verb`, `resource` and `aud` are reserved for the PCA action: a `tctx` that uses any of them must carry all three as strings, and then `action` is `{ verb, resource, aud }`. A `tctx` that is missing, `null`, an array or a scalar is refused, and so is an `rctx` that is present and is not an object. Minting still writes the PCA action as `tctx`.

**Replay store.** `fromTransactionToken` throws `TxnTokenError` with code `replay_store_required` unless you pass `seenTxn` or set `replayCheck: 'unchecked'` (the draft itself says a Transaction Token is not replay resistant; the opt-out is for deployments that rely on a short lifetime alone). The hook is called last, after every other check has passed, so a token refused for another reason never burns its `txn`. Back the hook with a store shared by every verifier instance.

## RFC 8693 chains

`subActChain` descends in delegation order (root holder outermost). RFC 8693 section 4.1 puts the most recent actor outermost. `toRfc8693Act(claim)` converts to the RFC order for consumers that expect it; `fromTransactionToken` returns whatever nesting the token carries, so an RFC-ordered `act` round-trips unchanged.

## Failure modes

Every row throws; nothing returns a partial result. "Missing X, result Y":

| Missing or invalid | Result |
| --- | --- |
| replay store (`seenTxn`) and no `replayCheck: 'unchecked'` | `TxnTokenError`, code `replay_store_required` (raised before the token is read) |
| `opts.audience` (draft-11) | `TypeError` |
| token string longer than 16384 characters | `transaction token: token exceeds the size limit` |
| non-canonical token spelling | refused before any verification |
| signature invalid, wrong key, tampered payload | `signature verification failed` |
| `alg` other than EdDSA (including `none`, HS256, ES256) | `"alg" (Algorithm) Header Parameter value not allowed` |
| header `typ` not the profile's value (including no `typ`) | `unexpected "typ" JWT header value` |
| `exp` missing (both profiles) or in the past | `missing required "exp" claim` / `"exp" claim timestamp check failed` |
| `nbf` in the future | `"nbf" claim timestamp check failed` |
| any draft-11 required claim missing | `missing required "<claim>" claim` |
| `txn`, `scope` or `req_wl` empty or not a string (draft-11) | `transaction token: <claim> must be a non-empty string` |
| `aud` does not contain `opts.audience` | `unexpected "aud" claim value` |
| `sub` missing or empty | `transaction token: missing sub (root principal)` |
| `tctx` missing, not an object, or using only part of the PCA action keys | `transaction token: missing or malformed tctx` |
| `rctx` present and not an object (draft-11) | `transaction token: malformed rctx` |
| `act` malformed at any depth | `transaction token: malformed act claim` or `act.sub must be a non-empty string` |
| `seenTxn` reports a repeat, has no identifier to check, or throws | refused (`replayed`, `no transaction identifier`, or the hook's own error) |
| minting without `scope` / `reqWl` / a trust domain (draft-11), empty issuer, bad ttl, key not 32 bytes | throws |

## Limits

- Pinned to draft-ietf-oauth-transaction-tokens-11 (30 July 2026) for the `draft-11` profile, and to RFC 8693 section 4.1 for `act`. The draft is still an Internet-Draft and will change; the pin names the revision the tests reproduce, and a later revision is a new release of this package, not a silent change. The `legacy` profile is this package's own shape.
- A Transaction Token is not a bearer credential here and is not replay resistant on its own (the draft says the same); keep the lifetime short and back `seenTxn` with a store shared by every verifier instance.
- Ed25519 (EdDSA) only.
- Only the claims named above are interpreted. `rctx` is checked to be an object and otherwise passed through; the draft's other optional claims are returned in `claims` untouched and never used for a decision.
- `fromTransactionToken` never decides authority: verify the PCActn's capability chain separately.
- Minting writes the PCA action as `tctx`; a free-form `tctx` is accepted on verification only.

## Status

Production, pinned to the draft revision above. The code verifies a token and returns what it carries; it keeps no state of its own (replay state is the store you supply). The tests assert whole outcomes, including adversarial inputs, and the token shapes were cross-checked against an independent implementation (see Cross-check). Cross-language conformance does not apply to this package: it is a bridge to an OAuth draft, not a PCA wire format, so there is no PCA conformance vector for it. The cryptography in the PCA stack has not been independently audited.

## Cross-check

`crosscheck/crosscheck.py` assembles and signs Transaction Tokens by hand (no JOSE library; only the Ed25519 primitive from `cryptography`) and writes `fixtures/python-vectors.json`, which the tests verify with this package, including negative variants. In the other direction it verifies the tokens this package mints. Run it from the package directory:

```sh
python3 crosscheck/crosscheck.py                    # regenerate the fixture (deterministic)
PCA_CROSSCHECK_OUT=crosscheck/out/ours.json npx vitest run src/crosscheck.test.ts
python3 crosscheck/crosscheck.py --verify-ours crosscheck/out/ours.json
```

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the Transaction Token: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
