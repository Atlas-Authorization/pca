# pca-attacks

Seven agent-authorization attacks, each run against five approaches, with the resource server's own
verdict for every cell:

| Approach | File |
|---|---|
| OAuth bearer token with scopes (RFC 6749, 6750, 9068, 8707) | `src/approaches/oauth.ts` |
| OAuth Rich Authorization Requests (RFC 9396) | `src/approaches/rar.ts` |
| Macaroons, standing in for Biscuit (attenuable bearer tokens) | `src/approaches/macaroon.ts` |
| UCAN 1.0 delegations and invocations | `src/approaches/ucan.ts` |
| Proof-Carrying Authority, using `@atlasauth/pca` and `requirePCA` | `src/approaches/pca.ts` |

The attacks (`src/attacks.ts`): a prompt-injected agent making an in-scope but unapproved payment; a
poisoned approval; a stolen credential used by someone else; a verbatim replay; over-broad delegation to a
sub-agent; payee and amount swapped after approval; and a cumulative spending limit exceeded across calls.

Every approach is configured as its specification intends and used well. Before each attack the suite
sends a legitimate request in the same setup and requires it to be allowed, so no approach can score
"Stopped" by refusing everything. If a control request is refused, the run stops with `SETUP ERROR`.

## Run

Node.js 20 or later. To get your own copy:

```sh
npm create pca-app@latest my-attacks -- --template attacks
cd my-attacks
```

Then:

```sh
npm install
npm start                       # full report: every attack, every approach, the server's reason
npm run matrix                  # only the attack x approach matrix, as Markdown
npm run json                    # machine-readable results
npm run check-doc -- <file.md>  # exit 1 unless <file.md> contains the current matrix verbatim
```

The comparison page, "Why PCA: a comparison", publishes this matrix; `check-doc` keeps the two in sync.

## Modeling notes

- OAuth and RAR tokens are EdDSA-signed JWT access tokens validated locally (signature, `aud`, `exp`).
- RAR uses `payment_initiation` details (the RFC 9396 §2 example shape) when the payments are known up
  front, and an API-defined type with a payee allowlist and ceilings otherwise. Its cumulative ceiling is
  a running total the server keeps per token; RFC 9396 does not define one.
- Macaroons use the chained-HMAC construction from the NDSS 2014 paper with first-party caveats, plus a
  third-party caveat discharged by the accounts-payable system in A2. Biscuit gives the same outcome in each
  scenario (bearer, offline attenuation, checks over authorizer facts, third-party blocks).
- UCAN uses JSON envelopes and raw Ed25519 key ids instead of DAG-CBOR and did:key multicodec strings;
  the executor refuses a nonce it has already seen. Neither simplification changes an outcome. In A2 the
  delegation chain runs principal -> accounts-payable system -> agent.
- PCA uses the library unchanged. A1 and A6 use a principal-authorized plan; A3, A4, A5 and A7 use
  grant-only mode (the server accepts any plan the agent commits). A2 adds per-parameter provenance from the
  Intent Layer v2 extension (not PCA Core): value-bound label receipts signed by the accounts-payable system,
  checked by `authorize` (the library's one authorization pipeline) with the Intent Layer context, bound to the
  payment the server executes. A2 needs `@atlasauth/pca` 0.5.0 or later; with an older version the run stops
  with a SETUP ERROR that says so.
