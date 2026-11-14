---
title: Keep API credentials away from the agent
order: 15
---

# Keep API credentials away from the agent

**Problem.** Your agent needs to call a third-party API (a bank, Gmail, a ticketing system) with an OAuth token. If the agent holds the token, a prompt-injected or buggy agent can use it for anything the token allows, for as long as it lives.

**Fix.** Put the token in a vault. The agent never receives it. It hands the vault the HTTP request it wants made, together with a signed proof that a person authorized exactly that request. The vault checks that the request matches the proof, attaches the token, makes the call itself, and returns the response with a signed receipt.

```bash
npm install @atlasauth/pca @atlasauth/pca-connect
```

## The four parts

1. **A connection.** The stored token, its scopes, and the principal whose grant must authorize its use.
2. **An action.** You pin, per verb, the provider, the minimum scopes the action needs, and an **extractor**: a function from an HTTP request back to the action's parameters. Scopes come from here, never from the caller.
3. **A proof.** The agent's signed action. Its `params_digest` commits to the exact parameters.
4. **The check.** The vault runs the extractor on the request and requires the result to hash to the proof's `params_digest`. Anything the extractor does not map (an extra body member, an extra query key, another host, a header) is a mismatch and is refused.

## Set up the vault

```ts
import { TokenVault, httpExtractor } from '@atlasauth/pca-connect';
import { InMemoryConnectionStore } from '@atlasauth/pca-connect/testing';

const VERB = 'bank.transfer.send';

const action = {
  verb: VERB,
  def_digest: 'A'.repeat(43),   // the digest of the reviewed action definition
  confirmed: true,              // that definition carries a valid signed confirmation
  upstream: { provider: 'bank', scopes_min: ['transfers:write'] },
  extract: httpExtractor({
    method: 'POST',
    url: 'https://api.bank.example/v1/accounts/{account}/transfers', // {account} becomes the parameter "account"
    body: 'json',                                                    // body members become parameters
    fixed: { source: 'vault' },                                       // always present, not a parameter
  }),
};

const vault = new TokenVault({
  strict: false,                        // development only, see "Going to production"
  insecureSkipPlanRootCheck: true,      // development only
  store: new InMemoryConnectionStore(), // plaintext, in memory
  actions: (verb) => (verb === VERB ? action : undefined),
  proxyFetch,                           // your outbound HTTP; it must not follow redirects
  receipts: { secretKey: vaultSecretKey, sink: (r) => console.log(r.outcome) },
});

await vault.putConnection({
  agentId, provider: 'bank', accessToken: providerToken, expiresAt,
  scopes: ['transfers:write', 'accounts:read'],
  authority: { principal: principalId, scopes: ['transfers:write', 'accounts:read'] },
});
```

`proxyFetch` receives `{ method, url, headers, body, redirect: 'manual' }` and returns `{ status, headers, body }`. Never follow a redirect inside it: a redirect would send the token to a host the extractor never saw.

## Make a call

The agent holds a grant from the person with an `oauthScopeCaveat('bank', ['transfers:write'])`, signs a proof for the verb, and sends the proof and the request:

```ts
const result = await vault.proxyCall(proof, {
  method: 'POST',
  url: 'https://api.bank.example/v1/accounts/acct_1/transfers',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ source: 'vault', amount: 12500, currency: 'EUR', payee: 'Acme GmbH' }),
}, { provider: 'bank' });

result.response.status; // 201
result.receipt;         // signed: mode 'proxy', outcome 'executed', http_status 201, the scopes the token really carried
```

The response is cleaned before it comes back: if the upstream echoes the token in a header or the body, the vault replaces it with `[redacted]`. A receipt is signed with the vault's key; check it with `verifyReleaseReceipt(receipt, vaultPublicKey)`. A receipt with any field edited does not verify.

## Expected output

The companion script (`npm run token-vault-proxy` in the `pca-guides-b` examples) uses a fake outbound transport, so it needs no network:

```
ok   the authorized transfer -> 201
ok   the vault attached the token -> "Bearer AT-SECRET-VALUE"
ok   the agent never sees the token -> false
ok   the receipt verifies against the vault key -> true
ok   a different amount -> "request_mismatch"
ok   an extra body member -> "request_mismatch"
ok   another host -> "request_mismatch"
ok   an Authorization header from the agent -> "request_mismatch"
ok   nothing extra was sent -> 0
ok   an action nobody pinned -> "unknown_action"

All outcomes as expected.
```

(The token shown is a placeholder inside the fake transport. The point of the line is that it appears on the outbound request, not in anything returned to the agent.)

## When it refuses

Every refusal is a typed error with a `code`. Nothing is sent upstream.

| Code | Why |
|---|---|
| `request_mismatch` | The request does not re-derive the proof's parameters: a changed value, an extra member or query key, another path, host or method, a repeated key, a header other than `content-type`, `accept` or `idempotency-key`, or no extractor on the action |
| `unknown_action` | No pinned action for the proof's verb |
| `unconfirmed_action` | The action definition has no valid signed confirmation |
| `scope_exceeded` | The action's minimum scopes are not inside the grant, or not inside the stored connection |
| `not_authorized` | The proof fails verification, the action is for another provider, or it needs no scopes |
| `proxy_failed` | The outbound call did not complete. A failed receipt is written and the message never contains the token |
| `bearer_release_disabled` | You called `getConnectionToken`, which hands the raw token to the caller and is off by default |

A refused request does not spend the proof: fix the request and send the same proof again.

## Going to production

`strict` is on unless you turn it off, and the constructor throws until the production profile is complete:

- an encrypting store (`EncryptedConnectionStore` with a key wrapper you control), not the in-memory one;
- a `replay` store, so a captured proof cannot be used twice;
- an `isRevoked` source, so a revoked grant stops releasing;
- a pinned `audience`, and `authorizedPlanRoots` instead of `insecureSkipPlanRootCheck`.

Prefer `proxyCall`. A bare bearer token released by `getConnectionToken` is good for anything inside its scopes until it expires, including a call other than the one that was authorized. It exists behind `insecureBearerRelease: true` for cases where a proxy is impossible.

## Next

- Use a lease so the access also expires: [Obligations, leases and break glass](./obligations-leases-break-glass.md).
- Keep your own authorization server and still require a proof on every call: [Carry a PCA grant in your OAuth server](./pca-grant-oauth.md).
- Understand the verifier's reasons: [Refusal reasons](../reference/refusals.md).
