# @atlasauth/pca-fetch

Runtime-neutral Web **Fetch** guard for Proof-Carrying Authority — verify an inbound PCActn in any
`Request → Response` runtime: Cloudflare Workers, Deno, Bun, Vercel Edge, Netlify, a Lambda Function
URL. Web platform only, no Node APIs.

## Install

```sh
npm i @atlasauth/pca-fetch
```

## Usage

```ts
import { withPCA } from '@atlasauth/pca-fetch';

export default {
  fetch: withPCA(
    {
      audience: 'ins_acme',
      resolveGrant: async (grantRef) => grants.get(grantRef),   // your grant store
      context: async () => ({ params: { amount: 20, currency: 'usd' }, budget: { B: 500, tau: 0 }, planAuthorized: true }),
    },
    async (req, { pca }) => Response.json({ ok: true, verdict: pca.verdict }),
  ),
};
```

On success your handler runs with `{ pca: { verdict, pcactn } }`; otherwise a `401/403` `Response`
with a `WWW-Authenticate` challenge is returned. `createPcaFetchGuard(opts)` returns the raw guard
result if you want to compose it into your own router. The client sends the PCActn as
`PCA-Action: <base64url>` or a JSON body `{ pcactn }`.

Nothing here authorizes on its own — the resource server's verifier (default-deny) decides.

Part of Proof-Carrying Authority — see [`@atlasauth/pca`](../pca).
