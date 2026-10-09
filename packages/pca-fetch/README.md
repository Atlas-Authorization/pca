# @atlasauth/pca-fetch

Runtime-neutral Web Fetch guard for Proof-Carrying Authority. It verifies an inbound PCActn in any `Request -> Response` runtime (Cloudflare Workers, Deno, Bun, Vercel Edge, Netlify, a Lambda Function URL) using only the web platform, with no Node APIs. It wraps the `requirePCA` guard from `@atlasauth/pca`, which is default-deny: a required check that is not enforced denies.

## Install

```sh
npm i @atlasauth/pca-fetch
```

Depends on `@atlasauth/pca`.

## Usage

```ts
import { withPCA } from '@atlasauth/pca-fetch';
import { memoryPcaStore } from '@atlasauth/pca';

export default {
  fetch: withPCA(
    {
      audience: 'ins_acme',                       // the audience a PCActn must name
      resolveGrant: async (grantRef) => grants.get(grantRef) ?? null, // your root-grant store
      budgetStore: memoryPcaStore(),              // replay counter + budget; use a shared store in production
      hooks: { revocation: myRevocationChecker }, // e.g. built with createRevocationChecker from @atlasauth/pca
      context: async (req, pcactn) => ({
        plan: knownPlan(pcactn),                  // the plan your server knows for this action
        planAuthorized: true,                     // only if the principal authorized that plan root
        params: { amount: 20, currency: 'usd' },
        risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 },
        budget: { B: 500, tau: 0, asOf: Date.now() },
      }),
    },
    async (req, { pca }) => Response.json({ ok: true, verb: pca.pcactn.action.verb }),
  ),
};
```

On success your handler runs with `{ pca: { verdict, pcactn } }`. Otherwise a `401` or `403` `Response` is returned with a `WWW-Authenticate: PCA realm=...` challenge and a JSON body (shape it with `denyBody`). `createPcaFetchGuard(opts)` returns the raw guard result if you want to compose it into your own router.

The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or a JSON body `{ pcactn }`. By default the following checks must pass or the request is denied: `counter` (needs a `budgetStore`), `revocation` (needs `hooks.revocation`), `plan_root_authorized` (needs `context()` returning `planAuthorized: true`), plus audience, validity and grant binding. Options are those of `requirePCA`; see `@atlasauth/pca`. `insecureAllowUnenforced: true` disables the default-deny profile and is for local development only.

Nothing here authorizes on its own: the verifier decides, not the client's proof.

## Status

Experimental. Part of Proof-Carrying Authority; the cryptography is unaudited.

## License

MIT - see LICENSE
