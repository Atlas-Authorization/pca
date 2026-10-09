# @atlasauth/pca-hono

Hono middleware for Proof-Carrying Authority (PCA). It verifies the inbound PCActn with the resource-server guard from `@atlasauth/pca`, puts the verdict on the Hono context, and otherwise answers 401/403 with a `WWW-Authenticate` challenge. Verification is default-deny: a required check the server does not enforce denies the request.

## Install

```sh
npm i @atlasauth/pca-hono @atlasauth/pca
npm i hono   # optional peer dependency (^4)
```

## Usage

```ts
import { Hono } from 'hono';
import { pcaHono } from '@atlasauth/pca-hono';
import { memoryPcaStore } from '@atlasauth/pca';

const app = new Hono();

app.post(
  '/refunds',
  pcaHono({
    audience: 'ins_acme',                       // this resource server's id; the PCActn's signed `aud` must match
    resolveGrant: async (ref) => grants.get(ref) ?? null, // look up the Root Intent Grant by grant_ref
    budgetStore: memoryPcaStore(),              // replay counter store (use a durable one in production)
    hooks: { revocation: async () => ({ enforced: true, ok: !(await isRevoked()) }) }, // revocation checker
    context: async (req, pcactn) => ({          // facts only the resource server can vouch for
      params: { amount: 20, currency: 'usd' },  // real action params (must hash to action.params_digest)
      plan: authorizedPlanNodes,                // your copy of the principal-authorized plan
      planAuthorized: true,
      budget: { B: 500, tau: 0 },
      risk: { blastRadius: 0.04 },              // risk inputs you can vouch for (missing ones fail closed to worst case)
    }),
  }),
  (c) => {
    const { verdict, pcactn } = c.get('pca');   // set only on success
    return c.json({ ok: true });
  },
);
```

The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or as a JSON body `{ pcactn }`; the default extractor reads both. By default a deployment must supply `budgetStore`, a `hooks.revocation` checker, and a `context()` that returns the server's own `plan` and `planAuthorized: true`; otherwise the request is denied. `insecureAllowUnenforced: true` relaxes this for local development only.

## API

- `pcaHono(options)` - returns the Hono middleware. Options extend `RequirePcaOptions` from `@atlasauth/pca`, plus `attachAs` (context key, default `pca`) and `onDeny(result, c)` to customize the error response.
- Re-exports `requirePCA`, `defaultExtract`, `memoryPcaStore`.

## Status

The middleware only wires the guard into Hono; all verification logic lives in `@atlasauth/pca`. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
