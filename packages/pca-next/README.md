# @atlasauth/pca-next

Next.js (App Router) helper for Proof-Carrying Authority (PCA). `withPCA` wraps a Route Handler so the inbound PCActn is verified with the resource-server guard from `@atlasauth/pca` before your handler runs; otherwise it returns a 401/403 JSON response with a `WWW-Authenticate` challenge. Verification is default-deny.

## Install

```sh
npm i @atlasauth/pca-next @atlasauth/pca
npm i next   # optional peer dependency (^14 || ^15)
```

## Usage

```ts
// app/refunds/route.ts
import { withPCA } from '@atlasauth/pca-next';
import { memoryPcaStore } from '@atlasauth/pca';

export const POST = withPCA(
  {
    audience: 'ins_acme',                       // this resource server's id; the PCActn's signed `aud` must match
    resolveGrant: async (ref) => grants.get(ref) ?? null, // look up the Root Intent Grant by grant_ref
    budgetStore: memoryPcaStore(),              // replay counter store (use a durable one in production)
    hooks: { revocation: async () => ({ enforced: true, ok: !(await isRevoked()) }) }, // revocation checker
    context: async (req, pcactn) => ({          // facts only the resource server can vouch for
      params: { amount: 20, currency: 'usd' },
      plan: authorizedPlanNodes,                // your copy of the principal-authorized plan
      planAuthorized: true,
      budget: { B: 500, tau: 0 },
      risk: { blastRadius: 0.04 },              // risk inputs you can vouch for (missing ones fail closed to worst case)
    }),
  },
  async (req, { pca }) => {
    const { verdict, pcactn } = pca;            // handler only runs for a valid PCActn
    return Response.json({ ok: true });
  },
);
```

The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or as a JSON body `{ pcactn }`; the default extractor reads both. The wrapper reads a clone of the request body, so your handler can still read it. By default a deployment must supply `budgetStore`, a `hooks.revocation` checker, and a `context()` returning the server's own `plan` and `planAuthorized: true`; otherwise requests are denied. `insecureAllowUnenforced: true` relaxes this for local development only.

## API

- `withPCA(options, handler)` - returns `(req: Request) => Promise<Response>`. Options extend `RequirePcaOptions` from `@atlasauth/pca`, plus `onDeny(result, req)` to customize the error response.
- Re-exports `requirePCA`, `defaultExtract`, `memoryPcaStore`.

## Status

This package only wires the guard into Next.js route handlers; all verification logic lives in `@atlasauth/pca`. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
