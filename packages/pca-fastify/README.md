# @atlasauth/pca-fastify

Fastify `preHandler` for Proof-Carrying Authority. `pcaFastify()` verifies the inbound PCActn with the `requirePCA` guard from `@atlasauth/pca`, attaches `{ verdict, pcactn }` to the request on success, and otherwise replies `401` or `403` with a `WWW-Authenticate` challenge (which short-circuits the route). It is default-deny: a required check that is not enforced denies.

## Install

```sh
npm i @atlasauth/pca-fastify
# peer dependency, install alongside:
npm i fastify
```

`fastify` (v4 or v5) is an optional peer dependency; it is never imported, so the handler works with any compatible request/reply shape. Depends on `@atlasauth/pca`.

## Usage

```ts
import { pcaFastify, type PcaAttachment } from '@atlasauth/pca-fastify';
import { memoryPcaStore } from '@atlasauth/pca';

app.post(
  '/refunds',
  {
    preHandler: pcaFastify({
      audience: 'ins_acme',                       // the audience a PCActn must name
      resolveGrant: async (ref) => grants.get(ref) ?? null, // your root-grant store
      budgetStore: memoryPcaStore(),              // replay counter + budget; use a shared store in production
      hooks: { revocation: myRevocationChecker }, // e.g. built with createRevocationChecker from @atlasauth/pca
      context: async (req, pcactn) => ({
        plan: knownPlan(pcactn),                  // the plan your server knows for this action
        planAuthorized: true,                     // only if the principal authorized that plan root
        params: (req.body as any)?.params,
        risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 },
        budget: { B: 500, tau: 0, asOf: Date.now() },
      }),
    }),
  },
  async (req) => {
    const { verdict, pcactn } = (req as unknown as { pca: PcaAttachment }).pca;
    return { ok: true };
  },
);
```

The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or a JSON body `{ pcactn }`; the default extractor reads both. Rename the attached property with `attachAs` and override the deny response with `onDeny(result, req, reply)`. All other options are those of `requirePCA`; see `@atlasauth/pca`.

By default the `counter`, `revocation` and `plan_root_authorized` checks (plus audience, validity and grant binding) must pass, which is why `budgetStore`, `hooks.revocation` and `context()` are supplied above. `insecureAllowUnenforced: true` turns that off and is for local development only.

The verifier decides, not the client's proof.

## Status

Experimental. Part of Proof-Carrying Authority; the cryptography is unaudited.

## License

MIT - see LICENSE
