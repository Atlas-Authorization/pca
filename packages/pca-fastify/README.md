# @atlasauth/pca-fastify

Fastify plugin/preHandler for Proof-Carrying Authority: verifies the inbound PCActn, attaches the verdict, or replies 401/403 with a WWW-Authenticate challenge.

## Install

```sh
npm i @atlasauth/pca-fastify
# peer dependency, install alongside:
npm i fastify
```

`fastify` (v4 or v5) is an optional peer dependency.

## Usage

```ts
import { pcaFastify } from '@atlasauth/pca-fastify';

app.post(
  '/refunds',
  {
    preHandler: pcaFastify({
      audience: 'ins_acme',   // this resource server's / instance id the PCActn must name
      resolveGrant,           // (ref) => Capability — look up the root grant
      budgetStore,            // per-holder replay/budget store
    }),
  },
  async (req, reply) => {
    const { verdict, pcactn } = (req as { pca: { verdict: unknown; pcactn: unknown } }).pca;
    return { ok: true };
  },
);
```

The client sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`) or a JSON body `{ pcactn }` — the default extractor reads both. The preHandler verifies and is default-deny; it is the verifier that decides, not the client's proof.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
