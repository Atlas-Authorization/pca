# @atlasauth/pca-hono

Hono middleware for Proof-Carrying Authority: verifies the inbound PCActn, sets the verdict on the context, or answers 401/403 with a WWW-Authenticate challenge.

## Install

```sh
npm i @atlasauth/pca-hono
# peer dependency, install alongside:
npm i hono
```

`hono` (^4) is an optional peer dependency.

## Usage

```ts
import { pcaHono } from '@atlasauth/pca-hono';

app.post(
  '/refunds',
  pcaHono({
    audience: 'ins_acme',   // this resource server's / instance id the PCActn must name
    resolveGrant,           // (ref) => Capability — look up the root grant
    budgetStore,            // per-holder replay/budget store
  }),
  (c) => {
    const { verdict, pcactn } = c.get('pca');  // set on success
    return c.json({ ok: true });
  },
);
```

The client sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`) or a JSON body `{ pcactn }` — the default extractor reads both. The middleware verifies and is default-deny; it is the verifier that decides, not the client's proof.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
