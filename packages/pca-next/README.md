# @atlasauth/pca-next

Next.js helper for Proof-Carrying Authority: wrap a Route Handler so the inbound PCActn is verified before your handler runs, with a 401/403 response otherwise.

## Install

```sh
npm i @atlasauth/pca-next
# peer dependency, install alongside:
npm i next
```

`next` (v14 or v15) is an optional peer dependency.

## Usage

```ts
// app/refunds/route.ts
import { withPCA } from '@atlasauth/pca-next';

export const POST = withPCA(
  {
    audience: 'ins_acme',   // this resource server's / instance id the PCActn must name
    resolveGrant,           // (ref) => Capability — look up the root grant
    budgetStore,            // per-holder replay/budget store
  },
  async (req, { pca }) => {
    const { verdict, pcactn } = pca;   // handler only runs on a valid PCActn
    return Response.json({ ok: true });
  },
);
```

The client sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`) or a JSON body `{ pcactn }` — the default extractor reads both. The wrapper verifies and is default-deny; it is the verifier that decides, not the client's proof.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
