# @atlasauth/pca-express

Express middleware for Proof-Carrying Authority: requirePCA() verifies the inbound PCActn and attaches the verdict, or answers 401/403 with a WWW-Authenticate challenge.

## Install

```sh
npm i @atlasauth/pca-express
# peer dependency, install alongside:
npm i express
```

`express` (v4 or v5) is an optional peer dependency.

## Usage

```ts
import { pcaExpress } from '@atlasauth/pca-express';

app.post(
  '/refunds',
  pcaExpress({
    audience: 'ins_acme',   // this resource server's / instance id the PCActn must name
    resolveGrant,           // (ref) => Capability — look up the root grant
    budgetStore,            // per-holder replay/budget store
  }),
  (req, res) => {
    const { verdict, pcactn } = req.pca!;  // attached on success
    res.json({ ok: true });
  },
);
```

The client sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`) or a JSON body `{ pcactn }` — the default extractor reads both. The middleware verifies and is default-deny (an unenforced required check denies); it is the verifier that decides, not the client's proof.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
