# PCA Playground

Interactive, client-side demo of Proof-Carrying Authority (spec §20.4). It runs the **real** `@atlasauth/pca`
library in the browser (bundled to `pca.esm.js`), nothing is reimplemented and nothing leaves the page.

Panels: keys, grant (goal + predicates + risk policy via `mintRoot`), plan (`commitPlan` Merkle root),
action + per-clause verification (`buildPCActn` -> `verifyPCActnCore`), an out-of-plan rejection demo, and the
**trust battery** (`riskScore`, `requiredThreshold`, `cost`/`debit`/`admit`/`leak`/`recharge`). A threshold-signature
panel appears automatically when the bundle exports `signShare`/`assembleThreshold`.

Wire format v2: the demo builds each PCActn with `aud` (the demo verifier id) and a 5-minute `iat`/`exp` window, and
verifies with `audience`, so the `wire`, `audience` and `validity` checks show per-clause.

## Serve

    cd tools/pca-playground && python3 -m http.server 8080   # open http://localhost:8080

(ES modules need http://, not file://.)

## Rebuild the bundle

From the repo root, using the repo's existing esbuild (no new dependency):

    npx esbuild packages/pca/src/index.ts --bundle --format=esm --platform=browser --outfile=tools/pca-playground/pca.esm.js

If `npx` cannot find it: `node_modules/.pnpm/esbuild@0.24.2/node_modules/esbuild/bin/esbuild ...`.

## Mapping

This is to PCA what Atlas's OIDC/JWT playground is to OAuth/JWT: mint the credential (grant), forge a
presentation (PCActn), and watch the verifier's per-clause verdicts.
