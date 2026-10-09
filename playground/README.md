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

    tools/pca-playground/build.sh

This bundles `entry.ts` (which re-exports only what `index.html` uses, directly from `packages/pca/src`) with the
repo's esbuild for `--platform=browser`. The only Node builtins the reachable code touches (`node:module`,
`node:path`, used by the lazy FN-DSA wasm loader in `pq.ts`) are aliased to tiny shims in `shims/`; the loader then
fails closed in the browser. The script fails if the output still references any `node:` builtin. The committed
`pca.esm.js` is generated: rebuild it after changing `packages/pca/src` (it includes the current normative checks,
e.g. `grant_ref_bound`, which the page shows per clause).

## Mapping

This is to PCA what Atlas's OIDC/JWT playground is to OAuth/JWT: mint the credential (grant), forge a
presentation (PCActn), and watch the verifier's per-clause verdicts.
