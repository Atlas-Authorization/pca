# PCA Playground

Interactive, client-side demo of Proof-Carrying Authority (spec §20.4). It runs the **real** `@atlasauth/pca`
library in the browser (bundled to `pca.esm.js`), nothing is reimplemented and nothing leaves the page.

Panels: keys, grant (goal + predicates + risk policy via `mintRoot`), plan (`commitPlan` Merkle root),
action + per-clause verification (`buildPCActn` -> `verifyPCActnCore`), an out-of-plan rejection demo, and the
**trust battery** (`riskScore`, `requiredThreshold`, `cost`/`debit`/`admit`/`leak`/`recharge`). The threshold panel uses a policy-decided t with role-bound shares (and shows a re-labelled share being rejected); the last panel shows a pure post-quantum root refused without a verifier pin (R3-01).

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

## Freshness gate

    tools/pca-playground/check-fresh.sh

Rebuilds the verified core's `dist/` and the bundle into a temp file and byte-compares it to the committed
`pca.esm.js` (esbuild output has no timestamps). Wired into `scripts/pca-audit-all.sh` as step 5b. `node:crypto`
(used only by the verified core's Merkle glue) is aliased to `shims/node-crypto.js`, backed by `@noble/hashes`.

## Mapping

This is to PCA what Atlas's OIDC/JWT playground is to OAuth/JWT: mint the credential (grant), forge a
presentation (PCActn), and watch the verifier's per-clause verdicts.
