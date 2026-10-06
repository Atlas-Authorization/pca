# PCA Playground

Interactive, client-side demo of Proof-Carrying Authority. It runs the real `@atlasauth/pca` library in the browser (bundled to `pca.esm.js`); nothing is reimplemented and nothing leaves the page.

Panels: keys, grant, plan commitment, action + per-clause verification, an out-of-plan rejection demo, and the trust battery. See [docs/guides/playground.md](../docs/guides/playground.md).

## Serve

    cd playground && python3 -m http.server 8080   # open http://localhost:8080

(ES modules need http://, not file://.)
