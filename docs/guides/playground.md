---
title: Playground
order: 12
---

# Playground

The PCA playground is an interactive, client-side demo of the framework. It is to PCA what an OIDC or JWT playground is to OAuth: mint the credential, forge a presentation, and watch the verifier's per-clause verdicts. It runs the **real** `@atlasauth/pca` library in the browser (bundled to `pca.esm.js`). Nothing is reimplemented and nothing leaves the page.

Location: [`playground/`](../../playground) (files: `index.html`, `pca.esm.js`, `README.md`).

## Run it

ES modules need `http://`, not `file://`.

```
cd playground
python3 -m http.server 8080
# open http://localhost:8080
```

## Panels

| # | Panel | What you do and see |
|---|---|---|
| 1 | Keys | Generate local Ed25519 keypairs for the principal and the agent |
| 2 | Grant | Author a goal, predicates and risk policy; mint the Root Intent Grant (`mintRoot`/grant machinery) |
| 3 | Plan | Commit a plan; see the Merkle root. Anything outside it has no inclusion proof |
| 4 | Action and verify | Pick a plan node, optionally add params, build a signed PCActn (`buildPCActn`) and run the verifier (`verifyPCActnCore`). Checks that depend on later components report `not-enforced` |
| 5 | The trust battery | Each action costs `c = κ·r`. Auto-admit only if `r <= θ₁` and the budget covers the cost. Watch the budget drain and the required threshold climb as actions move away from the goal; only a human recharge raises it |
| 6 | Threshold signatures | Appears when the bundle exports `signShare` and `assembleThreshold`: at `t > 1` the action needs guardian and principal shares over the same canonical message |

The out-of-plan rejection demo shows the first kill-chain cut: an action with no inclusion proof fails `plan_inclusion` ([threat model](../security/threat-model.md)).

## The narrated loop

The end-to-end loop has eight steps: mint a grant, delegate to a task capability, commit a plan, emit a PCActn, let the Policy VM decide, verify offline, attempt an out-of-plan action (rejected), and drain then recharge the trust budget. In the demo, the ledger is an in-memory stub and the human co-sign is simulated with `recharge`.

Next: [Verify in your language](./verify-in-your-language.md).
