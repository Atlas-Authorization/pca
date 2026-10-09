---
title: Run the end-to-end demo
order: 4
---

# Run the end-to-end demo

See Proof-Carrying Authority work in about a minute, on your laptop. No cloud account, no Docker, no API
keys: everything runs on `127.0.0.1`.

```bash
npm create pca-app@latest my-pca-demo
cd my-pca-demo
npm install
npm start
```

The demo starts a real resource server (the default-deny verifier from `@atlasauth/pca-fetch`), a guardian
that cosigns with FROST 3-of-5, and an agent. It plays nine scripted outcomes, prints a colorized
walkthrough with a one-line explanation per step, then a summary table of *action, expected, actual,
reason*. It **exits nonzero if any outcome deviates**, so you can also run it in CI as a smoke test.

```bash
npm start              # walkthrough; exit code 1 if anything deviates
npm run step           # pause before each step
npm run json           # machine-readable result, nothing else on stdout
```

## What each step proves

| Step | What happens | Guarantee |
|---|---|---|
| 1 | The principal signs a grant (`stripe.refund` up to $500, a $300 trust budget) and registers the committed plan. | Authority is explicit and bounded; the agent cannot enlarge it. |
| 2 | The agent refunds $42 on a planned charge: **allowed**. | The action is a node of the committed plan, inside the signed policy, for this audience, with a fresh counter. |
| 3 | A refund on a charge that is not in the plan: **denied** (`plan_root_authorized`). | Being permitted is not enough; the action must be one the principal authorized. |
| 4 | A $450 refund needs t=3. Agent alone: **denied**. Two guardian nodes alone: refused. Agent + guardian (FROST 3-of-5) + principal: **allowed**. | Risk-adaptive threshold step-up; the guardian's signature needs 3 of 5 key shares. |
| 5 | The step-2 request is replayed: **denied** (`counter ... replay`). | Counters strictly increase per holder; a captured proof is worthless. |
| 6 | A bit-flipped signature, a delegation with its caveat stripped, and an action re-addressed to another server: **all denied**. | Every field is signed; delegation cannot be widened; proofs are audience-bound. |
| 7 | Two auto-approved $140 refunds against a $300 budget: the second is **denied** (`trust budget depleted`). | Machine-only authority is metered; exhaustion escalates to a human. |
| 8 | A sub-agent delegated "refunds up to $100": $60 allowed; $200 and an out-of-scope email **denied**. | Authority can shrink down a delegation chain, never grow. |
| 9 | An auditor with only public keys verifies the receipt, ledger inclusion proof and signed tree head offline; a log with one denial rewritten as an allowance is refused. | Offline auditability; history cannot be rewritten undetected. |

## What the demo is not

The five FROST shares and the principal key live in one process, so the threshold property is shown by
the API refusing a 2-node quorum, not by separate trust domains; in production the shares sit on separate
hosts or HSMs. State (counters, budget, ledger) is in memory, so back the `budgetStore` with Redis or a
database. This is not a security audit; see the [trust model](../security/trust-model.md).

Next: [Add PCA in 5 minutes](./five-minute-quickstart.md) to protect your own route.
