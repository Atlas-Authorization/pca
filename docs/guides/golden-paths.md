---
title: Golden paths
order: 4
---

# Golden paths

Six jobs most integrations start with. Each has one scaffold you can run, the steps, how much you have to learn, and
the mistakes people make. Run a scaffold with `npm create pca-app@latest my-app -- --template <name>` (or
`npx create-pca-app my-app --template <name>`), then `npm install && npm start`.

| # | Job | Scaffold | Concepts | Lines you write |
|---|---|---|---|---|
| 1 | Protect an MCP server | `mcp` | grant, proof, tool-to-action mapping | about 60 server, 30 agent |
| 2 | Let an agent pay under $200 a day, with approval | `payments` | mandate, auto / step-up / deny | about 25 |
| 3 | Define my own actions | `actions` | action definition, traits | one YAML file |
| 4 | Goal to policy to review to enforcement | `goal` | draft, signed approval, pinned reviewer | about 25 |
| 5 | Delegate to a sub-agent | `delegation` | chain, narrowing caveat | about 10 |
| 6 | An A2A hop | none yet; code below | extension, per-hop proof | about 20 |

All six rest on the same server step, so learn it once: [Add PCA to your framework](./framework-recipes.md).

## 1. Protect an MCP server

```bash
npm create pca-app@latest my-mcp -- --template mcp
cd my-mcp && npm install && npm run demo
```

You see two refunds allowed and three refused (a tool the grant does not allow, an amount over the limit, no proof),
each with its reason.

1. Map each tool call to an action: `refund` is `stripe.refund` on `charge:<id>`. Server and agent use the same table.
2. On the server, call `authorizeToolCall` before running a tool, with your own grant store and a replay store.
3. On the agent, wrap `fetch` with `pcaFetch(agent, toolAction)`. It signs one proof per tool call.

Where people get stuck: the agent and server map the same tool to different action strings (the refusal reads
`operation: the proof is for ... but this operation is ...`), and two server instances without a shared replay store
(`replay`). Both are explained in [Refusal reasons](../reference/refusals.md). The longer walkthrough is the
[MCP quickstart](./mcp-quickstart.md).

## 2. Let an agent pay under $200 a day, with approval

```bash
npm create pca-app@latest my-pay -- --template payments
cd my-pay && npm install && npm start
```

One mandate holds the terms: the merchants it may pay, the currency, a hard ceiling per charge, the line under which the
agent pays alone ($50), and the total it may spend alone before a person must refill it ($200). Each charge is decided
against it: `auto`, `step_up` (ask a person) or `deny`.

1. Build the mandate with `buildPaymentMandate`.
2. Decide each charge with `authorizeCharge`, then `settleCharge` to carry the new budget forward.
3. When the answer is `step_up`, ask the person. A signed answer refills the budget (`applyHumanCosign`).
4. For more than one server, keep the budget in a store with a compare-and-set (`authorizeChargeAtomic`).

Where people get stuck: amounts must be whole numbers of the smallest unit (use cents), and the per-charge ceiling cannot
exceed the total. The constructor says which. Card-network tokens and wallet permissions are in
[Agent payments, risk-priced approvals and wallet permissions](./agent-payments-and-approvals.md).

## 3. Define my own actions

```bash
npm create pca-app@latest my-actions -- --template actions
cd my-actions && npm install && npm run lint && npm test && npm run build
```

An action is defined once, in YAML or the TypeScript builder: its verb, resource, typed parameters with units, effects and
reversibility. Everything else is derived from it: the signed schema, how a route is bound to it, the policy card text and
the risk. A definition you have not confirmed is treated as the most restrictive kind of action.

1. Edit `actions/acme.yaml`.
2. `npm run lint` (24 rules) and `npm test` (your examples must come out as written).
3. `npm run build`, then sign and publish with a key you control.

Importers read MCP tool schemas, OpenAPI, GraphQL and others; their suggestions are never trusted until you confirm
them.

## 4. Goal to policy to review to enforcement

```bash
npm create pca-app@latest my-goal -- --template goal
cd my-goal && npm install && npm start
```

1. A model drafts a policy from the sentence (your function; the template uses a stub so it runs offline).
2. A person reviews the draft: permissions, limits, analyzer findings, any invented verb.
3. The reviewer signs the exact draft. An edited draft or an unpinned key does not load.
4. Only a signed draft becomes an agent. The server decides every action against the signed grant.

This does not prove the model understood the sentence. For the typed version, with a goal compiled to policy, a semantic
diff and signed tests, see [Natural-language policy, generate then review](./nl-policy-review.md).

## 5. Delegate to a sub-agent

```bash
npm create pca-app@latest my-delegation -- --template delegation
cd my-delegation && npm install && npm start
```

```ts
const sub = parent.subAgent({ addedCaveats: [{ type: 'max_spend', usd: 100 }] });
```

One call adds a hop to the chain. A hop can only add restrictions, so the sub-agent never exceeds its parent. Revoking the
grant stops the parent and every sub-agent under it. The scaffold also shows the server side in one call, `protect()`, and
`explainRefusal()` for turning a refusal into a fix.

## 6. An A2A hop

PCA rides on A2A as an extension. The caller attaches a proof to the task; the callee verifies it before acting, and each
further hop must extend the previous chain (it can only narrow).

```ts
import { attachPcaToA2ATask, pcaA2AMiddleware } from '@atlasauth/pca-a2a';

// caller: one proof per task, from the same agent facade as everywhere else
const { pcactn } = parent.act('stripe.refund', 'charge:ch_1', { amount: 40, currency: 'usd' });
const task = attachPcaToA2ATask({ id: 't1', status: { state: 'submitted' } }, pcactn);

// callee: the full verifier, under the principal it trusts
const guard = pcaA2AMiddleware({
  aud: 'ins_callee',
  expectedRootIssuer: principalPublicKey,
  hooks: { revocation: ({ grant }) => ({ enforced: true, ok: !revoked.has(grant.id) }) },
  context: (p) => contextFor(p), // params, the authorized plan, the budget: from the callee's own data
});
const verdict = await guard(task); // { ok: true, ... } or { ok: false, reason }
```

When the callee needs authority it does not have, it answers `TASK_STATE_AUTH_REQUIRED` with a typed need; the caller
resumes the task with a proof for exactly that need. `verifyA2ADelegation` checks a multi-hop path. The A2A package
README has the complete API.

## When something is refused

Read the reason. It starts with the check that failed, and [Refusal reasons](../reference/refusals.md) says what it means and
how to fix it. In TypeScript, `explainRefusal(reason)` returns the same guidance in code.
