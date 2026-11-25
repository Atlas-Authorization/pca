---
title: Authorize a whole workflow
order: 47
---

# Authorize a whole workflow

A person signs one commitment to a multi-step job: which steps, in what order, what each step may take from the one
before, and how much it may cost. Every step is then admitted only as part of that commitment. Use it when an agent
does several things in sequence ("get a quote, then pay at most the quoted total") and approving each step alone
would miss the relationship between them.

## The idea

- The **commitment** is a signed DAG: steps (verb and resource), dependencies, **edges** that constrain one step's
  input by an earlier step's output, label (taint) rules, freshness, cost caps and a step budget.
- The **resource server** signs a **receipt** for every step it executes: output values (as digests, plus an optional
  integer to compare) and labels. Receipts form a chain, each naming the one before it.
- `admitStep` is a pure function: it takes the commitment, the pinned keys, the receipts so far, the clock and the
  step the agent wants to run, and returns `allow`, `deny` or `escalate`. There is no store and no network call.

Anything unknown, malformed, unsigned, out of order or unplanned is a `deny`. Only two things `escalate`: a step
that runs before the step it depends on and has no constraint on its input, and a label you marked "ask a human".

## Sign the commitment

```ts
import { admitStep, b64u, hashCanonical, publicKeyOf, signStepReceipt, signWorkflow, wfOutput, type WorkflowBody } from '@atlasauth/pca';

const NOW = Date.now();
const principalSecret = new Uint8Array(32).fill(11); // use real keys; fixed bytes keep this snippet short
const serverSecret = new Uint8Array(32).fill(12);
const PRINCIPAL = b64u(publicKeyOf(principalSecret));
const SERVER = b64u(publicKeyOf(serverSecret));

const step = (id: string, deps: string[], o = {}) =>
  ({ id, verb: `shop.${id}`, resource: 'cart/1', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });

const body: WorkflowBody = {
  v: 1, id: 'checkout-1', principal: PRINCIPAL, goal_digest: null, plan_root: null,
  issued_at: NOW - 1000, expires_at: NOW + 60_000,
  steps: [
    step('quote', []),
    step('pay', ['quote']),
    step('lookup', []),
    step('notify', ['lookup'], { deny_labels: ['pii'] }),
  ],
  // pay's amount must be at most quote's total
  edges: [{ from: { step: 'quote', field: 'total' }, to: { step: 'pay', param: 'amount' }, op: 'le', unit: null, deny_labels: [], promise: null }],
  budget: { max_steps: 3, caps: {} },
};
const workflow = signWorkflow(principalSecret, body);
```

`signWorkflow` throws if the body is malformed, is not a DAG, or names a principal other than the signer. List fields
(`deps`, `deny_labels`) must be sorted and unique. Edge operators are `eq`, `le`, `ge`, `lt` and `gt`; values are
integers, strings or booleans, never floats. Limits: 64 steps, 256 edges, 16 dependencies, 16 labels per list.

## Admit steps

```ts
const request = (id: string, params: Record<string, number> = {}) =>
  ({ step: id, verb: `shop.${id}`, resource: 'cart/1', params, units: {}, goal_digest: null, plan_root: null });
const admit = (receipts: unknown[], req: ReturnType<typeof request>) =>
  admitStep({ workflow, principal: PRINCIPAL, rsSigner: SERVER, receipts, now: NOW, request: req });

admit([], request('quote'));   // { decision: 'allow', code: null, ... }
```

The `principal` and `rsSigner` arguments are keys **you** pinned. A key written inside the workflow is never trusted.

After the quote runs, the resource server signs a receipt. The total goes in as an integer the next edge can compare:

```ts
const quote = signStepReceipt(serverSecret, {
  workflow: body, step: 'quote', outcome: 'ok', paramsDigest: hashCanonical({}),
  outputs: { total: wfOutput(30, { num: true }) }, issuedAt: NOW - 1,
});

admit([quote], request('pay', { amount: 30 })).decision;  // 'allow'
admit([quote], request('pay', { amount: 31 })).code;      // 'edge_relation'
```

## Expected outcomes

| Request | Receipts | Result |
|---|---|---|
| `quote` | none | allow |
| `pay` amount 30 or 12 | the quote (total 30) | allow |
| `pay` amount 31 | the quote | deny `edge_relation` |
| `pay` | none | escalate `pipeline_unconstrained` (nothing to check the amount against) |
| `wire` | the quote | deny `unplanned_step` |
| `quote` again | the quote | deny `already_done` |
| `pay` | a quote receipt signed by another key | deny `bad_receipt` |
| `quote` | a commitment edited after signing | deny `bad_signature` |
| `notify` | a `lookup` receipt whose output has label `pii` | deny `taint_flow` |
| `notify` as a fourth step | three receipts | deny `budget_exceeded` |

For the `taint_flow` row the lookup receipt carries `wfOutput('customer-contact', { labels: ['pii'] })`. The label
flows to every step downstream of it, not only the next one.

## Promises

A step can be allowed to run before its dependency has a receipt if every edge from that dependency names a
`promise` (an id you choose). Without one it escalates, as in the table. `admitStep` then reports the edge as `pending`. When the dependency's receipt exists, call
`bindPromises` with the same input: it re-checks the step's parameters against every edge and denies if the promise
turned out wrong. A broken promise is a violation, and what you do about it (revoke, compensate) is your policy.

## Other bindings

- `goal_digest` and `plan_root` in the commitment bind it to a goal and a Merkle plan root. A request must carry the
  same values, or it is denied (`goal_mismatch`, `plan_root_mismatch`). `planRootAuthorized` answers "does this signed
  commitment authorize that root?".
- `workflowCommitmentError(workflow, principal, now)` lets whoever signs receipts refuse to sign for a commitment the
  verifier would reject.
- `fresh_ms` on a step requires its dependencies' receipts to be recent (`stale_dep`).
- Costs: every cost name a step uses must have a cap in `budget.caps`, or the body is invalid.

## Failure modes

| Code | Meaning |
|---|---|
| `bad_workflow`, `bad_dag` | malformed body, or a cycle, a duplicate id, a missing dependency |
| `bad_signature`, `not_yet`, `expired` | wrong principal, or outside `issued_at` to `expires_at` |
| `bad_receipt` | a receipt is malformed, for another workflow, out of sequence, signed by another key, or from the future. `at` is its index. |
| `deps_unmet`, `dep_failed` | a dependency has no receipt, or its receipt says `failed` |
| `edge_unit`, `edge_value`, `edge_digest`, `edge_missing` | the value does not match the edge: unit, number, exact digest, or the field is absent |
| `params_mismatch`, `step_mismatch` | the request differs from what the step pins |

## Run it

The `workflow` script of the `pca-guides-a` example runs this scenario and prints each outcome.

## Next step

- Sign what an agent may see between steps with [read-side authorization](./read-side-authorization.md); the labels
  it produces are the labels this guide's rules act on.
- Decide a whole job once with [agent payments and approvals](./agent-payments-and-approvals.md).
