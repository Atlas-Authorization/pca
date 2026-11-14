---
title: Plan commitment (L1)
order: 3
---

# Plan commitment (L1)

Before acting, the agent commits to a **plan**: a DAG of intended action nodes. It commits the **Merkle root**, not the contents. The principal's side (in the hosted surface, the guardian) authorizes the plan root. From then on, every action ships a Merkle inclusion proof that it is a node of the committed plan.

An out-of-plan action, for example an injected "wire the money", has **no inclusion proof**. It is rejected before the credential is even consulted. The plan is a tamper-evident contract the agent is held to; deviating means committing a new plan, which is itself visible.

## Plan nodes

```ts
interface PlanNode {
  id: string;
  verb: string;
  resource: string;
  params_digest?: string;        // defaults to EMPTY_PARAMS_DIGEST
  reversibility_class?: string;  // defaults to DEFAULT_REVERSIBILITY_CLASS ('reversible')
  pre?: unknown;                 // pre-conditions
  post?: unknown;                // post-conditions
}
```

```ts
import { commitPlan } from '@atlasauth/pca';

const plan = commitPlan([
  { id: 'n1', verb: 'list_sessions', resource: 'session:*' },
  { id: 'n2', verb: 'revoke_session', resource: 'session:42', reversibility_class: 'rate_limited' },
]);
plan.root;                // base64url Merkle root
plan.proofFor('n2');      // InclusionProof { index, size, path: [{ side, hash }] }
```

`commitPlan` throws on duplicate node ids. Other helpers: `merkleRoot`, `merkleProof`, `verifyInclusion`, `planNodeLeaf`, `planLeaf`, `conditionsDigest`, `paramsDigest`.

## What is committed in each leaf

A leaf binds the whole action, so no field can change after commitment:

```
{ node_id, verb, resource, params_digest, reversibility_class, conditions }
```

- **Params commitment, one rule.** `params_digest = hashCanonical(params ?? {})`. A node that omits `params_digest` means "no params" and commits as `EMPTY_PARAMS_DIGEST`; the action for it carries the same value. Plan node and action therefore always reconcile; there is no null/absent form.
- **Conditions.** `conditions = conditionsDigest(pre, post)` = hash of `canonical({ pre: pre ?? null, post: post ?? null })`. It travels in the PCActn as `plan.conditions_digest`.
- **Reversibility class** defaults the same way on node and action.

The verifier recomputes the leaf from the PCActn's own `action` fields (plus `node_id` and `conditions_digest`) and checks it against `plan.root` using the carried proof. Changing the verb, resource, params digest or class after signing makes the inclusion proof fail.

## Merkle construction

RFC 6962 shape with domain separation:

- leaf hash = `SHA-256(0x00 || canonical(leaf))`
- node hash = `SHA-256(0x01 || left || right)`
- the tree splits at the largest power of two strictly less than `n`, so no leaf is ever duplicated
- a proof step `{ side, hash }` records which side the **sibling** sits on

The `0x00`/`0x01` prefixes make a leaf indistinguishable from an internal node (second-preimage safe). `verifyInclusion` never throws: malformed proofs return `false`. The exact bytes are in [Wire formats](../reference/wire-formats.md).

## Plan authorization

Verifier checks `plan_inclusion` (the leaf opens to the root) and `plan_root_authorized` (the root is one the principal side accepted). In `verifyPCActn`, `plan_root_authorized` passes only when the resource server supplies its own copy of the plan (`context.plan`), its Merkle root equals `plan.root`, and the server asserts that the principal authorized that root (`context.planAuthorized: true`). A plan whose root does not match, or `planAuthorized: false`, fails the check; with no plan or no `planAuthorized` it is `not-enforced` (and `verifyPCActnCore` alone, with no resource-server plan, always reports `not-enforced`: the agent supplies its own plan, so inclusion proves nothing about authorization; pass `require: ['plan_root_authorized']`, or use `requirePCA`, which demands it by default). On the hosted surface, a plan root must be a committed **and authorized** plan of the grant, or the action is denied on `plan_root_authorized`. Committing is not authorizing: the committer (the grant's holder or its principal) signs the plan root, and the principal then authorizes that root with a signature from the grant's principal key. A grant can opt out of the second step only in its signed envelope, with `plan_policy: "agent_commit"`; the plan is then authorized when committed, and the server takes each action's reversibility class from its own verb catalog instead of from the agent-committed plan node. See [API reference](../reference/api.md#plans) and [Trust model](../security/trust-model.md).

## Plan lifecycle (self-hosted verifiers)

A self-hosted resource server can keep its plans in a plan registry (`createPlanRegistry` from `@atlasauth/pca`) instead of computing `planAuthorized` itself. The registry gives each plan an explicit state:

| State | Reached by | Executable? |
|---|---|---|
| `draft` | `draft(grantRef, nodes)`: the root is computed from the nodes | no |
| `validated` | `validate`: unique node ids, a verb and a resource per node, known reversibility classes, then your own `validator` | no |
| `committed` | `commit`: the root is fixed | no: committing is not authorizing |
| `authorized` | `authorize(grantRef, root, { by, expiresAt? })`, called after you have verified the principal's consent | yes, while the approval has not expired |
| `revoked` | `revoke` from any other state | never again |

The transitions only go in this order, and a refused transition names the current state. Whether a plan is executable is decided when an action uses it, not stored. The plan must be `authorized`, its approval unexpired, and its stored nodes must still hash to the root. Right before execution, `check(grantRef, root, { nodeId, operation })` also requires that the node exists and that the operation's verb, resource and params are the ones the principal approved. Changed params are refused.

Pass the registry to `authorize({ plans })`. For an action whose plan root is registered, the verifier gets the stored plan, and `planAuthorized` is true only if the plan is executable now. A denial names the state, for example `plan_state: plan ... is committed but not authorized by the principal`, or `plan_state: plan ...: the principal's approval expired at ...`. An unregistered root is denied, unless `plan: 'single-step'` is set: a one-step action is then limited by the grant alone. For `authorizeExecution`, `authorizeToolCall` and the agent-framework guards, pass `registry.isPlanAuthorized` as their `isPlanAuthorized` option. With `createExecutor`, the plan state is checked again immediately before an irreversible side effect, so a plan revoked between the decision and the execution stops it. Nothing on the wire changes: the registry only decides what the verifier is told about the plan.

## Plans and risk

The plan also supplies the deterministic **semantic distance** used by the [risk functional](./policy-and-risk.md): the normalized geodesic between an action's node and the goal node in the committed DAG. Edges come from node references in `pre`/`post`; with no declared edges it falls back to index distance.

Next: [Policy and risk](./policy-and-risk.md).
