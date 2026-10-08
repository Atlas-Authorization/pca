---
title: Agent quickstart
order: 10
---

# Agent quickstart: integrate your agent

> Preview. The hosted `/v1/pca/*` surface must be enabled for the instance (see [Resource-server quickstart](./resource-server-quickstart.md#the-gate)).

Package: `@atlasauth/pca-agent`. It builds the plan commitment, the PCActn and the agent's threshold share for you. Concepts behind each step: [credential model](../concepts/credential-model.md), [plan commitment](../concepts/plan-commitment.md), [threshold and step-up](../concepts/threshold-and-step-up.md).

## Prerequisites

You need a Root Intent Grant whose **holder** is your agent's public key, and the agent's Ed25519 secret. The principal (a human, ideally via their WebAuthn-protected root) mints the grant and registers it with the resource server via `POST /v1/pca/grants` (body `{ grant }`). Minting, with `@atlasauth/pca`:

```ts
import { generateKeyPair, encodeKey, mintGrant, DEFAULT_RISK_POLICY } from '@atlasauth/pca';

const principal = generateKeyPair();
const agentKeys = generateKeyPair();

const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: encodeKey(agentKeys.publicKey),
  goal: 'summarize my documents',               // only a salted hash goes in the grant
  envelope: {
    predicates: [{ verb: 'read', resource: 'doc:*' }],
    caveats: [{ type: 'expires', at: Date.now() + 3_600_000 }, { type: 'delegation_depth', max: 2 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
});
```

## The loop (about 10 lines)

```ts
import { createAgent, type Receipt } from '@atlasauth/pca-agent';

const agent = createAgent({
  grant,
  agentSecret: agentKeys.secretKey,               // Uint8Array, 32 bytes
  agentPublic: encodeKey(agentKeys.publicKey),
  rsBaseUrl: 'https://rs.example.com',
});

await agent.commitPlan([{ id: 'n1', verb: 'read', resource: 'doc:1' }]);

const r = await agent.act('n1', { page: 2 });
switch (r.status) {
  case 'allowed':  agent.verifyReceipt(r.receipt); break;                 // true: anchored in the ledger
  case 'denied':   console.warn(r.httpStatus, r.verdict.reason, r.verdict.checks); break;
  case 'step_up': {
    const o = await agent.awaitStepUp(r.stepupId);                        // human approves out of band
    if (o.status === 'approved' && o.receipt) agent.verifyReceipt(o.receipt as Receipt);
    break;
  }
  case 'error':    throw r.error;                                         // PcaAgentError
}
```

Notes grounded in the client:

- `commitPlan(nodes)` computes the Merkle root locally, posts `{ grant_ref, nodes }` to `/v1/pca/plans`, and throws `PcaAgentError('bad_response')` if the server's `plan_root` differs. Nodes are `PlanNode`: `id`, `verb`, `resource`, optional `params_digest`, `reversibility_class`, `pre`, `post`.
- `act(nodeId, params?)` is bound to a committed node. A node not in the plan returns `{ status: 'error', error.code === 'unknown_node' }` locally; an action the server rejects comes back `denied`. It never throws for deny or step-up. The counter is monotonic and is never reused, even when the call fails.
- Plaintext `params` are committed by digest in the PCActn. The resource server receives the plaintext only if you send it separately where it needs predicates over params (the hosted `/v1/pca/actions` accepts optional `params`, `subject`, `env` beside `pcactn`; the client currently posts only `{ pcactn }`).
- Step-up: `awaitStepUp(id, { pollMs = 1000, timeoutMs = 300000 })` polls `GET /v1/pca/stepups/:id` until `approved | denied | expired`, else `{ status: 'timeout' }`. On `approved` the response carries the `receipt`.
- Error codes (`PcaAgentError.code`): `no_plan`, `unknown_node`, `no_secret`, `network`, `bad_response`, `build_failed`.
- `fetch` is injectable: `createAgent({ ..., fetch })` (any `(url, init) => Promise<{ status, json() }>`).
- Budget: when the verdict includes `budget`, `agent.budget` is updated.

## Delegate to a sub-agent

`delegate()` returns a client holding a longer chain with strictly lesser authority (caveats are only ever added). The sub-agent signs with its own key, so you pass its secret.

```ts
const subKeys = generateKeyPair();
const sub = agent.delegate({
  toPublic: encodeKey(subKeys.publicKey),
  addedCaveats: [{ type: 'expires', at: Date.now() + 600_000 }],
  agentSecret: subKeys.secretKey,
});

await sub.commitPlan([{ id: 's1', verb: 'read', resource: 'doc:2' }]);
const r2 = await sub.act('s1');
```

The sub-client starts at counter 0 (counters are per leaf holder) and the resource server evaluates the delegated caveats conjunctively with the root's. A revoked ancestor capability kills its descendants. `delegate()` throws `no_secret` if the parent has no `agentSecret`.

## Verify a receipt

`agent.verifyReceipt(receipt)` returns `true` when `receipt.inclusion_proof` proves `receipt.commit` is in the ledger at `receipt.root` (it wraps `verifyLedgerInclusion`; it never throws). A receipt is `{ index, commit, root, size?, grant_ref?, inclusion_proof }`. To check against a log head you trust, compare `root` with `GET /v1/pca/ledger?grant_ref=...` and, for consistency over time, use `verifyLedgerConsistency` from `@atlasauth/pca`.

## See it run

`pnpm --filter @atlasauth/pca example` walks the whole loop, including an out-of-plan rejection and trust-budget drain. See also the [playground](./playground.md).

## Optimistic claims, attestation and other extras

`@atlasauth/pca-agent` implements the core loop. For the optional paths, build the pieces with `@atlasauth/pca` and send them beside the PCActn in the `POST /v1/pca/actions` body (the stock client posts only `{ pcactn }`):

- `attestation`: an `AttestationDocument` ([attestation](../concepts/attestation.md)).
- `optimistic`: a `BondedClaim` from `openOptimistic` ([optimistic and ZK](../concepts/optimistic-and-zk.md)).
- `params`, `subject`, `env`: plaintext context for predicates. `params` must hash to the PCActn's `params_digest`.

Next: [Resource-server quickstart](./resource-server-quickstart.md).
