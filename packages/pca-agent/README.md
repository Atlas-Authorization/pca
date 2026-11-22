# @atlasauth/pca-agent

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Agent-side client for Proof-Carrying Authority (PCA). It commits a plan, builds and signs a PCActn (a proof-carrying action) for a plan node, posts it to a resource server, handles step-up approval, delegates attenuated authority to sub-agents, and checks ledger inclusion receipts.

The client talks to a resource server that exposes the PCA HTTP surface: `POST /v1/pca/plans`, `POST /v1/pca/actions` and `GET /v1/pca/stepups/:id` (the hosted Atlas API does, and so can your own server). `act` emits a proof; it does not authorize anything on its own. The resource server's verifier decides allow, step-up or deny.

## Install

```sh
npm i @atlasauth/pca-agent
```

Depends on `@atlasauth/pca` (installed transitively).

## Usage

```ts
import { createAgent } from '@atlasauth/pca-agent';

const client = createAgent({
  grant,                 // principal-signed Capability (see @atlasauth/pca)
  agentSecret,           // Ed25519 secret key (32 bytes) of the leaf holder
  rsBaseUrl: 'https://api.example.com',
  audience: 'ins_acme',  // required: the id the resource server verifies against
});

// 1. Commit the principal-authorised plan (once).
await client.commitPlan([{ id: 'refund-1', verb: 'stripe.refund', resource: 'ch_123' }]);

// 2. Act on a plan node: builds and signs a PCActn, then POSTs it.
const res = await client.act('refund-1', { amount: 500 });

if (res.status === 'allowed') {
  client.verifyReceipt(res.receipt);                       // ledger inclusion proof -> boolean
} else if (res.status === 'step_up') {
  const outcome = await client.awaitStepUp(res.stepupId);  // long-polls until a human approves or denies (timeout = deny)
} else if (res.status === 'denied') {
  console.log(res.verdict.reason);
}

// 3. Hand a narrower slice of authority to a sub-agent.
const sub = client.delegate({
  toPublic: subAgentPublicKey,
  addedCaveats: [{ type: 'ttl', secs: 60 }],
  agentSecret: subAgentSecret,
});
```

`audience` is required because a PCActn only verifies at the audience it names, which stops it being replayed at another server. A fresh random nonce is stamped on each action by default, and the per-action counter only moves forward. `act` resolves to `{ status: 'error', error }` (a `PcaAgentError`) for local failures such as calling before `commitPlan` or an unknown node id. Pass `fetch` to supply your own HTTP client.

## API

- `createAgent(options)` returns an `AgentClient` with `commitPlan`, `act`, `awaitStepUp`, `delegate`, `verifyReceipt`, plus `grant`, `chain`, `counter`, `budget`, `planRoot`.
- Types: `ActResult`, `StepUpOutcome`, `Receipt`, `Verdict`, `ActSlots` (optional signed slots such as `caution`), `PcaAgentError`.

## Failure modes

The client never reports `allowed` on anything less than an explicit, consistent allow with a receipt that verifies.

| Missing or wrong | Result |
|---|---|
| `audience` or a non-http(s) `rsBaseUrl` | `createAgent` throws `build_failed` |
| Plan commit answered non-2xx | `commitPlan` throws `bad_response`; no plan is kept |
| Plan commit response has no `plan_root`, or a different one | `commitPlan` throws `bad_response`; no plan is kept |
| `act` before `commitPlan` | `{ status: 'error', code: 'no_plan' }` |
| Node id not in the committed plan | `error` / `unknown_node` (the plan is copied at commit, later edits to your array do not count) |
| No `agentSecret` | `error` / `no_secret` |
| Network failure on `act` | `error` / `network`; the counter is still consumed, never reused |
| Non-JSON or empty body | `denied` |
| `allow` and `verdict.allow` disagree, or either is not the boolean `true` | `denied` |
| Allow on a non-2xx status | `denied` |
| Allow with no receipt, or a receipt whose inclusion proof does not verify | `error` / `bad_response` |
| Receipt discloses a `salt` that does not reproduce its commit for this action | `error` / `bad_response` |
| Step-up response without an id | `error` / `bad_response` |
| Step-up poll answered non-2xx with "approved" | not an approval; polling continues until `timeout` |
| Step-up poll answered 4xx (not 429) | `{ status: 'denied', httpStatus }`, polling stops |
| Step-up poll network failure | throws `network` |
| Budget in a response that is not three finite numbers | ignored |

## Limits

- `act` emits a proof. The resource server's verifier decides; the client only refuses to *claim* an allow it cannot support.
- The receipt check proves the entry is in the tree the server named. It does not prove that tree is the one other parties see: pin a signed tree head and a witness (see the transparency ledger guide) when that matters.
- The counter is local state. A restarted agent must resume from a persisted `counter`, or the server rejects its actions as replays.
- Pass `verifyReceipts: false` only for a test double with no real ledger.

## Status

Production: the fail-closed table above is covered by exact-outcome tests against a stateful fake server, and the package is in the mutation set. The underlying cryptography in `@atlasauth/pca` has not been independently audited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
