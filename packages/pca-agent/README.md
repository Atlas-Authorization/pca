# @atlasauth/pca-agent

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
  const outcome = await client.awaitStepUp(res.stepupId);  // polls for human co-sign
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

## Status

Experimental. The underlying cryptography in `@atlasauth/pca` has not been independently audited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
