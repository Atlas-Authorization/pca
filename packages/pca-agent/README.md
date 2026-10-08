# @atlasauth/pca-agent

Agent-side client for Proof-Carrying Authority: commit a plan, act with a PCActn + threshold share, handle step-up, delegate to sub-agents, verify receipts.

## Install

```sh
npm i @atlasauth/pca-agent
```

Depends on the core `@atlasauth/pca` (installed transitively).

## Usage

```ts
import { createAgent } from '@atlasauth/pca-agent';

const client = createAgent({
  grant,                 // principal-signed Capability
  agentSecret,           // Ed25519 secret (32 bytes) of the leaf holder
  rsBaseUrl: 'https://api.example.com',
  audience: 'ins_acme',  // the resource-server / Atlas instance id the PCActn is FOR
});

// 1. Commit the principal-authorised plan (once).
await client.commitPlan([{ id: 'refund-1', verb: 'stripe.refund', resource: 'ch_123' }]);

// 2. Act on a plan node — builds + signs a PCActn and POSTs it to the resource server.
const res = await client.act('refund-1', { amount: 500 });

if (res.status === 'allowed') {
  client.verifyReceipt(res.receipt);        // check the ledger inclusion proof
} else if (res.status === 'step_up') {
  const outcome = await client.awaitStepUp(res.stepupId); // poll for human co-sign
}
```

`act` emits a proof-carrying action; it does not authorize on its own. The resource server's verifier decides allow / step-up / deny.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
