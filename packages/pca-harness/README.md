# @atlasauth/pca-harness

PCA framework-evolution B1 reference prototype: an auditable orchestration harness (the attested TCB) that wraps an UNTRUSTED model/tool oracle and enforces the PCA invariants (plan-inclusion, taint, trust-budget) before any action becomes a signed PCActn.

## Install

```sh
npm i @atlasauth/pca-harness
```

Depends on the core `@atlasauth/pca` (installed transitively).

## Usage

```ts
import { Harness } from '@atlasauth/pca-harness';

const harness = new Harness({
  grant,                 // principal-signed root Capability
  agentSecret,           // Ed25519 secret — the oracle never sees this; only the harness signs
  plan: [{ id: 'refund-1', verb: 'stripe.refund', resource: 'ch_123' }],
  audience: 'ins_acme',
  budget,                // decaying TrustBudget
});

// The untrusted model proposes an action; the harness enforces plan-inclusion → taint → budget → sign.
const result = await harness.step(async () => ({
  nodeId: 'refund-1',
  verb: 'stripe.refund',
  resource: 'ch_123',
  params: { amount: 500 },
  inputs: [{ ref: 'email:42', provenance: 'untrusted' }],
}));

if (result.ok) {
  result.pcactn;          // signed PCActn + inclusionProof
} else {
  result.reason;          // 'out_of_plan' | 'over_budget' | 'bad_candidate' — no PCActn produced
}

harness.harnessMeasurement(); // digest of the harness's policy surface (what an attestation covers)
```

A compromised oracle cannot form an out-of-policy action — the harness signs only after the invariants pass. The signed PCActn still carries no authority of its own; the resource server's verifier decides.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
