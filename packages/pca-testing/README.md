# @atlasauth/pca-testing

Testing kit for Proof-Carrying Authority: factories for grants and PCActns, a fake verifier and state store, and assertion helpers so integrators can unit-test their PCA wiring.

## Install

```sh
npm i -D @atlasauth/pca-testing
```

Depends on the core `@atlasauth/pca` only — no backend, network, or running resource server needed.

## Usage

```ts
import { testAgent, makePCActn, expectVerifies, expectDenied, tamper, memoryStateStore } from '@atlasauth/pca-testing';

const agent = testAgent();                               // real signed grant + act/dryRun/subAgent
const { pcactn, encoded } = makePCActn(agent, 'refund', 'ch_123', { amount: 100 });

await expectVerifies(pcactn);                            // throws naming the failing checks if denied

// Tampering is caught by the REAL core verifier (plan_inclusion / leaf_signature):
const forged = tamper(encoded, (p) => { (p.action as any).verb = 'transfer'; });
await expectDenied(decodePCActn(forged));

const store = memoryStateStore();                        // in-memory budget/replay store for tests
```

`fakeVerify` is `verifyPCActnCore` unchanged — it stands in for the resource server but is not a weakened verifier, so a faithful round-trip verifies and tampering is caught exactly as in production. Nothing here authorizes anything.

Part of Proof-Carrying Authority — see `@atlasauth/pca`.
