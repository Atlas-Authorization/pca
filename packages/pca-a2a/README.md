# @atlasauth/pca-a2a

A2A (Agent2Agent) adapter for Proof-Carrying Authority (PCA). A2A defines how agents discover each other and exchange tasks; it does not prove that a relayed request is authorized by the principal behind it. This package binds PCA proofs onto three A2A surfaces, failing closed throughout:

1. **Proof-carrying tasks** - attach a PCActn (a signed single-action proof with its capability chain) to a Task or Message under a namespaced `metadata` key, and verify it on receipt.
2. **Signed Agent Cards** - issue and validate an A2A `AgentCardSignature` (a detached JWS, via `jose`) whose protected header commits to the agent's PCA passport id.
3. **AP2 payment profile** - map a PCActn to an AP2-shaped Payment Mandate that carries its authority by reference to the proof.

## Install

```sh
npm i @atlasauth/pca-a2a
```

Depends on `@atlasauth/pca` and `jose` (installed transitively). For the full AP2 Intent/Cart/Payment chain and settlement hooks, see `@atlasauth/pca-ap2`.

## Usage

```ts
import { buildPCActn } from '@atlasauth/pca';
import {
  attachPcaToA2ATask, pcaA2AMiddleware,
  issueSignedAgentCard, verifyAgentCard,
  a2aPaymentMandateFromPca, verifyA2APaymentMandate,
} from '@atlasauth/pca-a2a';

// Sender: build a PCActn with @atlasauth/pca, then ride it on the task.
const pcActn = buildPCActn({ grant, chain: [grant], plan, nodeId: 'buy-1', counter: 1,
                             signerSecret: agentSecret, aud: 'my-rs' });
const task = attachPcaToA2ATask({ id: 't1', status: { state: 'submitted' } }, pcActn);

// Receiver: guard incoming tasks. Pin the principal you trust.
const guard = pcaA2AMiddleware({ aud: 'my-rs', expectedRootIssuer: principalPublicKey });
const verdict = await guard(task);       // { ok: true, result, pcActn } | { ok: false, reason }

// Signed Agent Card (key is a jose KeyLike, Uint8Array or JWK).
const card = await issueSignedAgentCard({ name: 'Buyer', url: 'https://a.example' }, privateKey,
                                        { passport: { id: 'pp_1' } });
await verifyAgentCard(card, { key: publicKey });  // { ok: true, passportRef: 'pp_1', ... }

// Payment mandate that points at the PCActn.
const mandate = a2aPaymentMandateFromPca(pcActn, {
  amount: { currency: 'USD', value: 120 }, paymentMethod: { type: 'card' }, merchant: 'acme',
});
await verifyA2APaymentMandate(mandate, pcActn, { aud: 'my-rs', expectedRootIssuer: principalPublicKey });
```

By default a guard requires a proof (`require: true`); with `require: false` a task without a proof passes, but a proof that is present and invalid is still rejected. Always pin `expectedRootIssuer` (or `grant`): otherwise the chain root is taken from the proof itself and only proves internal consistency, not that a principal you trust issued it.

## API

- Tasks: `attachPcaToA2ATask`, `attachPcaToA2AMessage`, `extractPca`, `extractPcaFromMessage`, `verifyA2ATask`, `pcaA2AMiddleware`, `PCA_A2A_EXTENSION_URI`.
- Agent Cards: `issueSignedAgentCard`, `verifyAgentCard` (verify with a single `key` or a `jwks`).
- Payments: `a2aPaymentMandateFromPca`, `pcaBindingFromA2APaymentMandate`, `verifyA2APaymentMandate`, `A2A_AP2_CONTEXT`.

## Status

Experimental. The A2A object model here is structural and permissive, not a full A2A SDK. The Payment Mandate shape follows the AP2 vocabulary but its JSON-LD context is a placeholder and PCA-specific fields live in a non-standard `x_pca` extension; validate against the official AP2 schemas before production use. The cryptography is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
