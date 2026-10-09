# @atlasauth/pca-harness

A reference orchestration harness for Proof-Carrying Authority. It wraps an untrusted model or tool (the "oracle") and enforces the PCA invariants around it, so the model never holds a signing key. The oracle only proposes an action; the harness checks it against the principal-authorized plan, folds input taint into the risk score, meters the trust budget, and only then signs a PCActn. A compromised or prompt-injected oracle therefore cannot produce an out-of-plan action.

The trusted piece is this small, auditable harness rather than the opaque model, and `harnessMeasurement()` gives a digest of the harness's policy surface that a resource server can allowlist.

## Install

```sh
npm i @atlasauth/pca-harness
```

Depends on `@atlasauth/pca`.

## Usage

```ts
import { paramsDigest } from '@atlasauth/pca';
import { Harness, createHarnessAttestationVerifier } from '@atlasauth/pca-harness';

const params = { amount: 500 };
const harness = new Harness({
  grant,                                   // principal-signed root Capability
  agentSecret,                             // Ed25519 secret of the leaf holder; the oracle never sees it
  audience: 'ins_acme',
  plan: [{ id: 'refund-1', verb: 'stripe.refund', resource: 'charge:ch_123',
           reversibility_class: 'reversible', params_digest: paramsDigest(params) }],
  budget: { B: 1, tau: 3_600_000, asOf: Date.now() },   // decaying trust budget
  attestation: { operator: 'acme' },       // optional: stamp the harness measurement into each PCActn
});

// The untrusted model proposes; the harness enforces plan inclusion, taint, budget, then signs.
const result = await harness.step(async () => ({
  nodeId: 'refund-1',
  verb: 'stripe.refund',
  resource: 'charge:ch_123',
  params,
  inputs: [{ ref: 'email:42', provenance: 'untrusted' }],   // untrusted lineage raises risk
}));

if (result.ok) {
  result.pcactn;          // signed PCActn
  result.inclusionProof;  // Merkle proof under harness.planRoot
  result.risk;            // { r, inputs, taint, t }
} else {
  result.reason;          // 'out_of_plan' | 'over_budget' | 'bad_candidate' - nothing was signed
}

// Resource server: accept only actions emitted by an allowlisted harness build.
const attestation = createHarnessAttestationVerifier({ measurements: [harness.harnessMeasurement()] });
// pass as `hooks.attestation` to verifyPCActn / requirePCA from @atlasauth/pca
```

## API

- `Harness` with `step(propose)`, `harnessMeasurement()`, and the getters `planRoot`, `budget`, `counter`.
- `createHarnessAttestationVerifier({ measurements, required?, expectedModelId? })`: a fail-closed attestation hook that admits only allowlisted harness measurements.
- `computeHarnessMeasurement`, `ENFORCED_CHECKS`, `HARNESS_VERSION`, `HARNESS_MODEL_ID`.

## Status

Experimental prototype. An `over_budget` result means the action needs a human step-up; the harness does not run that ceremony. The harness measurement is self-asserted by the signer and is not hardware-attested: trust rests on the operator choosing to allowlist it, and on the leaf signature verifying. The cryptography is unaudited.

## License

MIT - see LICENSE
