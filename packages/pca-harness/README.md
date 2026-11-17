# @atlasauth/pca-harness

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

An orchestration harness for Proof-Carrying Authority. It wraps an untrusted model or tool (the "oracle") and enforces the PCA invariants around it, so the model never holds a signing key. The oracle only proposes an action; the harness checks it against the principal-authorized plan, folds input taint into the risk score, meters the trust budget, and only then signs a PCActn. A compromised or prompt-injected oracle therefore cannot produce an out-of-plan action.

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

## Where it fits

`@atlasauth/pca-agent` is the general agent-side wrapper. This package is the narrower mediator for deployments where the model is a black-box API: the model only proposes, and the harness checks the plan, folds taint into risk, meters the budget and signs. Pass `createHarnessAttestationVerifier` as `hooks.attestation` to `verifyPCActn` or `requirePCA` so a resource server accepts only allowlisted harness builds.

## Status

Production. Every malformed input fails closed with a typed refusal and nothing is signed:

| Input | Outcome |
|---|---|
| oracle throws or rejects | `bad_candidate`, detail `oracle failed: <message>` |
| candidate null, or missing `nodeId`, `verb` or `resource` | `bad_candidate` |
| `inputs` present but not an array | `bad_candidate` |
| an input that is not exactly `{ ref: string, provenance: 'trusted' }` (null, a typo, no ref) | counted as untrusted lineage (taint 1), never as trusted |
| node id not in the committed plan, or verb or resource differs from the node | `out_of_plan` |
| params do not match the node's committed digest | `bad_candidate` |
| budget cannot cover the risk cost of a machine-only action | `over_budget`, step-up to a human required |
| empty plan, duplicate node ids, a secret that is not 32 bytes, a non-finite or negative budget, an empty audience | the constructor throws |

An `over_budget` result means the action needs a human step-up; the harness does not run that ceremony. The harness measurement is self-asserted by the signer and is not hardware-attested: trust rests on the operator choosing to allowlist it, and on the leaf signature verifying.

## Fail-closed behaviour

The step table under Status covers `Harness.step` and the constructor. The attestation hook adds:

| Missing or invalid | Result |
|---|---|
| `createHarnessAttestationVerifier` configured with an empty measurement list | every PCActn is denied |
| The PCActn carries no harness measurement and `required` is not `false` | denied |
| No measurement and `required: false` | reported as not enforced; a present but wrong measurement still fails |
| A measurement not in the allowlist | denied (unknown mediator) |
| `expectedModelId` set and the PCActn names another identity | denied, even for an allowlisted measurement |
| The PCActn or its attestation block missing altogether | treated as no measurement |

## Limits

- It does not run the human step-up that `over_budget` calls for.
- The measurement is a digest of the harness's own policy surface, signed by the same key as the action. It is self-asserted, not hardware-attested.
- It checks the plan, taint and budget; it does not judge whether the plan itself is wise.
- It does not sandbox the oracle or stop it reading data it was already given.
- The harness measurement names a policy surface, not a binary. To root it in hardware, attest the process that runs the harness with the hardware attestation verifiers of `@atlasauth/pca`; this package does not do that for you.

## License

MIT - see LICENSE
