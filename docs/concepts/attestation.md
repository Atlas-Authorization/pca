---
title: Attestation (L0)
order: 6
---

# Attestation (L0)

L0 answers: **is the process acting actually the workload the grant names?** The design goal is that the agent holds no long-lived key. Its identity is derived per epoch from a remote-attestation quote that measures the **model id, weights digest, runtime measurement and operator**. Swap the model, tamper with the runtime or change the operator and the measurement changes, so the identity stops being valid. It is workload identity (SPIFFE/SVID style) taken down to the model.

`attestation.ts` provides the protocol and verifier for that quote in two modes.

| Mode | What it proves | Status |
|---|---|---|
| **Software** | "A key the resource server trusts vouched for these measurements." Measurements are self-asserted by the signer, not rooted in hardware. | Implemented. Suitable for dev, CI and the sanctioned attested-VM equivalent. |
| **Hardware** | A TEE report, rooted in the vendor's certificate chain, measured the loaded workload. | **Implemented** as `HardwareAttestationVerifier`s: AMD SEV-SNP (`createAmdSnpVerifier`), Intel TDX DCAP quotes (`createIntelDcapVerifier`), Azure Attestation tokens (`createAzureMaaVerifier`), Google Confidential Space tokens (`createGcpConfidentialSpaceVerifier`), NVIDIA confidential-computing GPU evidence (`createNvidiaSpdmVerifier`), and N-of-M corroboration across independent roots (`createMultiRootVerifier`). Tested on evidence captured from real confidential VMs and GPUs. |

## The attestation document

```ts
interface AttestationDocument {
  model_id: string;
  weights_digest: string;       // moves on a model swap or fine-tune
  runtime_measurement: string;
  operator: string;
  nonce: string;                // echoed in the quote; the PCActn binds to it
  issued_at: number;            // epoch ms
  expires_at: number;           // epoch ms (short-lived)
  attestor: string;             // b64u key that signed it (software mode)
  mode: 'software' | 'hardware';
  sig: string;
}
```

A software attestor signs documents: `createDevAttestor(secret).attest(claims)`. The resource server trusts it by listing `attestor.publicKey` in `trustedAttestorKeys`.

## Binding an action to its attestation

The PCActn carries `attestation.quote_digest`. The document's `nonce` must equal it (`nonceBinds`). Quotes are per epoch, not per action, so the verifier resolves the document through an `AttestationResolver`; `attestationRegistry(docs)` builds the common one, matching on nonce.

## The verifier

`createAttestationVerifier(opts)` returns the `attestation` hook for `verifyPCActn`. Steps, any of which fails closed with a reason:

1. resolve the document (none: reject);
2. **establish identity**: software mode checks `mode === 'software'`, `attestor` is in `trustedAttestorKeys`, and the Ed25519 signature; hardware mode delegates to `hardwareVerifier.verify(...)` and uses the **hardware-measured** identity, never the document's self-asserted fields;
3. **freshness**: now within `[issued_at - skew, expires_at + skew]`;
4. **nonce binding** to this PCActn;
5. **agent binding**: the identity satisfies the grant envelope's `agent_binding` (`matchAgentBinding`).

`agent_binding` fields:

| Field | Check |
|---|---|
| `model_allowlist` | `model_id` is in the list |
| `min_measurement` | `runtime_measurement` **equals** it (an opaque pinned value; hashes have no ordering) |
| `operator` | `operator` equals it |
| `weights_allowlist` | `weights_digest` is in the list |

```ts
const hook = createAttestationVerifier({
  trustedAttestorKeys: [attestor.publicKey],
  resolveDocument: attestationRegistry([doc]),
  // hardwareVerifier,   // plug a real TEE verifier here
  clockSkewMs: 5_000,
});
```

## Quick start: software attestation

Software attestation is in the production tier. It proves that a key your server trusts vouched for the measurements; it never proves silicon, and the verdict is labelled `software`.

```ts
import { createDevAttestor, createAttestationVerifier, attestationRegistry } from '@atlasauth/pca/ext/attestation';

const attestor = createDevAttestor(attestorSecret);                       // the workload's signing service
const doc = attestor.attest({ model_id: 'm1', weights_digest: 'w1', runtime_measurement: 'r1', operator: 'acme', nonce, issued_at: now, expires_at: now + 300_000 });

const hook = createAttestationVerifier({
  trustedAttestorKeys: [attestor.publicKey],
  resolveDocument: attestationRegistry([doc]),
  clockSkewMs: 5_000,
});
// pass it as hooks.attestation to verifyPCActn / requirePCA; set agent_binding on the grant to pin model, operator, runtime
```

To pin the measurements with a signed, rollback-proof list, publish a signed allowlist manifest and anchor it in a transparency log (`verifyAllowlistManifest`, `anchorAllowlistHead`, `verifyAllowlistAnchored`). To bind identity to a post-quantum software root, use `createPqSoftwareAttestor` and `createPqSoftwareVerifier`.

## Failure modes (software path)

Each row names something missing, stale or wrong. None is a pass.

| If this is missing, stale or wrong | Result |
|---|---|
| No document for the action | Rejected (`no attestation document`) |
| `mode` is not `software` for a software verifier | Rejected |
| The attestor key is not in `trustedAttestorKeys`, or the signature does not verify | Rejected |
| The document is outside `[issued_at - skew, expires_at + skew]` | Rejected as stale or not yet valid |
| The document's `nonce` is not the PCActn's `quote_digest`, or was already consumed | Rejected |
| The identity does not satisfy `agent_binding` (model, runtime, operator, weights) | Rejected with the field named |
| `require_hardware` or `require_measured_weights` is set | Rejected: a software document is never hardware-measured |
| A signed allowlist: bad signature, older version than the last seen, expired, unknown algorithm | Rejected with a typed code |
| An anchored allowlist: no proof, a head from another log, a stale head, a shrunk or forked log, an old version | `missing-proof`, `bad-head`, `stale-head`, `log-rollback`, `split-view`, `anchored-rollback` and the other anchor codes |
| A certificate with trailing bytes, a duplicate or unrecognised critical extension, or the wrong CA role | The chain is refused |

**Limits.** Measurements are self-asserted by the signer. The allowlist anchor needs at least one honest independent witness or a cached head to defeat a log operator who is also the attacker. Weights are only as trustworthy as whoever produced the document.

## The hardware seam

```ts
interface HardwareAttestationVerifier {
  verify(input: { document: AttestationDocument; ctx: VerifyContext; nowMs: number }):
    HardwareAttestationResult | Promise<HardwareAttestationResult>;
}
// HardwareAttestationResult: { ok, reason?, measured?: MeasuredIdentity }
```

Each shipped implementation (table above) parses the vendor report or token, verifies the certificate chain to the vendor root, checks the launch and measurement registers and the TCB / collateral policy, confirms that `report_data` (or the runtime data it hashes) binds the expected holder, grant, epoch and nonce, and returns the measured identity. Plug any of them in as `hardwareVerifier`, or write your own against this interface.

There is also a standardization gap: no cross-vendor standard attests a model's **weights** from inside a TEE (confidential-VM attestation measures the launch image, not "these weights are loaded"). Until the model runtime measures weights into the report, `weights_digest` is only as strong as whoever produced the document, and `weights_allowlist` is the policy hook for pinning it once the measurement is trustworthy.

## Hosted behavior

The attestation check is enforced for an action when the instance has at least one trusted attestor key **and** the action presents an attestation (a document in the request body, or a declared `quote_digest`), and **always** when the grant's `agent_binding` is non-empty: then a missing, unbound or untrusted attestation denies, whether or not the instance trusts any attestor key. Otherwise it stays `not-enforced`. The expected binding (holder, grant, epoch, nonce) is derived on the server from a nonce it issued, and each nonce is consumed once, in the same transaction that admits the action. The hosted surface verifies software attestors (and, when configured, an allowlisted orchestration harness); it does not run the hardware verifiers above, so a grant that sets `require_hardware` is refused there. Manage trusted keys with `GET`/`PUT /v1/pca/attestors` ([API reference](../reference/api.md)).

Next: [Ledger and revocation](./ledger-and-revocation.md).
