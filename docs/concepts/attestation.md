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
| **Hardware** | A TEE (SEV-SNP, TDX, SGX) report, rooted in the CPU vendor's certificate chain, measured the loaded workload. | **Seam only.** The interface and its plug-in point exist; real quote parsing is not implemented. |

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

## The hardware seam

```ts
interface HardwareAttestationVerifier {
  verify(input: { document: AttestationDocument; ctx: VerifyContext; nowMs: number }):
    HardwareAttestationResult | Promise<HardwareAttestationResult>;
}
// HardwareAttestationResult: { ok, reason?, measured?: MeasuredIdentity }
```

A production implementation parses the vendor report, verifies the certificate chain to the CPU root, checks the launch and measurement registers, confirms `report_data` binds the expected nonce, and returns the measured identity.

There is also a standardization gap: no cross-vendor standard attests a model's **weights** from inside a TEE (confidential-VM attestation measures the launch image, not "these weights are loaded"). Until the model runtime measures weights into the report, `weights_digest` is only as strong as whoever produced the document, and `weights_allowlist` is the policy hook for pinning it once the measurement is trustworthy.

## Hosted behavior

The attestation check is enforced for an action only when the instance has at least one trusted attestor key **and** the action presents an attestation (a document in the request body, or a declared `quote_digest`). Otherwise it stays `not-enforced`. Manage trusted keys with `GET`/`PUT /v1/pca/attestors` ([API reference](../reference/api.md)).

Next: [Ledger and revocation](./ledger-and-revocation.md).
