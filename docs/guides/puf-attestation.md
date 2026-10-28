---
title: PUF attestation root
order: 13
---

# PUF attestation root

Maturity: **hardened, awaiting hardware evaluation on a real PUF or TPM, and independent audit.**

A physical unclonable function (PUF) turns the manufacturing variation of one chip into a device identity that cannot be copied. PCA ships the software layer: a fuzzy extractor that turns a noisy reading into a stable key, enrollment, a registry, and a verifier that plugs into the attestation gate as one root of a multi-root policy. The PUF hardware itself is yours to provide through the `PufProvider` interface (an SRAM PUF, a vendor block, or the TPM 2.0 endorsement key reader that ships here).

Import from `@atlasauth/pca/ext/attestation`.

## What it does and does not prove

It proves that the statement was signed by a key that only a device with the enrolled PUF can reproduce, bound to your holder, grant, epoch and a single-use nonce. It does **not** measure the loaded model weights, and a PUF root is **never** reported as hardware assurance: the verifier is labelled `software`, the gate reports `software`, and in a multi-root policy a PUF root does not count toward `hardware` or `multi_root`. Unclonability is a classical property; choose an ML-DSA suite at enrollment if you also want a post-quantum signature.

## Missing or invalid input gives a specific refusal

| Situation | Outcome |
|---|---|
| No evidence resolver configured | denied |
| No statement for the action | denied |
| Provider not enrolled | denied |
| Provider revoked (`registry.revoke`, or your `isRevoked`) | denied, says revoked |
| Enrollment past `notAfter` | denied, says expired |
| Helper data changed after enrollment | denied, helper commitment mismatch |
| Statement suite differs from the enrolled suite | denied |
| `requirePq` and the enrolled key is classical | denied |
| Signed by another device, enrolled under another challenge, or too many bit flips for the repetition code | denied, signature does not verify |
| Binding does not match the server's holder, grant, epoch and nonce | denied |
| Measurement or weights digest not in your allowlist | denied |
| Replay of an accepted statement | denied by the gate's single-use nonce store |
| Empty measurement allowlist | the verifier cannot be constructed |
| Helper data missing, truncated, or with a wrong-length salt | `fuzzyReproduce` throws; no quiet wrong key |
| `tpm2-tools` missing, non-zero exit, empty or short output | the TPM provider throws |

## Wire it into the gate

```ts
const registry = createPufEnrollmentRegistry([enrollment]);
const puf = createPufVerifier({
  resolveEnrollment: (id) => registry.lookup(id),
  isRevoked: (id) => registry.isRevoked(id),
  policy: { measurements: [expectedMeasurement] },
  resolveEvidence: (doc, ctx) => statementFor(ctx),
});
const gate = createAttestationVerifier({ trustedAttestorKeys, resolveDocument, expectedBinding, nonceStore, hardwareVerifier: puf });
```

Pass the nonce store so a statement can be used once.

## Running on real hardware (owner action O-3)

1. On the target machine install `tpm2-tools` and confirm `tpm2_readpublic -c 0x81010001 -f der -o ek.der` succeeds. For an SRAM or vendor PUF, implement `PufProvider.response`.
2. Enroll once in a trusted setting with `enrollPuf` and store the public enrollment (it holds no secret).
3. Read the device a few hundred times, across temperature and voltage corners your deployment sees, and measure the worst bit-error count per repetition block. Pick `rep` so the correction bound `(rep - 1) / 2` exceeds it with margin.
4. Attest and verify end to end through the gate, then repeat on a second device and confirm it is refused.
5. Record the results and set an `notAfter` that matches your re-enrollment schedule.
