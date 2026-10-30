---
title: Agent passport
order: 24
---

# Agent passport

A passport is a signed statement, made by an issuer you trust, about which agent is presenting: its model, weights digest, system prompt digest, tool manifest digest, runtime measurement and operator. It is bound to the agent's signing key, so it cannot be lifted and presented by another agent. A grant's `agent_binding` says which passports it accepts; the passport verifier says whether a passport can be believed.

## What is signed

A signed passport carries `typ` (`atlas-pca/passport`), `ver` (`1`), the `passport` claims, `iss` (the issuer's Ed25519 public key, b64u: its key id), `sub` (the agent's Ed25519 key, b64u: the key its PCActns are signed by), `iat`, `nbf` and `exp` (epoch milliseconds), optional hardware `evidence` (the attestation document and `at`, the time the issuer obtained the quote), and the signature. The signature covers the domain tag `atlas-pca/passport-sig/v1` followed by a zero byte, then the canonical JSON of every other field. The signature suites are the ones PCA uses everywhere: Ed25519 by default, and ML-DSA, SLH-DSA and the hybrid suites, selected by `alg` with the suite and PQ key signed into the body. A non-Ed25519 passport is accepted only under a PQ key you pinned for that issuer (`pqPins`), exactly as for attestations.

## Issue and verify

```ts
import { issuePassport, signPassport, verifyPassport } from '@atlasauth/pca';

const passport = issuePassport({
  model_id: 'model-x', weights_digest: 'w1', operator: 'acme',
  hardware_rooted: false, issued_at: Date.now(),
});
const signed = signPassport(passport, { issuerSecret, subject: agentPublicKeyB64u, exp: Date.now() + 3_600_000 });

const verdict = await verifyPassport(signed, {
  trustedIssuers: [issuerPublicKeyB64u],
  now: Date.now(),
  subject: agentPublicKeyB64u,           // the key actually presenting
  revocation: ({ id, iss, sub }) => revoked.has(id),
});
// { ok: true, passport, iss, sub, exp, hardware_verified } or { ok: false, reason }
```

Issuing and verifying the same document does not need a network. Revocation is required: with no source, or a source that throws, the answer is `revocation_unavailable`.

## Hardware-rooted passports

`hardware_rooted: true` is accepted only when the passport carries `evidence` (an attestation document) and the verifier is given an `attestationVerifier`, the same hardware verifiers used for attestations (SEV-SNP, TDX, Azure MAA, Confidential Space, NVIDIA, or a multi-root policy). The verifier must confirm the quote is bound to the passport: holder = the subject key, grant reference = `passport:<passport id>`, epoch 0, nonce = the evidence nonce (`passportEvidenceBinding`). The hardware-measured identity must equal the claims (model, operator and, where the passport states them, weights, runtime measurement, prompt and tool digests; measured weights must be hardware-measured when the passport says so). Anything else is rejected with a reason; a passport is never silently treated as software.

The age of the quote is checked again at verification time: `now - evidence.at` must not exceed `maxEvidenceAgeMs` (default 24 hours), and evidence dated in the future beyond the clock skew is refused too. Stale evidence is rejected with `hardware_evidence_stale` before the verifier is consulted. `at` is signed with the passport (it defaults to `iat` when you sign), so it cannot be refreshed by the holder. The passport's `exp` still bounds how long the whole statement is believed; keep both short for hardware passports.

## Requiring a passport at the resource server

```ts
const authorizer = createAuthorizer({
  ...options,
  requirePassport: { trustedIssuers: [issuerKey], revocation, hardware: false /* true demands hardware */ , attestationVerifier },
});
const result = await authorizer({ operation, pcactn, passport: signed });
```

Without `requirePassport` nothing changes. With it, `trustedIssuers` and `revocation` are required (a missing one denies), the call must carry a passport, and its `sub` must be the PCActn's leaf holder. The result's `assurance.passport` reports `software`, or the attestation level and vendor of your hardware verifier when the evidence verified. The passport is checked before the PCActn is verified or its replay counter advances, so a refused passport never consumes the PCActn: the same PCActn succeeds afterwards with a valid passport. (The subject is read from the presented PCActn only to choose which key to compare; the PCActn is still fully verified, and its verified leaf holder must match.)

## Failure modes

Checks run in this order and the first failure is the answer.

| Reason | Meaning |
|---|---|
| `malformed` | Not a passport, a missing or mistyped field, a non-integer time, or `exp` not after `nbf`. |
| `unsupported_version` | `ver` is not `1`. |
| `unsupported_suite` | `alg` is not a known signature suite. |
| `unknown_issuer` | `iss` is not in `trustedIssuers` (an empty list trusts nobody). |
| `bad_signature` | The signature does not verify; includes any altered field, a dropped suite field, or a PQ key that is not pinned. |
| `id_mismatch` | The passport id is not the fingerprint of its identity fields. |
| `not_yet_valid` | `now` (plus skew) is before `nbf`. |
| `expired` | `now` (minus skew) is at or after `exp`. Skew defaults to 0 and is capped at 60 seconds. |
| `subject_mismatch` | `sub` differs from the key you said is presenting. |
| `revocation_unavailable` | No revocation source, or it failed. |
| `revoked` | The revocation source says this passport is revoked. |
| `hardware_evidence_missing` | `hardware_rooted` is true but no evidence is carried. |
| `hardware_evidence_stale` | The quote is older than `maxEvidenceAgeMs`, or dated in the future beyond the skew. |
| `hardware_verifier_missing` | Evidence is carried but no `attestationVerifier` was supplied (in Go: neither `Attest` nor `DefaultHardware`; in Rust: neither `attest` nor `default_verifier`; in Python: neither `attest` nor `default_verifier`). |
| `hardware_attestation_failed` | The hardware verifier refused the evidence, or did not confirm it is bound to the subject. |
| `hardware_identity_mismatch` | The hardware-measured identity differs from the passport's claims. |

## Limits

- A passport is only as trustworthy as its issuer and, for `hardware_rooted`, the hardware verifier you configure. The vendor verifiers have not had an independent review.
- Revocation is whatever source you supply; PCA does not distribute revocation lists for passports.
- The passport does not replace the grant: it identifies the agent, and `agent_binding` plus the capability chain still decide what it may do.
- Conformance vectors for the signed form are published with the conformance corpus: every signature suite, accept and reject, and the hardware branch. The Go, Python and Rust verifiers pass them. Each verifies every suite it implements for PCActns under a pinned issuer PQ key (`pq_pins`) and answers `unsupported_suite` for one it does not (Go and Python do not implement FN-DSA; Python needs a post-quantum backend for the others). Their hardware branch enforces the evidence age, hands the verifier the binding and compares the measured identity; the verifier is one you supply (`attest`) and, in Go, Rust and Python, otherwise the vendor verifier you configure as the default (Go `DefaultHardware`, Rust `default_verifier`, Python `default_verifier`: AMD SEV-SNP, Intel TDX, Azure MAA, Google Confidential Space or NVIDIA GPU, built by `VerifierFromConfig` / `attest::verifier_from_config` / `atlas_pca.attest.verifier_from_config`), and a verifier you supply always wins. Without either, a hardware-rooted passport is refused with `hardware_verifier_missing`. The TypeScript verifier ships the vendor verifiers.
