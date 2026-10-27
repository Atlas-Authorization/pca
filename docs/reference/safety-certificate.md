---
title: Safety certificate
order: 25
---

# Safety certificate

A safety certificate is a guardian-signed statement of two things: the risk-budget arithmetic of a grant's risk policy, and which checks ran, with links to their evidence. It is **not** a claim that an agent or a system is safe.

> **Status: experimental.** It lives under `@atlasauth/pca/ext/research`. See [maturity tiers](../maturity.md).

## What is signed

- `scope`: always `risk-budget-bound`. A verifier refuses any other value.
- `params` and `bound`: the risk policy parameters and `B_max / κ`, the most risk that autonomous actions can add between two human co-signs. The verifier recomputes the bound from the parameters and never trusts the stated number.
- `checks` (optional): a list of `{ id, status, evidence, at }`. `status` is `passed`, `failed` or `not_run`. `evidence` is an `https` URL (no credentials) or a lowercase SHA-256 digest of an evidence artifact. Ids are unique and there are at most 64 checks.

The verifier does not fetch or judge the evidence. A `passed` check is the guardian's assertion that the check ran and passed, with the evidence for you to inspect.

## Verifying

```ts
const verdict = verifySafetyCertificate(cert, {
  guardian: pinnedGuardianKey,
  requireChecks: ['fuzz', 'mutation'], // each must be present and passed
  maxAgeMs: 7 * 24 * 3_600_000,
});
```

Failure reasons are exact strings, for example `required check 'mutation' is failed` or `certificate is older than maxAgeMs`. The signature is checked before the policy options, so an unsigned certificate does not reveal which check was missing.

## Compliance export

`safetyCertificateForCompliance(cert, opts)` verifies the certificate and returns one evidence row (guardian, issue time, bound, and each check with its evidence link), or `null` if it does not verify. Add the row to your audit export next to the proofs it covers. It maps to evidence, not to a certification.
