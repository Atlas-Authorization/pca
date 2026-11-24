---
title: Require build provenance
order: 43
---

# Require build provenance for the tools an agent calls

A signed action pack or a pinned MCP server key proves that a key signed something. It does not prove which repository, which commit and which builder produced the code that is running. This guide shows how a grant can require that, offline, and how to tie it to the binary that actually runs.

## What a grant can ask for

A grant carries a caveat that asks your attestation verifier for a discharge:

```ts
import { provenanceCaveat } from '@atlasauth/pca';

const caveat = provenanceCaveat({
  issuer: 'provenance',          // the label of the verifier's key, pinned with class "artifact"
  min_level: 2,                  // SLSA build level floor
  source_repo: 'https://github.com/acme/refund-tool',
  // require_runtime defaults to true: the running image must be the one the provenance describes
});
```

The resource server pins the attestation verifier's key with class `artifact`. No other kind of key (a workload, an organisation, a person, a model) can discharge this caveat, and an `artifact` key cannot discharge any other kind.

Without a discharge the action is refused, and the verifier answers with a discharge request naming exactly what it needs. The caveat only removes authority; provenance never grants anything.

## What the attestation verifier checks

For each request, the verifier holding the `artifact` key:

1. verifies the Sigstore bundle offline against a trust root you pinned (a `trusted_root.json`): the transparency-log timestamp, the inclusion proof and its signed checkpoint, the certificate path to the pinned Fulcio CA at signing time, the embedded certificate-transparency timestamp, the log entry naming this exact envelope, and the DSSE signature over the in-toto statement with SLSA v1 provenance;
2. reads the digest of the image that is running from an attestation token (EAT) it has already accepted (signature, nonce, channel binding, appraisal);
3. checks the facts against its own policy: the SLSA level comes only from a signer and builder pair you pinned (SLSA v1.0 says the builder identity decides the level, and consumers must accept only specific signer-builder pairs); then the source repository and ref, the build type, the age, and that the running digest is one of the provenance subjects;
4. signs a discharge with the resulting claims (`slsa_level`, `source_repo`, `builder_id`, `runtime_bound`, the subject digest, and more).

```ts
import { issueArtifactDischarge, parseTrustedRoot, runtimeDigestFromEat, verifyFreshAttestedEAT } from '@atlasauth/pca-attest-eat';

const roots = parseTrustedRoot(trustedRootJson);            // pinned, shipped with your deployment
const eat = await verifyFreshAttestedEAT(token, eatOptions); // the running workload's attestation
const runtime = runtimeDigestFromEat(eat, { slot: 'image', alg: 'sha256' });

const r = issueArtifactDischarge({
  bundle, roots, runtime, request, now: Date.now(), issuerSecret,
  policy: {
    roots: [{
      oidc_issuer: 'https://token.actions.githubusercontent.com',
      identity_prefix: 'https://github.com/acme/refund-tool/.github/workflows/release.yml@refs/tags/',
      builder_id: 'https://github.com/actions/runner/github-hosted',
      level: 2,
    }],
    min_level: 2,
    source_repo: 'https://github.com/acme/refund-tool',
    source_ref_prefix: 'refs/tags/',
    require_runtime: true,
  },
});
if (!r.ok) console.log(r.stage, r.code); // e.g. "gate runtime_mismatch" for a swapped image
```

Pin levels from the builder's documentation. GitHub documents that artifact attestations alone provide SLSA v1.0 Build Level 2, and that reusable workflows can provide the isolation needed for Level 3.

## A swapped image

If someone replaces the image behind the tool with a different build, the measured digest no longer matches any provenance subject. The verifier refuses with `runtime_mismatch`, issues no discharge, and the resource server refuses the action. The same happens if the provenance was signed by an identity or builder you did not pin, from another repository, from a ref outside your prefix, or is older than your maximum age.

## Publishing action packs

Pin the identity that builds your pack in `pca.config.json`:

```json
{ "provenance": { "oidc_issuer": "https://token.actions.githubusercontent.com",
                  "identity_prefix": "https://github.com/acme/actions/.github/workflows/release.yml@refs/tags/",
                  "builder_id": "https://github.com/actions/runner/github-hosted" } }
```

`pca actions lint` warns (`LP-001`) about a beta or stable pack without it, and `--strict` fails.

## Supported bundles

Bundles v0.2 and v0.3 with a keyless (Fulcio) certificate and a DSSE in-toto statement; entries in a Rekor v1 log (`dsse`, `intoto`) or a Rekor v2 log (`hashedrekord` over the DSSE envelope, Ed25519-signed checkpoints); signing time from an RFC 3161 timestamp authority you pinned, from a Rekor v1 signed entry timestamp, or both (the certificate must be valid at each). The bundle check is implemented in TypeScript and in every native verifier, on the same shared test vectors (the sigstore-conformance fixtures plus mutations).

Refused, never skipped: public-key (non-keyless) bundles, v0.1 bundles, message-signature bundles, certificates whose identity is not a single URI or email, and SLSA v0.2 provenance.
