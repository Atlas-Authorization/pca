# @atlasauth/pca-attest-eat

Per-session attestation freshness and channel binding for Proof-Carrying Authority (PCA). TEE evidence (for example an AMD SEV-SNP attestation report) captured once is a static blob that can be replayed or relayed onto another session. This package emits that evidence as an Entity Attestation Token (EAT, RFC 9711, compact JWS with `typ: eat+jwt`), binds it to a live channel (RA-TLS style `cnf`) and a fresh per-session nonce, and appraises it with a RATS-style split of evidence, endorsements and reference values (RFC 9334).

It also verifies the AMD SEV-SNP report signature (ECDSA P-384) and the VCEK, ASK, ARK certificate chain using only `node:crypto`, and can co-sign the resulting verdict with a post-quantum signature.

## Install

```sh
npm i @atlasauth/pca-attest-eat
```

Depends on `@atlasauth/pca` (installed automatically). Node.js 20+.

## Usage

```ts
import {
  generateEatKeyPair, issueNonce, buildEAT, verifyFreshAttestedEAT,
} from '@atlasauth/pca-attest-eat';

// Verifier: issue a per-session challenge.
const nonce = issueNonce().value;

// Attester: emit an EAT bound to the live channel and the challenge.
const { publicKey, privateKey } = generateEatKeyPair(); // EdDSA by default, or 'ES256'
const eat = buildEAT({
  issuer: 'tee-attester',
  key: privateKey,
  nonce,
  channelId: tlsExporterValueOrChannelId,
  measured: { model_id: 'my-model', weights_digest, runtime_measurement, operator: chipIdHex },
  dbgstat: 'disabled',
});

// Verifier: signature, freshness, channel binding, then appraisal against a policy.
const verdict = await verifyFreshAttestedEAT(eat, {
  verifyKey: publicKey,
  nonce,
  channelId: tlsExporterValueOrChannelId,
  issuer: 'tee-attester',
  policy: {
    endorsements: { issuers: ['tee-attester'] },
    referenceValues: { models: ['my-model'], requireDebugDisabled: true },
  },
});
// verdict: { ok, tier, reasons, claims? }
```

`tier` is one of `affirming-hw-rooted`, `affirming`, `warning`, `contraindicated`, `rejected`. A stale `iat`, a wrong nonce, a different channel, or failed appraisal all fail closed.

To reach `affirming-hw-rooted`, pass `amd: { rawReport, vcek, ask, ark, family }` (`family` is `milan`, `genoa` or `turin`) to `verifyFreshAttestedEAT`. The report signature and the VCEK, ASK, ARK chain are then verified by `@atlasauth/pca`'s hardened verifier (this package keeps no AMD certificate cryptography of its own): the ARK is pinned to that family's AMD KDS root, the ASK and ARK must be CAs, every certificate must be inside its validity window at the verifier's clock (`now`), and the VCEK must certify the report's chip id and TCB. Debug-enabled guests are rejected unless you pass `allowDebug: true`.

## API

- EAT: `buildEAT`, `verifyEAT`, `generateEatKeyPair`, `issueNonce`
- Binding and freshness: `bindChannel`, `deriveChannelCnf`, `verifyFreshness`, `verifyChannelBinding`
- Appraisal: `appraise`, `verifyFreshAttestedEAT`
- AMD SEV-SNP: `verifyAmdAttestation` (async; delegates to `@atlasauth/pca`), `KNOWN_AMD_ARK_SPKI_SHA384` (`milan`, `genoa`, `turin`), `parseReportTolerant`, `evidenceFromReport`, `measuredFromReport`
- Post-quantum co-signing of a verdict: `verdictFromAppraisal`, `coSignAttestation`, `verifyCoSignedAttestation` (ML-DSA-65 by default; classical-only suites are refused)

## Status

Cryptography here is unaudited. The AMD hardware root of trust (the ARK) is itself a classical ECDSA/RSA key; verification of it is real, but it is not a post-quantum guarantee. The optional post-quantum co-signature protects the recorded verdict after the classical hardware check has passed; it does not make AMD's root post-quantum.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
