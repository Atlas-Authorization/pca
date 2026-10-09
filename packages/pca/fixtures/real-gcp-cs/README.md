# Real GCP Confidential Space attestation tokens (genuine-silicon evidence)

These are **genuine Google-signed Confidential Space attestation tokens** captured from a **real AMD SEV
Confidential VM** on Google Cloud (`n2d-standard-2`, `--confidential-compute-type=SEV`, zone
`us-central1-c`) on 2026-10-08, and the pinned Google JWKS that signed them. They make
`attest-gcp-confidential-space.ts` **real-silicon validated**, not merely synthetic-key tested — the
companion test is `src/attest-gcp-confidential-space.realsilicon.test.ts`.

| File | What it is |
|---|---|
| `prod-token.jwt` | Token from the **production** Confidential Space image → `dbgstat: disabled-since-boot`. Verifies with `allowDebug: false` (the strong claim). RS256, 2646 B. |
| `debug-token.jwt` | Token from the **debug** image → `dbgstat: enabled`. Used to prove the debug gate rejects it unless `allowDebug: true`. RS256, 2578 B. |
| `prod-tdx-token.jwt` | Token from the **production** image on an **Intel TDX** Confidential VM (`c3-standard-4`, `--confidential-compute-type=TDX`, us-central1-a): `hwmodel: GCP_INTEL_TDX`, `dbgstat: disabled-since-boot`, `attester_tcb: [INTEL]`, workload image digest `sha256:6597f3b7…` (a later rebuild of the same Dockerfile). RS256, same Google signing key. |
| `google-cs-jwks.json` | Snapshot of Google's live Confidential Space JWKS (issuer `https://confidentialcomputing.googleapis.com`, signer `signer@confidentialspace-sign.iam.gserviceaccount.com`); contains the `1be6ff…` key that signed both tokens. Pinned so the test is deterministic + offline (the live keys rotate and the tokens expire ~1 h after issue). |

Both tokens carry `iss=https://confidentialcomputing.googleapis.com`, `hwmodel=GCP_AMD_SEV` (→ `sev-snp`),
`swname=CONFIDENTIAL_SPACE`, the measured workload `image_digest`
`sha256:b1c058a8092d56dd77ec351b9e00b2565fba5e413d0cb08d260a1e40e64ca46e`, and
`eat_nonce=8bbd16f5…fad19`, which is `hex(sha256(attestationBinding(EXPECTED)))` for the fixed PCA binding
context in the test — so the token's nonce cryptographically binds the holder/grant/epoch/nonce.

## Capture method (no SSH, no secrets)

1. A tiny workload container (`alpine` + `curl`, built with Cloud Build) requests an OIDC attestation token
   from the Confidential Space launcher's teeserver socket
   (`curl --unix-socket /run/container_launcher/teeserver.sock -d '{"audience":...,"token_type":"OIDC","nonces":["<nonce>"]}' http://localhost/v1/token`)
   and prints it to stdout. The image declares `LABEL tee.launch_policy.allow_env_override="PCA_NONCE,PCA_AUDIENCE"`
   and `tee.launch_policy.log_redirect="always"` (the launcher refuses `tee-env-*` / log redirect otherwise).
2. The VM is created from `confidential-space-images/confidential-space` (prod) or `…-debug`, with metadata
   `tee-image-reference`, `tee-container-log-redirect` (`cloud_logging` for prod, serial for debug),
   `tee-env-PCA_NONCE`, `tee-env-PCA_AUDIENCE`, and a service account holding
   `roles/confidentialcomputing.workloadUser` + `roles/artifactregistry.reader`.
3. The token is read back from the serial console (debug) or Cloud Logging under logName
   `confidential-space-launcher` (prod). The VM is deleted immediately after (credit hygiene).

**Public evidence only** — these are signed attestation JWTs (public claims + a signature); they carry no
private key material and are expired (short-lived). The signing key is Google's, pinned by its public JWK.

## Hardware Google actually attests (a finding, not a gap in our code)

Google's attestation service issues Confidential Space tokens for **AMD SEV** (`GCP_AMD_SEV`) and **Intel TDX**
(`GCP_INTEL_TDX`). A `SEV_SNP` Confidential VM was tried on 2026-10-08 and the service refused it:
`UNSUPPORTED_CC_TECHNOLOGY — AMD SEV-SNP is not currently supported by Google Cloud Attestation`. So there is no GCP
SEV-SNP token to capture today; for SEV-SNP use the direct SNP verifier (`testdata/sevsnp-real`) or Azure MAA.
