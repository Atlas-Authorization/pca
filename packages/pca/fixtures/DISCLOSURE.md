# Fixture disclosure

Several fixtures here are real captures from real confidential-computing hardware and attestation services.
Real tokens and reports cannot be edited without breaking their signatures, so they are published as captured.
This file lists exactly which identifiers each real capture exposes and why that is acceptable, so a reviewer does
not have to decode them. Every capture was reviewed field by field; none carries a secret, a private key, or a
credential. All tokens are short-lived and have expired.

The public-leak gate (`scripts/pca-scrub-scan.sh`) decodes JWTs, base64, gzip and certificates inside fixtures. Each
identifier below is allowlisted there by exact value or by file, with a pointer back to this document.

## Published, with the identifiers they expose

| Fixture | Identifiers exposed | Why it is acceptable |
|---|---|---|
| `real-azure-maa/*.jwt`, `*-runtime-data.json` | `vmUniqueId` (one GUID per capture VM), `jti`, report id, measurements (MRTD, RTMRs, launch measurement), ephemeral vTPM public keys, the shared MAA instance host `sharedwus.wus.attest.azure.net`, the AMD `chipid` of the Azure host CPU (SEV-SNP token only) | The VMs were deleted right after capture (checked against the live subscription listing: none of the ids exists). The MAA instance is Microsoft's shared public instance and not an account. The AMD chip id is the value AMD's public KDS embeds in the VCEK certificate for that CPU. No subscription id, tenant id, resource group or hostname appears. |
| `real-azure-maa/sevsnp-hcl-report.bin`, `pcabound-tdx-dcap-quote.bin`, `real-tdx/azure-intel-tdx-*.bin` | The same `vmUniqueId` values inside the guest runtime-data JSON, TD measurements, Intel quote signature chain | Same as above. DCAP quotes carry only platform data signed by Intel. |
| `real-azure-maa/maa-signing-certs*.json`, `maa-pins-vantages/*` | Microsoft MAA signing certificates and roots | Public vendor certificates. |
| `real-tdx-collateral/*` | Intel SGX/TDX CRLs, TCB info, QE identity and issuer chains | Public Intel PCS data. |
| `real-nvidia-cc/**` | NVIDIA device-identity certificate chains of the captured GPUs, SPDM attestation transcripts (nonce, measurements, driver version), NVIDIA RIM/OCSP/CRL collateral, `capture-meta.json` (a third-party service's model name and enclave signer address) | Device identity certificates are issued by NVIDIA and verifiable by anyone. The signer address belongs to the third-party provider's public API response, not to this project. |
| `../testdata/sevsnp-real/*` | An Azure SEV-SNP report, its VCEK certificate (contains the AMD chip id) and the ASK/ARK chain | Public AMD KDS data plus a report from a deleted VM. |
| `real-gcp-cs/google-cs-jwks.json` | Google's published Confidential Space token signing keys | Public vendor keys. |

## Withheld from the public tree

| Fixture | Identifiers exposed | Decision |
|---|---|---|
| `real-gcp-cs/prod-token.jwt`, `debug-token.jwt`, `prod-tdx-token.jwt` | The capturing GCP project id and project number, the instance names and ids, the project's default service account, and the Artifact Registry path of the workload image (which embeds the project id) | These identify a live cloud project, so the public assembly (`scripts/sync-pca-flagship.sh`) leaves them out. The suite `src/attest-gcp-confidential-space.realsilicon.test.ts` detects the missing files and reports itself as skipped, with a warning that says why. The synthetic-key tests in `attest-gcp-confidential-space.test.ts` and the pinned Google JWKS stay in the public tree. |

The tokens are present in the private monorepo, where the real-silicon suite runs.

## Re-capturing

To replace a withheld capture with a publishable one, take it from a throwaway project, keep the workload image in a
registry path that does not embed the project id, delete the project afterwards, and run
`scripts/pca-scrub-scan.sh` over the fixtures before moving the files out of the withheld list.
