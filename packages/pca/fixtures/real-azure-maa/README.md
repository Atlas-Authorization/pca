# Real Azure MAA tokens over genuine Intel TDX quotes (genuine-silicon evidence)

Genuine **Microsoft Azure Attestation** RS256 tokens (instance `sharedwus.wus.attest.azure.net`, api
`2023-04-01-preview`, `POST /attest/TdxVm`) issued over **genuine Intel TDX DCAP quotes** from Azure
`Standard_DC4es_v6` confidential VMs (westus3), captured 2026-10-08. Companion test:
`src/attest-azure-maa.realsilicon.test.ts`.

| File | What it is |
|---|---|
| `pcabound-tdxvm-token.jwt` | MAA token whose `x-ms-runtime.user-data` is the **PCA binding** (`attestationBinding(EXPECTED)`), `attester_tcb_status: UpToDate`, `dbgstat: disabled`, `x-ms-attestation-type: tdxvm`. |
| `pcabound-runtime-data.json` | The 1230-byte guest runtime-data JSON (vTPM keys, vm-configuration, `user-data`) submitted to MAA. `sha256()` of it equals the quote's `report_data[0:32]`. |
| `pcabound-tdx-dcap-quote.bin` | The raw 5006-byte DCAP quote the token was issued over (same boot). |
| `tdxvm-token.jwt` | Negative control: a token over a different boot's quote with Azure's default `report_data`, no runtime data, no PCA binding. |
| `maa-signing-certs.json` | Snapshot of the instance's `/certs` (signing keys as `x5c`). The signer cert is pinned by SPKI in the test. |

## How the PCA binding reaches the token (and why `report_data` is not used directly)

On an Azure CVM the paravisor sets the TD's `report_data` to `sha256(runtime-data JSON)`; the guest can only
influence it through the JSON's `user-data` field (vTPM NV index `0x01400002`, which must be **defined**
before it is written, then the HCL report re-read from `0x01400001`). The caller submits that JSON to MAA as
`runtimeData`; MAA validates `sha256(runtimeData) == report_data[0:32]` and only then emits `x-ms-runtime`.
So a token whose `x-ms-runtime.user-data` equals the PCA binding proves, under MAA's signature, that a
genuine TD attested to that value. The adapter enables this with `policy.runtimeUserDataBinding: true`.
The test also cross-checks token ↔ raw quote with this repo's DCAP parser (MRTD and `report_data` match).

## Honest scope

- Trust is rooted in Microsoft's MAA service signing the claims (classical RS256), anchored here by pinning the
  shared instance's signing cert (these rotate; production should pin your MAA instance's root).
- The MRTD differs between boots/images (`a2e61f13…` here vs `6f3e84c5…` in `fixtures/real-tdx`), so MRTD
  allowlists are per platform image and must be maintained.
- Public evidence only: signed tokens and public keys; no private key material.
