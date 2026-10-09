# Real NVIDIA H100 GPU-CC attestation (genuine-silicon evidence)

A **genuine NVIDIA Hopper (GH100 / H100) confidential-computing attestation**, captured 2026-10-08, that
makes `attest-nvidia-spdm.ts` real-silicon validated. Companion test: `src/attest-nvidia-spdm.test.ts`.

| File | What it is |
|---|---|
| `h100-gpu-attestation-report.bin` | 4129-byte SPDM 1.1 transcript: GET_MEASUREMENTS **request (37 B) ‖ response** (64 measurement blocks of SHA-384 digests, GPU responder nonce, 434 B opaque TLVs incl. driver `580.95.05`, 96-byte ECDSA P-384 signature). |
| `h100-device-cert-chain.pem` | The GPU's 5-certificate device-identity chain: `GH100 A01 GSP FMC LF` → `GH100 A01 GSP BROM` → `NVIDIA GH100 Provisioner ICA 1` → `NVIDIA GH100 Identity` → `NVIDIA Device Identity CA` (self-signed, P-384). |
| `capture-meta.json` | Capture provenance (arch, sizes, model route). No secrets. |

**Trust anchor.** The root's SPKI SHA-256 is
`a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4`, byte-identical to the
`verifier_device_root.pem` NVIDIA ships pinned in its own open-source local GPU verifier (`nvtrust`).

**PCA challenge binding.** The request nonce (inside the signed transcript) is
`e58bb1d0…ab453a7 = sha256(attestationBinding(EXPECTED))` for the fixed binding context in the test, so the
GPU's signature covers a challenge that commits to holder / grant / epoch / nonce. The GPU also emits its
own responder nonce; the PCA challenge travels in the signed request.

## Capture method and honest provenance

Obtained from a Phala-operated confidential-GPU node (Intel TDX + NVIDIA H100 CC) through its attestation
endpoint, passing the 32-byte challenge as the nonce. The node reflected the nonce and returned the raw
`evidence` + `certificate` produced by the GPU's NVML attestation path. This is real GPU-signed evidence over
our nonce. That capture's host (Phala) is a third party; the same stack was then re-run on **an H100 we operate
ourselves** (see `own-h100/`). The cryptography does not depend on the host either way: the chain roots in
NVIDIA and the signature is the GPU's.

## What is and is not verified

`src/attest-nvidia-spdm.ts` verifies offline: every chain link (node X.509), CA flags, validity windows, P-384 key
type, SPKI root pin, the report signature over request‖response, the PCA nonce binding, and an operator-pinned set
of measurement digests.

`src/attest-nvidia-rim.ts` + `collateral/` (fetched 2026-10-08) adds NVIDIA's own reference data:

| File | What it is |
|---|---|
| `collateral/driver-rim-NV_GPU_DRIVER_GH100_580.95.05.xml` | Signed driver RIM from `rim.attestation.nvidia.com` (22 active golden measurements). |
| `collateral/vbios-rim-NV_GPU_VBIOS_G520_0280_895_9600D00003.xml` | Signed VBIOS RIM (12 active). Both ids are derived from the GPU's own signed opaque data. |
| `collateral/nvidia-corim-signing-root.pem` | NVIDIA CoRIM signing root (SPKI `dec1dc31…`), the pin for RIM signer chains; byte-identical to NVIDIA's shipped `verifier_RIM_root.pem`. |
| `collateral/l2-gh100.crl`, `l1-root.crl` | NVIDIA's published CRLs (`crl.ndis.nvidia.com`; ecdsa-with-SHA256; both currently empty). |
| `collateral/synthetic/` | **Synthetic** P-384 chain + CRLs, only to test the revoked-serial path (we hold no NVIDIA CA keys). |

Result on the genuine capture: both RIMs verify, and the real H100 report matches NVIDIA's golden values at **33
indices** (block 35 exempt because the report's NVDEC0 status is DISABLED, per NVIDIA's rules), driver version and
VBIOS version bind to the RIMs, and the chain is not revoked.

`src/attest-nvidia-ocsp.ts` + `ocsp/` adds NVIDIA's OCSP responder (see `ocsp/README.md`): real, nonce-echoing "good"
responses for the BROM, Provisioner ICA and Identity certificates, signed by delegated responder certificates; the
per-device leaf is answered `unauthorized` (the responder does not serve it), so it is never required-good.
`nvidiaCollateralHook({ revocation: 'crl' | 'ocsp' | 'both' })` runs either or both through the verifier.

**Still not done:** firmware-version *policy* beyond RIM equality. Public evidence only; no private key material.
