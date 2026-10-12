# NVIDIA H100 evidence from hardware we operate

Captured 2026-10-08 from an **Azure `Standard_NCC40ads_H100_v5` confidential VM in our own subscription** (centralus;
quota obtained by REST request after the first region declined): H100 NVL (`GH100 A01 GSP FMC LF` device chain),
Ubuntu 24.04 CVM, kernel `6.17.0-1018-azure-fde`, **CC status ON**, environment PRODUCTION, CPU CC = `AMD SEV-SNP (vTOM Mode)`.
The VM was deleted right after capture.

| File | What it is |
|---|---|
| `h100-gpu-attestation-report.bin` | 4129-byte SPDM request‖response from NVIDIA's own collector (`verifier.cc_admin.collect_gpu_evidence_remote`) over the PCA challenge `e58bb1d0…ab453a7` (same binding context as the Phala capture). Driver `595.71.05`, VBIOS `96.00.9f.00.04`. |
| `h100-device-cert-chain.pem` | The 5-certificate device chain (different leaf serial from the Phala GPU, same NVIDIA Device Identity CA root). |
| `driver-rim.xml`, `vbios-rim.xml` | Signed RIMs fetched for THIS gpu: `NV_GPU_DRIVER_GH100_595.71.05`, `NV_GPU_VBIOS_1010_0210_886_96009F0004`. |

NVIDIA's own local verifier ran on the same boot and printed **"GPU Attestation is Successful"** (chain + revocation,
nonce match, report signature, driver RIM, VBIOS RIM, runtime measurements == golden). Our verifier reaches the same
verdict independently (`src/attest-nvidia-own-h100.test.ts`).

## Setup notes (this took real debugging)
- Canonical's pre-signed `linux-modules-nvidia-<branch>-server-open-<kernel>` packages are needed with secure boot, and
  the archive had version skew: pin the whole NVIDIA family to one version with an apt preference.
- **Driver branch 580.173.02 does NOT initialise this GPU under Azure vTOM** (`RmInitAdapter failed`, "Disabling GSP
  offload -- GPU not supported"). **595.71.05 does.** `nvidia-smi conf-compute -f` shows `CC status: ON` once it loads.
- Install NVIDIA's `nv-local-gpu-verifier` in a venv; collect with `collect_gpu_evidence_remote(nonce, ppcie_mode=False)`.

Public evidence only; no private key material.
