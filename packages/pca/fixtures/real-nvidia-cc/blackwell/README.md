# Real NVIDIA Blackwell (GB100) GPU-CC evidence

Captured 2026-10-08 from a Phala-operated confidential-GPU node (8x GB100) through its attestation endpoint, with the PCA
challenge `e58bb1d0…ab453a7` as the SPDM request nonce. Third-party host; the cryptography does not depend on that.

| File | What it is |
|---|---|
| `gb100-gpu-attestation-report.bin`, `gb100-device-cert-chain.pem` | GPU 0: 4140-byte SPDM transcript and its 5-cert chain (`GB100 A01 GSP FMC LF` -> BROM -> `NVIDIA GB100 Provisioner ICA 00000` -> `NVIDIA GB100 Identity` -> `NVIDIA Device Identity CA`, the same P-384 root as Hopper). Driver 595.91.07, VBIOS 97.00.e4.00.1e. |
| `gb100-gpu1-*` | GPU 1 of the same node (a different device certificate). |
| `driver-rim.xml`, `vbios-rim.xml` | Signed RIMs: `NV_GPU_CC_DRIVER_GB100_595.91.07` and `NV_GPU_VBIOS_G525_0220_886_9700E4001E`. |

**Blackwell differs from Hopper in how the driver RIM is named.** Hopper: `NV_GPU_DRIVER_GH100_<version>`. Blackwell:
`NV_GPU_CC_DRIVER_<chip>_<version>` where `<chip>` is the report's signed opaque field 35 (`CHIP_INFO`, here `GB100`).
Fetching the Hopper-style id for a Blackwell GPU succeeds and returns a validly signed but WRONG manifest (product GH100),
so a consumer must also check the RIM's `product` against the chip.

## Revocation evidence (captured 2026-10-09)

| File | What it is |
|---|---|
| `l2-gb100.crl` | NVIDIA's CRL for `NVIDIA GB100 Identity` (`https://crl.ndis.nvidia.com/crl/l2-gb100.crl`), thisUpdate 2026-09-16, nextUpdate 2026-11-15. The Hopper `l2-gh100.crl` is issued by a different CA and cannot cover this chain. |
| `l1-root.crl` | The shared `NVIDIA Device Identity CA` CRL (byte-identical to `../collateral/l1-root.crl`). |
| `ocsp/*.nonce.resp.der` | OCSP responses from `http://ocsp.ndis.nvidia.com/` (request nonce `0123456789abcdef0123456789abcdef`), captured 2026-10-09T00:32:35Z, valid 24 h: `gpu0-1-brom` / `gpu1-1-brom` (per-device BROM certs), `2-provisioner-ica`, `3-identity` (shared). Tests fix the clock at 2026-10-09T00:33:00Z. |
