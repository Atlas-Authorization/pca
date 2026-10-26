/**
 * `@atlasauth/pca/ext/attestation`: Hardware and software attestation: AMD SEV-SNP, Intel TDX (DCAP), Azure Attestation, Google Confidential Space, NVIDIA SPDM / RIM / OCSP, PUF, software attestation, allowlists.
 *
 * Tier: experimental (see docs/pca/maturity.md). Not part of PCA Core and not re-exported from the root `@atlasauth/pca`.
 */
export * from '../attestation';
export * from '../hardware-sevsnp';
// Additional pluggable attestation roots for the multi-root N-of-M policy (see './attestation'). Namespaced
// so each root's purpose-named helpers (e.g. the per-root ECDSA-P256 key wrappers and `toHex`) compose
// without colliding with one another or with the flat SEV-SNP exports. HONEST PQ STATUS per root:
//   - attestIntelTdx  — Intel TDX/DCAP quote parsing + offline verification primitives. CLASSICAL (ECDSA-P256).
//   - attestPqSoftware — software/HSM root. POST-QUANTUM (ML-DSA / SLH-DSA, optional hybrid).
//   - attestPuf       — PUF unclonable root. Unclonability is CLASSICAL; the derived key MAY carry a PQ suite.
export * as attestIntelTdx from '../attest-intel-tdx';
export * as attestIntelCollateral from '../attest-intel-collateral'; // Intel PCS collateral (TCB info, QE identity, CRLs) vs the genuine TDX quote
//   - attestIntelDcap — the REAL Intel DCAP TDX quote as a first-class HardwareAttestationVerifier (quote + PCA binding,
//     incl. Azure runtime-data binding checked against Intel's signature, + PCS collateral); joins the N-of-M policy. CLASSICAL.
export * as attestIntelDcap from '../attest-intel-dcap';
//   - attestAmdSnp — the REAL AMD SEV-SNP report as a first-class HardwareAttestationVerifier with per-family ARK pins
//     (Milan / Genoa / Turin, from AMD KDS) and Azure runtime-data binding checked against AMD's signature. CLASSICAL.
export * as attestAmdSnp from '../attest-amd-snp';
//   - attestAzureMaa  — Azure-native MAA JWT root; covers BOTH SEV-SNP (sevsnpvm) and TDX (tdxvm) on
//     Azure CVMs via the MAA token-signing chain. CLASSICAL (ES256 / RS256).
export * as attestAzureMaa from '../attest-azure-maa';
//   - attestGcpConfidentialSpace — GCP-native Confidential Space attestation-token root; covers BOTH
//     AMD SEV-SNP and Intel TDX on GCP CVMs via Google's attestation-service signing chain. CLASSICAL (RS256).
export * as attestGcpConfidentialSpace from '../attest-gcp-confidential-space';
//   - attestNvidiaSpdm — NVIDIA GPU-CC root in the REAL wire format (SPDM transcript + X.509 device chain to the
//     NVIDIA Device Identity CA, ECDSA P-384); validated on a genuine H100. CLASSICAL.
export * as attestNvidiaSpdm from '../attest-nvidia-spdm';
//   - attestNvidiaRim — NVIDIA RIM golden measurements (signed XML, C14N via optional xml-crypto) + device-chain CRL
//     revocation, wired into attestNvidiaSpdm through its `postVerify` hook. CLASSICAL.
export * as attestNvidiaRim from '../attest-nvidia-rim';
export * as attestNvidiaOcsp from '../attest-nvidia-ocsp';
export * as attestPqSoftware from '../attest-pq-software';
export * as attestPuf from '../attest-puf';
export * from '../passport';
export * as attestAllowlist from '../attest-allowlist';
export * as attestMaaKeys from '../attest-maa-keys';
export * as attestMaaPins from '../attest-maa-pins';
export * as attestAllowlistAnchor from '../attest-allowlist-anchor';
export * from '../x509-validity';
