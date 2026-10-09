export * from './hash';
export * from './strict-json';
export * from './wire';
export * from './keys';
export * from './pq';
export * from './merkle';
export * from './capability';
export * from './pcactn';
export * from './threshold';
export * from './frost';
export * from './frost-dkg';
export * from './frost-net';
export * from './frost-pq';
export * from './predicates';
export * from './risk';
export * from './envelope';
export * from './policy-vm';
export * from './ledger';
export * from './revocation';
export * from './beacons';
export * from './replay'; // ReplayStore / CounterStore contract + guardPCActnReplay + reference in-memory store
export * from './attestation';
export * from './hardware-sevsnp';
// Additional pluggable attestation roots for the multi-root N-of-M policy (see './attestation'). Namespaced
// so each root's purpose-named helpers (e.g. the per-root ECDSA-P256 key wrappers and `toHex`) compose
// without colliding with one another or with the flat SEV-SNP exports. HONEST PQ STATUS per root:
//   - attestIntelTdx  — Intel TDX/DCAP quote parsing + offline verification primitives. CLASSICAL (ECDSA-P256).
//   - attestPqSoftware — software/HSM root. POST-QUANTUM (ML-DSA / SLH-DSA, optional hybrid).
//   - attestPuf       — PUF unclonable root. Unclonability is CLASSICAL; the derived key MAY carry a PQ suite.
export * as attestIntelTdx from './attest-intel-tdx';
export * as attestIntelCollateral from './attest-intel-collateral'; // Intel PCS collateral (TCB info, QE identity, CRLs) vs the genuine TDX quote
//   - attestIntelDcap — the REAL Intel DCAP TDX quote as a first-class HardwareAttestationVerifier (quote + PCA binding,
//     incl. Azure runtime-data binding checked against Intel's signature, + PCS collateral); joins the N-of-M policy. CLASSICAL.
export * as attestIntelDcap from './attest-intel-dcap';
//   - attestAmdSnp — the REAL AMD SEV-SNP report as a first-class HardwareAttestationVerifier with per-family ARK pins
//     (Milan / Genoa / Turin, from AMD KDS) and Azure runtime-data binding checked against AMD's signature. CLASSICAL.
export * as attestAmdSnp from './attest-amd-snp';
//   - attestAzureMaa  — Azure-native MAA JWT root; covers BOTH SEV-SNP (sevsnpvm) and TDX (tdxvm) on
//     Azure CVMs via the MAA token-signing chain. CLASSICAL (ES256 / RS256).
export * as attestAzureMaa from './attest-azure-maa';
//   - attestGcpConfidentialSpace — GCP-native Confidential Space attestation-token root; covers BOTH
//     AMD SEV-SNP and Intel TDX on GCP CVMs via Google's attestation-service signing chain. CLASSICAL (RS256).
export * as attestGcpConfidentialSpace from './attest-gcp-confidential-space';
//   - attestNvidiaSpdm — NVIDIA GPU-CC root in the REAL wire format (SPDM transcript + X.509 device chain to the
//     NVIDIA Device Identity CA, ECDSA P-384); validated on a genuine H100. CLASSICAL.
export * as attestNvidiaSpdm from './attest-nvidia-spdm';
//   - attestNvidiaRim — NVIDIA RIM golden measurements (signed XML, C14N via optional xml-crypto) + device-chain CRL
//     revocation, wired into attestNvidiaSpdm through its `postVerify` hook. CLASSICAL.
export * as attestNvidiaRim from './attest-nvidia-rim';
export * as attestNvidiaOcsp from './attest-nvidia-ocsp';
export * as attestPqSoftware from './attest-pq-software';
export * as attestPuf from './attest-puf';
export * from './optimistic';
export * from './bond-settlement';
export * from './zk';
export * from './objective-binding';
export * from './semantic-threshold';
export * from './policy-debug';
export * from './safety-certificate';
export * from './catalog';
export * from './facade';

// Frontier capabilities (docs/pca-frontier-research.md). Namespaced so their
// APIs compose cleanly and don't collide (e.g. objectiveRisk.commitGoal vs
// progress.commitGoal). Library-complete; server/wire integration is staged.
export * as objectiveRisk from './objective-risk';
export * as prohibitions from './prohibitions';
export * as contracts from './contracts';
export * as progress from './progress';
export * as mesh from './mesh';
export * as agentNative from './agent-native';
export * as taint from './taint';

export * from './adapters';
export * from './policy-sim';
export * from './approvals';
export * from './approval-channels';
export * from './immune';
export * from './policy-templates';
export * from './console';
export * from './passport';
export * from './dlp';
export * from './reputation';
export * from './compliance';
export * from './receipt';
export * from './budget-forecast';
export * from './session';
export * from './nl';
export * from './ha';
export * from './kem';
export * from './discovery';
export * from './entropy';
export * as pqThreshold from './pq-threshold';
export * as attestAllowlist from './attest-allowlist';
export * as attestMaaKeys from './attest-maa-keys';
export * as attestMaaPins from './attest-maa-pins';
export * as attestAllowlistAnchor from './attest-allowlist-anchor';
// NOTE: './durable-state' is Node-only (node:fs) and is deliberately NOT re-exported here; import it via '@atlasauth/pca/durable-state'.
// Resource-server verification (verdict + framework-neutral requirePCA guard). Lives HERE, not in any other product's SDK:
// PCA stands alone; the framework middleware packages (pca-fetch/express/fastify/hono/next) depend only on this package.
export * from './server/verify';
export * from './server/require-pca';
