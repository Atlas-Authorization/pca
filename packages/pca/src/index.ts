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
export * from './attestation';
export * from './hardware-sevsnp';
// Additional pluggable attestation roots for the multi-root N-of-M policy (see './attestation'). Namespaced
// so each root's purpose-named helpers (e.g. the per-root ECDSA-P256 key wrappers and `toHex`) compose
// without colliding with one another or with the flat SEV-SNP exports. HONEST PQ STATUS per root:
//   - attestIntelTdx  — Intel TDX/DCAP CPU-TEE root. CLASSICAL (ECDSA-P256).
//   - attestNvidiaCc  — NVIDIA GPU confidential-computing root. CLASSICAL (ECDSA-P256).
//   - attestPqSoftware — software/HSM root. POST-QUANTUM (ML-DSA / SLH-DSA, optional hybrid).
//   - attestPuf       — PUF unclonable root. Unclonability is CLASSICAL; the derived key MAY carry a PQ suite.
export * as attestIntelTdx from './attest-intel-tdx';
export * as attestNvidiaCc from './attest-nvidia-cc';
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
