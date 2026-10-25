// attest-dropins.ts - the attestation drop-ins whose DECISIONS are made by the proved Attest.dfy code. They used to live here
// (test support) and are now the PRODUCTION implementations in packages/pca/src/attest-proved.ts, which attestation.ts,
// attest-allowlist.ts and attest-allowlist-anchor.ts forward to. Re-exported under the old names so the differential tests
// compare production (proved) against the frozen hand-written code in ./legacy.
export {
  createAttestationVerifierProved as createAttestationVerifierVerified,
  verifyAllowlistAnchoredProved as verifyAllowlistAnchoredVerified,
  verifyAllowlistDurableProved as verifyAllowlistDurableVerified,
  verifyAttestationProved as verifyAttestationVerified,
} from '../../../pca/src/attest-proved';
