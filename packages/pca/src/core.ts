/**
 * `@atlasauth/pca/core`: the minimal PCA Core API (see docs/pca/core.md).
 *
 * Exactly what is needed to mint a grant, delegate it, build a PCActn for one action, verify it, evaluate the
 * baseline caveats and guard against replay; plus the strict wire helpers a Core implementation is tested on. Every
 * name here is a RE-EXPORT of the same binding the root `@atlasauth/pca` entry exports: nothing is redefined, so
 * behaviour and wire formats are identical. Everything else is an extension: the experimental ones (intent layer,
 * attestation, FROST, ZK, optimistic execution, ledger, research modules) are under `@atlasauth/pca/ext/*`, and
 * threshold / step-up, risk and trust budget and the post-quantum suites are on the root entry. Core loads no
 * experimental module: a PCActn or policy that needs the intent layer is refused here unless the extension is passed
 * (`extensions: INTENT_EXTENSIONS` from `@atlasauth/pca/ext/intent`).
 */

// Keys (Ed25519, the Core suite)
export { generateKeyPair, publicKeyOf, encodeKey, decodeKey, type KeyPair } from './keys';

// Grant + delegation chain
export {
  mintRoot,
  attenuate,
  delegate,
  verifyChain,
  capHash,
  MAX_CHAIN_DEPTH,
  type Caveat,
  type Capability,
  type CapabilityChain,
  type ChainResult,
} from './capability';

// Plan commitment (the action must be a node of a committed plan)
export {
  commitPlan,
  merkleRoot,
  planNodeLeaf,
  verifyInclusion,
  paramsDigest,
  type PlanNode,
  type InclusionProof,
  type ProofStep,
} from './merkle';

// PCActn: build, encode / decode, verify
export {
  buildPCActn,
  encodePCActn,
  decodePCActn,
  verifyPCActnCore,
  PCACTN_VERSION,
  PCACTN_MAX_LIFETIME_MS,
  type PCActn,
  type VerifyResult,
  type CheckStatus,
  type CoreExtensions,
} from './pcactn';

// PCA-Action HTTP header (transport)
export { PCA_HEADER, pcaHeaders, decodePcaHeader, PcaHeaderError } from './adapters';

// Caveat semantics (the baseline caveat types; unknown types are unsatisfied)
export { evaluateAgentCaveats, policyCaveats } from './policy-vm';
export type { CaveatContext, ActionContext } from './predicates';

// Anti-replay (run only AFTER the PCActn verified)
export {
  guardPCActnReplay,
  InMemoryReplayStore,
  type ReplayStore,
  type CounterStore,
  type ReplayVerdict,
  type GuardOptions,
} from './replay';

// Strict wire helpers (canonical JSON, strict JSON profile, strict base64url)
export { canonicalizeStrict, hashCanonical, b64u, decodeB64uStrict } from './hash';
export { strictParse } from './strict-json';
