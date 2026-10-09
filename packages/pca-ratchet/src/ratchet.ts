import { ed25519 } from '@noble/curves/ed25519';
import {
  type InclusionProof,
  b64u,
  merkleProof,
  merkleRoot,
  verifyB64u,
  verifyInclusion,
} from '@atlasauth/pca';
import {
  type CoverNode,
  MAX_RATCHET_DEPTH,
  allLeafPublicKeys,
  coverKey,
  covers,
  deriveLeafSeed,
  leafPublicKey,
  leafSigningSeed,
  punctureSiblings,
  rootSeed,
} from './ggm';
import { utf8 } from './group';

/**
 * Mechanism 1 — Puncturable forward-secure capability keys (cryptographic one-time-use).
 *
 * A capability holder commits, up front, to a Merkle root over 2^depth one-time Ed25519 leaf
 * keys (a GGM puncturable PRF tree; see ggm.ts). Signing at leaf `i` produces an offline-verifiable
 * signature AND returns a new state in which leaf `i` is PUNCTURED: its key material is dropped and
 * can never be re-derived, so the same leaf can never sign twice. This replaces the resource
 * server's spend-once counter bookkeeping with cryptography — "already spent" becomes "key no
 * longer exists", provable without shared state.
 */

export type RatchetErrorCode =
  | 'invalid_depth'
  | 'invalid_seed'
  | 'leaf_out_of_range'
  | 'leaf_punctured';

export class RatchetError extends Error {
  readonly code: RatchetErrorCode;
  constructor(code: RatchetErrorCode, message: string) {
    super(message);
    this.name = 'RatchetError';
    this.code = code;
  }
}

/** An offline-verifiable one-time signature at a ratchet leaf. */
export interface RatchetSignature {
  /** b64u Ed25519 signature (64 bytes) under the leaf's one-time key. */
  edSig: string;
  /** b64u Ed25519 public key (32 bytes) of the signing leaf. */
  leafPubKey: string;
  /** Merkle inclusion proof that `leafPubKey` is the leaf at this index under the root commitment. */
  merklePath: InclusionProof;
}

/**
 * The live ratchet. `leafPubKeys` are public (safe to retain; needed to build Merkle proofs).
 * `covering` is the SECRET co-path: disjoint GGM seeds whose subtrees are exactly the leaves that
 * can still sign. Punctured leaves are absent from every covering subtree.
 */
export interface RatchetState {
  readonly depth: number;
  readonly leafCount: number;
  readonly rootCommitment: string;
  readonly leafPubKeys: readonly string[];
  readonly covering: ReadonlyMap<string, CoverNode>;
}

const SIG_DOMAIN = utf8('atlas-pca-ratchet/leaf-sig/v1\0');

/** Domain-separated signed message: binds the leaf index so a signature cannot be lifted elsewhere. */
function leafSigMessage(leafIndex: number, message: Uint8Array): Uint8Array {
  const idx = new Uint8Array(8);
  let x = BigInt(leafIndex);
  for (let i = 7; i >= 0; i--) {
    idx[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  const out = new Uint8Array(SIG_DOMAIN.length + 8 + message.length);
  out.set(SIG_DOMAIN, 0);
  out.set(idx, SIG_DOMAIN.length);
  out.set(message, SIG_DOMAIN.length + 8);
  return out;
}

/**
 * Build a ratchet from a root `seed` (≥ 32 bytes of entropy) and tree `depth`. Returns the public
 * `rootCommitment` (a Merkle root over all 2^depth leaf public keys) and the live `state`.
 */
export function deriveRatchetRoot(seed: Uint8Array, depth: number): { rootCommitment: string; state: RatchetState } {
  if (!Number.isInteger(depth) || depth < 1 || depth > MAX_RATCHET_DEPTH) {
    throw new RatchetError('invalid_depth', `depth must be an integer in [1, ${MAX_RATCHET_DEPTH}]`);
  }
  if (!(seed instanceof Uint8Array) || seed.length < 32) {
    throw new RatchetError('invalid_seed', 'seed must be a Uint8Array of at least 32 bytes');
  }
  const root = rootSeed(seed);
  const leafPubKeys = allLeafPublicKeys(root, depth);
  const rootCommitment = merkleRoot(leafPubKeys.slice());
  const covering = new Map<string, CoverNode>([[coverKey(0, 0), { level: 0, nodeIndex: 0, seed: root }]]);
  return {
    rootCommitment,
    state: { depth, leafCount: 2 ** depth, rootCommitment, leafPubKeys, covering },
  };
}

/** Find the (unique) covering node whose subtree contains `leafIndex`, or undefined if punctured. */
function findCovering(state: RatchetState, leafIndex: number): CoverNode | undefined {
  for (const node of state.covering.values()) {
    if (covers(node.level, node.nodeIndex, leafIndex, state.depth)) return node;
  }
  return undefined;
}

/**
 * Sign `message` at leaf `leafIndex`, then puncture that leaf. Returns the signature and a new
 * state with the leaf's key permanently dropped. Throws {@link RatchetError} if the leaf is out of
 * range or already punctured (cryptographic one-time-use: a spent leaf can never sign again).
 */
export function signAtLeaf(
  state: RatchetState,
  leafIndex: number,
  message: Uint8Array,
): { signature: RatchetSignature; newState: RatchetState } {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= state.leafCount) {
    throw new RatchetError('leaf_out_of_range', `leaf ${leafIndex} is out of range [0, ${state.leafCount})`);
  }
  const node = findCovering(state, leafIndex);
  if (node === undefined) {
    throw new RatchetError('leaf_punctured', `leaf ${leafIndex} is already punctured (spent) and cannot sign`);
  }
  const leafSeed = deriveLeafSeed(node, leafIndex, state.depth);
  const signingSeed = leafSigningSeed(leafSeed);
  const edSig = b64u(ed25519.sign(leafSigMessage(leafIndex, message), signingSeed));
  const leafPubKey = leafPublicKey(leafSeed);
  const merklePath = merkleProof(state.leafPubKeys.slice(), leafIndex);

  // Puncture: replace the covering node with its off-path siblings; the on-path (and leaf) seeds vanish.
  const covering = new Map(state.covering);
  covering.delete(coverKey(node.level, node.nodeIndex));
  for (const sib of punctureSiblings(node, leafIndex, state.depth)) {
    covering.set(coverKey(sib.level, sib.nodeIndex), sib);
  }

  return {
    signature: { edSig, leafPubKey, merklePath },
    newState: { ...state, covering },
  };
}

/**
 * Verify a ratchet signature offline against the root commitment, with no shared state: the
 * Ed25519 signature must be valid under `leafPubKey`, and `merklePath` must prove `leafPubKey` is
 * the leaf at `leafIndex` under `rootCommitment`. Never throws; any malformed input returns false.
 */
export function verifyLeafSignature(
  rootCommitment: string,
  leafIndex: number,
  message: Uint8Array,
  signature: RatchetSignature,
): boolean {
  try {
    if (signature === null || typeof signature !== 'object') return false;
    const { edSig, leafPubKey, merklePath } = signature;
    if (typeof edSig !== 'string' || typeof leafPubKey !== 'string' || merklePath === null || typeof merklePath !== 'object') {
      return false;
    }
    if (merklePath.index !== leafIndex) return false;
    if (!verifyB64u(leafPubKey, leafSigMessage(leafIndex, message), edSig)) return false;
    return verifyInclusion(rootCommitment, merklePath, leafPubKey);
  } catch {
    return false;
  }
}

/** Indices of leaves that can still sign (not yet punctured), sorted ascending. */
export function availableLeaves(state: RatchetState): number[] {
  const out: number[] = [];
  for (const node of state.covering.values()) {
    const span = 2 ** (state.depth - node.level);
    const base = node.nodeIndex * span;
    for (let i = 0; i < span; i++) out.push(base + i);
  }
  return out.sort((a, b) => a - b);
}

/** Whether leaf `leafIndex` can still sign. */
export function isLeafAvailable(state: RatchetState, leafIndex: number): boolean {
  return findCovering(state, leafIndex) !== undefined;
}
