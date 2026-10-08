import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { b64u } from '@atlasauth/pca';
import { utf8 } from './group';

/**
 * GGM binary-tree puncturable PRF (Mechanism 1 internals).
 *
 * A depth-`d` complete binary tree. The root holds a 32-byte seed; every internal node derives
 * its two children with a length-doubling PRG built from HMAC-SHA256 (a PRF):
 *
 *   PRG(seed) = ( HMAC(seed, DOMAIN‖0x00), HMAC(seed, DOMAIN‖0x01) )
 *
 * Each of the 2^d leaves derives a one-time Ed25519 signing seed from its own leaf seed
 * (domain-separated again, so a leaf seed and its signing key are not the same bytes).
 *
 * PUNCTURING (forward security). The secret state is NOT the root seed; it is a *co-path*: a
 * set of disjoint "covering" node seeds whose subtrees are exactly the still-available leaves.
 * To puncture leaf i, the covering node above it is expanded down to i, each OFF-PATH sibling
 * seed is retained as a new covering node, and every ON-PATH seed (including leaf i's own) is
 * dropped. Because the PRG is one-way, a dropped seed can never be recovered from the retained
 * siblings — leaf i's signing key is gone forever. See `ratchet.ts` for the public API.
 */

const PRG_DOMAIN = utf8('atlas-pca-ratchet/ggm-prg/v1');
const LEAFKEY_DOMAIN = utf8('atlas-pca-ratchet/ggm-leafkey/v1');
const ROOT_DOMAIN = utf8('atlas-pca-ratchet/ggm-root/v1');

/** Longest tree accepted. Setup derives all 2^depth leaf public keys, so this bounds that cost. */
export const MAX_RATCHET_DEPTH = 20;

export interface CoverNode {
  /** Distance from the root (0 = root, `depth` = leaf). */
  level: number;
  /** Index of the node within its level, 0 .. 2^level − 1. */
  nodeIndex: number;
  /** The node's GGM seed (secret). */
  seed: Uint8Array;
}

function prgLeft(seed: Uint8Array): Uint8Array {
  const m = new Uint8Array(PRG_DOMAIN.length + 1);
  m.set(PRG_DOMAIN);
  m[PRG_DOMAIN.length] = 0x00;
  return hmac(sha256, seed, m);
}

function prgRight(seed: Uint8Array): Uint8Array {
  const m = new Uint8Array(PRG_DOMAIN.length + 1);
  m.set(PRG_DOMAIN);
  m[PRG_DOMAIN.length] = 0x01;
  return hmac(sha256, seed, m);
}

/** The GGM root seed, normalized/domain-separated from caller-supplied entropy. */
export function rootSeed(seed: Uint8Array): Uint8Array {
  return hmac(sha256, seed, ROOT_DOMAIN);
}

/** Ed25519 32-byte signing seed for a leaf, derived from that leaf's GGM seed. */
export function leafSigningSeed(leafSeed: Uint8Array): Uint8Array {
  return hmac(sha256, leafSeed, LEAFKEY_DOMAIN);
}

/** b64u Ed25519 public key for a leaf's GGM seed. */
export function leafPublicKey(leafSeed: Uint8Array): string {
  return b64u(ed25519.getPublicKey(leafSigningSeed(leafSeed)));
}

/** Does the subtree of node (level, nodeIndex) contain `leafIndex`? */
export function covers(level: number, nodeIndex: number, leafIndex: number, depth: number): boolean {
  return Math.floor(leafIndex / 2 ** (depth - level)) === nodeIndex;
}

/** The bit chosen when descending from `level` towards `leafIndex` (0 = left, 1 = right). */
function descendBit(level: number, leafIndex: number, depth: number): number {
  return Math.floor(leafIndex / 2 ** (depth - level - 1)) % 2;
}

/** Derive the leaf GGM seed for `leafIndex` from a covering node that contains it. */
export function deriveLeafSeed(node: CoverNode, leafIndex: number, depth: number): Uint8Array {
  let seed = node.seed;
  for (let level = node.level; level < depth; level++) {
    seed = descendBit(level, leafIndex, depth) === 0 ? prgLeft(seed) : prgRight(seed);
  }
  return seed;
}

/**
 * Puncture `leafIndex` out of `node`'s subtree: return the off-path sibling covering nodes that
 * together cover every leaf under `node` EXCEPT `leafIndex`. The on-path seeds (and the leaf seed
 * itself) are never returned — they are dropped, which is what makes the puncture irreversible.
 */
export function punctureSiblings(node: CoverNode, leafIndex: number, depth: number): CoverNode[] {
  const out: CoverNode[] = [];
  let seed = node.seed;
  let nodeIndex = node.nodeIndex;
  for (let level = node.level; level < depth; level++) {
    const bit = descendBit(level, leafIndex, depth);
    const left = prgLeft(seed);
    const right = prgRight(seed);
    const childBase = nodeIndex * 2;
    out.push({
      level: level + 1,
      nodeIndex: childBase + (1 - bit),
      seed: bit === 0 ? right : left,
    });
    seed = bit === 0 ? left : right;
    nodeIndex = childBase + bit;
  }
  // (level === depth, nodeIndex === leafIndex, seed === leaf seed) is DROPPED.
  return out;
}

/** Derive every leaf's public key from the root seed (used once, at setup, for the commitment). */
export function allLeafPublicKeys(root: Uint8Array, depth: number): string[] {
  const out = new Array<string>(2 ** depth);
  const recurse = (seed: Uint8Array, level: number, base: number): void => {
    if (level === depth) {
      out[base] = leafPublicKey(seed);
      return;
    }
    const half = 2 ** (depth - level - 1);
    recurse(prgLeft(seed), level + 1, base);
    recurse(prgRight(seed), level + 1, base + half);
  };
  recurse(root, 0, 0);
  return out;
}

export function coverKey(level: number, nodeIndex: number): string {
  return `${level}:${nodeIndex}`;
}
