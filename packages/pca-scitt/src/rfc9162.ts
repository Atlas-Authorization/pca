/**
 * RFC 9162 section 2.1 Merkle tree (SHA-256): tree hash, inclusion paths and consistency proofs, with
 * the verification algorithms of sections 2.1.3.2 and 2.1.4.2. Leaf inputs are the raw entry bytes
 * (`SHA-256(0x00 || entry)`), so any independent RFC 9162 / RFC 6962 verifier can check a proof given
 * the same entry bytes. Hashing is `node:crypto` SHA-256; no custom primitive is implemented here.
 */
import { createHash } from 'node:crypto';

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

/** Root hash of the empty tree: SHA-256 of the empty string. */
export function emptyRoot(): Uint8Array {
  return sha256();
}

/** `SHA-256(0x00 || entry)`. */
export function leafHash(entry: Uint8Array): Uint8Array {
  return sha256(LEAF_PREFIX, entry);
}

/** `SHA-256(0x01 || left || right)`. */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(NODE_PREFIX, left, right);
}

/** Largest power of two strictly less than `n` (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH over already-hashed leaves (RFC 9162 section 2.1.1). */
export function treeHash(leafHashes: readonly Uint8Array[]): Uint8Array {
  const n = leafHashes.length;
  if (n === 0) return emptyRoot();
  if (n === 1) return leafHashes[0]!;
  const k = splitPoint(n);
  return nodeHash(treeHash(leafHashes.slice(0, k)), treeHash(leafHashes.slice(k)));
}

/** Inclusion path for leaf `index` in the tree of `leafHashes` (RFC 9162 section 2.1.3.1), bottom-up. */
export function inclusionPath(leafHashes: readonly Uint8Array[], index: number): Uint8Array[] {
  const n = leafHashes.length;
  if (!Number.isSafeInteger(index) || index < 0 || index >= n) throw new RangeError('rfc9162: leaf index out of range');
  if (n === 1) return [];
  const k = splitPoint(n);
  if (index < k) return [...inclusionPath(leafHashes.slice(0, k), index), treeHash(leafHashes.slice(k))];
  return [...inclusionPath(leafHashes.slice(k), index - k), treeHash(leafHashes.slice(0, k))];
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/**
 * Recompute the tree root from a leaf hash and its inclusion path (RFC 9162 section 2.1.3.2).
 * Returns null when the (index, size, path length) combination is invalid.
 */
export function rootFromInclusionPath(leaf: Uint8Array, index: number, size: number, path: readonly Uint8Array[]): Uint8Array | null {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || size < 1 || index >= size) return null;
  if (leaf.length !== 32 || path.some((p) => p.length !== 32)) return null;
  let fn = BigInt(index);
  let sn = BigInt(size) - 1n;
  let r = leaf;
  for (const p of path) {
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n ? r : null;
}

/** Verify an inclusion proof: the recomputed root must equal `root`. */
export function verifyInclusionPath(leaf: Uint8Array, index: number, size: number, path: readonly Uint8Array[], root: Uint8Array): boolean {
  const computed = rootFromInclusionPath(leaf, index, size, path);
  return computed !== null && equal(computed, root);
}

function subproof(m: number, d: readonly Uint8Array[], complete: boolean): Uint8Array[] {
  const n = d.length;
  if (m === n) return complete ? [] : [treeHash(d)];
  const k = splitPoint(n);
  if (m <= k) return [...subproof(m, d.slice(0, k), complete), treeHash(d.slice(k))];
  return [...subproof(m - k, d.slice(k), false), treeHash(d.slice(0, k))];
}

/** Consistency proof between the first `m` leaves and all of `leafHashes` (RFC 9162 section 2.1.4.1). */
export function consistencyPath(leafHashes: readonly Uint8Array[], m: number): Uint8Array[] {
  if (!Number.isSafeInteger(m) || m < 1 || m > leafHashes.length) throw new RangeError('rfc9162: consistency size out of range');
  return subproof(m, leafHashes, true);
}

/**
 * Verify a consistency proof between a tree of `first` leaves (root `firstRoot`) and one of `second` leaves
 * (root `secondRoot`) per RFC 9162 section 2.1.4.2. A proof from an empty tree is rejected (meaningless).
 */
export function verifyConsistencyPath(
  first: number,
  second: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  path: readonly Uint8Array[],
): boolean {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 1 || second < first) return false;
  if (firstRoot.length !== 32 || secondRoot.length !== 32 || path.some((p) => p.length !== 32)) return false;
  if (first === second) return path.length === 0 && equal(firstRoot, secondRoot);
  if (path.length === 0) return false;
  const nodes: Uint8Array[] = [...path];
  if ((first & (first - 1)) === 0) nodes.unshift(firstRoot); // first is an exact power of two
  let fn = BigInt(first) - 1n;
  let sn = BigInt(second) - 1n;
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = nodes[0]!;
  let sr = nodes[0]!;
  for (const c of nodes.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(fr, firstRoot) && equal(sr, secondRoot);
}
