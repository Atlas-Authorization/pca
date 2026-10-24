/* eslint-disable @typescript-eslint/no-explicit-any */
// ext-merkle.ts - typed adapter over the Dafny-proved RFC 6962 / RFC 9162 Merkle verifiers (formal/dafny/Merkle.dfy ->
// generated/pca_merkle.js). Plain JS in, plain JS out (no Dafny runtime type leaks).
//
// TRUSTED GLUE (not proved; exercised by test/ext-merkle.diff.test.ts): the hash primitive (SHA-256 / SHA-384 via node:crypto),
// strict base64url decoding of roots / siblings, the JS-number <-> Dafny-int conversions, the proof-object shape checks
// (hash_suite, side tags, safe-integer index/size). Everything after that - tree shape, the verify loop, root comparison - is the proved code.
import { hardenDafnyRuntime } from './runtime';
import { createHash } from 'node:crypto';
import BigNumber from 'bignumber.js';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const mk = require('../generated/pca_merkle.js') as { _dafny: any; Merkle: any };
hardenDafnyRuntime(mk._dafny);
const M = mk.Merkle.__default;
const D = mk._dafny;

export type MerkleSuite = 'sha256' | 'sha384';
const HLEN: Record<MerkleSuite, number> = { sha256: 32, sha384: 48 };

function toSeq(u: Uint8Array): any {
  const s = D.Seq.of();
  for (let i = 0; i < u.length; i++) s.push(u[i]);
  return s;
}
function fromSeq(s: any): Uint8Array {
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s[i];
  return u;
}
const hashFn = (suite: MerkleSuite) => (d: any): any => toSeq(new Uint8Array(createHash(suite).update(fromSeq(d)).digest()));
const bn = (n: number): BigNumber => new BigNumber(n);

// ---- strict base64url (RFC 4648 section 5, no padding, canonical trailing bits); independent of @scure/base ---------------------------
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const REV = new Int16Array(128).fill(-1);
for (let i = 0; i < 64; i++) REV[ALPHA.charCodeAt(i)] = i;
export function b64uEncode(u: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < u.length; i += 3) {
    const v = (u[i]! << 16) | (u[i + 1]! << 8) | u[i + 2]!;
    out += ALPHA[(v >> 18) & 63]! + ALPHA[(v >> 12) & 63]! + ALPHA[(v >> 6) & 63]! + ALPHA[v & 63]!;
  }
  if (i + 1 === u.length) {
    const v = u[i]! << 16;
    out += ALPHA[(v >> 18) & 63]! + ALPHA[(v >> 12) & 63]!;
  } else if (i + 2 === u.length) {
    const v = (u[i]! << 16) | (u[i + 1]! << 8);
    out += ALPHA[(v >> 18) & 63]! + ALPHA[(v >> 12) & 63]! + ALPHA[(v >> 6) & 63]!;
  }
  return out;
}
/** Canonical decode, or null for ANY deviation (alphabet, length mod 4 == 1, non-zero trailing bits). Never throws. */
export function b64uDecodeStrict(s: unknown): Uint8Array | null {
  if (typeof s !== 'string') return null;
  const n = s.length;
  if (n % 4 === 1) return null;
  const vals = new Array<number>(n);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? REV[c]! : -1;
    if (v < 0) return null;
    vals[i] = v;
  }
  const out = new Uint8Array(Math.floor((n * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 3 < n; i += 4) {
    const v = (vals[i]! << 18) | (vals[i + 1]! << 12) | (vals[i + 2]! << 6) | vals[i + 3]!;
    out[o++] = (v >> 16) & 255;
    out[o++] = (v >> 8) & 255;
    out[o++] = v & 255;
  }
  const rem = n - i;
  if (rem === 2) {
    const v = (vals[i]! << 18) | (vals[i + 1]! << 12);
    if ((v & 0xffff) !== 0) return null;
    out[o++] = (v >> 16) & 255;
  } else if (rem === 3) {
    const v = (vals[i]! << 18) | (vals[i + 1]! << 12) | (vals[i + 2]! << 6);
    if ((v & 0xff) !== 0) return null;
    out[o++] = (v >> 16) & 255;
    out[o++] = (v >> 8) & 255;
  }
  return out;
}

// ---- tree builders (the proved generators) -----------------------------------------------------------------------------------------------
/** RFC 6962 tree hash over leaf DATA (already-canonical bytes). Empty list => H(""). */
export function merkleRootVerified(leaves: Uint8Array[], suite: MerkleSuite = 'sha256'): Uint8Array {
  const ds = D.Seq.of();
  for (const l of leaves) ds.push(toSeq(l));
  return fromSeq(M.Root(hashFn(suite), ds));
}
export interface VProofStep {
  side: 'L' | 'R';
  hash: string;
}
export interface VInclusionProof {
  index: number;
  size: number;
  path: VProofStep[];
  hash_suite?: MerkleSuite;
}
/** Honest inclusion proof (merkle.ts merkleProof). */
export function inclusionProofVerified(leaves: Uint8Array[], index: number, suite: MerkleSuite = 'sha256'): VInclusionProof {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new RangeError('index out of range');
  const ds = D.Seq.of();
  for (const l of leaves) ds.push(toSeq(l));
  const p = M.InclPath(hashFn(suite), ds, bn(index));
  const path: VProofStep[] = [];
  for (let i = 0; i < p.length; i++) path.push({ side: p[i].dtor_side.is_Lt ? 'L' : 'R', hash: b64uEncode(fromSeq(p[i].dtor_hash)) });
  const out: VInclusionProof = { index, size: leaves.length, path };
  if (suite !== 'sha256') out.hash_suite = suite;
  return out;
}
/** Honest consistency proof elements for (oldSize, leaves.length), b64u (ledger.ts consistencyProof; sha256). */
export function consistencyProofVerified(leaves: Uint8Array[], oldSize: number): { oldSize: number; newSize: number; path: string[] } {
  const ds = D.Seq.of();
  for (const l of leaves) ds.push(toSeq(l));
  // SUBPROOF(m, D[n], true) exactly as ledger.ts writes it (Merkle.SubProof; proved equal to the verifier's expected list: Merkle.SubEq).
  const p = oldSize > 0 && oldSize < leaves.length ? M.SubProof(hashFn('sha256'), ds, bn(oldSize), true) : D.Seq.of();
  const path: string[] = [];
  for (let i = 0; i < p.length; i++) path.push(b64uEncode(fromSeq(p[i])));
  return { oldSize, newSize: leaves.length, path };
}

// ---- verifiers --------------------------------------------------------------------------------------------------------------------------
/**
 * Inclusion verification, the proved decision. Same contract as merkle.ts `verifyInclusion` but takes the already-canonical leaf BYTES
 * (the caller hashes `canonicalBytes(leaf)`; canonicalisation failure => false at the call site). Never throws.
 */
export function verifyInclusionVerified(root: unknown, proof: unknown, leafBytes: Uint8Array): boolean {
  try {
    const pr = proof as any;
    if (!pr || !Array.isArray(pr.path)) return false;
    const rawSuite: unknown = pr.hash_suite;
    if (rawSuite !== undefined && rawSuite !== 'sha256' && rawSuite !== 'sha384') return false;
    const suite: MerkleSuite = rawSuite === undefined ? 'sha256' : (rawSuite as MerkleSuite);
    if (!Number.isSafeInteger(pr.index) || !Number.isSafeInteger(pr.size)) return false;
    const rootB = b64uDecodeStrict(root);
    if (!rootB) return false;
    const steps: any[] = [];
    for (let i = 0; i < pr.path.length; i++) {
      const st = pr.path[i];
      if (!st || (st.side !== 'L' && st.side !== 'R')) return false;
      const h = b64uDecodeStrict(st.hash);
      if (!h) return false;
      steps.push(mk.Merkle.Step.create_Step(st.side === 'L' ? mk.Merkle.Side.create_Lt() : mk.Merkle.Side.create_Rt(), toSeq(h)));
    }
    const path = D.Seq.of();
    for (const s of steps) path.push(s);
    return M.VerifyInclusion(hashFn(suite), bn(HLEN[suite]), toSeq(rootB), bn(pr.index), bn(pr.size), path, toSeq(leafBytes)) === true;
  } catch {
    return false;
  }
}

const MAX_CONSISTENCY_PATH = 2 * 53 + 2;

/**
 * Consistency verification (RFC 9162 section 2.1.4.2), the proved decision, STRICT: sizes are safe integers, roots and proof elements are
 * canonical base64url of exactly 32 bytes, an empty old tree requires oldRoot == SHA-256(""), equal sizes require equal canonical roots.
 * Never throws. See the notes for the (documented) points where ledger.ts verifyLedgerConsistency is more permissive.
 */
export function verifyConsistencyVerified(
  oldRoot: unknown,
  newRoot: unknown,
  proof: { oldSize: number; newSize: number; path: string[] },
): boolean {
  try {
    if (!proof || !Array.isArray(proof.path)) return false;
    if (!Number.isSafeInteger(proof.oldSize) || !Number.isSafeInteger(proof.newSize)) return false;
    // same DoS bound as ledger.ts (2*53+2); Merkle.PathCapRedundant proves it never rejects an acceptable proof below 2^53
    if (proof.path.length > MAX_CONSISTENCY_PATH) return false;
    const o = b64uDecodeStrict(oldRoot);
    const nw = b64uDecodeStrict(newRoot);
    // m == 0 requires oldRoot == SHA-256("") (and newRoot too when n == 0); m == n compares the two decoded roots. Both must be canonical (strict).
    if (!o || !nw) return false;
    const els = D.Seq.of();
    for (let i = 0; i < proof.path.length; i++) {
      const e = b64uDecodeStrict(proof.path[i]);
      if (!e) return false;
      els.push(toSeq(e));
    }
    return M.VerifyConsistency(hashFn('sha256'), bn(32), toSeq(o), toSeq(nw), bn(proof.oldSize), bn(proof.newSize), els) === true;
  } catch {
    return false;
  }
}

/**
 * Tree hash that a well-shaped inclusion proof folds to (null when the shape / sibling lengths are wrong). Proved equivalent to
 * `verifyInclusion` (Merkle.InclusionRootIff): verify(root) <=> inclusionRootVerified(...) == root.
 */
export function inclusionRootVerified(proof: unknown, leafBytes: Uint8Array): Uint8Array | null {
  try {
    const pr = proof as any;
    if (!pr || !Array.isArray(pr.path)) return null;
    const rawSuite: unknown = pr.hash_suite;
    if (rawSuite !== undefined && rawSuite !== 'sha256' && rawSuite !== 'sha384') return null;
    const suite: MerkleSuite = rawSuite === undefined ? 'sha256' : (rawSuite as MerkleSuite);
    if (!Number.isSafeInteger(pr.index) || !Number.isSafeInteger(pr.size)) return null;
    const path = D.Seq.of();
    for (let i = 0; i < pr.path.length; i++) {
      const st = pr.path[i];
      if (!st || (st.side !== 'L' && st.side !== 'R')) return null;
      const h = b64uDecodeStrict(st.hash);
      if (!h) return null;
      path.push(mk.Merkle.Step.create_Step(st.side === 'L' ? mk.Merkle.Side.create_Lt() : mk.Merkle.Side.create_Rt(), toSeq(h)));
    }
    const r = M.InclusionRoot(hashFn(suite), bn(HLEN[suite]), bn(pr.index), bn(pr.size), path, toSeq(leafBytes));
    return r.is_Some ? fromSeq(r.dtor_v) : null;
  } catch {
    return null;
  }
}

/**
 * revocation.ts `verifyMembership`, built on the proved fold: the size-bound root is sha256("pca-revset/v1\0" || {"size":n,"tree":"<b64u>"}).
 * `idBytes` is canonicalBytes(id). Never throws.
 */
export function verifyMembershipVerified(root: unknown, proof: any, idBytes: Uint8Array): boolean {
  try {
    if (typeof root !== 'string' || !proof || !Number.isSafeInteger(proof.size)) return false;
    const tree = inclusionRootVerified(proof, idBytes);
    if (!tree) return false;
    const body = `pca-revset/v1\0{"size":${proof.size},"tree":"${b64uEncode(tree)}"}`;
    return b64uEncode(new Uint8Array(createHash('sha256').update(new TextEncoder().encode(body)).digest())) === root;
  } catch {
    return false;
  }
}
