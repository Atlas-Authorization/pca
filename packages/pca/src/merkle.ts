import { b64u, canonicalBytes, decodeB64uStrict, hashCanonical, sha256 } from './hash';

/**
 * Binary Merkle tree (RFC 6962 shape: split at the largest power of two < n, so no leaf
 * duplication) with domain separation: leaf = H(0x00 || canon(leaf)), node = H(0x01 || L || R).
 * A leaf can therefore never be confused with an internal node (second-preimage safe).
 */
const LEAF = 0x00;
const NODE = 0x01;

export interface ProofStep {
  /** Side the SIBLING sits on. */
  side: 'L' | 'R';
  hash: string;
}
export interface InclusionProof {
  index: number;
  size: number;
  path: ProofStep[];
}

function cat(prefix: number, ...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(1 + parts.reduce((n, p) => n + p.length, 0));
  out[0] = prefix;
  let o = 1;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function leafHash(leaf: unknown): Uint8Array {
  return sha256(cat(LEAF, canonicalBytes(leaf)));
}
function nodeHash(l: Uint8Array, r: Uint8Array): Uint8Array {
  return sha256(cat(NODE, l, r));
}

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function build(hs: Uint8Array[]): Uint8Array {
  if (hs.length === 1) return hs[0]!;
  const k = split(hs.length);
  return nodeHash(build(hs.slice(0, k)), build(hs.slice(k)));
}

function prove(hs: Uint8Array[], idx: number, out: ProofStep[]): void {
  if (hs.length === 1) return;
  const k = split(hs.length);
  if (idx < k) {
    prove(hs.slice(0, k), idx, out);
    out.push({ side: 'R', hash: b64u(build(hs.slice(k))) });
  } else {
    prove(hs.slice(k), idx - k, out);
    out.push({ side: 'L', hash: b64u(build(hs.slice(0, k))) });
  }
}

export function merkleRoot(leaves: unknown[]): string {
  if (leaves.length === 0) throw new RangeError('merkleRoot: empty leaf set');
  return b64u(build(leaves.map(leafHash)));
}

export function merkleProof(leaves: unknown[], index: number): InclusionProof {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError('merkleProof: index out of range');
  }
  const path: ProofStep[] = [];
  prove(leaves.map(leafHash), index, path);
  return { index, size: leaves.length, path };
}

/** Sibling sides (leaf -> root) for leaf `index` in a tree of `size` leaves (RFC 6962 split). */
function pathShape(index: number, size: number): ('L' | 'R')[] {
  const out: ('L' | 'R')[] = [];
  let idx = index;
  let n = size;
  while (n > 1) {
    const k = split(n);
    if (idx < k) {
      out.push('R');
      n = k;
    } else {
      out.push('L');
      idx -= k;
      n -= k;
    }
  }
  return out.reverse();
}

/** Never throws; malformed proofs return false. */
export function verifyInclusion(root: string, proof: InclusionProof, leaf: unknown): boolean {
  try {
    if (!proof || !Array.isArray(proof.path)) return false;
    // Bind index+size: the path SHAPE (length and each sibling side) is fully determined by them.
    if (!Number.isSafeInteger(proof.index) || !Number.isSafeInteger(proof.size)) return false;
    if (proof.size < 1 || proof.index < 0 || proof.index >= proof.size) return false;
    const shape = pathShape(proof.index, proof.size);
    if (shape.length !== proof.path.length) return false;
    let h = leafHash(leaf);
    for (let i = 0; i < proof.path.length; i++) {
      const step = proof.path[i]!;
      if (step.side !== shape[i]) return false;
      const sib = decodeB64uStrict(step.hash, 32); // canonical base64url, exactly 32 bytes
      if (!sib) return false;
      h = step.side === 'L' ? nodeHash(sib, h) : nodeHash(h, sib);
    }
    return b64u(h) === root;
  } catch {
    return false;
  }
}

// ---- L1 plan commitment ----------------------------------------------------------------

/**
 * SINGLE CANONICAL RULE for params commitment: params_digest = hashCanonical(params ?? {}).
 * A plan node that omits `params_digest` means "no params" and is committed (in the Merkle leaf)
 * as EMPTY_PARAMS_DIGEST, exactly what a PCActn for it carries (`paramsDigest(undefined)`).
 * Plan node and action therefore always reconcile; there is no null/absent leaf form.
 */
export function paramsDigest(params?: unknown): string {
  return hashCanonical(params ?? {});
}
/** Likewise an omitted reversibility_class commits as this default (same on node and action). */
export const DEFAULT_REVERSIBILITY_CLASS = 'reversible';
export const EMPTY_PARAMS_DIGEST: string = paramsDigest();

export interface PlanNode {
  id: string;
  verb: string;
  resource: string;
  /** Defaults to EMPTY_PARAMS_DIGEST when omitted (see paramsDigest). */
  params_digest?: string;
  reversibility_class?: string;
  pre?: unknown;
  post?: unknown;
}

/** The committed form of pre/post conditions; carried in PCActn.plan.conditions_digest. */
export function conditionsDigest(pre?: unknown, post?: unknown): string {
  return b64u(sha256(canonicalBytes({ pre: pre ?? null, post: post ?? null })));
}

/**
 * The Merkle leaf for an action at a plan node. A PCActn recomputes this from its own action
 * fields (+ node_id, conditions_digest), so any change to the action breaks inclusion.
 */
export function planLeaf(
  nodeId: string,
  action: { verb: string; resource: string; params_digest?: string; reversibility_class?: string },
  conditions: string,
): Record<string, unknown> {
  return {
    node_id: nodeId,
    verb: action.verb,
    resource: action.resource,
    params_digest: action.params_digest ?? EMPTY_PARAMS_DIGEST,
    reversibility_class: action.reversibility_class ?? DEFAULT_REVERSIBILITY_CLASS,
    conditions,
  };
}

export function planNodeLeaf(n: PlanNode): Record<string, unknown> {
  return planLeaf(n.id, n, conditionsDigest(n.pre, n.post));
}

export function commitPlan(nodes: PlanNode[]): { root: string; proofFor(nodeId: string): InclusionProof } {
  const ids = new Set<string>();
  for (const n of nodes) {
    if (ids.has(n.id)) throw new Error(`commitPlan: duplicate node id ${n.id}`);
    ids.add(n.id);
  }
  const leaves = nodes.map(planNodeLeaf);
  const root = merkleRoot(leaves);
  return {
    root,
    proofFor(nodeId: string): InclusionProof {
      const i = nodes.findIndex((n) => n.id === nodeId);
      if (i < 0) throw new Error(`commitPlan: unknown node ${nodeId}`);
      return merkleProof(leaves, i);
    },
  };
}
