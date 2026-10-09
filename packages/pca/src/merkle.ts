import {
  b64u,
  canonicalBytes,
  decodeB64uStrict,
  DEFAULT_HASH_SUITE,
  hashCanonical,
  hashWithSuite,
  HASH_LEN,
  isHashSuite,
  sha256,
  type HashSuite,
} from './hash';

/**
 * Binary Merkle tree (RFC 6962 shape: split at the largest power of two < n, so no leaf
 * duplication) with domain separation: leaf = H(0x00 || canon(leaf)), node = H(0x01 || L || R).
 * A leaf can therefore never be confused with an internal node (second-preimage safe).
 *
 * HASH AGILITY (P4): `H` is selected by a {@link HashSuite}, DEFAULT `'sha256'`. The default path is
 * BYTE-IDENTICAL to before — a proof built under sha256 carries NO `hash_suite` field, so every existing
 * root/proof is unchanged and cross-SDK verifiers that never opt in see no difference. `'sha384'` is the
 * optional stronger-margin variant (see the agility note in `hash.ts`: margin/agility, NOT a fix for any
 * SHA-256 weakness). A proof is SELF-DESCRIBING: it records its suite in `hash_suite` only when non-default,
 * and {@link verifyInclusion} reads it back (absence => sha256). The suites are mutually fail-closed: a
 * sha384 proof's 48-byte siblings can never satisfy the 32-byte decode a sha256 reading demands, and vice
 * versa, so a proof built under one suite NEVER verifies under the other.
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
  /** Hash suite this proof was built under. ABSENT => `'sha256'` (back-compat; sha256 proofs are byte-identical). */
  hash_suite?: HashSuite;
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

/**
 * The sha256 leaf hash. Kept single-argument so it stays BYTE-IDENTICAL and usable as a bare
 * `leaves.map(leafHash)` callback (existing external callers rely on both). Suite-aware leaf hashing is
 * done internally by {@link leafHashSuite}; the suite is threaded through the tree/root/proof/verify APIs.
 */
export function leafHash(leaf: unknown): Uint8Array {
  return leafHashSuite(leaf, DEFAULT_HASH_SUITE);
}
function leafHashSuite(leaf: unknown, suite: HashSuite): Uint8Array {
  return hashWithSuite(cat(LEAF, canonicalBytes(leaf)), suite);
}
function nodeHash(l: Uint8Array, r: Uint8Array, suite: HashSuite = DEFAULT_HASH_SUITE): Uint8Array {
  return hashWithSuite(cat(NODE, l, r), suite);
}

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function build(hs: Uint8Array[], suite: HashSuite): Uint8Array {
  if (hs.length === 1) return hs[0]!;
  const k = split(hs.length);
  return nodeHash(build(hs.slice(0, k), suite), build(hs.slice(k), suite), suite);
}

function prove(hs: Uint8Array[], idx: number, out: ProofStep[], suite: HashSuite): void {
  if (hs.length === 1) return;
  const k = split(hs.length);
  if (idx < k) {
    prove(hs.slice(0, k), idx, out, suite);
    out.push({ side: 'R', hash: b64u(build(hs.slice(k), suite)) });
  } else {
    prove(hs.slice(k), idx - k, out, suite);
    out.push({ side: 'L', hash: b64u(build(hs.slice(0, k), suite)) });
  }
}

export function merkleRoot(leaves: unknown[], suite: HashSuite = DEFAULT_HASH_SUITE): string {
  if (leaves.length === 0) throw new RangeError('merkleRoot: empty leaf set');
  return b64u(build(leaves.map((l) => leafHashSuite(l, suite)), suite));
}

export function merkleProof(leaves: unknown[], index: number, suite: HashSuite = DEFAULT_HASH_SUITE): InclusionProof {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError('merkleProof: index out of range');
  }
  const path: ProofStep[] = [];
  prove(leaves.map((l) => leafHashSuite(l, suite)), index, path, suite);
  const proof: InclusionProof = { index, size: leaves.length, path };
  // Self-describing ONLY when non-default, so every sha256 proof stays byte-identical (absence => sha256).
  if (suite !== DEFAULT_HASH_SUITE) proof.hash_suite = suite;
  return proof;
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
    // Resolve the SELF-DESCRIBING hash suite fail-closed: absent => sha256 (back-compat); a present-but-
    // unknown value is rejected (never silently downgraded). The suite fixes the sibling byte length, so a
    // sha384 proof's 48-byte siblings can never satisfy a sha256 reading (32) and vice versa — cross-suite
    // proofs therefore fail here without any special-casing.
    const rawSuite: unknown = (proof as { hash_suite?: unknown }).hash_suite;
    if (rawSuite !== undefined && !isHashSuite(rawSuite)) return false;
    const suite: HashSuite = rawSuite === undefined ? DEFAULT_HASH_SUITE : rawSuite;
    const sibLen = HASH_LEN[suite];
    // Bind index+size: the path SHAPE (length and each sibling side) is fully determined by them.
    if (!Number.isSafeInteger(proof.index) || !Number.isSafeInteger(proof.size)) return false;
    if (proof.size < 1 || proof.index < 0 || proof.index >= proof.size) return false;
    const shape = pathShape(proof.index, proof.size);
    if (shape.length !== proof.path.length) return false;
    let h = leafHashSuite(leaf, suite);
    for (let i = 0; i < proof.path.length; i++) {
      const step = proof.path[i]!;
      if (step.side !== shape[i]) return false;
      const sib = decodeB64uStrict(step.hash, sibLen); // canonical base64url, exactly `sibLen` bytes
      if (!sib) return false;
      h = step.side === 'L' ? nodeHash(sib, h, suite) : nodeHash(h, sib, suite);
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
