import { isObject, isPosInt, isString } from './wire';

/**
 * Access structure over attributes — a MONOTONE boolean formula expressed as a threshold tree.
 *
 *   - `{ attr }`                         leaf: the holder must own the decryption key for this attribute.
 *   - `{ allOf: [...] }`                 AND  (n-of-n): every child subtree must be satisfied.
 *   - `{ anyOf: [...] }`                 OR   (1-of-n): at least one child subtree.
 *   - `{ threshold: k, of: [...] }`      k-of-n: at least k of the n child subtrees.
 *
 * Trees nest arbitrarily, so any monotone access structure (any AND/OR/threshold combination of
 * attributes) is expressible. Negation is intentionally NOT supported: ABE access structures are
 * monotone (you cannot grant decryption by LACKING an attribute).
 */
export type Policy =
  | { attr: string }
  | { allOf: Policy[] }
  | { anyOf: Policy[] }
  | { threshold: number; of: Policy[] };

/** Normalised internal form: every interior node is an explicit `t`-of-`n` threshold gate. */
export type ThresholdTree = { kind: 'leaf'; attr: string } | { kind: 'gate'; t: number; of: ThresholdTree[] };

export interface PolicyError {
  ok: false;
  reason: string;
}
export interface PolicyOk {
  ok: true;
  tree: ThresholdTree;
}
export type PolicyResult = PolicyOk | PolicyError;

/** Upper bound on total nodes in a policy tree (bounds work on untrusted input). */
export const MAX_POLICY_NODES = 1024;

/**
 * Validate and normalise an access structure into a threshold tree. Fails closed (returns a reason)
 * on any malformed node, empty gate, out-of-range threshold, or oversized tree.
 */
export function normalizePolicy(policy: unknown): PolicyResult {
  let nodes = 0;
  function walk(p: unknown, path: string): ThresholdTree | PolicyError {
    if (++nodes > MAX_POLICY_NODES) return { ok: false, reason: `policy too large (> ${MAX_POLICY_NODES} nodes)` };
    if (!isObject(p)) return { ok: false, reason: `${path}: not an object` };

    if ('attr' in p) {
      if (!isString(p.attr) || p.attr.length === 0) return { ok: false, reason: `${path}: 'attr' must be a non-empty string` };
      if ('allOf' in p || 'anyOf' in p || 'threshold' in p || 'of' in p) {
        return { ok: false, reason: `${path}: a leaf must not mix 'attr' with a gate` };
      }
      return { kind: 'leaf', attr: p.attr };
    }

    const parseChildren = (raw: unknown, key: string): ThresholdTree[] | PolicyError => {
      if (!Array.isArray(raw) || raw.length === 0) return { ok: false, reason: `${path}: '${key}' must be a non-empty array` };
      const out: ThresholdTree[] = [];
      for (let i = 0; i < raw.length; i++) {
        const child = walk(raw[i], `${path}.${key}[${i}]`);
        if ('ok' in child) return child;
        out.push(child);
      }
      return out;
    };

    if ('allOf' in p) {
      const kids = parseChildren(p.allOf, 'allOf');
      if ('ok' in kids) return kids;
      return { kind: 'gate', t: kids.length, of: kids };
    }
    if ('anyOf' in p) {
      const kids = parseChildren(p.anyOf, 'anyOf');
      if ('ok' in kids) return kids;
      return { kind: 'gate', t: 1, of: kids };
    }
    if ('threshold' in p) {
      if (!isPosInt(p.threshold)) return { ok: false, reason: `${path}: 'threshold' must be a positive integer` };
      const kids = parseChildren(p.of, 'of');
      if ('ok' in kids) return kids;
      if (p.threshold > kids.length) {
        return { ok: false, reason: `${path}: threshold ${p.threshold} exceeds the number of branches (${kids.length})` };
      }
      return { kind: 'gate', t: p.threshold, of: kids };
    }
    return { ok: false, reason: `${path}: unknown policy node (expected attr/allOf/anyOf/threshold)` };
  }

  const tree = walk(policy, 'policy');
  if ('ok' in tree) return tree;
  return { ok: true, tree };
}

/**
 * Pure, non-cryptographic satisfaction check: does the attribute SET satisfy the access structure?
 * This is a convenience / test oracle. The real enforcement is cryptographic (a key lacking an
 * attribute cannot recover that leaf's share); this just predicts the outcome.
 */
export function satisfies(tree: ThresholdTree, attrs: ReadonlySet<string>): boolean {
  if (tree.kind === 'leaf') return attrs.has(tree.attr);
  let met = 0;
  for (const child of tree.of) if (satisfies(child, attrs)) met++;
  return met >= tree.t;
}

/** Collect every attribute referenced anywhere in the tree (for diagnostics / key provisioning). */
export function policyAttributes(tree: ThresholdTree, into: Set<string> = new Set()): Set<string> {
  if (tree.kind === 'leaf') into.add(tree.attr);
  else for (const child of tree.of) policyAttributes(child, into);
  return into;
}
