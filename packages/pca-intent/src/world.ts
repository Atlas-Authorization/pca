import { compareUtf8, type Condition } from '@atlasauth/pca';
import { OTHER, type CatDim, type Dim, type NumDim, type NumDist, type Omega, type Outcome } from './omega';

/**
 * Ω̃ DIMENSIONS FILLED BY THE VERIFIER (Intent Layer v2 §2.6-2.8; milestones V6, V7, V8).
 *
 * The core verifier (`@atlasauth/pca` `decideIntentWB`, conformance rules 16-18) computes three `env` subtrees that
 * grant predicates read like any other path:
 *   env.world.<name>        world facts (median of signed oracle facts), relational values, the offer-set `excess`;
 *   env.prov.<param path>   the server-classified provenance of a material / critical parameter;
 *   env.class.<id>          the k-of-n label of an attested classifier.
 * Here they become ordinary dimensions of Ω̃ (v1 §2.1 numeric / categorical), so cells, questions, R̂ and the grant
 * synthesiser treat them exactly as action parameters. Every helper only ADDS a dimension, which REFINES Ω̃ (each
 * old cell is a union of new ones, T26).
 */

export const WORLD_PREFIX = 'env.world.';
export const PROV_PREFIX = 'env.prov.';
export const CLASS_PREFIX = 'env.class.';

/** A numeric world dimension `env.world.<name>` with the given domain and cuts. */
export function worldDim(name: string, o: { lo: number; hi: number; cuts?: number[]; dist?: NumDist }): NumDim {
  const cuts = [...new Set(o.cuts ?? [])].filter((c) => c >= o.lo && c <= o.hi).sort((a, b) => a - b);
  return { kind: 'num', path: WORLD_PREFIX + name, lo: o.lo, hi: o.hi, cuts, dist: o.dist ?? 'uniform' };
}

/**
 * The optimality dimension `excess` (§2.6): excess >= 0 by rule 16 (the chosen offer satisfies the filter, so the
 * minimum is at most its price). Cuts at 0 and at every slack literal: cells {0}, then the ranges between slacks.
 */
export function excessDim(name: string, hi: number, slacks: number[] = []): NumDim {
  return worldDim(name, { lo: 0, hi, cuts: [0, ...slacks], dist: 'loguniform' });
}

/**
 * The default slot compiler's optimality constraint (§3.13 item 2): `excess <= slack` (slack 0 = "the cheapest
 * matching offer"). A pricier choice is then a lazy question, not a silent choice.
 */
export function optimalityCondition(name: string, slack = 0): Condition {
  return { field: WORLD_PREFIX + name, op: 'lte', value: slack };
}

/**
 * The provenance dimension of a material or critical parameter: `env.prov.<path>` with the cells {first_party},
 * {trusted} and ⊥ = {tool, web, agent} (the TAINTED values). A "yes" given when the value came from the principal
 * does not cover the same value arriving from page content (T26).
 */
export function provenanceDim(paramPath: string): CatDim {
  return {
    kind: 'cat',
    path: PROV_PREFIX + paramPath,
    values: [
      { kind: 'exact', value: 'first_party' },
      { kind: 'exact', value: 'trusted' },
      { kind: 'other', value: OTHER },
    ],
  };
}

/** The classifier dimension `env.class.<id>` over the classifier's closed label set (⊥ is never output, rule 18). */
export function classifierDim(id: string, labels: readonly string[]): CatDim {
  return {
    kind: 'cat',
    path: CLASS_PREFIX + id,
    values: [...[...new Set(labels)].sort(compareUtf8).map((value) => ({ kind: 'exact' as const, value })), { kind: 'other' as const, value: OTHER }],
  };
}

/** A copy of Ω̃ with `dims` added to `verb` (dimensions kept sorted by path, as `deriveOmega` does). */
export function withDims(omega: Omega, verb: string, dims: readonly Dim[]): Omega {
  const verbs = omega.verbs.map((vs) => {
    if (vs.verb !== verb) return { ...vs, dims: [...vs.dims] };
    const have = new Set(vs.dims.map((d) => d.path));
    for (const d of dims) if (have.has(d.path)) throw new Error(`withDims: ${verb} already has a dimension ${d.path}`);
    return { ...vs, dims: [...vs.dims, ...dims].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) };
  });
  if (!verbs.some((v) => v.verb === verb)) throw new Error(`withDims: no verb ${verb} in Ω`);
  return { ...omega, verbs };
}

function get(root: unknown, segs: readonly string[]): unknown {
  let cur = root;
  for (const s of segs) {
    if (cur === null || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, s)) return undefined;
    cur = (cur as Record<string, unknown>)[s];
  }
  return cur;
}

/**
 * Lift a concrete outcome with the verifier-computed `env` (`decideIntentWB(...).env`): fill every `env.world.*`,
 * `env.prov.*` and `env.class.*` dimension path of `dimPaths` from it. A provenance dimension with no computed
 * label is `agent` (fail closed: it falls in ⊥, the tainted cell).
 */
export function liftOutcome(o: Outcome, env: { world?: Record<string, unknown>; prov?: Record<string, unknown>; class?: Record<string, unknown> }, dimPaths: readonly string[]): Outcome {
  const values = { ...o.values };
  for (const p of dimPaths) {
    if (p.startsWith(WORLD_PREFIX)) {
      const v = get(env.world, [p.slice(WORLD_PREFIX.length)]);
      if (typeof v === 'number' || typeof v === 'string') values[p] = v;
    } else if (p.startsWith(PROV_PREFIX)) {
      const v = get(env.prov, p.slice(PROV_PREFIX.length).split('.'));
      values[p] = typeof v === 'string' ? v : 'agent';
    } else if (p.startsWith(CLASS_PREFIX)) {
      const v = get(env.class, [p.slice(CLASS_PREFIX.length)]);
      if (typeof v === 'string') values[p] = v;
    }
  }
  return { verb: o.verb, values };
}
