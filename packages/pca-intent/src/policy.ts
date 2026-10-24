import { admitsAction, toModel, type AnalyzerAction, type PolicyInput, type PolicyModel } from '@atlasauth/pca-analyzer';
import type { Caveat, Predicate } from '@atlasauth/pca';
import type { Omega, Outcome, VerbSpace } from './omega';

/**
 * Policy plumbing: turn an outcome ω into the real evaluator's input and ask the REAL PCA evaluator
 * (`evaluatePredicates` + the static caveat gate, via @atlasauth/pca-analyzer) whether a grant admits it.
 * Nothing in this package re-implements predicate semantics.
 */

export type { PolicyInput };

export function normalizePolicy(p: PolicyInput): { predicates: Predicate[]; caveats: Caveat[] } {
  const predicates = Array.isArray(p?.predicates) ? p.predicates : [];
  const caveats = p && 'caveats' in p && Array.isArray(p.caveats) ? p.caveats : [];
  return { predicates, caveats };
}

/** Default resource string used when Ω has no resource dimension for a verb (the grant does not scope it). */
export const ANY_RESOURCE = 'resource:any';

function setPath(root: Record<string, unknown>, segs: string[], value: unknown): void {
  let cur = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const k = segs[i]!;
    const next = cur[k];
    if (next === null || typeof next !== 'object' || Array.isArray(next)) cur[k] = {};
    cur = cur[k] as Record<string, unknown>;
  }
  cur[segs[segs.length - 1]!] = value;
}

/** ω as the analyzer's concrete action (params / env / subject trees, reversibility from the catalog). */
export function outcomeToAction(vs: VerbSpace, o: Outcome): AnalyzerAction {
  const params: Record<string, unknown> = {};
  const env: Record<string, unknown> = {};
  const subject: Record<string, unknown> = {};
  let resource = ANY_RESOURCE;
  for (const [path, value] of Object.entries(o.values)) {
    const segs = path.split('.');
    if (path === 'action.resource') resource = String(value);
    else if (segs[0] === 'action' && segs[1] === 'params' && segs.length > 2) setPath(params, segs.slice(2), value);
    else if (segs[0] === 'env' && segs.length > 1) setPath(env, segs.slice(1), value);
    else if (segs[0] === 'subject' && segs.length > 1) setPath(subject, segs.slice(1), value);
  }
  const a: AnalyzerAction = { verb: o.verb, resource, params, reversibilityClass: vs.reversibility };
  if (Object.keys(env).length) a.env = env;
  if (Object.keys(subject).length) a.subject = subject;
  return a;
}

/** A compiled admission oracle for one policy (compile once, query many times). */
export interface Admitter {
  admits(vs: VerbSpace, o: Outcome): boolean;
}

export function admitter(policy: PolicyInput): Admitter {
  const model: PolicyModel = toModel(policy);
  return { admits: (vs, o) => admitsAction(model, outcomeToAction(vs, o)) };
}

/** Find the verb space of an outcome. */
export function vsOf(omega: Omega, o: Outcome): VerbSpace | undefined {
  return omega.verbs.find((v) => v.verb === o.verb);
}
