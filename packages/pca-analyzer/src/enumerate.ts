import { evaluatePredicates, isGroupCondition, isLeafCondition } from '@atlasauth/pca';
import type { ActionContext, Caveat, Condition, LeafCondition, Predicate } from '@atlasauth/pca';
import { analyzeCaveats } from './caveats';
import { fieldProbes } from './field';
import { REVERSIBILITY_ORDER } from './types';
import type { AnalyzerAction, PolicyInput } from './types';

/**
 * The bounded decision engine. It builds a finite set of representative actions ("the grid") from the
 * literals, thresholds, prefixes, verbs and resource matchers that appear in the policies (and, for
 * intent conformance, the intent). Because PCA's `where` theory is a boolean combination of
 * threshold/membership/prefix tests, each policy's admitted region is a union of grid cells, so one
 * representative per cell is DISTINGUISHING: any two policies that differ on some action also differ on
 * some representative. Evaluating the REAL `evaluatePredicates` at each representative (plus the static
 * caveat gate) therefore decides reachability, subsumption, disjointness and equivalence EXACTLY for
 * the decided fragment, and yields a concrete counterexample whenever a relation fails.
 *
 * Out-of-fragment features (`re:` regex resources, cross-field `ref` conditions) and grids larger than
 * the bound are detected and reported as `approximate`, and every verdict then fails safe.
 */

const ABSENT: unique symbol = Symbol('analyzer-absent-field');
type Cell = unknown;

const FRESH_VERB = '\u0000atlas-analyzer::fresh-verb\u0000';
const FRESH_RESOURCE = '\u0000atlas-analyzer::fresh-resource\u0000';

/** Default cap on the representative grid size (product of all dimensions). */
export const DEFAULT_MAX_COMBINATIONS = 200_000;

export interface PolicyModel {
  predicates: Predicate[];
  caveats: Caveat[];
  caveatSat: boolean;
  caveatReason?: string;
  /** Strictest `reversibility_max` cap (index into REVERSIBILITY_ORDER), if any. */
  revCap?: number;
  /** Non-empty when the policy uses features the analyzer cannot decide exactly. */
  undecidable: string[];
}

export function normalizePolicy(p: PolicyInput): { predicates: Predicate[]; caveats: Caveat[] } {
  const predicates = Array.isArray(p.predicates) ? p.predicates : [];
  const caveats = 'caveats' in p && Array.isArray(p.caveats) ? p.caveats : [];
  return { predicates, caveats };
}

/**
 * Collect over-approximation reasons from one condition tree. Boolean groupings (all_of/any_of/not)
 * are DECIDED EXACTLY as long as every leaf uses a decidable op — the admitted region stays a boolean
 * combination of the same per-field cells, so the representative grid remains distinguishing — so the
 * grouping itself is not undecidable; only its hard leaves are. The genuinely-hard leaf ops
 * (`like`/`matches`/`is_a`/`member_of`), a cross-field `ref`, and a whole-`action.params` condition
 * force a conservative over-approximation (verdict fails safe).
 */
function conditionUndecidable(c: Condition, reasons: Set<string>): void {
  if (c === null || typeof c !== 'object') return;
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of)) for (const x of c.all_of) conditionUndecidable(x, reasons);
    else if ('any_of' in c && Array.isArray(c.any_of)) for (const x of c.any_of) conditionUndecidable(x, reasons);
    else if ('not' in c) conditionUndecidable(c.not, reasons);
    return;
  }
  if (!isLeafCondition(c)) return;
  if (c.ref !== undefined) {
    reasons.add('cross-field `ref` condition — the relation between two fields is not resolved');
  }
  if (c.field === 'action.params') {
    reasons.add('condition on the whole `action.params` object is not enumerated precisely');
  }
  if (c.op === 'like' || c.op === 'matches' || c.op === 'is_a' || c.op === 'member_of') {
    reasons.add(`\`${c.op}\` condition — matched by over-approximation, not enumerated exactly`);
  }
}

function detectUndecidable(predicates: readonly Predicate[]): string[] {
  const reasons = new Set<string>();
  for (const p of predicates) {
    if (p === null || typeof p !== 'object') continue;
    const r = p.resource;
    if (typeof r === 'string' && r.startsWith('re:')) {
      reasons.add('re: regex resource matcher — resource dimension cannot be soundly enumerated');
    }
    if (Array.isArray(p.where)) for (const c of p.where) conditionUndecidable(c, reasons);
  }
  return [...reasons];
}

export function toModel(p: PolicyInput): PolicyModel {
  const { predicates, caveats } = normalizePolicy(p);
  const ca = analyzeCaveats(caveats);
  return {
    predicates,
    caveats,
    caveatSat: ca.sat,
    caveatReason: ca.reason,
    revCap: ca.revCap,
    undecidable: detectUndecidable(predicates),
  };
}

// ---- probe collection -----------------------------------------------------------------------------

export interface Probes {
  verbs: string[];
  resources: string[];
  /** `undefined` means "no reversibility dimension" (no policy sets a `reversibility_max`). */
  revClasses: (string | undefined)[];
  fields: { path: string; values: Cell[] }[];
}

export interface ProbeInputs {
  predicateSets: Predicate[][];
  extraVerbs?: string[];
  extraResources?: string[];
  extraFieldConditions?: { path: string; cond: Condition }[];
  /** Vary the reversibility class over all three classes (needed when any policy caps reversibility). */
  varyReversibility: boolean;
}

function addVerbLiterals(c: LeafCondition, into: Set<string>): void {
  const v = c.value;
  if (c.op === 'eq' || c.op === 'ne' || c.op === 'prefix' || c.op === 'like' || c.op === 'is_a') {
    if (typeof v === 'string') into.add(v);
  } else if ((c.op === 'in' || c.op === 'nin') && Array.isArray(v)) {
    for (const x of v) if (typeof x === 'string') into.add(x);
  }
}

export function collectProbes(inputs: ProbeInputs): Probes {
  const verbLiterals = new Set<string>(inputs.extraVerbs ?? []);
  const resourceLiterals = new Set<string>();
  const fieldConds = new Map<string, LeafCondition[]>();

  const addFieldCond = (path: string, c: LeafCondition): void => {
    const arr = fieldConds.get(path) ?? [];
    arr.push(c);
    fieldConds.set(path, arr);
  };

  const classifyResource = (r: string | undefined): void => {
    if (r === undefined || r === '*') return; // universal: FRESH_RESOURCE represents it
    if (r.startsWith('re:')) return; // undecidable: FRESH_RESOURCE stands in (flagged on the model)
    if (r.endsWith('*')) {
      const body = r.slice(0, -1);
      resourceLiterals.add(body);
      resourceLiterals.add(body + 'x');
      return;
    }
    resourceLiterals.add(r);
  };

  const handleCond = (c: Condition): void => {
    if (c === null || typeof c !== 'object') return;
    // Recurse through boolean groupings and bucket their leaves (keeps the grid distinguishing for
    // nested boolean logic over decidable ops).
    if (isGroupCondition(c)) {
      if ('all_of' in c && Array.isArray(c.all_of)) for (const x of c.all_of) handleCond(x);
      else if ('any_of' in c && Array.isArray(c.any_of)) for (const x of c.any_of) handleCond(x);
      else if ('not' in c) handleCond(c.not);
      return;
    }
    if (!isLeafCondition(c)) return;
    if (c.field === 'action.verb') {
      addVerbLiterals(c, verbLiterals);
      return;
    }
    if (c.field === 'action.resource') {
      if (c.op === 'prefix' && typeof c.value === 'string') classifyResource(c.value + '*');
      else if (typeof c.value === 'string') classifyResource(c.value);
      else if (Array.isArray(c.value)) for (const x of c.value) if (typeof x === 'string') classifyResource(x);
      return;
    }
    addFieldCond(c.field, c);
  };

  for (const list of inputs.predicateSets) {
    for (const p of list) {
      if (p === null || typeof p !== 'object') continue;
      if (typeof p.verb === 'string') {
        if (p.verb !== '*') verbLiterals.add(p.verb);
      } else if (Array.isArray(p.verb)) {
        for (const v of p.verb) if (typeof v === 'string' && v !== '*') verbLiterals.add(v);
      }
      classifyResource(p.resource);
      if (Array.isArray(p.where)) for (const c of p.where) handleCond(c);
    }
  }
  for (const r of inputs.extraResources ?? []) classifyResource(r);
  for (const ec of inputs.extraFieldConditions ?? []) handleCond({ ...ec.cond, field: ec.path });

  const fields = [...fieldConds.entries()].map(([path, conds]) => ({
    path,
    values: [...fieldProbes(conds), ABSENT] as Cell[],
  }));

  return {
    verbs: [...verbLiterals, FRESH_VERB],
    resources: [...resourceLiterals, FRESH_RESOURCE],
    revClasses: inputs.varyReversibility ? [...REVERSIBILITY_ORDER] : [undefined],
    fields,
  };
}

export function productSize(pr: Probes): number {
  let n = pr.verbs.length * pr.resources.length * pr.revClasses.length;
  for (const f of pr.fields) n *= f.values.length;
  return n;
}

// ---- representatives ------------------------------------------------------------------------------

export interface Rep {
  verb: string;
  resource: string;
  revClass: string | undefined;
  /** Field path -> value, excluding absent fields. */
  assignments: ReadonlyMap<string, unknown>;
}

function* enumerateFields(
  fields: Probes['fields'],
  i: number,
  acc: Map<string, unknown>,
): Generator<ReadonlyMap<string, unknown>> {
  if (i >= fields.length) {
    yield new Map(acc);
    return;
  }
  const f = fields[i];
  if (f === undefined) {
    yield new Map(acc);
    return;
  }
  for (const v of f.values) {
    if (v === ABSENT) {
      acc.delete(f.path);
    } else {
      acc.set(f.path, v);
    }
    yield* enumerateFields(fields, i + 1, acc);
  }
  acc.delete(f.path);
}

export function* representatives(pr: Probes): Generator<Rep> {
  for (const verb of pr.verbs) {
    for (const resource of pr.resources) {
      for (const revClass of pr.revClasses) {
        for (const assignments of enumerateFields(pr.fields, 0, new Map())) {
          yield { verb, resource, revClass, assignments };
        }
      }
    }
  }
}

// ---- context building + admission -----------------------------------------------------------------

/** A mutable action with an index signature so arbitrary `action.*` fields can be set soundly. */
interface MutableAction {
  verb: string;
  resource: string;
  params: Record<string, unknown>;
  reversibility_class?: string;
  [key: string]: unknown;
}

/**
 * A field-assignment tree, materialized into plain objects. A node is a leaf (a concrete value) or a
 * branch (named children). Building a tree and then materializing it keeps the whole context
 * construction statically typed — no reading-back of `unknown` object values, so no casts.
 */
type TreeNode = { leaf: true; value: unknown } | { leaf: false; children: Map<string, TreeNode> };

function branch(): TreeNode {
  return { leaf: false, children: new Map() };
}

function insert(root: TreeNode, segs: readonly string[], value: unknown): void {
  let node = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const key = segs[i];
    if (key === undefined || node.leaf) return;
    const next = node.children.get(key);
    if (next === undefined || next.leaf) {
      const created = branch();
      node.children.set(key, created);
      node = created;
    } else {
      node = next;
    }
  }
  const last = segs[segs.length - 1];
  if (last !== undefined && !node.leaf) node.children.set(last, { leaf: true, value });
}

function materialize(node: TreeNode): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (node.leaf) return out;
  for (const [key, child] of node.children) {
    out[key] = child.leaf ? child.value : materialize(child);
  }
  return out;
}

function buildRoots(rep: Rep): { action: MutableAction; subject: Record<string, unknown>; env: Record<string, unknown> } {
  const roots = new Map<string, TreeNode>([
    ['action', branch()],
    ['subject', branch()],
    ['env', branch()],
  ]);
  for (const [path, value] of rep.assignments) {
    const segs = path.split('.');
    const first = segs[0];
    if (first === undefined || segs.length < 2) continue;
    const root = roots.get(first);
    if (root === undefined) continue; // only action / subject / env roots are addressable
    insert(root, segs.slice(1), value);
  }
  const actionTree = roots.get('action');
  const subjectTree = roots.get('subject');
  const envTree = roots.get('env');

  const action: MutableAction = { verb: rep.verb, resource: rep.resource, params: {} };
  if (actionTree !== undefined && !actionTree.leaf) {
    for (const [key, child] of actionTree.children) {
      if (key === 'verb' || key === 'resource') continue; // fixed from the rep
      if (key === 'params') {
        // `action.params.*` branches materialize to a typed record; a whole-`params` leaf is flagged
        // undecidable upstream, so it is safe to ignore here (params stays an empty, present object).
        if (!child.leaf) action.params = materialize(child);
      } else {
        action[key] = child.leaf ? child.value : materialize(child);
      }
    }
  }
  if (rep.revClass !== undefined) action.reversibility_class = rep.revClass;
  const subject = subjectTree === undefined || subjectTree.leaf ? {} : materialize(subjectTree);
  const env = envTree === undefined || envTree.leaf ? {} : materialize(envTree);
  return { action, subject, env };
}

function contextFromRoots(roots: {
  action: MutableAction;
  subject: Record<string, unknown>;
  env: Record<string, unknown>;
}): ActionContext {
  return { action: roots.action, subject: roots.subject, env: roots.env };
}

function reversibilityOk(model: PolicyModel, revClass: string | undefined): boolean {
  if (model.revCap === undefined) return true;
  if (revClass === undefined) return false; // a reversibility_max caveat denies an action with no class
  const idx = (REVERSIBILITY_ORDER as readonly string[]).indexOf(revClass);
  return idx >= 0 && idx <= model.revCap;
}

/** Does the policy admit this representative action? (predicate match AND static caveat gate.) */
export function admits(model: PolicyModel, rep: Rep): boolean {
  if (!model.caveatSat) return false;
  if (!reversibilityOk(model, rep.revClass)) return false;
  const ctx = contextFromRoots(buildRoots(rep));
  return evaluatePredicates(model.predicates, ctx).allowed;
}

/** Concrete admission of a fully-specified action (used by reachable's fast path; exact). */
export function admitsAction(model: PolicyModel, action: AnalyzerAction): boolean {
  if (!model.caveatSat) return false;
  if (!reversibilityOk(model, action.reversibilityClass)) return false;
  const act: MutableAction = { verb: action.verb, resource: action.resource, params: { ...(action.params ?? {}) } };
  if (action.reversibilityClass !== undefined) act.reversibility_class = action.reversibilityClass;
  const ctx: ActionContext = {
    action: act,
    subject: { ...(action.subject ?? {}) },
    env: { ...(action.env ?? {}) },
  };
  return evaluatePredicates(model.predicates, ctx).allowed;
}

export function repToAction(rep: Rep): AnalyzerAction {
  const roots = buildRoots(rep);
  const action: AnalyzerAction = { verb: rep.verb, resource: rep.resource, params: { ...roots.action.params } };
  if (rep.revClass !== undefined) action.reversibilityClass = rep.revClass;
  if (Object.keys(roots.subject).length > 0) action.subject = roots.subject;
  if (Object.keys(roots.env).length > 0) action.env = roots.env;
  return action;
}

// ---- bounded search -------------------------------------------------------------------------------

export interface SearchOutcome {
  /** A representative for which the predicate returned true, if the search stopped on one. */
  hit?: Rep;
  /** The grid exceeded the configured bound; no enumeration was performed. */
  overflow: boolean;
}

/**
 * Walk the representative grid, stopping at the first rep for which `predicate` is true. Returns
 * `overflow: true` (without walking) when the grid is larger than `max`.
 */
export function search(pr: Probes, predicate: (rep: Rep) => boolean, max: number): SearchOutcome {
  if (productSize(pr) > max) return { overflow: true };
  for (const rep of representatives(pr)) {
    if (predicate(rep)) return { hit: rep, overflow: false };
  }
  return { overflow: false };
}
