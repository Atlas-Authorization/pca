import type { Predicate } from '@atlasauth/pca';
import type { BridgeResult, TranslationReport } from './types';

/**
 * OpenFGA / Zanzibar ReBAC model + tuples → PCA predicate translator.
 *
 * The relation check "user U has relation R on object O" becomes a PCA permit:
 *   { verb: R, resource: O, where: [{ field: 'subject.id', op: 'eq', value: U }] }
 * so admitting verb R on resource O requires the acting subject to be exactly U. The translator
 * evaluates the model against the supplied tuples and emits one permit per (user, object, relation)
 * triple that HOLDS. Default deny: triples that don't hold emit nothing.
 *
 * SUPPORTED REWRITES (documented boundary)
 * ----------------------------------------
 *   - `this` ({})                direct relationship tuples
 *   - `computedUserset`          "this relation is also granted by relation R on the same object"
 *   - `union`                    OR of children (nested unions flattened)
 *   - `intersection`             AND of children (→ an `all_of` of the per-child checks)
 *   - `difference`               base AND NOT subtract (→ a `not` on the subtract check)
 *   - `tupleToUserset`           userset rewrite "from" a related object (e.g. "viewer from parent"):
 *                                follows the `tupleset` relation to each related object and checks the
 *                                `computedUserset` relation there, as a BOUNDED, CYCLE-GUARDED closure
 *
 * All rewrites are resolved against the supplied tuple set at translation time (the whole tuple set is
 * in hand), so intersection/difference/tupleToUserset produce exact concrete permits. Resolution is
 * bounded by a maximum recursion depth and a per-(object, relation) visited set (so a cyclic model —
 * e.g. mutually-referential parents — terminates and fails closed on the cycle).
 *
 * NOT MODELED (reported; fails closed — the relation grants nothing):
 *   - userset-valued tuples (a tuple whose `user` is itself a userset, like "group:eng#member"):
 *     expanding these to concrete users needs group-membership resolution of the userset, which the
 *     concrete-user enumeration does not perform. Such tuples are reported and not expanded. (This is
 *     the real remaining boundary: everything structural in the model is now resolved.)
 */
export function openfgaToPca(model: unknown, tuples: unknown): BridgeResult {
  const report: TranslationReport = { source: 'openfga', translated: [], skipped: [], errors: [] };
  const predicates: Predicate[] = [];

  const typeRelations = parseModel(model, report);
  const tupleList = parseTuples(tuples, report);
  if (typeRelations === null) return { predicates, denies: [], caveats: [], report };

  // Index direct tuples: `${object}\u0000${relation}` -> Set<user>. Userset-valued users are noted.
  const direct = new Map<string, Set<string>>();
  const usersSeen = new Set<string>();
  const objectsSeen = new Set<string>();
  let usersetTuples = 0;
  for (const t of tupleList) {
    objectsSeen.add(t.object);
    const key = `${t.object}\u0000${t.relation}`;
    let set = direct.get(key);
    if (!set) {
      set = new Set<string>();
      direct.set(key, set);
    }
    set.add(t.user);
    if (t.user.includes('#')) usersetTuples++;
    else usersSeen.add(t.user);
  }
  if (usersetTuples > 0) {
    report.skipped.push(`${usersetTuples} userset-valued tuple(s) (user contains '#') not expanded to concrete users`);
  }

  // Build a resolution plan per (type, relation); report unsupported ones.
  const plans = new Map<string, Plan>();
  for (const [type, relations] of typeRelations) {
    for (const [relation, node] of relations) {
      const built = buildPlan(node);
      const key = `${type}\u0000${relation}`;
      if (!built.ok || built.plan === undefined) {
        report.skipped.push(`relation ${type}#${relation}: ${built.reason ?? 'unsupported rewrite'} — skipped`);
        continue;
      }
      if (built.partial) {
        report.skipped.push(`relation ${type}#${relation}: some union children unsupported and dropped (under-approximated)`);
      }
      plans.set(key, built.plan);
      report.translated.push(`relation ${type}#${relation} (${describePlan(built.plan)})`);
    }
  }

  const typeOf = (object: string): string => {
    const i = object.indexOf(':');
    return i < 0 ? object : object.slice(0, i);
  };
  const objectOfUserset = (p: string): string => {
    const i = p.indexOf('#');
    return i < 0 ? p : p.slice(0, i);
  };

  const MAX_DEPTH = 32;

  const holdsRel = (user: string, object: string, relation: string, depth: number, visited: Set<string>): boolean => {
    const key = `${object}\u0000${relation}`;
    if (depth > MAX_DEPTH || visited.has(key)) return false;
    const plan = plans.get(`${typeOf(object)}\u0000${relation}`);
    if (plan === undefined) return false;
    const next = new Set(visited);
    next.add(key);
    return evalPlan(user, object, relation, plan, depth, next);
  };

  const evalPlan = (
    user: string,
    object: string,
    relation: string,
    plan: Plan,
    depth: number,
    visited: Set<string>,
  ): boolean => {
    switch (plan.kind) {
      case 'direct':
        return direct.get(`${object}\u0000${relation}`)?.has(user) ?? false;
      case 'computed':
        return holdsRel(user, object, plan.relation, depth + 1, visited);
      case 'union':
        return plan.children.some((c) => evalPlan(user, object, relation, c, depth, visited));
      case 'intersection':
        return plan.children.every((c) => evalPlan(user, object, relation, c, depth, visited));
      case 'difference':
        return (
          evalPlan(user, object, relation, plan.base, depth, visited) &&
          !evalPlan(user, object, relation, plan.subtract, depth, visited)
        );
      case 'ttu': {
        const related = direct.get(`${object}\u0000${plan.tupleset}`);
        if (!related) return false;
        for (const p of related) {
          if (holdsRel(user, objectOfUserset(p), plan.computed, depth + 1, visited)) return true;
        }
        return false;
      }
    }
  };

  // Enumerate every (user, object, relation-defined-on-that-object's-type) triple that holds.
  const sortedUsers = [...usersSeen].sort();
  const sortedObjects = [...objectsSeen].sort();
  for (const object of sortedObjects) {
    const type = typeOf(object);
    const relations = typeRelations.get(type);
    if (!relations) {
      report.skipped.push(`object ${object}: type "${type}" not defined in model — ignored`);
      continue;
    }
    for (const relation of [...relations.keys()].sort()) {
      if (!plans.has(`${type}\u0000${relation}`)) continue; // unsupported relation
      for (const user of sortedUsers) {
        if (holdsRel(user, object, relation, 0, new Set())) {
          predicates.push({ verb: relation, resource: object, where: [{ field: 'subject.id', op: 'eq', value: user }] });
        }
      }
    }
  }

  return { predicates, denies: [], caveats: [], report };
}

// --- resolution plan ---------------------------------------------------------------------------

type Plan =
  | { kind: 'direct' }
  | { kind: 'computed'; relation: string }
  | { kind: 'union'; children: Plan[] }
  | { kind: 'intersection'; children: Plan[] }
  | { kind: 'difference'; base: Plan; subtract: Plan }
  | { kind: 'ttu'; tupleset: string; computed: string };

interface BuildResult {
  ok: boolean;
  plan?: Plan;
  partial: boolean;
  reason?: string;
}

function describePlan(plan: Plan): string {
  switch (plan.kind) {
    case 'direct':
      return 'direct';
    case 'computed':
      return `computed ${plan.relation}`;
    case 'union':
      return `union[${plan.children.map(describePlan).join(', ')}]`;
    case 'intersection':
      return `intersection[${plan.children.map(describePlan).join(', ')}]`;
    case 'difference':
      return `difference(${describePlan(plan.base)} - ${describePlan(plan.subtract)})`;
    case 'ttu':
      return `${plan.computed} from ${plan.tupleset}`;
  }
}

function childNodes(container: unknown): unknown[] | null {
  if (container === null || typeof container !== 'object') return null;
  const child = (container as { child?: unknown }).child;
  return Array.isArray(child) ? child : null;
}

/** Build a resolution plan from a userset-rewrite node. */
function buildPlan(node: Rewrite): BuildResult {
  if (hasOwn(node, 'this')) return { ok: true, plan: { kind: 'direct' }, partial: false };

  if (hasOwn(node, 'computedUserset')) {
    const cu = node.computedUserset;
    const rel = cu && typeof cu === 'object' ? (cu as { relation?: unknown }).relation : undefined;
    if (typeof rel !== 'string' || rel.length === 0) {
      return { ok: false, partial: false, reason: 'computedUserset without a relation' };
    }
    return { ok: true, plan: { kind: 'computed', relation: rel }, partial: false };
  }

  if (hasOwn(node, 'union')) {
    const children = childNodes(node.union);
    if (children === null) return { ok: false, partial: false, reason: 'union without children' };
    const subs: Plan[] = [];
    let partial = false;
    for (const child of children) {
      if (!isRewrite(child)) {
        partial = true;
        continue;
      }
      const sub = buildPlan(child);
      if (!sub.ok || sub.plan === undefined) {
        partial = true; // OR under-approximates safely: drop the unmodeled child
        continue;
      }
      if (sub.partial) partial = true;
      subs.push(sub.plan);
    }
    if (subs.length === 0) return { ok: false, partial, reason: 'union with no modeled children' };
    return { ok: true, plan: { kind: 'union', children: subs }, partial };
  }

  if (hasOwn(node, 'intersection')) {
    const children = childNodes(node.intersection);
    if (children === null) return { ok: false, partial: false, reason: 'intersection without children' };
    const subs: Plan[] = [];
    for (const child of children) {
      // An AND cannot drop a child without OVER-granting: every conjunct must be modeled.
      if (!isRewrite(child)) return { ok: false, partial: false, reason: 'intersection child is not a rewrite' };
      const sub = buildPlan(child);
      if (!sub.ok || sub.plan === undefined) {
        return { ok: false, partial: false, reason: `intersection child unmodeled (${sub.reason ?? 'unsupported'})` };
      }
      subs.push(sub.plan);
    }
    if (subs.length === 0) return { ok: false, partial: false, reason: 'intersection with no children' };
    return { ok: true, plan: { kind: 'intersection', children: subs }, partial: false };
  }

  if (hasOwn(node, 'difference')) {
    const diff = node.difference;
    if (diff === null || typeof diff !== 'object') return { ok: false, partial: false, reason: 'malformed difference' };
    const baseNode = (diff as { base?: unknown }).base;
    const subNode = (diff as { subtract?: unknown }).subtract;
    if (!isRewrite(baseNode) || !isRewrite(subNode)) {
      return { ok: false, partial: false, reason: 'difference needs both base and subtract' };
    }
    const base = buildPlan(baseNode);
    const subtract = buildPlan(subNode);
    // Both halves must be modeled: dropping `base` or `subtract` would change the result unsafely.
    if (!base.ok || base.plan === undefined) return { ok: false, partial: false, reason: `difference base unmodeled (${base.reason ?? '?'})` };
    if (!subtract.ok || subtract.plan === undefined) return { ok: false, partial: false, reason: `difference subtract unmodeled (${subtract.reason ?? '?'})` };
    return { ok: true, plan: { kind: 'difference', base: base.plan, subtract: subtract.plan }, partial: base.partial || subtract.partial };
  }

  if (hasOwn(node, 'tupleToUserset')) {
    const ttu = node.tupleToUserset;
    if (ttu === null || typeof ttu !== 'object') return { ok: false, partial: false, reason: 'malformed tupleToUserset' };
    const tuplesetRel = relationOf((ttu as { tupleset?: unknown }).tupleset);
    const computedRel = relationOf((ttu as { computedUserset?: unknown }).computedUserset);
    if (tuplesetRel === null) return { ok: false, partial: false, reason: 'tupleToUserset without a tupleset relation' };
    if (computedRel === null) return { ok: false, partial: false, reason: 'tupleToUserset without a computedUserset relation' };
    return { ok: true, plan: { kind: 'ttu', tupleset: tuplesetRel, computed: computedRel }, partial: false };
  }

  return { ok: false, partial: false, reason: 'unknown rewrite node' };
}

/** The `.relation` string of a `{ relation }` object, or null. */
function relationOf(v: unknown): string | null {
  if (v === null || typeof v !== 'object') return null;
  const rel = (v as { relation?: unknown }).relation;
  return typeof rel === 'string' && rel.length > 0 ? rel : null;
}

// --- model / tuple parsing ---------------------------------------------------------------------

interface Rewrite {
  this?: unknown;
  computedUserset?: unknown;
  union?: unknown;
  intersection?: unknown;
  difference?: unknown;
  tupleToUserset?: unknown;
}
interface Tuple {
  user: string;
  relation: string;
  object: string;
}

function hasOwn<K extends string>(o: object, k: K): o is Record<K, unknown> {
  return Object.prototype.hasOwnProperty.call(o, k);
}
function isRewrite(v: unknown): v is Rewrite {
  return v !== null && typeof v === 'object';
}

/** Parse the authorization model into type -> (relation -> rewrite node). Null if unusable. */
function parseModel(model: unknown, report: TranslationReport): Map<string, Map<string, Rewrite>> | null {
  if (model === null || typeof model !== 'object') {
    report.errors.push('model is not an object');
    return null;
  }
  const defs = (model as { type_definitions?: unknown }).type_definitions;
  if (!Array.isArray(defs)) {
    report.errors.push('model.type_definitions is missing or not an array');
    return null;
  }
  const out = new Map<string, Map<string, Rewrite>>();
  for (const def of defs) {
    if (def === null || typeof def !== 'object') continue;
    const type = (def as { type?: unknown }).type;
    if (typeof type !== 'string' || type.length === 0) continue;
    const rels = (def as { relations?: unknown }).relations;
    const relMap = new Map<string, Rewrite>();
    if (rels !== null && typeof rels === 'object') {
      for (const [name, node] of Object.entries(rels as Record<string, unknown>)) {
        if (isRewrite(node)) relMap.set(name, node);
      }
    }
    out.set(type, relMap);
  }
  return out;
}

function parseTuples(tuples: unknown, report: TranslationReport): Tuple[] {
  if (!Array.isArray(tuples)) {
    if (tuples !== undefined) report.errors.push('tuples is not an array');
    return [];
  }
  const out: Tuple[] = [];
  for (const t of tuples) {
    if (t === null || typeof t !== 'object') continue;
    const user = (t as { user?: unknown }).user;
    const relation = (t as { relation?: unknown }).relation;
    const object = (t as { object?: unknown }).object;
    if (typeof user === 'string' && typeof relation === 'string' && typeof object === 'string') {
      out.push({ user, relation, object });
    }
  }
  return out;
}
