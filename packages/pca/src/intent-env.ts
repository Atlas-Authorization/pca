import { decideClassifierDimensions, classifierCheckActive, type ClassifierPolicy } from './intent-classifier';
import { decideIntentWorld, intentWorldActive, type IntentWorldPolicy } from './oracle-facts';
import { decideParamProvenance, type ProvenancePolicy } from './param-provenance';
import { closedMembers, isPlainObject, ownGet } from './intent-artifacts';

/**
 * The W-B checks of an Intent Layer v2 verifier, composed in the order of spec §5:
 *     … → accumulators → facts → provenance → classes → predicates of the admitting root → jit → …
 * Each check is REPORTED only when its member is present or its policy is active (the v1 rule-12 convention), so a
 * PCActn without v2 members verifies exactly as before. The result's `env` is merged into the predicate context of
 * the admitting root (`env.world`, `env.prov`, `env.class`); the verifier computes all three, the agent never
 * supplies them. This is the integration point for the `intent_session` member (rule 13): pass its `facts`,
 * `offer_set`, `prov`, `classes` and `labels` here, with the artifacts delivered alongside the PCActn.
 */

export type WBCheck = 'pass' | 'question' | 'fail';

export interface IntentWBInput {
  now: number;
  aud: string;
  session: string;
  action: { verb: string; resource: string; params?: Record<string, unknown> };
  /** The signed members of `intent_session` this file consumes. */
  intent_session: { facts?: unknown; offer_set?: unknown; prov?: unknown; classes?: unknown; labels?: unknown };
  /** Artifacts delivered alongside the PCActn (bound by the commitments above). */
  artifacts?: { facts?: unknown[]; offer_set?: unknown; labels?: unknown[]; verdicts?: unknown[] };
  /** Absent = {}; a present non-object (null included) is malformed. */
  policy?: { world?: IntentWorldPolicy; provenance?: ProvenancePolicy; classifiers?: ClassifierPolicy[] };
}

export interface IntentWBResult {
  /** admit: continue with predicates; question: `intent_required` (lazy elicitation); deny: terminal. */
  outcome: 'admit' | 'question' | 'deny';
  checks: { facts?: WBCheck; provenance?: WBCheck; classes?: WBCheck };
  env: { world?: Record<string, number | string>; prov?: Record<string, unknown>; class?: Record<string, string> };
  reason?: string;
  friction?: 'tap' | 'typed';
  /** Worlds decided by a single oracle (§3.6: raise the friction of cells whose admission depends on them). */
  single_source?: string[];
}

/**
 * Is the rule-17 check active? Iff `prov` is present (any value: a malformed one must be refused, not skipped),
 * `labels` is a non-empty ARRAY, or a provenance policy is a plain object. Strict type checks, like rules 16 and 18.
 */
export function intentProvenanceActive(x: { prov?: unknown; labels?: unknown; policy?: unknown }): boolean {
  if (!obj(x)) return false; // total: a non-object input has no members
  return x.prov !== undefined || (Array.isArray(x.labels) && x.labels.length > 0) || (x.policy !== null && typeof x.policy === 'object' && !Array.isArray(x.policy));
}

const obj = (v: unknown): v is Record<string, unknown> => isPlainObject(v);
/** Own member of a plain object, else undefined (a non-object has no members). */
const mem = (o: unknown, k: string): unknown => (obj(o) ? ownGet(o, k) : undefined);

/**
 * Which W-B checks a verifier reports for these members and policies (conformance `primitives.intent_wb_active`).
 * Activity reads members strictly (own members of plain objects; a non-object container has none). It never treats a
 * malformed member as active or inactive by coercion: `decideIntentWB` refuses malformed containers before activity.
 */
export function intentWBActive(input: { intent_session?: unknown; policy?: unknown }): { facts: boolean; provenance: boolean; classes: boolean } {
  const s = mem(input, 'intent_session');
  const p = mem(input, 'policy');
  const committed: Record<string, unknown> = {};
  if (mem(s, 'facts') !== undefined) committed.facts = mem(s, 'facts');
  if (mem(s, 'offer_set') !== undefined) committed.offer_set = mem(s, 'offer_set');
  return {
    facts: intentWorldActive({ committed, policy: mem(p, 'world') }),
    provenance: intentProvenanceActive({ prov: mem(s, 'prov'), labels: mem(s, 'labels'), policy: mem(p, 'provenance') }),
    classes: classifierCheckActive({ committed: mem(s, 'classes'), policy: { classifiers: mem(p, 'classifiers') as ClassifierPolicy[] } }),
  };
}

/**
 * The shape rule for the W-B context (absent vs null): `intent_session` a plain object; `artifacts` absent or a plain
 * object whose `facts` / `labels` / `verdicts` are absent or arrays and whose `offer_set` is absent or a plain object;
 * `policy` absent or a plain object whose `world` / `provenance` are absent or plain objects and whose `classifiers` is
 * absent or an array. JSON `null` anywhere here is malformed, and both objects are CLOSED (an unknown member is malformed).
 * Null = well-formed.
 */
export function intentWBContextError(input: Pick<IntentWBInput, 'intent_session' | 'artifacts' | 'policy'>): string | null {
  if (!obj(input)) return 'input must be an object';
  if (!obj(input.intent_session)) return 'intent_session must be an object';
  const a = input.artifacts;
  if (a !== undefined) {
    if (!obj(a)) return 'artifacts must be an object';
    const am = closedMembers(a, [], ['facts', 'labels', 'verdicts', 'offer_set'], 'artifacts');
    if (am) return am;
    for (const k of ['facts', 'labels', 'verdicts']) if (ownGet(a, k) !== undefined && !Array.isArray(ownGet(a, k))) return `artifacts.${k} must be an array`;
    if (ownGet(a, 'offer_set') !== undefined && !obj(ownGet(a, 'offer_set'))) return 'artifacts.offer_set must be an object';
  }
  const p = input.policy;
  if (p !== undefined) {
    if (!obj(p)) return 'policy must be an object';
    const pm = closedMembers(p, [], ['world', 'provenance', 'classifiers'], 'policy');
    if (pm) return pm;
    for (const k of ['world', 'provenance']) if (ownGet(p, k) !== undefined && !obj(ownGet(p, k))) return `policy.${k} must be an object`;
    if (ownGet(p, 'classifiers') !== undefined && !Array.isArray(ownGet(p, 'classifiers'))) return 'policy.classifiers must be an array';
  }
  return null;
}

/**
 * Run rules 16, 17 and 18 in order; the first failing check denies and later checks are not reported. A malformed W-B
 * context ({@link intentWBContextError}; a non-object input included) fails `facts`, the first check of the unit. Never
 * throws: any internal error is a `facts` failure (fail closed).
 */
export function decideIntentWB(input: IntentWBInput): IntentWBResult {
  try {
    return decideIntentWBInner(input);
  } catch (e) {
    return { outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: `facts: evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

function decideIntentWBInner(input: IntentWBInput): IntentWBResult {
  const out: IntentWBResult = { outcome: 'admit', checks: {}, env: {} };
  const ce = intentWBContextError(input);
  if (ce) return { ...out, outcome: 'deny', checks: { facts: 'fail' }, reason: `facts: the W-B context is malformed: ${ce}` };
  const s = input.intent_session;
  const a: NonNullable<IntentWBInput['artifacts']> = input.artifacts === undefined ? {} : input.artifacts;
  const pol: NonNullable<IntentWBInput['policy']> = input.policy === undefined ? {} : input.policy;
  const committed: Record<string, unknown> = {};
  if (s.facts !== undefined) committed.facts = s.facts;
  if (s.offer_set !== undefined) committed.offer_set = s.offer_set;
  const worldPolicy = pol.world === undefined ? {} : pol.world;
  if (intentWorldActive({ committed, policy: worldPolicy })) {
    const w = decideIntentWorld({
      now: input.now,
      aud: input.aud,
      session: input.session,
      action: input.action,
      committed,
      ...(a.facts !== undefined ? { facts: a.facts } : {}),
      ...(a.offer_set !== undefined ? { offer_set: a.offer_set } : {}),
      policy: worldPolicy,
    });
    if (!w.ok) return { ...out, outcome: 'deny', checks: { facts: 'fail' }, reason: w.reason };
    out.checks.facts = 'pass';
    out.env.world = w.world;
    if (w.single_source.length) out.single_source = w.single_source;
  }
  if (intentProvenanceActive({ prov: s.prov, labels: s.labels, policy: pol.provenance })) {
    const p = decideParamProvenance({
      aud: input.aud,
      session: input.session,
      action: input.action,
      ...(s.prov !== undefined ? { prov: s.prov } : {}),
      ...(s.labels !== undefined ? { committed_labels: s.labels } : {}),
      ...(a.labels !== undefined ? { labels: a.labels } : {}),
      policy: pol.provenance === undefined ? { params: {} } : pol.provenance,
    });
    if (p.outcome === 'deny') return { ...out, outcome: 'deny', checks: { ...out.checks, provenance: 'fail' }, reason: p.reason };
    out.checks.provenance = p.outcome === 'question' ? 'question' : 'pass';
    out.env.prov = p.env;
    if (p.outcome === 'question') {
      out.outcome = 'question';
      out.reason = p.reason;
      out.friction = p.friction;
    }
  }
  const clsPolicy = { classifiers: pol.classifiers === undefined ? [] : pol.classifiers };
  if (classifierCheckActive({ committed: s.classes, policy: clsPolicy })) {
    const c = decideClassifierDimensions({ session: input.session, action: input.action, ...(s.classes !== undefined ? { committed: s.classes } : {}), ...(a.verdicts !== undefined ? { verdicts: a.verdicts } : {}), policy: clsPolicy });
    if (!c.ok) return { ...out, outcome: 'deny', checks: { ...out.checks, classes: 'fail' }, reason: c.reason };
    out.checks.classes = 'pass';
    out.env.class = c.classes;
  }
  return out;
}
