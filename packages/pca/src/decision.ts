import { evaluateConditionTri, type Condition, type Predicate } from './predicates';
import { compareUtf8 } from './hash';
import { isPlainObject } from './intent-strict';
import { MAX_TIGHTEN_RULES, PARAM_PATH_RE, tightenListError, unitTagsError, type TightenRule, type UnitTag } from './envelope-rules';

export { MAX_TIGHTEN_RULES, tightenListError, unitTagsError, type TightenRule, type UnitTag };

/**
 * THE TERNARY DECISION AND THE TIGHTEN-ONLY MODEL RULE (goal-to-decision track T2; security contract C-50..C-55).
 *
 * A decision is `deny < escalate < allow`. `meet` (the minimum) is the only way two decisions combine, so `escalate` is
 * absorbing against `allow` and never becomes `allow` by composition. A PEP admits an action only on `allow`, or on
 * `escalate` that carries a valid principal-signed `EscalationAnswer` bound to (policy digest, action digest, history head)
 * (`escalation.ts`); `escalate` with no answer is a refusal. The model of this file is machine-checked in
 * formal/dafny/VerdictDecision.dfy (the fold over the verifier's checks), formal/dafny/GoalTighten.dfy (G-T9) and
 * formal/dafny/PolicyVmDecision.dfy (Kleene `Unknown` is never `allow`); formal/tla/Escalation.tla checks the answer protocol.
 *
 * RULE 20 (`units`): a policy term that reads a unit-bearing action parameter carries a unit tag, and the tag must equal the
 * unit the signed action schema declares for that parameter. Cents vs dollars, EUR vs USD and exponent mismatches are refused.
 *
 * RULE 21 (`tighten`): MODEL-DERIVED env paths (`env.class.*`, `env.prov.*`, `env.judge.*`, `env.detect.*` (detector receipts), and `env.world.<w>` for a world
 * decided by a single oracle) may appear only in `tighten[]`, never in a grant's `where`. A model (a classifier, a judge, a
 * single oracle) can therefore only move a decision down (escalate or deny), never up. Grants minted before this rule that
 * read such a path are verified under the compatibility mode `model_polarity: 'legacy'` and reported as degraded.
 *
 * Every function here is total and never throws; anything malformed fails closed (a refusal, never an allow).
 */

export type Decision = 'deny' | 'escalate' | 'allow';
export type ModelSignal = 'ok' | 'escalate' | 'deny';

const RANK: Readonly<Record<Decision, number>> = { deny: 0, escalate: 1, allow: 2 };

/** The meet of two decisions: the lower one. Unknown values are `deny` (fail closed). */
export function meet(a: Decision, b: Decision): Decision {
  const x = RANK[a];
  const y = RANK[b];
  if (x === undefined || y === undefined) return 'deny';
  return x <= y ? a : b;
}

/** Meet over a list (`allow` for the empty list, the neutral element). */
export function meetAll(ds: readonly Decision[]): Decision {
  return ds.reduce<Decision>((acc, d) => meet(acc, d), 'allow');
}

/** The highest decision a model signal permits: ok -> allow, escalate -> escalate, deny -> deny; anything else -> deny. */
export function signalCeiling(s: unknown): Decision {
  return s === 'ok' ? 'allow' : s === 'escalate' ? 'escalate' : 'deny';
}

/** G-T9: a model can only tighten. `tighten(d, s) <= d` for every signal `s`; `tighten(d, 'ok') = d`. */
export function tighten(base: Decision, signal: unknown): Decision {
  return meet(base, signalCeiling(signal));
}

/** A failing check is escalate-class iff its reason (after `<check>: `) starts with one of these. */
export const ESCALATE_REASON_PREFIXES: readonly string[] = ['intent_required:', 'escalate:'];

/**
 * The decision of a verifier verdict, from `allow`, the failing checks and the reasons.
 *   allow                                                              -> allow
 *   at least one failing check and EVERY failing check is escalate-class -> escalate
 *   otherwise                                                          -> deny
 * A failing check is escalate-class iff it has at least one reason `<check>: <body>` and every such body starts with an
 * escalate prefix. A failing check with no reason of its own is a hard failure (deny): an unexplained failure never escalates.
 */
export function decisionOf(v: { allow: boolean; checks: Readonly<Record<string, string>>; reasons: readonly string[] }): Decision {
  try {
    if (v.allow === true) return 'allow';
    let failing = 0;
    for (const [name, status] of Object.entries(v.checks)) {
      if (status !== 'fail') continue;
      failing++;
      const head = `${name}: `;
      const own = v.reasons.filter((r) => typeof r === 'string' && r.startsWith(head));
      if (own.length === 0) return 'deny';
      if (!own.every((r) => ESCALATE_REASON_PREFIXES.some((p) => r.slice(head.length).startsWith(p)))) return 'deny';
    }
    return failing > 0 ? 'escalate' : 'deny';
  } catch {
    return 'deny';
  }
}

/**
 * The ordered reason list of a verdict: the core's own reason(s), then one `<check>: <reason>` for EVERY failing check the
 * intent-v2 pipeline reported that is not already listed (the core keeps only its first failure; the v2 checks are the
 * escalate-class ones, so each failed one must be visible to {@link decisionOf}). A failing check without a reason of its
 * own contributes nothing (it is then read as a hard failure, never as an escalation). Duplicates are listed once, in the
 * order first seen. The natives implement exactly this fold (conformance `escalation_fold`).
 */
export function foldV2Reasons(base: readonly string[], v2: readonly { name: string; ok: boolean; reason?: string }[]): string[] {
  const out = [...base];
  for (const c of v2) if (!c.ok && c.reason !== undefined && !out.includes(`${c.name}: ${c.reason}`)) out.push(`${c.name}: ${c.reason}`);
  return out;
}

/**
 * The decision of a PEP given the verifier's decision and an escalation answer. `answered` must be true only when a valid,
 * principal-signed answer bound to this exact (policy, action, history) was verified (`verifyEscalationAnswer`). An answer
 * can only upgrade `escalate`; it never upgrades `deny`.
 */
export function pepDecision(d: Decision, answered: boolean): Decision {
  return d === 'escalate' && answered === true ? 'allow' : d;
}

// ------------------------------------------------------------------------------------------------ rule 21: model polarity

/** `env.<root>` roots whose values come from a model or a classifier (never a signed, deterministic fact). */
export const MODEL_ENV_ROOTS: readonly string[] = ['class', 'prov', 'judge', 'detect'];

/** Is `path` a model-derived env path? `singleSource` names the worlds decided by ONE oracle (`env.world.<name>`). */
export function isModelDerivedPath(path: unknown, singleSource: readonly string[] = []): boolean {
  if (typeof path !== 'string') return false;
  const seg = path.split('.');
  if (seg[0] !== 'env' || seg.length < 2) return false;
  if (MODEL_ENV_ROOTS.includes(seg[1]!)) return true;
  if (seg[1] === 'world') return seg.length === 2 ? singleSource.length > 0 : singleSource.includes(seg[2]!);
  return false;
}

function collectPaths(c: unknown, out: Set<string>, depth: number): void {
  if (depth > 64 || c === null || typeof c !== 'object') return;
  const o = c as Record<string, unknown>;
  for (const k of ['all_of', 'any_of'] as const) if (Array.isArray(o[k])) for (const x of o[k] as unknown[]) collectPaths(x, out, depth + 1);
  if (o.not !== undefined) collectPaths(o.not, out, depth + 1);
  for (const k of ['field', 'ref', 'collection'] as const) if (typeof o[k] === 'string') out.add(o[k] as string);
}

/**
 * Every model-derived env path a list of predicate lists reads (`field`, `ref` or `collection` of any nested condition),
 * sorted by UTF-8 byte order and de-duplicated. A non-array / malformed list contributes nothing here (the verifier
 * refuses the grant elsewhere); an exotic condition cannot hide a path because the walk reads every own member.
 */
export function modelPathsRead(predicateLists: readonly unknown[], singleSource: readonly string[] = []): string[] {
  const found = new Set<string>();
  for (const list of predicateLists) {
    if (!Array.isArray(list)) continue;
    for (const p of list as Predicate[]) {
      const w = (p as { where?: unknown } | null)?.where;
      if (Array.isArray(w)) for (const c of w) collectPaths(c, found, 0);
    }
  }
  return [...found].filter((p) => isModelDerivedPath(p, singleSource)).sort(compareUtf8);
}

export interface TightenInput {
  /** The predicate lists of every grant-side `where` (envelope, `predicates` caveats of the chain, layers). */
  predicates?: readonly unknown[];
  tighten?: unknown;
  /** `'legacy'`: grants that read model-derived paths are accepted and reported degraded. Anything else but absent is malformed. */
  polarity?: unknown;
  /** Worlds decided by a single oracle (`env.world.<name>` of these is model-derived). */
  single_source?: readonly string[];
  /** The evaluation context for the rules' `when` conditions (action, subject, env). */
  context?: { action?: unknown; subject?: unknown; env?: unknown };
}

export interface TightenResult {
  /** `ok`: no friction added; `escalate` / `deny`: the decision is capped there. */
  outcome: ModelSignal;
  /** Legacy compatibility in effect AND a grant actually reads a model-derived path: report the verdict as degraded. */
  legacy: boolean;
  /** The model-derived paths grants read (always reported, also when legacy lets them through). */
  offending: string[];
  /** Why (a bare refusal text for typing or a deny rule; `escalate: ...` for an escalating rule). Absent on `ok`. */
  reason?: string;
}

/**
 * Rule 21. Typing first: a grant-side `where` that reads a model-derived path is a hard refusal (`deny`) unless the
 * compatibility mode is `legacy`. Then the rules in order: `when` true -> its signal; `when` unknown (a missing or ill-typed
 * model value) -> `escalate`; false -> no effect. The outcome is the meet of all signals. A malformed rule list or polarity
 * is a refusal. Total.
 */
export function decideTighten(input: TightenInput): TightenResult {
  try {
    const single = Array.isArray(input.single_source) ? input.single_source.filter((x): x is string => typeof x === 'string') : [];
    if (input.polarity !== undefined && input.polarity !== 'legacy') return { outcome: 'deny', legacy: false, offending: [], reason: "model_polarity must be 'legacy' when present" };
    const le = tightenListError(input.tighten);
    if (le) return { outcome: 'deny', legacy: false, offending: [], reason: `malformed tighten list: ${le}` };
    const offending = modelPathsRead(Array.isArray(input.predicates) ? input.predicates : [], single);
    const legacy = input.polarity === 'legacy' && offending.length > 0;
    if (offending.length > 0 && !legacy) return { outcome: 'deny', legacy: false, offending, reason: `a grant's where reads model-derived path(s) ${offending.join(', ')}: a model may only tighten (move them into tighten[]) (rule 21)` };
    let out: ModelSignal = 'ok';
    let reason: string | undefined;
    const lower = (s: 'escalate' | 'deny', why: string) => {
      if (RANK[signalCeiling(s)] < RANK[signalCeiling(out)]) {
        out = s;
        reason = why;
      }
    };
    const ctx = (isPlainObject(input.context) ? input.context : {}) as never;
    for (const r of (input.tighten ?? []) as TightenRule[]) {
      const t = evaluateConditionTri(r.when, ctx);
      if (t === 'true') lower(r.signal, `${r.signal === 'deny' ? 'denied by' : 'escalate: asked by'} tighten rule '${r.id}'${r.reason !== undefined ? ` (${r.reason})` : ''}`);
      else if (t === 'unknown') lower('escalate', `escalate: rule '${r.id}' could not be decided (a value it reads is missing or ill-typed)`);
    }
    return { outcome: out, legacy, offending, ...(reason !== undefined ? { reason } : {}) };
  } catch (e) {
    return { outcome: 'deny', legacy: false, offending: [], reason: `evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

// ------------------------------------------------------------------------------------------------ rule 20: units

const tagText = (t: Partial<UnitTag> | undefined): string => (t === undefined ? 'no unit' : `${t.kind ?? '?'}${t.currency !== undefined ? `/${t.currency}` : ''}${t.exponent !== undefined ? `/e${t.exponent}` : ''}`);
const sameTag = (a: Partial<UnitTag>, b: Partial<UnitTag>): boolean => a.kind === b.kind && a.currency === b.currency && a.exponent === b.exponent;

export interface UnitsInput {
  /** The policy's unit tags (`envelope.units`). */
  units?: unknown;
  /** The accepted action schema's `units` table (id -> tag) and the action's verb declaration (`params` path -> {unit?}). */
  schema_units?: unknown;
  verb_params?: unknown;
  /** The verb being decided, and the predicate lists whose terms must carry tags. */
  verb?: unknown;
  predicates?: readonly unknown[];
}

function verbInScope(p: unknown, verb: string): boolean {
  const v = (p as { verb?: unknown } | null)?.verb;
  return v === '*' || v === verb || (Array.isArray(v) && v.includes(verb));
}

/**
 * Rule 20. `ok` iff (1) every policy tag whose parameter the verb declares equals the unit the schema declares for it (a
 * parameter with no declared unit, or another unit, is refused), and (2) no grant-side `where` term in scope of the verb reads
 * a unit-bearing parameter without a tag. Tags for parameters the verb does not declare are ignored (one policy can cover
 * several verbs). Total: any malformed input is `{ok:false}`.
 */
export function decideUnits(input: UnitsInput): { ok: true } | { ok: false; reason: string } {
  const fail = (m: string) => ({ ok: false as const, reason: m });
  try {
    const te = unitTagsError(input.units);
    if (te) return fail(te);
    const tags = input.units as Record<string, UnitTag>;
    if (typeof input.verb !== 'string' || input.verb.length === 0) return fail('the verb is missing');
    const sUnits = input.schema_units === undefined ? {} : input.schema_units;
    if (!isPlainObject(sUnits)) return fail('the schema units table must be an object');
    if (!isPlainObject(input.verb_params)) return fail(`the schema does not declare verb '${input.verb}'`);
    const params = input.verb_params;
    const declared = (path: string): { has: boolean; tag?: Partial<UnitTag> } => {
      const d = Object.prototype.hasOwnProperty.call(params, path) ? params[path] : undefined;
      if (!isPlainObject(d)) return { has: false };
      const id = d.unit;
      const tag = typeof id === 'string' && Object.prototype.hasOwnProperty.call(sUnits, id) ? sUnits[id] : undefined;
      return { has: true, ...(isPlainObject(tag) ? { tag: tag as Partial<UnitTag> } : {}) };
    };
    for (const path of Object.keys(tags).sort()) {
      const d = declared(path);
      if (!d.has) continue;
      if (d.tag === undefined || !sameTag(d.tag, tags[path]!)) return fail(`'${path}' is declared as ${tagText(d.tag)} by the action schema but the policy term is tagged ${tagText(tags[path])} (unit confusion)`);
    }
    const read = new Set<string>();
    for (const list of Array.isArray(input.predicates) ? input.predicates : []) {
      if (!Array.isArray(list)) continue;
      for (const p of list) {
        if (!verbInScope(p, input.verb)) continue;
        const w = (p as { where?: unknown } | null)?.where;
        if (Array.isArray(w)) for (const c of w) collectPaths(c, read, 0);
      }
    }
    for (const path of [...read].sort()) {
      if (!PARAM_PATH_RE.test(path)) continue;
      const d = declared(path);
      if (d.has && d.tag !== undefined && !Object.prototype.hasOwnProperty.call(tags, path)) return fail(`a policy term reads '${path}' (${tagText(d.tag)}) without a unit tag`);
    }
    return { ok: true };
  } catch (e) {
    return fail(`evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}
