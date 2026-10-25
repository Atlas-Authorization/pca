import { compareUtf8, evaluatePredicates, hashCanonicalLenient, isGroupCondition, isLeafCondition, type Condition } from '@atlasauth/pca';
import type { IntentLearner } from './learner';
import { applyDivergence } from './map';
import type { Outcome } from './omega';
import type { RuntimeSignal } from './ramp';

/**
 * FRAME AND SIDE-EFFECT CONSTRAINTS (Intent Layer v2 §2.9, §3.8, milestone V9; T21).
 *
 * The schema declares monitored state 𝒱 (`account.contact_email`, `account.payment_methods`, `loyalty.points`,
 * `bookings`), each readable through the site's own record, and per verb a WRITE SET W(ω) ⊆ 𝒱 (fixed, or chosen by a
 * parameter) and POSTCONDITIONS over (action, pre-state, post-state, effect record) in the ordinary predicate DSL with
 * `env.pre.*`, `env.post.*`, `env.effect.*` (v1 `effects.ts`, extended), plus exact numeric deltas
 * (`bookings.count` grows by exactly 1). By default intent is FRAME-CLOSED:
 *     for every v ∈ 𝒱 ∖ W(ω): post(v) = pre(v), unless the change is attributed to another actor in the site's log.
 * A violated frame or postcondition is a runtime observation y = 0: it vetoes the action's cell for good (the v1
 * ratchet, `applyDivergence`) and opens recourse (T21). The middleware snapshots 𝒱 before and after the action in
 * the same transaction ({@link captureState}).
 *
 * [X] EFF: the site reports its own effects; the check is as honest as the site. Its value is against a misbehaving
 * AGENT, and as evidence against the site. Unmonitored state is not covered: with 𝒱 empty the report says
 * `unmonitored: true` (the map's `omega.frame.unmonitored`).
 */

export type WriteSetDecl = string[] | { param: string; map: Record<string, string[]>; default?: string[] };

export interface FramePostcondition {
  id: string;
  verb: string;
  description?: string;
  /** DSL conditions over action.*, env.pre.*, env.post.*, env.effect.* (all must hold). */
  where?: Condition[];
  /** post(var.path) = pre(var.path) + by, exactly (numbers). */
  deltas?: { path: string; by: number }[];
}

export interface FrameSpec {
  /** 𝒱. */
  state: string[];
  /** W per verb (a verb absent here writes nothing). */
  writes: Record<string, WriteSetDecl>;
  post?: FramePostcondition[];
}

/** One snapshot of 𝒱: per variable, the digest of its value (and the value when postconditions need it). */
export type StateSnapshot = Record<string, { digest: string; value?: unknown }>;

export const FRAME_STATE_DOMAIN = 'atlas-pca/intent-frame-state/v1';

/** Digest of a state value (site-local, never cross-language: the lenient canonical form). */
export function stateDigest(value: unknown): string {
  return hashCanonicalLenient({ d: FRAME_STATE_DOMAIN, v: value === undefined ? null : value });
}

const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Snapshot already-read values (a prototype-free record: any variable name is an ordinary key). */
export function snapshotState(values: Record<string, unknown>, keepValues = true): StateSnapshot {
  const out = Object.create(null) as StateSnapshot;
  for (const [k, v] of Object.entries(values)) out[k] = keepValues ? { digest: stateDigest(v), value: v } : { digest: stateDigest(v) };
  return out;
}

/** Read every monitored variable through its reader and snapshot it (middleware hook: call before and after). */
export async function captureState(readers: Record<string, () => unknown | Promise<unknown>>, keepValues = true): Promise<StateSnapshot> {
  const values = Object.create(null) as Record<string, unknown>;
  for (const k of Object.keys(readers).sort(compareUtf8)) values[k] = await readers[k]!();
  return snapshotState(values, keepValues);
}

function get(root: unknown, path: string): unknown {
  let cur = root;
  for (const s of path.split('.')) {
    if (cur === null || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, s)) return undefined;
    cur = (cur as Record<string, unknown>)[s];
  }
  return cur;
}

/** W(ω) for an action: the declared list, or the parameter-selected list (unknown parameter value: `default`, else ∅). */
export function writeSetOf(spec: FrameSpec, action: { verb: string; params?: Record<string, unknown> }): string[] {
  const d = Object.prototype.hasOwnProperty.call(spec.writes, action.verb) ? spec.writes[action.verb] : undefined;
  if (d === undefined) return [];
  if (Array.isArray(d)) return [...d];
  const v = get(action.params ?? {}, d.param.startsWith('action.params.') ? d.param.slice('action.params.'.length) : d.param);
  const key = typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v) : undefined;
  return [...(key !== undefined && Object.prototype.hasOwnProperty.call(d.map, key) ? d.map[key]! : (d.default ?? []))];
}

/** Every `env.*` path a condition reads (as `field` or `ref`). */
function envReads(c: Condition, out: string[]): void {
  if (c === null || typeof c !== 'object') return;
  if (isGroupCondition(c)) {
    if ('all_of' in c && Array.isArray(c.all_of)) c.all_of.forEach((x) => envReads(x, out));
    else if ('any_of' in c && Array.isArray(c.any_of)) c.any_of.forEach((x) => envReads(x, out));
    else if ('not' in c) envReads(c.not, out);
    return;
  }
  if (isLeafCondition(c)) {
    if (c.field.startsWith('env.')) out.push(c.field);
    if (typeof c.ref === 'string' && c.ref.startsWith('env.')) out.push(c.ref);
  }
}

function nest(s: StateSnapshot): Record<string, unknown> {
  const root = Object.create(null) as Record<string, unknown>;
  for (const [k, v] of Object.entries(s)) {
    if (!('value' in v)) continue;
    const segs = k.split('.');
    let cur = root;
    for (let i = 0; i < segs.length - 1; i++) {
      const s0 = segs[i]!;
      if (!own(cur, s0) || cur[s0] === null || typeof cur[s0] !== 'object') cur[s0] = Object.create(null) as Record<string, unknown>;
      cur = cur[s0] as Record<string, unknown>;
    }
    cur[segs[segs.length - 1]!] = v.value;
  }
  return root;
}

export interface FrameReport {
  status: 'ok' | 'violated' | 'pending';
  /** Variables outside W(ω) that changed with no attribution to another actor (frame violations). */
  outOfFrame: string[];
  /** Variables outside W(ω) that changed but are attributed to another actor (excused). */
  attributed: string[];
  /** Postconditions that failed. */
  postViolated: string[];
  /** Variables (or postcondition inputs) missing from a snapshot or the effect record: nothing is concluded for them. */
  missing: string[];
  /** 𝒱 is empty: nothing is monitored (said so, not hidden). */
  unmonitored: boolean;
}

/**
 * Check one executed action: the frame condition over 𝒱 ∖ W(ω) and the verb's postconditions. `attributions`
 * are the site's audit-log entries (variable, actor) for the action's window; a change by an actor other than
 * `self` (the session's agent) is excused. Total: never throws.
 */
export function checkFrame(
  spec: FrameSpec,
  action: { verb: string; resource: string; params?: Record<string, unknown> },
  pre: StateSnapshot,
  post: StateSnapshot,
  opts: { effect?: Record<string, unknown>; attributions?: readonly { var: string; actor: string }[]; self?: string } = {},
): FrameReport {
  const rep: FrameReport = { status: 'ok', outOfFrame: [], attributed: [], postViolated: [], missing: [], unmonitored: false };
  try {
    if (spec === null || typeof spec !== 'object' || !Array.isArray(spec.state) || action === null || typeof action !== 'object' || pre === null || typeof pre !== 'object' || post === null || typeof post !== 'object') {
      throw new Error('spec, action, pre and post must be objects (spec.state an array)');
    }
    rep.unmonitored = spec.state.length === 0;
    const W = new Set(writeSetOf(spec, action));
    for (const v of [...spec.state].sort(compareUtf8)) {
      if (W.has(v)) continue;
      const a = own(pre, v) ? pre[v] : undefined;
      const b = own(post, v) ? post[v] : undefined;
      if (!a || !b) {
        rep.missing.push(v);
        continue;
      }
      if (a.digest === b.digest) continue;
      const other = (opts.attributions ?? []).some((x) => x.var === v && x.actor !== opts.self);
      (other ? rep.attributed : rep.outOfFrame).push(v);
    }
    const env = { pre: nest(pre), post: nest(post), effect: opts.effect ?? {} };
    const ctx = { action: { verb: action.verb, resource: action.resource, params: action.params ?? {} }, env };
    for (const pc of spec.post ?? []) {
      if (pc.verb !== action.verb) continue;
      let pending = false;
      for (const d of pc.deltas ?? []) {
        const x = get(env.pre, d.path);
        const y = get(env.post, d.path);
        if (typeof x !== 'number' || typeof y !== 'number') {
          rep.missing.push(`${pc.id}:${d.path}`);
          pending = true;
        } else if (y !== x + d.by) {
          rep.postViolated.push(pc.id);
          pending = true; // concluded (violated): `where` is not evaluated
          break;
        }
      }
      if (pending) continue;
      const reads: string[] = [];
      (pc.where ?? []).forEach((c) => envReads(c, reads));
      const absent = reads.filter((r) => get({ env }, r) === undefined);
      if (absent.length) {
        rep.missing.push(...absent.map((r) => `${pc.id}:${r}`));
        continue;
      }
      if (pc.where && pc.where.length && !evaluatePredicates([{ verb: action.verb, where: pc.where }], ctx).allowed) rep.postViolated.push(pc.id);
    }
  } catch (e) {
    rep.missing.push(`error: ${(e as Error).message}`);
  }
  rep.missing = [...new Set(rep.missing)].sort(compareUtf8);
  rep.postViolated = [...new Set(rep.postViolated)].sort(compareUtf8);
  rep.status = rep.outOfFrame.length || rep.postViolated.length ? 'violated' : rep.missing.length ? 'pending' : 'ok';
  return rep;
}

/**
 * Feed a frame report back (T21): a violation is a negative runtime observation that vetoes the outcome's cell for
 * good (the ratchet); `ok` and `pending` change nothing (a met frame is not the principal's endorsement).
 */
export function applyFrameReport(l: IntentLearner, o: Outcome, report: FrameReport): { signal?: RuntimeSignal; divergence?: ReturnType<typeof applyDivergence> } {
  if (report === null || typeof report !== 'object' || report.status !== 'violated') return {};
  return { signal: 'postcondition-violation', divergence: applyDivergence(l, o, 0) };
}
