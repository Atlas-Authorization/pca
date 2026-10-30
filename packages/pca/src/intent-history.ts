import type { ActionSchema } from './action-schema';
import {
  type AccPreState,
  type AccumulatorDecl,
  type AccWindow,
  type MonitorDecl,
  accSelects,
  accValueOf,
  combineAcc,
  distinctKey,
  monitorInitialState,
  preValue,
  sortedDistinct,
} from './intent-acc';
import { predicateMatches, type ActionContext } from './predicates';
import { freeRecord, isSafeInt, ownGet, ownHas } from './intent-strict';

/**
 * SESSION HISTORIES (PCA Intent Layer v2 §2.1): the host side of accumulators and monitors.
 *
 * An event e = (ω, t, st) is an admitted action with its admission time and status st ∈ {reserved, committed, released,
 * reverted}; a history ξ is the session's events in admission order. COUNTED statuses are {reserved, committed}: a
 * reservation counts as soon as it is made, so two concurrent actions cannot both fit under a cap (§3.1). For an
 * accumulator ψ and a candidate ω at time t,
 *   E_ψ(ξ, ω, t) = { i : ω_i ∈ sel, st_i counted, t_i ∈ win(t) ∪ (t, ∞), key(ω_i) = key(ω) }
 * (a counted event stamped after t has not left the window: it always counts, see {@link inWindow})
 * and the verifier's PRE-STATE is the aggregate of E (what {@link accPreState} returns and the host hands to the
 * verifier, under the session lock); post_ψ = combine(pre, val(ω)) (intent-acc.ts). A monitor's state is the fold of its
 * step over ξ. Everything here is deterministic and pure; the store below adds the lock (LIN, T11).
 */

export type EventStatus = 'reserved' | 'committed' | 'released' | 'reverted';
export const EVENT_STATUSES: readonly EventStatus[] = ['reserved', 'committed', 'released', 'reverted'];
export const COUNTED_STATUSES: readonly EventStatus[] = ['reserved', 'committed'];

export interface IntentEvent {
  /** Unique per session (the PCActn digest). */
  id: string;
  verb: string;
  resource: string;
  params: Record<string, unknown>;
  /** Admission time, epoch ms. */
  t: number;
  status: EventStatus;
}

export const isCounted = (s: EventStatus): boolean => s === 'reserved' || s === 'committed';

/**
 * Does the counted event stamped t_i still count at t? t_i ∈ win(t) ∪ (t, ∞): task = all of ℕ; sliding(Δ) = (t − Δ, t];
 * period(P, t0) = the period of length P containing t; AND every event stamped AFTER t (spec §2.1, "future-stamped
 * events").
 *
 * An event with t_i > t has not left any window at t, so it counts toward the cap. It arises when the candidate's time was
 * read before a concurrent admission committed (a stale `now`), from clock skew between sequencer nodes, or from a clock
 * stepping back. Excluding it made the event invisible to the cap (over-admission: the 0.4.2 sequencer bug). In a history
 * whose times never decrease this changes nothing; otherwise it fails closed (the cap only ever sees more, never less).
 * A non-integer time is never in a window (fail closed: the caller treats the store as corrupt).
 */
export function inWindow(win: AccWindow, ti: number, t: number): boolean {
  if (!isSafeInt(ti) || !isSafeInt(t)) return false;
  if (ti > t) return true; // future-stamped: not yet out of any window
  switch (win.kind) {
    case 'task':
      return true;
    case 'sliding':
      return ti > t - win.ms;
    case 'period':
      return Math.floor((ti - win.t0) / win.ms) === Math.floor((t - win.t0) / win.ms);
  }
}

/** key(ω): the canonical key of the grouping parameter, '•' when ungrouped, null when the parameter is missing. */
export function accKeyOf(a: Pick<AccumulatorDecl, 'key'>, params: Record<string, unknown>): string | null {
  if (a.key === null) return '•';
  const name = a.key.slice('action.params.'.length);
  return ownHas(params, name) ? distinctKey(ownGet(params, name)) : null;
}

const emptyPre = (a: Pick<AccumulatorDecl, 'agg'>): AccPreState =>
  a.agg === 'sum' ? { sum: 0 } : a.agg === 'count' ? { count: 0 } : a.agg === 'max' ? { max: 0 } : { values: [] };

/**
 * The pre-state of ψ for a candidate action (window, key, selection and counted statuses applied). Throws if a past
 * event's value is unreadable (it was admitted, so this is store corruption: fail closed upstream).
 */
export function accPreState(a: AccumulatorDecl, history: readonly IntentEvent[], cand: { params: Record<string, unknown>; t: number }, schema?: Pick<ActionSchema, 'verbs'>): AccPreState {
  const key = accKeyOf(a, cand.params);
  if (key === null) throw new Error(`accPreState: the key parameter ${a.key} is missing`);
  let sum = 0;
  let count = 0;
  let max = 0;
  const vals: string[] = [];
  // An unreadable time must not silently drop a counted event out of the cap: fail closed (store corruption).
  if (!isSafeInt(cand.t)) throw new Error('accPreState: the candidate time is not a safe integer');
  for (const e of history) {
    if (isCounted(e.status) && !isSafeInt(e.t)) throw new Error(`accPreState: event ${e.id}: the time is not a safe integer`);
    if (!isCounted(e.status) || !inWindow(a.win, e.t, cand.t) || !accSelects(a, e.verb, schema) || accKeyOf(a, e.params) !== key) continue;
    const v = accValueOf(a, e.verb, e.params, schema);
    if (!v.ok) throw new Error(`accPreState: event ${e.id}: ${v.reason}`);
    sum += v.val;
    count += 1;
    max = Math.max(max, v.val);
    if (v.key !== undefined) vals.push(v.key);
  }
  // only a sum accumulator reports the sum: a max / count / distinct-values history whose values add past 2^53-1 is fine
  if (a.agg === 'sum' && !Number.isSafeInteger(sum)) throw new Error('accPreState: sum exceeds 2^53-1');
  return a.agg === 'sum' ? { sum } : a.agg === 'count' ? { count } : a.agg === 'max' ? { max } : { values: sortedDistinct(vals) };
}

/** post_ψ(ξ, ω, t) (spec §2.1): the pre-state combined with ω when ω ∈ sel, else the pre-state's value. */
export function accPost(a: AccumulatorDecl, history: readonly IntentEvent[], cand: { verb: string; params: Record<string, unknown>; t: number }, schema?: Pick<ActionSchema, 'verbs'>): number {
  const pre = a.key !== null && accKeyOf(a, cand.params) === null ? emptyPre(a) : accPreState(a, history, cand, schema);
  if (!accSelects(a, cand.verb, schema)) return preValue(a, pre);
  const v = accValueOf(a, cand.verb, cand.params, schema);
  if (!v.ok) throw new Error(`accPost: ${v.reason}`);
  const post = combineAcc(a, pre, v);
  if (post === null) throw new Error('accPost: overflow');
  return post;
}

const ctxOf = (e: Pick<IntentEvent, 'verb' | 'resource' | 'params'>): ActionContext => ({ action: { verb: e.verb, resource: e.resource, params: e.params } });

/** One monitor step on one event (deterministic; statuses that do not count leave the state unchanged). */
export function monitorStep(m: MonitorDecl, q: string, e: Pick<IntentEvent, 'verb' | 'resource' | 'params' | 'status'>): string {
  const counts = (m.status ?? 'admitted') === 'committed' ? e.status === 'committed' : isCounted(e.status);
  if (!counts) return q;
  const c = ctxOf(e);
  switch (m.kind) {
    case 'requires_prior':
    case 'precedes':
      return q === 'met' || predicateMatches(m.p, c) ? 'met' : 'unmet';
    case 'never':
      return q === 'seen' || predicateMatches(m.p, c) ? 'seen' : 'clean';
    case 'always':
      return q === 'broken' || !predicateMatches(m.p, c) ? 'broken' : 'ok';
    case 'responds_within': {
      if (q === 'missed') return 'missed';
      const W = m.within!;
      let pending: number | null = q.startsWith('pending:') ? Number(q.slice('pending:'.length)) : null;
      if (pending !== null) {
        if (predicateMatches(m.q!, c)) pending = null;
        else if (pending - 1 <= 0) return 'missed';
        else pending -= 1;
      }
      if (predicateMatches(m.p, c)) pending = pending === null ? W : Math.min(pending, W);
      return pending === null ? 'idle' : `pending:${pending}`;
    }
  }
}

/** q_𝔐(ξ): the fold of the monitor over the history (in admission order, current statuses). */
export function monitorState(m: MonitorDecl, history: readonly IntentEvent[]): string {
  let q = monitorInitialState(m);
  for (const e of history) q = monitorStep(m, q, e);
  return q;
}

/** The verifier context (`intentV2.acc`) for a candidate action: pre-states of the site-local ψ and monitor states. */
export function accContextFor(
  S: { accumulators: AccumulatorDecl[]; monitors: MonitorDecl[] },
  history: readonly IntentEvent[],
  cand: { params: Record<string, unknown>; t: number },
  schema?: Pick<ActionSchema, 'verbs'>,
): { state: Record<string, AccPreState>; monitors: Record<string, string> } {
  const state = freeRecord<AccPreState>();
  for (const a of S.accumulators) {
    if (a.holder.kind !== 'site_local') continue;
    if (a.key !== null && accKeyOf(a, cand.params) === null) continue; // the verifier fails the claim (missing key)
    state[a.id] = accPreState(a, history, cand, schema);
  }
  const monitors = freeRecord<string>();
  for (const m of S.monitors) monitors[m.id] = monitorState(m, history);
  return { state, monitors };
}

// ---- the session store port (LIN) -------------------------------------------------------------------------------

/** A transaction on ONE session's history, holding its exclusive lock. */
export interface SessionTx {
  events(): Promise<readonly IntentEvent[]>;
  append(e: IntentEvent): Promise<void>;
  setStatus(id: string, status: EventStatus): Promise<boolean>;
}

/**
 * The accumulator state holder. LIN (§2.10) holds iff `withSession` serialises every admission of a session: the
 * pre-state read, the verification and the `reserved` append happen under one lock (a row lock in a database, the
 * in-process mutex below). Hosts implement it over their database; Atlas's sequencer uses a Postgres row lock.
 */
export interface IntentSessionStore {
  withSession<T>(session: string, fn: (tx: SessionTx) => Promise<T>): Promise<T>;
  /**
   * `true` when the history survives a restart of the process (a database row lock and rows). A store that does not say so
   * is treated as volatile: after a restart its accumulators read zero, so a cap would admit again. `admitIntentAction`
   * refuses such a store unless the caller passes `requireDurable: false` (0.5, B16: durable is the default).
   */
  readonly durable?: boolean;
}

/**
 * Admit one action atomically against the session's accumulators (site-local holder): under the session lock, compute
 * the pre-states and monitor states from the history, run `verify` with them, and on `allow` append the event as
 * `reserved`. After the effect the host calls {@link settleIntentEvent} (`committed` or `released`).
 */
export async function admitIntentAction<V extends { allow: boolean }>(
  store: IntentSessionStore,
  args: {
    session: string;
    root: { accumulators: AccumulatorDecl[]; monitors: MonitorDecl[] };
    schema?: Pick<ActionSchema, 'verbs'>;
    event: Omit<IntentEvent, 'status'>;
    verify: (acc: { state: Record<string, AccPreState>; monitors: Record<string, string> }) => Promise<V>;
    /** Default `true` (0.5, B16): a store that is not durable (see {@link IntentSessionStore.durable}) is refused. Pass `false` only for tests and single-process sites that accept losing every cap on restart. */
    requireDurable?: boolean;
  },
): Promise<V> {
  if (args.requireDurable !== false && store?.durable !== true) throw new Error('admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore');
  return store.withSession(args.session, async (tx) => {
    const history = await tx.events();
    const acc = accContextFor(args.root, history, args.event, args.schema);
    const v = await args.verify(acc);
    if (v.allow) await tx.append({ ...args.event, status: 'reserved' });
    return v;
  });
}

export async function settleIntentEvent(store: IntentSessionStore, session: string, id: string, status: 'committed' | 'released' | 'reverted'): Promise<boolean> {
  return store.withSession(session, (tx) => tx.setStatus(id, status));
}
