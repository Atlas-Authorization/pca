/**
 * Operation records: execute an authorized operation at most once, with a durable record of what happened (0.5, additive).
 *
 * `authorize()` decides and consumes the PCActn's replay counter. Between that decision and the end of the side effect
 * the process can crash, the client can time out and retry, or two workers can pick up the same authorization. This
 * module closes that gap with a record per operation id (`AuthorizedOperation.id`, the digest of the presented PCActn):
 *
 *   1. `executeAuthorized(authorization, fn, { store })` creates the record in state `pending` BEFORE anything runs
 *      (one atomic create-if-absent: of N concurrent executions of one authorization exactly one gets to run `fn`);
 *   2. for an irreversible operation it re-checks revocation, expiry and approval immediately before `fn` (`recheck`;
 *      required, fail closed); a failed re-check records `aborted` and `fn` never runs;
 *   3. it moves the record to `executing` and only then calls `fn`, with the operation id as the idempotency key for the
 *      downstream call;
 *   4. the record becomes `committed` (with `fn`'s result) or `failed` (with its error) afterwards.
 *
 * A second execution of the same id never runs `fn` again: it is answered from the record. Nothing is re-run after a
 * crash either. Once `pendingTimeoutMs` has passed, a record still `pending` is settled as `aborted` (the side effect never
 * started: the agent may sign a fresh PCActn), and a record still `executing` as `uncertain` (the side effect may or may
 * not have happened: an operator or a reconciliation job settles it with `resolveOperation`, asking the downstream system
 * by the idempotency key). `createExecutor` combines `authorize` and `executeAuthorized` so that a retry of the
 * same PCActn (which `authorize` refuses as a replay) is answered from the record instead of a bare replay denial.
 */

import { decodePCActn, type PCActn } from '../pcactn';
import { hashCanonical } from '../hash';
import { effectiveReversibility } from '../revocation';
import { createAuthorizer, isAuthorizedFor, type AuthorizeInput, type AuthorizeOptions, type AuthorizeResult } from './authorize';
import { defaultExtract, type AtomicKv, type AuthorizedOperation, type PcaGuardResult } from './require-pca';
import type { PcaOperation, PcaVerdict } from './verify';

/** Where an operation is in its execution. */
export type OperationState =
  /** Claimed for execution, `fn` not started yet (re-check running), or the process crashed before starting it. */
  | 'pending'
  /** `fn` has been started: the side effect is running, or the process crashed during or after it. */
  | 'executing'
  /** The side effect completed; `result` is what `fn` returned. */
  | 'committed'
  /** `fn` threw; `error` is its message. Not re-run (the downstream may have applied part of it: use the idempotency key). */
  | 'failed'
  /** The pre-execution re-check refused (revoked, expired, approval withdrawn): `fn` never ran. */
  | 'aborted'
  /** Found `executing` after `pendingTimeoutMs`: the outcome is unknown and must be reconciled, never silently re-run. */
  | 'uncertain';

export interface OperationRecord {
  /** The operation id (`AuthorizedOperation.id`), also the idempotency key handed to `fn`. */
  id: string;
  state: OperationState;
  verb: string;
  resource: string;
  params_digest: string;
  /** The effective reversibility class the execution ran under. */
  reversibility: 'reversible' | 'costly' | 'irreversible';
  /** When the record was created (epoch ms). */
  startedAt: number;
  /** When `fn` was started (epoch ms). */
  executingAt?: number;
  /** When it reached its final state (epoch ms). */
  finishedAt?: number;
  /** `committed`: the value `fn` returned (keep it JSON-serialisable for a durable store). */
  result?: unknown;
  /** `failed` / `aborted` / `uncertain`: why. */
  error?: string;
}

/**
 * Durable, shared storage for operation records. Both methods that change state MUST be atomic across every process and
 * node that shares the store (a unique-key insert and a conditional `UPDATE ... WHERE state = $from`, a Redis Lua script,
 * `DurableKv.update`). A call that cannot decide MUST reject; the executor then refuses or reports the outcome as unknown.
 */
export interface OperationStore {
  /** Atomically insert `record` if no record with its id exists; otherwise return the existing record unchanged. */
  create(record: OperationRecord): Promise<{ created: true } | { created: false; record: OperationRecord }>;
  get(id: string): Promise<OperationRecord | undefined>;
  /** Atomically replace the record with `next` only if its current state is `from`. Returns whether it did. */
  transition(id: string, from: OperationState, next: OperationRecord): Promise<boolean>;
  /** Records still open, in state `pending` or `executing` (for {@link recoverOperations}). Optional: without it, recover by id. */
  listOpen?(): Promise<OperationRecord[]>;
  /** `'process'`: the records live in this process only (a crash loses them: tests and single-process tools only). */
  readonly scope?: 'process' | 'shared';
}

/** In-memory {@link OperationStore} for ONE process (tests, a single worker). Its records die with the process. */
export function memoryOperationStore(): OperationStore {
  const m = new Map<string, OperationRecord>();
  return {
    scope: 'process',
    // no await between the read and the write: one turn of the event loop is atomic in a single process
    async create(rec) {
      const cur = m.get(rec.id);
      if (cur) return { created: false, record: cur };
      m.set(rec.id, { ...rec });
      return { created: true };
    },
    get: async (id) => {
      const r = m.get(id);
      return r ? { ...r } : undefined;
    },
    async transition(id, from, next) {
      if (m.get(id)?.state !== from) return false;
      m.set(id, { ...next, id });
      return true;
    },
    listOpen: async () => [...m.values()].filter((r) => r.state === 'pending' || r.state === 'executing').map((r) => ({ ...r })),
  };
}

const asRecord = (v: unknown): OperationRecord | undefined =>
  v !== null && typeof v === 'object' && typeof (v as OperationRecord).id === 'string' && typeof (v as OperationRecord).state === 'string' ? (v as OperationRecord) : undefined;

/**
 * {@link OperationStore} over any atomic key/value store with `update` (e.g. `openDurableState({ dir })` from
 * `@atlasauth/pca/durable-state`: crash-safe and multi-process-safe on one host). `prefix` namespaces the keys. It has no
 * `listOpen`; recover a known id with {@link recoverOperation}.
 */
export function durableOperationStore(kv: AtomicKv, opts: { prefix?: string; scope?: 'process' | 'shared' } = {}): OperationStore {
  const pre = opts.prefix ?? 'pca-op:';
  return {
    scope: opts.scope ?? 'shared',
    async create(rec) {
      let existing: OperationRecord | undefined;
      await kv.update(pre + rec.id, (prev) => {
        existing = asRecord(prev);
        return existing ? undefined : { ...rec };
      });
      return existing ? { created: false, record: existing } : { created: true };
    },
    get: async (id) => asRecord(await kv.get(pre + id)),
    async transition(id, from, next) {
      let done = false;
      await kv.update(pre + id, (prev) => {
        done = asRecord(prev)?.state === from;
        return done ? { ...next, id } : undefined;
      });
      return done;
    },
  };
}

/** What a pre-execution re-check answered. */
export type RecheckResult = { ok: true } | { ok: false; reason: string };

/** What the executed function receives. */
export interface ExecutionHandle {
  /** The operation id: pass it as the idempotency key of the downstream call (e.g. `Idempotency-Key`). */
  idempotencyKey: string;
  operation: AuthorizedOperation;
  pcactn: PCActn;
}

export interface ExecuteAuthorizedOptions {
  /** REQUIRED: the operation record store (shared and durable in production; see {@link OperationStore}). */
  store: OperationStore;
  /**
   * The operation about to execute, as the handler will run it. When given, the authorization must be for exactly it
   * (`isAuthorizedFor`), else the call is refused before anything is recorded.
   */
  operation?: PcaOperation;
  /**
   * Re-check, immediately before `fn`, that the authorization still stands: the grant is not revoked, the approval
   * (plan, step-up) has not expired or been withdrawn. REQUIRED for an irreversible operation (fail closed); also run for
   * the other classes when `recheckFor: 'always'`. The PCActn's own expiry (`exp`) is always checked with it. A throw
   * counts as a refusal.
   */
  recheck?: (h: ExecutionHandle) => RecheckResult | Promise<RecheckResult>;
  /** Which operations are re-checked. Default `'irreversible'`. */
  recheckFor?: 'irreversible' | 'always';
  /** The server's authoritative reversibility class; the stricter of it and the signed class applies (missing = irreversible). */
  reversibilityClass?: string;
  /** An open record older than this (ms) is settled: `pending` as `aborted`, `executing` as `uncertain`. Default 5 minutes. */
  pendingTimeoutMs?: number;
  /** Clock (epoch ms). Default `Date.now`. */
  now?: () => number;
}

/**
 * What can be executed: an `authorize()` result, a guard result (`requireAuthorized`, `requirePCA` with `operation`), or
 * what the framework adapters attach to the request on success (`{ verdict, pcactn, operation }`). It must be allowed and
 * bound to an operation.
 */
export type ExecutableAuthorization = AuthorizeResult | PcaGuardResult | { verdict: PcaVerdict; pcactn: PCActn; operation?: AuthorizedOperation };

function allowedOperation(a: ExecutableAuthorization | null | undefined): { pcactn: PCActn; operation: AuthorizedOperation; verdict: PcaVerdict } | undefined {
  if (!a || typeof a !== 'object') return undefined;
  const ok = 'allow' in a ? a.allow === true : 'ok' in a ? a.ok === true : a.verdict?.allow === true;
  const x = a as { pcactn?: PCActn; operation?: AuthorizedOperation; verdict?: PcaVerdict };
  if (!ok || x.verdict?.allow !== true || !x.pcactn || typeof x.operation?.id !== 'string' || x.operation.id === '') return undefined;
  return { pcactn: x.pcactn, operation: x.operation, verdict: x.verdict };
}

/** The outcome of an execution attempt. `replayed: true` means it was answered from an existing record. */
export type ExecuteOutcome<T> =
  | { status: 'committed'; operationId: string; result: T; replayed: boolean; /** false: `fn` ran but the record could not be written (it stays executing -> uncertain). */ recorded: boolean }
  | { status: 'failed'; operationId: string; error: string; replayed: boolean }
  | { status: 'aborted'; operationId: string; reason: string; replayed: boolean }
  /** Another execution of this id is in flight (or crashed less than `pendingTimeoutMs` ago). `fn` did not run here. */
  | { status: 'pending'; operationId: string; replayed: true }
  /** The outcome of an earlier execution is unknown (see {@link OperationState}). `fn` did not run here. */
  | { status: 'uncertain'; operationId: string; reason: string; replayed: true }
  /** Not executed and nothing recorded: the authorization does not allow this operation, or the configuration is incomplete. */
  | { status: 'refused'; reason: string };

export const OPERATION_PENDING_TIMEOUT_MS = 5 * 60_000;

/** Settle an open record that is older than `timeoutMs`: `pending` -> `aborted` (never started), `executing` -> `uncertain`. */
async function settleStale(store: OperationStore, rec: OperationRecord, now: number, timeoutMs: number): Promise<OperationRecord> {
  if (rec.state !== 'pending' && rec.state !== 'executing') return rec;
  // `executing` is aged from the moment `fn` was started (a slow re-check does not count against it)
  if (!(now - (rec.state === 'executing' ? (rec.executingAt ?? rec.startedAt) : rec.startedAt) > timeoutMs)) return rec;
  const next: OperationRecord =
    rec.state === 'pending'
      ? { ...rec, state: 'aborted', error: `not started within ${timeoutMs} ms of the claim: the side effect never ran`, finishedAt: now }
      : { ...rec, state: 'uncertain', error: `no outcome recorded within ${timeoutMs} ms of the start: the side effect may or may not have happened`, finishedAt: now };
  await store.transition(rec.id, rec.state, next);
  // whatever is stored now (the original execution may have finished in between)
  return (await store.get(rec.id)) ?? next;
}

/** Answer an execution attempt from an existing record (never runs anything). */
async function fromRecord<T>(store: OperationStore, rec0: OperationRecord, now: number, timeoutMs: number): Promise<ExecuteOutcome<T>> {
  const rec = await settleStale(store, rec0, now, timeoutMs);
  const id = rec.id;
  switch (rec.state) {
    case 'committed':
      return { status: 'committed', operationId: id, result: rec.result as T, replayed: true, recorded: true };
    case 'failed':
      return { status: 'failed', operationId: id, error: rec.error ?? 'failed', replayed: true };
    case 'aborted':
      return { status: 'aborted', operationId: id, reason: rec.error ?? 'aborted', replayed: true };
    case 'uncertain':
      return { status: 'uncertain', operationId: id, reason: rec.error ?? 'outcome unknown', replayed: true };
    case 'pending':
    case 'executing':
      return { status: 'pending', operationId: id, replayed: true };
    default:
      return { status: 'uncertain', operationId: id, reason: `unknown record state '${String(rec.state)}'`, replayed: true };
  }
}

/** Leave `executing` (or `uncertain`, when recovery settled a slow execution) for the final state. */
async function finish(store: OperationStore, rec: OperationRecord, next: Partial<OperationRecord>): Promise<boolean> {
  const out: OperationRecord = { ...rec, ...next };
  if (await store.transition(rec.id, rec.state, out)) return true;
  return rec.state === 'executing' && store.transition(rec.id, 'uncertain', out);
}

/** Answer from the record as it is stored now (a concurrent recovery or execution changed it). */
async function answerCurrent<T>(store: OperationStore, id: string, now: number, timeoutMs: number): Promise<ExecuteOutcome<T>> {
  const cur = await store.get(id);
  return cur ? fromRecord<T>(store, cur, now, timeoutMs) : { status: 'uncertain', operationId: id, reason: 'the operation record disappeared', replayed: true };
}

const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/**
 * Execute an allowed `authorize()` result at most once, with a durable record (see the module doc). `fn` runs only if
 * this call created the `pending` record and the re-check (when required) passed; every other outcome is answered from
 * the record. A throw from `fn` is recorded as `failed` and returned, not re-thrown.
 */
export async function executeAuthorized<T>(
  authorization: ExecutableAuthorization,
  fn: (h: ExecutionHandle) => T | Promise<T>,
  opts: ExecuteAuthorizedOptions,
): Promise<ExecuteOutcome<T>> {
  const store = opts?.store;
  if (!store || typeof store.create !== 'function' || typeof store.get !== 'function' || typeof store.transition !== 'function') {
    return { status: 'refused', reason: 'executeAuthorized: missing required component: store (fail closed)' };
  }
  const az = allowedOperation(authorization);
  if (!az) return { status: 'refused', reason: 'executeAuthorized: the authorization did not allow an operation' };
  if (opts.operation !== undefined && !isAuthorizedFor({ ok: true, verdict: az.verdict, pcactn: az.pcactn, operation: az.operation }, opts.operation)) {
    return { status: 'refused', reason: 'executeAuthorized: the authorization is not for this operation (verb, resource or params differ)' };
  }
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.pendingTimeoutMs ?? OPERATION_PENDING_TIMEOUT_MS;
  const { pcactn, operation } = az;
  const reversibility = effectiveReversibility(opts.reversibilityClass, pcactn.action?.reversibility_class);
  const mustRecheck = reversibility === 'irreversible' || opts.recheckFor === 'always';
  if (mustRecheck && typeof opts.recheck !== 'function') {
    return { status: 'refused', reason: `executeAuthorized: a ${reversibility} operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)` };
  }

  const handle: ExecutionHandle = { idempotencyKey: operation.id, operation, pcactn };
  const rec: OperationRecord = {
    id: operation.id,
    state: 'pending',
    verb: operation.verb,
    resource: operation.resource,
    params_digest: operation.params_digest,
    reversibility,
    startedAt: now(),
  };
  const claimed = await store.create(rec);
  if (!claimed.created) return fromRecord(store, claimed.record, now(), timeoutMs);

  if (mustRecheck) {
    let rc: RecheckResult;
    try {
      const t = now();
      rc = typeof pcactn.exp === 'number' && t > pcactn.exp ? { ok: false, reason: `the PCActn expired at ${pcactn.exp}` } : await opts.recheck!(handle);
    } catch (e) {
      rc = { ok: false, reason: `recheck error (fail closed): ${message(e)}` };
    }
    if (rc?.ok !== true) {
      const reason = `recheck: ${rc && rc.ok === false && rc.reason ? rc.reason : 'refused'}`;
      if (await finish(store, rec, { state: 'aborted', error: reason, finishedAt: now() })) return { status: 'aborted', operationId: rec.id, reason, replayed: false };
      return answerCurrent(store, rec.id, now(), timeoutMs);
    }
  }

  // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
  const running: OperationRecord = { ...rec, state: 'executing', executingAt: now() };
  if (!(await store.transition(rec.id, 'pending', running))) return answerCurrent(store, rec.id, now(), timeoutMs);

  let result: T;
  try {
    result = await fn(handle);
  } catch (e) {
    const error = message(e);
    await finish(store, running, { state: 'failed', error, finishedAt: now() }).catch(() => false);
    return { status: 'failed', operationId: rec.id, error, replayed: false };
  }
  let recorded: boolean;
  try {
    recorded = await finish(store, running, { state: 'committed', result, finishedAt: now() });
  } catch {
    recorded = false;
  }
  return { status: 'committed', operationId: rec.id, result, replayed: false, recorded };
}

/**
 * Settle every open record older than `olderThanMs` (run it at startup and periodically): `pending` -> `aborted` (the
 * side effect never started), `executing` -> `uncertain`. Returns the records it settled. Needs `store.listOpen`.
 * Nothing is re-run: reconcile each `uncertain` one with {@link resolveOperation}.
 */
export async function recoverOperations(store: OperationStore, opts: { olderThanMs?: number; now?: () => number } = {}): Promise<OperationRecord[]> {
  if (typeof store.listOpen !== 'function') throw new TypeError('recoverOperations: the store has no listOpen (recover by id with recoverOperation)');
  const out: OperationRecord[] = [];
  for (const r of await store.listOpen()) {
    const u = await recoverOperation(store, r.id, opts);
    if (u && u.state !== r.state) out.push(u);
  }
  return out;
}

/** {@link recoverOperations} for one id. Returns the record as it now stands (undefined: no record, the operation never started). */
export async function recoverOperation(store: OperationStore, id: string, opts: { olderThanMs?: number; now?: () => number } = {}): Promise<OperationRecord | undefined> {
  const r = await store.get(id);
  return r ? settleStale(store, r, (opts.now ?? Date.now)(), opts.olderThanMs ?? OPERATION_PENDING_TIMEOUT_MS) : undefined;
}

/**
 * Settle an `uncertain` record after reconciling with the downstream system (look the idempotency key up there):
 * `committed` with the result it reports, or `failed` when it never applied. Returns false if the record is not `uncertain`.
 */
export async function resolveOperation(
  store: OperationStore,
  id: string,
  outcome: { state: 'committed'; result?: unknown } | { state: 'failed'; error: string },
  opts: { now?: () => number } = {},
): Promise<boolean> {
  const r = await store.get(id);
  if (r?.state !== 'uncertain') return false;
  const next: OperationRecord =
    outcome.state === 'committed'
      ? { ...r, state: 'committed', result: outcome.result, finishedAt: (opts.now ?? Date.now)() }
      : { ...r, state: 'failed', error: outcome.error, finishedAt: (opts.now ?? Date.now)() };
  return store.transition(id, 'uncertain', next);
}

/** Options for {@link createExecutor}: `authorize` options plus the operation store and the re-check policy. */
export interface ExecutorOptions extends AuthorizeOptions {
  /** REQUIRED: the operation record store. */
  operations: OperationStore;
  /**
   * Extra re-check before an irreversible operation (e.g. a step-up approval still stands). The executor always re-runs
   * `hooks.revocation` against the grant from `resolveGrant`, checks the PCActn's expiry and, with `plans`, that a
   * registered plan is still executable; this adds to them.
   */
  recheck?: (h: ExecutionHandle) => RecheckResult | Promise<RecheckResult>;
  recheckFor?: 'irreversible' | 'always';
  /** The server's reversibility class for an operation (catalog). Absent: the signed class. */
  reversibilityClassOf?: (op: PcaOperation) => string | undefined;
  pendingTimeoutMs?: number;
}

/** The executor's answer: the execution outcome, or the authorization denial (nothing ran). */
export type ExecutorOutcome<T> = ExecuteOutcome<T> | { status: 'denied'; authorization: Extract<AuthorizeResult, { allow: false }> };

/**
 * `authorize` + `executeAuthorized` in one call, with retries answered from the record: a second presentation of the
 * same PCActn is refused by `authorize` as a replay, and if that replay is the ONLY failing check (the proof, binding,
 * policy and revocation all still pass now) and a record exists for its operation id and this operation, the record's
 * outcome is returned (`replayed: true`) instead of the denial. No record means the first attempt never reached
 * execution: the denial stands (the authorization was consumed; the agent signs a fresh PCActn).
 */
export function createExecutor(opts: ExecutorOptions): <T>(input: AuthorizeInput, fn: (h: ExecutionHandle) => T | Promise<T>) => Promise<ExecutorOutcome<T>> {
  const { operations, recheck: extraRecheck, recheckFor, reversibilityClassOf, pendingTimeoutMs, ...azOpts } = opts;
  const az = createAuthorizer(azOpts);
  const now = azOpts.now ?? Date.now;
  const timeoutMs = pendingTimeoutMs ?? OPERATION_PENDING_TIMEOUT_MS;
  const ok = operations && typeof operations.create === 'function' && typeof operations.get === 'function' && typeof operations.transition === 'function';
  const recheck = async (h: ExecutionHandle): Promise<RecheckResult> => {
    const grant = await azOpts.resolveGrant(h.pcactn.grant_ref, h.pcactn);
    if (!grant) return { ok: false, reason: 'the grant is no longer known' };
    const rv = await azOpts.hooks!.revocation!({ pcactn: h.pcactn, grant, nowEpoch: now() });
    if (!rv.enforced || !rv.ok) return { ok: false, reason: rv.enforced ? (rv.reason ?? 'the grant has been revoked') : 'revocation could not be checked' };
    // a registered plan must still be executable: not revoked, the principal's approval not expired
    const root = h.pcactn.plan?.root;
    if (azOpts.plans && typeof root === 'string' && (await azOpts.plans.get(h.pcactn.grant_ref, root))) {
      const ps = await azOpts.plans.check(h.pcactn.grant_ref, root, { nodeId: h.pcactn.plan.node_id, now: now() });
      if (!ps.executable) return { ok: false, reason: ps.reason ?? `plan is ${ps.state}` };
    }
    return extraRecheck ? extraRecheck(h) : { ok: true };
  };
  return async <T>(input: AuthorizeInput, fn: (h: ExecutionHandle) => T | Promise<T>): Promise<ExecutorOutcome<T>> => {
    if (!ok) return { status: 'refused', reason: 'createExecutor: missing required component: operations (fail closed)' };
    const r = await az(input);
    const cls = input?.operation ? reversibilityClassOf?.(input.operation) : undefined;
    if (r.allow) {
      return executeAuthorized(r, fn, {
        store: operations,
        operation: input.operation,
        recheck,
        ...(recheckFor !== undefined ? { recheckFor } : {}),
        ...(cls !== undefined ? { reversibilityClass: cls } : {}),
        pendingTimeoutMs: timeoutMs,
        now,
      });
    }
    const failed = Object.entries(r.verdict.checks).filter(([, s]) => s === 'fail').map(([k]) => k);
    if (r.status !== 403 || failed.length !== 1 || failed[0] !== 'replay') return { status: 'denied', authorization: r };
    // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
    let p: PCActn;
    try {
      const raw = input.pcactn ?? (azOpts.extract ?? defaultExtract)(input.request ?? { headers: {} });
      if (raw === null || raw === undefined) return { status: 'denied', authorization: r };
      p = typeof raw === 'string' ? decodePCActn(raw) : raw;
    } catch {
      return { status: 'denied', authorization: r };
    }
    const rec = await operations.get(hashCanonical(p));
    const want = input.operation;
    if (!rec || rec.verb !== want.verb || rec.resource !== want.resource || rec.params_digest !== hashCanonical(want.params ?? {})) {
      return { status: 'denied', authorization: r };
    }
    return fromRecord<T>(operations, rec, now(), timeoutMs);
  };
}
