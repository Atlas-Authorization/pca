/**
 * The undo-window coordinator (0.5): admission, the durable ledger, the human surface and the real rollback.
 * Spec: docs/pca/specs/undo-windows.md. The pure record, token, receipts and store contract are in `../undo.ts`.
 *
 *   admit     ELIGIBILITY. An action gets a veto window only when ALL of these hold, else it is irreversible (the normal
 *             path: a plain allow stays an allow, an escalation stays an escalation):
 *               - the policy for (operation, grant) does not turn windows off;
 *               - the signed reversibility class is `reversible` (an agent that signs `irreversible` is taken at its word; an
 *                 agent that signs `reversible` for an irreversible action is overruled by the definition below);
 *               - the `engine` (the verifier's own action definitions, e.g. `@atlasauth/pca-actions` `undoEngine`) returns a
 *                 plan: the definition is CONFIRMED by a pinned reviewer, its effective class for these params is
 *                 `reversible`, and it names a confirmed compensating action that can be derived before the effect runs;
 *               - the compensating action is AUTHORIZED under the original grant: the Policy VM (`decide`) releases it over
 *                 the original PCActn's verified chain (predicates, envelope, root and delegated caveats).
 *   open      writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the
 *             `opened` receipt, mints the one-click undo token and notifies the principal. A window nobody was told about
 *             is no window: a failed notification aborts the record and raises an alert.
 *   veto      a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves `open -> vetoed`
 *             exactly once and starts the compensation.
 *   compensate re-decides the compensating action under the grant AS IT STOOD AT ADMISSION (with the target the original's
 *             result names), then runs it at most once per attempt through the `operations` store and the `compensate`
 *             executor. Success: `compensated`, the budget reservation released with a signed `rollback`. Anything else:
 *             `compensation_failed`, the reservation kept and an alert raised (never silent).
 *   finalizeDue closes the windows whose time is up (`open -> finalized`) and commits their budget reservations.
 */
import type { Capability } from '../capability';
import { decodePCActn, encodePCActn, pcactnDigest, type PCActn } from '../pcactn';
import { b64u, hashCanonical } from '../hash';
import { publicKeyOf } from '../keys';
import { decide } from '../policy-vm';
import { classRank } from '../reversibility';
import type { ApprovalRender } from '../approval-render';
import type { ApprovalDispatcher } from '../approval-channels';
import type { StepUpRequest } from '../approvals';
import type { Obligation } from '../obligations';
import type { BudgetLedger, ReleaseEvent } from '../budget-ledger';
import type { SettlementRecord } from '../bond-settlement';
import {
  UndoError,
  compensationDigest,
  decodeUndoToken,
  encodeUndoToken,
  isUndoStore,
  resolveUndoWindow,
  signUndoToken,
  undoTokenCheck,
  undoTokenDigest,
  undoTransition,
  withReceipt,
  type UndoCompensation,
  type UndoRecord,
  type UndoStore,
  type UndoToken,
  type UndoTokenCheck,
  type UndoTransitionCode,
  type UndoTransitionEvent,
  type UndoVeto,
} from '../undo';
import type { OperationRecord, OperationStore } from './operations';
import type { PcaOperation } from './verify';

/** What the verifier's action definitions say about undoing an operation (null/undefined: not undoable = irreversible). */
export interface UndoPlan {
  /** Digest of the CONFIRMED definition of the original action. */
  def_digest: string;
  compensation: { verb: string; params: Record<string, unknown>; def_digest: string; target_param?: string };
  /** K7: the canonical render of the original action and H(R): what the principal is shown. */
  render?: ApprovalRender;
  render_digest?: string;
}

/** The source of confirmed reversibility. It must answer from SIGNED, reviewer-confirmed definitions only. */
export interface UndoEngine {
  plan(op: PcaOperation, ctx: { operationId: string }): UndoPlan | null | undefined | Promise<UndoPlan | null | undefined>;
}

export interface UndoPolicy {
  /** `always` (default): every eligible action gets a window. `escalations`: only an action that would have asked first. `off`. */
  mode?: 'always' | 'escalations' | 'off';
  /** The veto window (clamped into the coordinator's bounds; never below 30 s). */
  windowMs?: number;
  /** When the grant is revoked while windows are open: `keep` (default; the principal is told and can still veto) or `veto`. */
  onRevocation?: 'keep' | 'veto';
}

export interface UndoAdmission {
  id: string;
  opened_at: number;
  window_end: number;
  converted: boolean;
  plan: UndoPlan;
  compensation: UndoCompensation;
  pcactn: PCActn;
  grant: Capability;
  operation: PcaOperation;
}

/** What an allowed `authorize()` result carries when the action got a veto window (`decision` stays `allow`). */
export interface UndoWindowInfo {
  id: string;
  window_end: number;
  /** True when the window replaced a prior approval. */
  converted: boolean;
  compensation: { verb: string; resource: string };
  /** The encoded one-click undo token (also delivered to the principal). */
  token: string;
  /** The obligation the enforcement point accepts with this allow: report the effect, let the window run. */
  obligation: Obligation;
}

export type UndoNoticeKind = 'opened' | 'vetoed' | 'compensated' | 'compensation_failed' | 'finalized' | 'revoked';
export interface UndoNotice {
  kind: UndoNoticeKind;
  record: Omit<UndoRecord, 'pcactn' | 'receipts'>;
  /** `opened` only: the encoded token for the one-click undo link. */
  token?: string;
  render?: ApprovalRender;
}
export interface UndoNotifier {
  /** Resolves (never rejects) with whether at least one of the principal's channels accepted the notice. */
  notify(n: UndoNotice): Promise<{ delivered: boolean; reason?: string }>;
}
export type UndoAlertCode = 'compensation_failed' | 'notify_failed' | 'effect_unknown' | 'slash_after_window' | 'budget_settle_failed' | 'revoked_open_window' | 'compensation_denied' | 'veto_relay_failed';
export interface UndoAlert {
  level: 'critical' | 'warning';
  code: UndoAlertCode;
  record: string;
  reason: string;
}

/** What the compensating-action executor receives. */
export interface UndoCompensationCall {
  /** The compensating operation with its target filled in (when the definition names one). */
  operation: PcaOperation;
  /** The idempotency key of this attempt (pass it to the downstream call). */
  idempotencyKey: string;
  /** The original operation id (`undo_of`) and its reported result. */
  undoOf: string;
  originalResult?: unknown;
  record: Omit<UndoRecord, 'pcactn'>;
}

export interface UndoCoordinatorOptions {
  /** REQUIRED: the durable undo ledger (`durable: true`). */
  store: UndoStore;
  /** REQUIRED: confirmed reversibility and compensations (`@atlasauth/pca-actions` `undoEngine`). */
  engine: UndoEngine;
  /** REQUIRED: the undo service key (32-byte Ed25519 secret): signs tokens and receipts. */
  signerSecret: Uint8Array;
  /** REQUIRED: this resource server's audience (bound into the token). */
  audience: string;
  /** REQUIRED: the grant by reference, from YOUR store (the same function `authorize` uses). */
  resolveGrant: (grantRef: string, pcactn: PCActn) => Capability | null | undefined | Promise<Capability | null | undefined>;
  /** REQUIRED: runs a compensating action (your connector). Throw on failure. */
  compensate: (call: UndoCompensationCall) => unknown | Promise<unknown>;
  /** REQUIRED: at-most-once records for compensation attempts (shared and durable in production). */
  operations: OperationStore;
  /** REQUIRED: the principal's channels (`undoNotifierFromDispatcher`). */
  notifier: UndoNotifier;
  /** REQUIRED: where a failure that needs a human goes (pager, SIEM). Never silent. */
  alert: (a: UndoAlert) => void | Promise<void>;
  policy?: (op: PcaOperation, grant: Capability) => UndoPolicy | undefined | Promise<UndoPolicy | undefined>;
  window?: { minMs?: number; maxMs?: number; defaultMs?: number };
  /** The value of the compensating action's target parameter. Default: `effect.result.id` when it is a non-empty string. */
  resolveTarget?: (rec: UndoRecord) => string | undefined;
  /** Aggregate budgets held during the window: committed on finalize, released (with `evidence`) on compensation or abort. */
  budget?: { ledger: BudgetLedger; evidence?: (r: { key: string; id: string }, reason: 'rollback' | 'effect_not_run') => ReleaseEvent | undefined };
  /** Verifier-side PQ pins forwarded to the compensation decision. */
  pqPins?: Readonly<Record<string, string>>;
  /** A vetoed record whose effect was never reported is compensated anyway after this long (ms). Default 5 minutes. */
  effectTimeoutMs?: number;
  now?: () => number;
  /**
   * Vetoes received somewhere else (the hosted veto endpoint): read before every finalize sweep, and applied with their
   * receipt time. A relay that cannot be read finalizes NOTHING (a veto may be waiting). See {@link hostedUndoVetoRelay}.
   */
  relay?: { pending: () => Promise<readonly UndoRelayedVeto[]> };
  /** TESTS ONLY: accept a store whose `durable` is false (every open window is lost on restart). */
  insecureVolatileStore?: boolean;
}

/**
 * A veto taken by a relay: the principal's token and the time the relay received it. The token is verified here as of `at`
 * (so a veto made inside the window counts even when the relay is read after it closed); `at` is the only thing the relay is
 * trusted for, and it can never precede the window's opening or lie in the future.
 */
export interface UndoRelayedVeto {
  id: string;
  token: unknown;
  at: number;
}

export type VetoResult =
  | { ok: true; record: UndoRecord; replayed: boolean }
  | { ok: false; code: UndoTokenCheck | UndoTransitionCode | 'unknown'; reason: string };

export interface UndoCoordinator {
  readonly signerPublic: string;
  admit(a: { pcactn: PCActn; grant?: Capability; operation: PcaOperation; converted: boolean }): Promise<UndoAdmission | { refused: string }>;
  open(adm: UndoAdmission, extra?: { bond?: { ref: string; challengeEndsAt: number } }): Promise<UndoWindowInfo>;
  get(id: string): Promise<UndoRecord | undefined>;
  holdBudget(id: string, reservations: readonly { key: string; id: string }[]): Promise<UndoRecord>;
  recordEffect(id: string, result?: unknown): Promise<UndoRecord>;
  abort(id: string, reason: string): Promise<UndoRecord>;
  /** Veto with the one-click token (the principal) or as an authenticated operator of this server. */
  veto(id: string, by: { token: unknown; at?: number } | { operator: string }): Promise<VetoResult>;
  /** Apply the relay's pending vetoes now (also done by every `finalizeDue`). Throws when the relay cannot be read. */
  syncRelay(): Promise<VetoResult[]>;
  compensate(id: string): Promise<UndoRecord>;
  retry(id: string): Promise<UndoRecord>;
  finalizeDue(): Promise<string[]>;
  recover(): Promise<string[]>;
  onRevocation(grantRef: string): Promise<string[]>;
  rollbackOnSlash<P extends { claimId: string }>(bonds: { slashBond(params: P): Promise<SettlementRecord> }, params: P): Promise<{ settlement: SettlementRecord; veto: VetoResult }>;
}

const MAX_CAS = 64;
/** With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands). */
export const UNDO_RELAY_GRACE_MS = 60_000;
const strip = (r: UndoRecord): Omit<UndoRecord, 'pcactn' | 'receipts'> => {
  const { pcactn: _p, receipts: _r, ...rest } = r;
  return rest;
};

export function missingUndoComponents(o: Partial<UndoCoordinatorOptions> | null | undefined): string[] {
  const x = o ?? {};
  const m: string[] = [];
  if (!isUndoStore(x.store)) m.push('store');
  if (!x.engine || typeof x.engine.plan !== 'function') m.push('engine');
  if (!(x.signerSecret instanceof Uint8Array) || x.signerSecret.length !== 32) m.push('signerSecret');
  if (typeof x.audience !== 'string' || x.audience.length === 0) m.push('audience');
  if (typeof x.resolveGrant !== 'function') m.push('resolveGrant');
  if (typeof x.compensate !== 'function') m.push('compensate');
  const ops = x.operations as Partial<OperationStore> | undefined;
  if (!ops || typeof ops.create !== 'function' || typeof ops.get !== 'function' || typeof ops.transition !== 'function') m.push('operations');
  if (!x.notifier || typeof x.notifier.notify !== 'function') m.push('notifier');
  if (typeof x.alert !== 'function') m.push('alert');
  return m;
}

/** Build the coordinator. Throws `config` for a missing component and `not_durable` for a volatile store (fail closed). */
export function createUndoCoordinator(opts: UndoCoordinatorOptions): UndoCoordinator {
  const missing = missingUndoComponents(opts);
  if (missing.length) throw new UndoError('config', `undo coordinator: missing required component(s): ${missing.join(', ')}`);
  if (opts.store.durable !== true && opts.insecureVolatileStore !== true) throw new UndoError('not_durable', 'an undo ledger must be durable: a restart would lose every open window and its compensation');
  const { store, engine, signerSecret, notifier } = opts;
  const signerPublic = b64u(publicKeyOf(signerSecret));
  const clock = opts.now ?? Date.now;
  const now = (): number => {
    const t = Math.floor(clock());
    if (!Number.isSafeInteger(t)) throw new UndoError('invalid', 'the clock returned a non-finite time');
    return t;
  };
  const effectTimeoutMs = opts.effectTimeoutMs ?? 5 * 60_000;
  const alert = async (a: UndoAlert): Promise<void> => {
    try {
      await opts.alert(a);
    } catch {
      // an alert sink that throws is itself a failure the operator must see: write it where a host always looks
      console.error(`pca undo alert (${a.code}) for ${a.record}: ${a.reason}`);
    }
  };
  const notify = async (n: UndoNotice): Promise<{ delivered: boolean; reason?: string }> => {
    try {
      const r = await notifier.notify(n);
      return r && r.delivered === true ? { delivered: true } : { delivered: false, reason: r?.reason ?? 'no channel delivered the notice' };
    } catch (e) {
      return { delivered: false, reason: e instanceof Error ? e.message : 'notifier error' };
    }
  };

  /** Apply one event with compare-and-swap retries; returns the stored record and whether this call applied it. */
  const apply = async (id: string, ev: UndoTransitionEvent, checkAt?: number): Promise<{ record: UndoRecord; applied: boolean } | { refused: UndoTransitionCode | 'unknown'; reason: string }> => {
    for (let i = 0; i < MAX_CAS; i++) {
      const cur = await store.get(id);
      if (!cur) return { refused: 'unknown', reason: `no undo record ${id}` };
      const t = now();
      // a relayed veto is judged as of when the principal made it; its receipt is still written at the current time
      const tr = undoTransition(cur, ev, checkAt ?? t);
      if (tr.outcome === 'refused') return { refused: tr.code, reason: tr.reason };
      if (tr.outcome === 'replayed') return { record: tr.record, applied: false };
      const next = withReceipt(tr.record, tr.receipt, t, signerSecret);
      if (await store.replace(id, cur.ver, next)) return { record: next, applied: true };
    }
    throw new UndoError('conflict_exhausted', `undo record ${id} kept changing`);
  };
  const must = async (id: string, ev: UndoTransitionEvent): Promise<{ record: UndoRecord; applied: boolean }> => {
    const r = await apply(id, ev);
    if ('refused' in r) throw new UndoError('invalid', `${r.refused}: ${r.reason}`);
    return r;
  };

  const settleBudget = async (rec: UndoRecord, how: 'commit' | 'rollback' | 'effect_not_run'): Promise<void> => {
    const b = opts.budget;
    if (!b || !rec.budget?.length) return;
    for (const r of rec.budget) {
      try {
        const o = how === 'commit' ? await b.ledger.commit(r.key, r.id) : await b.ledger.release(r.key, r.id, b.evidence?.(r, how));
        if (o.outcome !== 'settled' && o.outcome !== 'replayed') await alert({ level: 'warning', code: 'budget_settle_failed', record: rec.id, reason: `${how} of ${r.key}/${r.id}: ${o.outcome}` });
      } catch (e) {
        await alert({ level: 'warning', code: 'budget_settle_failed', record: rec.id, reason: `${how} of ${r.key}/${r.id}: ${e instanceof Error ? e.message : 'error'}` });
      }
    }
  };

  const policyOf = async (op: PcaOperation, grant: Capability): Promise<UndoPolicy> => (opts.policy ? ((await opts.policy(op, grant)) ?? {}) : {});

  /** The Policy VM on the compensating action under the original chain, at `at` (the admission time). */
  const compensationAllowed = (pc: PCActn, grant: Capability, op: PcaOperation, at: number): { ok: boolean; reason: string } => {
    const d = decide({
      grant,
      trustedRoot: grant,
      chain: pc.cap_chain,
      ...(opts.pqPins !== undefined ? { pqPins: opts.pqPins } : {}),
      action: { action: { verb: op.verb, resource: op.resource, params: op.params ?? {} } },
      risk: {},
      budget: { B: 0, tau: at },
      now: at,
    });
    return d.releaseGuardianShare ? { ok: true, reason: '' } : { ok: false, reason: d.reasons.find((r) => !r.startsWith('risk input')) ?? 'the grant does not authorize the compensating action' };
  };

  const admit: UndoCoordinator['admit'] = async (a) => {
    try {
      const pc = a.pcactn;
      const op = a.operation;
      if (!pc || !op || typeof op.verb !== 'string' || typeof op.resource !== 'string') return { refused: 'no operation' };
      const grant = a.grant ?? (await opts.resolveGrant(pc.grant_ref, pc));
      if (!grant) return { refused: 'unknown grant' };
      const pol = await policyOf(op, grant);
      const mode = pol.mode ?? 'always';
      if (mode === 'off') return { refused: 'policy: undo windows are off' };
      if (mode === 'escalations' && !a.converted) return { refused: 'policy: windows only replace approvals' };
      // the stricter of the signed class and the definition applies: an agent signing `irreversible` is taken at its word
      if (classRank(pc.action?.reversibility_class) !== 0) return { refused: `the signed class is ${String(pc.action?.reversibility_class)}` };
      const id = pcactnDigest(pc);
      const plan = await engine.plan(op, { operationId: id });
      if (!plan) return { refused: 'not confirmed reversible, or no confirmed compensating action' };
      const comp: UndoCompensation = { verb: plan.compensation.verb, resource: op.resource, params: structuredClone(plan.compensation.params), undo_of: id, def_digest: plan.compensation.def_digest, ...(plan.compensation.target_param !== undefined ? { target_param: plan.compensation.target_param } : {}) };
      const t = now();
      const allowed = compensationAllowed(pc, grant, { verb: comp.verb, resource: comp.resource, params: comp.params }, t);
      if (!allowed.ok) return { refused: `the compensating action is not authorized under the grant: ${allowed.reason}` };
      const windowMs = resolveUndoWindow(pol.windowMs, opts.window);
      return { id, opened_at: t, window_end: t + windowMs, converted: a.converted, plan, compensation: comp, pcactn: pc, grant, operation: { verb: op.verb, resource: op.resource, params: structuredClone(op.params ?? {}) } };
    } catch (e) {
      return { refused: `undo admission error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
    }
  };

  const tokenOf = (rec: UndoRecord): UndoToken => signUndoToken(rec, signerSecret);
  const infoOf = (rec: UndoRecord): UndoWindowInfo => ({
    id: rec.id,
    window_end: rec.window_end,
    converted: rec.converted,
    compensation: { verb: rec.compensation.verb, resource: rec.compensation.resource },
    token: encodeUndoToken(tokenOf(rec)),
    obligation: { kind: 'undo_window', params: { id: rec.id, window_end: rec.window_end }, due: rec.window_end },
  });

  const open: UndoCoordinator['open'] = async (adm, extra) => {
    const chain = adm.pcactn.cap_chain;
    const windowEnd = extra?.bond ? Math.max(adm.window_end, Math.floor(extra.bond.challengeEndsAt)) : adm.window_end;
    const cdig = compensationDigest(adm.compensation);
    const base: UndoRecord = {
      v: 1,
      id: adm.id,
      aud: opts.audience,
      grant_ref: adm.pcactn.grant_ref,
      holder: chain[chain.length - 1]!.holder,
      principal: adm.grant.issuer,
      action: { verb: adm.operation.verb, resource: adm.operation.resource, params_digest: adm.pcactn.action.params_digest, def_digest: adm.plan.def_digest },
      compensation: adm.compensation,
      compensation_digest: cdig,
      ...(adm.plan.render_digest !== undefined ? { render_digest: adm.plan.render_digest } : {}),
      opened_at: adm.opened_at,
      window_end: windowEnd,
      converted: adm.converted,
      state: 'open',
      ver: 0,
      pcactn: encodePCActn(adm.pcactn),
      ...(extra?.bond ? { bond_ref: extra.bond.ref } : {}),
      attempt: 0,
      receipts: [],
    };
    const rec = withReceipt(base, { event: 'opened', note: adm.converted ? 'converted' : '' }, adm.opened_at, signerSecret);
    const c = await store.create(rec);
    if (!c.created) {
      // a retry of the same admission returns the same window; anything else is a different action under the same id
      if (c.record.compensation_digest !== cdig || c.record.state !== 'open') throw new UndoError('invalid', `undo record ${adm.id} already exists with other terms or state ${c.record.state}`);
      return infoOf(c.record);
    }
    const info = infoOf(rec);
    const n = await notify({ kind: 'opened', record: strip(rec), token: info.token, ...(adm.plan.render ? { render: adm.plan.render } : {}) });
    if (!n.delivered) {
      await apply(rec.id, { kind: 'abort', reason: 'notify_failed' });
      await alert({ level: 'critical', code: 'notify_failed', record: rec.id, reason: `the principal could not be told about the undo window: ${n.reason ?? 'not delivered'}` });
      throw new UndoError('invalid', `notify_failed: the undo window could not be announced (${n.reason ?? 'not delivered'})`);
    }
    return info;
  };

  const runCompensation = async (rec0: UndoRecord): Promise<UndoRecord> => {
    let rec = rec0;
    if (rec.state !== 'vetoed') return rec;
    const t = now();
    if (rec.effect === undefined && t - (rec.veto?.at ?? t) < effectTimeoutMs) return rec; // wait for the effect report (recordEffect resumes)
    const pc = decodePCActn(rec.pcactn);
    const grant = await opts.resolveGrant(rec.grant_ref, pc);
    const fail = async (reason: string, code: UndoAlertCode = 'compensation_failed'): Promise<UndoRecord> => {
      const r = await apply(rec.id, { kind: 'compensation_failed', reason });
      const out = 'refused' in r ? ((await store.get(rec.id)) ?? rec) : r.record;
      if (!('refused' in r) && r.applied) {
        await alert({ level: 'critical', code, record: rec.id, reason });
        await notify({ kind: 'compensation_failed', record: strip(out) });
      }
      return out;
    };
    if (!grant) return fail('the grant is no longer known: the compensation cannot be authorized', 'compensation_denied');
    const params: Record<string, unknown> = { ...rec.compensation.params };
    const tp = rec.compensation.target_param;
    if (tp !== undefined) {
      const target = opts.resolveTarget ? opts.resolveTarget(rec) : (() => {
        const r = rec.effect?.result as { id?: unknown } | undefined;
        return r && typeof r.id === 'string' && r.id.length > 0 ? r.id : undefined;
      })();
      if (target === undefined) return fail(`the target '${tp}' of the compensation is unknown (no effect result names it)`);
      params[tp] = target;
    }
    const op: PcaOperation = { verb: rec.compensation.verb, resource: rec.compensation.resource, params };
    const dec = compensationAllowed(pc, grant, op, rec.opened_at);
    if (!dec.ok) return fail(`the compensating action is not authorized under the grant: ${dec.reason}`, 'compensation_denied');
    // at most once per attempt: the operation record is created before the compensator runs
    const opId = hashCanonical({ d: 'atlas-pca/undo-compensation-op/v1', record: rec.id, attempt: rec.attempt });
    const orec: OperationRecord = { id: opId, state: 'pending', verb: op.verb, resource: op.resource, params_digest: hashCanonical(params), reversibility: 'irreversible', startedAt: t };
    const claimed = await opts.operations.create(orec);
    if (!claimed.created) {
      const prev = claimed.record;
      if (prev.state === 'committed') {
        const r = await apply(rec.id, { kind: 'compensated', result: prev.result });
        rec = 'refused' in r ? rec : r.record;
        return finishCompensated(rec);
      }
      if (prev.state === 'failed' || prev.state === 'uncertain') return fail(`compensation attempt ${rec.attempt} ${prev.state}: ${prev.error ?? ''}`);
      if (prev.state === 'aborted') {
        const r = await apply(rec.id, { kind: 'compensation_failed', reason: 'attempt never started' });
        if ('refused' in r) return rec;
        const again = await apply(rec.id, { kind: 'retry' });
        return 'refused' in again ? r.record : runCompensation(again.record);
      }
      // pending / executing: another worker holds it, or a crash; stale ones are settled by recover()
      if (t - (prev.executingAt ?? prev.startedAt) > effectTimeoutMs) {
        const settled: OperationRecord = prev.state === 'pending' ? { ...prev, state: 'aborted', error: 'never started', finishedAt: t } : { ...prev, state: 'uncertain', error: 'no outcome recorded: the compensation may or may not have run', finishedAt: t };
        await opts.operations.transition(prev.id, prev.state, settled);
        return runCompensation((await store.get(rec.id)) ?? rec);
      }
      return rec;
    }
    // re-read under the record: a concurrent retry or resolution wins
    const cur = await store.get(rec.id);
    if (!cur || cur.state !== 'vetoed' || cur.attempt !== rec.attempt) {
      await opts.operations.transition(opId, 'pending', { ...orec, state: 'aborted', error: 'the undo record moved on', finishedAt: now() });
      return cur ?? rec;
    }
    const running: OperationRecord = { ...orec, state: 'executing', executingAt: now() };
    if (!(await opts.operations.transition(opId, 'pending', running))) return (await store.get(rec.id)) ?? rec;
    let result: unknown;
    try {
      result = await opts.compensate({ operation: op, idempotencyKey: opId, undoOf: rec.id, ...(rec.effect?.result !== undefined ? { originalResult: rec.effect.result } : {}), record: (({ pcactn: _p, ...x }) => x)(cur) });
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      await opts.operations.transition(opId, 'executing', { ...running, state: 'failed', error, finishedAt: now() }).catch(() => false);
      return fail(`the compensating action failed: ${error}`);
    }
    await opts.operations.transition(opId, 'executing', { ...running, state: 'committed', result, finishedAt: now() }).catch(() => false);
    const r = await apply(rec.id, { kind: 'compensated', ...(result !== undefined ? { result } : {}) });
    if ('refused' in r) return (await store.get(rec.id)) ?? rec;
    return finishCompensated(r.record);
  };
  const finishCompensated = async (rec: UndoRecord): Promise<UndoRecord> => {
    if (rec.state === 'compensated') {
      await settleBudget(rec, 'rollback');
      await notify({ kind: 'compensated', record: strip(rec) });
    }
    return rec;
  };

  const veto = async (id: string, by: { token: unknown; at?: number } | { operator: string } | { veto: UndoVeto }): Promise<VetoResult> => {
    try {
      const cur = await store.get(id);
      if (!cur) return { ok: false, code: 'unknown', reason: `no undo record ${id}` };
      let v: UndoVeto;
      let t = now();
      let checkAt: number | undefined;
      if ('token' in by) {
        if (by.at !== undefined) {
          if (!Number.isSafeInteger(by.at) || by.at > t || by.at < cur.opened_at) return { ok: false, code: 'malformed', reason: 'a relayed veto time must lie between the opening of the window and now' };
          t = by.at;
          checkAt = by.at;
        }
        const tok = typeof by.token === 'string' ? decodeUndoToken(by.token) : by.token;
        const chk = undoTokenCheck(tok, signerPublic, cur, t);
        if (chk !== 'ok') return { ok: false, code: chk, reason: `the undo token was refused (${chk})` };
        v = { at: t, via: 'token', by: cur.principal, evidence: undoTokenDigest(tok as UndoToken) };
      } else if ('operator' in by) {
        if (typeof by.operator !== 'string' || by.operator.length === 0) return { ok: false, code: 'malformed', reason: 'an operator veto names the operator' };
        v = { at: t, via: 'operator', by: by.operator };
      } else v = { ...by.veto, at: t };
      const r = await apply(id, { kind: 'veto', veto: v }, checkAt);
      if ('refused' in r) return { ok: false, code: r.refused, reason: r.reason };
      if (r.applied) await notify({ kind: 'vetoed', record: strip(r.record) });
      const done = await runCompensation(r.record);
      return { ok: true, record: done, replayed: !r.applied };
    } catch (e) {
      return { ok: false, code: 'malformed', reason: `veto error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
    }
  };

  const syncRelay = async (): Promise<VetoResult[]> => {
    if (!opts.relay) return [];
    const list = await opts.relay.pending();
    if (!Array.isArray(list)) throw new UndoError('invalid', 'the veto relay returned no list');
    const out: VetoResult[] = [];
    for (const x of list) {
      if (!x || typeof x.id !== 'string') continue;
      // a forged or late relay entry is refused by the same checks as any veto
      out.push(await veto(x.id, { token: x.token, at: x.at }));
    }
    return out;
  };

  const coordinator: UndoCoordinator = {
    signerPublic,
    syncRelay,
    admit,
    open,
    get: (id) => store.get(id),
    async holdBudget(id, reservations) {
      for (let i = 0; i < MAX_CAS; i++) {
        const cur = await store.get(id);
        if (!cur) throw new UndoError('invalid', `no undo record ${id}`);
        if (cur.state !== 'open' && cur.state !== 'vetoed') throw new UndoError('invalid', `a ${cur.state} record holds no budget`);
        const next: UndoRecord = { ...cur, budget: [...(cur.budget ?? []), ...reservations.map((r) => ({ key: r.key, id: r.id }))], ver: cur.ver + 1 };
        if (await store.replace(id, cur.ver, next)) return next;
      }
      throw new UndoError('conflict_exhausted', `undo record ${id} kept changing`);
    },
    async recordEffect(id, result) {
      const r = await must(id, { kind: 'effect', ...(result !== undefined ? { result } : {}) });
      // a veto that arrived while the effect was running is acted on now
      return r.record.state === 'vetoed' ? runCompensation(r.record) : r.record;
    },
    async abort(id, reason) {
      const r = await must(id, { kind: 'abort', reason });
      if (r.applied) await settleBudget(r.record, 'effect_not_run');
      return r.record;
    },
    veto,
    async compensate(id) {
      const cur = await store.get(id);
      if (!cur) throw new UndoError('invalid', `no undo record ${id}`);
      return runCompensation(cur);
    },
    async retry(id) {
      const r = await must(id, { kind: 'retry' });
      return runCompensation(r.record);
    },
    async finalizeDue() {
      const out: string[] = [];
      try {
        await syncRelay();
      } catch (e) {
        // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
        await alert({ level: 'critical', code: 'veto_relay_failed', record: '*', reason: `the veto relay could not be read; no window was finalized: ${e instanceof Error ? e.message : 'error'}` });
        return out;
      }
      // with a relay, a veto accepted there just before the window closed may still be in flight: wait out a grace period
      for (const rec of await store.list({ state: 'open', windowEndedBy: now() - 1 - (opts.relay ? UNDO_RELAY_GRACE_MS : 0) })) {
        const r = await apply(rec.id, { kind: 'finalize' });
        if ('refused' in r || !r.applied) continue;
        out.push(rec.id);
        if (r.record.effect === undefined) await alert({ level: 'warning', code: 'effect_unknown', record: rec.id, reason: 'the window closed without an effect report: reconcile the original operation' });
        await settleBudget(r.record, 'commit');
        await notify({ kind: 'finalized', record: strip(r.record) });
      }
      return out;
    },
    async recover() {
      const out: string[] = [];
      for (const rec of await store.list({ state: 'vetoed' })) {
        const r = await runCompensation(rec);
        if (r.state !== 'vetoed') out.push(rec.id);
      }
      out.push(...(await coordinator.finalizeDue()));
      return out;
    },
    async onRevocation(grantRef) {
      const out: string[] = [];
      for (const rec of await store.list({ state: 'open', grantRef })) {
        const pc = decodePCActn(rec.pcactn);
        const grant = await opts.resolveGrant(rec.grant_ref, pc);
        const pol = grant ? await policyOf({ verb: rec.action.verb, resource: rec.action.resource }, grant) : {};
        if ((pol.onRevocation ?? 'keep') === 'veto') {
          const v = await veto(rec.id, { veto: { at: 0, via: 'revocation', by: grantRef } });
          if (v.ok) out.push(rec.id);
        } else {
          await alert({ level: 'warning', code: 'revoked_open_window', record: rec.id, reason: `grant ${grantRef} was revoked while this window is open; the principal can still undo it` });
          await notify({ kind: 'revoked', record: strip(rec) });
        }
      }
      return out;
    },
    async rollbackOnSlash(bonds, params) {
      // the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window; only then is anything undone
      const settlement = await bonds.slashBond(params);
      const evidence = hashCanonical({ d: 'atlas-pca/undo-slash-ref/v1', settlement });
      const recs = await store.list({ state: 'open', bondRef: params.claimId });
      const target = recs[0] ?? (await store.get(params.claimId));
      if (!target) return { settlement, veto: { ok: false, code: 'unknown', reason: `no undo record for bond ${params.claimId}` } };
      const v = await veto(target.id, { veto: { at: 0, via: 'fraud_proof', by: params.claimId, evidence } });
      if (!v.ok) await alert({ level: 'critical', code: 'slash_after_window', record: target.id, reason: `the bond was slashed but the effect could not be rolled back: ${v.reason}` });
      return { settlement, veto: v };
    },
  };
  return coordinator;
}

/**
 * Execute an allowed `authorize()` result that carries an undo window, and report the effect to the ledger: a committed
 * effect is recorded (its result names the compensation target), an effect that failed or never started aborts the window
 * (nothing to undo; held budget released). Use it in place of a bare `executeAuthorized` for undo-windowed actions.
 */
export async function reportUndoEffect(undo: UndoCoordinator, id: string, outcome: { status: string; result?: unknown }): Promise<UndoRecord> {
  if (outcome.status === 'committed') return undo.recordEffect(id, outcome.result);
  if (outcome.status === 'failed' || outcome.status === 'aborted' || outcome.status === 'refused') return undo.abort(id, `effect_${outcome.status}`);
  // pending / uncertain: unknown; the window keeps running and finalizeDue alerts if it closes without a report
  const r = await undo.get(id);
  if (!r) throw new UndoError('invalid', `no undo record ${id}`);
  return r;
}

/**
 * An {@link UndoNotifier} over the existing approval channels (Slack, webhook, email, SMS, push). The notice becomes a
 * step-up-shaped message whose link is the one-click undo URL and whose render is the WYSIWYS render of the action.
 */
export function undoNotifierFromDispatcher(dispatcher: ApprovalDispatcher, cfg: { undoUrl: (token: string, id: string) => string; inboxUrl?: string }): UndoNotifier {
  return {
    async notify(n) {
      const r = n.record;
      const until = new Date(r.window_end).toISOString();
      const reason =
        n.kind === 'opened'
          ? `Already done: ${r.action.verb} on ${r.action.resource}. You can undo it until ${until}.`
          : n.kind === 'vetoed'
            ? `Undo started for ${r.action.verb} on ${r.action.resource}.`
            : n.kind === 'compensated'
              ? `Undone: ${r.action.verb} on ${r.action.resource}.`
              : n.kind === 'compensation_failed'
                ? `UNDO FAILED for ${r.action.verb} on ${r.action.resource}: ${r.outcome?.reason ?? 'unknown'}. An operator has been alerted.`
                : n.kind === 'revoked'
                  ? `The agent's grant was revoked. ${r.action.verb} on ${r.action.resource} can still be undone until ${until}.`
                  : `Final: ${r.action.verb} on ${r.action.resource} can no longer be undone.`;
      const req: StepUpRequest = {
        id: `undo:${r.id}:${n.kind}`,
        verb: r.action.verb,
        resource: r.action.resource,
        tier: 3,
        reason,
        goalCommit: '',
        lineage: { goalCommit: '', goalVerified: false, chain: [{ kind: 'action', label: `${r.action.verb} ${r.action.resource}`, detail: `undo: ${r.compensation.verb}` }], because: reason },
        r: 0,
        requestedAt: r.opened_at,
        ...(n.render !== undefined && r.render_digest !== undefined ? { render: n.render, renderDigest: r.render_digest } : {}),
      };
      const link = n.kind === 'opened' && n.token !== undefined ? cfg.undoUrl(n.token, r.id) : cfg.inboxUrl;
      const out = await dispatcher.notifyAll(req, { ...(link !== undefined ? { inboxUrl: link } : {}) });
      const ok = out.some((d) => d.delivered);
      return ok ? { delivered: true } : { delivered: false, reason: out.map((d) => `${d.kind}: ${d.reason ?? 'not delivered'}`).join('; ') || 'no enabled channel' };
    },
  };
}

/** The undo service key's public half, for verifying tokens and receipts elsewhere (e.g. the hosted veto route). */
export const undoSignerPublic = (secret: Uint8Array): string => b64u(publicKeyOf(secret));

/** The HTTP transport of {@link hostedUndoVetoRelay} (defaults to `globalThis.fetch`). */
export type UndoRelayFetch = (url: string, init: { method: string; headers: Record<string, string> }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * The relay over a hosted undo ledger: `GET {baseUrl}/v1/pca/undo/vetoes` with the instance secret key. Pass it as
 * `createUndoCoordinator({ relay })`. A non-2xx answer or a malformed body throws (and so finalizes nothing).
 */
export function hostedUndoVetoRelay(cfg: { baseUrl: string; secretKey: string; fetch?: UndoRelayFetch; limit?: number }): { pending: () => Promise<UndoRelayedVeto[]> } {
  const f = cfg.fetch ?? ((globalThis as unknown as { fetch?: UndoRelayFetch }).fetch as UndoRelayFetch | undefined);
  const base = cfg.baseUrl.replace(/\/+$/, '');
  return {
    async pending() {
      if (!f) throw new UndoError('config', 'no fetch available: pass one to hostedUndoVetoRelay');
      const res = await f(`${base}/v1/pca/undo/vetoes?limit=${Math.min(200, Math.max(1, Math.trunc(cfg.limit ?? 200)))}`, { method: 'GET', headers: { authorization: `Bearer ${cfg.secretKey}`, accept: 'application/json' } });
      if (!res.ok) throw new UndoError('invalid', `the veto relay answered ${res.status}`);
      const body = (await res.json()) as { data?: unknown };
      if (!body || !Array.isArray(body.data)) throw new UndoError('invalid', 'the veto relay answered without a data list');
      const out: UndoRelayedVeto[] = [];
      for (const row of body.data as { record_id?: unknown; veto?: { token?: unknown; at?: unknown } }[]) {
        if (typeof row?.record_id !== 'string' || typeof row.veto?.token !== 'string' || typeof row.veto.at !== 'number') throw new UndoError('invalid', 'the veto relay answered a malformed entry');
        out.push({ id: row.record_id, token: row.veto.token, at: row.veto.at });
      }
      return out;
    },
  };
}
