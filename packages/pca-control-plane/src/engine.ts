/**
 * The control plane engine. Storage-agnostic and clock-injected; it never touches the network.
 *
 *   ingest(envelope)     authenticate a source's batch, fold it into agent and fleet baselines, issue tightening directives
 *   freeze / issue       an operator's one-call tighten or freeze (authenticated by the caller; the engine signs)
 *   lift(humanAction)    the only loosening: a pinned human's signed, single-use, directive-bound action
 *
 * Automatic paths only ever call `write` (a tightening directive); there is no automatic route to `liftDirective`.
 */
import { b64u, hashCanonicalLenient, publicKeyOf } from '@atlasauth/pca';
import { INITIAL_IMMUNE_STATE, observe, validateImmuneState, type ImmuneState } from '@atlasauth/pca/ext/research';
import { atLeastAsStrict, claimError, signDirective, verifyDirective, MAX_DIRECTIVE_TTL_MS } from './directive';
import { DEFAULT_EVAL_CONFIG, evaluateAgent, type EvalConfig } from './evaluate';
import { effectiveOf, NO_EFFECT, type Effective } from './hooks';
import { humanActionDigest, verifyHumanAction, type HumanAction } from './human';
import { eventError, verifyEnvelope } from './ingest';
import type { DirectiveEvent } from './sinks';
import type { ControlPlaneStore } from './store';
import { FLEET, type AgentRecord, type ControlEvent, type Directive, type DirectiveKind, type DirectiveParams, type FleetRecord, type StoredDirective, type Subject } from './types';

export interface ControlPlaneOptions {
  store: ControlPlaneStore;
  /** The control plane's Ed25519 secret; directives are signed with it and consumers pin its public key. */
  signer: Uint8Array;
  /** source id -> pinned Ed25519 public key (b64u). A batch from any other source is refused. */
  sources: Readonly<Record<string, string>>;
  /** Earlier control-plane keys (b64u) whose still-unexpired directives and freezes stay in force after a key rotation. */
  previousSigners?: readonly string[];
  /** Pinned human keys (b64u). With none, nothing can ever be lifted. */
  humans: readonly string[];
  now?: () => number;
  eval?: Partial<EvalConfig>;
  /** Events per batch. Default 256. */
  maxBatch?: number;
  /** Tolerated clock skew on a batch and on its events. Default 5 minutes. */
  skewMs?: number;
  /** Events older than this are dropped as stale. Default 24 hours. */
  maxEventAgeMs?: number;
  /** Life of an automatic directive; a still-justified one is renewed at half-life. Default 15 minutes. */
  directiveTtlMs?: number;
  /** New agents beyond this many are folded into the fleet baseline only. Default 10000. */
  maxAgents?: number;
  /** Timeline entries kept per agent. Default 100. */
  timelineLimit?: number;
  /** Called for every issued or lifted directive (webhook / SIEM / signals). A throw is contained and reported to `onError`. */
  onDirective?: (e: DirectiveEvent) => void | Promise<void>;
  onError?: (err: unknown, what: string) => void;
}

export type IngestRefusal = 'malformed' | 'source' | 'signature' | 'too_large' | 'stale' | 'future' | 'replayed';
export interface IngestReport {
  ok: true;
  accepted: number;
  dropped: { stale: number; duplicate: number; malformed: number; agent_cap: number };
  directives: Directive[];
}
export type IngestResult = IngestReport | { ok: false; reason: IngestRefusal };

export type LiftResult = { ok: true; directive: Directive } | { ok: false; reason: 'malformed' | 'human' | 'signature' | 'expired' | 'not_yet_valid' | 'too_long' | 'replayed' | 'unknown_directive' | 'wrong_kind' | 'already_lifted' };

export interface IssueSpec {
  kind: DirectiveKind;
  subject: Subject;
  params?: DirectiveParams;
  reason: string;
  /** Who is asking (an operator id). */
  by: string;
  /** Life in ms for an expiring kind. Default: the automatic life. */
  ttlMs?: number;
}

const MAX_LIST = 500;
const KEEP = 8;

const push = <T>(arr: T[], v: T, max: number): T[] => (arr.includes(v) ? arr : [...arr, v].slice(-max));

export class ControlPlane {
  readonly publicKey: string;
  private readonly signers: readonly string[];
  private readonly o: Required<Pick<ControlPlaneOptions, 'maxBatch' | 'skewMs' | 'maxEventAgeMs' | 'directiveTtlMs' | 'maxAgents' | 'timelineLimit'>>;
  private readonly cfg: EvalConfig;
  private readonly now: () => number;

  constructor(private readonly opts: ControlPlaneOptions) {
    this.publicKey = b64u(publicKeyOf(opts.signer));
    this.signers = [this.publicKey, ...(opts.previousSigners ?? [])];
    this.now = opts.now ?? Date.now;
    this.cfg = { ...DEFAULT_EVAL_CONFIG, ...opts.eval };
    this.o = {
      maxBatch: opts.maxBatch ?? 256,
      skewMs: opts.skewMs ?? 5 * 60_000,
      maxEventAgeMs: opts.maxEventAgeMs ?? 24 * 3_600_000,
      directiveTtlMs: Math.min(opts.directiveTtlMs ?? 15 * 60_000, MAX_DIRECTIVE_TTL_MS),
      maxAgents: opts.maxAgents ?? 10_000,
      timelineLimit: opts.timelineLimit ?? 100,
    };
  }

  // ---- ingest ---------------------------------------------------------------------------------------------------

  /** Authenticate and fold one batch. Nothing is stored, and no sequence is consumed, until the signature has verified. */
  async ingest(envelope: unknown): Promise<IngestResult> {
    const v = verifyEnvelope(envelope, this.opts.sources, this.o.maxBatch);
    if (!v.ok) return v;
    const e = v.envelope;
    const now = this.now();
    if (e.sent_at > now + this.o.skewMs) return { ok: false, reason: 'future' };
    if (e.sent_at < now - this.o.skewMs) return { ok: false, reason: 'stale' };
    if (!(await this.opts.store.advanceSourceSeq(e.source, e.seq))) return { ok: false, reason: 'replayed' };
    return this.ingestEvents(e.events);
  }

  /**
   * Fold events whose source the CALLER has already authenticated ({@link ingest} does). Every event that is not
   * well formed, including a non-finite risk or time, counts against its agent as a violation at maximum risk, so
   * garbage tightens instead of reading as calm.
   */
  async ingestEvents(events: readonly unknown[]): Promise<IngestReport> {
    const now = this.now();
    const dropped = { stale: 0, duplicate: 0, malformed: 0, agent_cap: 0 };
    const seen = new Set<string>();
    const byAgent = new Map<string, Array<{ e: ControlEvent | null; bad: boolean }>>();
    let fleetEvents = 0;
    let fleetMalformed = 0;
    const prevFleet = await this.opts.store.getFleet();
    // a stored fleet state that does not validate is replaced by a violation-saturated one: fail closed, not calm
    const failed = prevFleet !== undefined && validateImmuneState(prevFleet.immune) !== null;
    let fleetState: ImmuneState = prevFleet && !failed ? prevFleet.immune : INITIAL_IMMUNE_STATE;
    const fleetFold = (r: number, at: number, denied: boolean, stepUp: boolean, prev: ImmuneState) => observe(prev, { r, at, denied, stepUp }, this.cfg.immune);

    for (const raw of events) {
      const bad = eventError(raw);
      const agentId = raw !== null && typeof raw === 'object' && typeof (raw as ControlEvent).agent === 'string' && (raw as ControlEvent).agent.length > 0 && (raw as ControlEvent).agent.length <= 256 ? (raw as ControlEvent).agent : undefined;
      if (bad === null) {
        const ev = raw as ControlEvent;
        if (seen.has(ev.id)) {
          dropped.duplicate++;
          continue;
        }
        seen.add(ev.id);
        if (ev.at > now + this.o.skewMs) {
          // a future-dated event cannot be placed on the timeline: treat it as malformed
          dropped.malformed++;
          fleetMalformed++;
          fleetState = fleetFold(1, now, true, false, fleetState);
          if (agentId) (byAgent.get(agentId) ?? byAgent.set(agentId, []).get(agentId)!).push({ e: null, bad: true });
          continue;
        }
        if (ev.at < now - this.o.maxEventAgeMs) {
          dropped.stale++;
          continue;
        }
        fleetEvents++;
        fleetState = fleetFold(ev.r, ev.at, ev.outcome === 'deny', ev.outcome === 'step_up', fleetState);
        (byAgent.get(ev.agent) ?? byAgent.set(ev.agent, []).get(ev.agent)!).push({ e: ev, bad: false });
      } else {
        dropped.malformed++;
        fleetMalformed++;
        fleetState = fleetFold(1, now, true, false, fleetState);
        if (agentId) (byAgent.get(agentId) ?? byAgent.set(agentId, []).get(agentId)!).push({ e: null, bad: true });
      }
    }

    let accepted = 0;
    let known = await this.opts.store.countAgents();
    const touched: AgentRecord[] = [];
    for (const [agent, items] of byAgent) {
      const existing = await this.opts.store.getAgent(agent);
      if (!existing && known >= this.o.maxAgents) {
        dropped.agent_cap += items.length;
        continue;
      }
      if (!existing) known++;
      const rec = await this.opts.store.updateAgent(agent, (prev) => this.foldAgent(agent, prev, items, now));
      accepted += items.filter((i) => !i.bad).length;
      touched.push(rec);
    }

    const fleet = await this.opts.store.updateFleet((prev) => ({
      immune: failed ? { ...INITIAL_IMMUNE_STATE, denies: 1e6, stepUps: 1e6, seeded: true, lastAt: now } : fleetState,
      agents: Math.max(known, prev?.agents ?? 0),
      events: (prev?.events ?? 0) + fleetEvents,
      malformed: (prev?.malformed ?? 0) + fleetMalformed,
      ver: 0,
    }));

    const directives: Directive[] = [];
    for (const rec of touched) directives.push(...(await this.react(rec, fleet, now)));
    return { ok: true, accepted, dropped, directives };
  }

  private foldAgent(agent: string, prev: AgentRecord | undefined, items: ReadonlyArray<{ e: ControlEvent | null; bad: boolean }>, now: number): AgentRecord {
    let r: AgentRecord = prev ?? { agent, immune: INITIAL_IMMUNE_STATE, first_seen: now, last_seen: now, actions: 0, autos: 0, step_ups: 0, denies: 0, executed: 0, malformed: 0, total_risk: 0, score: 0, level: 'calm', signals: [], sessions: [], grants: [], timeline: [], ver: 0 };
    r = { ...r, sessions: [...r.sessions], grants: [...r.grants], timeline: [...r.timeline] };
    // a stored immune state that does not validate is never reset to calm: it reads as saturated violations
    if (validateImmuneState(r.immune) !== null) r.immune = { ...INITIAL_IMMUNE_STATE, denies: 1e6, stepUps: 1e6, seeded: true, lastAt: now };
    for (const { e, bad } of items) {
      if (bad || e === null) {
        r.immune = observe(r.immune, { r: 1, at: now, denied: true }, this.cfg.immune);
        r.malformed++;
        r.total_risk += 1;
        r.last_seen = Math.max(r.last_seen, now);
        r.timeline.push({ at: now, verb: '', resource: '', outcome: 'malformed', r: 1 });
        continue;
      }
      r.immune = observe(r.immune, { r: e.r, at: e.at, stepUp: e.outcome === 'step_up', denied: e.outcome === 'deny' }, this.cfg.immune);
      r.actions++;
      if (e.outcome === 'auto') r.autos++;
      else if (e.outcome === 'step_up') r.step_ups++;
      else if (e.outcome === 'deny') r.denies++;
      else r.executed++;
      r.total_risk += e.r;
      r.first_seen = Math.min(r.first_seen, e.at);
      r.last_seen = Math.max(r.last_seen, e.at);
      if (e.session) r.sessions = push(r.sessions, e.session, KEEP);
      if (e.grant) r.grants = push(r.grants, e.grant, KEEP);
      r.timeline.push({ at: e.at, verb: e.verb, resource: e.resource, outcome: e.outcome, r: e.r });
    }
    r.timeline = r.timeline.sort((a, b) => a.at - b.at).slice(-this.o.timelineLimit);
    return r;
  }

  /** Evaluate one agent and issue what its threat justifies. Tighten-only; skips a directive that an active one already covers. */
  private async react(rec: AgentRecord, fleet: FleetRecord, now: number): Promise<Directive[]> {
    const ev = evaluateAgent(rec, fleet, this.cfg);
    if (rec.score !== ev.score || rec.level !== ev.level) {
      await this.opts.store.updateAgent(rec.agent, (p) => ({ ...(p ?? rec), score: ev.score, level: ev.level, signals: ev.signals.slice(0, 8) }));
    }
    const out: Directive[] = [];
    if (ev.desired.length === 0) return out;
    const subject: Subject = { kind: 'agent', id: rec.agent };
    const active = await this.opts.store.listDirectives({ subjects: [subject], activeAt: now, limit: MAX_LIST });
    const evidence = hashCanonicalLenient({ agent: rec.agent, ver: rec.ver, score: ev.score });
    for (const cand of ev.desired) {
      const reason = `${ev.level}: ${ev.signals.join('; ') || `threat score ${ev.score.toFixed(2)}`}`;
      const covered = active.some(({ directive: a }) => {
        if (a.kind !== cand.kind) return false;
        if (a.kind === 'freeze' || a.kind === 'require_step_up') return a.exp === undefined || a.exp - now > this.o.directiveTtlMs / 2;
        return atLeastAsStrict(a, { ...a, params: cand.params }) && (a.exp ?? Infinity) - now > this.o.directiveTtlMs / 2;
      });
      if (covered) continue;
      const d = await this.write({ kind: cand.kind, subject, params: cand.params, cause: 'auto', by: 'control-plane:immune', reason, evidence }, now, this.o.directiveTtlMs);
      if (d) out.push(d);
    }
    return out;
  }

  private async write(c: { kind: DirectiveKind; subject: Subject; params: DirectiveParams; cause: 'auto' | 'operator'; by: string; reason: string; evidence: string }, now: number, ttlMs: number): Promise<Directive | undefined> {
    const seq = await this.opts.store.nextSeq();
    const claim = { v: 1 as const, ...c, reason: c.reason.slice(0, 512), iat: now, ...(c.kind === 'freeze' ? {} : { exp: now + ttlMs }), seq };
    const d = signDirective(this.opts.signer, claim);
    const res = await this.opts.store.putDirective(d);
    if (!res.created) return undefined;
    await this.emit({ type: 'directive.issued', at: now, directive: d });
    return d;
  }

  private async emit(e: DirectiveEvent): Promise<void> {
    if (!this.opts.onDirective) return;
    try {
      await this.opts.onDirective(e);
    } catch (err) {
      this.opts.onError?.(err, 'onDirective');
    }
  }

  // ---- operator actions -----------------------------------------------------------------------------------------

  /** Issue a tightening directive for a subject. The caller has authenticated the operator. Throws on anything that would loosen. */
  async issue(spec: IssueSpec): Promise<{ created: boolean; directive: Directive }> {
    const now = this.now();
    const params = spec.params ?? {};
    const ttl = spec.ttlMs ?? this.o.directiveTtlMs;
    const probe = { v: 1 as const, kind: spec.kind, subject: spec.subject, params, cause: 'operator' as const, by: spec.by, reason: spec.reason, evidence: '', iat: now, ...(spec.kind === 'freeze' ? {} : { exp: now + ttl }), seq: 1, signer: this.publicKey };
    const bad = claimError(probe);
    if (bad) throw new RangeError(`issue: ${bad}`);
    const seq = await this.opts.store.nextSeq();
    const d = signDirective(this.opts.signer, { ...probe, seq });
    const res = await this.opts.store.putDirective(d);
    if (!res.created) return { created: false, directive: res.existing.directive };
    await this.emit({ type: 'directive.issued', at: now, directive: d });
    return { created: true, directive: d };
  }

  /** One-call freeze. Idempotent: freezing a frozen subject returns the freeze already in force. */
  freeze(subject: Subject, by: string, reason = 'operator freeze'): Promise<{ created: boolean; directive: Directive }> {
    return this.issue({ kind: 'freeze', subject, by, reason });
  }

  /** Freeze everything. */
  freezeFleet(by: string, reason = 'operator fleet freeze') {
    return this.freeze(FLEET, by, reason);
  }

  /**
   * Lift a freeze (`unfreeze`) or revoke an expiring directive (`revoke`) with a pinned human's signed action. The
   * signature, window, key, single-use nonce and the directive's kind are all checked; the first valid action wins a race.
   */
  async lift(action: unknown): Promise<LiftResult> {
    const now = this.now();
    const v = verifyHumanAction(action, { humans: this.opts.humans, now });
    if (!v.ok) return { ok: false, reason: v.reason };
    const a = action as HumanAction;
    const stored = await this.opts.store.getDirective(a.directive);
    if (!stored) return { ok: false, reason: 'unknown_directive' };
    if ((a.op === 'unfreeze') !== (stored.directive.kind === 'freeze')) return { ok: false, reason: 'wrong_kind' };
    if (stored.lift) return { ok: false, reason: 'already_lifted' };
    if (!(await this.opts.store.consumeNonce(`human:${a.human}:${a.nonce}`, a.exp + this.o.skewMs, now))) return { ok: false, reason: 'replayed' };
    const lift = { op: a.op, at: now, human: a.human, nonce: a.nonce, action: humanActionDigest(a) };
    if (!(await this.opts.store.liftDirective(a.directive, lift))) return { ok: false, reason: 'already_lifted' };
    await this.emit({ type: 'directive.lifted', at: now, directive: stored.directive, lift });
    return { ok: true, directive: stored.directive };
  }

  // ---- reads ----------------------------------------------------------------------------------------------------

  /** Directives in force now (verified, unlifted, unexpired) for the given subjects, or every subject. */
  async activeDirectives(subjects?: readonly Subject[]): Promise<Directive[]> {
    const now = this.now();
    const rows = await this.opts.store.listDirectives({ ...(subjects ? { subjects } : {}), activeAt: now, limit: MAX_LIST });
    return rows.map((r) => r.directive).filter((d) => this.signers.some((signer) => verifyDirective(d, { signer, now }).ok));
  }

  /** What applies to one actor: its agent, session and grant directives plus the fleet's. */
  async effective(who: { agent?: string; session?: string; grant?: string }): Promise<{ effective: Effective; invalid: number }> {
    const subjects: Subject[] = [FLEET];
    if (who.agent) subjects.push({ kind: 'agent', id: who.agent });
    if (who.session) subjects.push({ kind: 'session', id: who.session });
    if (who.grant) subjects.push({ kind: 'grant', id: who.grant });
    const rows = await this.opts.store.listDirectives({ subjects, activeAt: this.now(), limit: MAX_LIST });
    return rows.length === 0 ? { effective: { ...NO_EFFECT, directives: [] }, invalid: 0 } : effectiveOf(rows.map((r) => r.directive), { signer: this.signers, now: this.now() });
  }

  /** The threat view of one agent: its record, the directives on it (newest first) and what applies now. */
  async agentView(agent: string): Promise<{ agent: AgentRecord; directives: StoredDirective[]; effective: Effective } | undefined> {
    const rec = await this.opts.store.getAgent(agent);
    if (!rec) return undefined;
    const directives = await this.opts.store.listDirectives({ subjects: [{ kind: 'agent', id: agent }], order: 'desc', limit: 100 });
    return { agent: rec, directives, effective: (await this.effective({ agent })).effective };
  }

  /** The fleet overview: every agent by threat, the fleet baseline and the freezes in force. */
  async overview(limit = 100): Promise<{ agents: Array<AgentRecord & { frozen: boolean }>; fleet: FleetRecord | undefined; total_agents: number; frozen_fleet: boolean; active_directives: number }> {
    const [agents, fleet, total, active] = await Promise.all([this.opts.store.listAgents(Math.min(limit, MAX_LIST)), this.opts.store.getFleet(), this.opts.store.countAgents(), this.activeDirectives()]);
    const frozen = new Set(active.filter((d) => d.kind === 'freeze' && d.subject.kind === 'agent').map((d) => d.subject.id));
    return { agents: agents.map((a) => ({ ...a, frozen: frozen.has(a.agent) })), fleet, total_agents: total, frozen_fleet: active.some((d) => d.kind === 'freeze' && d.subject.kind === 'fleet'), active_directives: active.length };
  }

  /** Directive history, newest first, optionally after a sequence number (for streaming). */
  history(q: { afterSeq?: number; order?: 'asc' | 'desc'; limit?: number; subjects?: readonly Subject[] } = {}): Promise<StoredDirective[]> {
    return this.opts.store.listDirectives({ ...(q.afterSeq !== undefined ? { afterSeq: q.afterSeq } : {}), ...(q.subjects ? { subjects: q.subjects } : {}), order: q.order ?? 'desc', limit: Math.min(q.limit ?? 100, MAX_LIST) });
  }
}
