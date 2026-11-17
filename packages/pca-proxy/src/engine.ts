/**
 * The decision engine shared by the MCP proxy and the HTTP proxy.
 *
 * One call comes in (a tool call or an HTTP request already mapped to an action), one verdict goes out:
 *
 *   1. the action must be mapped (default deny) and its operator rule must not be `deny`;
 *   2. the arguments must conform to the action definition (closed world, bounded, canonical JSON);
 *   3. policy `approve` puts every call to a human first;
 *   4. the proxy mints a proof of the call from the grant it holds and runs the full PCA pipeline on it (`createAuthorizer`:
 *      chain, audience, the grant's limits and caveats, revocation, the replay counter, the trust budget, and the provenance gate);
 *   5. the provenance gate holds a sensitive call once the session has relayed untrusted content: the answer is `escalate`, and
 *      the call is forwarded only with a signed escalation answer, which the proxy produces only after a human approved the
 *      exact call (or, for policy `allow`, while the session is still clean);
 *   6. the receipt is written before the call is forwarded.
 *
 * Observe mode runs the same pipeline and records what would have been refused, but forwards everything.
 */

import {
  EXECUTION_REQUIRED_CHECKS,
  MAX_PROV_RECEIPTS,
  CATALOG_REVERSIBILITY_SCORE,
  agent as makeAgent,
  b64u,
  buildPCActn,
  createAuthorizer,
  createProvenanceRecorder,
  decodeB64uStrict,
  encodePCActn,
  generateKeyPair,
  hashCanonicalLenient,
  paramsDigest,
  parseLimit,
  pcaStateKey,
  publicKeyOf,
  readEnvelope,
  signEscalationAnswer,
  type Agent,
  type Capability,
  type PcaOperation,
  type PcaRequestLike,
  type KeyPair,
  type PCActn,
  type ProvenanceRecorder,
  type Receipt,
} from '@atlasauth/pca';
import { renderApproval, renderDigestForAction } from '@atlasauth/pca-actions';
import { instrumentGuard, type GuardResultLike, type MeterLike, type TracerLike } from '@atlasauth/pca-otel';
import { existsSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { DurableStateError } from '@atlasauth/pca/durable-state';
import { catalogOf, provInfo, specOf, type ActionEntry, type Spec } from './actions';
import { Approvals, type ApprovalOutcome } from './approvals';
import { AuditLog } from './audit';
import { ObservedParamsLog, bindingFacts } from './observed';
import { GrantOverlay as GrantOverlayClass, type GrantOverlay } from './grant-overlay';
import { checkArgs } from './check';
import { ConfigError, expandEnv, type ProxyConfig } from './config';
import { openProxyState, type ProxyState } from './state';

export interface Call {
  kind: 'mcp' | 'http';
  /** What the caller named: the tool, or `METHOD /path`. */
  name: string;
  entry: ActionEntry | undefined;
  args: unknown;
  session: string;
  /** Whatever the transport needs to pass to a verifier (HTTP verify mode). */
  ctx?: unknown;
  /** Why the transport found no usable action for the name (a held tool: no pin, changed since review). */
  why?: string;
}

export interface Verdict {
  /** The call may be sent upstream (always true in observe mode). */
  forward: boolean;
  /** The policy allowed it. False with `forward: true` is observe mode: it would have been refused. */
  allowed: boolean;
  code: string;
  reason: string;
  verb: string;
  resource: string;
  /** The encoded proof minted for the call (sidecar mode). */
  proof?: string;
  approvalId?: string;
  /** Observe mode: what enforce mode would have done beyond allowing (for example `would_hold`). */
  note?: string;
}

export type Verifier = (call: Call, args: Record<string, unknown>) => Promise<{ ok: true; pcactn: PCActn } | { ok: false; reason: string }>;

export interface EngineOptions {
  cfg: ProxyConfig;
  /** Every action the grant is compiled over (the operator's rules with an imported definition). */
  candidates: readonly ActionEntry[];
  now?: () => number;
  tracer?: TracerLike;
  meter?: MeterLike;
  approvals?: Approvals;
  audit?: AuditLog;
  /** The optional observed-parameters log (tests inject one); by default built from `audit.observedParams`. */
  observed?: ObservedParamsLog;
  /** Where the counters, the budget and the taint live. Default: what `cfg.state` names. */
  state?: ProxyState;
  env?: Record<string, string | undefined>;
  verifier?: Verifier;
  /** An issued, human-signed grant to enforce on top of the operator rules (see grant-overlay.ts). */
  overlay?: GrantOverlay;
}

interface Session {
  recorder: ProvenanceRecorder;
  /** Sticky: the session has relayed untrusted content. Never cleared. */
  tainted: boolean;
}

const MAX_SESSIONS = 1000;
/** Sessions named `client/session` (the HTTP downstream) share one persisted flag per client; any other session has its own. */
const taintKey = (id: string): string => (id.includes('/') ? `taint:client:${id.slice(0, id.indexOf('/'))}` : `taint:session:${id}`);
const clip = (s: string, n = 200): string => (s.length > n ? `${s.slice(0, n)}...` : s);

export class Engine {
  /** The grant the proxy holds; renewed when a periodic limit ends its lifetime. */
  agent: Agent;
  readonly audit: AuditLog;
  readonly observed: ObservedParamsLog | undefined;
  readonly approvals: Approvals;
  readonly principal: KeyPair;
  readonly state: ProxyState;
  private readonly cfg: ProxyConfig;
  private readonly now: () => number;
  private readonly specs = new Map<string, Spec>();
  private readonly info = new Map<string, { effects: string[]; traits: string[] }>();
  private readonly sessions = new Map<string, Session>();
  private readonly mediatorKey = randomBytes(32);
  private readonly authorizer: ReturnType<typeof createAuthorizer>;
  private readonly ctxs = new WeakMap<object, { e: ActionEntry; a: Record<string, unknown> }>();
  private readonly verdicts = new WeakMap<Call, Verdict>();
  private readonly instr: (c: Call) => Promise<GuardResultLike>;
  private readonly ns: string;
  private counter = 0;
  private windowStart: number;
  private readonly seed: Uint8Array;
  private readonly rates = new Map<string, { max: number; periodMs: number }>();
  private readonly agentArgs: Parameters<typeof makeAgent>[0];
  private chain: Promise<unknown> = Promise.resolve();
  verifier: Verifier | undefined;
  readonly overlay: GrantOverlay | undefined;
  /** Called after each receipt is written, with the observed parameters bound to it (observe mode). A failure here never touches the call. */
  onReceipt: ((r: Receipt, obs?: { params: Record<string, string | number | boolean>; omitted: string[]; digest: string }) => void) | undefined;
  /** Where warnings go (default: stderr). */
  warn: (line: string) => void = (l) => void process.stderr.write(`[pca-proxy] ${l}\n`);

  /** Open the state, load (or create) the grant's identity and build the engine. Throws when the state cannot be opened: the proxy does not start. */
  static async create(o: EngineOptions): Promise<Engine> {
    const env = o.env ?? process.env;
    const now = o.now ?? Date.now;
    const state = o.state ?? (await openProxyState(o.cfg, env));
    const fresh = { v: 1, seed: b64u(randomBytes(32)), windowStart: now() };
    const stored = (await state.kv.update('identity', (prev) => prev ?? fresh)) as { v?: unknown; seed?: unknown; windowStart?: unknown } | undefined;
    const seed = decodeB64uStrict(stored?.seed, 32);
    if (stored?.v !== 1 || seed === null || typeof stored.windowStart !== 'number' || !Number.isSafeInteger(stored.windowStart)) throw new ConfigError('the stored grant identity is malformed; refusing to start');
    const e = new Engine(o, state, seed, stored.windowStart);
    await e.renewIfNeeded();
    await e.syncCounter();
    return e;
  }

  private constructor(o: EngineOptions, state: ProxyState, seed: Uint8Array, windowStart: number) {
    this.state = state;
    this.seed = seed;
    this.windowStart = windowStart;
    this.cfg = o.cfg;
    this.now = o.now ?? Date.now;
    this.ns = o.cfg.mcp?.ns ?? o.cfg.http?.ns ?? 'api';
    if (this.ns === 'pcaproxy') throw new ConfigError("the namespace 'pcaproxy' is reserved");
    this.verifier = o.verifier;
    this.overlay = o.overlay ?? (o.cfg.agent.issuedGrant !== undefined ? GrantOverlayClass.load(o.cfg.agent.issuedGrant.file, o.cfg.agent.issuedGrant.signer) : undefined);
    const env = o.env ?? process.env;

    // the keys: the principal signs the grant and the escalation answers; it never reaches the agent
    const pkEnv = o.cfg.agent.principalKeyEnv;
    if (pkEnv !== undefined) {
      const seed = decodeB64uStrict(env[pkEnv], 32);
      if (seed === null) throw new ConfigError(`${pkEnv} must hold a base64url-encoded 32-byte key`);
      this.principal = { secretKey: seed, publicKey: publicKeyOf(seed) };
    } else this.principal = this.derivedPair('principal');
    const holder = this.derivedPair('holder');

    // the grant: exactly the actions the operator did not deny, each with its own cost; nothing else is permitted
    const specs: Spec[] = [{ connector: 'pcaproxy', action: 'audit', verb: 'pcaproxy.audit', reversibility: 'reversible', blastRadius: 0.05, description: 'audit receipt' }];
    const permissions: Record<string, string[]> = { pcaproxy: ['audit'] };
    const limits: Record<string, string> = {};
    for (const e of o.candidates) {
      const s = specOf(e);
      this.specs.set(e.verb, s);
      this.info.set(e.verb, provInfo(e));
      if (e.rule.policy === 'deny') continue;
      specs.push(s);
      (permissions[s.connector] ??= []).push(s.action);
      if (e.rule.limit !== undefined) {
        const p = parseLimit(e.rule.limit);
        // a count limit is the proxy's own sliding window per action (the grant's rate caveat is grant-wide); a $ limit is the grant's
        if (p.unit === 'count') this.rates.set(e.verb, { max: p.amount, periodMs: p.periodMs! });
        else limits[e.verb] = e.rule.limit;
      }
    }
    for (const s of specs) this.specs.set(s.verb, s);
    this.agentArgs = {
      principal: this.principal,
      goal: o.cfg.agent.goal,
      permissions,
      limits,
      catalog: catalogOf(specs),
      aud: o.cfg.audience,
      holder,
      goalSalt: b64u(this.derive('salt').subarray(0, 16)),
      provenance: { secretKey: this.derive('recorder'), session: b64u(this.derive('session')) },
      // the budget is blast radius: reads are cheap, irreversible writes are not; no tier above `auto` is ever needed
      budgetModel: 'risk',
      riskPolicy: { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 1, lambda: 0, rho: 0.5, bMax: o.cfg.budget.max },
    };
    this.agent = makeAgent({ ...this.agentArgs, now: this.windowStart });

    const wh = o.cfg.approvals.webhook;
    this.approvals =
      o.approvals ??
      new Approvals({
        waitSeconds: o.cfg.approvals.waitSeconds,
        now: this.now,
        ...(o.cfg.approvals.store !== undefined ? { storePath: o.cfg.approvals.store } : {}),
        ...(wh !== undefined ? { webhook: { url: wh.url, secret: expandEnv(`\${${wh.secretEnv}}`, env) } } : {}),
      });
    this.audit = o.audit ?? new AuditLog(o.cfg.audit.path);
    const op = o.cfg.audit.observedParams;
    if (op?.enabled === true) {
      // what the arguments were is recorded only while watching: enforce mode never writes it
      if (o.cfg.mode !== 'observe') throw new ConfigError('audit.observedParams is on, and it is written only in observe mode: run with --observe, or turn it off for enforce mode');
      const path = o.cfg.audit.observedParamsPath ?? (o.cfg.audit.path !== undefined ? `${o.cfg.audit.path}.params.jsonl` : undefined);
      if (path === undefined) throw new ConfigError('audit.observedParams needs audit.path (or audit.observedParamsPath)');
      this.observed = o.observed ?? new ObservedParamsLog(path, op.include);
    } else this.observed = o.observed;

    const recorder = createProvenanceRecorder({ mediator: 'pca-proxy', kid: 'k1', secretKey: this.mediatorKey });
    const revFile = o.cfg.agent.revocationFile;
    this.authorizer = createAuthorizer({
      audience: o.cfg.audience,
      budgetStore: state.pca,
      resolveGrant: async () => this.agent.grant,
      hooks: { revocation: async () => ({ enforced: true, ok: !(revFile !== undefined && existsSync(revFile)) }) },
      plan: 'single-step',
      allowedSuites: ['ed25519'],
      require: [...EXECUTION_REQUIRED_CHECKS],
      seedBudget: (g: Capability, t: number) => ({ B: readEnvelope(g)?.risk_policy.bMax ?? 0, tau: t, asOf: t }),
      risk: (_op: PcaOperation | undefined, _g: Capability, pc: PCActn) => this.riskOf(pc.action.verb),
      now: this.now,
      provenance: { mediators: [recorder.pin], actions: (op: PcaOperation) => this.info.get(op.verb) },
      escalation: { principals: [b64u(this.principal.publicKey)], render: (req: PcaRequestLike, pc: PCActn) => this.renderFor(req, pc), requestTtlMs: 60_000 },
    } as never);

    this.instr = instrumentGuard(
      async (c: Call): Promise<GuardResultLike> => {
        const v = await this.decide(c);
        this.verdicts.set(c, v);
        return { ok: v.allowed, status: v.allowed ? 200 : 403, verdict: { allow: v.allowed, reasons: [v.reason] }, pcactn: { action: { verb: v.verb, resource: v.resource } } };
      },
      { ...(o.tracer ? { tracer: o.tracer } : {}), ...(o.meter ? { meter: o.meter } : {}), spanName: 'pca.proxy.call' },
    );
  }

  /** Decide one call. Never throws. */
  async evaluate(call: Call): Promise<Verdict> {
    try {
      await this.instr(call);
    } catch {
      /* telemetry never decides */
    }
    return this.verdicts.get(call) ?? this.fail(call, 'internal_error', 'the decision could not be made (fail closed)');
  }

  /**
   * The session has relayed this content to the agent: it is untrusted from here on, for good. The flag is written to the state
   * before this returns, and throws if it cannot be (the caller must then not relay the content).
   */
  async taint(sessionId: string, origin: 'tool' | 'retrieval' | 'web', source: string, content: unknown): Promise<void> {
    const st = await this.session(sessionId);
    const was = st.tainted;
    st.tainted = true;
    try {
      if (st.recorder.receipts().length >= MAX_PROV_RECEIPTS - 4) st.recorder = this.newRecorder();
      if (origin === 'tool') st.recorder.tool(source, content);
      else if (origin === 'retrieval') st.recorder.retrieval(source, content);
      else st.recorder.web(source, content);
    } catch {
      /* the sticky flag is the record that matters; a chain that cannot grow only makes later calls more suspect */
    }
    if (!was) await this.state.kv.set(taintKey(sessionId), true);
  }

  isTainted(sessionId: string): boolean {
    return this.sessions.get(sessionId)?.tainted === true;
  }

  /** Forget a session's in-memory state (its persisted taint stays: a client that saw untrusted content starts its next session tainted). */
  closeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  // ---- internals ----------------------------------------------------------------------------------------------------

  private derive(label: string): Uint8Array {
    return new Uint8Array(createHash('sha256').update(this.seed).update(`pca-proxy/${label}`).digest());
  }

  private derivedPair(label: string): KeyPair {
    const secretKey = this.derive(label);
    return { secretKey, publicKey: publicKeyOf(secretKey) };
  }

  /** The counter continues where the stored one stopped, so a restart with the same grant is not a replay of its own proofs. */
  private async syncCounter(): Promise<void> {
    const key = pcaStateKey(this.agent.grant.id, b64u(this.agent.holder.publicKey), undefined, this.cfg.audience);
    const st = await this.state.pca.get(key);
    this.counter = Math.max(this.counter, st?.lastCounter ?? 0);
  }

  /** The proxy's own sliding window per action (`limit: 10/hour`), durable. Returns false when the window is full. */
  private async rateGate(verb: string): Promise<boolean> {
    const r = this.rates.get(verb);
    if (r === undefined) return true;
    const now = this.now();
    let ok = false;
    await this.state.kv.update(`rate:${verb}`, (prev) => {
      const live = (Array.isArray(prev) ? prev : []).filter((t): t is number => typeof t === 'number' && t > now - r.periodMs);
      ok = live.length < r.max;
      return ok ? [...live, now] : undefined;
    });
    return ok;
  }

  private newRecorder(): ProvenanceRecorder {
    return createProvenanceRecorder({ mediator: 'pca-proxy', kid: 'k1', secretKey: this.mediatorKey });
  }

  private async session(id: string): Promise<Session> {
    let s = this.sessions.get(id);
    if (s === undefined) {
      // a flood of new names must not buy a clean session: past the cap, unseen names share the default one
      if (this.sessions.size >= MAX_SESSIONS && id !== 'default') return this.session('default');
      // a session that was tainted before a restart, or a client that was tainted in an earlier session, starts tainted
      s = { recorder: this.newRecorder(), tainted: (await this.state.kv.get(taintKey(id))) === true };
      const raced = this.sessions.get(id);
      if (raced !== undefined) return raced;
      this.sessions.set(id, s);
    }
    return s;
  }

  /** The provenance facts of an action: only what the operator declared (`read` or not). */
  infoOf(verb: string): { effects: string[]; traits: string[] } | undefined {
    return this.info.get(verb);
  }

  /** The server-side risk inputs of an action: what the proxy knows from the operator's rule, never what the caller claims. */
  riskOf(verb: string): Record<string, number> {
    const s = this.specs.get(verb);
    if (s === undefined) return {};
    return { reversibility: CATALOG_REVERSIBILITY_SCORE[s.reversibility] ?? 0, blastRadius: s.blastRadius, confidence: 1, semanticDistance: 0, taint: 0, age: 0 };
  }

  private renderFor(req: object, pc: PCActn): string | undefined {
    const c = this.ctxs.get(req);
    if (c === undefined) return undefined;
    try {
      return renderDigestForAction(c.e.def, c.a, pc);
    } catch {
      return undefined;
    }
  }

  /**
   * A limit with a period (`10/hour`) compiles into a grant that lives for one period. When it is about to end the proxy mints the
   * next one from the same keys: a new window with a fresh budget and a fresh replay namespace, never a longer lease on the old one.
   */
  private async renewIfNeeded(): Promise<void> {
    const exp = this.agent.policy.caveats.find((c) => c.type === 'expires') as { at?: number } | undefined;
    if (typeof exp?.at !== 'number' || this.now() < exp.at - 2000) return;
    const t = this.now();
    const stored = (await this.state.kv.update('identity', (prev) => {
      const p = prev as { windowStart?: number } | undefined;
      return typeof p?.windowStart === 'number' && p.windowStart >= t - 2000 ? undefined : { ...(p ?? {}), windowStart: t };
    })) as { windowStart: number };
    this.windowStart = stored.windowStart;
    this.agent = makeAgent({ ...this.agentArgs, now: this.windowStart });
    await this.syncCounter();
  }

  /** Calls are authorized one at a time: the replay counter and the budget are a sequence. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.chain.then(fn, fn);
    this.chain = p.catch(() => undefined);
    return p;
  }

  private mint(verb: string, resource: string, params: Record<string, unknown>, counter?: number): PCActn {
    const spec = this.specs.get(verb);
    const rev = spec?.reversibility ?? 'reversible';
    const r = spec?.blastRadius ?? 0.05;
    return buildPCActn({
      grant: this.agent.grant,
      chain: this.agent.chain,
      plan: [{ id: 'n0', verb, resource, reversibility_class: rev, params_digest: paramsDigest(params) }],
      nodeId: 'n0',
      params,
      counter: counter ?? ++this.counter,
      signerSecret: this.agent.holder.secretKey,
      aud: this.cfg.audience,
      riskClaim: { r, inputs: { blastRadius: r } },
      now: this.now(),
    });
  }

  private fail(call: Call, code: string, reason: string, extra: Partial<Verdict> = {}): Verdict {
    return { forward: false, allowed: false, code, reason, verb: call.entry?.verb ?? 'pcaproxy.unmapped', resource: call.entry?.resource ?? clip(call.name, 120), ...extra };
  }

  private async decide(call: Call): Promise<Verdict> {
    let v: Verdict;
    let pc: PCActn | undefined;
    try {
      const r = await this.pipeline(call);
      v = r.v;
      pc = r.pc;
    } catch (e) {
      const store = e instanceof DurableStateError;
      v = this.fail(call, store ? 'state_unavailable' : 'internal_error', `${store ? 'the state store failed' : 'the decision failed'} (fail closed): ${clip(e instanceof Error ? e.message : 'error', 120)}`);
    }
    const observe = this.cfg.mode === 'observe';
    v.forward = v.allowed || observe;
    try {
      this.record(call, v, pc);
    } catch (e) {
      // an action nobody can account for does not run (observe mode only watches, so it keeps going)
      if (!observe) return { ...v, forward: false, allowed: false, code: 'audit_unavailable', reason: `the audit log cannot be written: ${clip(e instanceof Error ? e.message : 'error', 100)}` };
    }
    return v;
  }

  private record(call: Call, v: Verdict, pc: PCActn | undefined): void {
    const at = this.now();
    const params: Record<string, unknown> = { args_sha: hashCanonicalLenient(call.args ?? null), code: v.code };
    const p = pc ?? this.mint(v.verb, v.resource, params, 1);
    // observe mode only: the parameters that cannot carry content, bound to this receipt by a digest the receipt itself carries
    const obs = this.cfg.mode === 'observe' && this.observed !== undefined ? this.observed.prepare(call.entry?.def, call.args, this.audit.nextSeq, p.action.verb, p.action.resource) : undefined;
    const r = this.audit.append(p, v.forward, { code: v.code, reason: v.reason, mode: this.cfg.mode, kind: call.kind, session: call.session, allowed: String(v.allowed), ...(v.note !== undefined ? { note: v.note } : {}), ...(v.approvalId !== undefined ? { approval: v.approvalId } : {}), ...(obs ? bindingFacts(obs.digest) : {}) }, at);
    if (obs !== undefined) {
      try {
        this.observed!.write(obs, r);
      } catch (e) {
        // watching never blocks: the receipt stands and the reader tolerates a missing tail
        this.warn(`the observed-parameters line for receipt ${r.seq} could not be written: ${e instanceof Error ? e.message : 'error'}`);
      }
    }
    try {
      this.onReceipt?.(r, obs);
    } catch {
      /* reporting never decides */
    }
  }

  private async pipeline(call: Call): Promise<{ v: Verdict; pc?: PCActn }> {
    const e = call.entry;
    const no = (code: string, reason: string, extra: Partial<Verdict> = {}): { v: Verdict } => ({ v: this.fail(call, code, reason, extra) });
    if (e === undefined) return no('unmapped', call.why ?? `'${clip(call.name, 80)}' is not mapped to an action (default deny)`);
    if (e.rule.policy === 'deny') return no('policy_deny', 'the operator rule for this action is deny');
    if (!this.specs.has(e.verb) || this.agent.policy.actions.find((s) => s.verb === e.verb) === undefined) return no('no_grant', 'the grant does not cover this action (restart the proxy after changing the rules)');
    const bad = checkArgs(e.def.params, call.args, this.cfg.limits.maxRequestBytes);
    if (bad !== undefined) return no('bad_args', bad);
    const a = call.args as Record<string, unknown>;
    const st = await this.session(call.session);
    const observe = this.cfg.mode === 'observe';
    let approved = false;
    let approvalId: string | undefined;
    let note: string | undefined;

    // an issued, signed grant: it admits or refuses, and what it admits needs no further human (unless the session is tainted)
    let grantAdmits = false;
    if (this.overlay !== undefined) {
      const sp = this.specs.get(e.verb)!;
      const d = await this.overlay.decide({ verb: e.verb, resource: e.resource, params: a, reversibility: sp.reversibility, blastRadius: sp.blastRadius }, this.now(), this.state.kv);
      if (d.outcome === 'deny') return no('grant_denied', d.reason ?? 'the issued grant does not admit this call');
      grantAdmits = true;
    }

    if (e.rule.policy === 'approve' && !(grantAdmits && !st.tainted && !observe)) {
      if (observe) {
        approved = true;
        note = 'would_hold';
      } else {
        const h = await this.human(e, a, 'the operator requires approval for every call');
        if ('error' in h) return no('no_render', h.error);
        approvalId = h.out.id;
        if (h.out.status !== 'approved') return no(h.out.status === 'denied' ? 'approval_denied' : 'approval_timeout', h.out.status === 'denied' ? 'a human denied this call' : 'no human approved this call in time', { approvalId });
        approved = true;
      }
    }

    // verify mode: the caller's own proof is the credential
    if (this.verifier !== undefined && call.kind === 'http') {
      const r = await this.verifier(call, a);
      if (!r.ok) return no('verify_denied', r.reason, approvalId !== undefined ? { approvalId } : {});
      if (!(await this.rateGate(e.verb))) return no('rate_limited', `the limit ${e.rule.limit} for this action is used up`, approvalId !== undefined ? { approvalId } : {});
      return { v: { forward: true, allowed: true, code: 'allow', reason: 'the proof verified', verb: e.verb, resource: e.resource, ...(approvalId !== undefined ? { approvalId } : {}) }, pc: r.pcactn };
    }

    // sidecar mode. `allow` on a write is answered by the proxy itself only while the session is clean (or the operator said otherwise)
    const auto = (e.rule.policy === 'allow' || (grantAdmits && e.rule.policy === 'approve')) && (!st.tainted || e.rule.insecureAllowAfterUntrusted === true);
    let r = await this.authorizeOnce(e, a, st, approved || auto);
    if (r.kind === 'escalate') {
      if (observe) {
        note = 'would_hold';
        r = await this.authorizeOnce(e, a, st, true);
      } else {
        const h = await this.human(e, a, `held: ${r.reason}`);
        if ('error' in h) return no('no_render', h.error);
        approvalId = h.out.id;
        if (h.out.status !== 'approved') return no(h.out.status === 'denied' ? 'approval_denied' : 'approval_timeout', h.out.status === 'denied' ? 'a human denied this call' : 'no human approved this call in time', { approvalId });
        r = await this.authorizeOnce(e, a, st, true);
      }
    }
    if (r.kind === 'allow' && grantAdmits) await this.overlay!.record(this.now(), this.state.kv);
    if (r.kind === 'allow' && !(await this.rateGate(e.verb))) return no('rate_limited', `the limit ${e.rule.limit} for this action is used up`, approvalId !== undefined ? { approvalId } : {});
    if (r.kind === 'allow') {
      return { v: { forward: true, allowed: true, code: approvalId !== undefined ? 'approved' : 'allow', reason: approvalId !== undefined ? 'a human approved this call' : 'the grant, the policy and the provenance gate allow this call', verb: e.verb, resource: e.resource, proof: r.encoded, ...(approvalId !== undefined ? { approvalId } : {}), ...(note !== undefined ? { note } : {}) }, pc: r.pcactn };
    }
    return no(r.kind === 'escalate' ? 'held' : 'verify_denied', r.reason, { ...(approvalId !== undefined ? { approvalId } : {}), ...(note !== undefined ? { note } : {}) });
  }

  private async human(e: ActionEntry, a: Record<string, unknown>, reason: string): Promise<{ error: string } | { out: ApprovalOutcome }> {
    let render;
    try {
      render = renderApproval(e.def, a);
    } catch (err) {
      return { error: `the call cannot be shown to a human completely, so it is refused: ${clip(err instanceof Error ? err.message : 'render failed', 160)}` };
    }
    const spec = this.specs.get(e.verb)!;
    const step = this.approvals.step(this.agent, e.verb, e.resource, a, reason, spec.blastRadius, render);
    return { out: await this.approvals.ask(this.agent, step) };
  }

  private authorizeOnce(e: ActionEntry, a: Record<string, unknown>, st: Session, answer: boolean) {
    type R = { kind: 'allow'; pcactn: PCActn; encoded: string } | { kind: 'escalate'; reason: string } | { kind: 'deny'; reason: string };
    return this.serial<R>(async () => {
      const op = { verb: e.verb, resource: e.resource, params: a };
      await this.renewIfNeeded();
      let pcactn: PCActn;
      let bundle: unknown;
      try {
        pcactn = this.mint(e.verb, e.resource, a);
        if (st.recorder.receipts().length >= MAX_PROV_RECEIPTS - 2) st.recorder = this.newRecorder();
        bundle = st.recorder.forAction(op);
      } catch (err) {
        return { kind: 'deny', reason: `a proof could not be built: ${clip(err instanceof Error ? err.message : 'error', 120)}` };
      }
      const encoded = encodePCActn(pcactn);
      const req = { headers: {} };
      this.ctxs.set(req, { e, a });
      const input = { operation: op, pcactn: encoded, provenance: bundle, request: req };
      const r1 = await this.authorizer(input);
      if (r1.allow) return { kind: 'allow', pcactn, encoded };
      if (r1.decision !== 'escalate') return { kind: 'deny', reason: r1.reason };
      if (!answer) return { kind: 'escalate', reason: r1.reason };
      const er = r1.escalation;
      if (er === undefined || er.render_digest === undefined) return { kind: 'deny', reason: 'the escalation carries no approval render (fail closed)' };
      const t = this.now();
      const ans = signEscalationAnswer(
        { v: 1, kind: 'pca-escalation-answer', principal: b64u(this.principal.publicKey), policy_digest: er.policy_digest, action_digest: er.action_digest, history_head: er.history_head, decision: 'allow', iat: t, expires_at: Math.min(er.expires_at, t + 60_000), nonce: b64u(randomBytes(16)), render_digest: er.render_digest },
        this.principal.secretKey,
      );
      const r2 = await this.authorizer({ ...input, escalationAnswer: ans });
      return r2.allow ? { kind: 'allow', pcactn, encoded } : { kind: 'deny', reason: r2.reason };
    });
  }
}
