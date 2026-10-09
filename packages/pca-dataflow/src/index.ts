/**
 * @atlasauth/pca-dataflow — a capability-tagged, positive data-flow model for PCA.
 *
 * WHY THIS EXISTS. PCA's shipped DLP (`@atlasauth/pca` `dlp.ts` + the L4 `taint.ts` lattice) is a NEGATIVE
 * control: it answers "how dirty is this action's lineage?" and stops a high-taint flow heuristically — the
 * agent declares provenance, the server re-labels it, and a scalar taint number is compared to a ceiling.
 * That is sound as a floor, but it is still a classifier over a declared scalar.
 *
 * This module adds the complementary POSITIVE model from CaMeL (Debenedetti, Shumailov, et al.,
 * "Defeating Prompt Injections by Design", Google DeepMind / ETH Zürich / Google, arXiv:2503.18813,
 * March 2025). CaMeL reframes prompt injection as a DATA-FLOW problem rather than a detection problem:
 *
 *   1. Control flow derives ONLY from the trusted user query — never from tool output or retrieved text.
 *   2. Every VALUE carries CAPABILITIES describing its provenance (where it came from) and its readers
 *      (which sinks it is allowed to reach).
 *   3. An interpreter enforces a security policy on every flow to a sink. A value whose provenance includes
 *      untrusted sources can be PROVEN unable to reach an exfiltrating sink — no string matching, no model.
 *
 * The result is PROVABLE non-exfiltration: if the tags are correct at the trust boundary, no untrusted
 * byte can reach a forbidden sink, because the capability is carried structurally through every
 * combinator and checked at the edge.
 *
 * ──────────────────────────────────────────────────────────────────────────────────────────────────────
 * HONESTY / TRUST ASSUMPTION (read this). This is a CAPABILITY MODEL, not a classifier. Its guarantee is
 * conditional: non-exfiltration is provable GIVEN CORRECT TAGGING AT THE BOUNDARIES. The one thing a human
 * must get right is the labelling of inputs where data ENTERS the system — `fromTrustedQuery` for the
 * genuine user query, `fromToolOutput` / untrusted tags for everything a tool or document returns. This is
 * exactly CaMeL's assumption: the interpreter is sound, so the whole trust surface collapses to the
 * boundary tags. Mis-tag untrusted text as trusted and the proof is void — the model cannot and does not
 * detect that; it is not a detector. Pair it with the heuristic `dlp.ts`/`taint.ts` floor for defence in
 * depth: this module proves "untrusted cannot reach the sink", the heuristic catches mis-tagging.
 *
 * Pure and deterministic: no time, no randomness, no I/O. Capabilities are immutable and propagate
 * monotonically (a flow can never become MORE trusted by passing through a combinator).
 */

import type { DlpOutcome } from '@atlasauth/pca';

// Re-export the shared allow/step_up/deny vocabulary so callers gate PCA actions with ONE outcome type.
export type { DlpOutcome } from '@atlasauth/pca';

// ── provenance ──────────────────────────────────────────────────────────────────────────────────────────
//
// A provenance tag names WHERE a value originated. The two load-bearing kinds are `'trusted-query'` (the
// genuine user instruction — the only source control flow may derive from) and `tool:<name>` (output of a
// tool / retrieval, which is UNTRUSTED: it may contain an injected instruction). `'user'` and any other
// string are permitted for domain-specific sources. The `(string & {})` keeps literal autocompletion for
// the well-known tags while still accepting any origin string — it is not `any`.

export type Provenance = 'trusted-query' | 'user' | `tool:${string}` | (string & {});

/** The genuine, trusted user query — the one source CaMeL lets control flow and decisions derive from. */
export const TRUSTED_QUERY = 'trusted-query' satisfies Provenance;

/** Provenance tag for the output of a named tool / retrieval. Always UNTRUSTED. */
export const toolProvenance = (name: string): `tool:${string}` => `tool:${name}`;

// ── capability + tagged value ───────────────────────────────────────────────────────────────────────────

/**
 * The capability a value carries. It is the data-flow label CaMeL attaches to every value.
 *
 * - `sources`  — the set of provenance tags this value was derived from (its lineage). A derived value's
 *                sources are the UNION of its inputs' sources, so a single untrusted input taints the whole.
 * - `isTrusted`— `true` only if EVERY contributing source is trusted. This is the CaMeL rule that control
 *                and decisions must come from trusted data: one untrusted input flips the whole value
 *                untrusted, and no combinator can flip it back.
 * - `readers`  — OPTIONAL allow-list of sink ids this value may reach (the "readers" capability). `undefined`
 *                means unrestricted by the VALUE (the sink's own policy still applies). When defined, the
 *                value may ONLY reach a sink whose id is in the set. Combining values takes the INTERSECTION
 *                (meet): a derived value may reach only sinks ALL its inputs allowed.
 */
export interface Capability {
  readonly sources: ReadonlySet<Provenance>;
  readonly isTrusted: boolean;
  readonly readers?: ReadonlySet<string>;
}

/** A value carrying its data-flow capability. The capability travels with the value through every combinator. */
export interface Tagged<T> {
  readonly value: T;
  readonly cap: Capability;
}

function freezeCap(cap: Capability): Capability {
  const frozen: Capability = {
    sources: Object.freeze(new Set(cap.sources)),
    isTrusted: cap.isTrusted,
    ...(cap.readers !== undefined ? { readers: Object.freeze(new Set(cap.readers)) } : {}),
  };
  return Object.freeze(frozen);
}

/** Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors below). */
export function tag<T>(value: T, cap: Capability): Tagged<T> {
  return Object.freeze({ value, cap: freezeCap(cap) });
}

// ── boundary constructors (the trust assumption lives HERE) ─────────────────────────────────────────────

/**
 * Tag a value as coming from the genuine, trusted user query. This is a BOUNDARY assertion: the caller is
 * vouching that `value` really is the user's own instruction, not tool/retrieved content. Everything the
 * privileged planner is allowed to see must enter through here. Mis-use (tagging untrusted text trusted)
 * voids the proof — see the module honesty note.
 */
export function fromTrustedQuery<T>(value: T, opts: { readers?: Iterable<string> } = {}): Tagged<T> {
  return tag(value, {
    sources: new Set<Provenance>([TRUSTED_QUERY]),
    isTrusted: true,
    ...(opts.readers !== undefined ? { readers: new Set(opts.readers) } : {}),
  });
}

/**
 * Tag the output of a named tool / retrieval. ALWAYS untrusted: tool output may carry an injected
 * instruction, so it can never source control flow and may never reach an exfiltrating sink on its own.
 */
export function fromToolOutput<T>(name: string, value: T, opts: { readers?: Iterable<string> } = {}): Tagged<T> {
  return tag(value, {
    sources: new Set<Provenance>([toolProvenance(name)]),
    isTrusted: false,
    ...(opts.readers !== undefined ? { readers: new Set(opts.readers) } : {}),
  });
}

/**
 * Tag a value from an arbitrary named source. `isTrusted` defaults to `false` (fail-closed): a source is
 * untrusted unless the caller explicitly vouches for it at the boundary.
 */
export function fromSource<T>(
  source: Provenance,
  value: T,
  opts: { isTrusted?: boolean; readers?: Iterable<string> } = {},
): Tagged<T> {
  return tag(value, {
    sources: new Set<Provenance>([source]),
    isTrusted: opts.isTrusted === true,
    ...(opts.readers !== undefined ? { readers: new Set(opts.readers) } : {}),
  });
}

// ── capability algebra ──────────────────────────────────────────────────────────────────────────────────

/** Union of the provenance sources of several capabilities. Exported for auditing / explanation. */
export function unionSources(caps: readonly Capability[]): ReadonlySet<Provenance> {
  const out = new Set<Provenance>();
  for (const c of caps) {
    for (const s of c.sources) out.add(s);
  }
  return out;
}

/**
 * Combine capabilities the CaMeL way:
 *   - sources  = UNION of all input sources (lineage accumulates),
 *   - isTrusted= AND over inputs (trusted only if every input is trusted; empty input set → untrusted,
 *                fail-closed — "derived from nothing verifiable" is not "trusted"),
 *   - readers  = INTERSECTION (meet) of the inputs that restrict readers; an input with no reader
 *                restriction contributes the universe and drops out of the intersection.
 */
export function combineCaps(caps: readonly Capability[]): Capability {
  const sources = unionSources(caps);
  const isTrusted = caps.length > 0 && caps.every((c) => c.isTrusted);

  let readers: Set<string> | undefined;
  for (const c of caps) {
    if (c.readers === undefined) continue; // unrestricted input: universe, no effect on the meet
    if (readers === undefined) {
      readers = new Set(c.readers);
    } else {
      const next = new Set<string>();
      for (const id of readers) {
        if (c.readers.has(id)) next.add(id);
      }
      readers = next;
    }
  }

  return freezeCap({ sources, isTrusted, ...(readers !== undefined ? { readers } : {}) });
}

/**
 * Derive a new tagged value from existing ones. The returned capability is `combineCaps` over the inputs,
 * so provenance propagates and trust can only be LOST, never gained — the structural heart of the model.
 * A DECISION derived from any untrusted input is therefore itself untrusted and will be blocked by the
 * interpreter at a sink that requires trust, which is CaMeL's defence against injected control flow.
 *
 * The 1–3 input overloads give the combiner per-position value types; the variadic form handles the rest.
 */
export function derive<A, T>(inputs: readonly [Tagged<A>], combine: (a: A) => T): Tagged<T>;
export function derive<A, B, T>(inputs: readonly [Tagged<A>, Tagged<B>], combine: (a: A, b: B) => T): Tagged<T>;
export function derive<A, B, C, T>(
  inputs: readonly [Tagged<A>, Tagged<B>, Tagged<C>],
  combine: (a: A, b: B, c: C) => T,
): Tagged<T>;
export function derive<T>(inputs: readonly Tagged<unknown>[], combine: (...values: unknown[]) => T): Tagged<T>;
export function derive<T>(inputs: readonly Tagged<unknown>[], combine: (...values: unknown[]) => T): Tagged<T> {
  const value = combine(...inputs.map((t) => t.value));
  const cap = combineCaps(inputs.map((t) => t.cap));
  return Object.freeze({ value, cap });
}

// ── sinks + the policy interpreter ──────────────────────────────────────────────────────────────────────

/**
 * What a sink accepts. A sink is anywhere a value LEAVES the trusted interior — an external send, a write,
 * a reply, a tool call. The policy is declared over PROVENANCE, so a decision is provable from the tags:
 *
 * - `external`       — the sink exfiltrates (sends data where an attacker could read it). An untrusted value
 *                      reaching an external sink is the exfiltration path → hard DENY. This is the flagship
 *                      CaMeL guarantee.
 * - `requireTrusted` — the sink is sensitive and wants trusted provenance, but a human could authorise an
 *                      untrusted value → STEP_UP (not a hard deny), mapping to the DLP step_up outcome.
 * - `allowedSources` — if set, ONLY these provenances may reach the sink; any other source → DENY.
 * - `deniedSources`  — if set, these provenances may NEVER reach the sink → DENY (explicit forbidden flow).
 */
export interface FlowPolicy {
  readonly external?: boolean;
  readonly requireTrusted?: boolean;
  readonly allowedSources?: ReadonlySet<Provenance>;
  readonly deniedSources?: ReadonlySet<Provenance>;
}

export interface Sink {
  readonly id: string;
  readonly accepts: FlowPolicy;
}

/** The full decision for one value→sink flow, in the shared DLP vocabulary, with the responsible path. */
export interface FlowDecision {
  readonly outcome: DlpOutcome;
  readonly reason?: string;
  /** The provenance sources responsible for a non-allow outcome: the exfiltration / injection path. */
  readonly path?: readonly Provenance[];
}

const sortedSources = (cap: Capability): Provenance[] => [...cap.sources].sort();

/**
 * Classify a single value→sink flow. Pure; derived entirely from the value's capability tags and the
 * sink's declared policy — no heuristics, no content inspection. Checks, in order: value reader allow-list,
 * sink denied sources, sink allow-list, external-sink exfiltration, sensitive-sink trust requirement.
 */
export function classifyFlow(value: Tagged<unknown>, sink: Sink): FlowDecision {
  const cap = value.cap;
  const p = sink.accepts;

  // 1. The VALUE's own readers capability: it may only reach a sink it explicitly allows.
  if (cap.readers !== undefined && !cap.readers.has(sink.id)) {
    return {
      outcome: 'deny',
      reason: `value's readers capability [${[...cap.readers].sort().join(', ') || '∅'}] does not include sink '${sink.id}'`,
      path: sortedSources(cap),
    };
  }

  // 2. Explicitly forbidden provenance at this sink → hard deny.
  if (p.deniedSources !== undefined) {
    const bad = sortedSources(cap).filter((s) => p.deniedSources?.has(s));
    if (bad.length > 0) {
      return {
        outcome: 'deny',
        reason: `provenance [${bad.join(', ')}] is forbidden at sink '${sink.id}'`,
        path: bad,
      };
    }
  }

  // 3. Allow-list: every source must be permitted.
  if (p.allowedSources !== undefined) {
    const bad = sortedSources(cap).filter((s) => !p.allowedSources?.has(s));
    if (bad.length > 0) {
      return {
        outcome: 'deny',
        reason: `provenance [${bad.join(', ')}] is not in the allow-list of sink '${sink.id}'`,
        path: bad,
      };
    }
  }

  // 4. External (exfiltrating) sink + any untrusted provenance → the exfiltration path. Hard deny.
  if (p.external === true && !cap.isTrusted) {
    return {
      outcome: 'deny',
      reason: `untrusted value (provenance [${sortedSources(cap).join(', ')}]) may not flow to external-send sink '${sink.id}' — exfiltration / prompt-injection path`,
      path: sortedSources(cap),
    };
  }

  // 5. Sensitive (non-external) sink requires trust → a human could authorise: step_up.
  if (p.requireTrusted === true && !cap.isTrusted) {
    return {
      outcome: 'step_up',
      reason: `sink '${sink.id}' requires trusted provenance; value provenance [${sortedSources(cap).join(', ')}] is untrusted — needs human review`,
      path: sortedSources(cap),
    };
  }

  return { outcome: 'allow' };
}

/**
 * Decide whether a tagged value may reach a sink. Convenience boolean wrapper over {@link classifyFlow}:
 * `ok` is true only for a clean `allow` (a `step_up` is NOT ok without a human). Use `classifyFlow` when you
 * need the allow/step_up/deny distinction.
 */
export function canFlow(value: Tagged<unknown>, sink: Sink): { ok: boolean; reason?: string } {
  const d = classifyFlow(value, sink);
  return { ok: d.outcome === 'allow', ...(d.reason !== undefined ? { reason: d.reason } : {}) };
}

// ── action gate ─────────────────────────────────────────────────────────────────────────────────────────

/**
 * The minimal PCA action shape this gate reads: the verb + resource of a PCActn's `action`. Kept as a
 * structural subset so a real `@atlasauth/pca` `PCActn['action']` is directly assignable.
 */
export interface PcaStyleAction {
  readonly verb: string;
  readonly resource: string;
}

/** Resolves which sink an action dispatches to (e.g. `send_email` → the external-send sink). */
export interface FlowGovernor {
  sinkFor(action: PcaStyleAction): Sink;
}

export interface ActionDecision {
  readonly outcome: DlpOutcome;
  readonly sink: string;
  readonly reason?: string;
  /** Index of the argument that caused a non-allow outcome. */
  readonly arg?: number;
  /** The provenance path of the offending argument (the exfiltration / injection path). */
  readonly path?: readonly Provenance[];
}

const SEVERITY: Record<DlpOutcome, number> = { allow: 0, step_up: 1, deny: 2 };

/**
 * Gate a PCA action by data flow. Every tagged argument is checked against the sink the action dispatches to;
 * the WORST outcome wins (deny ≻ step_up ≻ allow). If any argument carrying untrusted / injected provenance
 * would flow to a sensitive or external sink, the action is DENIED (or stepped-up) with the provenance path
 * — the concrete exfiltration / prompt-injection path. The outcome uses the shared DLP vocabulary so a PCA
 * verifier can treat it exactly like an `evaluateDlp` result.
 */
export function checkAction(
  action: PcaStyleAction,
  taggedArgs: readonly Tagged<unknown>[],
  policy: FlowGovernor,
): ActionDecision {
  const sink = policy.sinkFor(action);
  let worst: ActionDecision = { outcome: 'allow', sink: sink.id };

  for (let i = 0; i < taggedArgs.length; i++) {
    const arg = taggedArgs[i];
    if (arg === undefined) continue; // noUncheckedIndexedAccess: array holes can't carry a flow
    const d = classifyFlow(arg, sink);
    if (SEVERITY[d.outcome] > SEVERITY[worst.outcome]) {
      worst = {
        outcome: d.outcome,
        sink: sink.id,
        arg: i,
        ...(d.reason !== undefined ? { reason: d.reason } : {}),
        ...(d.path !== undefined ? { path: d.path } : {}),
      };
    }
  }

  return worst;
}

// ── dual-context (privileged planner / quarantined handler) ─────────────────────────────────────────────

export interface DualContext<Q, P, R> {
  /** The TRUSTED user query. MUST be trusted — it is the only thing the privileged planner may see. */
  readonly query: Tagged<Q>;
  /**
   * The PRIVILEGED planner (P-LLM). It derives control flow / a plan from the TRUSTED query value ONLY and
   * is NEVER handed untrusted text — structurally, it receives `query.value` and nothing else.
   */
  readonly plan: (trustedQuery: Q) => P;
  /**
   * The QUARANTINED handler (Q-LLM). It processes untrusted content in isolation and returns a
   * CAPABILITY-TAGGED result. Only that tagged result (never raw untrusted text) flows back to the
   * interpreter, where its capability governs every onward flow.
   */
  readonly quarantine: (plan: P) => Tagged<R>;
}

/**
 * Run the CaMeL dual-LLM separation: a PRIVILEGED planner that sees only the trusted query, and a
 * QUARANTINED handler that processes untrusted content and returns only a capability-tagged result.
 *
 * This encodes, in types and at runtime, the pattern that prevents a prompt injection in tool/retrieved
 * content from ever steering the plan: the planner's input is provably the trusted query value, and
 * untrusted content can re-enter the trusted flow only as a `Tagged<R>` whose capability the interpreter
 * then enforces at every sink. Throws if `query` is not trusted — a mis-use that would defeat the pattern.
 */
export function dualContext<Q, P, R>(ctx: DualContext<Q, P, R>): { plan: P; result: Tagged<R> } {
  if (!ctx.query.cap.isTrusted) {
    throw new Error(
      'dualContext: the privileged planner may only run on a TRUSTED query; ' +
        `got provenance [${sortedSources(ctx.query.cap).join(', ')}]`,
    );
  }
  const plan = ctx.plan(ctx.query.value); // planner sees ONLY the trusted query value
  const result = ctx.quarantine(plan); // untrusted content handled here; returns a capability-tagged result
  return { plan, result };
}

// ── small sink presets ──────────────────────────────────────────────────────────────────────────────────

/** An external-send sink (email, HTTP POST, webhook, …): exfiltrating, so untrusted values hard-deny. */
export function externalSendSink(id: string): Sink {
  return { id, accepts: { external: true } };
}

/** A sensitive internal sink (write, privileged action): untrusted values step_up for human review. */
export function sensitiveSink(id: string): Sink {
  return { id, accepts: { requireTrusted: true } };
}
