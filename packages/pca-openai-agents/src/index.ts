/**
 * OpenAI Agents SDK (`@openai/agents`) guard for Proof-Carrying Authority.
 *
 * This is the *agent-framework* adapter — distinct from the chat-completions `openai` attach adapter.
 * It makes every **agent tool call** proof-carrying + policy-gated, and wires PCA step-up into the
 * SDK's guardrail / `needsApproval` (human-interruption) flow:
 *
 *  - {@link withPcaTool} wraps an Agents-SDK tool so its `execute(input, runContext)` first REQUIRES a
 *    proof-carrying action (pulled from the run context per the PCA-Action convention), VERIFIES it with
 *    the PCA core (fail closed → throws {@link PcaToolDenied}, which the SDK surfaces as a tool failure),
 *    and only then runs the original tool. {@link pcaTools} does a whole tool set at once.
 *  - {@link pcaInputGuardrail} / {@link pcaToolGuard} are Agents-SDK guardrails that trip (reject the run)
 *    when the run / tool call lacks a valid proof — the first line of defence before any step runs.
 *  - {@link pcaNeedsApproval} / {@link withApproval} map a risky tool to the SDK's `needsApproval`
 *    callback so the run *interrupts* for a human / guardian co-sign, driven by PCA {@link reviewToolCall}
 *    (tier 2 = guardian, tier 3 = human). {@link reviewToolCall} / {@link pendingStepUps} feed the
 *    approval inbox / FROST round that resolves those interruptions.
 *
 * Structural, zero-runtime coupling to `@openai/agents`: we touch only `description` / `parameters` /
 * `execute` / `needsApproval` and preserve every other field, and the SDK's tool / run-context /
 * guardrail shapes are modelled as minimal duck-typed interfaces — so this compiles and tests WITHOUT
 * the `@openai/agents` package installed, and slots into any compatible minor version.
 *
 * HONESTY: verification here is REAL (signature + capability chain + plan inclusion + audience + validity
 * window + counter, via `verifyPCActnCore`). It is still only as strong as the grant you verify against
 * and the gates you enable; it does not replace the resource server when a tool makes a remote call — it
 * makes the LOCAL agent-execution boundary refuse to act without a valid PCActn.
 */

import {
  type Agent,
  type Capability,
  type CheckStatus,
  type ClassApproval,
  type EnforcementGates,
  type PCActn,
  type Review,
  type StepUpRequest,
  type VerifyHooks,
  type VerifyResult,
  decodePCActn,
  decodePcaHeader,
  reviewAction,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  type AiSdkTool,
  type PcaCall,
  bridgeToolCall,
  pcaHeaders,
  withPCA,
  withPCATools,
} from '@atlasauth/pca-ai-sdk';

// ---- structural shapes of the OpenAI Agents SDK (duck-typed; `@openai/agents` is NOT a dependency) ----

/**
 * Minimal structural shape of the SDK's run context — the `RunContext<TContext>` the Agents SDK threads
 * through `run(agent, input, { context })` and hands to a tool's `execute` as the 2nd arg and to
 * guardrails as `args.context`. The caller-controlled `context` object is where a proof rides; the index
 * signature keeps us forward-compatible.
 */
export interface AgentRunContext {
  /** The caller's local context object (`run(agent, input, { context })`). Proof home by default. */
  context?: unknown;
  [k: string]: unknown;
}

/**
 * Minimal structural shape of an Agents-SDK tool (`tool({ name, description, parameters, execute })`).
 * `execute` is a METHOD (not an arrow property) on purpose: method parameters are checked bivariantly, so
 * a tool with concrete `Args` assigns cleanly to the general `AgentTool` when collected in a record — no
 * `any`, no casts. `(input, runContext)` mirrors the SDK's `execute` arity.
 */
export interface AgentTool<Args = Record<string, unknown>, Result = unknown> {
  name?: string;
  description?: string;
  parameters?: unknown;
  /** The SDK's human-approval hook: a run interrupts (needs co-sign) when this yields true. */
  needsApproval?: NeedsApproval;
  execute?(input: Args, runContext?: AgentRunContext): Promise<Result> | Result;
  [k: string]: unknown;
}

/** The SDK's `needsApproval`: a boolean, or `(runContext, input, callId?) => boolean | Promise<boolean>`. */
export type NeedsApproval =
  | boolean
  | ((runContext: AgentRunContext, input: Record<string, unknown>, callId?: string) => boolean | Promise<boolean>);

/** The output an Agents-SDK guardrail returns: a tripwire plus free-form info for the trace / exception. */
export interface GuardrailFunctionOutput {
  tripwireTriggered: boolean;
  outputInfo: unknown;
}

/** The argument the SDK passes to an input / tool guardrail (`{ agent, input, context }`). */
export interface GuardrailArgs {
  agent?: unknown;
  input?: unknown;
  context?: unknown;
  [k: string]: unknown;
}

/** Structural shape of an Agents-SDK guardrail: `{ name, execute(args) }` returning a tripwire output. */
export interface Guardrail {
  name: string;
  execute(args: GuardrailArgs): Promise<GuardrailFunctionOutput> | GuardrailFunctionOutput;
}

// ---- the proof surface --------------------------------------------------------------------------------

/** A proof as it arrives at the boundary: the PCActn object, its encoded JSON, or a base64url `PCA-Action` value. */
export type ProofInput = PCActn | string;

/** Pull the proof-carrying action for THIS tool call out of `(input, runContext)` (return null/undefined → fail closed). */
export type ProofSource<Args> = (input: Args, runContext: AgentRunContext) => ProofInput | null | undefined;

/** Pull the proof for a whole run out of the guardrail args (return null/undefined → trip the guardrail). */
export type GuardrailProofSource = (args: GuardrailArgs) => ProofInput | null | undefined;

/** Why a guarded execute / guardrail refused. */
export type PcaToolDenialKind = 'missing' | 'malformed' | 'verify' | 'binding';

/** Typed error thrown when a guarded tool refuses to run; the Agents SDK surfaces it as a tool error. */
export class PcaToolDenied extends Error {
  constructor(
    message: string,
    /** The PCA verb the proof claimed (or the configured verb / `(tool)` when unknown). */
    public readonly verb: string,
    public readonly kind: PcaToolDenialKind,
    /** The per-check verdicts from the core verifier, when the denial was a verification failure. */
    public readonly checks?: Record<string, CheckStatus>,
  ) {
    super(`PCA tool denied (${kind}) for ${verb}: ${message}`);
    this.name = 'PcaToolDenied';
  }
}

/** Core-verify config: the grant the proof must chain to, plus optional clock / gates / hooks. */
export interface VerifyGrant {
  /** The signed Root Intent Grant (or its head) the proof's capability chain must resolve to. */
  grant: Capability;
  /** Verifier clock (epoch ms); a thunk is evaluated per call. Defaults to the core's `Date.now()`. */
  nowEpoch?: number | (() => number);
  /** Opt-in M1 taint / M3 freshness / M5 attestation gates (each FAILS CLOSED when on). */
  enforce?: EnforcementGates;
  /** Later-milestone verifier hooks (attestation / threshold / revocation / zk). */
  hooks?: VerifyHooks;
}

/** A fully custom verifier: hand it a decoded PCActn, get back a {@link VerifyResult}. */
export type VerifyFn = (pcactn: PCActn) => VerifyResult | Promise<VerifyResult>;

export type Verify = VerifyGrant | VerifyFn;

export interface WithPcaToolOptions<Args> {
  /**
   * How to find the proof for a call. Default: {@link proofFromRunContext} — reads a string PCActn from
   * the run context's `context.pca` (or `.pcaProof`). Override to read it from the tool input, a header
   * bag, or anywhere else.
   */
  require?: ProofSource<Args>;
  /** How to verify the proof: the grant it must satisfy, or a custom `VerifyFn`. */
  verify: Verify;
  /**
   * This verifier's audience (resource-server / instance id), matched against the PCActn's signed `aud`:
   * a string must equal it; `null` opts out ("accept any audience"); OMITTING it fails closed when the
   * PCActn carries an `aud` (the safe default — don't silently lose cross-instance binding).
   */
  audience?: string | null;
  /** Defense-in-depth: assert the proof's `action.verb` equals this (bind the proof to THIS tool). */
  verb?: string;
  /** Observe a denial before it throws (e.g. metrics / audit). */
  onDeny?: (error: PcaToolDenied, input: Args) => void;
  /** Observe a successful verification before the original execute runs. */
  onVerified?: (result: VerifyResult, pcactn: PCActn, input: Args) => void;
}

// ---- proof sources ------------------------------------------------------------------------------------

/** True when `v` can be indexed as a record (safe narrowing without a cast). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object';
}

/** Read an encoded string PCActn from a `{ pca | pcaProof }` bag; undefined when neither is a string. */
function proofFromBag(bag: unknown): ProofInput | undefined {
  if (!isRecord(bag)) return undefined;
  const direct = bag['pca'] ?? bag['pcaProof'];
  return typeof direct === 'string' ? direct : undefined;
}

/**
 * Default {@link ProofSource}: read the encoded PCActn from the run context. The Agents SDK wraps the
 * caller's context as `runContext.context`, so we look at `runContext.context.{pca|pcaProof}` first, then
 * fall back to `runContext.{pca|pcaProof}` (for callers who pass the bag directly). Pass it through from
 * the run: `run(agent, input, { context: { pca: encoded } })`.
 */
export const proofFromRunContext: ProofSource<unknown> = (_input, runContext) =>
  proofFromBag(runContext.context) ?? proofFromBag(runContext);

/** A {@link ProofSource} that reads a base64url `PCA-Action` header from a headers-like bag on the tool input. */
export function proofFromInputHeaders<Args>(field = 'headers', header = 'PCA-Action'): ProofSource<Args> {
  return (input) => {
    if (!isRecord(input)) return undefined;
    const bag = input[field];
    if (!isRecord(bag)) return undefined;
    const value = bag[header];
    return typeof value === 'string' ? value : undefined;
  };
}

/** The guardrail-side default: read the proof from the run context the SDK passes as `args.context`. */
export const guardrailProofFromContext: GuardrailProofSource = (args) => {
  // `args.context` is the RunContext; `isRecord` narrows it (no cast), so we can read its `.context` bag.
  const outer = args.context;
  const inner = isRecord(outer) ? outer['context'] : undefined;
  return proofFromBag(inner) ?? proofFromBag(outer);
};

/** Decode a {@link ProofInput} to a PCActn. A string is tried as raw encoded JSON, then as a header value. */
function toPCActn(input: ProofInput): PCActn {
  if (typeof input !== 'string') return input;
  try {
    return decodePCActn(input);
  } catch {
    return decodePCActn(decodePcaHeader(input));
  }
}

async function runVerify(verify: Verify, pcactn: PCActn, audience: string | null | undefined): Promise<VerifyResult> {
  if (typeof verify === 'function') return verify(pcactn);
  const nowEpoch = typeof verify.nowEpoch === 'function' ? verify.nowEpoch() : verify.nowEpoch;
  return verifyPCActnCore(pcactn, {
    grant: verify.grant,
    audience,
    ...(nowEpoch !== undefined ? { nowEpoch } : {}),
    ...(verify.enforce !== undefined ? { enforce: verify.enforce } : {}),
    ...(verify.hooks !== undefined ? { hooks: verify.hooks } : {}),
  });
}

/**
 * Shared decode + bind + verify pipeline. Returns the verified PCActn, or throws {@link PcaToolDenied}.
 * `label` names the boundary (the configured verb, or `(tool)`) for the error's `verb` when unknown.
 */
async function assertProof(
  raw: ProofInput | null | undefined,
  opts: { verify: Verify; audience?: string | null; verb?: string; label: string },
): Promise<{ pcactn: PCActn; result: VerifyResult }> {
  if (raw === null || raw === undefined) {
    throw new PcaToolDenied('no proof-carrying action present on the call', opts.label, 'missing');
  }
  let pcactn: PCActn;
  try {
    pcactn = toPCActn(raw);
  } catch (cause) {
    throw new PcaToolDenied(`proof could not be decoded: ${String(cause)}`, opts.label, 'malformed');
  }
  if (opts.verb !== undefined && pcactn.action.verb !== opts.verb) {
    throw new PcaToolDenied(
      `proof is for '${pcactn.action.verb}', not this tool's '${opts.verb}'`,
      pcactn.action.verb,
      'binding',
    );
  }
  const result = await runVerify(opts.verify, pcactn, opts.audience);
  if (!result.allow) {
    throw new PcaToolDenied(result.reason ?? 'verification failed', pcactn.action.verb, 'verify', result.checks);
  }
  return { pcactn, result };
}

// ---- the execution guard ------------------------------------------------------------------------------

/**
 * Wrap an Agents-SDK tool so each `execute(input, runContext)` first REQUIRES + VERIFIES a proof-carrying
 * action (fail closed → throws {@link PcaToolDenied}), then runs the original `execute`. The returned tool
 * has the SAME shape and preserves every non-`execute` field, so it is a drop-in replacement in the
 * agent's `tools` list.
 */
export function withPcaTool<Args extends Record<string, unknown>, Result>(
  tool: AgentTool<Args, Result>,
  options: WithPcaToolOptions<Args>,
): AgentTool<Args, Result> {
  // proofFromRunContext is ProofSource<unknown>; a source that accepts `unknown` accepts Args
  // (contravariant), so it satisfies ProofSource<Args> by assignment — no cast needed.
  const source: ProofSource<Args> = options.require ?? proofFromRunContext;
  const label = options.verb ?? tool.name ?? '(tool)';

  // Method syntax (not an arrow property): the target `AgentTool.execute` is a METHOD, so its parameters
  // are checked bivariantly — a method shim with concrete arg types assigns cleanly, no `any`, no cast.
  return {
    ...tool,
    async execute(input: Args, runContext?: AgentRunContext): Promise<Result> {
      const raw = source(input, runContext ?? {});
      let verified: { pcactn: PCActn; result: VerifyResult };
      try {
        verified = await assertProof(raw, {
          verify: options.verify,
          ...(options.audience !== undefined ? { audience: options.audience } : {}),
          ...(options.verb !== undefined ? { verb: options.verb } : {}),
          label,
        });
      } catch (err) {
        if (err instanceof PcaToolDenied) options.onDeny?.(err, input);
        throw err;
      }
      options.onVerified?.(verified.result, verified.pcactn, input);
      if (typeof tool.execute !== 'function') throw new Error('withPcaTool: the wrapped tool has no execute()');
      return tool.execute(input, runContext);
    },
  };
}

/** Per-tool overrides layered over the shared options in {@link pcaTools} (e.g. bind each tool's `verb`). */
export type PcaToolOverride<Args> = Partial<WithPcaToolOptions<Args>>;

export interface PcaToolsOptions<T extends Record<string, AgentTool>> extends WithPcaToolOptions<Record<string, unknown>> {
  /** Override shared options for specific tools (commonly `{ refund: { verb: 'stripe.refund' } }`). */
  per?: { [K in keyof T]?: PcaToolOverride<Record<string, unknown>> };
  /** Guard only these tools; every other entry passes through unchanged. Default: guard all. */
  only?: readonly (keyof T)[];
}

function mergeToolOptions(
  base: WithPcaToolOptions<Record<string, unknown>>,
  over: PcaToolOverride<Record<string, unknown>> | undefined,
): WithPcaToolOptions<Record<string, unknown>> {
  if (!over) return base;
  return {
    verify: over.verify ?? base.verify,
    ...((over.require ?? base.require) !== undefined ? { require: over.require ?? base.require } : {}),
    ...('audience' in over ? { audience: over.audience } : base.audience !== undefined ? { audience: base.audience } : {}),
    ...((over.verb ?? base.verb) !== undefined ? { verb: over.verb ?? base.verb } : {}),
    ...(over.onDeny ?? base.onDeny ? { onDeny: over.onDeny ?? base.onDeny } : {}),
    ...(over.onVerified ?? base.onVerified ? { onVerified: over.onVerified ?? base.onVerified } : {}),
  };
}

/**
 * Guard a whole `{ name: tool }` record in one call — the drop-in integration:
 * `tools: Object.values(pcaTools({ refund, lookup }, { verify: { grant }, audience }))`. Every tool is
 * guarded with the shared options (override per tool via `per`, or limit the set via `only`; untouched
 * tools pass through unchanged by reference).
 */
export function pcaTools<T extends Record<string, AgentTool>>(record: T, options: PcaToolsOptions<T>): T {
  const only = options.only ? new Set<keyof T>(options.only) : undefined;
  const out: Record<string, AgentTool> = {};
  for (const [name, tool] of Object.entries(record)) {
    if (only && !only.has(name)) {
      out[name] = tool;
      continue;
    }
    out[name] = withPcaTool(tool, mergeToolOptions(options, options.per?.[name]));
  }
  return out as T;
}

// ---- guardrails: reject a run / tool call lacking a valid proof ---------------------------------------

export interface PcaGuardrailOptions {
  /** How to find the proof. Default reads it from the run context the SDK passes as `args.context`. */
  require?: GuardrailProofSource;
  /** How to verify the proof: the grant it must satisfy, or a custom `VerifyFn`. */
  verify: Verify;
  /** The verifier's audience (see {@link WithPcaToolOptions.audience}). */
  audience?: string | null;
  /** Bind the proof to a specific verb. */
  verb?: string;
  /** The guardrail's name (shown in traces / the thrown tripwire). */
  name?: string;
}

/** Build the shared guardrail `execute`: verify the proof; trip (reject) on any denial. */
function guardrailExecute(
  source: GuardrailProofSource,
  opts: { verify: Verify; audience?: string | null; verb?: string },
): (args: GuardrailArgs) => Promise<GuardrailFunctionOutput> {
  return async (args) => {
    try {
      const { pcactn } = await assertProof(source(args), {
        verify: opts.verify,
        ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
        ...(opts.verb !== undefined ? { verb: opts.verb } : {}),
        label: opts.verb ?? '(run)',
      });
      return { tripwireTriggered: false, outputInfo: { verb: pcactn.action.verb } };
    } catch (err) {
      if (err instanceof PcaToolDenied) {
        return { tripwireTriggered: true, outputInfo: { kind: err.kind, verb: err.verb, reason: err.message, checks: err.checks } };
      }
      throw err;
    }
  };
}

/**
 * An Agents-SDK **input guardrail**: it runs once at the top of a run and trips the tripwire (rejecting
 * the run before any step executes) when the run context carries no valid proof. Add it to the agent's
 * `inputGuardrails`.
 */
export function pcaInputGuardrail(options: PcaGuardrailOptions): Guardrail {
  const source = options.require ?? guardrailProofFromContext;
  return {
    name: options.name ?? 'pca-input-guardrail',
    execute: guardrailExecute(source, {
      verify: options.verify,
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      ...(options.verb !== undefined ? { verb: options.verb } : {}),
    }),
  };
}

/**
 * An Agents-SDK **tool guardrail**: the same proof gate scoped to a tool call. By default it reads the
 * proof from the tool call's run context; pass `require` to read it from the tool input instead. Trips
 * the tripwire (rejecting the call) when no valid proof is present — a lighter-weight alternative to
 * {@link withPcaTool} when you want the SDK's guardrail machinery to surface the denial.
 */
export function pcaToolGuard(options: PcaGuardrailOptions): Guardrail {
  const source = options.require ?? guardrailProofFromContext;
  return {
    name: options.name ?? 'pca-tool-guard',
    execute: guardrailExecute(source, {
      verify: options.verify,
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      ...(options.verb !== undefined ? { verb: options.verb } : {}),
    }),
  };
}

// ---- step-up: map a risky tool to needsApproval / the interruption flow -------------------------------

/** Map a tool name (+ its input) to the PCA action to review. Return null to treat the tool as unguarded (auto). */
export type ToolIntent = (
  tool: string,
  input?: Record<string, unknown>,
) => { verb: string; resource: string; params?: Record<string, unknown> } | null;

export interface StepUpOptions {
  /** Which PCA (verb, resource, params) a tool call maps to for risk review. */
  intent: ToolIntent;
  /** Standing "approve this class for N hours" grants that downgrade a matching step-up to auto. */
  standing?: ClassApproval[];
  /** Plaintext goal to carry on any step-up request (the "because you asked to…" line). */
  goal?: string;
  /** Review clock (epoch ms). */
  now?: number;
}

/** The outcome of reviewing one intended tool call. */
export interface ToolReview {
  tool: string;
  review: Review;
}

/**
 * Review a single intended tool call against the agent's grant: `auto` (no human needed), `deny` (the
 * grant forbids it), or `step_up` with a {@link StepUpRequest} — tier 2 = guardian co-sign, tier 3 =
 * human. A step-up request is exactly what a PCA FROST round / CIBA push carries to the approver, and
 * exactly what the SDK's `needsApproval` interruption resolves.
 */
export function reviewToolCall(
  agent: Agent,
  tool: string,
  input: Record<string, unknown> | undefined,
  opts: StepUpOptions,
): ToolReview {
  const mapped = opts.intent(tool, input);
  if (!mapped) return { tool, review: { kind: 'auto' } };
  const review = reviewAction(agent, mapped.verb, mapped.resource, mapped.params ?? input, {
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.goal !== undefined ? { goal: opts.goal } : {}),
    ...(opts.standing !== undefined ? { standing: opts.standing } : {}),
  });
  return { tool, review };
}

/** A step-up a tool call raised (what the approval inbox / FROST round / SDK interruption receives). */
export interface PendingStepUp {
  tool: string;
  request: StepUpRequest;
}

/** The step-up requests from a batch of {@link ToolReview}s (filters out auto / deny). */
export function pendingStepUps(reviews: readonly ToolReview[]): PendingStepUp[] {
  const out: PendingStepUp[] = [];
  for (const r of reviews) if (r.review.kind === 'step_up') out.push({ tool: r.tool, request: r.review.request });
  return out;
}

export interface PcaNeedsApprovalOptions extends StepUpOptions {
  /** The tool name to review (defaults to the wrapped tool's `name` in {@link withApproval}). */
  toolName?: string;
  /** Return true when a step-up request has already been co-signed (your FROST/CIBA result): it is then let through (no approval needed). */
  approved?: (request: StepUpRequest) => boolean;
  /** Receives each step-up this call raised — push it to the approval inbox / open the FROST round. */
  onStepUp?: (pending: PendingStepUp) => void;
  /**
   * Whether a policy `deny` also routes to approval (so the run interrupts and the approver rejects it,
   * rather than the tool silently running). Default true — fail safe.
   */
  denyNeedsApproval?: boolean;
}

/**
 * Build an Agents-SDK `needsApproval` callback from PCA risk review. For each call it reviews the
 * intended action: `auto` → false (run without interruption); `step_up` not yet approved → routes the
 * request to `onStepUp` and returns true (the SDK interrupts for a tier-2/3 co-sign); an already-approved
 * step-up → false; `deny` → true by default (interrupt so the approver can reject it). A tool with no
 * intent mapping is `auto`.
 */
export function pcaNeedsApproval(
  agent: Agent,
  opts: PcaNeedsApprovalOptions,
): (runContext: AgentRunContext, input: Record<string, unknown>, callId?: string) => boolean {
  const denyNeedsApproval = opts.denyNeedsApproval ?? true;
  const toolName = opts.toolName ?? '(tool)';
  return (_runContext, input) => {
    const { review } = reviewToolCall(agent, toolName, input, opts);
    if (review.kind === 'auto') return false;
    if (review.kind === 'deny') return denyNeedsApproval;
    if (opts.approved?.(review.request)) return false;
    opts.onStepUp?.({ tool: toolName, request: review.request });
    return true;
  };
}

/**
 * Set an Agents-SDK tool's `needsApproval` from PCA risk review (tier 2 guardian / tier 3 human). The
 * returned tool interrupts the run for a co-sign on risky calls; resolve the interruption with the
 * {@link StepUpRequest} delivered to `onStepUp`. The tool's name seeds the intent lookup unless `toolName`
 * is given. Every other field is preserved.
 */
export function withApproval<Args extends Record<string, unknown>, Result>(
  tool: AgentTool<Args, Result>,
  agent: Agent,
  opts: PcaNeedsApprovalOptions,
): AgentTool<Args, Result> {
  const toolName = opts.toolName ?? tool.name ?? '(tool)';
  const needsApproval = pcaNeedsApproval(agent, { ...opts, toolName });
  return { ...tool, needsApproval };
}

// ---- re-exports: the attach side (sibling adapter) + the core symbols a guard author needs ------------

export {
  // attach side (reuse the generic AI-SDK adapter rather than duplicating it)
  withPCA,
  withPCATools,
  bridgeToolCall,
  pcaHeaders,
  // verify side (so callers don't need a second import of the core)
  verifyPCActnCore,
  decodePCActn,
  reviewAction,
  type Agent,
  type AiSdkTool,
  type PcaCall,
  type PCActn,
  type Capability,
  type VerifyResult,
  type CheckStatus,
  type Review,
  type StepUpRequest,
  type ClassApproval,
};
