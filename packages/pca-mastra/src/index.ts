/**
 * Mastra tool-EXECUTION guard for Proof-Carrying Authority.
 *
 * Mastra (https://mastra.ai) is a TypeScript agent framework: you declare tools with
 * `createTool({ id, description, inputSchema, outputSchema, execute })` and compose workflows from
 * `createStep(...)`. A Mastra tool's `execute` receives a SINGLE object — `{ context, runtimeContext, … }`
 * — where `context` is the validated input and `runtimeContext` is the per-run context bag.
 *
 * This package makes each Mastra tool proof-carrying at the point of execution. `withPcaTool` wraps a
 * tool so its `execute({ context, runtimeContext })` first REQUIRES a proof-carrying action for THIS
 * call (by convention it rides on the run context under `pca` / `PCA-Action`), VERIFIES it with the PCA
 * core (fail closed → throws a typed {@link PcaToolDenied} that Mastra surfaces as a tool error), and
 * only then runs the original `execute`. A guard at the model call only constrains what the model is
 * *asked*; the authority that matters is checked where the effect is produced.
 *
 * Reuse, not duplication: the ATTACH side (make the agent emit + carry a PCActn when it CALLS a tool) is
 * the generic {@link withPCA} / {@link withPCATools} from `@atlasauth/pca-ai-sdk`, re-exported here; the
 * VERIFY side is `verifyPCActnCore` from the core. We only add the Mastra-shaped execution boundary.
 *
 * Structural, zero-runtime coupling to `@mastra/core`: we touch only `id` / `description` /
 * `inputSchema` / `outputSchema` / `execute` and preserve every other field, and the tool / step shapes
 * are duck-typed against minimal interfaces — so this compiles and tests without Mastra installed, and
 * slots into any Mastra version via `tools: pcaTools({ … }, { verify })`.
 *
 * HONESTY: verification here is REAL (signature + capability chain + plan inclusion + audience +
 * validity window + counter, via `verifyPCActnCore`). It is still only as strong as the grant you verify
 * against and the gates you enable; it does not replace the resource server when the tool makes a remote
 * call — it makes the LOCAL execution boundary refuse to act without a valid PCActn.
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
  type PcaCall,
  bridgeToolCall,
  pcaHeaders,
  withPCA,
  withPCATools,
} from '@atlasauth/pca-ai-sdk';

// ---- the Mastra tool / step shapes (a duck-typed subset; `@mastra/core` is NOT a dependency) --------

/** True when `v` can be indexed as a record (safe narrowing without a cast). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object';
}

/**
 * The per-run context bag Mastra threads through a tool/step `execute` (a `RuntimeContext`, a typed Map
 * with `.get(key)`). Duck-typed: we only ever READ via `.get`. Optional and forward-compatible.
 */
export interface RuntimeContextLike {
  get(key: string): unknown;
  [k: string]: unknown;
}

/**
 * The SINGLE object Mastra passes to a tool's `execute` (v0.10+: `{ context, runtimeContext, mastra,
 * runId, … }`). `context` is the validated input; the proof rides on `runtimeContext` by convention.
 * The index signature keeps us forward-compatible with the fields Mastra keeps adding.
 */
export interface MastraToolExecuteContext<INPUT = Record<string, unknown>> {
  context: INPUT;
  runtimeContext?: RuntimeContextLike;
  runId?: string;
  [k: string]: unknown;
}

/**
 * Minimal structural shape of a Mastra tool (the object `createTool(...)` returns). `execute` is a
 * METHOD (not an arrow property) on purpose: method signatures are bivariant, so a tool with a concrete
 * `INPUT`/`OUTPUT` assigns cleanly to the general `MastraTool` when collected in a record — no `any`, no
 * cast. We touch only these fields and preserve the rest.
 */
export interface MastraTool<INPUT = Record<string, unknown>, OUTPUT = unknown> {
  id?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  execute?(ctx: MastraToolExecuteContext<INPUT>, options?: unknown): Promise<OUTPUT> | OUTPUT;
  [k: string]: unknown;
}

// ---- the execute-time proof surface ---------------------------------------------------------------

/** A proof as it arrives at the tool: the PCActn object, its encoded JSON, or a base64url `PCA-Action` header value. */
export type ProofInput = PCActn | string;

/** Pull the proof-carrying action for THIS call out of the execute context (return null/undefined to fail closed). */
export type ProofSource<INPUT> = (ctx: MastraToolExecuteContext<INPUT>) => ProofInput | null | undefined;

/** Why a guarded execute refused. */
export type PcaToolDenialKind = 'missing' | 'malformed' | 'verify' | 'binding';

/** Typed error thrown when a guarded tool refuses to run; Mastra surfaces it as a tool error. */
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

export interface WithPcaToolOptions<INPUT> {
  /**
   * How to find the proof for a call. Default: {@link proofFromRunContext} — reads a string/object
   * PCActn from `runtimeContext.get('pca')` (then `'pcaProof'`, then the `'PCA-Action'` header value).
   * Override to read it from the tool's `context`, a header bag, or anywhere else.
   */
  require?: ProofSource<INPUT>;
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
  onDeny?: (error: PcaToolDenied, ctx: MastraToolExecuteContext<INPUT>) => void;
  /** Observe a successful verification before the original execute runs. */
  onVerified?: (result: VerifyResult, pcactn: PCActn, ctx: MastraToolExecuteContext<INPUT>) => void;
}

// ---- proof sources --------------------------------------------------------------------------------

/**
 * Default {@link ProofSource}: read the encoded PCActn from the run context (Mastra's `runtimeContext`).
 * Set it before the run, e.g. `runtimeContext.set('pca', encoded)`. Looks at `pca`, then `pcaProof`,
 * then the `PCA-Action` header value; returns undefined (→ fail closed) when none is a string. To pass a
 * PCActn *object* (not an encoded string), use a custom `require` that returns it directly.
 */
export const proofFromRunContext: ProofSource<unknown> = (ctx) => {
  const rc = ctx.runtimeContext;
  if (!rc || typeof rc.get !== 'function') return undefined;
  for (const key of ['pca', 'pcaProof', 'PCA-Action']) {
    const v = rc.get(key);
    if (typeof v === 'string') return v;
  }
  return undefined;
};

/**
 * A {@link ProofSource} that reads a base64url `PCA-Action` header from a headers-like bag on the tool's
 * `context` (e.g. when the proof is passed as a validated input field).
 */
export function proofFromContextHeaders<INPUT>(field = 'headers', header = 'PCA-Action'): ProofSource<INPUT> {
  return (ctx) => {
    if (!isRecord(ctx.context)) return undefined;
    const bag = ctx.context[field];
    if (!isRecord(bag)) return undefined;
    const value = bag[header];
    return typeof value === 'string' ? value : undefined;
  };
}

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

// ---- the execution guard --------------------------------------------------------------------------

/**
 * Wrap a Mastra tool so each `execute({ context, runtimeContext, … })` first REQUIRES + VERIFIES a
 * proof-carrying action (fail closed → throws {@link PcaToolDenied}), then runs the original `execute`.
 * The returned tool has the SAME shape and preserves every non-`execute` field, so it is a drop-in
 * replacement for the one you passed to `createTool`.
 */
export function withPcaTool<INPUT extends Record<string, unknown>, OUTPUT>(
  tool: MastraTool<INPUT, OUTPUT>,
  options: WithPcaToolOptions<INPUT>,
): MastraTool<INPUT, OUTPUT> {
  // proofFromRunContext is ProofSource<unknown>; a source that accepts `unknown` accepts INPUT
  // (contravariant), so it satisfies ProofSource<INPUT> by assignment — no cast needed.
  const source: ProofSource<INPUT> = options.require ?? proofFromRunContext;
  const label = options.verb ?? '(tool)';

  // Method syntax (not an arrow property): the target `MastraTool.execute` is a METHOD, so its parameters
  // are checked bivariantly — a method shim with concrete arg types assigns cleanly, no `any`, no cast.
  return {
    ...tool,
    async execute(ctx: MastraToolExecuteContext<INPUT>, opts?: unknown): Promise<OUTPUT> {
      const raw = source(ctx);
      if (raw === null || raw === undefined) {
        const err = new PcaToolDenied('no proof-carrying action present on the call', label, 'missing');
        options.onDeny?.(err, ctx);
        throw err;
      }
      let pcactn: PCActn;
      try {
        pcactn = toPCActn(raw);
      } catch (cause) {
        const err = new PcaToolDenied(`proof could not be decoded: ${String(cause)}`, label, 'malformed');
        options.onDeny?.(err, ctx);
        throw err;
      }
      if (options.verb !== undefined && pcactn.action.verb !== options.verb) {
        const err = new PcaToolDenied(
          `proof is for '${pcactn.action.verb}', not this tool's '${options.verb}'`,
          pcactn.action.verb,
          'binding',
        );
        options.onDeny?.(err, ctx);
        throw err;
      }
      const result = await runVerify(options.verify, pcactn, options.audience);
      if (!result.allow) {
        const err = new PcaToolDenied(result.reason ?? 'verification failed', pcactn.action.verb, 'verify', result.checks);
        options.onDeny?.(err, ctx);
        throw err;
      }
      options.onVerified?.(result, pcactn, ctx);
      if (typeof tool.execute !== 'function') throw new Error('withPcaTool: the wrapped tool has no execute()');
      return tool.execute(ctx, opts);
    },
  };
}

/** Per-tool overrides layered over the shared options in {@link pcaTools} (e.g. bind each tool's `verb`). */
export type PcaToolOverride<INPUT> = Partial<WithPcaToolOptions<INPUT>>;

export interface PcaToolsOptions<T extends Record<string, MastraTool>> extends WithPcaToolOptions<Record<string, unknown>> {
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
 * Guard a whole `{ id: tool }` record in one call — the drop-in integration:
 * `tools: pcaTools({ refund, lookup }, { verify: { grant }, audience })`. Every tool is guarded with the
 * shared options (override per tool via `per`, or limit the set via `only`; untouched tools pass through).
 */
export function pcaTools<T extends Record<string, MastraTool>>(record: T, options: PcaToolsOptions<T>): T {
  const only = options.only ? new Set<keyof T>(options.only) : undefined;
  const out: Record<string, MastraTool> = {};
  for (const [name, tool] of Object.entries(record)) {
    if (only && !only.has(name)) {
      out[name] = tool;
      continue;
    }
    out[name] = withPcaTool(tool, mergeToolOptions(options, options.per?.[name]));
  }
  // The single sanctioned generic-record cast (matches pca-ai-sdk / pca-vercel-ai's `withPCATools`): we
  // rebuild the record key-for-key preserving each tool's shape, so the output is a `T`.
  return out as T;
}

// ---- step-up on a workflow step -------------------------------------------------------------------

/**
 * The SINGLE object Mastra passes to a workflow STEP's `execute` (`{ inputData, runtimeContext, … }`).
 * A step receives its upstream data as `inputData` (not `context`, as a tool does).
 */
export interface MastraStepExecuteContext<INPUT = Record<string, unknown>> {
  inputData: INPUT;
  runtimeContext?: RuntimeContextLike;
  [k: string]: unknown;
}

/** Minimal structural shape of a Mastra workflow step (what `createStep(...)` returns). */
export interface MastraStep<INPUT = Record<string, unknown>, OUTPUT = unknown> {
  id?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  execute?(ctx: MastraStepExecuteContext<INPUT>): Promise<OUTPUT> | OUTPUT;
  [k: string]: unknown;
}

/** Map a step id (+ its input) to the PCA action to review. Return null to treat the step as unguarded (auto). */
export type StepIntent = (
  stepId: string,
  input?: Record<string, unknown>,
) => { verb: string; resource: string; params?: Record<string, unknown> } | null;

export interface StepUpOptions {
  /** Which PCA (verb, resource, params) a step maps to for risk review. */
  intent: StepIntent;
  /** Standing "approve this class for N hours" grants that downgrade a matching step-up to auto. */
  standing?: ClassApproval[];
  /** Plaintext goal to carry on any step-up request (the "because you asked to…" line). */
  goal?: string;
  /** Review clock (epoch ms). */
  now?: number;
}

/** The outcome of reviewing one workflow step. */
export interface StepReview {
  step: string;
  review: Review;
}

/**
 * Review a single workflow step against the agent's grant: `auto` (no human needed), `deny` (the grant
 * forbids it), or `step_up` with a {@link StepUpRequest} — tier 2 = guardian co-sign, tier 3 = human. A
 * step-up request is exactly what a PCA FROST round / CIBA push carries to the approver.
 */
export function reviewStep(
  agent: Agent,
  stepId: string,
  input: Record<string, unknown> | undefined,
  opts: StepUpOptions,
): StepReview {
  const mapped = opts.intent(stepId, input);
  if (!mapped) return { step: stepId, review: { kind: 'auto' } };
  const review = reviewAction(agent, mapped.verb, mapped.resource, mapped.params ?? input, {
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.goal !== undefined ? { goal: opts.goal } : {}),
    ...(opts.standing !== undefined ? { standing: opts.standing } : {}),
  });
  return { step: stepId, review };
}

/** A step-up a step raised (what the approval inbox / FROST round receives). */
export interface PendingStepUp {
  step: string;
  request: StepUpRequest;
}

/** The step-up requests from a batch of {@link StepReview}s (filters out auto / deny). */
export function pendingStepUps(reviews: readonly StepReview[]): PendingStepUp[] {
  const out: PendingStepUp[] = [];
  for (const r of reviews) if (r.review.kind === 'step_up') out.push({ step: r.step, request: r.review.request });
  return out;
}

/** Typed error thrown when a guarded step needs a (not-yet-granted) co-sign; Mastra surfaces it as a step error. */
export class PcaStepUpRequired extends Error {
  constructor(
    public readonly request: StepUpRequest,
  ) {
    super(`PCA step-up required (tier ${request.tier}) for ${request.verb} on ${request.resource}: ${request.reason}`);
    this.name = 'PcaStepUpRequired';
  }
}

/** Typed error thrown when the grant outright forbids a guarded step; Mastra surfaces it as a step error. */
export class PcaStepDenied extends Error {
  constructor(
    public readonly stepId: string,
    public readonly reason: string,
  ) {
    super(`PCA step denied for ${stepId}: ${reason}`);
    this.name = 'PcaStepDenied';
  }
}

export interface GuardStepOptions extends StepUpOptions {
  /** The agent whose grant the step is reviewed against. */
  agent: Agent;
  /** Override the step id used for the intent lookup (defaults to the step's own `id`). */
  stepId?: string;
  /** Return true when a step-up request has already been co-signed (your FROST/CIBA result): let it through. */
  approved?: (request: StepUpRequest) => boolean;
  /** Receives a step-up this step raised — push it to the approval inbox / open the FROST round. */
  onStepUp?: (pending: PendingStepUp) => void;
}

/**
 * Wrap a Mastra workflow step so it pauses on risk: before the original `execute` runs, the step is
 * reviewed against the agent's grant. `auto` runs through; `deny` throws {@link PcaStepDenied}; a
 * `step_up` that is not yet `approved` is routed to `onStepUp` (→ FROST/CIBA) and throws
 * {@link PcaStepUpRequired}, so the workflow cannot autonomously run a risky step — it waits for a human /
 * guardian co-sign. The returned step has the SAME shape and preserves every non-`execute` field.
 */
export function guardStep<INPUT extends Record<string, unknown>, OUTPUT>(
  step: MastraStep<INPUT, OUTPUT>,
  opts: GuardStepOptions,
): MastraStep<INPUT, OUTPUT> {
  const review: StepUpOptions = {
    intent: opts.intent,
    ...(opts.standing !== undefined ? { standing: opts.standing } : {}),
    ...(opts.goal !== undefined ? { goal: opts.goal } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
  };
  return {
    ...step,
    async execute(ctx: MastraStepExecuteContext<INPUT>): Promise<OUTPUT> {
      const stepId = opts.stepId ?? step.id ?? '(step)';
      const { review: verdict } = reviewStep(opts.agent, stepId, ctx.inputData, review);
      if (verdict.kind === 'deny') throw new PcaStepDenied(stepId, verdict.reason);
      if (verdict.kind === 'step_up' && !opts.approved?.(verdict.request)) {
        opts.onStepUp?.({ step: stepId, request: verdict.request });
        throw new PcaStepUpRequired(verdict.request);
      }
      if (typeof step.execute !== 'function') throw new Error('guardStep: the wrapped step has no execute()');
      return step.execute(ctx);
    },
  };
}

// ---- re-exports: the attach side (sibling adapter) + the core symbols a guard author needs ----------

export {
  // attach side (reuse the generic Vercel adapter rather than duplicating it)
  withPCA,
  withPCATools,
  bridgeToolCall,
  pcaHeaders,
  // verify side (so callers don't need a second import of the core)
  verifyPCActnCore,
  decodePCActn,
  reviewAction,
  type Agent,
  type PcaCall,
  type PCActn,
  type Capability,
  type VerifyResult,
  type CheckStatus,
  type Review,
  type StepUpRequest,
  type ClassApproval,
};
