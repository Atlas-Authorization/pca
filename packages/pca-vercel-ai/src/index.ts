/**
 * Vercel AI SDK tool-EXECUTION guard for Proof-Carrying Authority.
 *
 * The sibling `@atlasauth/pca-ai-sdk` makes the agent ATTACH a PCActn when it *calls* a tool (the
 * client/producer side). This package closes the other half: it makes each tool call proof-carrying at
 * the *point of execution*. `withPcaTool` wraps a Vercel AI SDK tool so its `execute(args, options)`
 * first REQUIRES a valid proof-carrying action for this call, VERIFIES it with the PCA core (fail
 * closed), and only then runs the original `execute`. A missing / malformed / invalid proof throws a
 * typed {@link PcaToolDenied} — which the AI SDK surfaces as a tool error — so the side effect never
 * happens. This matters because a guard at the model call only constrains what the model is *asked*;
 * the authority that actually matters is checked where the effect is produced.
 *
 * Structural, zero-runtime coupling to `ai`: we touch only `description` / `parameters` /
 * `inputSchema` / `execute` and preserve every other field, and the agent-loop hooks (`prepareStep`)
 * are typed against a minimal structural interface — so this compiles and tests without the `ai`
 * package installed, and slots into any v4/v5/v6 agent via `tools: pcaTools({ ... }, { verify })`.
 *
 * HONESTY: verification here is REAL (signature + capability chain + plan inclusion + audience +
 * validity window + counter, via `verifyPCActnCore`). It is still only as strong as the grant you
 * verify against and the gates you enable; it does not replace the resource server when the tool makes
 * a remote call — it makes the LOCAL execution boundary refuse to act without a valid PCActn.
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

// ---- the execute-time proof surface ---------------------------------------------------------------

/**
 * Structural shape of the `options` the AI SDK passes as the 2nd argument to a tool's `execute`
 * (v5: `{ toolCallId, messages, abortSignal, experimental_context }`). Every field is optional and the
 * index signature keeps us forward-compatible — we only ever read `experimental_context`, which is the
 * caller-controlled channel a proof rides on (`generateText({ experimental_context: { pca } })`).
 */
export interface PcaToolExecuteOptions {
  toolCallId?: string;
  messages?: unknown;
  abortSignal?: unknown;
  experimental_context?: unknown;
  [k: string]: unknown;
}

/** A proof as it arrives at the tool: the PCActn object, its encoded JSON, or a base64url `PCA-Action` header value. */
export type ProofInput = PCActn | string;

/** Pull the proof-carrying action for THIS call out of the execute options (return null/undefined to fail closed). */
export type ProofSource<ARGS> = (args: ARGS, options: PcaToolExecuteOptions) => ProofInput | null | undefined;

/** Why a guarded execute refused. */
export type PcaToolDenialKind = 'missing' | 'malformed' | 'verify' | 'binding';

/** Typed error thrown when a guarded tool refuses to run; the AI SDK surfaces it as a tool error. */
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

export interface WithPcaToolOptions<ARGS> {
  /**
   * How to find the proof for a call. Default: {@link proofFromContext} — reads a string PCActn from
   * `options.experimental_context.pca` (or `.pcaProof`). Override to read it from the args, a header
   * bag, or anywhere else.
   */
  require?: ProofSource<ARGS>;
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
  onDeny?: (error: PcaToolDenied, args: ARGS) => void;
  /** Observe a successful verification before the original execute runs. */
  onVerified?: (result: VerifyResult, pcactn: PCActn, args: ARGS) => void;
}

// ---- proof sources --------------------------------------------------------------------------------

/** True when `v` can be indexed as a record (safe narrowing without a cast). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object';
}

/**
 * Default {@link ProofSource}: read the encoded PCActn from the step's `experimental_context`. Pass it
 * through from the model call, e.g. `generateText({ tools, experimental_context: { pca: encoded } })`.
 * Looks at `pca` then `pcaProof`; returns undefined (→ fail closed) when neither is a string.
 */
export const proofFromContext: ProofSource<unknown> = (_args, options) => {
  const ctx = options.experimental_context;
  if (isRecord(ctx)) {
    const direct = ctx['pca'] ?? ctx['pcaProof'];
    if (typeof direct === 'string') return direct;
  }
  return undefined;
};

/** A {@link ProofSource} that reads a base64url `PCA-Action` header from a headers-like bag on the args. */
export function proofFromArgHeaders<ARGS>(field = 'headers', header = 'PCA-Action'): ProofSource<ARGS> {
  return (args) => {
    if (!isRecord(args)) return undefined;
    const bag = args[field];
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
 * Wrap a Vercel AI SDK tool so each `execute(args, options)` first REQUIRES + VERIFIES a proof-carrying
 * action (fail closed → throws {@link PcaToolDenied}), then runs the original `execute`. The returned
 * tool has the SAME shape and preserves every non-`execute` field, so it is a drop-in replacement.
 */
export function withPcaTool<ARGS extends Record<string, unknown>, RESULT>(
  tool: AiSdkTool<ARGS, RESULT>,
  options: WithPcaToolOptions<ARGS>,
): AiSdkTool<ARGS, RESULT> {
  // proofFromContext is ProofSource<unknown>; a source that accepts `unknown` accepts ARGS (contravariant),
  // so it satisfies ProofSource<ARGS> by assignment — no cast needed.
  const source: ProofSource<ARGS> = options.require ?? proofFromContext;
  const label = options.verb ?? '(tool)';

  // Method syntax (not an arrow property): the target `AiSdkTool.execute` is a METHOD, so its parameters
  // are checked bivariantly — a method shim with concrete arg types assigns cleanly, no `any`, no cast.
  return {
    ...tool,
    async execute(args: ARGS, opts?: PcaToolExecuteOptions): Promise<RESULT> {
      const raw = source(args, opts ?? {});
      if (raw === null || raw === undefined) {
        const err = new PcaToolDenied('no proof-carrying action present on the call', label, 'missing');
        options.onDeny?.(err, args);
        throw err;
      }
      let pcactn: PCActn;
      try {
        pcactn = toPCActn(raw);
      } catch (cause) {
        const err = new PcaToolDenied(`proof could not be decoded: ${String(cause)}`, label, 'malformed');
        options.onDeny?.(err, args);
        throw err;
      }
      if (options.verb !== undefined && pcactn.action.verb !== options.verb) {
        const err = new PcaToolDenied(
          `proof is for '${pcactn.action.verb}', not this tool's '${options.verb}'`,
          pcactn.action.verb,
          'binding',
        );
        options.onDeny?.(err, args);
        throw err;
      }
      const result = await runVerify(options.verify, pcactn, options.audience);
      if (!result.allow) {
        const err = new PcaToolDenied(result.reason ?? 'verification failed', pcactn.action.verb, 'verify', result.checks);
        options.onDeny?.(err, args);
        throw err;
      }
      options.onVerified?.(result, pcactn, args);
      if (typeof tool.execute !== 'function') throw new Error('withPcaTool: the wrapped tool has no execute()');
      return tool.execute(args, opts);
    },
  };
}

/** Per-tool overrides layered over the shared options in {@link pcaTools} (e.g. bind each tool's `verb`). */
export type PcaToolOverride<ARGS> = Partial<WithPcaToolOptions<ARGS>>;

export interface PcaToolsOptions<T extends Record<string, AiSdkTool>> extends WithPcaToolOptions<Record<string, unknown>> {
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
    ...(( over.require ?? base.require) !== undefined ? { require: over.require ?? base.require } : {}),
    ...('audience' in over ? { audience: over.audience } : base.audience !== undefined ? { audience: base.audience } : {}),
    ...((over.verb ?? base.verb) !== undefined ? { verb: over.verb ?? base.verb } : {}),
    ...(over.onDeny ?? base.onDeny ? { onDeny: over.onDeny ?? base.onDeny } : {}),
    ...(over.onVerified ?? base.onVerified ? { onVerified: over.onVerified ?? base.onVerified } : {}),
  };
}

/**
 * Guard a whole `{ name: tool }` record in one call — the drop-in integration:
 * `tools: pcaTools({ refund, lookup }, { verify: { grant }, audience })`. Every tool is guarded with the
 * shared options (override per tool via `per`, or limit the set via `only`; untouched tools pass through).
 */
export function pcaTools<T extends Record<string, AiSdkTool>>(record: T, options: PcaToolsOptions<T>): T {
  const only = options.only ? new Set<keyof T>(options.only) : undefined;
  const out: Record<string, AiSdkTool> = {};
  for (const [name, tool] of Object.entries(record)) {
    if (only && !only.has(name)) {
      out[name] = tool;
      continue;
    }
    out[name] = withPcaTool(tool, mergeToolOptions(options, options.per?.[name]));
  }
  return out as T;
}

// ---- step-up on the agent loop (prepareStep) ------------------------------------------------------

/** Map a tool name (+ its args) to the PCA action to review. Return null to treat the tool as unguarded (auto). */
export type ToolIntent = (
  tool: string,
  args?: Record<string, unknown>,
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
 * human. A step-up request is exactly what a PCA FROST round / CIBA push carries to the approver.
 */
export function reviewToolCall(
  agent: Agent,
  tool: string,
  args: Record<string, unknown> | undefined,
  opts: StepUpOptions,
): ToolReview {
  const mapped = opts.intent(tool, args);
  if (!mapped) return { tool, review: { kind: 'auto' } };
  const review = reviewAction(agent, mapped.verb, mapped.resource, mapped.params ?? args, {
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.goal !== undefined ? { goal: opts.goal } : {}),
    ...(opts.standing !== undefined ? { standing: opts.standing } : {}),
  });
  return { tool, review };
}

/** A step-up a batch of tool calls raised (what the approval inbox / FROST round receives). */
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

// --- structural `prepareStep` shapes (a subset of the AI SDK's; declared here so `ai` is not a dep) ---

/** One tool call the model emitted in a step (v5 uses `input`; v4 used `args`). */
export interface PrepareStepToolCall {
  toolName: string;
  input?: Record<string, unknown>;
  args?: Record<string, unknown>;
}

/** The result of a completed step, as `prepareStep` sees it in `steps`. */
export interface PrepareStepLike {
  toolCalls?: ReadonlyArray<PrepareStepToolCall>;
}

/** The argument the AI SDK passes to `prepareStep`. */
export interface PrepareStepInput {
  steps: ReadonlyArray<PrepareStepLike>;
  stepNumber: number;
}

/** What `prepareStep` returns to shape the next step (a subset we populate). */
export interface PrepareStepResult {
  activeTools?: string[];
  system?: string;
}

export interface PcaPrepareStepOptions extends StepUpOptions {
  /** The full set of tool names available to the agent (used to compute the next step's allow-list). */
  tools: readonly string[];
  /** Return true when a step-up request has already been co-signed (your FROST/CIBA result): it is then let through. */
  approved?: (request: StepUpRequest) => boolean;
  /** Receives the step-ups this step raised — push them to the approval inbox / open the FROST round. */
  onStepUp?: (pending: PendingStepUp[]) => void;
}

/**
 * Build a Vercel AI SDK `prepareStep` that pauses the agent loop on risky tools. Before each step it
 * reviews the tool calls the model made in the PREVIOUS step; any that need a tier-2/3 co-sign and are
 * not yet approved are routed to `onStepUp` (→ FROST/CIBA) and REMOVED from the next step's
 * `activeTools`, so the loop cannot keep autonomously escalating a risky tool — it waits for a human /
 * guardian. Returns `undefined` (no change) when nothing needs a step-up.
 */
export function pcaPrepareStep(
  agent: Agent,
  opts: PcaPrepareStepOptions,
): (input: PrepareStepInput) => PrepareStepResult | undefined {
  return (input) => {
    const last = input.steps[input.steps.length - 1];
    if (!last?.toolCalls || last.toolCalls.length === 0) return undefined;
    const reviews = last.toolCalls.map((c) => reviewToolCall(agent, c.toolName, c.input ?? c.args, opts));
    const pending = pendingStepUps(reviews).filter((p) => !opts.approved?.(p.request));
    if (pending.length === 0) return undefined;
    opts.onStepUp?.(pending);
    const blocked = new Set(pending.map((p) => p.tool));
    return { activeTools: opts.tools.filter((t) => !blocked.has(t)) };
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
