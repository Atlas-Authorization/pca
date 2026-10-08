/**
 * Vercel AI SDK adapter for Proof-Carrying Authority.
 *
 * Wrap an AI SDK tool so every call first builds a PCActn (via the core `guard`) — fast-failing on the
 * agent's local dry-run and handing the proof to your `execute` so it can forward it to the resource
 * server — then runs the original tool. Drop-in: the wrapped tool has the SAME shape, so it slots
 * straight into `tools: { refund: withPCA(agent, {...}, tool({...})) }`.
 *
 * Structurally compatible with the `ai` package v4/v5 (declare `ai` as a peer dependency). We touch only
 * `description` / `parameters` / `inputSchema` / `execute` and preserve every other field, so this works
 * across minor versions without importing the SDK's runtime.
 *
 * HONEST: this does not authorize — it attaches a proof-carrying action; the resource server's verifier
 * decides. A bypassed wrapper just means the action lacks a valid PCActn and fails server-side.
 */

import { type Agent, type PcaCall, bridgeToolCall, guard, pcaHeaders } from '@atlasauth/pca';

/**
 * Minimal structural shape of an AI SDK tool (v4 `parameters` / v5 `inputSchema`). `execute` is a
 * METHOD (not an arrow property) on purpose: method signatures are bivariant, so a tool with concrete
 * argument types assigns cleanly to the general `AiSdkTool` when collected in a `tools` record — no
 * `any`, no casts.
 */
export interface AiSdkTool<ARGS = Record<string, unknown>, RESULT = unknown> {
  description?: string;
  parameters?: unknown;
  inputSchema?: unknown;
  execute?(args: ARGS, options?: unknown): Promise<RESULT> | RESULT;
  [k: string]: unknown;
}

export interface GuardToolSpec<ARGS> {
  /** Catalog verb this tool maps to (e.g. `stripe.refund`). */
  verb: string;
  /** Resource for the call: fixed, or derived from the tool args. */
  resource: string | ((args: ARGS) => string);
  /** Audience (resource-server / instance id); falls back to the agent's default. */
  aud?: string;
  /** Fast-fail on the local dry-run before executing (default true). */
  failFast?: boolean;
  /** Receive the PCActn so `execute` can forward it (e.g. as request headers) to the resource server. */
  onProof?: (pca: PcaCall, args: ARGS) => void;
}

/** Wrap an AI SDK tool so each call emits + attaches a PCActn before `execute` runs. */
export function withPCA<ARGS extends Record<string, unknown>, RESULT>(
  agent: Agent,
  spec: GuardToolSpec<ARGS>,
  tool: AiSdkTool<ARGS, RESULT>,
): AiSdkTool<ARGS, RESULT> {
  const run = guard<ARGS, RESULT>(
    agent,
    {
      verb: spec.verb,
      resource: spec.resource,
      ...(spec.aud !== undefined ? { aud: spec.aud } : {}),
      ...(spec.failFast !== undefined ? { failFast: spec.failFast } : {}),
    },
    async (args, pca) => {
      spec.onProof?.(pca, args);
      if (typeof tool.execute !== 'function') throw new Error('withPCA: the wrapped tool has no execute()');
      return (await tool.execute(args)) as RESULT;
    },
  );
  return { ...tool, execute: (args: ARGS) => run(args) };
}

/** Wrap a whole `tools` object: each entry's spec is looked up by its key. Unlisted tools pass through. */
export function withPCATools<T extends Record<string, AiSdkTool>>(
  agent: Agent,
  tools: T,
  specs: { [K in keyof T]?: GuardToolSpec<Record<string, unknown>> },
): T {
  const out: Record<string, AiSdkTool> = {};
  for (const [name, tool] of Object.entries(tools)) {
    const spec = specs[name as keyof T];
    out[name] = spec ? withPCA(agent, spec, tool) : tool;
  }
  return out as T;
}

export { bridgeToolCall, pcaHeaders, type PcaCall };
