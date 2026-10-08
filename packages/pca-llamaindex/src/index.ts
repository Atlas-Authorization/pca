/**
 * LlamaIndex.TS adapter for Proof-Carrying Authority.
 *
 * Wrap a LlamaIndex FunctionTool so every call first builds a PCActn (via the core `guard`) — fast-failing
 * on the agent's local dry-run and handing the proof to your `onProof` so it can forward it to the resource
 * server — then runs the original tool. Drop-in: the wrapped tool has the SAME shape, so it slots straight
 * into the `tools` array you hand to a LlamaIndex agent.
 *
 * Structurally compatible with the `llamaindex` package (declare `llamaindex` as a peer dependency). We touch
 * only `call` and preserve `metadata` and every other field, so this works across minor versions without
 * importing the SDK's runtime.
 *
 * HONEST: this does not authorize — it attaches a proof-carrying action; the resource server's verifier
 * decides. A bypassed wrapper just means the action lacks a valid PCActn and fails server-side.
 */

import { type Agent, type PcaCall, bridgeToolCall, guard, pcaHeaders } from '@atlasauth/pca';

/**
 * Minimal structural shape of a LlamaIndex FunctionTool. `call` is a METHOD (not an arrow property) on
 * purpose: method signatures are bivariant, so a tool with concrete argument types assigns cleanly to the
 * general `LlamaIndexTool` when collected in a `tools` array — no `any`, no casts.
 */
export interface LlamaIndexTool<ARGS = Record<string, unknown>, RESULT = unknown> {
  metadata: { name: string; description?: string; parameters?: unknown };
  call(input: ARGS): Promise<RESULT> | RESULT;
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
  /** Receive the PCActn so `call` can forward it (e.g. as request headers) to the resource server. */
  onProof?: (pca: PcaCall, args: ARGS) => void;
}

/** Wrap a LlamaIndex FunctionTool so each call emits + attaches a PCActn before the original `call` runs. */
export function withPCA<ARGS extends Record<string, unknown>, RESULT>(
  agent: Agent,
  spec: GuardToolSpec<ARGS>,
  tool: LlamaIndexTool<ARGS, RESULT>,
): LlamaIndexTool<ARGS, RESULT> {
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
      return (await tool.call(args)) as RESULT;
    },
  );
  return { ...tool, call: (input: ARGS) => run(input) };
}

export { bridgeToolCall, pcaHeaders, type PcaCall };
