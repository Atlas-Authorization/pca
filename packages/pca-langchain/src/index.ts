/**
 * LangChain adapter for Proof-Carrying Authority.
 *
 * Wrap a LangChain structured tool so every invocation first builds a PCActn (via the core `guard`) —
 * fast-failing on the agent's local dry-run and handing the proof to your callback so it can forward it
 * to the resource server — then runs the original tool. Drop-in: the wrapped tool keeps the SAME shape,
 * so it slots straight into an agent's `tools: [withPCA(agent, {...}, myTool)]`.
 *
 * Structurally compatible with `@langchain/core` ^0.3 (declared as an OPTIONAL peer dependency). We touch
 * only `func` / `invoke` and preserve every other field, so this works across minor versions without
 * importing the framework's runtime — a LangChain tool is matched by its shape, not its class.
 *
 * HONEST: this does not authorize — it attaches a proof-carrying action; the resource server's verifier
 * decides. A bypassed wrapper just means the action lacks a valid PCActn and fails server-side.
 */

import { type Agent, type PcaCall, bridgeToolCall, guard, pcaHeaders } from '@atlasauth/pca';

/** Minimal structural shape of a LangChain structured tool (we don't import `@langchain/core`). */
export interface LangChainTool<ARGS = Record<string, unknown>, RESULT = unknown> {
  name: string;
  description?: string;
  schema?: unknown;
  func?: (input: ARGS) => Promise<RESULT> | RESULT;
  invoke?: (input: ARGS, config?: unknown) => Promise<RESULT> | RESULT;
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
  /** Receive the PCActn so you can forward it (e.g. as request headers) to the resource server. */
  onProof?: (pca: PcaCall, args: ARGS) => void;
}

/**
 * Wrap a LangChain tool so each call emits + attaches a PCActn before the original runs.
 *
 * Returns a copy of the tool. Whichever of `func` / `invoke` the tool exposes is wrapped (both, if both
 * are present); every other field (`name`, `description`, `schema`, …) is preserved. If the tool exposes
 * neither callable, the wrapped `func`/`invoke` throw a clear error when called.
 */
export function withPCA<ARGS extends Record<string, unknown>, RESULT>(
  agent: Agent,
  spec: GuardToolSpec<ARGS>,
  tool: LangChainTool<ARGS, RESULT>,
): LangChainTool<ARGS, RESULT> {
  const guardOpts = {
    verb: spec.verb,
    resource: spec.resource,
    ...(spec.aud !== undefined ? { aud: spec.aud } : {}),
    ...(spec.failFast !== undefined ? { failFast: spec.failFast } : {}),
  };

  const hasFunc = typeof tool.func === 'function';
  const hasInvoke = typeof tool.invoke === 'function';

  const out: LangChainTool<ARGS, RESULT> = { ...tool };

  if (hasFunc) {
    const runFunc = guard<ARGS, RESULT>(agent, guardOpts, async (args, pca) => {
      spec.onProof?.(pca, args);
      return (await tool.func!(args)) as RESULT;
    });
    out.func = (args: ARGS) => runFunc(args);
  }

  if (hasInvoke) {
    const runInvoke = guard<ARGS, RESULT>(agent, guardOpts, async (args, pca) => {
      spec.onProof?.(pca, args);
      return (await tool.invoke!(args)) as RESULT;
    });
    out.invoke = (args: ARGS, _config?: unknown) => runInvoke(args);
  }

  if (!hasFunc && !hasInvoke) {
    const fail = () => {
      throw new Error('withPCA: the wrapped tool exposes neither func() nor invoke()');
    };
    out.func = fail as LangChainTool<ARGS, RESULT>['func'];
    out.invoke = fail as LangChainTool<ARGS, RESULT>['invoke'];
  }

  return out;
}

export { bridgeToolCall, pcaHeaders, type PcaCall };
