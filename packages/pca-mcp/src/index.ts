/**
 * Model Context Protocol adapter for Proof-Carrying Authority.
 *
 * Wrap an MCP tool handler so every call first builds a PCActn (via the core `guard`) — fast-failing on
 * the agent's local dry-run and handing the proof to your `onProof` so it can be forwarded to / attached
 * for the resource server — then runs the original handler. Drop-in: the wrapped handler has the SAME
 * shape as an MCP tool handler, so it slots straight into `server.tool(name, schema, withPCA(agent, {...},
 * handler))` / `server.registerTool`.
 *
 * Structurally compatible with the `@modelcontextprotocol/sdk` package v1 (declared as an OPTIONAL peer
 * dependency). We never import the SDK's runtime — the handler/result types below are a minimal
 * structural shim, so this works across minor versions and even when the SDK is absent.
 *
 * HONEST: this does not authorize — it attaches a proof-carrying action; the resource server's verifier
 * decides. A bypassed wrapper just means the action lacks a valid PCActn and fails server-side. The local
 * dry-run is a convenience fast-fail, not a grant.
 */

import { type Agent, type PcaCall, PcaDenied, bridgeToolCall, guard, pcaHeaders } from '@atlasauth/pca';

/** Minimal structural shape of an MCP tool result (`server.tool` / `registerTool` handler return). */
export interface McpToolResult {
  content: Array<{ type: string; [k: string]: unknown }>;
  isError?: boolean;
  [k: string]: unknown;
}

/** An MCP tool handler: `(args, extra?) => result`, as registered via `server.tool` / `registerTool`. */
export type McpToolHandler<ARGS = Record<string, unknown>> = (
  args: ARGS,
  extra?: unknown,
) => Promise<McpToolResult> | McpToolResult;

export interface GuardToolSpec<ARGS> {
  /** Catalog verb this tool maps to (e.g. `stripe.refund`). */
  verb: string;
  /** Resource for the call: fixed, or derived from the tool args. */
  resource: string | ((args: ARGS) => string);
  /** Audience (resource-server / instance id); falls back to the agent's default. */
  aud?: string;
  /** Fast-fail on the local dry-run before running the handler (default true). */
  failFast?: boolean;
  /** Receive the PCActn so the proof can be forwarded (e.g. as request headers) to the resource server. */
  onProof?: (pca: PcaCall, args: ARGS) => void;
}

/**
 * Wrap an MCP tool handler so each call emits + attaches a PCActn before the original handler runs.
 *
 * On a local fast-fail (`PcaDenied`), returns an MCP error result (`{ isError: true }`) rather than
 * throwing — MCP handlers signal tool errors in-band via `isError` so the model can see them.
 */
export function withPCA<ARGS extends Record<string, unknown>>(
  agent: Agent,
  spec: GuardToolSpec<ARGS>,
  handler: McpToolHandler<ARGS>,
): McpToolHandler<ARGS> {
  return async (args: ARGS, extra?: unknown): Promise<McpToolResult> => {
    const run = guard<ARGS, McpToolResult>(
      agent,
      {
        verb: spec.verb,
        resource: spec.resource,
        ...(spec.aud !== undefined ? { aud: spec.aud } : {}),
        ...(spec.failFast !== undefined ? { failFast: spec.failFast } : {}),
      },
      async (a, pca) => {
        spec.onProof?.(pca, a);
        return handler(a, extra);
      },
    );
    try {
      return await run(args);
    } catch (err) {
      if (err instanceof PcaDenied) {
        return { content: [{ type: 'text', text: err.message }], isError: true };
      }
      throw err;
    }
  };
}

/**
 * Attach the encoded PCActn into a result's `_meta` so a downstream (gateway / RS) can read the proof off
 * the tool result. Additive and non-destructive: existing `content`, `isError` and `_meta` keys are kept.
 */
export function guardToolResult(pca: PcaCall, result: McpToolResult): McpToolResult {
  const prevMeta =
    result._meta && typeof result._meta === 'object' ? (result._meta as Record<string, unknown>) : {};
  return { ...result, _meta: { ...prevMeta, 'x-pca-action': pca.encoded } };
}

export { bridgeToolCall, pcaHeaders, type PcaCall };
