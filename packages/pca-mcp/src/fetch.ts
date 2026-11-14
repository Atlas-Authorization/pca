/**
 * `pcaFetch`: the agent side of an MCP server that requires a PCActn per tool call.
 *
 * Give the returned function to the MCP client transport (`new StreamableHTTPClientTransport(url, { fetch })`). For
 * every JSON-RPC `tools/call` request it builds a fresh PCActn for that call with `bridgeToolCall` (verb and resource
 * from your mapping, the tool arguments committed by digest, a new counter) and adds it as the `PCA-Action` header. Every
 * other request passes through unchanged. It does not decide anything: the server's verifier does.
 * Provenance by default: the agent's provenance bundle rides with the proof (`PCA-Provenance`), and every `tools/call` response
 * is recorded in the agent's chain as UNTRUSTED tool output before it is returned.
 */

import { bridgeToolCall, recordToolResult, type Agent } from '@atlasauth/pca';

/** Which PCA action an MCP tool call is: its verb and resource. `null` = send the call without a proof. */
export type ToolActionMap = (tool: string, args: Record<string, unknown>) => { verb: string; resource: string } | null;

export interface PcaFetchOptions {
  /** The fetch to wrap. Default: the global `fetch`. */
  fetch?: typeof fetch;
  /** Audience override for the proofs (else the agent's default `aud`). */
  aud?: string;
}

interface ToolsCallMessage {
  method?: unknown;
  params?: { name?: unknown; arguments?: unknown };
}

function toolCallOf(body: unknown): { name: string; arguments: Record<string, unknown> } | null {
  if (typeof body !== 'string') return null;
  let msg: ToolsCallMessage;
  try {
    msg = JSON.parse(body) as ToolsCallMessage;
  } catch {
    return null;
  }
  if (msg === null || typeof msg !== 'object' || Array.isArray(msg) || msg.method !== 'tools/call') return null;
  const name = msg.params?.name;
  const args = msg.params?.arguments;
  if (typeof name !== 'string') return null;
  return { name, arguments: args !== null && typeof args === 'object' && !Array.isArray(args) ? (args as Record<string, unknown>) : {} };
}

/** A fetch for an MCP client transport that attaches a fresh, signed `PCA-Action` header to every `tools/call`. */
export function pcaFetch(agent: Agent, toolAction: ToolActionMap, opts: PcaFetchOptions = {}): typeof fetch {
  const inner = opts.fetch ?? fetch;
  return (async (url: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const call = toolCallOf(init?.body);
    if (call) {
      const proof = bridgeToolCall(agent, call, (c) => toolAction(c.name, c.arguments), opts.aud !== undefined ? { aud: opts.aud } : undefined);
      if (proof) {
        const headers = new Headers(init?.headers);
        for (const [k, v] of Object.entries(proof.headers)) headers.set(k, v);
        const res = await inner(url, { ...init, headers });
        // the tool result enters the model's context: record it (untrusted) BEFORE the caller can act on it. A JSON body is
        // recorded by its bytes; a stream is recorded at once by its origin (its label does not depend on its bytes).
        const ct = res.headers?.get?.('content-type') ?? '';
        let content: unknown = { tool: call.name, stream: String(url) };
        if (!/event-stream/i.test(ct) && typeof res.clone === 'function') {
          try {
            content = await res.clone().text();
          } catch {
            /* unreadable: keep the origin-only record */
          }
        }
        recordToolResult(agent, call.name, content);
        return res;
      }
    }
    return inner(url, init);
  }) as typeof fetch;
}
