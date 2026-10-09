/**
 * OpenAI adapter for Proof-Carrying Authority.
 *
 * Turn an OpenAI chat `tool_call` into a PCActn (via the core `bridgeToolCall`), run your tool handler
 * with the proof attached, and hand back the `{ role: 'tool', ... }` message the app feeds to the next
 * model turn. Drop-in: you map each tool name to a catalog `{ verb, resource }`, and dispatch does the
 * rest — parse arguments, build + sign the proof, run the handler, serialize the result.
 *
 * Structurally compatible with the `openai` package v4/v5 (declare `openai` as an OPTIONAL peer
 * dependency). We only touch the tool-call shape the model returns, so we never import the SDK's
 * runtime and this works across minor versions.
 *
 * HONEST: this does NOT authorize — it attaches a proof-carrying action; the resource server's verifier
 * decides. `bridgeToolCall` does not dry-run or fast-fail, so an over-cap or out-of-policy call still
 * produces a (signed) PCActn here and is rejected server-side. OpenAI dispatch leaves enforcement to the
 * resource server.
 */

import { type Agent, type PcaCall, bridgeToolCall, pcaHeaders } from '@atlasauth/pca';

/** The shape OpenAI chat completions return for a function tool call (v4/v5). */
export interface OpenAIToolCall {
  id: string;
  type?: 'function';
  function: { name: string; arguments: string };
}

/** The `tool` message the app returns to the model after running the tool. */
export interface OpenAIToolMessage {
  role: 'tool';
  tool_call_id: string;
  content: string;
}

/** Map a parsed tool call to a catalog `{ verb, resource }`; `null` declines (no proof for this tool). */
export type ToolMapping = (call: {
  name: string;
  arguments: Record<string, unknown>;
}) => { verb: string; resource: string } | null;

/** Run the real tool. Receives the parsed args and the PcaCall so it can forward the proof to the RS. */
export type ToolHandler = (
  args: Record<string, unknown>,
  pca: PcaCall,
) => Promise<unknown> | unknown;

/** Parse a tool_call's `arguments` (JSON string; empty/whitespace → `{}`). */
function parseArguments(raw: string): Record<string, unknown> {
  if (raw == null) return {};
  const trimmed = raw.trim();
  if (trimmed === '') return {};
  const parsed = JSON.parse(trimmed);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('dispatchToolCall: tool_call arguments must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

/**
 * Dispatch a single OpenAI tool call: build + sign a PCActn, run the mapped handler with the proof, and
 * return the `tool` message for the next model turn.
 *
 * Throws if the `map` declines the tool (`null`): we refuse to run a tool we cannot produce a PCActn for.
 */
export async function dispatchToolCall(
  agent: Agent,
  call: OpenAIToolCall,
  map: ToolMapping,
  handlers: Record<string, ToolHandler>,
  opts?: { aud?: string; counter?: number; now?: number },
): Promise<OpenAIToolMessage> {
  const name = call.function.name;
  const args = parseArguments(call.function.arguments);

  const pca = bridgeToolCall(
    agent,
    { name, arguments: args },
    (c) => map({ name: c.name, arguments: c.arguments as Record<string, unknown> }),
    opts,
  );
  if (!pca) {
    throw new Error(`dispatchToolCall: no PCActn for unmapped tool "${name}" (the mapping declined)`);
  }

  const handler = handlers[name];
  const result = handler ? await handler(args, pca) : undefined;

  const content = JSON.stringify(result ?? { pca: pca.encoded });
  return { role: 'tool', tool_call_id: call.id, content };
}

/**
 * Dispatch an array of tool calls sequentially (a model turn may return several). When `opts.counter` is
 * given, it is incremented per call so each PCActn carries a distinct monotonic counter.
 */
export async function dispatchToolCalls(
  agent: Agent,
  calls: OpenAIToolCall[],
  map: ToolMapping,
  handlers: Record<string, ToolHandler>,
  opts?: { aud?: string; counter?: number; now?: number },
): Promise<OpenAIToolMessage[]> {
  const out: OpenAIToolMessage[] = [];
  let i = 0;
  for (const call of calls) {
    const perCall =
      opts?.counter !== undefined ? { ...opts, counter: opts.counter + i } : opts;
    out.push(await dispatchToolCall(agent, call, map, handlers, perCall));
    i += 1;
  }
  return out;
}

export { pcaHeaders, type PcaCall };
