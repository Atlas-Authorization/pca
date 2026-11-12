/**
 * Anthropic (Claude) adapter for Proof-Carrying Authority.
 *
 * Claude's tool use is a conversation: an assistant message carries content blocks, and a
 * `tool_use` block (`{ type, id, name, input }`) asks your app to run a tool. Your app runs it and
 * replies with a user message containing a matching `tool_result` block (`{ tool_use_id, content }`).
 * This adapter sits in that gap: it turns a `tool_use` block into a PCActn (via the core
 * `bridgeToolCall`), runs your handler with the proof in hand, and hands back the `tool_result` to
 * append to the next message — including the error-shaped result Claude expects when a tool refuses.
 *
 * Structurally compatible with the `@anthropic-ai/sdk` package (declared as an OPTIONAL peer
 * dependency). We model only the block shapes we touch, so this works across SDK minor versions
 * without importing its runtime — nothing here requires the SDK to be installed.
 *
 * HONEST: this does not authorize — it attaches a proof-carrying action; the resource server's
 * verifier decides. A handler that forgets to forward the proof just means the downstream action
 * lacks a valid PCActn and fails server-side.
 */

import { type Agent, type PcaCall, bridgeToolCall, pcaHeaders, recordInput, recordMessages, recordPrincipal, recordToolResult } from '@atlasauth/pca';

/** A Claude `tool_use` content block (what the model emits to call a tool). */
export interface ToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, unknown>;
}

/** A Claude `tool_result` content block (what your app replies with). */
export interface ToolResultBlock {
  type: 'tool_result';
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

/** How a Claude tool name + input maps onto a PCA (verb, resource). Return null to decline the tool. */
export type ToolMapping = (block: {
  name: string;
  input: Record<string, unknown>;
}) => { verb: string; resource: string } | null;

/** Your tool implementation: gets the model's input and the PCActn so it can carry the proof downstream. */
export type ToolHandler = (
  input: Record<string, unknown>,
  pca: import('@atlasauth/pca').PcaCall,
) => Promise<unknown> | unknown;

/**
 * Handle one `tool_use` block: build its PCActn, run the mapped handler, and return the `tool_result`.
 *
 * If the mapping declines the tool (returns null), we never run the handler — we return a
 * `tool_result` with `is_error: true` so Claude sees the refusal. If the handler throws, we likewise
 * return an error-shaped `tool_result`. On success, `content` is `JSON.stringify(result)`, falling
 * back to `{ pca: <encoded> }` when the handler returns nothing.
 */
export async function handleToolUse(
  agent: Agent,
  block: ToolUseBlock,
  map: ToolMapping,
  handlers: Record<string, ToolHandler>,
  opts?: { aud?: string; counter?: number; now?: number },
): Promise<ToolResultBlock> {
  const pca = bridgeToolCall(
    agent,
    { name: block.name, arguments: block.input },
    (b) => map({ name: b.name, input: b.arguments }),
    opts,
  );
  if (!pca) {
    return {
      type: 'tool_result',
      tool_use_id: block.id,
      content: `No proof-carrying authority is mapped for tool "${block.name}".`,
      is_error: true,
    };
  }
  const handler = handlers[block.name];
  if (!handler) {
    return {
      type: 'tool_result',
      tool_use_id: block.id,
      content: `No handler registered for tool "${block.name}".`,
      is_error: true,
    };
  }
  try {
    const result = await handler(block.input, pca);
    const content = JSON.stringify(result ?? { pca: pca.encoded });
    // the tool_result re-enters Claude's context: untrusted from here on (provenance by default)
    recordToolResult(agent, block.name, content);
    return {
      type: 'tool_result',
      tool_use_id: block.id,
      content,
    };
  } catch (err) {
    const content = err instanceof Error ? err.message : String(err);
    // a tool's error text reaches Claude too, and a tool can put anything in it
    recordToolResult(agent, block.name, content);
    return {
      type: 'tool_result',
      tool_use_id: block.id,
      content,
      is_error: true,
    };
  }
}

/** Handle many `tool_use` blocks (e.g. all of them from one assistant turn), preserving order. */
export async function handleToolUses(
  agent: Agent,
  blocks: ToolUseBlock[],
  map: ToolMapping,
  handlers: Record<string, ToolHandler>,
  opts?: { aud?: string; counter?: number; now?: number },
): Promise<ToolResultBlock[]> {
  const uses = blocks.filter((b): b is ToolUseBlock => b.type === 'tool_use');
  return Promise.all(uses.map((b) => handleToolUse(agent, b, map, handlers, opts)));
}

/** Pull the `tool_use` blocks out of an assistant message's `content` array (ignoring text/other blocks). */
export function extractToolUses(content: Array<{ type: string; [k: string]: unknown }>): ToolUseBlock[] {
  return content.filter((b): b is ToolUseBlock & Record<string, unknown> => b.type === 'tool_use');
}

/**
 * Provenance by default: wrap `client.messages.create` (or any call taking `{messages}`) so every model turn first records the
 * conversation's new messages (user text is the principal; `tool_result` blocks are untrusted). {@link handleToolUse} records every
 * tool result and attaches the provenance bundle to each PCActn's headers.
 */
export function withPCAMessages<P extends { messages?: unknown[] }, R>(agent: Agent, create: (params: P, ...rest: unknown[]) => R): (params: P, ...rest: unknown[]) => R {
  return (params: P, ...rest: unknown[]) => {
    if (Array.isArray(params?.messages)) recordMessages(agent, params.messages);
    return create(params, ...rest);
  };
}

export { pcaHeaders, recordInput, recordMessages, recordPrincipal, type PcaCall };
