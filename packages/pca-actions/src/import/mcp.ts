// mcp.ts - MCP `tools/list` -> drafts. The annotations are HINTS from the tool's own server and are untrusted: they can
// only add restriction (destructive, network egress) or describe a harmless-looking shape; they never lower a floor,
// because every output is `unreviewed` (the maximal floor) until a pinned reviewer signs it.

import { ActionKitError, type Effect } from '../def';
import { addTodo, clip, emitDef, finish, flattenObject, isObj, newBudget, newCtx, resolveSchema, withTrait, type ImportOpts, type ImportReport, type JsonSchemaLike } from './common';

export interface McpToolLike {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: JsonSchemaLike;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean; title?: string };
}

/** `tools/list` result, or the tool array itself. */
export function importMcp(source: unknown, opts: ImportOpts): ImportReport {
  const c = newCtx('mcp', source, opts);
  const tools = Array.isArray(source) ? source : isObj(source) && Array.isArray(source.tools) ? source.tools : undefined;
  if (tools === undefined) throw new ActionKitError('bad_source', 'an MCP source is a tool array or a tools/list result {tools: [...]}');
  const seen = new Set<string>();
  for (const raw of tools) {
    if (!isObj(raw) || typeof raw.name !== 'string' || raw.name.length === 0 || raw.name.length > 256) {
      addTodo(c, '(tool)', 'skipped_op', 'an entry without a usable name is skipped');
      continue;
    }
    const t = raw as unknown as McpToolLike;
    if (seen.has(t.name)) { addTodo(c, t.name, 'duplicate_tool', 'a tool name listed twice; the first is kept'); continue; }
    seen.add(t.name);
    c.root = t.inputSchema;
    const bud = newBudget(c);
    const input = resolveSchema(t.inputSchema, c, bud, `${t.name}: inputSchema`);
    const params: Record<string, import('../def').ParamDef> = {};
    flattenObject(input, c, bud, t.name, params);
    const a = isObj(t.annotations) ? t.annotations : {};
    // readOnly claims safety, so it is honoured only when nothing contradicts it
    const read = a.readOnlyHint === true && a.destructiveHint !== true;
    // a hint can only add restriction: an explicit destructiveHint adds `delete`; its absence adds nothing (the floor is `unreviewed`)
    const effects: Effect[] = read ? ['read'] : a.destructiveHint === true ? ['update', 'delete'] : ['update'];
    emitDef(c, {
      name: t.name,
      title: typeof a.title === 'string' && a.title.length > 0 ? a.title : t.title,
      description: t.description,
      effects,
      scope: 'one',
      params,
      ...(a.idempotentHint === true ? { idempotency: { mode: 'natural' as const } } : {}),
      ...(a.openWorldHint === true ? { traits: withTrait(undefined, 'pca.network_egress') } : {}),
      bindings: { mcp: { tool: clip(t.name, 256) } },
    });
  }
  return finish(c);
}
