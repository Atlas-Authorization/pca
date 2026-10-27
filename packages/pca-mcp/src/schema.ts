/**
 * MCP tools -> the site's signed action schema (PCA Intent Layer v2 §3.2), and the closed-world check on a tool call.
 *
 * A site that exposes its API as MCP tools derives its `/.well-known/pca-actions.json` from `tools/list`: the tool
 * `inputSchema` gives the parameter list, types and enums; the tool annotations give a LOWER bound on reversibility only
 * (hints never lower a classification). The draft lists the decisions a developer must make (semantic types,
 * sensitivities, units, reversibility); `applySchemaDecisions` records them, then the site signs the result
 * (`signActionSchema` in @atlasauth/pca, or `pca schema sign`). On the agent side, `conformToolCall` maps a tool call to
 * the schema's verb and runs the closed-world check before a PCActn is ever built: an undeclared argument, a missing
 * required one or an out-of-domain value is refused locally exactly as the site's verifier would refuse it.
 */
import {
  conformAction,
  draftSchemaFromMcpTools,
  type ActionParamDecl,
  type ActionSchema,
  type ConformResult,
  type DraftSchema,
  type McpToolLike,
  type SchemaReversibility,
  type UnsignedActionSchema,
} from '@atlasauth/pca/ext/intent';

/** Anything that lists tools like an MCP client / server (`tools/list`), or the list itself. */
export type ToolSource = readonly McpToolLike[] | { listTools(): Promise<{ tools: McpToolLike[] }> | { tools: McpToolLike[] } };

/** Draft an action schema from an MCP tool list. */
export async function draftActionSchemaFromMcp(source: ToolSource, site: { site: string; aud: string; version: string; verbPrefix?: string }): Promise<DraftSchema> {
  const tools = Array.isArray(source) ? (source as readonly McpToolLike[]) : (await (source as { listTools(): Promise<{ tools: McpToolLike[] }> | { tools: McpToolLike[] } }).listTools()).tools;
  return draftSchemaFromMcpTools(tools, site);
}

/** The developer's decisions on a draft: per verb, parameter semantics and the reversibility. */
export interface SchemaDecisions {
  verbs: Record<
    string,
    {
      reversibility?: SchemaReversibility;
      params?: Record<string, Partial<Pick<ActionParamDecl, 'semantic' | 'sensitivity' | 'unit' | 'accumulates_into' | 'required' | 'max_len' | 'min' | 'max'>>>;
    }
  >;
  units?: UnsignedActionSchema['units'];
}

/**
 * Record the decisions on a draft (a new object). A decision about a verb or parameter the draft does not have throws:
 * the schema is closed, so a typo must not silently publish a looser schema. Sensitivity may be lowered only explicitly.
 */
export function applySchemaDecisions(draft: UnsignedActionSchema, d: SchemaDecisions): UnsignedActionSchema {
  const out: UnsignedActionSchema = JSON.parse(JSON.stringify(draft));
  if (d.units) out.units = { ...(out.units ?? {}), ...d.units };
  for (const [verb, dv] of Object.entries(d.verbs)) {
    const v = out.verbs.find((x) => x.verb === verb);
    if (!v) throw new Error(`applySchemaDecisions: the draft has no verb '${verb}'`);
    if (dv.reversibility) v.reversibility = dv.reversibility;
    for (const [path, dp] of Object.entries(dv.params ?? {})) {
      const p = v.params[path];
      if (!p) throw new Error(`applySchemaDecisions: verb '${verb}' has no parameter '${path}'`);
      Object.assign(p, dp);
    }
  }
  return out;
}

/** The schema verb an MCP tool maps to (by `mcp.tool`), or undefined. */
export function verbOfTool(schema: Pick<ActionSchema, 'verbs'>, toolName: string): string | undefined {
  return schema.verbs.find((v) => v.mcp?.tool === toolName)?.verb;
}

/** Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb). */
export function conformToolCall(schema: Pick<ActionSchema, 'verbs'>, toolName: string, args: unknown): ConformResult {
  const verb = verbOfTool(schema, toolName);
  if (verb === undefined) return { ok: false, code: 'unknown_verb', reason: `MCP tool '${toolName}' is not declared by the site schema` };
  return conformAction(schema, verb, args);
}

