/**
 * `pca schema ...`: the site-side workflow for PCA Intent Layer v2 action schemas (docs/specs/pca-intent-layer-v2.md §3.2,
 * §3.15 step 2): draft from OpenAPI or an MCP `tools/list`, record the developer's decisions, sign as the site, verify,
 * check an action in the closed world, and publish (anchor) it in an Atlas instance's intent transparency log.
 *
 * Pure command functions (strings in, strings out) so they are unit-testable; `cmdSchemaPublish` takes an injectable
 * fetch. The signed document is what the site serves at `/.well-known/pca-actions.json`; the key entry printed by
 * `cmdSchemaSign` goes into the site's discovery document (`intent.schema_keys`).
 */
import { unb64u } from '@atlasauth/pca';
import {
  actionSchemaDigest,
  actionSchemaKeyOf,
  conformAction,
  draftSchemaFromMcpTools,
  draftSchemaFromOpenApi,
  signActionSchema,
  verifyActionSchema,
  type ActionSchema,
  type ActionSchemaKey,
  type McpToolLike,
  type OpenApiLike,
  type UnsignedActionSchema,
} from '@atlasauth/pca/ext/intent';

const parse = (text: string, what: string): unknown => {
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${what} is not JSON: ${(e as Error).message}`);
  }
};

export interface SchemaInitOptions {
  from: 'openapi' | 'mcp';
  site: string;
  aud: string;
  version: string;
  verbPrefix?: string;
}

/** Draft a schema. `input` is an OpenAPI document, or an MCP `tools/list` result (`{tools: [...]}`) or tool array. */
export function cmdSchemaInit(input: string, o: SchemaInitOptions): { schema: string; todo: string[] } {
  const v = parse(input, o.from === 'openapi' ? 'the OpenAPI document' : 'the MCP tool list');
  const site = { site: o.site, aud: o.aud, version: o.version };
  let draft;
  if (o.from === 'openapi') draft = draftSchemaFromOpenApi(v as OpenApiLike, site);
  else {
    const tools = Array.isArray(v) ? v : (v as { tools?: unknown }).tools;
    if (!Array.isArray(tools)) throw new Error('the MCP input must be a tools/list result {tools: [...]} or a tool array');
    draft = draftSchemaFromMcpTools(tools as McpToolLike[], { ...site, ...(o.verbPrefix !== undefined ? { verbPrefix: o.verbPrefix } : {}) });
  }
  return { schema: JSON.stringify(draft.schema, null, 2), todo: draft.todo };
}

/** A 32-byte Ed25519 secret given as base64url (the site's schema signing key). */
function secretOf(b64: string): Uint8Array {
  const sk = unb64u(b64.trim());
  if (sk.length !== 32) throw new Error('the signing key must be a base64url 32-byte Ed25519 secret');
  return sk;
}

/** Sign a (decided) draft as the site. Returns the signed schema, its digest, and the discovery key entry. */
export function cmdSchemaSign(draft: string, o: { kid: string; secret: string }): { schema: string; digest: string; key: ActionSchemaKey } {
  const d = parse(draft, 'the draft schema') as UnsignedActionSchema & { sig?: unknown };
  if (d && typeof d === 'object' && 'sig' in d) delete d.sig; // re-signing replaces the old signature
  const sk = secretOf(o.secret);
  const signed = signActionSchema(d, o.kid, sk);
  return { schema: JSON.stringify(signed, null, 2), digest: actionSchemaDigest(signed), key: actionSchemaKeyOf(o.kid, sk) };
}

/** `keys` is a key array, or a discovery document whose `intent.schema_keys` lists them. */
function keysOf(text: string): ActionSchemaKey[] {
  const v = parse(text, 'the keys') as unknown;
  if (Array.isArray(v)) return v as ActionSchemaKey[];
  const k = (v as { intent?: { schema_keys?: unknown } } | null)?.intent?.schema_keys;
  if (Array.isArray(k)) return k as ActionSchemaKey[];
  throw new Error('keys must be a key array or a discovery document with intent.schema_keys');
}

export function cmdSchemaVerify(schema: string, keys: string): { ok: boolean; text: string } {
  const s = parse(schema, 'the schema');
  const v = verifyActionSchema(s, keysOf(keys));
  return v.ok ? { ok: true, text: `OK  digest ${actionSchemaDigest(s as ActionSchema)}` } : { ok: false, text: `FAIL  ${v.reason}` };
}

/** The closed-world check of one action (verb + plaintext params) against the schema. */
export function cmdSchemaConform(schema: string, verb: string, params: string): { ok: boolean; text: string } {
  const r = conformAction(parse(schema, 'the schema') as ActionSchema, verb, parse(params, 'the params'));
  return r.ok ? { ok: true, text: `OK  '${verb}' conforms` } : { ok: false, text: `DENY  schema_violation ${r.code}${r.path ? ` (${r.path})` : ''}: ${r.reason}` };
}

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{ status: number; json(): Promise<unknown> }>;

/** Anchor the signed schema in an Atlas instance (POST /v1/pca/intent/schemas with a pca:write secret key). */
export async function cmdSchemaPublish(schema: string, keys: string, o: { api: string; secretKey: string; fetchImpl?: FetchLike }): Promise<{ ok: boolean; text: string }> {
  const s = parse(schema, 'the schema');
  const k = keysOf(keys);
  const v = verifyActionSchema(s, k);
  if (!v.ok) return { ok: false, text: `FAIL  not publishing a schema that does not verify: ${v.reason}` };
  const f = (o.fetchImpl ?? (globalThis as { fetch?: FetchLike }).fetch) as FetchLike | undefined;
  if (!f) throw new Error('no fetch available');
  const res = await f(o.api.replace(/\/+$/, '') + '/v1/pca/intent/schemas', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${o.secretKey}` },
    body: JSON.stringify({ schema: s, keys: k }),
  });
  const body = (await res.json().catch(() => null)) as { digest?: string; anchor?: { index?: number } } | null;
  if (res.status !== 200 && res.status !== 201) return { ok: false, text: `FAIL  HTTP ${res.status}` };
  return { ok: true, text: `OK  anchored ${body?.digest ?? actionSchemaDigest(s as ActionSchema)} at log index ${String(body?.anchor?.index)}` };
}
