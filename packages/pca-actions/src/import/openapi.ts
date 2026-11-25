// openapi.ts - OpenAPI 3.x and Swagger 2 -> drafts. This unifies and replaces `draftSchemaFromOpenApi` (the legacy v1 draft
// in @atlasauth/pca keeps working for existing callers): one def per operation, parameters from path/query/body (nested
// bodies flattened to dotted names), the method giving the initial effects. `x-` extensions are ignored unless allow-listed.

import { compareUtf8 } from '@atlasauth/pca';
import { ActionKitError, type ActionDef, type Effect, type ParamDef, type ResourceScope } from '../def';
import { addTodo, pointer, clip, emitDef, finish, flattenObject, isObj, newBudget, newCtx, paramSeg, resolveSchema, tokensOf, leafParam, verbOf, type Budget, type Ctx, type ImportOpts, type ImportReport, type JsonSchemaLike } from './common';

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;
const EFFECT_OF: Readonly<Record<string, Effect[]>> = {
  get: ['read'], head: ['read'], options: ['read'], trace: ['read'], post: ['create'], put: ['update'], patch: ['update'], delete: ['delete'],
};
const NATURAL = new Set(['get', 'head', 'options', 'trace', 'put', 'delete']);
const BODY_TYPES = ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data'];
const VERSIONISH = /^(v\d+(\.\d+)?|api|rest|public|latest)$/i;

interface Param { name?: string; in?: string; required?: boolean; description?: string; schema?: JsonSchemaLike; type?: string; [k: string]: unknown }

function deref<T>(c: Ctx, x: unknown, where: string): T | undefined {
  if (!isObj(x)) return undefined;
  if (typeof x.$ref !== 'string') return x as T;
  const seen = new Set<string>();
  let cur: unknown = x;
  while (isObj(cur) && typeof cur.$ref === 'string') {
    if (seen.has(cur.$ref) || seen.size > c.lim.max_ref_depth) { addTodo(c, where, 'cyclic_ref', 'a reference chain is cyclic or too deep'); return undefined; }
    seen.add(cur.$ref);
    const t = pointerOf(c, cur.$ref);
    if (t === undefined) { addTodo(c, where, 'unresolved_ref', `reference '${clip(cur.$ref, 120)}' does not resolve locally`); return undefined; }
    cur = t;
  }
  return cur as T;
}
const pointerOf = (c: Ctx, ref: string): unknown => pointer(c.root, ref);

/** Path -> scope and noun: `/v1/customers/{id}/cards` -> noun tokens `customers cards`, ends-with-id false. */
function pathFacts(path: string): { nouns: string[]; endsWithParam: boolean } {
  const segs = path.split('/').filter((s) => s.length > 0);
  const endsWithParam = segs.length > 0 && /^\{.+\}$/.test(segs[segs.length - 1]!);
  const nouns = segs.filter((s) => !/[{}]/.test(s) && !VERSIONISH.test(s)).flatMap((s) => tokensOf(s));
  return { nouns, endsWithParam };
}

/** Swagger 2 parameter -> the OpenAPI 3 shape the rest of the importer reads. */
function swagger2Param(p: Param): Param {
  if (p.schema !== undefined || p.in === 'body') return p;
  const { name, in: loc, required, description, ...sch } = p;
  return { name, in: loc, required, description, schema: sch as JsonSchemaLike };
}

function bodySchemaOf(c: Ctx, op: Record<string, unknown>, params: Param[], swagger: boolean, where: string): JsonSchemaLike | undefined {
  if (swagger) {
    const b = params.find((q) => q.in === 'body');
    return b?.schema;
  }
  const rb = deref<{ content?: Record<string, { schema?: JsonSchemaLike }> }>(c, op.requestBody, where);
  const content = rb?.content;
  if (!isObj(content)) return undefined;
  const keys = Object.keys(content).sort(compareUtf8);
  const pick = BODY_TYPES.map((t) => keys.find((k) => k.toLowerCase().split(';')[0]!.trim() === t)).find((k) => k !== undefined)
    ?? keys.find((k) => /^application\/[^;]*\+json(;|$)/i.test(k));
  if (pick === undefined) {
    if (keys.length > 0) addTodo(c, where, 'body_type', `request body media types (${keys.slice(0, 3).map((k) => clip(k, 40)).join(', ')}) are not form or JSON; the body is not declared`);
    return undefined;
  }
  return content[pick]?.schema;
}

export function importOpenApi(source: unknown, opts: ImportOpts): ImportReport {
  const c = newCtx('openapi', source, opts);
  if (!isObj(source)) throw new ActionKitError('bad_source', 'an OpenAPI document must be an object');
  const swagger = typeof source.swagger === 'string' && source.swagger.startsWith('2');
  const v3 = typeof source.openapi === 'string' && /^3\./.test(source.openapi);
  if (!swagger && !v3) throw new ActionKitError('bad_source', "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')");
  const paths = isObj(source.paths) ? source.paths : {};
  const globalSecurity = Array.isArray(source.security) ? source.security : undefined;
  for (const path of Object.keys(paths).sort(compareUtf8)) {
    const item0 = deref<Record<string, unknown>>(c, paths[path], path);
    if (item0 === undefined) continue;
    const shared = (Array.isArray(item0.parameters) ? item0.parameters : []) as unknown[];
    for (const method of METHODS) {
      const op = item0[method];
      if (!isObj(op)) continue;
      const where = `${method.toUpperCase()} ${clip(path, 120)}`;
      const operationId = typeof op.operationId === 'string' && op.operationId.length > 0 && op.operationId.length <= 200 ? op.operationId : undefined;
      const pf = pathFacts(path);
      const nameRaw = typeof op['x-pca-verb'] === 'string' && c.ext.has('x-pca-verb') ? (op['x-pca-verb'] as string) : undefined;
      const verb = nameRaw !== undefined && /^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}$/.test(nameRaw) && nameRaw.startsWith(opts.ns + '.') ? nameRaw
        : operationId !== undefined ? verbOf(opts.ns, operationId)
        : verbOf(opts.ns, [...pf.nouns.slice(-2), method === 'get' && !pf.endsWithParam ? 'list' : method].join(' '));
      c.root = source;
      const bud: Budget = newBudget(c);
      // parameters: the operation's own win over the path item's (by in+name)
      const merged = new Map<string, Param>();
      for (const raw of [...shared, ...(Array.isArray(op.parameters) ? op.parameters : [])]) {
        const q0 = deref<Param>(c, raw, where);
        if (!q0 || typeof q0.name !== 'string' || typeof q0.in !== 'string') continue;
        const q = swagger ? swagger2Param(q0) : q0;
        merged.set(`${q.in}:${q.name}`, q);
      }
      const all = [...merged.values()];
      const params: Record<string, ParamDef> = {};
      let idemParam: string | undefined;
      // request body first (it wins a name clash)
      const body = bodySchemaOf(c, op, all, swagger, where);
      if (body !== undefined) {
        const b = resolveSchema(body, c, bud, `${where}: request body`);
        if (b.type === 'object' || isObj(b.properties)) flattenObject(b, c, bud, where, params);
        else addTodo(c, where, 'body_shape', 'the request body is not an object schema; it is not declared');
      }
      for (const q of [...all].sort((a, b) => compareUtf8(`${a.in}:${a.name}`, `${b.in}:${b.name}`))) {
        const name = q.name!;
        if (q.in === 'header' && /^idempotency-key$/i.test(name)) { idemParam = 'idempotency_key'; continue; }
        if (q.in === 'body') continue;
        if (q.in !== 'path' && q.in !== 'query' && !(q.in === 'formData')) {
          addTodo(c, where, 'param_location', `${clip(String(q.in), 12)} parameter '${clip(name, 60)}' is not an action parameter (path, query and body only)`);
          continue;
        }
        const sname = paramSeg(name);
        if (sname !== name) addTodo(c, `${where}: ${name}`, 'renamed_param', `parameter '${clip(name, 80)}' is declared as '${sname}'`);
        if (Object.prototype.hasOwnProperty.call(params, sname) || Object.keys(params).some((k) => k.startsWith(sname + '.'))) {
          addTodo(c, `${where}: ${name}`, 'skipped_param', `'${sname}' is declared by the body and by a ${q.in} parameter; kept the body's`);
          continue;
        }
        if (Object.keys(params).length >= 64) { addTodo(c, where, 'too_many_params', 'more than 64 parameters; the rest are dropped'); break; }
        const sch = resolveSchema({ ...(q.schema ?? {}), ...(q.description && !(q.schema ?? {}).description ? { description: q.description } : {}) }, c, bud, `${where}: ${name}`);
        params[sname] = leafParam(sch, q.in === 'path' || q.required === true, c, bud, `${where}: ${name}`);
      }
      if (idemParam !== undefined && !Object.prototype.hasOwnProperty.call(params, idemParam)) params[idemParam] = { type: 'string', required: false, max_len: 255 };
      else idemParam = undefined;
      const scope: ResourceScope = pf.endsWithParam || method === 'post' ? 'one' : 'set';
      const natural = NATURAL.has(method);
      // security scopes are a note, not a field
      const sec = Array.isArray(op.security) ? op.security : globalSecurity;
      const scopes = [...new Set((sec ?? []).flatMap((r) => (isObj(r) ? Object.values(r).flatMap((v) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])) : [])))].sort(compareUtf8);
      if (scopes.length > 0) addTodo(c, where, 'required_scope', `requires scope: ${scopes.slice(0, 12).map((s) => clip(s, 60)).join(', ')}`);
      if (op.deprecated === true) addTodo(c, where, 'deprecated', 'the operation is marked deprecated');
      for (const k of Object.keys(op)) if (k.startsWith('x-') && !c.ext.has(k)) { addTodo(c, where, 'extension_ignored', `extension '${clip(k, 60)}' is ignored (not allow-listed)`); break; }
      emitDef(c, {
        name: operationId ?? where,
        noAlias: operationId === undefined,
        verb,
        title: typeof op.summary === 'string' && op.summary.length > 0 ? op.summary : operationId,
        description: typeof op.description === 'string' ? op.description : typeof op.summary === 'string' ? op.summary : undefined,
        effects: [...EFFECT_OF[method]!],
        scope,
        params,
        ...(idemParam !== undefined ? { idempotency: { mode: 'key_param' as const, param: idemParam } } : natural ? { idempotency: { mode: 'natural' as const } } : {}),
        bindings: { openapi: { operationId: operationId ?? clip(`${method}_${path}`, 200), method: method.toUpperCase(), path: clip(path, 240) } },
      });
    }
  }
  return finish(c);
}

export type { ActionDef };
