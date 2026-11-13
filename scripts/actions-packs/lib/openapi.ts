// openapi.ts - OpenAPI 3.x / Swagger 2 importer (offline, bounded). Produces RawOps; classification and defs are elsewhere.
import { capNouns, opIdName, pathName, snake } from './naming';
import type { RawOp, RawParam, RawType } from './types';

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head'];
const MAX_DEPTH = 6;

export interface OpenApiOpts {
  /** How verb segments are derived. */
  naming: 'path' | 'opid' | 'opid_or_path' | 'dotted';
  /** Parameters the platform supplies (auth tokens): never exposed to the agent. */
  skipParams?: RegExp;
  /** Keep only operations whose path matches. */
  include?: RegExp;
  exclude?: RegExp;
  /** Rewrite verb segments (e.g. drop a redundant leading noun). */
  rename?: (segs: string[], op: { method: string; path: string; opId?: string; tags: string[] }, raw: J) => string[];
  /** Flatten depth-1 object properties of the body into dotted params (default true). */
  flatten?: boolean;
}

function mkResolver(doc: J) {
  const cache = new Map<string, J>();
  const resolve = (node: any, depth = 0): any => { // eslint-disable-line @typescript-eslint/no-explicit-any
    let n = node;
    let guard = 0;
    while (n && typeof n === 'object' && typeof n.$ref === 'string' && guard++ < 16) {
      const ref: string = n.$ref;
      if (!ref.startsWith('#/')) return {};
      if (cache.has(ref)) { n = cache.get(ref); continue; }
      let cur: any = doc; // eslint-disable-line @typescript-eslint/no-explicit-any
      for (const k of ref.slice(2).split('/')) cur = cur?.[k.replace(/~1/g, '/').replace(/~0/g, '~')];
      cache.set(ref, cur ?? {});
      n = cur ?? {};
    }
    return depth > MAX_DEPTH ? {} : n ?? {};
  };
  return resolve;
}

/** Merge allOf members (shallow: properties, required, type). */
function flattenSchema(s: J, resolve: (n: any, d?: number) => any, depth = 0): J { // eslint-disable-line @typescript-eslint/no-explicit-any
  s = resolve(s, depth);
  if (depth > MAX_DEPTH) return s;
  const parts: J[] = Array.isArray(s.allOf) ? s.allOf.map((x: J) => flattenSchema(x, resolve, depth + 1)) : [];
  if (parts.length === 0) return s;
  const out: J = { ...s };
  delete out.allOf;
  out.properties = { ...(s.properties ?? {}) };
  out.required = [...(s.required ?? [])];
  for (const p of parts) {
    if (p.properties) Object.assign(out.properties, p.properties);
    if (Array.isArray(p.required)) out.required.push(...p.required);
    for (const k of ['type', 'enum', 'format', 'items', 'minimum', 'maximum', 'maxLength']) if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

function typeOf(s: J, resolve: (n: any, d?: number) => any): RawType { // eslint-disable-line @typescript-eslint/no-explicit-any
  s = resolve(s);
  let t = s.type;
  if (Array.isArray(t)) t = t.find((x: string) => x !== 'null') ?? 'string';
  if (!t) {
    const alt = s.anyOf ?? s.oneOf;
    if (Array.isArray(alt)) {
      const ts = alt.map((x: J) => typeOf(x, resolve)).filter((x: string, i: number, a: string[]) => a.indexOf(x) === i);
      return ts.length === 1 ? ts[0] : 'object';
    }
    if (s.properties || s.allOf) return 'object';
    return s.enum ? 'string' : 'string';
  }
  if (t === 'integer') return 'integer';
  if (t === 'boolean') return 'boolean';
  if (t === 'array') return 'array';
  if (t === 'object') return 'object';
  return 'string'; // string, number (no floats in the def model), file
}

const safeInt = (v: unknown): number | undefined => (typeof v === 'number' && Number.isSafeInteger(v) ? v : undefined);

function toRaw(name: string, where: RawParam['where'], required: boolean, schema: J, resolve: (n: any, d?: number) => any): RawParam { // eslint-disable-line @typescript-eslint/no-explicit-any
  const s = resolve(schema);
  const type = typeOf(s, resolve);
  const p: RawParam = { name, where, required, type };
  if (typeof s.format === 'string') p.format = s.format;
  if (Array.isArray(s.enum) && s.enum.every((x: unknown) => typeof x === 'string' && x.length > 0 && x.length < 100)) p.values = s.enum.slice(0, 256);
  if (type === 'integer') {
    const mn = safeInt(s.minimum), mx = safeInt(s.maximum);
    if (mn !== undefined) p.min = mn;
    if (mx !== undefined) p.max = mx;
  }
  if (type === 'string') {
    const ml = safeInt(s.maxLength);
    if (ml !== undefined) p.maxLength = ml;
  }
  if (type === 'array') {
    const it = typeOf(s.items ?? {}, resolve);
    p.items = it === 'array' ? 'object' : it;
    const mi = safeInt(s.maxItems);
    if (mi !== undefined) p.maxItems = mi;
  }
  return p;
}

export function importOpenApi(doc: J, opts: OpenApiOpts): RawOp[] {
  const resolve = mkResolver(doc);
  const out: RawOp[] = [];
  const paths: J = doc.paths ?? {};
  const isV2 = typeof doc.swagger === 'string';
  for (const httpPath of Object.keys(paths).sort()) {
    if (opts.include && !opts.include.test(httpPath)) continue;
    if (opts.exclude && opts.exclude.test(httpPath)) continue;
    const item = resolve(paths[httpPath]);
    for (const method of METHODS) {
      const o = item[method];
      if (!o || typeof o !== 'object') continue;
      const opId: string | undefined = typeof o.operationId === 'string' ? o.operationId : undefined;
      const tags: string[] = Array.isArray(o.tags) ? o.tags.filter((t: unknown) => typeof t === 'string') : [];
      const params: RawParam[] = [];
      const seen = new Set<string>();
      const add = (p: RawParam) => {
        const key = p.name;
        if (seen.has(key)) return;
        seen.add(key);
        params.push(p);
      };
      const plist: J[] = [...(item.parameters ?? []), ...(o.parameters ?? [])].map((x: J) => resolve(x));
      // an op-level parameter overrides a path-level one of the same name+in (op list is later, so keep the last)
      const dedup = new Map<string, J>();
      for (const p of plist) if (p && typeof p.name === 'string') dedup.set(`${p.in}:${p.name}`, p);
      for (const p of dedup.values()) {
        if (p.in === 'header' || p.in === 'cookie') {
          if (/^idempotency-?key$/i.test(p.name)) add({ name: 'idempotency_key', where: 'header', required: false, type: 'string', maxLength: 255 });
          continue;
        }
        if (p.in === 'body' && isV2) {
          const s = flattenSchema(p.schema ?? {}, resolve);
          addBody(s, p.required === true, add, resolve, opts.flatten !== false);
          continue;
        }
        const where = p.in === 'path' ? 'path' : p.in === 'formData' ? 'body' : 'query';
        add(toRaw(p.name, where, p.in === 'path' ? true : p.required === true, p.schema ?? p, resolve));
      }
      const rb = resolve(o.requestBody ?? {});
      if (rb.content) {
        const ct = Object.keys(rb.content).find((k) => /json/.test(k)) ?? Object.keys(rb.content).find((k) => /x-www-form-urlencoded/.test(k)) ?? Object.keys(rb.content)[0];
        if (ct) addBody(flattenSchema(rb.content[ct].schema ?? {}, resolve), rb.required === true, add, resolve, opts.flatten !== false);
      }
      if (opts.skipParams) for (let i = params.length - 1; i >= 0; i--) if (opts.skipParams.test(params[i]!.name)) params.splice(i, 1);
      let segs: string[];
      if (opts.naming === 'dotted') segs = httpPath.replace(/^\//, '').split('.').map(snake).filter(Boolean);
      else if (opts.naming === 'path' || (opts.naming === 'opid_or_path' && !opId)) segs = pathName(method, httpPath);
      else segs = opIdName(opId!);
      const info = { method: method.toUpperCase(), path: httpPath, opId, tags };
      if (opts.rename) segs = opts.rename(segs, info, o);
      segs = capNouns(segs.slice(0, -1)).concat([segs[segs.length - 1]!]);
      const summary = typeof o.summary === 'string' ? o.summary : '';
      out.push({
        path: segs, method: method.toUpperCase(), httpPath, opId, summary,
        desc: '', tags, params, deprecated: o.deprecated === true,
        bindings: { openapi: { operationId: opId ?? `${method.toUpperCase()} ${httpPath}`.slice(0, 250), method: method.toUpperCase(), path: httpPath.slice(0, 250) } },
      });
    }
  }
  return out;
}

function addBody(schema: J, bodyRequired: boolean, add: (p: RawParam) => void, resolve: (n: any, d?: number) => any, flatten: boolean): void { // eslint-disable-line @typescript-eslint/no-explicit-any
  const s = flattenSchema(schema, resolve);
  const props: J = s.properties ?? {};
  const req = new Set<string>(Array.isArray(s.required) ? s.required : []);
  if (Object.keys(props).length === 0) {
    if (s.type === 'array' || s.type === 'object' || s.additionalProperties) add({ name: 'body', where: 'body', required: bodyRequired, type: s.type === 'array' ? 'array' : 'object', items: 'object' });
    return;
  }
  for (const k of Object.keys(props).sort()) {
    const ps = flattenSchema(props[k], resolve);
    if (ps.readOnly === true) continue;
    const name = snake(k) === k.toLowerCase() ? k : k; // keep the wire name; sanitised later
    const t = typeOf(ps, resolve);
    const r = bodyRequired && req.has(k) || req.has(k);
    if (flatten && t === 'object' && ps.properties && Object.keys(ps.properties).length > 0 && Object.keys(ps.properties).length <= 12 && !ps.additionalProperties) {
      const sub: J = ps.properties;
      const sreq = new Set<string>(Array.isArray(ps.required) ? ps.required : []);
      let ok = true;
      const tmp: RawParam[] = [];
      for (const sk of Object.keys(sub).sort()) {
        const ss = flattenSchema(sub[sk], resolve);
        if (ss.readOnly === true) continue;
        const st = typeOf(ss, resolve);
        if (st === 'object') { ok = false; break; }
        tmp.push(toRaw(`${k}.${sk}`, 'body', r && sreq.has(sk), ss, resolve));
      }
      if (ok) { for (const x of tmp) add(x); continue; }
    }
    add(toRaw(name, 'body', r, ps, resolve));
  }
}
