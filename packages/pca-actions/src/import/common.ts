// common.ts - what every importer shares: result types, text hygiene, verb naming, the bounded `$ref` resolver and the
// JSON Schema -> ParamDef flattening, and the single place a draft ActionDef is assembled (always `unreviewed`).

import { hashCanonicalLenient, b64u, sha256, utf8, compareUtf8 } from '@atlasauth/pca';
import {
  ActionKitError, ALIAS_RE, CORE_ROLES, ID_ROLE_RE, MAX_DEF_PARAMS, MAX_DESCRIPTION_BYTES, MAX_PARAM_PATH_DEPTH, MAX_TITLE_BYTES, VERB_RE,
  type ActionDef, type DefParamType, type Effect, type ParamDef, type ParamTag, type ResourceScope,
} from '../def';
import { validateDef } from '../validate';
import { checkParsed, resolveLimits, textSizeCheck, type ImportLimits } from './limits';

// ---- result types ----------------------------------------------------------------------------------------------------

export const IMPORT_KINDS = ['openapi', 'mcp', 'graphql', 'grpc', 'asyncapi', 'jsonschema'] as const;
export type ImportKind = (typeof IMPORT_KINDS)[number];

/** A decision the importer could not make for the developer, or a fact worth a reviewer's eye. Never silent. */
export interface Todo {
  /** `<verb or operation>[: <param>]` */
  where: string;
  code: string;
  message: string;
}

export interface SourceRef {
  kind: ImportKind;
  uri: string;
  /** b64u sha256 of the source bytes (text) or of its lenient canonical form (parsed JSON). */
  spec_digest: string;
  licence: string;
  imported_at: number;
}

export interface ImportReport {
  defs: ActionDef[];
  todo: Todo[];
  source: SourceRef;
}

export interface ImportOpts {
  /** Namespace of every verb (`[a-z][a-z0-9_]{0,31}`). */
  ns: string;
  uri?: string;
  /** SPDX id or free text; recorded in `source.licence` and the pack ledger. */
  licence?: string;
  /** Seconds; recorded in `source.imported_at`. Default 0 so an import is byte-reproducible. */
  now?: number;
  limits?: Partial<ImportLimits>;
  /** `x-` extensions that may steer the import. Default {@link DEFAULT_EXTENSIONS}. */
  allowExtensions?: readonly string[];
}

export const DEFAULT_EXTENSIONS: readonly string[] = ['x-pca-verb', 'x-pca-role', 'x-pca-internal'];

export const NS_RE = /^[a-z][a-z0-9_]{0,31}$/;

// ---- context ---------------------------------------------------------------------------------------------------------

export interface Ctx {
  ns: string;
  kind: ImportKind;
  lim: ImportLimits;
  todo: Todo[];
  source: SourceRef;
  ext: ReadonlySet<string>;
  /** Parsed-source root that `#/...` references resolve in. */
  root: unknown;
  /** Verbs and aliases already taken in this import. */
  verbs: Set<string>;
  aliases: Map<string, string>;
  defs: ActionDef[];
}

export function newCtx(kind: ImportKind, source: unknown, opts: ImportOpts): Ctx {
  if (typeof opts?.ns !== 'string' || !NS_RE.test(opts.ns)) throw new ActionKitError('bad_ns', 'ns must match [a-z][a-z0-9_]{0,31}');
  const lim = resolveLimits(opts.limits);
  let digest: string;
  if (typeof source === 'string') {
    textSizeCheck(source, lim);
    digest = b64u(sha256(utf8(source)));
  } else if (source instanceof Uint8Array) {
    if (source.length > lim.max_bytes) throw new ActionKitError('import_limit', `the source is larger than ${lim.max_bytes} bytes`);
    digest = b64u(sha256(source));
  } else {
    checkParsed(source, lim);
    digest = hashCanonicalLenient(source);
  }
  const now = opts.now ?? 0;
  if (!Number.isSafeInteger(now) || now < 0) throw new ActionKitError('bad_opts', 'now must be a non-negative integer');
  const src: SourceRef = { kind, uri: clip(opts.uri ?? `source:${kind}`, 2048), spec_digest: digest, licence: clip(opts.licence ?? 'unknown', 128), imported_at: now };
  return { ns: opts.ns, kind, lim, todo: [], source: src, ext: new Set(opts.allowExtensions ?? DEFAULT_EXTENSIONS), root: source, verbs: new Set(), aliases: new Map(), defs: [] };
}

export const addTodo = (c: Ctx, where: string, code: string, message: string): void => {
  // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
  if (c.todo.length < 5000) c.todo.push({ where: clip(where, 200), code, message: clip(message, 400) });
  else if (c.todo.length === 5000) c.todo.push({ where: '*', code: 'todo_truncated', message: 'further notes omitted' });
};

export const finish = (c: Ctx): ImportReport => ({ defs: c.defs, todo: c.todo, source: c.source });

// ---- text hygiene ----------------------------------------------------------------------------------------------------

const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const LONE_ONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
// eslint-disable-next-line no-control-regex
const CTRL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/g;
const enc = new TextEncoder();
const u8 = (s: string): number => enc.encode(s).length;

/** NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to `maxBytes` at a code point. */
export function clip(s: unknown, maxBytes: number): string {
  if (typeof s !== 'string') return '';
  let t = s.replace(LONE, '').replace(CTRL, ' ').normalize('NFC').replace(/\s+/g, ' ').trim();
  if (u8(t) <= maxBytes) return t;
  let out = '';
  for (const ch of t) {
    if (u8(out) + u8(ch) > maxBytes) break;
    out += ch;
  }
  t = out.trim();
  return t;
}

/** A non-empty title/description candidate: first non-empty of the arguments, clipped. */
export const firstText = (max: number, ...xs: unknown[]): string => {
  for (const x of xs) {
    const t = clip(x, max);
    if (t.length > 0) return t;
  }
  return '';
};

// ---- tokens and verbs ------------------------------------------------------------------------------------------------

/** Lowercase word tokens of a name: camelCase, snake, kebab, dotted and slashed names alike. */
export function tokensOf(name: string): string[] {
  const s = String(name).normalize('NFKD').replace(/[\u0300-\u036F]/g, '');
  return s
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

/** Words that name an action; they lead or trail a name and become the last verb segment. */
export const ACTION_WORDS: ReadonlySet<string> = new Set([
  'get', 'list', 'read', 'fetch', 'find', 'search', 'query', 'show', 'describe', 'create', 'add', 'new', 'make', 'insert', 'post', 'put', 'set', 'update', 'patch', 'edit', 'modify',
  'delete', 'remove', 'destroy', 'drop', 'send', 'notify', 'publish', 'invite', 'cancel', 'refund', 'charge', 'pay', 'run', 'exec', 'execute', 'invoke', 'start', 'stop',
  'enable', 'disable', 'approve', 'reject', 'close', 'open', 'merge', 'export', 'import', 'upload', 'download', 'subscribe', 'unsubscribe', 'revoke', 'grant', 'transfer',
]);

const seg = (toks: readonly string[]): string => {
  const s = toks.join('_');
  if (s.length <= 32) return s;
  // deterministic truncation: 27 chars + '_' + 4 hex of a digest of the whole segment
  const h = b64u(sha256(utf8(s))).replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 4).padEnd(4, '0');
  return `${s.slice(0, 27)}_${h}`;
};

/**
 * A verb `<ns>.<noun...>.<action>` from a raw operation name. Explicit separators (`.` `/` `:` ` `) each become a segment;
 * a camelCase or snake name with a leading or trailing action word becomes `<noun>.<action>`; any other name is one
 * segment. Deterministic; the result always satisfies VERB_RE (or throws, which no input can cause).
 */
export function verbOf(ns: string, raw: string): string {
  const parts = String(raw).split(/[./:\s]+/).map(tokensOf).filter((t) => t.length > 0);
  let segs: string[];
  if (parts.length >= 2) {
    segs = parts.map(seg);
  } else {
    const t = parts[0] ?? ['op'];
    if (t.length >= 2 && ACTION_WORDS.has(t[0]!)) segs = [seg(t.slice(1)), seg([t[0]!])];
    else if (t.length >= 2 && ACTION_WORDS.has(t[t.length - 1]!)) segs = [seg(t.slice(0, -1)), seg([t[t.length - 1]!])];
    else segs = [seg(t)];
  }
  // at most 5 segments after the namespace: keep the first 2 and the last 3 (the action stays last)
  if (segs.length > 5) segs = [...segs.slice(0, 2), ...segs.slice(-3)];
  const v = `${ns}.${segs.join('.')}`;
  if (!VERB_RE.test(v) || u8(v) > 128) return `${ns}.op`;
  return v;
}

/** The short NL-layer alias of a raw name (snake tokens), or undefined when it is not a valid alias or equals the verb. */
export function aliasOf(raw: string, verb: string): string | undefined {
  const a = tokensOf(raw).join('_');
  return a.length > 0 && a.length <= 64 && ALIAS_RE.test(a) && a !== verb ? a : undefined;
}

/** "createCustomer" -> "Create customer": the title when the source gave none. */
export function humanize(name: string): string {
  const t = tokensOf(name);
  return t.length === 0 ? '' : [t[0]!.charAt(0).toUpperCase() + t[0]!.slice(1), ...t.slice(1)].join(' ');
}

/** Make `verb` unique inside the import (`_2`, `_3` on the last segment), noting the collision. */
export function uniqueVerb(c: Ctx, verb: string, where: string): string {
  if (!c.verbs.has(verb)) return verb;
  for (let n = 2; n < 100_000; n++) {
    const sfx = `_${n}`;
    const dot = verb.lastIndexOf('.');
    const last = verb.slice(dot + 1);
    const cand = `${verb.slice(0, dot + 1)}${last.slice(0, 32 - sfx.length)}${sfx}`;
    if (!c.verbs.has(cand) && VERB_RE.test(cand)) {
      addTodo(c, where, 'duplicate_verb', `verb '${verb}' is taken by an earlier operation; this one is '${cand}'`);
      return cand;
    }
  }
  throw new ActionKitError('import_limit', 'too many operations map to one verb');
}

// ---- JSON Schema: bounded resolution --------------------------------------------------------------------------------

export interface JsonSchemaLike {
  type?: string | string[];
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number | boolean;
  exclusiveMaximum?: number | boolean;
  maxLength?: number;
  format?: string;
  items?: JsonSchemaLike;
  uniqueItems?: boolean;
  minItems?: number;
  maxItems?: number;
  description?: string;
  $ref?: string;
  nullable?: boolean;
  properties?: Record<string, JsonSchemaLike>;
  required?: string[];
  anyOf?: JsonSchemaLike[];
  oneOf?: JsonSchemaLike[];
  allOf?: JsonSchemaLike[];
  const?: unknown;
  readOnly?: boolean;
  [k: string]: unknown;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Follow a local `#/a/b` JSON pointer in `root`; undefined when absent, not local, or not an object. */
export function pointer(root: unknown, ref: string): unknown {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return undefined;
  let cur: unknown = root;
  for (const raw of ref.slice(2).split('/')) {
    const s = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    let seg = s;
    try { seg = decodeURIComponent(s); } catch { /* keep the raw segment */ }
    if (!isObj(cur) && !Array.isArray(cur)) return undefined;
    if (!own(cur as object, seg)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur !== null && typeof cur === 'object' ? cur : undefined;
}

/** Per-operation expansion budget: every schema node visited costs one; running out ends the expansion. */
export interface Budget {
  left: number;
  exhausted: boolean;
}
export const newBudget = (c: Ctx): Budget => ({ left: c.lim.max_ref_nodes, exhausted: false });

const mergeAll = (a: JsonSchemaLike, m: JsonSchemaLike): JsonSchemaLike => ({
  ...a, ...m,
  properties: { ...(a.properties ?? {}), ...(m.properties ?? {}) },
  required: [...(a.required ?? []), ...(m.required ?? [])],
});

/**
 * Resolve what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, collapse `anyOf`/`oneOf` to the
 * single non-null variant or to a union of string constants. What stays unrepresentable (a remote or cyclic reference, a
 * real union, an exhausted budget) is noted in the todo list and left as `{}`, which the caller declares `string`: a
 * placeholder that rejects every non-string value, so the draft fails closed until it is refined.
 * Bounds: `max_ref_depth` per chain, `bud` nodes per operation, so a reference bomb costs a fixed amount of work.
 */
export function resolveSchema(s: unknown, c: Ctx, bud: Budget, where: string, chain: readonly string[] = [], depth = 0): JsonSchemaLike {
  if (!isObj(s)) return {};
  if (bud.left <= 0) {
    if (!bud.exhausted) {
      bud.exhausted = true;
      addTodo(c, where, 'ref_budget', `schema expansion stopped after ${c.lim.max_ref_nodes} nodes (declared string; refine or drop)`);
    }
    return {};
  }
  bud.left--;
  if (depth > c.lim.max_ref_depth) {
    addTodo(c, where, 'ref_depth', `schema nesting or reference chain deeper than ${c.lim.max_ref_depth} (declared string; refine or drop)`);
    return {};
  }
  let cur = s as JsonSchemaLike;
  if (typeof cur.$ref === 'string') {
    const ref = cur.$ref;
    if (chain.includes(ref)) {
      addTodo(c, where, 'cyclic_ref', `reference '${clip(ref, 120)}' is cyclic (declared string; refine or drop)`);
      return {};
    }
    const target = pointer(c.root, ref);
    if (target === undefined) {
      addTodo(c, where, 'unresolved_ref', `reference '${clip(ref, 120)}' is not a local reference that resolves (declared string; refine or drop)`);
      return {};
    }
    const { $ref: _r, ...siblings } = cur;
    cur = { ...resolveSchema(target, c, bud, where, [...chain, ref], depth + 1), ...siblings };
  }
  if (Array.isArray(cur.allOf)) {
    const { allOf, ...rest } = cur;
    cur = { ...allOf.map((m) => resolveSchema(m, c, bud, where, chain, depth + 1)).reduce<JsonSchemaLike>(mergeAll, {}), ...rest };
  }
  const alts = Array.isArray(cur.anyOf) ? cur.anyOf : Array.isArray(cur.oneOf) ? cur.oneOf : undefined;
  if (alts !== undefined) {
    const { anyOf: _a, oneOf: _o, ...rest } = cur;
    const live = alts.map((m) => resolveSchema(m, c, bud, where, chain, depth + 1)).filter((m) => !(m.type === 'null' || (Array.isArray(m.type) && m.type.length > 0 && m.type.every((x) => x === 'null'))));
    if (live.length === 1) return { ...live[0]!, ...rest };
    const consts = live.map((m) => (typeof m.const === 'string' ? [m.const] : Array.isArray(m.enum) && m.enum.every((x) => typeof x === 'string') ? (m.enum as string[]) : null));
    if (live.length > 1 && consts.every((x) => x !== null)) return { ...rest, type: 'string', enum: [...new Set(consts.flat() as string[])] };
    addTodo(c, where, 'union', `a union of ${live.length} schemas has no representation (declared string; refine or drop)`);
    return rest;
  }
  if (cur.const !== undefined && cur.enum === undefined && typeof cur.const === 'string') cur = { ...cur, enum: [cur.const] };
  return cur;
}

// ---- JSON Schema -> params ----------------------------------------------------------------------------------------------

/** Param name segment hygiene: `[A-Za-z0-9_]{1,64}`; anything else is replaced by `_` (noted). */
export function paramSeg(raw: string): string {
  const s = raw.replace(/[^A-Za-z0-9_]/g, '_').replace(/^_+$/, '').slice(0, 64);
  return s.length > 0 ? s : 'p';
}

const FORMATS: Readonly<Record<string, string>> = { email: 'email', uuid: 'uuid', uri: 'url', url: 'url', 'idn-email': 'email', semver: 'semver' };
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

export interface ParamSink {
  params: Record<string, ParamDef>;
  /** Names renamed or skipped, for the todo list. */
}

const isRoleOk = (r: string): boolean => (CORE_ROLES as readonly string[]).includes(r) || ID_ROLE_RE.test(r) || /^x\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}$/.test(r);
const INT_ROLES = new Set(['money.amount', 'money.fee', 'count.limit', 'bytes.size']);

/** A leaf schema -> ParamDef. Unrepresentable shapes become `string` placeholders, noted. */
export function leafParam(s: JsonSchemaLike, required: boolean, c: Ctx, bud: Budget, where: string): ParamDef {
  const t0 = Array.isArray(s.type) ? s.type.find((x) => x !== 'null') : s.type;
  const enumStr = Array.isArray(s.enum) && s.enum.length > 0 && s.enum.length <= 256 && s.enum.every((x) => typeof x === 'string' && x.length > 0 && u8(x) <= 256 && x === x.normalize('NFC') && !LONE_ONE.test(x)) ? [...new Set(s.enum as string[])] : undefined;
  const t = t0 ?? (enumStr ? 'string' : Array.isArray(s.items) || isObj(s.items) ? 'array' : undefined);
  const base: ParamDef = { type: 'string' as DefParamType };
  if (!required) base.required = false;
  const desc = clip(s.description, 280);
  if (desc.length > 0) base.description = desc;
  const roleExt = c.ext.has('x-pca-role') && typeof s['x-pca-role'] === 'string' ? (s['x-pca-role'] as string) : undefined;
  const intNum = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && !Object.is(n, -0);
  const withRole = (p: ParamDef): ParamDef => {
    if (roleExt === undefined) return p;
    if (!isRoleOk(roleExt) || (INT_ROLES.has(roleExt) && p.type !== 'integer')) {
      addTodo(c, where, 'role_ignored', `x-pca-role '${clip(roleExt, 64)}' is not valid for a ${p.type} parameter`);
      return p;
    }
    return { ...p, role: roleExt };
  };
  if (t === 'integer' || (t === 'number' && (s.format === 'int32' || s.format === 'int64'))) {
    const p: ParamDef = { ...base, type: 'integer' };
    const exMin = s.exclusiveMinimum, exMax = s.exclusiveMaximum;
    if (intNum(s.minimum) && s.exclusiveMinimum !== true) p.min = s.minimum;
    else if (intNum(exMin)) p.min = exMin + 1;
    else if (intNum(s.minimum) && exMin === true) p.min = s.minimum + 1;
    if (intNum(s.maximum) && s.exclusiveMaximum !== true) p.max = s.maximum;
    else if (intNum(exMax)) p.max = exMax - 1;
    else if (intNum(s.maximum) && exMax === true) p.max = s.maximum - 1;
    if (p.min !== undefined && p.max !== undefined && p.min > p.max) { delete p.min; delete p.max; }
    return withRole(p);
  }
  if (t === 'boolean') return withRole({ ...base, type: 'boolean' });
  if (t === 'string') {
    const f = typeof s.format === 'string' ? s.format : '';
    if (f === 'date') return withRole({ ...base, type: 'date' });
    if (f === 'date-time') return withRole({ ...base, type: 'datetime' });
    const p: ParamDef = { ...base, type: 'string' };
    if (enumStr) p.values = enumStr;
    else if (Array.isArray(s.enum) && s.enum.length > 0) addTodo(c, where, 'enum_dropped', 'enum values are not 1..256 plain strings (declared as a free string; refine)');
    if (Object.prototype.hasOwnProperty.call(FORMATS, f)) p.format = FORMATS[f]!;
    if (intNum(s.maxLength) && s.maxLength > 0 && s.maxLength <= 16_777_216) p.max_len = s.maxLength;
    return withRole(p);
  }
  if (t === 'array') {
    const it = resolveSchema(s.items, c, bud, `${where}[]`);
    const itEnum = Array.isArray(it.enum) && it.enum.length > 0 && it.enum.length <= 256 && it.enum.every((x) => typeof x === 'string' && x.length > 0 && u8(x) <= 256 && x === x.normalize('NFC') && !LONE_ONE.test(x)) ? [...new Set(it.enum as string[])] : undefined;
    const lim: Partial<ParamDef> = {};
    if (intNum(s.maxItems) && s.maxItems >= 0) lim.max_items = s.maxItems;
    if (intNum(s.minItems) && s.minItems >= 0) lim.min_items = s.minItems;
    if (lim.min_items !== undefined && lim.max_items !== undefined && lim.min_items > lim.max_items) { delete lim.min_items; delete lim.max_items; }
    if (s.uniqueItems === true && itEnum) return withRole({ ...base, type: 'set', values: itEnum, ...lim });
    const itT = Array.isArray(it.type) ? it.type.find((x) => x !== 'null') : it.type;
    const items = itT === 'integer' ? 'integer' : itT === 'string' ? 'string' : itT === 'boolean' ? 'boolean' : undefined;
    if (items === undefined && itT !== undefined) addTodo(c, where, 'array_items', `array items of type '${clip(String(itT), 40)}' are not declared (items left open)`);
    return withRole({ ...base, type: 'array', ...(items ? { items } : {}), ...lim });
  }
  if (t === 'number') addTodo(c, where, 'unsupported_type', "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)");
  else addTodo(c, where, 'unsupported_type', `type '${clip(String(t ?? 'none'), 40)}' has no representation (declared string; refine or drop)`);
  return withRole({ ...base, type: 'string' });
}

/**
 * Flatten an object schema into params: nested objects become dotted names up to {@link MAX_PARAM_PATH_DEPTH} segments,
 * an object below that (or without properties) is a `string` placeholder; a child of an optional parent is optional.
 * `extraRequired` seeds the required set (path parameters). At most MAX_DEF_PARAMS params; the rest are dropped, noted.
 */
export function flattenObject(
  schema: JsonSchemaLike, c: Ctx, bud: Budget, where: string,
  out: Record<string, ParamDef>, opts: { prefix?: string[]; parentRequired?: boolean; forceRequired?: ReadonlySet<string> } = {},
): void {
  const prefix = opts.prefix ?? [];
  const props = isObj(schema.properties) ? schema.properties : {};
  const req = new Set(Array.isArray(schema.required) ? schema.required.filter((x): x is string => typeof x === 'string') : []);
  for (const name of Object.keys(props).sort(compareUtf8)) {
    if (RESERVED.has(name)) { addTodo(c, `${where}: ${name}`, 'skipped_param', `parameter name '${name}' is reserved; dropped`); continue; }
    const child = resolveSchema(props[name], c, bud, `${where}: ${name}`);
    if (child.readOnly === true) continue; // response-only; not an input
    const sname = paramSeg(name);
    if (sname !== name) addTodo(c, `${where}: ${name}`, 'renamed_param', `parameter '${clip(name, 80)}' is declared as '${sname}'`);
    const path = [...prefix, sname];
    const full = path.join('.');
    const required = (opts.parentRequired ?? true) && (req.has(name) || (opts.forceRequired?.has(name) ?? false));
    const isObject = child.type === 'object' || (child.type === undefined && isObj(child.properties));
    if (isObject && isObj(child.properties) && Object.keys(child.properties).length > 0 && path.length < MAX_PARAM_PATH_DEPTH) {
      flattenObject(child, c, bud, `${where}: ${full}`, out, { prefix: path, parentRequired: required });
      continue;
    }
    if (Object.keys(out).length >= MAX_DEF_PARAMS) { addTodo(c, where, 'too_many_params', `more than ${MAX_DEF_PARAMS} parameters; '${full}' and the rest are dropped`); return; }
    if (own(out, full) || Object.keys(out).some((k) => k.startsWith(full + '.') || full.startsWith(k + '.'))) { addTodo(c, `${where}: ${full}`, 'skipped_param', `parameter '${full}' collides with another; kept the first`); continue; }
    out[full] = isObject ? placeholderObject(child, required, c, `${where}: ${full}`) : leafParam(child, required, c, bud, `${where}: ${full}`);
  }
}

function placeholderObject(s: JsonSchemaLike, required: boolean, c: Ctx, where: string): ParamDef {
  addTodo(c, where, 'object_leaf', 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)');
  const p: ParamDef = { type: 'string' };
  if (!required) p.required = false;
  const d = clip(s.description, 280);
  if (d.length > 0) p.description = d;
  return p;
}

// ---- assembling a draft def -------------------------------------------------------------------------------------------

export interface DraftSpec {
  /** Raw operation name (operationId, tool name, field, rpc, ...). */
  name: string;
  verb?: string;
  title?: string;
  description?: string;
  effects: Effect[];
  scope: ResourceScope;
  params: Record<string, ParamDef>;
  idempotency?: ActionDef['idempotency'];
  traits?: string[];
  noAlias?: boolean;
  bindings: NonNullable<ActionDef['bindings']>;
}

const ID_ANY = { prefix: '', class: 'any_safe', len: [1, 128] } as const;

/** Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted). */
export function emitDef(c: Ctx, d: DraftSpec): ActionDef | undefined {
  if (c.defs.length >= c.lim.max_ops) throw new ActionKitError('import_limit', `more than ${c.lim.max_ops} operations`);
  const rawVerb = d.verb ?? verbOf(c.ns, d.name);
  const verb = uniqueVerb(c, VERB_RE.test(rawVerb) ? rawVerb : verbOf(c.ns, d.name), d.name);
  const segs = verb.split('.');
  const rtype = segs.length > 2 ? segs.slice(0, -1).join('.') : segs[0]!;
  const title = firstText(MAX_TITLE_BYTES, d.title, humanize(d.name), verb);
  const description = clip(d.description, Math.min(MAX_DESCRIPTION_BYTES, 600));
  const alias = d.noAlias ? undefined : aliasOf(d.name, verb);
  const def: ActionDef = {
    v: 1,
    kind: 'pca-action-def',
    verb,
    ...(alias !== undefined && !c.aliases.has(alias) && !c.verbs.has(alias) ? { aliases: [alias] } : {}),
    title: title.length > 0 ? title : verb,
    ...(description.length > 0 ? { description } : {}),
    effects: [...new Set(d.effects)].sort() as Effect[],
    resource: { type: /^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}$/.test(rtype) ? rtype : segs[0]!, id: { ...ID_ANY, len: [...ID_ANY.len] as [number, number] }, scope: d.scope },
    params: d.params,
    ...(d.idempotency ? { idempotency: d.idempotency } : {}),
    ...(d.traits && d.traits.length > 0 ? { traits: [...new Set(d.traits)].sort() } : {}),
    bindings: d.bindings,
    review: { state: 'unreviewed' },
    source: { kind: c.source.kind, uri: c.source.uri, spec_digest: c.source.spec_digest, licence: c.source.licence, imported_at: c.source.imported_at },
  };
  const bad = validateDef(def);
  if (bad !== null) {
    addTodo(c, d.name, 'invalid_def', `not emitted: ${bad}`);
    return undefined;
  }
  c.verbs.add(verb);
  if (def.aliases) c.aliases.set(def.aliases[0]!, verb);
  c.defs.push(def);
  return def;
}

/** Add a declared trait to a draft (used for hint-derived traits such as network egress). */
export const withTrait = (traits: string[] | undefined, t: string): string[] => [...new Set([...(traits ?? []), t])];

export type { ParamTag };
export { isObj, own, u8 };
