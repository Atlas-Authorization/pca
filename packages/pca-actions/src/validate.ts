// validate.ts - strict, closed-world structural validation of an ActionDef (spec section 2.1). An unknown member is a
// hard error. Strings are NFC with no lone surrogates and bounded; numbers are safe integers (no floats anywhere).
// Returns null for a well-formed def, else the first reason. Never throws.

import {
  ACTION_DEF_KIND, ALIAS_RE, BINDING_KINDS, BLAST_RADII, CORE_ROLES, CUSTOM_ROLE_RE, EFFECTS, ID_FORMAT_RE, ID_ROLE_RE, IDEMPOTENCY_MODES,
  MAX_DEF_ALIASES, MAX_DEF_CONTEXT, MAX_DEF_PARAMS, MAX_DEF_SIDE_EFFECTS, MAX_DEF_TRAITS, MAX_DESCRIPTION_BYTES, MAX_TITLE_BYTES, MAX_VERB_BYTES, PARAM_FORMATS,
  PARAM_NAME_RE, PARAM_TAGS, PARAM_TYPES_V1, PPM_MAX, PROVENANCE_LEVELS, RESOURCE_SCOPES, RESOURCE_TYPE_RE, REVERSIBILITY, REVIEW_STATES, SENSITIVITY_LEVELS,
  TRAIT_ID_RE, UNIT_KINDS, VERB_RE,
} from './def';
import { idPatternError } from './idpattern';
import { isContextKey } from './traits';

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);
const enc = new TextEncoder();
const u8 = (s: string): number => enc.encode(s).length;

export const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const isNonNeg = (v: unknown): v is number => isInt(v) && v >= 0;
const isStr = (v: unknown, max = 256): v is string => typeof v === 'string' && v.length > 0 && u8(v) <= max;

/** Strict JSON profile: plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth <= 32. */
export function jsonProfileError(v: unknown, depth = 0): string | null {
  if (depth > 32) return 'nesting deeper than 32';
  if (v === null || typeof v === 'boolean') return null;
  if (typeof v === 'number') return isInt(v) ? null : 'numbers must be safe integers (no floats, no -0)';
  if (typeof v === 'string') return LONE_SURROGATE.test(v) ? 'string has a lone surrogate' : v !== v.normalize('NFC') ? 'string is not NFC' : null;
  if (Array.isArray(v)) {
    for (const x of v) {
      const e = jsonProfileError(x, depth + 1);
      if (e) return e;
    }
    return null;
  }
  if (isPlainObject(v)) {
    for (const [k, x] of Object.entries(v)) {
      if (LONE_SURROGATE.test(k) || k !== k.normalize('NFC')) return 'member name is not NFC / has a lone surrogate';
      const e = jsonProfileError(x, depth + 1);
      if (e) return e;
    }
    return null;
  }
  return 'only JSON values are allowed';
}

const PARAM_KEYS = new Set([
  'type', 'role', 'required', 'values', 'min', 'max', 'max_len', 'items', 'min_items', 'max_items', 'format', 'unit', 'tags',
  'provenance_min', 'sensitivity', 'accumulates', 'default', 'principal_neutral_default', 'description',
]);
const DEF_KEYS = new Set([
  'v', 'kind', 'verb', 'aliases', 'title', 'description', 'effects', 'resource', 'params', 'reversibility', 'blast', 'side_effects', 'idempotency',
  'context', 'traits', 'audience', 'compensates', 'bindings', 'examples', 'review', 'source', 'since',
]);
const UNIT_ID_RE = /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/;
const INT_ROLES = new Set(['money.amount', 'money.fee', 'count.limit', 'bytes.size']);

export const isRole = (r: unknown): r is string =>
  typeof r === 'string' && ((CORE_ROLES as readonly string[]).includes(r) || ID_ROLE_RE.test(r) || CUSTOM_ROLE_RE.test(r));
export const isFormat = (f: unknown): f is string => typeof f === 'string' && ((PARAM_FORMATS as readonly string[]).includes(f) || ID_FORMAT_RE.test(f));

export function paramNameError(name: string): string | null {
  if (!PARAM_NAME_RE.test(name)) return `param name '${name}' is malformed (a-z, 0-9, _ and up to 3 dotted segments)`;
  if (name.split('.').some((s) => RESERVED.has(s))) return `param name '${name}' is reserved`;
  return null;
}

function paramError(name: string, p: unknown, names: ReadonlySet<string>): string | null {
  if (!isPlainObject(p)) return `${name}: declaration must be an object`;
  for (const k of Object.keys(p)) if (!PARAM_KEYS.has(k)) return `${name}: unknown member '${k}'`;
  if (!(PARAM_TYPES_V1 as readonly unknown[]).includes(p.type)) return `${name}: unknown type`;
  const t = p.type as string;
  if (p.role !== undefined && !isRole(p.role)) return `${name}: unknown role`;
  if (typeof p.role === 'string' && INT_ROLES.has(p.role) && t !== 'integer') return `${name}: role ${p.role} requires an integer parameter`;
  if (p.required !== undefined && typeof p.required !== 'boolean') return `${name}: required must be a boolean`;
  if (p.values !== undefined) {
    if (!Array.isArray(p.values) || p.values.length === 0 || p.values.length > 256 || !p.values.every((x) => isStr(x))) return `${name}: values must be 1..256 non-empty strings`;
    if (new Set(p.values).size !== p.values.length) return `${name}: values must be distinct`;
    if (t !== 'string' && t !== 'set') return `${name}: values apply to string and set only`;
  }
  if (t === 'set' && p.values === undefined) return `${name}: a set needs values`;
  const intLike = t === 'integer' || t === 'duration' || (t === 'array' && p.items === 'integer');
  for (const k of ['min', 'max'] as const) if (p[k] !== undefined && (!isInt(p[k]) || !intLike)) return `${name}: ${k} must be a safe integer on an integer parameter`;
  if (isInt(p.min) && isInt(p.max) && p.min > p.max) return `${name}: min > max`;
  if (p.max_len !== undefined && (!isInt(p.max_len) || p.max_len < 1 || p.max_len > 16_777_216 || !['string', 'array', 'object_ref'].includes(t))) return `${name}: max_len must be 1..16777216 on a string or array`;
  if (p.items !== undefined && (t !== 'array' || !isStr(p.items, 64))) return `${name}: items applies to array only`;
  for (const k of ['min_items', 'max_items'] as const) if (p[k] !== undefined && (!isNonNeg(p[k]) || (t !== 'set' && t !== 'array'))) return `${name}: ${k} must be a non-negative integer on a set or array`;
  if (isInt(p.min_items) && isInt(p.max_items) && p.min_items > p.max_items) return `${name}: min_items > max_items`;
  if (p.format !== undefined && (!isFormat(p.format) || (t !== 'string' && t !== 'object_ref'))) return `${name}: format must be a known format on a string parameter`;
  if (p.unit !== undefined) {
    const u = p.unit;
    if (t !== 'integer') return `${name}: unit applies to integer parameters only`;
    if (!isPlainObject(u) || !(UNIT_KINDS as readonly unknown[]).includes(u.kind)) return `${name}: unit.kind is not a known kind`;
    if (u.kind === 'money') {
      if (Object.keys(u).some((k) => !['kind', 'ccy', 'exp'].includes(k))) return `${name}: unit has unknown members`;
      if (!isInt(u.exp) || u.exp < 0 || u.exp > 18) return `${name}: unit.exp must be an integer in 0..18`;
      const c = u.ccy;
      if (typeof c === 'string') {
        if (!/^[A-Z]{3}$/.test(c)) return `${name}: unit.ccy must be an ISO 4217 style code`;
      } else if (!isPlainObject(c) || Object.keys(c).join() !== 'from' || typeof c.from !== 'string' || !names.has(c.from)) return `${name}: unit.ccy.from must name a declared parameter`;
    } else if (Object.keys(u).join() !== 'kind') return `${name}: unit has unknown members`;
  }
  if (p.tags !== undefined && (!Array.isArray(p.tags) || p.tags.length > PARAM_TAGS.length || new Set(p.tags).size !== p.tags.length || !p.tags.every((x) => (PARAM_TAGS as readonly unknown[]).includes(x)))) return `${name}: tags must be distinct known tags`;
  if (p.provenance_min !== undefined && !(PROVENANCE_LEVELS as readonly unknown[]).includes(p.provenance_min)) return `${name}: unknown provenance_min`;
  if (p.sensitivity !== undefined && !(SENSITIVITY_LEVELS as readonly unknown[]).includes(p.sensitivity)) return `${name}: unknown sensitivity`;
  if (p.accumulates !== undefined) {
    if (t !== 'integer') return `${name}: accumulates applies to integer parameters only`;
    const a = p.accumulates;
    if (!Array.isArray(a) || a.length === 0 || a.length > 8 || !a.every((x) => typeof x === 'string' && x.length <= 64 && UNIT_ID_RE.test(x)) || new Set(a).size !== a.length) return `${name}: accumulates must be 1..8 distinct unit ids`;
  }
  if (p.default === null) return `${name}: default must not be null (absent = no default)`;
  if (p.principal_neutral_default !== undefined && typeof p.principal_neutral_default !== 'boolean') return `${name}: principal_neutral_default must be a boolean`;
  if (p.principal_neutral_default === true && p.default === undefined) return `${name}: principal_neutral_default needs a default`;
  if (p.description !== undefined && !isStr(p.description, MAX_DESCRIPTION_BYTES)) return `${name}: description must be a string up to ${MAX_DESCRIPTION_BYTES} bytes`;
  return null;
}

const strList = (v: unknown, max: number, ok: (s: string) => boolean): boolean =>
  Array.isArray(v) && v.length <= max && new Set(v).size === v.length && v.every((x) => typeof x === 'string' && ok(x));

function bindingsError(b: unknown): string | null {
  if (!isPlainObject(b)) return 'bindings must be an object';
  const shapes: Record<string, [string[], string[]]> = {
    mcp: [['tool'], []], openapi: [['operationId'], ['method', 'path']], http: [['method', 'path'], []],
    graphql: [['op', 'field'], []], grpc: [['service', 'method'], []], asyncapi: [['channel', 'op'], []],
  };
  for (const k of Object.keys(b)) {
    if (!(BINDING_KINDS as readonly string[]).includes(k)) return `bindings: unknown kind '${k}'`;
    const v = b[k];
    const [req, opt] = shapes[k]!;
    if (!isPlainObject(v)) return `bindings.${k} must be an object`;
    for (const m of Object.keys(v)) if (![...req, ...opt].includes(m)) return `bindings.${k}: unknown member '${m}'`;
    for (const m of req) if (!isStr(v[m], 256)) return `bindings.${k}.${m} must be a non-empty string`;
    for (const m of opt) if (v[m] !== undefined && !isStr(v[m], 256)) return `bindings.${k}.${m} must be a non-empty string`;
  }
  if (b.graphql && !['query', 'mutation', 'subscription'].includes((b.graphql as { op: string }).op)) return 'bindings.graphql.op is not a GraphQL operation kind';
  if (b.asyncapi && !['send', 'receive'].includes((b.asyncapi as { op: string }).op)) return 'bindings.asyncapi.op must be send or receive';
  return null;
}

function reviewError(r: unknown): string | null {
  if (!isPlainObject(r)) return 'review must be an object';
  for (const k of Object.keys(r)) if (!['state', 'attestation', 'suggested_by', 'provenance'].includes(k)) return `review: unknown member '${k}'`;
  if (!(REVIEW_STATES as readonly unknown[]).includes(r.state)) return 'review.state is not a review state';
  if (r.provenance !== undefined) {
    const pv = r.provenance;
    if (!isPlainObject(pv)) return 'review.provenance must be an object';
    for (const k of Object.keys(pv)) {
      if (k !== 'union' && k !== 'adjudicated') return `review.provenance: unknown member '${k}'`;
      const v = pv[k];
      if (!Array.isArray(v) || v.length > 32 || v.some((t) => typeof t !== 'string' || !/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(t)) || new Set(v).size !== v.length) return `review.provenance.${k} must be a list of at most 32 distinct trait ids`;
    }
  }
  if (r.attestation !== undefined) {
    const a = r.attestation;
    if (!isPlainObject(a)) return 'review.attestation must be an object';
    for (const k of Object.keys(a)) if (!['def_digest', 'traits_digest', 'facts_digest', 'final_traits', 'dismissed', 'reviewer_kid', 'ts', 'sig'].includes(k)) return `review.attestation: unknown member '${k}'`;
    if (!isStr(a.def_digest, 64) || !isStr(a.traits_digest, 64) || !isStr(a.facts_digest, 64) || !isStr(a.reviewer_kid, 128) || !isNonNeg(a.ts)) return 'review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required';
    if (!strList(a.final_traits, MAX_DEF_TRAITS, (s) => TRAIT_ID_RE.test(s))) return 'review.attestation.final_traits must be distinct trait ids';
    if (!Array.isArray(a.dismissed) || a.dismissed.length > MAX_DEF_TRAITS || !a.dismissed.every((x) => isPlainObject(x) && Object.keys(x).sort().join() === 'reason,trait' && typeof x.trait === 'string' && TRAIT_ID_RE.test(x.trait) && isStr(x.reason, 256))) return 'review.attestation.dismissed must be {trait, reason} entries';
    if (a.sig !== undefined && !isStr(a.sig, 4096)) return 'review.attestation.sig must be a string';
  }
  return null;
}

/** Null if `x` is a well-formed ActionDef (structure only: the registry, prules and lint checks are separate). */
export function validateDef(x: unknown): string | null {
  try {
    const je = jsonProfileError(x);
    if (je) return `not strict JSON: ${je}`;
    if (!isPlainObject(x)) return 'def must be an object';
    for (const k of Object.keys(x)) if (!DEF_KEYS.has(k)) return `unknown member '${k}'`;
    if (x.v !== 1) return 'unsupported def version';
    if (x.kind !== ACTION_DEF_KIND) return `kind must be '${ACTION_DEF_KIND}'`;
    if (typeof x.verb !== 'string' || !VERB_RE.test(x.verb) || u8(x.verb) > MAX_VERB_BYTES) return 'verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)';
    if (x.aliases !== undefined && (!strList(x.aliases, MAX_DEF_ALIASES, (s) => ALIAS_RE.test(s) && u8(s) <= MAX_VERB_BYTES) || (x.aliases as string[]).includes(x.verb))) return 'aliases must be distinct verb-shaped names other than the verb';
    if (!isStr(x.title, MAX_TITLE_BYTES)) return `title must be a non-empty string up to ${MAX_TITLE_BYTES} bytes`;
    if (x.description !== undefined && !isStr(x.description, MAX_DESCRIPTION_BYTES)) return 'description must be a string';
    if (!strList(x.effects, EFFECTS.length, (s) => (EFFECTS as readonly string[]).includes(s)) || (x.effects as string[]).length === 0) return 'effects must be 1..12 distinct known effects';
    // resource
    const r = x.resource;
    if (!isPlainObject(r) || Object.keys(r).sort().join() !== 'id,scope,type') return 'resource must be {type, id, scope}';
    if (typeof r.type !== 'string' || !RESOURCE_TYPE_RE.test(r.type) || r.type.length > 128) return 'resource.type is malformed';
    const ide = idPatternError(r.id);
    if (ide) return ide;
    if (!(RESOURCE_SCOPES as readonly unknown[]).includes(r.scope)) return 'resource.scope is not a scope';
    // params
    if (!isPlainObject(x.params)) return 'params must be an object';
    const names = Object.keys(x.params);
    if (names.length > MAX_DEF_PARAMS) return `more than ${MAX_DEF_PARAMS} parameters`;
    const nameSet = new Set(names);
    for (const n of names) {
      const ne = paramNameError(n);
      if (ne) return ne;
      // a dotted name may not also be a leaf and an ancestor of another declared name
      for (const m of names) if (m !== n && m.startsWith(n + '.')) return `param '${n}' is both a value and the parent of '${m}'`;
    }
    for (const n of names) {
      const e = paramError(n, x.params[n], nameSet);
      if (e) return e;
    }
    // reversibility
    const rv = x.reversibility;
    if (rv !== undefined && typeof rv !== 'string') {
      if (!isPlainObject(rv) || Object.keys(rv).some((k) => !['by', 'map', 'default'].includes(k))) return 'reversibility must be a class or {by, map, default?}';
      if (typeof rv.by !== 'string' || !nameSet.has(rv.by)) return 'reversibility.by must name a declared parameter';
      if (!isPlainObject(rv.map) || Object.keys(rv.map).length === 0 || Object.keys(rv.map).length > 256 || !Object.entries(rv.map).every(([k, v]) => isStr(k, 128) && (REVERSIBILITY as readonly unknown[]).includes(v))) return 'reversibility.map must map values to reversibility classes';
      if (rv.default !== undefined && !(REVERSIBILITY as readonly unknown[]).includes(rv.default)) return 'reversibility.default is not a class';
    } else if (rv !== undefined && !(REVERSIBILITY as readonly string[]).includes(rv)) return 'unknown reversibility class';
    // blast
    if (x.blast !== undefined) {
      const b = x.blast;
      if (!isPlainObject(b) || Object.keys(b).some((k) => !['radius', 'ppm'].includes(k)) || !(BLAST_RADII as readonly unknown[]).includes(b.radius)) return 'blast must be {radius, ppm?}';
      if (b.ppm !== undefined && !(isInt(b.ppm) && b.ppm >= 0 && b.ppm <= PPM_MAX)) return 'blast.ppm must be an integer in 0..1000000';
    }
    if (x.side_effects !== undefined) {
      const s = x.side_effects;
      if (!Array.isArray(s) || s.length > MAX_DEF_SIDE_EFFECTS || !s.every((e) => isPlainObject(e) && Object.keys(e).sort().join() === 'kind,target' && isStr(e.target, 128) && (EFFECTS as readonly unknown[]).includes(e.kind))) return 'side_effects must be {target, kind} entries';
    }
    if (x.idempotency !== undefined) {
      const i = x.idempotency;
      if (!isPlainObject(i) || Object.keys(i).some((k) => !['mode', 'param'].includes(k)) || !(IDEMPOTENCY_MODES as readonly unknown[]).includes(i.mode)) return 'idempotency must be {mode, param?}';
      if (i.mode === 'key_param' ? typeof i.param !== 'string' || !nameSet.has(i.param) : i.param !== undefined) return 'idempotency.param is required for key_param (a declared parameter) and forbidden otherwise';
    }
    if (x.context !== undefined && !strList(x.context, MAX_DEF_CONTEXT, isContextKey)) return 'context must be distinct known context keys';
    if (x.traits !== undefined && !strList(x.traits, MAX_DEF_TRAITS, (s) => TRAIT_ID_RE.test(s))) return 'traits must be distinct trait ids';
    if (x.audience !== undefined && x.audience !== 'resource') return "audience must be 'resource'";
    if (x.compensates !== undefined && (typeof x.compensates !== 'string' || !VERB_RE.test(x.compensates))) return 'compensates must be a verb';
    if (x.bindings !== undefined) {
      const be = bindingsError(x.bindings);
      if (be) return be;
    }
    if (x.examples !== undefined) {
      const ex = x.examples;
      if (!Array.isArray(ex) || ex.length > 32) return 'examples must be an array of up to 32 entries';
      for (const e of ex) {
        if (!isPlainObject(e) || Object.keys(e).some((k) => !['params', 'under', 'expect'].includes(k)) || !isPlainObject(e.params) || !['allow', 'escalate', 'deny'].includes(e.expect as string)) return 'example must be {params, under?, expect}';
      }
    }
    const re = reviewError(x.review);
    if (re) return re;
    if (x.source !== undefined) {
      const s = x.source;
      if (!isPlainObject(s) || Object.keys(s).some((k) => !['kind', 'uri', 'spec_digest', 'licence', 'imported_at'].includes(k)) || !isStr(s.kind, 64) || !isStr(s.uri, 2048) || !isStr(s.spec_digest, 128) || !isStr(s.licence, 128) || (s.imported_at !== undefined && !isNonNeg(s.imported_at))) return 'source must be {kind, uri, spec_digest, licence, imported_at?}';
    }
    if (x.since !== undefined && !isStr(x.since, 64)) return 'since must be a string';
    return null;
  } catch (e) {
    return `malformed def: ${(e as Error).message}`;
  }
}
