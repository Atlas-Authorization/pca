// suggest.ts - the deterministic suggestion layer (spec section 5.2, layer 1). A versioned rule set proposes traits, param
// roles and param tags for a draft def. Union only: a suggestion can ADD a trait, a role (to a param that has none) or a tag,
// never remove or replace anything, and it never marks a def confirmed. A suggested def is still `pca.unreviewed` for floor
// purposes (T(d) contains it until a pinned reviewer signs); suggestions only improve the card and the review queue.

import { b64u, canonicalBytesStrict, hashCanonical, sign, utf8, verifyB64u } from '@atlasauth/pca';
import {
  ActionKitError, PARAM_TAGS, TRAIT_ID_RE,
  type ActionDef, type DefParamType, type Effect, type ParamDef, type ParamTag, type TraitId,
} from '../def';
import { isRole } from '../validate';
import { tokensOf } from './common';
import type { Registry } from '../traits';

export const SUGGEST_RULES_KIND = 'pca-suggest-rules';
export const SUGGEST_RULES_DOMAIN = 'atlas-pca/suggest-rules/v1';

export interface RuleMatch {
  /** HTTP method, GraphQL operation kind (QUERY/MUTATION/SUBSCRIPTION) or AsyncAPI action (SEND/RECEIVE), uppercase. */
  methods?: string[];
  /** Regular expression (bounded subset) tested against each binding location: path, field, tool, channel, service/method. */
  path_re?: string;
  /** Word sequences (`api_key`, `invoice.pay`) in the operation's names and path segments; stemmed, contiguous. */
  name_tokens?: string[];
  /** Like `name_tokens` but only the operation's own names (verb, aliases, title, operation id, tool, field, rpc), not its path. */
  name_tokens_strict?: string[];
  /** Params whose name tokens contain one of these sequences. */
  param_names?: string[];
  /** Every one of these sequences must match some param (e.g. amount AND currency). */
  param_names_all?: string[];
  param_types?: DefParamType[];
  param_formats?: string[];
  /** A param already carries one of these roles. */
  roles?: string[];
  /** The def has one of these effects. */
  effects?: Effect[];
}

export interface SuggestRule {
  id: string;
  match: RuleMatch;
  /** Trait ids, role names, or `tag:<tag>`. Roles and tags are applied to the params the rule matched. */
  adds: string[];
  note: string;
}

export interface SuggestRules {
  v: 1;
  kind: typeof SUGGEST_RULES_KIND;
  version: string;
  rules: SuggestRule[];
}

export interface SignedSuggestRules extends SuggestRules {
  digest: string;
  sig?: { alg: 'ed25519'; kid: string; value: string };
}

const RULE_ID_RE = /^SR-\d{3,4}$/;
const MATCH_KEYS = ['methods', 'path_re', 'name_tokens', 'name_tokens_strict', 'param_names', 'param_names_all', 'param_types', 'param_formats', 'roles', 'effects'];
const MAX_RULES = 1024;
const MAX_LIST = 64;
// a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
const NESTED_QUANTIFIER = /\([^)]*[+*][^)]*\)[+*{]|\([^)]*\|[^)]*\)[+*{]/;

const isStrList = (v: unknown, max = MAX_LIST): v is string[] => Array.isArray(v) && v.length > 0 && v.length <= max && v.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 64);

/** Null if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names. */
export function suggestRulesError(r: unknown, known?: ReadonlySet<TraitId>): string | null {
  if (r === null || typeof r !== 'object' || Array.isArray(r)) return 'rules must be an object';
  const o = r as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!['v', 'kind', 'version', 'rules', 'digest', 'sig'].includes(k)) return `unknown member '${k}'`;
  if (o.v !== 1 || o.kind !== SUGGEST_RULES_KIND) return 'not a suggest-rules document (v 1)';
  if (typeof o.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(o.version)) return 'version must be semver';
  if (!Array.isArray(o.rules) || o.rules.length === 0 || o.rules.length > MAX_RULES) return `rules must be 1..${MAX_RULES} entries`;
  const ids = new Set<string>();
  for (const x of o.rules) {
    if (x === null || typeof x !== 'object' || Array.isArray(x)) return 'a rule must be an object';
    const rule = x as Record<string, unknown>;
    for (const k of Object.keys(rule)) if (!['id', 'match', 'adds', 'note'].includes(k)) return `rule: unknown member '${k}'`;
    if (typeof rule.id !== 'string' || !RULE_ID_RE.test(rule.id) || ids.has(rule.id)) return 'rule ids must be unique SR-nnn';
    ids.add(rule.id);
    const w = rule.id;
    if (typeof rule.note !== 'string' || rule.note.length === 0 || rule.note.length > 200) return `${w}: note must be 1..200 characters`;
    const m = rule.match as Record<string, unknown> | null;
    if (m === null || typeof m !== 'object' || Array.isArray(m) || Object.keys(m).length === 0) return `${w}: match must be a non-empty object`;
    for (const k of Object.keys(m)) if (!MATCH_KEYS.includes(k)) return `${w}: unknown match member '${k}'`;
    for (const k of ['methods', 'name_tokens', 'name_tokens_strict', 'param_names', 'param_names_all', 'param_formats', 'roles'] as const) if (m[k] !== undefined && !isStrList(m[k])) return `${w}: match.${k} must be 1..${MAX_LIST} short strings`;
    if (m.methods !== undefined && !(m.methods as string[]).every((s) => s === s.toUpperCase())) return `${w}: methods are uppercase`;
    if (m.param_types !== undefined && (!isStrList(m.param_types) || !(m.param_types as string[]).every((t) => ['string', 'integer', 'boolean', 'date', 'datetime', 'duration', 'set', 'array', 'object_ref'].includes(t)))) return `${w}: match.param_types is not a list of param types`;
    if (m.effects !== undefined && !isStrList(m.effects, 12)) return `${w}: match.effects must be a list of effects`;
    if (m.path_re !== undefined) {
      if (typeof m.path_re !== 'string' || m.path_re.length === 0 || m.path_re.length > 128) return `${w}: path_re must be 1..128 characters`;
      if (NESTED_QUANTIFIER.test(m.path_re) || /\\[1-9]/.test(m.path_re) || /\(\?[<=!]/.test(m.path_re)) return `${w}: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)`;
      try { new RegExp(m.path_re); } catch { return `${w}: path_re is not a regular expression`; }
    }
    const hasParam = m.param_names !== undefined || m.param_names_all !== undefined || m.param_formats !== undefined || m.roles !== undefined;
    if (m.param_types !== undefined && m.param_names === undefined && m.param_formats === undefined && m.param_names_all === undefined) return `${w}: param_types needs param_names, param_names_all or param_formats`;
    if (!isStrList(rule.adds, 16)) return `${w}: adds must be 1..16 entries`;
    for (const a of rule.adds as string[]) {
      if (a.startsWith('tag:')) {
        if (!(PARAM_TAGS as readonly string[]).includes(a.slice(4))) return `${w}: unknown tag '${a}'`;
        if (!hasParam) return `${w}: a tag needs a param matcher`;
      } else if (isRole(a)) {
        if (!hasParam) return `${w}: a role needs a param matcher`;
      } else if (TRAIT_ID_RE.test(a)) {
        if (known !== undefined && !known.has(a)) return `${w}: unknown trait '${a}'`;
      } else return `${w}: '${a}' is not a trait, role or tag:`;
    }
  }
  return null;
}

/** b64u sha256 of the strict canonical rule set (without digest and sig). */
export function rulesDigest(r: SuggestRules): string {
  const { v, kind, version, rules } = r;
  return hashCanonical({ d: SUGGEST_RULES_DOMAIN, rules: { v, kind, version, rules } });
}

export const sealRules = (r: SuggestRules): SignedSuggestRules => ({ ...r, digest: rulesDigest(r) });

const rulesMessage = (digest: string): Uint8Array => {
  const dom = utf8(SUGGEST_RULES_DOMAIN + '\0');
  const body = canonicalBytesStrict({ digest });
  const out = new Uint8Array(dom.length + body.length);
  out.set(dom);
  out.set(body, dom.length);
  return out;
};

/** Sign a rule set as the rules publisher (a release step; the signature covers the digest). */
export function signRules(r: SuggestRules, kid: string, secret: Uint8Array): SignedSuggestRules {
  const bad = suggestRulesError(r);
  if (bad) throw new ActionKitError('bad_rules', bad);
  const sealed = sealRules(r);
  return { ...sealed, sig: { alg: 'ed25519', kid, value: b64u(sign(secret, rulesMessage(sealed.digest))) } };
}

/** Verify a signed rule set against pinned publisher keys: shape, digest, signature. Never throws. */
export function verifyRules(doc: unknown, pins: readonly { kid: string; pk: string }[]): { ok: true } | { ok: false; reason: string } {
  try {
    const bad = suggestRulesError(doc);
    if (bad) return { ok: false, reason: bad };
    const d = doc as SignedSuggestRules;
    if (d.digest !== rulesDigest(d)) return { ok: false, reason: 'digest does not match the rules' };
    if (!d.sig) return { ok: false, reason: 'the rule set is not signed' };
    const k = pins.find((p) => p.kid === d.sig!.kid);
    if (!k) return { ok: false, reason: `no pinned rules key '${d.sig.kid}'` };
    return verifyB64u(k.pk, rulesMessage(d.digest), d.sig.value) ? { ok: true } : { ok: false, reason: 'rules signature invalid' };
  } catch (e) {
    return { ok: false, reason: `rules verification error: ${(e as Error).message}` };
  }
}


// ---- facts ------------------------------------------------------------------------------------------------------------

/** Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` -> `charg`). */
export function stem(t: string): string {
  let s = t;
  if (s.length > 4 && s.endsWith('ies')) s = s.slice(0, -3) + 'y';
  else if (/(ss|x|z|ch|sh)es$/.test(s) && s.length > 4) s = s.slice(0, -2);
  else if (s.length > 3 && s.endsWith('s') && !s.endsWith('ss')) s = s.slice(0, -1);
  if (s.length > 5 && s.endsWith('ing')) s = s.slice(0, -3);
  else if (s.length > 4 && s.endsWith('ed')) s = s.slice(0, -2);
  if (s.length > 3 && s.endsWith('e')) s = s.slice(0, -1);
  return s;
}

const SEP = '|';
interface Facts {
  methods: Set<string>;
  locs: string[];
  tokens: string[];
  /** The same without path segments. */
  strict: string[];
  params: { name: string; tokens: string[]; type: DefParamType; format?: string; role?: string }[];
  effects: Set<string>;
}

function pathTokens(p: string): string[] {
  return p.split('/').filter((s) => s.length > 0 && !/[{}]/.test(s)).flatMap((s) => tokensOf(s));
}

export function factsOf(d: ActionDef): Facts {
  const b = d.bindings ?? {};
  const methods = new Set<string>();
  const locs: string[] = [];
  const src: string[][] = [];
  const pathSrc = new Set<string[]>();
  const verbSegs = d.verb.split('.').slice(1);
  src.push(verbSegs.flatMap((s) => tokensOf(s)));
  for (const a of d.aliases ?? []) src.push(tokensOf(a));
  src.push(tokensOf(d.title));
  if (b.openapi) {
    src.push(tokensOf(b.openapi.operationId));
    if (b.openapi.method) methods.add(b.openapi.method.toUpperCase());
    if (b.openapi.path) { locs.push(b.openapi.path); { const pt = pathTokens(b.openapi.path); pathSrc.add(pt); src.push(pt); } }
  }
  if (b.http) { methods.add(b.http.method.toUpperCase()); locs.push(b.http.path); { const pt = pathTokens(b.http.path); pathSrc.add(pt); src.push(pt); } }
  if (b.mcp) { locs.push(b.mcp.tool); src.push(tokensOf(b.mcp.tool)); }
  if (b.graphql) { methods.add(b.graphql.op.toUpperCase()); locs.push(b.graphql.field); src.push(tokensOf(b.graphql.field)); }
  if (b.grpc) { locs.push(`${b.grpc.service}/${b.grpc.method}`); src.push(tokensOf(b.grpc.service), tokensOf(b.grpc.method)); }
  if (b.asyncapi) { methods.add(b.asyncapi.op.toUpperCase()); locs.push(b.asyncapi.channel); src.push(tokensOf(b.asyncapi.channel)); }
  const tokens: string[] = [];
  const strict: string[] = [];
  for (const s of src) {
    if (tokens.length > 0) tokens.push(SEP);
    tokens.push(...s.map(stem));
    if (!pathSrc.has(s)) { if (strict.length > 0) strict.push(SEP); strict.push(...s.map(stem)); }
  }
  const params = Object.keys(d.params).sort().map((name) => {
    const p = d.params[name]!;
    return { name, tokens: tokensOf(name).map(stem), type: p.type, ...(p.format ? { format: p.format } : {}), ...(p.role ? { role: p.role } : {}) };
  });
  return { methods, locs: locs.map((l) => l.slice(0, 512)), tokens, strict, params, effects: new Set(d.effects) };
}

/** True iff the stemmed pattern occurs as a contiguous run in `hay`. */
function hasSeq(hay: readonly string[], pat: readonly string[]): boolean {
  if (pat.length === 0) return false;
  outer: for (let i = 0; i + pat.length <= hay.length; i++) {
    for (let j = 0; j < pat.length; j++) if (hay[i + j] !== pat[j]) continue outer;
    return true;
  }
  return false;
}
const patOf = (s: string): string[] => tokensOf(s).map(stem);

export interface Suggestion {
  traits: TraitId[];
  /** param name -> role (only for params with no role). */
  roles: Record<string, string>;
  tags: Record<string, ParamTag[]>;
  /** Rule ids that fired, in rule order. */
  fired: string[];
}

export const EMPTY_SUGGESTION: Suggestion = Object.freeze({ traits: [], roles: {}, tags: {}, fired: [] }) as Suggestion;

const INT_ROLES = new Set(['money.amount', 'money.fee', 'count.limit', 'bytes.size']);
function roleFits(role: string, type: DefParamType): boolean {
  if (INT_ROLES.has(role)) return type === 'integer';
  if (role.startsWith('time.')) return type === 'date' || type === 'datetime' || type === 'integer';
  return type === 'string';
}

function isTraitAdd(a: string): boolean {
  return !a.startsWith('tag:') && !isRole(a);
}

/**
 * Run the rules over a def. Only trait ids in `registry` (when given) can be suggested; anything else is dropped (the
 * closed vocabulary). Pure and deterministic.
 */
export function suggestWithRules(d: ActionDef, rules: SuggestRules, registry?: Registry): Suggestion {
  const f = factsOf(d);
  const traits = new Set<string>();
  const roles: Record<string, string> = {};
  const tags: Record<string, Set<ParamTag>> = {};
  const fired: string[] = [];
  const stems = f.tokens;
  for (const rule of rules.rules) {
    const m = rule.match;
    if (m.methods && !m.methods.some((x) => f.methods.has(x))) continue;
    if (m.effects && !m.effects.some((e) => f.effects.has(e))) continue;
    if (m.name_tokens && !m.name_tokens.some((p) => hasSeq(stems, patOf(p)))) continue;
    if (m.name_tokens_strict && !m.name_tokens_strict.some((p) => hasSeq(f.strict, patOf(p)))) continue;
    if (m.path_re) {
      const re = new RegExp(m.path_re);
      if (!f.locs.some((l) => re.test(l))) continue;
    }
    if (m.roles && !f.params.some((p) => p.role !== undefined && m.roles!.includes(p.role))) continue;
    let matched: typeof f.params = [];
    const paramCond = m.param_names !== undefined || m.param_formats !== undefined;
    if (paramCond) {
      const pats = (m.param_names ?? []).map(patOf);
      matched = f.params.filter((p) => {
        if (m.param_types && !m.param_types.includes(p.type)) return false;
        if (m.param_names && !pats.some((q) => hasSeq(p.tokens, q))) return false;
        if (m.param_formats && (p.format === undefined || !m.param_formats.includes(p.format))) return false;
        return true;
      });
      if (matched.length === 0) continue;
    }
    if (m.param_names_all) {
      const ok = m.param_names_all.every((n) => { const q = patOf(n); return f.params.some((p) => hasSeq(p.tokens, q) && (!m.param_types || m.param_types.includes(p.type) || p.type === 'string')); });
      if (!ok) continue;
    }
    fired.push(rule.id);
    for (const a of rule.adds) {
      if (a.startsWith('tag:')) {
        for (const p of matched) (tags[p.name] ??= new Set()).add(a.slice(4) as ParamTag);
      } else if (isTraitAdd(a)) {
        if (registry === undefined || registry.traits.has(a)) traits.add(a);
      } else {
        for (const p of matched) if (p.role === undefined && roles[p.name] === undefined && roleFits(a, p.type)) roles[p.name] = a;
      }
    }
  }
  traits.delete('pca.unreviewed');
  return {
    traits: [...traits].sort(),
    roles,
    tags: Object.fromEntries(Object.keys(tags).sort().map((k) => [k, [...tags[k]!].sort() as ParamTag[]])),
    fired,
  };
}

/** Union two suggestions (the restrictive direction, so no intersection is needed). */
export function unionSuggestions(a: Suggestion, b: Suggestion): Suggestion {
  const roles: Record<string, string> = { ...b.roles, ...a.roles };
  const tags: Record<string, ParamTag[]> = {};
  for (const k of new Set([...Object.keys(a.tags), ...Object.keys(b.tags)])) tags[k] = [...new Set([...(a.tags[k] ?? []), ...(b.tags[k] ?? [])])].sort() as ParamTag[];
  return { traits: [...new Set([...a.traits, ...b.traits])].sort(), roles, tags, fired: [...a.fired, ...b.fired] };
}

/** What the reviewer sees of a suggestion, recorded in `review.suggested_by` (strict JSON: strings, lists, no floats). */
export interface SuggestedBy {
  rules?: { version: string; digest: string; fired: string[] };
  models?: { id: string; version?: string; prompt_digest: string; input_digest: string; output_digest: string; temperature: number; traits: string[] }[];
  added: { traits: string[]; roles: Record<string, string>; tags: Record<string, string[]> };
}

/**
 * Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added;
 * nothing is removed or replaced, no attestation is created, and `review.state` goes from `unreviewed` to `suggested` (a
 * `suggested` def stays `suggested`; an `authored` or `confirmed` def keeps its state, its digest simply changes).
 */
export function applySuggestion(d: ActionDef, s: Suggestion, by: Omit<SuggestedBy, 'added'>): ActionDef {
  const params: Record<string, ParamDef> = {};
  const addedRoles: Record<string, string> = {};
  const addedTags: Record<string, string[]> = {};
  for (const name of Object.keys(d.params)) {
    const p = d.params[name]!;
    let q: ParamDef = p;
    const role = s.roles[name];
    if (role !== undefined && p.role === undefined && roleFits(role, p.type)) { q = { ...q, role }; addedRoles[name] = role; }
    const t = s.tags[name];
    if (t !== undefined) {
      const fresh = t.filter((x) => !(p.tags ?? []).includes(x));
      if (fresh.length > 0) { q = { ...q, tags: [...new Set([...(p.tags ?? []), ...fresh])].sort() as ParamTag[] }; addedTags[name] = fresh; }
    }
    params[name] = q;
  }
  const freshTraits = s.traits.filter((t) => !(d.traits ?? []).includes(t));
  // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
  let idempotency = d.idempotency;
  if (s.traits.includes('pca.money_moving') && (idempotency === undefined || idempotency.mode === 'none')) {
    idempotency = { mode: 'key_param', param: 'idempotency_key' };
    if (params.idempotency_key === undefined) params.idempotency_key = { type: 'string', max_len: 64, required: false };
  }
  const prev = (d.review.suggested_by ?? {}) as Partial<SuggestedBy>;
  const prevAdded = prev.added ?? { traits: [], roles: {}, tags: {} };
  const added: SuggestedBy['added'] = {
    traits: [...new Set([...prevAdded.traits, ...freshTraits])].sort(),
    roles: { ...prevAdded.roles, ...addedRoles },
    tags: Object.fromEntries([...new Set([...Object.keys(prevAdded.tags), ...Object.keys(addedTags)])].sort().map((k) => [k, [...new Set([...(prevAdded.tags[k] ?? []), ...(addedTags[k] ?? [])])].sort()])),
  };
  const rules = by.rules ?? prev.rules;
  const models = [...(prev.models ?? []), ...(by.models ?? [])];
  const suggested_by: SuggestedBy = { ...(rules ? { rules } : {}), ...(models.length > 0 ? { models } : {}), added };
  const state = d.review.state === 'unreviewed' || d.review.state === 'suggested' ? 'suggested' : d.review.state;
  return {
    ...d,
    params,
    ...(idempotency !== undefined ? { idempotency } : {}),
    ...(freshTraits.length > 0 || (d.traits ?? []).length > 0 ? { traits: [...new Set([...(d.traits ?? []), ...s.traits])].sort() } : {}),
    review: { ...d.review, state, suggested_by },
  };
}

