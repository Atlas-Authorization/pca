// author.ts - authoring forms of an ActionDef (spec section 4): the YAML/JSON loader with shorthands and the TypeScript
// builder. Both expand to the SAME ActionDef through the SAME functions (expandAction, parseParamShorthand), so one action
// has one digest whichever way it was written. The strict JSON form (validateDef) stays the source of truth: nothing here
// can express what the JSON cannot, and every expanded def is checked by validateDef before it is returned.

import { LineCounter, isMap, isSeq, parseDocument, type Document } from 'yaml';
import {
  ACTION_DEF_KIND, ActionKitError, BLAST_RADII, ID_CLASSES, PROVENANCE_LEVELS, RESOURCE_SCOPES,
  type ActionDef, type BlastRadius, type Effect, type IdClass, type IdPattern, type ParamDef, type ResourceScope, type TraitId,
} from './def';
import { jsonProfileError, validateDef } from './validate';
import { businessRulesError, type BusinessRules } from './business-rules';

/** Largest authoring file the loader reads (a pack larger than this is sharded across files). */
export const MAX_AUTHOR_BYTES = 1 << 20;
export const IDEMPOTENCY_PARAM = 'idempotency_key';
/** Effects whose repeat is not harmless: an absent idempotency declaration gets a key parameter. */
export const AUTO_IDEMPOTENT_EFFECTS: readonly Effect[] = ['send', 'pay', 'create', 'provision', 'publish'];

export interface LoadNote { verb?: string; message: string }
/** A 1-based source position. */
export interface Loc { line: number; column: number }
export interface LoadError { index?: number; verb?: string; message: string; line?: number; column?: number }
/** Where an action (and each of its params) starts in the source text. */
export interface ActionLoc extends Loc { params: Record<string, Loc> }
export interface LoadResult {
  /** The file's `ns` (absent for raw single-def JSON). */
  ns?: string;
  defs: ActionDef[];
  /** Informational lint notes (for example "idempotency_key auto-added"). */
  notes: LoadNote[];
  errors: LoadError[];
  /** Source positions by verb (set for text input; absent for an already parsed value). */
  locs: Record<string, ActionLoc>;
  /** The business rules blocks (`rules:` of an action), by verb. Kept apart from the def: they are not part of its digest. */
  rules: Record<string, BusinessRules>;
}

// ---- param shorthands ---------------------------------------------------------------------------------------------------

type Args = { pos: string[]; named: Record<string, string> };
const splitArgs = (s: string): Args => {
  const pos: string[] = [];
  const named: Record<string, string> = {};
  for (const raw of s.split(',')) {
    const a = raw.trim();
    if (a === '') continue;
    const eq = a.indexOf('=');
    if (eq > 0) named[a.slice(0, eq).trim()] = a.slice(eq + 1).trim();
    else pos.push(a);
  }
  return { pos, named };
};
const intArg = (s: string | undefined, what: string): number | undefined => {
  if (s === undefined) return undefined;
  if (!/^-?\d{1,15}$/.test(s)) throw new ActionKitError('bad_shorthand', `${what} must be an integer, got '${s}'`);
  return Number(s);
};
const only = (a: Args, pos: number, names: string[], shorthand: string): void => {
  if (a.pos.length > pos) throw new ActionKitError('bad_shorthand', `'${shorthand}' takes at most ${pos} positional argument(s)`);
  for (const k of Object.keys(a.named)) if (!names.includes(k)) throw new ActionKitError('bad_shorthand', `'${shorthand}' has no option '${k}'`);
};
const listArg = (s: string, shorthand: string): string[] => {
  const xs = s.split('|').map((x) => x.trim());
  if (xs.length === 0 || xs.some((x) => x === '')) throw new ActionKitError('bad_shorthand', `'${shorthand}' needs values separated by |`);
  return xs;
};

/**
 * Expand one param shorthand. Forms: email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N)
 * int(MIN..MAX) count(MAX) money(CCY|@param, max=N, min=N, exp=N, provenance=first_party|tool|agent) id:<type> enum(a|b) set(a|b) array(items, max=N).
 * A trailing `?` makes the param optional. An unbounded form (`text`, `int`) is allowed and is what the linter then flags.
 */
export function parseParamShorthand(src: string): ParamDef {
  const m = /^([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\((.*)\))?(\?)?$/.exec(src.trim());
  if (!m) throw new ActionKitError('bad_shorthand', `unknown param shorthand '${src}'`);
  const name = m[1]!;
  const inner = m[2];
  const optional = m[3] === '?';
  const a = splitArgs(inner ?? '');
  const bare = (): void => { if (inner !== undefined) throw new ActionKitError('bad_shorthand', `'${name}' takes no arguments`); };
  let p: ParamDef;
  switch (name) {
    case 'email': bare(); p = { type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 }; break;
    case 'phone': bare(); p = { type: 'string', role: 'contact.phone', format: 'phone_e164', tags: ['pii'], max_len: 16 }; break;
    case 'url': bare(); p = { type: 'string', role: 'url.target', format: 'url', max_len: 2048 }; break;
    case 'uuid': bare(); p = { type: 'string', format: 'uuid', max_len: 36 }; break;
    case 'ccy': bare(); p = { type: 'string', role: 'money.currency', format: 'iso_currency', max_len: 3 }; break;
    case 'country': bare(); p = { type: 'string', format: 'iso_country', max_len: 2 }; break;
    case 'secret': bare(); p = { type: 'string', role: 'credential.secret', tags: ['secret'], max_len: 512 }; break;
    case 'bool': bare(); p = { type: 'boolean' }; break;
    case 'date': bare(); p = { type: 'date' }; break;
    case 'datetime': bare(); p = { type: 'datetime' }; break;
    case 'duration': {
      only(a, 1, [], 'duration');
      const max = intArg(a.pos[0], 'duration max (ms)');
      p = { type: 'duration', ...(max !== undefined ? { min: 0, max } : {}) };
      break;
    }
    case 'text': case 'string': {
      only(a, 1, [], name);
      const n = intArg(a.pos[0], `${name} length`);
      p = { type: 'string', ...(n !== undefined ? { max_len: n } : {}) };
      break;
    }
    case 'message': {
      only(a, 1, [], 'message');
      p = { type: 'string', role: 'text.message', tags: ['free_text_outbound'], max_len: intArg(a.pos[0], 'message length') ?? 1024 };
      break;
    }
    case 'int': {
      only(a, 1, [], 'int');
      const r = a.pos[0] === undefined ? null : /^(-?\d{1,15})\.\.(-?\d{1,15})$/.exec(a.pos[0]);
      if (a.pos[0] !== undefined && r === null) throw new ActionKitError('bad_shorthand', "int takes MIN..MAX, for example int(0..100)");
      p = { type: 'integer', ...(r ? { min: Number(r[1]), max: Number(r[2]) } : {}) };
      break;
    }
    case 'count': {
      only(a, 1, [], 'count');
      const max = intArg(a.pos[0], 'count max');
      p = { type: 'integer', role: 'count.limit', min: 1, ...(max !== undefined ? { max } : {}), unit: { kind: 'count' } };
      break;
    }
    case 'money': {
      only(a, 1, ['max', 'min', 'exp', 'provenance'], 'money');
      const c = a.pos[0];
      if (c === undefined) throw new ActionKitError('bad_shorthand', 'money needs a currency: money(USD) or money(@currency_param)');
      const ccy = c.startsWith('@') ? { from: c.slice(1) } : c;
      const max = intArg(a.named.max, 'money max');
      // an amount defaults to provenance first_party (the value must not come from an untrusted tool or agent output)
      const prov = a.named.provenance ?? 'first_party';
      if (!(PROVENANCE_LEVELS as readonly string[]).includes(prov)) throw new ActionKitError('bad_shorthand', `money provenance must be one of ${PROVENANCE_LEVELS.join(', ')}`);
      p = { type: 'integer', role: 'money.amount', min: intArg(a.named.min, 'money min') ?? 1, ...(max !== undefined ? { max } : {}), unit: { kind: 'money', ccy, exp: intArg(a.named.exp, 'money exp') ?? 2 }, provenance_min: prov as ParamDef['provenance_min'] };
      break;
    }
    case 'enum': case 'set': {
      if (inner === undefined) throw new ActionKitError('bad_shorthand', `${name} needs values: ${name}(a|b|c)`);
      p = { type: name === 'enum' ? 'string' : 'set', values: listArg(inner, name) };
      break;
    }
    case 'array': {
      only(a, 1, ['max', 'min'], 'array');
      const items = a.pos[0];
      if (items !== 'string' && items !== 'integer') throw new ActionKitError('bad_shorthand', 'array(items): items is string or integer');
      const max = intArg(a.named.max, 'array max');
      const min = intArg(a.named.min, 'array min');
      p = { type: 'array', items, ...(min !== undefined ? { min_items: min } : {}), ...(max !== undefined ? { max_items: max } : {}) };
      break;
    }
    default: {
      if (name.startsWith('id:')) { bare(); p = { type: 'string', role: `id.${name.slice(3)}`, max_len: 64 }; break; }
      throw new ActionKitError('bad_shorthand', `unknown param shorthand '${name}'`);
    }
  }
  return optional ? { ...p, required: false } : p;
}

// ---- resource shorthand ---------------------------------------------------------------------------------------------------

const DEFAULT_ID_LEN: [number, number] = [8, 32];

/**
 * `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`.
 * A prefix pattern is scope one (class alnum, length 8..32 after the prefix); `*` is scope set; a bare type is tenant.
 */
export function parseResourceShorthand(src: string): { type: string; id: IdPattern; scope: ResourceScope } {
  let s = src.trim();
  let scope: ResourceScope | undefined;
  const at = /@([a-z]+)$/.exec(s);
  if (at) {
    if (!(RESOURCE_SCOPES as readonly string[]).includes(at[1]!)) throw new ActionKitError('bad_shorthand', `unknown resource scope '@${at[1]}'`);
    scope = at[1] as ResourceScope;
    s = s.slice(0, at.index);
  }
  const colon = s.indexOf(':');
  if (colon < 0) return { type: s, id: '*', scope: scope ?? 'tenant' };
  const type = s.slice(0, colon);
  const idsrc = s.slice(colon + 1);
  if (idsrc === '*') return { type, id: '*', scope: scope ?? 'set' };
  const star = idsrc.indexOf('*');
  if (star < 0) return { type, id: { exact: idsrc }, scope: scope ?? 'one' };
  const prefix = idsrc.slice(0, star);
  const rest = idsrc.slice(star + 1);
  let cls: IdClass = 'alnum';
  let len = DEFAULT_ID_LEN;
  if (rest !== '') {
    const r = /^\{([a-z_]+),(\d{1,3})\.\.(\d{1,3})\}$/.exec(rest);
    if (!r || !(ID_CLASSES as readonly string[]).includes(r[1]!)) throw new ActionKitError('bad_shorthand', `resource id '${idsrc}': expected prefix*{class,min..max}`);
    cls = r[1] as IdClass;
    len = [Number(r[2]), Number(r[3])];
  }
  return { type, id: { prefix, class: cls, len }, scope: scope ?? 'one' };
}

// ---- action expansion -----------------------------------------------------------------------------------------------------

const ENTRY_KEYS = new Set([
  'v', 'kind', 'verb', 'aliases', 'title', 'description', 'effects', 'resource', 'params', 'reversibility', 'blast', 'side_effects', 'idempotency',
  'context', 'traits', 'audience', 'compensates', 'bindings', 'examples', 'review', 'source', 'since',
]);
const asList = (v: unknown): unknown => (typeof v === 'string' ? [v] : v);
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The title an action gets when it names none: the action word and its nouns, "acme.invoice.send" -> "Send invoice". */
export function defaultTitle(verb: string): string {
  const seg = verb.split('.').slice(1);
  const act = seg[seg.length - 1] ?? verb;
  const t = [act, ...seg.slice(0, -1)].join(' ').replace(/_/g, ' ');
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export interface ExpandOptions { since?: string }

/**
 * Expand one authoring entry (shorthands or full def members) to an ActionDef. Throws {@link ActionKitError} `bad_action`
 * for a malformed entry. Returns the def and the notes (auto-added idempotency key).
 */
export function expandAction(entry: unknown, opts: ExpandOptions = {}): { def: ActionDef; notes: LoadNote[] } {
  if (!isObj(entry)) throw new ActionKitError('bad_action', 'an action must be an object');
  for (const k of Object.keys(entry)) if (!ENTRY_KEYS.has(k)) throw new ActionKitError('bad_action', `unknown member '${k}'`);
  if (entry.v !== undefined && entry.v !== 1) throw new ActionKitError('bad_action', 'unsupported def version');
  if (entry.kind !== undefined && entry.kind !== ACTION_DEF_KIND) throw new ActionKitError('bad_action', `kind must be '${ACTION_DEF_KIND}'`);
  const verb = entry.verb;
  if (typeof verb !== 'string') throw new ActionKitError('bad_action', 'verb is required');
  const notes: LoadNote[] = [];
  if (entry.kind !== undefined) {
    // the full form (a `kind` member) is taken exactly as written: no shorthands, no defaults, validateDef decides
    const full = { v: 1, ...entry };
    const je0 = jsonProfileError(full);
    if (je0) throw new ActionKitError('bad_action', `not strict JSON: ${je0}`);
    return { def: full as unknown as ActionDef, notes };
  }
  const out: Record<string, unknown> = { v: 1, kind: ACTION_DEF_KIND, verb };
  if (entry.aliases !== undefined) out.aliases = asList(entry.aliases);
  out.title = entry.title ?? defaultTitle(verb);
  if (entry.description !== undefined) out.description = entry.description;
  out.effects = asList(entry.effects);
  const res = entry.resource;
  out.resource = typeof res === 'string' ? parseResourceShorthand(res) : res;
  const params: Record<string, unknown> = {};
  if (entry.params !== undefined) {
    if (!isObj(entry.params)) throw new ActionKitError('bad_action', 'params must be an object');
    for (const [k, v] of Object.entries(entry.params)) params[k] = typeof v === 'string' ? parseParamShorthand(v) : v;
  }
  if (entry.reversibility !== undefined) out.reversibility = entry.reversibility;
  if (entry.blast !== undefined) out.blast = typeof entry.blast === 'string' ? { radius: entry.blast as BlastRadius } : entry.blast;
  if (typeof entry.blast === 'string' && !(BLAST_RADII as readonly string[]).includes(entry.blast)) throw new ActionKitError('bad_action', `unknown blast radius '${entry.blast}'`);
  if (entry.side_effects !== undefined) out.side_effects = entry.side_effects;
  // idempotency: a string is the mode; absent on a non-idempotent effect gets the key parameter (the linter notes it)
  const effects = Array.isArray(out.effects) ? (out.effects as Effect[]) : [];
  let idem: unknown = entry.idempotency;
  if (typeof idem === 'string') idem = idem === 'key_param' ? { mode: 'key_param', param: IDEMPOTENCY_PARAM } : { mode: idem };
  if (idem === undefined && effects.some((e) => AUTO_IDEMPOTENT_EFFECTS.includes(e))) {
    idem = { mode: 'key_param', param: IDEMPOTENCY_PARAM };
    notes.push({ verb, message: `${IDEMPOTENCY_PARAM} auto-added` });
  }
  if (isObj(idem) && idem.mode === 'key_param' && idem.param === IDEMPOTENCY_PARAM && !Object.prototype.hasOwnProperty.call(params, IDEMPOTENCY_PARAM)) {
    params[IDEMPOTENCY_PARAM] = { type: 'string', max_len: 64 };
  }
  if (idem !== undefined) out.idempotency = idem;
  out.params = params;
  for (const k of ['context', 'traits'] as const) if (entry[k] !== undefined) out[k] = asList(entry[k]);
  for (const k of ['audience', 'compensates', 'bindings', 'examples', 'source'] as const) if (entry[k] !== undefined) out[k] = entry[k];
  out.review = entry.review ?? { state: 'authored' };
  const since = entry.since ?? opts.since;
  if (since !== undefined) out.since = since;
  const je = jsonProfileError(out);
  if (je) throw new ActionKitError('bad_action', `not strict JSON: ${je}`);
  return { def: out as unknown as ActionDef, notes };
}

// ---- the file loader --------------------------------------------------------------------------------------------------------

const FILE_KEYS = new Set(['ns', 'since', 'actions']);

function hasProtoKey(v: unknown, depth = 0): boolean {
  if (depth > 40 || v === null || typeof v !== 'object') return depth > 40;
  if (Array.isArray(v)) return v.some((x) => hasProtoKey(x, depth + 1));
  return Object.keys(v).some((k) => k === '__proto__' || hasProtoKey((v as Record<string, unknown>)[k], depth + 1));
}

/** Expand an already parsed document (`{ns, since?, actions: [...]}`, or one raw def). Never throws. */
export function loadActionsValue(doc: unknown): LoadResult {
  const res: LoadResult = { defs: [], notes: [], errors: [], locs: {}, rules: {} };
  if (hasProtoKey(doc)) return { ...res, errors: [{ message: "the document contains a '__proto__' member or nests deeper than 40" }] };
  if (!isObj(doc)) return { ...res, errors: [{ message: 'the document must be an object' }] };
  let entries: unknown[];
  let since: string | undefined;
  if (doc.kind === ACTION_DEF_KIND) entries = [doc];
  else {
    for (const k of Object.keys(doc)) if (!FILE_KEYS.has(k)) return { ...res, errors: [{ message: `unknown top-level member '${k}' (expected ns, since, actions)` }] };
    if (typeof doc.ns !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/.test(doc.ns)) return { ...res, errors: [{ message: 'ns must be a lowercase identifier' }] };
    res.ns = doc.ns;
    if (typeof doc.since === 'string') since = doc.since;
    else if (doc.since !== undefined) return { ...res, errors: [{ message: 'since must be a string' }] };
    if (!Array.isArray(doc.actions)) return { ...res, errors: [{ message: 'actions must be a list' }] };
    entries = doc.actions;
  }
  entries.forEach((e, index) => {
    const verb = isObj(e) && typeof e.verb === 'string' ? e.verb : undefined;
    try {
      // `rules` is the action's business rules block: validated against the def, kept out of the def (and its digest)
      let rules: unknown;
      let entry = e;
      if (isObj(e) && Object.prototype.hasOwnProperty.call(e, 'rules')) {
        const { rules: r, ...rest } = e;
        rules = r;
        entry = rest;
      }
      const { def, notes } = expandAction(entry, { ...(since !== undefined ? { since } : {}) });
      const bad = validateDef(def);
      if (bad) { res.errors.push({ index, ...(verb ? { verb } : {}), message: bad }); return; }
      if (rules !== undefined) {
        const re = businessRulesError(def, rules);
        if (re) { res.errors.push({ index, ...(verb ? { verb } : {}), message: re }); return; }
        res.rules[def.verb] = rules as BusinessRules;
      }
      res.defs.push(def);
      res.notes.push(...notes);
    } catch (err) {
      res.errors.push({ index, ...(verb ? { verb } : {}), message: err instanceof ActionKitError ? err.message : `malformed action: ${(err as Error).message}` });
    }
  });
  return res;
}

/**
 * Load an authoring file. YAML is parsed as YAML 1.2 core: no aliases, no merge keys, unique keys, no unknown tags, no
 * warnings; JSON is parsed as JSON. Input above {@link MAX_AUTHOR_BYTES} is refused. Never throws.
 */
export function loadActionsText(text: string, format: 'yaml' | 'json' = 'yaml'): LoadResult {
  const fail = (message: string): LoadResult => ({ defs: [], notes: [], errors: [{ message, line: 1, column: 1 }], locs: {}, rules: {} });
  if (new TextEncoder().encode(text).length > MAX_AUTHOR_BYTES) return fail(`the file is larger than ${MAX_AUTHOR_BYTES} bytes`);
  let value: unknown;
  let positions: Positions | null = null;
  const lc = new LineCounter();
  if (format === 'json') {
    try { value = JSON.parse(text); } catch (e) { return fail(`not JSON: ${(e as Error).message}`); }
    // JSON is YAML: only the positions are taken from this parse, the value from JSON.parse
    try { positions = positionsOf(parseDocument(text, { version: '1.2', schema: 'core', lineCounter: lc, prettyErrors: false }), lc); } catch { positions = null; }
  } else {
    const doc = parseDocument(text, { version: '1.2', schema: 'core', uniqueKeys: true, merge: false, strict: true, prettyErrors: false, lineCounter: lc });
    if (doc.errors.length > 0) { const r = fail(`not YAML: ${doc.errors[0]!.message}`); const l = doc.errors[0]!.linePos?.[0]; if (l) { r.errors[0]!.line = l.line; r.errors[0]!.column = l.col; } return r; }
    if (doc.warnings.length > 0) return fail(`YAML warning: ${doc.warnings[0]!.message}`);
    try { value = doc.toJS({ maxAliasCount: 0 }); } catch (e) { return fail(`not YAML: ${(e as Error).message}`); }
    positions = positionsOf(doc, lc);
  }
  const res = loadActionsValue(value);
  if (positions !== null) attachPositions(res, positions);
  return res;
}

/** Per-entry positions of a parsed document (`actions` items and their `params` keys), by entry index. */
type Positions = { item: Loc; params: Record<string, Loc> }[];

function positionsOf(doc: Document, lc: LineCounter): Positions | null {
  try {
    const root = doc.contents;
    const at = (offset: number): Loc => { const p = lc.linePos(offset); return { line: p.line, column: p.col }; };
    if (!isMap(root)) return null;
    const actions = root.get('actions', true);
    const items = isSeq(actions) ? actions.items : [root];
    return items.map((it) => {
      const node = it as { range?: [number, number, number] | null; get?: (k: string, keep: boolean) => unknown };
      const params: Record<string, Loc> = {};
      const pm = isMap(it) ? it.get('params', true) : undefined;
      if (isMap(pm)) for (const pair of pm.items) { const k = pair.key as { range?: [number, number, number] | null; value?: unknown }; if (k?.range) params[String(k.value ?? '')] = at(k.range[0]); }
      return { item: node.range ? at(node.range[0]) : { line: 1, column: 1 }, params };
    });
  } catch {
    return null;
  }
}

function attachPositions(res: LoadResult, pos: Positions): void {
  // entries are processed in order: defs and errors carry their entry index only for errors, so map defs by their entry order
  const order: number[] = [];
  const failed = new Set(res.errors.filter((e) => e.index !== undefined).map((e) => e.index!));
  for (let i = 0; i < pos.length; i++) if (!failed.has(i)) order.push(i);
  res.defs.forEach((d, k) => { const p = pos[order[k] ?? -1]; if (p) res.locs[d.verb] = { ...p.item, params: p.params }; });
  for (const e of res.errors) { const p = e.index !== undefined ? pos[e.index] : undefined; if (p) { e.line = p.item.line; e.column = p.item.column; } else if (e.index === undefined) { e.line = 1; e.column = 1; } }
}

// ---- the TypeScript builder --------------------------------------------------------------------------------------------------

type Extra = Partial<ParamDef>;
const withExtra = (p: ParamDef, x?: Extra): ParamDef => (x ? { ...p, ...x } : p);

/** Typed param constructors; each returns the same ParamDef the matching YAML shorthand expands to. */
export const p = {
  email: (x?: Extra): ParamDef => withExtra(parseParamShorthand('email'), x),
  phone: (x?: Extra): ParamDef => withExtra(parseParamShorthand('phone'), x),
  url: (x?: Extra): ParamDef => withExtra(parseParamShorthand('url'), x),
  uuid: (x?: Extra): ParamDef => withExtra(parseParamShorthand('uuid'), x),
  ccy: (x?: Extra): ParamDef => withExtra(parseParamShorthand('ccy'), x),
  country: (x?: Extra): ParamDef => withExtra(parseParamShorthand('country'), x),
  secret: (x?: Extra): ParamDef => withExtra(parseParamShorthand('secret'), x),
  bool: (x?: Extra): ParamDef => withExtra(parseParamShorthand('bool'), x),
  date: (x?: Extra): ParamDef => withExtra(parseParamShorthand('date'), x),
  datetime: (x?: Extra): ParamDef => withExtra(parseParamShorthand('datetime'), x),
  duration: (maxMs?: number, x?: Extra): ParamDef => withExtra(parseParamShorthand(maxMs === undefined ? 'duration' : `duration(${maxMs})`), x),
  message: (maxLen?: number, x?: Extra): ParamDef => withExtra(parseParamShorthand(maxLen === undefined ? 'message' : `message(${maxLen})`), x),
  text: (maxLen?: number, x?: Extra): ParamDef => withExtra(parseParamShorthand(maxLen === undefined ? 'text' : `text(${maxLen})`), x),
  int: (min?: number, max?: number, x?: Extra): ParamDef => withExtra(parseParamShorthand(min === undefined || max === undefined ? 'int' : `int(${min}..${max})`), x),
  count: (max?: number, x?: Extra): ParamDef => withExtra(parseParamShorthand(max === undefined ? 'count' : `count(${max})`), x),
  /** `ccy` is a literal ISO code, or `{from: 'param'}` naming the currency param. */
  money: (ccy: string | { from: string }, o: { max?: number; min?: number; exp?: number } = {}, x?: Extra): ParamDef =>
    withExtra(parseParamShorthand(`money(${typeof ccy === 'string' ? ccy : `@${ccy.from}`}${o.max !== undefined ? `, max=${o.max}` : ''}${o.min !== undefined ? `, min=${o.min}` : ''}${o.exp !== undefined ? `, exp=${o.exp}` : ''})`), x),
  id: (type: string, x?: Extra): ParamDef => withExtra(parseParamShorthand(`id:${type}`), x),
  enum: (values: readonly string[], x?: Extra): ParamDef => withExtra(parseParamShorthand(`enum(${values.join('|')})`), x),
  set: (values: readonly string[], x?: Extra): ParamDef => withExtra(parseParamShorthand(`set(${values.join('|')})`), x),
  array: (items: 'string' | 'integer', max?: number, x?: Extra): ParamDef => withExtra(parseParamShorthand(max === undefined ? `array(${items})` : `array(${items}, max=${max})`), x),
  optional: (d: ParamDef): ParamDef => ({ ...d, required: false }),
};

export interface ActionSpec {
  title?: string;
  description?: string;
  aliases?: string[];
  effects: Effect | Effect[];
  /** Shorthand string (`acme.invoice:inv_*`) or the full resource object. */
  resource: string | { type: string; id: IdPattern; scope: ResourceScope };
  params?: Record<string, string | ParamDef>;
  reversibility?: ActionDef['reversibility'];
  blast?: BlastRadius | { radius: BlastRadius; ppm?: number };
  side_effects?: ActionDef['side_effects'];
  idempotency?: 'key_param' | 'natural' | 'none' | NonNullable<ActionDef['idempotency']>;
  context?: string[];
  traits?: TraitId[];
  audience?: 'resource';
  compensates?: string;
  bindings?: ActionDef['bindings'];
  examples?: ActionDef['examples'];
  review?: ActionDef['review'];
  source?: ActionDef['source'];
  since?: string;
}

/**
 * `action('acme.invoice.send', {effects: ['send'], resource: 'acme.invoice:inv_*', params: {...}})`: the typed constructor over
 * the JSON form. Same expansion as the YAML loader (so the same digest); throws {@link ActionKitError} on a malformed spec.
 */
export function action(verb: string, spec: ActionSpec): ActionDef {
  const { def } = expandAction({ verb, ...spec });
  const bad = validateDef(def);
  if (bad) throw new ActionKitError('bad_action', `${verb}: ${bad}`);
  return def;
}
