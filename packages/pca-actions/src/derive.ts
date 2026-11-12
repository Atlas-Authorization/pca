// derive.ts - everything an ActionDef yields (spec section 2.4): the signed schema verb (v2) and document, the operation
// binding, risk inputs, policy predicates, Goal IR ontology terms, the policy card, the escalation tier and MCP
// annotations. Every function is pure and deterministic; none is hand-written by the integrator.

import type { ActionParamDecl, ActionSchema, ActionVerbDecl, SchemaConfirmation, SchemaFloors, UnsignedActionSchema } from '@atlasauth/pca/ext/intent';
import {
  ActionKitError, MAX_PARAM_PATH_DEPTH, isReadOnly,
  type ActionDef, type DefParamType, type NormalizedDef, type ParamDef, type ParamName, type Rev, type TraitId,
} from './def';
import { defDigest, traitsDigest } from './digest';
import { effective, impliedFromFacts, type Effective, type ReviewOpts } from './effective';
import { idMatches } from './idpattern';
import { normalize, worstReversibility } from './normalize';
import { CORE_REGISTRY } from './core-traits';
import { verbConfirmationError, type ReviewerPins } from './confirmation';
import { CORE_NAMESPACE, ESC_TIERS, RISK_NAMES, closure, extendRegistry, floorOf, leq, topTraits, type Profile, type Registry, type TraitDef } from './traits';

// ---- flattened params ------------------------------------------------------------------------------------------------------

/**
 * The flattened form a v2 schema is checked against: nested plain objects become dotted keys (up to
 * {@link MAX_PARAM_PATH_DEPTH} segments); arrays and scalars are leaves. A deeper object stays a leaf (and then fails
 * conformance as an undeclared or mistyped parameter).
 */
export function flattenParams(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const walk = (prefix: string, depth: number, v: unknown): void => {
    const plain = v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
    if (plain && depth < MAX_PARAM_PATH_DEPTH && Object.keys(v as object).length > 0) {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) walk(prefix === '' ? k : `${prefix}.${k}`, depth + 1, x);
    } else out[prefix] = v;
  };
  for (const [k, v] of Object.entries(params)) walk(k, 1, v);
  return out;
}

/** The unique param carrying `role`, or throws `no_param`/`ambiguous_param` (a grant compiler drops such a verb and reports it). */
export function paramByRole(d: Pick<ActionDef, 'params' | 'verb'>, role: string): ParamName {
  const hits = Object.keys(d.params).filter((n) => d.params[n]!.role === role).sort();
  if (hits.length === 0) throw new ActionKitError('no_param', `'${d.verb}' has no parameter with role ${role}`);
  if (hits.length > 1) throw new ActionKitError('ambiguous_param', `'${d.verb}' has several parameters with role ${role}`);
  return hits[0]!;
}

// ---- effect class (the ONE adapter to the Goal IR's 4 classes) ----------------------------------------------------------------

export type EffectClass = 'read' | 'reversible' | 'external_send' | 'irreversible';

/** read if effects = {read}; external_send if effects meet {send, publish, export} and not irreversible; irreversible if so declared; else reversible. */
export function effectClass(d: ActionDef): EffectClass {
  const n = normalize(d);
  if (isReadOnly(n.effects)) return 'read';
  const rev = worstReversibility(n.reversibility, n.params);
  if (rev === 'irreversible') return 'irreversible';
  if (n.effects.some((e) => e === 'send' || e === 'publish' || e === 'export')) return 'external_send';
  return 'reversible';
}

// ---- signed schema (v2) ------------------------------------------------------------------------------------------------------

const unitId = (p: ParamDef): string | undefined => {
  const u = p.unit;
  if (u === undefined) return undefined;
  if (u.kind !== 'money') return u.kind;
  return typeof u.ccy === 'string' ? `money.${u.ccy.toLowerCase()}` : undefined;
};

type SchemaUnit = NonNullable<ActionSchema['units']>[string];
const unitDecl = (p: ParamDef): SchemaUnit | undefined => {
  const u = p.unit;
  if (u === undefined) return undefined;
  if (u.kind !== 'money') return { kind: u.kind };
  return typeof u.ccy === 'string' ? { kind: 'money', currency: u.ccy, exponent: u.exp } : undefined;
};

function toParamDecl(n: NormalizedDef['params'][string]): ActionParamDecl {
  const d: ActionParamDecl = {
    type: n.type,
    semantic: n.role ?? `generic.${n.type}`,
    sensitivity: n.sensitivity,
  };
  if (!n.required) d.required = false;
  if (n.values !== undefined) d.values = [...n.values];
  for (const k of ['min', 'max', 'max_len', 'items', 'min_items', 'max_items', 'format', 'provenance_min', 'default', 'principal_neutral_default', 'description'] as const) {
    if (n[k] !== undefined) (d as unknown as Record<string, unknown>)[k] = n[k];
  }
  const uid = unitId(n);
  if (uid !== undefined) d.unit = uid;
  if (n.accumulates !== undefined) d.accumulates_into = [...n.accumulates];
  if (n.role !== undefined) d.role = n.role;
  if (n.tags !== undefined) d.tags = [...n.tags];
  return d;
}

export interface SchemaVerbOut {
  verb: ActionVerbDecl;
  /** Unit entries this verb needs in the document's `units`. */
  units: Record<string, SchemaUnit>;
}

/** The signed v2 verb declaration of a def: normative effects, traits, def digest and materialized floors. */
export function toSchemaVerb(d: ActionDef, reg: Registry, opts: ReviewOpts = {}): SchemaVerbOut {
  const n = normalize(d);
  const eff = effective(d, reg, opts);
  const params: Record<string, ActionParamDecl> = {};
  const units: Record<string, SchemaUnit> = {};
  for (const name of Object.keys(n.params)) {
    const p = n.params[name]!;
    params[`action.params.${name}`] = toParamDecl(p);
    const id = unitId(p);
    if (id !== undefined) units[id] = unitDecl(p)!;
  }
  const v: ActionVerbDecl = {
    verb: n.verb,
    kind: isReadOnly(n.effects) ? 'read' : 'write',
    params,
    effects: [...n.effects],
    traits: eff.traits,
    def: defDigest(d),
    floors: eff.eff as SchemaFloors,
  };
  // the proof that the traits above are a human's decision; without it a verifier treats the verb as unconfirmed (top)
  if (eff.confirmed && d.review.attestation?.sig !== undefined) v.confirmation = d.review.attestation as SchemaConfirmation;
  if (typeof n.reversibility === 'string') v.reversibility = n.reversibility;
  else v.reversibility_by = { param: `action.params.${n.reversibility.by}`, map: { ...n.reversibility.map }, ...(n.reversibility.default !== undefined ? { default: n.reversibility.default } : {}) };
  if (n.bindings.mcp) v.mcp = { tool: n.bindings.mcp.tool };
  if (n.bindings.openapi) v.openapi = { operationId: n.bindings.openapi.operationId };
  if (n.description !== undefined) v.description = n.description;
  return { verb: v, units };
}

export interface SchemaMeta {
  site: string;
  aud: string;
  version: string;
  pack?: { ns: string; version: string; root: string };
}

/** The unsigned v2 schema document of a set of defs (verbs sorted by name; units merged, a conflicting redefinition refused). */
export function toSchemaDoc(defs: readonly ActionDef[], reg: Registry, meta: SchemaMeta, opts: ReviewOpts = {}): UnsignedActionSchema {
  const verbs: ActionVerbDecl[] = [];
  const units: Record<string, SchemaUnit> = {};
  const seen = new Set<string>();
  for (const d of [...defs].sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0))) {
    if (seen.has(d.verb)) throw new ActionKitError('duplicate_verb', `verb '${d.verb}' appears twice`);
    seen.add(d.verb);
    const o = toSchemaVerb(d, reg, opts);
    verbs.push(o.verb);
    for (const [id, u] of Object.entries(o.units)) {
      const prev = units[id];
      if (prev !== undefined && (prev.kind !== u.kind || prev.currency !== u.currency || prev.exponent !== u.exponent)) {
        throw new ActionKitError('unit_conflict', `unit '${id}' is declared with two different definitions`);
      }
      units[id] = u;
    }
  }
  const custom = [...reg.traits.values()].filter((t) => !t.id.startsWith(CORE_NAMESPACE)).sort((a, b) => (a.id < b.id ? -1 : 1));
  const doc: UnsignedActionSchema = {
    v: 2,
    kind: 'pca-action-schema',
    site: meta.site,
    aud: meta.aud,
    version: meta.version,
    ...(Object.keys(units).length > 0 ? { units } : {}),
    verbs,
    traits_digest: traitsDigest(reg),
    ...(custom.length > 0 ? { trait_defs: custom as unknown[] } : {}),
    ...(meta.pack !== undefined ? { pack: meta.pack } : {}),
  };
  return doc;
}

/**
 * Rule 22's integrity half: recompute from the verb's own visible facts that its carried `traits` contain every implied
 * trait and that its `floors` are at least the floor of the carried traits' closure (and of its declared reversibility).
 * Null = consistent; else the reason (`schema_traits_forged` / `schema_floor_forged` / `unknown_trait`). Never throws.
 */
export function schemaVerbFloorError(v: ActionVerbDecl, reg: Registry, reviewers?: ReviewerPins): string | null {
  try {
    if (!Array.isArray(v.effects) || !Array.isArray(v.traits) || v.floors === undefined) return 'schema_floor_forged: not a v2 verb';
    const params = Object.entries(v.params).map(([path, p]) => ({ name: path.slice('action.params.'.length), p }));
    const byName: Record<string, ParamDef> = {};
    for (const { name, p } of params) byName[name] = { type: p.type as DefParamType, ...(p.values !== undefined ? { values: p.values } : {}) } as ParamDef;
    const decl = v.reversibility_by
      ? { by: v.reversibility_by.param.slice('action.params.'.length), map: v.reversibility_by.map, default: v.reversibility_by.default }
      : (v.reversibility ?? (v.kind === 'read' ? 'reversible' : 'irreversible'));
    const worstRev: Rev = worstReversibility(decl as never, byName);
    const implied = impliedFromFacts({
      effects: v.effects as never,
      worstRev,
      params: params.map(({ p }) => ({ type: p.type, role: p.role, tags: p.tags, max_items: p.max_items })),
    });
    for (const t of implied) if (!v.traits.includes(t)) return `schema_traits_forged: missing implied trait ${t}`;
    // unconfirmed means maximally dangerous: no valid signed confirmation => the verb must carry EVERY trait of the registry
    if (verbConfirmationError(v as unknown as Parameters<typeof verbConfirmationError>[0], reg, reviewers) !== null) {
      for (const t of topTraits(reg)) if (!v.traits.includes(t)) return `schema_traits_forged: unconfirmed action must carry every trait (missing ${t})`;
    }
    const floor = floorOf(reg, v.traits);
    if (!leq(floor, v.floors as Profile)) return 'schema_floor_forged: floors are below the floor of the carried traits';
    const revRank = ['reversible', 'rate_limited', 'irreversible'];
    if (revRank.indexOf(v.floors.rev) < revRank.indexOf(worstRev)) return 'schema_floor_forged: floors.rev is below the declared reversibility';
    return null;
  } catch (e) {
    return `${(e as ActionKitError).code ?? 'schema_floor_forged'}: ${(e as Error).message}`;
  }
}

/**
 * The trait registry a v2 schema document was built against: the embedded core traits plus the document's own `trait_defs`
 * (checked: custom traits extend what they imply, never use `pca.`), and, when the document carries `traits_digest`, the
 * registry must hash to it. Throws {@link ActionKitError} (`bad_registry` / `traits_digest_mismatch`).
 */
export function registryOfSchema(doc: Pick<ActionSchema, 'trait_defs' | 'traits_digest'>): Registry {
  const reg = doc.trait_defs && doc.trait_defs.length > 0 ? extendRegistry(CORE_REGISTRY, doc.trait_defs as TraitDef[]) : CORE_REGISTRY;
  if (doc.traits_digest !== undefined && doc.traits_digest !== traitsDigest(reg)) throw new ActionKitError('traits_digest_mismatch', 'the document\'s traits_digest does not match its trait registry');
  return reg;
}

/** Rule 22's integrity half for a whole v2 document: its registry loads and every verb's traits and floors are consistent. Null = consistent. */
export function schemaFloorError(doc: Pick<ActionSchema, 'trait_defs' | 'traits_digest' | 'verbs'>, reviewers?: ReviewerPins): string | null {
  try {
    const reg = registryOfSchema(doc);
    for (const v of doc.verbs) {
      const e = schemaVerbFloorError(v, reg, reviewers);
      if (e) return `${v.verb}: ${e}`;
    }
    return null;
  } catch (e) {
    return `${(e as ActionKitError).code ?? 'bad_registry'}: ${(e as Error).message}`;
  }
}

// ---- operation binding ---------------------------------------------------------------------------------------------------------

export interface OperationOut {
  verb: string;
  resource: string;
  params: Record<string, unknown>;
}
export type OperationResult = { ok: true; op: OperationOut } | { ok: false; reason: string };

/**
 * The PcaOperation of a call to this def: the verb, the resource `<type>:<id>` (from the param carrying `id.<type>`, the
 * pattern's exact id, or `<type>:*` for a tenant/global/set resource) and the declared params, flattened. Refuses (never
 * guesses) when the id is missing or does not match the resource pattern.
 */
export function operationOf(d: ActionDef, call: { params: Record<string, unknown> }): OperationResult {
  const flat = flattenParams(call.params);
  const declared = Object.keys(d.params);
  const params: Record<string, unknown> = {};
  for (const k of declared.sort()) if (Object.prototype.hasOwnProperty.call(flat, k)) params[k] = flat[k];
  const { type, id, scope } = d.resource;
  let resource: string;
  if (id !== '*' && 'exact' in id) resource = `${type}:${id.exact}`;
  else {
    const idParam = declared.find((n) => d.params[n]!.role === `id.${type}`);
    const val = idParam !== undefined ? params[idParam] : undefined;
    if (typeof val === 'string') {
      if (!idMatches(id, val)) return { ok: false, reason: `the id '${val}' does not match the resource pattern of ${d.verb}` };
      resource = `${type}:${val}`;
    } else if (scope !== 'one') resource = `${type}:*`;
    else return { ok: false, reason: `${d.verb} needs a parameter with role id.${type} to name its resource` };
  }
  return { ok: true, op: { verb: d.verb, resource, params } };
}

// ---- risk -----------------------------------------------------------------------------------------------------------------------

/** Reversibility score per effective class (1 = fully reversible), the scale the hosted adjudicator and catalogRisk use. */
export const REVERSIBILITY_SCORE: Readonly<Record<Rev, number>> = Object.freeze({ reversible: 1, rate_limited: 0.4, irreversible: 0 });

export interface RiskOut {
  reversibility: number;
  blastRadius: number;
  confidence: 1;
  taint?: number;
}
const unit01 = (x: number): number => Math.min(1, Math.max(0, x));

/**
 * Risk inputs for a call: reversibility score from the effective class, blast from the effective ppm, and for a def with a
 * `money.amount` parameter the blast `amount / kappa` from the verified amount and the grant's signed kappa (missing,
 * invalid or no kappa: 1, the worst case). Reads nothing the agent claims. Replaces `catalogRisk` and `toolCallRisk(amountField)`.
 */
export function riskOf(d: ActionDef, eff: Effective, params: Record<string, unknown> | undefined, opts: { kappa?: number; taint?: number } = {}): RiskOut {
  let blast = unit01(eff.eff.blast_ppm / 1_000_000);
  const moneyParam = Object.keys(d.params).filter((n) => d.params[n]!.role === 'money.amount').sort()[0];
  if (moneyParam !== undefined) {
    const flat = params ? flattenParams(params) : {};
    const amount = Object.prototype.hasOwnProperty.call(flat, moneyParam) ? flat[moneyParam] : undefined;
    blast = typeof amount === 'number' && Number.isFinite(amount) && amount >= 0 && typeof opts.kappa === 'number' && opts.kappa > 0 ? unit01(amount / opts.kappa) : 1;
  }
  const out: RiskOut = { reversibility: REVERSIBILITY_SCORE[eff.eff.rev], blastRadius: blast, confidence: 1 };
  if (typeof opts.taint === 'number' && Number.isFinite(opts.taint)) out.taint = unit01(opts.taint);
  return out;
}

// ---- predicates ----------------------------------------------------------------------------------------------------------------

export interface PredicateOut {
  verb: string;
  resource: string;
  where?: { field: string; op: 'lte' | 'gte'; value: number }[];
}

/** The resource matcher of a def's pattern (`<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`). */
export function resourceMatcher(d: Pick<ActionDef, 'resource'>): string {
  const { type, id } = d.resource;
  if (id === '*') return `${type}:*`;
  return 'exact' in id ? `${type}:${id.exact}` : `${type}:${id.prefix}*`;
}

/**
 * The policy predicate scaffold: the verb, its resource matcher, and for `limits.max_amount` a hard per-call ceiling
 * `amount <= max` plus `gte 0` on the `money.amount` parameter. A money limit on a def with no money.amount parameter throws
 * (the limit could not be enforced; never silently unbounded).
 */
export function predicatesOf(d: ActionDef, limits: { max_amount?: number } = {}): PredicateOut {
  const out: PredicateOut = { verb: d.verb, resource: resourceMatcher(d) };
  if (limits.max_amount !== undefined) {
    if (!Number.isSafeInteger(limits.max_amount) || limits.max_amount < 0) throw new ActionKitError('bad_limit', 'max_amount must be a non-negative safe integer');
    const name = paramByRole(d, 'money.amount');
    out.where = [
      { field: `action.params.${name}`, op: 'lte', value: limits.max_amount },
      { field: `action.params.${name}`, op: 'gte', value: 0 },
    ];
  }
  return out;
}

// ---- Goal IR ontology terms -----------------------------------------------------------------------------------------------------

export interface OntParamOut { kind: 'money' | 'count' | 'duration' | 'instant' | 'bytes' | 'ratio' | 'id' | 'enum' | 'text'; ccys?: string[]; values?: string[]; of?: string }
export interface OntVerbOut { id: string; effect: EffectClass; resource_type: string; params: Record<string, OntParamOut> }
export interface OntologyOut {
  types: { id: string; id_prefix: string }[];
  units: Record<string, { kind: 'money' | 'count' | 'duration' | 'bytes' | 'ratio' | 'instant'; exponent?: number }>;
  verbs: OntVerbOut[];
  /** synonym -> canonical verb id (total, from the defs' aliases). */
  aliases: Record<string, string>;
  /** verb -> the trait ids carried (declared + implied). */
  traits: Record<string, TraitId[]>;
}

function ontParam(d: ActionDef, name: string, p: ParamDef): OntParamOut {
  const u = p.unit;
  if (u !== undefined) {
    if (u.kind === 'money') {
      const c = u.ccy;
      if (typeof c === 'string') return { kind: 'money', ccys: [c] };
      const cp = d.params[c.from];
      return { kind: 'money', ccys: cp?.values ? [...cp.values].sort() : [] };
    }
    return { kind: u.kind === 'duration' ? 'duration' : u.kind === 'bytes' ? 'bytes' : u.kind === 'ratio' ? 'ratio' : 'count' };
  }
  void name;
  if (p.role !== undefined && p.role.startsWith('id.')) return { kind: 'id', of: p.role.slice(3) };
  if (p.format !== undefined && p.format.startsWith('id:')) return { kind: 'id', of: p.format.slice(3) };
  switch (p.type) {
    case 'duration': return { kind: 'duration' };
    case 'datetime': case 'date': return { kind: 'instant' };
    case 'integer': return { kind: 'count' };
    case 'boolean': return { kind: 'enum', values: ['false', 'true'] };
    case 'set': return { kind: 'enum', values: [...(p.values ?? [])].sort() };
    case 'string': return p.values ? { kind: 'enum', values: [...p.values].sort() } : { kind: 'text' };
    default: return { kind: 'text' };
  }
}

/** Ontology terms for a set of defs. `effect` is DERIVED ({@link effectClass}); there is no override by design. */
export function toOntology(defs: readonly ActionDef[], reg: Registry, opts: ReviewOpts = {}): OntologyOut {
  const types = new Map<string, string>();
  const units: OntologyOut['units'] = {};
  const verbs: OntVerbOut[] = [];
  const aliases: Record<string, string> = {};
  const traits: Record<string, TraitId[]> = {};
  for (const d of [...defs].sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0))) {
    const prefix = d.resource.id === '*' || 'exact' in d.resource.id ? '' : d.resource.id.prefix;
    if (!types.has(d.resource.type)) types.set(d.resource.type, prefix);
    const params: Record<string, OntParamOut> = {};
    for (const name of Object.keys(d.params).sort()) {
      params[name] = ontParam(d, name, d.params[name]!);
      const u = d.params[name]!.unit;
      if (u?.kind === 'money' && typeof u.ccy === 'string') units[u.ccy] = { kind: 'money', exponent: u.exp };
      else if (u !== undefined && u.kind !== 'money') units[u.kind] = { kind: u.kind };
    }
    verbs.push({ id: d.verb, effect: effectClass(d), resource_type: d.resource.type, params });
    for (const a of d.aliases ?? []) {
      if (Object.prototype.hasOwnProperty.call(aliases, a) && aliases[a] !== d.verb) throw new ActionKitError('alias_collision', `alias '${a}' names two verbs`);
      aliases[a] = d.verb;
    }
    traits[d.verb] = effective(d, reg, opts).traits;
  }
  return { types: [...types].map(([id, id_prefix]) => ({ id, id_prefix })), units, verbs, aliases, traits };
}

// ---- policy card + escalation + MCP annotations ---------------------------------------------------------------------------------

export interface CardOut {
  verb: string;
  title: string;
  /** Deterministic text, e.g. "Send an invoice. This action sends to people outside your organisation and cannot be undone." */
  text: string;
  risk: (typeof RISK_NAMES)[number];
  escalation: (typeof ESC_TIERS)[number];
  reversibility: Rev;
  blast_ppm: number;
  /** Caveat kinds a grant must carry before this action is auto-allowed. */
  needs: string[];
  /** Context a call must carry. */
  context: string[];
}

const sentence = (s: string): string => (/[.!?]$/.test(s) ? s : `${s}.`);
const list = (xs: string[]): string => (xs.length <= 1 ? (xs[0] ?? '') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);

/** The policy card of a def: deterministic text from its title and the phrases of its trait closure (riskiest first). */
export function cardOf(d: ActionDef, eff: Effective, reg: Registry): CardOut {
  const ids = closure(reg, eff.traits);
  const ordered = ids
    .map((id) => reg.traits.get(id)!)
    .sort((a, b) => b.floor.risk - a.floor.risk || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const phrases = [...new Set(ordered.map((t) => t.card_phrase))];
  const e = eff.eff;
  const text = [
    sentence(d.title),
    eff.confirmed
      ? phrases.length > 0 ? `This action ${list(phrases)}.` : 'This action only reads.'
      : `This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it ${list(phrases)}.`,
  ].join(' ');
  return { verb: d.verb, title: d.title, text, risk: RISK_NAMES[e.risk]!, escalation: ESC_TIERS[e.esc]!, reversibility: e.rev, blast_ppm: e.blast_ppm, needs: [...e.caveats], context: [...e.context] };
}

/** The minimum escalation tier of the effective profile (0 auto, 1 confirm, 2 cosign, 3 stepup). */
export const escalationOf = (eff: Effective): { tier: number; name: (typeof ESC_TIERS)[number] } => ({ tier: eff.eff.esc, name: ESC_TIERS[eff.eff.esc]! });

export interface McpAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}
/** Advisory MCP tool annotations (read-only / destructive / idempotent / open-world). */
export function mcpAnnotationsOf(d: ActionDef, eff: Effective): McpAnnotations {
  const cl = new Set(eff.closure);
  const idem = d.idempotency?.mode ?? 'none';
  return {
    // an unreviewed def's own claim of safety is never advertised
    readOnlyHint: eff.confirmed && isReadOnly(d.effects),
    destructiveHint: cl.has('pca.destructive'),
    idempotentHint: eff.confirmed && (idem !== 'none' || isReadOnly(d.effects)),
    openWorldHint: cl.has('pca.network_egress') || cl.has('pca.external_communication'),
  };
}
