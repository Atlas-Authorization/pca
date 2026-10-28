import { b64u, canonicalBytesStrict, compareUtf8, decodeB64uStrict, hasLoneSurrogate, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { type PqPinPolicy, type SignerSuiteOpts, type SigAlg, resolveSigAlg, signSuiteArtifact, suiteKeysOf, suitePqPublicKey, verifyPinnedSuite } from './pq';
import { RESERVED_NAMES, ownGet, ownHas, suiteCapabilityError } from './intent-strict';

const suiteErr = (alg: unknown) => suiteCapabilityError(alg, (a) => resolveSigAlg(a) !== null);

/**
 * SIGNED ACTION SCHEMAS (PCA Intent Layer v2, milestone V1; docs/specs/pca-intent-layer-v2.md §2.3, §3.2, §4.1 M2, §8).
 * NORMATIVE for the `schema` check (conformance rule 14): the TypeScript reference, the 9 native verifiers and the zkVM
 * guest implement exactly the rules below; the `schema-*` conformance vectors pin them.
 *
 * A site publishes `/.well-known/pca-actions.json` (referenced from its discovery document, `intent.actions_uri`): for
 * every verb it declares the FULL parameter list P_v with a type, a domain, a semantic type and a sensitivity
 * (free < material < critical). Whatever the schema does not declare is the fail-closed cell ⊠_v: an action that names
 * an undeclared verb, carries an undeclared parameter, misses a required one, or has a value of the wrong type or
 * outside its declared domain is a terminal deny (`schema_violation`), never a question (closed world, T12).
 *
 * DOCUMENT (`kind: "pca-action-schema"`, `v: 1`), closed member set: `v, kind, site, aud, version, units?, state?,
 * verbs, sig`. Signed under {@link ACTION_SCHEMA_DOMAIN} over `strictCanonical(doc without sig)` by a key the site lists
 * in its discovery document (`intent.schema_keys[]: {kid, alg, pk, pq_pk?}`); the suite comes from the KEY ENTRY (the
 * pinned configuration), never from the document, so it cannot be downgraded. Content address:
 * `actionSchemaDigest(doc) = b64u(sha256(strictCanonical({d: "atlas-pca/action-schema-ref/v1", s: doc})))` over the
 * whole signed document (the PCActn signs it as `intent_session.schema`).
 *
 * CLOSED-WORLD CONFORMANCE (`conformAction`): see the function for the exact, ordered rule list.
 *
 * VERSION 2 (action kit, docs/pca/specs/action-kit.md section 2.4 / 10): `v: 2` is the same document plus normative verb
 * members `effects` (a string list, replacing the reserved object of v1), `traits` (trait ids), `def` (the ActionDef
 * digest) and `floors` (the materialized effective restriction profile); the document may carry `traits_digest`,
 * `trait_defs` (custom traits) and `pack` (the pack the verbs come from). Parameters of a v2 verb may be named by a dotted
 * path of up to three segments (the caller presents the flattened form) and may carry `role`, `format`, `tags` and
 * `provenance_min`; three more types exist (`datetime`, `duration`, `object_ref`). A `v: 1` document is validated exactly
 * as before (these members are unknown members there). The semantic checks of the new members (rule 22) live with the
 * trait algebra in `@atlasauth/pca-actions`.
 */

export const ACTION_SCHEMA_DOMAIN = 'atlas-pca/action-schema/v1\0';
export const ACTION_SCHEMA_REF_DOMAIN = 'atlas-pca/action-schema-ref/v1';
export const ACTION_SCHEMA_KIND = 'pca-action-schema';
export const WELL_KNOWN_PCA_ACTIONS_PATH = '/.well-known/pca-actions.json';

export type Sensitivity = 'free' | 'material' | 'critical';
export const SENSITIVITIES: readonly Sensitivity[] = ['free', 'material', 'critical'];
export type SchemaReversibility = 'reversible' | 'rate_limited' | 'irreversible';
export const SCHEMA_REVERSIBILITY: readonly SchemaReversibility[] = ['reversible', 'rate_limited', 'irreversible'];
export type ParamTypeV1 = 'string' | 'integer' | 'boolean' | 'date' | 'set' | 'array';
export type ParamType = ParamTypeV1 | 'datetime' | 'duration' | 'object_ref';
/** The v1 parameter types (a v1 document accepts exactly these). */
export const PARAM_TYPES: readonly ParamTypeV1[] = ['string', 'integer', 'boolean', 'date', 'set', 'array'];
/** The v2 parameter types: the v1 types plus `datetime` (RFC 3339 UTC `...Z`), `duration` (integer milliseconds) and `object_ref` (an id string). */
export const PARAM_TYPES_V2: readonly ParamType[] = [...PARAM_TYPES, 'datetime', 'duration', 'object_ref'];

/** v2 vocabularies (mirrors of the pca-actions tables; a parity test pins them). */
export const SCHEMA_V2_EFFECTS: readonly string[] = ['read', 'create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'];
export const SCHEMA_V2_CAVEATS: readonly string[] = ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'];
export const SCHEMA_V2_PRULES: readonly string[] = ['array_bounded', 'export_bounded', 'id_not_wildcard', 'money_amount_bounded', 'money_has_currency', 'pay_has_idempotency', 'recipient_param_declared', 'secret_not_logged'];
export const SCHEMA_V2_CONTEXT: readonly string[] = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'];
export const SCHEMA_V2_TAGS: readonly string[] = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql'];
export const SCHEMA_V2_PROVENANCE: readonly string[] = ['first_party', 'tool', 'agent'];
/**
 * v2: the signed human confirmation of a verb (a review attestation, see pca-actions). Without a valid one - checked by rule 22
 * against the verifier's pinned reviewer keys - a verb is UNCONFIRMED and must carry every trait of the registry.
 */
export interface SchemaConfirmation {
  def_digest: string;
  traits_digest: string;
  facts_digest: string;
  final_traits: string[];
  dismissed: { trait: string; reason: string }[];
  reviewer_kid: string;
  ts: number;
  sig: string;
}
/** The materialized restriction profile of a v2 verb (`floors`): see the trait algebra in pca-actions. */
export interface SchemaFloors {
  risk: number;
  rev: SchemaReversibility;
  blast_ppm: number;
  esc: number;
  caveats: string[];
  context: string[];
  prules: string[];
}

/** Limits (normative). */
export const MAX_SCHEMA_VERBS = 256;
export const MAX_SCHEMA_PARAMS = 64;
export const MAX_SCHEMA_VALUES = 256;
/** Default `max_len` of a string (and of an `array` item) in UTF-8 bytes. */
export const DEFAULT_MAX_LEN = 1024;
/** Default `max_items` of an `array`. */
export const DEFAULT_MAX_ITEMS = 64;
/** A declared parameter path: `action.params.<name>`, top-level names only. */
export const PARAM_PATH_RE = /^action\.params\.[A-Za-z0-9_]{1,64}$/;
/** v2: `action.params.<name>` where name is up to three dotted segments (the flattened form of a nested body). */
export const PARAM_PATH_RE_V2 = /^action\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$/;
/** An accumulation unit (`accumulates_into` entry, a unit id). */
export const UNIT_ID_RE = /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/;

export interface ActionParamDecl {
  type: ParamType;
  /** Semantic type (`money.amount`, `party.payee`, `place.airport`, ...). Drives the wallet floor. */
  semantic: string;
  sensitivity: Sensitivity;
  /** Default true. */
  required?: boolean;
  /** string: the closed value set (enum); set: REQUIRED, the closed member set. */
  values?: string[];
  /** integer (and `array` of integers): inclusive bounds. */
  min?: number;
  max?: number;
  /** integer: a unit id declared in the document's `units`. */
  unit?: string;
  /** string / array item: max UTF-8 bytes (default {@link DEFAULT_MAX_LEN}). */
  max_len?: number;
  /** array: `"integer"`, or any other name (a named reference type: a string). Default string. */
  items?: string;
  /** set / array: item count bounds. */
  min_items?: number;
  max_items?: number;
  /** Wallet-side (Ω derivation, §3.2 step 3): the default value and whether it is principal-neutral. */
  default?: unknown;
  principal_neutral_default?: boolean;
  /** integer only: the accumulation units this amount feeds (SEL across verbs, §3.1). */
  accumulates_into?: string[];
  /** The site issues this value in its own signed responses (provenance, W-B). */
  issued_by_site?: boolean;
  description?: string;
  /** v2: semantic role (`money.amount`, `party.payee`, ...). Drives the derived sensitivity floor. */
  role?: string;
  /** v2, string / object_ref: a checked format (`email`, `uuid`, `iso_currency`, `id:<type>`, ...). */
  format?: string;
  /** v2: parameter tags (`pii`, `secret`, `free_text_outbound`, ...). */
  tags?: string[];
  /** v2: the least trusted source this value may have. */
  provenance_min?: 'first_party' | 'tool' | 'agent';
}

export interface ReversibilityBy {
  param: string;
  map: Record<string, SchemaReversibility>;
  default?: SchemaReversibility;
}

export interface ActionVerbDecl {
  verb: string;
  kind: 'read' | 'write';
  params: Record<string, ActionParamDecl>;
  reversibility?: SchemaReversibility;
  reversibility_by?: ReversibilityBy;
  mcp?: { tool: string };
  openapi?: { operationId: string };
  /**
   * Reserved extension members: signed with the schema and carried unchanged, checked only for their container type, and
   * NOT read by any verification step (no check enforces what they say). A site must not rely on them for enforcement.
   */
  harm?: Record<string, unknown>;
  world?: unknown[];
  /** v1: reserved object. v2: the normative effect list (sorted, distinct). */
  effects?: Record<string, unknown> | string[];
  returns?: Record<string, unknown>;
  description?: string;
  /** v2: trait ids (declared + implied), sorted and distinct. */
  traits?: string[];
  /** v2: the ActionDef digest this verb was derived from (b64u). */
  def?: string;
  /** v2: the materialized effective profile; a verifier checks it against the floors of `traits` (rule 22). */
  floors?: SchemaFloors;
  /** v2: the signed human confirmation (absent = unconfirmed = maximally dangerous). */
  confirmation?: SchemaConfirmation;
}

export interface ActionSchemaSig {
  /** Must equal the `alg` of the key entry named by `kid`. */
  alg: SigAlg;
  kid: string;
  /** b64u primary signature (Ed25519 for ed25519 / hybrid; the PQ signature for a pure PQ suite). */
  value: string;
  /** b64u PQ half of a hybrid suite. */
  pq_value?: string;
}

export interface ActionSchema {
  v: 1 | 2;
  kind: typeof ACTION_SCHEMA_KIND;
  site: string;
  aud: string;
  version: string;
  units?: Record<string, { kind: string; currency?: string; exponent?: number }>;
  /** Reserved extension member (state variables): signed and carried, checked only to be an array, not read by any check. */
  state?: unknown[];
  verbs: ActionVerbDecl[];
  /** v2: digest of the trait registry the floors were computed against. */
  traits_digest?: string;
  /** v2: custom trait definitions (core traits are embedded in verifiers). */
  trait_defs?: unknown[];
  /** v2: the pack the verbs come from. */
  pack?: { ns: string; version: string; root: string };
  sig: ActionSchemaSig;
}
export type UnsignedActionSchema = Omit<ActionSchema, 'sig'>;

/** A schema signing key as listed in the site's discovery document (`intent.schema_keys[]`). */
export interface ActionSchemaKey {
  kid: string;
  alg: SigAlg;
  /** b64u Ed25519 identity (32 bytes). */
  pk: string;
  /** b64u PQ public key for a non-ed25519 suite (pinned by the discovery entry). */
  pq_pk?: string;
}

const DOC_KEYS = new Set(['v', 'kind', 'site', 'aud', 'version', 'units', 'state', 'verbs', 'sig']);
const DOC_KEYS_V2 = new Set([...DOC_KEYS, 'traits_digest', 'trait_defs', 'pack']);
const VERB_KEYS = new Set(['verb', 'kind', 'params', 'reversibility', 'reversibility_by', 'mcp', 'openapi', 'harm', 'world', 'effects', 'returns', 'description']);
const VERB_KEYS_V2 = new Set([...VERB_KEYS, 'traits', 'def', 'floors', 'confirmation']);
const PARAM_KEYS = new Set([
  'type', 'semantic', 'sensitivity', 'required', 'values', 'min', 'max', 'unit', 'max_len', 'items', 'min_items', 'max_items',
  'default', 'principal_neutral_default', 'accumulates_into', 'issued_by_site', 'description',
]);
const PARAM_KEYS_V2 = new Set([...PARAM_KEYS, 'role', 'format', 'tags', 'provenance_min']);
const SIG_KEYS = new Set(['alg', 'kid', 'value', 'pq_value']);

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const isNonNegInt = (v: unknown): v is number => isInt(v) && v >= 0;
const u8len = (s: string): number => utf8(s).length;
const isStr = (v: unknown, max = 256): v is string => typeof v === 'string' && v.length > 0 && !hasLoneSurrogate(v) && u8len(v) <= max;
const own = (o: object, k: string) => ownHas(o, k);

function paramDeclError(path: string, d: unknown, units: Record<string, unknown> | undefined, v2 = false): string | null {
  if (!(v2 ? PARAM_PATH_RE_V2 : PARAM_PATH_RE).test(path)) return `parameter path '${path}' is not action.params.<name>`;
  if (path.slice('action.params.'.length).split('.').some((seg) => RESERVED_NAMES.has(seg))) return `parameter name '${path}' is reserved (__proto__ / constructor / prototype)`;
  if (!isObj(d)) return `${path}: declaration must be an object`;
  for (const k of Object.keys(d)) if (!(v2 ? PARAM_KEYS_V2 : PARAM_KEYS).has(k)) return `${path}: unknown member '${k}'`;
  if (!((v2 ? PARAM_TYPES_V2 : PARAM_TYPES) as readonly unknown[]).includes(d.type)) return `${path}: unknown type`;
  if (!isStr(d.semantic, 128)) return `${path}: semantic must be a non-empty string`;
  if (!SENSITIVITIES.includes(d.sensitivity as Sensitivity)) return `${path}: unknown sensitivity`;
  if (d.required !== undefined && typeof d.required !== 'boolean') return `${path}: required must be a boolean`;
  if (d.values !== undefined) {
    if (!Array.isArray(d.values) || d.values.length === 0 || d.values.length > MAX_SCHEMA_VALUES || !d.values.every((x) => isStr(x))) return `${path}: values must be 1..${MAX_SCHEMA_VALUES} strings`;
    if (new Set(d.values).size !== d.values.length) return `${path}: values must be distinct`;
    if (d.type !== 'string' && d.type !== 'set') return `${path}: values apply to string and set only`;
  }
  if (d.type === 'set' && d.values === undefined) return `${path}: a set needs values`;
  for (const k of ['min', 'max'] as const) {
    if (d[k] !== undefined && (!isInt(d[k]) || (d.type !== 'integer' && !(v2 && d.type === 'duration') && !(d.type === 'array' && d.items === 'integer')))) return `${path}: ${k} must be a safe integer on an integer parameter`;
  }
  if (isInt(d.min) && isInt(d.max) && d.min > d.max) return `${path}: min > max`;
  if (d.unit !== undefined && (d.type !== 'integer' || typeof d.unit !== 'string' || !units || !own(units, d.unit))) return `${path}: unit must name a declared unit of an integer parameter`;
  if (d.max_len !== undefined && (!isInt(d.max_len) || d.max_len < 1)) return `${path}: max_len must be a positive safe integer`;
  if (d.items !== undefined && (d.type !== 'array' || !isStr(d.items, 64))) return `${path}: items applies to array only`;
  for (const k of ['min_items', 'max_items'] as const) {
    if (d[k] !== undefined && (!isNonNegInt(d[k]) || (d.type !== 'set' && d.type !== 'array'))) return `${path}: ${k} must be a non-negative safe integer on a set or array`;
  }
  if (isInt(d.min_items) && isInt(d.max_items) && d.min_items > d.max_items) return `${path}: min_items > max_items`;
  if (d.default === null) return `${path}: default must not be null (absent = no default)`;
  if (d.principal_neutral_default !== undefined && typeof d.principal_neutral_default !== 'boolean') return `${path}: principal_neutral_default must be a boolean`;
  if (d.principal_neutral_default === true && d.default === undefined) return `${path}: principal_neutral_default needs a default`;
  if (d.accumulates_into !== undefined) {
    if (d.type !== 'integer') return `${path}: accumulates_into applies to integer parameters only`;
    if (!Array.isArray(d.accumulates_into) || d.accumulates_into.length === 0 || d.accumulates_into.length > 8) return `${path}: accumulates_into must be 1..8 unit ids`;
    if (!d.accumulates_into.every((u) => typeof u === 'string' && u.length <= 64 && UNIT_ID_RE.test(u))) return `${path}: accumulates_into entries must be unit ids`;
    if (new Set(d.accumulates_into).size !== d.accumulates_into.length) return `${path}: accumulates_into must be distinct`;
  }
  if (d.issued_by_site !== undefined && typeof d.issued_by_site !== 'boolean') return `${path}: issued_by_site must be a boolean`;
  if (d.description !== undefined && !isStr(d.description, 1024)) return `${path}: description must be a string`;
  if (v2) {
    if (d.role !== undefined && !isStr(d.role, 128)) return `${path}: role must be a non-empty string`;
    if (d.format !== undefined && (typeof d.format !== 'string' || formatCheck(d.format) === null || (d.type !== 'string' && d.type !== 'object_ref'))) return `${path}: format must be a known format on a string parameter`;
    if (d.tags !== undefined && (!Array.isArray(d.tags) || d.tags.length > SCHEMA_V2_TAGS.length || new Set(d.tags).size !== d.tags.length || !d.tags.every((t) => SCHEMA_V2_TAGS.includes(t as string)))) return `${path}: tags must be distinct known tags`;
    if (d.provenance_min !== undefined && !SCHEMA_V2_PROVENANCE.includes(d.provenance_min as string)) return `${path}: unknown provenance_min`;
  }
  return null;
}

const TRAIT_ID_V2 = /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$/;
/** Null if `c` is a well-formed `confirmation` (shape only; the signature check is rule 22). */
export function confirmationShapeError(c: unknown): string | null {
  if (!isObj(c)) return 'confirmation must be an object';
  for (const k of Object.keys(c)) if (!['def_digest', 'traits_digest', 'facts_digest', 'final_traits', 'dismissed', 'reviewer_kid', 'ts', 'sig'].includes(k)) return `confirmation: unknown member '${k}'`;
  if (decodeB64uStrict(c.def_digest, 32) === null || decodeB64uStrict(c.traits_digest, 32) === null || decodeB64uStrict(c.facts_digest, 32) === null) return 'confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests';
  if (decodeB64uStrict(c.sig, 64) === null) return 'confirmation: sig must be a canonical base64url 64-byte signature';
  const ft = c.final_traits;
  if (!Array.isArray(ft) || ft.length > 64 || !ft.every((x) => typeof x === 'string' && TRAIT_ID_V2.test(x))) return 'confirmation: final_traits must be trait ids';
  for (let i = 1; i < ft.length; i++) if (!((ft[i - 1] as string) < (ft[i] as string))) return 'confirmation: final_traits must be sorted and distinct';
  const dm = c.dismissed;
  if (!Array.isArray(dm) || dm.length > 64) return 'confirmation: dismissed must be an array';
  for (const d of dm) {
    if (!isObj(d) || Object.keys(d).some((k) => k !== 'trait' && k !== 'reason') || typeof d.trait !== 'string' || !TRAIT_ID_V2.test(d.trait) || !isStr(d.reason, 256)) return 'confirmation: dismissed entries must be {trait, reason}';
  }
  if (!isStr(c.reviewer_kid, 128)) return 'confirmation: reviewer_kid must be a non-empty string';
  if (typeof c.ts !== 'number' || !Number.isSafeInteger(c.ts) || c.ts < 0) return 'confirmation: ts must be a non-negative safe integer';
  return null;
}

/** Null if `f` is a well-formed materialized profile (shape only; the semantic check is rule 22). */
export function schemaFloorsError(f: unknown): string | null {
  if (!isObj(f)) return 'floors must be an object';
  for (const k of Object.keys(f)) if (!['risk', 'rev', 'blast_ppm', 'esc', 'caveats', 'context', 'prules'].includes(k)) return `floors: unknown member '${k}'`;
  const rng = (x: unknown, lo: number, hi: number) => isInt(x) && x >= lo && x <= hi;
  if (!rng(f.risk, 0, 3) || !rng(f.esc, 0, 3)) return 'floors.risk and floors.esc must be integers in 0..3';
  if (!SCHEMA_REVERSIBILITY.includes(f.rev as SchemaReversibility)) return 'floors.rev is not a reversibility class';
  if (!rng(f.blast_ppm, 0, 1_000_000)) return 'floors.blast_ppm must be an integer in 0..1000000';
  const sets: [string, (x: string) => boolean][] = [
    ['caveats', (x) => SCHEMA_V2_CAVEATS.includes(x)],
    ['context', (x) => SCHEMA_V2_CONTEXT.includes(x) || /^session_taint_max:[a-z_]{1,16}$/.test(x)],
    ['prules', (x) => SCHEMA_V2_PRULES.includes(x)],
  ];
  for (const [name, ok] of sets) {
    const a = f[name];
    if (!Array.isArray(a) || a.length > 64 || !a.every((x) => typeof x === 'string' && ok(x))) return `floors.${name} must be an array of known entries`;
    for (let i = 1; i < a.length; i++) if (!((a[i - 1] as string) < (a[i] as string))) return `floors.${name} must be sorted and distinct`;
  }
  return null;
}

function verbDeclError(v: unknown, units: Record<string, unknown> | undefined, v2 = false): string | null {
  if (!isObj(v)) return 'verb entry must be an object';
  for (const k of Object.keys(v)) if (!(v2 ? VERB_KEYS_V2 : VERB_KEYS).has(k)) return `verb entry: unknown member '${k}'`;
  if (!isStr(v.verb, 128)) return 'verb entry: verb must be a non-empty string';
  const at = `verb '${v.verb}'`;
  if (v.kind !== 'read' && v.kind !== 'write') return `${at}: kind must be read or write`;
  if (!isObj(v.params)) return `${at}: params must be an object`;
  const names = Object.keys(v.params);
  if (names.length > MAX_SCHEMA_PARAMS) return `${at}: more than ${MAX_SCHEMA_PARAMS} parameters`;
  for (const p of names) {
    const e = paramDeclError(p, ownGet(v.params, p), units, v2);
    if (e) return `${at}: ${e}`;
  }
  if (v2) {
    for (const p of names) for (const q of names) if (q !== p && q.startsWith(p + '.')) return `${at}: parameter '${p}' is both a value and the parent of '${q}'`;
  }
  if (v.reversibility !== undefined && !SCHEMA_REVERSIBILITY.includes(v.reversibility as SchemaReversibility)) return `${at}: unknown reversibility`;
  if (v.reversibility_by !== undefined) {
    const r = v.reversibility_by;
    if (!isObj(r) || Object.keys(r).some((k) => !['param', 'map', 'default'].includes(k))) return `${at}: reversibility_by must be {param, map, default?}`;
    if (typeof r.param !== 'string' || !own(v.params, r.param)) return `${at}: reversibility_by.param must be a declared parameter`;
    if (!isObj(r.map) || Object.keys(r.map).length === 0 || !Object.values(r.map).every((x) => SCHEMA_REVERSIBILITY.includes(x as SchemaReversibility))) return `${at}: reversibility_by.map must map values to reversibility classes`;
    if (r.default !== undefined && !SCHEMA_REVERSIBILITY.includes(r.default as SchemaReversibility)) return `${at}: reversibility_by.default is not a reversibility class`;
  }
  if (v.mcp !== undefined && (!isObj(v.mcp) || Object.keys(v.mcp).join() !== 'tool' || !isStr(v.mcp.tool, 128))) return `${at}: mcp must be {tool}`;
  if (v.openapi !== undefined && (!isObj(v.openapi) || Object.keys(v.openapi).join() !== 'operationId' || !isStr(v.openapi.operationId, 128))) return `${at}: openapi must be {operationId}`;
  for (const k of v2 ? (['harm', 'returns'] as const) : (['harm', 'effects', 'returns'] as const)) if (v[k] !== undefined && !isObj(v[k])) return `${at}: ${k} must be an object`;
  if (v2) {
    const ef = v.effects;
    if (!Array.isArray(ef) || ef.length === 0 || ef.length > SCHEMA_V2_EFFECTS.length || !ef.every((x) => SCHEMA_V2_EFFECTS.includes(x as string))) return `${at}: effects must be 1..${SCHEMA_V2_EFFECTS.length} known effects`;
    for (let i = 1; i < ef.length; i++) if (!((ef[i - 1] as string) < (ef[i] as string))) return `${at}: effects must be sorted and distinct`;
    if ((v.kind === 'read') !== ef.every((x) => x === 'read')) return `${at}: kind read must hold exactly when every effect is read`;
    const tr = v.traits;
    if (!Array.isArray(tr) || tr.length > 64 || !tr.every((x) => typeof x === 'string' && /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$/.test(x))) return `${at}: traits must be trait ids`;
    for (let i = 1; i < tr.length; i++) if (!((tr[i - 1] as string) < (tr[i] as string))) return `${at}: traits must be sorted and distinct`;
    if (decodeB64uStrict(v.def, 32) === null) return `${at}: def must be a canonical base64url SHA-256 digest`;
    const fe = schemaFloorsError(v.floors);
    if (fe) return `${at}: ${fe}`;
    if (v.confirmation !== undefined) {
      const ce = confirmationShapeError(v.confirmation);
      if (ce) return `${at}: ${ce}`;
    }
  }
  if (v.world !== undefined && !Array.isArray(v.world)) return `${at}: world must be an array`;
  if (v.description !== undefined && !isStr(v.description, 1024)) return `${at}: description must be a string`;
  return null;
}

/** Structural validation of an (optionally unsigned) schema document. Null = well-formed. */
export function actionSchemaShapeError(doc: unknown, opts: { signed?: boolean } = {}): string | null {
  try {
    if (!isObj(doc)) return 'schema is not an object';
    for (const k of Object.keys(doc)) if (!(doc.v === 2 ? DOC_KEYS_V2 : DOC_KEYS).has(k)) return `unknown member '${k}'`;
    if (doc.v !== 1 && doc.v !== 2) return 'unsupported schema version';
    const v2 = doc.v === 2;
    if (doc.kind !== ACTION_SCHEMA_KIND) return `kind must be '${ACTION_SCHEMA_KIND}'`;
    if (!isStr(doc.site, 2048) || !isStr(doc.aud, 256) || !isStr(doc.version, 128)) return 'site, aud and version must be non-empty strings';
    if (doc.units !== undefined) {
      if (!isObj(doc.units)) return 'units must be an object';
      for (const [id, u] of Object.entries(doc.units)) {
        if (!UNIT_ID_RE.test(id) || id.length > 64) return `unit id '${id}' is malformed`;
        if (!isObj(u) || !isStr(u.kind, 64)) return `unit '${id}' must be an object with a kind`;
        if (Object.keys(u).some((k) => !['kind', 'currency', 'exponent'].includes(k))) return `unit '${id}': unknown member`;
        if (u.currency !== undefined && !isStr(u.currency, 16)) return `unit '${id}': currency must be a string`;
        if (u.exponent !== undefined && !(isNonNegInt(u.exponent) && u.exponent <= 18)) return `unit '${id}': exponent must be an integer in [0, 18]`;
      }
    }
    if (doc.state !== undefined && !Array.isArray(doc.state)) return 'state must be an array';
    if (v2) {
      if (doc.traits_digest !== undefined && decodeB64uStrict(doc.traits_digest, 32) === null) return 'traits_digest must be a canonical base64url SHA-256 digest';
      if (doc.trait_defs !== undefined && (!Array.isArray(doc.trait_defs) || doc.trait_defs.length > 64 || !doc.trait_defs.every(isObj))) return 'trait_defs must be an array of up to 64 objects';
      if (doc.pack !== undefined) {
        const pk = doc.pack;
        if (!isObj(pk) || Object.keys(pk).sort().join() !== 'ns,root,version' || !isStr(pk.ns, 64) || !isStr(pk.version, 128) || decodeB64uStrict(pk.root, 32) === null) return 'pack must be {ns, version, root}';
      }
    }
    if (!Array.isArray(doc.verbs) || doc.verbs.length === 0 || doc.verbs.length > MAX_SCHEMA_VERBS) return `verbs must be 1..${MAX_SCHEMA_VERBS} entries`;
    const seen = new Set<string>();
    for (const v of doc.verbs) {
      const e = verbDeclError(v, doc.units as Record<string, unknown> | undefined, v2);
      if (e) return e;
      const name = (v as { verb: string }).verb;
      if (seen.has(name)) return `verb '${name}' is declared twice`;
      seen.add(name);
    }
    if (opts.signed !== false) {
      const s = doc.sig;
      if (!isObj(s)) return 'sig must be an object';
      for (const k of Object.keys(s)) if (!SIG_KEYS.has(k)) return `sig: unknown member '${k}'`;
      const se = suiteErr(s.alg);
      if (se) return `sig.alg: ${se}`;
      if (!isStr(s.kid, 128)) return 'sig.kid must be a non-empty string';
      if (decodeB64uStrict(s.value) === null) return 'sig.value is not canonical base64url';
      if (s.pq_value !== undefined && decodeB64uStrict(s.pq_value) === null) return 'sig.pq_value is not canonical base64url';
    } else if (doc.sig !== undefined) return 'an unsigned schema must not carry sig';
    const { sig: _s, ...body } = doc;
    void _s;
    canonicalBytesStrict(body); // throws on a non-strict number / lone surrogate / excessive depth
    return null;
  } catch (e) {
    return `malformed schema: ${(e as Error).message}`;
  }
}

function schemaMessage(doc: UnsignedActionSchema | ActionSchema): Uint8Array {
  const { sig: _sig, ...body } = doc as ActionSchema;
  void _sig;
  const dom = utf8(ACTION_SCHEMA_DOMAIN);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
}

/** Sign a schema as the site (`kid` names the discovery key entry; `suite` its suite and PQ key material). */
export function signActionSchema(doc: UnsignedActionSchema, kid: string, siteSecret: Uint8Array, suite?: SignerSuiteOpts): ActionSchema {
  const bad = actionSchemaShapeError(doc, { signed: false });
  if (bad) throw new Error(`signActionSchema: ${bad}`);
  const parts = signSuiteArtifact(suite?.alg, suiteKeysOf(siteSecret, suite), schemaMessage(doc));
  const alg = (resolveSigAlg(suite?.alg ?? 'ed25519')!.alg) as SigAlg;
  return { ...doc, sig: { alg, kid, value: parts.sig, ...(parts.pq_sig !== undefined ? { pq_value: parts.pq_sig } : {}) } };
}

/** The discovery key entry for a signer (helper for sites and tests). */
export function actionSchemaKeyOf(kid: string, siteSecret: Uint8Array, suite?: SignerSuiteOpts): ActionSchemaKey {
  const alg = resolveSigAlg(suite?.alg ?? 'ed25519')!.alg as SigAlg;
  const pq = suitePqPublicKey(alg, suite);
  return { kid, alg, pk: b64u(publicKeyOf(siteSecret)), ...(pq !== undefined ? { pq_pk: pq } : {}) };
}

export type SchemaVerdict = { ok: true } | { ok: false; reason: string };

/**
 * Verify a site-signed schema against the site's discovery key list: shape, `sig.kid` names a listed key, `sig.alg`
 * equals that key's `alg` (the suite is pinned by the key entry), and the signature verifies. Never throws.
 */
export function verifyActionSchema(doc: unknown, keys: readonly ActionSchemaKey[]): SchemaVerdict {
  try {
    const bad = actionSchemaShapeError(doc);
    if (bad) return { ok: false, reason: bad };
    const d = doc as ActionSchema;
    if (!Array.isArray(keys)) return { ok: false, reason: 'the schema keys must be an array' };
    const key = keys.find((k) => isObj(k) && k.kid === d.sig.kid);
    if (!key) return { ok: false, reason: `no schema key with kid '${d.sig.kid}'` };
    if (key.pq_pk !== undefined && typeof key.pq_pk !== 'string') return { ok: false, reason: 'the schema key pq_pk must be a string' };
    if (decodeB64uStrict(key.pk, 32) === null) return { ok: false, reason: 'schema key pk is not canonical base64url (32 bytes)' };
    const kse = suiteErr(key.alg);
    if (kse) return { ok: false, reason: `schema key: ${kse}` };
    const ka = resolveSigAlg(key.alg);
    if (ka === null || ka.alg !== resolveSigAlg(d.sig.alg)!.alg) return { ok: false, reason: 'sig.alg does not match the pinned key suite' };
    const pin: PqPinPolicy = key.pq_pk !== undefined ? { pqPins: { [key.pk]: key.pq_pk } } : {};
    if (!verifyPinnedSuite(ka.alg, key.pk, key.pq_pk, schemaMessage(d), { sig: d.sig.value, pq_sig: d.sig.pq_value }, pin)) return { ok: false, reason: 'schema signature invalid' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `schema verification error: ${(e as Error).message}` };
  }
}

/** The schema's content address (over the whole signed document). */
export function actionSchemaDigest(doc: ActionSchema): string {
  return hashCanonical({ d: ACTION_SCHEMA_REF_DOMAIN, s: doc });
}

export function schemaVerb(doc: Pick<ActionSchema, 'verbs'>, verb: string): ActionVerbDecl | undefined {
  return Array.isArray(doc?.verbs) ? doc.verbs.find((v) => v.verb === verb) : undefined;
}

// ---- closed-world conformance (rule 14, ⊠) -----------------------------------------------------------------------

export type SchemaViolationCode = 'params_not_object' | 'unknown_verb' | 'undeclared_param' | 'missing_param' | 'bad_type' | 'out_of_domain';
export type ConformResult = { ok: true; verb: ActionVerbDecl } | { ok: false; code: SchemaViolationCode; path?: string; reason: string };

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
function isCalendarDate(s: string): boolean {
  const m = DATE_RE.exec(s);
  if (!m) return false;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (y < 1 || mo < 1 || mo > 12 || d < 1) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]!;
  return d <= dim;
}
const strOk = (x: unknown, maxLen: number): x is string => typeof x === 'string' && !hasLoneSurrogate(x) && u8len(x) <= maxLen;

// ---- v2 string formats (syntactic checks, identical in every language; none consults a registry or the network) -------------
const IBAN_RE = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/;
function ibanOk(s: string): boolean {
  if (!IBAN_RE.test(s)) return false;
  let rem = 0;
  for (const ch of s.slice(4) + s.slice(0, 4)) {
    const v = ch >= 'A' ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48;
    rem = (v > 9 ? rem * 100 + v : rem * 10 + v) % 97;
  }
  return rem === 1;
}
function cidrOk(s: string): boolean {
  const m4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(s);
  if (m4) return [m4[1], m4[2], m4[3], m4[4]].every((o) => Number(o) <= 255 && String(Number(o)) === o) && Number(m4[5]) <= 32 && String(Number(m4[5])) === m4[5];
  const m6 = /^([0-9a-fA-F:]{2,39})\/(\d{1,3})$/.exec(s);
  return !!m6 && (m6[1]!.match(/:/g) ?? []).length >= 2 && !m6[1]!.includes(':::') && Number(m6[2]) <= 128 && String(Number(m6[2])) === m6[2];
}
const FORMAT_CHECKS: Record<string, (s: string) => boolean> = {
  email: (s) => s.length <= 254 && /^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+$/.test(s),
  url: (s) => /^[A-Za-z][A-Za-z0-9+.\-]{0,31}:\/\/[^\s/?#]+[^\s]*$/.test(s),
  uri_https: (s) => /^https:\/\/[^\s/?#]+[^\s]*$/.test(s),
  uuid: (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s),
  iban: ibanOk,
  phone_e164: (s) => /^\+[1-9][0-9]{6,14}$/.test(s),
  cidr: cidrOk,
  iso_country: (s) => /^[A-Z]{2}$/.test(s),
  iso_currency: (s) => /^[A-Z]{3}$/.test(s),
  semver: (s) => /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?(?:\+[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?$/.test(s),
  sha256: (s) => /^[0-9a-f]{64}$/.test(s),
};
const ID_FORMAT = /^id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$/;
/** The checker of a v2 `format`, or null when the format is unknown. `id:<type>` accepts a 1..128 character safe id. */
export function formatCheck(f: string): ((s: string) => boolean) | null {
  if (Object.prototype.hasOwnProperty.call(FORMAT_CHECKS, f)) return FORMAT_CHECKS[f]!;
  return ID_FORMAT.test(f) ? (s) => /^[A-Za-z0-9._:\-]{1,128}$/.test(s) : null;
}
const DATETIME_RE = /^(\d{4}-\d{2}-\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.\d{1,3})?Z$/;

function formatViolation(d: ActionParamDecl, x: string): { code: 'out_of_domain'; reason: string } | null {
  if (d.format === undefined) return null;
  const ck = formatCheck(d.format);
  return ck === null || !ck(x) ? { code: 'out_of_domain', reason: `not a valid ${d.format}` } : null;
}

/** Value check of one declared parameter: null = in the declared domain, else the violation. */
export function paramValueViolation(d: ActionParamDecl, x: unknown): { code: 'bad_type' | 'out_of_domain'; reason: string } | null {
  const maxLen = d.max_len ?? DEFAULT_MAX_LEN;
  switch (d.type) {
    case 'string':
      if (typeof x !== 'string' || hasLoneSurrogate(x)) return { code: 'bad_type', reason: 'expected a string' };
      if (u8len(x) > maxLen) return { code: 'out_of_domain', reason: `longer than ${maxLen} UTF-8 bytes` };
      if (d.values !== undefined && !d.values.includes(x)) return { code: 'out_of_domain', reason: 'not one of the declared values' };
      return formatViolation(d, x);
    case 'object_ref':
      if (typeof x !== 'string' || hasLoneSurrogate(x) || x.length === 0) return { code: 'bad_type', reason: 'expected a non-empty id string' };
      if (u8len(x) > maxLen) return { code: 'out_of_domain', reason: `longer than ${maxLen} UTF-8 bytes` };
      return formatViolation(d, x);
    case 'datetime': {
      if (typeof x !== 'string') return { code: 'bad_type', reason: 'expected an RFC 3339 UTC string' };
      const m = DATETIME_RE.exec(x);
      return m && isCalendarDate(m[1]!) ? null : { code: 'out_of_domain', reason: 'not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z' };
    }
    case 'duration':
      if (!isInt(x)) return { code: 'bad_type', reason: 'expected a safe integer (milliseconds)' };
      if (x < 0) return { code: 'out_of_domain', reason: 'a duration is not negative' };
      if (d.min !== undefined && x < d.min) return { code: 'out_of_domain', reason: `below min ${d.min}` };
      if (d.max !== undefined && x > d.max) return { code: 'out_of_domain', reason: `above max ${d.max}` };
      return null;
    case 'integer':
      if (!isInt(x)) return { code: 'bad_type', reason: 'expected a safe integer' };
      if (d.min !== undefined && x < d.min) return { code: 'out_of_domain', reason: `below min ${d.min}` };
      if (d.max !== undefined && x > d.max) return { code: 'out_of_domain', reason: `above max ${d.max}` };
      return null;
    case 'boolean':
      return typeof x === 'boolean' ? null : { code: 'bad_type', reason: 'expected a boolean' };
    case 'date':
      if (typeof x !== 'string') return { code: 'bad_type', reason: 'expected a YYYY-MM-DD string' };
      return isCalendarDate(x) ? null : { code: 'out_of_domain', reason: 'not a calendar date YYYY-MM-DD' };
    case 'set': {
      if (!Array.isArray(x) || !x.every((e) => typeof e === 'string')) return { code: 'bad_type', reason: 'expected an array of strings' };
      if (new Set(x).size !== x.length) return { code: 'out_of_domain', reason: 'set members must be distinct' };
      if (!x.every((e) => d.values!.includes(e as string))) return { code: 'out_of_domain', reason: 'set member not among the declared values' };
      if (x.length < (d.min_items ?? 0) || x.length > (d.max_items ?? d.values!.length)) return { code: 'out_of_domain', reason: 'set size outside the declared bounds' };
      return null;
    }
    case 'array': {
      if (!Array.isArray(x)) return { code: 'bad_type', reason: 'expected an array' };
      const ints = d.items === 'integer';
      for (const e of x) {
        if (ints ? !isInt(e) : !strOk(e, maxLen)) return { code: 'bad_type', reason: ints ? 'array items must be safe integers' : `array items must be strings of at most ${maxLen} UTF-8 bytes` };
        if (ints && ((d.min !== undefined && (e as number) < d.min) || (d.max !== undefined && (e as number) > d.max))) return { code: 'out_of_domain', reason: 'array item outside min/max' };
      }
      if (x.length < (d.min_items ?? 0) || x.length > (d.max_items ?? DEFAULT_MAX_ITEMS)) return { code: 'out_of_domain', reason: 'array length outside the declared bounds' };
      return null;
    }
    default:
      return { code: 'bad_type', reason: 'unknown declared type' };
  }
}

/**
 * Map an action to Ω_𝒮 or to ⊠ (NORMATIVE, rule 14 step 5). First failure wins:
 *   1. `params` is not a plain JSON object                                   -> params_not_object
 *   2. no verb entry named `verb`                                            -> unknown_verb
 *   3. a key of `params` (taken in UTF-8 byte order) whose path `action.params.<key>` is not declared -> undeclared_param
 *   4. for every declared path in UTF-8 byte order: absent and required (default true) -> missing_param;
 *      present: the value check of {@link paramValueViolation}               -> bad_type / out_of_domain
 * A conforming action lies in Ω_𝒮 (every material / critical value then lies in a cell the grant can constrain).
 */
export function conformAction(doc: Pick<ActionSchema, 'verbs'>, verb: string, params: unknown): ConformResult {
  if (!isObj(params)) return { ok: false, code: 'params_not_object', reason: 'params must be a JSON object' };
  const v = schemaVerb(doc, verb);
  if (!v) return { ok: false, code: 'unknown_verb', reason: `verb '${verb}' is not declared by the schema` };
  for (const k of Object.keys(params).sort(compareUtf8)) {
    const path = 'action.params.' + k;
    if (!own(v.params, path)) return { ok: false, code: 'undeclared_param', path, reason: `parameter '${path}' is not declared for '${verb}'` };
  }
  for (const path of Object.keys(v.params).sort(compareUtf8)) {
    const d = ownGet(v.params, path) as ActionParamDecl;
    const name = path.slice('action.params.'.length);
    if (!own(params, name)) {
      if (d.required !== false) return { ok: false, code: 'missing_param', path, reason: `required parameter '${path}' is missing` };
      continue;
    }
    const bad = paramValueViolation(d, ownGet(params, name));
    if (bad) return { ok: false, code: bad.code, path, reason: `'${path}': ${bad.reason}` };
  }
  return { ok: true, verb: v };
}

// ---- value-dependent reversibility (§2.3) ------------------------------------------------------------------------

const REV_RANK: Record<SchemaReversibility, number> = { reversible: 0, rate_limited: 1, irreversible: 2 };
const maxRev = (xs: SchemaReversibility[]): SchemaReversibility => xs.reduce((a, b) => (REV_RANK[b] > REV_RANK[a] ? b : a), 'reversible' as SchemaReversibility);
const keyOfValue = (x: unknown): string | null => (typeof x === 'string' ? x : typeof x === 'boolean' || isInt(x) ? String(x) : null);

/** rev_𝒮(ω): the value-dependent class (unmapped or absent value -> `default`, else irreversible: fail closed). */
export function reversibilityOf(v: ActionVerbDecl, params: Record<string, unknown>): SchemaReversibility {
  if (v.reversibility_by) {
    const name = v.reversibility_by.param.slice('action.params.'.length);
    const k = own(params, name) ? keyOfValue(ownGet(params, name)) : null;
    if (k !== null && own(v.reversibility_by.map, k)) return ownGet(v.reversibility_by.map, k) as SchemaReversibility;
    return v.reversibility_by.default ?? 'irreversible';
  }
  return v.reversibility ?? (v.kind === 'read' ? 'reversible' : 'irreversible');
}

/** rev(v) = max_ω rev_𝒮(v, ω), the conservative projection (v1 compatibility). */
export function verbReversibility(v: ActionVerbDecl): SchemaReversibility {
  if (!v.reversibility_by) return v.reversibility ?? (v.kind === 'read' ? 'reversible' : 'irreversible');
  const d = v.params[v.reversibility_by.param];
  const mapped = Object.values(v.reversibility_by.map);
  // the map covers the whole domain only for a boolean (both spellings) or a string enum
  const domain = d?.type === 'boolean' ? ['true', 'false'] : d?.type === 'string' && d.values ? d.values : null;
  const covered = domain !== null && domain.every((x) => own(v.reversibility_by!.map, x));
  return maxRev(covered ? mapped : [...mapped, v.reversibility_by.default ?? 'irreversible']);
}

// ---- the wallet floor (§3.2 step 5) --------------------------------------------------------------------------------

/** Semantic types that are ALWAYS at least material, whatever the site says (prefix match on `x.`, or exact). */
export const WALLET_FLOOR_PREFIXES: readonly string[] = ['money.', 'party.', 'contact.', 'person.', 'credential.'];
export const WALLET_FLOOR_EXACT: readonly string[] = ['text.message'];

export function floorApplies(semantic: string, floor: { prefixes?: readonly string[]; exact?: readonly string[] } = {}): boolean {
  const pre = floor.prefixes ?? WALLET_FLOOR_PREFIXES;
  const ex = floor.exact ?? WALLET_FLOOR_EXACT;
  return ex.includes(semantic) || pre.some((p) => semantic.startsWith(p));
}

export interface SensitivityOverride {
  verb: string;
  path: string;
  semantic: string;
  declared: Sensitivity;
  effective: Sensitivity;
}

/** The wallet's effective sensitivity: a site `free` on a floored semantic type becomes `material`. */
export function effectiveSensitivity(d: ActionParamDecl, floor?: { prefixes?: readonly string[]; exact?: readonly string[] }): Sensitivity {
  return d.sensitivity === 'free' && floorApplies(d.semantic, floor) ? 'material' : d.sensitivity;
}

/** Every override the wallet floor makes on a schema (recorded in the map, `omega.overrides`). */
export function walletFloorOverrides(doc: Pick<ActionSchema, 'verbs'>, floor?: { prefixes?: readonly string[]; exact?: readonly string[] }): SensitivityOverride[] {
  const out: SensitivityOverride[] = [];
  for (const v of doc.verbs) {
    for (const path of Object.keys(v.params).sort(compareUtf8)) {
      const d = v.params[path]!;
      const eff = effectiveSensitivity(d, floor);
      if (eff !== d.sensitivity) out.push({ verb: v.verb, path, semantic: d.semantic, declared: d.sensitivity, effective: eff });
    }
  }
  return out;
}

/** Every accumulation unit a verb feeds, with the integer params that feed it (SEL via `accumulates_into`). */
export function accumulationParams(v: ActionVerbDecl, unit: string): string[] {
  return Object.keys(v.params)
    .filter((p) => v.params[p]!.type === 'integer' && (v.params[p]!.accumulates_into ?? []).includes(unit))
    .sort(compareUtf8);
}

// ---- importers: MCP tools and OpenAPI operations -> DRAFT schema (§3.2 step 2) ---------------------------------------

/** An MCP tool as listed by `tools/list` (inputSchema is JSON Schema; annotations are HINTS). */
export interface McpToolLike {
  name: string;
  description?: string;
  inputSchema?: { type?: string; properties?: Record<string, JsonSchemaLike>; required?: string[] };
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean; title?: string };
}
export interface JsonSchemaLike {
  type?: string | string[];
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  maxLength?: number;
  format?: string;
  items?: JsonSchemaLike;
  uniqueItems?: boolean;
  minItems?: number;
  maxItems?: number;
  default?: unknown;
  description?: string;
  ['x-pca-semantic']?: string;
  ['x-pca-sensitivity']?: Sensitivity;
  ['x-pca-unit']?: string;
  ['x-pca-accumulates-into']?: string[];
  /** Local references (`#/...`) are resolved by the importers; anything else is flagged in `todo`. */
  $ref?: string;
  nullable?: boolean;
  properties?: Record<string, JsonSchemaLike>;
  required?: string[];
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  anyOf?: JsonSchemaLike[];
  oneOf?: JsonSchemaLike[];
  allOf?: JsonSchemaLike[];
  const?: unknown;
}

/** Where the importers resolve `#/...` references and where they report what they could not represent. */
interface ImportCtx {
  root: unknown;
  todo: string[];
  /** Schema nodes this operation may still expand (the reference-bomb bound); reset per operation. */
  left?: number;
}
const MAX_REF_DEPTH = 8;
const MAX_REF_NODES = 20_000;

/** Follow a local `#/a/b` JSON pointer in `root`; undefined when absent, not local, or not an object. */
function pointer(root: unknown, ref: string): unknown {
  if (!ref.startsWith('#/')) return undefined;
  let cur: unknown = root;
  for (const raw of ref.slice(2).split('/')) {
    const seg = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (cur === null || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur !== null && typeof cur === 'object' ? cur : undefined;
}

/**
 * Flatten what a parameter declaration cannot carry: follow local `$ref`s, merge `allOf`, and collapse `anyOf` / `oneOf`
 * to its single non-null variant (or to the union of string constants). Whatever remains unrepresentable (a remote or
 * cyclic reference, a real union) is flagged in `todo` and left as an empty schema, which the caller declares `string`
 * (a placeholder that rejects every non-string value: the draft fails closed until the developer refines it).
 */
function flattenSchema(s: JsonSchemaLike | undefined, c: ImportCtx, where: string, depth = 0): JsonSchemaLike {
  if (s === undefined || s === null || typeof s !== 'object') return {};
  c.left = (c.left ?? MAX_REF_NODES) - 1;
  if (c.left < 0) {
    if (c.left === -1) c.todo.push(`${where}: schema expansion stopped after ${MAX_REF_NODES} nodes (declared string; refine or drop)`);
    return {};
  }
  if (depth > MAX_REF_DEPTH) {
    c.todo.push(`${where}: schema nesting or reference chain deeper than ${MAX_REF_DEPTH} (declared string; refine or drop)`);
    return {};
  }
  let cur: JsonSchemaLike = s;
  if (typeof s.$ref === 'string') {
    const target = pointer(c.root, s.$ref);
    if (target === undefined) {
      c.todo.push(`${where}: reference '${s.$ref.slice(0, 120)}' is not a local reference that resolves (declared string; refine or drop)`);
      return {};
    }
    const { $ref: _r, ...siblings } = s;
    cur = { ...flattenSchema(target as JsonSchemaLike, c, where, depth + 1), ...siblings };
  }
  if (Array.isArray(cur.allOf)) {
    const { allOf, ...rest } = cur;
    cur = allOf.map((m) => flattenSchema(m, c, where, depth + 1)).reduce<JsonSchemaLike>((a, m) => ({ ...a, ...m, properties: { ...a.properties, ...m.properties }, required: [...(a.required ?? []), ...(m.required ?? [])] }), {});
    cur = { ...cur, ...rest };
  }
  const alts = cur.anyOf ?? cur.oneOf;
  if (Array.isArray(alts)) {
    const { anyOf: _a, oneOf: _o, ...rest } = cur;
    const live = alts.map((m) => flattenSchema(m, c, where, depth + 1)).filter((m) => !(m.type === 'null' || (Array.isArray(m.type) && m.type.every((x) => x === 'null'))));
    if (live.length === 1) return { ...live[0]!, ...rest };
    const consts = live.map((m) => (typeof m.const === 'string' ? [m.const] : Array.isArray(m.enum) && m.enum.every((x) => typeof x === 'string') ? (m.enum as string[]) : null));
    if (live.length > 1 && consts.every((x) => x !== null)) return { ...rest, type: 'string', enum: [...new Set(consts.flat() as string[])] };
    c.todo.push(`${where}: a union of ${live.length} schemas has no schema representation (declared string; refine or drop)`);
    return rest;
  }
  if (cur.const !== undefined && cur.enum === undefined && typeof cur.const === 'string') cur = { ...cur, enum: [cur.const] };
  return cur;
}

/**
 * JSON Schema property -> parameter declaration. Sensitivity defaults to `material` (the importer never marks anything
 * `free`: the developer lowers it explicitly, and the wallet floor still applies). Unrepresentable shapes (objects,
 * numbers with fractions) become `string` placeholders flagged in `todo` so the developer must decide.
 */
function declOfJsonSchema(name: string, schema: JsonSchemaLike, required: boolean, c: ImportCtx): ActionParamDecl {
  const todo = c.todo;
  const s = flattenSchema(schema, c, `action.params.${name}`);
  const t = Array.isArray(s.type) ? s.type.find((x) => x !== 'null') : s.type;
  const base = {
    semantic: s['x-pca-semantic'] ?? 'unknown',
    sensitivity: s['x-pca-sensitivity'] ?? ('material' as Sensitivity),
    ...(required ? {} : { required: false }),
    ...(s.description ? { description: s.description.slice(0, 1024) } : {}),
  };
  if (!s['x-pca-semantic']) todo.push(`action.params.${name}: semantic type`);
  const enumStrings = Array.isArray(s.enum) && s.enum.every((x) => typeof x === 'string') ? (s.enum as string[]) : undefined;
  if (t === 'integer') {
    return {
      type: 'integer',
      ...base,
      ...(Number.isSafeInteger(s.minimum) ? { min: s.minimum } : Number.isSafeInteger(s.exclusiveMinimum) ? { min: s.exclusiveMinimum! + 1 } : {}),
      ...(Number.isSafeInteger(s.maximum) ? { max: s.maximum } : Number.isSafeInteger(s.exclusiveMaximum) ? { max: s.exclusiveMaximum! - 1 } : {}),
      ...(s['x-pca-unit'] ? { unit: s['x-pca-unit'] } : {}),
      ...(s['x-pca-accumulates-into'] ? { accumulates_into: s['x-pca-accumulates-into'] } : {}),
    };
  }
  if (t === 'boolean') return { type: 'boolean', ...base };
  if (t === 'string' && s.format === 'date') return { type: 'date', ...base };
  if (t === 'string') return { type: 'string', ...base, ...(enumStrings ? { values: enumStrings } : {}), ...(Number.isSafeInteger(s.maxLength) && s.maxLength! > 0 ? { max_len: s.maxLength } : {}) };
  if (t === 'array') {
    const it = flattenSchema(s.items, c, `action.params.${name}[]`);
    const itEnum = Array.isArray(it.enum) && it.enum.every((x) => typeof x === 'string') ? (it.enum as string[]) : undefined;
    if (s.uniqueItems && itEnum) return { type: 'set', ...base, values: itEnum, ...(Number.isSafeInteger(s.minItems) ? { min_items: s.minItems } : {}), ...(Number.isSafeInteger(s.maxItems) ? { max_items: s.maxItems } : {}) };
    const itT = Array.isArray(it.type) ? it.type[0] : it.type;
    return { type: 'array', ...base, ...(itT === 'integer' ? { items: 'integer' } : {}), ...(Number.isSafeInteger(s.maxItems) ? { max_items: s.maxItems } : {}), ...(Number.isSafeInteger(s.minItems) ? { min_items: s.minItems } : {}) };
  }
  todo.push(`action.params.${name}: type '${String(t)}' has no schema representation (declared string; refine or drop)`);
  return { type: 'string', ...base };
}

/** MCP annotations give a LOWER bound on reversibility (hints never lower a classification). */
export function reversibilityFromMcpHints(a: McpToolLike['annotations']): { kind: 'read' | 'write'; atLeast: SchemaReversibility } {
  if (a?.readOnlyHint === true) return { kind: 'read', atLeast: 'reversible' };
  if (a?.destructiveHint === true) return { kind: 'write', atLeast: 'rate_limited' };
  return { kind: 'write', atLeast: 'reversible' };
}

export interface DraftSchema {
  schema: UnsignedActionSchema;
  /** Decisions the developer must make before signing (semantic types, sensitivities, units, reversibility). */
  todo: string[];
}

/**
 * @deprecated The v1 draft. `@atlasauth/pca-actions` has the importers for the action kit (`importMcp`, `importOpenApi`, ...):
 * they produce ActionDefs (typed, with roles and bounded nested params) that `toSchemaDoc` turns into a v2 schema. This function
 * stays for existing v1 callers; it cannot move into that package (which depends on this one).
 *
 * Draft schema from an MCP `tools/list`. Verb = `${prefix}${tool.name}`; every write verb is drafted `irreversible`
 * (the fail-closed default) unless the developer lowers it; a destructive hint can only keep it at least `rate_limited`.
 */
export function draftSchemaFromMcpTools(tools: readonly McpToolLike[], site: { site: string; aud: string; version: string; verbPrefix?: string }): DraftSchema {
  const todo: string[] = [];
  const verbs: ActionVerbDecl[] = [];
  for (const t of tools) {
    const c: ImportCtx = { root: t.inputSchema, todo };
    const input = flattenSchema(t.inputSchema as JsonSchemaLike | undefined, c, `${t.name}: inputSchema`);
    const props = input.properties ?? {};
    const req = new Set(input.required ?? []);
    const params: Record<string, ActionParamDecl> = {};
    for (const name of Object.keys(props).sort(compareUtf8)) {
      if (!/^[A-Za-z0-9_]{1,64}$/.test(name)) {
        todo.push(`${t.name}: parameter '${name}' is not a schema name ([A-Za-z0-9_]{1,64}); rename it`);
        continue;
      }
      params['action.params.' + name] = declOfJsonSchema(name, props[name]!, req.has(name), c);
    }
    const h = reversibilityFromMcpHints(t.annotations);
    const verb = (site.verbPrefix ?? '') + t.name;
    if (h.kind === 'write') todo.push(`${verb}: reversibility (drafted irreversible)`);
    verbs.push({ verb, kind: h.kind, params, reversibility: h.kind === 'read' ? 'reversible' : 'irreversible', mcp: { tool: t.name }, ...(t.description ? { description: t.description.slice(0, 1024) } : {}) });
  }
  verbs.sort((a, b) => compareUtf8(a.verb, b.verb));
  return { schema: { v: 1, kind: ACTION_SCHEMA_KIND, site: site.site, aud: site.aud, version: site.version, verbs }, todo };
}

/** A minimal OpenAPI 3.1 document view (paths -> operations with JSON request bodies). */
export interface OpenApiParameterLike {
  $ref?: string;
  name?: string;
  in?: string;
  required?: boolean;
  description?: string;
  schema?: JsonSchemaLike;
}
export interface OpenApiRequestBodyLike {
  $ref?: string;
  content?: Record<string, { schema?: JsonSchemaLike }>;
}
export interface OpenApiLike {
  /** Operations by method; a path item's own `parameters` array applies to every operation under it. */
  paths?: Record<string, Record<string, unknown>>;
  /** Targets of local `#/components/...` references. */
  components?: Record<string, unknown>;
}
interface OpenApiOperationLike {
  operationId?: string;
  description?: string;
  parameters?: OpenApiParameterLike[];
  requestBody?: OpenApiRequestBodyLike;
  'x-pca-verb'?: string;
  'x-pca-reversibility'?: SchemaReversibility;
  'x-pca-kind'?: 'read' | 'write';
}
/** The JSON media type of a request body: `application/json` first, else any `application/*+json`. */
function jsonBodySchema(b: OpenApiRequestBodyLike | undefined): JsonSchemaLike | undefined {
  const content = b?.content;
  if (content === undefined || content === null || typeof content !== 'object') return undefined;
  const key = Object.keys(content).sort(compareUtf8).find((k) => k.toLowerCase() === 'application/json') ?? Object.keys(content).sort(compareUtf8).find((k) => /^application\/[^;]*\+json(;|$)/i.test(k));
  return key === undefined ? undefined : content[key]?.schema;
}

/**
 * @deprecated The v1 draft; see `importOpenApi` in `@atlasauth/pca-actions`, which unifies this importer and adds nested bodies,
 * Swagger 2, size and reference-expansion bounds and the `unreviewed` default.
 *
 * Draft schema from OpenAPI: one verb per operation with an `operationId` (`x-pca-verb` names it, else the id). The
 * parameters are the operation's path and query parameters (path-item parameters included, the operation's own winning)
 * plus the properties of its JSON request body; local `$ref`s are followed. Header and cookie parameters are not action
 * parameters and are flagged in `todo`, as is any name the two sources share (the body declaration is kept).
 */
export function draftSchemaFromOpenApi(doc: OpenApiLike, site: { site: string; aud: string; version: string }): DraftSchema {
  const todo: string[] = [];
  const verbs: ActionVerbDecl[] = [];
  const c: ImportCtx = { root: doc, todo };
  const deref = <T extends { $ref?: string }>(x: T | undefined): T | undefined => {
    if (x === undefined || x === null || typeof x !== 'object') return undefined;
    if (typeof x.$ref !== 'string') return x;
    const t = pointer(doc, x.$ref) as T | undefined;
    if (t === undefined) todo.push(`reference '${x.$ref.slice(0, 120)}' is not a local reference that resolves`);
    return t;
  };
  const seen = new Set<string>();
  for (const path of Object.keys(doc.paths ?? {}).sort(compareUtf8)) {
    const ops = doc.paths![path]!;
    const shared = Array.isArray(ops.parameters) ? (ops.parameters as OpenApiParameterLike[]) : [];
    for (const method of Object.keys(ops).sort(compareUtf8)) {
      const op = ops[method] as OpenApiOperationLike | undefined;
      if (!op || typeof op !== 'object' || Array.isArray(op) || !op.operationId) continue;
      c.left = MAX_REF_NODES;
      const read = op['x-pca-kind'] ? op['x-pca-kind'] === 'read' : method.toLowerCase() === 'get' || method.toLowerCase() === 'head';
      const verb = op['x-pca-verb'] ?? op.operationId;
      if (seen.has(verb)) todo.push(`${verb}: declared by more than one operation; give each a distinct x-pca-verb`);
      seen.add(verb);
      const params: Record<string, ActionParamDecl> = {};
      const addName = (name: string, sch: JsonSchemaLike, required: boolean, source: string) => {
        if (!/^[A-Za-z0-9_]{1,64}$/.test(name)) {
          todo.push(`${op.operationId}: parameter '${name}' is not a schema name; rename it`);
          return;
        }
        const key = 'action.params.' + name;
        if (params[key] !== undefined) {
          todo.push(`${op.operationId}: '${name}' is declared by both the ${source} and another source; kept the first`);
          return;
        }
        params[key] = declOfJsonSchema(name, sch, required, c);
      };
      // request body first (it wins a name clash), then the operation's own parameters over the path item's
      const body = flattenSchema(jsonBodySchema(deref(op.requestBody)), c, `${op.operationId}: request body`);
      const bprops = body.properties ?? {};
      const breq = new Set(body.required ?? []);
      for (const name of Object.keys(bprops).sort(compareUtf8)) addName(name, bprops[name]!, breq.has(name), 'request body');
      const merged = new Map<string, OpenApiParameterLike>();
      for (const raw of [...shared, ...(Array.isArray(op.parameters) ? op.parameters : [])]) {
        const q = deref(raw);
        if (!q || typeof q.name !== 'string' || typeof q.in !== 'string') continue;
        merged.set(`${q.in}:${q.name}`, q);
      }
      for (const key of [...merged.keys()].sort(compareUtf8)) {
        const q = merged.get(key)!;
        if (q.in !== 'path' && q.in !== 'query') {
          todo.push(`${op.operationId}: ${q.in} parameter '${q.name}' is not an action parameter (the schema sees path, query and body parameters only)`);
          continue;
        }
        const sch = { ...(q.schema ?? {}), ...(q.description && !(q.schema ?? {}).description ? { description: q.description } : {}) };
        addName(q.name!, sch, q.in === 'path' || q.required === true, `${q.in} parameters`);
      }
      const rev = op['x-pca-reversibility'] ?? (read ? 'reversible' : 'irreversible');
      if (!read && !op['x-pca-reversibility']) todo.push(`${verb}: reversibility (drafted irreversible)`);
      verbs.push({ verb, kind: read ? 'read' : 'write', params, reversibility: rev, openapi: { operationId: op.operationId }, ...(op.description ? { description: op.description.slice(0, 1024) } : {}) });
    }
  }
  verbs.sort((a, b) => compareUtf8(a.verb, b.verb));
  return { schema: { v: 1, kind: ACTION_SCHEMA_KIND, site: site.site, aud: site.aud, version: site.version, verbs }, todo };
}
