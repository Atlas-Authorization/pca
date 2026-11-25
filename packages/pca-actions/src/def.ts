// def.ts - the ActionDef data model: closed vocabularies, constants and types (docs/pca/specs/action-kit.md section 2).
// Pure types and tables. NO imports: everything here is also the contract the native ports (A7) mirror.

/** Document kinds. */
export const ACTION_DEF_KIND = 'pca-action-def';
export const ACTION_PACK_KIND = 'pca-action-pack';
export const ACTION_DEF_VERSION = 1;

// ---- limits (normative) ----------------------------------------------------------------------------------------------

export const MAX_VERB_BYTES = 128;
export const MAX_TITLE_BYTES = 120;
export const MAX_DESCRIPTION_BYTES = 1024;
export const MAX_DEF_PARAMS = 64;
export const MAX_DEF_ALIASES = 16;
export const MAX_DEF_TRAITS = 32;
export const MAX_DEF_CONTEXT = 16;
export const MAX_DEF_SIDE_EFFECTS = 16;
export const MAX_PARAM_PATH_DEPTH = 3;
export const MAX_TRAIT_IMPLIES_DEPTH = 8;
export const MAX_REGISTRY_TRAITS = 512;
/** Packs above this many defs must be sharded (spec section 2.3). */
export const MAX_PACK_DEFS = 4096;

// ---- closed vocabularies ---------------------------------------------------------------------------------------------

/** What an action does. `read_only` is derived (effects = {read}), never declared. */
export const EFFECTS = ['read', 'create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'] as const;
export type Effect = (typeof EFFECTS)[number];

/** Canonical reversibility, ordered reversible < rate_limited < irreversible (the wire vocabulary). */
export const REVERSIBILITY = ['reversible', 'rate_limited', 'irreversible'] as const;
export type Rev = (typeof REVERSIBILITY)[number];
export const REV_RANK: Readonly<Record<Rev, number>> = { reversible: 0, rate_limited: 1, irreversible: 2 };

export const BLAST_RADII = ['one', 'bounded', 'tenant', 'global'] as const;
export type BlastRadius = (typeof BLAST_RADII)[number];
/** Default blast (parts per million) of each radius; `blast.ppm` may only raise it. */
export const BLAST_PPM: Readonly<Record<BlastRadius, number>> = { one: 50_000, bounded: 300_000, tenant: 700_000, global: 1_000_000 };
export const PPM_MAX = 1_000_000;

export const RESOURCE_SCOPES = ['one', 'set', 'tenant', 'global'] as const;
export type ResourceScope = (typeof RESOURCE_SCOPES)[number];
/** A resource scope's default blast radius when the def names none. */
export const SCOPE_BLAST: Readonly<Record<ResourceScope, BlastRadius>> = { one: 'one', set: 'bounded', tenant: 'tenant', global: 'global' };

export const PARAM_TYPES_V1 = ['string', 'integer', 'boolean', 'date', 'datetime', 'duration', 'set', 'array', 'object_ref'] as const;
export type DefParamType = (typeof PARAM_TYPES_V1)[number];

export const SENSITIVITY_LEVELS = ['free', 'material', 'critical'] as const;
export type DefSensitivity = (typeof SENSITIVITY_LEVELS)[number];
export const SENSITIVITY_RANK: Readonly<Record<DefSensitivity, number>> = { free: 0, material: 1, critical: 2 };

export const PROVENANCE_LEVELS = ['first_party', 'tool', 'agent'] as const;
export type ProvenanceMin = (typeof PROVENANCE_LEVELS)[number];

/** Core roles (param semantics). Open registry: `id.<type>` and `x.<ns>.<name>` are also valid roles. */
export const CORE_ROLES = [
  'money.amount', 'money.currency', 'money.fee', 'party.payee', 'party.payer',
  'contact.email', 'contact.phone', 'contact.address', 'person.name', 'person.dob', 'person.national_id',
  'credential.secret', 'credential.token', 'credential.key',
  'path.fs', 'query.sql', 'query.search', 'code.source', 'code.command', 'url.target',
  'text.message', 'text.public', 'time.not_before', 'time.not_after', 'count.limit', 'bytes.size',
] as const;
export type CoreRole = (typeof CORE_ROLES)[number];
export const ID_ROLE_RE = /^id\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$/;
export const CUSTOM_ROLE_RE = /^x\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}$/;

/** Param tags. */
export const PARAM_TAGS = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql'] as const;
export type ParamTag = (typeof PARAM_TAGS)[number];

export const PARAM_FORMATS = ['email', 'url', 'uri_https', 'uuid', 'iban', 'phone_e164', 'cidr', 'iso_country', 'iso_currency', 'semver', 'sha256'] as const;
export const ID_FORMAT_RE = /^id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$/;

export const UNIT_KINDS = ['money', 'count', 'bytes', 'duration', 'ratio'] as const;

export const CAVEAT_KINDS = ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'] as const;
export type CaveatKind = (typeof CAVEAT_KINDS)[number];

/** Context a call must carry. `session_taint_max:<level>` is the one parameterised form. */
export const CONTEXT_KEYS = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'] as const;
export const TAINT_CONTEXT_RE = /^session_taint_max:[a-z_]{1,16}$/;

/** Structural param rules (section 3.3). */
export const PARAM_RULE_IDS = [
  'array_bounded', 'export_bounded', 'id_not_wildcard', 'money_amount_bounded', 'money_has_currency',
  'pay_has_idempotency', 'recipient_param_declared', 'secret_not_logged',
] as const;
export type ParamRuleId = (typeof PARAM_RULE_IDS)[number];

export const IDEMPOTENCY_MODES = ['key_param', 'natural', 'none'] as const;
export const REVIEW_STATES = ['authored', 'unreviewed', 'suggested', 'confirmed'] as const;
export type ReviewState = (typeof REVIEW_STATES)[number];

export const BINDING_KINDS = ['mcp', 'openapi', 'http', 'graphql', 'grpc', 'asyncapi'] as const;

// ---- grammar ---------------------------------------------------------------------------------------------------------

/** `<ns>.<noun...>.<action>`: lowercase [a-z0-9_] segments, 2..6 segments. */
export const VERB_RE = /^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}$/;
/** An alias is a verb-shaped name with 1..6 segments (the NL layer's short ids such as `refund` are one segment). */
export const ALIAS_RE = /^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}$/;
/** A flat or dotted param name, up to depth {@link MAX_PARAM_PATH_DEPTH}. */
export const PARAM_NAME_RE = /^[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$/;
export const TRAIT_ID_RE = /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$/;
export const RESOURCE_TYPE_RE = /^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}$/;

// ---- types -----------------------------------------------------------------------------------------------------------

export type Verb = string;
export type TraitId = string;
export type ParamName = string;
export type ContextKey = string;
export type Role = string;

export const ID_CLASSES = ['digits', 'hex', 'alnum', 'slug', 'uuid', 'any_safe'] as const;
export type IdClass = (typeof ID_CLASSES)[number];
export type IdPattern = '*' | { exact: string } | { prefix: string; class: IdClass; len: [number, number] };

export type UnitDecl =
  | { kind: 'money'; ccy: string | { from: ParamName }; exp: number }
  | { kind: 'count' | 'bytes' | 'duration' | 'ratio' };

export interface ParamDef {
  type: DefParamType;
  role?: Role;
  /** Default true (closed world). */
  required?: boolean;
  values?: string[];
  min?: number;
  max?: number;
  max_len?: number;
  items?: string;
  min_items?: number;
  max_items?: number;
  format?: string;
  unit?: UnitDecl;
  tags?: ParamTag[];
  provenance_min?: ProvenanceMin;
  /** Floor is derived from role/tags; a declared value can only raise it. */
  sensitivity?: DefSensitivity;
  accumulates?: string[];
  default?: unknown;
  principal_neutral_default?: boolean;
  description?: string;
}

export type ReversibilityDecl = Rev | { by: ParamName; map: Record<string, Rev>; default?: Rev };

export interface ReviewRef {
  /** defDigest the review covers. */
  def_digest: string;
  /** Digest of the trait registry the reviewer saw. */
  traits_digest: string;
  /** Digest of the schema-verb facts (see `factsDigest`) of the definition the reviewer saw: a verifier accepts the confirmation only for a verb whose own facts hash to exactly this. */
  facts_digest: string;
  final_traits: TraitId[];
  dismissed: { trait: TraitId; reason: string }[];
  reviewer_kid: string;
  ts: number;
  /** Signature (b64u) by the reviewer key over the attestation body. Verified by the registry layer (A3/A4). */
  sig?: string;
}

/** Where a def's traits came from, beyond the plain declaration (review metadata, not part of the def digest).
 *  `union`: traits added because the suggestion rules flagged them (fail-strict union); dropping one needs a signed dismissal.
 *  `adjudicated`: traits the rules flagged that a person judged absent, so they were left off. */
export interface Provenance {
  union?: TraitId[];
  adjudicated?: TraitId[];
}

export interface ActionDef {
  v: 1;
  kind: typeof ACTION_DEF_KIND;
  verb: Verb;
  aliases?: Verb[];
  title: string;
  description?: string;
  effects: Effect[];
  resource: { type: string; id: IdPattern; scope: ResourceScope };
  params: Record<ParamName, ParamDef>;
  reversibility?: ReversibilityDecl;
  blast?: { radius: BlastRadius; ppm?: number };
  side_effects?: { target: string; kind: Effect }[];
  idempotency?: { mode: 'key_param' | 'natural' | 'none'; param?: ParamName };
  context?: ContextKey[];
  traits?: TraitId[];
  /** `resource`: the audience of a send is the named resource itself (a repository, a channel), so no recipient parameter is needed. */
  audience?: 'resource';
  /** The pack verb that undoes this action (lint LD-010). */
  compensates?: Verb;
  bindings?: {
    mcp?: { tool: string };
    openapi?: { operationId: string; method?: string; path?: string };
    http?: { method: string; path: string };
    graphql?: { op: 'query' | 'mutation' | 'subscription'; field: string };
    grpc?: { service: string; method: string };
    asyncapi?: { channel: string; op: 'send' | 'receive' };
  };
  /** Executable examples (A2 runs them). Not part of the digest. */
  examples?: { params: Record<string, unknown>; under?: unknown; expect: 'allow' | 'escalate' | 'deny' }[];
  review: { state: ReviewState; attestation?: ReviewRef; suggested_by?: unknown; provenance?: Provenance };
  source?: { kind: string; uri: string; spec_digest: string; licence: string; imported_at?: number };
  since?: string;
}

/** A def after {@link normalize}: every default filled, set-like arrays sorted, non-digest members removed. */
export interface NormalizedDef {
  v: 1;
  kind: typeof ACTION_DEF_KIND;
  verb: Verb;
  aliases: Verb[];
  title: string;
  description?: string;
  effects: Effect[];
  resource: { type: string; id: IdPattern; scope: ResourceScope };
  params: Record<ParamName, ParamDef & { required: boolean; sensitivity: DefSensitivity }>;
  reversibility: ReversibilityDecl;
  blast: { radius: BlastRadius; ppm: number };
  side_effects: { target: string; kind: Effect }[];
  idempotency: { mode: 'key_param' | 'natural' | 'none'; param?: ParamName };
  context: ContextKey[];
  traits: TraitId[];
  audience?: 'resource';
  compensates?: Verb;
  bindings: NonNullable<ActionDef['bindings']>;
}

/** The registry-level result of every pure operation that can refuse: a typed error, never a silent default. */
export class ActionKitError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'ActionKitError';
  }
}

export const isReadOnly = (effects: readonly Effect[]): boolean => effects.length > 0 && effects.every((e) => e === 'read');
