/**
 * @atlasauth/pca-scim — SCIM 2.0 provisioning for Proof-Carrying Authority agents.
 *
 * PCA agents are identified by an attested AGENT PASSPORT (`@atlasauth/pca` `passport.ts`): a
 * content-addressed statement of model + weights + operator + prompt/tool manifests, rooted (when
 * `hardware_rooted`) in a hardware attestation. On its own that passport is a parallel island — an
 * enterprise's directory (Microsoft Entra Agent ID, Okta) never learns the agent exists, so it gets no
 * lifecycle (joiner/mover/leaver), no governance, no access reviews.
 *
 * This package bridges the two directions of the emerging IETF SCIM `/Agents` work:
 *   - INBOUND  — expose the passport registry AS a SCIM 2.0 resource server (`scimHandler`), so an IdP
 *                can CRUD agents over the standard SCIM protocol (ListResponse envelope, PATCH ops,
 *                SCIM error schema, correct status codes). A `POST /Agents` REGISTERS a passport.
 *   - OUTBOUND — shape a PCA agent into the push-provisioning body an enterprise directory expects
 *                (`toEntraAgentPayload` / `toOktaScimPayload`), with an injectable fetch to deliver it.
 *
 * The SCIM `Agent` resource is its OWN resource type with its own schema urn (below): like a SCIM
 * `User`, all its attributes live at the top level of that one schema. The full passport rides as a
 * complex `passport` attribute so a passport ↔ SCIM mapping ROUND-TRIPS exactly (`passportToScim` /
 * `scimToProvisioningRequest`). The SCIM `id` is content-addressed to the passport (immutable, per
 * spec); mutable governance attributes (active, displayName, capabilities, owner, externalId, holder)
 * are what PUT/PATCH change — the attested identity itself is never mutated after registration.
 *
 * Dep-free beyond the PCA core: no SCIM framework, no HTTP server, no IdP SDK. The server surface is a
 * framework-agnostic `(ScimRequest) => ScimResponse`, and the push adapters take an injectable fetch,
 * so this runs on Node, an edge runtime or inside any web framework.
 */

import {
  type AgentPassport,
  type PassportIdentity,
  type PassportRegistry,
  buildRegistry,
  hashCanonical,
  issuePassport,
} from '@atlasauth/pca';

// ---------------------------------------------------------------------------
// SCIM schema URNs
// ---------------------------------------------------------------------------

/** The custom SCIM 2.0 resource-schema urn for a PCA agent (its primary schema). */
export const AGENT_SCHEMA_URN = 'urn:ietf:params:scim:schemas:atlas:2.0:Agent';
/** SCIM 2.0 ListResponse message schema. */
export const LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
/** SCIM 2.0 PatchOp message schema (RFC 7644 §3.5.2). */
export const PATCH_OP_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
/** SCIM 2.0 Error message schema (RFC 7644 §3.12). */
export const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
/** SCIM 2.0 resourceType of this resource (used in `meta.resourceType` and the ResourceType endpoint). */
export const AGENT_RESOURCE_TYPE = 'Agent';

// ---------------------------------------------------------------------------
// The SCIM Agent resource
// ---------------------------------------------------------------------------

/** SCIM `meta` complex attribute (RFC 7643 §3.1). */
export interface ScimMeta {
  resourceType: string;
  /** ISO-8601 creation timestamp. */
  created: string;
  /** ISO-8601 last-modified timestamp. */
  lastModified: string;
  /** Absolute (or base-relative) URI of this resource. */
  location: string;
  /** Opaque version / ETag, `W/"…"`. */
  version: string;
}

/**
 * A SCIM 2.0 `Agent` resource. Top-level attributes belong to {@link AGENT_SCHEMA_URN} (like a User's
 * `userName`/`active`). `passport` carries the full attested identity so the mapping is lossless.
 */
export interface ScimAgent {
  schemas: string[];
  /** Server-assigned, immutable id — content-addressed to the passport (equals `passportRef`). */
  id: string;
  /** The provisioning client's own id for this agent (e.g. the IdP object id). */
  externalId?: string;
  /** Human-readable name shown in the directory. */
  displayName: string;
  /** Lifecycle flag: `false` == deprovisioned/suspended (SCIM soft-delete). */
  active: boolean;
  /** The owning principal / organization accountable for the agent (distinct from the model operator). */
  owner: string;
  /** PCA capability verbs / scopes the agent is provisioned for (e.g. `stripe.refund`). */
  capabilities: string[];
  /** The agent's bound holder public key (b64u), when published. */
  holder?: string;
  /** Reference to the backing passport (its content id); equals `id`. */
  passportRef: string;
  /** The full attested passport — the immutable source of truth for the agent's identity. */
  passport: AgentPassport;
  meta: ScimMeta;
}

// ---------------------------------------------------------------------------
// Passport ↔ SCIM mapping
// ---------------------------------------------------------------------------

/** The governance/directory attributes that live ALONGSIDE a passport in its SCIM projection. */
export interface ScimProjection {
  displayName?: string;
  externalId?: string;
  owner: string;
  active?: boolean;
  capabilities?: string[];
  holder?: string;
}

/** Inputs for the SCIM `meta` block (lets a caller preserve `created` across an update). */
export interface MetaInput {
  /** Base URL the resource `location` is built from, e.g. `https://scim.acme.com/scim/v2`. */
  baseUrl?: string;
  /** ISO-8601 creation time; defaults to `now`. */
  created?: string;
  /** ISO-8601 last-modified time; defaults to `now`. */
  lastModified?: string;
  /** Clock for any defaulted timestamp. Default `Date.now`. */
  now?: () => number;
}

function isoAt(now: () => number): string {
  return new Date(now()).toISOString();
}

function trimTrailingSlash(s: string): string {
  return s.replace(/\/+$/, '');
}

/** Build the `meta` block for an Agent. `version` is an ETag over the resource sans `meta`. */
function buildMeta(id: string, resourceSansMeta: unknown, input: MetaInput): ScimMeta {
  const now = input.now ?? Date.now;
  const base = input.baseUrl !== undefined ? trimTrailingSlash(input.baseUrl) : '';
  const location = `${base}/Agents/${encodeURIComponent(id)}`;
  return {
    resourceType: AGENT_RESOURCE_TYPE,
    created: input.created ?? isoAt(now),
    lastModified: input.lastModified ?? isoAt(now),
    location,
    version: `W/"${hashCanonical(resourceSansMeta)}"`,
  };
}

function defaultDisplayName(passport: AgentPassport): string {
  return `${passport.model_id} (${passport.operator})`;
}

/**
 * Project a PCA passport + its governance attributes into a SCIM `Agent` resource. The passport's
 * content id becomes the (immutable) SCIM `id` / `passportRef`. Reverse with
 * {@link scimToProvisioningRequest}.
 */
export function passportToScim(passport: AgentPassport, proj: ScimProjection, meta: MetaInput = {}): ScimAgent {
  const base: Omit<ScimAgent, 'meta'> = {
    schemas: [AGENT_SCHEMA_URN],
    id: passport.id,
    displayName: proj.displayName ?? defaultDisplayName(passport),
    active: proj.active ?? true,
    owner: proj.owner,
    capabilities: proj.capabilities ? [...proj.capabilities] : [],
    passportRef: passport.id,
    passport,
  };
  if (proj.externalId !== undefined) base.externalId = proj.externalId;
  if (proj.holder !== undefined) base.holder = proj.holder;
  return { ...base, meta: buildMeta(passport.id, base, meta) };
}

/**
 * A provisioning request distilled from a SCIM write body: the passport IDENTITY to register plus the
 * governance projection. Feed `identity` to `issuePassport` to recover the passport.
 */
export interface ProvisioningRequest {
  identity: PassportIdentity;
  projection: ScimProjection;
}

// ---- untrusted-body readers ----------------------------------------------

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}
function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}
function asBoolean(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (v === 'true') return true;
  if (v === 'false') return false;
  return undefined;
}
function asStringArray(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === 'string') ? (v as string[]) : undefined;
}

class ScimValueError extends Error {
  constructor(
    public readonly scimType: string,
    detail: string,
  ) {
    super(detail);
    this.name = 'ScimValueError';
  }
}

/** Read a passport identity out of a SCIM body, accepting both a full nested `passport` and flat fields. */
function readIdentity(body: Record<string, unknown>): PassportIdentity {
  const nested = asRecord(body.passport);
  if (nested) {
    const modelId = asString(nested.model_id);
    const operator = asString(nested.operator);
    if (modelId === undefined || operator === undefined) {
      throw new ScimValueError('invalidValue', 'passport.model_id and passport.operator are required');
    }
    const identity: PassportIdentity = {
      model_id: modelId,
      operator,
      hardware_rooted: asBoolean(nested.hardware_rooted) ?? false,
      issued_at: typeof nested.issued_at === 'number' ? nested.issued_at : 0,
    };
    const weights = asString(nested.weights_digest);
    const prompt = asString(nested.system_prompt_digest);
    const tools = asString(nested.tool_manifest_digest);
    const runtime = asString(nested.runtime_measurement);
    const measured = asBoolean(nested.weights_measured);
    if (weights !== undefined) identity.weights_digest = weights;
    if (prompt !== undefined) identity.system_prompt_digest = prompt;
    if (tools !== undefined) identity.tool_manifest_digest = tools;
    if (runtime !== undefined) identity.runtime_measurement = runtime;
    if (measured !== undefined) identity.weights_measured = measured;
    return identity;
  }
  // Flat IdP form: `model` + `operator` custom attributes, hardware defaults to false.
  const modelId = asString(body.model) ?? asString(body.model_id);
  const operator = asString(body.operator);
  if (modelId === undefined || operator === undefined) {
    throw new ScimValueError('invalidValue', 'an Agent requires either a `passport` object or `model` + `operator`');
  }
  return { model_id: modelId, operator, hardware_rooted: asBoolean(body.hardwareRooted) ?? false, issued_at: 0 };
}

function readProjection(body: Record<string, unknown>): ScimProjection {
  const owner = asString(body.owner) ?? asString(body.operator) ?? asString(asRecord(body.passport)?.operator) ?? '';
  const proj: ScimProjection = { owner };
  const displayName = asString(body.displayName);
  const externalId = asString(body.externalId);
  const active = asBoolean(body.active);
  const capabilities = asStringArray(body.capabilities);
  const holder = asString(body.holder);
  if (displayName !== undefined) proj.displayName = displayName;
  if (externalId !== undefined) proj.externalId = externalId;
  if (active !== undefined) proj.active = active;
  if (capabilities !== undefined) proj.capabilities = capabilities;
  if (holder !== undefined) proj.holder = holder;
  return proj;
}

/**
 * Distil a SCIM `Agent` write body (an untrusted value) into a {@link ProvisioningRequest}. Accepts the
 * lossless round-trip form (a nested `passport`) and a flat IdP form (`model` + `operator` + the
 * governance attributes). Throws {@link ScimValueError} on a malformed body.
 */
export function scimToProvisioningRequest(value: unknown): ProvisioningRequest {
  const body = asRecord(value);
  if (!body) throw new ScimValueError('invalidSyntax', 'request body must be a JSON object');
  return { identity: readIdentity(body), projection: readProjection(body) };
}

// ---------------------------------------------------------------------------
// Agent store (pluggable; in-memory default)
// ---------------------------------------------------------------------------

/** A stored agent: its materialized SCIM resource plus the backing passport. */
export interface StoredAgent {
  resource: ScimAgent;
  passport: AgentPassport;
}

/**
 * The persistence seam the SCIM server writes through. Back it with a DB in production; the default
 * {@link createMemoryStore} keeps everything in a `Map`. Implementations only store/fetch — all SCIM
 * semantics (envelopes, status codes, PATCH) live in {@link scimHandler}.
 */
export interface AgentStore {
  all(): StoredAgent[];
  get(id: string): StoredAgent | undefined;
  /** Create or replace by `resource.id`. */
  put(stored: StoredAgent): void;
  /** Remove by id; returns whether a row existed. */
  delete(id: string): boolean;
  /** A read-only passport-registry view over the stored agents. */
  registry(): PassportRegistry;
}

/** The default in-memory {@link AgentStore}. Insertion order is preserved for stable list output. */
export function createMemoryStore(seed: StoredAgent[] = []): AgentStore {
  const byId = new Map<string, StoredAgent>();
  for (const s of seed) byId.set(s.resource.id, s);
  return {
    all: () => [...byId.values()],
    get: (id) => byId.get(id),
    put: (stored) => {
      byId.set(stored.resource.id, stored);
    },
    delete: (id) => byId.delete(id),
    registry: () => buildRegistry([...byId.values()].map((s) => s.passport)),
  };
}

// ---------------------------------------------------------------------------
// SCIM error + ListResponse envelopes
// ---------------------------------------------------------------------------

/** A SCIM 2.0 error response body (RFC 7644 §3.12). `status` is a STRING per spec. */
export interface ScimErrorBody {
  schemas: string[];
  status: string;
  scimType?: string;
  detail: string;
}

/** A SCIM 2.0 ListResponse envelope (RFC 7644 §3.4.2). */
export interface ScimListResponse {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: ScimAgent[];
}

/** Build a SCIM error body. `scimType` is omitted for errors (e.g. 404/500) that have no type. */
export function scimError(status: number, detail: string, scimType?: string): ScimErrorBody {
  const body: ScimErrorBody = { schemas: [ERROR_SCHEMA], status: String(status), detail };
  if (scimType !== undefined) body.scimType = scimType;
  return body;
}

/** Build a SCIM ListResponse over an already-paginated page of resources. */
export function scimListResponse(resources: ScimAgent[], totalResults: number, startIndex: number): ScimListResponse {
  return {
    schemas: [LIST_RESPONSE_SCHEMA],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

// ---------------------------------------------------------------------------
// SCIM filter (the `attr eq "value"` subset)
// ---------------------------------------------------------------------------

/** Attributes the `eq` filter understands. `userName` is an alias for `displayName`. */
const FILTERABLE = new Set(['userName', 'displayName', 'externalId', 'id', 'active', 'owner']);

interface EqFilter {
  attr: string;
  value: string | boolean;
}

/** Parse the SCIM `attr eq "value"` / `attr eq true|false` subset. Throws {@link ScimValueError}. */
export function parseFilter(filter: string): EqFilter {
  const m = /^\s*(\w+)\s+eq\s+(?:"((?:[^"\\]|\\.)*)"|(true|false))\s*$/i.exec(filter);
  if (!m) throw new ScimValueError('invalidFilter', `unsupported filter (only \`attr eq "value"\` is supported): ${filter}`);
  const attr = m[1] as string;
  if (!FILTERABLE.has(attr)) throw new ScimValueError('invalidFilter', `filter attribute not supported: ${attr}`);
  if (m[3] !== undefined) return { attr, value: m[3].toLowerCase() === 'true' };
  const raw = m[2] ?? '';
  return { attr, value: raw.replace(/\\(.)/g, '$1') };
}

function matchesFilter(agent: ScimAgent, f: EqFilter): boolean {
  switch (f.attr) {
    case 'userName':
    case 'displayName':
      return agent.displayName === f.value;
    case 'externalId':
      return agent.externalId === f.value;
    case 'id':
      return agent.id === f.value;
    case 'owner':
      return agent.owner === f.value;
    case 'active':
      return agent.active === f.value;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// PATCH (RFC 7644 §3.5.2)
// ---------------------------------------------------------------------------

/** One PATCH operation. `path` is optional for `add`/`replace` with an object `value`. */
export interface PatchOperation {
  op: 'add' | 'replace' | 'remove';
  path?: string;
  value?: unknown;
}

/** The mutable governance attributes PUT/PATCH may change (identity/id are immutable). */
const MUTABLE_PATHS = new Set(['active', 'displayName', 'externalId', 'owner', 'capabilities', 'holder']);

function readPatchOps(value: unknown): PatchOperation[] {
  const body = asRecord(value);
  if (!body) throw new ScimValueError('invalidSyntax', 'PATCH body must be a JSON object');
  const ops = body.Operations;
  if (!Array.isArray(ops) || ops.length === 0) throw new ScimValueError('invalidValue', 'PATCH requires a non-empty Operations array');
  return ops.map((raw) => {
    const o = asRecord(raw);
    const op = asString(o?.op)?.toLowerCase();
    if (op !== 'add' && op !== 'replace' && op !== 'remove') {
      throw new ScimValueError('invalidValue', `unsupported PATCH op: ${String(o?.op)}`);
    }
    const parsed: PatchOperation = { op };
    const path = asString(o?.path);
    if (path !== undefined) parsed.path = path;
    if (o && 'value' in o) parsed.value = o.value;
    return parsed;
  });
}

/** A shallow, typed copy of the mutable projection carried by a resource (for re-materialization). */
function projectionOf(resource: ScimAgent): ScimProjection {
  const proj: ScimProjection = { owner: resource.owner, active: resource.active, capabilities: [...resource.capabilities] };
  if (resource.displayName !== undefined) proj.displayName = resource.displayName;
  if (resource.externalId !== undefined) proj.externalId = resource.externalId;
  if (resource.holder !== undefined) proj.holder = resource.holder;
  return proj;
}

function applyScalar(proj: ScimProjection, path: string, op: PatchOperation['op'], value: unknown): void {
  if (path === 'active') {
    if (op === 'remove') {
      proj.active = true;
      return;
    }
    const b = asBoolean(value);
    if (b === undefined) throw new ScimValueError('invalidValue', '`active` must be a boolean');
    proj.active = b;
    return;
  }
  if (path === 'capabilities') {
    if (op === 'remove') {
      proj.capabilities = [];
      return;
    }
    const arr = asStringArray(value);
    if (arr === undefined) throw new ScimValueError('invalidValue', '`capabilities` must be a string array');
    proj.capabilities = op === 'add' ? [...(proj.capabilities ?? []), ...arr] : arr;
    return;
  }
  // displayName / externalId / owner / holder — string scalars.
  if (op === 'remove') {
    if (path === 'displayName' || path === 'owner') throw new ScimValueError('mutability', `\`${path}\` cannot be removed`);
    if (path === 'externalId') delete proj.externalId;
    if (path === 'holder') delete proj.holder;
    return;
  }
  const s = asString(value);
  if (s === undefined) throw new ScimValueError('invalidValue', `\`${path}\` must be a string`);
  if (path === 'displayName') proj.displayName = s;
  else if (path === 'externalId') proj.externalId = s;
  else if (path === 'owner') proj.owner = s;
  else if (path === 'holder') proj.holder = s;
}

/** Apply a parsed PATCH op onto a projection. A pathless add/replace merges an object `value`. */
function applyPatchOp(proj: ScimProjection, op: PatchOperation): void {
  if (op.path === undefined) {
    if (op.op === 'remove') throw new ScimValueError('noTarget', 'a `remove` op requires a `path`');
    const obj = asRecord(op.value);
    if (!obj) throw new ScimValueError('invalidValue', 'a pathless PATCH value must be an object');
    for (const key of Object.keys(obj)) {
      if (!MUTABLE_PATHS.has(key)) throw new ScimValueError('mutability', `attribute is immutable or unknown: ${key}`);
      applyScalar(proj, key, 'replace', obj[key]);
    }
    return;
  }
  if (!MUTABLE_PATHS.has(op.path)) throw new ScimValueError('mutability', `attribute is immutable or unknown: ${op.path}`);
  applyScalar(proj, op.path, op.op, op.value);
}

// ---------------------------------------------------------------------------
// The framework-agnostic SCIM server surface
// ---------------------------------------------------------------------------

/** The subset of an inbound HTTP request the SCIM handler needs, already routed under `/Agents`. */
export interface ScimRequest {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** The target resource id, for `/Agents/{id}` operations. Absent for the collection. */
  id?: string;
  /** Query string params (`filter`, `startIndex`, `count`). */
  query?: Record<string, string | undefined>;
  /** Parsed JSON body for writes. */
  body?: unknown;
}

/** The handler's response: status, a JSON body, and SCIM-appropriate headers. */
export interface ScimResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
}

export interface ScimHandlerOptions {
  /** Base URL for `meta.location`, e.g. `https://scim.acme.com/scim/v2`. */
  baseUrl?: string;
  /** Clock for `meta` timestamps. Default `Date.now`. */
  now?: () => number;
}

const SCIM_CONTENT_TYPE = 'application/scim+json';

function jsonResponse(status: number, body: unknown, extra?: Record<string, string>): ScimResponse {
  return { status, body, headers: { 'content-type': SCIM_CONTENT_TYPE, ...extra } };
}

function errorResponse(status: number, detail: string, scimType?: string): ScimResponse {
  return jsonResponse(status, scimError(status, detail, scimType));
}

function resourceResponse(status: number, resource: ScimAgent): ScimResponse {
  return jsonResponse(status, resource, { location: resource.meta.location, etag: resource.meta.version });
}

function parseIntParam(v: string | undefined, fallback: number): number {
  if (v === undefined) return fallback;
  const n = Number(v);
  return Number.isInteger(n) ? n : fallback;
}

/**
 * Build a framework-agnostic SCIM 2.0 `/Agents` handler over an {@link AgentStore}. Returns a
 * `(ScimRequest) => ScimResponse` implementing GET (list + `eq` filter + pagination), GET by id,
 * POST (register a passport), PUT (replace governance attributes), PATCH (RFC 7644 ops) and DELETE —
 * each with SCIM-correct JSON, status codes and envelopes. Wire it into Express/Fastify/Hono/a Worker
 * by translating that framework's req/res to/from {@link ScimRequest}/{@link ScimResponse}.
 */
export function scimHandler(store: AgentStore, options: ScimHandlerOptions = {}): (req: ScimRequest) => ScimResponse {
  const metaInput = (): MetaInput => {
    const input: MetaInput = {};
    if (options.baseUrl !== undefined) input.baseUrl = options.baseUrl;
    if (options.now !== undefined) input.now = options.now;
    return input;
  };

  const handleList = (query: Record<string, string | undefined> | undefined): ScimResponse => {
    let items = store.all().map((s) => s.resource);
    const filter = query?.filter;
    if (filter !== undefined && filter !== '') {
      let parsed: EqFilter;
      try {
        parsed = parseFilter(filter);
      } catch (e) {
        if (e instanceof ScimValueError) return errorResponse(400, e.message, e.scimType);
        throw e;
      }
      items = items.filter((a) => matchesFilter(a, parsed));
    }
    const total = items.length;
    const startIndex = Math.max(1, parseIntParam(query?.startIndex, 1));
    const count = query?.count === undefined ? undefined : Math.max(0, parseIntParam(query.count, total));
    const page = count === undefined ? items.slice(startIndex - 1) : items.slice(startIndex - 1, startIndex - 1 + count);
    return jsonResponse(200, scimListResponse(page, total, startIndex));
  };

  const handleCreate = (body: unknown): ScimResponse => {
    let req: ProvisioningRequest;
    try {
      req = scimToProvisioningRequest(body);
    } catch (e) {
      if (e instanceof ScimValueError) return errorResponse(400, e.message, e.scimType);
      throw e;
    }
    const passport = issuePassport(req.identity);
    if (store.get(passport.id)) {
      return errorResponse(409, `an agent with this attested identity already exists (id ${passport.id})`, 'uniqueness');
    }
    const resource = passportToScim(passport, req.projection, metaInput());
    store.put({ resource, passport });
    return resourceResponse(201, resource);
  };

  const rematerialize = (existing: StoredAgent, proj: ScimProjection): ScimAgent => {
    const meta = metaInput();
    meta.created = existing.resource.meta.created;
    return passportToScim(existing.passport, proj, meta);
  };

  const handleReplace = (id: string, body: unknown): ScimResponse => {
    const existing = store.get(id);
    if (!existing) return errorResponse(404, `Agent ${id} not found`);
    const body0 = asRecord(body);
    if (!body0) return errorResponse(400, 'request body must be a JSON object', 'invalidSyntax');
    let proj: ScimProjection;
    try {
      proj = readProjection(body0);
    } catch (e) {
      if (e instanceof ScimValueError) return errorResponse(400, e.message, e.scimType);
      throw e;
    }
    // PUT replaces governance attributes; owner defaults to the existing one when omitted.
    if (proj.owner === '') proj.owner = existing.resource.owner;
    const resource = rematerialize(existing, proj);
    store.put({ resource, passport: existing.passport });
    return resourceResponse(200, resource);
  };

  const handlePatch = (id: string, body: unknown): ScimResponse => {
    const existing = store.get(id);
    if (!existing) return errorResponse(404, `Agent ${id} not found`);
    let ops: PatchOperation[];
    const proj = projectionOf(existing.resource);
    try {
      ops = readPatchOps(body);
      for (const op of ops) applyPatchOp(proj, op);
    } catch (e) {
      if (e instanceof ScimValueError) return errorResponse(400, e.message, e.scimType);
      throw e;
    }
    const resource = rematerialize(existing, proj);
    store.put({ resource, passport: existing.passport });
    return resourceResponse(200, resource);
  };

  const handleDelete = (id: string): ScimResponse => {
    const removed = store.delete(id);
    if (!removed) return errorResponse(404, `Agent ${id} not found`);
    return { status: 204, body: undefined, headers: {} };
  };

  const handleGetOne = (id: string): ScimResponse => {
    const existing = store.get(id);
    if (!existing) return errorResponse(404, `Agent ${id} not found`);
    return resourceResponse(200, existing.resource);
  };

  return (req: ScimRequest): ScimResponse => {
    switch (req.method) {
      case 'GET':
        return req.id === undefined ? handleList(req.query) : handleGetOne(req.id);
      case 'POST':
        if (req.id !== undefined) return errorResponse(405, 'POST is not allowed on an individual Agent');
        return handleCreate(req.body);
      case 'PUT':
        if (req.id === undefined) return errorResponse(405, 'PUT requires an Agent id');
        return handleReplace(req.id, req.body);
      case 'PATCH':
        if (req.id === undefined) return errorResponse(405, 'PATCH requires an Agent id');
        return handlePatch(req.id, req.body);
      case 'DELETE':
        if (req.id === undefined) return errorResponse(405, 'DELETE requires an Agent id');
        return handleDelete(req.id);
      default:
        return errorResponse(405, `method not allowed: ${String(req.method)}`);
    }
  };
}

// ---------------------------------------------------------------------------
// Push-provision adapters — Microsoft Entra Agent ID / Okta
// ---------------------------------------------------------------------------

/** Microsoft Entra extension schema urn for the agent attributes (illustrative/structural). */
export const ENTRA_AGENT_EXTENSION_URN = 'urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent';
/** Okta custom-app extension schema urn for the agent attributes (illustrative/structural). */
export const OKTA_AGENT_EXTENSION_URN = 'urn:okta:scim:schemas:custom:1.0:Agent';

/** The attributes an enterprise directory carries for a PCA agent, under its own extension namespace. */
export interface AgentExtensionAttributes {
  owner: string;
  model: string;
  operator: string;
  hardwareRooted: boolean;
  capabilities: string[];
  passportRef: string;
  holder?: string;
}

function extensionAttributes(agent: ScimAgent): AgentExtensionAttributes {
  const attrs: AgentExtensionAttributes = {
    owner: agent.owner,
    model: agent.passport.model_id,
    operator: agent.passport.operator,
    hardwareRooted: agent.passport.hardware_rooted,
    capabilities: [...agent.capabilities],
    passportRef: agent.passportRef,
  };
  if (agent.holder !== undefined) attrs.holder = agent.holder;
  return attrs;
}

/** The SCIM body pushed to Microsoft Entra Agent ID's provisioning endpoint. */
export interface EntraAgentPayload {
  schemas: string[];
  externalId: string;
  displayName: string;
  active: boolean;
  [ENTRA_AGENT_EXTENSION_URN]: AgentExtensionAttributes;
}

/** The SCIM body pushed to Okta's provisioning endpoint (User-shaped with a custom agent extension). */
export interface OktaScimPayload {
  schemas: string[];
  userName: string;
  externalId: string;
  displayName: string;
  active: boolean;
  [OKTA_AGENT_EXTENSION_URN]: AgentExtensionAttributes;
}

/**
 * Shape a PCA agent into the outbound provisioning body for Microsoft Entra Agent ID: a SCIM 2.0
 * resource whose agent-specific attributes sit under the Microsoft extension namespace. `externalId`
 * carries the content-addressed passport id so Entra can correlate the directory object to the agent.
 */
export function toEntraAgentPayload(agent: ScimAgent): EntraAgentPayload {
  return {
    schemas: [AGENT_SCHEMA_URN, ENTRA_AGENT_EXTENSION_URN],
    externalId: agent.externalId ?? agent.passportRef,
    displayName: agent.displayName,
    active: agent.active,
    [ENTRA_AGENT_EXTENSION_URN]: extensionAttributes(agent),
  };
}

/**
 * Shape a PCA agent into the outbound provisioning body for Okta: a SCIM 2.0 resource whose `userName`
 * is the stable passport id and whose agent attributes sit under an Okta custom-app extension schema.
 */
export function toOktaScimPayload(agent: ScimAgent): OktaScimPayload {
  return {
    schemas: [AGENT_SCHEMA_URN, OKTA_AGENT_EXTENSION_URN],
    userName: agent.passportRef,
    externalId: agent.externalId ?? agent.passportRef,
    displayName: agent.displayName,
    active: agent.active,
    [OKTA_AGENT_EXTENSION_URN]: extensionAttributes(agent),
  };
}

/** Minimal structural shim of `fetch` so the push helper runs on any runtime without a global fetch. */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** Where and how to push an outbound provisioning body. */
export interface PushTarget {
  /** The directory's SCIM endpoint, e.g. `https://graph.microsoft.com/v1.0/…` or an Okta `/Users`. */
  endpoint: string;
  /** Bearer token for the directory. */
  token: string;
  /** Injected fetch; defaults to the global `fetch` when present. */
  fetch?: FetchLike;
}

/** The outcome of a push-provision call. */
export interface PushResult {
  ok: boolean;
  status: number;
  body: unknown;
}

/** POST an already-shaped provisioning payload to a directory endpoint (injectable fetch). */
export async function pushProvision(payload: EntraAgentPayload | OktaScimPayload, target: PushTarget): Promise<PushResult> {
  const f = target.fetch ?? (globalThis as { fetch?: FetchLike }).fetch;
  if (!f) throw new Error('pushProvision: no fetch available — pass one explicitly');
  const res = await f(target.endpoint, {
    method: 'POST',
    headers: { authorization: `Bearer ${target.token}`, 'content-type': SCIM_CONTENT_TYPE },
    body: JSON.stringify(payload),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { ok: res.ok, status: res.status, body };
}

/** Shape a PCA agent for Entra and push it (convenience over {@link toEntraAgentPayload} + {@link pushProvision}). */
export function pushToEntra(agent: ScimAgent, target: PushTarget): Promise<PushResult> {
  return pushProvision(toEntraAgentPayload(agent), target);
}

/** Shape a PCA agent for Okta and push it (convenience over {@link toOktaScimPayload} + {@link pushProvision}). */
export function pushToOkta(agent: ScimAgent, target: PushTarget): Promise<PushResult> {
  return pushProvision(toOktaScimPayload(agent), target);
}

// ---------------------------------------------------------------------------
// Re-exports from the PCA core (so a provisioner only needs this package)
// ---------------------------------------------------------------------------

export { issuePassport, passportFingerprint, buildRegistry } from '@atlasauth/pca';
export type { AgentPassport, PassportIdentity, PassportRegistry } from '@atlasauth/pca';
