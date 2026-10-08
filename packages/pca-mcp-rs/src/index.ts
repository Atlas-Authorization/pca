/**
 * MCP authorization RESOURCE SERVER for the 2026-07-28 revision, backed by Proof-Carrying Authority.
 *
 * This is the RS SIDE of the de-facto agent↔tool wire. Where `@atlasauth/pca-mcp` wraps a tool handler on
 * the CLIENT so each call carries a PCActn, THIS package makes the server that RECEIVES those calls a
 * correct OAuth-2.1 resource server per the MCP authorization revision of 2026-07-28 — the revision that
 *
 *   • keeps RFC 9728 Protected Resource Metadata discovery and the `WWW-Authenticate: Bearer
 *     resource_metadata="…"` 401 challenge (unchanged since 2025-11-25),
 *   • REPLACES Dynamic Client Registration with Client-ID Metadata Documents (CIMD): a client's
 *     `client_id` IS an https URL that dereferences to its own RFC-7591-shaped metadata document, so a
 *     resource/authorization server never has to register a client out of band,
 *   • REQUIRES RFC 8707 resource-indicator enforcement (a credential is bound to exactly one resource
 *     server, so a token minted for RS-A cannot be replayed to RS-B), and
 *   • REQUIRES RFC 9207 `iss` authorization-server validation (a token whose issuer is not an expected
 *     AS is rejected — the authorization-server mix-up defense),
 *   • layers OAuth step-up (RFC 9470, `insufficient_user_authentication`) for actions that need a human.
 *
 * The AUTHORITY here is the PCActn, not a bearer token: a PCActn's SIGNED `aud` is the RFC 8707 resource
 * binding (it cannot be spoofed the way a `resource` indicator can), its capability chain roots at a
 * pinned issuer (the RFC 9207 anchor), and its signed caveats carry the scope grant that NARROWS down the
 * delegation chain. `authorizeRequest` is the admission check that verifies all of this through the PCA
 * core (`verifyPCActnCore`) and FAILS CLOSED: any missing / mismatched / unverifiable element denies with
 * the correct 401/403 + `WWW-Authenticate` challenge. Step-up is wired to PCA's FROST/CIBA threshold
 * surface: a tool that needs escalation returns a 401 the MCP client drives to collect a guardian /
 * principal co-sign, then re-presents a PCActn carrying the threshold.
 *
 * Specs implemented (cited per export):
 *  - RFC 9728  — OAuth 2.0 Protected Resource Metadata       (https://www.rfc-editor.org/rfc/rfc9728)
 *  - RFC 8707  — Resource Indicators for OAuth 2.0            (https://www.rfc-editor.org/rfc/rfc8707)
 *  - RFC 9207  — OAuth 2.0 Authorization Server Issuer Id     (https://www.rfc-editor.org/rfc/rfc9207)
 *  - RFC 6750  — OAuth 2.0 Bearer Token Usage (the challenge shape)
 *  - RFC 7235  — HTTP/1.1 Authentication (multiple comma-separated challenges in one header)
 *  - RFC 9470  — OAuth 2.0 Step Up Authentication Challenge   (https://www.rfc-editor.org/rfc/rfc9470)
 *  - Client-ID Metadata Documents (CIMD) — the DCR replacement adopted by MCP authorization 2026-07-28.
 *  - MCP Authorization, protocol revision 2026-07-28.
 *
 * Pure: every export is I/O-free and runtime-neutral (no Node builtins, no framework) so the same code
 * mounts on Express / Fastify / Hono / Next / Fetch or any router. The PRM + CIMD documents are PUBLIC,
 * non-secret configuration. This package does NOT import or modify `@atlasauth/pca-oauth` or
 * `@atlasauth/pca-mcp`; it mirrors their conventions and verifies through the shared `@atlasauth/pca` core.
 */

import {
  buildDiscoveryDocument,
  decodePCActn,
  requiredThreshold,
  unb64u,
  verifyPCActnCore,
  WELL_KNOWN_PCA_PATH,
  type Capability,
  type CapabilityChain,
  type Caveat,
  type CheckStatus,
  type PcaDiscoveryDocument,
  type PCActn,
  type RequiredThreshold,
  type SignerRole,
} from '@atlasauth/pca';

/**
 * RFC 9728 §3: the Protected Resource Metadata is published at the well-known URI formed by inserting
 * `/.well-known/oauth-protected-resource` into the resource identifier's path. The MCP 2026-07-28 client
 * fetches it after a 401 to discover this RS's authorization servers and scopes.
 */
export const WELL_KNOWN_OAUTH_PRM = '/.well-known/oauth-protected-resource';

/** RFC 6750 §2 token-presentation methods an RFC 9728 `bearer_methods_supported` may advertise. */
export type BearerMethod = 'header' | 'body' | 'query';

// ---------------------------------------------------------------------------------------------------
// Header-value hygiene (RFC 7235 quoted auth-params): reject control / quote chars to stop injection.
// ---------------------------------------------------------------------------------------------------

function quotedParam(value: string): string {
  if (/["\r\n]/.test(value)) {
    throw new Error('pca-mcp-rs: a WWW-Authenticate parameter value may not contain a quote or newline');
  }
  return value;
}

// ===================================================================================================
// 1. RFC 9728 — Protected Resource Metadata
// ===================================================================================================

/**
 * The PCA extension block embedded in the PRM (RFC 9728 §3.1 permits collision-resistant extra params):
 * a generic OAuth/MCP client ignores it, while a PCA-aware client learns this RS verifies a PCActn, which
 * header it rides, and where the sibling `.well-known/pca-configuration` lives — one-fetch auto-config.
 */
export interface PcaResourceExtension {
  /** The HTTP header the PCActn is read from (base64url value). Mirrors the discovery doc `action_header`. */
  pca_action_header: string;
  /** Accepted PCActn signature suites (e.g. ["ed25519","hybrid-ed25519-ml-dsa-65"]). */
  pca_signature_suites: string[];
  /** PCActn wire version(s) this RS accepts. */
  pca_versions: number[];
  /** Absolute URL of this RS's `.well-known/pca-configuration`. */
  pca_configuration_endpoint: string;
  /** The embedded PCA discovery document (from `buildDiscoveryDocument`), for one-fetch auto-config. */
  pca: PcaDiscoveryDocument;
}

/** RFC 9728 §3 Protected Resource Metadata, as required by MCP authorization 2026-07-28, + the PCA block. */
export interface ProtectedResourceMetadata extends PcaResourceExtension {
  /**
   * RFC 9728 §3.1 `resource` (REQUIRED): this protected resource's identifier. For a PCA RS this IS the
   * value a PCActn's signed `aud` must equal (RFC 8707), so the OAuth advertisement and the cryptographic
   * audience are one string and cannot drift.
   */
  resource: string;
  /**
   * RFC 9728 §3.1 `authorization_servers`: the issuer identifiers of the ASs that may issue credentials
   * for this RS. This is the SAME allowlist `authorizeRequest` enforces as the RFC 9207 mix-up defense —
   * discovery advertises exactly what admission enforces.
   */
  authorization_servers: string[];
  /** RFC 9728 §3.1 `bearer_methods_supported`: how a bearer credential may be presented. */
  bearer_methods_supported: BearerMethod[];
  /** RFC 9728 §3.1 `scopes_supported`: the full scope vocabulary this RS recognizes. */
  scopes_supported: string[];
  /** RFC 9728 §3.1 `resource_name` (OPTIONAL). */
  resource_name?: string;
  /** RFC 9728 §3.1 `resource_documentation` (OPTIONAL). */
  resource_documentation?: string;
  /** RFC 9728 §3.1 `resource_signing_alg_values_supported` (OPTIONAL). */
  resource_signing_alg_values_supported?: string[];
  /**
   * CIMD advertisement (MCP 2026-07-28): this RS/AS accepts Client-ID Metadata Documents in place of
   * Dynamic Client Registration. Always `true` for a 2026-07-28 PCA RS.
   */
  client_id_metadata_document_supported: true;
}

export interface ProtectedResourceMetadataOptions {
  /** REQUIRED: the resource identifier — the SAME string a PCActn's signed `aud` must equal. */
  resource: string;
  /** REQUIRED (RFC 9207 anchor): issuer identifiers of the ASs this RS trusts. */
  authorizationServers: string[];
  /** REQUIRED: the full scope vocabulary this RS recognizes. */
  scopesSupported: string[];
  /** Token-presentation methods. Default `['header']` (a PCActn rides the `PCA-Action` header). */
  bearerMethodsSupported?: BearerMethod[];
  resourceName?: string;
  resourceDocumentation?: string;
  resourceSigningAlgValuesSupported?: string[];
  /** Absolute URL of this RS's `.well-known/pca-configuration` (defaults to `<resource>/.well-known/pca-configuration`). */
  pcaConfigurationEndpoint?: string;

  // --- embedded PCA discovery block (forwarded to `buildDiscoveryDocument`) ---
  signatureSuites?: string[];
  pcaVersions?: number[];
  actionHeader?: string;
  requiredChecks?: string[];
  endpoints?: PcaDiscoveryDocument['endpoints'];
  trustedRoots?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * RFC 9728 — build the Protected Resource Metadata served at {@link WELL_KNOWN_OAUTH_PRM}. The `resource`
 * is this RS's identifier (= the PCActn audience), `authorization_servers` is the RFC 9207 trusted-issuer
 * allowlist, and `scopes_supported` is the scope vocabulary. The embedded PCA discovery doc + the
 * `.well-known/pca-configuration` pointer auto-configure a PCA-aware client. Throws on an empty `resource`
 * or an absent/empty `authorization_servers`.
 */
export function protectedResourceMetadata(opts: ProtectedResourceMetadataOptions): ProtectedResourceMetadata {
  if (typeof opts.resource !== 'string' || opts.resource.length === 0) {
    throw new Error('protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required');
  }
  if (!Array.isArray(opts.authorizationServers) || opts.authorizationServers.length === 0) {
    throw new Error('protectedResourceMetadata: `authorizationServers` is required (RFC 9207 mix-up defense anchor)');
  }
  if (!Array.isArray(opts.scopesSupported)) {
    throw new Error('protectedResourceMetadata: `scopesSupported` must be an array');
  }
  // One source of truth: the discovery doc's `audience` IS the OAuth `resource`.
  const discovery = buildDiscoveryDocument({
    audience: opts.resource,
    ...(opts.signatureSuites ? { signatureSuites: opts.signatureSuites } : {}),
    ...(opts.pcaVersions ? { pcaVersions: opts.pcaVersions } : {}),
    ...(opts.actionHeader ? { actionHeader: opts.actionHeader } : {}),
    ...(opts.requiredChecks ? { requiredChecks: opts.requiredChecks } : {}),
    ...(opts.endpoints ? { endpoints: opts.endpoints } : {}),
    ...(opts.trustedRoots ? { trustedRoots: opts.trustedRoots } : {}),
    ...(opts.metadata ? { metadata: opts.metadata } : {}),
  });
  const pcaConfigurationEndpoint =
    opts.pcaConfigurationEndpoint ?? opts.resource.replace(/\/+$/, '') + WELL_KNOWN_PCA_PATH;

  const doc: ProtectedResourceMetadata = {
    resource: opts.resource,
    authorization_servers: [...opts.authorizationServers],
    bearer_methods_supported: opts.bearerMethodsSupported ? [...opts.bearerMethodsSupported] : ['header'],
    scopes_supported: [...opts.scopesSupported],
    client_id_metadata_document_supported: true,
    pca_action_header: discovery.action_header,
    pca_signature_suites: [...discovery.signature_suites],
    pca_versions: [...discovery.pca_versions],
    pca_configuration_endpoint: pcaConfigurationEndpoint,
    pca: discovery,
    ...(opts.resourceName ? { resource_name: opts.resourceName } : {}),
    ...(opts.resourceDocumentation ? { resource_documentation: opts.resourceDocumentation } : {}),
    ...(opts.resourceSigningAlgValuesSupported
      ? { resource_signing_alg_values_supported: [...opts.resourceSigningAlgValuesSupported] }
      : {}),
  };
  return doc;
}

/** Framework-agnostic glue — the body + path to serve the RFC 9728 PRM document. */
export function prmHandler(opts: ProtectedResourceMetadataOptions): { path: string; body: ProtectedResourceMetadata } {
  return { path: WELL_KNOWN_OAUTH_PRM, body: protectedResourceMetadata(opts) };
}

// ===================================================================================================
// 2. MCP 2026-07-28 + RFC 6750/7235/9470 — the WWW-Authenticate challenge
// ===================================================================================================

export interface WwwAuthenticateChallengeOptions {
  /** REQUIRED: the absolute URL where {@link protectedResourceMetadata} is served (RFC 9728 pointer). */
  resourceMetadataUrl: string;
  /** RFC 6750 §3 `error` (e.g. "invalid_token", "insufficient_scope", "insufficient_user_authentication"). */
  error?: string;
  /** RFC 6750 §3 `error_description`. */
  errorDescription?: string;
  /** RFC 6750 §3 `scope` the client would need (used with `insufficient_scope`). */
  scope?: string;
  /** RFC 9470 `acr_values` — the authentication-context the client must reach (step-up). */
  acrValues?: string;
  /** RFC 9470 `max_age` — freshness the client must satisfy (step-up). */
  maxAge?: number;
  /** Bearer realm (optional). */
  realm?: string;
  /**
   * Append a PCA step-up challenge as a second RFC-7235 challenge so a PCA-aware client gets the FROST/CIBA
   * requirement in the same header. Ignored unless set. The structured {@link StepUpChallenge} carries the
   * same information for the MCP client to drive.
   */
  pcaStepUp?: StepUpChallenge;
}

/**
 * MCP 2026-07-28 + RFC 6750 — build the `WWW-Authenticate` value a PCA resource server returns on a 401.
 * The MCP spec requires `Bearer resource_metadata="<PRM URL>"` pointing at the RFC 9728 document so a
 * generic MCP/OAuth client can discover the RS. `error`/`error_description`/`scope` follow RFC 6750;
 * `acr_values`/`max_age` follow RFC 9470 for a step-up challenge. When `pcaStepUp` is given, a second
 * `PCA-StepUp` challenge is appended (RFC 7235 allows multiple comma-separated challenges) carrying the
 * tier, required co-signer roles and the FROST/CIBA step-up endpoint. Throws on an empty metadata URL or
 * any header-injecting parameter value.
 */
export function wwwAuthenticateChallenge(opts: WwwAuthenticateChallengeOptions): string {
  if (typeof opts.resourceMetadataUrl !== 'string' || opts.resourceMetadataUrl.length === 0) {
    throw new Error('wwwAuthenticateChallenge: resourceMetadataUrl is required');
  }
  const params: string[] = [];
  if (opts.realm) params.push(`realm="${quotedParam(opts.realm)}"`);
  params.push(`resource_metadata="${quotedParam(opts.resourceMetadataUrl)}"`);
  if (opts.error) params.push(`error="${quotedParam(opts.error)}"`);
  if (opts.errorDescription) params.push(`error_description="${quotedParam(opts.errorDescription)}"`);
  if (opts.scope) params.push(`scope="${quotedParam(opts.scope)}"`);
  if (opts.acrValues) params.push(`acr_values="${quotedParam(opts.acrValues)}"`);
  if (typeof opts.maxAge === 'number' && Number.isFinite(opts.maxAge)) params.push(`max_age=${Math.max(0, Math.trunc(opts.maxAge))}`);
  const challenges: string[] = [`Bearer ${params.join(', ')}`];

  if (opts.pcaStepUp) {
    const su = opts.pcaStepUp;
    const suParams: string[] = [
      `realm="${quotedParam(opts.realm ?? 'pca')}"`,
      `tier="${quotedParam(String(su.tier))}"`,
      `roles="${quotedParam(su.requiredRoles.join(' '))}"`,
    ];
    if (su.stepUpEndpoint) suParams.push(`stepup_uri="${quotedParam(su.stepUpEndpoint)}"`);
    if (su.acr) suParams.push(`acr="${quotedParam(su.acr)}"`);
    challenges.push(`PCA-StepUp ${suParams.join(', ')}`);
  }
  return challenges.join(', ');
}

// ===================================================================================================
// 3. Client-ID Metadata Documents (CIMD) — the DCR replacement
// ===================================================================================================

/**
 * A Client-ID Metadata Document (MCP 2026-07-28). The client's `client_id` IS an https URL that
 * dereferences to this document; its fields mirror the OAuth 2.0 Dynamic Client Registration metadata
 * (RFC 7591). Because the document lives at the `client_id` URL, a resource/authorization server learns
 * the client's redirect URIs and metadata WITHOUT an out-of-band registration — DCR is not needed.
 */
export interface ClientIdMetadataDocument {
  /** MUST be the https URL this document is served from (self-referential — the CIMD integrity rule). */
  client_id: string;
  /** REQUIRED: the client's redirect URIs. Must be non-empty and each a valid, safe redirect URI. */
  redirect_uris: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
}

export interface ClientIdMetadataDocumentOptions {
  /** The https URL that is the `client_id` (and where this document is published). */
  clientId: string;
  /** The client's redirect URIs (non-empty). */
  redirectUris: string[];
  clientName?: string;
  clientUri?: string;
  logoUri?: string;
  scope?: string;
  contacts?: string[];
  tosUri?: string;
  policyUri?: string;
  grantTypes?: string[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: string;
}

function isHttpsUrl(s: unknown): s is string {
  if (typeof s !== 'string' || s.length === 0) return false;
  try {
    return new URL(s).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Is `uri` a safe OAuth redirect target? https is always allowed; plain http is allowed ONLY for loopback
 * (localhost / 127.0.0.1 / [::1]) per the native-app BCP (RFC 8252); a non-http custom scheme (e.g.
 * `myapp://cb`) is allowed for native apps. Anything else (a non-loopback http URL, an unparseable value)
 * is rejected.
 */
function isAllowedRedirectUri(uri: unknown): uri is string {
  if (typeof uri !== 'string' || uri.length === 0) return false;
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol === 'https:') return true;
  if (u.protocol === 'http:') {
    const h = u.hostname;
    return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1';
  }
  // A non-http(s) custom scheme (native app redirect) — allowed.
  return u.protocol !== 'http:' && u.protocol.length > 0;
}

/**
 * Build a well-formed Client-ID Metadata Document a client can publish at its `client_id` URL. Validates
 * the `client_id` is https and every redirect URI is safe; throws otherwise (fail closed at construction).
 */
export function clientIdMetadataDocument(opts: ClientIdMetadataDocumentOptions): ClientIdMetadataDocument {
  if (!isHttpsUrl(opts.clientId)) {
    throw new Error('clientIdMetadataDocument: `clientId` must be an https URL (CIMD requires https)');
  }
  if (!Array.isArray(opts.redirectUris) || opts.redirectUris.length === 0) {
    throw new Error('clientIdMetadataDocument: at least one redirect URI is required');
  }
  for (const r of opts.redirectUris) {
    if (!isAllowedRedirectUri(r)) throw new Error(`clientIdMetadataDocument: unsafe redirect URI ${JSON.stringify(r)}`);
  }
  const doc: ClientIdMetadataDocument = {
    client_id: opts.clientId,
    redirect_uris: [...opts.redirectUris],
    ...(opts.clientName !== undefined ? { client_name: opts.clientName } : {}),
    ...(opts.clientUri !== undefined ? { client_uri: opts.clientUri } : {}),
    ...(opts.logoUri !== undefined ? { logo_uri: opts.logoUri } : {}),
    ...(opts.scope !== undefined ? { scope: opts.scope } : {}),
    ...(opts.contacts !== undefined ? { contacts: [...opts.contacts] } : {}),
    ...(opts.tosUri !== undefined ? { tos_uri: opts.tosUri } : {}),
    ...(opts.policyUri !== undefined ? { policy_uri: opts.policyUri } : {}),
    ...(opts.grantTypes !== undefined ? { grant_types: [...opts.grantTypes] } : {}),
    ...(opts.responseTypes !== undefined ? { response_types: [...opts.responseTypes] } : {}),
    ...(opts.tokenEndpointAuthMethod !== undefined ? { token_endpoint_auth_method: opts.tokenEndpointAuthMethod } : {}),
  };
  return doc;
}

export type VerifyCimdResult =
  | { ok: true; clientId: string; doc?: ClientIdMetadataDocument }
  | { ok: false; reason: string };

export interface VerifyCimdOptions {
  /**
   * The `client_id` URL the document was dereferenced from. When set, the document's own `client_id` MUST
   * equal it (the CIMD self-reference / integrity rule): a document that claims a different id is rejected.
   */
  expectedClientId?: string;
}

/**
 * CIMD validation (MCP 2026-07-28), the DCR replacement. Two input forms:
 *
 *  - a STRING: the `client_id` URL itself. Validates it is a well-formed https URL (http / malformed →
 *    rejected). The document behind it must still be fetched and validated separately.
 *  - an OBJECT: a dereferenced {@link ClientIdMetadataDocument}. Validates `client_id` is https, matches
 *    `expectedClientId` when supplied, and `redirect_uris` is a non-empty array of safe redirect URIs.
 *
 * Fails closed: anything missing / http / malformed → `{ ok: false, reason }`. The object form accepts an
 * untrusted `Record<string, unknown>` (e.g. freshly parsed JSON) as well as a typed document.
 */
export function verifyCimd(
  input: string | ClientIdMetadataDocument | Record<string, unknown>,
  opts: VerifyCimdOptions = {},
): VerifyCimdResult {
  if (typeof input === 'string') {
    if (!isHttpsUrl(input)) return { ok: false, reason: 'client_id must be an https URL (CIMD requires https; http/malformed rejected)' };
    if (opts.expectedClientId !== undefined && input !== opts.expectedClientId) {
      return { ok: false, reason: 'client_id URL does not match the expected client_id' };
    }
    return { ok: true, clientId: input };
  }
  if (input === null || typeof input !== 'object') return { ok: false, reason: 'CIMD must be a string URL or a metadata object' };
  // The declared type is a hint only — the document is UNTRUSTED (often parsed JSON), so every field is
  // re-validated at runtime below; no cast is used to bypass that.
  const v: Record<string, unknown> = { ...input };
  if (!isHttpsUrl(v.client_id)) return { ok: false, reason: 'client_id must be an https URL (CIMD requires https)' };
  if (opts.expectedClientId !== undefined && v.client_id !== opts.expectedClientId) {
    return { ok: false, reason: 'document client_id does not match the URL it was fetched from (CIMD integrity)' };
  }
  const redirectUris = v.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return { ok: false, reason: 'redirect_uris is required and must be a non-empty array' };
  }
  for (const r of redirectUris) {
    if (!isAllowedRedirectUri(r)) return { ok: false, reason: `unsafe or malformed redirect URI ${JSON.stringify(r)}` };
  }
  // Narrow to the typed document (we validated client_id + redirect_uris above).
  const doc: ClientIdMetadataDocument = { client_id: v.client_id, redirect_uris: redirectUris.filter((r): r is string => typeof r === 'string') };
  if (typeof v.client_name === 'string') doc.client_name = v.client_name;
  if (typeof v.client_uri === 'string') doc.client_uri = v.client_uri;
  if (typeof v.logo_uri === 'string') doc.logo_uri = v.logo_uri;
  if (typeof v.scope === 'string') doc.scope = v.scope;
  if (Array.isArray(v.contacts) && v.contacts.every((c) => typeof c === 'string')) doc.contacts = v.contacts as string[];
  if (typeof v.tos_uri === 'string') doc.tos_uri = v.tos_uri;
  if (typeof v.policy_uri === 'string') doc.policy_uri = v.policy_uri;
  if (Array.isArray(v.grant_types) && v.grant_types.every((g) => typeof g === 'string')) doc.grant_types = v.grant_types as string[];
  if (Array.isArray(v.response_types) && v.response_types.every((g) => typeof g === 'string')) doc.response_types = v.response_types as string[];
  if (typeof v.token_endpoint_auth_method === 'string') doc.token_endpoint_auth_method = v.token_endpoint_auth_method;
  return { ok: true, clientId: v.client_id, doc };
}

// ===================================================================================================
// 4. Scope accumulation — scopes NARROW down the delegation chain
// ===================================================================================================

/** The scope caveat convention: a capability hop may carry `{ type: 'scope', scopes: [...] }`. */
export const SCOPE_CAVEAT = 'scope';

export interface ScopeCaveat extends Caveat {
  type: typeof SCOPE_CAVEAT;
  scopes: string[];
}

export function isScopeCaveat(cv: unknown): cv is ScopeCaveat {
  return (
    cv !== null &&
    typeof cv === 'object' &&
    (cv as Caveat).type === SCOPE_CAVEAT &&
    Array.isArray((cv as { scopes?: unknown }).scopes) &&
    (cv as ScopeCaveat).scopes.every((s) => typeof s === 'string')
  );
}

/**
 * Scope accumulation: the EFFECTIVE granted scopes NARROW monotonically down the chain. Because the
 * capability chain's caveats are append-only and conjunctive, each `scope` caveat INTERSECTS the running
 * set — a child can grant a subset of its parent's scopes but never widen. The leaf holds the full
 * append-only caveat list, so scanning it covers every hop.
 *
 *  - `base` given  → start from it and intersect each `scope` caveat (a delegation can only shrink it).
 *  - `base` absent → the FIRST `scope` caveat seeds the set; later ones intersect it.
 *  - no `base` and NO `scope` caveat → `[]` (fail closed: nothing is granted to a scoped tool).
 *
 * Returns a sorted, de-duplicated array.
 */
export function accumulateScopes(caveats: Caveat[], base?: string[]): string[] {
  let set: Set<string> | null = base ? new Set(base) : null;
  if (Array.isArray(caveats)) {
    for (const cv of caveats) {
      if (!isScopeCaveat(cv)) continue;
      const next = new Set(cv.scopes);
      set = set === null ? next : new Set([...set].filter((s) => next.has(s)));
    }
  }
  if (set === null) return base ? [...new Set(base)].sort() : [];
  return [...set].sort();
}

// ===================================================================================================
// 5. Step-up — PCA FROST/CIBA wired into the MCP step-up challenge
// ===================================================================================================

/**
 * The structured step-up requirement an MCP client drives. A tool that needs escalation makes the RS
 * return a 401 carrying this: the client collects the named co-signer shares via PCA's FROST (threshold)
 * round or a CIBA push, then re-presents a PCActn carrying the `threshold`. Tier 2 = a guardian co-sign,
 * tier 3 = a principal (human) co-sign.
 */
export interface StepUpChallenge {
  /** The threshold tier the re-presented PCActn must satisfy (2 guardian / 3 principal). */
  tier: 2 | 3;
  /** The signer roles whose FROST/CIBA shares satisfy the tier. */
  requiredRoles: SignerRole[];
  /** The PCA step-up endpoint the MCP client drives (FROST round / CIBA push), if advertised. */
  stepUpEndpoint?: string;
  /** Human-readable reason. */
  reason: string;
  /** The RFC-9470 `acr`-like value echoed in the Bearer challenge (e.g. "pca:tier2"). */
  acr: string;
}

/** The roles that satisfy a tier: tier 3 needs a principal; tier 2 a guardian OR a principal. */
export function requiredRolesForTier(tier: 2 | 3): SignerRole[] {
  return tier === 3 ? ['principal'] : ['guardian', 'principal'];
}

/**
 * Default step-up satisfaction: the PCActn already carries a `threshold` share from a role that meets the
 * tier. This is the ADMISSION-layer presence check (does the proof claim the co-sign?); the cryptographic
 * verification of each share against the signer set is the threshold verifier's / adjudicator's job — the
 * PCA core reports `threshold` as 'not-enforced' without a hook, and this mirrors that honesty. Supply
 * `AuthorizeRequestOptions.stepUpSatisfied` to plug a real verifier in.
 */
export function defaultStepUpSatisfied(p: PCActn, tier: 2 | 3): boolean {
  const shares = p.threshold?.shares;
  if (!Array.isArray(shares)) return false;
  const roles = requiredRolesForTier(tier);
  return shares.some((s) => roles.includes(s.role));
}

// ===================================================================================================
// 6. authorizeRequest — the RS admission check
// ===================================================================================================

/** Framework-agnostic request shape: headers (record or Headers-like) + an optional parsed/raw body. */
export interface McpRequestLike {
  headers: Record<string, string | string[] | undefined> | { get(name: string): string | null };
  body?: unknown;
}

function headerValue(req: McpRequestLike, name: string): string | undefined {
  const h = req.headers as { get?: (n: string) => string | null } & Record<string, string | string[] | undefined>;
  if (typeof h.get === 'function') return h.get(name) ?? h.get(name.toLowerCase()) ?? undefined;
  // Record form: HTTP header names are case-insensitive, but a plain object is not — scan case-insensitively.
  const lower = name.toLowerCase();
  let v: string | string[] | undefined = h[name] ?? h[lower];
  if (v === undefined) {
    for (const [k, val] of Object.entries(h)) {
      if (k.toLowerCase() === lower && (typeof val === 'string' || Array.isArray(val))) {
        v = val;
        break;
      }
    }
  }
  if (Array.isArray(v)) return v[0];
  return v;
}

/**
 * Extract a PCActn from a request: the `PCA-Action` header (base64url-encoded PCActn JSON), else a JSON
 * body `{ pcactn }` (string or object). Returns the decoded `PCActn`, or `null` when none is present.
 * Throws only on an unreadable / undecodable encoding (the caller maps that to a 401).
 */
export function extractPCActn(req: McpRequestLike): PCActn | null {
  const h = headerValue(req, 'pca-action');
  if (typeof h === 'string' && h.length > 0) {
    const json = new TextDecoder().decode(unb64u(h.trim()));
    return decodePCActn(json);
  }
  let b: unknown = req.body;
  if (typeof b === 'string' && b.length > 0) {
    b = JSON.parse(b);
  }
  if (b !== null && typeof b === 'object') {
    const x = (b as { pcactn?: unknown }).pcactn;
    if (typeof x === 'string') return decodePCActn(x);
    if (x !== null && typeof x === 'object') return x as PCActn;
  }
  return null;
}

export interface AuthorizeRequestOptions {
  /** REQUIRED (RFC 8707): this RS's id. A PCActn whose signed `aud` differs is rejected (no cross-RS replay). */
  resource: string;
  /**
   * REQUIRED (RFC 9207 mix-up defense): the trusted authorization-server / issuer allowlist. The resolved
   * grant's issuer (see `resolveIssuer`, default the grant's root issuer) MUST be a member, else the
   * credential is rejected as coming from an unexpected AS. Same value as the PRM `authorization_servers`.
   */
  authorizationServers: string[];
  /** Resolve the Root Intent Grant from the PCActn's `grant_ref`. `null` = unknown grant (→ 401). */
  resolveGrant: (grantRef: string, pcactn: PCActn) => Capability | null | Promise<Capability | null>;
  /** The absolute PRM URL for the `WWW-Authenticate` challenge. */
  prmUrl: string;
  /** The MCP tool being invoked (used to look up required scope + step-up tier). */
  tool?: string;
  /** Tool → required scope(s) map. The invoked tool's scopes must all be in the effective granted set. */
  toolScopes?: Record<string, string | string[]>;
  /** Explicit required scopes for this call (overrides `toolScopes[tool]`). */
  requiredScopes?: string[];
  /** Base granted scopes when the grant does not express them as `scope` caveats. Intersected with caveats. */
  baseScopes?: string[];
  /** Fully override how the effective granted scopes are computed (else `accumulateScopes(leaf.caveats, baseScopes)`). */
  resolveGrantedScopes?: (grant: Capability, chain: CapabilityChain, pcactn: PCActn) => string[];
  /** Tool → minimum threshold tier (2 guardian / 3 principal). A tool needing escalation returns a step-up 401. */
  toolStepUp?: Record<string, 2 | 3>;
  /** Explicit minimum tier for this call (overrides `toolStepUp[tool]`). */
  requiredTier?: 2 | 3;
  /**
   * Derive the required tier from the PCActn's own risk claim via the risk policy (RFC-9470 step-up by
   * risk). When set and no explicit tier applies, `requiredThreshold(pcactn.risk_claim.r, riskTiers).t` is
   * used. A caller passes the grant's `risk_policy` θ thresholds here.
   */
  riskTiers?: { theta1: number; theta2: number };
  /** The FROST/CIBA step-up endpoint advertised in the step-up challenge. */
  stepUpEndpoint?: string;
  /** Resolve the credential's issuer for RFC 9207 (default: the grant's root `issuer`). */
  resolveIssuer?: (grant: Capability, pcactn: PCActn) => string;
  /** Plug a real step-up verifier (default {@link defaultStepUpSatisfied} — a presence check). */
  stepUpSatisfied?: (pcactn: PCActn, tier: 2 | 3) => boolean;
  /** Verifier clock (epoch ms). Default `Date.now()`. */
  now?: number;
  /** Bearer realm on the challenge (default "pca"). */
  realm?: string;
}

export interface AuthorizeAllow {
  ok: true;
  status: 200;
  pcactn: PCActn;
  grant: Capability;
  /** The effective (narrowed) granted scopes for this credential. */
  grantedScopes: string[];
  /** The PCA core verdict's per-check status. */
  checks: Record<string, CheckStatus>;
}

export interface AuthorizeDeny {
  ok: false;
  status: 401 | 403;
  error: string;
  errorDescription: string;
  /** The ready-to-send `WWW-Authenticate` header value. */
  wwwAuthenticate: string;
  /** Present when the denial is a step-up requirement the MCP client must drive. */
  stepUp?: StepUpChallenge;
  /** The PCA core verdict's per-check status, when verification ran. */
  checks?: Record<string, CheckStatus>;
}

export type AuthorizeResult = AuthorizeAllow | AuthorizeDeny;

function requiredScopesFor(opts: AuthorizeRequestOptions): string[] {
  if (opts.requiredScopes) return opts.requiredScopes;
  if (opts.tool !== undefined && opts.toolScopes) {
    const req = opts.toolScopes[opts.tool];
    if (req === undefined) return [];
    return Array.isArray(req) ? req : [req];
  }
  return [];
}

function requiredTierFor(opts: AuthorizeRequestOptions, pcactn: PCActn): 2 | 3 | undefined {
  if (opts.requiredTier !== undefined) return opts.requiredTier;
  if (opts.tool !== undefined && opts.toolStepUp) {
    const t = opts.toolStepUp[opts.tool];
    if (t !== undefined) return t;
  }
  if (opts.riskTiers) {
    const rt: RequiredThreshold = requiredThreshold(pcactn.risk_claim?.r ?? 1, opts.riskTiers);
    return rt.t === 1 ? undefined : rt.t;
  }
  return undefined;
}

/**
 * The resource-server admission check for an MCP 2026-07-28 tool call, with a PCActn as the authority.
 * It FAILS CLOSED and runs the checks in this order, each with the correct 401/403 + `WWW-Authenticate`:
 *
 *   1. extract the PCActn (missing / unreadable → 401 `invalid_request`);
 *   2. resolve the grant from `grant_ref` (unknown → 401 `invalid_token`);
 *   3. RFC 8707 — the PCActn's signed `aud` MUST equal this RS's `resource` (mismatch → 401 `invalid_token`);
 *   4. RFC 9207 — the credential's issuer MUST be in `authorizationServers` (mix-up → 401 `invalid_token`);
 *   5. the PCA core verification (`verifyPCActnCore`: wire, version, audience, validity, cap_chain,
 *      plan inclusion, leaf signature, counter). A crypto/binding failure → 401; a policy failure → 403;
 *   6. scope accumulation — the tool's required scope(s) MUST be in the effective (narrowed) granted set
 *      (insufficient → 403 `insufficient_scope`, with `scope` in the challenge);
 *   7. step-up — if the tool needs a tier ≥ 2 co-sign the PCActn does not yet carry, return a 401
 *      `insufficient_user_authentication` (RFC 9470) carrying the {@link StepUpChallenge}.
 *
 * On success it returns the verified PCActn, the grant, the effective granted scopes and the core checks.
 */
export async function authorizeRequest(req: McpRequestLike, opts: AuthorizeRequestOptions): Promise<AuthorizeResult> {
  const realm = opts.realm ?? 'pca';
  const now = opts.now ?? Date.now();
  const deny = (
    status: 401 | 403,
    error: string,
    errorDescription: string,
    extra: { scope?: string; stepUp?: StepUpChallenge; checks?: Record<string, CheckStatus> } = {},
  ): AuthorizeDeny => {
    const header = wwwAuthenticateChallenge({
      resourceMetadataUrl: opts.prmUrl,
      error,
      errorDescription,
      realm,
      ...(extra.scope !== undefined ? { scope: extra.scope } : {}),
      ...(extra.stepUp
        ? { acrValues: extra.stepUp.acr, maxAge: 0, pcaStepUp: extra.stepUp }
        : {}),
    });
    return {
      ok: false,
      status,
      error,
      errorDescription,
      wwwAuthenticate: header,
      ...(extra.stepUp ? { stepUp: extra.stepUp } : {}),
      ...(extra.checks ? { checks: extra.checks } : {}),
    };
  };

  try {
    if (typeof opts.resource !== 'string' || opts.resource.length === 0) {
      throw new Error('authorizeRequest: `resource` is required');
    }
    if (!Array.isArray(opts.authorizationServers) || opts.authorizationServers.length === 0) {
      throw new Error('authorizeRequest: `authorizationServers` is required (RFC 9207)');
    }

    // 1. extract
    let pcactn: PCActn | null;
    try {
      pcactn = extractPCActn(req);
    } catch (e) {
      return deny(401, 'invalid_request', `unreadable PCActn: ${(e as Error).message}`);
    }
    if (pcactn === null) return deny(401, 'invalid_request', 'no PCActn presented (PCA-Action header or {pcactn} body)');
    if (typeof pcactn !== 'object' || typeof pcactn.grant_ref !== 'string') {
      return deny(401, 'invalid_token', 'malformed PCActn');
    }

    // 2. resolve grant
    const grant = await opts.resolveGrant(pcactn.grant_ref, pcactn);
    if (!grant) return deny(401, 'invalid_token', 'unknown grant_ref');

    // 3. RFC 8707 — resource-indicator / audience binding. The signed `aud` is the real binding (a
    // `resource` indicator can be dropped or spoofed in transit; the signature cannot).
    if (typeof pcactn.aud !== 'string' || pcactn.aud !== opts.resource) {
      return deny(401, 'invalid_token', `RFC 8707: PCActn audience (${String(pcactn.aud)}) is not this resource server (${opts.resource})`);
    }

    // 4. RFC 9207 — authorization-server issuer validation (mix-up defense).
    const issuer = opts.resolveIssuer ? opts.resolveIssuer(grant, pcactn) : grant.issuer;
    if (!opts.authorizationServers.includes(issuer)) {
      return deny(401, 'invalid_token', `RFC 9207: credential issuer (${issuer}) is not an expected authorization server`);
    }

    // 5. PCA core verification (crypto + binding). Pass THIS RS's audience so the core re-binds too.
    const verdict = await verifyPCActnCore(pcactn, { grant, audience: opts.resource, nowEpoch: now });
    if (!verdict.allow) {
      const reason = verdict.reason ?? 'PCActn verification failed';
      // Authentication-class failures are 401 (bad proof); everything else is a 403 (policy).
      const authnChecks = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'leaf_signature', 'malformed', 'counter'];
      const authnFailed = authnChecks.some((c) => verdict.checks[c] === 'fail');
      return authnFailed
        ? deny(401, 'invalid_token', reason, { checks: verdict.checks })
        : deny(403, 'forbidden', reason, { checks: verdict.checks });
    }

    // 6. scope accumulation — the narrowed granted scopes must cover the tool's required scope(s).
    const leaf = pcactn.cap_chain.at(-1);
    const leafCaveats: Caveat[] = leaf && Array.isArray(leaf.caveats) ? leaf.caveats : [];
    const grantedScopes = opts.resolveGrantedScopes
      ? opts.resolveGrantedScopes(grant, pcactn.cap_chain, pcactn)
      : accumulateScopes(leafCaveats, opts.baseScopes);
    const need = requiredScopesFor(opts);
    const missing = need.filter((s) => !grantedScopes.includes(s));
    if (missing.length > 0) {
      return deny(403, 'insufficient_scope', `missing required scope(s): ${missing.join(' ')}`, {
        scope: need.join(' '),
        checks: verdict.checks,
      });
    }

    // 7. step-up — a tool needing a tier ≥ 2 co-sign the PCActn does not yet carry.
    const tier = requiredTierFor(opts, pcactn);
    if (tier !== undefined) {
      const satisfied = (opts.stepUpSatisfied ?? defaultStepUpSatisfied)(pcactn, tier);
      if (!satisfied) {
        const stepUp: StepUpChallenge = {
          tier,
          requiredRoles: requiredRolesForTier(tier),
          reason: `this action requires a tier-${tier} ${tier === 3 ? 'principal (human)' : 'guardian'} co-sign; drive the step-up and re-present a PCActn carrying the threshold`,
          acr: `pca:tier${tier}`,
          ...(opts.stepUpEndpoint !== undefined ? { stepUpEndpoint: opts.stepUpEndpoint } : {}),
        };
        return deny(401, 'insufficient_user_authentication', stepUp.reason, { stepUp, checks: verdict.checks });
      }
    }

    return { ok: true, status: 200, pcactn, grant, grantedScopes, checks: verdict.checks };
  } catch (e) {
    // Fail closed: any unexpected error is a 403 deny, never an accidental admit.
    return deny(403, 'forbidden', `admission error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}
