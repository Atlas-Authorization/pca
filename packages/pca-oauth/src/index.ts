/**
 * OAuth 2.1 / MCP-authorization interop bridge for Proof-Carrying Authority.
 *
 * PCA is the PROOF layer: a signed PCActn whose `aud` binds one action to one resource server is the
 * credential a verifier (`@atlasauth/backend` `requirePCA`) checks default-deny. This package does NOT
 * turn a PCActn into a bearer token and does NOT add an authorization server. It makes a PCA resource
 * server *compose with* the de-facto agent↔tool wire — the MCP OAuth 2.1 Resource-Server handshake —
 * so a generic OAuth / MCP client can DISCOVER the RS, be CHALLENGED by it, and BIND its request to it,
 * while a PCA-aware client gets everything it needs to sign a PCActn. The bridge is the discovery /
 * challenge envelope around the proof; the PCActn remains the thing that is verified.
 *
 * Specs implemented (cited per export):
 *  - RFC 9728  — OAuth 2.0 Protected Resource Metadata  (https://www.rfc-editor.org/rfc/rfc9728)
 *  - RFC 8707  — Resource Indicators for OAuth 2.0       (https://www.rfc-editor.org/rfc/rfc8707)
 *  - RFC 6750  — OAuth 2.0 Bearer Token Usage (the `Bearer` WWW-Authenticate challenge shape)
 *  - RFC 7235  — HTTP/1.1 Authentication (multiple comma-separated challenges in one header)
 *  - MCP Authorization, protocol revision 2025-11-25 — a 401 MUST carry
 *    `WWW-Authenticate: Bearer resource_metadata="<PRM URL>"` pointing at the RFC 9728 document
 *    (https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
 *
 * Pure: every export is I/O-free and runtime-neutral (no Node, no framework) so the same code mounts on
 * Express/Fastify/Hono/Next/Fetch or any router. The PRM document is PUBLIC, non-secret configuration.
 */

import { buildDiscoveryDocument, WELL_KNOWN_PCA_PATH } from '@atlasauth/pca';
import type { PcaDiscoveryDocument } from '@atlasauth/pca';

/**
 * RFC 9728 §3: the Protected Resource Metadata is published at the well-known URI formed by inserting
 * `/.well-known/oauth-protected-resource` into the resource identifier's path. This is the default
 * path component to serve it at.
 */
export const WELL_KNOWN_OAUTH_PRM = '/.well-known/oauth-protected-resource';

/** RFC 6750 §2 token-presentation methods an RFC 9728 `bearer_methods_supported` may advertise. */
export type BearerMethod = 'header' | 'body' | 'query';

/**
 * The PCA extension block embedded inside the PRM document. RFC 9728 §3.1 permits additional, registered
 * or collision-resistant metadata parameters; we namespace ours under a single `pca` object (plus a few
 * flat `pca_*` conveniences) so a generic OAuth client simply ignores it while a PCA-aware client learns
 * that this RS is verified with a PCActn and where its `.well-known/pca-configuration` lives.
 */
export interface PcaResourceExtension {
  /** The HTTP header the PCActn is read from (base64url value). Mirrors the discovery doc `action_header`. */
  pca_action_header: string;
  /** Accepted signature suites, mirrored from the discovery doc (e.g. ["ed25519","hybrid-ed25519-ml-dsa-65"]). */
  pca_signature_suites: string[];
  /** PCActn wire version(s) this RS accepts. */
  pca_versions: number[];
  /** Absolute URL of this RS's `.well-known/pca-configuration` (RFC-9728-style sibling discovery). */
  pca_configuration_endpoint?: string;
  /** The full PCA discovery document (from `buildDiscoveryDocument`), embedded for one-fetch auto-config. */
  pca: PcaDiscoveryDocument;
}

/** RFC 9728 §3 Protected Resource Metadata, extended with the PCA block. */
export interface ProtectedResourceMetadata extends PcaResourceExtension {
  /**
   * RFC 9728 §3.1 `resource` (REQUIRED): the resource identifier of this protected resource. For a PCA RS
   * this IS the value a PCActn's signed `aud` must equal — the OAuth metadata and the cryptographic
   * audience are the same string, so discovery and enforcement cannot drift.
   */
  resource: string;
  /** RFC 9728 §3.1 `authorization_servers` (OPTIONAL): issuer identifiers of ASs that may issue tokens for this RS. */
  authorization_servers?: string[];
  /** RFC 9728 §3.1 `bearer_methods_supported`: how a bearer token may be presented. */
  bearer_methods_supported: BearerMethod[];
  /** RFC 9728 §3.1 `resource_documentation` (OPTIONAL): human-readable docs URL. */
  resource_documentation?: string;
  /** RFC 9728 §3.1 `scopes_supported` (OPTIONAL). */
  scopes_supported?: string[];
  /** RFC 9728 §3.1 `resource_name` (OPTIONAL): human-readable name. */
  resource_name?: string;
  /** RFC 9728 §3.1 `resource_signing_alg_values_supported` (OPTIONAL). */
  resource_signing_alg_values_supported?: string[];
}

export interface ProtectedResourceMetadataOptions {
  /**
   * REQUIRED: the resource identifier — the SAME string as this RS's PCActn audience. We reuse it as the
   * `resource` metadata field and as the discovery document's `audience`, so there is one source of truth.
   */
  resource: string;
  /** OPTIONAL authorization-server issuer identifiers (present only if this RS also accepts AS-issued bearer tokens). */
  authorizationServers?: string[];
  /** Token-presentation methods to advertise. Default `['header']` (a PCActn rides the `PCA-Action` header). */
  bearerMethodsSupported?: BearerMethod[];
  /** Human-readable documentation URL (RFC 9728 `resource_documentation`). */
  resourceDocumentation?: string;
  /** RFC 9728 `scopes_supported`. */
  scopesSupported?: string[];
  /** RFC 9728 `resource_name`. */
  resourceName?: string;
  /** RFC 9728 `resource_signing_alg_values_supported`. */
  resourceSigningAlgValuesSupported?: string[];
  /** Absolute URL of this RS's `.well-known/pca-configuration` (defaults to `<resource>/.well-known/pca-configuration`). */
  pcaConfigurationEndpoint?: string;

  // --- PCA discovery block (forwarded to `buildDiscoveryDocument`) ---
  /** Accepted PCActn signature suites. */
  signatureSuites?: string[];
  /** Accepted PCActn wire versions. */
  pcaVersions?: number[];
  /** Header the PCActn is read from. Default "PCA-Action". */
  actionHeader?: string;
  /** Enforcement profile (the checks that must pass). */
  requiredChecks?: string[];
  /** Freshness / step-up endpoint URLs. */
  endpoints?: PcaDiscoveryDocument['endpoints'];
  /** Pinned principal / trusted-root public keys (b64u) the RS accepts grants from. */
  trustedRoots?: string[];
  /** Freeform extension bag forwarded onto the discovery document's `metadata`. */
  metadata?: Record<string, unknown>;
}

/**
 * RFC 9728 — build the OAuth 2.0 Protected Resource Metadata document served at
 * {@link WELL_KNOWN_OAUTH_PRM}. The `resource` field is this RS's identifier, which for PCA is exactly the
 * value a PCActn's signed `aud` must equal (so the OAuth-layer advertisement and the cryptographic
 * audience are one string). The PCA extension block embeds {@link buildDiscoveryDocument}'s output plus a
 * pointer to `.well-known/pca-configuration`, so one fetch of this PRM auto-configures a PCA-aware client
 * (suites, header, audience, freshness endpoints) while a generic OAuth client reads only the standard
 * RFC 9728 fields. Throws on an empty `resource`.
 */
export function protectedResourceMetadata(opts: ProtectedResourceMetadataOptions): ProtectedResourceMetadata {
  if (typeof opts.resource !== 'string' || opts.resource.length === 0) {
    throw new Error('protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required');
  }
  // One source of truth: the discovery doc's `audience` IS the OAuth `resource`.
  const discovery = buildDiscoveryDocument({
    audience: opts.resource,
    signatureSuites: opts.signatureSuites,
    pcaVersions: opts.pcaVersions,
    actionHeader: opts.actionHeader,
    requiredChecks: opts.requiredChecks,
    endpoints: opts.endpoints,
    trustedRoots: opts.trustedRoots,
    metadata: opts.metadata,
  });
  const pcaConfigurationEndpoint =
    opts.pcaConfigurationEndpoint ?? opts.resource.replace(/\/+$/, '') + WELL_KNOWN_PCA_PATH;

  const doc: ProtectedResourceMetadata = {
    resource: opts.resource,
    bearer_methods_supported: opts.bearerMethodsSupported ?? ['header'],
    // PCA extension (flat conveniences + embedded discovery doc):
    pca_action_header: discovery.action_header,
    pca_signature_suites: [...discovery.signature_suites],
    pca_versions: [...discovery.pca_versions],
    pca_configuration_endpoint: pcaConfigurationEndpoint,
    pca: discovery,
    ...(opts.authorizationServers ? { authorization_servers: [...opts.authorizationServers] } : {}),
    ...(opts.resourceDocumentation ? { resource_documentation: opts.resourceDocumentation } : {}),
    ...(opts.scopesSupported ? { scopes_supported: [...opts.scopesSupported] } : {}),
    ...(opts.resourceName ? { resource_name: opts.resourceName } : {}),
    ...(opts.resourceSigningAlgValuesSupported
      ? { resource_signing_alg_values_supported: [...opts.resourceSigningAlgValuesSupported] }
      : {}),
  };
  return doc;
}

/** Validate + narrow an untrusted value into a {@link ProtectedResourceMetadata}. Throws on anything malformed. */
export function parseProtectedResourceMetadata(value: unknown): ProtectedResourceMetadata {
  if (value === null || typeof value !== 'object') throw new Error('parseProtectedResourceMetadata: not an object');
  const v = value as Record<string, unknown>;
  if (typeof v.resource !== 'string' || v.resource.length === 0) {
    throw new Error('parseProtectedResourceMetadata: missing `resource`');
  }
  if (!Array.isArray(v.bearer_methods_supported) || !v.bearer_methods_supported.every((m) => typeof m === 'string')) {
    throw new Error('parseProtectedResourceMetadata: bearer_methods_supported must be a string[]');
  }
  if (typeof v.pca_action_header !== 'string' || v.pca_action_header.length === 0) {
    throw new Error('parseProtectedResourceMetadata: missing pca_action_header');
  }
  if (!Array.isArray(v.pca_signature_suites) || !v.pca_signature_suites.every((s) => typeof s === 'string')) {
    throw new Error('parseProtectedResourceMetadata: pca_signature_suites must be a string[]');
  }
  if (!Array.isArray(v.pca_versions) || !v.pca_versions.every((n) => typeof n === 'number')) {
    throw new Error('parseProtectedResourceMetadata: pca_versions must be a number[]');
  }
  if (v.pca === null || typeof v.pca !== 'object') {
    throw new Error('parseProtectedResourceMetadata: missing embedded `pca` discovery document');
  }
  const pca = v.pca as PcaDiscoveryDocument;
  if (typeof pca.audience !== 'string' || pca.audience.length === 0) {
    throw new Error('parseProtectedResourceMetadata: embedded pca.audience is required');
  }
  const doc: ProtectedResourceMetadata = {
    resource: v.resource,
    bearer_methods_supported: v.bearer_methods_supported as BearerMethod[],
    pca_action_header: v.pca_action_header,
    pca_signature_suites: v.pca_signature_suites as string[],
    pca_versions: v.pca_versions as number[],
    pca,
  };
  if (typeof v.pca_configuration_endpoint === 'string') doc.pca_configuration_endpoint = v.pca_configuration_endpoint;
  if (Array.isArray(v.authorization_servers) && v.authorization_servers.every((s) => typeof s === 'string')) {
    doc.authorization_servers = v.authorization_servers as string[];
  }
  if (typeof v.resource_documentation === 'string') doc.resource_documentation = v.resource_documentation;
  if (Array.isArray(v.scopes_supported) && v.scopes_supported.every((s) => typeof s === 'string')) {
    doc.scopes_supported = v.scopes_supported as string[];
  }
  if (typeof v.resource_name === 'string') doc.resource_name = v.resource_name;
  if (
    Array.isArray(v.resource_signing_alg_values_supported) &&
    v.resource_signing_alg_values_supported.every((s) => typeof s === 'string')
  ) {
    doc.resource_signing_alg_values_supported = v.resource_signing_alg_values_supported as string[];
  }
  return doc;
}

/** A value destined for a quoted `auth-param` (RFC 7235). We reject control / quote chars to prevent header injection. */
function quotedParam(value: string): string {
  if (/["\r\n]/.test(value)) {
    throw new Error('pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline');
  }
  return value;
}

export interface WwwAuthenticateOptions {
  /** RFC 6750 §3 `error` code on the Bearer challenge (e.g. "invalid_request", "invalid_token"). */
  error?: string;
  /** RFC 6750 §3 `error_description`. */
  errorDescription?: string;
  /** RFC 6750 §3 `scope` the client would need. */
  scope?: string;
  /**
   * Include a PCA challenge alongside the Bearer one so a PCA-aware client gets the proof hint too.
   * Default `true`. Set `false` for a pure MCP/OAuth challenge.
   */
  includePca?: boolean;
  /**
   * Reuse an EXISTING PCA challenge string verbatim (e.g. the `wwwAuthenticate` returned by `requirePCA`'s
   * deny result, which already reads `PCA realm="pca", ...`). When set, it is appended unchanged and the
   * `realm`/`hint` options are ignored.
   */
  pcaChallenge?: string;
  /** PCA realm when building a fresh PCA challenge (default "pca"). Ignored if `pcaChallenge` is given. */
  realm?: string;
  /** PCA hint when building a fresh PCA challenge. Ignored if `pcaChallenge` is given. */
  hint?: string;
}

const DEFAULT_PCA_HINT = 'send PCA-Action: <base64url PCActn> or JSON body {pcactn}';

/**
 * MCP (rev 2025-11-25) + RFC 6750 — build the `WWW-Authenticate` value a PCA resource server returns on a
 * 401. The MCP spec requires `Bearer resource_metadata="<PRM URL>"` pointing at the RFC 9728 document so a
 * generic MCP/OAuth client can discover the RS. By default we ALSO append the existing
 * `PCA realm="pca", hint="..."` challenge (RFC 7235 allows multiple comma-separated challenges in one
 * header) so a PCA-aware client learns, in the same response, that it should present a PCActn. The two
 * clients each read the challenge they understand and ignore the other.
 *
 * `prmUrl` is the absolute URL where {@link protectedResourceMetadata} is served (i.e. ends in
 * {@link WELL_KNOWN_OAUTH_PRM}).
 */
export function wwwAuthenticate(prmUrl: string, opts: WwwAuthenticateOptions = {}): string {
  if (typeof prmUrl !== 'string' || prmUrl.length === 0) {
    throw new Error('wwwAuthenticate: prmUrl is required');
  }
  const bearerParams: string[] = [`resource_metadata="${quotedParam(prmUrl)}"`];
  if (opts.error) bearerParams.push(`error="${quotedParam(opts.error)}"`);
  if (opts.errorDescription) bearerParams.push(`error_description="${quotedParam(opts.errorDescription)}"`);
  if (opts.scope) bearerParams.push(`scope="${quotedParam(opts.scope)}"`);
  const challenges: string[] = [`Bearer ${bearerParams.join(', ')}`];

  const includePca = opts.includePca ?? true;
  if (opts.pcaChallenge) {
    challenges.push(opts.pcaChallenge);
  } else if (includePca) {
    const realm = opts.realm ?? 'pca';
    const hint = opts.hint ?? DEFAULT_PCA_HINT;
    let pca = `PCA realm="${quotedParam(realm)}"`;
    if (hint) pca += `, hint="${quotedParam(hint)}"`;
    challenges.push(pca);
  }
  return challenges.join(', ');
}

export interface ResourceIndicatorResult {
  /** True iff an incoming `resource` indicator matches this RS's expected audience. */
  ok: boolean;
  /** The indicator value that matched (when `ok`). */
  matched?: string;
  /** Why it failed (when `!ok`). */
  reason?: string;
}

/**
 * RFC 8707 — validate an incoming OAuth `resource` indicator against this RS's expected audience. A client
 * (or MCP host) sends `resource=<RS id>` on its token request to scope the credential to one resource
 * server; this checks that echo matches. `resourceParam` may be a single value or the array form (RFC 8707
 * §2 permits multiple `resource` parameters) — the check passes if ANY provided value equals
 * `expectedAudience` by exact string comparison.
 *
 * IMPORTANT: this is the OAuth-LAYER echo only. The cryptographic cross-server-binding is the PCActn's
 * SIGNED `aud`, which `requirePCA` enforces default-deny: a resource indicator can be spoofed or dropped by
 * an intermediary, but the signed `aud` cannot, so a PCActn minted for a different RS is still rejected
 * even if the resource indicator were made to match. Treat agreement here as a courtesy/early-reject, never
 * as the security boundary.
 */
export function checkResourceIndicator(
  resourceParam: string | string[] | undefined | null,
  expectedAudience: string,
): ResourceIndicatorResult {
  if (typeof expectedAudience !== 'string' || expectedAudience.length === 0) {
    throw new Error('checkResourceIndicator: expectedAudience is required');
  }
  if (resourceParam === undefined || resourceParam === null) {
    return { ok: false, reason: 'no resource indicator presented' };
  }
  const values = Array.isArray(resourceParam) ? resourceParam : [resourceParam];
  if (values.length === 0) return { ok: false, reason: 'empty resource indicator' };
  for (const r of values) {
    if (typeof r !== 'string' || r.length === 0) continue;
    if (r === expectedAudience) return { ok: true, matched: r };
  }
  return {
    ok: false,
    reason: `resource indicator ${JSON.stringify(values)} does not match audience ${JSON.stringify(expectedAudience)}`,
  };
}

/**
 * Framework-agnostic glue — the body + path to serve the RFC 9728 PRM document. Mount it in any runtime:
 *
 *   const { path, body } = oauthDiscoveryHandler({ resource: AUDIENCE });
 *   app.get(path, (_req, res) => res.json(body));
 */
export function oauthDiscoveryHandler(
  opts: ProtectedResourceMetadataOptions,
): { path: string; body: ProtectedResourceMetadata } {
  return { path: WELL_KNOWN_OAUTH_PRM, body: protectedResourceMetadata(opts) };
}

export interface McpUnauthorized {
  status: 401;
  headers: { 'WWW-Authenticate': string };
  body: { error: string; error_description?: string; resource_metadata: string };
}

/**
 * Framework-agnostic glue — the complete MCP/OAuth 401 challenge: a 401 status, the
 * `WWW-Authenticate` header from {@link wwwAuthenticate} (Bearer `resource_metadata` + PCA challenge), and a
 * small JSON body echoing the error and the PRM pointer. `prmUrl` is the absolute PRM URL.
 */
export function mcpUnauthorized(prmUrl: string, opts: WwwAuthenticateOptions = {}): McpUnauthorized {
  const body: McpUnauthorized['body'] = {
    error: opts.error ?? 'invalid_request',
    resource_metadata: prmUrl,
  };
  if (opts.errorDescription) body.error_description = opts.errorDescription;
  return {
    status: 401,
    headers: { 'WWW-Authenticate': wwwAuthenticate(prmUrl, opts) },
    body,
  };
}

/**
 * Thin helper — upgrade a `requirePCA` deny result's 401 so its `WWW-Authenticate` ALSO carries the MCP
 * `resource_metadata` pointer. Given the deny result (any object with an optional `wwwAuthenticate: string`,
 * i.e. `@atlasauth/backend`'s `PcaGuardResult` deny arm) and the PRM URL, it reuses the existing PCA
 * challenge verbatim and prepends the `Bearer resource_metadata="<prmUrl>"` challenge, so one 401 now
 * satisfies both a generic MCP/OAuth client and a PCA-aware client. All other fields are preserved.
 */
export function upgradeUnauthorizedChallenge<T extends { wwwAuthenticate?: string }>(
  result: T,
  prmUrl: string,
  opts: WwwAuthenticateOptions = {},
): T & { wwwAuthenticate: string } {
  const existing = result.wwwAuthenticate;
  const header = wwwAuthenticate(prmUrl, {
    ...opts,
    ...(existing ? { pcaChallenge: existing } : {}),
  });
  return { ...result, wwwAuthenticate: header };
}
