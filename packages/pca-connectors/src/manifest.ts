/**
 * The declarative unit of the connector catalog: a {@link ProviderManifest}.
 *
 * A manifest is PURE DATA (no secrets): it names a SaaS provider's OAuth 2.0 authorize/token endpoints,
 * the scopes it offers, how its access token is presented to the API, and how (if at all) it refreshes.
 * Wiring a new outbound tool is therefore a data edit, not code. Every connection minted from a manifest
 * is stored in the `@atlasauth/pca-connect` vault bound to a PCA capability, so each outbound token is a
 * proof-carrying, least-privilege capability — the property Composio / Descope / Auth0 Token Vault lack.
 */

/** How a provider's ACCESS token is presented to its API on an outbound call. */
export type TokenPlacement = 'bearer' | 'header' | 'query';

/** Whether (and how) a provider's access token can be refreshed. */
export type RefreshMode = 'refresh_token' | 'none';

/** How client credentials are presented at the token endpoint (RFC 6749 §2.3.1). */
export type ClientAuthMethod = 'post' | 'basic';

/** The refresh contract for a provider: how a stale access token is renewed. */
export interface RefreshSpec {
  /** `refresh_token` = standard OAuth refresh-token grant; `none` = tokens do not refresh (static/long-lived). */
  mode: RefreshMode;
  /** Token endpoint used for refresh. Defaults to the manifest's `tokenUrl`. */
  tokenEndpoint?: string;
  /** When true, a narrowed `scope` is sent on refresh so the minted token is no wider than requested. */
  supportsScopeNarrowing?: boolean;
  /** Extra static form parameters merged into every refresh request. */
  extraParams?: Record<string, string>;
}

/** A declarative outbound-provider definition. See the module doc. */
export interface ProviderManifest {
  /** Stable, lowercase, globally-unique registry id (e.g. `google`, `microsoft`). */
  id: string;
  /** Human label for consent / directory UIs. */
  displayName: string;
  /** OAuth 2.0 authorization endpoint (RFC 6749 §3.1). May carry `{var}` placeholders (see `requiredVars`). */
  authorizeUrl: string;
  /** OAuth 2.0 token endpoint (RFC 6749 §3.2). May carry `{var}` placeholders. */
  tokenUrl: string;
  /** The full set of scopes this connector knows about (catalog/consent UI surface). */
  scopesAvailable: string[];
  /** The least-privilege default requested when a caller names no scopes. Must be ⊆ `scopesAvailable`. */
  defaultScopes: string[];
  /** The refresh contract. */
  refresh: RefreshSpec;
  /** How the access token is presented to the provider API. */
  tokenPlacement: TokenPlacement;
  /** Whether this provider supports / requires PKCE (RFC 7636). */
  pkce?: boolean;
  /** Scope delimiter in the authorize request. Default `' '`; some providers use `','` (Slack, Shopify, Linear). */
  scopeSeparator?: string;
  /** Static extra parameters added to the authorize URL (e.g. Google `access_type=offline`). */
  authParams?: Record<string, string>;
  /** How client credentials are sent at the token endpoint. Default `'post'`; `'basic'` for Notion / Zoom. */
  clientAuth?: ClientAuthMethod;
  /** Header name to carry the token when `tokenPlacement === 'header'`. */
  headerName?: string;
  /** Query-parameter name to carry the token when `tokenPlacement === 'query'`. */
  queryParam?: string;
  /** `{var}` placeholder names that must be substituted in `authorizeUrl` / `tokenUrl` (e.g. `['shop']`). */
  requiredVars?: string[];
  /** Optional human documentation link. */
  docsUrl?: string;
}

// ---- errors -----------------------------------------------------------------------------------

/** Base class for every runtime refusal this package raises. */
export class ConnectorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConnectorError';
  }
}

/** A manifest failed structural validation. `issues` lists every problem found. */
export class ManifestValidationError extends ConnectorError {
  readonly issues: readonly string[];
  constructor(issues: readonly string[]) {
    super(`invalid provider manifest: ${issues.join('; ')}`);
    this.name = 'ManifestValidationError';
    this.issues = issues;
  }
}

/** No manifest is registered for the requested provider id. */
export class UnknownProviderError extends ConnectorError {
  readonly providerId: string;
  constructor(providerId: string) {
    super(`no connector registered for provider '${providerId}'`);
    this.name = 'UnknownProviderError';
    this.providerId = providerId;
  }
}

// ---- validation -------------------------------------------------------------------------------

/** Read own property `k` off `o` as `unknown`, without a cast. Absent => `undefined`. */
function prop(o: object, k: string): unknown {
  return Object.prototype.hasOwnProperty.call(o, k) ? Reflect.get(o, k) : undefined;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

function isStringRecord(v: unknown): v is Record<string, string> {
  return isRecord(v) && Object.values(v).every((x) => typeof x === 'string');
}

const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;
const TOKEN_PLACEMENTS = new Set<string>(['bearer', 'header', 'query']);
const REFRESH_MODES = new Set<string>(['refresh_token', 'none']);
const CLIENT_AUTHS = new Set<string>(['post', 'basic']);
const oneOf = (s: Set<string>): string => [...s].join(' | ');

function isHttpsUrl(v: unknown): v is string {
  return typeof v === 'string' && v.startsWith('https://');
}

/** The result of validating an untrusted manifest. */
export type ManifestValidation =
  | { ok: true; manifest: ProviderManifest }
  | { ok: false; issues: string[] };

/**
 * Structurally validate an untrusted value as a {@link ProviderManifest}. Pure (no I/O); collects every
 * issue rather than failing on the first, so a custom-manifest author sees all problems at once. Enforces
 * the catalog invariants: a well-formed id, HTTPS endpoints, string scope lists, `defaultScopes ⊆
 * scopesAvailable`, a known `tokenPlacement` / `refresh.mode` / `clientAuth`, a `headerName`/`queryParam`
 * present for the matching placement, and that every `{var}` in the URLs is declared in `requiredVars`.
 */
export function validateManifest(input: unknown): ManifestValidation {
  const issues: string[] = [];
  if (!isRecord(input)) {
    return { ok: false, issues: ['manifest must be an object'] };
  }

  const id = prop(input, 'id');
  if (!isNonEmptyString(id)) issues.push('id must be a non-empty string');
  else if (!ID_PATTERN.test(id)) issues.push(`id '${id}' must be lowercase and match ${ID_PATTERN.source}`);

  if (!isNonEmptyString(prop(input, 'displayName'))) issues.push('displayName must be a non-empty string');

  const authorizeUrl = prop(input, 'authorizeUrl');
  if (!isHttpsUrl(authorizeUrl)) issues.push('authorizeUrl must be an https:// URL');
  const tokenUrl = prop(input, 'tokenUrl');
  if (!isHttpsUrl(tokenUrl)) issues.push('tokenUrl must be an https:// URL');

  const scopesAvailable = prop(input, 'scopesAvailable');
  if (!isStringArray(scopesAvailable)) issues.push('scopesAvailable must be an array of strings');
  const defaultScopes = prop(input, 'defaultScopes');
  if (!isStringArray(defaultScopes)) issues.push('defaultScopes must be an array of strings');
  if (isStringArray(scopesAvailable) && isStringArray(defaultScopes) && scopesAvailable.length > 0) {
    const available = new Set(scopesAvailable);
    const missing = defaultScopes.filter((s) => !available.has(s));
    if (missing.length > 0) issues.push(`defaultScopes must be a subset of scopesAvailable (unknown: ${missing.join(', ')})`);
  }

  const refresh = prop(input, 'refresh');
  if (!isRecord(refresh)) {
    issues.push('refresh must be an object');
  } else {
    const mode = prop(refresh, 'mode');
    if (typeof mode !== 'string' || !REFRESH_MODES.has(mode)) {
      issues.push(`refresh.mode must be one of ${oneOf(REFRESH_MODES)}`);
    }
    const te = prop(refresh, 'tokenEndpoint');
    if (te !== undefined && !isHttpsUrl(te)) issues.push('refresh.tokenEndpoint, when present, must be an https:// URL');
    const sn = prop(refresh, 'supportsScopeNarrowing');
    if (sn !== undefined && typeof sn !== 'boolean') issues.push('refresh.supportsScopeNarrowing must be a boolean');
    const ep = prop(refresh, 'extraParams');
    if (ep !== undefined && !isStringRecord(ep)) issues.push('refresh.extraParams must be a string→string map');
  }

  const tokenPlacement = prop(input, 'tokenPlacement');
  if (typeof tokenPlacement !== 'string' || !TOKEN_PLACEMENTS.has(tokenPlacement)) {
    issues.push(`tokenPlacement must be one of ${oneOf(TOKEN_PLACEMENTS)}`);
  } else if (tokenPlacement === 'header' && !isNonEmptyString(prop(input, 'headerName'))) {
    issues.push("tokenPlacement 'header' requires a non-empty headerName");
  } else if (tokenPlacement === 'query' && !isNonEmptyString(prop(input, 'queryParam'))) {
    issues.push("tokenPlacement 'query' requires a non-empty queryParam");
  }

  const pkce = prop(input, 'pkce');
  if (pkce !== undefined && typeof pkce !== 'boolean') issues.push('pkce must be a boolean');
  const scopeSeparator = prop(input, 'scopeSeparator');
  if (scopeSeparator !== undefined && typeof scopeSeparator !== 'string') issues.push('scopeSeparator must be a string');
  const authParams = prop(input, 'authParams');
  if (authParams !== undefined && !isStringRecord(authParams)) issues.push('authParams must be a string→string map');
  const clientAuth = prop(input, 'clientAuth');
  if (clientAuth !== undefined && (typeof clientAuth !== 'string' || !CLIENT_AUTHS.has(clientAuth))) {
    issues.push(`clientAuth must be one of ${oneOf(CLIENT_AUTHS)}`);
  }

  const requiredVars = prop(input, 'requiredVars');
  if (requiredVars !== undefined && !isStringArray(requiredVars)) issues.push('requiredVars must be an array of strings');
  // Every `{var}` that appears in a URL must be declared, and vice-versa, so substitution can never silently
  // leave a placeholder in a live request.
  if (isHttpsUrl(authorizeUrl) && isHttpsUrl(tokenUrl)) {
    const declared = new Set(isStringArray(requiredVars) ? requiredVars : []);
    const used = new Set<string>([...urlVars(authorizeUrl), ...urlVars(tokenUrl)]);
    for (const v of used) if (!declared.has(v)) issues.push(`url uses '{${v}}' but requiredVars does not declare it`);
    for (const v of declared) if (!used.has(v)) issues.push(`requiredVars declares '${v}' but no URL uses '{${v}}'`);
  }

  const docsUrl = prop(input, 'docsUrl');
  if (docsUrl !== undefined && typeof docsUrl !== 'string') issues.push('docsUrl must be a string');

  if (issues.length > 0) return { ok: false, issues };
  // Every branch above has narrowed the fields; rebuild a clean manifest from the validated values so the
  // returned object carries only known keys.
  return { ok: true, manifest: freezeManifest(input) };
}

/** Collect the `{var}` placeholder names used in a URL. */
function urlVars(url: string): string[] {
  const out: string[] = [];
  const re = /\{(\w+)\}/g;
  let m: RegExpExecArray | null = re.exec(url);
  while (m !== null) {
    const name = m[1];
    if (name !== undefined) out.push(name);
    m = re.exec(url);
  }
  return out;
}

/** Build a {@link ProviderManifest} from an already-validated record, copying only known fields. */
function freezeManifest(input: Record<string, unknown>): ProviderManifest {
  // Each read is guarded by validateManifest having passed; the casts here are to the ALREADY-CHECKED
  // shapes, expressed as narrowing helpers rather than `as` on raw unknown.
  const refreshRaw = prop(input, 'refresh');
  const refreshRec = isRecord(refreshRaw) ? refreshRaw : {};
  const refresh: RefreshSpec = { mode: readRefreshMode(prop(refreshRec, 'mode')) };
  const te = prop(refreshRec, 'tokenEndpoint');
  if (typeof te === 'string') refresh.tokenEndpoint = te;
  const sn = prop(refreshRec, 'supportsScopeNarrowing');
  if (typeof sn === 'boolean') refresh.supportsScopeNarrowing = sn;
  const ep = prop(refreshRec, 'extraParams');
  if (isStringRecord(ep)) refresh.extraParams = { ...ep };

  const manifest: ProviderManifest = {
    id: readString(prop(input, 'id')),
    displayName: readString(prop(input, 'displayName')),
    authorizeUrl: readString(prop(input, 'authorizeUrl')),
    tokenUrl: readString(prop(input, 'tokenUrl')),
    scopesAvailable: readStringArray(prop(input, 'scopesAvailable')),
    defaultScopes: readStringArray(prop(input, 'defaultScopes')),
    refresh,
    tokenPlacement: readTokenPlacement(prop(input, 'tokenPlacement')),
  };
  const pkce = prop(input, 'pkce');
  if (typeof pkce === 'boolean') manifest.pkce = pkce;
  const sep = prop(input, 'scopeSeparator');
  if (typeof sep === 'string') manifest.scopeSeparator = sep;
  const authParams = prop(input, 'authParams');
  if (isStringRecord(authParams)) manifest.authParams = { ...authParams };
  const clientAuth = prop(input, 'clientAuth');
  if (clientAuth === 'post' || clientAuth === 'basic') manifest.clientAuth = clientAuth;
  const headerName = prop(input, 'headerName');
  if (typeof headerName === 'string') manifest.headerName = headerName;
  const queryParam = prop(input, 'queryParam');
  if (typeof queryParam === 'string') manifest.queryParam = queryParam;
  const requiredVars = prop(input, 'requiredVars');
  if (isStringArray(requiredVars)) manifest.requiredVars = [...requiredVars];
  const docsUrl = prop(input, 'docsUrl');
  if (typeof docsUrl === 'string') manifest.docsUrl = docsUrl;
  return manifest;
}

function readString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}
function readStringArray(v: unknown): string[] {
  return isStringArray(v) ? [...v] : [];
}
function readRefreshMode(v: unknown): RefreshMode {
  return v === 'none' ? 'none' : 'refresh_token';
}
function readTokenPlacement(v: unknown): TokenPlacement {
  return v === 'header' ? 'header' : v === 'query' ? 'query' : 'bearer';
}

/** Validate `input`, returning the manifest or throwing {@link ManifestValidationError}. */
export function assertManifest(input: unknown): ProviderManifest {
  const result = validateManifest(input);
  if (!result.ok) throw new ManifestValidationError(result.issues);
  return result.manifest;
}
