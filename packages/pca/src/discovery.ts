/**
 * Resource-server discovery — `.well-known/pca-configuration` (spec Part: internet-wide integration).
 *
 * The OIDC-discovery analog for Proof-Carrying Authority. A resource server publishes a small JSON
 * document at `/.well-known/pca-configuration` describing how to talk PCA to it — its audience id, the
 * signature suites it accepts, the header it reads the PCActn from, and the URLs for the attestation
 * challenge, revocation epoch, liveness beacon and step-up endpoints. A client (or an agent SDK) fetches
 * it once and auto-configures: it learns the exact `aud` to sign into every PCActn and where to fetch
 * the freshness material, with no out-of-band setup.
 *
 * Pure: `buildDiscoveryDocument` + `parseDiscoveryDocument` have no I/O; `fetchDiscovery` takes an
 * injectable `fetch` (defaults to the global) so it runs anywhere. The document is PUBLIC, non-secret
 * configuration — never put keys or secrets in it beyond the already-public principal/trusted-root ids.
 */

export const WELL_KNOWN_PCA_PATH = '/.well-known/pca-configuration';

export interface PcaDiscoveryDocument {
  /** The resource-server / instance id a PCActn's signed `aud` must equal. REQUIRED. */
  audience: string;
  /** PCActn wire version(s) this server accepts (e.g. [2]). */
  pca_versions: number[];
  /** Accepted signature suites, e.g. ["ed25519","hybrid-ed25519-ml-dsa-65"]. */
  signature_suites: string[];
  /** The HTTP header the PCActn is read from (base64url value). Default "PCA-Action". */
  action_header: string;
  /** The enforcement profile this server applies (the checks that must pass). */
  required_checks?: string[];
  /** Absolute URLs for the freshness / step-up endpoints a client may need. */
  endpoints?: {
    attestation_challenge?: string;
    revocation_epoch?: string;
    liveness_beacon?: string;
    stepup?: string;
    grant?: string;
  };
  /** Optional pinned principal / trusted-root public keys (b64u) the server will accept grants from. */
  trusted_roots?: string[];
  /** Freeform, versioned extension bag. */
  metadata?: Record<string, unknown>;
}

export interface BuildDiscoveryOptions {
  audience: string;
  signatureSuites?: string[];
  pcaVersions?: number[];
  actionHeader?: string;
  requiredChecks?: string[];
  endpoints?: PcaDiscoveryDocument['endpoints'];
  trustedRoots?: string[];
  metadata?: Record<string, unknown>;
}

const DEFAULT_SUITES = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'];
const DEFAULT_REQUIRED = ['counter', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];

/** Build a well-formed discovery document. Throws on an empty audience. */
export function buildDiscoveryDocument(opts: BuildDiscoveryOptions): PcaDiscoveryDocument {
  if (typeof opts.audience !== 'string' || opts.audience.length === 0) {
    throw new Error('buildDiscoveryDocument: audience is required');
  }
  return {
    audience: opts.audience,
    pca_versions: opts.pcaVersions ?? [2],
    signature_suites: opts.signatureSuites ?? [...DEFAULT_SUITES],
    action_header: opts.actionHeader ?? 'PCA-Action',
    required_checks: opts.requiredChecks ?? [...DEFAULT_REQUIRED],
    ...(opts.endpoints ? { endpoints: opts.endpoints } : {}),
    ...(opts.trustedRoots ? { trusted_roots: opts.trustedRoots } : {}),
    ...(opts.metadata ? { metadata: opts.metadata } : {}),
  };
}

/** Validate + narrow an untrusted value into a PcaDiscoveryDocument. Throws on anything malformed. */
export function parseDiscoveryDocument(value: unknown): PcaDiscoveryDocument {
  if (value === null || typeof value !== 'object') throw new Error('parseDiscoveryDocument: not an object');
  const v = value as Record<string, unknown>;
  if (typeof v.audience !== 'string' || v.audience.length === 0) throw new Error('parseDiscoveryDocument: missing audience');
  if (!Array.isArray(v.pca_versions) || !v.pca_versions.every((n) => typeof n === 'number')) {
    throw new Error('parseDiscoveryDocument: pca_versions must be a number[]');
  }
  if (!Array.isArray(v.signature_suites) || !v.signature_suites.every((s) => typeof s === 'string')) {
    throw new Error('parseDiscoveryDocument: signature_suites must be a string[]');
  }
  if (typeof v.action_header !== 'string' || v.action_header.length === 0) throw new Error('parseDiscoveryDocument: missing action_header');
  const doc: PcaDiscoveryDocument = {
    audience: v.audience,
    pca_versions: v.pca_versions as number[],
    signature_suites: v.signature_suites as string[],
    action_header: v.action_header,
  };
  if (Array.isArray(v.required_checks) && v.required_checks.every((s) => typeof s === 'string')) doc.required_checks = v.required_checks as string[];
  if (v.endpoints !== null && typeof v.endpoints === 'object') doc.endpoints = v.endpoints as PcaDiscoveryDocument['endpoints'];
  if (Array.isArray(v.trusted_roots) && v.trusted_roots.every((s) => typeof s === 'string')) doc.trusted_roots = v.trusted_roots as string[];
  if (v.metadata !== null && typeof v.metadata === 'object') doc.metadata = v.metadata as Record<string, unknown>;
  return doc;
}

type FetchLike = (url: string, init?: { headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Fetch + parse a resource server's discovery document. `baseUrl` is the server origin (e.g.
 * `https://api.acme.com`); the well-known path is appended. Pass a `fetch` for non-browser/edge
 * runtimes, else the global is used. Throws on a non-2xx response or a malformed document.
 */
export async function fetchDiscovery(baseUrl: string, fetchImpl?: FetchLike): Promise<PcaDiscoveryDocument> {
  const f = (fetchImpl ?? (globalThis as { fetch?: FetchLike }).fetch) as FetchLike | undefined;
  if (!f) throw new Error('fetchDiscovery: no fetch available — pass one explicitly');
  const url = baseUrl.replace(/\/+$/, '') + WELL_KNOWN_PCA_PATH;
  const res = await f(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`fetchDiscovery: ${url} returned ${res.status}`);
  return parseDiscoveryDocument(await res.json());
}

/** True iff this server (per its discovery doc) accepts a given signature suite. */
export function acceptsSuite(doc: PcaDiscoveryDocument, suite: string): boolean {
  return doc.signature_suites.includes(suite);
}
