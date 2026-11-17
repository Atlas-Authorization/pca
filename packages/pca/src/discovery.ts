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

/**
 * Intent Layer v2 discovery block (docs/specs/pca-intent-layer-v2.md §4.1 M1, §8): the intent versions the site
 * verifies, where its signed action schema lives and the keys that sign it (and its `intent_required` bodies), whether
 * it relays questions to the wallet, the access tier per verb, and its evidence endpoint. An agent sends
 * `intent_session` only to a site whose `intent.versions` contains 2 (a v1 verifier rejects the unknown member).
 */
export interface PcaDiscoveryIntent {
  versions: number[];
  actions_uri?: string;
  schema_keys?: { kid: string; alg: string; pk: string; pq_pk?: string }[];
  question_relay?: boolean;
  /** verb -> access tier 0..4 (§3.15). */
  tiers?: Record<string, number>;
  evidence_uri?: string;
}

/** Validate an `intent` discovery block (throws on anything malformed: fail closed). */
export function parseDiscoveryIntent(v: unknown): PcaDiscoveryIntent {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('parseDiscoveryDocument: intent must be an object');
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!['versions', 'actions_uri', 'schema_keys', 'question_relay', 'tiers', 'evidence_uri'].includes(k)) throw new Error(`parseDiscoveryDocument: intent has unknown member '${k}'`);
  }
  if (!Array.isArray(o.versions) || o.versions.length === 0 || !o.versions.every((n) => n === 1 || n === 2)) throw new Error('parseDiscoveryDocument: intent.versions must list 1 and/or 2');
  const out: PcaDiscoveryIntent = { versions: [...(o.versions as number[])] };
  for (const k of ['actions_uri', 'evidence_uri'] as const) {
    if (o[k] !== undefined) {
      if (typeof o[k] !== 'string' || (o[k] as string).length === 0) throw new Error(`parseDiscoveryDocument: intent.${k} must be a non-empty string`);
      out[k] = o[k] as string;
    }
  }
  if (o.schema_keys !== undefined) {
    if (!Array.isArray(o.schema_keys)) throw new Error('parseDiscoveryDocument: intent.schema_keys must be an array');
    out.schema_keys = o.schema_keys.map((x) => {
      const e = x as Record<string, unknown>;
      if (e === null || typeof e !== 'object' || typeof e.kid !== 'string' || typeof e.alg !== 'string' || typeof e.pk !== 'string' || (e.pq_pk !== undefined && typeof e.pq_pk !== 'string')) {
        throw new Error('parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}');
      }
      return { kid: e.kid, alg: e.alg, pk: e.pk, ...(e.pq_pk !== undefined ? { pq_pk: e.pq_pk as string } : {}) };
    });
  }
  if (o.question_relay !== undefined) {
    if (typeof o.question_relay !== 'boolean') throw new Error('parseDiscoveryDocument: intent.question_relay must be a boolean');
    out.question_relay = o.question_relay;
  }
  if (o.tiers !== undefined) {
    if (o.tiers === null || typeof o.tiers !== 'object' || Array.isArray(o.tiers)) throw new Error('parseDiscoveryDocument: intent.tiers must be an object');
    const t = o.tiers as Record<string, unknown>;
    if (!Object.values(t).every((n) => Number.isInteger(n) && (n as number) >= 0 && !Object.is(n, -0) && (n as number) <= 4)) throw new Error('parseDiscoveryDocument: intent.tiers values must be integers 0..4');
    out.tiers = { ...(t as Record<string, number>) };
  }
  return out;
}

/**
 * Agent trust directory block (`@atlasauth/pca-directory`): where the site's directory log lives and the keys to pin for it. OPTIONAL
 * and additive: a document without `directory` is byte-for-byte what it was, and a verifier that does not know the member ignores it.
 * Discovery is fetched from the site itself, so these keys are a convenience to bootstrap from, not an independent root of trust:
 * a relying party that needs one pins the log and witness keys out of band.
 */
export interface PcaDiscoveryDirectory {
  /** The log's id, as written into its entries and stapled proofs. */
  id?: string;
  /** Absolute http(s) base URL of the log's routes (`/sth`, `/proof`, `/status`, ...). */
  url: string;
  /** The log's signing key(s), b64u, current first. */
  log_keys: string[];
  /** Trusted witnesses and the number whose cosignatures a head needs. */
  witnesses?: { keys: string[]; threshold: number };
  /** Entry modes the log accepts. */
  modes?: ('public' | 'hashed')[];
  /** Anyone may submit (a valid passport and a proof of possession are still required). */
  open?: boolean;
}

const strList = (v: unknown, what: string): string[] => {
  if (!Array.isArray(v) || v.length === 0 || !v.every((s) => typeof s === 'string' && s.length > 0) || new Set(v).size !== v.length) throw new Error(`parseDiscoveryDocument: ${what} must be a non-empty list of distinct strings`);
  return [...(v as string[])];
};

/** Validate a `directory` discovery block (throws on anything malformed: fail closed). */
export function parseDiscoveryDirectory(v: unknown): PcaDiscoveryDirectory {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('parseDiscoveryDocument: directory must be an object');
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!['id', 'url', 'log_keys', 'witnesses', 'modes', 'open'].includes(k)) throw new Error(`parseDiscoveryDocument: directory has unknown member '${k}'`);
  if (typeof o.url !== 'string' || !/^https?:\/\/[^\s/?#]+[^\s]*$/.test(o.url)) throw new Error('parseDiscoveryDocument: directory.url must be an absolute http(s) URL');
  const out: PcaDiscoveryDirectory = { url: o.url, log_keys: strList(o.log_keys, 'directory.log_keys') };
  if (o.id !== undefined) {
    if (typeof o.id !== 'string' || o.id.length === 0) throw new Error('parseDiscoveryDocument: directory.id must be a non-empty string');
    out.id = o.id;
  }
  if (o.witnesses !== undefined) {
    const w = o.witnesses as Record<string, unknown> | null;
    if (w === null || typeof w !== 'object' || Array.isArray(w) || Object.keys(w).some((k) => k !== 'keys' && k !== 'threshold')) throw new Error('parseDiscoveryDocument: directory.witnesses is {keys, threshold}');
    const keys = strList(w.keys, 'directory.witnesses.keys');
    if (!Number.isInteger(w.threshold) || (w.threshold as number) < 1 || (w.threshold as number) > keys.length) throw new Error('parseDiscoveryDocument: directory.witnesses.threshold must be an integer from 1 to the number of keys');
    out.witnesses = { keys, threshold: w.threshold as number };
  }
  if (o.modes !== undefined) {
    const m = strList(o.modes, 'directory.modes');
    if (!m.every((x) => x === 'public' || x === 'hashed')) throw new Error("parseDiscoveryDocument: directory.modes lists 'public' and/or 'hashed'");
    out.modes = m as ('public' | 'hashed')[];
  }
  if (o.open !== undefined) {
    if (typeof o.open !== 'boolean') throw new Error('parseDiscoveryDocument: directory.open must be a boolean');
    out.open = o.open;
  }
  return out;
}

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
  /** Intent Layer v2 block (see {@link PcaDiscoveryIntent}). */
  intent?: PcaDiscoveryIntent;
  /**
   * The decision-obligation kinds this resource server performs (`log`, `notify`, `redact`, `watermark`, `require_receipt`).
   * A decision whose `allow` carries a kind outside this list is a deny at this server. Absent: none supported.
   */
  obligations_supported?: string[];
  /** Agent trust directory block (see {@link PcaDiscoveryDirectory}). Optional; absent is today's document. */
  directory?: PcaDiscoveryDirectory;
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
  intent?: PcaDiscoveryIntent;
  obligationsSupported?: string[];
  directory?: PcaDiscoveryDirectory;
}

const DEFAULT_SUITES = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'];
const DEFAULT_REQUIRED = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'];

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
    ...(opts.intent ? { intent: parseDiscoveryIntent(opts.intent) } : {}),
    ...(opts.obligationsSupported ? { obligations_supported: [...opts.obligationsSupported] } : {}),
    ...(opts.directory ? { directory: parseDiscoveryDirectory(opts.directory) } : {}),
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
  if (v.intent !== undefined) doc.intent = parseDiscoveryIntent(v.intent);
  if (v.obligations_supported !== undefined) {
    if (!Array.isArray(v.obligations_supported) || !v.obligations_supported.every((s) => typeof s === 'string')) throw new Error('parseDiscoveryDocument: obligations_supported must be a string[]');
    doc.obligations_supported = [...(v.obligations_supported as string[])];
  }
  if (v.directory !== undefined) doc.directory = parseDiscoveryDirectory(v.directory);
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
