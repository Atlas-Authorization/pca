import { SpiffeError } from './index';

/** What `verifyX509Svid` asks the revocation check about, once per presented certificate (leaf first). */
export interface X509RevocationSubject {
  /** The SPIFFE ID of the SVID being verified (the same for every certificate of the chain). */
  readonly spiffeId: string;
  /** Certificate serial number, uppercase hexadecimal as Node reports it. Unique only per issuer. */
  readonly serialNumber: string;
  /** SHA-256 fingerprint of the certificate, uppercase colon-separated hexadecimal. Globally unique. */
  readonly fingerprint256: string;
  /** Index in the presented chain: 0 is the leaf. */
  readonly position: number;
  readonly isLeaf: boolean;
}

/** What `verifyJwtSvid` asks the revocation check about. */
export interface JwtRevocationSubject {
  readonly spiffeId: string;
  /** The `jti` claim, when the token has a string one. */
  readonly jti?: string;
  /** The `exp` claim (UNIX seconds). */
  readonly expiresAt: number;
  /** base64url SHA-256 of the token string (the token spelling is canonical, so this is one value per token). */
  readonly tokenHash: string;
}

/** Return exactly `false` to admit, `true` when revoked. Anything else, or a throw, refuses (`revocation_unavailable`). */
export type X509RevocationCheck = (subject: X509RevocationSubject) => boolean;
/** As {@link X509RevocationCheck}, and may be asynchronous. */
export type JwtRevocationCheck = (subject: JwtRevocationSubject) => boolean | Promise<boolean>;

/** A snapshot of what is revoked. Every field is optional; an empty snapshot revokes nothing. */
export interface RevocationList {
  /** Certificate SHA-256 fingerprints (colons and case ignored). Exact: one certificate. */
  fingerprints?: readonly string[];
  /** Certificate serial numbers in hexadecimal (colons, case and leading zeros ignored). Matches that serial under ANY issuer: use only when one CA issues your SVIDs. */
  serials?: readonly string[];
  /** SPIFFE IDs: every certificate and token of that workload is refused. */
  spiffeIds?: readonly string[];
  /** JWT `jti` values. */
  jtis?: readonly string[];
  /** base64url SHA-256 hashes of JWT-SVID token strings. */
  tokenHashes?: readonly string[];
}

export interface RevocationSourceOptions {
  /** REQUIRED. Fetches the current revocation snapshot (your CRL tooling, a database, an admin API). May reject. */
  fetch: () => Promise<RevocationList>;
  /** REQUIRED. Re-fetch when the snapshot is older than this (ms, > 0). */
  refreshMs: number;
  /** REQUIRED. Longest a snapshot may be used after its last successful fetch (ms, >= refreshMs). Past it, every check refuses. */
  maxStaleMs: number;
  /** Clock in ms (default Date.now). */
  now?: () => number;
}

export interface RevocationSource {
  /** For `verifyX509Svid({ revocation })`. Synchronous: it uses the cached snapshot, so call {@link RevocationSource.ensureFresh} first. */
  readonly x509: X509RevocationCheck;
  /** For `verifyJwtSvid({ revocation })`. Refreshes the snapshot itself when it is due. */
  readonly jwt: JwtRevocationCheck;
  /** Fetch now. Rejects with `revocation_unavailable` when the fetch fails or returns a malformed snapshot. */
  refresh(): Promise<void>;
  /** Fetch when the snapshot is older than `refreshMs`; rejects with `revocation_unavailable` when no snapshot younger than `maxStaleMs` exists afterwards. */
  ensureFresh(): Promise<void>;
}

interface Snapshot {
  fingerprints: Set<string>;
  serials: Set<string>;
  spiffeIds: Set<string>;
  jtis: Set<string>;
  tokenHashes: Set<string>;
}

const normHex = (s: string): string => s.replace(/:/g, '').toUpperCase();
const normSerial = (s: string): string => normHex(s).replace(/^0+(?=.)/, '');

function listOf(raw: Record<string, unknown>, key: string): readonly string[] {
  const v = raw[key];
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) {
    throw new SpiffeError('revocation_unavailable', `revocation list field "${key}" must be an array of strings`);
  }
  return v as string[];
}

function toSnapshot(list: unknown): Snapshot {
  if (list === null || typeof list !== 'object' || Array.isArray(list)) {
    throw new SpiffeError('revocation_unavailable', 'revocation list must be an object');
  }
  const raw = list as Record<string, unknown>;
  return {
    fingerprints: new Set(listOf(raw, 'fingerprints').map(normHex)),
    serials: new Set(listOf(raw, 'serials').map(normSerial)),
    spiffeIds: new Set(listOf(raw, 'spiffeIds')),
    jtis: new Set(listOf(raw, 'jtis')),
    tokenHashes: new Set(listOf(raw, 'tokenHashes')),
  };
}

/**
 * A revocation snapshot cache that fails closed, in the shape of `createTrustBundleSource`: before the first successful
 * fetch, or once the last good snapshot is older than `maxStaleMs`, every check refuses with `revocation_unavailable`
 * (a failed or malformed refresh keeps the previous snapshot only until then). A successful refresh replaces the snapshot.
 */
export function createRevocationSource(opts: RevocationSourceOptions): RevocationSource {
  if (typeof opts?.fetch !== 'function') throw new SpiffeError('revocation_unavailable', 'createRevocationSource requires `fetch`');
  const { refreshMs, maxStaleMs } = opts;
  if (!(Number.isFinite(refreshMs) && refreshMs > 0) || !(Number.isFinite(maxStaleMs) && maxStaleMs >= refreshMs)) {
    throw new SpiffeError('revocation_unavailable', 'refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)');
  }
  const now = opts.now ?? Date.now;
  let good: { snap: Snapshot; at: number } | undefined;
  let inflight: Promise<void> | undefined;
  let lastFailure: SpiffeError | undefined;

  const run = (): Promise<void> => (inflight ??= (async () => {
    try {
      good = { snap: toSnapshot(await opts.fetch()), at: now() };
      lastFailure = undefined;
    } catch (e) {
      lastFailure = e instanceof SpiffeError ? e : new SpiffeError('revocation_unavailable', `revocation fetch failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      inflight = undefined;
    }
  })());

  const usable = (): Snapshot => {
    if (good === undefined || now() - good.at > maxStaleMs) {
      throw lastFailure ?? new SpiffeError('revocation_unavailable', 'no revocation snapshot available');
    }
    return good.snap;
  };

  const ensureFresh = async (): Promise<void> => {
    if (good === undefined || now() - good.at >= refreshMs) await run();
    usable();
  };

  return {
    x509: (s) => {
      const snap = usable();
      return snap.fingerprints.has(normHex(s.fingerprint256)) || snap.serials.has(normSerial(s.serialNumber)) || snap.spiffeIds.has(s.spiffeId);
    },
    jwt: async (s) => {
      await ensureFresh();
      const snap = usable();
      return snap.spiffeIds.has(s.spiffeId) || (s.jti !== undefined && snap.jtis.has(s.jti)) || snap.tokenHashes.has(s.tokenHash);
    },
    refresh: async () => {
      await run();
      if (lastFailure !== undefined) throw lastFailure;
    },
    ensureFresh,
  };
}
