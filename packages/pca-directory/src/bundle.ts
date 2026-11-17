/**
 * The stapling format: one object (or one header value) that carries a passport and, for each log, the inclusion proof, the
 * signed tree head and its witness cosignatures. The SCT analogue: an agent presents it, a relying party checks it offline.
 */
import { b64u, canonicalBytesStrict, unb64u, utf8, type InclusionProof } from '@atlasauth/pca';
import type { SignedTreeHead } from '@atlasauth/pca/ext/ledger';
import type { SignedPassport } from '@atlasauth/pca/ext/attestation';
import type { DirectoryEntry } from './entry';
import { isDirectoryEntry } from './entry';
import type { LogClient, StatusView } from './client';
import type { SignedKeyTransition } from './rotation';
import { passportDigest } from './entry';

export const BUNDLE_TYP = 'atlas-pca/directory-bundle';
export const BUNDLE_VERSION = 1;
/** The A2A agent card extension URI under which a bundle rides in `capabilities.extensions[].params.bundle`. */
export const DIRECTORY_EXTENSION_URI = 'https://atlasauth.net/pca/extensions/directory/v1';
/** The request header carrying `encodeBundle(bundle)`. */
export const DIRECTORY_HEADER = 'PCA-Directory';
/** Decoded bundles above this size are refused (an attacker-supplied bundle must not cost memory or CPU). */
export const MAX_BUNDLE_BYTES = 256 * 1024;
export const MAX_BUNDLE_PROOFS = 16;
export const MAX_FRESHNESS_TOKENS = 16;
/** A header value above this is likely to be dropped by proxies; prefer the agent card or the well-known path then. */
export const MAX_HEADER_VALUE = 16 * 1024;

export interface LogProof {
  /** The id of the log (`DirectoryLog.id`), matched against the relying party's trusted logs. */
  log: string;
  index: number;
  entry: DirectoryEntry;
  proof: InclusionProof;
  sth: SignedTreeHead;
  /** Key transitions of this log, so a head signed by a rotated key can be traced to the key the relying party pinned. */
  transitions?: SignedKeyTransition[];
}

/**
 * A freshness token: the log's CURRENT head (re-signed, with the witness cosignatures that still apply to it) and every entry it holds
 * for the agent's subject, each proved against that head. It shows the passport is still listed and carries no revocation or newer
 * passport as of the head's signed time, and an agent can refresh it cheaply (`refreshBundle`) without the relying party going online.
 */
export interface FreshnessToken {
  log: string;
  status: StatusView;
  transitions?: SignedKeyTransition[];
}

export interface StapledBundle {
  typ: typeof BUNDLE_TYP;
  ver: number;
  passport: SignedPassport;
  proofs: LogProof[];
  /** Optional recent head + non-revocation proof per log (see `FreshnessToken`). */
  freshness?: FreshnessToken[];
}

/** Collect a proof of `passport` from each log client. Logs that do not hold it are skipped (the checker decides if that is enough). */
export async function stapleBundle(passport: SignedPassport, logs: ReadonlyArray<{ id: string; client: LogClient }>): Promise<StapledBundle> {
  const digest = passportDigest(passport);
  const proofs: LogProof[] = [];
  for (const l of logs) {
    try {
      const p = await l.client.inclusion(digest);
      if (p) {
        const transitions = (await l.client.transitions?.()) ?? [];
        proofs.push({ log: l.id, index: p.entry.index, entry: p.entry.entry, proof: p.proof, sth: p.sth, ...(transitions.length ? { transitions } : {}) });
      }
    } catch {
      // an unreachable log simply contributes nothing
    }
  }
  return { typ: BUNDLE_TYP, ver: BUNDLE_VERSION, passport, proofs };
}

/**
 * Refresh the freshness tokens of a bundle: ask each log for the subject's current entries against its current head. Cheap (one
 * request per log); an agent does it every few minutes and presents the result. Logs that do not answer keep their old token.
 */
export async function refreshBundle(bundle: StapledBundle, logs: ReadonlyArray<{ id: string; client: LogClient }>): Promise<StapledBundle> {
  const next = new Map((bundle.freshness ?? []).map((f) => [f.log, f] as const));
  for (const l of logs) {
    const proof = bundle.proofs.find((p) => p.log === l.id);
    if (!proof) continue;
    try {
      const status = await l.client.status(proof.entry.subject);
      const transitions = (await l.client.transitions?.()) ?? [];
      next.set(l.id, { log: l.id, status, ...(transitions.length ? { transitions } : {}) });
    } catch {
      // keep the previous token
    }
  }
  return { ...bundle, freshness: [...next.values()] };
}

/** base64url of the canonical bundle: the value of the `PCA-Directory` header. */
export function encodeBundle(b: StapledBundle): string {
  const bytes = canonicalBytesStrict(b);
  if (bytes.length > MAX_BUNDLE_BYTES) throw new RangeError('encodeBundle: bundle too large');
  return b64u(bytes);
}

/** Strict decode. Throws on anything that is not a well-formed bundle; callers treat a throw as "no bundle presented". */
export function decodeBundle(value: string): StapledBundle {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil((MAX_BUNDLE_BYTES * 4) / 3) + 4) throw new Error('bundle: bad size');
  const bytes = unb64u(value);
  if (b64u(bytes) !== value) throw new Error('bundle: non-canonical base64url');
  return parseBundle(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
}

/** Structural check of an already-parsed bundle object. */
export function parseBundle(x: unknown): StapledBundle {
  const b = x as Partial<StapledBundle> | null;
  if (!b || typeof b !== 'object' || b.typ !== BUNDLE_TYP || b.ver !== BUNDLE_VERSION) throw new Error('bundle: wrong type or version');
  if (!b.passport || typeof b.passport !== 'object' || !Array.isArray(b.proofs) || b.proofs.length > MAX_BUNDLE_PROOFS) throw new Error('bundle: malformed');
  for (const p of b.proofs) {
    if (!p || typeof p.log !== 'string' || !Number.isSafeInteger(p.index) || !isDirectoryEntry(p.entry) || !p.proof || typeof p.proof !== 'object' || !p.sth || typeof p.sth !== 'object') throw new Error('bundle: malformed proof');
  }
  if (b.freshness !== undefined && (!Array.isArray(b.freshness) || b.freshness.length > MAX_FRESHNESS_TOKENS || b.freshness.some((f) => !f || typeof f.log !== 'string' || !f.status || typeof f.status !== 'object' || !f.status.sth || !Array.isArray(f.status.entries)))) throw new Error('bundle: malformed freshness token');
  if (utf8(JSON.stringify(b)).length > MAX_BUNDLE_BYTES) throw new Error('bundle: too large');
  return b as StapledBundle;
}
