/**
 * Directory log entries: what is appended to the log, and the statements an agent or issuer signs to get one there.
 *
 * A log leaf is the commitment string `entryCommit(entry)` (the same leaf shape the PCA transparency ledger uses), so every
 * inclusion and consistency proof is the ordinary RFC 9162 / PCA ledger proof. The entry carries digests, not the passport:
 * in `public` mode the log also serves the signed passport next to the entry, in `hashed` mode it serves nothing but the entry.
 */
import { b64u, canonicalBytesStrict, publicKeyOf, sha256, sign, utf8, verifyB64u } from '@atlasauth/pca';
import type { SignedPassport } from '@atlasauth/pca/ext/attestation';

export const DIRECTORY_ENTRY_TYP = 'atlas-pca/directory-entry';
export const DIRECTORY_VERSION = 1;
const REF_DOMAIN = 'atlas-pca/directory-ref/v1\0';
const PASSPORT_DOMAIN = 'atlas-pca/directory-passport/v1\0';
const ENTRY_DOMAIN = 'atlas-pca/directory-leaf/v1\0';
const REVOKE_DOMAIN = 'atlas-pca/directory-revoke/v1\0';
const POP_DOMAIN = 'atlas-pca/directory-pop/v1\0';

export type EntryKind = 'register' | 'update' | 'revoke';
/** `public`: subject and issuer keys appear in the entry. `hashed`: only salt-free domain-separated hashes of them do. */
export type EntryMode = 'public' | 'hashed';

export interface DirectoryEntry {
  typ: typeof DIRECTORY_ENTRY_TYP;
  ver: number;
  /** The log this leaf was written for: a leaf cannot be replayed into another log. */
  log: string;
  kind: EntryKind;
  mode: EntryMode;
  /** Subject reference: the agent key (`public`) or `subjectRef(key, 'hashed')`. */
  subject: string;
  /** Issuer reference: the issuer key (`public`) or `issuerRef(key, 'hashed')`. */
  issuer: string;
  /** register/update: digest of the signed passport. revoke: digest of the signed revocation statement. */
  digest: string;
  /** revoke only: the digest of the passport being revoked. */
  revokes?: string;
  /** register/update: the passport's own expiry (epoch ms), so a monitor can age entries out. */
  exp?: number;
  /** Epoch ms the log accepted the entry. */
  iat: number;
}

const ref = (kind: 'subject' | 'issuer', key: string, mode: EntryMode): string =>
  mode === 'public' ? key : b64u(sha256(utf8(`${REF_DOMAIN}${kind}\0${key}`)));

/** The lookup key of an agent in a log: its key, or a hash of it. */
export const subjectRef = (key: string, mode: EntryMode): string => ref('subject', key, mode);
export const issuerRef = (key: string, mode: EntryMode): string => ref('issuer', key, mode);

const cat = (domain: string, body: Uint8Array): Uint8Array => {
  const p = utf8(domain);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
};

/** Digest of a signed passport, as written into register/update entries. Includes the signature, so it cannot be guessed from the claims. */
export const passportDigest = (sp: SignedPassport): string => b64u(sha256(cat(PASSPORT_DOMAIN, canonicalBytesStrict(sp))));

/** The Merkle leaf for an entry. */
export const entryCommit = (e: DirectoryEntry): string => b64u(sha256(cat(ENTRY_DOMAIN, canonicalBytesStrict(e))));

// ---- proof of possession ------------------------------------------------------------------------------------------

/** What the subject key signs to show it consented to being listed (so nobody can list a key they do not hold). */
export const popMessage = (logId: string, digest: string): Uint8Array => cat(POP_DOMAIN, canonicalBytesStrict({ log: logId, digest }));

export const signPop = (subjectSecret: Uint8Array, logId: string, passport: SignedPassport): string => b64u(sign(subjectSecret, popMessage(logId, passportDigest(passport))));

export const verifyPop = (subject: string, logId: string, digest: string, pop: unknown): boolean => typeof pop === 'string' && verifyB64u(subject, popMessage(logId, digest), pop);

// ---- revocation statements -----------------------------------------------------------------------------------------

/** A revocation of one passport, signed by the issuer key or the subject key (key compromise is reported by the key itself). */
export interface SignedRevocation {
  typ: 'atlas-pca/directory-revocation';
  ver: number;
  passport_digest: string;
  iss: string;
  sub: string;
  iat: number;
  reason?: string;
  signer: string;
  sig: string;
}

const revokeMessage = (r: Omit<SignedRevocation, 'sig'>): Uint8Array => cat(REVOKE_DOMAIN, canonicalBytesStrict(r));

/** Sign a revocation of `passport` with the issuer's or the subject's secret key. */
export function signRevocation(secret: Uint8Array, passport: SignedPassport, o: { iat: number; reason?: string }): SignedRevocation {
  const body: Omit<SignedRevocation, 'sig'> = {
    typ: 'atlas-pca/directory-revocation',
    ver: DIRECTORY_VERSION,
    passport_digest: passportDigest(passport),
    iss: passport.iss,
    sub: passport.sub,
    iat: o.iat,
    ...(o.reason !== undefined ? { reason: o.reason } : {}),
    signer: b64u(publicKeyOf(secret)),
  };
  return { ...body, sig: b64u(sign(secret, revokeMessage(body))) };
}

/** True iff the statement is well formed and signed by its issuer or subject key. Never throws. */
export function verifyRevocation(r: unknown): r is SignedRevocation {
  try {
    const x = r as Partial<SignedRevocation> | null;
    if (!x || x.typ !== 'atlas-pca/directory-revocation' || x.ver !== DIRECTORY_VERSION) return false;
    for (const k of ['passport_digest', 'iss', 'sub', 'signer', 'sig'] as const) if (typeof x[k] !== 'string' || x[k]!.length === 0) return false;
    if (!Number.isSafeInteger(x.iat)) return false;
    if (x.reason !== undefined && (typeof x.reason !== 'string' || x.reason.length > 256)) return false;
    if (x.signer !== x.iss && x.signer !== x.sub) return false;
    const { sig, ...body } = x as SignedRevocation;
    return verifyB64u(x.signer!, revokeMessage(body), sig);
  } catch {
    return false;
  }
}

export const revocationDigest = (r: SignedRevocation): string => b64u(sha256(cat(REVOKE_DOMAIN, canonicalBytesStrict(r))));

// ---- entry checks --------------------------------------------------------------------------------------------------

const isStr = (x: unknown): x is string => typeof x === 'string' && x.length > 0 && x.length <= 2048;

/** Structural validation of an entry as read off the wire. */
export function isDirectoryEntry(x: unknown): x is DirectoryEntry {
  const e = x as Partial<DirectoryEntry> | null;
  if (!e || typeof e !== 'object' || e.typ !== DIRECTORY_ENTRY_TYP || e.ver !== DIRECTORY_VERSION) return false;
  if (!isStr(e.log) || !isStr(e.subject) || !isStr(e.issuer) || !isStr(e.digest)) return false;
  if (e.kind !== 'register' && e.kind !== 'update' && e.kind !== 'revoke') return false;
  if (e.mode !== 'public' && e.mode !== 'hashed') return false;
  if (!Number.isSafeInteger(e.iat)) return false;
  if (e.kind === 'revoke') {
    if (!isStr(e.revokes) || e.exp !== undefined) return false;
  } else if (e.revokes !== undefined || !Number.isSafeInteger(e.exp)) return false;
  return true;
}

/** Does this register/update entry describe exactly this passport? (digest, subject and issuer references, expiry). */
export function entryMatchesPassport(e: DirectoryEntry, sp: SignedPassport): boolean {
  return (
    (e.kind === 'register' || e.kind === 'update') &&
    e.digest === passportDigest(sp) &&
    e.subject === subjectRef(sp.sub, e.mode) &&
    e.issuer === issuerRef(sp.iss, e.mode) &&
    e.exp === sp.exp
  );
}
