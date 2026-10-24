import { type RevocationEpoch, RevocationSet, checkRevocationEpoch } from './revocation';
import { compareUtf8 } from './hash';
import { type PqPinPolicy, resolveSigAlg } from './pq';
import { isPlainObject, isSafeInt, isSafeNonNeg, suiteCapabilityError } from './intent-strict';

/** Strict shape of a revocation epoch as rule 13 consumes it: every number a safe integer, every string a string. */
export function revocationEpochShapeError(ep: unknown): string | null {
  if (!isPlainObject(ep)) return 'the revocation epoch must be an object';
  for (const k of ['instance_id', 'grant_ref', 'root', 'guardian', 'sig']) if (typeof ep[k] !== 'string') return `revocation epoch ${k} must be a string`;
  for (const k of ['epoch', 'set_size', 'issued_at', 'not_after']) if (!isSafeNonNeg(ep[k])) return `revocation epoch ${k} must be a non-negative safe integer`;
  if (ep.guardian_epoch !== undefined && !isSafeNonNeg(ep.guardian_epoch)) return 'revocation epoch guardian_epoch must be a non-negative safe integer';
  const se = suiteCapabilityError(ep.alg, (a) => resolveSigAlg(a) !== null);
  if (se) return `revocation epoch alg: ${se}`;
  if (ep.pq_pk !== undefined && typeof ep.pq_pk !== 'string') return 'revocation epoch pq_pk must be a string';
  if (ep.pq_sig !== undefined && typeof ep.pq_sig !== 'string') return 'revocation epoch pq_sig must be a string';
  return null;
}

/**
 * INTENT REVOCATION (PCA Intent Layer v2, milestone V10; docs/specs/pca-intent-layer-v2.md §3.9 step 3, T22).
 *
 * Session ids, map digests, delta-grant ids and profile versions go into the session's revocation set, published as
 * signed epochs in the revocation-epoch format of `revocation.ts` (sorted Merkle set root) with namespaced ids. A site
 * checks that no id an action relies on is revoked, against an epoch AT MOST Δ_rev OLD; push revocation (SSF / CAEP) is
 * best effort and the pull bound is the guarantee:
 *
 *   T22. If the verifier requires an epoch at most Δ_rev old (issued_at >= now - Δ_rev) and the publisher includes a
 *   revoked id in every epoch it issues at or after t_r, then no action verified at now > t_r + Δ_rev is admitted
 *   (+ the clock skew s the epoch check tolerates on issued_at).
 *
 * WHO SIGNS, AND APPEND-ONLY. A session's epochs are signed by ONE dedicated revocation authority, `S.revocation.key`,
 * which is never a session principal (so a co-principal cannot publish an epoch that drops another principal's
 * revocation). Every epoch carries its FULL revoked list (`revoked`, sorted, distinct; its sorted-set root must be the
 * signed `root`, its length the signed `set_size`, and `epoch == set_size`), so append-only is checkable: a verifier that
 * tracks the last epoch it accepted for the scope refuses any epoch whose number is lower, whose list is not a SUPERSET
 * of the tracked list, or that has the same number with another root. The authority itself therefore cannot drop an id
 * without detection by any verifier that tracks (and by an evidence-bundle replay, which checks consecutive epochs).
 * Profiles use the same check with the profile owner as the authority. NORMATIVE inside rule 13 (step 7).
 */

export const INTENT_REVOCATION_PREFIX = 'pca-intent:';
export const sessionRevocationId = (session: string): string => `pca-intent:session:${session}`;
export const mapRevocationId = (mapDigest: string): string => `pca-intent:map:${mapDigest}`;
export const deltaRevocationId = (grantId: string): string => `pca-intent:delta:${grantId}`;
export const profileRevocationId = (profileId: string, version: number): string => `pca-intent:profile:${profileId}@${version}`;
/** The `grant_ref` of a session revocation epoch. */
export const sessionRevocationScope = (session: string): string => `pca-intent-session:${session}`;
/** The `grant_ref` of a profile's revocation epoch (the owner publishes it at `revocation.epoch_uri`). */
export const profileRevocationScope = (profileId: string): string => `pca-intent-profile:${profileId}`;

/** Default Δ_rev by tier (§3.9): 60 s for payment tiers, 300 s otherwise. */
export const DEFAULT_REVOCATION_MAX_AGE_S = { payment: 60, default: 300 } as const;

export interface SessionRevocationEvidence {
  epoch: RevocationEpoch;
  /** The full revoked list of the epoch, sorted by UTF-8 bytes and distinct (its sorted-set root is `epoch.root`). */
  revoked: string[];
}

export interface SessionRevocationCheck {
  session: string;
  /** The dedicated revocation authority (`S.revocation.key`; for a profile, its owner): the only accepted epoch signer. */
  authority: string;
  /** Every id the action relies on (session, map, every delta of the chain, the standing-profile version). */
  ids: readonly string[];
  now: number;
  /** Δ_rev in ms: the epoch's `issued_at` must be >= now - maxAgeMs. */
  maxAgeMs: number;
  pin?: PqPinPolicy;
  /** The epoch's `grant_ref`; default {@link sessionRevocationScope}(session). */
  scope?: string;
  /** The last epoch this verifier accepted for the scope (its tracked state): the new one must extend it. */
  last?: SessionRevocationEvidence;
}

/** The evidence is CLOSED: exactly the members `epoch` and `revoked` (an extra member is malformed). */
function closedEvidenceError(ev: object): string | null {
  for (const k of Object.keys(ev)) if (k !== 'epoch' && k !== 'revoked') return `has the unknown member '${k}' (it is exactly {epoch, revoked})`;
  return null;
}

/** The revoked list is well-formed and is exactly what the epoch signs (root, size, epoch == size). */
function revokedListError(ev: { epoch: RevocationEpoch; revoked: unknown }): string | null {
  const r = ev.revoked;
  if (!Array.isArray(r) || !r.every((x) => typeof x === 'string')) return 'revoked must be an array of ids';
  for (let i = 1; i < r.length; i++) if (!(compareUtf8(r[i - 1] as string, r[i] as string) < 0)) return 'revoked must be sorted by UTF-8 bytes and distinct';
  if (r.length !== ev.epoch.set_size || ev.epoch.epoch !== ev.epoch.set_size) return 'the epoch must be numbered by its set size and list exactly set_size ids';
  if (new RevocationSet(r as string[]).root !== ev.epoch.root) return 'the revoked list is not the signed set (root mismatch)';
  return null;
}

/**
 * The session revocation step (NORMATIVE, rule 13 step 7). First failure wins:
 *   a. `maxAgeMs` is a safe integer >= 0, `now` a safe integer, `ids` an array, `authority` a string;
 *   b. the evidence is exactly {epoch, revoked} (closed; so is `last`); the epoch is strictly typed (`revocationEpochShapeError`) and its `guardian` is the authority;
 *   c. it verifies as a revocation epoch (signature under the authority, PQ only under the pinned key; `grant_ref` ==
 *      the scope; now <= not_after; issued_at <= now + 60 s);
 *   d. now - issued_at <= maxAgeMs (the T22 bound);
 *   e. `revoked` is the signed set: an array of strings, strictly ascending in UTF-8 byte order, length == set_size ==
 *      epoch, and its sorted-set root == root;
 *   f. APPEND-ONLY, when the verifier tracks `last` (itself well-formed per e): epoch >= last.epoch; every id of
 *      last.revoked is in revoked; epoch == last.epoch implies root == last.root;
 *   g. no required id is in `revoked`.
 */
export function checkSessionRevocation(ev: SessionRevocationEvidence | undefined, c: SessionRevocationCheck): { ok: true } | { ok: false; reason: string } {
  try {
    if (!isSafeNonNeg(c.maxAgeMs)) return { ok: false, reason: 'revocation max age misconfigured (fail closed)' };
    if (!isSafeInt(c.now)) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
    if (!Array.isArray(c.ids) || typeof c.authority !== 'string') return { ok: false, reason: 'ids must be an array and the authority a key' };
    if (!isPlainObject(ev)) return { ok: false, reason: 'no session revocation epoch supplied' };
    if (closedEvidenceError(ev)) return { ok: false, reason: `the revocation evidence ${closedEvidenceError(ev)}` };
    const ep = ev.epoch as RevocationEpoch;
    const shape = revocationEpochShapeError(ep);
    if (shape) return { ok: false, reason: shape };
    if (ep.guardian !== c.authority) return { ok: false, reason: 'the revocation epoch is not signed by the session revocation authority' };
    const r = checkRevocationEpoch(ep, { guardianPublic: ep.guardian, now: c.now, grantRef: c.scope ?? sessionRevocationScope(c.session), ...(c.pin ?? {}) });
    if (!r.ok) return { ok: false, reason: r.reason ?? 'revocation epoch rejected' };
    if (!(c.now - ep.issued_at <= c.maxAgeMs)) return { ok: false, reason: `the session revocation epoch is older than ${c.maxAgeMs} ms` };
    const le = revokedListError(ev);
    if (le) return { ok: false, reason: le };
    if (c.last !== undefined) {
      const L = c.last;
      if (!isPlainObject(L) || closedEvidenceError(L) !== null || revocationEpochShapeError(L.epoch) !== null || revokedListError(L) !== null) return { ok: false, reason: 'the tracked last epoch is malformed (fail closed)' };
      if (ep.epoch < L.epoch.epoch) return { ok: false, reason: 'revocation epoch rollback (older than the last accepted)' };
      const now = new Set(ev.revoked);
      for (const id of L.revoked) if (!now.has(id)) return { ok: false, reason: `the epoch drops '${id}', revoked in the last accepted epoch (not append-only)` };
      if (ep.epoch === L.epoch.epoch && ep.root !== L.epoch.root) return { ok: false, reason: 'two different revocation sets under one epoch number (equivocation)' };
    }
    const revoked = new Set(ev.revoked);
    for (const id of c.ids) if (typeof id !== 'string' || revoked.has(id)) return { ok: false, reason: `'${String(id)}' is revoked` };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `session revocation check error (fail closed): ${(e as Error).message}` };
  }
}

/**
 * The exposure window of T22 for an honest publisher: an action verified at `now` can rely on an epoch that predates a
 * revocation at `tRevoked` only while `now <= tRevoked + maxAgeMs + skewMs`. Hosts use it to report the bound.
 */
export function revocationExposureEnd(tRevoked: number, maxAgeMs: number, skewMs = 60_000): number {
  return tRevoked + maxAgeMs + skewMs;
}
