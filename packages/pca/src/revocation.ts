import { verifyMembershipVerified } from '@atlasauth/pca-verified-core';
import { verifiedCoreOptIn } from './verified-core-mode';
import { snapshotConfig } from './config-snapshot';
/**
 * L5 revocation "accumulator" — v0 as a SORTED MERKLE SET (deterministic, pure, no RSA modulus).
 *
 * Leaves are the revoked ids in ascending UTF-8 byte order (== Unicode code-point order, `compareUtf8`, the same ordering canonical JSON uses), in an RFC-6962-shaped Merkle
 * tree. The published root also binds the set size: root = H("pca-revset/v1" || size || treeRoot).
 *
 * Membership: an ordinary inclusion proof.
 *
 * Non-membership (offline-verifiable): because leaves are sorted, an id X is absent iff two
 * ADJACENT leaves lo < X < hi exist (both proven included, at consecutive indices), or X is below
 * the first leaf (proof: leaf 0), above the last (proof: leaf size-1), or the set is empty. Leaf
 * positions are verified from the proof path shape (index + size are bound by the root), so a
 * prover cannot pass off non-adjacent leaves as neighbours. A revoked id has no bracketing pair,
 * hence no valid non-membership proof.
 *
 * Freshness caveat: a proof is against a specific root. Verifiers must obtain the current root from
 * a trusted, fresh source (guardian-signed / witnessed epoch root); a stale root can't show later
 * revocations.
 */
import { b64u, canonicalBytes, compareUtf8, decodeB64uStrict, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type SignerSuiteOpts,
  type SigAlg,
  bindSuiteFields,
  suitePqPublicKey,
  suiteKeysOf,
  type PqPinPolicy,
  resolveSigAlg,
  signSuiteArtifact,
  verifyPinnedSuite,
} from './pq';
import { type InclusionProof, leafHash, merkleProof, merkleRoot } from './merkle';
import { type RevocationChecker, type VerifyContext } from './pcactn';
import { classRank } from './reversibility';

const NODE = 0x01;

function nodeHash(l: Uint8Array, r: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + l.length + r.length);
  out[0] = NODE;
  out.set(l, 1);
  out.set(r, 1 + l.length);
  return sha256(out);
}

function bindRoot(size: number, treeRoot: string): string {
  const prefix = utf8('pca-revset/v1\0');
  const tail = canonicalBytes({ size, tree: treeRoot });
  const m = new Uint8Array(prefix.length + tail.length);
  m.set(prefix);
  m.set(tail, prefix.length);
  return b64u(sha256(m));
}

const EMPTY_TREE = b64u(sha256(new Uint8Array(0)));

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Expected sibling sides (leaf-to-root order) for `index` in a tree of `size` leaves. */
function expectedSides(index: number, size: number): ('L' | 'R')[] {
  const out: ('L' | 'R')[] = [];
  const go = (i: number, n: number): void => {
    if (n === 1) return;
    const k = split(n);
    if (i < k) {
      go(i, k);
      out.push('R');
    } else {
      go(i - k, n - k);
      out.push('L');
    }
  };
  go(index, size);
  return out;
}

export interface LeafProof {
  id: string;
  proof: InclusionProof;
}
export interface NonMembershipProof {
  size: number;
  lo?: LeafProof;
  hi?: LeafProof;
}

/** Check a leaf proof against the bound root, including that index/size are what the path says. */
function leafOk(root: string, size: number, id: string, proof: InclusionProof): boolean {
  try {
    // STRICT (normative, like the PCActn plan proof): safe-integer index / size, every sibling canonical base64url of exactly
    // 32 bytes. A sibling of another length cannot fold to the signed root, but it used to be decoded and hashed anyway.
    if (!proof || proof.size !== size || !Number.isSafeInteger(proof.index) || proof.index < 0 || proof.index >= size) return false;
    const sides = expectedSides(proof.index, size);
    if (!Array.isArray(proof.path) || proof.path.length !== sides.length) return false;
    let h = leafHash(id);
    for (let i = 0; i < sides.length; i++) {
      const step = proof.path[i]!;
      if (step.side !== sides[i]) return false;
      const sib = decodeB64uStrict(step.hash, 32);
      if (sib === null) return false;
      h = step.side === 'L' ? nodeHash(sib, h) : nodeHash(h, sib);
    }
    return bindRoot(size, b64u(h)) === root;
  } catch {
    return false;
  }
}

export class RevocationSet {
  private ids: string[] = [];

  constructor(initial: Iterable<string> = []) {
    for (const id of initial) this.revoke(id);
  }

  get size(): number {
    return this.ids.length;
  }

  /** Idempotent. Returns true when newly revoked. */
  revoke(id: string): boolean {
    if (typeof id !== 'string') throw new TypeError('revoke: id must be a string');
    let lo = 0;
    let hi = this.ids.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (compareUtf8(this.ids[mid]!, id) < 0) lo = mid + 1;
      else hi = mid;
    }
    if (this.ids[lo] === id) return false;
    this.ids.splice(lo, 0, id);
    return true;
  }

  has(id: string): boolean {
    return this.indexOf(id) >= 0;
  }

  private indexOf(id: string): number {
    let lo = 0;
    let hi = this.ids.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (compareUtf8(this.ids[mid]!, id) < 0) lo = mid + 1;
      else hi = mid;
    }
    return this.ids[lo] === id ? lo : -1;
  }

  /** Sorted revoked ids (copy). */
  list(): string[] {
    return [...this.ids];
  }

  get root(): string {
    return bindRoot(this.ids.length, this.ids.length === 0 ? EMPTY_TREE : merkleRoot(this.ids));
  }

  membershipProof(id: string): InclusionProof {
    const i = this.indexOf(id);
    if (i < 0) throw new Error('membershipProof: id is not revoked');
    return merkleProof(this.ids, i);
  }

  /** Throws when the id IS revoked (no such proof can exist). */
  nonMembershipProof(id: string): NonMembershipProof {
    if (this.has(id)) throw new Error('nonMembershipProof: id is revoked');
    const n = this.ids.length;
    // first index whose leaf is > id
    let lo = 0;
    let hi = n;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (compareUtf8(this.ids[mid]!, id) < 0) lo = mid + 1;
      else hi = mid;
    }
    const leaf = (i: number): LeafProof => ({ id: this.ids[i]!, proof: merkleProof(this.ids, i) });
    const p: NonMembershipProof = { size: n };
    if (lo > 0) p.lo = leaf(lo - 1);
    if (lo < n) p.hi = leaf(lo);
    return p;
  }
}

/** Verify id IS in the set (inclusion against the size-bound root). */
export function verifyMembership(root: string, proof: InclusionProof, id: string): boolean {
  // OPT-IN (`PCA_VERIFIED_CORE=merkle-strict`): the Dafny-proved inclusion fold (formal/dafny/Merkle.dfy, verified-core
  // `verifyMembershipVerified`). Same sibling-encoding rule as leafOk (canonical base64url of exactly 32 bytes, 0.4.2).
  if (verifiedCoreOptIn('merkle-strict')) {
    try {
      return verifyMembershipVerified(root, proof, canonicalBytes(id));
    } catch {
      return false;
    }
  }
  return !!proof && leafOk(root, proof.size, id, proof);
}

/** Verify id is NOT in the set the root commits to. */
export function verifyNonMembership(root: string, proof: NonMembershipProof, id: string): boolean {
  try {
    if (!proof || !Number.isSafeInteger(proof.size) || proof.size < 0) return false;
    const { size, lo, hi } = proof;
    if (size === 0) return !lo && !hi && root === bindRoot(0, EMPTY_TREE);
    if (!lo && !hi) return false;
    if (lo) {
      if (!(compareUtf8(lo.id, id) < 0) || !leafOk(root, size, lo.id, lo.proof)) return false;
      if (!hi && lo.proof.index !== size - 1) return false; // id above the maximum
    }
    if (hi) {
      if (!(compareUtf8(id, hi.id) < 0) || !leafOk(root, size, hi.id, hi.proof)) return false;
      if (!lo && hi.proof.index !== 0) return false; // id below the minimum
    }
    if (lo && hi && hi.proof.index !== lo.proof.index + 1) return false;
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// Signed revocation epoch (audit P2-3): the guardian signs {instance, grant, epoch, set_size, root,
// issued_at, not_after}. `epoch` is bumped ONLY when the revocation set changes; the same epoch is
// RE-SIGNED (new issued_at / not_after) at least every REVOCATION_EPOCH_REFRESH_MS so a verifier can
// tell "current" from "a captured pre-revocation root". The PCActn's already-signed
// `freshness.epoch` is bound to it, so no wire change is needed.
// ---------------------------------------------------------------------------------------------

export const REVEPOCH_DOMAIN = 'atlas-pca/revepoch/v1\0';
/** The server re-signs the epoch at least this often (T). */
export const REVOCATION_EPOCH_REFRESH_MS = 60_000;
/** How long a signed epoch is acceptable (> T so a refresh always lands before expiry). */
export const REVOCATION_EPOCH_VALIDITY_MS = 5 * 60_000;
/**
 * Default verifier-side maximum age of revocation state for an IRREVERSIBLE action when a staleness policy is on: two
 * refresh periods, so one missed re-sign is tolerated and a root captured before a revocation stops working within 2 min.
 */
export const REVOCATION_IRREVERSIBLE_MAX_AGE_MS = 2 * REVOCATION_EPOCH_REFRESH_MS;

/**
 * Verifier-side revocation staleness policy (0.5, additive: nothing changes unless you set it). The signer chooses
 * `not_after`; this lets the VERIFIER cap how old (`now - issued_at`) the revocation state may be, with a stricter window
 * for actions that cannot be undone. The class is the stricter of the server's authoritative class and the PCActn's signed
 * `reversibility_class`; a missing or unknown class counts as irreversible (fail closed).
 */
export interface RevocationStalenessPolicy {
  /** Maximum age for any action. Default {@link REVOCATION_EPOCH_VALIDITY_MS} (5 min). */
  maxRevocationAgeMs?: number;
  /**
   * Per-class maximum age, each capped by `maxRevocationAgeMs`. Defaults: `irreversible`
   * {@link REVOCATION_IRREVERSIBLE_MAX_AGE_MS} (2 min); `rate_limited` (the old name `costly` is still accepted for one release) = `maxRevocationAgeMs`.
   */
  staleness?: { irreversible?: number; rate_limited?: number; /** The old name of `rate_limited`, accepted for one release. */ costly?: number };
  /**
   * Accept revocation state that is not guardian-signed (a bare `root`) for an IRREVERSIBLE action. Default false: an
   * unsigned root can be any root the verifier was handed, so irreversible actions need a signed epoch.
   */
  allowUnsignedRootForIrreversible?: boolean;
}

function checkPositiveMs(name: string, v: unknown): void {
  if (v !== undefined && !(typeof v === 'number' && Number.isFinite(v) && v > 0)) {
    throw new TypeError(`${name} must be a positive number of milliseconds`);
  }
}

/** Throws a TypeError on a malformed policy (configuration error, raised at construction, never at request time). */
export function validateRevocationStaleness(p: RevocationStalenessPolicy): void {
  checkPositiveMs('maxRevocationAgeMs', p.maxRevocationAgeMs);
  checkPositiveMs('staleness.irreversible', p.staleness?.irreversible);
  checkPositiveMs('staleness.rate_limited', p.staleness?.rate_limited);
  checkPositiveMs('staleness.costly', p.staleness?.costly);
}

/** True when the policy object turns the staleness check on (any age option set). */
export const stalenessPolicyOn = (p: RevocationStalenessPolicy): boolean => p.maxRevocationAgeMs !== undefined || p.staleness !== undefined;

/** The effective reversibility class: the stricter of the server's class and the signed one. Unknown/missing = irreversible. */
export function effectiveReversibility(serverClass: string | undefined, signedClass: unknown): 'reversible' | 'rate_limited' | 'irreversible' {
  const rank = Math.max(serverClass === undefined ? 0 : classRank(serverClass), classRank(signedClass));
  return rank >= 2 ? 'irreversible' : rank === 1 ? 'rate_limited' : 'reversible';
}

/** The maximum age of revocation state the policy allows for an action of `cls`. */
export function revocationMaxAgeMs(p: RevocationStalenessPolicy, cls: 'reversible' | 'rate_limited' | 'costly' | 'irreversible'): number {
  const max = p.maxRevocationAgeMs ?? REVOCATION_EPOCH_VALIDITY_MS;
  if (cls === 'irreversible') return Math.min(max, p.staleness?.irreversible ?? REVOCATION_IRREVERSIBLE_MAX_AGE_MS);
  if (cls === 'rate_limited' || cls === 'costly') return Math.min(max, p.staleness?.rate_limited ?? p.staleness?.costly ?? max);
  return max;
}

/**
 * Age check of revocation state issued (or fetched from a trusted source) at `issuedAt`. Never throws. An unknown issue time
 * is unverifiable and denies; a time more than 60 s in the future denies (same skew as the signed epoch check).
 */
export function checkRevocationAge(issuedAt: number | undefined, now: number, maxAgeMs: number, what = 'revocation state'): { ok: boolean; reason?: string } {
  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt)) return { ok: false, reason: `${what} age is unknown (unverifiable revocation state)` };
  if (!(issuedAt <= now + 60_000)) return { ok: false, reason: `${what} issued in the future` };
  if (!(now - issuedAt <= maxAgeMs)) return { ok: false, reason: `${what} is ${now - issuedAt} ms old, over the verifier's maximum of ${maxAgeMs} ms (stale revocation state)` };
  return { ok: true };
}

export interface RevocationEpoch {
  /** UNSIGNED annotation: which guardian key epoch signed this (the signature is checked against `guardian`). */
  guardian_epoch?: number;
  instance_id: string;
  grant_ref: string;
  epoch: number;
  set_size: number;
  /** The size-bound revocation set root ({@link RevocationSet.root}). */
  root: string;
  issued_at: number;
  not_after: number;
  guardian: string;
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility). For
   * `ml-dsa-65`/`hybrid` the suite + the guardian's ML-DSA key `pq_pk` are SIGNED INTO the epoch body,
   * and `sig`/`pq_sig` carry the component signatures.
   */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the guardian — ml-dsa-65 / hybrid (body-bound). */
  pq_pk?: string;
  /** b64u ML-DSA-65 epoch signature — hybrid only. */
  pq_sig?: string;
}

/** Optional signature-suite material for a revocation-epoch signature (default ed25519). */
export type RevocationEpochSuiteOpts = SignerSuiteOpts;

type RevocationEpochBody = Omit<RevocationEpoch, 'guardian' | 'sig'>;

function epochMessage(e: RevocationEpochBody): Uint8Array {
  const body = canonicalBytes(
    bindSuiteFields(
      {
        instance_id: e.instance_id,
        grant_ref: e.grant_ref,
        epoch: e.epoch,
        set_size: e.set_size,
        root: e.root,
        issued_at: e.issued_at,
        not_after: e.not_after,
      },
      e.alg,
      e.pq_pk,
    ),
  );
  const p = utf8(REVEPOCH_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

export function signRevocationEpoch(
  guardianSecret: Uint8Array,
  body: RevocationEpochBody,
  suite?: RevocationEpochSuiteOpts,
): RevocationEpoch {
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  // Bind the suite into the signed body (epochMessage reads alg/pq_pk off the body).
  const annotated = { ...body, ...bindSuiteFields({}, suite?.alg, pqPk) } as RevocationEpochBody;
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(guardianSecret, suite), epochMessage(annotated));
  return {
    instance_id: body.instance_id,
    grant_ref: body.grant_ref,
    epoch: body.epoch,
    set_size: body.set_size,
    root: body.root,
    issued_at: body.issued_at,
    not_after: body.not_after,
    guardian: b64u(publicKeyOf(guardianSecret)),
    ...fields,
  };
}

export interface EpochCheckOptions extends PqPinPolicy {
  guardianPublic: string;
  /** epoch ms; REQUIRED (no implicit clock: the caller owns freshness). */
  now: number;
  grantRef?: string;
  /** The newest epoch number this verifier has already accepted for the grant: an older one is a rollback. */
  lastAcceptedEpoch?: number;
  /** The epoch the PCActn signed in `freshness.epoch`; must be >= the signed epoch (no pre-revocation action). */
  pcactnEpoch?: number;
  /**
   * Verifier-side maximum age (`now - issued_at`, ms). An epoch older than this is refused even before its signed
   * `not_after`. Absent: only `not_after` bounds staleness (the signer's choice).
   */
  maxAgeMs?: number;
}

/** Verify a signed revocation epoch (signature, binding, expiry, rollback, PCActn freshness). Never throws. */
export function checkRevocationEpoch(ep: RevocationEpoch, o: EpochCheckOptions): { ok: boolean; reason?: string } {
  try {
    if (!ep || ep.guardian !== o.guardianPublic || resolveSigAlg(ep.alg) === null) return { ok: false, reason: 'revocation epoch not signed by the pinned guardian' };
    if (
      !Number.isSafeInteger(ep.epoch) || ep.epoch < 0 || !Number.isSafeInteger(ep.set_size) || ep.set_size < 0 ||
      // epoch-ms instants: safe integers (a string, null or fractional value used to reach the window comparisons)
      !Number.isSafeInteger(ep.issued_at) || !Number.isSafeInteger(ep.not_after)
    ) {
      return { ok: false, reason: 'malformed revocation epoch' };
    }
    if (!verifyPinnedSuite(ep.alg, o.guardianPublic, ep.pq_pk, epochMessage(ep), { sig: ep.sig, pq_sig: ep.pq_sig }, o)) {
      return { ok: false, reason: 'revocation epoch signature invalid' };
    }
    if (o.grantRef !== undefined && ep.grant_ref !== o.grantRef) return { ok: false, reason: 'revocation epoch is for a different grant' };
    if (!(o.now <= ep.not_after)) return { ok: false, reason: 'revocation epoch expired (stale revocation root)' };
    if (!(ep.issued_at <= o.now + 60_000)) return { ok: false, reason: 'revocation epoch issued in the future' };
    if (o.maxAgeMs !== undefined) {
      const age = checkRevocationAge(ep.issued_at, o.now, o.maxAgeMs, 'revocation epoch');
      if (!age.ok) return age;
    }
    if (o.lastAcceptedEpoch !== undefined && ep.epoch < o.lastAcceptedEpoch) {
      return { ok: false, reason: `revocation epoch ${ep.epoch} is older than the last accepted ${o.lastAcceptedEpoch} (rollback)` };
    }
    if (o.pcactnEpoch !== undefined && !(o.pcactnEpoch >= ep.epoch)) {
      return { ok: false, reason: `PCActn freshness.epoch ${o.pcactnEpoch} predates the revocation epoch ${ep.epoch}` };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: 'revocation epoch check error' };
  }
}

/** Domain-separated bytes a PRINCIPAL signs to revoke a capability under their own grant. */
export function revokeMessage(grantRef: string, revokedCapId: string): Uint8Array {
  const body = canonicalBytes({ grant_ref: grantRef, revoked_cap_id: revokedCapId });
  const p = utf8('atlas-pca/revoke/v1\0');
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

export interface RevocationCheckerOptions extends RevocationStalenessPolicy {
  /** Trusted current revocation root for this verification (e.g. guardian-signed epoch root). With
   * `epoch` set this is optional: the signed epoch's root is used (and must equal this one if both given). */
  root?: (ctx: VerifyContext) => string | undefined;
  /**
   * Guardian-signed revocation epoch for this verification. When supplied the checker REQUIRES it to
   * verify (signature, grant binding, `now <= not_after`, not older than `lastAcceptedEpoch`, and the
   * PCActn's signed `freshness.epoch >= epoch`), and checks non-membership against ITS root - closing
   * the circular-freshness gap (a stale pre-revocation root can no longer be presented).
   */
  epoch?: (ctx: VerifyContext) => RevocationEpoch | undefined;
  guardianPublic?: string;
  /** PQ-key pins for the epoch guardian (R2-01); required for a pure-PQ/hybrid epoch. */
  pqPins?: PqPinPolicy['pqPins'];
  /** Legacy opt-out of the PQ-key pin (R2-01). */
  allowUnboundPq?: boolean;
  /** Newest epoch number already accepted for this grant (verifier-side monotonic pin). */
  lastAcceptedEpoch?: (ctx: VerifyContext) => number | undefined;
  /** Called with an epoch that passed every check (persist it as the new pin). */
  onEpochAccepted?: (ep: RevocationEpoch, ctx: VerifyContext) => void;
  /** Supply the non-membership proof for a capability id (offline: carried with the action). */
  proofFor: (id: string, ctx: VerifyContext) => NonMembershipProof | undefined;
  /** Which capability ids to check. Default: every `id` in the PCActn's cap_chain (a revoked
   * ancestor kills its descendants). */
  ids?: (ctx: VerifyContext) => string[];
  /**
   * With a staleness policy (`maxRevocationAgeMs` / `staleness`) and NO signed `epoch`: when the bare `root` was issued
   * by (or fetched from) your trusted source, epoch ms. Unknown = unverifiable = denied. Ignored for a signed epoch (its
   * signed `issued_at` is used).
   */
  rootIssuedAt?: (ctx: VerifyContext) => number | undefined;
  /** Your authoritative reversibility class for the action (e.g. from the tool catalog). The PCActn's signed class can only make it stricter. */
  reversibilityClass?: (ctx: VerifyContext) => string | undefined;
}

/**
 * RevocationChecker hook (pcactn.ts) backed by non-membership proofs. Fails closed: a missing
 * root, a missing proof, or a revoked id (which has no valid proof) all reject.
 */
export function createRevocationChecker(opts: RevocationCheckerOptions): RevocationChecker {
  opts = snapshotConfig(opts); // freeze the configuration: later edits by the caller must not change what this verifier enforces
  validateRevocationStaleness(opts);
  const staleness = stalenessPolicyOn(opts);

  return (ctx) => {
    let root = opts.root?.(ctx);
    let accepted: RevocationEpoch | undefined;
    const now = ctx.nowEpoch ?? Date.now();
    const cls = staleness ? effectiveReversibility(opts.reversibilityClass?.(ctx), ctx.pcactn.action?.reversibility_class) : undefined;
    const maxAgeMs = cls ? revocationMaxAgeMs(opts, cls) : undefined;
    if (opts.epoch) {
      const ep = opts.epoch(ctx);
      if (!ep || !opts.guardianPublic) return { enforced: true, ok: false, reason: 'no signed revocation epoch' };
      const chk = checkRevocationEpoch(ep, {
        guardianPublic: opts.guardianPublic,
        now,
        grantRef: ctx.pcactn.grant_ref,
        lastAcceptedEpoch: opts.lastAcceptedEpoch?.(ctx),
        pcactnEpoch: ctx.pcactn.freshness?.epoch,
        pqPins: opts.pqPins,
        allowUnboundPq: opts.allowUnboundPq,
        ...(maxAgeMs !== undefined ? { maxAgeMs } : {}),
      });
      if (!chk.ok) return { enforced: true, ok: false, reason: chk.reason };
      if (root !== undefined && root !== ep.root) return { enforced: true, ok: false, reason: 'revocation root does not match the signed epoch' };
      root = ep.root;
      accepted = ep;
    } else if (cls !== undefined && maxAgeMs !== undefined) {
      // Unsigned-root path under a staleness policy: refused outright for an irreversible action (unless allowed), and
      // otherwise held to the same age cap via the time YOUR trusted source issued the root.
      if (cls === 'irreversible' && !opts.allowUnsignedRootForIrreversible) {
        return { enforced: true, ok: false, reason: 'unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)' };
      }
      const age = checkRevocationAge(opts.rootIssuedAt?.(ctx), now, maxAgeMs, 'revocation root');
      if (!age.ok) return { enforced: true, ok: false, reason: age.reason };
    }
    if (!root) return { enforced: true, ok: false, reason: 'no revocation root' };
    const ids = opts.ids ? opts.ids(ctx) : ctx.pcactn.cap_chain.map((c) => c.id);
    for (const id of ids) {
      const proof = opts.proofFor(id, ctx);
      if (!proof) return { enforced: true, ok: false, reason: `no non-membership proof for ${id}` };
      if (!verifyNonMembership(root, proof, id)) {
        return { enforced: true, ok: false, reason: `capability ${id} is revoked or proof invalid` };
      }
    }
    if (accepted) opts.onEpochAccepted?.(accepted, ctx);
    return { enforced: true, ok: true };
  };
}
