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
import { b64u, canonicalBytes, compareUtf8, sha256, unb64u, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type MlDsaKeyPair,
  type SigAlg,
  bindSuiteFields,
  encodeMlDsaPublicKey,
  resolveSigAlg,
  signSuiteArtifact,
  verifyWithSuite,
} from './pq';
import { type InclusionProof, leafHash, merkleProof, merkleRoot } from './merkle';
import { type RevocationChecker, type VerifyContext } from './pcactn';

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
    if (!proof || proof.size !== size || !Number.isInteger(proof.index) || proof.index < 0 || proof.index >= size) return false;
    const sides = expectedSides(proof.index, size);
    if (!Array.isArray(proof.path) || proof.path.length !== sides.length) return false;
    let h = leafHash(id);
    for (let i = 0; i < sides.length; i++) {
      const step = proof.path[i]!;
      if (step.side !== sides[i]) return false;
      const sib = unb64u(step.hash);
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
  return !!proof && leafOk(root, proof.size, id, proof);
}

/** Verify id is NOT in the set the root commits to. */
export function verifyNonMembership(root: string, proof: NonMembershipProof, id: string): boolean {
  try {
    if (!proof || !Number.isInteger(proof.size) || proof.size < 0) return false;
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
export interface RevocationEpochSuiteOpts {
  alg?: SigAlg;
  /** The guardian's ML-DSA-65 key pair — required for ml-dsa-65 / hybrid. */
  mlDsa?: MlDsaKeyPair;
}

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
  const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
  // Bind the suite into the signed body (epochMessage reads alg/pq_pk off the body).
  const annotated = { ...body, ...bindSuiteFields({}, suite?.alg, pqPk) } as RevocationEpochBody;
  const fields = signSuiteArtifact(suite?.alg, { edSecret: guardianSecret, mlDsa: suite?.mlDsa }, epochMessage(annotated));
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

export interface EpochCheckOptions {
  guardianPublic: string;
  /** epoch ms; REQUIRED (no implicit clock: the caller owns freshness). */
  now: number;
  grantRef?: string;
  /** The newest epoch number this verifier has already accepted for the grant: an older one is a rollback. */
  lastAcceptedEpoch?: number;
  /** The epoch the PCActn signed in `freshness.epoch`; must be >= the signed epoch (no pre-revocation action). */
  pcactnEpoch?: number;
}

/** Verify a signed revocation epoch (signature, binding, expiry, rollback, PCActn freshness). Never throws. */
export function checkRevocationEpoch(ep: RevocationEpoch, o: EpochCheckOptions): { ok: boolean; reason?: string } {
  try {
    if (!ep || ep.guardian !== o.guardianPublic || resolveSigAlg(ep.alg) === null) return { ok: false, reason: 'revocation epoch not signed by the pinned guardian' };
    if (!Number.isSafeInteger(ep.epoch) || ep.epoch < 0 || !Number.isSafeInteger(ep.set_size) || ep.set_size < 0) {
      return { ok: false, reason: 'malformed revocation epoch' };
    }
    if (!verifyWithSuite(ep.alg, { edPub: o.guardianPublic, mlDsaPub: ep.pq_pk }, epochMessage(ep), { sig: ep.sig, pq_sig: ep.pq_sig })) {
      return { ok: false, reason: 'revocation epoch signature invalid' };
    }
    if (o.grantRef !== undefined && ep.grant_ref !== o.grantRef) return { ok: false, reason: 'revocation epoch is for a different grant' };
    if (!(o.now <= ep.not_after)) return { ok: false, reason: 'revocation epoch expired (stale revocation root)' };
    if (!(ep.issued_at <= o.now + 60_000)) return { ok: false, reason: 'revocation epoch issued in the future' };
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

export interface RevocationCheckerOptions {
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
  /** Newest epoch number already accepted for this grant (verifier-side monotonic pin). */
  lastAcceptedEpoch?: (ctx: VerifyContext) => number | undefined;
  /** Called with an epoch that passed every check (persist it as the new pin). */
  onEpochAccepted?: (ep: RevocationEpoch, ctx: VerifyContext) => void;
  /** Supply the non-membership proof for a capability id (offline: carried with the action). */
  proofFor: (id: string, ctx: VerifyContext) => NonMembershipProof | undefined;
  /** Which capability ids to check. Default: every `id` in the PCActn's cap_chain (a revoked
   * ancestor kills its descendants). */
  ids?: (ctx: VerifyContext) => string[];
}

/**
 * RevocationChecker hook (pcactn.ts) backed by non-membership proofs. Fails closed: a missing
 * root, a missing proof, or a revoked id (which has no valid proof) all reject.
 */
export function createRevocationChecker(opts: RevocationCheckerOptions): RevocationChecker {
  return (ctx) => {
    let root = opts.root?.(ctx);
    let accepted: RevocationEpoch | undefined;
    if (opts.epoch) {
      const ep = opts.epoch(ctx);
      if (!ep || !opts.guardianPublic) return { enforced: true, ok: false, reason: 'no signed revocation epoch' };
      const chk = checkRevocationEpoch(ep, {
        guardianPublic: opts.guardianPublic,
        now: ctx.nowEpoch ?? Date.now(),
        grantRef: ctx.pcactn.grant_ref,
        lastAcceptedEpoch: opts.lastAcceptedEpoch?.(ctx),
        pcactnEpoch: ctx.pcactn.freshness?.epoch,
      });
      if (!chk.ok) return { enforced: true, ok: false, reason: chk.reason };
      if (root !== undefined && root !== ep.root) return { enforced: true, ok: false, reason: 'revocation root does not match the signed epoch' };
      root = ep.root;
      accepted = ep;
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
