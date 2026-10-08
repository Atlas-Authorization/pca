/**
 * L5 transparency ledger (Deep Dive II): a per-principal append-only Merkle log, Certificate-
 * Transparency lineage (RFC 6962 tree shape, RFC 9162 consistency verification).
 *
 * Entries are SALTED COMMITMENTS: commit = hashCanonical({ salt, pcactn_digest }). The Merkle leaf
 * is the commit string alone, so the tree (and every inclusion / consistency proof) is independent
 * of the opening. `shred(i)` drops the opening (salt + PCActn) but keeps the commit: the content is
 * cryptographically unrecoverable (GDPR erasure) while the log stays tamper-evident.
 *
 * Pure and deterministic given explicit salts; the default salt is 16 random bytes.
 */
import { randomBytes } from '@noble/hashes/utils';
import { b64u, canonicalBytes, hashCanonical, sha256, unb64u, utf8 } from './hash';
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
import { type InclusionProof, leafHash, merkleProof, verifyInclusion as verifyMerkleInclusion } from './merkle';
import { type PCActn, pcactnDigest } from './pcactn';

const NODE = 0x01;

function nodeHash(l: Uint8Array, r: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + l.length + r.length);
  out[0] = NODE;
  out.set(l, 1);
  out.set(r, 1 + l.length);
  return sha256(out);
}

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** RFC 6962 MTH over precomputed leaf hashes; empty tree = SHA-256(""). */
function mth(hs: Uint8Array[]): Uint8Array {
  if (hs.length === 0) return sha256(new Uint8Array(0));
  if (hs.length === 1) return hs[0]!;
  const k = split(hs.length);
  return nodeHash(mth(hs.slice(0, k)), mth(hs.slice(k)));
}

export interface LedgerOpening {
  salt: string;
  pcactn: PCActn;
}
export interface LedgerEntry {
  commit: string;
  opening?: LedgerOpening;
}
export interface LedgerHead {
  size: number;
  root: string;
}
export interface ConsistencyProof {
  oldSize: number;
  newSize: number;
  path: string[];
}
export interface WitnessedHead {
  principal: string;
  size: number;
  root: string;
  /** Witness / guardian public key (b64u Ed25519 identity). */
  witness: string;
  sig: string;
  /** Signature suite (crypto-agility). Absent == ed25519 (byte-identical). */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the witness — ml-dsa-65 / hybrid (body-bound). */
  pq_pk?: string;
  /** b64u ML-DSA-65 signature — hybrid only. */
  pq_sig?: string;
}

/** Optional signature-suite material for a guardian/witness signature (default ed25519). */
export interface LedgerSuiteOpts {
  alg?: SigAlg;
  /** The guardian/witness ML-DSA-65 key pair — required for ml-dsa-65 / hybrid. */
  mlDsa?: MlDsaKeyPair;
}

/** The salted commitment of a PCActn. */
export function entryCommit(salt: string, pcactn: PCActn): string {
  return hashCanonical({ salt, pcactn_digest: pcactnDigest(pcactn) });
}

/** True when the opening reproduces the commit. */
export function verifyOpening(commit: string, opening: LedgerOpening): boolean {
  try {
    return entryCommit(opening.salt, opening.pcactn) === commit;
  } catch {
    return false;
  }
}

/** Root of an arbitrary commit sequence (empty log = SHA-256("")). */
export function ledgerRootOf(commits: string[]): string {
  return b64u(mth(commits.map(leafHash)));
}

export function verifyLedgerInclusion(root: string, proof: InclusionProof, commit: string): boolean {
  return verifyMerkleInclusion(root, proof, commit);
}

/** RFC 9162 §2.1.4.2 consistency verification. Never throws. */
export function verifyLedgerConsistency(oldRoot: string, newRoot: string, proof: ConsistencyProof): boolean {
  try {
    const first = proof.oldSize;
    const second = proof.newSize;
    if (!Number.isInteger(first) || !Number.isInteger(second) || first < 0 || first > second) return false;
    if (!Array.isArray(proof.path)) return false;
    if (first === 0) return proof.path.length === 0; // the empty log is a prefix of everything
    if (first === second) return proof.path.length === 0 && oldRoot === newRoot;
    const path = proof.path.map(unb64u);
    if ((first & (first - 1)) === 0) path.unshift(unb64u(oldRoot));
    if (path.length === 0) return false;
    let fn = first - 1;
    let sn = second - 1;
    while (fn & 1) {
      fn >>= 1;
      sn >>= 1;
    }
    let fr = path[0]!;
    let sr = path[0]!;
    for (const c of path.slice(1)) {
      if (sn === 0) return false;
      if (fn & 1 || fn === sn) {
        fr = nodeHash(c, fr);
        sr = nodeHash(c, sr);
        while (!(fn & 1) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      } else {
        sr = nodeHash(sr, c);
      }
      fn >>= 1;
      sn >>= 1;
    }
    return sn === 0 && b64u(fr) === oldRoot && b64u(sr) === newRoot;
  } catch {
    return false;
  }
}

const WITNESS_DOMAIN = 'atlas-pca/ledger-head/v1\0';

function headMessage(principal: string, size: number, root: string, alg?: SigAlg, pqPk?: string): Uint8Array {
  const body = canonicalBytes(bindSuiteFields({ principal, size, root }, alg, pqPk));
  const p = utf8(WITNESS_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/** Verify a (co-)signed head against the witness' public key (b64u). Suite-agile; ed25519 == pre-agility. */
export function verifyWitnessedHead(wh: WitnessedHead, witnessPublic: string): boolean {
  if (!wh || wh.witness !== witnessPublic || resolveSigAlg(wh.alg) === null) return false;
  return verifyWithSuite(
    wh.alg,
    { edPub: witnessPublic, mlDsaPub: wh.pq_pk },
    headMessage(wh.principal, wh.size, wh.root, wh.alg, wh.pq_pk),
    { sig: wh.sig, pq_sig: wh.pq_sig },
  );
}

/**
 * Split-view detection: two validly witnessed heads from the same witness for the same principal
 * and size but different roots prove equivocation. (Cross-size inconsistency is detected with
 * verifyLedgerConsistency.)
 */
export function detectEquivocation(a: WitnessedHead, b: WitnessedHead, witnessPublic: string): boolean {
  return (
    verifyWitnessedHead(a, witnessPublic) &&
    verifyWitnessedHead(b, witnessPublic) &&
    a.principal === b.principal &&
    a.size === b.size &&
    a.root !== b.root
  );
}

export class TransparencyLedger {
  private readonly _entries: LedgerEntry[] = [];
  private _hashes: Uint8Array[] = [];

  constructor(readonly principal: string = '') {}

  /** Rebuild from stored entries (e.g. after persistence, or to model tampering). */
  static fromEntries(entries: LedgerEntry[], principal = ''): TransparencyLedger {
    const l = new TransparencyLedger(principal);
    for (const e of entries) {
      l._entries.push({ commit: e.commit, ...(e.opening ? { opening: e.opening } : {}) });
      l._hashes.push(leafHash(e.commit));
    }
    return l;
  }

  get size(): number {
    return this._entries.length;
  }

  /** Append a PCActn as a salted commitment. Pass `opts.salt` for deterministic output. */
  append(pcactn: PCActn, opts: { salt?: string } = {}): { index: number; commit: string } {
    const salt = opts.salt ?? b64u(randomBytes(16));
    const commit = entryCommit(salt, pcactn);
    const index = this._entries.length;
    this._entries.push({ commit, opening: { salt, pcactn } });
    this._hashes.push(leafHash(commit));
    return { index, commit };
  }

  /**
   * Append a PRECOMPUTED opaque commitment leaf (CT-style): the caller holds the opening off-log (e.g. a
   * guardian-signed settlement record + its salt, or a trajectory-head commitment). The leaf, root and every
   * inclusion / consistency proof behave exactly as for {@link append}; no opening is stored here, so the
   * entry is already shredded and {@link auditOpenings} ignores it. The log stays append-only and witnessable,
   * so anything anchored this way is externally auditable (inclusion proof + a signed/witnessed STH) and a
   * rollback that drops the leaf fails the consistency proof against a pinned head. Refuses a non-string /
   * empty commit (fail closed).
   */
  appendCommitment(commit: string): { index: number; commit: string } {
    if (typeof commit !== 'string' || commit.length === 0) throw new Error('appendCommitment: commit must be a non-empty string');
    const index = this._entries.length;
    this._entries.push({ commit });
    this._hashes.push(leafHash(commit));
    return { index, commit };
  }

  head(): LedgerHead {
    return { size: this.size, root: b64u(mth(this._hashes)) };
  }

  /** Root the log had when it contained only the first `size` entries. */
  rootAt(size: number): string {
    if (!Number.isInteger(size) || size < 0 || size > this.size) throw new RangeError('rootAt: size out of range');
    return b64u(mth(this._hashes.slice(0, size)));
  }

  commits(): string[] {
    return this._entries.map((e) => e.commit);
  }

  entry(index: number): LedgerEntry {
    const e = this._entries[index];
    if (!e) throw new RangeError('entry: index out of range');
    return { commit: e.commit, ...(e.opening ? { opening: e.opening } : {}) };
  }

  /** Indices whose stored opening no longer matches its commit (storage tamper detection). */
  auditOpenings(): number[] {
    const bad: number[] = [];
    this._entries.forEach((e, i) => {
      if (e.opening && !verifyOpening(e.commit, e.opening)) bad.push(i);
    });
    return bad;
  }

  inclusionProof(index: number): InclusionProof {
    return merkleProof(this.commits(), index);
  }

  verifyInclusion(root: string, proof: InclusionProof, commit: string): boolean {
    return verifyLedgerInclusion(root, proof, commit);
  }

  /** RFC 6962 SUBPROOF(m, D[n], true). */
  consistencyProof(oldSize: number, newSize: number = this.size): ConsistencyProof {
    if (!Number.isInteger(oldSize) || !Number.isInteger(newSize) || oldSize < 0 || oldSize > newSize || newSize > this.size) {
      throw new RangeError('consistencyProof: invalid sizes');
    }
    const out: Uint8Array[] = [];
    const sub = (m: number, hs: Uint8Array[], b: boolean): void => {
      const n = hs.length;
      if (m === n) {
        if (!b) out.push(mth(hs));
        return;
      }
      const k = split(n);
      if (m <= k) {
        sub(m, hs.slice(0, k), b);
        out.push(mth(hs.slice(k)));
      } else {
        sub(m - k, hs.slice(k), false);
        out.push(mth(hs.slice(0, k)));
      }
    };
    if (oldSize > 0 && oldSize < newSize) sub(oldSize, this._hashes.slice(0, newSize), true);
    return { oldSize, newSize, path: out.map(b64u) };
  }

  verifyConsistency(oldRoot: string, newRoot: string, proof: ConsistencyProof): boolean {
    return verifyLedgerConsistency(oldRoot, newRoot, proof);
  }

  /**
   * Crypto-shred: destroy the opening (salt + PCActn), keep the commit. The leaf, the root and every
   * inclusion/consistency proof are unchanged. Returns whether an opening was actually removed.
   */
  shred(index: number): boolean {
    const e = this._entries[index];
    if (!e) throw new RangeError('shred: index out of range');
    const had = e.opening !== undefined;
    delete e.opening;
    return had;
  }

  /** Sign the current head for third-party witnessing / anti-equivocation (co-sign hook). Suite-agile. */
  witnessHead(guardianSecret: Uint8Array, suite?: LedgerSuiteOpts): WitnessedHead {
    const { size, root } = this.head();
    const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
    const fields = signSuiteArtifact(suite?.alg, { edSecret: guardianSecret, mlDsa: suite?.mlDsa }, headMessage(this.principal, size, root, suite?.alg, pqPk));
    return { principal: this.principal, size, root, witness: b64u(publicKeyOf(guardianSecret)), ...fields };
  }
}

// ---------------------------------------------------------------------------------------------
// Signed Tree Heads (STH): the guardian signs `{instance_id, principal, size, root, prev_root,
// timestamp}` on EVERY append, under a domain separator distinct from the witness head and from
// every other guardian signature. A client pins the latest STH and demands a consistency proof from
// the pinned size to the new one on every poll; the operator can no longer rewrite history or show
// two clients different logs without a signed, attributable contradiction.
// ---------------------------------------------------------------------------------------------

export const STH_DOMAIN = 'atlas-pca/sth/v1\0';

export interface SignedTreeHead {
  /** UNSIGNED annotation: which guardian key epoch signed this (the signature is checked against `guardian`). */
  guardian_epoch?: number;
  instance_id: string;
  /** The log key (grant_ref). */
  principal: string;
  size: number;
  root: string;
  /** Root of the previous STH of this log ('' for the first). */
  prev_root: string;
  /** epoch ms the head was signed. */
  timestamp: number;
  /** Signing guardian public key (b64u Ed25519 identity). */
  guardian: string;
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility: no suite
   * fields and the signed tree-head bytes are unchanged). For `ml-dsa-65`/`hybrid` the suite + the
   * guardian's ML-DSA key `pq_pk` are SIGNED INTO the STH body, and `sig`/`pq_sig` carry the components.
   */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the guardian — ml-dsa-65 / hybrid (body-bound). */
  pq_pk?: string;
  /** b64u ML-DSA-65 STH signature — hybrid only. */
  pq_sig?: string;
  /**
   * OPTIONAL external witness cosignatures (C2SP tlog-witness / Sigsum model). A trusted witness other
   * than the operator cosigns the SAME tree-head statement under its own key (see {@link cosignTreeHead}),
   * turning a self-attested STH into an anti-equivocation artefact: a split view can no longer gather a
   * threshold of honest-witness cosignatures on two conflicting roots at the same size.
   *
   * ADDITIVE: this field is NOT part of the guardian-signed bytes ({@link sthMessage}). An STH with no
   * witnesses is byte-identical to before and verifies exactly as today; the field is absent, never `[]`,
   * when there are none.
   */
  witnesses?: WitnessCosignature[];
}

/** A C2SP tlog-witness cosignature: a trusted witness's signature over the STH statement. Suite-agile. */
export interface WitnessCosignature {
  /** Witness public key (b64u Ed25519 identity). */
  key: string;
  /** Signature over the domain-separated witness message (b64u). Ed25519 for ed25519/hybrid, ML-DSA-65 for pure. */
  sig: string;
  /** Signature suite (crypto-agility). Absent == ed25519 (byte-identical). */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the witness — ml-dsa-65 / hybrid (bound into the cosigned bytes). */
  pq_pk?: string;
  /** b64u ML-DSA-65 cosignature — hybrid only. */
  pq_sig?: string;
}

/** The k-of-n trust policy a monitor / verifier applies to an STH's witness cosignatures. */
export interface WitnessPolicy {
  /** The set of TRUSTED witness public keys (b64u). */
  witnessKeys: string[];
  /** Minimum number of DISTINCT trusted witnesses that must have a valid cosignature. */
  threshold: number;
}

function sthMessage(h: Omit<SignedTreeHead, 'guardian' | 'sig'>): Uint8Array {
  const body = canonicalBytes(
    bindSuiteFields(
      {
        instance_id: h.instance_id,
        principal: h.principal,
        size: h.size,
        root: h.root,
        prev_root: h.prev_root,
        timestamp: h.timestamp,
      },
      h.alg,
      h.pq_pk,
    ),
  );
  const p = utf8(STH_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

// ---------------------------------------------------------------------------------------------
// C2SP external witness cosignatures (anti-equivocation). A witness cosigns the tree-head STATEMENT
// — {size, root, prev_root, guardian_epoch} — under a domain separator DISTINCT from the guardian STH
// domain and from the legacy ledger-head witness domain, so a cosignature can never be mistaken for (or
// replayed as) a guardian signature. The witness binds to WHAT the log is at this size; it does not
// re-sign the guardian's bytes. Honest witnesses cosign at most one root per size, so two conflicting
// roots at the same size cannot both reach a threshold of honest cosignatures.
// ---------------------------------------------------------------------------------------------

export const STH_WITNESS_DOMAIN = 'atlas-pca/sth-witness/v1\0';

function sthWitnessMessage(
  h: Pick<SignedTreeHead, 'size' | 'root' | 'prev_root' | 'guardian_epoch'>,
  alg?: SigAlg,
  pqPk?: string,
): Uint8Array {
  const body = canonicalBytes(
    bindSuiteFields(
      {
        size: h.size,
        root: h.root,
        prev_root: h.prev_root,
        guardian_epoch: h.guardian_epoch ?? 0,
      },
      alg,
      pqPk,
    ),
  );
  const p = utf8(STH_WITNESS_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/**
 * A trusted witness cosigns the tree-head statement of `sth` with its own secret key. The cosignature is
 * bound to the exact {size, root, prev_root, guardian_epoch} (plus the suite for a non-default `suite`); a
 * cosignature minted for one head does not verify against a head with a different size or root. Suite-agile:
 * ed25519 (default) is byte-identical; ml-dsa-65/hybrid bind the witness ML-DSA key into the cosigned bytes.
 */
export function cosignTreeHead(
  sth: Pick<SignedTreeHead, 'size' | 'root' | 'prev_root' | 'guardian_epoch'>,
  witnessSecret: Uint8Array,
  suite?: LedgerSuiteOpts,
): WitnessCosignature {
  const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
  const fields = signSuiteArtifact(suite?.alg, { edSecret: witnessSecret, mlDsa: suite?.mlDsa }, sthWitnessMessage(sth, suite?.alg, pqPk));
  return { key: b64u(publicKeyOf(witnessSecret)), ...fields };
}

/**
 * Verify a single cosignature against a trusted witness key, bound to this exact head. Never throws.
 */
export function verifyWitnessCosignature(sth: SignedTreeHead, cosig: WitnessCosignature, witnessPublic: string): boolean {
  try {
    if (!cosig || cosig.key !== witnessPublic || typeof cosig.sig !== 'string' || resolveSigAlg(cosig.alg) === null) return false;
    return verifyWithSuite(
      cosig.alg,
      { edPub: witnessPublic, mlDsaPub: cosig.pq_pk },
      sthWitnessMessage(sth, cosig.alg, cosig.pq_pk),
      { sig: cosig.sig, pq_sig: cosig.pq_sig },
    );
  } catch {
    return false;
  }
}

/**
 * k-of-n verification of an STH's witness cosignatures. FAIL-CLOSED: an UNKNOWN witness (key not in the
 * trusted set), a DUPLICATE trusted key (counted at most once), and a MIS-BOUND / tampered signature (one
 * that does not verify over this exact {size, root, prev_root, guardian_epoch}) none of them count toward
 * the threshold. Returns true iff at least `threshold` DISTINCT trusted witnesses carry a valid cosignature.
 * `threshold === 0` is vacuously satisfied (no witnesses demanded). Never throws.
 */
export function verifyWitnessCosignatures(sth: SignedTreeHead, policy: WitnessPolicy): boolean {
  try {
    const threshold = policy?.threshold;
    if (!Number.isInteger(threshold) || threshold! < 0) return false;
    if (threshold === 0) return true;
    const trusted = new Set(policy.witnessKeys ?? []);
    if (trusted.size === 0) return false;
    const witnesses = sth?.witnesses;
    if (!Array.isArray(witnesses)) return false;
    const counted = new Set<string>();
    for (const w of witnesses) {
      if (!w || typeof w.key !== 'string' || typeof w.sig !== 'string') continue;
      if (!trusted.has(w.key) || counted.has(w.key)) continue; // unknown or duplicate
      // Suite-agile per cosignature (each binds its own alg + the witness ML-DSA key); ed25519 == before.
      if (!verifyWitnessCosignature(sth, w, w.key)) continue; // mis-bound / tampered / unknown suite
      counted.add(w.key);
      if (counted.size >= threshold!) return true;
    }
    return counted.size >= threshold!;
  } catch {
    return false;
  }
}

export function signTreeHead(
  guardianSecret: Uint8Array,
  head: Omit<SignedTreeHead, 'guardian' | 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>,
  suite?: LedgerSuiteOpts,
): SignedTreeHead {
  const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
  // The suite fields are bound into the signed body (sthMessage reads alg/pq_pk off the head).
  const annotated = { ...head, ...bindSuiteFields({}, suite?.alg, pqPk) } as Omit<SignedTreeHead, 'guardian' | 'sig'>;
  const fields = signSuiteArtifact(suite?.alg, { edSecret: guardianSecret, mlDsa: suite?.mlDsa }, sthMessage(annotated));
  return {
    instance_id: head.instance_id,
    principal: head.principal,
    size: head.size,
    root: head.root,
    prev_root: head.prev_root,
    timestamp: head.timestamp,
    guardian: b64u(publicKeyOf(guardianSecret)),
    ...fields,
  };
}

/**
 * Verify an STH against the (pinned) guardian public key. Never throws.
 *
 * When `requireWitnessThreshold` is supplied (opt-in), the head ALSO has to carry at least `threshold`
 * distinct valid cosignatures from the trusted witness set — a monitor can thus refuse a head the operator
 * signed alone. Omitting it leaves the check exactly as before (a witness-less head still verifies).
 */
export function verifyTreeHead(
  sth: SignedTreeHead,
  guardianPublic: string,
  requireWitnessThreshold?: WitnessPolicy,
): boolean {
  try {
    if (!sth || sth.guardian !== guardianPublic || resolveSigAlg(sth.alg) === null) return false;
    if (!Number.isSafeInteger(sth.size) || sth.size < 0) return false;
    if (!verifyWithSuite(sth.alg, { edPub: guardianPublic, mlDsaPub: sth.pq_pk }, sthMessage(sth), { sig: sth.sig, pq_sig: sth.pq_sig })) return false;
    if (requireWitnessThreshold && !verifyWitnessCosignatures(sth, requireWitnessThreshold)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Pin-and-check: both heads must be genuine, for the same instance + log, and the consistency proof
 * must connect `older` to `newer` (an append-only extension). A forged, truncated or rewritten head
 * fails. Never throws.
 *
 * HASH-CHAIN ENFORCEMENT (hardening). The STH carries a SIGNED `prev_root` — the root of the log's
 * immediately-preceding STH — which used to be decorative (never verified; only the RFC 9162 consistency
 * proof linked the two roots). It is now REAL: when `older` is the immediate predecessor of `newer`
 * (consecutive heads under the per-append STH model, `older.size + 1 === newer.size`), the signed
 * `newer.prev_root` MUST equal `older.root`, IN ADDITION to the consistency-proof check. This catches a
 * guardian-signed head that carries a forged/inconsistent `prev_root` even when a valid (or forged)
 * Merkle consistency proof would otherwise accept it — the hash chain and the Merkle proof must agree.
 * For a NON-adjacent pin (skip-ahead), `prev_root` links to an intermediate STH not supplied here, so the
 * consistency proof remains the sole cross-size check (unchanged). No signed byte of the STH changes.
 */
export function verifyHeadConsistency(
  older: SignedTreeHead,
  newer: SignedTreeHead,
  proof: ConsistencyProof,
  guardianPublic: string,
  requireWitnessThreshold?: WitnessPolicy,
): boolean {
  try {
    if (
      !verifyTreeHead(older, guardianPublic, requireWitnessThreshold) ||
      !verifyTreeHead(newer, guardianPublic, requireWitnessThreshold)
    )
      return false;
    if (older.instance_id !== newer.instance_id || older.principal !== newer.principal) return false;
    if (proof.oldSize !== older.size || proof.newSize !== newer.size) return false;
    // Enforce the signed prev_root hash-chain link when `older` is `newer`'s immediate predecessor.
    if (newer.size === older.size + 1 && newer.prev_root !== older.root) return false;
    return verifyLedgerConsistency(older.root, newer.root, proof);
  } catch {
    return false;
  }
}
