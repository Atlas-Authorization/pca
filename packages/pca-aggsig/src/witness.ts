import { type SignedTreeHead, b64u, canonicalBytes, unb64u, utf8 } from '@atlasauth/pca';
import { aggregate, fastAggregateVerify, publicKeyOf, sign } from './bls';
import { BLS_SUITE } from './chain';

/**
 * BLS aggregation of transparency-ledger witness cosignatures (the C2SP tlog-witness / Sigsum model).
 *
 * In `@atlasauth/pca`'s ledger, a quorum of trusted witnesses each cosign the SAME tree-head statement
 * — `{ size, root, prev_root, guardian_epoch }` — under their own key, turning a self-attested Signed
 * Tree Head into an anti-equivocation artefact. With Ed25519 that is N independent signatures the
 * monitor verifies one by one. Here each witness cosigns with the BLS12-381 PoP scheme, so
 * {@link aggregateWitnessCosignatures} collapses the whole quorum into ONE 96-byte aggregate and
 * {@link verifyAggregatedWitnessCosignatures} checks it with a single FastAggregateVerify (all
 * witnesses signed the identical STH statement → same-message aggregation).
 */

/** Domain separator — distinct from the Ed25519 ledger's `atlas-pca/sth-witness/v1`, so a BLS
 *  cosignature can never be confused with (or replayed against) the core witness domain. */
const STH_WITNESS_BLS_DOMAIN = 'atlas-pca/sth-witness-bls/v1\0';

/** The tree-head statement a witness binds to — the same fields the core ledger cosigns. */
export type SthStatement = Pick<SignedTreeHead, 'size' | 'root' | 'prev_root' | 'guardian_epoch'>;

/** A BLS C2SP tlog-witness cosignature. */
export interface BlsWitnessCosignature {
  /** b64u BLS12-381 G1 witness public key. */
  key: string;
  /** b64u BLS12-381 G2 signature over the domain-separated STH statement. */
  sig: string;
  suite: typeof BLS_SUITE;
}

/** The exact bytes a witness cosigns: domain separator followed by the canonical STH statement. */
function witnessMessage(h: SthStatement): Uint8Array {
  const body = canonicalBytes({
    size: h.size,
    root: h.root,
    prev_root: h.prev_root,
    guardian_epoch: h.guardian_epoch ?? 0,
  });
  const p = utf8(STH_WITNESS_BLS_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/** A trusted witness cosigns the tree-head statement with its BLS secret key. */
export function cosignTreeHead(statement: SthStatement, witnessSecret: Uint8Array): BlsWitnessCosignature {
  return {
    key: b64u(publicKeyOf(witnessSecret)),
    sig: b64u(sign(witnessSecret, witnessMessage(statement))),
    suite: BLS_SUITE,
  };
}

/** Verify ONE cosignature against the exact tree-head statement. Never throws. */
export function verifyWitnessCosignature(statement: SthStatement, cosig: BlsWitnessCosignature): boolean {
  try {
    if (cosig === null || typeof cosig !== 'object' || cosig.suite !== BLS_SUITE) return false;
    return fastAggregateVerify([unb64u(cosig.key)], witnessMessage(statement), unb64u(cosig.sig));
  } catch {
    return false;
  }
}

/**
 * Collapse a quorum of witness cosignatures into ONE 96-byte aggregate. Throws on an empty set or a
 * cosignature whose `sig` is not valid b64u.
 */
export function aggregateWitnessCosignatures(cosigs: BlsWitnessCosignature[]): Uint8Array {
  if (!Array.isArray(cosigs) || cosigs.length === 0) throw new RangeError('aggregateWitnessCosignatures: empty set');
  return aggregate(cosigs.map((c) => unb64u(c.sig)));
}

/**
 * Verify an aggregate of witness cosignatures over ONE tree-head statement with a single
 * FastAggregateVerify. `witnessKeys` are the b64u public keys whose cosignatures were aggregated (the
 * caller supplies exactly the quorum it trusts); every key is KeyValidate'd. Never throws; returns
 * `false` on an empty set, a malformed key, or a failed pairing check.
 */
export function verifyAggregatedWitnessCosignatures(statement: SthStatement, witnessKeys: string[], aggSig: Uint8Array): boolean {
  try {
    if (!Array.isArray(witnessKeys) || witnessKeys.length === 0) return false;
    const pks = witnessKeys.map((k) => unb64u(k));
    return fastAggregateVerify(pks, witnessMessage(statement), aggSig);
  } catch {
    return false;
  }
}
