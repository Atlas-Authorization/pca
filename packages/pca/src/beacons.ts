/**
 * Dead-man liveness beacons v2 + global kill switch (Deep Dive II "Sovereign kill switch", audit P2-4).
 *
 * An issuer (the grant's principal, or the operator/guardian) signs short-lived beacons. Authority is live
 * only while a valid beacon covers the current moment; if the issuer stops issuing, every agent freezes by
 * the next (short) epoch.
 *
 * NOTE: legacy beacon v1 ({scope, epoch, not_after}, no `instance` and no `seq`) was REMOVED — it was
 * replayable across instances and could not be superseded. It had no consumers outside its own tests. Use the
 * v2 LivenessBeacon below, which binds an `instance`, enforces a strictly monotonic `seq`, and hard-caps
 * validity.
 */
import { b64u, canonicalBytes, sha256, utf8 } from './hash';
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

export const GLOBAL_SCOPE = '*';

export interface BeaconVerdict {
  ok: boolean;
  reason?: string;
}

// ---------------------------------------------------------------------------------------------
// Liveness beacons v2 (audit P2-4): the DEAD-MAN layer. A beacon is `{instance, scope, epoch, seq,
// issued_at, not_after, issuer}` signed by an issuer key. The issuer is EITHER the grant's principal
// (so a principal halts their agents just by withholding, without trusting the operator) OR the
// operator/guardian. Properties enforced here:
//   - explicit epoch length (epoch = floor(issued_at / BEACON_EPOCH_MS)),
//   - a HARD maximum validity (BEACON_MAX_VALIDITY_MS) no issuer can exceed,
//   - a strictly monotonic `seq` per (instance, scope, issuer) so an older beacon cannot be replayed
//     over a newer one (`acceptBeacon`),
//   - fail-closed: absent / stale / unpinned-issuer / wrong-scope beacon => frozen.
// The PCActn binds a beacon through its existing signed `freshness.beacon_ref` (= `beaconRef(b)`), so
// no wire change is needed.
// ---------------------------------------------------------------------------------------------

const LIVENESS_DOMAIN = 'atlas-pca/beacon/v2\0';
/** Length of one beacon epoch. */
export const BEACON_EPOCH_MS = 60_000;
/** HARD ceiling on `not_after - issued_at`: no issuer can mint a longer-lived beacon. */
export const BEACON_MAX_VALIDITY_MS = 60 * 60_000;
/** Tolerated clock skew for a beacon issued "in the future". */
export const BEACON_CLOCK_SKEW_MS = 30_000;

export interface LivenessBeacon {
  v: 2;
  instance: string;
  /** '*' = every grant of the instance; otherwise a grant_ref. */
  scope: string;
  epoch: number;
  seq: number;
  issued_at: number;
  not_after: number;
  /** Issuer public key (b64u Ed25519 identity): the principal's registered key or the operator/guardian key. */
  issuer: string;
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility). For
   * `ml-dsa-65`/`hybrid` the suite + the issuer's ML-DSA key `pq_pk` are SIGNED INTO the beacon body,
   * and `sig`/`pq_sig` carry the component signatures.
   */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the issuer — ml-dsa-65 / hybrid (body-bound). */
  pq_pk?: string;
  /** b64u ML-DSA-65 beacon signature — hybrid only. */
  pq_sig?: string;
}

/** Optional signature-suite material for a liveness-beacon signature (default ed25519). */
export interface BeaconSuiteOpts {
  alg?: SigAlg;
  /** The issuer's ML-DSA-65 key pair — required for ml-dsa-65 / hybrid. */
  mlDsa?: MlDsaKeyPair;
}

type LivenessBody = Omit<LivenessBeacon, 'sig'>;

function livenessMsg(b: LivenessBody): Uint8Array {
  const body = canonicalBytes(
    bindSuiteFields(
      {
        v: b.v,
        instance: b.instance,
        scope: b.scope,
        epoch: b.epoch,
        seq: b.seq,
        issued_at: b.issued_at,
        not_after: b.not_after,
        issuer: b.issuer,
      },
      b.alg,
      b.pq_pk,
    ),
  );
  const p = utf8(LIVENESS_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/** The unsigned body a principal signs client-side (then submits as a full beacon). */
export function livenessBeaconMessage(b: LivenessBody): Uint8Array {
  return livenessMsg(b);
}

export function issueLivenessBeacon(args: {
  issuerSecret: Uint8Array;
  instance: string;
  scope?: string;
  seq: number;
  issuedAt: number;
  /** ms of validity from issuedAt; clamped-checked against the hard maximum (throws if above). */
  validityMs?: number;
  /** Signature suite (default ed25519, byte-identical). For ml-dsa-65/hybrid pass the issuer's ML-DSA key pair. */
  suite?: BeaconSuiteOpts;
}): LivenessBeacon {
  const validity = args.validityMs ?? 5 * BEACON_EPOCH_MS;
  if (!Number.isInteger(args.seq) || args.seq < 0) throw new RangeError('issueLivenessBeacon: seq must be a non-negative integer');
  if (!Number.isInteger(args.issuedAt) || args.issuedAt < 0) throw new RangeError('issueLivenessBeacon: issuedAt must be an integer');
  if (!Number.isInteger(validity) || validity <= 0 || validity > BEACON_MAX_VALIDITY_MS) {
    throw new RangeError(`issueLivenessBeacon: validity must be in (0, ${BEACON_MAX_VALIDITY_MS}] ms`);
  }
  const suite = args.suite;
  const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
  const body: LivenessBody = {
    v: 2,
    instance: args.instance,
    scope: args.scope ?? GLOBAL_SCOPE,
    epoch: Math.floor(args.issuedAt / BEACON_EPOCH_MS),
    seq: args.seq,
    issued_at: args.issuedAt,
    not_after: args.issuedAt + validity,
    issuer: b64u(publicKeyOf(args.issuerSecret)),
    ...bindSuiteFields({}, suite?.alg, pqPk),
  };
  const fields = signSuiteArtifact(suite?.alg, { edSecret: args.issuerSecret, mlDsa: suite?.mlDsa }, livenessMsg(body));
  return { ...body, ...fields };
}

/** Stable reference to a beacon: what the PCActn commits in `freshness.beacon_ref`. */
export function beaconRef(b: LivenessBeacon): string {
  return b64u(sha256(canonicalBytes({ ...b })));
}

export interface LivenessCheck {
  /** Pinned issuer key(s): the grant principal and/or the operator/guardian. */
  issuers: readonly string[];
  now: number;
  instance: string;
  /** The grant_ref being exercised: the beacon's scope must be '*' or equal this. */
  scope?: string;
}

/** Signature, pinned issuer, instance + scope binding, HARD max validity, and the freshness window. Never throws. */
export function verifyLivenessBeacon(b: LivenessBeacon, o: LivenessCheck): BeaconVerdict {
  try {
    if (!b || b.v !== 2 || resolveSigAlg(b.alg) === null) return { ok: false, reason: 'malformed beacon' };
    if (b.instance !== o.instance) return { ok: false, reason: 'wrong instance' };
    if (!o.issuers.includes(b.issuer)) return { ok: false, reason: 'issuer not pinned' };
    if (!verifyWithSuite(b.alg, { edPub: b.issuer, mlDsaPub: b.pq_pk }, livenessMsg(b), { sig: b.sig, pq_sig: b.pq_sig })) return { ok: false, reason: 'bad signature' };
    if (![b.epoch, b.seq, b.issued_at, b.not_after].every(Number.isInteger) || b.seq < 0) {
      return { ok: false, reason: 'malformed window' };
    }
    if (b.not_after <= b.issued_at || b.not_after - b.issued_at > BEACON_MAX_VALIDITY_MS) {
      return { ok: false, reason: 'validity exceeds the hard maximum' };
    }
    if (b.epoch !== Math.floor(b.issued_at / BEACON_EPOCH_MS)) return { ok: false, reason: 'epoch does not match issued_at' };
    if (o.now + BEACON_CLOCK_SKEW_MS < b.issued_at) return { ok: false, reason: 'not yet valid' };
    if (o.now > b.not_after) return { ok: false, reason: 'expired' };
    if (o.scope !== undefined && b.scope !== GLOBAL_SCOPE && b.scope !== o.scope) {
      return { ok: false, reason: 'scope not covered' };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: 'malformed beacon' };
  }
}

/**
 * Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher `seq` (same
 * instance + scope + issuer). A replayed older (or equal) beacon is rejected, so a captured beacon
 * cannot be re-presented to resurrect a halted grant.
 */
export function acceptBeacon(prev: Pick<LivenessBeacon, 'seq'> | null | undefined, next: LivenessBeacon): BeaconVerdict {
  if (prev && !(next.seq > prev.seq)) return { ok: false, reason: `replayed beacon: seq ${next.seq} <= ${prev.seq}` };
  return { ok: true };
}

/** Frozen unless at least one beacon verifies for (instance, scope, now). Absence is a freeze. */
export function isFrozenLiveness(beacons: readonly LivenessBeacon[], o: LivenessCheck): boolean {
  return !beacons.some((b) => verifyLivenessBeacon(b, o).ok);
}
