/**
 * SIGNED GROUP DESCRIPTOR: pins the FROST threshold to the group key.
 *
 * A FROST aggregate is a plain Ed25519 signature, so a verifier looking at (group key, signature) cannot tell
 * whether the key was dealt 1-of-5 or 3-of-5: a "t" supplied by the caller or declared in the artifact is a
 * label, not a fact. The fact has to come from whoever ran setup. At DKG / dealing time an AUTHORITY key (the
 * setup ceremony's coordinator, a root of trust the verifier already pins) signs a descriptor:
 *
 *     { v, suite, groupPublicKey, t, n, signerSetCommitment }
 *
 * and the verifier refuses an aggregate unless a descriptor (a) verifies under a pinned authority key, (b) is
 * for exactly the pinned group key, (c) has `t` EQUAL to the threshold the verifier requires, and (d) is
 * well formed (1 <= t <= n). `signerSetCommitment` commits to the participants' verification shares, so the
 * descriptor also fixes WHO the n signers are (a membership change needs a new descriptor).
 *
 * Why an authority and not "the group signs its own descriptor": a group that was dealt 1-of-n can produce a
 * valid self-signature claiming 3-of-n, since one participant alone can sign. Only a signer outside the group
 * can attest how the group was formed. The authority is a trust assumption, stated rather than hidden: a
 * compromised authority can certify a false t. Its key is the thing the verifier pins.
 *
 * Ed25519 (strict RFC 8032 verification) and SHA-256 come from `@atlasauth/pca`; nothing is reimplemented.
 */

import {
  type ParticipantId,
  b64u,
  canonicalBytes,
  decodeB64uStrict,
  publicKeyOf,
  sha256,
  sign,
  utf8,
  verify,
} from '@atlasauth/pca';

export const GROUP_DESCRIPTOR_VERSION = 1 as const;
export const GROUP_SUITE = 'frost-ed25519' as const;
const DESCRIPTOR_DOMAIN = 'atlas-pca-pq-threshold/group-descriptor/v1\0';
const SIGNER_SET_DOMAIN = 'atlas-pca-pq-threshold/signer-set/v1\0';
/** Upper bound on n (bounds the work of committing to, and checking, a signer set). */
export const MAX_GROUP_SIZE = 1024;

export interface GroupDescriptor {
  readonly v: typeof GROUP_DESCRIPTOR_VERSION;
  readonly suite: typeof GROUP_SUITE;
  /** b64u(32) FROST group public key. */
  readonly groupPublicKey: string;
  /** Threshold the group key was shared for. */
  readonly t: number;
  /** Number of participants. */
  readonly n: number;
  /** b64u(32) {@link signerSetCommitment} of the participants' verification shares. */
  readonly signerSetCommitment: string;
}

export interface SignedGroupDescriptor {
  readonly descriptor: GroupDescriptor;
  /** b64u(32) Ed25519 public key of the issuing authority. */
  readonly authority: string;
  /** b64u(64) Ed25519 signature over the domain-separated canonical descriptor. */
  readonly sig: string;
}

export interface GroupParticipant {
  readonly identifier: ParticipantId;
  /** 32-byte verification share (`FrostParticipantShare.publicKey`). */
  readonly publicKey: Uint8Array | string;
}

const asB64u = (k: Uint8Array | string): string => (k instanceof Uint8Array ? b64u(k) : k);

/** Commitment to the signer set: `sha256(DOMAIN || canonical(sorted [{id, pk}]))`. Order-insensitive; ids distinct. */
export function signerSetCommitment(participants: readonly GroupParticipant[]): string {
  if (!Array.isArray(participants) || participants.length === 0 || participants.length > MAX_GROUP_SIZE) {
    throw new RangeError(`signerSetCommitment: need 1..${MAX_GROUP_SIZE} participants`);
  }
  const rows = participants.map((p) => {
    const pk = asB64u(p.publicKey);
    if (typeof p.identifier !== 'number' || !Number.isSafeInteger(p.identifier) || p.identifier <= 0) {
      throw new RangeError('signerSetCommitment: participant identifiers must be positive safe integers');
    }
    if (decodeB64uStrict(pk, 32) === null) throw new RangeError('signerSetCommitment: verification share is not a canonical b64u(32) value');
    return { id: p.identifier, pk };
  });
  rows.sort((a, b) => a.id - b.id);
  for (let i = 1; i < rows.length; i++) {
    if (rows[i]?.id === rows[i - 1]?.id) throw new RangeError('signerSetCommitment: duplicate participant identifier');
  }
  const body = canonicalBytes(rows);
  const d = utf8(SIGNER_SET_DOMAIN);
  const m = new Uint8Array(d.length + body.length);
  m.set(d);
  m.set(body, d.length);
  return b64u(sha256(m));
}

function descriptorBytes(d: GroupDescriptor): Uint8Array {
  const body = canonicalBytes({
    v: d.v,
    suite: d.suite,
    group_pk: d.groupPublicKey,
    t: d.t,
    n: d.n,
    signer_set: d.signerSetCommitment,
  });
  const p = utf8(DESCRIPTOR_DOMAIN);
  const m = new Uint8Array(p.length + body.length);
  m.set(p);
  m.set(body, p.length);
  return m;
}

/**
 * Issue a descriptor at DKG / dealing time. `authoritySecretKey` is the setup authority's Ed25519 secret key.
 * Throws on an impossible group (t < 1, t > n, n != participants.length, a group key that is not canonical b64u(32)).
 */
export function issueGroupDescriptor(args: {
  authoritySecretKey: Uint8Array;
  groupPublicKey: Uint8Array | string;
  t: number;
  participants: readonly GroupParticipant[];
}): SignedGroupDescriptor {
  const { t } = args;
  const n = args.participants.length;
  if (!Number.isInteger(t) || t < 1 || t > n) throw new RangeError(`issueGroupDescriptor: need 1 <= t <= n (t=${String(t)}, n=${n})`);
  const groupPublicKey = asB64u(args.groupPublicKey);
  if (decodeB64uStrict(groupPublicKey, 32) === null) throw new RangeError('issueGroupDescriptor: group public key is not canonical b64u(32)');
  if (!(args.authoritySecretKey instanceof Uint8Array) || args.authoritySecretKey.length !== 32) throw new RangeError('issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key');
  const descriptor: GroupDescriptor = {
    v: GROUP_DESCRIPTOR_VERSION,
    suite: GROUP_SUITE,
    groupPublicKey,
    t,
    n,
    signerSetCommitment: signerSetCommitment(args.participants),
  };
  return {
    descriptor,
    authority: b64u(publicKeyOf(args.authoritySecretKey)),
    sig: b64u(sign(args.authoritySecretKey, descriptorBytes(descriptor))),
  };
}

export type DescriptorCheck = { ok: true; descriptor: GroupDescriptor } | { ok: false; reason: string };

export interface DescriptorExpectations {
  /** Pinned b64u(32) Ed25519 keys of the setup authorities the verifier trusts. */
  readonly trustedAuthorities: readonly (Uint8Array | string)[];
  /** The verifier's pinned FROST group key. */
  readonly groupKey: Uint8Array | string;
  /** The threshold the verifier requires; the descriptor's `t` must EQUAL it. */
  readonly t: number;
  /** Optional: pin the signer set too. */
  readonly signerSetCommitment?: string;
}

/** Check a signed descriptor against the verifier's pins. Never throws. */
export function verifyGroupDescriptor(s: unknown, exp: DescriptorExpectations): DescriptorCheck {
  const fail = (reason: string): DescriptorCheck => ({ ok: false, reason });
  try {
    if (s === null || typeof s !== 'object') return fail('no signed group descriptor: the threshold is unattested');
    const x = s as Partial<SignedGroupDescriptor>;
    const d = x.descriptor;
    if (d === null || typeof d !== 'object' || typeof x.authority !== 'string' || typeof x.sig !== 'string') return fail('malformed group descriptor');
    if (d.v !== GROUP_DESCRIPTOR_VERSION || d.suite !== GROUP_SUITE) return fail('unsupported group descriptor version or suite');
    if (typeof d.groupPublicKey !== 'string' || typeof d.signerSetCommitment !== 'string') return fail('malformed group descriptor');
    if (!Number.isInteger(d.t) || !Number.isInteger(d.n) || d.t < 1 || d.n < d.t || d.n > MAX_GROUP_SIZE) return fail('malformed group descriptor: need 1 <= t <= n');
    const trusted = new Set(exp.trustedAuthorities.map(asB64u));
    if (!trusted.has(x.authority)) return fail('group descriptor authority is not trusted');
    const authorityKey = decodeB64uStrict(x.authority, 32);
    const sig = decodeB64uStrict(x.sig, 64);
    if (authorityKey === null || sig === null) return fail('malformed authority key or signature');
    if (!verify(authorityKey, descriptorBytes(d), sig)) return fail('group descriptor signature does not verify');
    if (d.groupPublicKey !== asB64u(exp.groupKey)) return fail('group descriptor is for a different group key');
    if (!Number.isInteger(exp.t) || exp.t < 1) return fail('required t must be a positive integer');
    if (d.t !== exp.t) return fail(`group was set up as ${d.t}-of-${d.n} but ${exp.t} is required: the threshold is not bound to this key`);
    if (exp.signerSetCommitment !== undefined && d.signerSetCommitment !== exp.signerSetCommitment) return fail('group descriptor is for a different signer set');
    return { ok: true, descriptor: d };
  } catch {
    return fail('group descriptor could not be verified (malformed)');
  }
}
