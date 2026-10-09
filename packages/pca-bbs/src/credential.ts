/**
 * PCA layer: a Proof-Carrying Authority capability as a multi-message BBS credential.
 *
 * A PCA {@link Capability} authorizes a holder under an issuer, constrained by an append-only list
 * of caveats (scopes/limits). Normally a capability travels as a signed chain and is presented
 * whole — every attribute is visible to whoever verifies it. That is fine for a server, but it
 * leaks: a tool that only needs to know "the holder may call search" also learns the budget caveat,
 * the delegation lineage, and a stable signature value it can use to correlate requests.
 *
 * Here we map the capability's attributes to an ORDERED BBS message vector and sign it once. The
 * holder can then present it with SELECTIVE DISCLOSURE: reveal only the attributes a given tool
 * needs, and prove in zero knowledge that the issuer signed the rest — without showing them, and
 * without showing the signature. Because every presentation re-randomizes the signature, two
 * presentations of the same credential are UNLINKABLE.
 *
 * ## Attribute ↔ message mapping
 *
 * The message vector is, in order:
 *   - index 0: `iss` — the issuer public key
 *   - index 1: `sub` — the holder (subject) public key
 *   - index 2..: one message per caveat, name `cav:<i>:<type>`, value the strict-canonical JSON of
 *     the caveat object (so a caveat's full content is one atomically-disclosable attribute).
 *
 * Each message's octets are `utf8(name) || 0x00 || utf8(value)`: the NUL separator makes the name
 * unambiguous, and binding the name into the signed message means a verifier that reconstructs a
 * disclosed attribute from `{name, value}` gets byte-identical octets, so disclosing index `i` as a
 * different attribute cannot verify.
 *
 * ## Relationship to a PCActn
 *
 * A PCActn (proof-carrying action) normally carries the capability chain plus a signed action/plan
 * commitment, which the adjudicator verifies in full. For privacy-sensitive flows, the capability
 * component can instead be carried as a {@link BBSPresentation}: the agent discloses only the
 * attributes the action needs (e.g. the scope caveat that authorizes this exact tool call) and
 * proves knowledge of the issuer's signature over the whole credential. The presentation header
 * (`ph`) binds the proof to the action — pass the PCActn's action/nonce digest as `presentationHeader`
 * so a proof minted for one action cannot be replayed against another. The adjudicator then checks
 * the BBS proof in place of the raw signed chain; the undisclosed attributes stay hidden and the
 * action is still cryptographically bound to an issuer-signed grant.
 */
import type { Capability, Caveat } from '@atlasauth/pca';
import { b64u, canonicalizeStrict, unb64u } from '@atlasauth/pca';
import { proofGen, proofVerify, sign, verify } from './bbs';

const NAME_ISSUER = 'iss';
const NAME_HOLDER = 'sub';
const NUL = 0x00;
const TEXT = new TextEncoder();

/** One disclosable attribute of a capability credential, at its position in the message vector. */
export interface CredentialAttribute {
  /** Position in the BBS message vector (0 = issuer, 1 = holder, 2.. = caveats). */
  index: number;
  /** Stable attribute name (`iss`, `sub`, or `cav:<i>:<type>`). */
  name: string;
  /** The attribute's value (a key for `iss`/`sub`, strict-canonical JSON for a caveat). */
  value: string;
}

/** A capability signed as a BBS credential. Portable; `signature` is the issuer's BBS signature. */
export interface BBSCredential {
  /** b64u of the issuer's BBS public key (G2 point). */
  issuerPublicKey: string;
  /** b64u of the signed header (application context bound into the signature). */
  header: string;
  /** The ordered attribute vector that was signed. */
  attributes: CredentialAttribute[];
  /** b64u of the 80-octet BBS signature. */
  signature: string;
}

/** A selective-disclosure presentation of a {@link BBSCredential}. Self-contained and verifiable. */
export interface BBSPresentation {
  /** b64u of the issuer's BBS public key the proof is under. */
  issuerPublicKey: string;
  /** b64u of the credential header the proof was made over. */
  header: string;
  /** b64u of the presentation header (`ph`) binding the proof to a context/action. */
  presentationHeader: string;
  /** Total number of messages in the credential (L). */
  messageCount: number;
  /** The attributes actually revealed, each at its original index. */
  disclosed: CredentialAttribute[];
  /** b64u of the BBS proof octets. */
  proof: string;
}

/** Deterministic message octets for one attribute: utf8(name) || 0x00 || utf8(value). */
function encodeAttribute(name: string, value: string): Uint8Array {
  const n = TEXT.encode(name);
  const v = TEXT.encode(value);
  const out = new Uint8Array(n.length + 1 + v.length);
  out.set(n, 0);
  out[n.length] = NUL;
  out.set(v, n.length + 1);
  return out;
}

function encode(attr: CredentialAttribute): Uint8Array {
  return encodeAttribute(attr.name, attr.value);
}

/** Build the ordered attribute vector for a capability (issuer, holder, then each caveat). */
export function capabilityAttributes(capability: Pick<Capability, 'issuer' | 'holder' | 'caveats'>): CredentialAttribute[] {
  const attrs: CredentialAttribute[] = [
    { index: 0, name: NAME_ISSUER, value: capability.issuer },
    { index: 1, name: NAME_HOLDER, value: capability.holder },
  ];
  const caveats: Caveat[] = Array.isArray(capability.caveats) ? capability.caveats : [];
  caveats.forEach((cv, i) => {
    attrs.push({ index: i + 2, name: `cav:${i}:${cv.type}`, value: canonicalizeStrict(cv) });
  });
  return attrs;
}

/**
 * issueCapabilityCredential: sign a capability's attributes as a BBS credential.
 * `header` is optional application context bound into the signature (not selectively disclosable).
 */
export function issueCapabilityCredential(
  capability: Pick<Capability, 'issuer' | 'holder' | 'caveats'>,
  opts: { sk: bigint; pk: Uint8Array; header?: Uint8Array },
): BBSCredential {
  const attributes = capabilityAttributes(capability);
  const header = opts.header ?? new Uint8Array(0);
  const messages = attributes.map(encode);
  const signature = sign(opts.sk, opts.pk, header, messages);
  return {
    issuerPublicKey: b64u(opts.pk),
    header: b64u(header),
    attributes,
    signature: b64u(signature),
  };
}

/** Verify a whole credential against its issuer key (no disclosure — checks every attribute). */
export function verifyCredential(cred: BBSCredential): boolean {
  let pk: Uint8Array;
  let header: Uint8Array;
  let signature: Uint8Array;
  try {
    pk = unb64u(cred.issuerPublicKey);
    header = unb64u(cred.header);
    signature = unb64u(cred.signature);
  } catch {
    return false;
  }
  const messages = cred.attributes.map(encode);
  return verify(pk, signature, header, messages);
}

/**
 * presentCredential: produce a selective-disclosure proof revealing only the named attributes.
 * `presentationHeader` binds the proof to a context (e.g. the PCActn action digest / a nonce).
 */
export function presentCredential(
  cred: BBSCredential,
  opts: { disclose: readonly string[]; presentationHeader?: Uint8Array },
): BBSPresentation {
  const pk = unb64u(cred.issuerPublicKey);
  const header = unb64u(cred.header);
  const signature = unb64u(cred.signature);
  const ph = opts.presentationHeader ?? new Uint8Array(0);

  const wanted = new Set(opts.disclose);
  const messages = cred.attributes.map(encode);
  const disclosedIndexes: number[] = [];
  const disclosed: CredentialAttribute[] = [];
  for (const attr of cred.attributes) {
    if (wanted.has(attr.name)) {
      disclosedIndexes.push(attr.index);
      disclosed.push(attr);
    }
  }
  const missing = [...wanted].filter((name) => !disclosed.some((d) => d.name === name));
  if (missing.length > 0) throw new RangeError(`presentCredential: unknown attribute(s): ${missing.join(', ')}`);

  const proof = proofGen(pk, signature, header, ph, messages, disclosedIndexes);
  return {
    issuerPublicKey: cred.issuerPublicKey,
    header: cred.header,
    presentationHeader: b64u(ph),
    messageCount: cred.attributes.length,
    disclosed,
    proof: b64u(proof),
  };
}

/**
 * verifyPresentation: check a selective-disclosure proof. Verifies that the issuer (`pk`) signed a
 * credential whose disclosed attributes are exactly `disclosed` at their indexes, bound to
 * `presentationHeader`. The undisclosed attributes stay hidden.
 *
 * `pk`, `disclosed` and `presentationHeader` default to the values carried in the presentation, so
 * `verifyPresentation(pres)` checks it as-is; pass them to assert the verifier's own expectations
 * (e.g. a pinned issuer key, the exact attributes the tool requires, or the action digest the proof
 * must be bound to).
 */
export function verifyPresentation(
  pres: BBSPresentation,
  opts?: { pk?: Uint8Array; disclosed?: readonly CredentialAttribute[]; presentationHeader?: Uint8Array },
): boolean {
  let pk: Uint8Array;
  let header: Uint8Array;
  let proof: Uint8Array;
  try {
    pk = opts?.pk ?? unb64u(pres.issuerPublicKey);
    header = unb64u(pres.header);
    proof = unb64u(pres.proof);
  } catch {
    return false;
  }

  // If the verifier pinned an issuer key, it must match the one the presentation claims.
  if (opts?.pk !== undefined && b64u(opts.pk) !== pres.issuerPublicKey) return false;

  const ph = opts?.presentationHeader ?? safeDecode(pres.presentationHeader);
  if (ph === null) return false;
  // If the verifier pinned a presentation header, it must match the one the proof was made over.
  if (opts?.presentationHeader !== undefined && opts.presentationHeader.length > 0 && b64u(ph) !== pres.presentationHeader) {
    return false;
  }

  const disclosed = opts?.disclosed ?? pres.disclosed;
  // When the verifier asserts its own expected disclosure, it must match what the presentation shows.
  if (opts?.disclosed !== undefined && !sameDisclosure(opts.disclosed, pres.disclosed)) return false;

  const ordered = [...disclosed].sort((a, b) => a.index - b.index);
  const disclosedMessages = ordered.map(encode);
  const disclosedIndexes = ordered.map((d) => d.index);
  if (disclosedIndexes.some((i) => i >= pres.messageCount || i < 0)) return false;

  return proofVerify(pk, proof, header, ph, disclosedMessages, disclosedIndexes);
}

function safeDecode(s: string): Uint8Array | null {
  try {
    return unb64u(s);
  } catch {
    return null;
  }
}

function sameDisclosure(a: readonly CredentialAttribute[], b: readonly CredentialAttribute[]): boolean {
  if (a.length !== b.length) return false;
  const key = (x: CredentialAttribute): string => `${x.index}\u0000${x.name}\u0000${x.value}`;
  const sa = a.map(key).sort();
  const sb = b.map(key).sort();
  return sa.every((v, i) => v === sb[i]);
}
