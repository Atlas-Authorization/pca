import { b64u, canonicalBytes, compareUtf8, decodeB64uStrict, sha256, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import {
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type MlDsaKeyPair,
  type SigAlg,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from './pq';
import { type PCActn, type ThresholdVerifier, type VerifyContext, thresholdMessage } from './pcactn';
import { readEnvelope } from './envelope';
import { requiredThreshold } from './risk';

/**
 * Risk-adaptive threshold signatures (spec §6 L2 "policy-as-cosigner", §6 L3 "risk-adaptive
 * threshold", Deep Dive I "mathematically short of a key").
 *
 * This is a SOUND t-of-n MULTI-SIGNATURE: a threshold signature is a bag of `t` INDEPENDENT
 * Ed25519 signatures, each produced by a distinct allowed role over the SAME canonical message
 * (`thresholdMessage(pcactn)`). Verification counts the number of DISTINCT roles whose share both
 * (a) is signed by that role's registered key and (b) verifies over the message; the signature is
 * accepted iff that count is >= t.
 *
 * The security property (Deep Dive I): a PCActn requiring threshold `t` cannot be accepted without
 * `t` distinct valid signatures from the allowed signer set. A compromised agent holds only the
 * agent key, so it can produce exactly ONE share — it is `t-1` short for anything above t=1. The
 * guardian share is released only by the Policy VM on a compliant action, and the principal share
 * requires a human; neither can be forged from the agent key. Authority is "a property of a
 * verified computation, not of a possessed secret."
 *
 * GUARDIAN COSIGN IS NOW A FROST THRESHOLD SIGNATURE (§15 M4). The 'guardian' role's share is no longer
 * a single Ed25519 signature minted by one key the server holds — it is a FROST(Ed25519) AGGREGATE
 * produced by a quorum of guardian participants whose group key was established by the no-dealer DKG
 * (`frost-dkg.ts`), released only once the Policy VM has ALLOWED the action (`frost.ts` `frostCosign`).
 * Because a FROST aggregate is byte-for-byte an ordinary Ed25519 signature under the group public key,
 * NOTHING changes here: the 'guardian' entry in the signer set is simply the FROST GROUP public key, and
 * `verifyThreshold` checks the aggregate under it with the EXACT same `verifyB64u` call as any other
 * share. The security property is strengthened from "a compromised agent holds only the agent key" to
 * "a compromised agent — and a server that skips the Policy VM — is mathematically short of ≥ t_guardian
 * FROST shares", which is literally true once those shares live in separate trust domains (nodes / HSMs);
 * the in-process coordinator is the reference. The agent / principal roles remain plain Ed25519 shares.
 *
 * The 'agent' and 'principal' roles could likewise collapse into the FROST aggregate (set the leaf
 * `holder` to a group key, as the `FROST ⨯ PCActn` test shows); that is a further wire-size optimization
 * that does not change the security property proven above. The multi-signature form stays the DEFAULT
 * carrier because it is simple and auditable — each role contributes an independently-verifiable share.
 */

export type SignerRole = 'agent' | 'guardian' | 'principal';

/** A registered member of the signer set: the public key (b64u) allowed to sign for `role`. */
export interface Signer {
  role: SignerRole;
  /** b64u Ed25519 public key. */
  publicKey: string;
  /**
   * OPTIONAL b64u ML-DSA-65 public key registered for this role (crypto-agility). When present it is
   * bound into {@link signerSetHash} (so it cannot be swapped without invalidating every share), and a
   * role's `ml-dsa-65` / `hybrid` share is verified against it. Absent => the role is ed25519-only and
   * the signer set hashes byte-identically to pre-agility.
   */
  pq_pk?: string;
}

/** One role's independent signature (see {@link shareMessage} for exactly what is signed). */
export interface ThresholdShare {
  role: SignerRole;
  /** b64u Ed25519 public key that produced `sig` (the role's registered Ed25519 key). */
  publicKey: string;
  /** b64u signature: Ed25519 for ed25519/hybrid, ML-DSA-65 for pure ml-dsa-65. */
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility). For
   * `ml-dsa-65` / `hybrid` the suite is bound into the share's signed bytes (so a downgrade of a share
   * fails), and the ML-DSA key is the role's registered `pq_pk` in the signer set. The GUARDIAN role is
   * the highest-priority to run `hybrid` (its key is long-lived), so a quantum adversary must break both.
   */
  alg?: SigAlg;
  /** b64u ML-DSA-65 signature — present for hybrid only (alongside the Ed25519 `sig`). */
  pq_sig?: string;
}

/** Optional per-share signature suite material (default ed25519, byte-identical to pre-agility). */
export interface ShareSuiteOpts {
  alg?: SigAlg;
  /** The role's ML-DSA-65 key pair — required for ml-dsa-65 / hybrid. Its public key must be the signer set's `pq_pk` for the role. */
  mlDsa?: MlDsaKeyPair;
}

/** A t-of-n multi-signature: the collected shares. `t` itself lives in the risk policy, not here. */
export interface ThresholdSignature {
  shares: ThresholdShare[];
}

/** The legal required thresholds (L1 agent-only, L2 + guardian, L3 + principal). */
export const VALID_THRESHOLDS = [1, 2, 3] as const;
const isValidT = (t: unknown): t is 1 | 2 | 3 => t === 1 || t === 2 || t === 3;

const SIGNER_SET_DOMAIN = 'atlas-pca/signerset/v1\0';

/**
 * Hash of a signer set: sha256(DOMAIN || canonical(sorted [{publicKey, role}])), sorted bytewise by
 * (role, publicKey). Order-insensitive, so signer and verifier agree however the set is listed.
 */
export function signerSetHash(signerSet: Signer[]): Uint8Array {
  const rows = (Array.isArray(signerSet) ? signerSet : [])
    .map((s) => {
      // ADDITIVE: carry the registered ML-DSA key ONLY when present, so an ed25519-only signer set
      // hashes byte-identically to pre-agility; a registered `pq_pk` becomes part of the bound set.
      const row: { publicKey: string; role: string; pq_pk?: string } = { publicKey: String(s?.publicKey), role: String(s?.role) };
      if (typeof s?.pq_pk === 'string') row.pq_pk = s.pq_pk;
      return row;
    })
    .sort((a, b) => compareUtf8(a.role, b.role) || compareUtf8(a.publicKey, b.publicKey));
  return sha256(concat(utf8(SIGNER_SET_DOMAIN), canonicalBytes(rows)));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * The bytes a guardian / principal SHARE signs (audit security-section finding 2): role-, signer-set- and
 * t-bound, so a share cannot be replayed under another role, in a different signer set, or at a different
 * threshold:
 *
 *     "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t   (t = ONE byte, 1..3)
 *
 * The AGENT role's share is the PCActn leaf signature `sig`, which signs `thresholdMessage` directly (the
 * leaf-signed body is unchanged); its role/set/t binding is carried by the leaf key being the single
 * registered 'agent' key in the signer set.
 */
const SHARE_SUITE_TAG = '\0atlas-pca/share-suite/v1\0';

/**
 * Domain-separated suite tag appended to a share's signed bytes for a NON-default suite, so a hybrid or
 * ml-dsa-65 share cannot be stripped back to ed25519 (a downgraded share's ed25519 signature was minted
 * over the tagged bytes and no longer verifies over the untagged ones). ed25519 / absent / unknown =>
 * zero bytes, so the share message is byte-identical to pre-agility.
 */
function shareSuiteTag(alg: SigAlg | undefined): Uint8Array {
  const suite = resolveSigAlg(alg);
  if (suite === null || suite.alg === 'ed25519') return new Uint8Array(0);
  return utf8(SHARE_SUITE_TAG + suite.alg);
}

export function shareMessage(role: SignerRole, message: Uint8Array, signerSet: Signer[], t: number, alg?: SigAlg): Uint8Array {
  if (!isValidT(t)) throw new RangeError('shareMessage: t must be 1, 2 or 3');
  return concat(utf8(`atlas-pca/share/${role}\0`), sha256(message), signerSetHash(signerSet), new Uint8Array([t]), shareSuiteTag(alg));
}

/**
 * Produce a role's share. For 'guardian' / 'principal' the signed bytes are {@link shareMessage}(role, message,
 * signerSet, t, suite?.alg) — `bind` (the signer set + t the share is for) is REQUIRED. The 'agent' share signs
 * `message` itself (it is the leaf signature; its PQ agility rides on the leaf/pcactn seam, not here).
 *
 * `suite` (default ed25519) makes a guardian/principal share post-quantum: for `ml-dsa-65`/`hybrid` it signs
 * through {@link signWithSuite} and emits `alg` + `pq_sig`; the role's `mlDsa` public key must be registered as
 * the signer set's `pq_pk` for that role. ed25519 / absent is byte-identical to the pre-agility share.
 */
export function signShare(
  role: SignerRole,
  secretKey: Uint8Array,
  message: Uint8Array,
  bind?: { signerSet: Signer[]; t: number },
  suite?: ShareSuiteOpts,
): ThresholdShare {
  if (role === 'agent') return { role, publicKey: b64u(publicKeyOf(secretKey)), sig: b64u(sign(secretKey, message)) };
  if (!bind) throw new TypeError(`signShare: a '${role}' share must bind {signerSet, t}`);
  return signPreparedShare(role, secretKey, shareMessage(role, message, bind.signerSet, bind.t, suite?.alg), suite);
}

/** Sign already-computed share bytes (e.g. the `share_message` a step-up hands a principal device). */
export function signPreparedShare(
  role: SignerRole,
  secretKey: Uint8Array,
  preparedShareMessage: Uint8Array,
  suite?: ShareSuiteOpts,
): ThresholdShare {
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new RangeError(`signPreparedShare: unknown signature alg '${String(suite?.alg)}'`);
  const publicKey = b64u(publicKeyOf(secretKey));
  if (resolved.alg === 'ed25519') {
    // Byte-identical to the pre-agility share (no alg/pq_sig fields emitted).
    return { role, publicKey, sig: b64u(sign(secretKey, preparedShareMessage)) };
  }
  const parts = signWithSuite(suite!.alg, { edSecret: secretKey, mlDsa: suite!.mlDsa }, preparedShareMessage);
  const share: ThresholdShare = { role, publicKey, sig: parts.sig, alg: resolved.alg };
  if (parts.pq_sig !== undefined) share.pq_sig = parts.pq_sig;
  return share;
}

/** Collect shares into a ThresholdSignature (defensively copied). */
export function assembleThreshold(shares: ThresholdShare[]): ThresholdSignature {
  return { shares: Array.isArray(shares) ? [...shares] : [] };
}

export interface ThresholdVerdict {
  ok: boolean;
  /** number of DISTINCT valid KEYS (== distinct roles: the signer set maps one key to one role). */
  count: number;
  /** the roles whose key contributed a valid share, in first-seen order. */
  roles: SignerRole[];
  reason?: string;
}

const ROLES: readonly SignerRole[] = ['agent', 'guardian', 'principal'];

/**
 * Verify a t-of-n multi-signature over `message` (= `thresholdMessage(pcactn)`).
 *
 * The signer set is validated FIRST and the whole verification fails closed if it is malformed: every role
 * is a known role, each role has EXACTLY ONE registered key, and no public key is registered under two
 * roles (so one key can never satisfy two role slots — closes the `holder == principal` collapse). `t` must
 * be 1, 2 or 3. A share counts iff its role+key are registered and its signature verifies over that role's
 * message (`shareMessage`, or `message` itself for the agent/leaf share). The count is of DISTINCT KEYS.
 * Deterministic and TOTAL — never throws.
 */
export function verifyThreshold(
  sig: ThresholdSignature,
  message: Uint8Array,
  signerSet: Signer[],
  t: number,
): ThresholdVerdict {
  const fail = (reason: string): ThresholdVerdict => ({ ok: false, count: 0, roles: [], reason });
  if (!isValidT(t)) return fail(`invalid threshold t=${String(t)} (must be 1, 2 or 3)`);

  const keyOfRole = new Map<SignerRole, string>();
  const pqKeyOfRole = new Map<SignerRole, string | undefined>();
  const roleOfKey = new Map<string, SignerRole>();
  for (const s of Array.isArray(signerSet) ? signerSet : []) {
    if (!s || !ROLES.includes(s.role) || decodeB64uStrict(s.publicKey, 32) === null) return fail('malformed signer set');
    // A registered ML-DSA key, when present, must be well-formed (fail-closed on a malformed one).
    if (s.pq_pk !== undefined && decodeB64uStrict(s.pq_pk, ML_DSA_65_PUBLIC_KEY_BYTES) === null) return fail('malformed signer set (pq_pk)');
    const prevKey = keyOfRole.get(s.role);
    if (prevKey !== undefined && prevKey !== s.publicKey) return fail(`signer set registers more than one key for role ${s.role}`);
    const prevRole = roleOfKey.get(s.publicKey);
    if (prevRole !== undefined && prevRole !== s.role) return fail('signer set registers one key under two roles');
    keyOfRole.set(s.role, s.publicKey);
    pqKeyOfRole.set(s.role, typeof s.pq_pk === 'string' ? s.pq_pk : undefined);
    roleOfKey.set(s.publicKey, s.role);
  }

  const validKeys = new Set<string>();
  const validRoles: SignerRole[] = [];
  let reason: string | undefined;

  for (const share of sig && Array.isArray(sig.shares) ? sig.shares : []) {
    if (!share || typeof share.role !== 'string' || typeof share.publicKey !== 'string') {
      reason ??= 'malformed share';
      continue;
    }
    if (validKeys.has(share.publicKey)) continue; // a key counts once
    const registeredKey = keyOfRole.get(share.role);
    if (registeredKey === undefined) {
      reason ??= `role ${share.role} is not in the signer set`;
      continue;
    }
    if (share.publicKey !== registeredKey) {
      reason ??= `share for role ${share.role} uses a key not registered for that role`;
      continue;
    }
    // Fail-closed on an unknown suite BEFORE recomputing the message.
    if (resolveSigAlg(share.alg) === null) {
      reason ??= `share for role ${share.role} declares an unknown signature alg`;
      continue;
    }
    // The agent share signs `message` (the leaf) directly; others sign the role/set/t/suite-bound share
    // message. The suite tag inside `shareMessage` binds `share.alg`, so a downgraded share fails here.
    const signed = share.role === 'agent' ? message : shareMessage(share.role, message, signerSet, t, share.alg);
    const mlDsaPub = pqKeyOfRole.get(share.role);
    if (typeof share.sig !== 'string' || !verifyWithSuite(share.alg, { edPub: share.publicKey, mlDsaPub }, signed, { sig: share.sig, pq_sig: share.pq_sig })) {
      reason ??= `invalid signature for role ${share.role}`;
      continue;
    }
    validKeys.add(share.publicKey);
    validRoles.push(share.role);
  }

  const count = validKeys.size;
  const ok = count >= t;
  if (ok) return { ok, count, roles: validRoles };
  return { ok, count, roles: validRoles, reason: reason ?? `only ${count} distinct valid key(s), need ${t}` };
}

export interface ThresholdVerifierOpts {
  /** The roles + public keys permitted to co-sign. MUST register the agent role's key = the leaf. */
  signerSet: Signer[];
  /**
   * Fixed required threshold. If omitted, `requiredT` (or the default risk-derived resolver) sets
   * it per action, per Appendix A step 7: `t = requiredThreshold(risk_claim.r, G.risk_policy).t`.
   */
  t?: number;
  /** Override how the required `t` is derived from the verify context. Takes precedence over `t`. */
  requiredT?: (ctx: VerifyContext) => number;
}

/** Default: Appendix A step 7 — t from the action's claimed risk against the grant's risk policy. */
function riskDerivedT(ctx: VerifyContext): number {
  const env = readEnvelope(ctx.grant);
  if (!env) return 1; // no policy to consult => agent-leaf baseline.
  const r = ctx.pcactn?.risk_claim?.r;
  return requiredThreshold(typeof r === 'number' ? r : 1, env.risk_policy).t;
}

/**
 * Build a `ThresholdVerifier` hook (the L2/M4 hook interface in pcactn.ts). Given a PCActn it:
 *  1. recomputes the canonical signed message via `thresholdMessage` (the SAME bytes the agent
 *     `sig` and every share cover — one definition, no drift);
 *  2. assembles the shares to check = the agent-leaf share (role 'agent', key = the capability
 *     chain's leaf holder, sig = pcactn.sig) PLUS any shares carried in `pcactn.threshold`. This is
 *     why a t=1 action with only the baseline `sig` and no `threshold` field still passes;
 *  3. resolves the required `t` (fixed, custom, or risk-derived), and returns an ENFORCED pass/fail
 *     from `verifyThreshold`.
 */
export function createThresholdVerifier(opts: ThresholdVerifierOpts): ThresholdVerifier {
  const resolveT = opts.requiredT ?? (opts.t !== undefined ? () => opts.t as number : riskDerivedT);
  return (ctx: VerifyContext) => {
    const p: PCActn = ctx.pcactn;
    const message = thresholdMessage(p);
    const shares: ThresholdShare[] = [];
    const chain = p.cap_chain;
    const leaf = Array.isArray(chain) ? chain[chain.length - 1] : undefined;
    if (leaf && typeof leaf.holder === 'string' && typeof p.sig === 'string') {
      shares.push({ role: 'agent', publicKey: leaf.holder, sig: p.sig });
    }
    if (p.threshold && Array.isArray(p.threshold.shares)) shares.push(...p.threshold.shares);
    const t = resolveT(ctx);
    const verdict = verifyThreshold({ shares }, message, opts.signerSet, t);
    return verdict.ok
      ? { enforced: true, ok: true }
      : { enforced: true, ok: false, reason: verdict.reason ?? 'threshold not met' };
  };
}
