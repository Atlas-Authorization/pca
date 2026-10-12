import { snapshotConfig } from './config-snapshot';
import { decideThreshold, type ThresholdReason } from '@atlasauth/pca-verified-core';
import { b64u, canonicalBytes, compareUtf8, decodeB64uStrict, sha256, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import {
  SIG_SUITES,
  type SignerSuiteOpts,
  type SigAlg,
  resolveSigAlg,
  signWithSuite,
  verifyLeafSuite,
  verifyWithSuite,
  suiteKeysOf,
  resolvePqVerifyKey,
  type PinnedPqKey,
} from './pq';
import { pqBindingError } from './capability';
import { type PCActn, type ThresholdVerifier, type VerifyContext, thresholdMessage } from './pcactn';

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
   * role's `ml-dsa-65` / `hybrid` share is verified against it. Present => the role REQUIRES a PQ (pure or
   * hybrid) share (R6-02): an ed25519-only share, or an ed25519 agent-leaf baseline, does not count for it.
   * Absent => the role is ed25519-only and the signer set hashes byte-identically to pre-agility.
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
  /**
   * OPTIONAL echo of the role's PQ key. It never selects the key (the signer set's registered `pq_pk` does), but when a share
   * names one it MUST be exactly the role's registered `pq_pk`: a different key, a non-string, or a `pq_pk` on a share for a
   * role that registers none is refused ('share ... names a pq_pk that is not the key its role registers').
   */
  pq_pk?: string;
}

/** Optional per-share signature suite material (default ed25519, byte-identical to pre-agility). */
export type ShareSuiteOpts = SignerSuiteOpts;

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
 * The bytes EVERY role's SHARE signs (audit security-section finding 2): role-, signer-set- and t-bound, so
 * a share cannot be replayed under another role, in a different signer set, or at a different threshold:
 *
 *     "atlas-pca/share/<role>\0" || sha256(thresholdMessage) || signerSetHash || t   (t = ONE byte, 1..3)
 *
 * v2.1 AGENT-LEAF BINDING (this change): the AGENT role's EXPLICIT threshold share now signs these same
 * signerSetHash‖t-bound bytes — role `'agent'` — EXACTLY like guardian / principal. Previously the agent
 * share signed the bare `thresholdMessage`, relying only on the implicit one-key-one-role binding; that bare
 * form is NO LONGER accepted by {@link verifyThreshold} (a bare agent share is rejected). This is a clean
 * break on the threshold wire (PCA is Preview; all SDKs regenerate from the conformance corpus).
 *
 * The one thing that stays bare is the PCActn LEAF SIGNATURE `p.sig` itself: it signs `thresholdMessage`
 * directly because it predates knowing the signer set (the leaf-signed body is unchanged, and the
 * `leaf_signature` verifier check is untouched). {@link createThresholdVerifier} admits that leaf signature
 * as the agent's "effective t=1" baseline (§6 L2) via the one-key-one-role rule — it is NOT a bound share
 * and is handled by its own code path, not by this role-bound share message.
 */
const SHARE_SUITE_TAG = '\0atlas-pca/share-suite/v1\0';

/**
 * Version marker for the v2.1 agent-leaf share binding (GAP 2). Guardian / principal share bytes are
 * UNCHANGED by this change; only the agent EXPLICIT share moved from the bare threshold message to the
 * role/set/t-bound {@link shareMessage}. SDKs regenerate from the conformance corpus, which carries this
 * marker in its `agent_leaf_binding` metadata field.
 */
export const AGENT_LEAF_SHARE_BINDING_VERSION = '2.1';

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

/** Registered signer-set `pq_pk` must be canonical b64u of some registered suite's PQ public-key length (any supported suite). */
const PQ_PK_LENGTHS: ReadonlySet<number> = new Set(Object.values(SIG_SUITES).map((x) => x.pqPkBytes).filter((n) => n > 0));
function isPqPkOfSomeSuite(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const bytes = decodeB64uStrict(v);
  return bytes !== null && PQ_PK_LENGTHS.has(bytes.length);
}

/**
 * Produce a role's EXPLICIT threshold share. For EVERY role — `agent` (v2.1), `guardian`, `principal` — the
 * signed bytes are {@link shareMessage}(role, message, signerSet, t, suite?.alg), so `bind` (the signer set
 * + t the share is for) is REQUIRED for all of them. A bare agent share (no `bind`) is no longer produced:
 * the agent's explicit share is now signerSetHash‖t-bound exactly like the others (so it cannot be replayed
 * into a different signer-set / threshold context). The PCActn leaf signature `p.sig` is NOT produced here;
 * it is the leaf baseline and `createThresholdVerifier` admits it on its own path.
 *
 * `suite` (default ed25519) makes a share post-quantum: for `ml-dsa-65`/`hybrid` it signs through
 * {@link signWithSuite} and emits `alg` + `pq_sig`; the role's `mlDsa` public key must be registered as the
 * signer set's `pq_pk` for that role. ed25519 / absent is byte-identical to the pre-agility share.
 */
export function signShare(
  role: SignerRole,
  secretKey: Uint8Array,
  message: Uint8Array,
  bind?: { signerSet: Signer[]; t: number },
  suite?: ShareSuiteOpts,
): ThresholdShare {
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
  const parts = signWithSuite(suite!.alg, suiteKeysOf(secretKey, suite), preparedShareMessage);
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
 * The PCActn LEAF-signature baseline, admitted as the agent's "effective t=1" share (§6 L2). It is the
 * leaf signature `p.sig` over the BARE `message` (== `thresholdMessage`), verified under the agent's suite —
 * NOT a signerSetHash‖t-bound share. It counts only when its `holder` equals the signer set's registered
 * 'agent' key and that key is not already satisfied by an explicit (bound) share. Supplied by
 * {@link createThresholdVerifier}; omitted by generic callers (whose agent shares must be bound).
 */
export interface AgentLeafBaseline {
  /** The capability-chain leaf holder (b64u Ed25519) — must equal the registered 'agent' key to count. */
  holder: string;
  /** The PCActn's `sig` (b64u). */
  sig: unknown;
  /** The PCActn's `alg` (suite); absent => ed25519. */
  alg?: unknown;
  /** The PCActn's `pq_pk` (b64u PQ key) for a PQ / hybrid leaf. */
  pqPk?: unknown;
  /** The PCActn's `pq_sig` (b64u) for a hybrid leaf. */
  pqSig?: unknown;
  /** The leaf capability's `holder_pq` commitment (F-2): the artifact's `pqPk` must hash to it unless the signer set registers the agent's PQ key. */
  holderPq?: string;
  /** LEGACY opt-out of the F-2 binding (default false). */
  allowUnboundPq?: boolean;
}

/** R6-02: true iff `alg` names a known suite with a PQ component (pure PQ or hybrid); absent / ed25519 / unknown => false. */
function suiteHasPq(alg: unknown): boolean {
  const suite = resolveSigAlg(alg);
  return suite !== null && suite.needsPqPk;
}

/** R3-01: the agent baseline's PQ key via the choke point: the registered signer-set key, else the leaf's `holder_pq` commitment. */
function baselineKey(b: AgentLeafBaseline, agentKey: string, registered: string | undefined): { pq?: PinnedPqKey } {
  const pq =
    registered !== undefined
      ? resolvePqVerifyKey(agentKey, undefined, { trustedPk: registered })
      : resolvePqVerifyKey(agentKey, b.pqPk, { holderPq: b.holderPq, allowUnboundPq: b.allowUnboundPq });
  return pq === null ? {} : { pq };
}

/**
 * Verify a t-of-n multi-signature over `message` (= `thresholdMessage(pcactn)`).
 *
 * The signer set is validated FIRST and the whole verification fails closed if it is malformed: every role
 * is a known role, each role has EXACTLY ONE registered key, and no public key is registered under two
 * roles (so one key can never satisfy two role slots — closes the `holder == principal` collapse). `t` must
 * be 1, 2 or 3. A share counts iff its role+key are registered and its signature verifies over that role's
 * signerSetHash‖t-bound `shareMessage` — v2.1: this now includes the `agent` role (a bare agent share, over
 * `message` itself, is REJECTED). The count is of DISTINCT KEYS. Deterministic and TOTAL — never throws.
 *
 * `baseline` (optional, additive) admits the PCActn leaf signature as the agent's effective-t=1 baseline
 * (see {@link AgentLeafBaseline}); generic callers omit it and are unaffected.
 */
export function verifyThreshold(
  sig: ThresholdSignature,
  message: Uint8Array,
  signerSet: Signer[],
  t: number,
  baseline?: AgentLeafBaseline,
): ThresholdVerdict {
  // TRUSTED GLUE + VERIFIED DECISION. This function evaluates every primitive (strict key parsing, the share and leaf
  // signature checks, the R3-01 PQ-key choke point) and hands the RESULTS to the machine-proved
  // `decideThreshold` (formal/dafny/Threshold.dfy: Verify), which validates the signer set (one key per role, one role
  // per key), counts DISTINCT keys/roles, applies the t rule and picks the first failure reason. The proved code runs in
  // production; see docs/pca/security/verified-core.md. `scripts/check-verified-core.sh` fails if this call is removed.
  const set: Signer[] = Array.isArray(signerSet) ? signerSet : [];
  const pqKeyOfRole = new Map<SignerRole, string | undefined>();
  const seenEntry = new Map<string, string | undefined>();
  const signers = set.map((s) => {
    const role = s ? asRole(s.role) : undefined;
    const keyOk = !!s && decodeB64uStrict(s.publicKey, 32) !== null;
    let pqOk = !s || s.pq_pk === undefined || isPqPkOfSomeSuite(s.pq_pk);
    if (role !== undefined && keyOk && pqOk) {
      // R6-03: a duplicate (role, key) entry is harmless only if it registers the SAME pq_pk (or none on both); a
      // conflicting pq_pk would make the role's PQ key depend on first-wins / last-wins resolution, so the set is refused.
      const id = role + '\0' + s.publicKey;
      const pq = typeof s.pq_pk === 'string' ? s.pq_pk : undefined;
      if (seenEntry.has(id) && seenEntry.get(id) !== pq) pqOk = false;
      else seenEntry.set(id, pq);
    }
    if (role !== undefined && keyOk && pqOk && !pqKeyOfRole.has(role)) pqKeyOfRole.set(role, typeof s.pq_pk === 'string' ? s.pq_pk : undefined);
    return { role, keyOk, pqOk, key: s?.publicKey as string };
  });
  const rawShares: ThresholdShare[] = sig && Array.isArray(sig.shares) ? sig.shares : [];
  const shares = rawShares.map((share) => {
    const wellFormed = !!share && typeof share.role === 'string' && typeof share.publicKey === 'string';
    return {
      wellFormed,
      role: wellFormed ? asRole(share.role) : undefined,
      key: share?.publicKey as string,
      algKnown: wellFormed && resolveSigAlg(share.alg) !== null,
      // a share that names its own pq_pk must name exactly its role's registered one (absent on both = fine)
      pqPkOk: !wellFormed || !Object.hasOwn(share, 'pq_pk') || (typeof share.pq_pk === 'string' && share.pq_pk === pqKeyOfRole.get(asRole(share.role)!)),
      // v2.1: EVERY role (agent included) signs the role/set/t/suite-bound share message; a bare agent share no longer verifies.
      sigOk: () => {
        const signed = shareMessage(share.role, message, signerSet, t, share.alg);
        // the signer set's registered pq_pk is the verifier-side pin (R3-01 choke point); the share's suite selects the primitive
        const registeredPq = pqKeyOfRole.get(share.role);
        // R6-02: a role that registers a pq_pk MUST be satisfied by a PQ (pure or hybrid) share; an Ed25519-only
        // share for it would let an Ed25519 break forge the role, so it does not count.
        if (registeredPq !== undefined && !suiteHasPq(share.alg)) return false;
        const resolved = registeredPq !== undefined ? resolvePqVerifyKey(share.publicKey, undefined, { trustedPk: registeredPq }) : null;
        const shareKey = resolved !== null ? { pq: resolved } : {};
        return typeof share.sig === 'string' && verifyWithSuite(share.alg, { edPub: share.publicKey, ...shareKey }, signed, { sig: share.sig, pq_sig: share.pq_sig });
      },
    };
  });
  // Agent-leaf BASELINE (§6 L2 effective t=1): the PCActn leaf signature over the BARE `message`, admitted as the agent's share.
  const bl = baseline
    ? {
        holderIsString: typeof baseline.holder === 'string',
        holder: baseline.holder,
        pqKeyOk: () => {
          if (pqKeyOfRole.get('agent') !== undefined) return true;
          return pqBindingError(baseline.alg, baseline.pqPk, baseline.holderPq, 'threshold baseline', { allowUnboundPq: baseline.allowUnboundPq }) === undefined;
        },
        leafSigOk: () => {
          const agentKey = baseline.holder;
          // R6-02: same rule for the leaf baseline: an agent with a registered pq_pk needs a PQ / hybrid leaf.
          if (pqKeyOfRole.get('agent') !== undefined && !suiteHasPq(baseline.alg)) return false;
          return verifyLeafSuite({ alg: baseline.alg, holder: agentKey, ...baselineKey(baseline, agentKey, pqKeyOfRole.get('agent')), message, sig: baseline.sig, pqSig: baseline.pqSig });
        },
      }
    : undefined;
  const d = decideThreshold<string>(signers, shares, Number.isSafeInteger(t) ? t : -1, bl);
  if (d.ok) return { ok: true, count: d.count, roles: d.roles };
  return { ok: false, count: d.count, roles: d.roles, reason: renderThresholdReason(d.reason!, set, rawShares, t, d.count) };
}

const asRole = (r: unknown): SignerRole | undefined => (ROLES.includes(r as SignerRole) ? (r as SignerRole) : undefined);

/** Reason text for a possibly hostile value: primitives as `String(v)`, containers by kind only. `String()` of a nested
 *  array joins it RECURSIVELY, so a deeply nested `t` / role would exhaust the stack and break totality. */
const showValue = (v: unknown): string => (v !== null && typeof v === 'object' ? (Array.isArray(v) ? '<array>' : '<object>') : String(v));

function renderThresholdReason(r: ThresholdReason, signerSet: Signer[], shares: readonly { role?: unknown }[], t: unknown, count: number): string {
  switch (r.kind) {
    case 'invalid-t':
      return `invalid threshold t=${showValue(t)} (must be 1, 2 or 3)`;
    case 'set-malformed':
      return 'malformed signer set';
    case 'set-pq':
      return 'malformed signer set (pq_pk)';
    case 'two-keys-for-role':
      return 'signer set registers more than one key for role ' + showValue(signerSet[r.entry]?.role);
    case 'one-key-two-roles':
      return 'signer set registers one key under two roles';
    case 'malformed-share':
      return 'malformed share';
    case 'role-not-in-set':
      return `role ${showValue(shares[r.share]?.role)} is not in the signer set`;
    case 'key-not-registered':
      return `share for role ${showValue(shares[r.share]?.role)} uses a key not registered for that role`;
    case 'unknown-alg':
      return `share for role ${showValue(shares[r.share]?.role)} declares an unknown signature alg`;
    case 'pq-pk-mismatch':
      return `share for role ${showValue(shares[r.share]?.role)} names a pq_pk that is not the key its role registers`;
    case 'invalid-sig':
      return `invalid signature for role ${showValue(shares[r.share]?.role)}`;
    case 'need-more':
      return `only ${count} distinct valid key(s), need ${showValue(t)}`;
  }
  return 'unreachable';
}

export interface ThresholdVerifierOpts {
  /** The roles + public keys permitted to co-sign. MUST register the agent role's key = the leaf. */
  signerSet: Signer[];
  /**
   * Fixed required threshold, decided by the SERVER. Exactly one of `t` / `requiredT` MUST be supplied.
   * There is deliberately NO default derived from the PCActn's `risk_claim.r`: that value is the AGENT's own
   * claim, and a threshold derived from it lets a compromised agent claim r=0 and be held to t=1 (finding F-1).
   */
  t?: number;
  /**
   * Derive the required `t` from SERVER-HELD data only (your own recomputed risk, the grant's risk policy,
   * the action class). Takes precedence over `t`. It must never read `ctx.pcactn.risk_claim`.
   * `verifyPCActn` additionally refuses any hook whose enforced `t` is below the server's own decision.
   */
  requiredT?: (ctx: VerifyContext) => number;
  /** LEGACY: accept an agent-leaf PQ key not committed by `holder_pq` nor registered in the signer set (F-2). Default false. */
  allowUnboundPq?: boolean;
}

/**
 * Build a `ThresholdVerifier` hook (the L2/M4 hook interface in pcactn.ts). Given a PCActn it:
 *  1. recomputes the canonical signed message via `thresholdMessage` (the SAME bytes the agent
 *     `sig` and every share cover — one definition, no drift);
 *  2. verifies the EXPLICIT (signerSetHash‖t-bound, v2.1) shares carried in `pcactn.threshold`, and
 *     ALSO admits the PCActn's own leaf signature `pcactn.sig` as the agent's effective-t=1 BASELINE
 *     (the `AgentLeafBaseline` passed to `verifyThreshold`) — which is why a t=1 action with only the
 *     baseline `sig` and no `threshold` field still passes. A separately-transmitted, bound agent share
 *     (if present) supersedes the baseline (same key, counted once);
 *  3. resolves the required `t` (a fixed `t` or a server-side `requiredT`; one is MANDATORY, there is no
 *     agent-claim-derived default), and returns an ENFORCED pass/fail that also reports the `t` it enforced,
 *     so `verifyPCActn` can reject a hook enforcing less than the server's own threshold.
 */
export function createThresholdVerifier(opts: ThresholdVerifierOpts): ThresholdVerifier {
  opts = snapshotConfig(opts); // freeze the configuration: later edits by the caller must not change what this verifier enforces

  if (typeof opts.requiredT !== 'function' && opts.t === undefined) {
    throw new TypeError(
      'createThresholdVerifier: supply `t` or `requiredT` derived from SERVER-held data. The risk_claim.r-derived default was removed (F-1): it is the agent\'s own claim.',
    );
  }
  const resolveT = opts.requiredT ?? (() => opts.t as number);
  return (ctx: VerifyContext) => {
    const p: PCActn = ctx.pcactn;
    const message = thresholdMessage(p);
    const explicit: ThresholdShare[] = p.threshold && Array.isArray(p.threshold.shares) ? p.threshold.shares : [];
    const chain = p.cap_chain;
    const leaf = Array.isArray(chain) ? chain[chain.length - 1] : undefined;
    const baseline: AgentLeafBaseline | undefined =
      leaf && typeof leaf.holder === 'string' && typeof p.sig === 'string'
        ? { holder: leaf.holder, sig: p.sig, alg: p.alg, pqPk: p.pq_pk, pqSig: p.pq_sig, holderPq: leaf.holder_pq, allowUnboundPq: opts.allowUnboundPq }
        : undefined;
    const t = resolveT(ctx);
    const verdict = verifyThreshold({ shares: explicit }, message, opts.signerSet, t, baseline);
    return verdict.ok
      ? { enforced: true, ok: true, t }
      : { enforced: true, ok: false, reason: verdict.reason ?? 'threshold not met', t };
  };
}
