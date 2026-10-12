import { ed25519 } from '@noble/curves/ed25519';
import { b64u, sha256, verifyB64u } from '@atlasauth/pca';
import {
  type BudgetProof,
  type RiskRangeProof,
  type RiskUnits,
  commitRisk,
  proveRiskRange,
  verifyBoundedBudget,
} from './accumulator';
import { type RatchetSignature, leafNullifier, verifyLeafSignature } from './ratchet';
import { utf8 } from './group';

/**
 * Verifier-side bindings that the stateless primitives cannot give on their own (red-team RT-11):
 *
 *  1. {@link verifyLeafSignatureOnce}: a spent-leaf store so a SECOND signature at the same leaf is
 *     detected (replay) and a different message at the same leaf is flagged as equivocation, with
 *     both signed digests as evidence. Ed25519 is deterministic and the ratchet holds no
 *     verifier-extractable secret, so this is DETECTION by the verifier, not key extraction.
 *  2. {@link issueRiskCommitment} / {@link verifyAttestedBudget}: the risk commitment is created
 *     by the party that COMPUTES the risk (a risk authority) and signed together with the action
 *     digest, so a prover cannot commit 0 for a 1.0-risk action or move a commitment between actions.
 */

type MaybePromise<T> = T | Promise<T>;

// ---- (1) spent-leaf store ------------------------------------------------------------

/** Atomic first-claim store keyed by leaf nullifier. */
export interface SpentLeafStore {
  /**
   * Atomically record `record` under `nullifier` if absent. Resolve `{ first: true }` on first claim,
   * else `{ first: false, record }` with the record stored earlier.
   */
  claim(nullifier: string, record: string): MaybePromise<{ first: true } | { first: false; record: string }>;
}

/** In-process {@link SpentLeafStore}. Per process: use a shared store for a verifier fleet. */
export function memorySpentLeafStore(): SpentLeafStore {
  const seen = new Map<string, string>();
  return {
    claim(nullifier, record) {
      const prev = seen.get(nullifier);
      if (prev !== undefined) return { first: false, record: prev };
      seen.set(nullifier, record);
      return { first: true };
    },
  };
}

export type LeafUseResult =
  | { ok: true }
  | { ok: false; reason: 'invalid' }
  | { ok: false; reason: 'replay'; nullifier: string }
  | { ok: false; reason: 'equivocation'; nullifier: string; firstMessageDigest: string; secondMessageDigest: string }
  | { ok: false; reason: 'store-error' };

function messageDigest(leafIndex: number, message: Uint8Array): string {
  return b64u(sha256(message)) + '@' + String(leafIndex);
}

/**
 * Verify a leaf signature AND enforce one-time use at the verifier: the first valid signature at a
 * leaf is accepted and its message digest recorded; any later signature at that leaf is refused as
 * `replay` (same message) or `equivocation` (different message, the evidence of a holder that kept an
 * old state). Fail closed: a store that throws denies.
 */
export async function verifyLeafSignatureOnce(
  rootCommitment: string,
  leafIndex: number,
  message: Uint8Array,
  signature: RatchetSignature,
  store: SpentLeafStore,
): Promise<LeafUseResult> {
  if (!verifyLeafSignature(rootCommitment, leafIndex, message, signature)) return { ok: false, reason: 'invalid' };
  const nullifier = leafNullifier(rootCommitment, leafIndex);
  const mine = messageDigest(leafIndex, message);
  try {
    const r = await store.claim(nullifier, mine);
    if (r.first) return { ok: true };
    if (r.record === mine) return { ok: false, reason: 'replay', nullifier };
    return { ok: false, reason: 'equivocation', nullifier, firstMessageDigest: r.record, secondMessageDigest: mine };
  } catch {
    return { ok: false, reason: 'store-error' };
  }
}

// ---- (2) action-bound risk commitments -------------------------------------------------

const ATTEST_DOMAIN = utf8('atlas-pca-ratchet/risk-attestation/v1\0');

/** A risk authority's signature binding a commitment to one action. */
export interface RiskAttestation {
  /** The action (e.g. `pcactnDigest`) this commitment is for. */
  actionDigest: string;
  /** b64u Ed25519 signature by the risk authority over (domain, actionDigest, commitment). */
  sig: string;
}

function attestMessage(actionDigest: string, commitment: string): Uint8Array {
  const a = utf8(actionDigest);
  const c = utf8(commitment);
  const out = new Uint8Array(ATTEST_DOMAIN.length + 4 + a.length + 4 + c.length);
  const dv = new DataView(out.buffer);
  out.set(ATTEST_DOMAIN, 0);
  let o = ATTEST_DOMAIN.length;
  dv.setUint32(o, a.length, false);
  out.set(a, o + 4);
  o += 4 + a.length;
  dv.setUint32(o, c.length, false);
  out.set(c, o + 4);
  return out;
}

/**
 * RISK AUTHORITY side: commit to the risk it computed for `actionDigest`, prove the range, and sign
 * (actionDigest, commitment). Hand `blinding` privately to the prover (needed for the budget proof);
 * publish `commitment`, `rangeProof`, `attestation`.
 */
export function issueRiskCommitment(
  risk: RiskUnits,
  actionDigest: string,
  authoritySecretKey: Uint8Array,
): { commitment: string; blinding: bigint; rangeProof: RiskRangeProof; attestation: RiskAttestation } {
  const { commitment, blinding } = commitRisk(risk);
  const rangeProof = proveRiskRange(risk, blinding);
  const sig = b64u(ed25519.sign(attestMessage(actionDigest, commitment), authoritySecretKey));
  return { commitment, blinding, rangeProof, attestation: { actionDigest, sig } };
}

/** Verify one attestation against the risk authority's public key (b64u). Never throws. */
export function verifyRiskAttestation(commitment: string, attestation: RiskAttestation, authorityPublicKey: string): boolean {
  try {
    if (attestation === null || typeof attestation !== 'object') return false;
    if (typeof attestation.actionDigest !== 'string' || typeof attestation.sig !== 'string') return false;
    return verifyB64u(authorityPublicKey, attestMessage(attestation.actionDigest, commitment), attestation.sig);
  } catch {
    return false;
  }
}

/**
 * Sound end-to-end budget check over ATTESTED commitments. For the verifier's own list of action
 * digests (in order), every item must carry a valid authority attestation for exactly that digest and
 * commitment, then {@link verifyBoundedBudget} must hold. Accepting implies the authority-computed
 * risks of exactly these actions sum, as integers, to at most `bMax`. Never throws.
 */
export function verifyAttestedBudget(
  items: readonly { commitment: string; rangeProof: RiskRangeProof; attestation: RiskAttestation }[],
  expectedActionDigests: readonly string[],
  authorityPublicKey: string,
  bMax: RiskUnits,
  budgetProof: BudgetProof,
): boolean {
  try {
    if (!Array.isArray(items) || !Array.isArray(expectedActionDigests) || items.length !== expectedActionDigests.length) return false;
    for (let i = 0; i < items.length; i++) {
      const it = items[i]!;
      if (it.attestation?.actionDigest !== expectedActionDigests[i]) return false;
      if (!verifyRiskAttestation(it.commitment, it.attestation, authorityPublicKey)) return false;
    }
    return verifyBoundedBudget(
      items.map((i) => i.commitment),
      items.map((i) => i.rangeProof),
      bMax,
      budgetProof,
    );
  } catch {
    return false;
  }
}
