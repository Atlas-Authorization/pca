/**
 * §9A — Cryptoeconomic BOND SETTLEMENT for the optimistic fast-path.
 *
 * `optimistic.ts` is the pure claim + challenge + fraud LOGIC: it decides whether a bonded claim was
 * fraudulent (`verifyFraudProof` → a server-derived `FraudVerdict`), but it deliberately leaves the
 * economic bond — escrow, release, slashing, the ledger of balances — to a settlement layer, resolving
 * only opaque `bond_ref` handles. THIS module is that settlement layer's PURE accounting + signed
 * records: who deposited, whether the bond was returned (unchallenged) or slashed (proven fraud), and a
 * non-repudiable `SettlementRecord` for each transition that anyone can verify against the guardian key.
 *
 * WHAT BINDS A SLASH TO REALITY. A slash is NOT authorized by challenger assertion. `slashBond` re-runs
 * `verifyFraudProof` itself (against the grant the settlement layer trusts) and refuses unless the
 * SERVER-DERIVED verdict is `fraudulent` and names this very bond. The record's `evidenceDigest` is a
 * `settlementEvidenceDigest(claim, verdict)` over that verdict's output — so the signed slash commits to
 * the fraud finding the server recomputed, never to anything the challenger supplied.
 *
 * SCOPE. INTERNAL ACCOUNTING ONLY; no money moves. This file holds the pure decision logic (`BondSettlementPlanner`: it
 * validates a transition, re-derives every slash verdict itself, divides the bond and signs the record) and the in-memory
 * `BondLedger`, which applies a plan to `Map`s and loses everything with the process: it is a TEST DOUBLE and the reference for
 * the decisions. A deployment uses `StoreBondLedger` (`bond-store.ts`), which commits the SAME plans to a `BondStore` atomically
 * and idempotently and owns the challenge-window clock. Re-verify any record with `verifySettlement`; the signing key is the
 * guardian / settlement key and only the public half is needed to verify.
 */
// Bond settlement records + fraud-verdict evidence are server-only (guardian-signed,
// carry amount/claimed_r floats), never recomputed by the language verifiers — lenient
// canonical, not the strict protocol form.
import { randomBytes } from '@noble/hashes/utils';
import { b64u, canonicalBytesLenient as canonicalBytes, hashCanonicalLenient as hashCanonical, utf8 } from './hash';
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
import type { Capability } from './capability';
import type { DecideInput } from './policy-vm';
import type { TransparencyLedger } from './ledger';
import { type InsurancePricing, type PricingOptions, type Reputation, priceCoverage } from './reputation';
import {
  type BondedClaim,
  type DisputeClaim,
  type DisputeVerdict,
  type FraudProof,
  type FraudVerdict,
  type ObjectiveOracle,
  adjudicateDispute,
  verifyFraudProof,
} from './optimistic';

const DOMAIN = 'atlas-pca/bond-settlement/v1\0';

/** The default escrow account label (where an open bond is locked until it is released or slashed). */
export const ESCROW_ACCOUNT = 'escrow';

/**
 * The default victim-compensation POOL account label. A slash against an identified challenger diverts a
 * `victimCompensation` share here (the caller keys a concrete pool per grant/principal — see the server's
 * `compensationPoolFor`). Reserved name: contains `:`, so it can never collide with a 43-char Ed25519
 * principal account and can never be named as a challenger `reward_account`.
 */
export const COMPENSATION_POOL_ACCOUNT = 'pca:pool:compensation';

export type SettlementAction = 'open' | 'release' | 'slash';

// ---- SLASH SPLIT — the cryptoeconomic engine (audit: challenger reward + victim compensation) ---------
//
// WHY. Today a slash sends 100% of the bond to the treasury, so challenging fraud is a PURE COST: a rational
// watchtower never bothers, and fraud goes uncaught. This split makes catching fraud economically rational by
// paying the successful challenger and the party harmed, with the remainder to the treasury.
//
// PRODUCT CAVEAT — THE PERCENTAGES BELOW ARE TUNABLE REFERENCE DEFAULTS, **NOT A FINAL PRODUCT DECISION.**
// They are intentionally conservative (the challenger share is capped, the treasury keeps a cut and all
// rounding dust) and are config-driven via `SlashSplitPolicy`; a deployment MUST review them against its own
// bond sizing, griefing surface and regulatory posture before treating them as settled.

/**
 * How a slashed bond is divided, in BASIS POINTS (bps; 1/10000). The treasury receives the remainder
 * (`10000 - challengerBps - victimBps`) plus any integer-rounding dust. TUNABLE — see the caveat above.
 */
export interface SlashSplitPolicy {
  /** Share to the successful (identified) challenger — the watchtower incentive. Default 50%. */
  challengerBps: number;
  /** Share to the victim-compensation pool keyed to the harmed grant/principal. Default 40%. */
  victimBps: number;
}

/**
 * CONSERVATIVE REFERENCE DEFAULT: challenger 50% / victim-pool 40% / treasury 10%. **Tunable, not gospel.**
 * Rationale for conservatism: the challenger never takes the whole bond (so a self-challenge griefing round
 * trip is never net-profitable on fees alone), the harmed party is made partly whole, and the treasury
 * always retains a cut plus all rounding dust.
 */
export const DEFAULT_SLASH_SPLIT_POLICY: SlashSplitPolicy = { challengerBps: 5000, victimBps: 4000 };

/** The exact, verifiable division of one slashed bond. The three payouts sum EXACTLY to `amount`. */
export interface SlashSplit {
  /** The full slashed amount; `challengerReward + victimCompensation + treasuryRemainder === amount`. */
  amount: number;
  /** Credited to `challengerAccount` (0 when anonymous). */
  challengerReward: number;
  /** Credited to `victimAccount` (0 when anonymous). */
  victimCompensation: number;
  /** Credited to `treasuryAccount` (the remainder + rounding dust; the full amount when anonymous). */
  treasuryRemainder: number;
  /** The identified challenger's payout account, or `null` for an anonymous challenge. */
  challengerAccount: string | null;
  /** The victim-compensation pool account. */
  victimAccount: string;
  /** The treasury account. */
  treasuryAccount: string;
}

function assertSplitPolicy(p: SlashSplitPolicy): void {
  for (const [k, v] of [['challengerBps', p.challengerBps], ['victimBps', p.victimBps]] as const) {
    if (!Number.isInteger(v) || v < 0 || v > 10_000) throw new Error(`slash split: ${k} must be an integer in [0,10000]`);
  }
  if (p.challengerBps + p.victimBps > 10_000) throw new Error('slash split: challengerBps + victimBps must not exceed 10000');
}

// ---- EXACT MONEY: micro-unit (1e-6) integer arithmetic ---------------------------------------------------
//
// Money is never accumulated or divided in binary floating point. Every bond/payout amount lives on the
// MICRO grid (1e-6 of a unit); splitting is done in BigInt micro-units, so shares are exact integers, the
// three payouts sum EXACTLY to the slashed amount in micro-units, and the rounding remainder goes to the
// treasury deterministically. A JS number on the grid is just `micros / 1e6` (correctly rounded, so it prints
// as the exact decimal). Databases store the same quantity as NUMERIC(30,6).

/** Micro-units per whole unit. */
export const MICROS_PER_UNIT = 1_000_000;
// Above 1e15 micros (1e9 units) a double no longer resolves single micro-units, so exactness is not claimed there.
const MAX_SAFE_MICROS = 1e15;

/** Integer micro-units of `x` when `x` is (within float noise) a micro-grid amount below 2^53 micros; else null. */
export function toMicros(x: number): bigint | null {
  if (!Number.isFinite(x) || x < 0) return null;
  const scaled = x * MICROS_PER_UNIT;
  if (scaled > MAX_SAFE_MICROS) return null;
  const r = Math.round(scaled);
  if (r / MICROS_PER_UNIT !== x && Math.abs(scaled - r) > 1e-3) return null; // genuinely sub-micro: not a micro-grid amount (a micro amount round-trips exactly)
  return BigInt(r);
}

/** The JS number for an integer micro-unit amount (exact decimal; round-trips through `toMicros`). */
export function fromMicros(m: bigint): number {
  return Number(m) / MICROS_PER_UNIT;
}

/**
 * Snap a computed amount UP onto the micro grid (a bond is never rounded down: under-collateralisation is the
 * unsafe direction). Float noise below 1e-3 micro-units (e.g. 27.500000000000004) is absorbed, not carried.
 * Amounts too large for exact micro representation are returned unchanged.
 */
export function quantizeUp(x: number): number {
  if (!Number.isFinite(x) || x <= 0) return x;
  const scaled = x * MICROS_PER_UNIT;
  if (scaled > MAX_SAFE_MICROS) return x;
  const r = Math.round(scaled);
  const m = r / MICROS_PER_UNIT === x || Math.abs(scaled - r) <= 1e-3 ? r : Math.ceil(scaled);
  return m / MICROS_PER_UNIT;
}

/** Exact floor(micros * bps / 10000). */
function shareMicros(micros: bigint, bps: number): bigint {
  return (micros * BigInt(bps)) / 10_000n;
}

/** Smallest fractional grid for payout shares (2^-30, ~9.3e-10). A power of two so grid multiples are exact in binary floating point. */
const MIN_SHARE_QUANTUM = 2 ** -30;

/** Unit in the last place of a positive finite double (exact power of two). */
function ulpOf(x: number): number {
  let e = Math.floor(Math.log2(x));
  if (2 ** e > x) e--;
  else if (2 ** (e + 1) <= x) e++;
  return 2 ** Math.max(e - 52, -1074);
}

/**
 * The grid every payout share is a multiple of. Integer bonds below 2^53 use 1 (integer shares); every
 * other amount uses max(ulp(amount), 2^-30). Because the quantum is a power of two at least ulp(amount),
 * each share and the subtraction `amount - challenger - victim` are exactly representable, so the three
 * shares sum to `amount` with NO floating-point dust (R3-10).
 */
function shareQuantum(amount: number): number {
  const u = ulpOf(amount);
  if (Number.isInteger(amount)) return Math.max(1, u);
  return Math.max(MIN_SHARE_QUANTUM, u);
}

/**
 * One payout share: floor(amount * bps / 10000) onto the amount's quantum grid. The caller derives the
 * treasury remainder by SUBTRACTION (exact on the grid), so the three shares always reconcile to `amount`
 * exactly and the rounding remainder goes to the treasury deterministically.
 */
function shareOf(amount: number, bps: number, quantum: number): number {
  const raw = (amount * bps) / 10_000;
  return Math.floor(raw / quantum) * quantum;
}

/**
 * Compute the challenger / victim / treasury division of a slashed `amount`. The split is EXACT
 * (treasury = amount - challenger - victim, so the three always sum to `amount`) and INTEGER-SAFE (an
 * integer bond yields integer shares with the dust going to the treasury).
 *
 * ANONYMOUS CHALLENGE (`dest.challengerAccount === null`): the whole bond goes to the treasury —
 * **exactly today's behavior**. This is a deliberate, conservative, tunable choice: with no identified
 * watchtower there is no one to reward, so the reference implementation leaves the economics unchanged
 * rather than pre-funding a pool no one yet claims. (A deployment that wants the victim pool to accrue even
 * on anonymous challenges would branch here — flagged as a tunable product decision.)
 */
export function computeSlashSplit(
  amount: number,
  policy: SlashSplitPolicy,
  dest: { challengerAccount: string | null; victimAccount: string; treasuryAccount: string },
): SlashSplit {
  if (!Number.isFinite(amount) || amount <= 0) throw new Error('computeSlashSplit: amount must be a positive finite number');
  assertSplitPolicy(policy);
  if (typeof dest.victimAccount !== 'string' || !dest.victimAccount) throw new Error('computeSlashSplit: victimAccount is required');
  if (typeof dest.treasuryAccount !== 'string' || !dest.treasuryAccount) throw new Error('computeSlashSplit: treasuryAccount is required');

  if (dest.challengerAccount === null) {
    // Anonymous: preserve today's behavior — 100% treasury, no pool pre-funding.
    return {
      amount,
      challengerReward: 0,
      victimCompensation: 0,
      treasuryRemainder: amount,
      challengerAccount: null,
      victimAccount: dest.victimAccount,
      treasuryAccount: dest.treasuryAccount,
    };
  }
  const micros = Number.isInteger(amount) ? null : toMicros(amount); // integer bonds keep whole-unit shares (legacy, already exact)
  if (micros !== null) {
    // EXACT path: integer micro-unit arithmetic. Shares floor; the remainder (and dust) is the treasury's.
    const c = shareMicros(micros, policy.challengerBps);
    const v = shareMicros(micros, policy.victimBps);
    const t = micros - c - v; // >= 0 because challengerBps + victimBps <= 10000
    return {
      amount: fromMicros(micros),
      challengerReward: fromMicros(c),
      victimCompensation: fromMicros(v),
      treasuryRemainder: fromMicros(t),
      challengerAccount: dest.challengerAccount,
      victimAccount: dest.victimAccount,
      treasuryAccount: dest.treasuryAccount,
    };
  }
  // Fallback for amounts outside the exact micro range (huge or sub-micro): dyadic-grid float split (legacy).
  const q = shareQuantum(amount);
  const challengerReward = Math.min(shareOf(amount, policy.challengerBps, q), amount);
  // clamp so float rounding in `raw` can never make the shares exceed the amount
  const victimCompensation = Math.min(shareOf(amount, policy.victimBps, q), amount - challengerReward);
  const treasuryRemainder = amount - challengerReward - victimCompensation; // exact remainder + rounding dust
  return {
    amount,
    challengerReward,
    victimCompensation,
    treasuryRemainder,
    challengerAccount: dest.challengerAccount,
    victimAccount: dest.victimAccount,
    treasuryAccount: dest.treasuryAccount,
  };
}

/** A signed, non-repudiable record of one bond transition (open / release / slash). */
export interface SettlementRecord {
  /**
   * Which guardian/settlement key epoch signed this record — like the transparency ledger's
   * {@link SignedTreeHead.guardian_epoch}, but (unlike the STH's unsigned annotation) BOUND INTO the signed
   * body: it rides through {@link settlementMessage} and is covered by `sig`/`pq_sig`, so the epoch a record
   * names is non-repudiable and a verifier can reject a record attributed to a rotated-out key. Absent when
   * the ledger was not configured with an epoch (byte-identical to pre-epoch records).
   */
  guardian_epoch?: number;
  /** The bond/claim handle this record settles (== the optimistic claim's `bond_ref`). */
  claimId: string;
  action: SettlementAction;
  /** The bonded amount moved by this transition. */
  amount: number;
  /** Source account: the depositor (open), or the escrow (release / slash). */
  from: string;
  /** Destination account: the escrow (open), the depositor (release), or the treasury (slash). */
  to: string;
  /** Settlement time (epoch ms). */
  at: number;
  /**
   * For a slash: `settlementEvidenceDigest(claim, verdict)` binding this record to the SERVER-DERIVED
   * fraud verdict. Empty string for open/release (no fraud evidence underlies them).
   */
  evidenceDigest: string;
  /**
   * For a slash ONLY: the challenger / victim-pool / treasury division of the slashed `amount`. It is part
   * of the signed body (and thus guardian-verifiable), so anyone can confirm each payout against the bond.
   * Absent on open/release. `to`/`amount` on the record remain the treasury destination and the FULL bonded
   * amount moved out of escrow; `split` details where that amount landed.
   */
  split?: SlashSplit;
  /** b64u signature by the guardian/settlement key over the canonical record body (Ed25519 for ed25519/hybrid, ML-DSA-65 for pure). */
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility). For
   * `ml-dsa-65`/`hybrid` the suite + the guardian's ML-DSA key `pq_pk` are SIGNED INTO the record body,
   * and `pq_sig` carries the ML-DSA signature (hybrid).
   */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the guardian/settlement key — ml-dsa-65 / hybrid (body-bound). */
  pq_pk?: string;
  /** b64u ML-DSA-65 record signature — hybrid only. */
  pq_sig?: string;
}

export type SettlementRecordBody = Omit<SettlementRecord, 'sig'>;

/** The canonical signed body EXCLUDES both the signature fields (`sig`, `pq_sig`); `alg`/`pq_pk` are bound in and signed. */
function settlementMessage(body: Omit<SettlementRecord, 'sig' | 'pq_sig'>): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/**
 * The digest that binds a slash to the server-derived fraud verdict. It hashes the claim identity
 * (digest + bond) together with `verifyFraudProof`'s OWN output (`fraudulent`, `slashBondRef`, `reason`)
 * — never challenger-supplied fields — so a settlement record provably commits to the fraud finding the
 * settlement layer recomputed.
 */
export function settlementEvidenceDigest(claim: BondedClaim, fraudVerdict: FraudVerdict): string {
  return hashCanonical({
    claimDigest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    fraudulent: fraudVerdict.fraudulent,
    slashBondRef: fraudVerdict.slashBondRef ?? null,
    reason: fraudVerdict.reason,
  });
}

/**
 * Evidence digest for a REVOCATION slash — a capability in the claim's chain was revoked after the
 * bond opened. The authorizing fact is server-derived (membership in the instance's revocation set),
 * not a challenger assertion; the caller MUST confirm the revocation before slashing. Binds the signed
 * record to the revoked capability id.
 */
export function revocationEvidenceDigest(claim: BondedClaim, revokedCapId: string): string {
  return hashCanonical({
    claimDigest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    kind: 'revocation',
    revokedCapId,
  });
}

/**
 * Evidence digest for a DISPUTE-GAME slash (a contested, understated risk input). The authorizing fact is
 * server-derived: `adjudicateDispute`'s OWN verdict (the outcome, the disputed input, the oracle value that
 * refuted the claim) — never a challenger assertion. Binds the signed record to that recomputed verdict.
 */
export function disputeEvidenceDigest(claim: BondedClaim, verdict: DisputeVerdict): string {
  return hashCanonical({
    claimDigest: claim.pcactn_digest,
    bond_ref: claim.bond_ref,
    kind: 'dispute',
    outcome: verdict.outcome,
    input: verdict.input,
    agentValue: verdict.agentValue ?? null,
    oracleValue: verdict.oracleValue ?? null,
    slashBondRef: verdict.slashBondRef ?? null,
    reason: verdict.reason,
  });
}

/** Verify a settlement record's signature under the guardian/settlement public key. Suite-agile; ed25519 == pre-agility. Never throws. */
export function verifySettlement(record: SettlementRecord, guardianPublicKey: string, pin?: PqPinPolicy): boolean {
  try {
    if (!record || typeof record !== 'object') return false;
    const { sig, pq_sig, ...body } = record; // the signed body keeps alg/pq_pk, drops both signatures
    if (typeof sig !== 'string' || resolveSigAlg(record.alg) === null) return false;
    return verifyPinnedSuite(record.alg, guardianPublicKey, record.pq_pk, settlementMessage(body), { sig, pq_sig }, pin);
  } catch {
    return false;
  }
}

/** The first check a settlement record fails at the wire level; `ok` when none. */
export type SettlementWireCheck = 'ok' | 'malformed' | 'suite' | 'shape' | 'split' | 'signature';

const nonEmpty = (x: unknown): x is string => typeof x === 'string' && x.length > 0;
const nonNegNum = (x: unknown): x is number => Number.isFinite(x) && (x as number) >= 0;

/**
 * WIRE-LEVEL check of a settlement record, in this order: it is an object (`malformed`); its signature suite is known
 * (`suite`); its fields have the shape its `action` requires (`shape`: names present, `amount` a positive finite number,
 * `evidenceDigest` empty and `split` absent unless the action is `slash`, and then both present, a guardian epoch a
 * non-negative integer when present); its split conserves the amount (`split`: `amount` equal to the record's, payouts
 * non-negative, `(challengerReward + victimCompensation) + treasuryRemainder === amount`, the treasury account is the
 * record's destination, and an anonymous split pays the treasury everything); and the guardian signature verifies
 * (`signature`). Pure data: every language runs it from the shared vectors. Never throws.
 */
export function settlementWireCheck(record: SettlementRecord, guardianPublicKey: string, pin?: PqPinPolicy): SettlementWireCheck {
  try {
    if (!record || typeof record !== 'object' || Array.isArray(record)) return 'malformed';
    if (resolveSigAlg(record.alg) === null) return 'suite';
    const r = record as unknown as Record<string, unknown>;
    const slash = r.action === 'slash';
    if (
      !nonEmpty(r.claimId) ||
      !(r.action === 'open' || r.action === 'release' || r.action === 'slash') ||
      !Number.isFinite(r.amount) || (r.amount as number) <= 0 ||
      !nonEmpty(r.from) || !nonEmpty(r.to) ||
      !Number.isFinite(r.at) ||
      typeof r.evidenceDigest !== 'string' || (slash ? r.evidenceDigest === '' : r.evidenceDigest !== '') ||
      (slash ? typeof r.split !== 'object' || r.split === null : r.split !== undefined) ||
      typeof r.sig !== 'string' ||
      (r.guardian_epoch !== undefined && !(Number.isSafeInteger(r.guardian_epoch) && (r.guardian_epoch as number) >= 0))
    ) {
      return 'shape';
    }
    if (slash) {
      const sp = r.split as Record<string, unknown>;
      const conserved =
        sp.amount === r.amount &&
        nonNegNum(sp.challengerReward) && nonNegNum(sp.victimCompensation) && nonNegNum(sp.treasuryRemainder) &&
        sp.challengerReward + sp.victimCompensation + sp.treasuryRemainder === r.amount &&
        nonEmpty(sp.victimAccount) && sp.treasuryAccount === r.to &&
        (sp.challengerAccount === null ? sp.challengerReward === 0 && sp.victimCompensation === 0 : nonEmpty(sp.challengerAccount));
      if (!conserved) return 'split';
    }
    return verifySettlement(record, guardianPublicKey, pin) ? 'ok' : 'signature';
  } catch {
    return 'malformed';
  }
}

// ---- A3d: settlement records are anchored into the transparency ledger (externally auditable) ----------
//
// WHY. Settlements are the money moves of the fast-path, but until now they lived only in the settlement
// store: a guardian could sign a slash and never expose it, and nothing tied the stream of settlements to the
// tamper-evident, witnessed log. Anchoring each record as a salted commitment in the `TransparencyLedger`
// makes settlement EXTERNALLY AUDITABLE — anyone with the record, its salt and an inclusion proof against a
// signed/witnessed STH can confirm it is in the append-only log, and a guardian can no longer quietly drop or
// rewrite a settlement without a signed, attributable contradiction (the STH + consistency-proof machinery).

/** Domain-separated tag for the settlement transparency leaf (distinct from every other commitment domain). */
export const SETTLEMENT_LEAF_DOMAIN = 'atlas-pca/settlement-leaf/v1';

/**
 * Canonical digest of a (signed) settlement record — commits to the WHOLE record, signature included, so the
 * anchored leaf binds the exact guardian-signed artifact (not just its body).
 */
export function settlementRecordDigest(record: SettlementRecord): string {
  return hashCanonical({ t: SETTLEMENT_LEAF_DOMAIN, record });
}

/** The salted commitment of a settlement record — the opaque leaf appended to the transparency ledger. */
export function settlementCommit(salt: string, record: SettlementRecord): string {
  if (typeof salt !== 'string' || salt.length === 0) throw new Error('settlementCommit: salt must be a non-empty string');
  return hashCanonical({ salt, settlement_digest: settlementRecordDigest(record) });
}

/** True iff `salt`+`record` reproduce the anchored `commit`. Never throws (part of external audit). */
export function verifySettlementCommit(commit: string, salt: string, record: SettlementRecord): boolean {
  try {
    return settlementCommit(salt, record) === commit;
  } catch {
    return false;
  }
}

export interface SettlementAnchor {
  /** 0-based index of the leaf in the transparency ledger. */
  index: number;
  /** The salted commitment that was appended (== `settlementCommit(salt, record)`). */
  commit: string;
  /** The salt the caller MUST retain to later prove inclusion / open the leaf. */
  salt: string;
}

/**
 * Append a settlement record into a {@link TransparencyLedger} as a salted commitment, returning the leaf
 * index, commit and salt. The salt defaults to 16 random bytes; pass `opts.salt` for deterministic output.
 * The caller retains `{record, salt}` as the (off-log) opening. VERIFIABLE PATH: a third party later confirms
 * the settlement with `verifySettlementCommit(commit, salt, record)` + `ledger.verifyInclusion(root, proof,
 * commit)` against a witnessed STH root, plus `verifySettlement(record, guardianPublicKey)` for the money move.
 */
export function appendSettlement(ledger: TransparencyLedger, record: SettlementRecord, opts: { salt?: string } = {}): SettlementAnchor {
  const salt = opts.salt ?? b64u(randomBytes(16));
  const commit = settlementCommit(salt, record);
  const { index } = ledger.appendCommitment(commit);
  return { index, commit, salt };
}

// ---- bond sizing + collateral (audit finding 1 / P3-1) ------------------------------------

// ---- A3c: non-linear (convex) bond curve --------------------------------------------------
//
// Linear sizing makes a huge fraudulent claim only proportionally more expensive to stake; a CONVEX curve
// makes it disproportionately expensive, so the marginal cost of a bigger lie grows with its size. `linear`
// is the DEFAULT (back-compat: `bondAmount` is byte-identical to before when `curve` is absent). The two
// optional shapes are both MONOTONE NON-DECREASING and CONVEX in exposure:
//   - `power`: bond = max(floor, k · exposure^gamma),  gamma >= 1 (gamma = 1 ⇒ exactly the linear curve).
//   - `piecewise`: a tiered marginal schedule with non-decreasing marginal rates (each tier at least as
//     steep as the previous), which is convex and lets a deployment cap how steep the top tier gets.

export type BondCurve =
  | { kind: 'linear' }
  | { kind: 'power'; gamma: number }
  | { kind: 'piecewise'; tiers: readonly { upTo: number; marginalK: number }[] };

/** Bond sizing + per-depositor aggregate caps. Configurable; there is no hardcoded constant bond. */
export interface BondPolicy {
  /** Minimum bond regardless of exposure. */
  floor: number;
  /** Multiplier on the claim's exposure (the base/marginal rate the curve scales). */
  k: number;
  /** Max simultaneously-open bonds per depositor. */
  maxOpenClaims: number;
  /** Max aggregate open bonded amount per depositor. */
  maxOpenAmount: number;
  /** Optional non-linear (convex) sizing. Absent ⇒ `linear` (exactly `max(floor, k·exposure)`). */
  curve?: BondCurve;
}

export const DEFAULT_BOND_POLICY: BondPolicy = { floor: 1, k: 1, maxOpenClaims: 100, maxOpenAmount: Number.POSITIVE_INFINITY };

function curveComponent(curve: BondCurve | undefined, k: number, e: number): number {
  if (!curve || curve.kind === 'linear') return k * e;
  if (curve.kind === 'power') {
    if (!(Number.isFinite(curve.gamma) && curve.gamma >= 1)) throw new Error('bondAmount: power curve requires finite gamma >= 1');
    return k * Math.pow(e, curve.gamma);
  }
  // piecewise: integrate a non-decreasing marginal schedule (convex), scaled by k.
  if (!Array.isArray(curve.tiers) || curve.tiers.length === 0) throw new Error('bondAmount: piecewise curve requires at least one tier');
  let acc = 0;
  let prevUpTo = 0;
  let prevMarginal = 0;
  for (const tier of curve.tiers) {
    if (!(Number.isFinite(tier.upTo) && tier.upTo > prevUpTo) && tier.upTo !== Number.POSITIVE_INFINITY) {
      throw new Error('bondAmount: piecewise tier `upTo` must be strictly increasing');
    }
    if (!(Number.isFinite(tier.marginalK) && tier.marginalK >= 0)) throw new Error('bondAmount: piecewise `marginalK` must be a finite number >= 0');
    if (tier.marginalK < prevMarginal) throw new Error('bondAmount: piecewise marginal rates must be non-decreasing (convex)');
    const width = Math.min(e, tier.upTo) - prevUpTo;
    if (width > 0) acc += width * tier.marginalK;
    prevUpTo = tier.upTo;
    prevMarginal = tier.marginalK;
    if (e <= tier.upTo) break;
  }
  if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal; // beyond the last tier: extend its marginal rate
  return k * acc;
}

/**
 * `bondAmount(policy, exposure)` — `max(floor, curve(k, exposure))`. With no `policy.curve` (the default) the
 * curve is LINEAR and this is exactly `max(floor, k·exposure)` as before. A `power`/`piecewise` curve is
 * convex and monotone non-decreasing, so a bigger exposure always stakes at least as much and the marginal
 * cost of a larger claim grows. Non-finite / non-positive exposure ⇒ `floor`.
 */
export function bondAmount(policy: BondPolicy, exposure: number): number {
  const e = Number.isFinite(exposure) && exposure > 0 ? exposure : 0;
  return quantizeUp(Math.max(policy.floor, curveComponent(policy.curve, policy.k, e)));
}

/**
 * The collateral account interface. Real balances live in a server-side store fronted by a concrete
 * `BondAccount` implementation in the hosting layer; this `InMemoryBondAccount` is the pure reference
 * used by the library + tests.
 * `debit` MUST throw if the balance is insufficient.
 */
export interface BondAccount {
  balanceOf(account: string): number;
  debit(account: string, amount: number): void;
  credit(account: string, amount: number): void;
}

/** a + sign*b in exact micro-unit integers when both are micro-grid amounts (no float drift); plain float otherwise. */
export function exactAdd(a: number, b: number, sign: 1 | -1): number {
  const ma = toMicros(a);
  const mb = toMicros(b);
  if (ma === null || mb === null) return a + sign * b;
  return fromMicros(sign === 1 ? ma + mb : ma - mb);
}

/** The lifecycle status of a bond in the ledger. */
export type BondPhase = 'none' | 'open' | 'released' | 'slashed';

/**
 * One bond as a store holds it. `records` is the signed settlement history in order: the `open` record, then (once
 * settled) exactly one `release` or `slash` record. `window` is the challenge window as the SETTLEMENT LAYER measured
 * it (see {@link BondRegistration}); it is absent for a bond opened without a claim registration.
 */
export interface BondRow extends BondHead {
  window?: BondRegistration;
  records: SettlementRecord[];
}

/** What deciding a transition needs to know about a bond: who staked how much, and where it stands. */
export interface BondHead {
  claimId: string;
  amount: number;
  depositor: string;
  status: Exclude<BondPhase, 'none'>;
}

/**
 * The challenge window of a registered claim, measured on the settlement layer's own clock. `registeredAt` is
 * stamped by the ledger's clock when the bond opens; it is NEVER read from the claim, so a claimant who backdates or
 * forward-dates `issued_at` (within the skew the claim check tolerates) cannot move the window.
 */
export interface BondRegistration {
  registeredAt: number;
  windowMs: number;
  /** Digest of the exact claim that was registered; a later slash must present that same claim. */
  claimDigest: string;
}

/** What a planner needs to read to decide a transition. Stores expose a read view; planning never mutates. */
export interface BondView {
  bond(claimId: string): BondHead | undefined;
  balanceOf(account: string): number;
  /** Count and summed amount of the depositor's currently open bonds. */
  openTotals(depositor: string): { count: number; sum: number };
}

/** One balance movement of a transition. Applied in order; a debit that would overdraw aborts the whole transition. */
export interface BondMove {
  account: string;
  op: 'debit' | 'credit';
  amount: number;
}

/**
 * A fully decided transition, ready to be committed atomically: the compare-and-swap precondition (`expect`), the new
 * phase, every balance movement, and the guardian-signed record. A store applies ALL of it or NONE of it.
 */
export interface BondPlan {
  claimId: string;
  /** The phase the bond MUST be in for the plan to apply (`none` for an open). */
  expect: BondPhase;
  next: Exclude<BondPhase, 'none'>;
  /** Present on an open: the new bond's terms and the caps the store re-checks under its own atomicity. */
  open?: { amount: number; depositor: string; maxOpenClaims: number; maxOpenAmount: number; window?: BondRegistration };
  moves: BondMove[];
  record: SettlementRecord;
}

export interface BondPlannerOpts {
  /** The guardian/settlement secret key that signs every record. */
  guardianSecret: Uint8Array;
  guardianEpoch?: number;
  suite?: SignerSuiteOpts;
  escrowAccount?: string;
  bondPolicy?: BondPolicy;
  slashSplitPolicy?: SlashSplitPolicy;
}

type SlashShared = {
  claimId: string;
  claim: BondedClaim;
  treasury: string;
  /** The successful challenger's payout account; omit/`null` for an anonymous challenge (→ 100% treasury). */
  challengerAccount?: string | null;
  /** The victim-compensation pool account (default `COMPENSATION_POOL_ACCOUNT`). */
  compensationAccount?: string;
  /** Override the ledger's slash split policy for this slash. TUNABLE. */
  splitPolicy?: SlashSplitPolicy;
};
export type SlashBondParams = SlashShared & {
  fraudProof: FraudProof;
  grant: Capability;
  /** FROZEN open-time `DecideInput` (server-held, captured at claim open). */
  openSnapshot: DecideInput;
};
export type SlashOnRevocationParams = SlashShared & { revokedCapId: string };
export type SlashOnDisputeParams = SlashShared & {
  dispute: DisputeClaim;
  grant: Capability;
  openSnapshot: DecideInput;
  /** The objective oracle resolving the truthful value of the disputed input. */
  oracle: ObjectiveOracle;
  rMargin?: number;
};
export interface SlashCounterBondParams {
  /** The challenger's counter-bond id (its own open bond). */
  counterBondId: string;
  /** The agent's DISPUTED claim (what the frivolous dispute targeted). */
  claim: BondedClaim;
  dispute: DisputeClaim;
  grant: Capability;
  openSnapshot: DecideInput;
  oracle: ObjectiveOracle;
  treasury: string;
  /** Optional compensation to the wrongly-accused agent; default `COMPENSATION_POOL_ACCOUNT` (receives 0 when anonymous). */
  compensationAccount?: string;
  splitPolicy?: SlashSplitPolicy;
  rMargin?: number;
}

/**
 * The pure half of bond settlement: validates a transition against a read view, re-derives every slash verdict
 * itself, computes the balance movements and signs the record. It holds no state and touches no store. The
 * in-memory {@link BondLedger} applies a plan to its maps; a durable ledger (see `bond-store.ts`) commits the same
 * plan to a {@link BondStore} atomically, so both paths decide identically.
 */
export class BondSettlementPlanner {
  /** The guardian/settlement public key (b64u) — hand this to verifiers of the signed records. */
  readonly guardianPublicKey: string;
  readonly escrow: string;
  readonly bondPolicy: BondPolicy;
  readonly slashSplitPolicy: SlashSplitPolicy;
  private readonly guardianSecret: Uint8Array;
  private readonly guardianEpoch?: number;
  private readonly suite?: SignerSuiteOpts;
  private readonly pqPk?: string;

  constructor(opts: BondPlannerOpts) {
    if (!(opts.guardianSecret instanceof Uint8Array)) {
      throw new Error('BondLedger: guardianSecret must be a Uint8Array');
    }
    this.guardianSecret = opts.guardianSecret;
    this.guardianPublicKey = b64u(publicKeyOf(opts.guardianSecret));
    if (opts.guardianEpoch !== undefined && !(Number.isSafeInteger(opts.guardianEpoch) && opts.guardianEpoch >= 0)) {
      throw new Error('BondLedger: guardianEpoch must be a non-negative safe integer');
    }
    this.guardianEpoch = opts.guardianEpoch;
    if (resolveSigAlg(opts.suite?.alg) === null) throw new Error(`BondLedger: unknown signature alg '${String(opts.suite?.alg)}'`);
    this.suite = opts.suite;
    this.pqPk = suitePqPublicKey(opts.suite?.alg, opts.suite);
    this.escrow = opts.escrowAccount ?? ESCROW_ACCOUNT;
    this.bondPolicy = opts.bondPolicy ?? DEFAULT_BOND_POLICY;
    this.slashSplitPolicy = opts.slashSplitPolicy ?? DEFAULT_SLASH_SPLIT_POLICY;
  }

  private signRecord(base: Omit<SettlementRecord, 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>): SettlementRecord {
    // Stamp + bind the guardian epoch (when configured) so it is covered by the signature; omitted => absent.
    const withEpoch = this.guardianEpoch === undefined ? base : { ...base, guardian_epoch: this.guardianEpoch };
    // Bind the suite (alg + guardian ML-DSA key) into the signed body; ed25519 is byte-identical.
    const signedBody = bindSuiteFields(withEpoch, this.suite?.alg, this.pqPk);
    const fields = signSuiteArtifact(this.suite?.alg, suiteKeysOf(this.guardianSecret, this.suite), settlementMessage(signedBody));
    return { ...signedBody, ...fields };
  }

  /** The balance movements of a slash: the full bond leaves escrow and is divided per {@link computeSlashSplit}. */
  private slashMoves(params: {
    amount: number;
    treasury: string;
    challengerAccount?: string | null;
    compensationAccount?: string;
    splitPolicy?: SlashSplitPolicy;
  }): { split: SlashSplit; moves: BondMove[] } {
    const split = computeSlashSplit(params.amount, params.splitPolicy ?? this.slashSplitPolicy, {
      challengerAccount: params.challengerAccount ?? null,
      victimAccount: params.compensationAccount ?? COMPENSATION_POOL_ACCOUNT,
      treasuryAccount: params.treasury,
    });
    const moves: BondMove[] = [{ account: this.escrow, op: 'debit', amount: params.amount }]; // the full bond leaves escrow
    if (split.challengerAccount && split.challengerReward > 0) moves.push({ account: split.challengerAccount, op: 'credit', amount: split.challengerReward });
    if (split.victimCompensation > 0) moves.push({ account: split.victimAccount, op: 'credit', amount: split.victimCompensation });
    if (split.treasuryRemainder > 0) moves.push({ account: split.treasuryAccount, op: 'credit', amount: split.treasuryRemainder });
    return { split, moves };
  }

  private openBondOrThrow(view: BondView, who: string, claimId: string): BondHead {
    const bond = view.bond(claimId);
    if (!bond) throw new Error(`${who}: no bond for ${claimId}`);
    if (bond.status !== 'open') throw new Error(`${who}: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    return bond;
  }

  private slashPlan(
    bond: BondHead,
    claimId: string,
    now: number,
    evidenceDigest: string,
    p: { treasury: string; challengerAccount?: string | null; compensationAccount?: string; splitPolicy?: SlashSplitPolicy },
  ): BondPlan {
    const { split, moves } = this.slashMoves({
      amount: bond.amount,
      treasury: p.treasury,
      challengerAccount: p.challengerAccount,
      compensationAccount: p.compensationAccount,
      splitPolicy: p.splitPolicy,
    });
    const record = this.signRecord({ claimId, action: 'slash', amount: bond.amount, from: this.escrow, to: p.treasury, at: now, evidenceDigest, split });
    return { claimId, expect: 'open', next: 'slashed', moves, record };
  }

  /**
   * Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, and
   * one that would breach the per-depositor open-claim caps; debits real collateral. Refuses a non-positive/non-finite amount and a double-open of the same claim.
   * The bond moves from the depositor into escrow; it credits no account until it settles.
   */
  planOpen(view: BondView, params: { claimId: string; amount: number; depositor: string; exposure?: number; now: number; window?: BondRegistration }): BondPlan {
    const { claimId, amount, depositor } = params;
    if (typeof claimId !== 'string' || claimId.length === 0) throw new Error('openBond: claimId is required');
    if (!Number.isFinite(amount) || amount <= 0) throw new Error('openBond: amount must be a positive finite number');
    if (typeof depositor !== 'string' || depositor.length === 0) throw new Error('openBond: depositor is required');
    if (view.bond(claimId)) throw new Error(`openBond: bond ${claimId} already exists (double-open refused)`);

    const required = bondAmount(this.bondPolicy, params.exposure ?? 0);
    if (amount < required) throw new Error(`openBond: amount ${amount} is below the required bond ${required}`);
    const { count: openCount, sum: openSum } = view.openTotals(depositor);
    if (openCount + 1 > this.bondPolicy.maxOpenClaims) throw new Error('openBond: depositor open-claim cap reached');
    if (openSum + amount > this.bondPolicy.maxOpenAmount) throw new Error('openBond: depositor aggregate open-bond cap exceeded');
    if (view.balanceOf(depositor) < amount) throw new Error('openBond: insufficient balance for the bond');

    const record = this.signRecord({ claimId, action: 'open', amount, from: depositor, to: this.escrow, at: params.now, evidenceDigest: '' });
    return {
      claimId,
      expect: 'none',
      next: 'open',
      open: { amount, depositor, maxOpenClaims: this.bondPolicy.maxOpenClaims, maxOpenAmount: this.bondPolicy.maxOpenAmount, ...(params.window ? { window: params.window } : {}) },
      moves: [
        { account: depositor, op: 'debit', amount }, // collateral is really taken
        { account: this.escrow, op: 'credit', amount },
      ],
      record,
    };
  }

  /**
   * Release a bond back to its depositor after an unchallenged challenge window. Refuses a bond that
   * does not exist or is not currently `open` (double-settle refused). Credits the depositor.
   */
  planRelease(view: BondView, params: { claimId: string; now: number }): BondPlan {
    const { claimId } = params;
    const bond = view.bond(claimId);
    if (!bond) throw new Error(`releaseBond: no bond for ${claimId}`);
    if (bond.status !== 'open') throw new Error(`releaseBond: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    const record = this.signRecord({ claimId, action: 'release', amount: bond.amount, from: this.escrow, to: bond.depositor, at: params.now, evidenceDigest: '' });
    return {
      claimId,
      expect: 'open',
      next: 'released',
      moves: [
        { account: this.escrow, op: 'debit', amount: bond.amount },
        { account: bond.depositor, op: 'credit', amount: bond.amount },
      ],
      record,
    };
  }

  /** Slash against a VERIFIED fraud verdict; re-runs `verifyFraudProof` itself (see {@link BondLedger.slashBond}). */
  planSlash(view: BondView, params: SlashBondParams & { now: number }): BondPlan {
    const { claimId, claim, fraudProof, grant, treasury, openSnapshot } = params;
    const bond = this.openBondOrThrow(view, 'slashBond', claimId);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashBond: treasury is required');
    if (claim.bond_ref !== claimId) throw new Error('slashBond: claim.bond_ref does not match claimId');

    // Independently re-derive the fraud verdict — NOT challenger input.
    const verdict = verifyFraudProof(claim, fraudProof, grant, openSnapshot);
    if (!verdict.fraudulent || verdict.slashBondRef !== claimId) {
      throw new Error(`slashBond: refused — no verified fraud verdict slashing ${claimId} (${verdict.reason})`);
    }
    return this.slashPlan(bond, claimId, params.now, settlementEvidenceDigest(claim, verdict), params);
  }

  /** Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). */
  planSlashOnRevocation(view: BondView, params: SlashOnRevocationParams & { now: number }): BondPlan {
    const { claimId, claim, revokedCapId, treasury } = params;
    const bond = this.openBondOrThrow(view, 'slashBondOnRevocation', claimId);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashBondOnRevocation: treasury is required');
    if (claim.bond_ref !== claimId) throw new Error('slashBondOnRevocation: claim.bond_ref does not match claimId');
    if (typeof revokedCapId !== 'string' || revokedCapId.length === 0) throw new Error('slashBondOnRevocation: revokedCapId is required');
    return this.slashPlan(bond, claimId, params.now, revocationEvidenceDigest(claim, revokedCapId), params);
  }

  /** Slash the AGENT's bond because a dispute proved it UNDERSTATED a risk input; re-runs `adjudicateDispute` itself. */
  planSlashOnDispute(view: BondView, params: SlashOnDisputeParams & { now: number }): BondPlan {
    const { claimId, claim, dispute, grant, openSnapshot, oracle, treasury } = params;
    const bond = this.openBondOrThrow(view, 'slashBondOnDispute', claimId);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashBondOnDispute: treasury is required');
    if (claim.bond_ref !== claimId) throw new Error('slashBondOnDispute: claim.bond_ref does not match claimId');

    // Independently re-derive the dispute verdict — NOT challenger input.
    const verdict = adjudicateDispute({ claim, dispute, grant, openSnapshot, oracle, rMargin: params.rMargin });
    if (verdict.outcome !== 'agent-fraud' || !verdict.fraudulent || verdict.slashBondRef !== claimId) {
      throw new Error(`slashBondOnDispute: refused — no verified agent-fraud verdict slashing ${claimId} (${verdict.outcome}: ${verdict.reason})`);
    }
    return this.slashPlan(bond, claimId, params.now, disputeEvidenceDigest(claim, verdict), params);
  }

  /** Slash the CHALLENGER's counter-bond because the dispute was FRIVOLOUS (anti-griefing); re-runs `adjudicateDispute`. */
  planSlashCounterBond(view: BondView, params: SlashCounterBondParams & { now: number }): BondPlan {
    const { counterBondId, claim, dispute, grant, openSnapshot, oracle, treasury } = params;
    const bond = view.bond(counterBondId);
    if (!bond) throw new Error(`slashCounterBond: no counter-bond for ${counterBondId}`);
    if (bond.status !== 'open') throw new Error(`slashCounterBond: counter-bond ${counterBondId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashCounterBond: treasury is required');

    const verdict = adjudicateDispute({ claim, dispute, grant, openSnapshot, oracle, rMargin: params.rMargin });
    if (verdict.outcome !== 'claim-upheld' || !verdict.slashCounterBond) {
      throw new Error(`slashCounterBond: refused — the dispute is not frivolous (${verdict.outcome}: ${verdict.reason})`);
    }
    // Anonymous slash of the griefer's own stake: 100% treasury (no rewardable challenger). The victim pool
    // accrues 0 here because `challengerAccount` is null (see `computeSlashSplit`); a deployment that wants to
    // compensate the wrongly-accused agent on a griefing slash would branch — flagged tunable.
    return this.slashPlan(bond, counterBondId, params.now, disputeEvidenceDigest(claim, verdict), {
      treasury,
      challengerAccount: null,
      compensationAccount: params.compensationAccount,
      splitPolicy: params.splitPolicy,
    });
  }
}

/**
 * Apply `moves` to a balance lookup in order, exactly as {@link InMemoryBondAccount} would, and return the resulting
 * balances. THROWS (applying nothing) on an invalid amount or an overdraft. Shared by every store so no store can
 * diverge on the arithmetic (micro-unit exact where the amounts are on the micro grid).
 */
export function applyBondMoves(balanceOf: (account: string) => number, moves: readonly BondMove[]): Map<string, number> {
  const out = new Map<string, number>();
  const bal = (a: string): number => out.get(a) ?? balanceOf(a);
  for (const m of moves) {
    if (!Number.isFinite(m.amount) || m.amount < 0) throw new Error(`${m.op}: invalid amount`);
    if (m.op === 'debit' && bal(m.account) < m.amount) throw new Error(`debit: insufficient balance for ${m.account}`);
    out.set(m.account, exactAdd(bal(m.account), m.amount, m.op === 'debit' ? -1 : 1));
  }
  return out;
}

// ---- A3c: insurance capital pool (scarce collateral) --------------------------------------
//
// A linear bond is just the claimant's own stake; it is not SCARCE shared collateral. An insurance pool is:
// premiums paid by (or on behalf of) agents accumulate finite capital, and victim payouts draw it down. The
// pool can only ever pay what it holds — coverage is CAPITAL-CONSTRAINED, fail-closed — which is what makes
// the collateral scarce. Premiums are priced off `reputation.ts:priceCoverage` (imported, never modified):
// a worse-reputation subject pays a higher premium for the same coverage, so the pool is funded in
// proportion to the risk it underwrites. Pure accounting; the real custody ledger is a seam (see header).

/** An immutable snapshot of the pool's accounting. Invariant: `initial + premiumsIn - payoutsOut === balance`. */
export interface InsurancePoolState {
  /** Opening capital the pool was seeded with. */
  initial: number;
  /** Total premiums collected. */
  premiumsIn: number;
  /** Total victim payouts made. */
  payoutsOut: number;
  /** Current free capital = `initial + premiumsIn - payoutsOut`. */
  balance: number;
}

/** The result of collecting a premium: the underwriting quote plus the pool state after crediting it. */
export interface PremiumCollection {
  pricing: InsurancePricing;
  state: InsurancePoolState;
}

/**
 * A finite, fail-closed insurance capital pool. Premiums (priced via {@link priceCoverage}) are credited;
 * victim payouts are debited and REFUSED when they exceed the pool's free capital (scarce collateral). All
 * amounts are checked finite and non-negative. The three ledgers (`initial`, `premiumsIn`, `payoutsOut`)
 * always reconcile to `balance` exactly — payouts never silently overdraw.
 */
export class InsuranceCapitalPool {
  private readonly initial: number;
  private _premiumsIn = 0;
  private _payoutsOut = 0;

  constructor(initial = 0) {
    if (!Number.isFinite(initial) || initial < 0) throw new Error('InsuranceCapitalPool: initial capital must be a non-negative finite number');
    this.initial = initial;
  }

  get balance(): number {
    return this.initial + this._premiumsIn - this._payoutsOut;
  }
  get premiumsIn(): number {
    return this._premiumsIn;
  }
  get payoutsOut(): number {
    return this._payoutsOut;
  }
  /** Current accounting snapshot (the conservation invariant always holds over these). */
  state(): InsurancePoolState {
    return { initial: this.initial, premiumsIn: this._premiumsIn, payoutsOut: this._payoutsOut, balance: this.balance };
  }

  /** Price coverage of `exposure` for `rep` WITHOUT mutating the pool (delegates to {@link priceCoverage}). */
  quote(rep: Reputation, exposure: number, opts: PricingOptions = {}): InsurancePricing {
    return priceCoverage(rep, exposure, opts);
  }

  /**
   * Price coverage of `exposure` for `rep` and, if not declined, credit the premium to the pool. A declined
   * quote (reputation below the underwriting floor) credits nothing. Returns the quote + the post-credit state.
   */
  collectPremium(rep: Reputation, exposure: number, opts: PricingOptions = {}): PremiumCollection {
    const pricing = this.quote(rep, exposure, opts);
    if (!pricing.declined && pricing.premium > 0) {
      if (!Number.isFinite(pricing.premium) || pricing.premium < 0) throw new Error('collectPremium: priced premium is not a non-negative finite number');
      this._premiumsIn += pricing.premium;
    }
    return { pricing, state: this.state() };
  }

  /** True iff the pool currently holds at least `amount` of free capital. */
  canCover(amount: number): boolean {
    return Number.isFinite(amount) && amount >= 0 && this.balance >= amount;
  }

  /**
   * Pay `amount` of victim compensation out of the pool. REFUSED (throws) when `amount` is non-positive /
   * non-finite or exceeds the free capital — the pool never pays what it does not hold (fail-closed, scarce
   * collateral). Returns the post-payout state.
   */
  payClaim(amount: number): InsurancePoolState {
    if (!Number.isFinite(amount) || amount <= 0) throw new Error('payClaim: amount must be a positive finite number');
    if (amount > this.balance) throw new Error(`payClaim: insufficient pool capital (need ${amount}, have ${this.balance})`);
    this._payoutsOut += amount;
    return this.state();
  }
}

// SERVER WAVE — IMPLEMENTED: the real escrow store + finalize sweeper live in the backend, not this pure
// reference module. Balances/bonds persist in `pca_bond_accounts` (the concrete server-side BondAccount) +
// the signed settlement records are persisted server-side, and every money move commits in the SAME
// transaction as the claim-status change (openBond / finalizeClaim / slashClaim); a finalize sweeper in
// the hosting layer releases expired-window bonds. This module keeps the pure, Map-backed reference
// ledger (`InMemoryBondAccount`) the server re-verifies records against.
