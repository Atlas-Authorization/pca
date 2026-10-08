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
 * SCOPE / SEAM. Balances live in a simple in-memory `Map` here so the logic is testable and
 * self-contained. In production the real store (a database, an on-chain escrow, a custody ledger) is a
 * SEAM: persist the `SettlementRecord`s and the per-account balances exactly as this class computes
 * them, and re-verify records with `verifySettlement`. The signing key is the guardian / settlement key;
 * only the public half is needed to verify.
 */
// Bond settlement records + fraud-verdict evidence are server-only (guardian-signed,
// carry amount/claimed_r floats), never recomputed by the language verifiers — lenient
// canonical, not the strict protocol form.
import { b64u, canonicalBytesLenient as canonicalBytes, hashCanonicalLenient as hashCanonical, utf8 } from './hash';
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
import type { Capability } from './capability';
import type { DecideInput } from './policy-vm';
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

/**
 * One payout share, INTEGER-SAFE: for an integer bond we floor so every share is an integer and the dust
 * accrues to the treasury remainder; for a fractional bond we keep the exact fraction. Either way the caller
 * derives the treasury remainder by SUBTRACTION, so the three shares always reconcile to `amount` exactly.
 */
function shareOf(amount: number, bps: number): number {
  const raw = (amount * bps) / 10_000;
  return Number.isInteger(amount) ? Math.floor(raw) : raw;
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
  const challengerReward = shareOf(amount, policy.challengerBps);
  const victimCompensation = shareOf(amount, policy.victimBps);
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
export function verifySettlement(record: SettlementRecord, guardianPublicKey: string): boolean {
  try {
    if (!record || typeof record !== 'object') return false;
    const { sig, pq_sig, ...body } = record; // the signed body keeps alg/pq_pk, drops both signatures
    if (typeof sig !== 'string' || resolveSigAlg(record.alg) === null) return false;
    return verifyWithSuite(record.alg, { edPub: guardianPublicKey, mlDsaPub: record.pq_pk }, settlementMessage(body), { sig, pq_sig });
  } catch {
    return false;
  }
}

// ---- bond sizing + collateral (audit finding 1 / P3-1) ------------------------------------

/** Bond sizing + per-depositor aggregate caps. Configurable; there is no hardcoded constant bond. */
export interface BondPolicy {
  /** Minimum bond regardless of exposure. */
  floor: number;
  /** Multiplier on the claim's exposure. */
  k: number;
  /** Max simultaneously-open bonds per depositor. */
  maxOpenClaims: number;
  /** Max aggregate open bonded amount per depositor. */
  maxOpenAmount: number;
}

export const DEFAULT_BOND_POLICY: BondPolicy = { floor: 1, k: 1, maxOpenClaims: 100, maxOpenAmount: Number.POSITIVE_INFINITY };

/**
 * `bondAmount(policy, exposure) = max(floor, k * exposure)` — a LINEAR bond in exposure (plus the Phase-2
 * blast-radius floor applied upstream at open time).
 *
 * SUPERLINEAR BOND NOTE (where a bond curve would plug in — NOT changed in this task): a convex curve
 * (e.g. `floor + k * exposure^gamma` with `gamma > 1`, or a tiered schedule) would make a large fraudulent
 * claim disproportionately expensive and compound the challenger/victim economics above. It plugs in HERE,
 * behind `BondPolicy` (add the curve params to the policy and apply them in this one function); nothing else
 * in the ledger assumes linearity. Deliberately deferred: Phase 2 already added the blast-radius floor, and
 * `openBond` sizing is out of scope for the economic-split work.
 */
export function bondAmount(policy: BondPolicy, exposure: number): number {
  const e = Number.isFinite(exposure) && exposure > 0 ? exposure : 0;
  return Math.max(policy.floor, policy.k * e);
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

/** In-memory `BondAccount` (tests / reference). */
export class InMemoryBondAccount implements BondAccount {
  private readonly balances = new Map<string, number>();
  constructor(initial: Record<string, number> = {}) {
    for (const [k, v] of Object.entries(initial)) this.balances.set(k, v);
  }
  balanceOf(account: string): number {
    return this.balances.get(account) ?? 0;
  }
  debit(account: string, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) throw new Error('debit: invalid amount');
    if (this.balanceOf(account) < amount) throw new Error(`debit: insufficient balance for ${account}`);
    this.balances.set(account, this.balanceOf(account) - amount);
  }
  credit(account: string, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) throw new Error('credit: invalid amount');
    this.balances.set(account, this.balanceOf(account) + amount);
  }
}

/** The lifecycle status of a bond in the ledger. */
export type BondPhase = 'none' | 'open' | 'released' | 'slashed';

interface BondState {
  claimId: string;
  amount: number;
  depositor: string;
  status: Exclude<BondPhase, 'none'>;
}

export interface BondLedgerOpts {
  /** The guardian/settlement secret key that signs every record. */
  guardianSecret: Uint8Array;
  /**
   * Signature suite for every record this ledger signs (crypto-agility). Default ed25519 (byte-identical
   * to pre-agility). For ml-dsa-65/hybrid pass the guardian/settlement ML-DSA-65 key pair.
   */
  suite?: { alg?: SigAlg; mlDsa?: MlDsaKeyPair };
  /** The escrow account label (default `ESCROW_ACCOUNT`). */
  escrowAccount?: string;
  /** Collateral store (default: a fresh empty `InMemoryBondAccount`; fund it for `openBond` to succeed). */
  accounts?: BondAccount;
  /** Bond sizing + aggregate caps (default `DEFAULT_BOND_POLICY`). */
  bondPolicy?: BondPolicy;
  /** Slash split (challenger / victim-pool / treasury; default `DEFAULT_SLASH_SPLIT_POLICY`). TUNABLE. */
  slashSplitPolicy?: SlashSplitPolicy;
}

/**
 * A simple in-memory, `Map`-backed bond ledger (the real store is a seam — see module header). It
 * locks a bond on `openBond`, returns it to the depositor on `releaseBond` (after an unchallenged
 * window), or moves it to the treasury on `slashBond` (only against a VERIFIED fraud verdict). Each
 * transition produces a guardian-signed `SettlementRecord`. `balanceOf` reports settled credits (a
 * release credits the depositor; a slash credits the treasury); an open bond is locked in escrow and
 * credits no one until it settles.
 */
export class BondLedger {
  /** The guardian/settlement public key (b64u) — hand this to verifiers of the signed records. */
  readonly guardianPublicKey: string;
  private readonly guardianSecret: Uint8Array;
  private readonly suite?: { alg?: SigAlg; mlDsa?: MlDsaKeyPair };
  private readonly pqPk?: string;
  private readonly escrow: string;
  private readonly bonds = new Map<string, BondState>();
  private readonly accounts: BondAccount;
  readonly bondPolicy: BondPolicy;
  readonly slashSplitPolicy: SlashSplitPolicy;

  constructor(opts: BondLedgerOpts) {
    if (!(opts.guardianSecret instanceof Uint8Array)) {
      throw new Error('BondLedger: guardianSecret must be a Uint8Array');
    }
    this.guardianSecret = opts.guardianSecret;
    this.guardianPublicKey = b64u(publicKeyOf(opts.guardianSecret));
    if (resolveSigAlg(opts.suite?.alg) === null) throw new Error(`BondLedger: unknown signature alg '${String(opts.suite?.alg)}'`);
    this.suite = opts.suite;
    this.pqPk = opts.suite?.mlDsa ? encodeMlDsaPublicKey(opts.suite.mlDsa.publicKey) : undefined;
    this.escrow = opts.escrowAccount ?? ESCROW_ACCOUNT;
    this.accounts = opts.accounts ?? new InMemoryBondAccount();
    this.bondPolicy = opts.bondPolicy ?? DEFAULT_BOND_POLICY;
    this.slashSplitPolicy = opts.slashSplitPolicy ?? DEFAULT_SLASH_SPLIT_POLICY;
  }

  /**
   * Debit the full bonded amount out of escrow and credit it across the challenger / victim-pool / treasury
   * per {@link computeSlashSplit}. Returns the exact split to embed in the signed record. Shared by both
   * slash paths (fraud proof + revocation) so they divide identically.
   */
  private settleSlashSplit(params: {
    amount: number;
    treasury: string;
    challengerAccount?: string | null;
    compensationAccount?: string;
    splitPolicy?: SlashSplitPolicy;
  }): SlashSplit {
    const split = computeSlashSplit(params.amount, params.splitPolicy ?? this.slashSplitPolicy, {
      challengerAccount: params.challengerAccount ?? null,
      victimAccount: params.compensationAccount ?? COMPENSATION_POOL_ACCOUNT,
      treasuryAccount: params.treasury,
    });
    this.accounts.debit(this.escrow, params.amount); // the full bond leaves escrow
    if (split.challengerAccount && split.challengerReward > 0) this.credit(split.challengerAccount, split.challengerReward);
    if (split.victimCompensation > 0) this.credit(split.victimAccount, split.victimCompensation);
    if (split.treasuryRemainder > 0) this.credit(split.treasuryAccount, split.treasuryRemainder);
    return split;
  }

  /** The settled credit balance of `account` (0 if unknown). */
  balanceOf(account: string): number {
    return this.accounts.balanceOf(account);
  }

  /** The lifecycle status of the bond for `claimId`. */
  bondStatus(claimId: string): BondPhase {
    return this.bonds.get(claimId)?.status ?? 'none';
  }

  private credit(account: string, amount: number): void {
    this.accounts.credit(account, amount);
  }

  private signRecord(base: Omit<SettlementRecord, 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>): SettlementRecord {
    // Bind the suite (alg + guardian ML-DSA key) into the signed body; ed25519 is byte-identical.
    const signedBody = bindSuiteFields(base, this.suite?.alg, this.pqPk);
    const fields = signSuiteArtifact(this.suite?.alg, { edSecret: this.guardianSecret, mlDsa: this.suite?.mlDsa }, settlementMessage(signedBody));
    return { ...signedBody, ...fields };
  }

  private now(at?: number): number {
    return Number.isFinite(at) ? (at as number) : Date.now();
  }

  /**
   * Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, and
   * one that would breach the per-depositor open-claim caps; debits real collateral. Refuses a non-positive/non-finite amount and a double-open of the same claim.
   * The bond moves from the depositor into escrow; it credits no account until it settles.
   */
  openBond(params: { claimId: string; amount: number; depositor: string; exposure?: number; at?: number }): SettlementRecord {
    const { claimId, amount, depositor } = params;
    if (typeof claimId !== 'string' || claimId.length === 0) throw new Error('openBond: claimId is required');
    if (!Number.isFinite(amount) || amount <= 0) throw new Error('openBond: amount must be a positive finite number');
    if (typeof depositor !== 'string' || depositor.length === 0) throw new Error('openBond: depositor is required');
    if (this.bonds.has(claimId)) throw new Error(`openBond: bond ${claimId} already exists (double-open refused)`);

    const required = bondAmount(this.bondPolicy, params.exposure ?? 0);
    if (amount < required) throw new Error(`openBond: amount ${amount} is below the required bond ${required}`);
    let openCount = 0;
    let openSum = 0;
    for (const b of this.bonds.values()) {
      if (b.status === 'open' && b.depositor === depositor) {
        openCount += 1;
        openSum += b.amount;
      }
    }
    if (openCount + 1 > this.bondPolicy.maxOpenClaims) throw new Error('openBond: depositor open-claim cap reached');
    if (openSum + amount > this.bondPolicy.maxOpenAmount) throw new Error('openBond: depositor aggregate open-bond cap exceeded');
    if (this.accounts.balanceOf(depositor) < amount) throw new Error('openBond: insufficient balance for the bond');

    this.accounts.debit(depositor, amount); // collateral is really taken
    this.accounts.credit(this.escrow, amount);
    this.bonds.set(claimId, { claimId, amount, depositor, status: 'open' });
    return this.signRecord({
      claimId,
      action: 'open',
      amount,
      from: depositor,
      to: this.escrow,
      at: this.now(params.at),
      evidenceDigest: '',
    });
  }

  /**
   * Release a bond back to its depositor after an unchallenged challenge window. Refuses a bond that
   * does not exist or is not currently `open` (double-settle refused). Credits the depositor.
   */
  releaseBond(params: { claimId: string; at?: number }): SettlementRecord {
    const { claimId } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`releaseBond: no bond for ${claimId}`);
    if (bond.status !== 'open') throw new Error(`releaseBond: bond ${claimId} is already ${bond.status} (double-settle refused)`);

    bond.status = 'released';
    this.accounts.debit(this.escrow, bond.amount);
    this.credit(bond.depositor, bond.amount);
    return this.signRecord({
      claimId,
      action: 'release',
      amount: bond.amount,
      from: this.escrow,
      to: bond.depositor,
      at: this.now(params.at),
      evidenceDigest: '',
    });
  }

  /**
   * Slash a bond — ONLY against a VERIFIED fraud verdict. This method itself re-runs `verifyFraudProof`
   * (against the grant the settlement layer trusts) and refuses unless the server-derived verdict is
   * `fraudulent` and slashes THIS bond; the challenger's assertion alone never authorizes a slash. Refuses a
   * non-existent / already-settled bond (double-settle). The signed record's `evidenceDigest` binds to the
   * recomputed verdict, and its `split` records the challenger / victim-pool / treasury division.
   *
   * SLASH SPLIT: pass `challengerAccount` (the successful challenger's payout account) to divert the
   * challenger + victim shares; omit it (anonymous) to send the whole bond to the treasury — today's
   * behavior. `compensationAccount` is the victim pool (default `COMPENSATION_POOL_ACCOUNT`). All credits
   * happen here, in the same synchronous settlement as the status change.
   */
  slashBond(params: {
    claimId: string;
    claim: BondedClaim;
    fraudProof: FraudProof;
    grant: Capability;
    /** FROZEN open-time `DecideInput` (server-held, captured at claim open). */
    openSnapshot: DecideInput;
    treasury: string;
    /** The successful challenger's payout account; omit/`null` for an anonymous challenge (→ 100% treasury). */
    challengerAccount?: string | null;
    /** The victim-compensation pool account (default `COMPENSATION_POOL_ACCOUNT`). */
    compensationAccount?: string;
    /** Override the ledger's slash split policy for this slash. TUNABLE. */
    splitPolicy?: SlashSplitPolicy;
    at?: number;
  }): SettlementRecord {
    const { claimId, claim, fraudProof, grant, treasury, openSnapshot } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`slashBond: no bond for ${claimId}`);
    if (bond.status !== 'open') throw new Error(`slashBond: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashBond: treasury is required');
    if (claim.bond_ref !== claimId) throw new Error('slashBond: claim.bond_ref does not match claimId');

    // Independently re-derive the fraud verdict — NOT challenger input.
    const verdict = verifyFraudProof(claim, fraudProof, grant, openSnapshot);
    if (!verdict.fraudulent || verdict.slashBondRef !== claimId) {
      throw new Error(`slashBond: refused — no verified fraud verdict slashing ${claimId} (${verdict.reason})`);
    }

    bond.status = 'slashed';
    const split = this.settleSlashSplit({
      amount: bond.amount,
      treasury,
      challengerAccount: params.challengerAccount,
      compensationAccount: params.compensationAccount,
      splitPolicy: params.splitPolicy,
    });
    return this.signRecord({
      claimId,
      action: 'slash',
      amount: bond.amount,
      from: this.escrow,
      to: treasury,
      at: this.now(params.at),
      evidenceDigest: settlementEvidenceDigest(claim, verdict),
      split,
    });
  }

  /**
   * Slash a bond because a capability in the claim's chain was REVOKED after the bond opened. The
   * authorizing evidence is server-derived (the caller MUST have confirmed `revokedCapId` is both in
   * the claim's chain and currently in the instance's revocation set) — never a challenger assertion.
   * Credits the treasury; binds the record to the revocation evidence. Refuses a missing/already-settled
   * bond (double-settle).
   */
  slashBondOnRevocation(params: {
    claimId: string;
    claim: BondedClaim;
    revokedCapId: string;
    treasury: string;
    /** The successful challenger's payout account; omit/`null` for an anonymous challenge (→ 100% treasury). */
    challengerAccount?: string | null;
    /** The victim-compensation pool account (default `COMPENSATION_POOL_ACCOUNT`). */
    compensationAccount?: string;
    /** Override the ledger's slash split policy for this slash. TUNABLE. */
    splitPolicy?: SlashSplitPolicy;
    at?: number;
  }): SettlementRecord {
    const { claimId, claim, revokedCapId, treasury } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`slashBondOnRevocation: no bond for ${claimId}`);
    if (bond.status !== 'open') throw new Error(`slashBondOnRevocation: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashBondOnRevocation: treasury is required');
    if (claim.bond_ref !== claimId) throw new Error('slashBondOnRevocation: claim.bond_ref does not match claimId');
    if (typeof revokedCapId !== 'string' || revokedCapId.length === 0) throw new Error('slashBondOnRevocation: revokedCapId is required');

    bond.status = 'slashed';
    const split = this.settleSlashSplit({
      amount: bond.amount,
      treasury,
      challengerAccount: params.challengerAccount,
      compensationAccount: params.compensationAccount,
      splitPolicy: params.splitPolicy,
    });
    return this.signRecord({
      claimId,
      action: 'slash',
      amount: bond.amount,
      from: this.escrow,
      to: treasury,
      at: this.now(params.at),
      evidenceDigest: revocationEvidenceDigest(claim, revokedCapId),
      split,
    });
  }

  /**
   * Slash the AGENT's bond because a dispute proved it UNDERSTATED a risk input. This method itself re-runs
   * `adjudicateDispute` (with the objective oracle, against the grant + frozen snapshot the settlement layer
   * trusts) and refuses unless the SERVER-DERIVED verdict is `agent-fraud` and names THIS bond — the
   * challenger's assertion alone never authorizes a slash. Refuses a missing / already-settled bond
   * (double-settle). The signed record's `evidenceDigest` binds to the recomputed dispute verdict, and its
   * `split` records the challenger / victim-pool / treasury division (identical to the fraud-proof path).
   */
  slashBondOnDispute(params: {
    claimId: string;
    claim: BondedClaim;
    dispute: DisputeClaim;
    grant: Capability;
    /** FROZEN open-time `DecideInput` (server-held, captured at claim open). */
    openSnapshot: DecideInput;
    /** The objective oracle resolving the truthful value of the disputed input. */
    oracle: ObjectiveOracle;
    treasury: string;
    /** The successful challenger's payout account; omit/`null` for an anonymous challenge (→ 100% treasury). */
    challengerAccount?: string | null;
    /** The victim-compensation pool account (default `COMPENSATION_POOL_ACCOUNT`). */
    compensationAccount?: string;
    /** Override the ledger's slash split policy for this slash. TUNABLE. */
    splitPolicy?: SlashSplitPolicy;
    rMargin?: number;
    at?: number;
  }): SettlementRecord {
    const { claimId, claim, dispute, grant, openSnapshot, oracle, treasury } = params;
    const bond = this.bonds.get(claimId);
    if (!bond) throw new Error(`slashBondOnDispute: no bond for ${claimId}`);
    if (bond.status !== 'open') throw new Error(`slashBondOnDispute: bond ${claimId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashBondOnDispute: treasury is required');
    if (claim.bond_ref !== claimId) throw new Error('slashBondOnDispute: claim.bond_ref does not match claimId');

    // Independently re-derive the dispute verdict — NOT challenger input.
    const verdict = adjudicateDispute({ claim, dispute, grant, openSnapshot, oracle, rMargin: params.rMargin });
    if (verdict.outcome !== 'agent-fraud' || !verdict.fraudulent || verdict.slashBondRef !== claimId) {
      throw new Error(`slashBondOnDispute: refused — no verified agent-fraud verdict slashing ${claimId} (${verdict.outcome}: ${verdict.reason})`);
    }

    bond.status = 'slashed';
    const split = this.settleSlashSplit({
      amount: bond.amount,
      treasury,
      challengerAccount: params.challengerAccount,
      compensationAccount: params.compensationAccount,
      splitPolicy: params.splitPolicy,
    });
    return this.signRecord({
      claimId,
      action: 'slash',
      amount: bond.amount,
      from: this.escrow,
      to: treasury,
      at: this.now(params.at),
      evidenceDigest: disputeEvidenceDigest(claim, verdict),
      split,
    });
  }

  /**
   * Slash the CHALLENGER's COUNTER-BOND because the dispute was FRIVOLOUS — the objective oracle UPHELD the
   * agent's disputed input, so fast-path admission survives at the truthful value (anti-griefing). Like every
   * slash here it is server-derived: this method re-runs `adjudicateDispute` and refuses unless the verdict is
   * `claim-upheld`. `counterBondId` is the challenger's OWN bond (opened via {@link openBond}); the agent's
   * claim bond is untouched (the honest agent keeps its bond and its provisional effect). The counter-bond
   * folds to the treasury (anonymous — the griefer is not a rewardable challenger); the signed record's
   * `evidenceDigest` binds to the recomputed dispute verdict. Refuses a missing / already-settled counter-bond.
   */
  slashCounterBond(params: {
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
    at?: number;
  }): SettlementRecord {
    const { counterBondId, claim, dispute, grant, openSnapshot, oracle, treasury } = params;
    const bond = this.bonds.get(counterBondId);
    if (!bond) throw new Error(`slashCounterBond: no counter-bond for ${counterBondId}`);
    if (bond.status !== 'open') throw new Error(`slashCounterBond: counter-bond ${counterBondId} is already ${bond.status} (double-settle refused)`);
    if (typeof treasury !== 'string' || treasury.length === 0) throw new Error('slashCounterBond: treasury is required');

    const verdict = adjudicateDispute({ claim, dispute, grant, openSnapshot, oracle, rMargin: params.rMargin });
    if (verdict.outcome !== 'claim-upheld' || !verdict.slashCounterBond) {
      throw new Error(`slashCounterBond: refused — the dispute is not frivolous (${verdict.outcome}: ${verdict.reason})`);
    }

    bond.status = 'slashed';
    // Anonymous slash of the griefer's own stake: 100% treasury (no rewardable challenger). The victim pool
    // accrues 0 here because `challengerAccount` is null (see `computeSlashSplit`); a deployment that wants to
    // compensate the wrongly-accused agent on a griefing slash would branch — flagged tunable.
    const split = this.settleSlashSplit({
      amount: bond.amount,
      treasury,
      challengerAccount: null,
      compensationAccount: params.compensationAccount,
      splitPolicy: params.splitPolicy,
    });
    return this.signRecord({
      claimId: counterBondId,
      action: 'slash',
      amount: bond.amount,
      from: this.escrow,
      to: treasury,
      at: this.now(params.at),
      evidenceDigest: disputeEvidenceDigest(claim, verdict),
      split,
    });
  }
}

// SERVER WAVE — IMPLEMENTED: the real escrow store + finalize sweeper live in the backend, not this pure
// reference module. Balances/bonds persist in `pca_bond_accounts` (the concrete server-side BondAccount) +
// the signed settlement records are persisted server-side, and every money move commits in the SAME
// transaction as the claim-status change (openBond / finalizeClaim / slashClaim); a finalize sweeper in
// the hosting layer releases expired-window bonds. This module keeps the pure, Map-backed reference
// ledger (`InMemoryBondAccount`) the server re-verifies records against.
