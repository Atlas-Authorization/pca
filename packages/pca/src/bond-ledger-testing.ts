/**
 * TEST DOUBLES for bond settlement (`@atlasauth/pca/ext/optimistic-testing`): a Map-backed {@link BondLedger} and an
 * in-memory {@link InMemoryBondAccount}. State is lost with the process, so they are NOT part of `@atlasauth/pca/ext/optimistic`
 * (0.5, B17): production code uses `StoreBondLedger` over a durable `BondStore` (`bond-store.ts`).
 */
import type { SignerSuiteOpts } from './pq';
import {
  type BondAccount,
  type BondHead,
  type BondPhase,
  type BondPlan,
  type BondPlannerOpts,
  type BondPolicy,
  type BondView,
  type SettlementRecord,
  type SlashBondParams,
  type SlashCounterBondParams,
  type SlashOnDisputeParams,
  type SlashOnRevocationParams,
  type SlashSplitPolicy,
  BondSettlementPlanner,
  applyBondMoves,
  exactAdd,
} from './bond-settlement';

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
    this.balances.set(account, exactAdd(this.balanceOf(account), amount, -1));
  }
  credit(account: string, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) throw new Error('credit: invalid amount');
    this.balances.set(account, exactAdd(this.balanceOf(account), amount, 1));
  }
}

export interface BondLedgerOpts {
  /** The guardian/settlement secret key that signs every record. */
  guardianSecret: Uint8Array;
  /**
   * Optional guardian key epoch stamped into (and SIGNED into) every record this ledger produces, so a
   * record is attributable to the exact key generation that signed it (see {@link SettlementRecord.guardian_epoch}).
   * Must be a non-negative safe integer. Omit to produce pre-epoch records (byte-identical to before).
   */
  guardianEpoch?: number;
  /**
   * Signature suite for every record this ledger signs (crypto-agility). Default ed25519 (byte-identical
   * to pre-agility). For ml-dsa-65/hybrid pass the guardian/settlement ML-DSA-65 key pair.
   */
  suite?: SignerSuiteOpts;
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
 * A simple in-memory, `Map`-backed bond ledger (internal accounting only; no money moves). It
 * locks a bond on `openBond`, returns it to the depositor on `releaseBond` (after an unchallenged
 * window), or moves it to the treasury on `slashBond` (only against a VERIFIED fraud verdict). Each
 * transition produces a guardian-signed `SettlementRecord`. `balanceOf` reports settled credits (a
 * release credits the depositor; a slash credits the treasury); an open bond is locked in escrow and
 * credits no one until it settles. State is lost with the process: for a durable ledger use
 * `StoreBondLedger` (`bond-store.ts`), which commits the same decisions to a {@link BondStore}.
 */
export class BondLedger {
  private readonly planner: BondSettlementPlanner;
  private readonly bonds = new Map<string, BondHead>();
  private readonly accounts: BondAccount;
  private readonly view: BondView;

  constructor(opts: BondLedgerOpts) {
    this.planner = new BondSettlementPlanner(opts);
    this.accounts = opts.accounts ?? new InMemoryBondAccount();
    this.view = {
      bond: (id) => this.bonds.get(id),
      balanceOf: (a) => this.accounts.balanceOf(a),
      openTotals: (depositor) => {
        let count = 0;
        let sum = 0;
        for (const b of this.bonds.values()) {
          if (b.status === 'open' && b.depositor === depositor) {
            count += 1;
            sum += b.amount;
          }
        }
        return { count, sum };
      },
    };
  }

  /** The guardian/settlement public key (b64u) — hand this to verifiers of the signed records. */
  get guardianPublicKey(): string {
    return this.planner.guardianPublicKey;
  }
  get bondPolicy(): BondPolicy {
    return this.planner.bondPolicy;
  }
  get slashSplitPolicy(): SlashSplitPolicy {
    return this.planner.slashSplitPolicy;
  }

  /** The settled credit balance of `account` (0 if unknown). */
  balanceOf(account: string): number {
    return this.accounts.balanceOf(account);
  }

  /** The lifecycle status of the bond for `claimId`. */
  bondStatus(claimId: string): BondPhase {
    return this.bonds.get(claimId)?.status ?? 'none';
  }

  private now(at?: number): number {
    return Number.isFinite(at) ? (at as number) : Date.now();
  }

  /** Apply a plan all-or-nothing: the moves are checked against an overlay first, so a refused debit leaves no trace. */
  private commit(plan: BondPlan): SettlementRecord {
    applyBondMoves((a) => this.accounts.balanceOf(a), plan.moves); // throws before anything is mutated
    for (const m of plan.moves) {
      if (m.op === 'debit') this.accounts.debit(m.account, m.amount);
      else this.accounts.credit(m.account, m.amount);
    }
    if (plan.open) this.bonds.set(plan.claimId, { claimId: plan.claimId, amount: plan.open.amount, depositor: plan.open.depositor, status: 'open' });
    else this.bonds.get(plan.claimId)!.status = plan.next; // a settle plan was made from this bond, so it exists
    return plan.record;
  }

  /**
   * Open (lock) a bond: refuses an unaffordable bond, one below `bondAmount(policy, exposure)`, and
   * one that would breach the per-depositor open-claim caps; debits real collateral. Refuses a non-positive/non-finite amount and a double-open of the same claim.
   * The bond moves from the depositor into escrow; it credits no account until it settles.
   */
  openBond(params: { claimId: string; amount: number; depositor: string; exposure?: number; at?: number }): SettlementRecord {
    return this.commit(this.planner.planOpen(this.view, { ...params, now: this.now(params.at) }));
  }

  /** Release a bond back to its depositor after an unchallenged challenge window (double-settle refused). */
  releaseBond(params: { claimId: string; at?: number }): SettlementRecord {
    return this.commit(this.planner.planRelease(this.view, { claimId: params.claimId, now: this.now(params.at) }));
  }

  /**
   * Slash a bond — ONLY against a VERIFIED fraud verdict. This method itself re-runs `verifyFraudProof`
   * (against the grant the settlement layer trusts) and refuses unless the server-derived verdict is
   * `fraudulent` and slashes THIS bond; the challenger's assertion alone never authorizes a slash. Refuses a
   * non-existent / already-settled bond (double-settle). The signed record's `evidenceDigest` binds to the
   * recomputed verdict, and its `split` records the challenger / victim-pool / treasury division.
   *
   * SLASH SPLIT: pass `challengerAccount` (the successful challenger's payout account) to divert the
   * challenger + victim shares; omit it (anonymous) to send the whole bond to the treasury. `compensationAccount`
   * is the victim pool (default `COMPENSATION_POOL_ACCOUNT`). All credits happen here, in the same synchronous
   * settlement as the status change.
   */
  slashBond(params: SlashBondParams & { at?: number }): SettlementRecord {
    return this.commit(this.planner.planSlash(this.view, { ...params, now: this.now(params.at) }));
  }

  /**
   * Slash a bond because a capability in the claim's chain was REVOKED after the bond opened. The
   * authorizing evidence is server-derived (the caller MUST have confirmed `revokedCapId` is both in
   * the claim's chain and currently in the instance's revocation set) — never a challenger assertion.
   */
  slashBondOnRevocation(params: SlashOnRevocationParams & { at?: number }): SettlementRecord {
    return this.commit(this.planner.planSlashOnRevocation(this.view, { ...params, now: this.now(params.at) }));
  }

  /**
   * Slash the AGENT's bond because a dispute proved it UNDERSTATED a risk input. This method itself re-runs
   * `adjudicateDispute` and refuses unless the SERVER-DERIVED verdict is `agent-fraud` and names THIS bond.
   */
  slashBondOnDispute(params: SlashOnDisputeParams & { at?: number }): SettlementRecord {
    return this.commit(this.planner.planSlashOnDispute(this.view, { ...params, now: this.now(params.at) }));
  }

  /**
   * Slash the CHALLENGER's COUNTER-BOND because the dispute was FRIVOLOUS — the objective oracle UPHELD the
   * agent's disputed input (anti-griefing). Server-derived: this method re-runs `adjudicateDispute` and refuses
   * unless the verdict is `claim-upheld`. The counter-bond folds to the treasury.
   */
  slashCounterBond(params: SlashCounterBondParams & { at?: number }): SettlementRecord {
    return this.commit(this.planner.planSlashCounterBond(this.view, { ...params, now: this.now(params.at) }));
  }
}

