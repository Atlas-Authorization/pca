/**
 * Durable bond settlement: the `BondStore` contract, a reference store, and `StoreBondLedger`.
 *
 * INTERNAL ACCOUNTING ONLY. Nothing here moves money. Balances are numbers a store keeps for the deployment's own
 * books (escrow, depositors, challengers, the compensation pool, the treasury). A hosting layer that wants real
 * custody reconciles these books with its payment rail; PCA does not.
 *
 * WHAT THE STORE GUARANTEES. `BondStore.commit` applies a {@link BondPlan} ALL OR NOTHING: the compare-and-swap on the
 * bond's phase, every balance movement, the new phase and the signed record become visible together. A crash at any
 * point leaves either the state before the transition or the state after it, never a mix (a bond that is `slashed`
 * while escrow still holds its collateral, or the reverse). Committing the same transition twice is idempotent: the
 * second commit returns the stored record and moves nothing.
 *
 * WHAT THE LEDGER ADDS. `StoreBondLedger` plans each transition with the same {@link BondSettlementPlanner} the
 * in-memory {@link BondLedger} uses (so a slash is still authorised by a verdict the ledger recomputes, never by the
 * challenger), stamps every time from a clock the claimant cannot touch, and FAILS CLOSED:
 *
 *   | missing / wrong                          | result                                                         |
 *   |------------------------------------------|----------------------------------------------------------------|
 *   | no store, or an object that is not one   | constructor throws `store_missing`                             |
 *   | no guardian key                          | constructor throws `guardian_key_missing`                      |
 *   | clock returns a non-finite value         | operation throws `clock_invalid`; nothing is written           |
 *   | store throws / is unreachable            | operation throws `store_unavailable`; nothing is returned      |
 *   | stored state is malformed                | operation throws `store_corrupt`                               |
 *   | claim fails `verifyClaim` or the floor   | `openClaim` throws `invalid_claim`; nothing is written         |
 *   | release inside the challenge window      | throws `window_open`                                           |
 *   | fraud / dispute slash after the window   | throws `window_closed`                                         |
 *   | release / slash of an unregistered bond  | throws `unregistered` (counter-bonds use `releaseUnregistered`)|
 *   | claim differs from the one registered    | throws `claim_mismatch`                                        |
 *   | concurrent / conflicting transition      | throws `conflict`; the winner's record stands                  |
 *
 * THE CHALLENGE-WINDOW CLOCK. The window opens at the ledger's own `registeredAt` (its clock at `openClaim`), lasts the
 * claim's `challenge_window_ms`, and is never derived from the claim's `issued_at` or from a caller-supplied time. The
 * ledger's notion of "now" is `max(clock(), highest time the store has ever recorded)`, so a clock that steps backwards
 * (or a restart on a host with a slow clock) cannot reopen a closed window or release early.
 */
import { hashCanonicalLenient as hashCanonical } from './hash';
import type { PCActn } from './pcactn';
import {
  type BondPhase,
  type BondPlan,
  type BondPlannerOpts,
  type BondRegistration,
  type BondRow,
  type BondView,
  type SettlementRecord,
  type SlashBondParams,
  type SlashCounterBondParams,
  type SlashOnDisputeParams,
  type SlashOnRevocationParams,
  BondSettlementPlanner,
  applyBondMoves,
} from './bond-settlement';
import {
  type BondedClaim,
  type ChallengeWindowPolicy,
  DEFAULT_MIN_CHALLENGE_WINDOW_MS,
  DEFAULT_WINDOW_POLICY,
  verifyClaim,
} from './optimistic';
import type { DurableKv } from './durable-state';

export type BondStoreErrorCode =
  | 'store_missing'
  | 'guardian_key_missing'
  | 'clock_invalid'
  | 'store_unavailable'
  | 'store_corrupt'
  | 'invalid_claim'
  | 'window_open'
  | 'window_closed'
  | 'unregistered'
  | 'claim_mismatch'
  | 'conflict';

/** The typed failure of every store-backed bond operation. `code` is stable; `message` is for humans. */
export class BondStoreError extends Error {
  constructor(
    readonly code: BondStoreErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(`${code}: ${message}`, options);
    this.name = 'BondStoreError';
  }
}

/** What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark. */
export interface BondSnapshot {
  bond?: BondRow;
  /** `[account, balance]` pairs for the accounts asked for in {@link BondReadScope}. */
  balances: Array<[string, number]>;
  openTotals: { count: number; sum: number };
  /** Highest `observedAt` any committed transition has recorded (0 for an empty store). */
  highWater: number;
}

export interface BondReadScope {
  claimId: string;
  /** Also return this account's balance and its open-bond totals. */
  depositor?: string;
}

export type BondCommitOutcome =
  | { outcome: 'committed'; record: SettlementRecord }
  /** The very same transition had already been committed (a retry or a lost acknowledgement): its stored record, nothing moved. */
  | { outcome: 'replayed'; record: SettlementRecord }
  | { outcome: 'conflict'; reason: string; current: BondPhase };

/**
 * The persistence contract for bond settlement. Implement it over a database transaction, a compare-and-swap register,
 * or the {@link KvBondStore} reference. Run `runBondStoreConformance` (in `@atlasauth/pca-store-conformance`) against it.
 */
export interface BondStore {
  /** A consistent snapshot for planning. May be stale by the time of `commit`; `commit` re-checks everything. */
  read(scope: BondReadScope): Promise<BondSnapshot>;
  /**
   * Apply `plan` atomically (see the module comment) and record `observedAt` in the time high-water mark. Rules:
   *  - `plan.expect === 'none'` (open): absent bond -> check the caps and the balance, create it (`committed`); same
   *    bond already there with the same depositor, amount and registration -> `replayed`; anything else -> `conflict`.
   *  - otherwise: absent bond or a phase other than `plan.expect` -> `replayed` iff the bond is already in `plan.next`
   *    via the same settlement (same action, amount, parties, evidence and split), else `conflict`; an overdraft
   *    -> `conflict`; otherwise commit.
   * Must never throw for a refused plan (that is a `conflict`); throws only when the store itself fails.
   */
  commit(plan: BondPlan, observedAt: number): Promise<BondCommitOutcome>;
  /** Atomically credit `account` with `amount` (internal accounting top-up; a positive finite number). Returns the new balance. */
  deposit(account: string, amount: number): Promise<number>;
}

/** True iff `s` has the BondStore methods. */
export function isBondStore(s: unknown): s is BondStore {
  const o = s as Record<string, unknown> | null;
  return !!o && typeof o === 'object' && typeof o.read === 'function' && typeof o.commit === 'function' && typeof o.deposit === 'function';
}

/** Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored). */
export function sameSettlement(a: SettlementRecord, b: SettlementRecord): boolean {
  return (
    a.claimId === b.claimId &&
    a.action === b.action &&
    a.amount === b.amount &&
    a.from === b.from &&
    a.to === b.to &&
    a.evidenceDigest === b.evidenceDigest &&
    hashCanonical(a.split ?? null) === hashCanonical(b.split ?? null)
  );
}

const sameWindow = (a?: BondRegistration, b?: BondRegistration): boolean =>
  a === undefined || b === undefined ? a === b : a.windowMs === b.windowMs && a.claimDigest === b.claimDigest; // registeredAt is the first call's

// ---- the reference transition function (pure) ---------------------------------------------------------------------

/** The state a reference store keeps. Entry arrays, not objects: an account or claim named `__proto__` is just a key. */
export interface BondDoc {
  v: 1;
  balances: Map<string, number>;
  bonds: Map<string, BondRow>;
  highWater: number;
}

export const emptyBondDoc = (): BondDoc => ({ v: 1, balances: new Map(), bonds: new Map(), highWater: 0 });

/**
 * Apply `plan` to `doc` following the {@link BondStore.commit} rules. Mutates `doc` ONLY on `committed` (the moves are
 * checked on an overlay first). Pure and synchronous: every reference store is this function plus a lock.
 */
export function commitBondPlan(doc: BondDoc, plan: BondPlan, observedAt: number): BondCommitOutcome {
  const bond = doc.bonds.get(plan.claimId);
  if (plan.expect === 'none') {
    const o = plan.open;
    if (!o || plan.next !== 'open') return { outcome: 'conflict', reason: 'malformed open plan', current: bond?.status ?? 'none' };
    if (bond) {
      const same = bond.depositor === o.depositor && bond.amount === o.amount && sameWindow(bond.window, o.window) && bond.records[0] !== undefined && sameSettlement(bond.records[0], plan.record);
      return same ? { outcome: 'replayed', record: bond.records[0]! } : { outcome: 'conflict', reason: `bond ${plan.claimId} already exists`, current: bond.status };
    }
    let count = 0;
    let sum = 0;
    for (const b of doc.bonds.values()) {
      if (b.status === 'open' && b.depositor === o.depositor) {
        count += 1;
        sum += b.amount;
      }
    }
    if (count + 1 > o.maxOpenClaims) return { outcome: 'conflict', reason: 'depositor open-claim cap reached', current: 'none' };
    if (sum + o.amount > o.maxOpenAmount) return { outcome: 'conflict', reason: 'depositor aggregate open-bond cap exceeded', current: 'none' };
  } else if (!bond) {
    return { outcome: 'conflict', reason: `no bond for ${plan.claimId}`, current: 'none' };
  } else if (bond.status !== plan.expect) {
    const last = bond.records[bond.records.length - 1];
    return bond.status === plan.next && last !== undefined && sameSettlement(last, plan.record)
      ? { outcome: 'replayed', record: last }
      : { outcome: 'conflict', reason: `bond ${plan.claimId} is already ${bond.status}`, current: bond.status };
  }
  let next: Map<string, number>;
  try {
    next = applyBondMoves((a) => doc.balances.get(a) ?? 0, plan.moves);
  } catch (e) {
    return { outcome: 'conflict', reason: (e as Error).message, current: bond?.status ?? 'none' };
  }
  for (const [a, v] of next) doc.balances.set(a, v);
  if (plan.open) {
    doc.bonds.set(plan.claimId, {
      claimId: plan.claimId,
      amount: plan.open.amount,
      depositor: plan.open.depositor,
      status: 'open',
      ...(plan.open.window ? { window: plan.open.window } : {}),
      records: [plan.record],
    });
  } else {
    bond!.status = plan.next; // a settle plan reached here only with the bond present
    bond!.records.push(plan.record);
  }
  doc.highWater = Math.max(doc.highWater, Number.isFinite(observedAt) ? observedAt : 0);
  return { outcome: 'committed', record: plan.record };
}

export function snapshotOf(doc: BondDoc, scope: BondReadScope): BondSnapshot {
  const bond = doc.bonds.get(scope.claimId);
  let count = 0;
  let sum = 0;
  const balances: Array<[string, number]> = [];
  if (scope.depositor !== undefined) {
    for (const b of doc.bonds.values()) {
      if (b.status === 'open' && b.depositor === scope.depositor) {
        count += 1;
        sum += b.amount;
      }
    }
    balances.push([scope.depositor, doc.balances.get(scope.depositor) ?? 0]);
  }
  return { ...(bond ? { bond: structuredClone(bond) } : {}), balances, openTotals: { count, sum }, highWater: doc.highWater };
}

// ---- the reference store: one document in any DurableKv -----------------------------------------------------------

const DOC_KEY = 'pca-bond-store/v1';
const PHASES = new Set(['open', 'released', 'slashed']);
const isObj = (x: unknown): x is Record<string, unknown> => !!x && !Array.isArray(x);

function decodeDoc(raw: unknown): BondDoc {
  if (raw === undefined) return emptyBondDoc();
  const bad = (why: string): never => {
    throw new BondStoreError('store_corrupt', why);
  };
  if (!isObj(raw) || raw.v !== 1 || !Array.isArray(raw.balances) || !Array.isArray(raw.bonds) || typeof raw.highWater !== 'number') return bad('bond document has the wrong shape');
  const doc = emptyBondDoc();
  if (!Number.isFinite(raw.highWater) || raw.highWater < 0) bad('highWater is not a non-negative number');
  doc.highWater = raw.highWater as number;
  for (const e of raw.balances) {
    if (!Array.isArray(e) || e.length !== 2 || typeof e[0] !== 'string' || !Number.isFinite(e[1]) || e[1] < 0) bad('malformed balance entry');
    doc.balances.set((e as [string, number])[0], (e as [string, number])[1]);
  }
  for (const b of raw.bonds) {
    if (!isObj(b) || typeof b.claimId !== 'string' || typeof b.depositor !== 'string' || !Number.isFinite(b.amount) || !PHASES.has(b.status as string) || !Array.isArray(b.records) || b.records.length === 0) {
      return bad('malformed bond row');
    }
    if (doc.bonds.has(b.claimId)) bad('duplicate bond row');
    doc.bonds.set(b.claimId, b as unknown as BondRow);
  }
  return doc;
}

const encodeDoc = (d: BondDoc): unknown => ({ v: 1, balances: [...d.balances], bonds: [...d.bonds.values()], highWater: d.highWater });

/**
 * The reference {@link BondStore}: the whole book is one document in a {@link DurableKv}, so every transition is a single
 * atomic read-modify-write. Over `openDurableState({ dir })` (`@atlasauth/pca/durable-state`) it is crash-safe,
 * hash-chained and multi-process safe on one host; over `createMemoryDurableKv()` it is the in-process variant (no
 * durability: for tests only).
 *
 * LIMIT: one document, rewritten on every commit and bounded by the kv's `maxValueBytes` (1 MiB by default, raise it in
 * `openDurableState`). That caps the book at some thousands of bonds; past `too-large` the kv refuses the write and the
 * operation fails closed. A production deployment implements {@link BondStore} over a database transaction instead.
 */
export class KvBondStore implements BondStore {
  constructor(
    private readonly kv: DurableKv,
    private readonly key: string = DOC_KEY,
  ) {
    if (!kv || typeof kv.get !== 'function' || typeof kv.update !== 'function') throw new BondStoreError('store_missing', 'KvBondStore needs a DurableKv');
  }

  async read(scope: BondReadScope): Promise<BondSnapshot> {
    return snapshotOf(decodeDoc(await this.kv.get(this.key)), scope);
  }

  async commit(plan: BondPlan, observedAt: number): Promise<BondCommitOutcome> {
    let out: BondCommitOutcome | undefined;
    await this.kv.update(this.key, (prev) => {
      const doc = decodeDoc(prev);
      out = commitBondPlan(doc, plan, observedAt);
      return out.outcome === 'committed' ? encodeDoc(doc) : undefined; // undefined: leave the key untouched
    });
    return out as BondCommitOutcome;
  }

  async deposit(account: string, amount: number): Promise<number> {
    if (typeof account !== 'string' || account.length === 0) throw new RangeError('deposit: account is required');
    if (!Number.isFinite(amount) || amount <= 0) throw new RangeError('deposit: amount must be a positive finite number');
    let balance = 0;
    await this.kv.update(this.key, (prev) => {
      const doc = decodeDoc(prev);
      balance = applyBondMoves((a) => doc.balances.get(a) ?? 0, [{ account, op: 'credit', amount }]).get(account) as number;
      doc.balances.set(account, balance);
      return encodeDoc(doc);
    });
    return balance;
  }
}

// ---- the ledger -----------------------------------------------------------------------------------------------------

export interface StoreBondLedgerOpts extends BondPlannerOpts {
  /** REQUIRED. There is deliberately no default store: a security state must be chosen, not defaulted to memory. */
  store: BondStore;
  /** Epoch-ms clock. Default `Date.now`. A non-finite reading fails the operation. */
  clock?: () => number;
  /** Window bounds applied to `openClaim` (default `DEFAULT_WINDOW_POLICY`); a window is never below the 30 s realistic floor. */
  windowPolicy?: ChallengeWindowPolicy;
}

/** Where a registered claim's challenge window stands. */
export interface ChallengeStatus {
  phase: 'open' | 'finalized';
  /** Last instant a challenge is accepted (`registeredAt + windowMs`, inclusive). */
  endsAt: number;
  now: number;
}

/**
 * Durable, restart-safe bond settlement over a {@link BondStore}. Every method is idempotent under retry: repeating a
 * transition that already committed returns the stored record and moves nothing, while a conflicting transition
 * (a release after a slash, a second slash with different evidence) throws. See the module comment for the
 * fail-closed table.
 */
export class StoreBondLedger {
  private readonly planner: BondSettlementPlanner;
  private readonly store: BondStore;
  private readonly clock: () => number;
  private readonly windowPolicy: ChallengeWindowPolicy;

  constructor(opts: StoreBondLedgerOpts) {
    if (!opts || !isBondStore(opts.store)) throw new BondStoreError('store_missing', 'a BondStore is required (there is no in-memory default)');
    if (!(opts.guardianSecret instanceof Uint8Array) || opts.guardianSecret.length === 0) throw new BondStoreError('guardian_key_missing', 'a guardian secret key is required');
    this.store = opts.store;
    this.planner = new BondSettlementPlanner(opts);
    this.clock = opts.clock ?? Date.now;
    this.windowPolicy = opts.windowPolicy ?? DEFAULT_WINDOW_POLICY;
  }

  /** The guardian/settlement public key (b64u) the records verify under. */
  get guardianPublicKey(): string {
    return this.planner.guardianPublicKey;
  }

  private async guard<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof BondStoreError) throw e;
      throw new BondStoreError('store_unavailable', e instanceof Error ? e.message : 'store failed', { cause: e });
    }
  }

  private async load(scope: BondReadScope): Promise<{ snap: BondSnapshot; view: BondView; now: number }> {
    const snap = await this.guard(() => this.store.read(scope));
    const t = this.clock();
    if (!Number.isFinite(t)) throw new BondStoreError('clock_invalid', 'the clock returned a non-finite time');
    const bonds = new Map(snap.bond ? [[snap.bond.claimId, snap.bond]] : []);
    const bal = new Map(snap.balances);
    const view: BondView = { bond: (id) => bonds.get(id), balanceOf: (a) => bal.get(a) ?? 0, openTotals: () => snap.openTotals };
    return { snap, view, now: Math.max(t, snap.highWater) };
  }

  private async submit(plan: BondPlan, now: number): Promise<SettlementRecord> {
    const out = await this.guard(() => this.store.commit(plan, now));
    if (out.outcome === 'conflict') throw new BondStoreError('conflict', out.reason);
    return out.record;
  }

  /** Settle: plan against the true view; if the bond is already settled, a retry that would have produced the same settlement returns the stored record. */
  private async settle(scope: BondReadScope, plan: (view: BondView, now: number) => BondPlan, gate?: (bond: BondRow, now: number) => void): Promise<SettlementRecord> {
    const { snap, view, now } = await this.load(scope);
    const bond = snap.bond;
    if (bond && bond.status !== 'open') {
      const last = bond.records[bond.records.length - 1];
      const asOpen: BondView = { ...view, bond: () => ({ ...bond, status: 'open' }) };
      const again = plan(asOpen, now); // throws if the evidence no longer holds
      if (last && sameSettlement(last, again.record)) return last;
      return plan(view, now).record; // throws the standard double-settle refusal
    }
    if (bond && gate) gate(bond, now);
    return this.submit(plan(view, now), now);
  }

  /** Top up an account of the internal books (a positive finite amount). */
  deposit(account: string, amount: number): Promise<number> {
    return this.guard(() => this.store.deposit(account, amount));
  }

  async balanceOf(account: string): Promise<number> {
    const snap = await this.guard(() => this.store.read({ claimId: '', depositor: account }));
    return snap.balances[0]?.[1] ?? 0;
  }

  async bondStatus(claimId: string): Promise<BondPhase> {
    return (await this.guard(() => this.store.read({ claimId }))).bond?.status ?? 'none';
  }

  async getBond(claimId: string): Promise<BondRow | undefined> {
    return (await this.guard(() => this.store.read({ claimId }))).bond;
  }

  /** Where the claim's challenge window stands on the ledger's clock; throws `unregistered` for a bond with no claim. */
  async challengeStatus(claimId: string): Promise<ChallengeStatus> {
    const { snap, now } = await this.load({ claimId });
    const w = snap.bond?.window;
    if (!w) throw new BondStoreError('unregistered', `bond ${claimId} has no registered claim`);
    const endsAt = w.registeredAt + w.windowMs;
    return { phase: now <= endsAt ? 'open' : 'finalized', endsAt, now };
  }

  /**
   * Register an optimistic claim and lock its bond in one atomic commit. The claim must pass `verifyClaim` against the
   * ledger's clock and its window must be at least the realistic floor; the window then runs from the ledger's own
   * `registeredAt`. Retrying the same call returns the original `open` record.
   */
  async openClaim(params: { claim: BondedClaim; pcactn: PCActn; signerPublic: string; amount: number; depositor: string; exposure?: number }): Promise<SettlementRecord> {
    const { claim } = params;
    const { snap, view, now } = await this.load({ claimId: String(claim?.bond_ref), depositor: params.depositor });
    const verdict = verifyClaim(claim, params.pcactn, params.signerPublic, { serverNow: now, windowPolicy: this.windowPolicy });
    if (!verdict.ok) throw new BondStoreError('invalid_claim', verdict.reason!);
    const floor = Math.max(this.windowPolicy.minWindowMs, DEFAULT_MIN_CHALLENGE_WINDOW_MS);
    if (claim.challenge_window_ms < floor) throw new BondStoreError('invalid_claim', `challenge window ${claim.challenge_window_ms} ms is below the ${floor} ms floor`);
    if (typeof claim.bond_ref !== 'string' || claim.bond_ref.length === 0) throw new BondStoreError('invalid_claim', 'claim has no bond_ref');
    const window: BondRegistration = { registeredAt: now, windowMs: claim.challenge_window_ms, claimDigest: hashCanonical(claim) };
    const prior = snap.bond;
    if (prior) return this.replayOpen(prior, params.depositor, params.amount, window);
    return this.submit(this.planner.planOpen(view, { claimId: claim.bond_ref, amount: params.amount, depositor: params.depositor, exposure: params.exposure, now, window }), now);
  }

  /** A retried open: the same terms return the original `open` record; anything else is the standard double-open refusal. */
  private replayOpen(prior: BondRow, depositor: string, amount: number, window?: BondRegistration): SettlementRecord {
    const same = prior.depositor === depositor && prior.amount === amount && prior.window?.claimDigest === window?.claimDigest;
    if (same && prior.records[0]) return prior.records[0];
    throw new BondStoreError('conflict', `openBond: bond ${prior.claimId} already exists (double-open refused)`);
  }

  /** Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with `slashCounterBond` or `releaseUnregistered`. */
  async openBond(params: { claimId: string; amount: number; depositor: string; exposure?: number }): Promise<SettlementRecord> {
    const { snap, view, now } = await this.load({ claimId: params.claimId, depositor: params.depositor });
    if (snap.bond) return this.replayOpen(snap.bond, params.depositor, params.amount);
    return this.submit(this.planner.planOpen(view, { ...params, now }), now);
  }

  /** Release a registered claim's bond once its challenge window has closed on the ledger's clock. */
  release(claimId: string): Promise<SettlementRecord> {
    return this.settle({ claimId }, (view, now) => this.planner.planRelease(view, { claimId, now }), (bond, now) => {
      if (!bond.window) throw new BondStoreError('unregistered', `bond ${claimId} has no registered claim; use releaseUnregistered for a counter-bond`);
      if (now <= bond.window.registeredAt + bond.window.windowMs) throw new BondStoreError('window_open', `the challenge window of ${claimId} closes at ${bond.window.registeredAt + bond.window.windowMs}`);
    });
  }

  /** Release a bond that backs no claim (a counter-bond). */
  releaseUnregistered(claimId: string): Promise<SettlementRecord> {
    return this.settle({ claimId }, (view, now) => this.planner.planRelease(view, { claimId, now }), (bond) => {
      if (bond.window) throw new BondStoreError('conflict', `bond ${claimId} backs a registered claim; use release`);
    });
  }

  private challengeGate(claim: BondedClaim) {
    return (bond: BondRow, now: number): void => {
      const w = bond.window;
      if (!w) throw new BondStoreError('unregistered', `bond ${bond.claimId} has no registered claim`);
      if (w.claimDigest !== hashCanonical(claim)) throw new BondStoreError('claim_mismatch', `the claim is not the one registered for ${bond.claimId}`);
      if (now > w.registeredAt + w.windowMs) throw new BondStoreError('window_closed', `the challenge window of ${bond.claimId} closed at ${w.registeredAt + w.windowMs}`);
    };
  }

  /** Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. */
  slashBond(params: SlashBondParams): Promise<SettlementRecord> {
    return this.settle({ claimId: params.claimId }, (view, now) => this.planner.planSlash(view, { ...params, now }), this.challengeGate(params.claim));
  }

  /** Slash on a dispute the ledger re-adjudicates itself, inside the challenge window. */
  slashBondOnDispute(params: SlashOnDisputeParams): Promise<SettlementRecord> {
    return this.settle({ claimId: params.claimId }, (view, now) => this.planner.planSlashOnDispute(view, { ...params, now }), this.challengeGate(params.claim));
  }

  /** Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated). */
  slashBondOnRevocation(params: SlashOnRevocationParams): Promise<SettlementRecord> {
    return this.settle({ claimId: params.claimId }, (view, now) => this.planner.planSlashOnRevocation(view, { ...params, now }), (bond) => {
      if (bond.window && bond.window.claimDigest !== hashCanonical(params.claim)) throw new BondStoreError('claim_mismatch', `the claim is not the one registered for ${bond.claimId}`);
    });
  }

  /** Slash a challenger's counter-bond after a frivolous dispute. */
  slashCounterBond(params: SlashCounterBondParams): Promise<SettlementRecord> {
    return this.settle({ claimId: params.counterBondId }, (view, now) => this.planner.planSlashCounterBond(view, { ...params, now }));
  }
}
