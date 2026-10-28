import { snapshotConfig } from '../config-snapshot';
import { createAttestationVerifier, type AttestationVerifierOpts } from '../attestation';
import { type LivenessBeacon } from '../beacons';
import { type Capability } from '../capability';
import { decodePcaHeader } from '../adapters';
import { decodePCActn, type EnforcementGates, type PCActn, type VerifyHooks } from '../pcactn';
import type { IntentV2Context } from '../intent-v2';
import type { FreshAtPolicy } from '../fresh-at';
import type { SigAlg } from '../pq';
import {
  effectiveReversibility,
  revocationMaxAgeMs,
  validateRevocationStaleness,
  type RevocationEpoch,
  type RevocationStalenessPolicy,
} from '../revocation';
import { strictParse } from '../strict-json';
import { type AssuranceRequirement, refreshAssurance } from '../assurance';
import { hashCanonical } from '../hash';
import { decisionOf, type Decision } from '../decision';
import { buildEscalationRequest, escalationActionDigest, escalationHistoryHead, escalationPolicyDigest, verifyEscalationAnswer, type EscalationRequest } from '../escalation';
import type { PinnedSigner } from '../intent-artifacts';
import { reserveMaxUses, type K1Input } from '../caveat-lang';
import type { ReplayStore } from '../replay';
import { readEnvelope } from '../envelope';
import { decideArgProvenance, provEnvelopeError, type ProvActionInfo, type ProvEnvelope, type ProvMediatorPin, type ProvObservation } from '../arg-provenance';
import { type RiskInputs, type TrustBudget } from '../risk';
import {
  STATEFUL_REQUIRED_CHECKS,
  enforceRequired,
  verifyPCActn,
  type PcaContext,
  type PcaOperation,
  type PcaPrincipalInfo,
  type PcaVerdict,
} from './verify';

/** Framework-agnostic request shape: anything with headers and (optionally) a parsed/raw body. */
export interface PcaRequestLike {
  headers: Record<string, string | string[] | undefined> | { get(name: string): string | null };
  body?: unknown;
  /** HTTP method, when the adapter knows it (for an `operation` mapping). */
  method?: string;
  /** Request URL or path, when the adapter knows it (for an `operation` mapping). */
  url?: string;
}

/** Per-holder replay + budget state. Implement over Redis/DB; the in-memory one is for tests/single node. */
export interface PcaHolderState {
  budget?: TrustBudget;
  lastCounter?: number;
  /** newest signed revocation epoch accepted for the grant (monotonic pin). */
  lastEpoch?: number;
  /** newest liveness-beacon seq accepted for the grant (monotonic pin). */
  lastBeaconSeq?: number;
}

export interface PcaStateStore {
  get(key: string): Promise<PcaHolderState | undefined>;
  put(key: string, state: PcaHolderState): Promise<void>;
  /**
   * OPTIONAL mutual exclusion across EVERY node that shares this store (a Redis lock, a Postgres advisory lock, a
   * row lock inside a transaction). `requirePCA` reads the replay counter + budget, verifies, and writes them back:
   * a read-modify-write that two concurrent requests can interleave, accepting the same counter twice or spending
   * the same budget twice. It therefore runs that whole section inside `withKeyLock(grantId, ...)`. The lock MUST be
   * exclusive per `key` across all nodes, MUST release when `fn` settles (resolve or reject), and MUST reject (never
   * run `fn`) if it cannot be acquired: the guard then fails closed. When absent, an in-process per-key lock is
   * used, which is correct for ONE process only; a multi-node deployment MUST supply this method.
   *
   * THE LOCK MUST NOT EXPIRE UNDER ITS HOLDER. A row lock, a Postgres advisory lock or a DB-session mutex is held until
   * the holder finishes or dies, so it qualifies. A time-leased lock (Redis `SET lock NX PX ttl`) does NOT, unless the
   * `put` is also a compare-and-set on the version `get` returned (a fencing token): if the lease runs out while the
   * holder is paused, a second node enters, and the first node's later `put` silently accepts the same counter twice.
   * Model-checked in formal/tla/RequirePcaLock.tla (rp_exclusive_lock / rp_lease_fenced hold; rp_bad_lease_unfenced and
   * rp_bad_nolock_multinode produce the double-accept counterexamples).
   */
  withKeyLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
  /** `'process'`: the state lives in this process only (refused when `requirePCA` runs with `multiInstance: true`). */
  readonly scope?: 'process' | 'shared';
}

/** What one atomic claim asks the store to do (see {@link AtomicPcaStateStore.claim}). */
export interface PcaStateClaim {
  /** The PCActn's counter: must be strictly greater than the stored `lastCounter` (or none stored). */
  counter: number;
  /** The budget this decision was computed from (what `get` returned): the stored budget must still equal it. */
  budgetBefore?: TrustBudget;
  /** The budget to store on success (absent: keep the stored one). */
  budgetAfter?: TrustBudget;
}

export type PcaClaimResult =
  | { ok: true }
  /**
   * `replay`: the stored counter is >= `counter` (this action, or a later one, was already admitted). `conflict`: the
   * counter is fresh but the stored budget changed since it was read (another action of the same holder won the race);
   * `requirePCA` re-reads and re-verifies, then claims again.
   */
  | { ok: false; reason: 'replay' | 'conflict'; lastCounter?: number };

/**
 * A `PcaStateStore` that can CLAIM an action in one atomic compare-and-set instead of `get` -> verify -> `put` under a lock
 * (0.5, additive). When the `budgetStore` passed to `requirePCA` has `claim`, the guard uses it and needs no lock, so it is
 * correct across any number of processes and nodes that share the backend: of N concurrent presentations of one PCActn,
 * at most one claim succeeds. Implement it as ONE atomic operation of your backend (a conditional
 * `UPDATE ... WHERE last_counter < $counter AND budget IS NOT DISTINCT FROM $before RETURNING`, a unique-constraint
 * insert, a Redis Lua script, `DurableKv.update`). A claim that cannot decide MUST reject (the guard then denies).
 * The replay-state invariant this enforces is written in the anti-replay reference ("Replay-state invariant").
 */
export interface AtomicPcaStateStore extends PcaStateStore {
  /**
   * Atomically: if `lastCounter` is stored and `!(c.counter > lastCounter)` -> `{ ok: false, reason: 'replay' }`; else if
   * the stored budget differs from `c.budgetBefore` (both absent counts as equal) -> `{ ok: false, reason: 'conflict' }`;
   * else store `{ lastCounter: c.counter, budget: c.budgetAfter ?? stored budget }` and return `{ ok: true }`.
   */
  claim(key: string, c: PcaStateClaim): Promise<PcaClaimResult>;
  /** Atomically raise a monotone pin (`lastEpoch` / `lastBeaconSeq`) to `value` when it is higher. Never lowers it. */
  raisePin(key: string, pin: 'lastEpoch' | 'lastBeaconSeq', value: number): Promise<void>;
}

/** How a `requirePCA` guard serialises its replay / budget state (exposed as `guard.stateMode`). */
export type PcaStateMode =
  /** `budgetStore.claim`: one atomic compare-and-set per action; correct across processes and nodes sharing the store. */
  | 'atomic-claim'
  /** `budgetStore.withKeyLock`: get -> verify -> put under YOUR cross-node lock. */
  | 'shared-lock'
  /** Neither: get -> verify -> put under an in-process lock. Correct for ONE process only (refused with `multiInstance`). */
  | 'process-lock'
  /** No `budgetStore`: replay is not checked (the default `replay` requirement then denies). */
  | 'none';

export const isAtomicPcaStateStore = (s: PcaStateStore | undefined): s is AtomicPcaStateStore =>
  !!s && typeof (s as Partial<AtomicPcaStateStore>).claim === 'function' && typeof (s as Partial<AtomicPcaStateStore>).raisePin === 'function';

const sameBudget = (a: TrustBudget | undefined, b: TrustBudget | undefined): boolean =>
  a === undefined || b === undefined ? a === b : a.B === b.B && a.tau === b.tau && a.asOf === b.asOf;

function claimOn(cur: PcaHolderState | undefined, c: PcaStateClaim): { result: PcaClaimResult; next?: PcaHolderState } {
  if (cur?.lastCounter !== undefined && !(c.counter > cur.lastCounter)) return { result: { ok: false, reason: 'replay', lastCounter: cur.lastCounter } };
  if (!sameBudget(cur?.budget, c.budgetBefore)) return { result: { ok: false, reason: 'conflict' } };
  const budget = c.budgetAfter ?? cur?.budget;
  return { result: { ok: true }, next: { ...cur, ...(budget !== undefined ? { budget } : {}), lastCounter: c.counter } };
}

function raiseOn(cur: PcaHolderState | undefined, pin: 'lastEpoch' | 'lastBeaconSeq', value: number): PcaHolderState | undefined {
  const prev = cur?.[pin];
  return prev !== undefined && prev >= value ? undefined : { ...cur, [pin]: value };
}

/**
 * In-memory {@link AtomicPcaStateStore}: the reference for ONE process (tests, a single node). Its state dies with the
 * process, so it declares `scope: 'process'` and `requirePCA({ multiInstance: true })` refuses it.
 */
export function atomicMemoryPcaStore(): AtomicPcaStateStore {
  const m = new Map<string, PcaHolderState>();
  return {
    scope: 'process',
    get: async (k) => m.get(k),
    put: async (k, v) => void m.set(k, v),
    async claim(k, c) {
      // no await between the read and the write: one turn of the event loop is atomic in a single process
      const { result, next } = claimOn(m.get(k), c);
      if (next) m.set(k, next);
      return result;
    },
    async raisePin(k, pin, value) {
      const next = raiseOn(m.get(k), pin, value);
      if (next) m.set(k, next);
    },
  };
}

/** The atomic read-modify-write a {@link durablePcaStateStore} needs (`DurableKv.update` from `@atlasauth/pca/durable-state`). */
export interface AtomicKv {
  get(key: string): Promise<unknown | undefined>;
  set(key: string, value: unknown): Promise<void>;
  /** Atomic across every client of the backend: `fn` gets the current value and returns the next one, or undefined to keep it. */
  update(key: string, fn: (prev: unknown | undefined) => unknown | undefined): Promise<unknown | undefined>;
}

/**
 * {@link AtomicPcaStateStore} over any atomic key/value store with `update` (e.g. `openDurableState({ dir })` from
 * `@atlasauth/pca/durable-state`: crash-safe and multi-process-safe on one host, so `scope: 'shared'`). `prefix` namespaces the keys.
 */
export function durablePcaStateStore(kv: AtomicKv, opts: { prefix?: string; scope?: 'process' | 'shared' } = {}): AtomicPcaStateStore {
  const pre = opts.prefix ?? 'pca-state:';
  const read = (v: unknown): PcaHolderState | undefined => (v !== null && typeof v === 'object' ? (v as PcaHolderState) : undefined);
  return {
    scope: opts.scope ?? 'shared',
    get: async (k) => read(await kv.get(pre + k)),
    put: (k, v) => kv.set(pre + k, v),
    async claim(k, c) {
      let result: PcaClaimResult = { ok: false, reason: 'conflict' };
      await kv.update(pre + k, (prev) => {
        const r = claimOn(read(prev), c);
        result = r.result;
        return r.next;
      });
      return result;
    },
    async raisePin(k, pin, value) {
      await kv.update(pre + k, (prev) => raiseOn(read(prev), pin, value));
    },
  };
}

const localLocks = new Map<string, Promise<unknown>>();

/** In-process FIFO mutex per key (single-node correctness for the get -> verify -> put section). */
function withLocalLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = localLocks.get(key) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.then(
    () => undefined,
    () => undefined,
  );
  localLocks.set(key, tail);
  void tail.then(() => {
    if (localLocks.get(key) === tail) localLocks.delete(key);
  });
  return run;
}

export function memoryPcaStore(): PcaStateStore {
  const m = new Map<string, PcaHolderState>();
  return { get: async (k) => m.get(k), put: async (k, v) => void m.set(k, v), scope: 'process' };
}

export interface RequirePcaOptions {
  /**
   * REQUIRED: this resource server's audience id. A PCActn whose signed `aud` differs is denied (audit P0-5:
   * no cross-server replay). Omit only with `insecureAllowUnenforced`.
   */
  audience?: string;
  /** Resolve the Root Intent Grant from the PCActn's `grant_ref`. null = unknown grant. */
  resolveGrant: (grantRef: string, pcactn: PCActn) => Promise<Capability | null>;
  hooks?: VerifyHooks;
  /**
   * Attestation enforcement for this resource server. Builds the `attestation` hook with the SAME binding the
   * Atlas server enforces: supply `expectedBinding(ctx)` (leaf holder + grant + epoch + the server-issued nonce
   * and its issue time, e.g. from `GET /v1/pca/attest-challenge`) and `resolveDocument`. A grant whose
   * `agent_binding` is non-empty DENIES without a bound attestation (require-when-bound), regardless of this
   * option being set. An explicit `hooks.attestation` wins.
   */
  attestation?: AttestationVerifierOpts;
  extract?: (req: PcaRequestLike) => PCActn | string | null;
  /** Anti-replay counter + budget persistence. Without it counters are not checked (surfaced in checks). */
  budgetStore?: PcaStateStore;
  /** Build verification context (params, plan, risk) per request. */
  context?: (req: PcaRequestLike, pcactn: PCActn) => PcaContext | Promise<PcaContext>;
  now?: () => number;
  /** WWW-Authenticate realm (default "pca"). */
  realm?: string;
  /**
   * Minimum enforcement rungs: every named check must be 'pass'; a required check that is 'not-enforced'
   * DENIES (default-deny). Default: `['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound']`, i.e. you must supply
   * a `budgetStore` (replay counter), a `hooks.revocation` checker, and a `context()` that returns the
   * RS's own `plan` + `planAuthorized: true`.
   */
  require?: string[];
  /**
   * EXPLICIT, LOUDLY-NAMED opt-out of the default-deny profile: required-but-unenforced checks are allowed
   * (the pre-hardening behaviour). Only for local development / migration; never in production.
   */
  insecureAllowUnenforced?: boolean;
  /**
   * Supply the guardian-signed revocation epoch for a grant (e.g. fetched from `GET /v1/pca/revocations/epoch`)
   * plus the pinned guardian public key. When given, the `freshness` check is REQUIRED (default-deny): the
   * epoch must verify, be unexpired, not roll back past the last one accepted, and the PCActn's signed
   * `freshness.epoch` must be at least as new. Needs a `budgetStore` to pin the last accepted epoch.
   */
  revocationEpoch?: (
    grantRef: string,
    pcactn: PCActn,
  ) => Promise<{ epoch: RevocationEpoch; guardianPublic: string } | null | undefined>;
  /**
   * Supply the current liveness beacon for a grant (e.g. from `GET /v1/pca/beacons`) plus the pinned issuer key(s)
   * (the grant principal and/or operator) and your instance id. When given, the `beacon` check is REQUIRED
   * (default-deny): a stale / absent / replayed / unbound beacon DENIES, so a principal who stops issuing halts
   * the agent. The PCActn must commit it via `freshness.beacon_ref = beaconRef(beacon)`. Needs a `budgetStore`
   * to pin the last accepted seq.
   */
  beacon?: (
    grantRef: string,
    pcactn: PCActn,
  ) => Promise<{ beacon: LivenessBeacon; issuers: string[]; instance: string; pqPins?: Readonly<Record<string, string>> } | null | undefined>;
  /**
   * Suite policy, forwarded to `verifyPCActn` (F-4): the only signature suites accepted for the PCActn leaf and every
   * delegation hop. Fail closed: an artifact using any other suite fails `cap_chain` / `leaf_signature` (401).
   */
  allowedSuites?: readonly SigAlg[];
  /** Server-side PQ pins `issuer -> pq_pk`, forwarded to `verifyPCActn` (`pq_pin` check, fail closed for non-Ed25519 grants). */
  pqPins?: Readonly<Record<string, string>>;
  /** Resolve the grant's issuer to an enrolled principal. Its result is returned on `verdict.principal`. */
  resolvePrincipal?: (principalPub: string, grant: Capability) => Promise<PcaPrincipalInfo | null | undefined>;
  /** Deny unless `resolvePrincipal` yields a `verified` principal (identity enforcement at the resource server). */
  requireVerifiedPrincipal?: boolean;
  /**
   * Declare that more than one process or node runs this guard against the same `budgetStore` (0.5). The guard then
   * REFUSES (throws at construction) a store that can only be serialised by the in-process lock: one with neither
   * `claim` (an {@link AtomicPcaStateStore}) nor `withKeyLock`, or one that declares `scope: 'process'`
   * (`memoryPcaStore`, `atomicMemoryPcaStore`). Default (0.5): true, unless the store declares `scope: 'process'`; so a
   * plain get/put store with neither `claim` nor `withKeyLock` is refused instead of silently serialised in-process. Pass
   * `false` to run a plain get/put store in ONE process on purpose. The mode in use is visible as `guard.stateMode`.
   */
  multiInstance?: boolean;
  /**
   * Replay-state scope (0.5). `'audience-grant-holder'` (default when the guard has an `audience`): the key carries this
   * guard's `audience`, so resource servers that share one store keep separate counter streams (the draft's
   * (aud, grant, holder) scope). `'grant-holder'`: one counter stream per (grant, leaf holder), the 0.4 key.
   * Upgrading a live store is automatic: when the audience-scoped key has no state yet, the guard starts from the 0.4
   * key's `lastCounter` and budget (it never writes the old key again), so a PCActn already spent is still refused.
   */
  replayScope?: 'grant-holder' | 'audience-grant-holder';
  /**
   * Bounded re-verification when an atomic `claim` reports a budget `conflict` (another action of the same holder won the
   * race between read and claim). Default 3; after that the request is denied (fail closed).
   */
  claimRetries?: number;
  /**
   * Verifier-side revocation staleness (0.5, additive; off unless set). With a signed `revocationEpoch` the epoch's age
   * (`now - issued_at`) is capped by class (irreversible default 2 min). Without verifiable signed revocation state (no
   * `revocationEpoch` option, or it returned nothing), an IRREVERSIBLE action is denied unless
   * `allowUnsignedRootForIrreversible`. The class is the stricter of `context().reversibilityClass` and the PCActn's
   * signed class; missing or unknown counts as irreversible.
   */
  revocationStaleness?: RevocationStalenessPolicy;
  /**
   * The operation this request WILL EXECUTE, from the server's own routing (route verb / resource, the parsed body as
   * params), never from the PCActn. When set, the proof must be for exactly this verb, resource and params (`operation`
   * check, see `verifyPCActn`), its params are what the predicates and caveats read, `operation` and `params_digest`
   * join the required checks, and the success result carries the bound `operation`. A mapping that returns null or
   * throws denies. REQUIRED since 0.5: a guard built without it throws, unless `insecureAllowUnboundOperation` or
   * `insecureAllowUnenforced` is set. For the strict pipeline (missing store / revocation denies) use `authorize`.
   */
  operation?: (req: PcaRequestLike) => PcaOperation | null | undefined | Promise<PcaOperation | null | undefined>;
  /**
   * EXPLICIT, LOUDLY-NAMED opt-out of operation binding (0.5): the guard then verifies the proof but not that it is for
   * the operation the handler runs (a valid proof for one tool is accepted for another the grant also permits, and the
   * grant's limits are not checked against the real params). For migration only; never in production.
   */
  insecureAllowUnboundOperation?: boolean;
  /**
   * Intent Layer v2 context (session root, signed action schema, provenance policy, label receipts, accumulators),
   * forwarded to `verifyPCActn` so per-parameter provenance runs inside this guard. A function is called per request
   * (receipts and accumulator state are per request). Absent: unchanged.
   */
  intentV2?: IntentV2Context | ((req: PcaRequestLike, pcactn: PCActn) => IntentV2Context | undefined | Promise<IntentV2Context | undefined>);
  /**
   * Consistency-token policy (see fresh-at.ts), forwarded to `verifyPCActn`. A function is called per request (the verifier's
   * state counters move). A token in the `pca-fresh-at` request header (the pre-member, side-carried form) is read when the PCActn
   * has no `fresh_at` member; that form is removed after 0.5.
   */
  freshAt?: FreshAtPolicy | ((req: PcaRequestLike, pcactn: PCActn) => FreshAtPolicy | undefined | Promise<FreshAtPolicy | undefined>);
  /** Opt-in core gates (taint / freshness / attestation), forwarded to `verifyPCActn`. Each gate that is set fails closed. */
  enforce?: EnforcementGates;
  /** Risk inputs the server must supply (see `verifyPCActn`); a missing one denies with its name (`risk_inputs`). */
  requireRiskInputs?: readonly (keyof RiskInputs)[];
  /**
   * Server-derived risk inputs for the operation (e.g. `catalogRisk`). Combined with `context().risk` input by input,
   * keeping the riskier value of the two, so neither source can lower the other.
   */
  risk?: (operation: PcaOperation | undefined, grant: Capability, pcactn: PCActn) => Partial<RiskInputs> | undefined | Promise<Partial<RiskInputs> | undefined>;
  /**
   * Starting trust budget for a holder with no stored budget (e.g. the grant's signed `bMax`). Used only when the store
   * has none and `context()` supplies none; persisted after the first allowed call like any budget.
   */
  seedBudget?: (grant: Capability, now: number) => TrustBudget | undefined;
  /** Attach the per-check assurance report to the verdict (`verdict.assurance`, see `assurance.ts`). Absent: unchanged. */
  assurance?: boolean;
  /**
   * High-assurance policy, forwarded to `verifyPCActn` (0.5, additive): e.g. `{ attestation: 'hardware', zk: 'snark' }`.
   * Weaker, missing, failed, unlabelled, preview or unsupported evidence fails the `assurance` check and denies, before
   * any replay or budget state is written.
   */
  requireAssurance?: AssuranceRequirement;
  /**
   * Escalation (0.5, additive; off unless set). A verdict whose every failing check is escalate-class (an unanswered
   * `intent_required` question, a `tighten[]` rule that asks for a human) is an `escalate` decision: refused (403, and the
   * result carries `escalation`, the request to put to the principal), never admitted by itself. With `escalation` set the guard
   * admits it only when the request carries an `EscalationAnswer` (header `PCA-Escalation-Answer`, body `escalation_answer`, or
   * `answer(req)`) that is signed by one of the pinned `principals`, says `allow`, is unexpired, and is bound to THIS grant, THIS
   * PCActn and THIS state of the holder's history. The answer is spent by the replay counter that admits the action. An answer
   * never upgrades a `deny`.
   */
  escalation?: {
    /** The principals whose answers count: b64u Ed25519 keys, or `{pk, pq_pk}` pins for a post-quantum / hybrid suite. */
    principals: readonly (string | PinnedSigner)[];
    /** Read the answer from the request (default: header `PCA-Escalation-Answer`, base64url JSON; else body `escalation_answer`). */
    answer?: (req: PcaRequestLike, pcactn: PCActn) => unknown | Promise<unknown>;
    /** How long the issued `EscalationRequest` is valid (default one hour). */
    requestTtlMs?: number;
    /**
     * K7, what you see is what you sign: recompute H(R), the digest of the canonical approval render, from the EXECUTED parameters
     * and the verifier's own definition (`@atlasauth/pca-actions` `renderDigestForAction`). The request carries it and the answer
     * must be signed over exactly it. Returning `undefined` means no render could be derived.
     */
    render?: (req: PcaRequestLike, pcactn: PCActn) => string | undefined | Promise<string | undefined>;
    /**
     * DOCUMENTED INSECURE opt-out. By default (K7) an answer is admitted only when the verifier recomputed the approval render
     * (`render`) and the answer is signed over exactly that digest: what the principal saw is what was signed. Set this to
     * accept answers without a recomputed render (the pre-0.5 behaviour: an answer then binds the action digest only, and
     * whatever the approver client drew is not committed). An answer that carries a render is still refused when none was recomputed.
     */
    insecureUnboundApproval?: boolean;
  };
  /**
   * Caveat language v2 (K1; off unless the chain carries a K1 caveat). The verifier's own inputs: the discharge-issuer `pins`,
   * `revoked_discharges`, the verified `spiffe_id` of the presenting workload and the holder's `history`. Discharges and a
   * narrow block are read from the request (headers `PCA-Discharges`, a base64url JSON array, and `PCA-Narrow`, base64url
   * JSON; see {@link presentedK1}) unless the function form supplies them. They are verified against the pins and are
   * never trusted for who signed them.
   */
  k1?: K1Input | ((req: PcaRequestLike, pcactn: PCActn) => K1Input | Promise<K1Input>);
  /**
   * Provenance gate (see `arg-provenance.ts`; spec provenance-by-default). `authorize()` always sets it (the default); on a bare
   * `requirePCA` it is off unless set. A SENSITIVE action (anything not defined as read-only) whose choice or any sink argument does
   * not derive from the principal is refused as `escalate` (check `provenance_flow`, reason `provenance_flow: escalate: ...`); only a principal-signed escalation answer
   * admits it. A forged or malformed provenance bundle is `deny`. The bundle is read from `bundle(req)` (default header
   * `PCA-Provenance`, base64url JSON, else body `pca_provenance`).
   */
  provenance?: ProvenanceGuardOptions;
  /**
   * Where `max_uses` caveats are spent: the same atomic, durable first-use store as `replayGuard` (a shared database store
   * makes the count hold across processes). A chain with a `max_uses` caveat and no store is refused (fail closed).
   */
  usesStore?: ReplayStore;
}

/** The operation a successful decision is bound to (present when the guard has an `operation` mapping). */
export interface AuthorizedOperation {
  verb: string;
  resource: string;
  /** The signed `action.params_digest`, equal to the digest of the executed params. */
  params_digest: string;
  /** Digest of the presented PCActn: one id per authorization (counter and signature included). */
  id: string;
}

/**
 * The result of a guard. `ok` is true only for an admitted action. `decision` (0.5) names the ternary outcome: `allow` (ok),
 * `escalate` (refused, ask the principal: `escalation` is the request to put to them) or `deny`. A result without `decision`
 * is a refusal before any verdict (no PCActn, unknown grant): read it with {@link decisionOfResult}. `escalate` is NEVER `ok`.
 */
export type PcaGuardResult =
  | { ok: true; verdict: PcaVerdict; pcactn: PCActn; operation?: AuthorizedOperation; decision?: 'allow'; escalation?: { answered_by: string } }
  | { ok: false; status: 401 | 403; verdict: PcaVerdict; wwwAuthenticate?: string; decision?: 'deny' | 'escalate'; escalation?: EscalationRequest };

/** The ternary decision of a guard result (a refusal without `decision` is `deny`). */
export function decisionOfResult(r: { ok: boolean; decision?: Decision }): Decision {
  return r.ok === true ? 'allow' : r.decision === 'escalate' ? 'escalate' : 'deny';
}

function header(req: PcaRequestLike, name: string): string | undefined {
  const h = req.headers as { get?: (n: string) => string | null } & Record<string, string | string[] | undefined>;
  if (typeof h.get === 'function') return h.get(name) ?? undefined;
  // Plain object: HTTP field names are case-insensitive (RFC 9110 §5.1). Match own keys only (never the prototype). If the
  // object carries several case-variants of the name with DIFFERENT values the credential is ambiguous -> treat as absent
  // (the caller then denies), never silently pick one.
  const want = name.toLowerCase();
  let found: string | undefined;
  for (const k of Object.keys(h)) {
    if (k.toLowerCase() !== want) continue;
    const raw = (h as Record<string, string | string[] | undefined>)[k];
    const v = Array.isArray(raw) ? raw[0] : raw;
    if (typeof v !== 'string') continue;
    if (found !== undefined && found !== v) return undefined;
    found = v;
  }
  return found;
}


/**
 * Default extraction: `PCA-Action: <base64url PCActn JSON>` header, else JSON body `{ pcactn }`.
 * R6-ALIAS-05: a STRING body is parsed with the strict JSON profile (strictParse), like the header path: native JSON.parse
 * collapsed `1.0` / `1e0` / `10e-1` to 1 and duplicate keys last-wins before verification, so byte-distinct bodies verified
 * as the same signed PCActn. A body that is not strict-profile JSON yields null (deny). An already-parsed object body (e.g.
 * from a framework body parser) has lost its spelling; send the PCActn as a string (header, or `{"pcactn":"<json>"}`) or
 * give requirePCA the raw body text for strict handling.
 */
export function defaultExtract(req: PcaRequestLike): PCActn | string | null {
  const h = header(req, 'pca-action');
  // 0.4.1: strict unpadded base64url (decodePcaHeader). Padding, the standard alphabet, whitespace or invalid characters
  // used to be accepted (Buffer's lenient decoder); now they throw, which requirePCA turns into a 401.
  if (h !== undefined && h !== '') return decodePcaHeader(h);
  let b = req.body;
  if (typeof b === 'string') {
    try {
      b = strictParse(b);
    } catch {
      return null;
    }
  }
  const x = (b as { pcactn?: unknown } | null | undefined)?.pcactn;
  if (typeof x === 'string' || (x !== null && typeof x === 'object')) return x as PCActn | string;
  return null;
}

/** Discharges and a narrow block as presented with a request: headers `PCA-Discharges` (base64url JSON array) and `PCA-Narrow` (base64url JSON). Malformed text throws (the guard turns it into no K1 input, which fails closed). */
export function presentedK1(req: PcaRequestLike): Pick<K1Input, 'discharges' | 'narrow'> {
  const out: { discharges?: unknown[]; narrow?: unknown } = {};
  const d = header(req, 'pca-discharges');
  if (d !== undefined && d !== '') {
    const arr = strictParse(decodePcaHeader(d));
    if (!Array.isArray(arr)) throw new Error('PCA-Discharges must be a JSON array');
    out.discharges = arr;
  }
  const n = header(req, 'pca-narrow');
  if (n !== undefined && n !== '') out.narrow = strictParse(decodePcaHeader(n));
  return out;
}

/** Default escalation-answer extraction: header `PCA-Escalation-Answer` (strict base64url JSON), else body `escalation_answer`. */
export function defaultEscalationAnswer(req: PcaRequestLike): unknown {
  const h = header(req, 'pca-escalation-answer');
  if (h !== undefined && h !== '') return strictParse(decodePcaHeader(h));
  let b = req.body;
  if (typeof b === 'string') {
    try {
      b = strictParse(b);
    } catch {
      return undefined;
    }
  }
  return (b as { escalation_answer?: unknown } | null | undefined)?.escalation_answer;
}

/** Default provenance-bundle extraction: header `PCA-Provenance` (strict base64url JSON), else body `pca_provenance`. Malformed text throws. */
export function defaultProvenanceBundle(req: PcaRequestLike): unknown {
  const h = header(req, 'pca-provenance');
  if (h !== undefined && h !== '') return strictParse(decodePcaHeader(h));
  let b = req.body;
  if (typeof b === 'string') {
    try {
      b = strictParse(b);
    } catch {
      return undefined;
    }
  }
  return (b as { pca_provenance?: unknown } | null | undefined)?.pca_provenance;
}

/** Options of the provenance gate (see {@link RequirePcaOptions.provenance}). */
export interface ProvenanceGuardOptions {
  /** Pinned mediator keys (the agent harness, gateway or MCP client that labels context segments). The grant envelope may add more. */
  mediators?: readonly ProvMediatorPin[];
  /**
   * The facts of the action about to run, from YOUR action definitions (`@atlasauth/pca-actions` `provenanceActions`). Undefined for
   * an operation = unknown action: every argument is a sink and the choice must derive from the principal.
   */
  actions?: (operation: PcaOperation) => ProvActionInfo | undefined | Promise<ProvActionInfo | undefined>;
  /** Read the bundle from the request (default {@link defaultProvenanceBundle}). `operation` is the operation this request binds. */
  bundle?: (req: PcaRequestLike, pcactn: PCActn, operation: PcaOperation) => unknown;
  /** Untrusted content THIS server saw reach the agent's context in this session (raise only), e.g. the gateway's own log. */
  observed?: (pcactn: PCActn, operation: PcaOperation, session: string | undefined) => readonly ProvObservation[] | Promise<readonly ProvObservation[]>;
  /** Principal commitments the host established for this request (an executable principal-authorized plan; an admitted workflow step). */
  principal?: (req: PcaRequestLike, pcactn: PCActn) => { plan?: boolean; control?: boolean } | undefined;
}

/** The bundle's session id when it names one (for `observed`). */
const bundleSession = (b: unknown): string | undefined => {
  const r = (b as { receipts?: Array<{ session?: unknown }> } | null | undefined)?.receipts?.[0]?.session;
  return typeof r === 'string' ? r : undefined;
};

/**
 * Run the provenance gate for one admitted-so-far request. Returns the check status and, on a refusal, the reason (the escalate
 * reasons carry the `escalate:` prefix so the ternary decision reads them as escalate-class).
 */
async function provenanceCheck(o: ProvenanceGuardOptions, req: PcaRequestLike, p: PCActn, grant: Capability, operation: PcaOperation | undefined): Promise<{ status: 'pass' | 'fail' | 'not-enforced'; reason?: string }> {
  const env = readEnvelope(grant);
  const pe = env?.provenance;
  if (pe !== undefined) {
    const e = provEnvelopeError(pe);
    if (e) return { status: 'fail', reason: `the grant's provenance member is malformed: ${e}` };
  }
  const penv = pe as ProvEnvelope | undefined;
  // the principal's signed, documented-dangerous opt-out
  if (penv?.mode === 'insecure_off') return { status: 'not-enforced' };
  if (!operation || typeof operation.verb !== 'string' || typeof operation.resource !== 'string') return { status: 'fail', reason: 'no operation is bound to this request (fail closed)' };
  let bundle: unknown;
  try {
    bundle = o.bundle ? await o.bundle(req, p, operation) : defaultProvenanceBundle(req);
  } catch {
    return { status: 'fail', reason: 'the provenance bundle is unreadable (fail closed)' };
  }
  const op = { verb: operation.verb, resource: operation.resource, params: operation.params ?? {} };
  const action = o.actions ? await o.actions(op) : undefined;
  const flags = o.principal?.(req, p) ?? {};
  const observed = o.observed ? await o.observed(p, op, bundleSession(bundle)) : [];
  const d = decideArgProvenance({
    bundle,
    operation: op,
    mediators: [...(o.mediators ?? []), ...(penv?.mediators ?? [])],
    ...(action !== undefined ? { action } : {}),
    principalPlan: flags.plan === true,
    principalControl: flags.control === true,
    observed,
  });
  if (d.outcome === 'pass') return { status: 'pass' };
  return { status: 'fail', reason: d.outcome === 'escalate' ? `escalate: ${d.reason}` : `${d.code}: ${d.reason}` };
}

/** Riskier of two values per input: higher is riskier, except reversibility and confidence (lower is riskier). */
function riskier(a: Partial<RiskInputs> | undefined, b: Partial<RiskInputs> | undefined): Partial<RiskInputs> | undefined {
  if (!a || !b) return a ?? b;
  const out: Partial<RiskInputs> = { ...a };
  for (const k of Object.keys(b) as (keyof RiskInputs)[]) {
    const x = a[k];
    const y = b[k];
    if (typeof y !== 'number' || !Number.isFinite(y)) continue;
    if (typeof x !== 'number' || !Number.isFinite(x)) out[k] = y;
    else out[k] = k === 'reversibility' || k === 'confidence' ? Math.min(x, y) : Math.max(x, y);
  }
  return out;
}

const denyVerdict = (reason: string): PcaVerdict => ({
  allow: false,
  r: 1,
  requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false },
  checks: { pcactn: 'fail' },
  reasons: [reason],
});

/** The guard `requirePCA` returns. `stateMode` says how replay / budget state is serialised (see {@link PcaStateMode}). */
export type PcaGuard = ((req: PcaRequestLike) => Promise<PcaGuardResult>) & { readonly stateMode: PcaStateMode };

/** The store key of a holder's counter stream. */
export function pcaStateKey(grantId: string, leafHolder: string, scope?: RequirePcaOptions['replayScope'], audience?: string): string {
  // default (0.5): audience-scoped whenever an audience is given
  scope ??= audience !== undefined ? 'audience-grant-holder' : 'grant-holder';
  return scope === 'audience-grant-holder' ? `aud:${encodeURIComponent(audience ?? '')}:${grantId}:${leafHolder}` : `${grantId}:${leafHolder}`;
}

export function requirePCA(opts: RequirePcaOptions): PcaGuard {
  // Freeze the configuration (e.g. the `require` list, the attestation trust list): later edits by the caller must not
  // change what this guard enforces. Stores and hook objects stay the caller's (behaviour/state, not data).
  opts = Object.freeze({
    ...snapshotConfig(opts, { keep: ['budgetStore', 'hooks', 'attestation', 'intentV2'] }),
    ...(opts.attestation ? { attestation: snapshotConfig(opts.attestation, { keep: ['nonceStore', 'hardwareVerifier', 'resolveDocument'] }) } : {}),
  });
  if (!opts.audience && !opts.insecureAllowUnenforced) {
    throw new TypeError('requirePCA: `audience` (this resource server\'s id) is required (or set insecureAllowUnenforced)');
  }
  if (!opts.operation && !opts.insecureAllowUnboundOperation && !opts.insecureAllowUnenforced) {
    throw new TypeError(
      "requirePCA: `operation` is required (0.5): map each request to the operation it will execute so the proof is bound to it, or use `authorize`; set insecureAllowUnboundOperation only to migrate",
    );
  }
  const store0 = opts.budgetStore;
  const atomic = isAtomicPcaStateStore(store0);
  const stateMode: PcaStateMode = !store0 ? 'none' : atomic ? 'atomic-claim' : store0.withKeyLock ? 'shared-lock' : 'process-lock';
  const multiInstance = opts.multiInstance ?? (store0 !== undefined && store0.scope !== 'process');
  if (multiInstance) {
    if (stateMode === 'process-lock') {
      throw new TypeError(
        'requirePCA: multiInstance needs a budgetStore with `claim` (AtomicPcaStateStore) or `withKeyLock`; the in-process lock is correct for one process only (multiInstance is on unless the store declares `scope: \'process\'`; pass multiInstance: false to run this store in one process on purpose)',
      );
    }
    if (store0?.scope === 'process') {
      throw new TypeError('requirePCA: multiInstance with a process-local budgetStore (its state is not shared between instances)');
    }
  }
  if (opts.replayScope !== undefined && opts.replayScope !== 'grant-holder' && opts.replayScope !== 'audience-grant-holder') {
    throw new TypeError(`requirePCA: unknown replayScope '${String(opts.replayScope)}'`);
  }
  if (opts.replayScope === 'audience-grant-holder' && !opts.audience) {
    throw new TypeError('requirePCA: replayScope audience-grant-holder needs `audience`');
  }
  const replayScope: NonNullable<RequirePcaOptions['replayScope']> = opts.replayScope ?? (opts.audience ? 'audience-grant-holder' : 'grant-holder');
  const claimRetries = opts.claimRetries ?? 3;
  if (!Number.isSafeInteger(claimRetries) || claimRetries < 0) throw new TypeError('requirePCA: claimRetries must be a non-negative integer');
  if (opts.revocationStaleness) validateRevocationStaleness(opts.revocationStaleness);
  const realm = opts.realm ?? 'pca';
  const challenge = (error?: string) =>
    `PCA realm="${realm}"${error ? `, error="${error}"` : ''}, hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"`;
  const unauth = (reason: string, error = 'invalid_request'): PcaGuardResult => ({
    ok: false,
    status: 401,
    verdict: denyVerdict(reason),
    wwwAuthenticate: challenge(error),
  });

  const guard = async (req: PcaRequestLike): Promise<PcaGuardResult> => {
    try {
      let raw: PCActn | string | null;
      try {
        raw = (opts.extract ?? defaultExtract)(req);
      } catch (e) {
        return unauth(`unreadable PCActn: ${(e as Error).message}`);
      }
      if (raw === null || raw === undefined) return unauth('no PCActn presented', 'missing_pcactn');
      let p: PCActn;
      try {
        p = typeof raw === 'string' ? decodePCActn(raw) : raw;
      } catch (e) {
        return unauth(`undecodable PCActn: ${(e as Error).message}`, 'invalid_pcactn');
      }
      if (p === null || typeof p !== 'object' || typeof p.grant_ref !== 'string') {
        return unauth('malformed PCActn', 'invalid_pcactn');
      }
      const grant = await opts.resolveGrant(p.grant_ref, p);
      if (!grant) return unauth('unknown grant_ref', 'unknown_grant');

      const k1Of = async (rq: PcaRequestLike, pa: PCActn): Promise<K1Input> => {
        let presented: Pick<K1Input, 'discharges' | 'narrow'> = {};
        try {
          presented = presentedK1(rq);
        } catch {
          presented = {}; // unreadable discharges are no discharges: the K1 caveat stays unsatisfied
        }
        const own = typeof opts.k1 === 'function' ? await opts.k1(rq, pa) : (opts.k1 ?? {});
        return { ...presented, ...own };
      };

      // Everything from the first state read to the last state write is ONE critical section per grant: otherwise N
      // concurrent requests carrying the same counter all read the same `lastCounter`, all pass, and all execute
      // (replay), and concurrent spends all debit the same starting budget (over-spend). See PcaStateStore.withKeyLock.
      const section = async (): Promise<PcaGuardResult | 'conflict'> => {
        const now = opts.now?.() ?? Date.now();
        const leafHolder = p.cap_chain?.[p.cap_chain.length - 1]?.holder;
        const key = pcaStateKey(grant.id, leafHolder ?? '', replayScope, opts.audience);
        let state = opts.budgetStore && leafHolder ? await opts.budgetStore.get(key) : undefined;
        // 0.5 upgrade: the audience-scoped key starts from the 0.4 key's state (never written again), so a spent counter stays spent
        let carried = false;
        if (!state && opts.budgetStore && leafHolder && replayScope === 'audience-grant-holder') {
          const legacy = await opts.budgetStore.get(pcaStateKey(grant.id, leafHolder, 'grant-holder'));
          if (legacy) {
            state = legacy;
            carried = true;
          }
        }
        const ctx: PcaContext = { ...(await opts.context?.(req, p)) };
        if (state?.budget && ctx.budget === undefined) ctx.budget = state.budget;
        if (opts.seedBudget && ctx.budget === undefined) ctx.budget = opts.seedBudget(grant, now);
        let operation: PcaOperation | undefined;
        if (opts.operation) {
          let op: PcaOperation | null | undefined;
          try {
            op = await opts.operation(req);
          } catch {
            op = undefined;
          }
          // no operation from the server: bind to an impossible one, so the `operation` check fails (fail closed)
          operation = op ?? { verb: undefined as unknown as string, resource: undefined as unknown as string };
        }
        if (opts.risk) ctx.risk = riskier(ctx.risk, await opts.risk(operation, grant, p));
        if (opts.revocationEpoch && ctx.revocationEpoch === undefined) {
          const re = await opts.revocationEpoch(p.grant_ref, p);
          // an unavailable epoch is NOT silently skipped: the required `freshness` check stays not-enforced -> denied.
          if (re) {
            const epochState = opts.budgetStore ? await opts.budgetStore.get(`${grant.id}:epoch`) : undefined;
            ctx.revocationEpoch = { ...re, lastAcceptedEpoch: epochState?.lastEpoch };
          }
        }
        // T9: class-dependent maximum age of the signed revocation state (the signer's `not_after` still applies too).
        const revCls = opts.revocationStaleness ? effectiveReversibility(ctx.reversibilityClass, p.action?.reversibility_class) : undefined;
        if (revCls && ctx.revocationEpoch && ctx.revocationEpoch.maxAgeMs === undefined) {
          ctx.revocationEpoch = { ...ctx.revocationEpoch, maxAgeMs: revocationMaxAgeMs(opts.revocationStaleness!, revCls) };
        }

        if (opts.beacon && ctx.beacon === undefined) {
          const b = await opts.beacon(p.grant_ref, p);
          // an unavailable beacon is NOT skipped: the required `beacon` check stays not-enforced -> denied (dead-man).
          if (b) {
            const bs = opts.budgetStore ? await opts.budgetStore.get(`${grant.id}:beacon`) : undefined;
            ctx.beacon = { ...b, lastAcceptedSeq: bs?.lastBeaconSeq };
          }
        }

        const hooks: VerifyHooks | undefined =
          opts.attestation && !opts.hooks?.attestation
            ? { ...opts.hooks, attestation: createAttestationVerifier({ now: () => now, ...opts.attestation }) }
            : opts.hooks;
        let freshAtPolicy = opts.freshAt === undefined ? undefined : typeof opts.freshAt === 'function' ? await opts.freshAt(req, p) : opts.freshAt;
        if (freshAtPolicy !== undefined && p.fresh_at === undefined && freshAtPolicy.sideCarried === undefined) {
          const side = header(req, 'pca-fresh-at');
          if (side !== undefined) {
            try {
              freshAtPolicy = { ...freshAtPolicy, sideCarried: JSON.parse(side) };
            } catch {
              freshAtPolicy = { ...freshAtPolicy, sideCarried: null }; // an unparseable token is a bad token (deny), never a missing one
            }
          }
        }
        const verdict = await verifyPCActn(p, {
          grant,
          hooks,
          now,
          context: ctx,
          audience: opts.audience,
          require: [], // this guard applies its own required checks after the replay counter below
          ...(opts.insecureAllowUnenforced === true ? { insecureSkipPlanRootCheck: true } : {}),
          ...(opts.allowedSuites !== undefined ? { allowedSuites: opts.allowedSuites } : {}),
          ...(opts.pqPins !== undefined ? { pqPins: opts.pqPins } : {}),
          ...(operation !== undefined ? { operation } : {}),
          ...(opts.enforce !== undefined ? { enforce: opts.enforce } : {}),
          ...(opts.requireRiskInputs !== undefined ? { requireRiskInputs: opts.requireRiskInputs } : {}),
          ...(opts.assurance === true ? { assurance: true } : {}),
          ...(opts.requireAssurance !== undefined ? { requireAssurance: opts.requireAssurance } : {}),
          ...(opts.intentV2 !== undefined ? { intentV2: typeof opts.intentV2 === 'function' ? await opts.intentV2(req, p) : opts.intentV2 } : {}),
          ...(opts.k1 !== undefined ? { k1: await k1Of(req, p) } : {}),
          ...(freshAtPolicy !== undefined ? { freshAt: freshAtPolicy } : {}),
        });

        // K1 `max_uses` is spent only for an action that is otherwise admitted, after the counter below accepted it
        const spendUses = async (): Promise<PcaGuardResult | undefined> => {
          const bound = verdict.k1Bound;
          if (!bound) return undefined;
          let why: string;
          if (!opts.usesStore) why = 'max_uses: the chain carries a max_uses caveat and this guard has no usesStore (fail closed)';
          else {
            const r = await reserveMaxUses(opts.usesStore, bound, now);
            if (r.ok) return undefined;
            why = `max_uses: ${r.reason}`;
          }
          verdict.allow = false;
          verdict.checks.max_uses = 'fail';
          verdict.reasons.push(why);
          return { ok: false, status: 403, verdict, decision: 'deny' };
        };

        // Anti-replay (Appendix A step 5): strictly increasing per holder.
        if (opts.budgetStore) {
          if (state?.lastCounter !== undefined && !(p.counter > state.lastCounter)) {
            verdict.allow = false;
            verdict.checks.replay = 'fail';
            verdict.reasons.push(`replay: ${String(p.counter)} is not greater than last seen ${state.lastCounter} (replay)`);
          } else verdict.checks.replay = 'pass';
        } else {
          verdict.checks.replay = 'not-enforced';
        }

        // T9: irreversible actions need VERIFIABLE revocation state: without a signed epoch (none configured, or the source
        // returned nothing) the revocation hook's answer cannot be dated, so it is refused unless explicitly allowed.
        if (revCls === 'irreversible' && !ctx.revocationEpoch && !opts.revocationStaleness!.allowUnsignedRootForIrreversible) {
          verdict.allow = false;
          verdict.checks.freshness = 'fail';
          verdict.reasons.push('freshness: no verifiable (guardian-signed) revocation state for an irreversible action');
        }

        if (!opts.insecureAllowUnenforced) {
          enforceRequired(verdict, opts.require ?? [
            ...STATEFUL_REQUIRED_CHECKS,
            ...(opts.revocationEpoch ? ['freshness'] : []),
            ...(opts.beacon ? ['beacon'] : []),
          ]);
          // additive options add their own checks to whatever list applies (never remove any)
          enforceRequired(verdict, [
            ...(opts.operation ? ['operation', 'params_digest'] : []),
            ...(opts.requireRiskInputs?.length ? ['risk_inputs'] : []),
          ]);
        }

        if (opts.provenance) {
          // its own check name: `provenance` is the Intent Layer v2 rule 17 check, whose outcome must never be overwritten
          const pv = await provenanceCheck(opts.provenance, req, p, grant, operation);
          verdict.checks.provenance_flow = pv.status;
          if (pv.status === 'fail') {
            verdict.allow = false;
            verdict.reasons.push(`provenance_flow: ${pv.reason ?? 'refused'}`);
          }
        }

        if (opts.resolvePrincipal) {
          const resolved = await opts.resolvePrincipal(grant.issuer, grant);
          const principal: PcaPrincipalInfo = resolved ?? {
            pub: grant.issuer,
            subject_type: 'unverified',
            subject_id: null,
            verified: false,
          };
          verdict.principal = principal;
          if (opts.requireVerifiedPrincipal && !principal.verified) {
            verdict.allow = false;
            verdict.checks.principal = 'fail';
            verdict.reasons.push('principal: the grant issuer is not an enrolled, verified principal');
          } else verdict.checks.principal = principal.verified ? 'pass' : 'not-enforced';
        } else if (opts.requireVerifiedPrincipal) {
          verdict.allow = false;
          verdict.checks.principal = 'fail';
          verdict.reasons.push('principal: requireVerifiedPrincipal needs a resolvePrincipal resolver');
        }

        // Ternary decision (G-T4): a verdict whose every failing check is escalate-class is `escalate`, never `allow` by itself.
        let escalation: EscalationRequest | undefined;
        let answeredBy: string | undefined;
        if (!verdict.allow && decisionOf(verdict) === 'escalate') {
          const esc = opts.escalation;
          const bind = {
            policy_digest: escalationPolicyDigest(grant),
            action_digest: escalationActionDigest(p),
            history_head: escalationHistoryHead(state?.lastCounter),
          };
          let renderDigest: string | undefined;
          if (esc?.render) {
            try {
              renderDigest = await esc.render(req, p);
            } catch {
              renderDigest = undefined; // a render that cannot be derived is no render (fail closed below when required)
            }
          }
          escalation = buildEscalationRequest({ aud: opts.audience, grant, pcactn: p, lastCounter: state?.lastCounter, reasons: verdict.reasons, now, ...(esc?.requestTtlMs !== undefined ? { ttlMs: esc.requestTtlMs } : {}), ...(renderDigest !== undefined ? { renderDigest } : {}) });
          if (esc) {
            let ans: unknown;
            try {
              ans = esc.answer ? await esc.answer(req, p) : defaultEscalationAnswer(req);
            } catch {
              ans = undefined; // an unreadable answer is no answer: the decision stays escalate (refused)
            }
            if (ans !== undefined && ans !== null && esc.insecureUnboundApproval !== true && renderDigest === undefined) {
              // K7 default: an answer is admitted only over a render the verifier recomputed
              verdict.reasons.push('escalation: an approval render is required and none could be recomputed (set escalation.render, or insecureUnboundApproval)');
            } else if (ans !== undefined && ans !== null) {
              const v = verifyEscalationAnswer(ans, esc.principals, renderDigest !== undefined ? { ...bind, render_digest: renderDigest } : bind, now);
              if (v.ok && v.decision === 'allow') {
                // The answer upgrades ONLY the escalate-class failures; every other check was already passing. The replay
                // counter claimed below spends the answer (it is bound to this exact PCActn).
                for (const [n, st] of Object.entries(verdict.checks)) if (st === 'fail') verdict.checks[n] = 'pass';
                verdict.checks.escalation = 'pass';
                verdict.reasons.push(`escalation: answered allow by principal ${v.principal.slice(0, 8)}`);
                verdict.allow = true;
                answeredBy = v.principal;
                escalation = undefined;
              } else verdict.reasons.push(`escalation: ${v.ok ? 'the principal answered deny' : v.reason}`);
            }
          }
        }
        if (!verdict.allow) {
          const decision: 'deny' | 'escalate' = escalation !== undefined ? 'escalate' : 'deny';
          // A bad signature / chain is an authentication failure; policy denial is authorization.
          const authnFailed = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'leaf_signature', 'malformed', 'grant_ref', 'pq_pin'].some(
            (c) => verdict.checks[c] === 'fail',
          );
          return authnFailed
            ? { ok: false, status: 401, verdict, wwwAuthenticate: challenge('invalid_pcactn'), decision: 'deny' }
            : { ok: false, status: 403, verdict, decision, ...(escalation ? { escalation } : {}) };
        }
        // computed before any state write: the id of this authorization, for the bound operation
        const operationId = operation ? hashCanonical(p) : undefined;
        const answered = answeredBy !== undefined ? { escalation: { answered_by: answeredBy } } : {};
        const succeed = (): PcaGuardResult =>
          operation
            ? { ok: true, decision: 'allow', verdict, pcactn: p, operation: { verb: operation.verb, resource: operation.resource, params_digest: p.action.params_digest, id: operationId! }, ...answered }
            : { ok: true, decision: 'allow', verdict, pcactn: p, ...answered };
        if (atomic) {
          // Atomic path: monotone pins first (raising a pin to a value that just verified is safe even if the claim then
          // loses), then ONE compare-and-set decides admission. No lock: the store's atomicity is the critical section.
          const st = opts.budgetStore as AtomicPcaStateStore;
          if (ctx.revocationEpoch && verdict.checks.freshness === 'pass') await st.raisePin(`${grant.id}:epoch`, 'lastEpoch', ctx.revocationEpoch.epoch.epoch);
          if (ctx.beacon && verdict.checks.beacon === 'pass') await st.raisePin(`${grant.id}:beacon`, 'lastBeaconSeq', ctx.beacon.beacon.seq);
          if (leafHolder) {
            const c = await st.claim(key, { counter: p.counter, budgetBefore: carried ? undefined : state?.budget, budgetAfter: verdict.budget ?? state?.budget });
            if (!c.ok && c.reason === 'conflict') return 'conflict';
            if (!c.ok) {
              verdict.allow = false;
              verdict.checks.replay = 'fail';
              verdict.reasons.push(
                c.lastCounter !== undefined
                  ? `replay: ${String(p.counter)} is not greater than last seen ${c.lastCounter} (replay)`
                  : `replay: ${String(p.counter)} was already claimed (replay)`,
              );
              return { ok: false, status: 403, verdict, decision: 'deny' };
            }
          }
          return (await spendUses()) ?? succeed();
        }
        if (opts.budgetStore && ctx.revocationEpoch && verdict.checks.freshness === 'pass') {
          const k = `${grant.id}:epoch`;
          const prev = await opts.budgetStore.get(k);
          if ((prev?.lastEpoch ?? -1) < ctx.revocationEpoch.epoch.epoch) await opts.budgetStore.put(k, { lastEpoch: ctx.revocationEpoch.epoch.epoch });
        }
        if (opts.budgetStore && ctx.beacon && verdict.checks.beacon === 'pass') {
          const k = `${grant.id}:beacon`;
          const prev = await opts.budgetStore.get(k);
          if ((prev?.lastBeaconSeq ?? -1) < ctx.beacon.beacon.seq) await opts.budgetStore.put(k, { lastBeaconSeq: ctx.beacon.beacon.seq });
        }
        if (opts.budgetStore && leafHolder) {
          await opts.budgetStore.put(key, { budget: verdict.budget ?? state?.budget, lastCounter: p.counter });
        }
        return (await spendUses()) ?? succeed();
      };
      const store = opts.budgetStore;
      const once = (): Promise<PcaGuardResult | 'conflict'> =>
        !store || (atomic && !store.withKeyLock)
          ? section()
          : store.withKeyLock
            ? store.withKeyLock(grant.id, section)
            : withLocalLock(grant.id, section);
      for (let attempt = 0; ; attempt++) {
        const r = await once();
        if (r !== 'conflict') return r;
        if (attempt >= claimRetries) {
          const verdict = denyVerdict('replay: concurrent state update for this holder kept conflicting (fail closed, retry the request)');
          return { ok: false, status: 403, verdict: { ...verdict, checks: { replay: 'fail' } } };
        }
      }
    } catch (e) {
      return { ok: false, status: 403, verdict: denyVerdict(`guard error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`) };
    }
  };
  // the assurance report follows the final checks (replay, default-deny of required checks, principal)
  const reported = async (req: PcaRequestLike): Promise<PcaGuardResult> => {
    const r = await guard(req);
    if (r.verdict.assurance) refreshAssurance(r.verdict.assurance, r.verdict.checks);
    return r;
  };
  return Object.assign(reported, { stateMode });
}
