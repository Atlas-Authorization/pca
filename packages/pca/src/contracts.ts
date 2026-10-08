import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { sign, verifyB64u } from './keys';
import {
  type ActionContext,
  type Predicate,
} from './predicates';
import {
  advanceStateStrict,
  checkProhibitions,
  emptyState,
  MAX_DEADLINE,
  MAX_INVARIANTS,
  stateDigest,
  stateProblem,
  validateInvariant,
  validateWhen,
  whenAffirmative,
  whenMatches,
  type Constitution,
  type Invariant,
  type MonitorState,
  type ProhibitionResult,
  type When,
} from './prohibitions';

/**
 * BOUNDED SAFETY-LTL BEHAVIORAL CONTRACTS (PCA frontier B2, v1).
 *
 * The existing `prohibitions` monitor expresses NEGATIVE authority as a static set of invariants a
 * plan may never violate. This layer GENERALIZES it: authority — positive AND negative — is a small
 * temporal-logic program of invariants that EACH ACTION proves it transitions validly, over the same
 * hash-chained action trace and the same declarative predicate DSL. A plan DAG is no longer the unit
 * of authority; a behavioral contract is.
 *
 * It is a strict, additive superset: a `Contract` carries an (optional) embedded prohibition
 * constitution PLUS a set of temporal `clauses`. A contract whose `clauses` is empty is the DEGENERATE
 * case — `advanceContract` then does exactly what the prohibition monitor does, byte-for-byte (same
 * ledger, same latches, same hash chain, same digests). So nothing about `SignedConstitution` /
 * prohibition behavior changes.
 *
 * OPERATORS (predicates P/Q are the SAME `When = Predicate` the constitution uses; no new predicate syntax):
 *   - `always P`                 safety:    every action must satisfy P (affirmative; unresolvable => violation).
 *   - `never P`                  safety:    = `always ¬P`; no action may satisfy P (conservative; unresolvable => matched/violation).
 *   - `p precedes q`             precedence: q may not be admitted until some p has been admitted earlier
 *                                            (generalizes the constitution's `require_prior`).
 *   - `q requires_prior p`       precedence: alias of `p precedes q` (q requires a prior p).
 *   - `p responds_within N (q)`  bounded liveness: whenever p occurs, q must occur within the next N
 *                                            actions — enforced as a SAFETY obligation with a deadline
 *                                            counter held in the monitor state; a MISSED deadline is a violation.
 *   - `and[...]`                 conjunction: all sub-clauses must hold (contract-level is already a conjunction).
 *
 * Everything is PURE DATA + total pure functions. No eval. Everything malformed / unknown / unresolvable
 * FAILS CLOSED exactly as the prohibition monitor does (`whenMatches` conservative for a veto trigger;
 * `whenAffirmative` for a positive obligation). Determinism: the same (state, action, contract) always
 * yields the same verdict and the same next-state digest. The next-state hash-chains onto the previous
 * (seq strictly increases; the digest binds the whole history, including open liveness deadlines), so
 * state rollback is detectable and refusable via compare-and-swap.
 */

/** Contract schema version. New clause forms are additive: an older verifier rejects an unknown kind (fail closed). */
export const CONTRACT_VERSION = 1;
/** Domain separator for the principal's contract signature (distinct from the constitution domain). */
export const CONTRACT_SIG_DOMAIN = 'atlas-pca/contract/v1\0';

/** Max clauses (counting nested) in one contract. */
export const MAX_CLAUSES = 256;
/** Max nesting depth of `and` clauses. */
export const MAX_CLAUSE_DEPTH = 16;
const MAX_ID_LEN = 128;
const FORBIDDEN_IDS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

// ---- clause types ----------------------------------------------------------------------

interface ClauseBase {
  /** Unique across the WHOLE contract (incl. nested) and disjoint from the embedded constitution ids. */
  id: string;
  description?: string;
}
/** SAFETY: every action must satisfy `p` (affirmative match; unresolvable => violation). */
export interface AlwaysClause extends ClauseBase {
  kind: 'always';
  p: When;
}
/** SAFETY: no action may satisfy `p` (= `always ¬p`; conservative match; unresolvable => matched => violation). */
export interface NeverClause extends ClauseBase {
  kind: 'never';
  p: When;
}
/** PRECEDENCE: an action matching `q` is forbidden until an action matching `p` has been admitted earlier. */
export interface PrecedesClause extends ClauseBase {
  kind: 'precedes';
  /** The prerequisite (matched AFFIRMATIVELY — an ambiguous prerequisite never counts as satisfied). */
  p: When;
  /** The guarded action (matched CONSERVATIVELY — an ambiguous guarded action still demands the prior). */
  q: When;
}
/** PRECEDENCE alias: `q requires_prior p` ⇔ `p precedes q`. */
export interface RequiresPriorClause extends ClauseBase {
  kind: 'requires_prior';
  q: When;
  p: When;
}
/**
 * BOUNDED LIVENESS: whenever an action matching `p` occurs, an action matching `q` must occur within
 * the next `within` actions. Enforced as a safety obligation: a deadline counter is opened on `p`
 * (conservative) and discharged by `q` (affirmative); if the counter is exhausted before `q`, the
 * action that exhausts it is a VIOLATION.
 */
export interface RespondsWithinClause extends ClauseBase {
  kind: 'responds_within';
  /** Stimulus (conservative: an ambiguous stimulus still opens the obligation). */
  p: When;
  /** Response (affirmative: an ambiguous action does not discharge the obligation). */
  q: When;
  /** Deadline in actions (integer in [1, MAX_DEADLINE]); the response must land within the next `within` actions. */
  within: number;
}
/** CONJUNCTION: all sub-clauses must hold. */
export interface AndClause extends ClauseBase {
  kind: 'and';
  clauses: Clause[];
}
/** Any supported temporal clause. */
export type Clause =
  | AlwaysClause
  | NeverClause
  | PrecedesClause
  | RequiresPriorClause
  | RespondsWithinClause
  | AndClause;

/**
 * A behavioral contract: an optional embedded prohibition constitution (`invariants`) PLUS a set of
 * temporal `clauses`. Both run against one shared, hash-chained `MonitorState`.
 */
export interface Contract {
  version: number;
  /** Principal public key (b64u) that commits to (and signs) this contract. */
  principal: string;
  /** Embedded negative-authority constitution (optional; defaults to none). Runs exactly as today. */
  invariants?: Invariant[];
  /** Temporal-logic behavioral clauses (optional; defaults to none — then this is a plain constitution). */
  clauses?: Clause[];
  issued_at?: number;
}
/** A contract plus its content id and the principal's signature. */
export interface SignedContract extends Contract {
  /** hashCanonical of the body (without `id`, `sig`). */
  id: string;
  sig: string;
}

/** Outcome of evaluating a whole contract against one action. Mirrors `ProhibitionResult`. */
export interface ContractResult {
  ok: boolean;
  /** Violated ids (constitution invariant ids and/or clause ids; '<contract>'/'<action>'/'<state>' for structural). */
  violated: string[];
  reasons: string[];
  /** Every clause + every embedded invariant considered, in order (no short-circuit). */
  evaluated: Array<{ id: string; kind: string; result: 'pass' | 'violated'; reason?: string }>;
}

/** Result of `advanceContract`: the verdict plus the next state (== input state unless `ok`). */
export interface AdvanceContractResult extends ContractResult {
  /** Advanced, hash-chained state when `ok`; otherwise the input state, unchanged (fail closed). */
  next: MonitorState;
  decidedBy: 'contract' | 'state' | 'none';
}

// ---- small helpers (local, matching the prohibition monitor's conventions) --------------

const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const UNHASHABLE = '<unhashable>';
const safe = (f: () => string): string => {
  try {
    return f();
  } catch {
    return UNHASHABLE;
  }
};

// ---- validation ------------------------------------------------------------------------

/** Normalize a precedence clause to {p (prerequisite), q (guarded)} regardless of spelling. */
function precedencePair(cl: PrecedesClause | RequiresPriorClause): { p: When; q: When } {
  return { p: cl.p, q: cl.q };
}

/**
 * Structural problems with a clause (empty = well-formed). Collects every id into `seen` to enforce
 * global uniqueness; `depth` bounds nesting. Total; never throws.
 */
export function validateClause(cl: unknown, seen: Set<string>, depth: number): string[] {
  if (depth > MAX_CLAUSE_DEPTH) return ['clause nesting too deep'];
  if (!isObj(cl)) return ['clause not an object'];
  const rawId = cl.id;
  if (typeof rawId !== 'string' || !rawId) return ['<no id>: missing clause id'];
  const id = rawId;
  const err = (m: string) => [`${id}: ${m}`];
  if (id.length > MAX_ID_LEN) return err('id too long');
  if (FORBIDDEN_IDS.has(id)) return err('forbidden id');
  if (seen.has(id)) return err('duplicate id');
  seen.add(id);
  let e: string | null;
  switch (cl.kind) {
    case 'always':
    case 'never':
      return (e = validateWhen(cl.p, 'p')) ? err(e) : [];
    case 'precedes':
    case 'requires_prior': {
      if ((e = validateWhen(cl.p, 'p'))) return err(e);
      if ((e = validateWhen(cl.q, 'q'))) return err(e);
      return [];
    }
    case 'responds_within': {
      if ((e = validateWhen(cl.p, 'p'))) return err(e);
      if ((e = validateWhen(cl.q, 'q'))) return err(e);
      const within = cl.within;
      if (!Number.isInteger(within) || (within as number) < 1 || (within as number) > MAX_DEADLINE) return err('within must be an integer in [1, MAX_DEADLINE]');
      return [];
    }
    case 'and': {
      const subs = cl.clauses;
      if (!Array.isArray(subs) || subs.length === 0) return err('and.clauses must be a non-empty array');
      const out: string[] = [];
      for (const sub of subs) out.push(...validateClause(sub, seen, depth + 1));
      return out;
    }
    default:
      return err(`unknown clause kind ${String(cl.kind)}`);
  }
}

/** Count clauses (including nested). */
function countClauses(cls: Clause[]): number {
  let n = 0;
  for (const cl of cls) {
    n += 1;
    if (isObj(cl) && cl.kind === 'and' && Array.isArray((cl as AndClause).clauses)) n += countClauses((cl as AndClause).clauses);
  }
  return n;
}

/** Structural problems with a contract (empty = well-formed). Total; never throws. */
export function validateContract(c: unknown): string[] {
  if (!isObj(c)) return ['contract not an object'];
  const out: string[] = [];
  if (c.version !== CONTRACT_VERSION) out.push(`unsupported version ${String(c.version)}`);
  if (typeof c.principal !== 'string' || !c.principal) out.push('principal missing');

  const ids = new Set<string>();
  // Embedded constitution (optional) — validated by the existing validator, reusing its id rules.
  const invariants = c.invariants;
  if (invariants !== undefined) {
    if (!Array.isArray(invariants)) return [...out, 'invariants not an array'];
    if (invariants.length > MAX_INVARIANTS) out.push('too many invariants');
    for (const inv of invariants) {
      out.push(...validateInvariant(inv));
      const id = isObj(inv) ? inv.id : undefined;
      if (typeof id === 'string') {
        if (ids.has(id)) out.push(`${id}: duplicate id`);
        ids.add(id);
      }
    }
  }
  // Temporal clauses (optional).
  const clauses = c.clauses;
  if (clauses !== undefined) {
    if (!Array.isArray(clauses)) return [...out, 'clauses not an array'];
    if (countClauses(clauses as Clause[]) > MAX_CLAUSES) out.push('too many clauses');
    // clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
    for (const cl of clauses) out.push(...validateClause(cl, ids, 1));
  }
  return out;
}

// ---- contract commitment (mirrors signConstitution/verifyConstitution) ------------------

function body(c: Contract): Contract {
  const { id: _id, sig: _sig, ...rest } = c as SignedContract;
  void _id;
  void _sig;
  return rest;
}
function domainMessage(domain: string, id: string): Uint8Array {
  const pre = utf8(domain);
  const d = sha256(utf8(id));
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}
const sigMessage = (id: string): Uint8Array => domainMessage(CONTRACT_SIG_DOMAIN, id);

/** Content address of a contract body. Throws only on non-canonicalizable input (authoring time). */
export function contractId(c: Contract): string {
  return hashCanonical(body(c));
}

/** Principal signs the contract. Refuses to sign a malformed one (authoring-time guard). */
export function signContract(c: Contract, principalSecret: Uint8Array): SignedContract {
  const problems = validateContract(c);
  if (problems.length) throw new TypeError('signContract: ' + problems.join('; '));
  const id = contractId(c);
  return { ...body(c), id, sig: b64u(sign(principalSecret, sigMessage(id))) };
}

/** Verify: well-formed, id matches content, signature by `expectedPrincipal` (or the embedded one). Never throws. */
export function verifyContract(sc: SignedContract, expectedPrincipal?: string): { ok: boolean; reason?: string } {
  try {
    const problems = validateContract(sc);
    if (problems.length) return { ok: false, reason: problems[0] };
    if (expectedPrincipal !== undefined && sc.principal !== expectedPrincipal) return { ok: false, reason: 'principal mismatch' };
    if (typeof sc.id !== 'string' || sc.id !== contractId(sc)) return { ok: false, reason: 'id does not match content' };
    if (typeof sc.sig !== 'string' || !verifyB64u(sc.principal, sigMessage(sc.id), sc.sig)) return { ok: false, reason: 'bad signature' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'verification error (fail closed)' };
  }
}

// ---- composition with the existing constitution ----------------------------------------

/** The embedded prohibition constitution of a contract (empty when `invariants` is omitted). */
export function embeddedConstitution(c: Contract): Constitution {
  return { version: 1, principal: c.principal, invariants: Array.isArray(c.invariants) ? c.invariants : [] };
}

/** Lift a plain prohibition constitution into the degenerate contract (no temporal clauses). */
export function contractFromConstitution(c: Constitution): Contract {
  return { version: CONTRACT_VERSION, principal: c.principal, invariants: c.invariants, clauses: [] };
}

// ---- clause evaluation (per-action transition) ------------------------------------------

/**
 * Per-clause transition against ONE action and the pre-state. Pure, total, fail-closed. Returns the
 * verdict plus the intended state updates (`latchSet`: precedence latches to set now; `deadlineSet`:
 * new bounded-liveness budget, or `null` to clear an open obligation). Updates are applied to the next
 * state ONLY if the whole contract is `ok`; on violation the pre-state is returned unchanged.
 */
interface ClauseTransition {
  ok: boolean;
  reason?: string;
  /** rows for the `evaluated` trace (one per clause, recursing into `and`). */
  rows: Array<{ id: string; kind: string; result: 'pass' | 'violated'; reason?: string }>;
  latchSet: Record<string, number>;
  /** id -> new deadline budget, or null to clear. */
  deadlineSet: Record<string, number | null>;
}

function evalClause(cl: Clause, ctx: ActionContext, state: MonitorState, now: number): ClauseTransition {
  const latched = state.latched;
  const deadlines = state.deadlines ?? {};
  const base = (ok: boolean, reason?: string): ClauseTransition => ({
    ok,
    ...(reason ? { reason } : {}),
    rows: [{ id: cl.id, kind: cl.kind, result: ok ? 'pass' : 'violated', ...(reason ? { reason } : {}) }],
    latchSet: {},
    deadlineSet: {},
  });
  try {
    switch (cl.kind) {
      case 'always': {
        // positive authority: every action must AFFIRMATIVELY satisfy p; unresolvable => violation.
        return whenAffirmative(cl.p, ctx) ? base(true) : base(false, cl.description ?? 'always-invariant violated (action does not satisfy p)');
      }
      case 'never': {
        // = always ¬p; conservative: an unresolvable trigger counts as matched (veto).
        return whenMatches(cl.p, ctx) ? base(false, cl.description ?? 'never-invariant violated (forbidden action)') : base(true);
      }
      case 'precedes':
      case 'requires_prior': {
        const { p, q } = precedencePair(cl);
        const isQ = whenMatches(q, ctx); // guarded action, conservative
        const t = base(!isQ || has(latched, cl.id), !isQ || has(latched, cl.id) ? undefined : cl.description ?? 'precedence violated (prerequisite p not yet admitted before q)');
        // latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
        if (!has(latched, cl.id) && whenAffirmative(p, ctx)) t.latchSet[cl.id] = now;
        return t;
      }
      case 'responds_within': {
        const open = has(deadlines, cl.id);
        let violated = false;
        let carried: number | null = null; // budget carried from an existing obligation (not yet discharged)
        if (open) {
          const cur = deadlines[cl.id]!;
          if (whenAffirmative(cl.q, ctx)) {
            carried = null; // any response discharges all open obligations
          } else {
            const r = cur - 1;
            if (r <= 0) violated = true; // window exhausted with no response => violation at this action
            else carried = r;
          }
        }
        const rows: ClauseTransition['rows'] = [
          { id: cl.id, kind: cl.kind, result: violated ? 'violated' : 'pass', ...(violated ? { reason: cl.description ?? `bounded-liveness deadline missed (no q within ${cl.within} actions of p)` } : {}) },
        ];
        if (violated) return { ok: false, reason: rows[0]!.reason, rows, latchSet: {}, deadlineSet: {} };
        // a (conservative) stimulus opens a fresh obligation of budget `within`; the binding deadline
        // is the MOST URGENT open obligation (any q discharges them all), i.e. min(carried, within).
        let next: number | null = carried;
        if (whenMatches(cl.p, ctx)) next = next === null ? cl.within : Math.min(next, cl.within);
        return { ok: true, rows, latchSet: {}, deadlineSet: { [cl.id]: next } };
      }
      case 'and': {
        const rows: ClauseTransition['rows'] = [];
        const latchSet: Record<string, number> = {};
        const deadlineSet: Record<string, number | null> = {};
        let ok = true;
        let reason: string | undefined;
        for (const sub of cl.clauses) {
          const r = evalClause(sub, ctx, state, now);
          rows.push(...r.rows);
          Object.assign(latchSet, r.latchSet);
          Object.assign(deadlineSet, r.deadlineSet);
          if (!r.ok && ok) {
            ok = false;
            reason = r.reason;
          }
        }
        // the `and` itself does not emit a row — its children's rows carry the detail. (ok rolls up.)
        return { ok, ...(reason ? { reason } : {}), rows, latchSet, deadlineSet };
      }
      default:
        return base(false, 'unknown clause kind (fail closed)');
    }
  } catch {
    return base(false, 'clause evaluation error (fail closed)');
  }
}

// ---- the contract monitor ---------------------------------------------------------------

/**
 * Evaluate a whole contract (embedded constitution + temporal clauses) against one action and the
 * running state, WITHOUT advancing. Pure, total, fail-closed. Every invariant and clause is evaluated
 * (no short-circuit) so the trace is complete.
 */
export function checkContract(action: ActionContext, contract: Contract, state: MonitorState): ContractResult {
  const fail = (id: string, reason: string): ContractResult => ({
    ok: false,
    violated: [id],
    reasons: [`${id}: ${reason}`],
    evaluated: [{ id, kind: 'structural', result: 'violated', reason }],
  });
  try {
    const cp = validateContract(contract);
    if (cp.length) return fail('<contract>', cp[0]!);
    const a = action?.action;
    if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') return fail('<action>', 'malformed action');
    const sp = stateProblem(state);
    if (sp) return fail('<state>', sp);

    const evaluated: ContractResult['evaluated'] = [];
    // 1) embedded constitution (unchanged semantics — reuse the prohibition monitor verbatim)
    const constitution = embeddedConstitution(contract);
    if (constitution.invariants.length) {
      const pr: ProhibitionResult = checkProhibitions(action, constitution, state);
      evaluated.push(...pr.evaluated);
    }
    // 2) temporal clauses
    const now = state.now;
    for (const cl of contract.clauses ?? []) {
      let t: ClauseTransition;
      try {
        t = evalClause(cl, action, state, now);
      } catch {
        t = { ok: false, reason: 'clause evaluation error (fail closed)', rows: [{ id: cl.id, kind: (cl as Clause).kind ?? 'clause', result: 'violated', reason: 'clause evaluation error (fail closed)' }], latchSet: {}, deadlineSet: {} };
      }
      evaluated.push(...t.rows);
    }
    const bad = evaluated.filter((e) => e.result === 'violated');
    return { ok: bad.length === 0, violated: bad.map((e) => e.id), reasons: bad.map((e) => `${e.id}: ${e.reason ?? 'violated'}`), evaluated };
  } catch {
    return fail('<monitor>', 'monitor error (fail closed)');
  }
}

/** Optimistic-concurrency guards for `advanceContract` (compare-and-swap on the hash-chain head). */
export interface AdvanceContractOptions {
  /** Refuse unless `state.seq` equals this. */
  expectedSeq?: number;
  /** Refuse unless `stateDigest(state)` equals this. */
  expectedStateDigest?: string;
  /** Evaluation time (epoch ms); must be >= state.now. Defaults to state.now. */
  now?: number;
}

/**
 * Deterministic, total verifier: check the whole contract against one action and, iff it holds, advance
 * the hash-chained monitor state EXACTLY like the prohibition monitor (`advanceStateStrict` handles the
 * ledger/latches/seq/parent of the embedded constitution; this function then overlays the temporal
 * clauses' precedence latches and bounded-liveness deadline counters). Fail-closed on anything
 * unresolvable/unknown/unsafe or on a stale chain head; `next` is then the input state, unchanged.
 * Never throws.
 */
export function advanceContract(
  state: MonitorState,
  action: ActionContext,
  contract: Contract,
  opts: AdvanceContractOptions = {},
): AdvanceContractResult {
  const check = (): ContractResult => checkContract(action, contract, state);
  const refuse = (decidedBy: AdvanceContractResult['decidedBy'], r?: ContractResult, reason?: string): AdvanceContractResult => {
    const base = r ?? check();
    return {
      ok: false,
      violated: reason ? [...base.violated.filter((v) => v !== '<state>'), '<state>'] : base.violated,
      reasons: reason ? [...base.reasons, `<state>: ${reason}`] : base.reasons,
      evaluated: base.evaluated,
      next: state,
      decidedBy,
    };
  };
  try {
    const now = opts.now ?? state?.now;
    // CAS on the chain head FIRST — a rolled-back / stale state is refused before anything else.
    if (opts.expectedSeq !== undefined && (!isObj(state) || state.seq !== opts.expectedSeq)) return refuse('state', undefined, 'stale state head (seq)');
    if (opts.expectedStateDigest !== undefined && safe(() => stateDigest(state)) !== opts.expectedStateDigest) return refuse('state', undefined, 'stale state head (digest)');

    const verdict = checkContract(action, contract, state);
    if (!verdict.ok) {
      const structural = verdict.violated.some((v) => v.startsWith('<') && v.endsWith('>'));
      return { ...verdict, next: state, decidedBy: structural ? 'state' : 'contract' };
    }

    // Advance. The embedded constitution's ledger/latches/seq/parent via the existing strict advance.
    const constitution = embeddedConstitution(contract);
    const adv = advanceStateStrict(action, constitution, state, now);
    if (!adv.ok) return refuse('state', verdict, 'advance failed: ' + adv.reason);

    // Overlay the temporal clauses' state. Recompute their transitions against the PRE-state (the same
    // ones the verdict used) and apply latch/deadline updates to the advanced base.
    const latched: Record<string, number> = { ...adv.state.latched };
    const deadlines: Record<string, number> = { ...(state.deadlines ?? {}) };
    for (const cl of contract.clauses ?? []) {
      const t = evalClause(cl, action, state, now!);
      for (const [k, v] of Object.entries(t.latchSet)) if (!has(latched, k)) latched[k] = v;
      for (const [k, v] of Object.entries(t.deadlineSet)) {
        if (v === null) delete deadlines[k];
        else deadlines[k] = v;
      }
    }
    const next: MonitorState = { ...adv.state, latched };
    if (Object.keys(deadlines).length) next.deadlines = deadlines;
    const sp = stateProblem(next);
    if (sp) return refuse('state', verdict, 'resulting state invalid: ' + sp);
    return { ...verdict, next, decidedBy: 'none' };
  } catch {
    return refuse('state', undefined, 'advance error (fail closed)');
  }
}

/**
 * Convenience: compose a permission verdict with a contract. `allow = permitted AND contract.ok`, and on
 * allow the state advances. Mirrors `composeAuthority`/`checkAndAdvance` — the permission verdict is an
 * INPUT that can only be ANDed; the contract monitor runs unconditionally so denial reasons are complete.
 */
export function checkAndAdvanceContract(
  permitted: boolean,
  state: MonitorState,
  action: ActionContext,
  contract: Contract,
  opts: AdvanceContractOptions = {},
): AdvanceContractResult & { allow: boolean; permitted: boolean } {
  const adv = advanceContract(state, action, contract, opts);
  const p = permitted === true;
  // If the contract refused, keep its verdict. If it passed but permission denied, deny with next=state.
  if (!adv.ok) return { ...adv, allow: false, permitted: p };
  if (!p) {
    return {
      ok: false,
      violated: adv.violated,
      reasons: [...adv.reasons, '<permission>: not permitted'],
      evaluated: adv.evaluated,
      next: state,
      decidedBy: 'contract',
      allow: false,
      permitted: p,
    };
  }
  return { ...adv, allow: true, permitted: p };
}

/** Genesis monitor state at `now` (re-exported for ergonomics; identical to the prohibition one). */
export { emptyState };

export type { ActionContext, MonitorState, Predicate };
