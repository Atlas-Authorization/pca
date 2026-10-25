/**
 * Per-key linearizability check of a recorded history (P-compositionality: a history is linearizable iff every key's
 * sub-history is, because keys are independent registers), with a minimal counterexample per violating key.
 *
 * Per key: (1) two overlapping definite TRUEs are an immediate violation (the pair is the counterexample); (2) explained
 * FALSEs are pruned (verdict-preserving, `model.prune`); (3) a key with no unknown outcome is decided exactly
 * (`model.fastCheck`); (4) otherwise the budgeted search decides, and a key over budget is UNRESOLVED (never a pass).
 */
import { fastCheck, overlappingTrues, prune, type Op } from './model';
import { DEFAULT_SEARCH_BUDGET, searchLinearizable, type Verdict } from './search';

export interface CheckOptions {
  /** Search states per key before the key is UNRESOLVED (default 200,000). */
  budget?: number;
  /** Shrink each violating key's history to a 1-minimal counterexample (default true). */
  minimize?: boolean;
  /** Keys with more operations than this (after pruning) are reported without shrinking (default 200). */
  minimizeLimit?: number;
}

export interface KeyResult {
  key: string;
  kind: Op['kind'];
  /** Operations recorded for the key, and how many remained after pruning. */
  ops: number;
  searched: number;
  verdict: Verdict;
  method: 'overlap' | 'exact' | 'search';
  /** For a violation: a history that is itself non-linearizable; 1-minimal unless `minimized` is false. */
  counterexample?: Op[];
  minimized?: boolean;
}

export interface HistoryCheck {
  ops: number;
  keys: number;
  ok: boolean;
  /** Counts by outcome over the whole history. */
  outcomes: Record<Op['res'], number>;
  violations: KeyResult[];
  unresolved: KeyResult[];
}

/** Decide one key's history (all operations share `kind` and `key`). */
export function decideKey(ops: readonly Op[], budget: number = DEFAULT_SEARCH_BUDGET): { verdict: Verdict; method: KeyResult['method']; kept: Op[] } {
  if (overlappingTrues(ops)) return { verdict: 'violation', method: 'overlap', kept: [...ops] };
  const kept = prune(ops);
  const exact = fastCheck(kept);
  if (exact !== undefined) return { verdict: exact ? 'ok' : 'violation', method: 'exact', kept };
  return { verdict: searchLinearizable(kept, budget), method: 'search', kept };
}

/**
 * The SOUND deletion step for `op`: a deletion under which a linearizable history stays linearizable, so a violating
 * result proves the original violating. Deleting a FALSE never helps it (it does not move the register). Deleting a
 * writer (TRUE or unknown) lowers the register, which can only break FALSEs that it may have explained (`lo <= w`), so
 * those go with it; every other FALSE was explained by some other write that is still there.
 */
export function deletion(ops: readonly Op[], op: Op): Op[] {
  if (op.res === 'false') return ops.filter((o) => o !== op);
  return ops.filter((o) => o !== op && !(o.res === 'false' && o.lo <= op.w));
}

/** Greedy sound deletion to a 1-minimal violating history (no single deletion step keeps it violating). */
export function minimize(ops: readonly Op[], budget: number = DEFAULT_SEARCH_BUDGET): Op[] {
  let cur = [...ops];
  for (let changed = true; changed; ) {
    changed = false;
    for (const op of cur) {
      const next = deletion(cur, op);
      if (decideKey(next, budget).verdict === 'violation') {
        cur = next;
        changed = true;
        break;
      }
    }
  }
  return cur;
}

export function checkKey(ops: readonly Op[], opts: CheckOptions = {}): KeyResult {
  const budget = opts.budget ?? DEFAULT_SEARCH_BUDGET;
  const first = ops[0]!;
  const { verdict, method, kept } = decideKey(ops, budget);
  const r: KeyResult = { key: first.key, kind: first.kind, ops: ops.length, searched: kept.length, verdict, method };
  if (verdict !== 'violation') return r;
  const pair = overlappingTrues(ops);
  if (pair) {
    r.counterexample = [...pair].sort((a, b) => a.call - b.call);
    r.minimized = true;
  } else if (opts.minimize !== false && kept.length <= (opts.minimizeLimit ?? 200)) {
    r.counterexample = minimize(kept, budget);
    r.minimized = true;
  } else {
    r.counterexample = kept;
    r.minimized = false;
  }
  return r;
}

/** Split a history by (kind, key) and check every key. */
export function checkHistory(ops: readonly Op[], opts: CheckOptions = {}): HistoryCheck {
  const byKey = new Map<string, Op[]>();
  const outcomes: Record<Op['res'], number> = { true: 0, false: 0, unknown: 0 };
  for (const o of ops) {
    outcomes[o.res] += 1;
    const id = `${o.kind}\u0000${o.key}`;
    const list = byKey.get(id);
    if (list) list.push(o);
    else byKey.set(id, [o]);
  }
  const violations: KeyResult[] = [];
  const unresolved: KeyResult[] = [];
  for (const list of byKey.values()) {
    const r = checkKey(list, opts);
    if (r.verdict === 'violation') violations.push(r);
    else if (r.verdict === 'unresolved') unresolved.push(r);
  }
  return { ops: ops.length, keys: byKey.size, ok: violations.length === 0 && unresolved.length === 0, outcomes, violations, unresolved };
}

const fmtT = (t: number, base: number): string => (t === Infinity ? 'open' : `+${(t - base).toFixed(3)}ms`);
const res = (r: Op['res']): string => (r === 'true' ? 'TRUE' : r === 'false' ? 'false' : 'unknown');

/** One line per operation, times relative to the first invocation. */
export function formatOps(ops: readonly Op[]): string[] {
  const base = Math.min(...ops.map((o) => o.call));
  return [...ops]
    .sort((a, b) => a.call - b.call)
    .map((o) => {
      const what = o.kind === 'consume' ? `consumeOnce(now=${o.lo}, retainUntil=${o.w})` : `advance(${o.lo})`;
      return `${o.client}: ${what} [${fmtT(o.call, base)} .. ${fmtT(o.ret, base)}] -> ${res(o.res)}`;
    });
}
