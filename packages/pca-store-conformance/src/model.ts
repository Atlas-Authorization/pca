/**
 * The sequential specification both store operations share, and the verdict-preserving reductions of the checker.
 *
 * ONE MODEL FOR BOTH OPERATIONS. Each operation carries a threshold `lo` and a write value `w`:
 *  - `consumeOnce(key, retainUntil, now)`: lo = now, w = retainUntil (the record is live while its horizon is >= now);
 *  - `advance(stream, counter)`:           lo = w = counter.
 * The register `s` starts at -Infinity (no record / no counter). A TRUE answer is legal iff `s < lo`, and then
 * `s := max(s, w)`; a FALSE answer is legal iff `s >= lo` and leaves `s` unchanged. An UNKNOWN outcome (error, timeout,
 * killed client) may or may not have taken effect: from `s < lo` it may leave `s` or move it to `max(s, w)`. The
 * register never decreases, which is what the reductions below rely on.
 */

export type OpKind = 'consume' | 'advance';
export type Outcome = 'true' | 'false' | 'unknown';

export interface Op {
  /** The client (connection / process) that issued it. Informational. */
  client: string;
  kind: OpKind;
  key: string;
  /** consume: nowMs. advance: the counter. */
  lo: number;
  /** consume: retainUntilMs. advance: the counter. */
  w: number;
  /** Invocation time (ms, any shared clock). Recorded BEFORE the request leaves the client. */
  call: number;
  /** Response time; Infinity when the outcome is unknown (the operation may still take effect at any later time). */
  ret: number;
  res: Outcome;
}

/** The register's successor states after `op` from `s` (empty: the answer is impossible from `s`). */
export function step(s: number, op: Op): number[] {
  const fresh = s < op.lo;
  if (op.res === 'true') return fresh ? [Math.max(s, op.w)] : [];
  if (op.res === 'false') return fresh ? [] : [s];
  return fresh ? [s, Math.max(s, op.w)] : [s];
}

const definiteTrue = (o: Op): boolean => o.res === 'true';

/**
 * Two definite TRUE answers whose [lo, w] intervals overlap can never both linearize (after the first, `s >= w >= lo` of
 * the second). For consume-once with a retention horizon past every `now`, that is "two TRUEs for one key"; for a
 * counter, "two TRUEs for one value". Returns such a pair (the minimal counterexample), or undefined.
 */
export function overlappingTrues(ops: readonly Op[]): [Op, Op] | undefined {
  // Sorted by lo, the intervals are pairwise disjoint iff each one starts after the previous one ends (then the w are
  // increasing too, as lo <= w), so comparing neighbours finds an overlap if there is one.
  const ts = ops.filter(definiteTrue).sort((a, b) => a.lo - b.lo);
  for (let i = 1; i < ts.length; i++) if (ts[i - 1]!.w >= ts[i]!.lo) return [ts[i - 1]!, ts[i]!];
  return undefined;
}

/**
 * Drop every definite FALSE that a definite TRUE explains: a TRUE with `w >= lo` that RETURNED before the FALSE was
 * invoked. From that TRUE's linearization point on the register is `>= lo`, so the FALSE can be placed at its own
 * invocation without affecting any other operation: the history is linearizable iff the reduced one is.
 */
export function prune(ops: readonly Op[]): Op[] {
  const ts = ops.filter(definiteTrue).sort((a, b) => a.ret - b.ret);
  // prefix maximum of w over the TRUEs in return order
  const pm: number[] = [];
  for (const t of ts) pm.push(Math.max(t.w, pm.length ? pm[pm.length - 1]! : -Infinity));
  return ops.filter((o) => {
    if (o.res !== 'false') return true;
    let n = 0; // number of TRUEs that returned strictly before o.call
    while (n < ts.length && ts[n]!.ret < o.call) n++;
    return !(n > 0 && pm[n - 1]! >= o.lo);
  });
}

/**
 * EXACT decision for a history with no unknown operation, in O(n log n) (undefined when one is unknown):
 *  - every TRUE moves the register, so their order is forced: ascending `lo`, each one's `lo` above the previous `w`;
 *  - the earliest schedule t_i = max(call_i, t_{i-1}) is feasible iff every t_i <= ret_i (earliest dominates);
 *  - a FALSE needs a point in its interval at which the register is >= its `lo`: at or after the first TRUE (in that
 *    order) with `w >= lo`, whose earliest point must not be later than the FALSE's return.
 */
export function fastCheck(ops: readonly Op[]): boolean | undefined {
  if (ops.some((o) => o.res === 'unknown')) return undefined;
  const ts = ops.filter(definiteTrue).sort((a, b) => a.lo - b.lo);
  const t: number[] = [];
  let prev = -Infinity;
  for (let i = 0; i < ts.length; i++) {
    const o = ts[i]!;
    if (i > 0 && ts[i - 1]!.w >= o.lo) return false;
    const ti = Math.max(o.call, prev);
    if (ti > o.ret) return false;
    t.push(ti);
    prev = ti;
  }
  for (const f of ops) {
    if (f.res !== 'false') continue;
    const j = ts.findIndex((x) => x.w >= f.lo);
    if (j < 0 || t[j]! > f.ret) return false;
  }
  return true;
}
