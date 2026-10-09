import { isLeafCondition, type Condition, type ConditionOp } from '@atlasauth/pca';

/**
 * The interval + finite-set engine for a single `where` field.
 *
 * PCA's `where` conditions over one field are a conjunction of threshold tests (lt/lte/gt/gte/eq on
 * numbers), membership tests (eq/ne/in/nin over finite values) and string-prefix tests. Any such
 * conjunction partitions the value line into finitely many CELLS on which every condition is constant,
 * bounded by the literals that appear. Picking one representative value per cell is therefore a SOUND
 * AND COMPLETE probe set for the decided fragment: two policies agree on all actions iff they agree on
 * all actions drawn from these representatives (the finite-distinguishing-value property that makes the
 * relational queries decidable by enumeration — see enumerate.ts).
 *
 * `ref` conditions (operand is another field) are NOT a single-field constraint; they are flagged
 * upstream as undecidable and skipped here.
 */

/** A sentinel string guaranteed not to equal, be a prefix of, or be prefixed by any policy literal. */
export const FRESH_STRING = '\u0000atlas-analyzer::fresh-unmatched\u0000';

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

/**
 * Representatives of a numeric threshold arrangement: below the min, each threshold exactly, the open
 * interval between each pair of consecutive thresholds (its midpoint), and above the max. This is the
 * minimal set on which every `x {lt,lte,gt,gte,eq} t` built from these thresholds is constant per cell.
 */
function numericCellReps(thresholds: readonly number[]): number[] {
  const sorted = [...new Set(thresholds)].filter(Number.isFinite).sort((a, b) => a - b);
  if (sorted.length === 0) return [];
  const first = sorted[0];
  const last = sorted[sorted.length - 1];
  if (first === undefined || last === undefined) return [];
  const out: number[] = [first - 1];
  for (let i = 0; i < sorted.length; i++) {
    const ti = sorted[i];
    if (ti === undefined) continue;
    out.push(ti);
    const tn = sorted[i + 1];
    if (tn !== undefined) out.push((ti + tn) / 2);
  }
  out.push(last + 1);
  return out;
}

/** A stable key for de-duplicating representative values of mixed type. */
function valueKey(x: unknown): string {
  if (x === FRESH_STRING) return 's:__fresh__';
  try {
    return typeof x + ':' + JSON.stringify(x);
  } catch {
    return typeof x + ':<unserializable>';
  }
}

/**
 * Compute the representative probe values for one field from the conjunction of `where` conditions on
 * it. The result is finite and distinguishing for the decided fragment. The caller adds an `absent`
 * representative separately (to probe `exists` and the params-absent fail-closed semantics).
 */
export function fieldProbes(conditions: readonly Condition[]): unknown[] {
  const literals: unknown[] = [];
  const thresholds: number[] = [];
  const prefixes: string[] = [];
  let hasNumericOp = false;

  for (const c of conditions) {
    // Group conditions (all_of/any_of/not) are flattened to their leaves upstream by `collectProbes`;
    // a cross-field `ref` relation is undecidable and also handled upstream. Skip either here.
    if (!isLeafCondition(c) || c.ref !== undefined) continue;
    const v = c.value;
    switch (c.op) {
      case 'eq':
      case 'ne':
        literals.push(v);
        if (isFiniteNumber(v)) {
          thresholds.push(v);
          hasNumericOp = true;
        }
        break;
      case 'in':
      case 'nin':
        if (Array.isArray(v)) {
          for (const x of v) {
            literals.push(x);
            if (isFiniteNumber(x)) {
              thresholds.push(x);
              hasNumericOp = true;
            }
          }
        }
        break;
      case 'lt':
      case 'lte':
      case 'gt':
      case 'gte':
        if (isFiniteNumber(v)) {
          thresholds.push(v);
          hasNumericOp = true;
        }
        break;
      case 'prefix':
      case 'like':
      case 'matches':
      case 'is_a':
        // The literal and a strictly-extending variant give the enumerator something to hit; the op
        // itself is flagged undecidable, so the verdict fails safe regardless.
        if (typeof v === 'string') {
          literals.push(v);
          if (c.op === 'prefix') prefixes.push(v);
        }
        break;
      case 'member_of':
        if (typeof v === 'string') literals.push(v);
        else if (Array.isArray(v)) for (const x of v) if (typeof x === 'string') literals.push(x);
        break;
      case 'exists':
      default:
        break;
    }
  }

  const out: unknown[] = [];
  const seen = new Set<string>();
  const add = (x: unknown): void => {
    const k = valueKey(x);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(x);
    }
  };

  for (const l of literals) add(l);
  for (const n of numericCellReps(thresholds)) add(n);
  for (const p of prefixes) {
    add(p);
    add(p + 'x'); // a value strictly extending the prefix (distinguishes prefix from exact)
  }
  add(FRESH_STRING); // a value matching no eq/in/prefix literal
  if (hasNumericOp && thresholds.length > 0) {
    const mx = Math.max(...thresholds);
    if (Number.isFinite(mx)) add(mx + 1); // a value above every numeric threshold
  }
  return out;
}

// ---- standalone numeric-conjunction satisfiability (documented interval engine) ------------------

export interface NumInterval {
  lo: number;
  loInclusive: boolean;
  hi: number;
  hiInclusive: boolean;
}

export const FULL_INTERVAL: NumInterval = { lo: -Infinity, loInclusive: false, hi: Infinity, hiInclusive: false };

/** Tighten an interval by one numeric condition. Returns the same interval for non-numeric operands. */
export function tightenInterval(iv: NumInterval, op: ConditionOp, value: unknown): NumInterval {
  if (!isFiniteNumber(value)) return iv;
  const next: NumInterval = { ...iv };
  switch (op) {
    case 'eq':
      if (value > next.lo || (value === next.lo && !next.loInclusive)) {
        next.lo = value;
        next.loInclusive = true;
      }
      if (value < next.hi || (value === next.hi && !next.hiInclusive)) {
        next.hi = value;
        next.hiInclusive = true;
      }
      break;
    case 'gte':
      // A stricter existing lower bound (gt at the same value) is kept; only a higher value binds.
      if (value > next.lo) {
        next.lo = value;
        next.loInclusive = true;
      }
      break;
    case 'gt':
      if (value > next.lo || (value === next.lo && next.loInclusive)) {
        next.lo = value;
        next.loInclusive = false;
      }
      break;
    case 'lte':
      if (value < next.hi) {
        next.hi = value;
        next.hiInclusive = true;
      }
      break;
    case 'lt':
      if (value < next.hi || (value === next.hi && next.hiInclusive)) {
        next.hi = value;
        next.hiInclusive = false;
      }
      break;
    default:
      break;
  }
  return next;
}

/** An interval is empty iff lo > hi, or lo == hi with either bound exclusive. */
export function intervalEmpty(iv: NumInterval): boolean {
  if (iv.lo > iv.hi) return true;
  if (iv.lo === iv.hi) return !(iv.loInclusive && iv.hiInclusive);
  return false;
}

/**
 * Decide whether the numeric subset of a field's `where` conjunction is satisfiable. Detects, e.g.,
 * `amount >= 100 AND amount <= 10` as unsatisfiable (empty interval). Conditions with non-numeric or
 * `ref` operands, and boolean groupings (all_of/any_of/not), do not participate (they are decided by
 * the finite-set / enumeration path); ignoring them only ever widens the interval, so a satisfiable
 * verdict here is sound as a necessary condition.
 */
export function numericConjunctionSatisfiable(conditions: readonly Condition[]): boolean {
  let iv = FULL_INTERVAL;
  for (const c of conditions) {
    if (!isLeafCondition(c) || c.ref !== undefined) continue;
    iv = tightenInterval(iv, c.op, c.value);
  }
  return !intervalEmpty(iv);
}
