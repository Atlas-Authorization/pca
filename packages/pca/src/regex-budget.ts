import { setRegexCacheSourceProvider } from './regex-cache';
import { compileSafeRegexCached } from './safe-regex';

/**
 * R4-05: per-DOCUMENT regex work budget.
 *
 * `safe-regex.ts` bounds ONE match (2M steps, 4096 instructions). The number of patterns per verification is bounded
 * only by document size, so a 30 KB envelope of 152 admitted patterns still blocked the event loop for 140-190 ms.
 * A scope (opened by `decide`, `evaluatePredicates`, `evaluateCaveats`, `predicateMatches`, `evaluateConditionTri`)
 * sums, across EVERY `re:` resource pattern and `matches` condition evaluated inside it: the number of regex
 * evaluations, the pattern source size, and the worst-case NFA steps (instructions x (subject length + 1), the same
 * bound `runSafeRegex` enforces). Charging happens BEFORE matching; once any cap is exceeded, every further regex
 * evaluation in the scope is refused (the caller treats it as no-match / unknown, i.e. fail closed). The charge is a
 * pure function of the document and the subject (never of timing), so the outcome is deterministic.
 *
 * The scope is a synchronous module-level slot: it must only be opened around synchronous code (it is, everywhere).
 */
export const MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64;
export const MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192;
export const MAX_REGEX_STEPS_PER_DOCUMENT = 5_000_000;

/** A request-level budget (see {@link RegexBudget.request}) allows this many documents' worth of regex work in total. */
export const REGEX_REQUEST_SCALE = 4;

/**
 * R5-API-01: the budget is an OBJECT. There are two layers:
 *  - a DOCUMENT budget (opened by every library entry point: `decide`, `evaluatePredicates`, `evaluateCaveats`,
 *    `predicateMatches`, `evaluateConditionTri`, `checkProhibitions`, `checkContract`): the per-document caps above, fresh per
 *    document so a verdict is a pure function of (document, subject) and a verifier recomputing it gets the same answer;
 *  - an optional REQUEST budget (`RegexBudget.request()`, `budget.run(fn)`), opened by the server once per HTTP request: every
 *    document budget opened inside it ALSO charges the request budget, whose caps are {@link REGEX_REQUEST_SCALE} documents'
 *    worth. A constitution with 256 invariants therefore shares ONE document budget (not one per invariant), and N documents
 *    in one request cannot exceed the request cap.
 * Every `matches` / `re:` evaluation calls {@link chargeRegex}; outside ANY scope it is charged to a fresh single-use
 * budget (never "unbudgeted"), so a caller that forgets to open a scope is still bounded to one budget's worth per call.
 */
export class RegexBudget {
  evaluations = 0;
  chars = 0;
  steps = 0;
  /** Number of evaluations refused so far (a veto/guard must treat a refusal as "could not decide", fail closed). */
  refusals = 0;

  constructor(
    private readonly scale = 1,
    private readonly parent: RegexBudget | null = null,
    readonly isDocument = true,
    /** R5-API-05/06: the request's source (the server's client key), used for per-source admission to the regex cache. */
    readonly source: string | null = null,
  ) {}

  /** The enclosing budget this one also charges (null for a top-level budget). */
  get parentBudget(): RegexBudget | null {
    return this.parent;
  }

  /**
   * A request-scoped budget: run the request's synchronous regex-evaluating sections through `.run`. `source` (optional) is
   * the request's client key; compiled patterns first seen in this request count against that source's regex-cache share.
   */
  static request(source?: string | null): RegexBudget {
    return new RegexBudget(REGEX_REQUEST_SCALE, null, false, source ?? null);
  }

  /** Charge one evaluation of `src` against a subject of `subjectLen` chars; false = refused (caller must NOT match). */
  charge(src: string, subjectLen: number): boolean {
    const len = progLen(src);
    if (len === null) {
      this.refusals++;
      return false;
    }
    const ev = this.evaluations + 1;
    const chars = this.chars + src.length;
    const steps = this.steps + len * (subjectLen + 1);
    const k = this.scale;
    if (
      ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT * k ||
      chars > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT * k ||
      steps > MAX_REGEX_STEPS_PER_DOCUMENT * k ||
      (this.parent !== null && !this.parent.charge(src, subjectLen))
    ) {
      // Poison the budget so a later, cheaper pattern cannot sneak in after an over-budget one (order-independent refusal).
      this.evaluations = MAX_REGEX_EVALUATIONS_PER_DOCUMENT * k + 1;
      this.refusals++;
      return false;
    }
    this.evaluations = ev;
    this.chars = chars;
    this.steps = steps;
    return true;
  }

  /** Make this the open scope for the synchronous `fn` (restores the previous scope afterwards). */
  run<T>(fn: () => T): T {
    const prev = current;
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- not a closure alias: installing this budget as the module's open scope is the point of run()
    current = this;
    try {
      return fn();
    } finally {
      current = prev;
    }
  }
}

let current: RegexBudget | null = null;
let provider: (() => RegexBudget | null) | null = null;

/**
 * Install an AMBIENT request-budget provider (the server passes `() => asyncLocalStorage.getStore() ?? null`). Every document
 * budget opened with no explicit enclosing scope chains to it, so a server can bound ALL regex work of an HTTP request without
 * threading a budget through each call (the module slot itself is synchronous and cannot span an `await`). `null` uninstalls.
 */
export function setRegexBudgetProvider(fn: (() => RegexBudget | null) | null): void {
  provider = fn;
}

function ambient(): RegexBudget | null {
  if (current !== null) return current;
  try {
    return provider === null ? null : provider();
  } catch {
    return null;
  }
}
/** R5-API-05/06: the program length comes from the shared bounded compiled-regex cache (no second clear-on-full map). */
function progLen(src: string): number | null {
  const c = compileSafeRegexCached(src);
  return c === null ? null : c.program.length;
}

/** The source (client key) of the innermost open budget, walking document budgets up to the request budget. */
function currentRegexSource(): string | null {
  for (let b: RegexBudget | null = current ?? ambient(); b !== null; b = b.parentBudget) {
    if (b.source !== null) return b.source;
  }
  return null;
}
setRegexCacheSourceProvider(currentRegexSource);

/**
 * Run `fn` as ONE document. With an explicit `budget` it runs inside that budget. Otherwise: if a document scope is already
 * open it joins it (nested evaluators share the document's caps); else it opens a fresh document budget, chained to the
 * enclosing request budget if there is one.
 */
export function withRegexBudget<T>(fn: () => T, budget?: RegexBudget): T {
  if (budget !== undefined) return budget.run(fn);
  if (current !== null && current.isDocument) return fn();
  return new RegexBudget(1, ambient(), true).run(fn);
}

/** The open scope's refusal count (0 outside a scope). A before/after difference tells a guard that a match was REFUSED. */
export function regexRefusals(): number {
  return current === null ? 0 : current.refusals;
}

/**
 * Charge one regex evaluation (pattern `src` against a subject of `subjectLen` chars) to the open scope. Returns false
 * when it would exceed the document budget (the caller must NOT run the match). Outside any scope the evaluation is
 * charged to a fresh single-use budget (so it is still bounded; it just shares nothing).
 */
export function chargeRegex(src: string, subjectLen: number): boolean {
  return (current ?? new RegexBudget(1, ambient(), true)).charge(src, subjectLen);
}
