import type { CorpusItem } from './corpus';
import { isObj, sameJson, type Json } from './util';

/**
 * pass         the driver gave the expected answer
 * refused      the item needs a suite the driver does not declare and the driver refused it the way the rule requires
 * unsupported  the driver does not implement this kind of item (it answered with something that is not this kind's shape)
 * fail         wrong answer, or an answer that fails closed the wrong way
 * fault        no usable answer: the driver hung, crashed or never answered (set by the runner, never by `judge`)
 */
export type Outcome = 'pass' | 'refused' | 'unsupported' | 'fail' | 'fault';
export const PASSING: ReadonlySet<Outcome> = new Set<Outcome>(['pass', 'refused']);
export interface Verdict {
  outcome: Outcome;
  why?: string;
}
const pass = (): Verdict => ({ outcome: 'pass' });
const fail = (why: string): Verdict => ({ outcome: 'fail', why });
const unsupported = (why: string): Verdict => ({ outcome: 'unsupported', why });

/** What a driver that does not answer the `suites` query is assumed to implement. */
export const LEGACY_SUITES: readonly string[] = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'];

const CHECK_ORDER = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format', 'intent'];
const PRE_INTENT = CHECK_ORDER.slice(0, 9);
const firstFailed = (checks: Json, order: string[] = CHECK_ORDER): string | null => (isObj(checks) ? order.find((k) => k in checks && checks[k] === false) ?? null : null);
const onlyWireFalse = (r: Json): boolean => isObj(r) && r.allow === false && isObj(r.checks) && Object.keys(r.checks).length === 1 && r.checks.wire === false;
const short = (v: unknown): string => String(typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 80);
const isFlagged = (a: Json): boolean => typeof a.unsupported_suite === 'string' && a.unsupported_suite.includes('unsupported_suite');

/** The suites a driver declares: its manifest when it is a valid one, otherwise the legacy set. */
export function declaredSuites(answer: Json, registered: readonly string[]): Set<string> {
  const reg = new Set(registered);
  const s = answer?.suites;
  if (Array.isArray(s) && s.every((x) => typeof x === 'string')) return new Set((s as string[]).filter((x) => reg.has(x)));
  return new Set(LEGACY_SUITES);
}

function compareVerdict(expect: Json, a: Json): string | null {
  if (a.allow !== expect.allow) return `allow: expected ${expect.allow}, got ${a.allow}`;
  const ef = firstFailed(expect.checks);
  const af = firstFailed(a.checks);
  if (ef !== af) return `first failed check: expected ${ef}, got ${af}`;
  for (const [k, v] of Object.entries(expect.checks as Record<string, Json>)) {
    if (a.checks[k] !== v) return `check ${k}: expected ${v}, got ${short(a.checks[k])}`;
  }
  return null;
}

function judgeVerify(item: CorpusItem, a: Json, declared: Set<string>): Verdict {
  if (item.soft && item.expect.allow === false && typeof a.error === 'string' && a.allow === undefined) return pass();
  if (typeof a.allow !== 'boolean' || !isObj(a.checks)) return fail(typeof a.error === 'string' ? `driver error: ${short(a.error)}` : 'no verdict (allow and checks missing)');
  const missing = (item.suites ?? []).filter((s) => !declared.has(s));
  const flagged = isFlagged(a);
  if (missing.length) {
    // A suite the driver does not declare must be refused: never accepted, never silently mis-verified.
    const e = item.expect;
    const early = e.allow === false && a.allow === false && firstFailed(e.checks, PRE_INTENT) !== null && firstFailed(e.checks, PRE_INTENT) === firstFailed(a.checks, PRE_INTENT);
    const ok = a.allow === false && (flagged || (onlyWireFalse(e) && onlyWireFalse(a)) || early);
    return ok ? { outcome: 'refused' } : fail(`needs undeclared suite ${missing.join(',')} and was not refused`);
  }
  if (flagged && item.expect.allow !== false) return fail('refused with unsupported_suite although every suite it needs is declared');
  const why = compareVerdict(item.expect, a);
  return why === null ? pass() : fail(why);
}

function judgeChain(item: CorpusItem, a: Json, declared: Set<string>): Verdict {
  if (item.soft && item.expect.ok === false && typeof a.error === 'string' && a.allow === undefined) return pass();
  if (typeof a.allow !== 'boolean') return fail(typeof a.error === 'string' ? `driver error: ${short(a.error)}` : 'no verdict');
  const missing = (item.suites ?? []).filter((s) => !declared.has(s));
  if (missing.length) return a.allow === false ? { outcome: 'refused' } : fail(`needs undeclared suite ${missing.join(',')} and was accepted`);
  return a.allow === item.expect.ok ? pass() : fail(`allow: expected ${item.expect.ok}, got ${a.allow}`);
}

function judgeCanon(item: CorpusItem, a: Json): Verdict {
  const e = item.expect;
  if (e.accept) {
    if (typeof a.canon !== 'string') return fail('rejected a document the strict profile accepts');
    return a.canon === e.canon ? pass() : fail('canonical form differs');
  }
  return a.canon === undefined ? pass() : fail('accepted a document the strict profile rejects');
}

function judgePolicy(item: CorpusItem, a: Json): Verdict {
  if (typeof a.allow !== 'boolean' || !Array.isArray(a.failed)) {
    return typeof a.error === 'string' && a.error.startsWith('exception') ? fail(`driver error: ${short(a.error)}`) : unsupported('no policy answer');
  }
  if (!sameJson({ allow: a.allow, failed: a.failed }, item.expect.caveats)) return fail('caveat projection differs');
  if (a.decision !== undefined && !sameJson(a.decision, item.expect.decision)) return fail('policy decision differs');
  return pass();
}

function judgeProduce(item: CorpusItem, a: Json, declared: Set<string>): Verdict {
  const want = item.expect;
  if (a.out === undefined && typeof a.error !== 'string') return unsupported('no producer answer');
  if (typeof a.error === 'string' && (a.error.startsWith('unsupported_op') || a.error.includes('unsupported_suite'))) {
    const missing = (item.suites ?? []).filter((s) => !declared.has(s));
    return missing.length ? { outcome: 'refused' } : unsupported(short(a.error));
  }
  if (isObj(want) && want.error !== undefined && Object.keys(want).length === 1) {
    if (typeof a.error !== 'string') return fail('produced an artifact the reference refuses');
    const op = item.produce?.op;
    if ((op === 'parse_limit' || op === 'compile_policy') && a.error !== want.error) return fail(`error text: ${short(a.error)}`);
    return pass();
  }
  if (typeof a.error === 'string') return fail(`driver error: ${short(a.error)}`);
  // `act` carries a threshold message that only some producers emit; it is not part of the comparison
  const drop = (v: Json): Json => {
    if (item.produce?.op === 'act' && isObj(v)) {
      const { threshold_message: _t, ...rest } = v;
      return rest;
    }
    return v;
  };
  return sameJson(drop(a.out), drop(want)) ? pass() : fail('output differs from the reference');
}

function judgeStateful(item: CorpusItem, a: Json): Verdict {
  if (!Array.isArray(a.steps)) return typeof a.error === 'string' && a.error.startsWith('exception') ? fail(`driver error: ${short(a.error)}`) : unsupported('no stateful answer');
  const want = item.expect.steps as Json[];
  if (a.steps.length !== want.length) return fail(`${a.steps.length} step results for ${want.length} steps`);
  for (let i = 0; i < want.length; i++) {
    const w = want[i];
    const g = a.steps[i];
    if (w === null) {
      if (g !== null) return fail(`step ${i}: a revoke step has no result`);
      continue;
    }
    if (!isObj(g) || g.allow !== w.allow || !Array.isArray(g.failed) || !sameJson([...g.failed].sort(), [...(w.failed as string[])].sort())) return fail(`step ${i}: result differs`);
  }
  return pass();
}

function judgeSuites(a: Json, registered: readonly string[]): Verdict {
  if (!Array.isArray(a.suites)) return unsupported('no suite manifest');
  const s = a.suites as unknown[];
  if (!s.every((x) => typeof x === 'string')) return fail('manifest has a non-string entry');
  if (new Set(s).size !== s.length) return fail('manifest lists a suite twice');
  const reg = new Set(registered);
  const unknown = (s as string[]).filter((x) => !reg.has(x));
  if (unknown.length) return fail(`manifest names unregistered suite(s): ${unknown.join(',')}`);
  return s.includes('ed25519') ? pass() : fail('manifest does not declare ed25519');
}

/** Judge one driver answer against the item's expectation. `declared` is the driver's suite manifest. Pure and deterministic. */
export function judge(item: CorpusItem, answer: Json, declared: Set<string>, registered: readonly string[]): Verdict {
  if (!isObj(answer)) return fail('answer is not a JSON object');
  switch (item.kind) {
    case 'verify': return judgeVerify(item, answer, declared);
    case 'chain': return judgeChain(item, answer, declared);
    case 'canon': return judgeCanon(item, answer);
    case 'policy': return judgePolicy(item, answer);
    case 'produce': return judgeProduce(item, answer, declared);
    case 'stateful': return judgeStateful(item, answer);
    case 'suites': return judgeSuites(answer, registered);
    default: return fail('unknown item kind');
  }
}
