import {
  artifactRef,
  artifactSuiteError,
  closedMembers,
  INTENT_NAME_RE,
  isBoundedString,
  isDigest,
  isParamPath,
  isPlainObject,
  isClock,
  isSafeInt,
  nullRecord,
  ownGet,
  pinPqOk,
  resolveParamPath,
  SUITE_MEMBERS,
  signArtifact,
  verifyArtifactSig,
} from './intent-artifacts';
import { decideOfferSet, validateOfferPolicy, type OfferPolicy } from './offer-set';
import type { SignerSuiteOpts } from './pq';

/**
 * WORLD DIMENSIONS FROM SIGNED ORACLE FACTS, RELATIONAL DIMENSIONS, AND THE OFFER-SET OPTIMALITY DIMENSION
 * (Intent Layer v2 §2.6, §3.6, §3.13; T19, T25; NORMATIVE conformance rule 16, `primitives.intent_world`).
 *
 * A fact is a signed statement by an oracle key about a subject ("the fare of OF-2 is 39800", "the fraud flag of
 * customer c_9 is 0", "the tier of c_9 is gold"). The verifier fills `env.world.<name>` from facts at ACTION time,
 * so a grant never bakes in a stale value. Fail closed: a world dimension without enough fresh facts has no value,
 * which is a deny (the ⊠ cell of §2.3), never "unknown means allowed".
 *
 * ROBUSTNESS (T19). With n_w >= 2·f_w + 1 fresh facts from DISTINCT pinned oracles of which at most f_w lie, the
 * LOWER MEDIAN (index ⌊(n−1)/2⌋ of the ascending values) lies between the smallest and the largest honest value: at
 * least ⌊(n−1)/2⌋+1 >= f_w+1 values are <= it and at least n−⌊(n−1)/2⌋ >= f_w+1 are >= it, so each side contains an
 * honest value. String-valued facts (categorical worlds such as a tier) must ALL agree: with >= f_w+1 facts that
 * includes an honest one, so the value is an honest value. A world with min_oracles = 1 is `single_source`: one
 * compromised key moves it arbitrarily (the result reports it so friction can be raised, §3.6).
 *
 * WIRE `pca-fact` v1 (closed member set): v: 1, kind: "pca-fact", name (a world name, `^[a-z][a-z0-9_]{0,63}$`),
 * subject (string <= 256 B), value (safe integer or string <= 256 B), t_obs (safe integer >= 0, ms), oracle (kid,
 * string <= 64 B), sig, and the optional suite members alg / pq_pk / pq_sig. Signature domain `atlas-pca/fact/v1\0` over
 * strictCanonical(fact without sig / pq_sig) under the signer PINNED for (name, oracle) (`{kid, pk, pq_pk?}`); reference
 * `atlas-pca/fact-ref/v1`, slot `f` (`intent-artifacts.ts`).
 *
 * RELATIONAL dimensions are fixed integer functions of action parameters and earlier world values:
 *   sub(a, b)       = a − b                          (must be a safe integer)
 *   ratio_ppm(a, b) = ⌊a · 10^6 / b⌋ with b > 0, a >= 0 (exact integer arithmetic; must be a safe integer)
 * Operands are `action.params.*` paths or `env.world.<name>` of a world or relational dimension listed EARLIER.
 */

export const FACT_DOMAIN = 'atlas-pca/fact/v1\0';
export const FACT_REF_DOMAIN = 'atlas-pca/fact-ref/v1';
export const MAX_COMMITTED_FACTS = 16;
export const MAX_WORLDS = 16;
export const MAX_RELATIONAL = 16;
/** Default clock skew the verifier tolerates on `t_obs` / `issued_at` in the future. */
export const DEFAULT_WORLD_SKEW_MS = 60_000;

export interface PcaFact {
  v: 1;
  kind: 'pca-fact';
  name: string;
  subject: string;
  value: number | string;
  t_obs: number;
  oracle: string;
  alg?: string;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}

export interface WorldPolicy {
  name: string;
  /** Path (rooted at `action.` / `action.params.`) whose STRING value is the subject every fact must name. */
  subject_path: string;
  oracles: { kid: string; pk: string; pq_pk?: string }[];
  freshness_ms: number;
  /** n_w: fresh facts from distinct oracles required. */
  min_oracles: number;
  /** f_w: tolerated faulty oracles; the policy needs min_oracles >= 2·max_faulty + 1. */
  max_faulty: number;
}

export interface RelationalPolicy {
  name: string;
  fn: 'sub' | 'ratio_ppm';
  a: string;
  b: string;
}

/** Rule 16 verifier policy (from the schema's world block and the site's `oracles` policy). */
export interface IntentWorldPolicy {
  skew_ms?: number;
  worlds?: WorldPolicy[];
  relational?: RelationalPolicy[];
  offers?: OfferPolicy;
}

export interface IntentWorldInput {
  now: number;
  aud: string;
  /** σ_id (b64u 32): `intent_session.session`. */
  session: string;
  action: { verb: string; resource: string; params?: Record<string, unknown> };
  /** The signed commitments of `intent_session`: `facts` digests and the optional `offer_set` digest (absent = {}). */
  committed?: { facts?: unknown; offer_set?: unknown };
  /** The facts and the offer set, delivered alongside the PCActn (unsigned transport; bound by `committed`). */
  facts?: unknown[];
  offer_set?: unknown;
  policy: IntentWorldPolicy;
}

export type IntentWorldDecision =
  | { ok: true; world: Record<string, number | string>; single_source: string[] }
  | { ok: false; reason: string };

/** Wire validation of a fact. Null = well-formed. */
export function validateFactWire(f: unknown): string | null {
  if (!isPlainObject(f)) return 'fact must be an object';
  const m = closedMembers(f, ['v', 'kind', 'name', 'subject', 'value', 't_obs', 'oracle', 'sig'], SUITE_MEMBERS, 'fact');
  if (m) return m;
  if (f.v !== 1 || f.kind !== 'pca-fact') return 'fact must be {v: 1, kind: "pca-fact"}';
  if (typeof f.name !== 'string' || !INTENT_NAME_RE.test(f.name)) return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$";
  if (!isBoundedString(f.subject, 256)) return "'fact.subject' must be a non-empty string (<= 256 bytes)";
  if (!isSafeInt(f.value) && !isBoundedString(f.value, 256)) return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)";
  if (!isSafeInt(f.t_obs) || f.t_obs < 0) return "'fact.t_obs' must be a non-negative safe integer";
  if (!isBoundedString(f.oracle, 64)) return "'fact.oracle' must be a non-empty string (<= 64 bytes)";
  if (typeof f.sig !== 'string') return "'fact.sig' must be a string";
  return null;
}

/** Sign a fact (oracle side; `suite` for a post-quantum or hybrid signature). */
export function signFact(body: Omit<PcaFact, 'v' | 'kind' | 'sig' | 'alg' | 'pq_pk' | 'pq_sig'>, secretKey: Uint8Array, suite?: SignerSuiteOpts): PcaFact {
  return signArtifact(FACT_DOMAIN, { v: 1, kind: 'pca-fact', ...body }, secretKey, suite) as unknown as PcaFact;
}

/** The content address committed in `intent_session.facts[]`. */
export function factRef(f: PcaFact): string {
  return artifactRef(FACT_REF_DOMAIN, 'f', f);
}

/** The lower median of a non-empty list of integers (index ⌊(n−1)/2⌋ ascending). */
export function lowerMedian(xs: readonly number[]): number {
  if (xs.length === 0) throw new Error('lowerMedian: empty');
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor((s.length - 1) / 2)]!;
}

/** ⌊a·10^6 / b⌋ exactly (BigInt), or null when b <= 0, a < 0 or the result is not a safe integer. */
export function ratioPpm(a: number, b: number): number | null {
  if (!isSafeInt(a) || !isSafeInt(b) || !(b > 0) || a < 0) return null; // never BigInt(non-integer): that throws
  const q = (BigInt(a) * 1_000_000n) / BigInt(b);
  return q <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(q) : null;
}

/** Policy sanity (rule 16 step 0). Null = well-formed. */
export function validateWorldPolicy(p: IntentWorldPolicy): string | null {
  if (!isPlainObject(p)) return 'world policy must be an object';
  // Closed member sets everywhere (README "closed and typed"): an unknown member is malformed.
  const cm = closedMembers(p, [], ['skew_ms', 'worlds', 'relational', 'offers'], 'policy');
  if (cm) return cm;
  if (p.skew_ms !== undefined && (!isSafeInt(p.skew_ms) || p.skew_ms < 0)) return 'skew_ms must be a non-negative safe integer';
  const names = new Set<string>();
  const claim = (n: unknown): string | null => {
    if (typeof n !== 'string' || !INTENT_NAME_RE.test(n)) return `dimension name '${String(n)}' must match ^[a-z][a-z0-9_]{0,63}$`;
    if (names.has(n)) return `duplicate dimension name '${n}'`;
    names.add(n);
    return null;
  };
  const worlds = p.worlds === undefined ? [] : p.worlds; // absent = []; null or any non-array is malformed
  if (!Array.isArray(worlds) || worlds.length > MAX_WORLDS) return `worlds must be a list of at most ${MAX_WORLDS}`;
  for (const w of worlds) {
    if (!isPlainObject(w)) return 'world entry must be an object';
    const wm = closedMembers(w, ['name', 'subject_path', 'oracles', 'freshness_ms', 'min_oracles', 'max_faulty'], [], 'world');
    if (wm) return wm;
    const e = claim(w.name);
    if (e) return e;
    if (typeof w.subject_path !== 'string' || !w.subject_path.startsWith('action.')) return `world '${w.name}': subject_path must be rooted at action.`;
    if (!isSafeInt(w.freshness_ms) || w.freshness_ms < 0) return `world '${w.name}': freshness_ms must be a non-negative safe integer`;
    if (!isSafeInt(w.max_faulty) || w.max_faulty < 0) return `world '${w.name}': max_faulty must be a non-negative safe integer`;
    if (!isSafeInt(w.min_oracles) || w.min_oracles < 2 * w.max_faulty + 1) return `world '${w.name}': min_oracles must be a safe integer >= 2*max_faulty+1`;
    if (!Array.isArray(w.oracles) || w.oracles.length < w.min_oracles) return `world '${w.name}': fewer pinned oracles than min_oracles`;
    const kids = new Set<string>();
    for (const o of w.oracles) {
      if (!isPlainObject(o) || closedMembers(o, ['kid', 'pk'], ['pq_pk'], 'oracle') !== null || !isBoundedString(o.kid, 64) || !isDigest(o.pk) || !pinPqOk(o.pq_pk) || kids.has(o.kid)) return `world '${w.name}': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk`;
      kids.add(o.kid);
    }
  }
  const rel = p.relational === undefined ? [] : p.relational;
  if (!Array.isArray(rel) || rel.length > MAX_RELATIONAL) return `relational must be a list of at most ${MAX_RELATIONAL}`;
  for (const r of rel) {
    if (!isPlainObject(r)) return 'relational entry must be an object';
    const rm = closedMembers(r, ['name', 'fn', 'a', 'b'], [], 'relational');
    if (rm) return rm;
    const e = claim(r.name);
    if (e) return e;
    if (r.fn !== 'sub' && r.fn !== 'ratio_ppm') return `relational '${r.name}': fn must be "sub" or "ratio_ppm"`;
    for (const op of [r.a, r.b]) {
      const ok = isParamPath(op) || (typeof op === 'string' && op.startsWith('env.world.') && names.has(op.slice('env.world.'.length)) && op.slice('env.world.'.length) !== r.name);
      if (!ok) return `relational '${r.name}': operand '${String(op)}' must be an action.params path or an earlier env.world dimension`;
    }
  }
  const offers = (p as IntentWorldPolicy).offers;
  if (offers !== undefined) {
    const e = validateOfferPolicy(offers) ?? claim(offers.name);
    if (e) return e;
  }
  return null;
}

/**
 * Is the rule-16 check active (the verdict reports it)? Iff `committed.facts` is a non-empty ARRAY, `committed.offer_set`
 * is a STRING, `policy.worlds` or `policy.relational` is a non-empty ARRAY, or `policy.offers` is a plain object. Strict
 * type checks: an object with its own `length` member is not an array, so it never makes the check active.
 */
export function intentWorldActive(input: { committed?: unknown; policy?: unknown }): boolean {
  if (!isPlainObject(input)) return false; // total: a non-object input has no members
  const c: Record<string, unknown> = isPlainObject(input.committed) ? input.committed : {};
  const p: Record<string, unknown> = isPlainObject(input.policy) ? input.policy : {};
  const nonEmpty = (x: unknown) => Array.isArray(x) && x.length > 0;
  return nonEmpty(ownGet(c, 'facts')) || typeof ownGet(c, 'offer_set') === 'string' || nonEmpty(ownGet(p, 'worlds')) || nonEmpty(ownGet(p, 'relational')) || isPlainObject(ownGet(p, 'offers'));
}

function subjectOf(action: IntentWorldInput['action'], params: Record<string, unknown>, path: string): string | null {
  if (path === 'action.resource') return typeof action.resource === 'string' ? action.resource : null;
  if (path === 'action.verb') return typeof action.verb === 'string' ? action.verb : null;
  const r = resolveParamPath(params, path);
  return r.found && typeof r.value === 'string' ? r.value : null;
}

/**
 * NORMATIVE rule 16 (`facts`): compute `env.world` for one action. First failure wins:
 *   0. policy sanity ({@link validateWorldPolicy}); ABSENT optional members are empty / default, PRESENT ones of the
 *      wrong JSON type (`null` included) fail: `policy`, `committed`, `committed.facts`, `facts`, `offer_set`,
 *      `action.params`, and every optional policy member;
 *   1. `committed.facts` (absent = []) is a list of at most 16 distinct canonical 32-byte digests; `committed.offer_set`,
 *      when present, is a canonical 32-byte digest;
 *   2. every committed fact digest is the reference of a SUPPLIED fact (supplied facts nobody committed are ignored);
 *   3. for each committed fact in committed order: its suite members (`unsupported_suite` for a suite this verifier
 *      does not implement); its `name` is a declared world; its `oracle` kid is
 *      pinned for that world; the signature verifies under the pinned key; its `subject` equals the action's subject
 *      for the world (the string at `subject_path`); no second fact for the same (name, oracle);
 *   4. for each world in policy order: the FRESH facts (t_obs <= now + skew and now − t_obs <= freshness_ms; stale or
 *      future facts are not counted, never an error; a `now` that is not a safe integer makes every fact stale) number at least min_oracles; all integers → the lower median;
 *      all strings → they must all be equal; a mix fails;
 *   5. each relational dimension in policy order (operands must resolve to safe integers);
 *   6. the offer set, when the policy has `offers` (see `decideOfferSet`): world[offers.name] = excess.
 * On success `world` maps every declared name to its value and `single_source` lists the worlds with min_oracles = 1.
 * Never throws.
 */
export function decideIntentWorld(input: IntentWorldInput): IntentWorldDecision {
  const fail = (reason: string): IntentWorldDecision => ({ ok: false, reason: `facts: ${reason}` });
  try {
    if (!isPlainObject(input)) return fail('input must be an object');
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail closed.
    const policy = input.policy === undefined ? {} : input.policy;
    const pe = validateWorldPolicy(policy);
    if (pe) return fail(`policy misconfigured (fail closed): ${pe}`);
    const skew = policy.skew_ms ?? DEFAULT_WORLD_SKEW_MS;
    if (!isPlainObject(input.action)) return fail('action must be an object');
    const params = input.action.params === undefined ? {} : input.action.params;
    if (!isPlainObject(params)) return fail('action.params must be an object');
    const committed = input.committed === undefined ? {} : input.committed;
    if (!isPlainObject(committed)) return fail('committed must be an object');
    const committedFacts = committed.facts === undefined ? [] : committed.facts;
    if (!Array.isArray(committedFacts) || committedFacts.length > MAX_COMMITTED_FACTS) return fail(`committed facts must be a list of at most ${MAX_COMMITTED_FACTS} digests`);
    const seenDigest = new Set<string>();
    for (const d of committedFacts) {
      if (!isDigest(d)) return fail('a committed fact digest is not canonical base64url (32 bytes)');
      if (seenDigest.has(d)) return fail('duplicate committed fact digest');
      seenDigest.add(d);
    }
    const committedOffer = committed.offer_set;
    if (committedOffer !== undefined && !isDigest(committedOffer)) return fail('the committed offer_set is not canonical base64url (32 bytes)');

    const supplied = input.facts === undefined ? [] : input.facts;
    if (!Array.isArray(supplied)) return fail('facts must be an array');
    if (input.offer_set !== undefined && !isPlainObject(input.offer_set)) return fail('offer_set must be an object');
    const byRef = new Map<string, unknown>();
    for (const f of supplied) {
      if (validateFactWire(f) !== null) continue; // an unusable supplied fact can only matter if committed: caught at step 2
      try {
        byRef.set(factRef(f as PcaFact), f);
      } catch {
        /* not strictly canonical (e.g. a lone surrogate): it has no reference, so it can never match a commitment */
      }
    }
    const worlds = policy.worlds === undefined ? [] : policy.worlds;
    const accepted: PcaFact[] = [];
    const pairs = new Set<string>();
    for (const d of committedFacts as string[]) {
      const f = byRef.get(d);
      if (f === undefined) return fail('a committed fact was not supplied (or is malformed)');
      const fact = f as PcaFact;
      const se = artifactSuiteError(fact as unknown as Record<string, unknown>);
      if (se) return fail(`fact signature suite: ${se}`);
      const w = worlds.find((x) => x.name === fact.name);
      if (!w) return fail(`fact for undeclared world '${fact.name}'`);
      const pin = w.oracles.find((o) => o.kid === fact.oracle);
      if (!pin) return fail(`oracle '${fact.oracle}' is not pinned for world '${w.name}'`);
      if (!verifyArtifactSig(FACT_DOMAIN, fact as unknown as Record<string, unknown>, pin)) return fail(`bad oracle signature on a '${w.name}' fact`);
      const subject = subjectOf(input.action, params, w.subject_path);
      if (subject === null || fact.subject !== subject) return fail(`a '${w.name}' fact names another subject`);
      const pair = `${w.name}\u0000${fact.oracle}`;
      if (pairs.has(pair)) return fail(`two facts from oracle '${fact.oracle}' for world '${w.name}'`);
      pairs.add(pair);
      accepted.push(fact);
    }

    const world = nullRecord<number | string>();
    const singleSource: string[] = [];
    for (const w of worlds) {
      // A non-integer `now` (a string, a float, NaN) is no clock: every fact is stale (fail closed, never JS coercion).
      const now = input.now;
      const fresh = isClock(now) ? accepted.filter((f) => f.name === w.name && f.t_obs <= now + skew && now - f.t_obs <= w.freshness_ms) : [];
      if (fresh.length < w.min_oracles) return fail(`world '${w.name}' has ${fresh.length} fresh fact(s), needs ${w.min_oracles}`);
      const nums = fresh.filter((f) => typeof f.value === 'number').map((f) => f.value as number);
      if (nums.length === fresh.length) world[w.name] = lowerMedian(nums);
      else if (nums.length === 0) {
        const v = fresh[0]!.value as string;
        if (fresh.some((f) => f.value !== v)) return fail(`world '${w.name}': string facts disagree`);
        world[w.name] = v;
      } else return fail(`world '${w.name}': facts mix integer and string values`);
      if (w.min_oracles === 1) singleSource.push(w.name);
    }

    const operand = (path: string): number | null => {
      if (path.startsWith('env.world.')) {
        const v = ownGet(world, path.slice('env.world.'.length));
        return isSafeInt(v) ? v : null;
      }
      const r = resolveParamPath(params, path);
      return r.found && isSafeInt(r.value) ? r.value : null;
    };
    for (const r of policy.relational === undefined ? [] : policy.relational) {
      const a = operand(r.a);
      const b = operand(r.b);
      if (a === null || b === null) return fail(`relational '${r.name}': an operand is missing or not a safe integer`);
      const v = r.fn === 'sub' ? a - b : ratioPpm(a, b);
      if (v === null || !isSafeInt(v)) return fail(`relational '${r.name}': result undefined or outside the safe integer range`);
      world[r.name] = v;
    }

    if (policy.offers !== undefined) {
      const od = decideOfferSet({
        policy: policy.offers,
        committed: committedOffer as string | undefined,
        offerSet: input.offer_set,
        params,
        aud: input.aud,
        session: input.session,
        now: input.now,
        skewMs: skew,
      });
      if (!od.ok) return fail(od.reason);
      world[policy.offers.name] = od.excess;
    }
    return { ok: true, world, single_source: singleSource };
  } catch (e) {
    return fail(`evaluation error (fail closed): ${(e as Error).message}`);
  }
}
