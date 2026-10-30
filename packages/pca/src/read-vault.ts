/**
 * TOKENISATION VAULT and AGGREGATE READ LIMITS (K5 follow-up, C-315..C-319). Companion of readside.ts.
 *
 * VAULT. A `token` mask replaces a value with `tok_...`; the agent can pass the token to a later action and only the resource server
 * can turn it back. {@link redactReadWithVault} runs {@link redactRead} and records, for every token it minted, the class, the value and the
 * grant digest in a {@link VaultStore}. {@link detokenize} returns the value only when the same signed, unexpired, pinned-principal grant
 * allows the token's class to reach the named sink (`allow`; an `escalate` class asks), and the token was minted under THIS grant.
 * Everything else denies: unknown token, token of another grant, sink the grant does not list, class not allowed, expired grant.
 *
 * AGGREGATES. An aggregate (count or sum over rows) can leak by repetition or differencing. A signed {@link AggregateGrant} bounds it:
 * a minimum group size (k), a per-value clamp (the sensitivity), a query count cap, and an epsilon budget (integer micro-epsilon) with
 * a per-query cost. {@link aggregateRead} is a pure step over an explicit {@link AggregateState}: it charges the budget, refuses when
 * it would be exceeded (`epsilon_exhausted`), refuses groups below k (`group_too_small`) and returns the SAME answer for a repeated
 * identical query without charging again (so averaging repeated queries does not shrink the noise). With `dp: true` the answer gets
 * discrete Laplace noise drawn with an INTEGER-EXACT sampler (Canonne-Kamath-Steinke) from a stream of SHA-256 blocks: in `seeded` mode the
 * stream is keyed by the salt and the query digest, so every language produces the same bytes (the shared vectors pin them); in `secure`
 * mode (the production setting) the stream is keyed by the OS CSPRNG. Differential privacy here is the standard epsilon accounting under
 * sequential composition; it is a stated limit, not a guarantee beyond it.
 */
import { b64u, hashCanonical, decodeB64uStrict } from './hash';
import { publicKeyOf } from './keys';
import { redactRead, readGrantDigest, validReadGrantBody, READ_GRANT_DOMAIN, type ReadInput, type ReadResult, type SignedReadGrant } from './readside';
import { ID_RE, isB32, isObj, isStr, isUint, onlyKeys, own, signBody, sortedUnique, verifyBody, type K5Decision } from './workflow';

export interface VaultEntry { cls: string; value: string | number | boolean; grant: string; exp: number }
export interface VaultStore { put(token: string, e: VaultEntry): void; get(token: string): VaultEntry | undefined }
export function memoryVault(): VaultStore {
  const m = new Map<string, VaultEntry>();
  return { put: (t, e) => void m.set(t, e), get: (t) => m.get(t) };
}

/** {@link redactRead} that also records every token it minted in `store`. */
export function redactReadWithVault(inp: ReadInput, store: VaultStore): ReadResult {
  const r = redactRead(inp);
  if (r.decision !== 'allow') return r;
  const g = (inp.grant as SignedReadGrant).body;
  const digest = readGrantDigest(g);
  for (const [path, f] of Object.entries(r.fields)) {
    if (f.action === 'masked' && f.kind === 'token') {
      store.put(r.view[path] as string, { cls: f.class, value: inp.record[path] as string | number | boolean, grant: digest, exp: g.expires_at });
    }
  }
  return r;
}

export interface DetokenizeInput { grant: unknown; principal: string; now: number; sink: string; token: string; store: VaultStore }
export interface DetokenizeResult { decision: K5Decision; code: string | null; value: string | number | boolean | null }
const no = (code: string): DetokenizeResult => ({ decision: 'deny', code, value: null });

/** Turn a token back into its value, only for a sink the grant allows that token's class to reach. */
export function detokenize(inp: DetokenizeInput): DetokenizeResult {
  try {
    if (!isB32(inp.principal) || !isUint(inp.now) || typeof inp.token !== 'string' || typeof inp.sink !== 'string') return no('bad_request');
    const sg = inp.grant as SignedReadGrant;
    if (!isObj(sg) || !onlyKeys(sg, ['body', 'sig']) || !validReadGrantBody(sg.body)) return no('bad_grant');
    if (sg.body.principal !== inp.principal || !verifyBody(READ_GRANT_DOMAIN, sg.body, inp.principal, sg.sig)) return no('bad_signature');
    if (inp.now < sg.body.issued_at) return no('not_yet');
    if (inp.now >= sg.body.expires_at) return no('expired');
    const e = inp.store.get(inp.token);
    if (e === undefined || e.grant !== readGrantDigest(sg.body)) return no('unknown_token');
    if (inp.now >= e.exp) return no('expired');
    const rule = own(sg.body.sinks, inp.sink);
    if (rule === undefined) return no('unknown_sink');
    if (rule.allow.includes(e.cls)) return { decision: 'allow', code: null, value: e.value };
    if (rule.escalate.includes(e.cls)) return { decision: 'escalate', code: 'label_escalate', value: null };
    return no('label_flow');
  } catch {
    return no('bad_request');
  }
}

// ---- aggregates ----------------------------------------------------------------------------------------------------------------

export const AGGREGATE_DOMAIN = 'atlas-pca/aggregate-grant/v1\0';
const AG_REF = 'atlas-pca/aggregate-grant-ref/v1';
const AG_Q = 'atlas-pca/aggregate-query/v1';
const AG_N = 'atlas-pca/aggregate-noise/v1';

export interface AggregateRule { verb: string; resource_prefix: string; purposes: string[]; fns: ('count' | 'sum')[]; min_group: number; clamp: number; epsilon_micro: number; dp: boolean }
export interface AggregateGrantBody { v: 1; id: string; principal: string; issued_at: number; expires_at: number; rules: AggregateRule[]; epsilon_budget_micro: number; max_queries: number }
export interface SignedAggregateGrant { body: AggregateGrantBody; sig: string }
export interface AggregateState { spent_micro: number; queries: number; answered: Record<string, number> }
export const emptyAggregateState = (): AggregateState => ({ spent_micro: 0, queries: 0, answered: {} });

function validRule(r: unknown): r is AggregateRule {
  return isObj(r) && onlyKeys(r, ['verb', 'resource_prefix', 'purposes', 'fns', 'min_group', 'clamp', 'epsilon_micro', 'dp']) && isStr(r.verb, 128) && isStr(r.resource_prefix, 512) && sortedUnique(r.purposes, ID_RE, 16) && r.purposes.length > 0 &&
    sortedUnique(r.fns, /^(count|sum)$/, 2) && r.fns.length > 0 && isUint(r.min_group) && r.min_group >= 1 && isUint(r.clamp) && r.clamp <= 1_000_000 && isUint(r.epsilon_micro) && r.epsilon_micro <= 1_073_741_824 && typeof r.dp === 'boolean' && (r.dp ? r.epsilon_micro >= 1 : true);
}
export function validAggregateGrantBody(b: unknown): b is AggregateGrantBody {
  return isObj(b) && onlyKeys(b, ['v', 'id', 'principal', 'issued_at', 'expires_at', 'rules', 'epsilon_budget_micro', 'max_queries']) && b.v === 1 && typeof b.id === 'string' && ID_RE.test(b.id) && isB32(b.principal) && isUint(b.issued_at) && isUint(b.expires_at) &&
    Array.isArray(b.rules) && b.rules.length >= 1 && b.rules.length <= 16 && b.rules.every(validRule) && isUint(b.epsilon_budget_micro) && isUint(b.max_queries);
}
export const aggregateGrantDigest = (b: AggregateGrantBody): string => hashCanonical({ d: AG_REF, g: b });
export function signAggregateGrant(secret: Uint8Array, body: AggregateGrantBody): SignedAggregateGrant {
  if (!validAggregateGrantBody(body) || body.principal !== b64u(publicKeyOf(secret))) throw new RangeError('signAggregateGrant: malformed grant');
  return { body, sig: signBody(secret, AGGREGATE_DOMAIN, body) };
}

export interface AggregateInput {
  grant: unknown; principal: string; now: number; verb: string; resource: string; purpose: string; fn: 'count' | 'sum';
  /** one integer per row (the values to sum; for `count` only the number of rows matters) */
  values: number[];
  /** salt of at least 16 characters; with `noise: 'seeded'` it (and the query digest) seeds the noise */
  salt: string;
  /** `'seeded'`: deterministic noise from the salt and the query (vectors, tests, reproducible audits). `'secure'`: noise from the OS CSPRNG (PRODUCTION: the answer is then not reproducible and the salt need not stay secret). */
  noise: 'seeded' | 'secure';
  state: AggregateState;
}
export interface AggregateResult { decision: K5Decision; code: string | null; value: number | null; state: AggregateState; charged_micro: number }

/** Answer one aggregate under the grant, or refuse. The input state is never mutated. */
export function aggregateRead(inp: AggregateInput): AggregateResult {
  const fail = (code: string, s?: AggregateState): AggregateResult => ({ decision: 'deny', code, value: null, state: s ?? emptyAggregateState(), charged_micro: 0 });
  try {
    const st = inp.state;
    if (!isObj(st) || !isUint(st.spent_micro) || !isUint(st.queries) || !isObj(st.answered) || !Object.values(st.answered).every((v) => Number.isSafeInteger(v))) return fail('bad_request');
    const keep = (code: string) => fail(code, st);
    if (!isB32(inp.principal) || !isUint(inp.now)) return keep('bad_request');
    const sg = inp.grant as SignedAggregateGrant;
    if (!isObj(sg) || !onlyKeys(sg, ['body', 'sig']) || !validAggregateGrantBody(sg.body)) return keep('bad_grant');
    const g = sg.body;
    if (g.principal !== inp.principal || !verifyBody(AGGREGATE_DOMAIN, g, inp.principal, sg.sig)) return keep('bad_signature');
    if (inp.now < g.issued_at) return keep('not_yet');
    if (inp.now >= g.expires_at) return keep('expired');
    if (!isStr(inp.verb, 128) || !isStr(inp.resource, 512) || typeof inp.purpose !== 'string' || !ID_RE.test(inp.purpose) || (inp.fn !== 'count' && inp.fn !== 'sum') || (inp.noise !== 'seeded' && inp.noise !== 'secure') || typeof inp.salt !== 'string' || inp.salt.length < 16 ||
      !Array.isArray(inp.values) || inp.values.length > 1_000_000 || !inp.values.every((v) => Number.isSafeInteger(v))) return keep('bad_request');
    const rule = g.rules.find((r) => r.verb === inp.verb && inp.resource.startsWith(r.resource_prefix) && r.purposes.includes(inp.purpose));
    if (rule === undefined || !rule.fns.includes(inp.fn)) return keep('no_read_scope');
    if (inp.values.length < rule.min_group) return keep('group_too_small');
    const qd = hashCanonical({ d: AG_Q, g: aggregateGrantDigest(g), verb: inp.verb, resource: inp.resource, purpose: inp.purpose, fn: inp.fn, n: inp.values.length, s: inp.values.reduce((a, v) => a + Math.max(-rule.clamp, Math.min(rule.clamp, v)), 0) });
    const prior = own(st.answered, qd);
    if (prior !== undefined) return { decision: 'allow', code: null, value: prior, state: st, charged_micro: 0 };
    if (st.queries + 1 > g.max_queries) return keep('query_cap');
    const cost = rule.dp ? rule.epsilon_micro : 0;
    if (st.spent_micro + cost > g.epsilon_budget_micro) return keep('epsilon_exhausted');
    let exact = inp.fn === 'count' ? inp.values.length : inp.values.reduce((a, v) => a + Math.max(-rule.clamp, Math.min(rule.clamp, v)), 0);
    if (rule.dp) {
      const sens = inp.fn === 'count' ? 1 : rule.clamp;
      const draws = inp.noise === 'secure' ? secureDraws() : seededDraws(hashCanonical({ d: AG_N, salt: inp.salt, q: qd }));
      exact += discreteLaplace(draws, rule.epsilon_micro, sens * 1_000_000);
    }
    const next: AggregateState = { spent_micro: st.spent_micro + cost, queries: st.queries + 1, answered: { ...st.answered, [qd]: exact } };
    return { decision: 'allow', code: null, value: exact, state: next, charged_micro: cost };
  } catch {
    return fail('bad_request');
  }
}
// ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, "The Discrete Gaussian for Differential Privacy", Alg. 1-2) ----
// Every step is integer arithmetic over a stream of 48-bit draws taken from SHA-256 blocks, so every language agrees byte for byte.
// P[noise = x] is proportional to exp(-|x| * epsilon / sensitivity) with epsilon = epsilon_micro / 1e6.
const DP_STREAM = 'atlas-pca/dp-stream/v1';
const TWO48 = 2 ** 48;
const MAX_STEPS = 100_000;
export interface Draws { uniform(n: number): number }
/** A draw source: block i is SHA-256 of the canonical {d, seed, i}; each block yields five 48-bit values. */
export function seededDraws(seed: string): Draws {
  let block = 0;
  let buf: number[] = [];
  const next48 = (): number => {
    if (buf.length === 0) {
      const bytes = decodeB64uStrict(hashCanonical({ d: DP_STREAM, seed, i: block++ }), 32) as Uint8Array;
      for (let k = 0; k < 5; k++) {
        let v = 0;
        for (let j = 0; j < 6; j++) v = v * 256 + (bytes[k * 6 + j] as number);
        buf.push(v);
      }
      buf = buf.reverse();
    }
    return buf.pop() as number;
  };
  return {
    uniform(n: number): number {
      if (!Number.isSafeInteger(n) || n < 1 || n > 2 ** 47) throw new RangeError('uniform: bad bound');
      const limit = TWO48 - (TWO48 % n);
      for (let i = 0; i < MAX_STEPS; i++) {
        const r = next48();
        if (r < limit) return r % n;
      }
      throw new RangeError('uniform: no draw');
    },
  };
}
/** The PRODUCTION mode: a seed from the operating system's CSPRNG. Answers differ per process; a repeated query is still answered from the cache. */
export function secureDraws(): Draws {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return seededDraws(b64u(bytes));
}
const bern = (d: Draws, num: number, den: number): boolean => d.uniform(den) < num; // Bernoulli(num/den)
/** Bernoulli(exp(-num/den)) for 0 <= num/den <= 1. */
function bernExpSmall(d: Draws, num: number, den: number): boolean {
  let k = 1;
  for (; k <= MAX_STEPS; k++) if (!bern(d, num, den * k)) return k % 2 === 1;
  throw new RangeError('bernoulli: no termination');
}
/** Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: s is the rate numerator, t the scale denominator). */
export function discreteLaplace(d: Draws, s: number, t: number): number {
  for (let outer = 0; outer < MAX_STEPS; outer++) {
    const u = d.uniform(t);
    if (!bernExpSmall(d, u, t)) continue;
    let v = 0;
    while (bernExpSmall(d, 1, 1)) if (++v > MAX_STEPS) throw new RangeError('laplace: no termination');
    const y = Math.floor((u + t * v) / s);
    const negative = d.uniform(2) === 1;
    if (negative && y === 0) continue;
    return negative ? -y : y;
  }
  throw new RangeError('laplace: no sample');
}
