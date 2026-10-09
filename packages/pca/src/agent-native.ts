import { canonicalBytes, canonicalize, hashCanonical, b64u, unb64u, compareUtf8 } from './hash';
import { sign, verifyB64u } from './keys';
import { verifyChain, type Caveat, type CapabilityChain } from './capability';
import { ENVELOPE_CAVEAT, readEnvelope } from './envelope';
import {
  REVERSIBILITY_ORDER,
  envelopeCaveatEvaluator,
  predicateMatches,
  type ActionContext,
  type Condition,
  type Predicate,
} from './predicates';

/**
 * Agent-native authority primitives (frontier research §4) — production-hardened.
 * Pure and deterministic: no clocks (callers pass `now`), no randomness except the default rationale
 * salt. Verification/evaluation functions are total and fail closed (never throw on malformed input);
 * only the AUTHORING helpers (`signCaution`, `bindRationale`, `toolSchemaCaveat`, `grantLease`) throw
 * on invalid input so a bad artefact is never minted.
 *
 *  1. Uncertainty attestation  — combineCaution / signCaution / verifyCaution / combineSignedCaution
 *  2. Rationale binding        — bindRationale / verifyRationale / auditRationale
 *  3. Semantic firewall        — toolSchemaCaveat / evaluateToolSchema / toolSchemaEvaluator
 *  4. Capability introspection — describeEnvelope / envelopePermits / envelopePermitsToolCall
 *  5. Authority lease          — grantLease / leaseState / signHeartbeat / renewLease
 *
 * ---- Canonical caveat vocabulary --------------------------------------------------------------
 * The real verifier stack is: root grant = `envelope` caveat (`{predicates, caveats, ...}`, see
 * envelope.ts) + chain-appended caveats evaluated conjunctively. The stock evaluator
 * (`envelopeCaveatEvaluator`) understands ONLY the envelope caveats (`expires`, `not_before`, `rate`,
 * `max_blast_radius`, `reversibility_max`, `delegation_depth`) and fails closed on anything else.
 * Therefore this module:
 *  - reuses those names verbatim (constants below);
 *  - expresses verb/resource scope as the canonical `Predicate` shape: the ROOT scope is
 *    `envelope.predicates`; DELEGATED narrowing is a `predicates` caveat `{allow: Predicate[]}`
 *    (the only new name besides `tool_schema`; canonical has no delegated-scope caveat, and reusing the
 *    identical `Predicate` shape keeps `predicateMatches` the single matching authority);
 *  - ships `agentNativeCaveatEvaluator`, a superset evaluator that adds `predicates` + `tool_schema`.
 * The old ad-hoc `verbs` / `resources` caveat types are REMOVED: no verifier evaluates them, so they
 * would have been silently unenforced (and would fail closed under the stock evaluator).
 */

/** Canonical caveat type names (envelope.ts / predicates.ts), re-exported as constants. */
export const CAVEAT_ENVELOPE = ENVELOPE_CAVEAT;
export const CAVEAT_EXPIRES = 'expires';
export const CAVEAT_NOT_BEFORE = 'not_before';
export const CAVEAT_RATE = 'rate';
export const CAVEAT_MAX_BLAST_RADIUS = 'max_blast_radius';
export const CAVEAT_REVERSIBILITY_MAX = 'reversibility_max';
export const CAVEAT_DELEGATION_DEPTH = 'delegation_depth';
/** New (documented above): delegated verb/resource narrowing, `{allow: Predicate[]}`. */
export const CAVEAT_PREDICATES = 'predicates';
/** New: tool-call authority bound to an exact tool + signature + (nested) arg schema. */
export const CAVEAT_TOOL_SCHEMA = 'tool_schema';

const fin = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);
const isObj = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);
const isPlain = (x: unknown): x is Record<string, unknown> => {
  if (!isObj(x)) return false;
  const p = Object.getPrototypeOf(x);
  return p === Object.prototype || p === null;
};
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isStr = (x: unknown): x is string => typeof x === 'string';
const nonEmpty = (x: unknown): x is string => typeof x === 'string' && x.length > 0;
const msgOf = (domain: string, body: unknown) => canonicalBytes({ d: domain, b: body });
const onlyKeys = (o: Record<string, unknown>, allowed: readonly string[]) => Object.keys(o).every((k) => allowed.includes(k));
const clamp01 = (x: number) => Math.min(1, Math.max(0, x));

// ======================================================================================
// 1. Uncertainty attestation (monotone self-escalation)
// ======================================================================================

/** Max length of the optional machine-readable caution reason. */
export const MAX_CAUTION_REASON_LEN = 64;
const REASON_RE = /^[A-Za-z0-9_.:-]+$/; // linear, anchored, no nested quantifiers

/** What the agent signs: its caution is part of the signed body, bound to one action. */
export interface CautionClaimBody {
  /** hashCanonical of the action this caution is about. */
  action_digest: string;
  /** Declared caution in [0,1]: 0 = confident, 1 = maximally unsure. Out-of-range claims are invalid. */
  caution: number;
  /** Optional coarse machine-readable reason (e.g. 'ambiguous_instruction', 'ood'); <= 64 chars [A-Za-z0-9_.:-]. */
  reason?: string;
  /** Holder public key (b64u) making the claim. */
  holder: string;
}
/** A caution claim plus the holder's Ed25519 signature over the canonical body (domain-separated). */
export interface CautionClaim extends CautionClaimBody {
  sig: string;
}

const CAUTION_KEYS = ['action_digest', 'caution', 'reason', 'holder', 'sig'] as const;

/** Structural validity of a caution body (shared by sign + verify). Returns an error or null. */
function cautionBodyError(b: unknown): string | null {
  if (!isPlain(b)) return 'not an object';
  if (!nonEmpty(b.action_digest)) return 'action_digest required';
  if (!nonEmpty(b.holder)) return 'holder required';
  if (!fin(b.caution) || b.caution < 0 || b.caution > 1) return 'caution must be a finite number in [0,1]';
  if (b.reason !== undefined && (!isStr(b.reason) || b.reason.length > MAX_CAUTION_REASON_LEN || !REASON_RE.test(b.reason))) {
    return 'invalid reason';
  }
  return null;
}

/** Sign a caution. THROWS (authoring error) on an invalid body (e.g. NaN / out-of-range caution). */
export function signCaution(body: CautionClaimBody, holderSecret: Uint8Array): CautionClaim {
  const err = cautionBodyError(body);
  if (err) throw new RangeError(`signCaution: ${err}`);
  const clean: CautionClaimBody = { action_digest: body.action_digest, caution: body.caution, holder: body.holder };
  if (body.reason !== undefined) clean.reason = body.reason;
  return { ...clean, sig: b64u(sign(holderSecret, msgOf('atlas-pca/caution/v1', clean))) };
}

/**
 * Verify a caution claim: strict shape (no smuggled fields), caution in [0,1], valid signature by
 * `claim.holder`, bound to `expectedActionDigest` (when given) and signed by `expectedHolder` (when
 * given — production callers MUST pass the PCActn's holder, otherwise any key may attest).
 */
export function verifyCaution(claim: CautionClaim, expectedActionDigest?: string, expectedHolder?: string): boolean {
  try {
    if (!isPlain(claim) || !isStr(claim.sig) || !onlyKeys(claim, CAUTION_KEYS)) return false;
    if (cautionBodyError(claim) !== null) return false;
    if (expectedActionDigest !== undefined && claim.action_digest !== expectedActionDigest) return false;
    if (expectedHolder !== undefined && claim.holder !== expectedHolder) return false;
    const { sig, ...body } = claim;
    return verifyB64u(claim.holder, msgOf('atlas-pca/caution/v1', body), sig);
  } catch {
    return false;
  }
}

/**
 * effectiveRisk = max(agentDeclaredCaution, serverRisk).
 *
 * Monotonicity: the result is >= serverRisk for EVERY declared value, and non-decreasing in the
 * declared value. So (a) under-reporting (declared < serverRisk) returns exactly serverRisk —
 * a lying agent gains nothing; (b) a declared caution above serverRisk strictly raises friction.
 * Unusable declarations (undefined / NaN / +-Infinity / non-number) are IGNORED (cannot lower
 * anything). An unusable serverRisk fails closed to 1.
 */
export function combineCaution(agentDeclaredCaution: number | undefined, serverRisk: number): number {
  const s = fin(serverRisk) ? clamp01(serverRisk) : 1;
  if (!fin(agentDeclaredCaution)) return s;
  return Math.max(clamp01(agentDeclaredCaution), s);
}

/**
 * Same, taking a signed claim: only a valid claim bound to THIS action (and, if given, to THIS holder)
 * is honoured. An invalid/misbound/forged claim degrades to `serverRisk` — never below it.
 */
export function combineSignedCaution(
  claim: CautionClaim | undefined,
  actionDigest: string,
  serverRisk: number,
  expectedHolder?: string,
): { effectiveRisk: number; honoured: boolean; escalated: boolean } {
  const s = fin(serverRisk) ? clamp01(serverRisk) : 1;
  const ok = claim !== undefined && verifyCaution(claim, actionDigest, expectedHolder);
  const effectiveRisk = combineCaution(ok ? claim!.caution : undefined, s);
  return { effectiveRisk, honoured: ok, escalated: effectiveRisk > s };
}

/** Exhaustive-grid check of the monotonicity property (used by tests; also a runnable proof aid). */
export function checkCautionMonotone(grid: number[]): { ok: boolean; counterexample?: [number, number] } {
  const g = grid.filter(fin);
  for (const s of g) {
    for (const d of g) {
      const e = combineCaution(d, s);
      if (e < clamp01(s)) return { ok: false, counterexample: [d, s] };
      for (const d2 of g) if (d2 >= d && combineCaution(d2, s) < e) return { ok: false, counterexample: [d2, s] };
    }
  }
  return { ok: true };
}

// ======================================================================================
// 2. Rationale binding (commit / reveal)
// ======================================================================================

/** Minimum decoded salt length (bytes). */
export const MIN_SALT_BYTES = 16;
/** Minimum number of distinct byte values in a salt (rejects `AAAA…`, counters, repeated patterns of 1-7 values). */
export const MIN_SALT_DISTINCT_BYTES = 8;
/** Max UTF-8-agnostic rationale length (UTF-16 units). */
export const MAX_RATIONALE_LEN = 8192;

/**
 * Entropy FLOOR for a commitment salt: base64url that decodes to >= 16 bytes with >= 8 distinct byte
 * values. This is a sanity floor against obviously weak salts (it cannot prove randomness).
 */
export function isStrongSalt(salt: unknown): boolean {
  if (!isStr(salt) || salt.length > 256 || !/^[A-Za-z0-9_-]+$/.test(salt)) return false;
  try {
    const b = unb64u(salt);
    return b.length >= MIN_SALT_BYTES && new Set(b).size >= MIN_SALT_DISTINCT_BYTES;
  } catch {
    return false;
  }
}

/** The commitment published in the ledger. Binds (action digest, salt, rationale). */
export interface RationaleCommitment {
  v: 1;
  /** hashCanonical of the action this stated reason is attached to. */
  action_digest: string;
  /** H(domain, action_digest, salt, rationale). Hiding (salted) and binding. Goes in the ledger entry. */
  commitment: string;
}
/** What the agent keeps and reveals on audit. */
export interface RationaleReveal {
  rationale: string;
  salt: string;
}

/** 32 random bytes, b64u. Uses WebCrypto (`getRandomValues`). */
function randomSalt(): string {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return b64u(b);
}
const commitDigest = (actionDigest: string, salt: string, rationale: string) =>
  hashCanonical({ d: 'atlas-pca/rationale/v1', a: actionDigest, s: salt, r: rationale });

/**
 * The agent commits to its stated reason. Publish `commitment`; KEEP `reveal` (rationale + salt).
 * `salt` may be supplied (deterministic tests) but must pass `isStrongSalt`; the default is 32 random
 * bytes. THROWS (authoring error) on a weak salt, non-string or oversized rationale, or a
 * non-canonicalizable action.
 */
export function bindRationale(
  action: unknown,
  rationaleText: string,
  salt: string = randomSalt(),
): { commitment: RationaleCommitment; reveal: RationaleReveal } {
  if (!isStr(rationaleText)) throw new TypeError('bindRationale: rationale must be a string');
  if (rationaleText.length > MAX_RATIONALE_LEN) throw new RangeError('bindRationale: rationale too long');
  if (!isStrongSalt(salt)) throw new RangeError(`bindRationale: salt must be b64u of >=${MIN_SALT_BYTES} bytes with >=${MIN_SALT_DISTINCT_BYTES} distinct values`);
  const action_digest = hashCanonical(action);
  return {
    commitment: { v: 1, action_digest, commitment: commitDigest(action_digest, salt, rationaleText) },
    reveal: { rationale: rationaleText, salt },
  };
}

/**
 * Does the revealed rationale open the commitment (optionally: for this very action)? A reveal whose
 * salt is below the entropy floor is rejected even if it hashes correctly (the commitment was not
 * hiding, so it is not an acceptable accountability artefact).
 */
export function verifyRationale(commitment: RationaleCommitment, reveal: RationaleReveal, action?: unknown): boolean {
  try {
    if (!isPlain(commitment) || !isPlain(reveal)) return false;
    if (commitment.v !== 1 || !nonEmpty(commitment.action_digest) || !nonEmpty(commitment.commitment)) return false;
    if (!isStr(reveal.rationale) || reveal.rationale.length > MAX_RATIONALE_LEN || !isStrongSalt(reveal.salt)) return false;
    if (action !== undefined && hashCanonical(action) !== commitment.action_digest) return false;
    return commitDigest(commitment.action_digest, reveal.salt, reveal.rationale) === commitment.commitment;
  } catch {
    return false;
  }
}

/** Outcome class of a rationale audit. `malformed`/`judge_error` are never slashable (not the agent's fault). */
export type RationaleVerdict = 'consistent' | 'false_rationale' | 'unopened' | 'wrong_action' | 'malformed' | 'judge_error';
/** Result of {@link auditRationale}. */
export interface RationaleAudit {
  verdict: RationaleVerdict;
  /** Slashable iff the agent is provably attributable for a false/unrevealed rationale. */
  slashable: boolean;
  evidence: { commitment: string; action_digest: string; rationale?: string };
}

/**
 * After-the-fact audit. The resource server never judges the rationale; an auditor supplies a
 * `judge(rationale, action)` (human, model, or rule). A rationale that opens the commitment and is
 * judged false is attributable (the commitment is in the signed ledger entry) => slashable. Failing
 * to open the commitment on demand is itself slashable (can't hide a bad reason by withholding it).
 * A throwing judge yields `judge_error` (not slashable). Total: never throws.
 */
export function auditRationale(
  commitment: RationaleCommitment,
  action: unknown,
  reveal: RationaleReveal | undefined,
  judge: (rationale: string, action: unknown) => boolean,
): RationaleAudit {
  const evidence = {
    commitment: isPlain(commitment) && isStr(commitment.commitment) ? commitment.commitment : '',
    action_digest: isPlain(commitment) && isStr(commitment.action_digest) ? commitment.action_digest : '',
  };
  try {
    if (!isPlain(commitment) || commitment.v !== 1 || !nonEmpty(commitment.action_digest) || !nonEmpty(commitment.commitment)) {
      return { verdict: 'malformed', slashable: false, evidence };
    }
    if (hashCanonical(action) !== commitment.action_digest) return { verdict: 'wrong_action', slashable: false, evidence };
    if (!reveal || !verifyRationale(commitment, reveal, action)) return { verdict: 'unopened', slashable: true, evidence };
    let ok: boolean;
    try {
      ok = judge(reveal.rationale, action) === true;
    } catch {
      return { verdict: 'judge_error', slashable: false, evidence: { ...evidence, rationale: reveal.rationale } };
    }
    return {
      verdict: ok ? 'consistent' : 'false_rationale',
      slashable: !ok,
      evidence: { ...evidence, rationale: reveal.rationale },
    };
  } catch {
    return { verdict: 'malformed', slashable: false, evidence };
  }
}

// ======================================================================================
// 3. Semantic firewall (tool-schema binding, nested arguments)
// ======================================================================================

/** Limits that bound both schema size and evaluation cost (no regex is ever evaluated: no ReDoS). */
export const MAX_SCHEMA_DEPTH = 8;
export const MAX_SCHEMA_NODES = 256;
export const MAX_OBJECT_PROPS = 64;
export const MAX_ENUM_VALUES = 256;
/** Default and absolute caps on array length / string length when the schema omits/raises them. */
export const DEFAULT_MAX_ARRAY_ITEMS = 256;
export const ABSOLUTE_MAX_ARRAY_ITEMS = 4096;
export const DEFAULT_MAX_STRING_LEN = 65_536;
export const ABSOLUTE_MAX_STRING_LEN = 1_048_576;
/** Max total argument values visited in one evaluation. */
export const MAX_VALUE_NODES = 10_000;

/** A scalar usable in `enum` / `const`. */
export type Scalar = string | number | boolean;

/** String argument. */
export interface StringSpec {
  type: 'string';
  enum?: string[];
  const?: string;
  minLength?: number;
  maxLength?: number;
  prefix?: string;
}
/** Number / integer argument (finite only). */
export interface NumberSpec {
  type: 'number' | 'integer';
  enum?: number[];
  const?: number;
  min?: number;
  max?: number;
}
/** Boolean argument. */
export interface BooleanSpec {
  type: 'boolean';
  enum?: boolean[];
  const?: boolean;
}
/** Nested object argument. CLOSED: properties not in `props` are rejected. */
export interface ObjectSpec {
  type: 'object';
  props: Record<string, ArgSpec>;
  required?: string[];
}
/** Array argument; every element must satisfy `items`. */
export interface ArraySpec {
  type: 'array';
  items: ArgSpec;
  minItems?: number;
  maxItems?: number;
}
/** Recursive argument spec. `null` / `undefined` are never accepted. */
export type ArgSpec = StringSpec | NumberSpec | BooleanSpec | ObjectSpec | ArraySpec;

/** Closed top-level schema for the tool's argument object: unknown args are ALWAYS rejected. */
export interface ArgSchema {
  props: Record<string, ArgSpec>;
  required?: string[];
}

/** Caveat type `tool_schema`: authority exists ONLY for this exact tool + signature + arg schema. */
export interface ToolSchemaCaveat extends Caveat {
  type: 'tool_schema';
  tool: string;
  /** Digest of the tool's signature (name + declared param types) as the agent runtime sees it. */
  signature_digest: string;
  schema: ArgSchema;
  /** hashCanonical(schema). */
  schema_digest: string;
  /** hashCanonical({tool, signature_digest, schema}) — also covers tool name + signature binding. */
  binding_digest: string;
}

const SAFE_NAME = /^[A-Za-z0-9_]{1,64}$/;
const SPEC_KEYS: Record<ArgSpec['type'], readonly string[]> = {
  string: ['type', 'enum', 'const', 'minLength', 'maxLength', 'prefix'],
  number: ['type', 'enum', 'const', 'min', 'max'],
  integer: ['type', 'enum', 'const', 'min', 'max'],
  boolean: ['type', 'enum', 'const'],
  object: ['type', 'props', 'required'],
  array: ['type', 'items', 'minItems', 'maxItems'],
};

const nonNegInt = (x: unknown, max: number): x is number => fin(x) && Number.isInteger(x) && x >= 0 && x <= max;

/**
 * Validate a schema (shape, depth, node count, bounds). Returns an error string, or null if valid.
 * Closed: unknown spec keys are errors, so a schema cannot smuggle semantics a verifier ignores.
 */
export function validateArgSchema(schema: unknown): string | null {
  if (!isPlain(schema)) return 'schema must be an object';
  if (!onlyKeys(schema, ['props', 'required'])) return 'unknown schema key';
  const budget = { nodes: 0 };
  return objectSchemaError(schema.props, schema.required, 1, budget);
}

function objectSchemaError(props: unknown, required: unknown, depth: number, budget: { nodes: number }): string | null {
  if (depth > MAX_SCHEMA_DEPTH) return 'schema too deep';
  if (++budget.nodes > MAX_SCHEMA_NODES) return 'schema too large';
  if (!isPlain(props)) return 'props must be an object';
  const names = Object.keys(props);
  if (names.length > MAX_OBJECT_PROPS) return 'too many props';
  for (const n of names) {
    if (!SAFE_NAME.test(n)) return `invalid property name '${n.slice(0, 32)}'`;
    const e = specError(props[n], depth + 1, budget);
    if (e) return `${n}: ${e}`;
  }
  if (required !== undefined) {
    if (!Array.isArray(required) || required.length > MAX_OBJECT_PROPS) return 'required must be a short array';
    for (const r of required) if (!isStr(r) || !has(props, r)) return 'required names an undeclared property';
  }
  return null;
}

function specError(spec: unknown, depth: number, budget: { nodes: number }): string | null {
  if (depth > MAX_SCHEMA_DEPTH) return 'schema too deep';
  if (++budget.nodes > MAX_SCHEMA_NODES) return 'schema too large';
  if (!isPlain(spec) || !isStr(spec.type) || !has(SPEC_KEYS, spec.type)) return 'unknown type';
  const t = spec.type as ArgSpec['type'];
  if (!onlyKeys(spec, SPEC_KEYS[t])) return 'unknown spec key';
  if (t === 'object') {
    budget.nodes--; // counted once by objectSchemaError
    return objectSchemaError(spec.props, spec.required, depth, budget);
  }
  if (t === 'array') {
    if (spec.minItems !== undefined && !nonNegInt(spec.minItems, ABSOLUTE_MAX_ARRAY_ITEMS)) return 'bad minItems';
    if (spec.maxItems !== undefined && !nonNegInt(spec.maxItems, ABSOLUTE_MAX_ARRAY_ITEMS)) return 'bad maxItems';
    if (fin(spec.minItems) && fin(spec.maxItems) && spec.minItems > spec.maxItems) return 'minItems > maxItems';
    return specError(spec.items, depth + 1, budget);
  }
  // scalars
  const ok = (v: unknown): boolean =>
    t === 'string' ? isStr(v) && v.length <= 1024 : t === 'boolean' ? typeof v === 'boolean' : fin(v) && (t === 'number' || Number.isInteger(v));
  if (has(spec, 'const') && !ok(spec.const)) return 'bad const';
  if (spec.enum !== undefined) {
    if (!Array.isArray(spec.enum) || spec.enum.length === 0 || spec.enum.length > MAX_ENUM_VALUES || !spec.enum.every(ok)) return 'bad enum';
  }
  if (t === 'string') {
    if (spec.minLength !== undefined && !nonNegInt(spec.minLength, ABSOLUTE_MAX_STRING_LEN)) return 'bad minLength';
    if (spec.maxLength !== undefined && !nonNegInt(spec.maxLength, ABSOLUTE_MAX_STRING_LEN)) return 'bad maxLength';
    if (fin(spec.minLength) && fin(spec.maxLength) && spec.minLength > spec.maxLength) return 'minLength > maxLength';
    if (spec.prefix !== undefined && (!isStr(spec.prefix) || spec.prefix.length > 512)) return 'bad prefix';
  } else if (t === 'number' || t === 'integer') {
    if (spec.min !== undefined && !fin(spec.min)) return 'bad min';
    if (spec.max !== undefined && !fin(spec.max)) return 'bad max';
    if (fin(spec.min) && fin(spec.max) && spec.min > spec.max) return 'min > max';
  }
  return null;
}

const bindingOf = (tool: string, signature_digest: string, schema: ArgSchema) => hashCanonical({ tool, signature_digest, schema });

/**
 * Build a `tool_schema` caveat. THROWS (authoring error) if the signature has no tool name, the
 * schema is invalid (see `validateArgSchema`), or anything is not canonicalizable. The schema is
 * deep-cloned in canonical form, so later mutation of the input cannot alter the caveat.
 */
export function toolSchemaCaveat(toolSignature: unknown, argSchema: ArgSchema): ToolSchemaCaveat {
  const sig = toolSignature as { name?: unknown } | string;
  const tool = typeof sig === 'string' ? sig : isObj(sig) && isStr(sig.name) ? sig.name : '';
  if (!tool) throw new TypeError('toolSchemaCaveat: tool name required');
  const err = validateArgSchema(argSchema);
  if (err) throw new TypeError(`toolSchemaCaveat: ${err}`);
  const schema = JSON.parse(canonicalize(argSchema)) as ArgSchema;
  const signature_digest = hashCanonical(toolSignature);
  return {
    type: 'tool_schema',
    tool,
    signature_digest,
    schema,
    schema_digest: hashCanonical(schema),
    binding_digest: bindingOf(tool, signature_digest, schema),
  };
}

/** A tool call as seen by the runtime / MCP gateway. */
export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
  /** The signature the runtime actually dispatches to; a swapped/shadowed tool changes it. */
  toolSignature?: unknown;
  /** Digest form of `toolSignature` (the PCActn's signed `tool_binding`); must equal the caveat's `signature_digest`. */
  toolSignatureDigest?: string;
}

/** Firewall verdict; `reason` names the failing path on rejection. */
export interface FirewallResult {
  ok: boolean;
  reason?: string;
}

const show = (k: string) => JSON.stringify(k.length > 48 ? k.slice(0, 48) + '…' : k);

/** Recursive validation. Returns an error string or null. Fail closed on every mismatch. */
function checkValue(spec: ArgSpec, v: unknown, path: string, depth: number, budget: { n: number }): string | null {
  if (depth > MAX_SCHEMA_DEPTH + 1) return `${path}: too deep`;
  if (++budget.n > MAX_VALUE_NODES) return `${path}: too many values`;
  switch (spec.type) {
    case 'object': {
      if (!isPlain(v)) return `${path}: expected object`;
      return checkObject(spec.props, spec.required, v, path, depth, budget);
    }
    case 'array': {
      if (!Array.isArray(v)) return `${path}: expected array`;
      const max = Math.min(spec.maxItems ?? DEFAULT_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_ARRAY_ITEMS);
      if (v.length > max) return `${path}: exceeds maxItems`;
      if (spec.minItems !== undefined && v.length < spec.minItems) return `${path}: below minItems`;
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) return `${path}[${i}]: hole in array`;
        const e = checkValue(spec.items, v[i], `${path}[${i}]`, depth + 1, budget);
        if (e) return e;
      }
      return null;
    }
    case 'string': {
      if (!isStr(v)) return `${path}: wrong type (expected string)`;
      if (v.length > Math.min(spec.maxLength ?? DEFAULT_MAX_STRING_LEN, ABSOLUTE_MAX_STRING_LEN)) return `${path}: exceeds maxLength`;
      if (spec.minLength !== undefined && v.length < spec.minLength) return `${path}: below minLength`;
      if (spec.prefix !== undefined && !v.startsWith(spec.prefix)) return `${path}: violates prefix`;
      break;
    }
    case 'number':
    case 'integer': {
      if (!fin(v) || (spec.type === 'integer' && !Number.isInteger(v))) return `${path}: wrong type (expected ${spec.type})`;
      if (spec.min !== undefined && v < spec.min) return `${path}: below min`;
      if (spec.max !== undefined && v > spec.max) return `${path}: above max`;
      break;
    }
    case 'boolean':
      if (typeof v !== 'boolean') return `${path}: wrong type (expected boolean)`;
      break;
    default:
      return `${path}: unknown type`;
  }
  const sc = spec as StringSpec | NumberSpec | BooleanSpec;
  if (has(sc, 'const') && (sc as { const?: Scalar }).const !== v) return `${path}: violates const`;
  if (sc.enum !== undefined && !(sc.enum as Scalar[]).some((e) => e === v)) return `${path}: violates enum`;
  return null;
}

function checkObject(
  props: Record<string, ArgSpec>,
  required: string[] | undefined,
  obj: Record<string, unknown>,
  path: string,
  depth: number,
  budget: { n: number },
): string | null {
  const keys = Object.keys(obj);
  for (const k of keys) if (!has(props, k)) return `${path}: unexpected argument ${show(k)}`;
  for (const r of required ?? []) if (!has(obj, r)) return `${path}: missing required argument '${r}'`;
  for (const k of keys) {
    const e = checkValue(props[k]!, obj[k], `${path}.${k}`, depth + 1, budget);
    if (e) return e;
  }
  return null;
}

/**
 * Evaluate a tool call against a `tool_schema` caveat. Fails AUTHORITY, not just validation.
 * The caveat must be self-consistent (schema valid, both digests match), the tool name and signature
 * must match, and the (possibly nested) arguments must satisfy the closed recursive schema: any type
 * mismatch, extra property, missing required property, out-of-range value or oversized structure is a
 * rejection. No regular expressions are evaluated; work is bounded by `MAX_VALUE_NODES`.
 */
export function evaluateToolSchema(caveat: ToolSchemaCaveat, call: ToolCall): FirewallResult {
  try {
    if (!isObj(caveat) || caveat.type !== 'tool_schema' || !nonEmpty(caveat.tool)) {
      return { ok: false, reason: 'malformed tool_schema caveat' };
    }
    const verr = validateArgSchema(caveat.schema);
    if (verr) return { ok: false, reason: `malformed tool_schema caveat: ${verr}` };
    // The caveat itself must be self-consistent (digest checks block post-hoc edits).
    if (hashCanonical(caveat.schema) !== caveat.schema_digest) return { ok: false, reason: 'schema digest mismatch' };
    if (bindingOf(caveat.tool, String(caveat.signature_digest), caveat.schema) !== caveat.binding_digest) {
      return { ok: false, reason: 'binding digest mismatch' };
    }
    if (!isObj(call) || !isStr(call.tool) || !isPlain(call.args)) return { ok: false, reason: 'malformed call' };
    if (call.tool !== caveat.tool) return { ok: false, reason: `tool ${show(call.tool)} not authorized` };
    if (call.toolSignature !== undefined && hashCanonical(call.toolSignature) !== caveat.signature_digest) {
      return { ok: false, reason: 'tool signature differs from the authorized signature' };
    }
    if (call.toolSignatureDigest !== undefined && call.toolSignatureDigest !== caveat.signature_digest) {
      return { ok: false, reason: 'signed tool_binding differs from the authorized tool signature' };
    }
    const e = checkObject(caveat.schema.props, caveat.schema.required, call.args, 'args', 1, { n: 0 });
    return e ? { ok: false, reason: e } : { ok: true };
  } catch {
    return { ok: false, reason: 'evaluation error (fail closed)' };
  }
}

/** Plugs into the `CaveatEvaluator` extension point: ctx = { toolCall }. Other caveat types: unsatisfied here. */
export function toolSchemaEvaluator(caveat: Caveat, ctx: unknown): boolean {
  if (!isObj(ctx) || !isObj(ctx.toolCall)) return false;
  return evaluateToolSchema(caveat as ToolSchemaCaveat, ctx.toolCall as unknown as ToolCall).ok;
}

/** Context for {@link agentNativeCaveatEvaluator}: the stock `CaveatContext` fields + the action/tool call. */
export interface AgentCaveatContext {
  now: number;
  blastRadius?: number;
  reversibilityClass?: string;
  delegationDepth?: number;
  recentActionTimes?: number[];
  /** Required to satisfy a `predicates` caveat. */
  action?: ActionContext;
  /** Required to satisfy a `tool_schema` caveat. */
  toolCall?: ToolCall;
}

/** A delegated-scope caveat: the action must match at least one `allow` predicate. */
export interface PredicatesCaveat extends Caveat {
  type: 'predicates';
  allow: Predicate[];
}

/** Build the canonical delegated-narrowing caveat (deep-cloned canonical form). */
export function predicatesCaveat(allow: Predicate[]): PredicatesCaveat {
  return { type: CAVEAT_PREDICATES, allow: JSON.parse(canonicalize(allow)) as Predicate[] };
}

/**
 * Superset of the stock `envelopeCaveatEvaluator`: adds `predicates` (needs `ctx.action`) and
 * `tool_schema` (needs `ctx.toolCall`). Anything else defers to the stock evaluator (which fails
 * closed on unknown types). Total.
 */
export function agentNativeCaveatEvaluator(caveat: Caveat, ctx: unknown): boolean {
  try {
    if (!isObj(caveat) || !isObj(ctx)) return false;
    if (caveat.type === CAVEAT_TOOL_SCHEMA) return toolSchemaEvaluator(caveat, ctx);
    if (caveat.type === CAVEAT_PREDICATES) {
      const a = ctx.action as ActionContext | undefined;
      if (!isObj(a) || !Array.isArray(caveat.allow)) return false;
      return (caveat.allow as Predicate[]).some((p) => predicateMatches(p, a));
    }
    return envelopeCaveatEvaluator(caveat, ctx);
  } catch {
    return false;
  }
}

// ======================================================================================
// 4. Capability introspection
// ======================================================================================

/** One symbolic permitted region: verbs x (all resource patterns) under `where`. Predicate-compatible. */
export interface Scope {
  /** Permitted verbs (may contain '*'). */
  verbs: string[];
  /** CONJUNCTIVE resource patterns (exact | 'prefix*' | '*' | 're:..'); the action must match all. */
  resources: string[];
  /** Param/subject/env conditions (conjunctive) that could not be decided symbolically. */
  where: Condition[];
}

/**
 * What an attenuated chain permits NOW, derived with the same vocabulary the verifier uses:
 * root `envelope.predicates` (+ `envelope.caveats`), then every appended `predicates` / `tool_schema` /
 * built-in caveat. Conjunctive across hops.
 */
export interface AuthorityEnvelope {
  /** false => the chain does not verify (reason set) and nothing is permitted. */
  ok: boolean;
  reason?: string;
  /** Root grant carried a valid `envelope` caveat (without one the stock policy VM denies everything). */
  hasEnvelope: boolean;
  /** Exact symbolic scopes after intersection; null = unrestricted by predicates (no envelope caveat). */
  scopes: Scope[] | null;
  /** Projection: union of scope verbs. null = unrestricted; [] = nothing permitted. */
  verbs: string[] | null;
  /** Projection: union of scope resource patterns (non-regex form when decidable). */
  resources: string[] | null;
  /** Regex resource constraints that could not be intersected symbolically; still enforced at use. */
  opaqueResourceConstraints: string[];
  /** Tools callable under ALL `tool_schema` caveats (intersection). null = no tool constraint; [] = none. */
  tools: string[] | null;
  /** Every `tool_schema` caveat in the chain (all must hold). Self-inconsistent ones empty `tools`. */
  toolSchemas: ToolSchemaCaveat[];
  /** Caveat types the verifier would reject (unknown/malformed/duplicate envelope): when non-empty NOTHING is permitted. */
  unsatisfiable: string[];
  /** All leaf caveats, as signed. */
  caveats: Caveat[];
  remainingBudgetHints: {
    expiresAt?: number;
    expiresIn?: number;
    maxRate?: { max: number; per_secs: number };
    maxBlastRadius?: number;
    reversibilityMax?: string;
    delegationDepthRemaining?: number;
    notBefore?: number;
    /** The tightest carried per-subtree trust-budget allocation (`budget_alloc`), when any hop declares one. */
    budgetAlloc?: number;
  };
}

function intersectVerbs(a: string[], b: string[]): string[] {
  if (a.includes('*')) return [...new Set(b)].sort(compareUtf8);
  if (b.includes('*')) return [...new Set(a)].sort(compareUtf8);
  return [...new Set(a.filter((x) => b.includes(x)))].sort(compareUtf8);
}

/** Intersect two resource patterns; null = empty; undefined = cannot decide symbolically (regex). */
function interRes(a: string, b: string): string | null | undefined {
  if (a === b) return a;
  if (a.startsWith('re:') || b.startsWith('re:')) return undefined;
  if (a === '*') return b;
  if (b === '*') return a;
  const ap = a.endsWith('*'), bp = b.endsWith('*');
  if (ap && bp) {
    const pa = a.slice(0, -1), pb = b.slice(0, -1);
    return pb.startsWith(pa) ? b : pa.startsWith(pb) ? a : null;
  }
  if (ap) return b.startsWith(a.slice(0, -1)) ? b : null;
  if (bp) return a.startsWith(b.slice(0, -1)) ? a : null;
  return null;
}

/** Collapse a conjunction of resource patterns; null = unsatisfiable. */
function collapseResources(list: string[]): string[] | null {
  let lit: string | undefined;
  const res = new Set<string>();
  for (const p of list) {
    if (p.startsWith('re:')) {
      res.add(p);
      continue;
    }
    if (lit === undefined) lit = p;
    else {
      const r = interRes(lit, p);
      if (r === null || r === undefined) return null;
      lit = r;
    }
  }
  const out = [...(lit !== undefined && lit !== '*' ? [lit] : []), ...[...res].sort(compareUtf8)];
  return out.length ? out : ['*'];
}

function scopeOfPredicate(p: Predicate): Scope | null {
  if (!isObj(p)) return null;
  const verbs = typeof p.verb === 'string' ? [p.verb] : Array.isArray(p.verb) && p.verb.every(isStr) ? [...p.verb] : null;
  if (!verbs) return null;
  if (p.resource !== undefined && !isStr(p.resource)) return null;
  const where = p.where === undefined ? [] : Array.isArray(p.where) ? (p.where as Condition[]) : null;
  if (!where) return null;
  return { verbs: [...new Set(verbs)].sort(compareUtf8), resources: [p.resource ?? '*'], where };
}

function intersectScopes(a: Scope[], b: Scope[]): Scope[] {
  const out = new Map<string, Scope>();
  for (const x of a) {
    for (const y of b) {
      const verbs = intersectVerbs(x.verbs, y.verbs);
      if (!verbs.length) continue;
      const resources = collapseResources([...x.resources, ...y.resources]);
      if (!resources) continue;
      const s: Scope = { verbs, resources, where: [...x.where, ...y.where] };
      out.set(hashCanonical(s), s);
    }
  }
  return [...out.entries()].sort(([p], [q]) => (p < q ? -1 : p > q ? 1 : 0)).map(([, s]) => s);
}

function scopeMatches(s: Scope, verb: string, resource: string, params?: Record<string, unknown>): boolean {
  if (!s.verbs.includes('*') && !s.verbs.includes(verb)) return false;
  const ctx: ActionContext = { action: { verb, resource, ...(params ? { params } : {}) } };
  for (const r of s.resources) if (!predicateMatches({ verb: '*', resource: r }, ctx)) return false;
  if (params !== undefined && s.where.length) return predicateMatches({ verb: '*', where: s.where }, ctx);
  return true;
}

const REV = REVERSIBILITY_ORDER as readonly string[];

/** Is this appended/envelope caveat one the verifier (stock + this module's superset) can satisfy at all? */
function wellFormedCaveat(cv: Caveat): boolean {
  switch (cv.type) {
    case CAVEAT_EXPIRES:
    case CAVEAT_NOT_BEFORE:
      return fin(cv.at);
    case CAVEAT_RATE:
      return fin(cv.max) && fin(cv.per_secs) && cv.per_secs > 0;
    case CAVEAT_MAX_BLAST_RADIUS:
    case CAVEAT_DELEGATION_DEPTH:
      return fin(cv.max);
    case CAVEAT_REVERSIBILITY_MAX:
      return REV.includes(String(cv.class));
    case CAVEAT_PREDICATES:
      return Array.isArray(cv.allow) && cv.allow.every((p) => scopeOfPredicate(p as Predicate) !== null);
    case CAVEAT_TOOL_SCHEMA:
      return nonEmpty(cv.tool);
    case 'budget_alloc': {
      const lim = cv.limit;
      return fin(lim) && lim >= 0;
    }
    default:
      return false;
  }
}

/**
 * Compute what an attenuated chain actually permits NOW. Deterministic (`now` supplied). Because
 * caveats are conjunctive and append-only, the envelope is the intersection across all hops —
 * exactly the set the verifier would accept, so the answer is sound (never wider than reality).
 * A caveat the verifier cannot satisfy (unknown type, malformed fields, a second `envelope`) makes
 * the verifier deny everything; it is listed in `unsatisfiable` and `envelopePermits` returns false.
 * Total: never throws.
 */
export function describeEnvelope(chain: CapabilityChain, now?: number, expectedRootIssuer?: string): AuthorityEnvelope {
  const empty: AuthorityEnvelope = {
    ok: false,
    hasEnvelope: false,
    scopes: [],
    verbs: [],
    resources: [],
    opaqueResourceConstraints: [],
    tools: [],
    toolSchemas: [],
    unsatisfiable: [],
    caveats: [],
    remainingBudgetHints: {},
  };
  try {
    const v = verifyChain(chain, expectedRootIssuer);
    if (!v.ok) return { ...empty, reason: v.reason };

    const root = chain[0]!;
    const leaf = chain[chain.length - 1]!;
    const env0 = readEnvelope(root);
    const env: AuthorityEnvelope = { ...empty, ok: true, hasEnvelope: env0 !== null, caveats: leaf.caveats };
    const h = env.remainingBudgetHints;
    const bad = new Set<string>();

    let scopes: Scope[] | null = null;
    if (env0) {
      const base = env0.predicates.map(scopeOfPredicate);
      if (base.some((s) => s === null)) bad.add('envelope.predicates');
      scopes = intersectScopes(base.filter((s): s is Scope => s !== null), [{ verbs: ['*'], resources: ['*'], where: [] }]);
    }
    let tools: string[] | null = null;
    let seenEnvelope = false;

    const fold = (cv: Caveat, inEnvelope: boolean) => {
      if (!isObj(cv) || !isStr(cv.type)) {
        bad.add('<malformed>');
        return;
      }
      if (cv.type === CAVEAT_ENVELOPE) {
        // Only the root's FIRST envelope caveat is read; the policy VM evaluates any other as unknown => unsatisfied.
        if (seenEnvelope || inEnvelope) bad.add(CAVEAT_ENVELOPE);
        seenEnvelope = true;
        return;
      }
      if (!wellFormedCaveat(cv)) {
        bad.add(cv.type);
        return;
      }
      switch (cv.type) {
        case CAVEAT_PREDICATES: {
          const next = (cv.allow as Predicate[]).map((p) => scopeOfPredicate(p)!);
          scopes = intersectScopes(scopes ?? [{ verbs: ['*'], resources: ['*'], where: [] }], next);
          break;
        }
        case CAVEAT_TOOL_SCHEMA: {
          const tc = cv as ToolSchemaCaveat;
          env.toolSchemas.push(tc);
          const consistent =
            validateArgSchema(tc.schema) === null &&
            hashCanonical(tc.schema) === tc.schema_digest &&
            bindingOf(tc.tool, String(tc.signature_digest), tc.schema) === tc.binding_digest;
          if (!consistent) {
            tools = [];
            bad.add(CAVEAT_TOOL_SCHEMA);
          } else tools = tools === null ? [tc.tool] : tools.filter((t) => t === tc.tool);
          break;
        }
        case CAVEAT_EXPIRES:
          h.expiresAt = h.expiresAt === undefined ? (cv.at as number) : Math.min(h.expiresAt, cv.at as number);
          break;
        case CAVEAT_NOT_BEFORE:
          h.notBefore = h.notBefore === undefined ? (cv.at as number) : Math.max(h.notBefore, cv.at as number);
          break;
        case CAVEAT_RATE: {
          const cur = h.maxRate;
          const m = cv.max as number, p = cv.per_secs as number;
          // lower sustained rate (max/per_secs) is the binding one; ties broken by smaller max for determinism
          if (!cur || m / p < cur.max / cur.per_secs || (m / p === cur.max / cur.per_secs && m < cur.max)) h.maxRate = { max: m, per_secs: p };
          break;
        }
        case CAVEAT_MAX_BLAST_RADIUS:
          h.maxBlastRadius = h.maxBlastRadius === undefined ? (cv.max as number) : Math.min(h.maxBlastRadius, cv.max as number);
          break;
        case CAVEAT_REVERSIBILITY_MAX: {
          const i = REV.indexOf(String(cv.class));
          const j = h.reversibilityMax === undefined ? REV.length : REV.indexOf(h.reversibilityMax);
          if (i < j) h.reversibilityMax = REV[i];
          break;
        }
        case CAVEAT_DELEGATION_DEPTH: {
          const rem = (cv.max as number) - (chain.length - 1);
          h.delegationDepthRemaining = h.delegationDepthRemaining === undefined ? rem : Math.min(h.delegationDepthRemaining, rem);
          break;
        }
        case 'budget_alloc': {
          // The tightest carried subtree allocation on this chain (monotone non-increasing, so the min).
          const lim = cv.limit as number;
          h.budgetAlloc = h.budgetAlloc === undefined ? lim : Math.min(h.budgetAlloc, lim);
          break;
        }
      }
    };

    if (env0) for (const cv of env0.caveats) fold(cv, true);
    for (const cv of leaf.caveats) fold(cv, false);

    env.scopes = scopes;
    const opaque = new Set<string>();
    if (scopes) {
      const vs = new Set<string>(), rs = new Set<string>();
      for (const s of scopes as Scope[]) {
        s.verbs.forEach((x) => vs.add(x));
        s.resources.forEach((r) => {
          rs.add(r);
          if (r.startsWith('re:')) opaque.add(r);
        });
      }
      env.verbs = [...vs].sort(compareUtf8);
      env.resources = [...rs].sort(compareUtf8);
    } else {
      env.verbs = null;
      env.resources = null;
    }
    env.opaqueResourceConstraints = [...opaque].sort(compareUtf8);
    env.tools = tools === null ? null : [...new Set<string>(tools)].sort(compareUtf8);
    env.unsatisfiable = [...bad].sort(compareUtf8);
    if (env.unsatisfiable.length) {
      env.scopes = [];
      env.verbs = [];
      env.resources = [];
      env.tools = [];
      env.reason = `unsatisfiable caveat(s): ${env.unsatisfiable.join(', ')}`;
    }
    if (h.expiresAt !== undefined && fin(now)) h.expiresIn = h.expiresAt - now;
    return env;
  } catch {
    return { ...empty, reason: 'introspection error (fail closed)' };
  }
}

/**
 * Cheap pre-flight an agent can run before attempting. `false` is DEFINITIVE (the verifier will
 * refuse); `true` means the symbolic envelope allows it. When `params` is given, `where` conditions
 * are evaluated too (fail closed); without it, conditional scopes count as "may permit".
 */
export function envelopePermits(
  env: AuthorityEnvelope,
  verb: string,
  resource: string,
  now?: number,
  params?: Record<string, unknown>,
): boolean {
  try {
    if (!env.ok || env.unsatisfiable.length) return false;
    if (env.scopes !== null && !env.scopes.some((s) => scopeMatches(s, verb, resource, params))) return false;
    const h = env.remainingBudgetHints;
    if (h.delegationDepthRemaining !== undefined && h.delegationDepthRemaining < 0) return false;
    if (now !== undefined) {
      if (!fin(now)) return false;
      if (h.expiresAt !== undefined && now >= h.expiresAt) return false;
      if (h.notBefore !== undefined && now < h.notBefore) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Pre-flight for a tool call: tool must be in `env.tools` and satisfy EVERY `tool_schema` caveat. */
export function envelopePermitsToolCall(env: AuthorityEnvelope, call: ToolCall): FirewallResult {
  try {
    if (!env.ok || env.unsatisfiable.length) return { ok: false, reason: env.reason ?? 'envelope not usable' };
    if (env.tools !== null && !env.tools.includes(call.tool)) return { ok: false, reason: `tool ${show(String(call.tool))} not authorized` };
    for (const tc of env.toolSchemas) {
      const r = evaluateToolSchema(tc, call);
      if (!r.ok) return r;
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: 'evaluation error (fail closed)' };
  }
}

// ======================================================================================
// 5. Authority lease (liveness-decaying, per capability)
// ======================================================================================

/** Max tolerated skew between a heartbeat's `at` (or the clock vs the last renewal) and server `now`. */
export const HEARTBEAT_SKEW_MS = 30_000;
/** Longest lease ttl accepted (7 days). */
export const MAX_LEASE_TTL_MS = 7 * 24 * 3_600_000;

/**
 * Server-side lease record. Persist and update it atomically (row lock / compare-and-swap on
 * `last_seq`); `renewLease` is a pure function returning the next record.
 */
export interface CapabilityLease {
  cap_id: string;
  /** Holder public key (b64u) that must sign heartbeats. */
  holder: string;
  issued_at: number;
  /** Time of the last grant/renewal (clock-rollback anchor). */
  renewed_at: number;
  /** Lease lifetime from the last renewal. */
  ttl_ms: number;
  /** Absolute upper bound; heartbeats can never extend past it. Optional. */
  hard_expires_at?: number;
  /** Cap on number of renewals. Optional. */
  max_renewals?: number;
  /** Server-side state. */
  renewals: number;
  last_seq: number;
  expires_at: number;
}

/**
 * Issue a lease. THROWS (authoring error) unless: ids non-empty, `now` finite, 0 < ttl_ms <=
 * MAX_LEASE_TTL_MS, hard_expires_at (if any) finite and > now, max_renewals (if any) a non-negative
 * integer.
 */
export function grantLease(args: {
  cap_id: string;
  holder: string;
  now: number;
  ttl_ms: number;
  hard_expires_at?: number;
  max_renewals?: number;
}): CapabilityLease {
  if (!nonEmpty(args.cap_id) || !nonEmpty(args.holder)) throw new TypeError('grantLease: cap_id and holder required');
  if (!fin(args.now) || !fin(args.ttl_ms) || args.ttl_ms <= 0 || args.ttl_ms > MAX_LEASE_TTL_MS) throw new RangeError('grantLease: invalid now/ttl_ms');
  if (args.hard_expires_at !== undefined && (!fin(args.hard_expires_at) || args.hard_expires_at <= args.now)) throw new RangeError('grantLease: hard_expires_at must be finite and in the future');
  if (args.max_renewals !== undefined && !(Number.isInteger(args.max_renewals) && args.max_renewals >= 0)) throw new RangeError('grantLease: invalid max_renewals');
  const exp = args.hard_expires_at === undefined ? args.now + args.ttl_ms : Math.min(args.now + args.ttl_ms, args.hard_expires_at);
  const l: CapabilityLease = {
    cap_id: args.cap_id,
    holder: args.holder,
    issued_at: args.now,
    renewed_at: args.now,
    ttl_ms: args.ttl_ms,
    renewals: 0,
    last_seq: 0,
    expires_at: exp,
  };
  if (args.hard_expires_at !== undefined) l.hard_expires_at = args.hard_expires_at;
  if (args.max_renewals !== undefined) l.max_renewals = args.max_renewals;
  return l;
}

/** Structural + invariant check of a lease record. Returns an error or null. */
function leaseError(l: unknown): string | null {
  if (!isPlain(l)) return 'malformed lease';
  if (!nonEmpty(l.cap_id) || !nonEmpty(l.holder)) return 'malformed lease';
  if (![l.issued_at, l.renewed_at, l.ttl_ms, l.expires_at].every(fin)) return 'malformed lease';
  const ttl = l.ttl_ms as number;
  if (ttl <= 0 || ttl > MAX_LEASE_TTL_MS) return 'malformed lease';
  if (!(Number.isInteger(l.renewals) && (l.renewals as number) >= 0) || !(Number.isInteger(l.last_seq) && (l.last_seq as number) >= 0)) return 'malformed lease';
  if (l.max_renewals !== undefined && !(Number.isInteger(l.max_renewals) && (l.max_renewals as number) >= 0)) return 'malformed lease';
  if (l.hard_expires_at !== undefined) {
    if (!fin(l.hard_expires_at)) return 'malformed lease';
    if ((l.expires_at as number) > l.hard_expires_at) return 'lease exceeds hard expiry';
  }
  // A lease can never outlive one ttl past its last renewal: anything else is corruption/tampering.
  if ((l.expires_at as number) > (l.renewed_at as number) + ttl) return 'malformed lease';
  return null;
}

/**
 * Live iff the record is well-formed, the clock has not rolled back more than the skew window past
 * the last renewal, and now < expires_at (a lapsed lease has expiresIn 0). Malformed/NaN/rolled-back
 * => not live (fail closed), with a `reason`.
 */
export function leaseState(lease: CapabilityLease, now: number): { live: boolean; expiresIn: number; reason?: string } {
  const dead = (reason: string) => ({ live: false, expiresIn: 0, reason });
  if (!fin(now)) return dead('invalid clock');
  const e = leaseError(lease);
  if (e) return dead(e);
  if (now < lease.renewed_at - HEARTBEAT_SKEW_MS) return dead('clock before last renewal');
  const expiresIn = lease.expires_at - now;
  if (expiresIn <= 0) return dead('lease lapsed');
  return { live: true, expiresIn };
}

/** A holder-signed liveness proof for one specific lease grant. */
export interface Heartbeat {
  cap_id: string;
  /** Strictly increasing; blocks replay of an old heartbeat to resurrect authority. */
  seq: number;
  at: number;
  holder: string;
  /** The `issued_at` of the lease grant this heartbeat is for (blocks replay onto a re-granted lease). */
  lease_issued_at: number;
  sig: string;
}

const HB_KEYS = ['cap_id', 'seq', 'at', 'holder', 'lease_issued_at', 'sig'] as const;

/** Sign a heartbeat as the lease holder. */
export function signHeartbeat(
  body: { cap_id: string; seq: number; at: number; holder: string; lease_issued_at: number },
  holderSecret: Uint8Array,
): Heartbeat {
  const clean = { cap_id: body.cap_id, seq: body.seq, at: body.at, holder: body.holder, lease_issued_at: body.lease_issued_at };
  return { ...clean, sig: b64u(sign(holderSecret, msgOf('atlas-pca/lease-hb/v2', clean))) };
}

/** Result of {@link renewLease}. */
export type RenewResult = { ok: true; lease: CapabilityLease } | { ok: false; reason: string };

/**
 * Renew on a valid, fresh, in-order, holder-signed heartbeat for THIS lease grant. A lease that has
 * ALREADY lapsed (or is malformed / clock-anomalous) is dead for good — no resurrection by a late
 * heartbeat; re-issue needs a fresh grant. Renewal never extends past `hard_expires_at`, never shortens
 * the lease, and consumes the renewal budget. Total: never throws.
 */
export function renewLease(lease: CapabilityLease, hb: Heartbeat, now: number): RenewResult {
  try {
    const st = leaseState(lease, now);
    if (!st.live) return { ok: false, reason: st.reason === 'lease lapsed' ? 'lease lapsed' : `lease not live: ${st.reason}` };
    if (!isPlain(hb) || !onlyKeys(hb, HB_KEYS) || !isStr(hb.sig)) return { ok: false, reason: 'malformed heartbeat' };
    if (hb.cap_id !== lease.cap_id || hb.holder !== lease.holder || hb.lease_issued_at !== lease.issued_at) {
      return { ok: false, reason: 'heartbeat not for this lease' };
    }
    if (!Number.isSafeInteger(hb.seq) || hb.seq <= lease.last_seq) return { ok: false, reason: 'stale or replayed heartbeat' };
    if (!fin(hb.at) || Math.abs(hb.at - now) > HEARTBEAT_SKEW_MS) return { ok: false, reason: 'heartbeat outside skew window' };
    const { sig, ...body } = hb;
    if (!verifyB64u(lease.holder, msgOf('atlas-pca/lease-hb/v2', body), sig)) return { ok: false, reason: 'bad heartbeat signature' };
    if (lease.max_renewals !== undefined && lease.renewals >= lease.max_renewals) return { ok: false, reason: 'renewal budget exhausted' };
    let exp = now + lease.ttl_ms;
    if (lease.hard_expires_at !== undefined) exp = Math.min(exp, lease.hard_expires_at);
    if (!fin(exp)) return { ok: false, reason: 'malformed lease' };
    return {
      ok: true,
      lease: { ...lease, renewals: lease.renewals + 1, last_seq: hb.seq, renewed_at: Math.max(now, lease.renewed_at), expires_at: Math.max(exp, lease.expires_at) },
    };
  } catch {
    return { ok: false, reason: 'malformed heartbeat' };
  }
}
