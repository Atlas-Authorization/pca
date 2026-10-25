import { randomBytes } from '@noble/hashes/utils';
import { type Capability, type CapSuiteOpts, mintRoot } from './capability';
import { ENVELOPE_CAVEAT, goalCommitOf, type AgentBinding } from './envelope';
import { INTENT_GOAL_V2C_PREFIX, INTENT_GOAL_V2_PREFIX } from './intent-binding';
import { type IntentSessionCaveat, INTENT_SESSION_CAVEAT, MAX_SESSION_SEQ, intentSessionCaveatError } from './intent-session-caveat';
import { suiteCapabilityError } from './intent-strict';

const suiteErr = (alg: unknown) => suiteCapabilityError(alg, (a) => resolveSigAlg(a) !== null);
import { b64u, canonicalBytesStrict, decodeB64uStrict, hasLoneSurrogate, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { type PqPinPolicy, type SignerSuiteOpts, type SigAlg, bindSuiteFields, resolveSigAlg, signSuiteArtifact, suiteKeysOf, suitePqPublicKey, verifyPinnedSuite } from './pq';
import type { Caveat } from './capability';
import type { Predicate } from './predicates';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from './risk';
import { type AccumulatorDecl, type MonitorDecl, ACC_ID_RE, MAX_SESSION_ACCUMULATORS, MAX_SESSION_MONITORS, accumulatorDeclError, monitorDeclError } from './intent-acc';

/**
 * INTENT SESSIONS (PCA Intent Layer v2, milestone V3; docs/specs/pca-intent-layer-v2.md §2.4, §3.3, §4.2 M3, §4.3 M4/M7,
 * §8). NORMATIVE for the wire of the PCActn's `intent_session` member and for the `intent_session` check (conformance
 * rule 13); the `session-*` vectors pin it.
 *
 * A session σ (32 bytes) has a principal-signed SESSION ROOT S (`pca-intent-session` v1) that fixes the principal keys,
 * the statement (`intent_ref`), the site schema, the layers, the accumulators and monitors Ψ, the question endpoint, the
 * revocation source and an expiry. The task's first grant G_0 and every DELTA GRANT D_k are ordinary ROOT capabilities
 * SIGNED BY A PRINCIPAL KEY NAMED IN S, each carrying a root-level caveat
 *   {type: "intent_session", session: σ, seq: k, root: digest(S), prev?: id(D_{k-1})}      (prev absent iff k = 0)
 * and an envelope whose goal is `pca-intent:v2:<σ>:<map_digest_k>`. An agent holds a capability under D_k (a normal
 * attenuation hop) and signs PCActns rooted at it. The agent never signs a grant: it can only narrow (T14, T15).
 *
 * Accumulator and monitor state is keyed on σ, NOT on `grant_ref`, so a delta never starts a fresh total (§3.1). Nonce
 * and counter state stay keyed on `grant_ref`.
 */

export const INTENT_SESSION_KIND = 'pca-intent-session';
export const INTENT_SESSION_SIG_DOMAIN = 'atlas-pca/intent-session/v1\0';
export const INTENT_SESSION_REF_DOMAIN = 'atlas-pca/intent-session-ref/v1';

// ---- the PCActn member `intent_session` (wire) ------------------------------------------------------------------

export const MAX_IS_ACC = 16;
export const MAX_IS_FACTS = 16;
export const MAX_IS_PROV_PATHS = 32;
export const MAX_IS_PROV_REFS = 8;
export const MAX_IS_CLASSES = 8;
export const MAX_IS_LABELS = 16;
export const MAX_IS_STRING_BYTES = 256;
export const INTENT_SESSION_FIELDS = ['session', 'root', 'seq', 'schema', 'acc', 'facts', 'offer_set', 'prov', 'classes', 'labels', 'map_form'] as const;

/** The signed PCActn member `intent_session` (spec §8). `facts`, `offer_set`, `prov`, `classes`, `labels` are W-B
 *  members: their wire shape is fixed here, their semantics by rules 16–18. */
export interface IntentSessionWire {
  session: string;
  root: string;
  seq: number;
  schema: string;
  acc?: { id: string; post: number; receipt?: string }[];
  facts?: string[];
  offer_set?: string;
  prov?: Record<string, string[]>;
  classes?: string[];
  labels?: string[];
  /** Rule 19: "commit" = `intent.map_digest` is the salted map commitment and the goal is `pca-intent:v2c:` (absent = plain digest). */
  map_form?: 'commit';
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0);
const isNonNeg = (v: unknown): v is number => isInt(v) && v >= 0;
const u8len = (s: string): number => utf8(s).length;
const b32 = (v: unknown): boolean => decodeB64uStrict(v, 32) !== null;
const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const shortStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && !hasLoneSurrogate(v) && u8len(v) <= MAX_IS_STRING_BYTES;

function digestList(v: unknown, name: string, max: number): string | null {
  if (!Array.isArray(v) || v.length > max) return `'intent_session.${name}' must be an array of at most ${max} digests`;
  for (const x of v) if (!b32(x)) return `'intent_session.${name}' entries must be canonical base64url (32 bytes)`;
  if (new Set(v).size !== v.length) return `'intent_session.${name}' entries must be distinct`;
  return null;
}

/**
 * Wire validation of `intent_session` (called by `validateWireV2`; a failure is the terminal `wire` check). Closed
 * member set {@link INTENT_SESSION_FIELDS}; required: `session`, `root`, `schema` (canonical base64url, 32 bytes each),
 * `seq` (safe integer in [0, 2^31-1]). Optional: `acc` (array of at most 16 objects with exactly `id`
 * ([A-Za-z0-9_]{1,64}, distinct), `post` (safe integer >= 0) and an optional `receipt` (32-byte digest)); `facts`,
 * `classes`, `labels` (arrays of at most 16 / 8 / 16 distinct 32-byte digests); `offer_set` (32-byte digest); `prov` (an
 * object of at most 32 entries: key `action.params.<name>`, value 1..8 non-empty strings of at most 256 UTF-8 bytes).
 */
export function validateIntentSessionWire(v: unknown): string | null {
  if (!isObj(v)) return "'intent_session' must be an object";
  for (const k of Object.keys(v)) if (!(INTENT_SESSION_FIELDS as readonly string[]).includes(k)) return `unknown field 'intent_session.${k}'`;
  for (const k of ['session', 'root', 'seq', 'schema']) if (!own(v, k)) return `missing field 'intent_session.${k}'`;
  for (const k of ['session', 'root', 'schema']) if (!b32(v[k])) return `'intent_session.${k}' is not canonical base64url (32 bytes)`;
  if (!isNonNeg(v.seq) || v.seq > MAX_SESSION_SEQ) return "'intent_session.seq' must be a safe integer in [0, 2147483647]";
  if (v.acc !== undefined) {
    if (!Array.isArray(v.acc) || v.acc.length > MAX_IS_ACC) return `'intent_session.acc' must be an array of at most ${MAX_IS_ACC} entries`;
    const ids = new Set<string>();
    for (const [i, a] of v.acc.entries()) {
      if (!isObj(a)) return `'intent_session.acc[${i}]' must be an object`;
      for (const k of Object.keys(a)) if (!['id', 'post', 'receipt'].includes(k)) return `unknown field 'intent_session.acc[${i}].${k}'`;
      if (typeof a.id !== 'string' || !ACC_ID_RE.test(a.id)) return `'intent_session.acc[${i}].id' must match [A-Za-z0-9_]{1,64}`;
      if (ids.has(a.id)) return `'intent_session.acc' ids must be distinct`;
      ids.add(a.id);
      if (!isNonNeg(a.post)) return `'intent_session.acc[${i}].post' must be a non-negative safe integer`;
      if (a.receipt !== undefined && !b32(a.receipt)) return `'intent_session.acc[${i}].receipt' is not canonical base64url (32 bytes)`;
    }
  }
  if (v.facts !== undefined) {
    const e = digestList(v.facts, 'facts', MAX_IS_FACTS);
    if (e) return e;
  }
  if (v.offer_set !== undefined && !b32(v.offer_set)) return "'intent_session.offer_set' is not canonical base64url (32 bytes)";
  if (v.prov !== undefined) {
    if (!isObj(v.prov) || Object.keys(v.prov).length > MAX_IS_PROV_PATHS) return `'intent_session.prov' must be an object of at most ${MAX_IS_PROV_PATHS} entries`;
    for (const [path, refs] of Object.entries(v.prov)) {
      if (!/^action\.params\.[A-Za-z0-9_]{1,64}$/.test(path)) return `'intent_session.prov' key '${path}' is not action.params.<name>`;
      if (!Array.isArray(refs) || refs.length === 0 || refs.length > MAX_IS_PROV_REFS || !refs.every(shortStr)) return `'intent_session.prov.${path}' must be 1..${MAX_IS_PROV_REFS} non-empty strings of at most ${MAX_IS_STRING_BYTES} UTF-8 bytes`;
    }
  }
  if (v.classes !== undefined) {
    const e = digestList(v.classes, 'classes', MAX_IS_CLASSES);
    if (e) return e;
  }
  if (v.labels !== undefined) {
    const e = digestList(v.labels, 'labels', MAX_IS_LABELS);
    if (e) return e;
  }
  if (own(v, 'map_form') && v.map_form !== 'commit') return "'intent_session.map_form' must be \"commit\" when present";
  return null;
}

// ---- goals and the grant caveat ----------------------------------------------------------------------------------

/** The goal a session grant (G_0 or D_k) commits to: `pca-intent:v2:<σ>:<map_digest_k>` (`pca-intent:v2c:` over a committed map). */
export function intentGoalV2(session: string, mapDigest: string, mapForm?: 'commit'): string {
  return (mapForm === 'commit' ? INTENT_GOAL_V2C_PREFIX : INTENT_GOAL_V2_PREFIX) + session + ':' + mapDigest;
}

export function parseIntentGoalV2(goal: string): { session: string; mapDigest: string } | null {
  if (typeof goal !== 'string' || !goal.startsWith(INTENT_GOAL_V2_PREFIX)) return null;
  const parts = goal.slice(INTENT_GOAL_V2_PREFIX.length).split(':');
  if (parts.length !== 2 || !b32(parts[0]) || !b32(parts[1])) return null;
  return { session: parts[0]!, mapDigest: parts[1]! };
}

/** The FIRST caveat of `grant` whose type is `intent_session` (as is; validate with {@link intentSessionCaveatError}). */
export function grantSessionCaveat(grant: unknown): Record<string, unknown> | undefined {
  if (!isObj(grant) || !Array.isArray(grant.caveats)) return undefined;
  return grant.caveats.find((c) => isObj(c) && c.type === INTENT_SESSION_CAVEAT) as Record<string, unknown> | undefined;
}

// ---- the session root S ---------------------------------------------------------------------------------------

export interface SessionPrincipal {
  /** b64u Ed25519 identity. */
  key: string;
  alg?: SigAlg;
  /**
   * The principal's PQ key for a non-ed25519 suite, as the signer DECLARES it. Not a trust anchor: verifiers take the
   * signer's PQ key from their own pins (`verifySessionRoot(S, { pqPins })`); a declared key must agree with them.
   */
  pq_pk?: string;
}

export interface SessionLayerRef {
  digest: string;
  [k: string]: unknown;
}

export interface SessionRoot {
  v: 1;
  kind: typeof INTENT_SESSION_KIND;
  session: string;
  principals: SessionPrincipal[];
  intent_ref: string;
  schema: { aud: string; digest: string };
  /** G^org / G^std / G^task references (V5 owns their semantics; `std` is the standing profile version, V10). */
  /** An absent `org` / `std` means no such layer; null is malformed. */
  layers: { org?: SessionLayerRef; std?: { profile: string; version: number; digest: string }; task: { map_digest: string } };
  accumulators: AccumulatorDecl[];
  monitors: MonitorDecl[];
  question_uri: string;
  /**
   * The session's revocation source: `key` is the DEDICATED revocation authority (never a principal), the only key whose
   * epochs count, with its pinned PQ key `pq_pk` for a PQ suite.
   */
  revocation?: { epoch_uri: string; max_age_s: number; key: string; pq_pk?: string };
  /** Read-side flow rules (V14); a container here. */
  flows?: Record<string, unknown>;
  expires_at: number;
  /** The principal key (in `principals`) that signed S. */
  signer: string;
  alg?: SigAlg;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
}
export type SessionRootBody = Omit<SessionRoot, 'signer' | 'alg' | 'pq_pk' | 'sig' | 'pq_sig'>;

const ROOT_KEYS = ['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors', 'question_uri', 'revocation', 'flows', 'expires_at', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];
export const MAX_SESSION_PRINCIPALS = 16;

export function sessionRootShapeError(s: unknown, opts: { signed?: boolean } = {}): string | null {
  try {
    if (!isObj(s)) return 'session root is not an object';
    for (const k of Object.keys(s)) if (!ROOT_KEYS.includes(k)) return `session root: unknown member '${k}'`;
    if (s.v !== 1 || s.kind !== INTENT_SESSION_KIND) return 'not a pca-intent-session v1';
    if (!b32(s.session) || !b32(s.intent_ref)) return 'session and intent_ref must be canonical base64url (32 bytes)';
    if (!Array.isArray(s.principals) || s.principals.length === 0 || s.principals.length > MAX_SESSION_PRINCIPALS) return `principals must be 1..${MAX_SESSION_PRINCIPALS} keys`;
    const keys = new Set<string>();
    for (const p of s.principals) {
      if (!isObj(p) || Object.keys(p).some((k) => !['key', 'alg', 'pq_pk'].includes(k)) || !b32(p.key)) return 'principals entries are {key, alg?, pq_pk?} with a 32-byte key';
      if (suiteErr(p.alg)) return `principal alg: ${suiteErr(p.alg)}`;
      if (p.pq_pk !== undefined && decodeB64uStrict(p.pq_pk) === null) return 'principal pq_pk is not canonical base64url';
      if (keys.has(p.key as string)) return 'principal keys must be distinct';
      keys.add(p.key as string);
    }
    if (!isObj(s.schema) || Object.keys(s.schema).sort().join() !== 'aud,digest' || typeof s.schema.aud !== 'string' || s.schema.aud.length === 0 || !b32(s.schema.digest)) return 'schema must be {aud, digest}';
    if (!isObj(s.layers)) return 'layers must be an object';
    for (const k of Object.keys(s.layers)) if (!['org', 'std', 'task'].includes(k)) return `layers: unknown member '${k}'`;
    const L = s.layers;
    if (!isObj(L.task) || Object.keys(L.task).join() !== 'map_digest' || !b32(L.task.map_digest)) return 'layers.task must be {map_digest}';
    if (L.org !== undefined && (!isObj(L.org) || !b32(L.org.digest))) return 'layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)';
    if (L.std !== undefined) {
      const d = L.std;
      if (!isObj(d) || Object.keys(d).sort().join() !== 'digest,profile,version' || typeof d.profile !== 'string' || d.profile.length === 0 || u8len(d.profile) > 128 || !(isInt(d.version) && d.version >= 1) || !b32(d.digest)) {
        return 'layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)';
      }
    }
    if (!Array.isArray(s.accumulators) || s.accumulators.length > MAX_SESSION_ACCUMULATORS) return `accumulators must be an array of at most ${MAX_SESSION_ACCUMULATORS}`;
    const ids = new Set<string>();
    for (const a of s.accumulators) {
      const e = accumulatorDeclError(a);
      if (e) return e;
      if (ids.has((a as AccumulatorDecl).id)) return 'accumulator and monitor ids must be distinct';
      ids.add((a as AccumulatorDecl).id);
    }
    if (!Array.isArray(s.monitors) || s.monitors.length > MAX_SESSION_MONITORS) return `monitors must be an array of at most ${MAX_SESSION_MONITORS}`;
    const mids = new Set<string>();
    for (const m of s.monitors) {
      const e = monitorDeclError(m);
      if (e) return e;
      if (mids.has((m as MonitorDecl).id)) return 'monitor ids must be distinct';
      mids.add((m as MonitorDecl).id);
    }
    if (typeof s.question_uri !== 'string' || s.question_uri.length === 0 || u8len(s.question_uri) > 2048) return 'question_uri must be a non-empty string';
    if (s.revocation !== undefined) {
      const r = s.revocation;
      if (!isObj(r) || Object.keys(r).some((k) => !['epoch_uri', 'max_age_s', 'key', 'pq_pk'].includes(k))) return 'revocation must be {epoch_uri, max_age_s, key, pq_pk?}';
      if (typeof r.epoch_uri !== 'string' || r.epoch_uri.length === 0) return 'revocation.epoch_uri must be a non-empty string';
      if (!isNonNeg(r.max_age_s)) return 'revocation.max_age_s must be a non-negative safe integer';
      if (!b32(r.key)) return 'revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)';
      if (keys.has(r.key as string)) return 'revocation.key must not be a session principal (a dedicated revocation authority)';
      if (r.pq_pk !== undefined && decodeB64uStrict(r.pq_pk) === null) return 'revocation.pq_pk must be canonical base64url';
    }
    if (s.flows !== undefined && !isObj(s.flows)) return 'flows must be an object';
    if (!isNonNeg(s.expires_at)) return 'expires_at must be a non-negative safe integer (epoch ms)';
    if (opts.signed !== false) {
      if (!b32(s.signer)) return 'signer must be canonical base64url (32 bytes)';
      if (!keys.has(s.signer as string)) return 'signer is not one of the session principals';
      if (suiteErr(s.alg)) return `alg: ${suiteErr(s.alg)}`;
      const suite = resolveSigAlg(s.alg)!;
      if (suite.alg === 'ed25519' && (s.pq_pk !== undefined || s.pq_sig !== undefined)) return 'an ed25519 session root must not carry pq_pk / pq_sig';
      if (typeof s.sig !== 'string') return 'sig must be a string';
    }
    canonicalBytesStrict(sessionRootBody(s as unknown as SessionRoot));
    return null;
  } catch (e) {
    return `malformed session root: ${(e as Error).message}`;
  }
}

function sessionRootBody(s: SessionRootBody): SessionRootBody {
  const { v, kind, session, principals, intent_ref, schema, layers, accumulators, monitors, question_uri, revocation, flows, expires_at } = s;
  return {
    v, kind, session, principals, intent_ref, schema, layers, accumulators, monitors, question_uri,
    ...(revocation !== undefined ? { revocation } : {}),
    ...(flows !== undefined ? { flows } : {}),
    expires_at,
  };
}

function rootMessage(body: object): Uint8Array {
  const dom = utf8(INTENT_SESSION_SIG_DOMAIN);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
}

/** Sign S as one of its principals (the signer's Ed25519 identity must be listed in `principals`). */
export function signSessionRoot(body: SessionRootBody, principalSecret: Uint8Array, suite?: SignerSuiteOpts): SessionRoot {
  const bad = sessionRootShapeError(body, { signed: false });
  if (bad) throw new Error(`signSessionRoot: ${bad}`);
  const signer = b64u(publicKeyOf(principalSecret));
  if (!body.principals.some((p) => p.key === signer)) throw new Error('signSessionRoot: the signer is not one of the session principals');
  const pqPk = suitePqPublicKey(suite?.alg, suite);
  const base = { ...sessionRootBody(body), signer };
  const fields = signSuiteArtifact(suite?.alg, suiteKeysOf(principalSecret, suite), rootMessage(bindSuiteFields(base, suite?.alg, pqPk)));
  return { ...base, ...fields } as SessionRoot;
}

/** Verifier-side PQ pins for {@link verifySessionRoot}: `{ [signer ed25519 b64u]: pq_pk b64u }`, from the verifier's own registry. */
export interface SessionRootVerifyOpts {
  /**
   * The signer's PQ public key, pinned OUT OF BAND (an enrolled-key registry, `pqPinFor` over a signed binding, a reader's
   * trust file). REQUIRED for a pure-PQ or hybrid root: the root's own `principals[].pq_pk` is part of the presented
   * artifact, so it proves nothing about who signed it. Ignored for an Ed25519 root.
   */
  pqPins?: Readonly<Record<string, string>>;
}

/**
 * Verify S: shape, signer listed, suite signature. FAIL-CLOSED for PQ: a non-ed25519 root verifies only under
 * `opts.pqPins[S.signer]` (never under the root's own `principals[].pq_pk`, which would let anyone naming the signer sign a
 * pure-PQ root under a key of their choosing); no pin, or a pin that differs from the root's `pq_pk`, fails. The signer's
 * own principals entry, when it declares a `pq_pk`, must also agree. An Ed25519 root is unchanged (pins are not consulted).
 */
export function verifySessionRoot(s: unknown, opts: SessionRootVerifyOpts = {}): { ok: true } | { ok: false; reason: string } {
  try {
    const bad = sessionRootShapeError(s);
    if (bad) return { ok: false, reason: bad };
    const r = s as SessionRoot;
    const suite = resolveSigAlg(r.alg)!;
    let pin: PqPinPolicy = {};
    if (suite.needsPqPk) {
      const pins = opts?.pqPins;
      const pinned = pins !== undefined && pins !== null && Object.prototype.hasOwnProperty.call(pins, r.signer) ? pins[r.signer] : undefined;
      if (typeof pinned !== 'string') return { ok: false, reason: `session root suite '${suite.alg}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it` };
      if (pinned !== r.pq_pk) return { ok: false, reason: "session root pq_pk does not match the verifier's pin for the signer" };
      const entry = r.principals.find((x) => x.key === r.signer)!;
      if (entry.pq_pk !== undefined && entry.pq_pk !== r.pq_pk) return { ok: false, reason: "session root pq_pk does not match the signer's principals entry" };
      pin = { pqPins: { [r.signer]: pinned } };
    }
    const msg = rootMessage(bindSuiteFields({ ...sessionRootBody(r), signer: r.signer }, r.alg, r.pq_pk));
    if (!verifyPinnedSuite(r.alg, r.signer, r.pq_pk, msg, { sig: r.sig, pq_sig: r.pq_sig }, pin)) return { ok: false, reason: 'session root signature invalid' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed session root: ${(e as Error).message}` };
  }
}

/** digest(S): the content address of the whole signed session root (what `root` carries everywhere). */
export function sessionRootDigest(s: SessionRoot): string {
  return hashCanonical({ d: INTENT_SESSION_REF_DOMAIN, s });
}

// ---- minting G_0 and the delta grants D_k ---------------------------------------------------------------------

export interface MintSessionGrantArgs {
  principalSecret: Uint8Array;
  principalPublic: string;
  /** The wallet / agent holder of the root (the agent then gets an attenuation hop under it). */
  holder: string;
  holderPq?: string;
  session: string;
  seq: number;
  /** id of D_{k-1} (or G_0); required iff seq > 0. */
  prev?: string;
  /** sessionRootDigest(S). */
  root: string;
  /** The task map digest m_k this grant was computed from (the goal); the map COMMITMENT when `mapForm` is "commit". */
  mapDigest: string;
  /** Rule 19: mint over a committed map (goal `pca-intent:v2c:<σ>:<map_commit>`). */
  mapForm?: 'commit';
  /** The predicates of the cells this grant admits (G̃_1(m_0) for G_0; D_k = G̃_1(m_k) ∖ G̃_1(m_{k-1}) for a delta). */
  predicates: Predicate[];
  caveats?: Caveat[];
  agentBinding?: AgentBinding;
  riskPolicy?: RiskPolicy;
  salt?: string;
  suite?: CapSuiteOpts;
}

/**
 * Mint G_0 (seq 0) or a delta grant D_k (seq k): a principal-signed ROOT capability whose caveats are the envelope
 * (goal `pca-intent:v2:<σ>:<map_digest>`) and the `intent_session` caveat. Returns the goal salt (it goes into the
 * PCActn's `intent.goal_salt`).
 */
export function mintSessionGrant(a: MintSessionGrantArgs): { grant: Capability; goalSalt: string } {
  const sc: IntentSessionCaveat = { type: INTENT_SESSION_CAVEAT, session: a.session, seq: a.seq, root: a.root, ...(a.prev !== undefined ? { prev: a.prev } : {}) };
  const bad = intentSessionCaveatError(sc);
  if (bad) throw new Error(`mintSessionGrant: ${bad}`);
  if (!b32(a.mapDigest)) throw new Error('mintSessionGrant: mapDigest must be canonical base64url (32 bytes)');
  const goalSalt = a.salt ?? b64u(randomBytes(16));
  const envelope = JSON.parse(
    JSON.stringify({
      type: ENVELOPE_CAVEAT,
      goal_commit: goalCommitOf(intentGoalV2(a.session, a.mapDigest, a.mapForm), goalSalt),
      predicates: a.predicates,
      caveats: a.caveats ?? [],
      agent_binding: a.agentBinding ?? {},
      risk_policy: a.riskPolicy ?? DEFAULT_RISK_POLICY,
    }),
  ) as Caveat;
  const grant = mintRoot({
    principalSecret: a.principalSecret,
    principalPublic: a.principalPublic,
    holder: a.holder,
    ...(a.holderPq !== undefined ? { holderPq: a.holderPq } : {}),
    caveats: [envelope, sc],
    ...(a.suite ? { suite: a.suite } : {}),
  });
  return { grant, goalSalt };
}
