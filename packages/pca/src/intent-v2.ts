import type { Capability } from './capability';
import { type ActionSchema, type ActionSchemaKey, actionSchemaDigest, conformAction, schemaVerb, verifyActionSchema } from './action-schema';
import {
  type AccPreState,
  type AccReceipt,
  accReceiptDigest,
  accSelects,
  accValueOf,
  combineAcc,
  monitorStates,
  pcactnReservationDigest,
  preStateError,
  preValue,
  receiptArithmeticOk,
  type TrackedKeySet,
  trackedKeySetError,
  verifyReceiptAgainstHolder,
} from './intent-acc';
import { type SessionRevocationEvidence, checkSessionRevocation, deltaRevocationId, mapRevocationId, profileRevocationId, sessionRevocationId } from './intent-revocation';
import { type IntentSessionWire, type SessionRoot, grantSessionCaveat, sessionRootDigest, verifySessionRoot } from './intent-session';
import { intentSessionCaveatError } from './intent-session-caveat';
import { paramsDigest } from './merkle';
import { type LayerCeilings, decideLayerCeilings } from './intent-layers';
import { type IntentWBInput, decideIntentWB } from './intent-env';
import { canonicalizeStrict, compareUtf8 } from './hash';
import { type MapPolicy, decideMapDisclosure } from './intent-map-commit';
import { freeRecord, isPlainObject, isSafeInt, isSafeNonNeg, ownGet, suiteCapabilityError } from './intent-strict';
import { resolveSigAlg } from './pq';
import { readEnvelope } from './envelope';
import { decideTighten, decideUnits, modelPathsRead } from './decision';
import { type EvolutionRecord, type Reapproval, type Rule22Engine, type ReviewerPinsCtx, MAX_ESC_TIER, actionPinError, decidePin } from './action-pin';

/** Shape of the verifier context a check reads (lists are arrays, records plain objects, numbers safe integers). */
const optObj = (v: unknown) => v === undefined || isPlainObject(v);
const optArr = (v: unknown) => v === undefined || Array.isArray(v);

/**
 * The whole v2 context: ABSENT members mean empty / default, a member PRESENT with null (or of the wrong JSON type) is
 * malformed and fails closed. This covers the members passed through to the V5 `layers` and W-B checks too.
 */
export function intentV2ContextError(ctx: unknown): string | null {
  if (ctx === undefined) return null;
  if (!isPlainObject(ctx)) return 'the v2 verifier context must be an object';
  const pol = ctx.policy;
  if (!optObj(pol)) return 'policy must be an object';
  if (pol !== undefined) {
    // closed member sets; every flag is a JSON boolean and every number a safe integer when present (absent = default)
    const pr = pol as Record<string, unknown>;
    for (const k of Object.keys(pr)) if (k !== 'session' && k !== 'schema' && k !== 'acc' && k !== 'map' && k !== 'model_polarity') return `policy: unknown member '${k}'`;
    if (pr.model_polarity !== undefined && pr.model_polarity !== 'strict' && pr.model_polarity !== 'legacy') return "policy.model_polarity must be 'strict' or 'legacy'";
    const ps = pr.session;
    if (!optObj(ps)) return 'policy.session must be an object';
    if (ps !== undefined) {
      const o = ps as Record<string, unknown>;
      for (const k of Object.keys(o)) if (k !== 'require' && k !== 'max_revocation_age_s') return `policy.session: unknown member '${k}'`;
      if (o.require !== undefined && typeof o.require !== 'boolean') return 'policy.session.require must be a boolean';
      if (o.max_revocation_age_s !== undefined && !isSafeNonNeg(o.max_revocation_age_s)) return 'policy.session.max_revocation_age_s must be a non-negative safe integer';
    }
    const pc = pr.schema;
    if (!optObj(pc)) return 'policy.schema must be an object';
    if (pc !== undefined) {
      const o = pc as Record<string, unknown>;
      for (const k of Object.keys(o)) if (k !== 'closed_world') return `policy.schema: unknown member '${k}'`;
      if (o.closed_world !== undefined && typeof o.closed_world !== 'boolean') return 'policy.schema.closed_world must be a boolean';
    }
    const pa = pr.acc;
    if (!optObj(pa)) return 'policy.acc must be an object';
    if (pa !== undefined) {
      const o = pa as Record<string, unknown>;
      for (const k of Object.keys(o)) if (k !== 'max_receipt_age_s' && k !== 'max_keyset_age_s') return `policy.acc: unknown member '${k}'`;
      for (const k of ['max_receipt_age_s', 'max_keyset_age_s']) if (o[k] !== undefined && !isSafeNonNeg(o[k])) return `policy.acc.${k} must be a non-negative safe integer`;
    }
    const pm = pr.map;
    if (!optObj(pm)) return 'policy.map must be an object';
    if (pm !== undefined) {
      const o = pm as Record<string, unknown>;
      for (const k of Object.keys(o)) if (k !== 'require' && k !== 'max_residual_risk_ppm') return `policy.map: unknown member '${k}'`;
      if (o.require !== undefined && typeof o.require !== 'boolean') return 'policy.map.require must be a boolean';
      if (o.max_residual_risk_ppm !== undefined && !isSafeNonNeg(o.max_residual_risk_ppm)) return 'policy.map.max_residual_risk_ppm must be a non-negative safe integer';
    }
  }
  if (ctx.rule22 !== undefined && (!isPlainObject(ctx.rule22) || typeof ctx.rule22.schemaError !== 'function' || typeof ctx.rule22.decide !== 'function')) return 'rule22 must be {schemaError, decide}';
  if (!optObj(ctx.reviewers) || (ctx.reviewers !== undefined && !Array.isArray((ctx.reviewers as { keys?: unknown }).keys))) return 'reviewers must be {keys: [...]}';
  if (ctx.call_context !== undefined && (!Array.isArray(ctx.call_context) || ctx.call_context.some((x) => typeof x !== 'string'))) return 'call_context must be an array of strings';
  const ac = ctx.actions;
  if (!optObj(ac)) return 'actions must be an object';
  if (ac !== undefined) for (const k of ['records', 'keys', 'reapprovals']) if (!optArr((ac as Record<string, unknown>)[k])) return `actions.${k} must be an array`;
  if (!optObj(ctx.params)) return 'params must be an object';
  if (!optObj(ctx.env)) return 'env must be an object';
  for (const k of ['schema', 'session', 'acc'] as const) if (!optObj(ctx[k])) return `${k} must be an object`;
  const M = ctx.map;
  if (!optObj(M)) return 'map must be an object';
  if (M !== undefined) for (const k of Object.keys(M as object)) if (k !== 'disclosure') return `map: unknown member '${k}'`;
  const L = ctx.layers;
  if (L !== undefined) {
    if (!isPlainObject(L)) return 'layers must be an object';
    for (const [k, v] of Object.entries(L)) {
      if (!['org', 'site', 'std'].includes(k)) return `layers: unknown member '${k}'`;
      if (!isPlainObject(v) || !Array.isArray(v.predicates)) return `layers.${k} must be {predicates: [...]}`;
    }
  }
  const wb = ctx.wb;
  if (wb !== undefined) {
    if (!isPlainObject(wb)) return 'wb must be an object';
    const a = wb.artifacts;
    if (!optObj(a)) return 'wb.artifacts must be an object';
    if (a !== undefined) {
      const ar = a as Record<string, unknown>;
      for (const k of ['facts', 'labels', 'verdicts']) if (!optArr(ar[k])) return `wb.artifacts.${k} must be an array`;
      if (!optObj(ar.offer_set)) return 'wb.artifacts.offer_set must be an object';
    }
    const p = wb.policy;
    if (!optObj(p)) return 'wb.policy must be an object';
    if (p !== undefined) {
      const pr = p as Record<string, unknown>;
      if (!optObj(pr.world) || !optObj(pr.provenance)) return 'wb.policy.world / provenance must be objects';
      if (!optArr(pr.classifiers)) return 'wb.policy.classifiers must be an array';
    }
  }
  return null;
}

function schemaCtxError(ctx: IntentV2Context | undefined): string | null {
  const sc = ctx?.schema;
  if (sc === undefined) return null;
  if (!isPlainObject(sc) || !Array.isArray(sc.docs) || !Array.isArray(sc.keys)) return 'the schema context must be {docs: [...], keys: [...]}';
  return null;
}
function sessionCtxError(ctx: IntentV2Context | undefined): string | null {
  const se = ctx?.session;
  if (se === undefined) return null;
  if (!isPlainObject(se)) return 'the session context must be an object';
  if (se.grants !== undefined && !Array.isArray(se.grants)) return 'the session grants must be an array';
  if (se.revocation !== undefined && !isPlainObject(se.revocation)) return 'the session revocation evidence must be an object';
  if (se.revocation_last !== undefined && !isPlainObject(se.revocation_last)) return 'the tracked last revocation epoch must be an object';
  if (se.pq_pins !== undefined && (!isPlainObject(se.pq_pins) || Object.values(se.pq_pins).some((v) => typeof v !== 'string'))) return 'the session pq_pins must be an object of strings';
  return null;
}
function accCtxError(ctx: IntentV2Context | undefined): string | null {
  const a = ctx?.acc;
  if (a === undefined) return null;
  if (!isPlainObject(a)) return 'the accumulator context must be an object';
  for (const k of ['state', 'monitors', 'last_seq', 'keyset_versions'] as const) if (a[k] !== undefined && !isPlainObject(a[k])) return `acc.${k} must be an object`;
  if (a.keyset_versions !== undefined) for (const v of Object.values(a.keyset_versions)) {
    const e = trackedKeySetError(v);
    if (e) return `acc.keyset_versions: ${e}`;
  }
  for (const k of ['receipts', 'sequencer_keys'] as const) if (a[k] !== undefined && !Array.isArray(a[k])) return `acc.${k} must be an array`;
  if (a.last_seq !== undefined) for (const v of Object.values(a.last_seq)) if (!isSafeNonNeg(v)) return 'acc.last_seq values must be non-negative safe integers';
  return null;
}

/**
 * The Intent Layer v2 checks of the core verifier, in their normative order after `intent` (rule 12, spec §5):
 *   `schema` (rule 14) -> `intent_session` (rule 13) -> `layers` (V5, `decideLayerCeilings`) -> `accumulators` (rule 15)
 *   -> `facts` (rule 16) -> `provenance` (rule 17) -> `classes` (rule 18)   (the last three: `decideIntentWB`).
 *
 * REPORTING (back-compat, exactly like rule 12): `schema` is reported iff the PCActn carries `intent_session` or the
 * policy's `schema.closed_world` is true; `intent_session` iff the PCActn carries it or `session.require` is true;
 * `layers` iff the PCActn carries `intent_session` and the verifier configured `layers`; `accumulators` iff the PCActn
 * carries `intent_session`; `facts` / `provenance` / `classes` iff the PCActn carries `intent_session` and
 * `decideIntentWB` reports them (their member is present or their policy is active; the first W-B failure ends W-B).
 * A W-B `question` outcome (rule 17: a tainted material value) fails its check with reason `intent_required: ...`: the
 * core denies and the host answers with a site-signed `intent_required`. A PCActn without the member, under a verifier without an
 * active v2 policy, verifies byte-identically to a pre-v2 verifier. Within each check the FIRST failing step wins.
 *
 * The decision also returns the verifier-computed `env` the grant predicates read (`env.acc.<id>.post`,
 * `env.mon.<id>.state`); it is filled only when `accumulators` passes.
 */

export interface IntentV2Policy {
  session?: {
    /** Require every PCActn to carry `intent_session` (Tier 3+). */
    require?: boolean;
    /** Δ_rev ceiling in seconds; the stricter of this and the session root's `revocation.max_age_s` applies. */
    max_revocation_age_s?: number;
  };
  schema?: {
    /** Closed world: run the `schema` check even for a PCActn without `intent_session` (against the first schema). */
    closed_world?: boolean;
  };
  /** Sequenced receipts: max age at verification (default 900 s) and max key-set age (default 3600 s). */
  acc?: { max_receipt_age_s?: number; max_keyset_age_s?: number };
  /** Rule 19 (V15): require a committed map and bound its claimed residual risk (ε). */
  map?: MapPolicy;
  /**
   * Rule 21 compatibility: `'legacy'` lets a grant read model-derived env paths in `predicates[].where` (reported degraded);
   * `'strict'` forbids it even for a grant whose envelope says `model_polarity: 'legacy'`. Absent: the envelope decides
   * (default strict).
   */
  model_polarity?: 'strict' | 'legacy';
}

/** Everything the v2 checks read. All of it is VERIFIER state (its store, its configuration), never the agent's. */
export interface IntentV2Context {
  policy?: IntentV2Policy;
  /** Plaintext action params; must hash to `action.params_digest`. */
  params?: Record<string, unknown>;
  /** Host-supplied env members `tighten[]` rules may read (e.g. `judge`); the verifier-computed members replace same-named ones. */
  env?: Record<string, unknown>;
  /** Accepted schemas (current first, then previous versions still inside their acceptance window) and the site keys. */
  schema?: { docs: ActionSchema[]; keys: ActionSchemaKey[] };
  /**
   * Rule 22 (`traits`): the trait algebra (`@atlasauth/pca-actions` exports `RULE22_ENGINE`). A version 2 schema is REFUSED
   * (check `schema`) when this is absent: a verifier that cannot recompute the floors must not trust the document's.
   */
  rule22?: Rule22Engine;
  /**
   * Reviewer keys the verifier pins (role `reviewer`). A v2 verb counts as human-confirmed only when it carries a confirmation
   * signed by one of them; every other verb is unconfirmed and must carry every trait of the registry (rule 22). Absent: none.
   */
  reviewers?: ReviewerPinsCtx;
  /** Context keys the verifier OBSERVED for this call (e.g. `fresh_revocation`, `idempotency`): never the agent's claims. */
  call_context?: string[];
  /** Pin evidence (`envelope.actions`): the registry's signed evolution records and keys, and the principal's re-approvals. */
  actions?: { records?: EvolutionRecord[]; keys?: ActionSchemaKey[]; reapprovals?: Reapproval[] };
  session?: {
    /** The session root S (from the verifier's store / the wallet, by digest). */
    root?: SessionRoot;
    /** The session's earlier admitting roots G_0, D_1, ..., D_{k-1} in seq order (the verifier's own store). */
    grants?: Capability[];
    revocation?: SessionRevocationEvidence;
    /** The last session revocation epoch this verifier accepted (tracked state): a new epoch must extend it (append-only). */
    revocation_last?: SessionRevocationEvidence;
    /**
     * The verifier's PQ pins for the session principals, `{ [ed25519 b64u]: pq_pk b64u }` (its own enrolled-key registry,
     * never the session root). A pure-PQ / hybrid session root verifies only when its signer is pinned here with the root's
     * `pq_pk`; an Ed25519 root ignores it. Absent = no pins.
     */
    pq_pins?: Record<string, string>;
  };
  /** Rule 19 (V15): the agent's Z0 disclosure of the committed map (header, the action's cell, metrics). */
  map?: { disclosure?: unknown };
  /** The ceilings G^org / G^site / G^std as predicate sets (V5); absent = no `layers` check. */
  layers?: LayerCeilings;
  /** W-B inputs (rules 16–18): the artifacts delivered with the PCActn and the world / provenance / classifier policy. */
  wb?: { artifacts?: IntentWBInput['artifacts']; policy?: IntentWBInput['policy'] };
  acc?: {
    /** Pre-state per site-local accumulator id (window + key applied by the host, read under the row lock). */
    state?: Record<string, AccPreState>;
    /** Current state per monitor id (computed by the host from the session history). */
    monitors?: Record<string, string>;
    /** Reservation receipts presented with the request (sequenced accumulators). */
    receipts?: AccReceipt[];
    /** The highest receipt seq this verifier has accepted per accumulator id. */
    last_seq?: Record<string, number>;
    /** The sequencers' root-signed key sets (`pca-sequencer-keys`, fetched from `holder.keys_uri` and cached). */
    sequencer_keys?: unknown[];
    /** The newest key-set version this verifier has accepted per sequencer root (tracked state). */
    keyset_versions?: Record<string, TrackedKeySet>;
  };
}

export interface IntentV2Check {
  name: 'schema' | 'intent_session' | 'layers' | 'accumulators' | 'map' | 'facts' | 'provenance' | 'classes' | 'units' | 'tighten' | 'traits' | 'pin';
  ok: boolean;
  reason?: string;
}
/**
 * The verifier-computed predicate env. `acc` / `mon` are filled when `accumulators` passes; `canon` when `schema` passes:
 * for every PRESENT parameter of type boolean, set or array, `env.canon.<name>` is its canonical text (boolean: "true" /
 * "false"; set: the strict canonical JSON of its members sorted by UTF-8 bytes; array: the strict canonical JSON of the
 * array as sent). Grant predicates compare those with the ordinary `eq` / `in` operators: the DSL gains NO operator.
 */
export interface IntentV2Env {
  acc?: Record<string, { post: number }>;
  mon?: Record<string, { state: string }>;
  canon?: Record<string, string>;
  /** W-B (rules 16–18), filled when those checks pass. */
  world?: Record<string, number | string>;
  prov?: Record<string, unknown>;
  class?: Record<string, string>;
}
export interface IntentV2Decision {
  checks: IntentV2Check[];
  env?: IntentV2Env;
  /** The schema the action was checked against (when `schema` passed). */
  schema?: ActionSchema;
  /** Worlds decided by a single oracle (their `env.world.<name>` is model-derived, rule 21). */
  single_source?: string[];
  /** Rule 21 compatibility mode in effect: a grant reads model-derived paths and was accepted as legacy (report it degraded). */
  legacy_model_polarity?: boolean;
}

interface PcactnView {
  aud?: unknown;
  action?: { verb?: unknown; resource?: unknown; params_digest?: unknown };
  intent?: { ref: string; map_digest: string };
  intent_session?: IntentSessionWire;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isNonNeg = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

type Step = { ok: true } | { ok: false; reason: string };
const bad = (reason: string): Step => ({ ok: false, reason });

/** Rule 14 (`schema`). Returns the matched schema on success. */
function schemaStep(p: PcactnView, ctx: IntentV2Context | undefined): Step & { doc?: ActionSchema } {
  const is = p.intent_session;
  const ce = schemaCtxError(ctx);
  if (ce) return bad(ce);
  const docs = ctx?.schema?.docs;
  if (!Array.isArray(docs) || docs.length === 0) return bad('this verifier has no action schema configured');
  let doc: ActionSchema | undefined;
  if (is !== undefined) {
    doc = docs.find((d) => {
      try {
        return actionSchemaDigest(d) === is.schema;
      } catch {
        return false;
      }
    });
    if (!doc) return bad('intent_session.schema names no schema this verifier accepts');
  } else doc = docs[0];
  const v = verifyActionSchema(doc, ctx?.schema?.keys ?? []);
  if (!v.ok) return bad(`schema does not verify: ${v.reason}`);
  if (doc!.aud !== p.aud) return bad('schema aud does not match the PCActn aud');
  if (doc!.v === 2) {
    // rule 22, integrity half: the document's materialized floors and traits are recomputed, never trusted
    const eng = ctx?.rule22;
    if (eng === undefined) return bad('schema_floor_unchecked: a v2 schema needs the rule 22 trait engine to check its floors (fail closed)');
    const fe = eng.schemaError(doc, ctx?.reviewers);
    if (fe !== null) return bad(`schema_floor_forged: ${fe}`);
  }
  const params = ctx?.params;
  if (!isObj(params)) return bad('no plaintext params to check against the schema (closed world needs them)');
  if (paramsDigest(params) !== p.action?.params_digest) return bad('params do not hash to action.params_digest');
  const c = conformAction(doc!, String(p.action?.verb), params);
  if (!c.ok) return bad(`schema_violation: ${c.code}: ${c.reason}`);
  return { ok: true, doc };
}

/** The bound, verified session root (shared by rules 13 and 15). */
function boundRoot(p: PcactnView, ctx: IntentV2Context | undefined, now: number): Step & { S?: SessionRoot } {
  const is = p.intent_session!;
  const S = ctx?.session?.root;
  if (S === undefined) return bad('no session root for this session');
  // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals list
  const v = verifySessionRoot(S, { pqPins: ctx?.session?.pq_pins });
  if (!v.ok) return bad(`session root: ${v.reason}`);
  if (sessionRootDigest(S) !== is.root) return bad('intent_session.root is not the digest of the session root');
  if (S.session !== is.session) return bad('the session root names another session');
  if (!(now < S.expires_at)) return bad('the session root has expired');
  return { ok: true, S };
}

/** Rule 13 (`intent_session`). */
function sessionStep(p: PcactnView, grant: Capability, ctx: IntentV2Context | undefined, now: number): Step {
  const pol = ctx?.policy?.session;
  const maxAgeS = pol?.max_revocation_age_s;
  if (maxAgeS !== undefined && !isNonNeg(maxAgeS)) return bad('session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)');
  const is = p.intent_session;
  if (is === undefined) return bad('this verifier requires an intent_session but the PCActn carries none');
  const ce = sessionCtxError(ctx);
  if (ce) return bad(ce);
  if (p.intent === undefined) return bad('an intent_session needs the envelope.intent binding');
  const r = boundRoot(p, ctx, now);
  if (!r.ok) return r;
  const S = r.S!;
  if (S.intent_ref !== p.intent.ref) return bad('intent.ref is not the session statement');
  if (S.schema.digest !== is.schema) return bad('intent_session.schema is not the session schema');
  if (S.schema.aud !== p.aud) return bad('the session schema is for another audience');
  if (is.seq === 0 && p.intent.map_digest !== S.layers.task.map_digest) return bad('a seq-0 action must use the session task map');
  // the admitting root (the verifier's grant) is a principal-signed session grant at this seq
  const gc = grantSessionCaveat(grant);
  const ge = intentSessionCaveatError(gc);
  if (ge) return bad(`admitting root: ${ge}`);
  if (gc!.session !== is.session || gc!.root !== is.root || gc!.seq !== is.seq) return bad('the admitting root is bound to another session, root or seq');
  const principals = new Set(S.principals.map((x) => x.key));
  if (!principals.has(grant.issuer)) return bad('the admitting root is not signed by a session principal');
  // the delta chain G_0 -> D_1 -> ... -> D_k
  const prior = ctx?.session?.grants ?? [];
  if (!Array.isArray(prior) || prior.length < is.seq) return bad(`the verifier does not hold the ${is.seq} earlier grants of this session`);
  for (let i = 0; i < is.seq; i++) {
    const g = prior[i]!;
    if (!isPlainObject(g) || typeof g.id !== 'string' || typeof g.issuer !== 'string') return bad(`session grant ${i} is not a capability`);
    const gse = suiteCapabilityError(g.alg, (x) => resolveSigAlg(x) !== null);
    if (gse) return bad(`session grant ${i}: ${gse}`);
    const c = grantSessionCaveat(g);
    if (intentSessionCaveatError(c) !== null || c!.session !== is.session || c!.root !== is.root || c!.seq !== i) return bad(`session grant ${i} does not belong to this session at seq ${i}`);
    if (!principals.has(g.issuer)) return bad(`session grant ${i} is not signed by a session principal`);
    if (i > 0 && c!.prev !== prior[i - 1]!.id) return bad(`session grant ${i} does not chain to grant ${i - 1}`);
  }
  if (is.seq > 0 && gc!.prev !== prior[is.seq - 1]!.id) return bad(`the admitting root does not chain to grant ${is.seq - 1}`);
  // revocation (T22)
  if (S.revocation !== undefined || maxAgeS !== undefined) {
    const ages = [S.revocation?.max_age_s, maxAgeS].filter((x): x is number => x !== undefined);
    const maxAgeMs = Math.min(...ages) * 1000;
    if (S.revocation === undefined) return bad('revocation: the policy requires a revocation epoch but the session root names no revocation authority');
    const ids = [
      sessionRevocationId(is.session),
      mapRevocationId(p.intent.map_digest),
      ...prior.slice(0, is.seq).map((g) => deltaRevocationId(g.id)),
      deltaRevocationId(grant.id),
      ...(S.layers.std ? [profileRevocationId(S.layers.std.profile, S.layers.std.version)] : []),
    ];
    // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
    const pqPins = freeRecord<string>();
    if (S.revocation.pq_pk !== undefined) pqPins[S.revocation.key] = S.revocation.pq_pk;
    const last = ctx?.session?.revocation_last;
    const rv = checkSessionRevocation(ctx?.session?.revocation, { session: is.session, authority: S.revocation.key, ids, now, maxAgeMs, pin: { pqPins }, ...(last !== undefined ? { last } : {}) });
    if (!rv.ok) return bad(`revocation: ${rv.reason}`);
  }
  return { ok: true };
}

/** Rule 15 (`accumulators`). */
function accStep(p: PcactnView, ctx: IntentV2Context | undefined, now: number): Step & { env?: Required<Pick<IntentV2Env, 'acc' | 'mon'>> } {
  const is = p.intent_session!;
  const r = boundRoot(p, ctx, now);
  if (!r.ok) return r;
  const S = r.S!;
  const ce = accCtxError(ctx) ?? schemaCtxError(ctx);
  if (ce) return bad(ce);
  const verb = String(p.action?.verb);
  const claims = is.acc ?? [];
  for (const c of claims) {
    const a = S.accumulators.find((x) => x.id === c.id);
    if (!a) return bad(`claim '${c.id}' names no accumulator of the session`);
    if (a.holder.kind === 'wallet') return bad(`accumulator '${c.id}' is wallet-held and cannot be claimed at a site`);
  }
  const docs = ctx?.schema?.docs ?? [];
  const schemaDoc = docs.find((d) => {
    try {
      return actionSchemaDigest(d) === is.schema;
    } catch {
      return false;
    }
  });
  const params = ctx?.params;
  const env: Required<Pick<IntentV2Env, 'acc' | 'mon'>> = { acc: freeRecord(), mon: freeRecord() };
  const state = ctx?.acc?.state ?? {};
  for (const a of S.accumulators) {
    if (a.holder.kind === 'wallet') continue;
    if (a.sel.accumulates_into !== undefined && !schemaDoc) return bad(`accumulator '${a.id}' selects by accumulates_into but the session schema is not available`);
    const selected = accSelects(a, verb, schemaDoc);
    const claim = claims.find((c) => c.id === a.id);
    const pre = ownGet(state, a.id) as AccPreState | undefined;
    if (!selected) {
      if (claim) return bad(`claim '${a.id}' for an accumulator this action does not feed`);
      if (a.holder.kind === 'site_local' && pre !== undefined) {
        const pe = preStateError(a, pre);
        if (pe) return bad(`accumulator '${a.id}': ${pe}`);
        env.acc[a.id] = { post: preValue(a, pre) };
      }
      continue;
    }
    if (!claim) return bad(`no claim for accumulator '${a.id}' that this action feeds`);
    if (!isObj(params)) return bad('no plaintext params to compute accumulator values');
    if (a.key !== null) {
      const name = a.key.slice('action.params.'.length);
      if (!own(params, name)) return bad(`accumulator '${a.id}': the key parameter ${a.key} is missing`);
      const kd = schemaDoc ? schemaVerb(schemaDoc, verb)?.params[a.key] : undefined;
      if (!kd || kd.semantic.startsWith('text.')) return bad(`accumulator '${a.id}': the key must be a schema-declared identity (not free text)`);
    }
    const v = accValueOf(a, verb, params, schemaDoc);
    if (!v.ok) return bad(`accumulator '${a.id}': ${v.reason}`);
    let post: number;
    if (a.holder.kind === 'site_local') {
      if (claim.receipt !== undefined) return bad(`accumulator '${a.id}' is site-local: a receipt is not accepted`);
      if (pre === undefined) return bad(`no state for site-local accumulator '${a.id}'`);
      const pe = preStateError(a, pre);
      if (pe) return bad(`accumulator '${a.id}': ${pe}`);
      const x = combineAcc(a, pre, v);
      if (x === null) return bad(`accumulator '${a.id}' overflows 2^53-1`);
      post = x;
    } else {
      if (claim.receipt === undefined) return bad(`accumulator '${a.id}' is sequenced: the claim needs a reservation receipt`);
      const rc = (ctx?.acc?.receipts ?? []).find((x) => {
        try {
          return accReceiptDigest(x) === claim.receipt;
        } catch {
          return false;
        }
      });
      if (!rc) return bad(`the reservation receipt for '${a.id}' was not presented`);
      const pa = ctx?.policy?.acc;
      const tracked = ownGet(ctx?.acc?.keyset_versions, a.holder.root) as TrackedKeySet | undefined;
      const fresh = {
        ...(pa?.max_receipt_age_s !== undefined ? { maxReceiptAgeMs: pa.max_receipt_age_s * 1000 } : {}),
        ...(pa?.max_keyset_age_s !== undefined ? { maxKeySetAgeMs: pa.max_keyset_age_s * 1000 } : {}),
        ...(tracked !== undefined ? { tracked } : {}),
      };
      if (!verifyReceiptAgainstHolder(rc, a.holder, ctx?.acc?.sequencer_keys ?? [], now, fresh)) return bad(`the reservation receipt for '${a.id}' is not signed by a key the session sequencer's root-signed key set lists for its issue time`);
      if (rc.session !== is.session || rc.acc !== a.id || rc.aud !== p.aud) return bad(`the reservation receipt for '${a.id}' is for another session, accumulator or audience`);
      if (rc.pcactn_digest !== pcactnReservationDigest(p as unknown as Record<string, unknown>)) return bad(`the reservation receipt for '${a.id}' is for another action`);
      if (!(now <= rc.expires_at)) return bad(`the reservation receipt for '${a.id}' has expired`);
      const last = ownGet(ctx?.acc?.last_seq, a.id) as number | undefined;
      if (last !== undefined && !(rc.seq > last)) return bad(`the reservation receipt for '${a.id}' replays seq ${rc.seq} (last accepted ${last})`);
      if (!receiptArithmeticOk(a, rc, v.val)) return bad(`the reservation receipt for '${a.id}' does not add up`);
      post = rc.post;
    }
    if (a.domain_max !== undefined && post > a.domain_max) return bad(`accumulator '${a.id}' post ${post} is outside its domain (max ${a.domain_max})`);
    if (claim.post !== post) return bad(`claimed post ${claim.post} for '${a.id}' differs from the verifier's ${post}`);
    env.acc[a.id] = { post };
  }
  const mons = ctx?.acc?.monitors ?? {};
  for (const m of S.monitors) {
    const st = ownGet(mons, m.id);
    if (typeof st !== 'string' || !monitorStates(m).includes(st)) return bad(`no valid state for monitor '${m.id}'`);
    env.mon[m.id] = { state: st };
  }
  return { ok: true, env };
}

/**
 * Run the v2 checks (never throws: an internal error fails the check being evaluated). `p.intent_session` must have passed
 * `validateIntentSessionWire` (the core verifier wire-checks the PCActn first): a committed member of the wrong type is read as
 * absent here, so a host that calls this function directly validates the member itself.
 */
export function decideIntentV2(p: PcactnView, grant: Capability, ctx: IntentV2Context | undefined, now: number): IntentV2Decision {
  const out: IntentV2Decision = { checks: [] };
  const present = p?.intent_session !== undefined;
  const clockOk = isSafeInt(now);
  const ctxErr = intentV2ContextError(ctx);
  if (ctxErr !== null) {
    // a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
    const committed = present && (p.intent_session as { map_form?: unknown } | null)?.map_form === 'commit';
    for (const name of ['schema', 'intent_session', ...(present ? (['accumulators'] as const) : []), ...(committed ? (['map'] as const) : [])] as const) out.checks.push({ name, ok: false, reason: `malformed v2 context: ${ctxErr}` });
    return out;
  }
  const run = (name: IntentV2Check['name'], f: () => Step) => {
    let s: Step;
    try {
      s = clockOk ? f() : bad('the verifier clock is not a safe integer (fail closed)');
    } catch (e) {
      s = bad(`${name} error (fail closed): ${(e as Error).message}`);
    }
    out.checks.push(s.ok ? { name, ok: true } : { name, ok: false, reason: s.reason });
    return s;
  };
  if (present || ctx?.policy?.schema?.closed_world === true) {
    run('schema', () => {
      const s = schemaStep(p, ctx);
      if (s.ok) {
        out.schema = s.doc;
        out.env = { canon: canonProjection(s.doc!, String(p.action?.verb), ctx!.params!) };
      }
      return s;
    });
  }
  if (present || ctx?.policy?.session?.require === true) run('intent_session', () => sessionStep(p, grant, ctx, now));
  const mapActive = p.intent_session?.map_form === 'commit' || ctx?.policy?.map?.require === true;
  const params = ctx?.params;
  const action = { verb: String(p.action?.verb), resource: String(p.action?.resource), params: isObj(params) ? params : {} };
  const layers = ctx?.layers;
  if (present && layers !== undefined) {
    run('layers', () => {
      const d = decideLayerCeilings(layers, { action, env: { ...(out.env?.canon ? { canon: out.env.canon } : {}) } });
      return d.status === 'pass' ? { ok: true } : bad(d.reason);
    });
  }
  if (present) {
    run('accumulators', () => {
      const s = accStep(p, ctx, now);
      if (s.ok) out.env = { ...out.env, ...s.env };
      return s;
    });
    if (mapActive) run('map', () => mapStep(p, ctx));
    let wb: ReturnType<typeof decideIntentWB> | undefined;
    try {
      wb = decideIntentWB({ now, aud: String(p.aud), session: p.intent_session!.session, action, intent_session: p.intent_session!, ...(ctx?.wb?.artifacts ? { artifacts: ctx.wb.artifacts } : {}), policy: ctx?.wb?.policy ?? {} });
    } catch (e) {
      out.checks.push({ name: 'facts', ok: false, reason: `W-B error (fail closed): ${(e as Error).message}` });
    }
    if (wb) {
      for (const name of ['facts', 'provenance', 'classes'] as const) {
        const c = wb.checks[name];
        if (c === undefined) continue;
        if (c === 'pass') out.checks.push({ name, ok: true });
        else out.checks.push({ name, ok: false, reason: c === 'question' ? `intent_required: ${wb.reason ?? 'a question is required'}` : (wb.reason ?? 'rejected') });
      }
      if (wb.outcome !== 'deny') out.env = { ...out.env, ...(wb.env.world ? { world: wb.env.world } : {}), ...(wb.env.prov ? { prov: wb.env.prov } : {}), ...(wb.env.class ? { class: wb.env.class } : {}) };
      if (wb.single_source?.length) out.single_source = [...wb.single_source];
    }
  } else if (mapActive) {
    run('map', () => mapStep(p, ctx));
  }
  modelRules(p, grant, ctx, out, run, action);
  return out;
}

/** The predicate lists a model-derived path could widen: the grant's allow-list and the ceilings (V5 layers). */
function allowSidePredicates(env: { predicates?: unknown } | null, ctx: IntentV2Context | undefined): unknown[] {
  const lists: unknown[] = [env?.predicates];
  const L = ctx?.layers as Record<string, { predicates?: unknown } | undefined> | undefined;
  if (L && typeof L === 'object') for (const k of ['org', 'site', 'std']) lists.push(L[k]?.predicates);
  return lists;
}

/**
 * Rules 20 and 21, evaluated last (after `classes`, so the verifier-computed `env` is complete). Both read the signed
 * ENVELOPE of the stored grant:
 *   `units` (20): reported iff `envelope.units` is present.
 *   `tighten` (21): reported iff `envelope.tighten` or a `model_polarity` (envelope or policy) is present, or a grant-side
 *   `where` reads a model-derived env path (so that case is refused, never silently skipped). A PCActn with none of these
 *   verifies byte-identically to a verifier without the two rules.
 */
function modelRules(
  p: PcactnView,
  grant: Capability,
  ctx: IntentV2Context | undefined,
  out: IntentV2Decision,
  run: (name: IntentV2Check['name'], f: () => Step) => Step,
  action: { verb: string; resource: string; params: Record<string, unknown> },
): void {
  const env = readEnvelope(grant);
  const preds = allowSidePredicates(env, ctx);
  let schemaMemo: (Step & { doc?: ActionSchema }) | undefined;
  const schemaFor = (): Step & { doc?: ActionSchema } => (schemaMemo ??= out.schema !== undefined ? { ok: true, doc: out.schema } : schemaStep(p, ctx));
  if (env?.actions !== undefined) {
    run('pin', () => {
      const s = schemaFor();
      if (!s.ok) return s;
      const d = decidePin({ pin: env.actions, doc: s.doc!, verb: action.verb, records: ctx?.actions?.records ?? [], keys: ctx?.actions?.keys ?? [], reapprovals: ctx?.actions?.reapprovals ?? [], grant: { id: grant.id, issuer: grant.issuer } });
      if (d.ok) return { ok: true };
      return bad(`${d.escalate ? 'escalate: ' : ''}${d.code}: ${d.reason}${d.needs_reapproval !== undefined ? ` (re-approve diff ${d.needs_reapproval})` : ''}`);
    });
  }
  if (out.schema?.v === 2 || (env?.actions !== undefined && schemaFor().doc?.v === 2)) {
    run('traits', () => {
      const s = schemaFor();
      if (!s.ok) return s;
      const eng = ctx?.rule22;
      if (eng === undefined) return bad('schema_floor_unchecked: no rule 22 trait engine (fail closed)');
      const pin = env?.actions !== undefined && actionPinError(env.actions) === null ? env.actions : undefined;
      const caveats = [...(env?.caveats ?? []).map((c) => c?.type), ...(pin?.caveats ?? [])].filter((t): t is string => typeof t === 'string');
      const d = eng.decide({ doc: s.doc, verb: action.verb, grant: { caveats, max_esc: pin?.max_esc ?? MAX_ESC_TIER, preauth_esc: pin?.preauth_esc ?? 0 }, context: ctx?.call_context ?? [] });
      return d === 'allow' ? { ok: true } : bad(d === 'escalate' ? 'escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)' : 'the action floors exceed what the grant authorizes (rule 22)');
    });
  }
  if (env?.units !== undefined) {
    run('units', () => {
      const s = schemaFor();
      if (!s.ok) return s;
      const doc = s.doc!;
      const v = schemaVerb(doc, action.verb);
      const d = decideUnits({ units: env.units, schema_units: doc.units, verb_params: v?.params, verb: action.verb, predicates: preds });
      return d.ok ? { ok: true } : bad(d.reason);
    });
  }
  const single = out.single_source ?? [];
  const polarity = ctx?.policy?.model_polarity === 'strict' ? undefined : ctx?.policy?.model_polarity ?? env?.model_polarity;
  if (env?.tighten !== undefined || polarity !== undefined || ctx?.policy?.model_polarity !== undefined || modelPathsRead(preds, single).length > 0) {
    run('tighten', () => {
      const r = decideTighten({ predicates: preds, tighten: env?.tighten, polarity, single_source: single, context: { action, env: { ...(ctx?.env ?? {}), ...(out.env ?? {}) } } });
      if (r.legacy) out.legacy_model_polarity = true;
      return r.outcome === 'ok' ? { ok: true } : bad(r.reason ?? 'refused');
    });
  }
}

/**
 * Rule 19 (`map`, V15 Z0): reported iff the PCActn's `intent_session.map_form` is "commit" or the policy sets
 * `map.require: true`; evaluated after `accumulators` (independent of the earlier checks) and before W-B.
 */
function mapStep(p: PcactnView, ctx: IntentV2Context | undefined): Step {
  if (p.intent_session?.map_form !== 'commit') return bad('this verifier requires a committed map (intent_session.map_form "commit")');
  if (p.intent === undefined) return bad('a committed map needs the envelope.intent binding');
  const disclosure = ctx?.map?.disclosure;
  if (disclosure === undefined) return bad('no disclosure of the committed map was presented');
  const d = decideMapDisclosure({ mapCommit: p.intent.map_digest, action: p.action ?? {}, params: ctx?.params, disclosure, ...(ctx?.policy?.map?.max_residual_risk_ppm !== undefined ? { maxResidualRiskPpm: ctx.policy.map.max_residual_risk_ppm } : {}) });
  return d.ok ? { ok: true } : bad(d.reason);
}

/** `env.canon` (see {@link IntentV2Env}) for a conforming action. */
export function canonProjection(doc: ActionSchema, verb: string, params: Record<string, unknown>): Record<string, string> {
  const v = schemaVerb(doc, verb);
  const out = freeRecord<string>();
  if (!v) return out;
  for (const path of Object.keys(v.params).sort(compareUtf8)) {
    const d = ownGet(v.params, path) as ActionSchema['verbs'][number]['params'][string];
    const name = path.slice('action.params.'.length);
    if (!own(params, name)) continue;
    const x = ownGet(params, name);
    if (d.type === 'boolean') out[name] = x === true ? 'true' : 'false';
    else if (d.type === 'set') out[name] = canonicalizeStrict([...(x as string[])].sort(compareUtf8));
    else if (d.type === 'array') out[name] = canonicalizeStrict(x);
  }
  return out;
}

/** True iff any v2 check would be reported (the PCActn carries `intent_session`, a v2 policy is active, or a present context is malformed and the checks fail closed). */
export function intentV2Active(p: { intent_session?: unknown }, ctx: IntentV2Context | undefined): boolean {
  return p?.intent_session !== undefined || intentV2ContextError(ctx) !== null || ctx?.policy?.schema?.closed_world === true || ctx?.policy?.session?.require === true || ctx?.policy?.map?.require === true;
}
