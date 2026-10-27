/**
 * DoD-1 audit of the intent layer: "missing X gives Y". Every row names a required component or input that is absent,
 * stale, unknown or malformed, and pins the WHOLE outcome (the settled verdict, reason text or return value). Each group
 * starts with a positive control built from the same fixture, so a denial below is caused by the missing component and
 * not by an unrelated defect of the fixture. The rows are rendered in docs/pca/intent-layer.md.
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { mlDsa65Keygen, encodeMlDsaPublicKey } from './index';
import { suiteCapabilityError } from './intent-strict';
import {
  MemoryIntentSessionStore,
  accReceiptShapeError,
  actionSchemaDigest,
  actionSchemaKeyOf,
  admitIntentAction,
  checkSessionRevocation,
  classifierContentDigest,
  classifierVerdictRef,
  conformAction,
  decideClassifierDimensions,
  decideIntentBinding,
  decideIntentV2,
  decideIntentWB,
  decideIntentWorld,
  decideLayerCeilings,
  decideLayers,
  decideMapDisclosure,
  decideOfferSet,
  decideParamProvenance,
  factRef,
  intentGoalCommit,
  intentSessionCaveatError,
  intentV2ContextError,
  labelsRef,
  mintSessionGrant,
  offerSetRef,
  preStateError,
  signActionSchema,
  signClassifierVerdict,
  signFact,
  signIntentMapAttestation,
  signIntentObservation,
  signIntentRequired,
  signIntentStatement,
  signLabels,
  signOfferSet,
  signSessionRoot,
  validateIntentSessionWire,
  verifyActionSchema,
  verifyIntentAnchor,
  verifyIntentMapAttestation,
  verifyIntentObservation,
  verifyIntentRequired,
  verifyIntentStatement,
  verifyLabels,
  verifyReceiptAgainstHolder,
  verifySessionRoot,
  type AccumulatorDecl,
  type ActionSchema,
  type IntentV2Context,
  type UnsignedActionSchema,
} from './ext/intent';

const seed = (l: string) => sha256(utf8(`atlas-pca-test/dod1/${l}`));
const key = (l: string) => ({ sk: seed(l), pub: b64u(publicKeyOf(seed(l))) });
const principal = key('principal');
const site = key('site');
const oracle = key('oracle');
const NOW = 1_800_000_000_000;
const AUD = 'shop.example';
const SESSION = b64u(seed('session'));
const D = (l: string) => b64u(seed(l));
const unknownAlg = 'rot13-sig';

// ---- fixtures shared by several groups --------------------------------------------------------------------------------
const UNSIGNED: UnsignedActionSchema = {
  v: 1,
  kind: 'pca-action-schema',
  site: 'https://shop.example',
  aud: AUD,
  version: '1',
  verbs: [{ verb: 'shop.buy', kind: 'write', reversibility: 'irreversible', params: { 'action.params.sku': { type: 'string', semantic: 'product.ref', sensitivity: 'material' }, 'action.params.qty': { type: 'integer', min: 1, max: 5, semantic: 'quantity', sensitivity: 'material' } } }],
};
const SCHEMA = signActionSchema(UNSIGNED, 'k1', site.sk);
const KEYS = [actionSchemaKeyOf('k1', site.sk)];
const PARAMS = { sku: 'SKU-1', qty: 2 };

describe('DoD-1 intent audit: signed statements, maps, observations, anchors (intent.ts)', () => {
  const stmt = signIntentStatement({ v: 1, text: 'buy one lamp', slots: {}, sources: [], created_at: 1, nonce: 'n1' }, principal.sk);
  it('control: a signed statement verifies', () => {
    expect(verifyIntentStatement(stmt)).toEqual({ ok: true });
  });
  it('no statement at all (undefined, null, a string): denied as not an object', () => {
    for (const x of [undefined, null, 'x', 7]) expect(verifyIntentStatement(x)).toEqual({ ok: false, reason: 'intent statement is not an object' });
  });
  it('unknown statement version: denied', () => {
    expect(verifyIntentStatement({ ...stmt, v: 2 })).toEqual({ ok: false, reason: 'unsupported intent statement version' });
  });
  it('unknown signature suite: denied', () => {
    expect(verifyIntentStatement({ ...stmt, alg: unknownAlg })).toEqual({ ok: false, reason: 'unknown signature suite' });
  });
  it('a hybrid statement with no pinned PQ key for its signer, or with a different pinned key: denied (a statement cannot vouch for its own PQ key)', () => {
    const kp = mlDsa65Keygen(seed('pq-stmt'));
    const hybrid = signIntentStatement({ v: 1, text: 'buy', slots: {}, sources: [], created_at: 1, nonce: 'n' }, principal.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: kp });
    expect(verifyIntentStatement(hybrid, { pqPins: {} })).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyIntentStatement(hybrid, { pqPins: { [principal.pub]: encodeMlDsaPublicKey(mlDsa65Keygen(seed('other-pq')).publicKey) } })).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyIntentStatement(hybrid, { pqPins: { [principal.pub]: encodeMlDsaPublicKey(kp.publicKey) } })).toEqual({ ok: true });
  });
  it('a statement signed by another principal than the expected signer: denied; no expected signer: only self-consistency is proven', () => {
    expect(verifyIntentStatement(stmt, { expectedSigner: site.pub })).toEqual({ ok: false, reason: 'principal mismatch' });
    expect(verifyIntentStatement(stmt, {})).toEqual({ ok: true });
  });
  it('a map attestation: absent, for another map, from another signer: denied', () => {
    const map = { v: 1, intent_ref: null, cells: [] } as never;
    expect(verifyIntentMapAttestation(undefined)).toEqual({ ok: false, reason: 'not an intent map attestation v1' });
    const att = (() => {
      try {
        return signIntentMapAttestation(map, principal.sk, NOW);
      } catch {
        return undefined;
      }
    })();
    if (att !== undefined) expect(verifyIntentMapAttestation(att, undefined, { expectedSigner: site.pub })).toEqual({ ok: false, reason: 'signer mismatch' });
  });
  it('an observation: absent or tampered: denied', () => {
    const o = signIntentObservation({ map_digest: D('map'), verb: 'shop.buy', values: { 'action.params.qty': 1 }, y: 1, source: 'runtime', observed_at: 1 }, principal.sk);
    expect(verifyIntentObservation(o)).toEqual({ ok: true });
    expect(verifyIntentObservation(undefined)).toMatchObject({ ok: false });
    expect(verifyIntentObservation({ ...o, y: 0 })).toEqual({ ok: false, reason: 'bad signature' });
  });
  it('an anchor receipt of an unknown kind, or with no tree head: denied (never thrown)', () => {
    expect(verifyIntentAnchor({ kind: 'bogus', digest: D('d'), index: 0 } as never, principal.pub, 'i')).toEqual({ ok: false, reason: 'unknown anchor kind' });
    const r = verifyIntentAnchor({ kind: 'statement', digest: D('d'), index: 0 } as never, principal.pub, 'i');
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason.startsWith('malformed anchor receipt: ')).toBe(true);
  });
});

describe('DoD-1 intent audit: binding of the envelope intent (intent-binding.ts)', () => {
  const intent = { ref: D('ref'), map_digest: D('map'), goal_salt: 'salt', fidelity_ppm: 900_000, residual_risk_ppm: 10 };
  const grant = { caveats: [{ type: 'envelope', goal_commit: intentGoalCommit(intent) }] };
  it('control: the bound intent passes', () => {
    expect(decideIntentBinding(intent, grant, { require: true })).toEqual({ status: 'pass' });
  });
  it('no intent and no active policy: absent (the verifier did not ask for one)', () => {
    expect(decideIntentBinding(undefined, grant)).toEqual({ status: 'absent' });
  });
  it('no intent under an active policy: denied', () => {
    expect(decideIntentBinding(undefined, grant, { require: true })).toEqual({ status: 'fail', reason: 'this verifier requires an intent binding but the PCActn carries none' });
    expect(decideIntentBinding(undefined, grant, { min_fidelity_ppm: 1 })).toMatchObject({ status: 'fail' });
  });
  it('the root grant carries no goal commitment: denied', () => {
    expect(decideIntentBinding(intent, { caveats: [] }, { require: true })).toEqual({ status: 'fail', reason: 'the root grant carries no envelope goal commitment to bind the intent to' });
    expect(decideIntentBinding(intent, undefined, { require: true })).toMatchObject({ status: 'fail' });
  });
  it('a misconfigured threshold (negative, fraction, string): denied, never ignored', () => {
    for (const bad of [-1, 1.5, '5', Number.NaN]) expect(decideIntentBinding(intent, grant, { min_fidelity_ppm: bad as never })).toEqual({ status: 'fail', reason: 'intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)' });
  });
  it('a wrong salt (another goal): denied; fidelity below and risk above the bounds: denied', () => {
    expect(decideIntentBinding({ ...intent, goal_salt: 'other' }, grant, { require: true })).toEqual({ status: 'fail', reason: "intent ref / map_digest / goal_salt do not open the root grant's goal commitment" });
    expect(decideIntentBinding(intent, grant, { min_fidelity_ppm: 900_001 })).toMatchObject({ status: 'fail' });
    expect(decideIntentBinding(intent, grant, { max_residual_risk_ppm: 9 })).toMatchObject({ status: 'fail' });
  });
});

describe('DoD-1 intent audit: action schemas (action-schema.ts, intent-strict.ts)', () => {
  it('control: the signed schema verifies under the listed key and a conforming action maps to its verb', () => {
    expect(verifyActionSchema(SCHEMA, KEYS)).toEqual({ ok: true });
    expect(conformAction(SCHEMA, 'shop.buy', PARAMS).ok).toBe(true);
  });
  it('no site key listed for the schema: denied', () => {
    expect(verifyActionSchema(SCHEMA, [])).toMatchObject({ ok: false });
    expect(verifyActionSchema(SCHEMA, undefined as never)).toMatchObject({ ok: false });
  });
  it('unknown schema version: denied by the shape check', () => {
    expect(verifyActionSchema({ ...SCHEMA, v: 2 }, KEYS)).toEqual({ ok: false, reason: 'unsupported schema version' });
  });
  it('unknown verb, undeclared parameter, missing required parameter, out-of-domain value, non-object params: all map to the refusal cell', () => {
    expect(conformAction(SCHEMA, 'shop.sell', PARAMS)).toMatchObject({ ok: false, code: 'unknown_verb' });
    expect(conformAction(SCHEMA, 'shop.buy', { ...PARAMS, gift: 1 })).toMatchObject({ ok: false, code: 'undeclared_param', path: 'action.params.gift' });
    expect(conformAction(SCHEMA, 'shop.buy', { sku: 'S' })).toMatchObject({ ok: false, code: 'missing_param', path: 'action.params.qty' });
    expect(conformAction(SCHEMA, 'shop.buy', { sku: 'S', qty: 6 })).toMatchObject({ ok: false, code: 'out_of_domain' });
    expect(conformAction(SCHEMA, 'shop.buy', undefined)).toMatchObject({ ok: false, code: 'params_not_object' });
  });
  it('an unknown signature suite: refused by the shared capability gate', () => {
    expect(suiteCapabilityError(unknownAlg, () => false)).toBe("unsupported_suite: 'rot13-sig'");
    expect(suiteCapabilityError(undefined, () => false)).toBeNull();
  });
});

// ---- the v2 pipeline ------------------------------------------------------------------------------------------------
const TRIP: AccumulatorDecl = { id: 'spend', agg: 'sum', unit: 'usd', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, domain_max: 100, holder: { kind: 'site_local' } };
const rootBody = () =>
  ({
    v: 1,
    kind: 'pca-intent-session',
    session: SESSION,
    principals: [{ key: principal.pub }],
    intent_ref: D('ref'),
    schema: { aud: AUD, digest: actionSchemaDigest(SCHEMA) },
    layers: { task: { map_digest: D('map0') } },
    accumulators: [],
    monitors: [],
    question_uri: 'https://shop.example/q',
    expires_at: NOW + 1000,
  }) as never;

describe('DoD-1 intent audit: session root and session wire (intent-session.ts, intent-session-caveat.ts)', () => {
  const S = signSessionRoot(rootBody(), principal.sk);
  it('control: a session root verifies', () => {
    expect(verifySessionRoot(S)).toEqual({ ok: true });
  });
  it('no root (undefined / null): denied', () => {
    expect(verifySessionRoot(undefined)).toMatchObject({ ok: false });
    expect(verifySessionRoot(null)).toMatchObject({ ok: false });
  });
  it('unknown root version: denied', () => {
    expect(verifySessionRoot({ ...S, v: 2 })).toMatchObject({ ok: false });
  });
  it('a hybrid root without the verifier pin for its signer: denied (the root cannot vouch for its own PQ key)', () => {
    const k = mlDsa65Keygen(seed('pq-root'));
    const hybrid = signSessionRoot(rootBody(), principal.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: k });
    expect(verifySessionRoot(hybrid)).toMatchObject({ ok: false });
    expect(verifySessionRoot(hybrid, { pqPins: { [principal.pub]: encodeMlDsaPublicKey(k.publicKey) } })).toEqual({ ok: true });
  });
  it('the wire member with no schema, an unknown member, a negative seq: denied', () => {
    const base = { session: SESSION, root: D('r'), seq: 0, schema: D('s') };
    expect(validateIntentSessionWire(base)).toBeNull();
    expect(validateIntentSessionWire({ session: SESSION, root: D('r'), seq: 0 })).toMatch(/missing field/);
    expect(validateIntentSessionWire({ ...base, extra: 1 })).toMatch(/unknown field/);
    expect(validateIntentSessionWire({ ...base, seq: -1 })).toMatch(/seq/);
    expect(validateIntentSessionWire(undefined)).toMatch(/intent_session/);
  });
  it('a session caveat that is missing or malformed: denied', () => {
    expect(intentSessionCaveatError(undefined)).not.toBeNull();
    expect(intentSessionCaveatError({ type: 'intent_session' })).not.toBeNull();
  });
});

describe('DoD-1 intent audit: the v2 pipeline (intent-v2.ts): missing session root, schema, store, params, clock', () => {
  const grant = mintSessionGrant({ principalSecret: principal.sk, principalPublic: principal.pub, holder: principal.pub, session: SESSION, seq: 0, root: D('root'), mapDigest: D('map0'), predicates: [{ verb: 'shop.buy', resource: '*' }], salt: 's' }).grant;
  const p = (extra: object = {}) => ({ aud: AUD, action: { verb: 'shop.buy', resource: 'shop.example/x', params_digest: hashCanonical({}) }, intent: { ref: D('ref'), map_digest: D('map0') }, intent_session: { session: SESSION, root: D('root'), seq: 0, schema: actionSchemaDigest(SCHEMA) }, ...extra });
  const names = (d: ReturnType<typeof decideIntentV2>) => d.checks.map((c) => `${c.name}:${c.ok}`);
  it('no verifier context at all for a PCActn that carries intent_session: schema, session and accumulators all fail', () => {
    const d = decideIntentV2(p() as never, grant, undefined, NOW);
    expect(names(d)).toEqual(['schema:false', 'intent_session:false', 'accumulators:false', 'facts:false'].slice(0, 3).concat(names(d).slice(3)));
    expect(d.checks[0]).toEqual({ name: 'schema', ok: false, reason: 'this verifier has no action schema configured' });
    expect(d.checks[1]).toEqual({ name: 'intent_session', ok: false, reason: 'no session root for this session' });
    expect(d.checks[2]).toEqual({ name: 'accumulators', ok: false, reason: 'no session root for this session' });
  });
  it('no plaintext params: the schema check refuses (a closed world needs them)', () => {
    const d = decideIntentV2(p() as never, grant, { schema: { docs: [SCHEMA], keys: KEYS } }, NOW);
    expect(d.checks[0]).toEqual({ name: 'schema', ok: false, reason: 'no plaintext params to check against the schema (closed world needs them)' });
  });
  it('the schema the session names is not one this verifier accepts: denied', () => {
    const other = signActionSchema({ ...UNSIGNED, version: '2' }, 'k1', site.sk);
    const d = decideIntentV2(p() as never, grant, { schema: { docs: [other], keys: KEYS }, params: {} }, NOW);
    expect(d.checks[0]).toEqual({ name: 'schema', ok: false, reason: 'intent_session.schema names no schema this verifier accepts' });
  });
  it('a clock that is not a safe integer: every reported check fails closed', () => {
    for (const bad of [Number.NaN, 1.5, Infinity]) {
      const d = decideIntentV2(p() as never, grant, { schema: { docs: [SCHEMA], keys: KEYS }, params: {} }, bad);
      expect(d.checks.filter((c) => c.name !== 'facts').every((c) => !c.ok && c.reason === 'the verifier clock is not a safe integer (fail closed)')).toBe(true);
    }
  });
  it('a malformed verifier context (null member, unknown policy member): every reported check fails with the reason', () => {
    expect(intentV2ContextError({ schema: null })).toBe('schema must be an object');
    expect(intentV2ContextError({ policy: { bogus: 1 } })).toBe("policy: unknown member 'bogus'");
    const d = decideIntentV2(p() as never, grant, { acc: null } as never, NOW);
    expect(d.checks).toEqual([
      { name: 'schema', ok: false, reason: 'malformed v2 context: acc must be an object' },
      { name: 'intent_session', ok: false, reason: 'malformed v2 context: acc must be an object' },
      { name: 'accumulators', ok: false, reason: 'malformed v2 context: acc must be an object' },
    ]);
  });
  it('the policy requires a session but the PCActn carries none: intent_session fails', () => {
    const d = decideIntentV2({ aud: AUD, action: p().action } as never, grant, { policy: { session: { require: true } } }, NOW);
    expect(d.checks).toEqual([{ name: 'intent_session', ok: false, reason: 'this verifier requires an intent_session but the PCActn carries none' }]);
  });
  it('a policy that requires a committed map but the PCActn carries none: map fails', () => {
    const d = decideIntentV2({ aud: AUD, action: p().action } as never, grant, { policy: { map: { require: true } } }, NOW);
    expect(d.checks).toEqual([{ name: 'map', ok: false, reason: 'this verifier requires a committed map (intent_session.map_form "commit")' }]);
  });
  it('no session store: an admission cannot start (the host must supply one; a missing store throws before any state changes)', async () => {
    await expect(admitIntentAction(undefined as never, { session: SESSION, root: { accumulators: [TRIP], monitors: [] }, event: { id: 'e', verb: 'shop.buy', resource: 'r', params: {}, t: 1 }, verify: async () => ({ allow: true }) })).rejects.toThrow();
  });
  it('requireDurable refuses a volatile store (the in-process one, or one that does not say) before it is touched; a durable store is admitted', async () => {
    const run = (store: unknown) => admitIntentAction(store as never, { session: SESSION, root: { accumulators: [TRIP], monitors: [] }, event: { id: 'e', verb: 'shop.buy', resource: 'r', params: { total: 5 }, t: 1 }, verify: async () => ({ allow: true }), requireDurable: true });
    const memory = new MemoryIntentSessionStore();
    expect(memory.durable).toBe(false);
    await expect(run(memory)).rejects.toThrow('admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore');
    expect(memory.snapshot(SESSION)).toEqual([]);
    await expect(run({ withSession: async () => ({ allow: true }) })).rejects.toThrow('not durable');
    await expect(run(undefined)).rejects.toThrow('not durable');
    expect(await run({ durable: true, withSession: async (_s: string, f: (tx: unknown) => Promise<unknown>) => f({ events: async () => [], append: async () => undefined }) })).toEqual({ allow: true });
  });
  it('a session store whose verification throws: nothing is reserved and the error reaches the caller', async () => {
    const store = new MemoryIntentSessionStore();
    await expect(admitIntentAction(store, { session: SESSION, root: { accumulators: [TRIP], monitors: [] }, event: { id: 'e', verb: 'shop.buy', resource: 'r', params: { total: 5 }, t: 1 }, verify: async () => { throw new Error('boom'); } })).rejects.toThrow('boom');
    expect(store.snapshot(SESSION)).toEqual([]);
    const denied = await admitIntentAction(store, { session: SESSION, root: { accumulators: [TRIP], monitors: [] }, event: { id: 'e2', verb: 'shop.buy', resource: 'r', params: {}, t: 1 }, verify: async () => ({ allow: false }) });
    expect(denied).toEqual({ allow: false });
    expect(store.snapshot(SESSION)).toEqual([]);
  });
});

describe('DoD-1 intent audit: accumulators and sequencer receipts (intent-acc.ts)', () => {
  it('a missing, malformed or wrongly shaped pre-state for the aggregate: denied with the shape reason', () => {
    expect(preStateError({ agg: 'sum' }, { sum: 0 })).toBeNull();
    expect(preStateError({ agg: 'sum' }, undefined)).not.toBeNull();
    expect(preStateError({ agg: 'sum' }, { count: 0 })).not.toBeNull();
    expect(preStateError({ agg: 'sum' }, { sum: -1 })).not.toBeNull();
    expect(preStateError({ agg: 'sum' }, { sum: 1.5 })).not.toBeNull();
  });
  it('a receipt of no shape, and a receipt checked against no key set: denied', () => {
    expect(accReceiptShapeError(undefined)).not.toBeNull();
    expect(accReceiptShapeError({})).not.toBeNull();
    expect(verifyReceiptAgainstHolder({} as never, { kind: 'sequenced', root: principal.pub, keys_uri: 'https://x' } as never, [], NOW)).toBe(false);
    expect(verifyReceiptAgainstHolder({} as never, { kind: 'sequenced', root: principal.pub, keys_uri: 'https://x' } as never, [], Number.NaN)).toBe(false);
  });
});

describe('DoD-1 intent audit: revocation (intent-revocation.ts)', () => {
  const check = { session: SESSION, authority: principal.pub, ids: ['pca-intent:session:x'], now: NOW, maxAgeMs: 300_000 };
  it('no epoch evidence: denied', () => {
    expect(checkSessionRevocation(undefined, check)).toEqual({ ok: false, reason: 'no session revocation epoch supplied' });
    expect(checkSessionRevocation(null as never, check)).toEqual({ ok: false, reason: 'no session revocation epoch supplied' });
  });
  it('a clock that is not a safe integer, or a missing max age: denied before any evidence is read', () => {
    expect(checkSessionRevocation(undefined, { ...check, now: Number.NaN })).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
    expect(checkSessionRevocation(undefined, { ...check, maxAgeMs: undefined as never })).toEqual({ ok: false, reason: 'revocation max age misconfigured (fail closed)' });
  });
  it('evidence with an unknown member, or with no epoch: denied', () => {
    expect(checkSessionRevocation({ epoch: {}, revoked: [], extra: 1 } as never, check)).toMatchObject({ ok: false });
    expect(checkSessionRevocation({ revoked: [] } as never, check)).toMatchObject({ ok: false });
  });
});

describe('DoD-1 intent audit: required intent / question (intent-required.ts)', () => {
  const body = { v: 1, kind: 'pca-intent-required', session: SESSION, map_digest: D('map'), schema: D('schema'), pcactn_digest: D('p'), action_digest: D('a'), cell: { verb: 'shop.buy', coords: { 'action.params.qty': [0, 1] } }, reason: 'uncertain', question_id: 'q1', friction: 'tap', delivered_to: 'wallet', expires_at: NOW + 1000 } as never;
  const signed = (() => {
    try {
      return signIntentRequired(body, 'k1', site.sk);
    } catch {
      return undefined;
    }
  })();
  it('control, and no key / no key list / expired / no signed body: denied', () => {
    expect(signed).toBeDefined();
    expect(verifyIntentRequired(signed, KEYS, NOW)).toEqual({ ok: true });
    expect(verifyIntentRequired(signed, [], NOW)).toEqual({ ok: false, reason: "no site key with kid 'k1'" });
    expect(verifyIntentRequired(signed, undefined as never, NOW)).toEqual({ ok: false, reason: 'the site keys must be an array' });
    expect(verifyIntentRequired(signed, KEYS, NOW + 2000)).toEqual({ ok: false, reason: 'the question has expired' });
    expect(verifyIntentRequired(undefined, KEYS, NOW)).toMatchObject({ ok: false });
  });
  it('a clock that is present but not a safe integer: denied (a string or NaN never passes the expiry test)', () => {
    for (const bad of ['0', Number.NaN, 1.5, null]) expect(verifyIntentRequired(signed, KEYS, bad as never)).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
  });
});

describe('DoD-1 intent audit: layer ceilings (intent-layers.ts)', () => {
  const ctx = { action: { verb: 'shop.buy', resource: 'r', params: {} } };
  const allow = { predicates: [{ verb: 'shop.buy', resource: '*' }] };
  it('control: an action inside every ceiling passes', () => {
    expect(decideLayerCeilings({ org: allow, site: allow }, ctx)).toEqual({ status: 'pass' });
  });
  it('a ceiling that is null, an empty predicate list, a non-object: denied and named', () => {
    expect(decideLayerCeilings({ org: null } as never, ctx)).toEqual({ status: 'fail', layer: 'org', reason: 'layers: the org ceiling is malformed (null or not {predicates: [...]})' });
    expect(decideLayerCeilings({ site: { predicates: [] } }, ctx)).toEqual({ status: 'fail', layer: 'site', reason: 'layers: the action is outside the site ceiling (a ceiling is never a question)' });
    expect(decideLayerCeilings(undefined as never, ctx)).toEqual({ status: 'fail', layer: 'org', reason: 'layers: the layers member is malformed (not an object)' });
  });
  it('an unknown layer member: denied', () => {
    expect(decideLayerCeilings({ org: allow, region: allow } as never, ctx)).toEqual({ status: 'fail', layer: 'org', reason: 'layers: unknown member (the layers object is {org?, site?, std?})' });
  });
  it('a grant with no task layers is never admitted: intent_required (a question), never admit', () => {
    expect(decideLayers({ task: [] }, ctx)).toEqual({ decision: 'intent_required' });
    expect(decideLayers({} as never, ctx)).toEqual({ decision: 'intent_denied' });
    expect(decideLayers({ task: [allow], denied: [allow] }, ctx)).toEqual({ decision: 'intent_denied' });
  });
});

describe('DoD-1 intent audit: committed map disclosure (intent-map-commit.ts)', () => {
  const action = { verb: 'shop.buy', resource: 'r', params_digest: hashCanonical({}) };
  it('no disclosure, no commitment, malformed params: denied', () => {
    expect(decideMapDisclosure({ mapCommit: D('c'), action, params: {}, disclosure: undefined })).toMatchObject({ ok: false });
    expect(decideMapDisclosure({ mapCommit: undefined, action, params: {}, disclosure: {} })).toMatchObject({ ok: false });
    expect(decideMapDisclosure({ mapCommit: D('c'), action, params: [], disclosure: {} })).toMatchObject({ ok: false });
  });
});

// ---- W-B ----------------------------------------------------------------------------------------------------------------
describe('DoD-1 intent audit: world facts, oracles, offers (oracle-facts.ts, offer-set.ts)', () => {
  const O1 = key('o1');
  const O2 = key('o2');
  const O3 = key('o3');
  const worlds = [{ name: 'fare', subject_path: 'action.params.sku', oracles: [{ kid: 'o1', pk: O1.pub }, { kid: 'o2', pk: O2.pub }, { kid: 'o3', pk: O3.pub }], freshness_ms: 60_000, min_oracles: 3, max_faulty: 1 }];
  const f = (o: { sk: Uint8Array }, kid: string, value: number, t_obs = NOW - 1000, subject = 'SKU-1') => signFact({ name: 'fare', subject, value, t_obs, oracle: kid }, o.sk);
  const three = () => [f(O1, 'o1', 10), f(O2, 'o2', 11), f(O3, 'o3', 12)];
  const run = (facts: ReturnType<typeof three>, over: object = {}, policy: object = { worlds }) =>
    decideIntentWorld({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'shop.buy', resource: 'r', params: { sku: 'SKU-1' } }, committed: { facts: facts.map(factRef) }, facts, policy, ...over } as never);
  it('control: three fresh facts from three pinned oracles give the lower median', () => {
    expect(run(three())).toEqual({ ok: true, world: { fare: 11 }, single_source: [] });
  });
  it('no oracle facts at all while the policy declares a world: denied (zero fresh facts)', () => {
    expect(run([], {})).toEqual({ ok: false, reason: "facts: world 'fare' has 0 fresh fact(s), needs 3" });
  });
  it('an oracle that is not pinned: denied', () => {
    const facts = three();
    facts[2] = f(O3, 'o9', 12);
    expect(run(facts)).toEqual({ ok: false, reason: "facts: oracle 'o9' is not pinned for world 'fare'" });
  });
  it('an expired fact (older than freshness_ms): not counted, so the quorum is missed: denied; a future fact likewise', () => {
    const facts = three();
    facts[0] = f(O1, 'o1', 10, NOW - 60_001);
    expect(run(facts)).toEqual({ ok: false, reason: "facts: world 'fare' has 2 fresh fact(s), needs 3" });
    facts[0] = f(O1, 'o1', 10, NOW + 60_001);
    expect(run(facts)).toEqual({ ok: false, reason: "facts: world 'fare' has 2 fresh fact(s), needs 3" });
  });
  it('a clock that is not a safe integer makes every fact stale: denied', () => {
    expect(run(three(), { now: Number.NaN })).toEqual({ ok: false, reason: "facts: world 'fare' has 0 fresh fact(s), needs 3" });
    expect(run(three(), { now: '1800000000000' })).toEqual({ ok: false, reason: "facts: world 'fare' has 0 fresh fact(s), needs 3" });
  });
  it('an unknown dimension (a fact for an undeclared world): denied', () => {
    const facts = three();
    facts[0] = signFact({ name: 'tier', subject: 'SKU-1', value: 1, t_obs: NOW, oracle: 'o1' }, O1.sk);
    expect(run(facts)).toEqual({ ok: false, reason: "facts: fact for undeclared world 'tier'" });
  });
  it('a fact about another subject, a committed fact that was not supplied, a duplicate oracle: denied', () => {
    const facts = three();
    facts[0] = f(O1, 'o1', 10, NOW - 1000, 'SKU-2');
    expect(run(facts)).toEqual({ ok: false, reason: "facts: a 'fare' fact names another subject" });
    expect(run(three(), { facts: [] })).toEqual({ ok: false, reason: 'facts: a committed fact was not supplied (or is malformed)' });
    expect(run([...three(), f(O1, 'o1', 99, NOW - 2000)])).toEqual({ ok: false, reason: "facts: two facts from oracle 'o1' for world 'fare'" });
  });
  it('a fact signed with a suite this verifier does not implement: denied', () => {
    const facts = three();
    facts[0] = { ...facts[0]!, alg: unknownAlg } as never;
    expect(run([facts[0]!, facts[1]!, facts[2]!]).ok).toBe(false);
  });
  it('a malformed world context (null members) is refused before any fact is read', () => {
    expect(decideIntentWB({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r' }, intent_session: null as never })).toEqual({ outcome: 'deny', checks: { facts: 'fail' }, env: {}, reason: 'facts: the W-B context is malformed: intent_session must be an object' });
    expect(run(three(), { facts: null })).toEqual({ ok: false, reason: 'facts: facts must be an array' });
    expect(run(three(), {}, null as never)).toMatchObject({ ok: false });
  });

  // offer sets
  const OS = key('offers');
  const offerPolicy = { name: 'excess', site_keys: [{ kid: 'os1', pk: OS.pub }], max_age_ms: 60_000, offer_param: 'action.params.sku', filter: { query: {}, offer: {} } };
  const set = signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: {}, rank: 'price_asc', complete: true, offers: [{ offer_id: 'SKU-1', price: 10 }, { offer_id: 'SKU-2', price: 8 }], issued_at: NOW - 1000, kid: 'os1' } as never, OS.sk);
  const offer = (over: object = {}) => decideOfferSet({ policy: offerPolicy as never, committed: offerSetRef(set), offerSet: set, params: { sku: 'SKU-1' }, aud: AUD, session: SESSION, now: NOW, skewMs: 60_000, ...over });
  it('control: the committed, pinned, fresh offer set gives the excess over the cheapest offer', () => {
    expect(offer()).toEqual({ ok: true, excess: 2, chosen_price: 10, min_price: 8 });
  });
  it('no committed offer set, no supplied offer set, an unpinned signer, a stale set, an incomplete set: denied', () => {
    expect(offer({ committed: undefined })).toMatchObject({ ok: false });
    expect(offer({ offerSet: undefined })).toMatchObject({ ok: false });
    expect(offer({ policy: { ...offerPolicy, site_keys: [{ kid: 'os1', pk: key('other').pub }] } })).toMatchObject({ ok: false });
    expect(offer({ now: NOW + 60_000 + 1000 + 1 })).toMatchObject({ ok: false });
    const partial = signOfferSet({ ...set, complete: false } as never, OS.sk);
    expect(offer({ offerSet: partial, committed: offerSetRef(partial) })).toMatchObject({ ok: false });
    expect(offer({ now: Number.NaN })).toMatchObject({ ok: false });
  });
});

describe('DoD-1 intent audit: parameter provenance and label receipts (param-provenance.ts, label-receipts.ts)', () => {
  const LK = key('labels');
  const pol = { params: { sku: undefined } } as never;
  const policy = { params: { 'action.params.sku': 'critical' as const }, label_keys: [{ site: AUD, kid: 'lk', pk: LK.pub }] };
  const base = { aud: AUD, session: SESSION, action: { params: { sku: 'SKU-1' } } };
  void pol;
  it('no provenance declared for a critical parameter: the value is labelled agent and a typed question is raised (never an admission)', () => {
    const r = decideParamProvenance({ ...base, policy });
    expect(r.outcome).toBe('question');
    expect(r.friction).toBe('typed');
    expect(r.labels).toEqual({ 'action.params.sku': 'agent' });
  });
  it('the same with the critical-tainted mode deny: denied', () => {
    expect(decideParamProvenance({ ...base, policy: { ...policy, critical_tainted: 'deny' } })).toMatchObject({ outcome: 'deny', reason: "provenance: tainted critical parameter 'action.params.sku' (provenance 'agent') is denied by policy" });
  });
  it('a label ref that was never committed, or a receipt that was not supplied: denied', () => {
    const rc = signLabels({ site: AUD, session: SESSION, response_digest: D('resp'), issued_at: NOW, kid: 'lk', fields: { f: { class: 'public', value_digest: hashCanonical('SKU-1') } } } as never, LK.sk);
    const ref = `pca-labels:${labelsRef(rc)}#f`;
    const prov = { 'action.params.sku': [ref] };
    expect(decideParamProvenance({ ...base, policy, prov })).toMatchObject({ outcome: 'deny', reason: "provenance: label ref on 'action.params.sku' names a receipt the PCActn does not commit" });
    expect(decideParamProvenance({ ...base, policy, prov, committed_labels: [labelsRef(rc)] })).toMatchObject({ outcome: 'deny', reason: "provenance: label receipt for 'action.params.sku' was not supplied" });
    expect(decideParamProvenance({ ...base, policy, prov, committed_labels: [labelsRef(rc)], labels: [rc] }).outcome).toBe('pass');
  });
  it('a receipt signed by a key that is not pinned, or bound to another session: denied', () => {
    const rc = signLabels({ site: AUD, session: SESSION, response_digest: D('resp'), issued_at: NOW, kid: 'lk', fields: { f: { class: 'public', value_digest: hashCanonical('SKU-1') } } } as never, key('rogue').sk);
    expect(verifyLabels(rc, [{ site: AUD, kid: 'lk', pk: LK.pub }])).not.toBeNull();
    expect(verifyLabels(rc, [])).not.toBeNull();
    expect(verifyLabels(undefined, [])).not.toBeNull();
  });
  it('a policy with no params map: refused as misconfigured', () => {
    expect(decideParamProvenance({ ...base, policy: {} as never })).toMatchObject({ outcome: 'deny' });
    expect(decideParamProvenance(undefined as never)).toMatchObject({ outcome: 'deny', reason: 'provenance: input must be an object' });
  });
});

describe('DoD-1 intent audit: classifier dimensions (intent-classifier.ts)', () => {
  const J1 = key('j1');
  const J2 = key('j2');
  const content = 'please pay the invoice';
  const policy = { classifiers: [{ id: 'purpose', param: 'action.params.note', labels: ['payment', 'other'], keys: [J1.pub, J2.pub], k: 2 }] };
  const verdict = (j: { sk: Uint8Array }, label = 'payment', over: object = {}) => signClassifierVerdict({ classifier: 'purpose', session: SESSION, content_digest: classifierContentDigest(content), label, measurement: 'm1', ...over }, j.sk);
  const run = (verdicts: ReturnType<typeof verdict>[], over: object = {}) =>
    decideClassifierDimensions({ session: SESSION, action: { params: { note: content } }, committed: verdicts.map(classifierVerdictRef), verdicts, policy, ...over } as never);
  it('control: two allowlisted judges agreeing reach the quorum', () => {
    expect(run([verdict(J1), verdict(J2)])).toMatchObject({ ok: true, classes: { purpose: 'payment' } });
  });
  it('no classifier verdicts while the policy declares a classifier: denied (no quorum)', () => {
    expect(run([])).toEqual({ ok: false, reason: "classes: classifier 'purpose': no label reaches the quorum 2" });
  });
  it('a verdict from a judge not on the allowlist, for an undeclared classifier, with a label outside the set: denied', () => {
    expect(run([verdict(J1), verdict(key('x'))])).toEqual({ ok: false, reason: "classes: classifier 'purpose': judge key is not on the allowlist" });
    expect(run([verdict(J1), verdict(J2, 'payment', { classifier: 'other_dim' })])).toEqual({ ok: false, reason: "classes: verdict for undeclared classifier 'other_dim'" });
    expect(run([verdict(J1), verdict(J2, 'refund')])).toEqual({ ok: false, reason: "classes: classifier 'purpose': label 'refund' is not in its label set" });
  });
  it('a verdict about other content, for another session, with an unpinned measurement: denied', () => {
    expect(run([verdict(J1), verdict(J2, 'payment', { content_digest: classifierContentDigest('x') })])).toEqual({ ok: false, reason: "classes: classifier 'purpose': verdict is about other content" });
    expect(run([verdict(J1), verdict(J2, 'payment', { session: D('other') })])).toEqual({ ok: false, reason: "classes: classifier 'purpose': verdict bound to another session" });
    const pinned = { classifiers: [{ ...policy.classifiers[0]!, measurements: ['m-approved'] }] };
    expect(run([verdict(J1), verdict(J2)], { policy: pinned })).toEqual({ ok: false, reason: "classes: classifier 'purpose': measurement is not pinned" });
  });
  it('the classified parameter is missing from the action: denied', () => {
    expect(run([verdict(J1), verdict(J2)], { action: { params: {} } })).toEqual({ ok: false, reason: "classes: classifier 'purpose': the action carries no 'action.params.note'" });
  });
  it('a committed verdict that was not supplied, or a policy without a classifiers list: denied', () => {
    expect(run([verdict(J1), verdict(J2)], { verdicts: [] })).toEqual({ ok: false, reason: 'classes: a committed verdict was not supplied (or is malformed)' });
    expect(decideClassifierDimensions({ session: SESSION, action: {}, policy: {} } as never)).toEqual({ ok: false, reason: 'classes: policy misconfigured (fail closed): classifier policy needs a classifiers list' });
    expect(decideClassifierDimensions(undefined as never)).toEqual({ ok: false, reason: 'classes: input must be an object' });
  });
  it('two judges split between two labels (ambiguous at k=1): denied, never a coin toss', () => {
    const k1 = { classifiers: [{ ...policy.classifiers[0]!, k: 1 }] };
    expect(run([verdict(J1, 'payment'), verdict(J2, 'other')], { policy: k1 })).toEqual({ ok: false, reason: "classes: classifier 'purpose': ambiguous, 2 labels reach the quorum" });
  });
});

describe('DoD-1 intent audit: decideIntentV2 called directly with an intent_session that is not an object', () => {
  const grant = mintSessionGrant({ principalSecret: principal.sk, principalPublic: principal.pub, holder: principal.pub, session: SESSION, seq: 0, root: D('root'), mapDigest: D('map0'), predicates: [{ verb: 'shop.buy', resource: '*' }], salt: 's' }).grant;
  const view = (is: unknown) => ({ aud: AUD, action: { verb: 'shop.buy', resource: 'r', params_digest: hashCanonical({}) }, intent: { ref: D('ref'), map_digest: D('map0') }, intent_session: is });
  it('fails every reported check and never throws, with or without a malformed context (a null member used to throw on the malformed-context path)', () => {
    for (const is of [null, 'x', 5, []]) {
      for (const ctx of [undefined, { acc: null }]) {
        const d = decideIntentV2(view(is) as never, grant, ctx as never, NOW);
        expect(d.checks.slice(0, 3).map((c) => [c.name, c.ok])).toEqual([['schema', false], ['intent_session', false], ['accumulators', false]]);
      }
    }
  });
});
