import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  RevocationSet,
  b64u,
  buildDiscoveryDocument,
  buildPCActn,
  envelopeCaveatEvaluator,
  parseDiscoveryDocument,
  paramsDigest,
  publicKeyOf,
  sha256,
  mlDsa65Keygen,
  encodeMlDsaPublicKey,
  signPCActn,
  signRevocationEpoch,
  utf8,
  validateWireV2,
  verifyPCActn as verifyPCActn05,
  verifyPCActnCore,
  type PCActn,
} from './index';
import {
  MemoryIntentSessionStore,
  accContextFor,
  accPost,
  accPreState,
  accReceiptDigest,
  actionSchemaDigest,
  actionSchemaKeyOf,
  admitIntentAction,
  checkSessionRevocation,
  conformAction,
  decideIntentV2,
  intentV2Active,
  deltaRevocationId,
  draftSchemaFromMcpTools,
  draftSchemaFromOpenApi,
  intentActionDigest,
  intentProblem,
  intentSessionCaveatError,
  mapRevocationId,
  mintSessionGrant,
  monitorState,
  pcactnReservationDigest,
  reversibilityOf,
  revocationExposureEnd,
  sessionRevocationId,
  sessionRevocationScope,
  sessionRootDigest,
  settleIntentEvent,
  signAccReceipt,
  signSequencerKeySet,
  accReceiptShapeError,
  actionSchemaShapeError,
  sequencerKeySetShapeError,
  signActionSchema,
  signIntentRequired,
  signSessionRoot,
  validateIntentSessionWire,
  verbReversibility,
  verifyActionSchema,
  verifyIntentRequired,
  verifyReceiptAgainstHolder,
  sequencerKeySetDigest,
  trackedKeySetError,
  verifySessionRoot,
  walletFloorOverrides,
  type AccumulatorDecl,
  type ActionSchema,
  type IntentEvent,
  type IntentSessionWire,
  type IntentV2Context,
  type MonitorDecl,
  type SessionRoot,
  type SessionRootBody,
  type UnsignedActionSchema,
} from './ext/intent';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


// ---- fixture: the §4 walkthrough, scaled down ----------------------------------------------------------------
const seed = (l: string) => sha256(utf8(`intent-v2-test/${l}`));
const key = (l: string) => {
  const sk = seed(l);
  return { sk, pub: b64u(publicKeyOf(sk)) };
};
const principal = key('principal');
const agent = key('agent');
const site = key('site');
const sequencer = key('sequencer');
const seqRoot = key('sequencer-root');
const stranger = key('stranger');
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const REF = b64u(seed('ref'));
const MAP0 = b64u(seed('map0'));
const MAP1 = b64u(seed('map1'));
const SESSION = b64u(seed('session'));

const UNSIGNED: UnsignedActionSchema = {
  v: 1,
  kind: 'pca-action-schema',
  site: 'https://skyair.example',
  aud: AUD,
  version: '2026-10-01',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
  verbs: [
    {
      verb: 'air.book',
      kind: 'write',
      params: {
        'action.params.offer_id': { type: 'string', semantic: 'product.ref', sensitivity: 'material', issued_by_site: true },
        'action.params.total': { type: 'integer', unit: 'usd_cents', min: 0, max: 5_000_000, semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] },
        'action.params.add_ons': { type: 'set', values: ['none', 'tripshield', 'seat_plus'], default: ['none'], principal_neutral_default: true, semantic: 'product.addon', sensitivity: 'material' },
        'action.params.refundable': { type: 'boolean', semantic: 'flag', sensitivity: 'material' },
        'action.params.note': { type: 'string', semantic: 'text.note', sensitivity: 'free', required: false },
        'action.params.payee': { type: 'string', semantic: 'party.payee', sensitivity: 'free', required: false },
      },
      reversibility_by: { param: 'action.params.refundable', map: { true: 'reversible', false: 'irreversible' } },
      mcp: { tool: 'book_flight' },
    },
    {
      verb: 'air.search',
      kind: 'read',
      params: {
        'action.params.from': { type: 'string', semantic: 'place.airport', sensitivity: 'material' },
        'action.params.pax': { type: 'integer', min: 1, max: 9, semantic: 'quantity', sensitivity: 'material' },
        'action.params.date': { type: 'date', semantic: 'schedule.date', sensitivity: 'material' },
      },
      reversibility: 'reversible',
    },
  ],
};
const SCHEMA = signActionSchema(UNSIGNED, 'skyair-2026', site.sk);
const KEYS = [actionSchemaKeyOf('skyair-2026', site.sk)];
const SCHEMA_DIGEST = actionSchemaDigest(SCHEMA);

const TRIP: AccumulatorDecl = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
const QUESTIONS: AccumulatorDecl = { id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' } };
const rootBody = (over: Partial<SessionRootBody> = {}): SessionRootBody => ({
  v: 1,
  kind: 'pca-intent-session',
  session: SESSION,
  principals: [{ key: principal.pub }],
  intent_ref: REF,
  schema: { aud: AUD, digest: SCHEMA_DIGEST },
  layers: { task: { map_digest: MAP0 } },
  accumulators: [TRIP, QUESTIONS],
  monitors: [],
  question_uri: 'https://atlas.example/v1/pca/intent/sessions/x/questions',
  expires_at: NOW + 86_400_000,
  ...over,
});
const S = signSessionRoot(rootBody(), principal.sk);
const ROOT = sessionRootDigest(S);

const cap = (verb: string, lo: number | null, hi: number) => [{ verb, resource: '*', where: [...(lo !== null ? [{ field: 'env.acc.trip_spend.post', op: 'gt' as const, value: lo }] : []), { field: 'env.acc.trip_spend.post', op: 'lte' as const, value: hi }] }];
const mint = (o: { seq: number; prev?: string; map: string; salt: string; signer?: typeof principal; root?: string; session?: string; predicates?: ReturnType<typeof cap> }) =>
  mintSessionGrant({
    principalSecret: (o.signer ?? principal).sk,
    principalPublic: (o.signer ?? principal).pub,
    holder: agent.pub,
    session: o.session ?? SESSION,
    seq: o.seq,
    ...(o.prev !== undefined ? { prev: o.prev } : {}),
    root: o.root ?? ROOT,
    mapDigest: o.map,
    predicates: o.predicates ?? (o.seq === 0 ? cap('air.book', null, 40_000) : cap('air.book', 40_000, 80_000)),
    salt: o.salt,
  }).grant;
const G0 = mint({ seq: 0, map: MAP0, salt: 'salt0' });
const D1 = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1' });

const PARAMS = { offer_id: 'OF-1', total: 38_900, add_ons: ['none'], refundable: false };
// the committed plan node pins the action's params_digest (an action outside its own plan fails plan_inclusion)
const planFor = (params: Record<string, unknown>) => [{ id: 'book', verb: 'air.book', resource: 'skyair.example/bookings', reversibility_class: 'irreversible', params_digest: paramsDigest(params) }];
const build = (grant: typeof G0, o: { salt: string; map: string; is?: IntentSessionWire; params?: Record<string, unknown>; ref?: string }): PCActn =>
  buildPCActn({
    grant,
    chain: [grant],
    plan: planFor(o.params ?? PARAMS),
    nodeId: 'book',
    params: o.params ?? PARAMS,
    counter: 1,
    signerSecret: agent.sk,
    aud: AUD,
    now: NOW,
    ttlMs: 600_000,
    intent: { ref: o.ref ?? REF, map_digest: o.map, goal_salt: o.salt, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 },
    ...(o.is ? { intentSession: o.is } : {}),
  });
const is0 = (over: Partial<IntentSessionWire> = {}): IntentSessionWire => ({ session: SESSION, root: ROOT, seq: 0, schema: SCHEMA_DIGEST, acc: [{ id: 'trip_spend', post: 38_900 }], ...over });
const ctx = (over: Partial<IntentV2Context> = {}): IntentV2Context => ({
  params: PARAMS,
  schema: { docs: [SCHEMA], keys: KEYS },
  session: { root: S, grants: [] },
  acc: { state: { trip_spend: { sum: 0 } }, monitors: {} },
  ...over,
});
const core = (p: PCActn, grant: typeof G0, c: IntentV2Context | undefined) => verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: AUD, ...(c ? { intentV2: c } : {}) });
const resign = (p: PCActn): PCActn => {
  const { sig: _s, ...body } = p;
  void _s;
  return signPCActn(body, agent.sk);
};

// ---- V1: action schemas ---------------------------------------------------------------------------------------
describe('action schemas (V1, rule 14)', () => {
  it('signs, verifies and content-addresses a schema; the suite is pinned by the key entry', () => {
    expect(verifyActionSchema(SCHEMA, KEYS)).toEqual({ ok: true });
    expect(verifyActionSchema(SCHEMA, [actionSchemaKeyOf('skyair-2026', stranger.sk)])).toMatchObject({ ok: false });
    expect(verifyActionSchema(SCHEMA, [{ ...KEYS[0]!, kid: 'other' }])).toMatchObject({ ok: false });
    expect(verifyActionSchema({ ...SCHEMA, version: 'x' }, KEYS)).toMatchObject({ ok: false, reason: 'schema signature invalid' });
    expect(verifyActionSchema({ ...SCHEMA, sig: { ...SCHEMA.sig, alg: 'ml-dsa-65' } }, KEYS)).toMatchObject({ ok: false });
    expect(verifyActionSchema({ ...SCHEMA, extra: 1 }, KEYS)).toMatchObject({ ok: false });
    expect(actionSchemaDigest(SCHEMA)).toBe(SCHEMA_DIGEST);
    expect(actionSchemaDigest({ ...SCHEMA, version: 'y' })).not.toBe(SCHEMA_DIGEST);
  });

  it('maps a conforming action to Ω_S and every non-conforming one to ⊠ with the first failing rule', () => {
    expect(conformAction(SCHEMA, 'air.book', PARAMS)).toMatchObject({ ok: true });
    expect(conformAction(SCHEMA, 'air.cancel', PARAMS)).toMatchObject({ ok: false, code: 'unknown_verb' });
    expect(conformAction(SCHEMA, 'air.book', [])).toMatchObject({ ok: false, code: 'params_not_object' });
    expect(conformAction(SCHEMA, 'air.book', { ...PARAMS, reseller: 'x' })).toMatchObject({ ok: false, code: 'undeclared_param', path: 'action.params.reseller' });
    const { total: _t, ...noTotal } = PARAMS;
    void _t;
    expect(conformAction(SCHEMA, 'air.book', noTotal)).toMatchObject({ ok: false, code: 'missing_param', path: 'action.params.total' });
    expect(conformAction(SCHEMA, 'air.book', { ...PARAMS, total: '38900' })).toMatchObject({ ok: false, code: 'bad_type' });
    expect(conformAction(SCHEMA, 'air.book', { ...PARAMS, total: 5_000_001 })).toMatchObject({ ok: false, code: 'out_of_domain' });
    expect(conformAction(SCHEMA, 'air.book', { ...PARAMS, total: -0 })).toMatchObject({ ok: false, code: 'bad_type' });
    expect(conformAction(SCHEMA, 'air.book', { ...PARAMS, add_ons: ['bag'] })).toMatchObject({ ok: false, code: 'out_of_domain' });
    expect(conformAction(SCHEMA, 'air.book', { ...PARAMS, add_ons: ['none', 'none'] })).toMatchObject({ ok: false, code: 'out_of_domain' });
    expect(conformAction(SCHEMA, 'air.search', { from: 'SFO', pax: 2, date: '2026-02-29' })).toMatchObject({ ok: false, code: 'out_of_domain' });
    expect(conformAction(SCHEMA, 'air.search', { from: 'SFO', pax: 2, date: '2028-02-29' })).toMatchObject({ ok: true });
    // undeclared keys are reported before missing ones, in UTF-8 byte order
    expect(conformAction(SCHEMA, 'air.book', { zz: 1, aa: 1 })).toMatchObject({ code: 'undeclared_param', path: 'action.params.aa' });
  });

  it('T12 (property): a conforming action carries only declared parameters, all in their declared domains', () => {
    const val = fc.oneof(fc.integer({ min: -10, max: 6_000_000 }), fc.string({ maxLength: 4 }), fc.boolean(), fc.constant(['none']), fc.constant(['tripshield', 'none']), fc.constant(null));
    fc.assert(
      fc.property(fc.dictionary(fc.constantFrom('offer_id', 'total', 'add_ons', 'refundable', 'note', 'payee', 'extra'), val), (params) => {
        const r = conformAction(SCHEMA, 'air.book', params);
        if (!r.ok) return true;
        const decl = SCHEMA.verbs[0]!.params;
        for (const [k, x] of Object.entries(params)) {
          const d = decl['action.params.' + k];
          if (!d) return false;
          if (d.type === 'integer' && !(typeof x === 'number' && x >= (d.min ?? -Infinity) && x <= (d.max ?? Infinity))) return false;
          if (d.type === 'set' && !(Array.isArray(x) && x.every((e) => d.values!.includes(e as string)))) return false;
          if (d.type === 'boolean' && typeof x !== 'boolean') return false;
        }
        return ['offer_id', 'total', 'add_ons', 'refundable'].every((k) => k in params);
      }),
      { numRuns: 300 },
    );
  });

  it('value-dependent reversibility with a conservative projection', () => {
    const book = SCHEMA.verbs[0]!;
    expect(reversibilityOf(book, { refundable: true })).toBe('reversible');
    expect(reversibilityOf(book, { refundable: false })).toBe('irreversible');
    expect(reversibilityOf(book, {})).toBe('irreversible');
    expect(verbReversibility(book)).toBe('irreversible');
    expect(verbReversibility({ ...book, reversibility_by: { param: 'action.params.refundable', map: { true: 'reversible', false: 'rate_limited' } } })).toBe('rate_limited');
  });

  it('the wallet floor overrides a site `free` on money / party / contact / person / credential / text.message', () => {
    expect(walletFloorOverrides(SCHEMA)).toEqual([{ verb: 'air.book', path: 'action.params.payee', semantic: 'party.payee', declared: 'free', effective: 'material' }]);
  });

  it('imports MCP tools and OpenAPI operations as drafts (hints never lower reversibility)', () => {
    const d = draftSchemaFromMcpTools(
      [
        { name: 'book_flight', inputSchema: { type: 'object', properties: { total: { type: 'integer', minimum: 0, 'x-pca-semantic': 'money.amount' }, add_ons: { type: 'array', uniqueItems: true, items: { enum: ['none', 'bag'] } } }, required: ['total'] }, annotations: { destructiveHint: true } },
        { name: 'search', inputSchema: { type: 'object', properties: { from: { type: 'string' } } }, annotations: { readOnlyHint: true } },
      ],
      { site: 's', aud: 'a', version: '1' },
    );
    expect(d.schema.verbs.map((v) => [v.verb, v.kind, v.reversibility])).toEqual([['book_flight', 'write', 'irreversible'], ['search', 'read', 'reversible']]);
    expect(d.schema.verbs[0]!.params['action.params.add_ons']).toMatchObject({ type: 'set', values: ['none', 'bag'], required: false });
    expect(d.todo.some((t) => t.includes('reversibility'))).toBe(true);
    const o = draftSchemaFromOpenApi({ paths: { '/book': { post: { operationId: 'createBooking', 'x-pca-verb': 'air.book', requestBody: { content: { 'application/json': { schema: { properties: { total: { type: 'integer' } }, required: ['total'] } } } } } } } }, { site: 's', aud: 'a', version: '1' });
    expect(o.schema.verbs[0]).toMatchObject({ verb: 'air.book', kind: 'write', openapi: { operationId: 'createBooking' } });
  });

  it('the discovery document carries the v2 intent block (fail closed on a malformed one)', () => {
    const doc = buildDiscoveryDocument({ audience: AUD, intent: { versions: [1, 2], actions_uri: 'https://skyair.example/.well-known/pca-actions.json', schema_keys: KEYS, tiers: { 'air.book': 3 } } });
    expect(parseDiscoveryDocument(JSON.parse(JSON.stringify(doc))).intent).toMatchObject({ versions: [1, 2], tiers: { 'air.book': 3 } });
    expect(() => parseDiscoveryDocument({ ...doc, intent: { versions: [3] } })).toThrow();
    expect(() => parseDiscoveryDocument({ ...doc, intent: { versions: [2], tiers: { x: 5 } } })).toThrow();
  });
});

// ---- wire + session root + caveat ------------------------------------------------------------------------------
describe('intent_session wire, session roots and session grants (V3, rule 13)', () => {
  it('validates the closed member set and every bound', () => {
    expect(validateIntentSessionWire(is0())).toBeNull();
    expect(validateIntentSessionWire({ ...is0(), extra: 1 })).toMatch(/unknown field/);
    expect(validateIntentSessionWire({ ...is0(), seq: -1 })).toMatch(/seq/);
    expect(validateIntentSessionWire({ ...is0(), seq: 2_147_483_648 })).toMatch(/seq/);
    expect(validateIntentSessionWire({ ...is0(), acc: [{ id: 'a', post: 1 }, { id: 'a', post: 2 }] })).toMatch(/distinct/);
    expect(validateIntentSessionWire({ ...is0(), acc: [{ id: 'a-b', post: 1 }] })).toMatch(/id/);
    expect(validateIntentSessionWire({ ...is0(), prov: { 'action.params.x': [] } })).toMatch(/prov/);
    expect(validateIntentSessionWire({ ...is0(), facts: [REF, REF] })).toMatch(/distinct/);
    const { schema: _s, ...noSchema } = is0();
    void _s;
    expect(validateIntentSessionWire(noSchema)).toMatch(/missing field/);
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
    expect(validateWireV2(p)).toBeNull();
    expect(validateWireV2({ ...p, intent_session: { ...is0(), root: 'x' } })).toMatch(/intent_session.root/);
  });

  it('a session root verifies only as signed by one of its principals', () => {
    expect(verifySessionRoot(S)).toEqual({ ok: true });
    expect(verifySessionRoot({ ...S, expires_at: S.expires_at + 1 })).toMatchObject({ ok: false });
    expect(() => signSessionRoot(rootBody(), stranger.sk)).toThrow(/not one of the session principals/);
    expect(verifySessionRoot({ ...S, accumulators: [{ ...TRIP, holder: { kind: 'wallet' } }] })).toMatchObject({ ok: false });
  });

  it('the session caveat is well-formed and satisfied by the policy evaluator (it constrains nothing per action)', () => {
    const c = G0.caveats.find((x) => x.type === 'intent_session')!;
    expect(intentSessionCaveatError(c)).toBeNull();
    expect(envelopeCaveatEvaluator(c, { now: NOW })).toBe(true);
    expect(envelopeCaveatEvaluator({ ...c, prev: G0.id }, { now: NOW })).toBe(false); // seq 0 has no prev
    expect(intentSessionCaveatError(D1.caveats.find((x) => x.type === 'intent_session'))).toBeNull();
  });
});

// ---- the verifier checks -----------------------------------------------------------------------------------------
describe('core verifier: schema / intent_session / accumulators', () => {
  it('admits G_0 with the session bound, the schema conforming and the claimed post equal to the verifier value', async () => {
    const r = await core(build(G0, { salt: 'salt0', map: MAP0, is: is0() }), G0, ctx());
    expect(r.allow).toBe(true);
    expect(r.checks).toMatchObject({ intent: 'pass', schema: 'pass', intent_session: 'pass', accumulators: 'pass' });
  });

  it('back-compat: no intent_session and no active v2 policy reports no v2 check at all', async () => {
    const r = await core(build(G0, { salt: 'salt0', map: MAP0 }), G0, ctx());
    expect(Object.keys(r.checks)).not.toContain('schema');
    expect(Object.keys(r.checks)).not.toContain('intent_session');
    expect(Object.keys(r.checks)).not.toContain('accumulators');
    // the v1 goal does not open a v2 session grant
    expect(r.checks.intent).toBe('fail');
  });

  it('an active policy fails closed on a PCActn without the member', async () => {
    const p = build(G0, { salt: 'salt0', map: MAP0 });
    const r = await core(p, G0, ctx({ policy: { session: { require: true }, schema: { closed_world: true } } }));
    expect(r.checks.intent_session).toBe('fail');
    expect(r.checks.schema).toBe('pass'); // closed world against the current schema
    expect(Object.keys(r.checks)).not.toContain('accumulators');
    const bad = await core(p, G0, ctx({ policy: { session: { max_revocation_age_s: -1 } } }));
    expect(bad.checks.intent_session).toBe('fail'); // a malformed policy member fails closed even when nothing else activates the check
  });

  it('closed world: an undeclared parameter is a terminal schema deny', async () => {
    const params = { ...PARAMS, reseller: 'evil' };
    const r = await core(build(G0, { salt: 'salt0', map: MAP0, is: is0(), params }), G0, ctx({ params }));
    expect(r.checks.schema).toBe('fail');
    expect(r.reason).toMatch(/schema_violation: undeclared_param/);
  });

  it('schema: an unknown digest, a forged schema, plaintext params that do not open the digest, another audience', async () => {
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
    expect((await core(p, G0, ctx({ schema: { docs: [], keys: KEYS } }))).checks.schema).toBe('fail');
    expect((await core(p, G0, ctx({ schema: { docs: [SCHEMA], keys: [actionSchemaKeyOf('skyair-2026', stranger.sk)] } }))).checks.schema).toBe('fail');
    expect((await core(p, G0, ctx({ params: { ...PARAMS, total: 1 } }))).checks.schema).toBe('fail');
    const other = signActionSchema({ ...UNSIGNED, aud: 'other.example' }, 'skyair-2026', site.sk);
    const p2 = build(G0, { salt: 'salt0', map: MAP0, is: is0({ schema: actionSchemaDigest(other) }) });
    expect((await core(p2, G0, ctx({ schema: { docs: [other], keys: KEYS } }))).checks.schema).toBe('fail');
  });

  it('delta chain: D_1 verifies only with G_0 held, chained, principal-signed (T15)', async () => {
    const p1 = build(D1, { salt: 'salt1', map: MAP1, is: is0({ seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) });
    const c1 = ctx({ session: { root: S, grants: [G0] }, acc: { state: { trip_spend: { sum: 38_900 } }, monitors: {} } });
    expect((await core(p1, D1, c1)).allow).toBe(true);
    expect((await core(p1, D1, ctx({ session: { root: S, grants: [] }, acc: c1.acc }))).checks.intent_session).toBe('fail');
    // a delta the AGENT minted (agent key as issuer) is refused
    const forged = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1', signer: agent });
    const pf = build(forged, { salt: 'salt1', map: MAP1, is: is0({ seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) });
    expect((await core(pf, forged, c1)).reason).toMatch(/not signed by a session principal/);
    // a broken prev link
    const loose = mint({ seq: 1, prev: b64u(seed('nope')), map: MAP1, salt: 'salt1' });
    const pl = build(loose, { salt: 'salt1', map: MAP1, is: is0({ seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) });
    expect((await core(pl, loose, c1)).checks.intent_session).toBe('fail');
    // replayed under another session id: the root names another session
    const other = b64u(seed('other-session'));
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', session: other });
    const po = build(g, { salt: 'salt0', map: MAP0, is: is0({ session: other }) });
    expect((await core(po, g, ctx())).checks.intent_session).toBe('fail');
    // seq claimed by the PCActn differs from the grant's
    const ps = build(G0, { salt: 'salt0', map: MAP0, is: is0({ seq: 1 }) });
    expect((await core(ps, G0, ctx({ session: { root: S, grants: [G0] } }))).checks.intent_session).toBe('fail');
  });

  it('rule 12 under a session: the goal is pca-intent:v2:<session>:<map>, and the statement is bound through S', async () => {
    const wrongRef = build(G0, { salt: 'salt0', map: MAP0, is: is0(), ref: b64u(seed('x')) });
    const r = await core(wrongRef, G0, ctx());
    expect(r.checks.intent).toBe('pass'); // the v2 goal does not include the ref
    expect(r.checks.intent_session).toBe('fail'); // S.intent_ref binds it
    const wrongMap = build(G0, { salt: 'salt0', map: MAP1, is: is0() });
    expect((await core(wrongMap, G0, ctx())).checks.intent).toBe('fail');
  });

  it('accumulators: the claim must equal the verifier post; unknown, unselected and wallet-held claims are refused', async () => {
    const run = (is: IntentSessionWire, c = ctx()) => core(build(G0, { salt: 'salt0', map: MAP0, is }), G0, c);
    expect((await run(is0({ acc: [{ id: 'trip_spend', post: 38_899 }] }))).checks.accumulators).toBe('fail');
    expect((await run(is0({ acc: [] }))).checks.accumulators).toBe('fail');
    expect((await run(is0({ acc: [{ id: 'trip_spend', post: 38_900 }, { id: 'nope', post: 0 }] }))).checks.accumulators).toBe('fail');
    expect((await run(is0({ acc: [{ id: 'trip_spend', post: 38_900 }, { id: 'questions', post: 1 }] }))).checks.accumulators).toBe('fail');
    expect((await run(is0(), ctx({ acc: { state: {}, monitors: {} } }))).checks.accumulators).toBe('fail');
    expect((await run(is0({ acc: [{ id: 'trip_spend', post: 500_100 }] }), ctx({ acc: { state: { trip_spend: { sum: 461_200 } }, monitors: {} } }))).checks.accumulators).toBe('fail'); // outside A_ψ
  });

  it('monitors: the verifier requires a valid injected state for every monitor of S', async () => {
    const mon: MonitorDecl = { id: 'hotel_after_flight', kind: 'requires_prior', p: { verb: 'air.book' }, q: { verb: 'hotel.book' }, status: 'committed' };
    const S2 = signSessionRoot(rootBody({ monitors: [mon] }), principal.sk);
    const root2 = sessionRootDigest(S2);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: root2 });
    const p = build(g, { salt: 'salt0', map: MAP0, is: is0({ root: root2 }) });
    const c = (m: Record<string, string>) => ctx({ session: { root: S2, grants: [] }, acc: { state: { trip_spend: { sum: 0 } }, monitors: m } });
    expect((await core(p, g, c({}))).checks.accumulators).toBe('fail');
    expect((await core(p, g, c({ hotel_after_flight: 'maybe' }))).checks.accumulators).toBe('fail');
    expect((await core(p, g, c({ hotel_after_flight: 'unmet' }))).allow).toBe(true);
    expect(decideIntentV2(p, g, c({ hotel_after_flight: 'met' }), NOW).env).toMatchObject({ mon: { hotel_after_flight: { state: 'met' } }, acc: { trip_spend: { post: 38_900 } }, canon: { add_ons: '["none"]', refundable: 'false' } });
  });

  it('sequenced accumulators: the claim carries a sequencer receipt bound to this action, audience and session', async () => {
    const SEQ: AccumulatorDecl = { ...TRIP, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: seqRoot.pub } };
    const S3 = signSessionRoot(rootBody({ accumulators: [SEQ] }), principal.sk);
    const root3 = sessionRootDigest(S3);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: root3 });
    const draft = build(g, { salt: 'salt0', map: MAP0 });
    const KS = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 5_000, keys: [{ kid: 's1', pk: sequencer.pub, not_before: NOW - 10_000 }] }, seqRoot.sk);
    const rcBody = { v: 1 as const, kind: 'pca-acc-receipt' as const, session: SESSION, acc: 'trip_spend', seq: 3, pre: 10_000, delta: 38_900, post: 48_900, pcactn_digest: pcactnReservationDigest(draft as unknown as Record<string, unknown>), aud: AUD, issued_at: NOW, expires_at: NOW + 60_000, kid: 's1', ledger: { index: 7, head: b64u(seed('head')) } };
    const rc = signAccReceipt(rcBody, sequencer.sk);
    const withReceipt = (r: typeof rc, post = 48_900) => build(g, { salt: 'salt0', map: MAP0, is: is0({ root: root3, acc: [{ id: 'trip_spend', post, receipt: accReceiptDigest(r) }] }) });
    const p = withReceipt(rc);
    const c = (o: { receipts?: typeof rc[]; last?: number; keys?: unknown[] } = {}) =>
      ctx({ session: { root: S3, grants: [] }, acc: { receipts: o.receipts ?? [rc], monitors: {}, sequencer_keys: o.keys ?? [KS], ...(o.last !== undefined ? { last_seq: { trip_spend: o.last } } : {}) } });
    expect((await core(p, g, c())).allow).toBe(true);
    expect((await core(p, g, c({ receipts: [] }))).checks.accumulators).toBe('fail');
    expect((await core(p, g, c({ keys: [] }))).checks.accumulators).toBe('fail'); // no key set presented
    expect((await core(p, g, c({ keys: [signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW, keys: [{ kid: 's1', pk: sequencer.pub, not_before: 0 }] }, stranger.sk)] }))).checks.accumulators).toBe('fail'); // set not signed by the pinned root
    expect((await core(p, g, c({ last: 3 }))).checks.accumulators).toBe('fail'); // replayed seq
    const forged = signAccReceipt(rcBody, stranger.sk);
    expect((await core(withReceipt(forged), g, c({ receipts: [forged] }))).checks.accumulators).toBe('fail');
    const bent = signAccReceipt({ ...rcBody, post: 48_901 }, sequencer.sk);
    expect((await core(withReceipt(bent, 48_901), g, c({ receipts: [bent] }))).checks.accumulators).toBe('fail'); // pre + delta != post
    const site2 = signAccReceipt({ ...rcBody, aud: 'hotel.example' }, sequencer.sk);
    expect((await core(withReceipt(site2), g, c({ receipts: [site2] }))).checks.accumulators).toBe('fail');
  });

  it('sequencer signing-key rotation keeps the session valid: the root signs a new key set, receipts name their kid', async () => {
    const SEQ: AccumulatorDecl = { ...TRIP, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: seqRoot.pub } };
    const S3 = signSessionRoot(rootBody({ accumulators: [SEQ] }), principal.sk);
    const root3 = sessionRootDigest(S3);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: root3 });
    const draft = build(g, { salt: 'salt0', map: MAP0 });
    const next = key('sequencer-2');
    const rotated = signSequencerKeySet(
      { v: 1, kind: 'pca-sequencer-keys', version: 2, issued_at: NOW - 100, keys: [{ kid: 's1', pk: sequencer.pub, not_before: NOW - 10_000, not_after: NOW - 1_000 }, { kid: 's2', pk: next.pub, not_before: NOW - 1_000 }] },
      seqRoot.sk,
    );
    const body = (kid: string, issued: number) => ({ v: 1 as const, kind: 'pca-acc-receipt' as const, session: SESSION, acc: 'trip_spend', seq: 1, pre: 0, delta: 38_900, post: 38_900, pcactn_digest: pcactnReservationDigest(draft as unknown as Record<string, unknown>), aud: AUD, issued_at: issued, expires_at: issued + 60_000, kid, ledger: { index: 0, head: b64u(seed('h')) } });
    const run = async (r: ReturnType<typeof signAccReceipt>) =>
      (await core(build(g, { salt: 'salt0', map: MAP0, is: is0({ root: root3, acc: [{ id: 'trip_spend', post: 38_900, receipt: accReceiptDigest(r) }] }) }), g, ctx({ session: { root: S3, grants: [] }, acc: { receipts: [r], monitors: {}, sequencer_keys: [rotated] } }))).checks.accumulators;
    expect(await run(signAccReceipt(body('s2', NOW), next.sk))).toBe('pass'); // the new key, same session root
    expect(await run(signAccReceipt(body('s1', NOW - 5_000), sequencer.sk))).toBe('pass'); // issued while s1 was valid
    expect(await run(signAccReceipt(body('s1', NOW), sequencer.sk))).toBe('fail'); // the retired key after its window
    expect(await run(signAccReceipt(body('s2', NOW + 61_000), next.sk))).toBe('fail'); // issued in the future
    expect(await run(signAccReceipt(body('s1', NOW), next.sk))).toBe('fail'); // kid / signer mismatch
  });

  it('receipt freshness: a leaked retired key, an old receipt, an old or superseded key set, an over-long lifetime are refused', () => {
    const holder = { kind: 'sequenced' as const, uri: 'u', root: seqRoot.pub };
    const body = (kid: string, issued: number, expires = issued + 60_000) => ({ v: 1 as const, kind: 'pca-acc-receipt' as const, session: SESSION, acc: 'trip_spend', seq: 1, pre: 0, delta: 1, post: 1, pcactn_digest: SESSION, aud: AUD, issued_at: issued, expires_at: expires, kid, ledger: { index: 0, head: SESSION } });
    // s1 was retired 10 minutes ago; its holder leaked it
    const ks = (version: number, issued = NOW - 100) => signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issued, keys: [{ kid: 's1', pk: sequencer.pub, not_before: NOW - 3_600_000, not_after: NOW - 600_000 }, { kid: 's2', pk: stranger.pub, not_before: NOW - 600_000 }] }, seqRoot.sk);
    const leaked = signAccReceipt(body('s1', NOW - 700_000), sequencer.sk); // back-dated into s1's window
    expect(verifyReceiptAgainstHolder(leaked, holder, [ks(3)], NOW)).toBe(false); // s1 is retired (not_after < now - skew)
    const fresh = signAccReceipt(body('s2', NOW - 1_000), stranger.sk);
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3)], NOW)).toBe(true);
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3)], NOW, { maxReceiptAgeMs: 500 })).toBe(false); // too old for the policy
    const old = signAccReceipt(body('s2', NOW - 600_000), stranger.sk);
    expect(verifyReceiptAgainstHolder(old, holder, [ks(3)], NOW + 300_000)).toBe(true); // exactly 15 min old
    expect(verifyReceiptAgainstHolder(old, holder, [ks(3)], NOW + 300_001)).toBe(false); // older than the default 15 min
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3, NOW - 3_700_000)], NOW)).toBe(false); // key set older than 1 h
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3)], NOW, { minKeySetVersion: 4 })).toBe(false); // superseded set
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(4)], NOW, { minKeySetVersion: 4 })).toBe(true);
    // tracked {version, digest}: an older set is a rollback, ANOTHER set under the same version is an equivocation
    const t3 = { version: 3, digest: sequencerKeySetDigest(ks(3)) };
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3)], NOW, { tracked: t3 })).toBe(true);
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3, NOW - 200)], NOW, { tracked: t3 })).toBe(false); // same version, other content
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(4)], NOW, { tracked: t3 })).toBe(true); // a newer set
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(2)], NOW, { tracked: t3 })).toBe(false); // rollback
    for (const bad of [{ version: 3 }, { version: 0, digest: t3.digest }, { ...t3, extra: 1 }, 3, null]) expect(trackedKeySetError(bad)).not.toBeNull();
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3)], NOW, { tracked: { version: '3', digest: t3.digest } as never })).toBe(false); // malformed tracked state
    expect(() => signAccReceipt(body('s2', NOW, NOW + 900_001), stranger.sk)).toThrow(/expires_at/); // lifetime > 15 min
    expect(verifyReceiptAgainstHolder(fresh, holder, [ks(3)], 1.5)).toBe(false); // clock not a safe integer
  });

  it('layers (V5) sit between intent_session and accumulators; W-B checks appear only with their members', async () => {
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
    const deny = await core(p, G0, ctx({ layers: { org: { predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: 10_000 }] }] } } }));
    expect(deny.checks.layers).toBe('fail');
    expect(deny.reason).toMatch(/outside the org ceiling/);
    const pass = await core(p, G0, ctx({ layers: { site: { predicates: [{ verb: 'air.book', where: [{ field: 'env.canon.add_ons', op: 'eq', value: '["none"]' }] }] } } }));
    expect(pass.checks.layers).toBe('pass');
    expect(Object.keys(pass.checks).filter((k) => ['schema', 'intent_session', 'layers', 'accumulators', 'facts', 'provenance', 'classes'].includes(k)).sort()).toEqual(['accumulators', 'intent_session', 'layers', 'schema']);
  });

  it('tampering with intent_session after signing breaks the leaf signature', async () => {
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
    const t = { ...p, intent_session: { ...p.intent_session!, acc: [{ id: 'trip_spend', post: 1 }] } };
    expect((await core(t, G0, ctx())).checks.leaf_signature).toBe('fail');
    expect((await core(resign(t), G0, ctx())).checks.leaf_signature).toBe('pass');
  });
});

// ---- T22: revocation (dedicated authority, append-only) --------------------------------------------------------
const revAuth = key('revocation-authority');
/** A session revocation epoch by `signer` over the given revoked ids: epoch number = set size, full sorted list. */
const revEv = (revoked: string[], issuedAt: number, signer = revAuth, suite?: Parameters<typeof signRevocationEpoch>[2]) => {
  const set = new RevocationSet(revoked);
  const epoch = signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: issuedAt, not_after: issuedAt + 300_000 }, suite);
  return { epoch, revoked: set.list() };
};
describe('session revocation epochs (V10, T22, append-only)', () => {
  const S4 = signSessionRoot(rootBody({ revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub } }), principal.sk);
  const root4 = sessionRootDigest(S4);
  const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: root4 });
  const p = build(g, { salt: 'salt0', map: MAP0, is: is0({ root: root4 }) });
  const ids = [sessionRevocationId(SESSION), mapRevocationId(MAP0), deltaRevocationId(g.id)];
  const c = (rev: ReturnType<typeof revEv> | undefined, last?: ReturnType<typeof revEv>) => ctx({ session: { root: S4, grants: [], ...(rev ? { revocation: rev } : {}), ...(last ? { revocation_last: last } : {}) } });

  it('the session root names a dedicated authority that is not a principal', () => {
    expect(() => signSessionRoot(rootBody({ revocation: { epoch_uri: 'x', max_age_s: 60, key: principal.pub } }), principal.sk)).toThrow(/not be a session principal/);
    expect(verifySessionRoot({ ...S4, revocation: { epoch_uri: 'x', max_age_s: 60 } })).toMatchObject({ ok: false });
  });
  it('admits with a fresh epoch by the authority whose full list omits every relied-on id', async () => {
    expect((await core(p, g, c(revEv(['pca-intent:session:zzz'], NOW - 30_000)))).checks.intent_session).toBe('pass');
  });
  it('refuses: no epoch, a stale epoch, a revoked session / map / delta, a co-principal or stranger signer, a list that is not the signed set', async () => {
    expect((await core(p, g, c(undefined))).checks.intent_session).toBe('fail');
    expect((await core(p, g, c(revEv([], NOW - 61_000)))).checks.intent_session).toBe('fail');
    for (const id of ids) expect((await core(p, g, c(revEv([id], NOW - 1_000)))).checks.intent_session).toBe('fail');
    expect((await core(p, g, c(revEv([], NOW - 1_000, principal)))).checks.intent_session).toBe('fail'); // a principal is not the authority
    expect((await core(p, g, c(revEv([], NOW - 1_000, stranger)))).checks.intent_session).toBe('fail');
    const e = revEv([ids[0]!], NOW - 1_000);
    expect((await core(p, g, c({ epoch: e.epoch, revoked: [] }))).checks.intent_session).toBe('fail'); // hiding the revoked id from the list
    const misnumbered = signRevocationEpoch(revAuth.sk, { instance_id: 'ana', grant_ref: sessionRevocationScope(SESSION), epoch: 7, set_size: 0, root: new RevocationSet([]).root, issued_at: NOW - 1_000, not_after: NOW + 1 });
    expect((await core(p, g, c({ epoch: misnumbered, revoked: [] }))).checks.intent_session).toBe('fail'); // epoch must equal set_size
  });
  it('the evidence (and the tracked last epoch) is closed: exactly {epoch, revoked}', async () => {
    const e = revEv([], NOW - 1_000);
    expect((await core(p, g, c({ ...e, proofs: {} } as never))).checks.intent_session).toBe('fail');
    expect((await core(p, g, c(e, { ...revEv([], NOW - 2_000), note: 'x' } as never))).checks.intent_session).toBe('fail');
    expect(checkSessionRevocation({ ...e, extra: 1 } as never, { session: SESSION, authority: revAuth.pub, ids: [], now: NOW, maxAgeMs: 60_000 })).toMatchObject({ ok: false });
    expect(checkSessionRevocation(e, { session: SESSION, authority: revAuth.pub, ids: [], now: NOW, maxAgeMs: 60_000 })).toEqual({ ok: true });
  });
  it('append-only: an epoch that drops an id revoked in the tracked last epoch, or rolls back, or equivocates, is refused', async () => {
    const last = revEv(['pca-intent:session:a', 'pca-intent:session:b'], NOW - 30_000);
    expect((await core(p, g, c(revEv(['pca-intent:session:a', 'pca-intent:session:b', 'pca-intent:session:c'], NOW - 1_000), last))).checks.intent_session).toBe('pass');
    // the authority drops "b" and adds "c" (same size): not a superset of the last accepted epoch
    expect((await core(p, g, c(revEv(['pca-intent:session:a', 'pca-intent:session:c'], NOW - 1_000), last))).checks.intent_session).toBe('fail');
    expect((await core(p, g, c(revEv(['pca-intent:session:a'], NOW - 1_000), last))).checks.intent_session).toBe('fail'); // rollback
    expect((await core(p, g, c(revEv(['pca-intent:session:a', 'pca-intent:session:b'], NOW - 1_000), last))).checks.intent_session).toBe('pass'); // same set re-signed
  });
  it('the stricter of the policy and the root max age applies', async () => {
    const rev = revEv([], NOW - 20_000);
    expect((await core(p, g, { ...c(rev), policy: { session: { max_revocation_age_s: 10 } } })).checks.intent_session).toBe('fail');
    expect((await core(p, g, { ...c(rev), policy: { session: { max_revocation_age_s: 30 } } })).checks.intent_session).toBe('pass');
  });
  it('a policy age bound without a revocation authority in S fails closed', async () => {
    expect((await core(P0g(), G0, ctx({ policy: { session: { max_revocation_age_s: 60 } } }))).checks.intent_session).toBe('fail');
  });
  it('T22 (property): an honest publisher that includes a revoked id from t_r on bounds the exposure by Δ_rev', () => {
    const maxAgeMs = 60_000;
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 600_000 }), fc.integer({ min: 0, max: 600_000 }), fc.integer({ min: 1, max: 600_000 }), (tR, issueOffset, verifyOffset) => {
        const issued = NOW + issueOffset;
        const revokedAt = NOW + tR;
        const now = issued + verifyOffset;
        const id = sessionRevocationId(SESSION);
        const set = new RevocationSet(issued >= revokedAt ? [id] : []);
        const epoch = signRevocationEpoch(revAuth.sk, { instance_id: 'ana', grant_ref: sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 3_600_000 });
        const ok = checkSessionRevocation({ epoch, revoked: set.list() }, { session: SESSION, authority: revAuth.pub, ids: [id], now, maxAgeMs }).ok;
        return !(ok && now > revokedAt) || now <= revocationExposureEnd(revokedAt, maxAgeMs, 0);
      }),
      { numRuns: 200 },
    );
  });
  it('append-only (property): with a tracked last epoch, no accepted epoch ever omits an id the last one revoked', () => {
    const pool = ['pca-intent:session:a', 'pca-intent:session:b', 'pca-intent:session:c', 'pca-intent:session:d'];
    fc.assert(
      fc.property(fc.subarray(pool), fc.subarray(pool), (a, b) => {
        const last = revEv(a, NOW - 10_000);
        const next = revEv(b, NOW - 1_000);
        const ok = checkSessionRevocation(next, { session: SESSION, authority: revAuth.pub, ids: [], now: NOW, maxAgeMs: 60_000, last }).ok;
        return !ok || a.every((x) => b.includes(x));
      }),
      { numRuns: 100 },
    );
  });
});

const P0g = () => build(G0, { salt: 'salt0', map: MAP0, is: is0() });

// ---- T11: splitting is useless (site-local holder, LIN) ------------------------------------------------------------
describe('accumulators and the session store (T11, LIN)', () => {
  const CAP = 40_000;
  const verifyWith = async (params: Record<string, unknown>, acc: { state: Record<string, unknown>; monitors: Record<string, string> }) => {
    // the claim is the honest post value (the agent cannot claim another: the core check compares)
    const post = (acc.state.trip_spend as { sum: number }).sum + (params.total as number);
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0({ acc: [{ id: 'trip_spend', post }] }), params });
    const v = await verifyPCActn(p, { grant: G0, audience: AUD, now: NOW, context: { params }, intentV2: ctx({ params, acc: acc as IntentV2Context['acc'] }) });
    const predicateDenied = v.reasons.some((r) => r.includes('no predicate permits') || r.includes(' not satisfied for '));
    return { allow: v.checks.accumulators === 'pass' && !predicateDenied, v };
  };

  it('the grant predicate on env.acc.<id>.post enforces the cap; the root session caveat is satisfied', async () => {
    const ok = await verifyWith({ ...PARAMS, total: 38_900 }, { state: { trip_spend: { sum: 0 } }, monitors: {} });
    expect(ok.allow).toBe(true);
    expect(ok.v.reasons.join('\n')).not.toMatch(/root caveat/);
    const over = await verifyWith({ ...PARAMS, total: 38_900 }, { state: { trip_spend: { sum: 2_000 } }, monitors: {} });
    expect(over.allow).toBe(false);
  });

  it('T11 (property): any split of any amounts, admitted concurrently, never pushes the counted sum over the cap', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(fc.integer({ min: 0, max: 30_000 }), { minLength: 1, maxLength: 12 }), async (amounts) => {
        const store = new MemoryIntentSessionStore();
        await Promise.all(
          amounts.map((total, i) =>
            admitIntentAction(store, {
              session: SESSION,
              root: S,
              schema: SCHEMA,
              event: { id: `e${i}`, verb: 'air.book', resource: 'skyair.example/bookings', params: { ...PARAMS, total }, t: NOW + i },
              verify: async (acc) => {
                const post = accPost(TRIP, [], { verb: 'air.book', params: { ...PARAMS, total }, t: NOW }, SCHEMA) + (acc.state.trip_spend as { sum: number }).sum;
                return { allow: post <= CAP };
              },
            }),
          ),
        );
        const counted = store.snapshot(SESSION).reduce((s, e) => s + (e.params.total as number), 0);
        return counted <= CAP;
      }),
      { numRuns: 60 },
    );
  });

  it('released reservations stop counting; windows and keys group the pre-state', async () => {
    const store = new MemoryIntentSessionStore();
    const ev = (id: string, total: number, t: number): Omit<IntentEvent, 'status'> => ({ id, verb: 'air.book', resource: 'r', params: { ...PARAMS, total }, t });
    for (const [id, total] of [['a', 10_000], ['b', 20_000]] as const) {
      await admitIntentAction(store, { session: SESSION, root: S, schema: SCHEMA, event: ev(id, total, NOW), verify: async () => ({ allow: true }) });
    }
    await settleIntentEvent(store, SESSION, 'a', 'released');
    const h = store.snapshot(SESSION);
    expect(accContextFor(S, h, { params: PARAMS, t: NOW }, SCHEMA).state.trip_spend).toEqual({ sum: 20_000 });
    const sliding: AccumulatorDecl = { ...TRIP, win: { kind: 'sliding', ms: 1_000 } };
    expect(accPreState(sliding, h, { params: PARAMS, t: NOW + 1_000 }, SCHEMA)).toEqual({ sum: 0 });
    const keyed: AccumulatorDecl = { ...TRIP, agg: 'count', sel: { verbs: ['air.book'] }, key: 'action.params.offer_id' };
    expect(accPreState(keyed, h, { params: { offer_id: 'OF-1' }, t: NOW }, SCHEMA)).toEqual({ count: 1 });
    expect(accPreState(keyed, h, { params: { offer_id: 'OF-2' }, t: NOW }, SCHEMA)).toEqual({ count: 0 });
  });

  it('monitors fold over statuses: requires_prior(committed) and responds_within', () => {
    const m: MonitorDecl = { id: 'm', kind: 'requires_prior', p: { verb: 'air.book' }, q: { verb: 'hotel.book' }, status: 'committed' };
    const e = (status: IntentEvent['status'], verb = 'air.book'): IntentEvent => ({ id: Math.random().toString(), verb, resource: 'r', params: {}, t: NOW, status });
    expect(monitorState(m, [e('reserved')])).toBe('unmet');
    expect(monitorState(m, [e('committed')])).toBe('met');
    const rw: MonitorDecl = { id: 'r', kind: 'responds_within', p: { verb: 'a' }, q: { verb: 'b' }, within: 2 };
    expect(monitorState(rw, [e('committed', 'a')])).toBe('pending:2');
    expect(monitorState(rw, [e('committed', 'a'), e('committed', 'x')])).toBe('pending:1');
    expect(monitorState(rw, [e('committed', 'a'), e('committed', 'x'), e('committed', 'x')])).toBe('missed');
    expect(monitorState(rw, [e('committed', 'a'), e('committed', 'b')])).toBe('idle');
  });
});

// ---- intent_required --------------------------------------------------------------------------------------------
describe('intent_required (site-signed, never agent text)', () => {
  const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
  const body = {
    v: 1 as const, kind: 'pca-intent-required' as const, session: SESSION, map_digest: MAP0, schema: SCHEMA_DIGEST, pcactn_digest: b64u(seed('p')), action_digest: intentActionDigest(p.action),
    cell: { verb: 'air.book', coords: { 'env.acc.trip_spend.post': [2, 3] as [number, number], 'env.canon.add_ons': ['["none"]'] } }, reason: 'uncertain' as const, question_id: 'q_7Hk2', friction: 'typed' as const, delivered_to: 'wallet' as const, expires_at: NOW + 900_000,
  };
  it('signs and verifies under the discovery keys; any edit fails; expiry is enforced', () => {
    const s = signIntentRequired(body, 'skyair-2026', site.sk);
    expect(verifyIntentRequired(s, KEYS, NOW)).toEqual({ ok: true });
    expect(verifyIntentRequired({ ...s, friction: 'tap' }, KEYS, NOW)).toMatchObject({ ok: false });
    expect(verifyIntentRequired(s, KEYS, NOW + 900_001)).toMatchObject({ ok: false });
    expect(verifyIntentRequired({ ...s, note: 'click yes' }, KEYS, NOW)).toMatchObject({ ok: false });
  });
  it('builds the RFC 9457 response with WWW-Authenticate', () => {
    const s = signIntentRequired(body, 'skyair-2026', site.sk);
    const r = intentProblem('intent-required', { body: s });
    expect(r.status).toBe(403);
    expect(r.headers['WWW-Authenticate']).toBe(`PCA error="intent_required", session="${SESSION}", question="q_7Hk2"`);
    expect(r.body).toMatchObject({ type: 'https://atlasauth.net/pca/problems/intent-required', pca: s });
    expect(intentProblem('ceiling').headers['WWW-Authenticate']).toBe('PCA error="ceiling"');
  });
});

// ---- schema typing sanity used by the fixtures ------------------------------------------------------------------
it('fixture schema conforms to its own shape (signed)', () => {
  const s: ActionSchema = SCHEMA;
  expect(s.sig.kid).toBe('skyair-2026');
  const r: SessionRoot = S;
  expect(r.signer).toBe(principal.pub);
});

// ---- strictness: no coercion, real arrays, own keys, suite capability ------------------------------------------
describe('strictness of rules 13-15 (no coercion, real arrays, own keys, unsupported_suite)', () => {
  const P0 = () => build(G0, { salt: 'salt0', map: MAP0, is: is0() });
  const accWith = (acc: unknown) => ctx({ acc: acc as IntentV2Context['acc'] });

  it('every numeric field is a safe integer or the check fails closed (null / string / fraction / -0 / NaN clock)', async () => {
    for (const bad of [null, '0', 0.5, -0, '38900']) expect((await core(P0(), G0, accWith({ state: { trip_spend: { sum: bad } }, monitors: {} }))).checks.accumulators).toBe('fail');
    expect((await core(P0(), G0, accWith({ state: { trip_spend: { sum: 0 } }, monitors: {}, last_seq: { trip_spend: '3' } }))).checks.accumulators).toBe('fail');
    expect((await core(P0(), G0, ctx({ policy: { session: { max_revocation_age_s: '60' as unknown as number } } }))).checks.intent_session).toBe('fail');
    expect(decideIntentV2(P0(), G0, ctx(), Number.NaN).checks.every((c) => !c.ok)).toBe(true);
    expect(decideIntentV2(P0(), G0, ctx(), 1.5).checks.every((c) => !c.ok)).toBe(true);
    expect(accReceiptShapeError({ v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'a', seq: '1', pre: 0, delta: 0, post: 0, pcactn_digest: SESSION, aud: AUD, issued_at: 0, expires_at: 0, kid: 'k', ledger: { index: 0, head: SESSION }, signer: SESSION, sig: '' })).not.toBeNull();
    expect(sequencerKeySetShapeError({ v: 1, kind: 'pca-sequencer-keys', sequencer: SESSION, version: 1, issued_at: 0, keys: [{ kid: 'k', pk: SESSION, not_before: 0, not_after: null }], sig: '' })).not.toBeNull();
    // a revocation epoch whose not_after is a numeric string is refused before any comparison
    const e0 = revEv([], NOW);
    const rc = { session: SESSION, authority: revAuth.pub, ids: [sessionRevocationId(SESSION)], now: NOW, maxAgeMs: 60_000 };
    expect(checkSessionRevocation({ epoch: { ...e0.epoch, not_after: String(NOW + 1) as unknown as number }, revoked: [] }, rc).ok).toBe(false);
    expect(checkSessionRevocation({ epoch: { ...e0.epoch, set_size: '0' as unknown as number }, revoked: [] }, rc).ok).toBe(false);
    expect(checkSessionRevocation(e0, rc).ok).toBe(true);
  });

  it('every list is a real array: a string or an object in its place fails closed (never iterated)', async () => {
    expect((await core(P0(), G0, ctx({ schema: { docs: 'x' as unknown as never, keys: KEYS } }))).checks.schema).toBe('fail');
    expect((await core(P0(), G0, ctx({ schema: { docs: [SCHEMA], keys: { 0: KEYS[0] } as unknown as never } }))).checks.schema).toBe('fail');
    expect((await core(P0(), G0, ctx({ session: { root: S, grants: 'G0' as unknown as never } }))).checks.intent_session).toBe('fail');
    expect((await core(P0(), G0, accWith({ state: { trip_spend: { sum: 0 } }, monitors: {}, receipts: 'r' }))).checks.accumulators).toBe('fail');
    expect((await core(P0(), G0, accWith({ state: { trip_spend: { sum: 0 } }, monitors: {}, sequencer_keys: {} }))).checks.accumulators).toBe('fail');
    expect((await core(P0(), G0, accWith({ state: [], monitors: {} }))).checks.accumulators).toBe('fail');
    expect(validateIntentSessionWire({ ...is0(), acc: 'trip_spend' })).not.toBeNull();
    expect(checkSessionRevocation({ epoch: revEv([], NOW).epoch, revoked: 'pca-intent:session:x' as unknown as string[] }, { session: SESSION, authority: revAuth.pub, ids: [], now: NOW, maxAgeMs: 1 }).ok).toBe(false);
    expect(checkSessionRevocation(revEv([], NOW), { session: SESSION, authority: revAuth.pub, ids: 'x' as unknown as string[], now: NOW, maxAgeMs: 1 }).ok).toBe(false);
  });

  it('keyed lookups read own properties only; reserved names are refused', async () => {
    // an inherited name is never read as state: accumulator "toString" with no state fails, it does not see Object.prototype.toString
    const TS: AccumulatorDecl = { ...TRIP, id: 'toString' };
    const S5 = signSessionRoot(rootBody({ accumulators: [TS] }), principal.sk);
    const r5 = sessionRootDigest(S5);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: r5 });
    const p = build(g, { salt: 'salt0', map: MAP0, is: is0({ root: r5, acc: [{ id: 'toString', post: 38_900 }] }) });
    expect((await core(p, g, ctx({ session: { root: S5, grants: [] }, acc: { state: {}, monitors: {} } }))).checks.accumulators).toBe('fail');
    const ok = await core(p, g, ctx({ session: { root: S5, grants: [] }, acc: { state: { toString: { sum: 0 } }, monitors: {}, last_seq: {} } }));
    expect(ok.checks.accumulators).toBe('pass');
    expect(Object.getPrototypeOf(decideIntentV2(p, g, ctx({ session: { root: S5, grants: [] }, acc: { state: { toString: { sum: 0 } }, monitors: {} } }), NOW).env!.acc)).toBeNull();
    // a JSON-own "__proto__" key is data, never the prototype
    const weird = JSON.parse('{"__proto__": {"sum": 0}}') as Record<string, never>;
    expect((await core(P0(), G0, accWith({ state: weird, monitors: {} }))).checks.accumulators).toBe('fail');
    for (const id of ['__proto__', 'constructor', 'prototype']) expect(() => signSessionRoot(rootBody({ accumulators: [{ ...TRIP, id }] }), principal.sk)).toThrow(/reserved|__proto__/);
    expect(actionSchemaShapeError({ ...UNSIGNED, verbs: [{ ...UNSIGNED.verbs[0]!, params: { 'action.params.constructor': { type: 'integer', semantic: 'q', sensitivity: 'material' } } }] }, { signed: false })).toMatch(/reserved/);
    expect(conformAction(SCHEMA, 'air.book', JSON.parse('{"__proto__": 1, "offer_id": "OF-1", "total": 1, "add_ons": ["none"], "refundable": false}'))).toMatchObject({ ok: false, code: 'undeclared_param', path: 'action.params.__proto__' });
  });

  it('absent means empty / default; present with null is malformed and fails closed', async () => {
    const all = (r: Awaited<ReturnType<typeof core>>) => ['schema', 'intent_session', 'accumulators'].every((k) => r.checks[k] === 'fail');
    for (const bad of [{ policy: { session: { require: null } } }, { policy: { session: { require: 'true' } } }, { policy: { schema: { closed_world: null } } }, { policy: { schema: { closed_world: 1 } } }, { policy: { session: { max_revocation_age_s: null } } }, { policy: { session: { other: true } } }, { policy: { extra: {} } }]) {
      const r = await core(build(G0, { salt: 'salt0', map: MAP0 }), G0, ctx(bad as unknown as Partial<IntentV2Context>)); // even without intent_session
      expect([r.checks.schema, r.checks.intent_session, 'accumulators' in r.checks]).toEqual(['fail', 'fail', false]);
    }
    expect(Object.keys((await core(build(G0, { salt: 'salt0', map: MAP0 }), G0, ctx({ policy: { session: { require: false }, schema: { closed_world: false } } }))).checks)).not.toContain('intent_session');
    for (const bad of [{ policy: null }, { policy: { session: null } }, { layers: null }, { layers: { site: null } }, { params: null }, { wb: { artifacts: { facts: null } } }, { wb: { policy: { classifiers: null } } }]) {
      expect(all(await core(P0(), G0, ctx(bad as unknown as Partial<IntentV2Context>)))).toBe(true);
    }
    expect((await core(P0(), G0, ctx({ layers: {} }))).allow).toBe(true);
    expect((await core(P0(), G0, ctx({ wb: { artifacts: {} } }))).allow).toBe(true);
    expect((await core(P0(), G0, ctx({ session: { root: S, grants: null as unknown as never } }))).checks.intent_session).toBe('fail');
    expect((await core(P0(), G0, ctx({ session: { root: S } }))).checks.intent_session).toBe('pass');
    expect((await core(P0(), G0, accWith({ state: { trip_spend: { sum: 0 } }, monitors: null }))).checks.accumulators).toBe('fail');
    expect((await core(P0(), G0, accWith({ state: { trip_spend: { sum: 0 } } }))).checks.accumulators).toBe('pass');
    expect(verifySessionRoot({ ...S, layers: { ...S.layers, org: null } })).toMatchObject({ ok: false });
    expect(verifySessionRoot({ ...S, revocation: null })).toMatchObject({ ok: false });
    expect(validateIntentSessionWire({ ...is0(), facts: null })).not.toBeNull();
    expect(actionSchemaShapeError({ ...UNSIGNED, verbs: [{ ...UNSIGNED.verbs[0]!, params: { ...UNSIGNED.verbs[0]!.params, 'action.params.add_ons': { ...UNSIGNED.verbs[0]!.params['action.params.add_ons']!, default: null } } }] }, { signed: false })).toMatch(/null/);
  });

  it('a suite this verifier does not implement is refused with the distinct reason unsupported_suite', () => {
    expect(verifySessionRoot({ ...S, alg: 'ml-dsa-99' })).toMatchObject({ ok: false, reason: expect.stringContaining('unsupported_suite') });
    expect(verifyActionSchema({ ...SCHEMA, sig: { ...SCHEMA.sig, alg: 'x-suite' } }, KEYS)).toMatchObject({ ok: false, reason: expect.stringContaining('unsupported_suite') });
    expect(verifyActionSchema(SCHEMA, [{ ...KEYS[0]!, alg: 'x-suite' as never }])).toMatchObject({ ok: false, reason: expect.stringContaining('unsupported_suite') });
    expect(accReceiptShapeError({ v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'a', seq: 1, pre: 0, delta: 0, post: 0, pcactn_digest: SESSION, aud: AUD, issued_at: 0, expires_at: 0, kid: 'k', ledger: { index: 0, head: SESSION }, signer: SESSION, alg: 'x-suite', sig: '' })).toMatch(/unsupported_suite/);
    expect(sequencerKeySetShapeError({ v: 1, kind: 'pca-sequencer-keys', sequencer: SESSION, version: 1, issued_at: 0, keys: [{ kid: 'k', pk: SESSION, not_before: 0, alg: 'x-suite' }], sig: '' })).toMatch(/unsupported_suite/);
    const e1 = revEv([], NOW);
    expect(checkSessionRevocation({ ...e1, epoch: { ...e1.epoch, alg: 'x-suite' as never } }, { session: SESSION, authority: revAuth.pub, ids: [], now: NOW, maxAgeMs: 60_000 })).toMatchObject({ ok: false, reason: expect.stringContaining('unsupported_suite') });
  });

  it('post-quantum artifacts: a hybrid session root verifies only under the VERIFIER pin; an ML-DSA-65 revocation epoch only under the PQ key S pins', () => {
    const ml = mlDsa65Keygen(seed('ml-principal'));
    const pq = encodeMlDsaPublicKey(ml.publicKey);
    const other = encodeMlDsaPublicKey(mlDsa65Keygen(seed('ml-other')).publicKey);
    const body = rootBody({ principals: [{ key: principal.pub, alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: pq }], revocation: { epoch_uri: 'x', max_age_s: 60, key: revAuth.pub, pq_pk: pq } });
    const Sh = signSessionRoot(body, principal.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml });
    const pinned = { pqPins: { [principal.pub]: pq } };
    expect(verifySessionRoot(Sh, pinned)).toEqual({ ok: true });
    // R3-01: the root's own principals entry is NOT a pin; no verifier pin, or a pin for another key, fails closed
    expect(verifySessionRoot(Sh)).toEqual({ ok: false, reason: expect.stringContaining("needs the signer's PQ key pinned by the verifier") });
    expect(verifySessionRoot(Sh, { pqPins: {} })).toMatchObject({ ok: false, reason: expect.stringContaining('pinned by the verifier') });
    expect(verifySessionRoot(Sh, { pqPins: { [revAuth.pub]: pq } })).toMatchObject({ ok: false, reason: expect.stringContaining('pinned by the verifier') });
    expect(verifySessionRoot(Sh, { pqPins: { [principal.pub]: other } })).toEqual({ ok: false, reason: "session root pq_pk does not match the verifier's pin for the signer" });
    expect(verifySessionRoot(Sh, { pqPins: Object.create({ [principal.pub]: pq }) as Record<string, string> })).toMatchObject({ ok: false }); // own pins only
    expect(verifySessionRoot({ ...Sh, principals: [{ key: principal.pub }] }, pinned)).toMatchObject({ ok: false }); // the principals list is signed
    // the signer's own principals entry must agree with the key it signs under (a root that declares one key and signs with another)
    const Sx = signSessionRoot({ ...body, principals: [{ key: principal.pub, alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: other }] }, principal.sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml });
    expect(verifySessionRoot(Sx, pinned)).toEqual({ ok: false, reason: "session root pq_pk does not match the signer's principals entry" });
    // an Ed25519 root is unchanged: pins are not consulted
    expect(verifySessionRoot(S, { pqPins: { [principal.pub]: other } })).toEqual({ ok: true });
    // the revocation authority signs with ML-DSA-65; its PQ key is pinned by S.revocation.pq_pk
    const ev = revEv([], NOW, revAuth, { alg: 'ml-dsa-65', mlDsa: ml });
    const c = { session: SESSION, authority: revAuth.pub, ids: [sessionRevocationId(SESSION)], now: NOW, maxAgeMs: 60_000 };
    expect(checkSessionRevocation(ev, { ...c, pin: { pqPins: { [revAuth.pub]: pq } } }).ok).toBe(true);
    expect(checkSessionRevocation(ev, c).ok).toBe(false); // an unpinned PQ epoch never verifies
  });
});

describe('intentV2Active', () => {
  it('is true iff any v2 check would be reported, a present malformed context included (fail closed)', () => {
    const plain = {};
    expect(intentV2Active(plain, undefined)).toBe(false);
    expect(intentV2Active(plain, {})).toBe(false);
    expect(intentV2Active({ intent_session: {} }, undefined)).toBe(true);
    expect(intentV2Active(plain, { policy: { session: { require: true } } })).toBe(true);
    expect(intentV2Active(plain, { policy: { schema: { closed_world: true } } })).toBe(true);
    expect(intentV2Active(plain, { policy: { map: { require: true } } })).toBe(true);
    // a misconfigured verifier: decideIntentV2 reports failing checks, so the helper must say active
    const bad = { policy: { session: { require: 'yes' } } } as never;
    expect(decideIntentV2({} as never, {} as never, bad, 0).checks.length).toBeGreaterThan(0);
    expect(intentV2Active(plain, bad)).toBe(true);
    expect(intentV2Active(plain, { policy: null } as never)).toBe(true);
    expect(intentV2Active(plain, 5 as never)).toBe(true);
  });
});
