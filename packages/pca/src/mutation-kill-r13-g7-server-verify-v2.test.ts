/**
 * r13 mutation kills for server/verify.ts (Intent Layer v2 wiring): the intentV2 params fallback to context.params,
 * and v2Env: a host env member survives for a session action, the six verifier-owned members (acc, mon, canon, world,
 * prov, class) are dropped from the host env when the verifier does not compute them, and a non-session action keeps
 * the host env untouched. Fixture: the intent-v2.test.ts §4 walkthrough.
 */
import { describe, expect, it } from 'vitest';
import { validateWireV2 } from './pcactn-full'; // the intent slots are validated by the full entry (Core alone refuses them)
import {
  b64u,
  buildPCActn,
  paramsDigest,
  publicKeyOf,
  sha256,
  signPCActn,
  utf8,
  verifyPCActn as verifyPCActn05,
  verifyPCActnCore,
  type PCActn,
} from './index';
import {
  actionSchemaDigest,
  actionSchemaKeyOf,
  mintSessionGrant,
  sessionRootDigest,
  signActionSchema,
  signSessionRoot,
  type AccumulatorDecl,
  type IntentSessionWire,
  type IntentV2Context,
  type SessionRootBody,
  type UnsignedActionSchema,
} from './ext/intent';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)



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

const denied = (v: { reasons: string[] }) => v.reasons.some((r) => r.includes('no predicate permits') || r.includes(' not satisfied for '));
const KS = ['acc', 'mon', 'canon', 'world', 'prov', 'class'] as const;
const forgedEnv = Object.fromEntries(KS.map((k) => [k, { f: 'forged' }]));
const forgedPreds = KS.map((k) => ({ verb: 'air.book', resource: '*', where: [{ field: `env.${k}.f`, op: 'eq' as const, value: 'forged' }] }));

describe('server verifyPCActn: intentV2 wiring', () => {
  it('intentV2 without params falls back to context.params', async () => {
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
    const v = await verifyPCActn(p, { grant: G0, audience: AUD, now: NOW, context: { params: PARAMS }, intentV2: ctx({ params: undefined }) });
    expect(v.checks.accumulators).toBe('pass');
    expect(denied(v)).toBe(false);
  });
  it('a host env member survives for a session action', async () => {
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', predicates: [{ verb: 'air.book', resource: '*', where: [{ field: 'env.acc.trip_spend.post', op: 'lte', value: 40_000 }, { field: 'env.region', op: 'eq', value: 'eu' }] }] as never });
    const p = build(g, { salt: 'salt0', map: MAP0, is: is0() });
    const run = (region: string) => verifyPCActn(p, { grant: g, audience: AUD, now: NOW, context: { params: PARAMS, env: { region } }, intentV2: ctx() });
    expect(denied(await run('eu'))).toBe(false);
    expect(denied(await run('us'))).toBe(true);
  });
  it('host-supplied verifier members are dropped for a session action', async () => {
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', predicates: forgedPreds as never });
    const p = build(g, { salt: 'salt0', map: MAP0, is: is0() });
    // the schema cannot be verified, so the verifier computes none of the six members itself
    const v = await verifyPCActn(p, { grant: g, audience: AUD, now: NOW, context: { params: PARAMS, env: forgedEnv }, intentV2: ctx({ schema: { docs: [], keys: [] } }) });
    expect(denied(v)).toBe(true);
  });
  it('a non-session action reads the host env as given', async () => {
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', predicates: forgedPreds as never });
    const p = build(g, { salt: 'salt0', map: MAP0 });
    const v = await verifyPCActn(p, { grant: g, audience: AUD, now: NOW, context: { params: PARAMS, env: forgedEnv } });
    expect(denied(v)).toBe(false);
  });
  it('wire validation continues past a well-formed intent_session', () => {
    const p = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
    expect(validateWireV2(p)).toBeNull();
    expect(validateWireV2({ ...p, prohibition_evidence: 5 })).toBe("'prohibition_evidence' must be an object or array");
  });
});
