/**
 * An Intent Layer v2 provenance question (rule 17: a tainted material value) is an escalate-class failure of the
 * `provenance` check. requirePCA must never replace it with an undo window: reversibility does not make a value that
 * untrusted content chose safe to run. Fixture: a session-bound grant and a signed action schema, as in the verifier's
 * Intent Layer v2 wiring tests.
 */
import { describe, expect, it } from 'vitest';
import { b64u, buildPCActn, paramsDigest, publicKeyOf, sha256, utf8, type PCActn } from '../index';
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
  type UnsignedActionSchema,
} from '../ext/intent';
import { requirePCA } from './require-pca';

const seed = (l: string) => sha256(utf8(`require-pca-intent-undo/${l}`));
const key = (l: string) => ({ sk: seed(l), pub: b64u(publicKeyOf(seed(l))) });
const principal = key('principal');
const agent = key('agent');
const site = key('site');
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const REF = b64u(seed('ref'));
const MAP0 = b64u(seed('map0'));
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
      },
      reversibility_by: { param: 'action.params.refundable', map: { true: 'reversible', false: 'irreversible' } },
    },
  ],
};
const SCHEMA = signActionSchema(UNSIGNED, 'skyair-2026', site.sk);
const SCHEMA_DIGEST = actionSchemaDigest(SCHEMA);
const TRIP: AccumulatorDecl = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
const S = signSessionRoot(
  {
    v: 1,
    kind: 'pca-intent-session',
    session: SESSION,
    principals: [{ key: principal.pub }],
    intent_ref: REF,
    schema: { aud: AUD, digest: SCHEMA_DIGEST },
    layers: { task: { map_digest: MAP0 } },
    accumulators: [TRIP],
    monitors: [],
    question_uri: 'https://atlas.example/v1/pca/intent/sessions/x/questions',
    expires_at: NOW + 86_400_000,
  },
  principal.sk,
);
const G0 = mintSessionGrant({
  principalSecret: principal.sk,
  principalPublic: principal.pub,
  holder: agent.pub,
  session: SESSION,
  seq: 0,
  root: sessionRootDigest(S),
  mapDigest: MAP0,
  predicates: [{ verb: 'air.book', resource: '*', where: [{ field: 'env.acc.trip_spend.post', op: 'lte', value: 40_000 }] }],
  salt: 'salt0',
}).grant;
const PARAMS = { offer_id: 'OF-1', total: 38_900, add_ons: ['none'], refundable: true };
const build = (is: IntentSessionWire): PCActn =>
  buildPCActn({
    grant: G0,
    chain: [G0],
    plan: [{ id: 'book', verb: 'air.book', resource: 'skyair.example/bookings', reversibility_class: 'reversible', params_digest: paramsDigest(PARAMS) }],
    nodeId: 'book',
    params: PARAMS,
    counter: 1,
    signerSecret: agent.sk,
    aud: AUD,
    now: NOW,
    ttlMs: 600_000,
    intent: { ref: REF, map_digest: MAP0, goal_salt: 'salt0', fidelity_ppm: 1_000_000, residual_risk_ppm: 0 },
    intentSession: is,
  });
const is0 = (over: Partial<IntentSessionWire> = {}): IntentSessionWire => ({ session: SESSION, root: sessionRootDigest(S), seq: 0, schema: SCHEMA_DIGEST, acc: [{ id: 'trip_spend', post: 38_900 }], ...over });
const intentV2 = (): IntentV2Context => ({
  params: PARAMS,
  schema: { docs: [SCHEMA], keys: [actionSchemaKeyOf('skyair-2026', site.sk)] },
  session: { root: S, grants: [] },
  acc: { state: { trip_spend: { sum: 0 } }, monitors: {} },
  wb: { policy: { provenance: { params: { 'action.params.offer_id': 'material' }, registry: { 'web:skyair.example/results#ad-3': 'web' } } } },
} as IntentV2Context);
const ADM = { id: 'undo-1', window_end: NOW + 60_000, compensation: { verb: 'air.cancel' } };
const guard = (over: Partial<Parameters<typeof requirePCA>[0]> = {}) =>
  requirePCA({
    audience: AUD,
    resolveGrant: async (ref) => (ref === G0.id ? G0 : null),
    now: () => NOW,
    insecureAllowUnenforced: true,
    multiInstance: false,
    intentV2: intentV2(),
    context: () => ({ params: PARAMS, risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 } }),
    ...over,
  });

describe('requirePCA: an Intent Layer v2 provenance question is never lifted by an undo window', () => {
  const p = () => build(is0({ prov: { 'action.params.offer_id': ['web:skyair.example/results#ad-3'] } }));
  it('baseline: the tainted material value fails provenance with an escalate-class reason (decision escalate)', async () => {
    const r = await guard()({ headers: {}, body: { pcactn: p() } });
    expect(r.verdict.checks.provenance).toBe('fail');
    expect(r.verdict.reasons.filter((x) => x.startsWith('provenance: '))[0]).toMatch(/^provenance: intent_required: /);
    expect(r).toMatchObject({ ok: false, status: 403, decision: 'escalate' });
  });
  it('with an undo coordinator that would admit it, the escalation stands and admit is never asked', async () => {
    let asked = 0;
    const r = await guard({ undo: { admit: async () => (asked++, ADM as never) } })({ headers: {}, body: { pcactn: p() } });
    expect(r).toMatchObject({ ok: false, status: 403, decision: 'escalate' });
    expect(r.verdict.checks.undo_window).toBeUndefined();
    expect(asked).toBe(0);
  });
});
