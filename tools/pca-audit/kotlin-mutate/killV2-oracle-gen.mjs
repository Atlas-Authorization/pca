// Oracle for the Kotlin "V2" kill tests (KillV2Test.kt): runs the TS reference (intent-v2.ts `decideIntentV2` /
// `intentV2Active`, intent-revocation.ts `checkSessionRevocation` / `revocationEpochShapeError`) on the Intent Layer v2
// vectors of the conformance core corpus plus targeted variants, and writes the golden JSON (every check's EXACT reason
// and the verifier-computed env). Deterministic (byte-for-byte reproducible; Ed25519 only).
//   tsx <this> <out.json>       (out: sdks/kotlin-pca/test-data/killV2.json, then gzip -9n it to killV2.json.gz)
// Numbers whose LEXICAL form matters (-0, 1e21) are carried as Raw(text, value): the TS reference sees the value
// JSON.parse would yield, the golden file carries the text.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const corpus = JSON.parse(fs.readFileSync(new URL('../../../packages/pca/conformance/vectors.json', import.meta.url), 'utf8'));

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };

class Raw { constructor(text, value) { this.text = text; this.value = value; } }
const NEG0 = new Raw('-0', -0);
const toTs = (x) => {
  if (x instanceof Raw) return x.value;
  if (Array.isArray(x)) return x.map(toTs);
  if (x && typeof x === 'object') { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = toTs(v); return o; }
  return x;
};
const raws = [];
const toJsonable = (x) => {
  if (x instanceof Raw) { raws.push(x.text); return `__RAW${raws.length - 1}__`; }
  if (typeof x === 'number' && Object.is(x, -0)) { raws.push('-0'); return `__RAW${raws.length - 1}__`; }
  if (Array.isArray(x)) return x.map(toJsonable);
  if (x && typeof x === 'object') { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = toJsonable(v); return o; }
  return x;
};
const clone = (x) => {
  if (x instanceof Raw) return x;
  if (Array.isArray(x)) return x.map(clone);
  if (x && typeof x === 'object') { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = clone(v); return o; }
  return x;
};

const names = new Set();
const out = { decide: [], rev: [], shape: [], truthy: [], jstext: [], active: [] };
const add = (sec, c) => {
  const k = `${sec}/${c.name}`;
  if (names.has(k)) throw new Error(`duplicate ${k}`);
  names.add(k);
  out[sec].push(c);
};

// ---------------------------------------------------------------- decideIntentV2
const envText = (env) => pca.canonicalizeStrict(env ?? {});
/** One decide case: `ctx` undefined = no context (the member absent). */
function dec(name, { p, grant, ctx, now = NOW }) {
  const d = pca.decideIntentV2(toTs(p), toTs(grant), ctx === undefined ? undefined : toTs(ctx), toTs(now));
  add('decide', {
    name, p: toJsonable(clone(p)), grant: toJsonable(clone(grant)), ...(ctx === undefined ? {} : { ctx: toJsonable(clone(ctx)) }), now: toJsonable(now),
    checks: d.checks.map((c) => [c.name, c.ok, c.reason ?? null]), env: envText(d.env),
  });
}
const NOW = 1_800_000_000_000;
for (const v of corpus.vectors) {
  if (!v.context || !('intent_v2' in v.context) || !v.pcactn) continue;
  dec(`corpus/${v.name}`, { p: v.pcactn, grant: v.grant, ctx: v.context.intent_v2, now: v.context.now });
}

// ---------------------------------------------------------------- primitives.intent_revocation
const PARAMS_R = ['session', 'scope', 'authority', 'ids', 'now', 'max_age_ms', 'last'];
function rev(name, input) {
  const t = toTs(input);
  let reason;
  if (t === null || typeof t !== 'object' || Array.isArray(t)) reason = 'NOT-OBJECT';
  else {
    const ev = {};
    for (const [k, v] of Object.entries(t)) if (!PARAMS_R.includes(k)) ev[k] = v;
    const r = pca.checkSessionRevocation(ev, { session: t.session, authority: t.authority, ids: t.ids, now: t.now, maxAgeMs: t.max_age_ms, ...('last' in t ? { last: t.last } : {}) });
    reason = r.ok ? null : r.reason;
  }
  add('rev', { name, input: toJsonable(clone(input)), reason });
}
for (const x of corpus.primitives.intent_revocation) rev(`corpus/${x.name}`, x.input);

// ---------------------------------------------------------------- the signed v2 scenario (gen-conformance-intent-v2.mjs)
const principal = mk('v2/principal'), agent = mk('v2/agent'), site = mk('v2/site'), stranger = mk('v2/stranger'), revAuth = mk('v2/revocation-authority');
const AUD = 'skyair.example';
const REF = pca.b64u(seed('v2/ref'));
const MAP0 = pca.b64u(seed('v2/map0'));
const MAP1 = pca.b64u(seed('v2/map1'));
const MAP2 = pca.b64u(seed('v2/map2'));
const SESSION = pca.b64u(seed('v2/session'));
const UNSIGNED = {
  v: 1, kind: 'pca-action-schema', site: 'https://skyair.example', aud: AUD, version: '2026-10-01',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
  verbs: [
    {
      verb: 'air.book', kind: 'write',
      params: {
        'action.params.offer_id': { type: 'string', semantic: 'product.ref', sensitivity: 'material' },
        'action.params.total': { type: 'integer', unit: 'usd_cents', min: 0, max: 5_000_000, semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] },
        'action.params.add_ons': { type: 'set', values: ['none', 'tripshield', 'seat_plus'], default: ['none'], principal_neutral_default: true, semantic: 'product.addon', sensitivity: 'material' },
        'action.params.refundable': { type: 'boolean', semantic: 'flag', sensitivity: 'material' },
        'action.params.passengers': { type: 'array', max_items: 9, max_len: 64, semantic: 'person.identity', sensitivity: 'critical', required: false },
        'action.params.note': { type: 'string', semantic: 'text.note', sensitivity: 'free', required: false, max_len: 16 },
      },
      reversibility_by: { param: 'action.params.refundable', map: { true: 'reversible', false: 'irreversible' } },
    },
    {
      verb: 'air.search', kind: 'read',
      params: {
        'action.params.from': { type: 'string', values: ['SFO', 'JFK'], semantic: 'place.airport', sensitivity: 'material' },
        'action.params.date': { type: 'date', semantic: 'schedule.date', sensitivity: 'material' },
        'action.params.pax': { type: 'integer', min: 1, max: 9, semantic: 'quantity', sensitivity: 'material' },
      },
      reversibility: 'reversible',
    },
  ],
};
const SCHEMA = pca.signActionSchema(UNSIGNED, 'skyair-2026', site.sk);
const OTHER_SCHEMA = pca.signActionSchema({ ...UNSIGNED, version: 'v2' }, 'skyair-2026', site.sk);
const FOREIGN_AUD_SCHEMA = pca.signActionSchema({ ...UNSIGNED, aud: 'hotel.example' }, 'skyair-2026', site.sk);
const KEYS = [pca.actionSchemaKeyOf('skyair-2026', site.sk)];
const SD = pca.actionSchemaDigest(SCHEMA);
const TRIP = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
const QUESTIONS = { id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' } };
const rootBody = (over = {}) => ({
  v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: principal.pub }], intent_ref: REF, schema: { aud: AUD, digest: SD },
  layers: { task: { map_digest: MAP0 } }, accumulators: [TRIP, QUESTIONS], monitors: [], question_uri: 'https://atlas.example/q', expires_at: NOW + 86_400_000, ...over,
});
const rootOf = (over) => { const S = pca.signSessionRoot(rootBody(over), principal.sk); return { S, R: pca.sessionRootDigest(S) }; };
const BASE = rootOf();
const mint = ({ seq, prev, map, salt, signer = principal, root = BASE.R, session = SESSION }) =>
  pca.mintSessionGrant({ principalSecret: signer.sk, principalPublic: signer.pub, holder: agent.pub, session, seq, ...(prev !== undefined ? { prev } : {}), root, mapDigest: map, predicates: [{ verb: 'air.book', resource: '*' }], salt }).grant;
const PARAMS = { offer_id: 'OF-1', total: 38_900, add_ons: ['none'], refundable: false };
const planFor = (params) => [{ id: 'book', verb: 'air.book', resource: 'skyair.example/bookings', reversibility_class: 'irreversible', params_digest: pca.paramsDigest(params) }];
const build = (grant, { salt = 'salt0', map = MAP0, is, params = PARAMS, ref = REF }) =>
  pca.buildPCActn({ grant, chain: [grant], plan: planFor(params), nodeId: 'book', params, counter: 1, signerSecret: agent.sk, aud: AUD, now: NOW, ttlMs: 600_000, intent: { ref, map_digest: map, goal_salt: salt, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 }, ...(is ? { intentSession: is } : {}) });
const is0 = (over = {}) => ({ session: SESSION, root: BASE.R, seq: 0, schema: SD, acc: [{ id: 'trip_spend', post: 38_900 }], ...over });
const ctx = (over = {}) => ({ params: PARAMS, schema: { docs: [SCHEMA], keys: KEYS }, session: { root: BASE.S, grants: [] }, acc: { state: { trip_spend: { sum: 0 } }, monitors: {} }, ...over });
const G0 = mint({ seq: 0, map: MAP0, salt: 'salt0' });
const P0 = build(G0, { is: is0() });
const PLAIN = build(G0, {});
const without = (o, ...ks) => { const c = clone(o); for (const k of ks) delete c[k]; return c; };
const withIs = (p, over) => ({ ...clone(p), intent_session: { ...clone(p.intent_session), ...over } });
const D = (name, c) => dec(`v2/${name}`, c);

// -- context shape (contextError): every member, wrong types, each with a present and an absent intent_session
const COMMIT = withIs(P0, { map_form: 'commit' });
const ctxBad = [
  ['null', null], ['array', []], ['string', 'x'],
  ['policy-null', ctx({ policy: null })], ['policy-array', ctx({ policy: [] })], ['policy-extra', ctx({ policy: { extra: 1 } })],
  ['policy-session-null', ctx({ policy: { session: null } })], ['policy-session-extra', ctx({ policy: { session: { x: 1 } } })],
  ['policy-session-require-str', ctx({ policy: { session: { require: 'true' } } })], ['policy-session-require-null', ctx({ policy: { session: { require: null } } })],
  ['policy-session-age-neg', ctx({ policy: { session: { max_revocation_age_s: -1 } } })], ['policy-session-age-frac', ctx({ policy: { session: { max_revocation_age_s: 1.5 } } })],
  ['policy-session-age-neg0', ctx({ policy: { session: { max_revocation_age_s: NEG0 } } })], ['policy-session-age-str', ctx({ policy: { session: { max_revocation_age_s: '1' } } })],
  ['policy-schema-null', ctx({ policy: { schema: null } })], ['policy-schema-array', ctx({ policy: { schema: [] } })], ['policy-schema-extra', ctx({ policy: { schema: { open: true } } })],
  ['policy-schema-cw-num', ctx({ policy: { schema: { closed_world: 1 } } })],
  ['policy-acc-null', ctx({ policy: { acc: null } })], ['policy-acc-extra', ctx({ policy: { acc: { x: 1 } } })],
  ['policy-acc-receipt-neg', ctx({ policy: { acc: { max_receipt_age_s: -1 } } })], ['policy-acc-keyset-neg', ctx({ policy: { acc: { max_keyset_age_s: -1 } } })],
  ['policy-acc-keyset-str', ctx({ policy: { acc: { max_receipt_age_s: 1, max_keyset_age_s: '1' } } })],
  ['policy-map-null', ctx({ policy: { map: null } })], ['policy-map-extra', ctx({ policy: { map: { x: 1 } } })], ['policy-map-require-num', ctx({ policy: { map: { require: 1 } } })],
  ['policy-map-eps-neg', ctx({ policy: { map: { max_residual_risk_ppm: -1 } } })], ['policy-map-eps-frac', ctx({ policy: { map: { require: false, max_residual_risk_ppm: 0.5 } } })],
  ['params-null', ctx({ params: null })], ['params-array', ctx({ params: [] })],
  ['schema-null', ctx({ schema: null })], ['schema-array', ctx({ schema: [] })], ['session-null', ctx({ session: null })], ['session-num', ctx({ session: 1 })],
  ['acc-null', ctx({ acc: null })], ['acc-str', ctx({ acc: 'x' })],
  ['map-null', ctx({ map: null })], ['map-array', ctx({ map: [] })], ['map-extra', ctx({ map: { disclosure: {}, x: 1 } })],
  ['layers-null', ctx({ layers: null })], ['layers-array', ctx({ layers: [] })], ['layers-extra', ctx({ layers: { team: { predicates: [] } } })],
  ['layers-org-null', ctx({ layers: { org: null } })], ['layers-site-nopred', ctx({ layers: { site: {} } })], ['layers-std-pred-num', ctx({ layers: { std: { predicates: 1 } } })],
  ['layers-std-then-bad', ctx({ layers: { std: { predicates: [] }, org: { predicates: {} } } })],
  ['wb-null', ctx({ wb: null })], ['wb-array', ctx({ wb: [] })], ['wb-artifacts-null', ctx({ wb: { artifacts: null } })],
  ['wb-artifacts-facts-num', ctx({ wb: { artifacts: { facts: 1 } } })], ['wb-artifacts-labels-num', ctx({ wb: { artifacts: { labels: 1 } } })],
  ['wb-artifacts-verdicts-obj', ctx({ wb: { artifacts: { facts: [], labels: [], verdicts: {} } } })], ['wb-artifacts-offer-num', ctx({ wb: { artifacts: { offer_set: 1 } } })],
  ['wb-policy-null', ctx({ wb: { policy: null } })], ['wb-policy-world-num', ctx({ wb: { policy: { world: 1 } } })], ['wb-policy-prov-num', ctx({ wb: { policy: { world: {}, provenance: 1 } } })],
  ['wb-policy-classifiers-obj', ctx({ wb: { policy: { classifiers: {} } } })],
];
for (const [n, c] of ctxBad) {
  D(`ctx-${n}/present`, { p: P0, grant: G0, ctx: c });
  D(`ctx-${n}/plain`, { p: PLAIN, grant: G0, ctx: c });
  D(`ctx-${n}/commit`, { p: COMMIT, grant: G0, ctx: c });
}
// well-formed edge contexts
const ctxOk = [
  ['absent', undefined], ['empty', {}], ['no-session', without(ctx(), 'session')], ['no-schema', without(ctx(), 'schema')], ['no-acc', without(ctx(), 'acc')],
  ['no-params', without(ctx(), 'params')], ['policy-empty', ctx({ policy: {} })], ['policy-all-ok', ctx({ policy: { session: { require: false, max_revocation_age_s: 0 }, schema: { closed_world: false }, acc: { max_receipt_age_s: 0, max_keyset_age_s: 0 }, map: { require: false, max_residual_risk_ppm: 0 } } })],
  ['cw', ctx({ policy: { schema: { closed_world: true } } })], ['require', ctx({ policy: { session: { require: true } } })], ['map-require', ctx({ policy: { map: { require: true } } })],
  ['cw-no-params', without(ctx({ policy: { schema: { closed_world: true } } }), 'params')], ['cw-no-schema', without(ctx({ policy: { schema: { closed_world: true } } }), 'schema')],
  ['cw-docs-empty', ctx({ policy: { schema: { closed_world: true } }, schema: { docs: [], keys: KEYS } })],
  ['cw-docs-other-first', ctx({ policy: { schema: { closed_world: true } }, schema: { docs: [FOREIGN_AUD_SCHEMA, SCHEMA], keys: KEYS } })],
  ['cw-docs-ours-first', ctx({ policy: { schema: { closed_world: true } }, schema: { docs: [SCHEMA, FOREIGN_AUD_SCHEMA], keys: KEYS } })],
  ['docs-other-then-ours', ctx({ schema: { docs: [OTHER_SCHEMA, SCHEMA], keys: KEYS } })], ['docs-ours-then-other', ctx({ schema: { docs: [SCHEMA, OTHER_SCHEMA], keys: KEYS } })],
  ['docs-junk-then-ours', ctx({ schema: { docs: [1, null, { v: 1 }, SCHEMA], keys: KEYS } })],
  ['schema-docs-num', ctx({ schema: { docs: 1, keys: KEYS } })], ['schema-keys-num', ctx({ schema: { docs: [SCHEMA], keys: 1 } })], ['schema-keys-absent', ctx({ schema: { docs: [SCHEMA] } })],
  ['schema-empty', ctx({ schema: {} })],
  ['session-grants-num', ctx({ session: { root: BASE.S, grants: 1 } })], ['session-grants-absent', ctx({ session: { root: BASE.S } })],
  ['session-rev-num', ctx({ session: { root: BASE.S, grants: [], revocation: 1 } })], ['session-rev-null', ctx({ session: { root: BASE.S, grants: [], revocation: null } })],
  ['session-revlast-num', ctx({ session: { root: BASE.S, grants: [], revocation_last: 1 } })], ['session-empty', ctx({ session: {} })],
  ['acc-state-num', ctx({ acc: { state: 1, monitors: {} } })], ['acc-monitors-num', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: 1 } })],
  ['acc-last-seq-num', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, last_seq: 1 } })], ['acc-last-seq-neg', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, last_seq: { trip_spend: -1 } } })],
  ['acc-last-seq-ok', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, last_seq: { trip_spend: 3, x: 0 } } })],
  ['acc-ksv-num', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, keyset_versions: 1 } })], ['acc-ksv-bad', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, keyset_versions: { r: { version: 'x' } } } })],
  ['acc-receipts-num', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, receipts: 1 } })], ['acc-seqkeys-obj', ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, sequencer_keys: {} } })],
  ['acc-empty', ctx({ acc: {} })], ['acc-state-absent', ctx({ acc: { monitors: {} } })], ['acc-state-empty', ctx({ acc: { state: {}, monitors: {} } })],
  ['acc-state-pre', ctx({ acc: { state: { trip_spend: { sum: 100 } }, monitors: {} } })],
  ['acc-state-bad', ctx({ acc: { state: { trip_spend: { sum: -1 } }, monitors: {} } })],
  ['layers-empty', ctx({ layers: {} })], ['layers-extra-member', ctx({ layers: { org: { predicates: [], x: 1 } } })],
  ['layers-all-pass', ctx({ layers: { org: { predicates: [{ verb: 'air.book' }] }, site: { predicates: [{ verb: 'air.book' }] }, std: { predicates: [{ verb: 'air.book' }] } } })],
  ['layers-std-fails', ctx({ layers: { org: { predicates: [{ verb: 'air.book' }] }, std: { predicates: [{ verb: 'air.search' }] } } })],
  ['layers-site-fails', ctx({ layers: { site: { predicates: [{ verb: 'air.search' }] } } })],
  ['layers-canon', ctx({ layers: { site: { predicates: [{ verb: 'air.book', where: [{ field: 'env.canon.refundable', op: 'eq', value: 'false' }] }] } } })],
  ['layers-canon-no-params', without(ctx({ layers: { site: { predicates: [{ verb: 'air.book', where: [{ field: 'env.canon.refundable', op: 'eq', value: 'false' }] }] } } }), 'params')],
  ['layers-params', ctx({ layers: { site: { predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: 40_000 }] }] } } })],
  ['layers-params-absent', without(ctx({ layers: { site: { predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: 40_000 }] }] } } }), 'params')],
  ['layers-resource', ctx({ layers: { site: { predicates: [{ verb: 'air.book', resource: 'skyair.example/bookings' }] } } })],
  ['layers-resource-other', ctx({ layers: { site: { predicates: [{ verb: 'air.book', resource: 'skyair.example/x' }] } } })],
  ['map-disclosure-null', ctx({ map: { disclosure: null } })], ['map-empty', ctx({ map: {} })], ['map-disclosure-junk', ctx({ map: { disclosure: { x: 1 } } })],
  ['map-eps', ctx({ policy: { map: { max_residual_risk_ppm: 5 } }, map: { disclosure: {} } })],
  ['wb-empty', ctx({ wb: {} })], ['wb-art-empty', ctx({ wb: { artifacts: {} } })], ['wb-policy-empty', ctx({ wb: { policy: {} } })],
  ['wb-policy-world', ctx({ wb: { policy: { world: {}, provenance: {}, classifiers: [] } } })],
];
const PNOINTENT = without(P0, 'intent');
const COMMIT_NOINTENT = without(COMMIT, 'intent');
for (const [n, c] of ctxOk) {
  D(`ok-${n}/present`, { p: P0, grant: G0, ctx: c });
  D(`ok-${n}/plain`, { p: PLAIN, grant: G0, ctx: c });
  D(`ok-${n}/commit`, { p: COMMIT, grant: G0, ctx: c });
  D(`ok-${n}/no-intent`, { p: PNOINTENT, grant: G0, ctx: c });
  D(`ok-${n}/commit-no-intent`, { p: COMMIT_NOINTENT, grant: G0, ctx: c });
}

// -- the clock
for (const [n, now] of [['max', 9_007_199_254_740_991], ['max+1', 9_007_199_254_740_992], ['min', -9_007_199_254_740_991], ['min-1', -9_007_199_254_740_992], ['zero', 0], ['root-expiry', NOW + 86_400_000], ['root-expiry-1', NOW + 86_399_999]]) {
  D(`clock-${n}/present`, { p: P0, grant: G0, ctx: ctx(), now });
  D(`clock-${n}/cw`, { p: PLAIN, grant: G0, ctx: ctx({ policy: { schema: { closed_world: true }, session: { require: true }, map: { require: true } } }), now });
}

// -- rule 13: the session step
D('s13-grant-null', { p: P0, grant: null, ctx: ctx() });
D('s13-grant-no-caveat', { p: P0, grant: { ...clone(G0), caveats: [] }, ctx: ctx() });
D('s13-grant-other-seq', { p: withIs(P0, { seq: 1 }), grant: G0, ctx: ctx({ session: { root: BASE.S, grants: [G0] } }) });
D('s13-grant-stranger', { p: P0, grant: mint({ seq: 0, map: MAP0, salt: 'salt0', signer: stranger }), ctx: ctx() });
D('s13-intent-ref', { p: build(G0, { is: is0(), ref: pca.b64u(seed('v2/x')) }), grant: G0, ctx: ctx() });
D('s13-is-schema', { p: withIs(P0, { schema: pca.b64u(seed('v2/sch')) }), grant: G0, ctx: ctx() });
D('s13-seq0-map', { p: build(G0, { is: is0(), map: MAP1 }), grant: G0, ctx: ctx() });
{
  const SA = rootOf({ schema: { aud: 'hotel.example', digest: SD } });
  const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: SA.R });
  D('s13-schema-aud', { p: build(g, { is: is0({ root: SA.R }) }), grant: g, ctx: ctx({ session: { root: SA.S, grants: [] } }) });
  D('s13-root-other-session', { p: withIs(P0, { session: pca.b64u(seed('v2/s2')) }), grant: G0, ctx: ctx() });
  D('s13-root-digest', { p: withIs(P0, { root: SA.R }), grant: G0, ctx: ctx() });
  D('s13-root-bad-sig', { p: P0, grant: G0, ctx: ctx({ session: { root: { ...clone(BASE.S), sig: SA.S.sig }, grants: [] } }) });
}
// the delta chain: G0 -> D1 -> D2 (and broken variants at each position)
const D1 = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1' });
const D2 = mint({ seq: 2, prev: D1.id, map: MAP2, salt: 'salt2' });
const D1loose = mint({ seq: 1, prev: pca.b64u(seed('v2/nope')), map: MAP1, salt: 'salt1' });
const D2loose = mint({ seq: 2, prev: D1loose.id, map: MAP2, salt: 'salt2' });
const D1stranger = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1', signer: stranger });
const D2s = mint({ seq: 2, prev: D1stranger.id, map: MAP2, salt: 'salt2' });
const G0stranger = mint({ seq: 0, map: MAP0, salt: 'salt0', signer: stranger });
const D1fromStr = mint({ seq: 1, prev: G0stranger.id, map: MAP1, salt: 'salt1' });
const G0other = mint({ seq: 0, map: MAP0, salt: 'salt0', session: pca.b64u(seed('v2/s2')) });
const p1 = build(D1, { salt: 'salt1', map: MAP1, is: is0({ seq: 1 }) });
const p2 = build(D2, { salt: 'salt2', map: MAP2, is: is0({ seq: 2 }) });
const chain = [
  ['d1-ok', p1, D1, [G0]], ['d1-extra-held', p1, D1, [G0, D1]], ['d1-none', p1, D1, []], ['d1-prior-num', p1, D1, [1]], ['d1-prior-null', p1, D1, [null]],
  ['d1-prior-id-num', p1, D1, [{ ...clone(G0), id: 1 }]], ['d1-prior-issuer-num', p1, D1, [{ ...clone(G0), issuer: 1 }]], ['d1-prior-no-id', p1, D1, [without(G0, 'id')]],
  ['d1-prior-alg-bad', p1, D1, [{ ...clone(G0), alg: 'nope' }]], ['d1-prior-alg-num', p1, D1, [{ ...clone(G0), alg: 1 }]], ['d1-prior-alg-ok', p1, D1, [{ ...clone(G0), alg: 'ed25519' }]],
  ['d1-prior-is-d1', p1, D1, [D1]], ['d1-prior-other-session', p1, D1, [G0other]], ['d1-prior-no-caveat', p1, D1, [{ ...clone(G0), caveats: [] }]],
  ['d1-prior-stranger', p1, D1fromStr, [G0stranger]], ['d1-loose', p1, D1loose, [G0]], ['d1-admit-stranger', p1, D1stranger, [G0]],
  ['d2-ok', p2, D2, [G0, D1]], ['d2-one-held', p2, D2, [G0]], ['d2-loose', p2, D2loose, [G0, D1loose]], ['d2-swapped', p2, D2, [D1, G0]],
  ['d2-prior1-stranger', p2, D2s, [G0, D1stranger]], ['d2-prior1-alg', p2, D2, [G0, { ...clone(D1), alg: 'nope' }]], ['d2-prior1-num', p2, D2, [G0, 7]],
  ['d2-prior1-other-seq', p2, D2, [G0, G0]], ['d2-prior0-bad-prior1-ok', p2, D2, [{ ...clone(G0), issuer: 1 }, D1]], ['d2-admit-prev-g0', p2, mint({ seq: 2, prev: G0.id, map: MAP2, salt: 'salt2' }), [G0, D1]],
];
for (const [n, p, g, prior] of chain) {
  const st = { trip_spend: { sum: 0 } };
  D(`chain-${n}`, { p, grant: g, ctx: ctx({ session: { root: BASE.S, grants: prior }, acc: { state: st, monitors: {} } }) });
}

// -- rule 13 step 7: revocation through the session (the ids each action relies on, exactly)
{
  const REV = { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub };
  const STD = { profile: 'std-travel', version: 3, digest: pca.b64u(seed('v2/std')) };
  const R4 = rootOf({ revocation: REV });
  const R5 = rootOf({ revocation: REV, layers: { task: { map_digest: MAP0 }, std: STD } });
  const R6 = rootOf({ revocation: { ...REV, max_age_s: 120 } });
  const R7 = rootOf({ layers: { task: { map_digest: MAP0 }, std: STD } });
  const ev = (revoked, issued = NOW - 1_000, signer = revAuth, over = {}) => {
    const set = new pca.RevocationSet(revoked);
    return { epoch: pca.signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: pca.sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000, ...over }), revoked: set.list() };
  };
  const scen = (R) => {
    const g0 = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R.R });
    const d1 = mint({ seq: 1, prev: g0.id, map: MAP1, salt: 'salt1', root: R.R });
    const d2 = mint({ seq: 2, prev: d1.id, map: MAP2, salt: 'salt2', root: R.R });
    return { g0, d1, d2, q0: build(g0, { is: is0({ root: R.R }) }), q2: build(d2, { salt: 'salt2', map: MAP2, is: is0({ root: R.R, seq: 2 }) }) };
  };
  const c = (R, prior, rev, policy, last) => ctx({ ...(policy ? { policy } : {}), session: { root: R.S, grants: prior, ...(rev !== undefined ? { revocation: rev } : {}), ...(last !== undefined ? { revocation_last: last } : {}) } });
  const s4 = scen(R4), s5 = scen(R5), s6 = scen(R6), s7 = scen(R7);
  const ids2 = (s) => [pca.sessionRevocationId(SESSION), pca.mapRevocationId(MAP2), pca.deltaRevocationId(s.g0.id), pca.deltaRevocationId(s.d1.id), pca.deltaRevocationId(s.d2.id)];
  D('rev-q2-ok', { p: s4.q2, grant: s4.d2, ctx: c(R4, [s4.g0, s4.d1], ev(['pca-intent:zz'])) });
  for (const [i, id] of ids2(s4).entries()) D(`rev-q2-revoked-${i}`, { p: s4.q2, grant: s4.d2, ctx: c(R4, [s4.g0, s4.d1], ev([id])) });
  D('rev-q2-map0-not-relied', { p: s4.q2, grant: s4.d2, ctx: c(R4, [s4.g0, s4.d1], ev([pca.mapRevocationId(MAP0)])) });
  D('rev-q0-grant-no-id', { p: s4.q0, grant: without(s4.g0, 'id'), ctx: c(R4, [], ev(['pca-intent:delta:undefined'])) });
  D('rev-q0-grant-id-num', { p: s4.q0, grant: { ...clone(s4.g0), id: 7 }, ctx: c(R4, [], ev(['pca-intent:delta:7'])) });
  D('rev-q0-grant-id-null', { p: s4.q0, grant: { ...clone(s4.g0), id: null }, ctx: c(R4, [], ev(['pca-intent:delta:null'])) });
  D('rev-q0-grant-null-id-ok', { p: s4.q0, grant: { ...clone(s4.g0), id: null }, ctx: c(R4, [], ev([])) });
  D('rev-std-ok', { p: s5.q0, grant: s5.g0, ctx: c(R5, [], ev([])) });
  D('rev-std-revoked', { p: s5.q0, grant: s5.g0, ctx: c(R5, [], ev([pca.profileRevocationId('std-travel', 3)])) });
  D('rev-std-other-version', { p: s5.q0, grant: s5.g0, ctx: c(R5, [], ev([pca.profileRevocationId('std-travel', 2)])) });
  D('rev-nostd-profile-listed', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev([pca.profileRevocationId('std-travel', 3)])) });
  D('rev-std-no-revocation', { p: s7.q0, grant: s7.g0, ctx: c(R7, [], ev([pca.profileRevocationId('std-travel', 3)])) });
  // the age bound: the stricter of S.revocation.max_age_s and the policy
  for (const [n, R, s, issued, pol] of [
    ['s60-at', R4, s4, NOW - 60_000], ['s60-over', R4, s4, NOW - 60_001], ['s120-over60', R6, s6, NOW - 90_000],
    ['s120-pol60', R6, s6, NOW - 90_000, { session: { max_revocation_age_s: 60 } }], ['s60-pol120', R4, s4, NOW - 90_000, { session: { max_revocation_age_s: 120 } }],
    ['s60-pol120-ok', R4, s4, NOW - 30_000, { session: { max_revocation_age_s: 120 } }], ['s60-pol0', R4, s4, NOW - 1, { session: { max_revocation_age_s: 0 } }],
    ['s60-pol0-now', R4, s4, NOW, { session: { max_revocation_age_s: 0 } }],
  ]) D(`rev-age-${n}`, { p: s.q0, grant: s.g0, ctx: c(R, [], ev([], issued), pol) });
  D('rev-policy-no-authority', { p: P0, grant: G0, ctx: ctx({ policy: { session: { max_revocation_age_s: 60 } }, session: { root: BASE.S, grants: [], revocation: ev([]) } }) });
  D('rev-absent', { p: s4.q0, grant: s4.g0, ctx: c(R4, []) });
  D('rev-last-ok', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev(['pca-intent:a', 'pca-intent:b']), undefined, ev(['pca-intent:a'])) });
  D('rev-last-null', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev([]), undefined, null) });
  D('rev-last-drop', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev(['pca-intent:b']), undefined, ev(['pca-intent:a'])) });
  D('rev-last-rollback', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev(['pca-intent:a']), undefined, ev(['pca-intent:a', 'pca-intent:b'])) });
  D('rev-last-equivocation', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev(['pca-intent:a']), undefined, ev(['pca-intent:b'])) });
  D('rev-shape-bad', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], { epoch: { ...ev([]).epoch, sig: 1 }, revoked: [] }) });
  D('rev-foreign', { p: s4.q0, grant: s4.g0, ctx: c(R4, [], ev([], NOW - 1_000, stranger)) });
}

// -- rule 15: accumulators
{
  const st0 = { trip_spend: { sum: 0 } };
  const A = (n, p, c, g = G0) => D(`acc-${n}`, { p, grant: g, ctx: c });
  A('no-claims-member', build(G0, { is: without(is0(), 'acc') }), ctx());
  A('claims-empty', build(G0, { is: is0({ acc: [] }) }), ctx());
  A('claim-unknown-first', build(G0, { is: is0({ acc: [{ id: 'nope', post: 1 }, { id: 'trip_spend', post: 38_900 }] }) }), ctx());
  A('claim-wallet', build(G0, { is: is0({ acc: [{ id: 'questions', post: 1 }, { id: 'trip_spend', post: 38_900 }] }) }), ctx());
  A('claim-receipt-site-local', build(G0, { is: is0({ acc: [{ id: 'trip_spend', post: 38_900, receipt: pca.b64u(seed('v2/rc')) }] }) }), ctx());
  A('claim-wrong-post', build(G0, { is: is0({ acc: [{ id: 'trip_spend', post: 1 }] }) }), ctx());
  A('pre-state', P0, ctx({ acc: { state: { trip_spend: { sum: 5 } }, monitors: {} } }));
  A('pre-state-overflow', build(G0, { is: is0({ acc: [{ id: 'trip_spend', post: 1 }] }) }), ctx({ acc: { state: { trip_spend: { sum: 9_007_199_254_740_991 } }, monitors: {} } }));
  A('over-domain', build(G0, { is: is0({ acc: [{ id: 'trip_spend', post: 500_001 }] }) }), ctx({ acc: { state: { trip_spend: { sum: 461_101 } }, monitors: {} } }));
  A('at-domain', build(G0, { is: is0({ acc: [{ id: 'trip_spend', post: 500_000 }] }) }), ctx({ acc: { state: { trip_spend: { sum: 461_100 } }, monitors: {} } }));
  A('no-schema', P0, without(ctx(), 'schema'));
  A('schema-other', P0, ctx({ schema: { docs: [OTHER_SCHEMA], keys: KEYS } }));
  A('params-absent', P0, without(ctx(), 'params'));
  A('params-total-str', P0, ctx({ params: { ...PARAMS, total: 'x' } }));
  A('params-total-absent', P0, ctx({ params: without(PARAMS, 'total') }));
  A('ctx-absent', P0, undefined);
  A('ctx-empty', P0, {});
  // other accumulator shapes: verb-selected (no schema needed), keyed, unselected with pre-state, monitors
  const DIST = { id: 'payees', agg: 'distinct', val: 'action.params.offer_id', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 3, holder: { kind: 'site_local' } };
  const MAX = { id: 'largest', agg: 'max', val: 'action.params.total', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
  const CNT = { id: 'per_offer', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'sliding', ms: 60_000 }, key: 'action.params.offer_id', domain_max: 1, holder: { kind: 'site_local' } };
  const NOTE = { id: 'per_note', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: 'action.params.note', holder: { kind: 'site_local' } };
  const SEARCH = { id: 'searches', agg: 'count', sel: { verbs: ['air.search'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
  const SEARCH_SEQ = { id: 'seq_searches', agg: 'count', sel: { verbs: ['air.search'] }, win: { kind: 'task' }, key: null, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: stranger.pub } };
  const SEQ = { ...TRIP, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: mk('v2/sequencer-root').pub } };
  const MON = { id: 'hotel_after_flight', kind: 'requires_prior', p: { verb: 'air.book' }, q: { verb: 'hotel.book' }, status: 'committed' };
  const MON2 = { id: 'm2', kind: 'requires_prior', p: { verb: 'air.book' }, q: { verb: 'hotel.book' }, status: 'committed' };
  const sc = (n, over, isAcc, state, extraCtx = {}, params = PARAMS) => {
    const R = rootOf(over);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R.R });
    const p = build(g, { is: is0({ root: R.R, acc: isAcc }), params });
    A(n, p, ctx({ params, session: { root: R.S, grants: [] }, acc: { state, monitors: {} }, ...extraCtx }), g);
    return { R, g, p };
  };
  const good = [{ id: 'payees', post: 2 }, { id: 'largest', post: 40_000 }, { id: 'per_offer', post: 1 }];
  const st = { payees: { values: ['"OF-1"', '"OF-9"'] }, largest: { max: 40_000 }, per_offer: { count: 0 } };
  sc('x-ok', { accumulators: [DIST, MAX, CNT] }, good, st);
  sc('x-no-schema', { accumulators: [DIST, MAX, CNT] }, good, st, { schema: undefined });
  sc('x-key-missing', { accumulators: [DIST, MAX, CNT] }, good, st, {}, without(PARAMS, 'offer_id'));
  sc('x-key-schema-other', { accumulators: [DIST, MAX, CNT] }, good, st, { schema: { docs: [OTHER_SCHEMA], keys: KEYS } });
  sc('note-key-free-text', { accumulators: [NOTE] }, [{ id: 'per_note', post: 1 }], { per_note: { count: 0 } }, {}, { ...PARAMS, note: 'hi' });
  sc('note-key-missing', { accumulators: [NOTE] }, [{ id: 'per_note', post: 1 }], { per_note: { count: 0 } });
  sc('unselected-pre', { accumulators: [TRIP, SEARCH] }, [{ id: 'trip_spend', post: 38_900 }], { trip_spend: { sum: 0 }, searches: { count: 4 } });
  sc('unselected-no-pre', { accumulators: [TRIP, SEARCH] }, [{ id: 'trip_spend', post: 38_900 }], { trip_spend: { sum: 0 } });
  sc('unselected-bad-pre', { accumulators: [TRIP, SEARCH] }, [{ id: 'trip_spend', post: 38_900 }], { trip_spend: { sum: 0 }, searches: { sum: 4 } });
  sc('unselected-claimed', { accumulators: [TRIP, SEARCH] }, [{ id: 'trip_spend', post: 38_900 }, { id: 'searches', post: 1 }], { trip_spend: { sum: 0 }, searches: { count: 0 } });
  sc('unselected-seq-pre', { accumulators: [TRIP, SEARCH_SEQ] }, [{ id: 'trip_spend', post: 38_900 }], { trip_spend: { sum: 0 }, seq_searches: { count: 4 } });
  sc('seq-no-receipt', { accumulators: [SEQ] }, [{ id: 'trip_spend', post: 48_900 }], {});
  sc('seq-receipt-absent', { accumulators: [SEQ] }, [{ id: 'trip_spend', post: 48_900, receipt: pca.b64u(seed('v2/rc')) }], {});
  sc('seq-receipts-junk', { accumulators: [SEQ] }, [{ id: 'trip_spend', post: 48_900, receipt: pca.b64u(seed('v2/rc')) }], {}, { acc: { receipts: [1, null, 'x', {}], monitors: {} } });
  sc('mon-ok', { monitors: [MON, MON2] }, [{ id: 'trip_spend', post: 38_900 }], st0, { acc: { state: st0, monitors: { hotel_after_flight: 'unmet', m2: 'met' } } });
  sc('mon-second-bad', { monitors: [MON, MON2] }, [{ id: 'trip_spend', post: 38_900 }], st0, { acc: { state: st0, monitors: { hotel_after_flight: 'unmet', m2: 'nah' } } });
  sc('mon-num', { monitors: [MON] }, [{ id: 'trip_spend', post: 38_900 }], st0, { acc: { state: st0, monitors: { hotel_after_flight: 1 } } });
  sc('mon-absent', { monitors: [MON] }, [{ id: 'trip_spend', post: 38_900 }], st0, { acc: { state: st0 } });
}

// -- rule 19: the committed map step without its inputs
D('map-no-intent', { p: COMMIT_NOINTENT, grant: G0, ctx: ctx({ map: { disclosure: {} } }) });
D('map-policy-plain', { p: PLAIN, grant: G0, ctx: ctx({ policy: { map: { require: true } }, map: { disclosure: {} } }) });
D('map-policy-present-uncommitted', { p: P0, grant: G0, ctx: ctx({ policy: { map: { require: true } }, map: { disclosure: {} } }) });
D('map-commit-no-ctx', { p: COMMIT, grant: G0 });

// ---------------------------------------------------------------- intentV2Active
for (const [n, p, c] of [
  ['plain-none', PLAIN, undefined], ['present-none', P0, undefined], ['plain-empty', PLAIN, {}], ['plain-cw', PLAIN, { policy: { schema: { closed_world: true } } }],
  ['plain-cw-false', PLAIN, { policy: { schema: { closed_world: false } } }], ['plain-cw-str', PLAIN, { policy: { schema: { closed_world: 'true' } } }],
  ['plain-require', PLAIN, { policy: { session: { require: true } } }], ['plain-require-1', PLAIN, { policy: { session: { require: 1 } } }],
  ['plain-map', PLAIN, { policy: { map: { require: true } } }], ['plain-map-false', PLAIN, { policy: { map: { require: false } } }],
  ['present-null-ctx', P0, null], ['plain-null-ctx', PLAIN, null], ['plain-str-ctx', PLAIN, 'x'], ['is-null', { ...clone(PLAIN), intent_session: null }, undefined],
  ['plain-policy-null', PLAIN, { policy: null }], ['plain-all-false', PLAIN, { policy: { schema: { closed_world: false }, session: { require: false }, map: { require: false } } }],
]) add('active', { name: n, p: toJsonable(clone(p)), ...(c === undefined ? {} : { ctx: toJsonable(clone(c)) }), want: pca.intentV2Active(p, c) });

// ---------------------------------------------------------------- the revocation primitive, targeted
{
  const ID = pca.sessionRevocationId(SESSION);
  const make = (revoked, issued = NOW - 10_000, signer = revAuth, over = {}) => {
    const set = new pca.RevocationSet(revoked);
    return { epoch: pca.signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: pca.sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000, ...over }), revoked: set.list() };
  };
  const base = (over = {}, ev = make(['pca-intent:map:a', 'pca-intent:session:zzzz'])) => ({ ...clone(ev), session: SESSION, authority: revAuth.pub, ids: [ID], now: NOW, max_age_ms: 60_000, ...over });
  const R = (n, input) => rev(`t/${n}`, input);
  R('ok', base());
  for (const [n, v] of [['0', 0], ['neg', -1], ['neg0', NEG0], ['frac', 0.5], ['str', '1'], ['null', null], ['max', 9_007_199_254_740_991], ['max+1', 9_007_199_254_740_992], ['big', 1e300]]) {
    R(`max-age-${n}`, base({ max_age_ms: v }));
    R(`now-${n}`, base({ now: v }));
  }
  R('now-neg-max', base({ now: -9_007_199_254_740_991 }));
  R('now-neg-max-1', base({ now: -9_007_199_254_740_992 }));
  R('max-age-absent', without(base(), 'max_age_ms'));
  R('now-absent', without(base(), 'now'));
  R('ids-absent', without(base(), 'ids'));
  R('ids-not-list', base({ ids: {} }));
  R('authority-absent', without(base(), 'authority'));
  R('authority-num', base({ authority: 1 }));
  R('authority-other', base({ authority: stranger.pub }));
  R('session-absent', without(base(), 'session'));
  R('session-num', base({ session: 1 }));
  R('epoch-absent', without(base(), 'epoch'));
  R('epoch-null', base({ epoch: null }));
  R('revoked-absent', without(base(), 'revoked'));
  R('evidence-extra', base({ proofs: 1 }));
  R('evidence-extra-first', { extra: 1, ...base() });
  R('not-object', [1]);
  R('input-null', null);
  for (const [n, ids] of [['num', [1]], ['null', [null]], ['neg0', [NEG0]], ['nested', [[1, null, [2, 'x']]]], ['obj', [{}]], ['bool', [true]], ['frac', [1.5]], ['empty-list', [[]]],
    ['str-then-num', [ID + 'x', 5]], ['revoked-second', ['pca-intent:other', 'pca-intent:map:a']], ['none', []], ['dup-ok', [ID, ID]]]) R(`ids-${n}`, base({ ids }));
  R('revoked-in-list', base({}, make([ID])));
  R('empty-set', base({}, make([])));
  R('age-at', base({}, make([], NOW - 60_000)));
  R('age-over', base({}, make([], NOW - 60_001)));
  R('future-at', base({}, make([], NOW + 60_000)));
  R('future-over', base({}, make([], NOW + 60_001)));
  R('not-after-at', base({}, make([], NOW - 10_000, revAuth, { not_after: NOW })));
  R('not-after-over', base({ max_age_ms: 9_000_000 }, make([], NOW - 400_000, revAuth, { not_after: NOW - 1 })));
  R('other-scope', base({}, (() => { const set = new pca.RevocationSet([]); return { epoch: pca.signRevocationEpoch(revAuth.sk, { instance_id: 'ana', grant_ref: 'pca-intent-session:x', epoch: 0, set_size: 0, root: set.root, issued_at: NOW, not_after: NOW + 1 }), revoked: [] }; })()));
  R('sig-tampered', base({}, (() => { const e = make([]); e.epoch.instance_id = 'bob'; return e; })()));
  R('alg-ed25519', base({}, (() => { const e = make([]); e.epoch.alg = 'ed25519'; return e; })()));
  R('alg-unknown', base({}, (() => { const e = make([]); e.epoch.alg = 'nope'; return e; })()));
  R('pq-pk-present', base({}, (() => { const e = make([]); e.epoch.pq_pk = 'AA'; return e; })()));
  R('pq-sig-present', base({}, (() => { const e = make([]); e.epoch.pq_sig = 'AA'; return e; })()));
  const e2 = make(['pca-intent:a', 'pca-intent:b']);
  for (const [n, list] of [['short', ['pca-intent:a']], ['long', ['pca-intent:a', 'pca-intent:b', 'pca-intent:c']], ['swapped', ['pca-intent:b', 'pca-intent:a']], ['dup', ['pca-intent:a', 'pca-intent:a']],
    ['other', ['pca-intent:a', 'pca-intent:c']], ['num', ['pca-intent:a', 1]], ['null-item', [null, 'pca-intent:b']], ['obj', { 0: 'pca-intent:a' }], ['str', 'pca-intent:a'], ['null', null],
    ['utf8-order', ['pca-intent:￿', 'pca-intent:\u{10000}']], ['empty', []]]) R(`list-${n}`, base({}, { epoch: e2.epoch, revoked: list }));
  for (const [n, over] of [['epoch-3', { epoch: 3 }], ['size-3', { set_size: 3 }], ['both-3', { epoch: 3, set_size: 3 }], ['epoch-1', { epoch: 1 }]]) R(`count-${n}`, base({}, make(['pca-intent:a', 'pca-intent:b'], NOW - 10_000, revAuth, over)));
  // the tracked last epoch
  const L1 = make(['pca-intent:a'], NOW - 30_000), L2 = make(['pca-intent:a', 'pca-intent:b'], NOW - 30_000), L2b = make(['pca-intent:a', 'pca-intent:c'], NOW - 30_000);
  for (const [n, cur, last] of [['extends', e2, L1], ['same', L1, L1], ['rollback', L1, L2], ['drop', make(['pca-intent:b', 'pca-intent:c']), L2], ['equivocation', e2, L2b],
    ['last-null', e2, null], ['last-num', e2, 1], ['last-extra', e2, { ...clone(L1), x: 1 }], ['last-no-epoch', e2, { revoked: ['pca-intent:a'] }], ['last-epoch-bad', e2, { epoch: { ...clone(L1.epoch), sig: 1 }, revoked: ['pca-intent:a'] }],
    ['last-list-bad', e2, { epoch: L1.epoch, revoked: ['pca-intent:z'] }], ['last-no-list', e2, { epoch: L1.epoch }], ['last-empty', e2, make([], NOW - 30_000)],
    ['last-same-size-other-list', make(['pca-intent:a', 'pca-intent:c']), L2], ['last-drop-first', make(['pca-intent:b', 'pca-intent:c', 'pca-intent:d']), L2]]) R(`last-${n}`, base({ last }, cur));
  R('last-ok-id-revoked', base({ last: L1, ids: ['pca-intent:a'] }, e2));
}

// ---------------------------------------------------------------- revocationEpochShapeError, JS truthiness, JS String()
{
  const set = new pca.RevocationSet([]);
  const E = pca.signRevocationEpoch(revAuth.sk, { instance_id: 'ana', grant_ref: 'g', epoch: 0, set_size: 0, root: set.root, issued_at: NOW, not_after: NOW + 1 });
  const S = (n, ep) => add('shape', { name: n, ep: toJsonable(clone(ep)), want: pca.revocationEpochShapeError(toTs(ep)) });
  S('ok', E);
  for (const x of [null, [], 'x', 1]) S(`not-object-${JSON.stringify(x)}`, x);
  for (const k of ['instance_id', 'grant_ref', 'root', 'guardian', 'sig']) { S(`${k}-absent`, without(E, k)); S(`${k}-num`, { ...E, [k]: 1 }); S(`${k}-null`, { ...E, [k]: null }); }
  for (const k of ['epoch', 'set_size', 'issued_at', 'not_after']) for (const [n, v] of [['absent', undefined], ['neg', -1], ['frac', 0.5], ['str', '1'], ['neg0', NEG0], ['big', 9_007_199_254_740_992], ['max', 9_007_199_254_740_991], ['null', null]]) S(`${k}-${n}`, v === undefined ? without(E, k) : { ...E, [k]: v });
  for (const [n, v] of [['0', 0], ['neg', -1], ['null', null], ['str', '1'], ['frac', 2.5], ['max', 9_007_199_254_740_991]]) S(`guardian_epoch-${n}`, { ...E, guardian_epoch: v });
  for (const [n, v] of [['ed25519', 'ed25519'], ['ml-dsa-65', 'ml-dsa-65'], ['hybrid', 'ed25519+ml-dsa-65'], ['nope', 'nope'], ['num', 1], ['null', null]]) S(`alg-${n}`, { ...E, alg: v });
  for (const k of ['pq_pk', 'pq_sig']) for (const [n, v] of [['str', 'x'], ['num', 1], ['null', null]]) S(`${k}-${n}`, { ...E, [k]: v });
  S('two-bad-strings', { ...E, root: 1, sig: 1 });
  S('bad-number-and-alg', { ...E, not_after: -1, alg: 'nope' });
  S('bad-alg-and-pq', { ...E, alg: 'nope', pq_pk: 1 });
  S('bad-pq-both', { ...E, pq_pk: 1, pq_sig: 1 });
  S('bad-pq-sig-only', { ...E, pq_pk: 'x', pq_sig: 1 });
  S('extra-member', { ...E, extra: 1 });
  for (const [n, v] of [['null', null], ['true', true], ['false', false], ['empty', ''], ['str', 'a'], ['zero', 0], ['neg0', NEG0], ['one', 1], ['neg', -1], ['frac', 0.5], ['list', []], ['obj', {}], ['big', 1e300]])
    add('truthy', { name: n, v: toJsonable(v), want: Boolean(toTs(v)) });
  for (const [n, v] of [['null', null], ['true', true], ['str', 'a'], ['empty', ''], ['zero', 0], ['neg0', NEG0], ['int', 42], ['neg', -7], ['frac', 1.5], ['list', [1, null, [2, 3], 'a', true]], ['list-empty', []],
    ['list-nested-empty', [[], []]], ['list-null', [null]], ['obj', {}], ['list-obj', [{}, 1]]])
    add('jstext', { name: n, v: toJsonable(v), want: String(toTs(v)) });
}

// ---------------------------------------------------------------- write
let text = JSON.stringify(out, null, 0).replace(/"__RAW(\d+)__"/g, (_, i) => raws[Number(i)]);
fs.writeFileSync(process.argv[2], text + '\n');
console.log(Object.entries(out).map(([k, v]) => `${k}=${v.length}`).join(' '));
