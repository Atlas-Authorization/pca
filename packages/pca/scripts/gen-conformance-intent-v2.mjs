// Stage of the conformance pipeline for Intent Layer v2 wire batch W-A (run AFTER gen-conformance-intent.mjs; idempotent):
// normative rules 13 (intent_session wire, binding, delta chain, session revocation), 14 (schema, closed world) and 15
// (accumulators and monitors), plus the V5 `layers` slot of the pipeline (conformance/README.md "Intent Layer v2").
//
//   vectors[]  schema-* / session-* / acc-* / layers-* / ctx-*   full PCActn vectors. `context.intent_v2` carries the VERIFIER
//              state a runner passes to its verifier: { policy?, params?, schema?: {docs, keys}, session?: {root, grants,
//              revocation?, revocation_last?, pq_pins?}, layers?, acc?: {state?, monitors?, receipts?, last_seq?, sequencer_keys?,
//              keyset_versions?} }. `expect.checks` holds the core
//              checks, `intent` when reported (rule 12), then `schema`, `intent_session`, `layers`, `accumulators` each
//              exactly when reported (README "pipeline order"). Reason strings are not compared.
//              A vector may carry `requires_suite` (a runner without that suite must fail the reported checks with a
//              reason containing `unsupported_suite`) and `expect.reason_contains` (every runner must give that reason).
//   primitives.intent_schema[]      rule 14 on its own: { name, input: {schema, keys, verb, params}, expect: {sig, digest?,
//              conform: {ok, code?, path?}} } (`sig`: verifyActionSchema; `digest`: actionSchemaDigest when sig is valid;
//              `conform`: conformAction).
//   primitives.intent_revocation[]  rule 13 step 7 on its own: { name, input: {epoch, revoked, session, scope?, authority,
//              ids, now, max_age_ms, last?: {epoch, revoked}}, expect: {ok} } (checkSessionRevocation; the EVIDENCE is the
//              input without the parameters session, scope, authority, ids, now, max_age_ms, last, and is closed).
//
//     node packages/pca/scripts/gen-conformance-intent-v2.mjs            (reads ../dist, like every stage)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-intent-v2.mjs   (reads ../src)
import { createHash } from 'node:crypto';
import { cloneJson, readCore, writeCore } from './conformance-io.mjs';

import { loadPca } from './pca-all.mjs';
const pca = await loadPca();

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const clone = cloneJson; // JSON deep copy that keeps -0 (conformance-io.mjs)
const principal = mk('v2/principal'), agent = mk('v2/agent'), site = mk('v2/site'), sequencer = mk('v2/sequencer'), sequencer2 = mk('v2/sequencer-2'), seqRoot = mk('v2/sequencer-root'), stranger = mk('v2/stranger'), revAuth = mk('v2/revocation-authority');
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
const V2 = ['schema', 'intent_session', 'layers', 'accumulators', 'map'];
const KEYMAP = { chain: 'cap_chain' };
const REF = pca.b64u(seed('v2/ref'));
const MAP0 = pca.b64u(seed('v2/map0'));
const MAP1 = pca.b64u(seed('v2/map1'));
const SESSION = pca.b64u(seed('v2/session'));

// ---- the site schema --------------------------------------------------------------------------------------------
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
const KEYS = [pca.actionSchemaKeyOf('skyair-2026', site.sk)];
const SD = pca.actionSchemaDigest(SCHEMA);

// ---- session roots -------------------------------------------------------------------------------------------------
const TRIP = { id: 'trip_spend', agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } };
const QUESTIONS = { id: 'questions', agg: 'count', sel: { event: 'intent_required' }, win: { kind: 'task' }, key: null, cap: 6, holder: { kind: 'wallet' } };
const rootBody = (over = {}) => ({
  v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: principal.pub }], intent_ref: REF, schema: { aud: AUD, digest: SD },
  layers: { task: { map_digest: MAP0 } }, accumulators: [TRIP, QUESTIONS], monitors: [], question_uri: 'https://atlas.example/q', expires_at: NOW + 86_400_000, ...over,
});
const rootOf = (over) => { const S = pca.signSessionRoot(rootBody(over), principal.sk); return { S, R: pca.sessionRootDigest(S) }; };
const BASE = rootOf();
/** Sign a session root body WITHOUT the shape check (vectors for roots the shape rule must refuse). */
const rawRoot = (body) => {
  const base = { ...body, signer: principal.pub };
  const dom = new TextEncoder().encode(pca.INTENT_SESSION_SIG_DOMAIN);
  const b = pca.canonicalBytesStrict(base);
  const msg = new Uint8Array(dom.length + b.length);
  msg.set(dom);
  msg.set(b, dom.length);
  return { ...base, ...pca.signSuiteArtifact(undefined, pca.suiteKeysOf(principal.sk, undefined), msg) };
};

const cap = (lo, hi) => [{ verb: 'air.book', resource: '*', where: [...(lo !== null ? [{ field: 'env.acc.trip_spend.post', op: 'gt', value: lo }] : []), { field: 'env.acc.trip_spend.post', op: 'lte', value: hi }] }];
const mint = ({ seq, prev, map, salt, signer = principal, root = BASE.R, session = SESSION }) =>
  pca.mintSessionGrant({ principalSecret: signer.sk, principalPublic: signer.pub, holder: agent.pub, session, seq, ...(prev !== undefined ? { prev } : {}), root, mapDigest: map, predicates: seq === 0 ? cap(null, 40_000) : cap(40_000, 80_000), salt }).grant;
const G0 = mint({ seq: 0, map: MAP0, salt: 'salt0' });
const D1 = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1' });

const PARAMS = { offer_id: 'OF-1', total: 38_900, add_ons: ['none'], refundable: false };
// the committed plan node pins the action's params_digest, so every PCActn is a node of ITS OWN plan
const planFor = (params) => [{ id: 'book', verb: 'air.book', resource: 'skyair.example/bookings', reversibility_class: 'irreversible', params_digest: pca.paramsDigest(params) }];
/** The plan a vector's PCActn commits to, from its signed action (also for resigned / tampered copies). */
const planOf = (p) => [{ id: 'book', verb: 'air.book', resource: 'skyair.example/bookings', reversibility_class: 'irreversible', params_digest: p?.action?.params_digest }];
const build = (grant, { salt, map, is, params = PARAMS, ref = REF }) =>
  pca.buildPCActn({ grant, chain: [grant], plan: planFor(params), nodeId: 'book', params, counter: 1, signerSecret: agent.sk, aud: AUD, now: NOW, ttlMs: 600_000, intent: { ref, map_digest: map, goal_salt: salt, fidelity_ppm: 1_000_000, residual_risk_ppm: 0 }, ...(is ? { intentSession: is } : {}) });
const is0 = (over = {}) => ({ session: SESSION, root: BASE.R, seq: 0, schema: SD, acc: [{ id: 'trip_spend', post: 38_900 }], ...over });
const ctx = (over = {}) => ({ params: PARAMS, schema: { docs: [SCHEMA], keys: KEYS }, session: { root: BASE.S, grants: [] }, acc: { state: { trip_spend: { sum: 0 } }, monitors: {} }, ...over });
const resign = (p) => { const { sig: _s, ...body } = p; return pca.signPCActn(body, agent.sk); };

// ---- vectors -------------------------------------------------------------------------------------------------------
const vectors = [];
// `requires_suite`: the vector needs that signature suite; a verifier that does not implement it must report the
// failing check with a reason containing `unsupported_suite` (never allow, never another reason). `unsupported: true`:
// even the reference refuses with `unsupported_suite` (an alg no verifier implements).
// `reasonContains`: the reference reason contains this text and every runner must give a reason containing it.
async function add(name, description, { grant, pcactn, context, must, requiresSuite, unsupported, reasonContains }) {
  const r = await pca.verifyPCActnCore(pcactn, { grant, nowEpoch: NOW, audience: AUD, intentV2: context });
  const c = r.checks;
  const checks = {};
  if (c.wire === 'fail') checks.wire = false;
  else {
    checks.wire = true;
    for (const k of CHECKS) checks[k] = c[KEYMAP[k] ?? k] === 'pass';
    if (c.intent !== undefined) checks.intent = c.intent === 'pass';
    for (const k of V2) if (c[k] !== undefined) checks[k] = c[k] === 'pass';
  }
  const failed = Object.entries(checks).filter(([, v]) => v === false).map(([k]) => k);
  // `must`: 'allow', 'wire', one failing check name, or the exact list of failing checks
  const want = Array.isArray(must) ? [...must].sort() : [must];
  const ok = must === 'allow' ? r.allow === true : must === 'wire' ? checks.wire === false : r.allow === false && JSON.stringify([...failed].sort()) === JSON.stringify(want);
  if (!ok) throw new Error(`vector ${name}: reference ${JSON.stringify(checks)} allow=${r.allow} does not meet ${must} (${r.reason ?? ''})`);
  if (unsupported && !String(r.reason ?? '').includes('unsupported_suite')) throw new Error(`vector ${name}: expected an unsupported_suite reason, got ${r.reason}`);
  if (reasonContains && !String(r.reason ?? '').includes(reasonContains)) throw new Error(`vector ${name}: expected a reason containing ${reasonContains}, got ${r.reason}`);
  vectors.push({
    name, class: r.allow ? 'positive' : 'negative', description, grant, plan_nodes: planOf(pcactn), context: { now: NOW, aud: AUD, intent_v2: clone(context) }, pcactn,
    ...(requiresSuite ? { requires_suite: requiresSuite } : {}),
    expect: { allow: r.allow === true, checks, ...(unsupported ? { reason_contains: 'unsupported_suite' } : reasonContains ? { reason_contains: reasonContains } : {}) },
  });
}

const P0 = build(G0, { salt: 'salt0', map: MAP0, is: is0() });
// -- accepts
await add('session-g0', 'G_0 (seq 0): session root bound, schema conforms, the claimed post equals the verifier post (0 + 38900).', { grant: G0, pcactn: P0, context: ctx(), must: 'allow' });
{
  const p1 = build(D1, { salt: 'salt1', map: MAP1, is: is0({ seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) });
  await add('session-d1', 'Delta D_1 (seq 1): principal-signed, prev = id(G_0), the verifier holds G_0; pre-state 38900 so post 77800.', { grant: D1, pcactn: p1, context: ctx({ session: { root: BASE.S, grants: [G0] }, acc: { state: { trip_spend: { sum: 38_900 } }, monitors: {} } }), must: 'allow' });
  await add('session-d1-unheld', 'D_1 but the verifier holds no grant at seq 0: intent_session fails (the chain cannot be checked).', { grant: D1, pcactn: p1, context: ctx({ acc: { state: { trip_spend: { sum: 38_900 } }, monitors: {} } }), must: 'intent_session' });
}
await add('session-backcompat', 'No intent_session and no v2 policy: no v2 check is reported (the v1 goal does not open the v2 grant, so intent fails).', { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0 }), context: ctx(), must: 'intent' });
await add('session-require-absent', 'Policy session.require with no intent_session: intent_session fails (and the v1 goal does not open the v2 grant, so intent fails too).', {
  grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0 }), context: ctx({ policy: { session: { require: true } } }), must: ['intent', 'intent_session'],
});

// -- rule 13 failures (only intent_session fails)
{
  const forged = mint({ seq: 1, prev: G0.id, map: MAP1, salt: 'salt1', signer: agent });
  await add('session-agent-signed-delta', 'A delta whose root signer is the AGENT key (not a principal of S): intent_session fails (T15).', { grant: forged, pcactn: build(forged, { salt: 'salt1', map: MAP1, is: is0({ seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) }), context: ctx({ session: { root: BASE.S, grants: [G0] }, acc: { state: { trip_spend: { sum: 38_900 } }, monitors: {} } }), must: 'intent_session' });
  const loose = mint({ seq: 1, prev: pca.b64u(seed('v2/nope')), map: MAP1, salt: 'salt1' });
  await add('session-broken-prev', 'D_1 whose prev is not id(G_0): intent_session fails.', { grant: loose, pcactn: build(loose, { salt: 'salt1', map: MAP1, is: is0({ seq: 1, acc: [{ id: 'trip_spend', post: 77_800 }] }) }), context: ctx({ session: { root: BASE.S, grants: [G0] }, acc: { state: { trip_spend: { sum: 38_900 } }, monitors: {} } }), must: 'intent_session' });
  await add('session-seq-mismatch', 'intent_session.seq 1 under G_0 (caveat seq 0): intent_session fails.', { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0, is: is0({ seq: 1 }) }), context: ctx({ session: { root: BASE.S, grants: [G0] } }), must: 'intent_session' });
  await add('session-ref-not-statement', 'intent.ref differs from S.intent_ref (the v2 goal does not carry the ref, so rule 12 passes): intent_session fails.', { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0, is: is0(), ref: pca.b64u(seed('v2/x')) }), context: ctx(), must: 'intent_session' });
  await add('session-root-missing', 'The verifier holds no session root: intent_session and accumulators fail.', { grant: G0, pcactn: P0, context: ctx({ session: { grants: [] } }), must: ['intent_session', 'accumulators'] });
  const expired = rootOf({ expires_at: NOW });
  const ge = mint({ seq: 0, map: MAP0, salt: 'salt0', root: expired.R });
  await add('session-root-expired', 'S.expires_at == now: the root has expired; intent_session and accumulators both fail.', { grant: ge, pcactn: build(ge, { salt: 'salt0', map: MAP0, is: is0({ root: expired.R }) }), context: ctx({ session: { root: expired.S, grants: [] } }), must: ['intent_session', 'accumulators'] });
}

// -- rule 13 step 7: session revocation (T22). Only the DEDICATED authority S.revocation.key signs epochs; the evidence
// is the epoch plus its FULL revoked list; a tracked last epoch makes the sequence append-only.
{
  const REV = { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub };
  const R4 = rootOf({ revocation: REV });
  const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R4.R });
  const p = build(g, { salt: 'salt0', map: MAP0, is: is0({ root: R4.R }) });
  const ids = [pca.sessionRevocationId(SESSION), pca.mapRevocationId(MAP0), pca.deltaRevocationId(g.id)];
  const ev = (revoked, issued, signer = revAuth, over = {}) => {
    const set = new pca.RevocationSet(revoked);
    const epoch = pca.signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: pca.sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000, ...over });
    return { epoch, revoked: set.list() };
  };
  const c = (rev, policy, last) => ctx({ ...(policy ? { policy } : {}), session: { root: R4.S, grants: [], ...(rev ? { revocation: rev } : {}), ...(last ? { revocation_last: last } : {}) } });
  const A = 'pca-intent:session:aa', Z = 'pca-intent:session:zz';
  await add('session-revocation-fresh', 'S names a dedicated revocation authority (max 60 s): a 30 s old authority-signed epoch whose full revoked list holds none of the session, map and delta ids.', { grant: g, pcactn: p, context: c(ev([Z], NOW - 30_000)), must: 'allow' });
  await add('session-revocation-empty', 'An authority-signed epoch 0 with the empty list: accepted.', { grant: g, pcactn: p, context: c(ev([], NOW - 1_000)), must: 'allow' });
  await add('session-revocation-absent', 'S names a revocation source but no epoch is supplied: intent_session fails.', { grant: g, pcactn: p, context: c(undefined), must: 'intent_session' });
  await add('session-revocation-stale', 'The epoch is 61 s old (> 60 s): intent_session fails (T22).', { grant: g, pcactn: p, context: c(ev([], NOW - 61_000)), must: 'intent_session' });
  await add('session-revocation-session-revoked', 'The session id is in the revoked list: intent_session fails.', { grant: g, pcactn: p, context: c(ev([ids[0]], NOW - 1_000)), must: 'intent_session' });
  await add('session-revocation-map-revoked', 'The map digest is revoked: intent_session fails.', { grant: g, pcactn: p, context: c(ev([ids[1]], NOW - 1_000)), must: 'intent_session' });
  await add('session-revocation-delta-revoked', 'The admitting grant id is revoked: intent_session fails.', { grant: g, pcactn: p, context: c(ev([ids[2]], NOW - 1_000)), must: 'intent_session' });
  await add('session-revocation-foreign-signer', 'The epoch is signed by a key that is not S.revocation.key: intent_session fails.', { grant: g, pcactn: p, context: c(ev([], NOW - 1_000, stranger)), must: 'intent_session' });
  await add('session-revocation-principal-signer', 'The epoch is signed by a session PRINCIPAL (not the dedicated authority): intent_session fails (a co-principal cannot publish an epoch that drops a revocation).', { grant: g, pcactn: p, context: c(ev([], NOW - 1_000, principal)), must: 'intent_session' });
  // the full list must be exactly the signed set
  const e2 = ev([A, Z], NOW - 1_000);
  await add('session-revocation-list-missing', 'The evidence carries the epoch but no revoked list: intent_session fails.', { grant: g, pcactn: p, context: c({ epoch: e2.epoch }), must: 'intent_session' });
  await add('session-revocation-list-short', 'The revoked list omits one id of the signed set (length != set_size): intent_session fails.', { grant: g, pcactn: p, context: c({ epoch: e2.epoch, revoked: [Z] }), must: 'intent_session' });
  await add('session-revocation-list-swapped', 'A revoked list of the right length whose root is not the signed root: intent_session fails.', { grant: g, pcactn: p, context: c({ epoch: e2.epoch, revoked: [A, 'pca-intent:session:zy'] }), must: 'intent_session' });
  await add('session-revocation-list-unsorted', 'The revoked list is the signed set in descending order: intent_session fails (strict UTF-8 ascending order).', { grant: g, pcactn: p, context: c({ epoch: e2.epoch, revoked: [Z, A] }), must: 'intent_session' });
  await add('session-revocation-list-dup', 'The revoked list repeats an id: intent_session fails.', { grant: g, pcactn: p, context: c({ epoch: e2.epoch, revoked: [A, A] }), must: 'intent_session' });
  await add('session-revocation-list-null', 'revoked is null: intent_session fails.', { grant: g, pcactn: p, context: c({ epoch: e2.epoch, revoked: null }), must: 'intent_session' });
  await add('session-revocation-epoch-not-size', 'An authority-signed epoch numbered 5 over a 2-id set (epoch != set_size): intent_session fails.', { grant: g, pcactn: p, context: c(ev([A, Z], NOW - 1_000, revAuth, { epoch: 5 })), must: 'intent_session' });
  // append-only against the tracked last epoch
  const last = ev([ids[0], Z], NOW - 20_000);
  await add('session-revocation-extends-last', 'The tracked last epoch revokes {aa}; the new epoch revokes {aa, zz}: an extension, accepted.', { grant: g, pcactn: p, context: c(ev([A, Z], NOW - 1_000), undefined, ev([A], NOW - 20_000)), must: 'allow' });
  await add('session-revocation-same-as-last', 'The new epoch is the tracked last epoch re-presented: accepted.', { grant: g, pcactn: p, context: c(ev([A], NOW - 1_000), undefined, ev([A], NOW - 1_000)), must: 'allow' });
  await add('session-revocation-drop', 'DROP ATTEMPT: the tracked last epoch revokes the session; the authority-signed new epoch {aa, zz} (same size) leaves it out: intent_session fails (not append-only; equivocation at epoch 2).', { grant: g, pcactn: p, context: c(ev([A, Z], NOW - 1_000), undefined, last), must: 'intent_session' });
  await add('session-revocation-drop-grow', 'DROP ATTEMPT: the new epoch is LARGER ({aa, ab, zz}, epoch 3) but drops the revoked session id of the last epoch: intent_session fails.', { grant: g, pcactn: p, context: c(ev([A, 'pca-intent:session:ab', Z], NOW - 1_000), undefined, last), must: 'intent_session' });
  await add('session-revocation-rollback', 'ROLLBACK: the tracked last epoch is 2 ({session, zz}); the new epoch is the older epoch 1 ({zz}): intent_session fails.', { grant: g, pcactn: p, context: c(ev([Z], NOW - 1_000), undefined, last), must: 'intent_session' });
  await add('session-revocation-last-null', 'session.revocation_last is null (absent = not tracked): intent_session fails.', { grant: g, pcactn: p, context: ctx({ session: { root: R4.S, grants: [], revocation: ev([], NOW - 1_000), revocation_last: null } }), must: 'intent_session' });
  await add('session-revocation-extra-member', 'The evidence carries an extra member (proofs) beside {epoch, revoked}: the evidence is closed, intent_session fails.', { grant: g, pcactn: p, context: c({ ...ev([], NOW - 1_000), proofs: {} }), must: 'intent_session' });
  await add('session-revocation-last-extra-member', 'The tracked last epoch carries an extra member: malformed tracked state, intent_session fails (fail closed).', { grant: g, pcactn: p, context: c(ev([A], NOW - 1_000), undefined, { ...ev([A], NOW - 2_000), note: 'x' }), must: 'intent_session' });
  await add('session-revocation-last-malformed', 'The tracked last epoch carries a list that is not its signed set: intent_session fails (fail closed).', { grant: g, pcactn: p, context: c(ev([A], NOW - 1_000), undefined, { epoch: ev([A], NOW - 2_000).epoch, revoked: [Z] }), must: 'intent_session' });
  await add('session-revocation-policy-stricter', 'Policy max_revocation_age_s 10 < S max 60: a 20 s old epoch fails (the stricter bound applies).', { grant: g, pcactn: p, context: c(ev([], NOW - 20_000), { session: { max_revocation_age_s: 10 } }), must: 'intent_session' });
  await add('session-revocation-policy-misconfigured', 'Policy max_revocation_age_s -1: the context is malformed, every v2 check fails.', { grant: g, pcactn: p, context: c(ev([], NOW - 1_000), { session: { max_revocation_age_s: -1 } }), must: ['schema', 'intent_session', 'accumulators'] });
  await add('session-revocation-policy-no-authority', 'policy.session.max_revocation_age_s 60 but S names no revocation authority: intent_session fails (an epoch can only be checked against S.revocation.key).', { grant: G0, pcactn: P0, context: ctx({ policy: { session: { max_revocation_age_s: 60 } }, session: { root: BASE.S, grants: [], revocation: ev([], NOW - 1_000) } }), must: 'intent_session' });
  // S.revocation shape: the authority is required and is never a principal
  for (const [n, rv, d] of [['keyless', { epoch_uri: REV.epoch_uri, max_age_s: 60 }, 'S.revocation has no key'], ['principal-key', { ...REV, key: principal.pub }, 'S.revocation.key is a session principal']]) {
    const S = rawRoot(rootBody({ revocation: rv }));
    await add(`session-root-revocation-${n}`, `${d} (signed): the session root is malformed; intent_session and accumulators fail.`, { grant: G0, pcactn: P0, context: ctx({ session: { root: S, grants: [], revocation: ev([], NOW - 1_000) } }), must: ['intent_session', 'accumulators'] });
  }
}

// -- rule 14 failures (only schema fails)
{
  const bad = (params) => build(G0, { salt: 'salt0', map: MAP0, is: is0(), params });
  await add('schema-undeclared-param', 'An undeclared parameter (reseller): ⊠, schema fails (never a question).', { grant: G0, pcactn: bad({ ...PARAMS, reseller: 'x' }), context: ctx({ params: { ...PARAMS, reseller: 'x' } }), must: 'schema' });
  await add('schema-set-out-of-domain', 'add_ons carries an undeclared member: schema fails.', { grant: G0, pcactn: bad({ ...PARAMS, add_ons: ['bag'] }), context: ctx({ params: { ...PARAMS, add_ons: ['bag'] } }), must: 'schema' });
  await add('schema-note-too-long', 'A free string over its declared max_len (16 UTF-8 bytes; 17 here): schema fails.', { grant: G0, pcactn: bad({ ...PARAMS, note: 'é'.repeat(8) + 'a' }), context: ctx({ params: { ...PARAMS, note: 'é'.repeat(8) + 'a' } }), must: 'schema' });
  await add('schema-note-at-max-len', 'A free string of exactly 16 UTF-8 bytes: accepted.', { grant: G0, pcactn: bad({ ...PARAMS, note: 'é'.repeat(8) }), context: ctx({ params: { ...PARAMS, note: 'é'.repeat(8) } }), must: 'allow' });
  await add('schema-params-not-opening-digest', 'The supplied params do not hash to action.params_digest: schema fails (and the accumulator value read from them no longer matches the claim).', { grant: G0, pcactn: P0, context: ctx({ params: { ...PARAMS, total: 1 } }), must: ['schema', 'accumulators'] });
  await add('schema-unknown-digest', 'intent_session.schema names no schema the verifier accepts: schema fails, and accumulators (which selects by accumulates_into in that schema) fails too.', { grant: G0, pcactn: P0, context: ctx({ schema: { docs: [pca.signActionSchema({ ...UNSIGNED, version: 'v2' }, 'skyair-2026', site.sk)], keys: KEYS } }), must: ['schema', 'accumulators'] });
  await add('schema-forged', 'The schema signature does not verify under the discovery key: schema fails.', { grant: G0, pcactn: P0, context: ctx({ schema: { docs: [SCHEMA], keys: [pca.actionSchemaKeyOf('skyair-2026', stranger.sk)] } }), must: 'schema' });
  await add('schema-closed-world-policy', 'No intent_session, policy schema.closed_world: schema runs against the first accepted schema and passes (the v1 intent goal still fails).', { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0 }), context: ctx({ policy: { schema: { closed_world: true } } }), must: 'intent' });
}

// -- rule 15 failures (only accumulators fails)
{
  const run = (name, d, is, c = ctx()) => add(name, d, { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0, is }), context: c, must: 'accumulators' });
  await run('acc-claim-mismatch', 'The claimed post 38899 differs from the verifier post 38900: accumulators fails.', is0({ acc: [{ id: 'trip_spend', post: 38_899 }] }));
  await run('acc-claim-missing', 'The action feeds trip_spend but carries no claim: accumulators fails.', is0({ acc: [] }));
  await run('acc-claim-unknown', 'A claim for an id that S does not declare: accumulators fails.', is0({ acc: [{ id: 'trip_spend', post: 38_900 }, { id: 'nope', post: 0 }] }));
  await run('acc-claim-wallet', 'A claim for the wallet-held question counter: accumulators fails.', is0({ acc: [{ id: 'trip_spend', post: 38_900 }, { id: 'questions', post: 1 }] }));
  await run('acc-no-state', 'The verifier has no pre-state for a site-local accumulator: accumulators fails.', is0(), ctx({ acc: { state: {}, monitors: {} } }));
  await run('acc-bad-state', 'The injected pre-state has the wrong shape ({count} for a sum): accumulators fails.', is0(), ctx({ acc: { state: { trip_spend: { count: 0 } }, monitors: {} } }));
  await run('acc-over-domain', 'post 500100 is above domain_max 500000 (outside Ω̃): accumulators fails.', is0({ acc: [{ id: 'trip_spend', post: 500_100 }] }), ctx({ acc: { state: { trip_spend: { sum: 461_200 } }, monitors: {} } }));
  await add('acc-at-domain-max', 'post exactly domain_max (500000): accepted.', { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0, is: is0({ acc: [{ id: 'trip_spend', post: 500_000 }] }) }), context: ctx({ acc: { state: { trip_spend: { sum: 461_100 } }, monitors: {} } }), must: 'allow' });
  // monitors
  const mon = { id: 'hotel_after_flight', kind: 'requires_prior', p: { verb: 'air.book' }, q: { verb: 'hotel.book' }, status: 'committed' };
  const RM = rootOf({ monitors: [mon] });
  const gm = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RM.R });
  const pm = build(gm, { salt: 'salt0', map: MAP0, is: is0({ root: RM.R }) });
  const cm = (m) => ctx({ session: { root: RM.S, grants: [] }, acc: { state: { trip_spend: { sum: 0 } }, monitors: m } });
  await add('acc-monitor-state', 'A requires_prior monitor with the injected state "unmet" (a state of Q): accepted.', { grant: gm, pcactn: pm, context: cm({ hotel_after_flight: 'unmet' }), must: 'allow' });
  await add('acc-monitor-missing', 'No injected monitor state: accumulators fails.', { grant: gm, pcactn: pm, context: cm({}), must: 'accumulators' });
  await add('acc-monitor-bad-state', 'An injected state outside Q ("maybe"): accumulators fails.', { grant: gm, pcactn: pm, context: cm({ hotel_after_flight: 'maybe' }), must: 'accumulators' });
  // distinct + max + count + keyed
  const DIST = { id: 'payees', agg: 'distinct', val: 'action.params.offer_id', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 3, holder: { kind: 'site_local' } };
  const MAX = { id: 'largest', agg: 'max', val: 'action.params.total', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
  const CNT = { id: 'per_offer', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'sliding', ms: 60_000 }, key: 'action.params.offer_id', domain_max: 1, holder: { kind: 'site_local' } };
  const RX = rootOf({ accumulators: [DIST, MAX, CNT] });
  const gx = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RX.R });
  const px = (acc) => build(gx, { salt: 'salt0', map: MAP0, is: is0({ root: RX.R, acc }) });
  const cx = (state) => ctx({ session: { root: RX.S, grants: [] }, acc: { state, monitors: {} } });
  const goodAcc = [{ id: 'payees', post: 2 }, { id: 'largest', post: 40_000 }, { id: 'per_offer', post: 1 }];
  const st = { payees: { values: ['"OF-1"', '"OF-9"'] }, largest: { max: 40_000 }, per_offer: { count: 0 } };
  await add('acc-distinct-max-count', 'distinct (OF-1 already counted: post 2), max (max(40000, 38900) = 40000), keyed count (0 + 1 = 1 <= domain 1): accepted.', { grant: gx, pcactn: px(goodAcc), context: cx(st), must: 'allow' });
  await add('acc-distinct-new-value', 'distinct with a NEW value: post = |pre| + 1 = 3, but the claim says 2: accumulators fails.', { grant: gx, pcactn: px(goodAcc), context: cx({ ...st, payees: { values: ['"OF-7"', '"OF-9"'] } }), must: 'accumulators' });
  await add('acc-keyed-count-over-domain', 'keyed count: a second action for the same offer in the window (pre 1, post 2 > domain 1): accumulators fails.', { grant: gx, pcactn: px([...goodAcc.slice(0, 2), { id: 'per_offer', post: 2 }]), context: cx({ ...st, per_offer: { count: 1 } }), must: 'accumulators' });
  // sequenced
  const SEQ = { ...TRIP, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: seqRoot.pub } };
  // the sequencer's root-signed key set (version 2): s1 retired at NOW - 1000 (inside the 60 s skew), s2 current
  const KS = pca.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 2, issued_at: NOW - 100, keys: [{ kid: 's1', pk: sequencer.pub, not_before: NOW - 100_000, not_after: NOW - 1_000 }, { kid: 's2', pk: sequencer2.pub, not_before: NOW - 1_000 }] }, seqRoot.sk);
  const RS = rootOf({ accumulators: [SEQ] });
  const gs = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RS.R });
  const draft = build(gs, { salt: 'salt0', map: MAP0 });
  const rcBody = { v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'trip_spend', seq: 3, pre: 10_000, delta: 38_900, post: 48_900, pcactn_digest: pca.pcactnReservationDigest(draft), aud: AUD, issued_at: NOW, expires_at: NOW + 60_000, kid: 's2', ledger: { index: 7, head: pca.b64u(seed('v2/head')) } };
  const rc = pca.signAccReceipt(rcBody, sequencer2.sk);
  const ps = (r, post = 48_900) => build(gs, { salt: 'salt0', map: MAP0, is: is0({ root: RS.R, acc: [{ id: 'trip_spend', post, receipt: pca.accReceiptDigest(r) }] }) });
  const cs = (receipts, last, keys = [KS]) => ctx({ session: { root: RS.S, grants: [] }, acc: { receipts, monitors: {}, sequencer_keys: keys, ...(last !== undefined ? { last_seq: { trip_spend: last } } : {}) } });
  await add('acc-receipt', 'A sequenced accumulator: the receipt is signed by key s2 of the key set the pinned sequencer root signed, valid at issued_at, bound to this action (reservation digest), audience and session; post = receipt.post.', { grant: gs, pcactn: ps(rc), context: cs([rc]), must: 'allow' });
  const old = pca.signAccReceipt({ ...rcBody, kid: 's1', issued_at: NOW - 5_000 }, sequencer.sk);
  await add('acc-receipt-rotated-key-in-window', 'A receipt by s1, issued inside its validity window, s1 retired 1 s ago (within the 60 s skew): accepted (rotation never invalidates the session).', { grant: gs, pcactn: ps(old), context: cs([old]), must: 'allow' });
  const late1 = pca.signAccReceipt({ ...rcBody, kid: 's1' }, sequencer.sk);
  await add('acc-receipt-retired-key', 'A receipt by s1 issued after its not_after: accumulators fails.', { grant: gs, pcactn: ps(late1), context: cs([late1]), must: 'accumulators' });
  await add('acc-receipt-no-keyset', 'No key set presented: accumulators fails.', { grant: gs, pcactn: ps(rc), context: cs([rc], undefined, []), must: 'accumulators' });
  const rogueSet = pca.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 2, issued_at: NOW, keys: [{ kid: 's2', pk: sequencer2.pub, not_before: 0 }] }, stranger.sk);
  await add('acc-receipt-foreign-keyset', 'The key set is not signed by the pinned sequencer root: accumulators fails.', { grant: gs, pcactn: ps(rc), context: cs([rc], undefined, [rogueSet]), must: 'accumulators' });
  const future = pca.signAccReceipt({ ...rcBody, issued_at: NOW + 61_000, expires_at: NOW + 121_000 }, sequencer2.sk);
  await add('acc-receipt-future', 'receipt.issued_at more than 60 s ahead of the verifier clock: accumulators fails.', { grant: gs, pcactn: ps(future), context: cs([future]), must: 'accumulators' });
  await add('acc-receipt-missing', 'The receipt the claim names is not presented: accumulators fails.', { grant: gs, pcactn: ps(rc), context: cs([]), must: 'accumulators' });
  await add('acc-receipt-replay', 'receipt.seq 3 is not above the last accepted seq 3: accumulators fails.', { grant: gs, pcactn: ps(rc), context: cs([rc], 3), must: 'accumulators' });
  const forged = pca.signAccReceipt(rcBody, stranger.sk);
  await add('acc-receipt-foreign-signer', 'The receipt names kid s2 but is signed by another key: accumulators fails.', { grant: gs, pcactn: ps(forged), context: cs([forged]), must: 'accumulators' });
  const bent = pca.signAccReceipt({ ...rcBody, post: 48_901 }, sequencer2.sk);
  await add('acc-receipt-arithmetic', 'receipt pre + delta != post: accumulators fails.', { grant: gs, pcactn: ps(bent, 48_901), context: cs([bent]), must: 'accumulators' });
  const other = pca.signAccReceipt({ ...rcBody, aud: 'hotel.example' }, sequencer2.sk);
  await add('acc-receipt-other-aud', 'The receipt is for another audience: accumulators fails.', { grant: gs, pcactn: ps(other), context: cs([other]), must: 'accumulators' });
  const late = pca.signAccReceipt({ ...rcBody, issued_at: NOW - 1_000, expires_at: NOW - 1 }, sequencer2.sk);
  await add('acc-receipt-expired', 'receipt.expires_at < now (well formed, signed, fresh): accumulators fails, reason "has expired".', { grant: gs, pcactn: ps(late), context: cs([late]), must: 'accumulators', reasonContains: "the reservation receipt for 'trip_spend' has expired" });
  // check order: the signature step (which includes the receipt shape, issued_at <= expires_at) runs before the expiry
  // step. The expired receipt above with issued_at moved past expires_at (malformed, and the signature no longer covers it).
  const inverted = { ...late, issued_at: NOW };
  await add('acc-receipt-expires-before-issue', 'The expired receipt with issued_at moved after expires_at (malformed, signature broken): the signature step refuses it before the expiry step: accumulators fails, reason "not signed by a key".', { grant: gs, pcactn: ps(inverted), context: cs([inverted]), must: 'accumulators', reasonContains: "the reservation receipt for 'trip_spend' is not signed by a key" });
  const ontheside = pca.signAccReceipt({ ...rcBody, pcactn_digest: pca.b64u(seed('v2/other-action')) }, sequencer2.sk);
  await add('acc-receipt-other-action', 'The receipt reserves for another action (pcactn_digest): accumulators fails.', { grant: gs, pcactn: ps(ontheside), context: cs([ontheside]), must: 'accumulators' });
  // freshness (the retired-key, receipt-age and key-set-age bounds)
  const ksAt = (version, issued, keys) => pca.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issued, keys }, seqRoot.sk);
  const KSR = ksAt(3, NOW - 100, [{ kid: 's1', pk: sequencer.pub, not_before: NOW - 3_600_000, not_after: NOW - 120_000 }, { kid: 's2', pk: sequencer2.pub, not_before: NOW - 600_000 }]);
  const leaked = pca.signAccReceipt({ ...rcBody, kid: 's1', issued_at: NOW - 150_000, expires_at: NOW + 60_000 }, sequencer.sk);
  await add('acc-receipt-leaked-retired-key', 'LEAKED RETIRED KEY: s1 was retired 120 s ago (not_after < now - 60 s); a receipt it signs back-dated into its window (issued 150 s ago, unexpired): accumulators fails.', { grant: gs, pcactn: ps(leaked), context: cs([leaked], undefined, [KSR]), must: 'accumulators' });
  const aged = pca.signAccReceipt({ ...rcBody, issued_at: NOW - 30_000, expires_at: NOW + 30_000 }, sequencer2.sk);
  const csp = (r, pol, keys = [KSR], extra = {}) => ctx({ ...(pol !== undefined ? { policy: pol } : {}), session: { root: RS.S, grants: [] }, acc: { receipts: [r], monitors: {}, sequencer_keys: keys, ...extra } });
  await add('acc-receipt-age-at-policy', 'policy.acc.max_receipt_age_s 30 and a receipt issued exactly 30 s ago: accepted (inclusive).', { grant: gs, pcactn: ps(aged), context: csp(aged, { acc: { max_receipt_age_s: 30 } }), must: 'allow' });
  await add('acc-receipt-age-over-policy', 'policy.acc.max_receipt_age_s 29 and a receipt issued 30 s ago: accumulators fails.', { grant: gs, pcactn: ps(aged), context: csp(aged, { acc: { max_receipt_age_s: 29 } }), must: 'accumulators' });
  const KSO = ksAt(3, NOW - 3_600_001, [{ kid: 's2', pk: sequencer2.pub, not_before: NOW - 600_000 }]);
  await add('acc-keyset-too-old', 'The only key set was issued 3600001 ms ago (default max key-set age 3600 s): accumulators fails.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSO]), must: 'accumulators' });
  await add('acc-keyset-age-policy', 'The same key set under policy.acc.max_keyset_age_s 7200: accepted.', { grant: gs, pcactn: ps(rc), context: csp(rc, { acc: { max_keyset_age_s: 7_200 } }, [KSO]), must: 'allow' });
  const KSF = ksAt(3, NOW + 61_000, [{ kid: 's2', pk: sequencer2.pub, not_before: NOW - 600_000 }]);
  await add('acc-keyset-future', 'The only key set is issued 61 s in the future: accumulators fails.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSF]), must: 'accumulators' });
  // tracked state acc.keyset_versions[root] = {version, digest}: rollback and same-version equivocation
  const T3 = { version: 3, digest: pca.sequencerKeySetDigest(KSR) };
  const KSE = ksAt(3, NOW - 200, [{ kid: 's2', pk: sequencer2.pub, not_before: NOW - 600_000 }]); // another version-3 set
  await add('acc-keyset-version-current', 'acc.keyset_versions tracks {version 3, digest of this set} for the sequencer root and this set is presented: accepted.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSR], { keyset_versions: { [seqRoot.pub]: T3 } }), must: 'allow' });
  await add('acc-keyset-version-newer', 'Tracked version 3; a version-4 set is presented (an ordinary rotation): accepted.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [ksAt(4, NOW - 50, [{ kid: 's2', pk: sequencer2.pub, not_before: NOW - 600_000 }])], { keyset_versions: { [seqRoot.pub]: T3 } }), must: 'allow' });
  await add('acc-keyset-version-superseded', 'acc.keyset_versions tracks version 4; the only key set presented is version 3 (older than the newest seen): accumulators fails.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSR], { keyset_versions: { [seqRoot.pub]: { version: 4, digest: T3.digest } } }), must: 'accumulators' });
  await add('acc-keyset-equivocation', 'EQUIVOCATION: the tracked state is {version 3, digest D}; the root presents ANOTHER version-3 set (digest != D) that lists the receipt key: accumulators fails.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSE], { keyset_versions: { [seqRoot.pub]: T3 } }), must: 'accumulators' });
  await add('acc-keyset-equivocation-plus-tracked', 'The equivocating version-3 set AND the tracked one are both presented: the tracked one verifies the receipt, accepted (only the conflicting set is skipped).', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSE, KSR], { keyset_versions: { [seqRoot.pub]: T3 } }), must: 'allow' });
  await add('acc-keyset-version-other-root', 'acc.keyset_versions tracks version 9 for ANOTHER root only: no bound for this holder, accepted.', { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSR], { keyset_versions: { [stranger.pub]: { version: 9, digest: T3.digest } } }), must: 'allow' });
  const ALL = ['schema', 'intent_session', 'accumulators'];
  for (const [n, pol] of [['null', null], ['age-string', { max_receipt_age_s: '30' }], ['age-negative', { max_receipt_age_s: -1 }], ['age-fraction', { max_receipt_age_s: 1.5 }], ['age-null', { max_receipt_age_s: null }], ['keyset-age-string', { max_keyset_age_s: '60' }], ['unknown-member', { max_age_s: 30 }]]) {
    await add(`acc-policy-${n}`, `policy.acc ${JSON.stringify(pol)}: the v2 context is malformed, every v2 check fails.`, { grant: gs, pcactn: ps(rc), context: csp(rc, { acc: pol }), must: ALL });
  }
  for (const [n, kv, d] of [
    ['null', null, 'acc.keyset_versions is null'], ['array', [T3], 'acc.keyset_versions is an array'],
    ['bare-number', { [seqRoot.pub]: 3 }, 'a tracked entry is a bare version number (it is {version, digest})'],
    ['entry-null', { [seqRoot.pub]: null }, 'a tracked entry is null'],
    ['version-string', { [seqRoot.pub]: { ...T3, version: '3' } }, 'a tracked version is the string "3"'],
    ['version-zero', { [seqRoot.pub]: { ...T3, version: 0 } }, 'a tracked version is 0 (versions start at 1)'],
    ['digest-missing', { [seqRoot.pub]: { version: 3 } }, 'a tracked entry has no digest'],
    ['digest-short', { [seqRoot.pub]: { version: 3, digest: 'AAAA' } }, 'a tracked digest is not 32 bytes'],
    ['entry-unknown-member', { [seqRoot.pub]: { ...T3, seen_at: NOW } }, 'a tracked entry has an unknown member'],
  ]) {
    await add(`acc-keyset-versions-${n}`, `${d}: accumulators fails.`, { grant: gs, pcactn: ps(rc), context: csp(rc, undefined, [KSR], { keyset_versions: kv }), must: 'accumulators' });
  }
}

// -- the layers slot (V5): G^org / G^site / G^std as predicate sets
await add('layers-pass', 'A site ceiling over env.canon.add_ons == ["none"] admits the action: layers passes.', { grant: G0, pcactn: P0, context: ctx({ layers: { site: { predicates: [{ verb: 'air.book', where: [{ field: 'env.canon.add_ons', op: 'eq', value: '["none"]' }] }] } } }), must: 'allow' });
await add('layers-org-ceiling', 'An org ceiling total <= 10000: the action is outside it, layers fails (a ceiling is never a question).', { grant: G0, pcactn: P0, context: ctx({ layers: { org: { predicates: [{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: 10_000 }] }] } } }), must: 'layers' });

// -- wire (terminal) and signature
{
  const W = (name, d, is) => add('session-wire-' + name, d + ' The wire check fails (terminal).', { grant: G0, pcactn: resign({ ...clone(P0), intent_session: is }), context: ctx(), must: 'wire' });
  const { schema: _s, ...noSchema } = is0();
  await W('not-object', 'intent_session is an array.', [is0()]);
  await W('unknown-member', 'intent_session carries an unknown member (closed set).', { ...is0(), note: 'x' });
  await W('missing-schema', 'intent_session lacks schema.', noSchema);
  await W('seq-negative', 'seq is -1.', is0({ seq: -1 }));
  await W('seq-over', 'seq is 2^31 (above 2^31-1).', is0({ seq: 2_147_483_648 }));
  await W('root-31-bytes', 'root decodes to 31 bytes.', is0({ root: pca.b64u(seed('v2/r').slice(0, 31)) }));
  await W('acc-dup-id', 'two acc claims share an id.', is0({ acc: [{ id: 'a', post: 1 }, { id: 'a', post: 2 }] }));
  await W('acc-bad-id', 'an acc id outside [A-Za-z0-9_]{1,64}.', is0({ acc: [{ id: 'a-b', post: 1 }] }));
  await W('acc-post-fraction', 'an acc post 1.5.', is0({ acc: [{ id: 'a', post: 1.5 }] }));
  await W('acc-17', 'seventeen acc claims (max 16).', is0({ acc: Array.from({ length: 17 }, (_, i) => ({ id: `a${i}`, post: 0 })) }));
  await W('facts-dup', 'duplicate fact digests.', is0({ facts: [REF, REF] }));
  await W('prov-bad-path', 'a prov key that is not action.params.<name>.', is0({ prov: { 'env.x': ['r'] } }));
  await W('prov-empty-refs', 'a prov entry with no refs.', is0({ prov: { 'action.params.total': [] } }));
  await W('prov-9-refs', 'a prov entry with 9 refs (max 8).', is0({ prov: { 'action.params.total': Array.from({ length: 9 }, (_, i) => `r${i}`) } }));
  await add('session-unsigned-tamper', 'acc claim changed AFTER signing (not re-signed): leaf_signature fails, and the claim no longer equals the verifier post.', { grant: G0, pcactn: { ...clone(P0), intent_session: is0({ acc: [{ id: 'trip_spend', post: 1 }] }) }, context: ctx(), must: ['leaf_signature', 'accumulators'] });
}

// ---- strictness: no coercion, real arrays, own-property keys (rules 13-15 "Strict values") -----------------------
{
  const st = (state, extra = {}) => ctx({ acc: { state, monitors: {}, ...extra } });
  for (const [n, v] of [['null', null], ['string', '0'], ['fraction', 0.5], ['negative', -1]]) {
    await add(`acc-state-sum-${n}`, `The injected pre-state sum is ${JSON.stringify(v)} (not a non-negative safe integer): accumulators fails (no null-as-0, no string arithmetic).`, { grant: G0, pcactn: P0, context: st({ trip_spend: { sum: v } }), must: 'accumulators' });
  }
  await add('acc-last-seq-string', 'acc.last_seq holds the string "3": accumulators fails (every number is a safe integer).', { grant: G0, pcactn: P0, context: st({ trip_spend: { sum: 0 } }, { last_seq: { trip_spend: '3' } }), must: 'accumulators' });
  await add('session-policy-age-string', 'Policy max_revocation_age_s is the string "60": the context is malformed, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ policy: { session: { max_revocation_age_s: '60' } } }), must: ['schema', 'intent_session', 'accumulators'] });
  // lists
  await add('schema-docs-string', 'The accepted schemas are a string, not an array: schema fails (a string is never iterated); accumulators cannot read the schema either.', { grant: G0, pcactn: P0, context: ctx({ schema: { docs: 'x', keys: KEYS } }), must: ['schema', 'accumulators'] });
  await add('schema-keys-object', 'The schema keys are an object {"0": key}, not an array: schema fails; accumulators refuses the malformed schema context too.', { grant: G0, pcactn: P0, context: ctx({ schema: { docs: [SCHEMA], keys: { 0: KEYS[0] } } }), must: ['schema', 'accumulators'] });
  await add('session-grants-string', 'The held session grants are a string: intent_session fails.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: 'G0' } }), must: 'intent_session' });
  await add('acc-receipts-string', 'acc.receipts is a string: accumulators fails.', { grant: G0, pcactn: P0, context: st({ trip_spend: { sum: 0 } }, { receipts: 'r' }), must: 'accumulators' });
  await add('acc-sequencer-keys-object', 'acc.sequencer_keys is an object: accumulators fails.', { grant: G0, pcactn: P0, context: st({ trip_spend: { sum: 0 } }, { sequencer_keys: {} }), must: 'accumulators' });
  await add('acc-state-array', 'acc.state is an array: accumulators fails.', { grant: G0, pcactn: P0, context: st([]), must: 'accumulators' });
  // own-property keys
  const TS = { ...TRIP, id: 'toString' };
  const RT = rootOf({ accumulators: [TS] });
  const gt = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RT.R });
  const pt = build(gt, { salt: 'salt0', map: MAP0, is: is0({ root: RT.R, acc: [{ id: 'toString', post: 38_900 }] }) });
  await add('acc-inherited-name', 'An accumulator named "toString" with no injected state: accumulators fails (an inherited member is never read as state).', { grant: gt, pcactn: pt, context: ctx({ session: { root: RT.S, grants: [] }, acc: { state: {}, monitors: {}, last_seq: {} } }), must: 'accumulators' });
  await add('acc-own-name', 'The same accumulator "toString" with its own state {sum: 0}: accepted.', { grant: gt, pcactn: pt, context: ctx({ session: { root: RT.S, grants: [] }, acc: { state: { toString: { sum: 0 } }, monitors: {} } }), must: 'allow' });
  await add('acc-state-own-proto-key', 'acc.state has an own "__proto__" key and no trip_spend: accumulators fails (the key is data, never the prototype).', { grant: G0, pcactn: P0, context: st(JSON.parse('{"__proto__": {"sum": 0}}')), must: 'accumulators' });
  const protoParams = JSON.parse('{"__proto__": 1, "offer_id": "OF-1", "total": 38900, "add_ons": ["none"], "refundable": false}');
  await add('schema-param-own-proto', 'The params carry an own "__proto__" key: an undeclared parameter, schema fails (⊠).', { grant: G0, pcactn: build(G0, { salt: 'salt0', map: MAP0, is: is0(), params: protoParams }), context: ctx({ params: protoParams }), must: 'schema' });
}

// ---- null vs absent (README "Absent vs null"): absent = empty / default, null = malformed (fail closed) -----------
{
  const ALL = ['schema', 'intent_session', 'accumulators'];
  await add('ctx-policy-null', 'context.intent_v2.policy is null (absent would mean no policy): the context is malformed, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ policy: null }), must: ALL });
  await add('ctx-policy-session-null', 'policy.session is null: malformed context, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ policy: { session: null } }), must: ALL });
  // boolean policy flags: absent = default (false); present must be a JSON boolean
  const V1P = build(G0, { salt: 'salt0', map: MAP0 }); // no intent_session: only an active policy reports v2 checks
  for (const [n, pol] of [
    ['require-null', { session: { require: null } }], ['require-string', { session: { require: 'true' } }], ['require-number', { session: { require: 1 } }],
    ['closed-world-null', { schema: { closed_world: null } }], ['closed-world-string', { schema: { closed_world: 'false' } }],
    ['age-null', { session: { max_revocation_age_s: null } }], ['session-unknown-member', { session: { required: true } }], ['unknown-member', { schemas: {} }],
  ]) {
    await add(`ctx-policy-${n}`, `policy ${JSON.stringify(pol)} on a PCActn without intent_session: malformed policy, schema and intent_session are reported and fail (intent fails too: v1 goal under a v2 grant).`, { grant: G0, pcactn: V1P, context: ctx({ policy: pol }), must: ['intent', 'schema', 'intent_session'] });
  }
  await add('ctx-policy-flags-false', 'policy {session: {require: false}, schema: {closed_world: false}} (explicit booleans, inactive) on a PCActn without intent_session: no v2 check is reported (only the v1 intent check fails).', { grant: G0, pcactn: V1P, context: ctx({ policy: { session: { require: false }, schema: { closed_world: false } } }), must: 'intent' });
  await add('ctx-layers-null', 'layers is null (absent = no layers check): malformed context, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ layers: null }), must: ALL });
  await add('ctx-layers-site-null', 'layers.site is null (absent = no site ceiling): malformed context, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ layers: { site: null } }), must: ALL });
  await add('ctx-layers-site-absent', 'layers is {} (every ceiling absent): layers passes.', { grant: G0, pcactn: P0, context: ctx({ layers: {} }), must: 'allow' });
  await add('ctx-wb-artifacts-facts-null', 'wb.artifacts.facts is null: malformed context, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ wb: { artifacts: { facts: null } } }), must: ALL });
  await add('ctx-wb-artifacts-facts-absent', 'wb.artifacts is {} (facts absent): no W-B check is active, accepted.', { grant: G0, pcactn: P0, context: ctx({ wb: { artifacts: {} } }), must: 'allow' });
  await add('ctx-session-grants-null', 'session.grants is null (absent = no held grants): intent_session fails.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: null } }), must: 'intent_session' });
  await add('ctx-session-grants-absent', 'session.grants absent at seq 0: accepted.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S } }), must: 'allow' });
  await add('ctx-session-revocation-null', 'session.revocation is null: intent_session fails.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: [], revocation: null } }), must: 'intent_session' });
  await add('ctx-session-pq-pins-null', 'session.pq_pins is null (absent = no pins): intent_session fails.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: [], pq_pins: null } }), must: 'intent_session' });
  await add('ctx-session-pq-pins-array', 'session.pq_pins is an array: intent_session fails.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: [], pq_pins: [] } }), must: 'intent_session' });
  await add('ctx-session-pq-pins-non-string', 'session.pq_pins maps a key to a number: intent_session fails.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: [], pq_pins: { [principal.pub]: 1 } } }), must: 'intent_session' });
  await add('ctx-session-pq-pins-empty', 'session.pq_pins is {} (an Ed25519 root needs no pin): accepted.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: [], pq_pins: {} } }), must: 'allow' });
  await add('ctx-acc-receipts-null', 'acc.receipts is null (absent = none presented): accumulators fails.', { grant: G0, pcactn: P0, context: ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: {}, receipts: null } }), must: 'accumulators' });
  await add('ctx-acc-monitors-null', 'acc.monitors is null: accumulators fails.', { grant: G0, pcactn: P0, context: ctx({ acc: { state: { trip_spend: { sum: 0 } }, monitors: null } }), must: 'accumulators' });
  await add('ctx-acc-monitors-absent', 'acc.monitors absent and S declares no monitor: accepted.', { grant: G0, pcactn: P0, context: ctx({ acc: { state: { trip_spend: { sum: 0 } } } }), must: 'allow' });
  await add('ctx-params-null', 'params is null: malformed context, every v2 check fails.', { grant: G0, pcactn: P0, context: ctx({ params: null }), must: ALL });
  // artifacts
  await add('session-root-layers-org-null', 'S.layers.org is null (absent = no org layer): the session root is malformed; intent_session and accumulators fail.', { grant: G0, pcactn: P0, context: ctx({ session: { root: { ...BASE.S, layers: { ...BASE.S.layers, org: null } }, grants: [] } }), must: ['intent_session', 'accumulators'] });
  await add('session-root-revocation-null', 'S.revocation is null (absent = no revocation source): the session root is malformed.', { grant: G0, pcactn: P0, context: ctx({ session: { root: { ...BASE.S, revocation: null }, grants: [] } }), must: ['intent_session', 'accumulators'] });
  await add('session-wire-facts-null', 'intent_session.facts is null (absent = no facts committed): the wire check fails (terminal).', { grant: G0, pcactn: resign({ ...clone(P0), intent_session: { ...is0(), facts: null } }), context: ctx(), must: 'wire' });
  await add('session-wire-acc-null', 'intent_session.acc is null: the wire check fails (terminal).', { grant: G0, pcactn: resign({ ...clone(P0), intent_session: { ...is0(), acc: null } }), context: ctx(), must: 'wire' });
  const nullDefault = clone(SCHEMA); // a deep copy: never mutate the shared fixture
  nullDefault.verbs[0].params['action.params.add_ons'].default = null;
  await add('schema-param-default-null', 'A schema parameter default of null (absent = no default): the schema is malformed; schema and accumulators fail.', { grant: G0, pcactn: P0, context: ctx({ schema: { docs: [nullDefault], keys: KEYS } }), must: ['schema', 'accumulators'] });
}

// ---- suite capability (README "Suite capability"): vectors carry the suite they need -----------------------------
{
  const ml65 = pca.mlDsa65Keygen(seed('v2/ml65'));
  const ml87 = pca.mlDsa87Keygen(seed('v2/ml87'));
  const pq65 = pca.encodeMlDsaPublicKey(ml65.publicKey);
  const pq87 = pca.encodeMlDsa87PublicKey(ml87.publicKey);
  const signedRoot = (alg, mat, pq) => {
    const S = pca.signSessionRoot(rootBody({ principals: [{ key: principal.pub, alg, pq_pk: pq }] }), principal.sk, { alg, ...mat });
    return { S, R: pca.sessionRootDigest(S) };
  };
  // every registered suite (the LESS suites need the optional pca-less-wasm backend and are left to the suite corpus)
  // n-byte seeds (SLH-DSA-128f: 48, SLH-DSA-256s: 96)
  const seedN = (l, n) => new Uint8Array(Array.from({ length: Math.ceil(n / 32) }, (_, i) => [...seed(`${l}/${i}`)]).flat().slice(0, n));
  const fn512 = pca.fnDsa512Keygen(seed('v2/fn512'));
  const fn1024 = pca.fnDsa1024Keygen(seed('v2/fn1024'));
  const MATERIAL = {
    mlDsa: ml65, mlDsa87: ml87, slhDsa: pca.slhDsa128fKeygen(seedN('v2/slh128f', 48)), slhDsa256s: pca.slhDsa256sKeygen(seedN('v2/slh256s', 96)),
    fnDsa512: { ...fn512, signSeed: seed('v2/fn512-sign') }, fnDsa1024: { ...fn1024, signSeed: seed('v2/fn1024-sign') },
  };
  const SUITES = Object.keys(pca.SIG_SUITES).filter((a) => a !== 'ed25519' && !a.includes('less')).sort();
  console.log(`suites: ${SUITES.join(' ')}`);
  // R3-01: a PQ / hybrid session root verifies only under the VERIFIER's pin for its signer (context session.pq_pins),
  // never under the root's own principals[].pq_pk (part of the presented artifact)
  for (const [alg, mat, pq] of SUITES.map((a) => [a, MATERIAL, pca.suitePqPublicKey(a, MATERIAL)])) {
    const { S, R } = signedRoot(alg, mat, pq);
    const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R });
    await add(`session-root-${alg}`, `The session root is signed with ${alg} and the verifier pins the signer's PQ key (session.pq_pins): accepted where the suite is implemented, else intent_session and accumulators fail with unsupported_suite.`, { grant: g, pcactn: build(g, { salt: 'salt0', map: MAP0, is: is0({ root: R }) }), context: ctx({ session: { root: S, grants: [], pq_pins: { [principal.pub]: pq } } }), must: 'allow', requiresSuite: alg });
  }
  {
    const PIN_REASON = "needs the signer's PQ key pinned by the verifier";
    const other65 = pca.encodeMlDsaPublicKey(pca.mlDsa65Keygen(seed('v2/ml65-other')).publicKey);
    for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']) {
      const { S, R } = signedRoot(alg, MATERIAL, pq65);
      const g = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R });
      const p = build(g, { salt: 'salt0', map: MAP0, is: is0({ root: R }) });
      const both = ['intent_session', 'accumulators'];
      await add(`session-root-${alg}-unpinned`, `The ${alg} session root names its PQ key only in its own principals entry and the verifier pins none (session.pq_pins absent): intent_session and accumulators fail (a root's own principals list proves nothing about who signed it).`, { grant: g, pcactn: p, context: ctx({ session: { root: S, grants: [] } }), must: both, requiresSuite: alg, reasonContains: PIN_REASON });
      await add(`session-root-${alg}-pin-other-signer`, `The verifier pins a PQ key for another key only, not for the ${alg} root's signer: intent_session and accumulators fail.`, { grant: g, pcactn: p, context: ctx({ session: { root: S, grants: [], pq_pins: { [revAuth.pub]: pq65 } } }), must: both, requiresSuite: alg, reasonContains: PIN_REASON });
      await add(`session-root-${alg}-pin-mismatch`, `The verifier pins a different PQ key for the ${alg} root's signer than the root carries: intent_session and accumulators fail.`, { grant: g, pcactn: p, context: ctx({ session: { root: S, grants: [], pq_pins: { [principal.pub]: other65 } } }), must: both, requiresSuite: alg, reasonContains: "does not match the verifier's pin" });
    }
    // the signer's own principals entry declares one PQ key while the root is signed (and pinned) under another
    const Sx = pca.signSessionRoot(rootBody({ principals: [{ key: principal.pub, alg: 'ml-dsa-65', pq_pk: other65 }] }), principal.sk, { alg: 'ml-dsa-65', ...MATERIAL });
    const Rx = pca.sessionRootDigest(Sx);
    const gx = mint({ seq: 0, map: MAP0, salt: 'salt0', root: Rx });
    await add('session-root-ml-dsa-65-principal-entry-mismatch', "The ml-dsa-65 root is signed under the verifier-pinned key, but the signer's own principals entry declares another PQ key: intent_session and accumulators fail.", { grant: gx, pcactn: build(gx, { salt: 'salt0', map: MAP0, is: is0({ root: Rx }) }), context: ctx({ session: { root: Sx, grants: [], pq_pins: { [principal.pub]: pq65 } } }), must: ['intent_session', 'accumulators'], requiresSuite: 'ml-dsa-65', reasonContains: "does not match the signer's principals entry" });
    // an Ed25519 root ignores pq_pins entirely (even one naming its signer with an unrelated key)
    await add('session-root-ed25519-pq-pins-ignored', 'An Ed25519 session root with session.pq_pins naming its signer: the pins are not consulted, accepted.', { grant: G0, pcactn: P0, context: ctx({ session: { root: BASE.S, grants: [], pq_pins: { [principal.pub]: other65 } } }), must: 'allow' });
  }
  {
    const S = { ...BASE.S, alg: 'x-unknown-suite' };
    await add('session-root-unknown-suite', 'The session root names an alg no verifier implements: intent_session and accumulators fail with unsupported_suite.', { grant: G0, pcactn: P0, context: ctx({ session: { root: S, grants: [] } }), must: ['intent_session', 'accumulators'], unsupported: true });
  }
  // a PQ revocation epoch: verifies only under the PQ key S pins for its authority (S.revocation.pq_pk)
  const R6 = rootOf({ revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub, pq_pk: pq65 } });
  const g6 = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R6.R });
  const p6 = build(g6, { salt: 'salt0', map: MAP0, is: is0({ root: R6.R }) });
  const set6 = new pca.RevocationSet([]);
  const ep6 = pca.signRevocationEpoch(revAuth.sk, { instance_id: 'ana', grant_ref: pca.sessionRevocationScope(SESSION), epoch: 0, set_size: 0, root: set6.root, issued_at: NOW - 1_000, not_after: NOW + 300_000 }, { alg: 'ml-dsa-65', mlDsa: ml65 });
  await add('session-revocation-ml-dsa-65-pinned', 'An ML-DSA-65 revocation epoch by the authority whose ML-DSA key S pins (S.revocation.pq_pk): accepted where ml-dsa-65 is implemented.', { grant: g6, pcactn: p6, context: ctx({ session: { root: R6.S, grants: [], revocation: { epoch: ep6, revoked: [] } } }), must: 'allow', requiresSuite: 'ml-dsa-65' });
  const R7 = rootOf({ revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub } });
  const g7 = mint({ seq: 0, map: MAP0, salt: 'salt0', root: R7.R });
  await add('session-revocation-ml-dsa-65-unpinned', 'The same ML-DSA-65 epoch, but S pins no PQ key for its authority: intent_session fails (an unpinned PQ epoch never verifies).', { grant: g7, pcactn: build(g7, { salt: 'salt0', map: MAP0, is: is0({ root: R7.R }) }), context: ctx({ session: { root: R7.S, grants: [], revocation: { epoch: ep6, revoked: [] } } }), must: 'intent_session', requiresSuite: 'ml-dsa-65' });
  // a receipt signed with ML-DSA-65 under a key set entry that pins it
  const SEQ = { ...TRIP, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: seqRoot.pub } };
  const RS = rootOf({ accumulators: [SEQ] });
  const gs = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RS.R });
  const draft = build(gs, { salt: 'salt0', map: MAP0 });
  const KS = pca.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: NOW - 100, keys: [{ kid: 'pq1', pk: sequencer.pub, alg: 'ml-dsa-65', pq_pk: pq65, not_before: NOW - 10_000 }] }, seqRoot.sk);
  const rc = pca.signAccReceipt({ v: 1, kind: 'pca-acc-receipt', session: SESSION, acc: 'trip_spend', seq: 1, pre: 0, delta: 38_900, post: 38_900, pcactn_digest: pca.pcactnReservationDigest(draft), aud: AUD, issued_at: NOW, expires_at: NOW + 60_000, kid: 'pq1', ledger: { index: 0, head: pca.b64u(seed('v2/head')) } }, sequencer.sk, { alg: 'ml-dsa-65', mlDsa: ml65 });
  await add('acc-receipt-ml-dsa-65', 'A receipt signed with ML-DSA-65 by a key set entry that pins the ML-DSA key: accepted where ml-dsa-65 is implemented.', { grant: gs, pcactn: build(gs, { salt: 'salt0', map: MAP0, is: is0({ root: RS.R, acc: [{ id: 'trip_spend', post: 38_900, receipt: pca.accReceiptDigest(rc) }] }) }), context: ctx({ session: { root: RS.S, grants: [] }, acc: { receipts: [rc], monitors: {}, sequencer_keys: [KS] } }), must: 'allow', requiresSuite: 'ml-dsa-65' });
  // an action schema signed with ML-DSA-65
  const schemaPq = pca.signActionSchema(UNSIGNED, 'pq-1', site.sk, { alg: 'ml-dsa-65', mlDsa: ml65 });
  const keyPq = pca.actionSchemaKeyOf('pq-1', site.sk, { alg: 'ml-dsa-65', mlDsa: ml65 });
  const RQ = rootOf({ schema: { aud: AUD, digest: pca.actionSchemaDigest(schemaPq) } });
  const gq = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RQ.R });
  await add('schema-ml-dsa-65', 'The site schema is signed with ML-DSA-65 under a discovery key entry of that suite: accepted where ml-dsa-65 is implemented.', { grant: gq, pcactn: build(gq, { salt: 'salt0', map: MAP0, is: is0({ root: RQ.R, schema: pca.actionSchemaDigest(schemaPq) }) }), context: ctx({ schema: { docs: [schemaPq], keys: [keyPq] }, session: { root: RQ.S, grants: [] } }), must: 'allow', requiresSuite: 'ml-dsa-65' });
  const badSchema = { ...SCHEMA, sig: { ...SCHEMA.sig, alg: 'x-unknown-suite' } };
  const RU = rootOf({ schema: { aud: AUD, digest: pca.actionSchemaDigest(badSchema) } });
  const gu = mint({ seq: 0, map: MAP0, salt: 'salt0', root: RU.R });
  await add('schema-unknown-suite', 'The schema the session names carries a signature alg no verifier implements: schema fails with unsupported_suite.', { grant: gu, pcactn: build(gu, { salt: 'salt0', map: MAP0, is: is0({ root: RU.R, schema: pca.actionSchemaDigest(badSchema) }) }), context: ctx({ schema: { docs: [badSchema], keys: KEYS }, session: { root: RU.S, grants: [] } }), must: 'schema', unsupported: true });
}

// ---- primitives.intent_schema (rule 14 alone) ---------------------------------------------------------------------
const schemaPrims = [];
function addSchema(name, description, input) {
  const v = pca.verifyActionSchema(input.schema, input.keys);
  const c = pca.conformAction(input.schema, input.verb, input.params);
  schemaPrims.push({ name: 'schema14-' + name, description, input: clone(input), expect: { sig: v.ok, ...(v.ok ? { digest: pca.actionSchemaDigest(input.schema) } : {}), conform: c.ok ? { ok: true } : { ok: false, code: c.code, ...(c.path ? { path: c.path } : {}) } } });
}
const base = { schema: SCHEMA, keys: KEYS, verb: 'air.book', params: PARAMS };
addSchema('ok', 'A conforming action under a valid schema.', base);
addSchema('unknown-verb', 'A verb the schema does not declare.', { ...base, verb: 'air.cancel' });
addSchema('params-array', 'params is an array.', { ...base, params: [] });
addSchema('undeclared-order', 'Two undeclared keys: the FIRST in UTF-8 byte order is reported (aa before zz).', { ...base, params: { ...PARAMS, zz: 1, aa: 1 } });
addSchema('undeclared-before-missing', 'An undeclared key and a missing required one: undeclared wins (step 3 before 4).', { ...base, params: { offer_id: 'x', extra: 1 } });
addSchema('missing-order', 'Several required parameters missing: the first declared path in byte order (add_ons).', { ...base, params: {} });
addSchema('int-string', 'An integer given as a string.', { ...base, params: { ...PARAMS, total: '38900' } });
addSchema('int-fraction', 'An integer given as 1.5.', { ...base, params: { ...PARAMS, total: 1.5 } });
addSchema('int-neg-zero', 'An integer given as -0 (not a safe integer under the strict profile).', { ...base, params: { ...PARAMS, total: -0 } });
addSchema('int-below-min', 'total -1 < min 0.', { ...base, params: { ...PARAMS, total: -1 } });
addSchema('int-at-max', 'total == max 5000000.', { ...base, params: { ...PARAMS, total: 5_000_000 } });
addSchema('int-above-max', 'total == max + 1.', { ...base, params: { ...PARAMS, total: 5_000_001 } });
addSchema('bool-string', 'refundable "false" (a string).', { ...base, params: { ...PARAMS, refundable: 'false' } });
addSchema('set-dup', 'add_ons with a repeated member.', { ...base, params: { ...PARAMS, add_ons: ['none', 'none'] } });
addSchema('set-empty', 'add_ons empty (min_items default 0): accepted.', { ...base, params: { ...PARAMS, add_ons: [] } });
addSchema('set-non-string', 'add_ons with a number.', { ...base, params: { ...PARAMS, add_ons: [1] } });
addSchema('array-10', 'passengers with 10 items (max_items 9).', { ...base, params: { ...PARAMS, passengers: Array.from({ length: 10 }, (_, i) => `p${i}`) } });
addSchema('array-item-long', 'a passenger ref over max_len 64 bytes.', { ...base, params: { ...PARAMS, passengers: ['x'.repeat(65)] } });
addSchema('string-enum', 'from not in its declared values.', { ...base, verb: 'air.search', params: { from: 'LAX', date: '2026-11-20', pax: 2 } });
addSchema('date-leap-ok', '2028-02-29 is a calendar date.', { ...base, verb: 'air.search', params: { from: 'SFO', date: '2028-02-29', pax: 2 } });
addSchema('date-leap-bad', '2026-02-29 is not a calendar date.', { ...base, verb: 'air.search', params: { from: 'SFO', date: '2026-02-29', pax: 2 } });
addSchema('date-1900', '1900-02-29 is not a calendar date (century rule).', { ...base, verb: 'air.search', params: { from: 'SFO', date: '1900-02-29', pax: 2 } });
addSchema('date-2000', '2000-02-29 is a calendar date (400-year rule).', { ...base, verb: 'air.search', params: { from: 'SFO', date: '2000-02-29', pax: 2 } });
addSchema('date-format', '2026-1-05 is not YYYY-MM-DD.', { ...base, verb: 'air.search', params: { from: 'SFO', date: '2026-1-05', pax: 2 } });
addSchema('forged', 'Signed by another key than the discovery entry: sig false (conform is still reported).', { ...base, keys: [pca.actionSchemaKeyOf('skyair-2026', stranger.sk)] });
addSchema('kid-unknown', 'sig.kid names no discovery key: sig false.', { ...base, keys: [{ ...KEYS[0], kid: 'other' }] });
addSchema('alg-mismatch', 'sig.alg differs from the pinned key suite: sig false.', { ...base, schema: { ...SCHEMA, sig: { ...SCHEMA.sig, alg: 'ml-dsa-65' } } });
addSchema('tampered', 'A member changed after signing: sig false.', { ...base, schema: { ...SCHEMA, version: 'x' } });
addSchema('unknown-member', 'An unknown top-level member: sig false (shape).', { ...base, schema: { ...SCHEMA, extra: 1 } });

// ---- primitives.intent_revocation (rule 13 step 7 alone) --------------------------------------------------------
const revPrims = [];
{
  const ID = pca.sessionRevocationId(SESSION);
  const make = (revoked, issued, signer = revAuth, scope = pca.sessionRevocationScope(SESSION), over = {}) => {
    const set = new pca.RevocationSet(revoked);
    return { epoch: pca.signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: scope, epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000, ...over }), revoked: set.list() };
  };
  const DEF = ['pca-intent:map:a', 'pca-intent:session:zzzz'];
  const addRev = (name, description, { revoked = DEF, issued = NOW - 10_000, signer = revAuth, scope, ids = [ID], maxAge = 60_000, list, last, over, extra }) => {
    const e = make(revoked, issued, signer, scope, over);
    // the evidence = the input minus the check parameters (session, scope, authority, ids, now, max_age_ms, last)
    const evidence = { epoch: e.epoch, revoked: list !== undefined ? list : e.revoked, ...(extra ?? {}) };
    const input = { ...evidence, session: SESSION, authority: revAuth.pub, ids, now: NOW, max_age_ms: maxAge, ...(last ? { last } : {}) };
    const r = pca.checkSessionRevocation(evidence, { session: SESSION, authority: revAuth.pub, ids, now: NOW, maxAgeMs: maxAge, ...(last ? { last } : {}) });
    revPrims.push({ name: 'rev13-' + name, description, input: clone(input), expect: { ok: r.ok } });
  };
  addRev('ok', 'A fresh epoch (10 s) by the authority, the id not in its full list: ok.', {});
  addRev('ok-empty-set', 'An empty revocation set (epoch 0): ok.', { revoked: [] });
  addRev('ok-at-max-age', 'issued exactly max_age_ms ago: ok (inclusive).', { issued: NOW - 60_000 });
  addRev('stale', 'issued max_age_ms + 1 ago: refused.', { issued: NOW - 60_001 });
  addRev('revoked', 'The id is in the list: refused.', { revoked: [ID] });
  addRev('foreign-signer', 'The epoch signer is not the authority: refused.', { signer: stranger });
  addRev('principal-signer', 'The epoch is signed by a session principal, not the authority: refused.', { signer: principal });
  addRev('other-scope', 'grant_ref is another session scope: refused.', { scope: pca.sessionRevocationScope(pca.b64u(seed('v2/s2'))) });
  addRev('max-age-negative', 'max_age_ms -1: misconfigured, refused.', { maxAge: -1 });
  addRev('future', 'issued 61 s in the future (beyond the 60 s skew): refused.', { issued: NOW + 61_000 });
  addRev('list-short', 'The list omits one signed id: refused.', { list: ['pca-intent:map:a'] });
  addRev('list-swapped', 'A list of the right size that is not the signed set: refused.', { list: ['pca-intent:map:a', 'pca-intent:session:zzzy'] });
  addRev('list-unsorted', 'The signed set in descending order: refused.', { list: [...DEF].reverse() });
  addRev('list-not-array', 'The list is an object: refused.', { list: { 0: DEF[0], 1: DEF[1] } });
  addRev('evidence-extra-member', 'The evidence carries a member beside {epoch, revoked} (input member proofs): refused (closed).', { extra: { proofs: {} } });
  addRev('epoch-not-size', 'Epoch number 7 over a 2-id set: refused.', { over: { epoch: 7 } });
  const L1 = make(['pca-intent:map:a'], NOW - 30_000);
  const L2 = make([ID, 'pca-intent:session:zzzz'], NOW - 30_000);
  addRev('append-extends', 'The tracked last epoch {map:a}; the new epoch {map:a, session:zzzz}: ok.', { last: L1 });
  addRev('append-same', 'The new epoch equals the tracked last epoch: ok.', { revoked: ['pca-intent:map:a'], last: L1 });
  addRev('append-drop', 'DROP: the tracked last epoch revokes the id; the new authority-signed epoch (same size) does not: refused.', { last: L2 });
  addRev('append-drop-grow', 'DROP: a larger new epoch that still drops the id revoked in the last epoch: refused.', { revoked: ['pca-intent:map:a', 'pca-intent:map:b', 'pca-intent:session:zzzz'], last: L2 });
  addRev('append-rollback', 'ROLLBACK: the new epoch 1 is older than the tracked epoch 2: refused.', { revoked: ['pca-intent:session:zzzz'], last: L2 });
  addRev('append-last-malformed', 'The tracked last epoch carries a list that is not its signed set: refused (fail closed).', { last: { epoch: L1.epoch, revoked: ['pca-intent:map:z'] } });
}

// -- rule 19 (V15): a committed map, the v2c goal and the Z0 `map` check
{
  const dims = [
    { kind: 'num', path: 'action.params.total', lo: 0, hi: 5_000_000, cuts: [40_000] },
    { kind: 'cat', path: 'action.resource', values: [{ kind: 'exact', value: 'skyair.example/bookings' }, { kind: 'other', value: '⊥' }] },
  ];
  const METRICS = { residual_risk_ppm: 2_000, burden_ppm: 1, uncertainty_ppm: 1, disagreement_ppm: 0, mean_harm_ppm: 5, fidelity_est_ppm: 980_000, entropy_mbits: 8, questions: 1, conflicts: 0 };
  const committed = (label, granted) => pca.commitMap({
    headers: [{ verb: 'air.book', dims }],
    // flat = total cell * 2 + resource cell; total cell 0 is [0, 39999]
    cells: { 'air.book': Array.from({ length: 6 }, (_, f) => ({ cell: [Math.floor(f / 2), f % 2], p_ppm: granted(f) ? 990_000 : 10_000, in_grant: granted(f) })) },
    metrics: METRICS,
    learner_digest: pca.b64u(seed('v2/map-learner')),
  }, seed(`v2/map-secret-${label}`));
  const scenario = (cm, { form = 'commit', mintForm = 'commit' } = {}) => {
    // null = omit (undefined would take the default)
    const R = rootOf({ layers: { task: { map_digest: cm.map_commit } } });
    const g = pca.mintSessionGrant({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, session: SESSION, seq: 0, root: R.R, mapDigest: cm.map_commit, ...(mintForm ? { mapForm: mintForm } : {}), predicates: cap(null, 40_000), salt: 'saltc' }).grant;
    const p = build(g, { salt: 'saltc', map: cm.map_commit, is: is0({ root: R.R, ...(form ? { map_form: form } : {}) }) });
    const c = (over = {}) => ctx({ session: { root: R.S, grants: [] }, map: { disclosure: cm.disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, PARAMS) }, ...over });
    return { g, p, c };
  };
  const CMa = committed('a', (f) => f === 0);
  const A = scenario(CMa);
  await add('map-commit-ok', 'A committed map (intent_session.map_form "commit", goal pca-intent:v2c:<session>:<map_commit>): the Z0 disclosure opens the commitment and the action cell is in the grant: map passes.', { grant: A.g, pcactn: A.p, context: A.c(), must: 'allow' });
  await add('map-commit-eps-ok', 'policy.map.max_residual_risk_ppm 2000 equals the committed residual risk: map passes.', { grant: A.g, pcactn: A.p, context: A.c({ policy: { map: { max_residual_risk_ppm: 2_000 } } }), must: 'allow' });
  await add('map-commit-eps-breach', 'ε = 1999 < the committed residual risk 2000: map fails.', { grant: A.g, pcactn: A.p, context: A.c({ policy: { map: { max_residual_risk_ppm: 1_999 } } }), must: 'map' });
  await add('map-commit-no-disclosure', 'A committed map but no disclosure presented: map fails.', { grant: A.g, pcactn: A.p, context: A.c({ map: {} }), must: 'map' });
  {
    const other = committed('a', (f) => f === 0).disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, { ...PARAMS, total: 50_000 });
    await add('map-commit-wrong-cell', "A disclosure of another cell of the same commitment: map fails (not the action's cell).", { grant: A.g, pcactn: A.p, context: A.c({ map: { disclosure: other } }), must: 'map' });
    const foreign = committed('b', (f) => f === 0).disclose({ verb: 'air.book', resource: 'skyair.example/bookings' }, PARAMS);
    await add('map-commit-foreign', 'The same map committed under another session secret: the disclosure does not open this commitment: map fails.', { grant: A.g, pcactn: A.p, context: A.c({ map: { disclosure: foreign } }), must: 'map' });
  }
  const B = scenario(committed('c', () => false));
  await add('map-commit-outside-grant', "The action's committed cell has in_grant false: map fails.", { grant: B.g, pcactn: B.p, context: B.c(), must: 'map' });
  const V = scenario(CMa, { mintForm: null });
  await add('map-commit-v2-goal', 'The grant was minted with the plain v2 goal over the commitment while the PCActn claims the commit form: intent fails (v2c goal), map passes.', { grant: V.g, pcactn: V.p, context: V.c(), must: 'intent' });
  const N = scenario(CMa, { form: null });
  await add('map-form-absent', 'A v2c grant but the PCActn omits map_form: the v2 goal does not open it (intent fails); map is not reported.', { grant: N.g, pcactn: N.p, context: N.c(), must: 'intent' });
  await add('map-require-plain', 'policy.map.require true and a PCActn over a plain map digest: map fails.', { grant: G0, pcactn: P0, context: ctx({ policy: { map: { require: true } } }), must: 'map' });
  await add('map-require-false', 'policy.map.require false (explicit) and a plain map: map is not reported.', { grant: G0, pcactn: P0, context: ctx({ policy: { map: { require: false } } }), must: 'allow' });
  for (const [name, pol] of [['require-string', { require: 'true' }], ['require-null', { require: null }], ['eps-string', { max_residual_risk_ppm: '2000' }], ['eps-negative', { max_residual_risk_ppm: -1 }], ['eps-fraction', { max_residual_risk_ppm: 1.5 }], ['unknown', { strict: true }], ['null', null]]) {
    await add(`map-policy-${name}`, `policy.map ${JSON.stringify(pol)}: the v2 context is malformed: every reportable check fails.`, { grant: A.g, pcactn: A.p, context: A.c({ policy: { map: pol } }), must: ['schema', 'intent_session', 'accumulators', 'map'] });
  }
  await add('map-context-unknown', 'intent_v2.map carries an unknown member: the context is malformed.', { grant: A.g, pcactn: A.p, context: A.c({ map: { disclosure: A.c().map.disclosure, extra: 1 } }), must: ['schema', 'intent_session', 'accumulators', 'map'] });
  await add('map-context-null', 'intent_v2.map is null: the context is malformed.', { grant: A.g, pcactn: A.p, context: A.c({ map: null }), must: ['schema', 'intent_session', 'accumulators', 'map'] });
  for (const [name, v] of [['plain', 'plain'], ['null', null], ['bool', true]]) {
    await add(`map-form-wire-${name}`, `intent_session.map_form ${JSON.stringify(v)} (only "commit"): the wire check fails (terminal).`, { grant: A.g, pcactn: resign({ ...clone(A.p), intent_session: { ...A.p.intent_session, map_form: v } }), context: A.c(), must: 'wire' });
  }
}

const file = readCore();
const mine = (n) => /^(schema|session|acc|layers|ctx|map)-/.test(n);
file.vectors = file.vectors.filter((v) => !mine(v.name)).concat(vectors);
file.primitives = { ...file.primitives, intent_schema: schemaPrims, intent_revocation: revPrims };
writeCore(file);
console.log(`intent v2 (W-A): ${vectors.length} vectors (${vectors.filter((v) => v.class === 'positive').length} positive), ${schemaPrims.length} intent_schema, ${revPrims.length} intent_revocation primitives`);
