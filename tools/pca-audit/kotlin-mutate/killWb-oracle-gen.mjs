// Oracle for the Kotlin W-B kill tests (KillWbTest.kt / KillWbArtifactsTest.kt): runs the TS reference
// (packages/pca/src: decideIntentWB, intentWBActive and the intent-artifacts helpers) on targeted inputs and writes the
// FULL expected results (outcome, ordered checks, env.world / env.prov / env.class, reason, friction, single_source).
// Deterministic (Ed25519 and ML-DSA-65 signing are deterministic; inputs are fixed): byte-for-byte reproducible.
//   K/tsx/run.sh tools/pca-audit/kotlin-mutate/killWb-oracle-gen.mjs sdks/kotlin-pca/test-data/killWb.json
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const pq = await import(new URL('../../../packages/pca/src/pq.ts', import.meta.url).href);

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const s = (n, ch = 'x') => ch.repeat(n);
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const SESSION = pca.b64u(seed('wb/session'));
const OTHER_SESSION = pca.b64u(seed('wb/other-session'));
const O = [mk('wb/oracle-1'), mk('wb/oracle-2'), mk('wb/oracle-3')];
const SITE = mk('wb/site');
const GOV = mk('wb/gov');
const J = [mk('wb/judge-1'), mk('wb/judge-2'), mk('wb/judge-3')];

const cases = [];
const names = new Set();
const push = (c) => {
  if (names.has(c.name)) throw new Error(`duplicate case ${c.name}`);
  names.add(c.name);
  cases.push(c);
};

// ---------------------------------------------------------------- W-B fixtures
const pin = (i) => ({ kid: `o${i + 1}`, pk: O[i].pk });
const fareWorld = (over = {}) => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: [pin(0), pin(1), pin(2)], freshness_ms: 60_000, min_oracles: 3, max_faulty: 1, ...over });
const one = (over = {}) => fareWorld({ min_oracles: 1, max_faulty: 0, ...over });
const fact = (i, value, t_obs = NOW - 1_000) => pca.signFact({ name: 'fare', subject: 'OF-2', value, t_obs, oracle: `o${i + 1}` }, O[i].sk);
const three = () => [fact(0, 39_800), fact(1, 39_900), fact(2, 1)];
const OFFERS = [
  { offer_id: 'OF-1', price: 38_900, stops: 1, refundable: false },
  { offer_id: 'OF-2', price: 39_800, stops: 0, refundable: false },
  { offer_id: 'OF-3', price: 41_200, stops: 0, refundable: true },
];
const QUERY = { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 };
const offerSet = (over = {}) => pca.signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, SITE.sk);
const offerPolicy = () => ({ name: 'excess_cents', site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: QUERY, offer: { refundable: false } } });
const MESSAGE = 'We are sorry for the delay.';
const TONE = { id: 'tone', param: 'action.params.body', labels: ['neutral', 'apologetic', 'hostile', 'other'], keys: J.map((j) => j.pk), k: 2, measurements: ['m-tone-1'] };
const verdict = (j, label, over = {}) => pca.signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(MESSAGE), label, measurement: 'm-tone-1', ...over }, j.sk);
const two = () => [verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')];
const HX = pca.hashCanonical('X1234567');
const receipt = (site, key, kid, fields, session = SESSION) => pca.signLabels({ site, session, response_digest: pca.b64u(seed('wb/response')), fields, issued_at: NOW - 5_000, kid }, key.sk);
const PASSPORT = receipt(AUD, SITE, 'k1', { pp: { class: 'pii.identity', value_digest: HX } });
const GOVR = receipt('gov.example', GOV, 'g1', { pp: { class: 'pii.identity', value_digest: HX } });
const PASSPORT_OTHER = receipt(AUD, SITE, 'k1', { pp: { class: 'pii.identity', value_digest: HX } }, OTHER_SESSION);
const lref = (r, f) => `pca-labels:${pca.labelsRef(r)}#${f}`;
const LABEL_KEYS = [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: 'gov.example', kid: 'g1', pk: GOV.pk }];
const PARAMS = { offer_id: 'OF-2', total: 77_800, quote: 38_900, passport: 'X1234567', body: MESSAGE };

// ---------------------------------------------------------------- the W-B unit (full result)
function wb(name, input) {
  const r = pca.decideIntentWB(clone(input));
  if (/evaluation error/.test(r.reason ?? '')) throw new Error(`${name}: TS threw: ${r.reason}`);
  push({ kind: 'wb', name: `wb/${name}`, input: clone(input), expect: { ...r, check_order: Object.keys(r.checks) } });
}
const IS = (o = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'air.book', resource: 'r', params: PARAMS }, intent_session: {}, policy: {}, ...o });
const f3 = three();
const vs = two();
const FACTS = { intent_session: { facts: f3.map(pca.factRef) }, artifacts: { facts: f3 }, policy: { world: { worlds: [fareWorld()] } } };
const fs1 = [fact(0, 39_800)];
const PROV_OK = { 'action.params.offer_id': ['wallet:profile:ana'] };
const PROV_POL = { params: {}, registry: { 'wallet:profile:ana': 'trusted' } };
const QPOL = { params: { 'action.params.offer_id': 'material' } };

wb('empty', IS());
wb('no-policy-member', (() => { const i = IS(); delete i.policy; return i; })());
wb('facts-pass', IS(FACTS));
wb('facts-single-source', IS({ intent_session: { facts: fs1.map(pca.factRef) }, artifacts: { facts: fs1 }, policy: { world: { worlds: [one()] } } }));
wb('facts-no-artifacts', IS({ ...FACTS, artifacts: undefined }));
wb('facts-no-artifacts-member', IS({ intent_session: FACTS.intent_session, policy: FACTS.policy }));
wb('facts-fail', IS({ ...FACTS, artifacts: { facts: f3.slice(0, 2) } }));
wb('facts-stale', IS({ ...FACTS, now: NOW + 120_000 }));
wb('facts-committed-no-world-policy', IS({ intent_session: FACTS.intent_session, artifacts: FACTS.artifacts }));
wb('facts-committed-policy-no-world', IS({ intent_session: FACTS.intent_session, artifacts: FACTS.artifacts, policy: { provenance: PROV_POL } }));
wb('world-relational-only', IS({ policy: { world: { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] } } }));
wb('world-relational-other-action', IS({ action: { verb: 'v', resource: 'r', params: { total: 5, quote: 7 } }, policy: { world: { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] } } }));
wb('world-relational-uncommitted-facts-empty', IS({ intent_session: { facts: [] }, policy: { world: { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] } } }));
wb('offer-pass', IS({ intent_session: { offer_set: pca.offerSetRef(offerSet()) }, artifacts: { offer_set: offerSet() }, policy: { world: { offers: offerPolicy() } } }));
wb('offer-other-aud', IS({ aud: 'other.example', intent_session: { offer_set: pca.offerSetRef(offerSet()) }, artifacts: { offer_set: offerSet() }, policy: { world: { offers: offerPolicy() } } }));
wb('offer-other-session', IS({ session: OTHER_SESSION, intent_session: { offer_set: pca.offerSetRef(offerSet()) }, artifacts: { offer_set: offerSet() }, policy: { world: { offers: offerPolicy() } } }));
wb('offer-no-artifact', IS({ intent_session: { offer_set: pca.offerSetRef(offerSet()) }, artifacts: {}, policy: { world: { offers: offerPolicy() } } }));
wb('offer-uncommitted', IS({ artifacts: { offer_set: offerSet() }, policy: { world: { offers: offerPolicy() } } }));
wb('offer-and-facts', IS({ intent_session: { facts: f3.map(pca.factRef), offer_set: pca.offerSetRef(offerSet()) }, artifacts: { facts: f3, offer_set: offerSet() }, policy: { world: { worlds: [fareWorld()], offers: offerPolicy() } } }));
wb('prov-pass', IS({ intent_session: { prov: PROV_OK }, policy: { provenance: PROV_POL } }));
wb('prov-question-tap', IS({ intent_session: { prov: { 'action.params.offer_id': ['web:ad'] } }, policy: { provenance: QPOL } }));
wb('prov-question-typed', IS({ intent_session: { prov: { 'action.params.total': ['web:ad'] } }, policy: { provenance: { params: { 'action.params.total': 'critical' } } } }));
wb('prov-no-policy', IS({ intent_session: { prov: { 'action.params.offer_id': ['x'] } } }));
wb('prov-no-policy-pass', IS({ intent_session: { prov: {} } }));
wb('prov-policy-only', IS({ policy: { provenance: QPOL } }));
wb('prov-deny', IS({ intent_session: { prov: { 'action.params.nope': ['x'] } } }));
wb('prov-null', IS({ intent_session: { prov: null } }));
wb('prov-other-action', IS({ action: { verb: 'v', resource: 'r', params: { total: 1 } }, intent_session: { prov: PROV_OK }, policy: { provenance: PROV_POL } }));
const LABELS_IS = { labels: [pca.labelsRef(PASSPORT)], prov: { 'action.params.passport': [lref(PASSPORT, 'pp')] } };
const LPOL = { provenance: { params: { 'action.params.passport': 'critical' }, label_keys: LABEL_KEYS } };
wb('labels-pass', IS({ intent_session: LABELS_IS, artifacts: { labels: [PASSPORT] }, policy: LPOL }));
wb('labels-other-aud', IS({ aud: 'gov.example', intent_session: LABELS_IS, artifacts: { labels: [PASSPORT] }, policy: LPOL }));
wb('labels-other-session', IS({ session: OTHER_SESSION, intent_session: LABELS_IS, artifacts: { labels: [PASSPORT] }, policy: LPOL }));
wb('labels-session-mismatch-receipt', IS({ intent_session: { labels: [pca.labelsRef(PASSPORT_OTHER)], prov: { 'action.params.passport': [lref(PASSPORT_OTHER, 'pp')] } }, artifacts: { labels: [PASSPORT_OTHER] }, policy: LPOL }));
wb('labels-gov', IS({ intent_session: { labels: [pca.labelsRef(GOVR)], prov: { 'action.params.passport': [lref(GOVR, 'pp')] } }, artifacts: { labels: [GOVR] }, policy: LPOL }));
wb('labels-no-artifacts', IS({ intent_session: LABELS_IS, policy: LPOL }));
wb('labels-uncommitted', IS({ intent_session: { prov: LABELS_IS.prov }, artifacts: { labels: [PASSPORT] }, policy: LPOL }));
wb('labels-only-active', IS({ intent_session: { labels: [pca.labelsRef(PASSPORT)] }, artifacts: { labels: [PASSPORT] } }));
wb('labels-only-no-artifacts', IS({ intent_session: { labels: [pca.labelsRef(PASSPORT)] } }));
wb('labels-empty-inactive', IS({ intent_session: { labels: [] } }));
wb('cls-pass', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs }, policy: { classifiers: [TONE] } }));
wb('cls-no-policy', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs } }));
wb('cls-policy-only', IS({ policy: { classifiers: [TONE] } }));
wb('cls-no-verdicts', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, policy: { classifiers: [TONE] } }));
wb('cls-uncommitted', IS({ artifacts: { verdicts: vs }, policy: { classifiers: [TONE] } }));
wb('cls-fail', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: [vs[0]] }, policy: { classifiers: [TONE] } }));
wb('cls-other-session', IS({ session: OTHER_SESSION, intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs }, policy: { classifiers: [TONE] } }));
wb('cls-other-action', IS({ action: { verb: 'v', resource: 'r', params: { body: 'other' } }, intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs }, policy: { classifiers: [TONE] } }));
wb('prov-question-then-cls-fail', IS({ intent_session: { prov: { 'action.params.offer_id': ['web:ad'] }, classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: [vs[0]] }, policy: { provenance: QPOL, classifiers: [TONE] } }));
wb('prov-question-then-cls-pass', IS({ intent_session: { prov: { 'action.params.offer_id': ['web:ad'] }, classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs }, policy: { provenance: QPOL, classifiers: [TONE] } }));
wb('facts-single-then-prov-deny', IS({ intent_session: { facts: fs1.map(pca.factRef), prov: { 'action.params.nope': ['x'] } }, artifacts: { facts: fs1 }, policy: { world: { worlds: [one()] } } }));
wb('facts-single-then-cls-fail', IS({ intent_session: { facts: fs1.map(pca.factRef), classes: vs.map(pca.classifierVerdictRef) }, artifacts: { facts: fs1, verdicts: [vs[0]] }, policy: { world: { worlds: [one()] }, classifiers: [TONE] } }));
wb('facts-single-prov-question', IS({ intent_session: { facts: fs1.map(pca.factRef), prov: { 'action.params.offer_id': ['web:ad'] } }, artifacts: { facts: fs1 }, policy: { world: { worlds: [one()] }, provenance: QPOL } }));
wb('all-pass', IS({ intent_session: { facts: f3.map(pca.factRef), prov: PROV_OK, classes: vs.map(pca.classifierVerdictRef) }, artifacts: { facts: f3, verdicts: vs }, policy: { world: { worlds: [fareWorld()] }, provenance: PROV_POL, classifiers: [TONE] } }));
wb('facts-fail-skips-rest', IS({ intent_session: { facts: f3.map(pca.factRef), prov: { 'action.params.nope': ['x'] } }, artifacts: { facts: [] }, policy: { world: { worlds: [fareWorld()] } } }));
// the context shape rule: every refusal message and the accepted boundary shapes
wb('ctx-session-null', IS({ intent_session: null }));
wb('ctx-session-array', IS({ intent_session: [] }));
wb('ctx-session-absent', (() => { const i = IS(); delete i.intent_session; return i; })());
wb('ctx-artifacts-null', IS({ artifacts: null }));
wb('ctx-artifacts-array', IS({ artifacts: [] }));
wb('ctx-artifacts-string', IS({ artifacts: 'x' }));
wb('ctx-artifacts-extra', IS({ artifacts: { x: [] } }));
wb('ctx-artifacts-extra-after-known', IS({ artifacts: { facts: [], zz: 1 } }));
for (const k of ['facts', 'labels', 'verdicts']) {
  wb(`ctx-artifacts-${k}-null`, IS({ artifacts: { [k]: null } }));
  wb(`ctx-artifacts-${k}-obj`, IS({ artifacts: { [k]: {} } }));
  wb(`ctx-artifacts-${k}-ok`, IS({ artifacts: { [k]: [] } }));
}
wb('ctx-artifacts-offer-array', IS({ artifacts: { offer_set: [] } }));
wb('ctx-artifacts-offer-null', IS({ artifacts: { offer_set: null } }));
wb('ctx-artifacts-offer-ok', IS({ artifacts: { offer_set: {} } }));
wb('ctx-artifacts-ok', IS({ artifacts: { facts: [], labels: [], verdicts: [], offer_set: {} } }));
wb('ctx-artifacts-empty', IS({ artifacts: {} }));
wb('ctx-policy-null', IS({ policy: null }));
wb('ctx-policy-array', IS({ policy: [] }));
wb('ctx-policy-extra', IS({ policy: { x: 1 } }));
wb('ctx-policy-extra-after-known', IS({ policy: { world: {}, zz: 1 } }));
for (const k of ['world', 'provenance']) {
  wb(`ctx-policy-${k}-null`, IS({ policy: { [k]: null } }));
  wb(`ctx-policy-${k}-array`, IS({ policy: { [k]: [] } }));
}
wb('ctx-policy-world-ok', IS({ policy: { world: {} } }));
wb('ctx-policy-cls-obj', IS({ policy: { classifiers: {} } }));
wb('ctx-policy-cls-null', IS({ policy: { classifiers: null } }));
wb('ctx-policy-cls-ok', IS({ policy: { classifiers: [] } }));
wb('ctx-policy-all-ok', IS({ policy: { world: {}, classifiers: [] } }));
wb('ctx-artifacts-bad-and-policy-bad', IS({ artifacts: { facts: 1 }, policy: null }));

// ---------------------------------------------------------------- activity
function active(name, input) { push({ kind: 'active', name: `active/${name}`, input: clone(input), expect: pca.intentWBActive(clone(input)) }); }
active('empty', { intent_session: {}, policy: {} });
active('absent-both', {});
active('facts', { intent_session: { facts: [SESSION] }, policy: {} });
active('offer-set', { intent_session: { offer_set: SESSION }, policy: {} });
active('offer-set-number', { intent_session: { offer_set: 1 }, policy: {} });
active('facts-and-offer', { intent_session: { facts: [SESSION], offer_set: SESSION }, policy: {} });
active('world-worlds', { intent_session: {}, policy: { world: { worlds: [{}] } } });
active('world-offers', { intent_session: {}, policy: { world: { offers: {} } } });
active('prov-null', { intent_session: { prov: null }, policy: {} });
active('labels', { intent_session: { labels: [SESSION] }, policy: {} });
active('labels-empty', { intent_session: { labels: [] }, policy: {} });
active('prov-policy', { intent_session: {}, policy: { provenance: {} } });
active('prov-policy-array', { intent_session: {}, policy: { provenance: [] } });
active('classes', { intent_session: { classes: [SESSION] }, policy: {} });
active('classifiers', { intent_session: {}, policy: { classifiers: [{}] } });
active('classifiers-empty', { intent_session: {}, policy: { classifiers: [] } });
active('session-array', { intent_session: [], policy: {} });
active('policy-null', { intent_session: { facts: [SESSION] }, policy: null });
active('numbers', { intent_session: { facts: [1.0], prov: 2.50 }, policy: { classifiers: [1e2] } });

// ---------------------------------------------------------------- intent-artifacts helpers
const art = (fn, name, args, expect) => push({ kind: 'art', fn, name: `art/${fn}/${name}`, args: clone(args), expect });
for (const [n, v] of Object.entries({ simple: 'a', dash: 'a-b', under: 'A_9', '64': s(64), '65': s(65), empty: '', dot: 'a.b', proto: '__proto__', ctor: 'constructor', prototype: 'prototype', space: 'a b', protoLike: 'constructors', unicode: 'é' }))
  art('isPathSegment', n, [v], pca.isPathSegment(v));
for (const [n, v] of Object.entries({ ok: 'fare', len64: 'a' + s(63, '0'), len65: 'a' + s(64, '0'), upper: 'Fare', digit: '9a', empty: '', number: 7, nul: null, list: ['a'] }))
  art('isName', n, [v], typeof v === 'string' && pca.INTENT_NAME_RE.test(v));
for (const [n, v, max] of [['ok', 'abc', 3], ['over', 'abcd', 3], ['under', 'ab', 3], ['empty', '', 3], ['number', 5, 3], ['nul', null, 3], ['utf8-at', 'é', 2], ['utf8-over', 'é', 1], ['max0', 'a', 0]])
  art('isBoundedString', n, [v, max], pca.isBoundedString(v, max));
for (const [n, a, b] of [['str', 'a', 'a'], ['str-ne', 'a', 'b'], ['str-num', '2', 2], ['num-str', 2, '2'], ['bool', true, true], ['bool-ne', true, false], ['bool-num', true, 1], ['num-bool', 1, true],
  ['num', 2, 2], ['num-ne', 2, 3], ['null-null', null, null], ['null-num', null, 0], ['num-null', 0, null], ['null-str', null, ''], ['null-obj', null, {}], ['obj-null', {}, null], ['obj-obj', {}, {}], ['arr-arr', [], []], ['null-arr', null, []], ['arr-null', [], null], ['obj-num', {}, 1], ['num-obj', 1, {}]])
  art('scalarEq', n, [a, b], pca.scalarEq(a, b));
for (const [n, o, req, opt, where] of [['ok', { a: 1 }, ['a'], ['b'], 'w'], ['unknown', { a: 1, z: 2 }, ['a'], [], 'w'], ['missing', { a: 1 }, ['a', 'b'], [], 'w'], ['missing-first', {}, ['a', 'b'], [], 'w'],
  ['optional-only', { b: 1 }, [], ['b'], 'w'], ['empty', {}, [], [], 'x'], ['unknown-before-missing', { z: 1 }, ['a'], [], 'w']])
  art('closedMembers', n, [o, req, opt, where], pca.closedMembers(o, req, opt, where));
for (const [n, pin0] of [['absent', {}], ['ok', { pq_pk: 'x' }], ['empty', { pq_pk: '' }], ['nul', { pq_pk: null }], ['number', { pq_pk: 1 }], ['list', { pq_pk: ['x'] }]])
  art('pinPqOk', n, [pin0], pca.pinPqOk(pin0.pq_pk === undefined && !('pq_pk' in pin0) ? undefined : pin0.pq_pk));
for (const [n, a] of [['empty', {}], ['ed', { alg: 'ed25519' }], ['alg-number', { alg: 1 }], ['alg-null', { alg: null }], ['alg-unknown', { alg: 'no-such' }], ['pqpk-number', { pq_pk: 1 }], ['pqsig-number', { pq_sig: 1 }],
  ['pqpk-null', { pq_pk: null }], ['pqsig-null', { alg: 'ml-dsa-65', pq_sig: null }], ['ed-pqpk', { pq_pk: 'x' }], ['ed-pqsig', { pq_sig: 'x' }], ['ed-named-pqpk', { alg: 'ed25519', pq_pk: 'x' }],
  ['mldsa', { alg: 'ml-dsa-65', pq_pk: 'x' }], ['mldsa-both', { alg: 'ml-dsa-65', pq_pk: 'x', pq_sig: 'y' }], ['hybrid-pqsig-number', { alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'x', pq_sig: 2 }], ['mldsa-pqpk-number-pqsig-ok', { alg: 'ml-dsa-65', pq_pk: 3, pq_sig: 'y' }]])
  art('artifactSuiteError', n, [a], pca.artifactSuiteError(a));
{
  const DOM = 'atlas-pca/kill-wb/v1';
  const ED = mk('wb/art-ed');
  const PQSEED = seed('wb/art-pq');
  const mlDsa = pq.mlDsa65Keygen(PQSEED);
  const edArt = pca.signArtifact(DOM, { x: 1, y: 'z' }, ED.sk);
  const pqArt = pca.signArtifact(DOM, { x: 1 }, ED.sk, { alg: 'ml-dsa-65', mlDsa });
  const pqPk = pqArt.pq_pk;
  const v = (n, a, pk, pqpk) => art('verifyArtifactSig', n, [DOM, a, pk, pqpk], pca.verifyArtifactSig(DOM, a, pqpk === undefined || pqpk === null ? pk : { pk, pq_pk: pqpk }));
  v('ed-ok', edArt, ED.pk, null);
  v('ed-ok-with-pq-pin', edArt, ED.pk, 'unused');
  v('ed-wrong-key', edArt, O[0].pk, null);
  v('ed-tampered', { ...edArt, y: 'w' }, ED.pk, null);
  v('ed-sig-number', { ...edArt, sig: 5 }, ED.pk, null);
  v('ed-sig-absent', (() => { const a = { ...edArt }; delete a.sig; return a; })(), ED.pk, null);
  v('ed-pk-number', edArt, 5, null);
  v('ed-pk-null', edArt, null, null);
  v('ed-float-body', { ...edArt, f: 1.5 }, ED.pk, null);
  v('pq-ok', pqArt, ED.pk, pqPk);
  v('pq-no-pin', pqArt, ED.pk, null);
  v('pq-wrong-pin', pqArt, ED.pk, edArt.sig);
  v('pq-sig-number', { ...pqArt, sig: 1 }, ED.pk, pqPk);
  v('unknown-alg', { ...edArt, alg: 'no-such' }, ED.pk, null);
}
// verifyArtifactSig over a body strict canonicalisation refuses (a lone surrogate): false, never a throw
{
  const DOM = 'atlas-pca/kill-wb/v1';
  const ED = mk('wb/art-ed');
  const a = { s: '\ud800', sig: pca.signArtifact(DOM, { x: 1 }, ED.sk).sig };
  art('verifyArtifactSig', 'lone-surrogate', [DOM, a, ED.pk, null], pca.verifyArtifactSig(DOM, a, ED.pk));
}
const PP = { a: { b: { c: 1 } }, n: null, arr: [{ x: 1 }], s: 'str', z: 0, 'k-1': { '0': 'zero' } };
for (const [n, path] of [['leaf', 'action.params.a.b.c'], ['sub', 'action.params.a.b'], ['top', 'action.params.a'], ['null', 'action.params.n'], ['zero', 'action.params.z'], ['missing', 'action.params.q'], ['deep-missing', 'action.params.a.x'],
  ['through-leaf', 'action.params.s.length'], ['through-null', 'action.params.n.x'], ['through-array', 'action.params.arr.0'], ['proto', 'action.params.constructor'], ['empty-seg', 'action.params.a..b'],
  ['prefix-only', 'action.params.'], ['no-prefix', 'params.a'], ['upper-prefix', 'ACTION.PARAMS.a'], ['number', 5], ['nul', null], ['dash-digit', 'action.params.k-1.0'], ['trailing-dot', 'action.params.a.']]) {
  const r = pca.resolveParamPath(PP, path);
  art('resolveParamPath', n, [PP, path], { found: r.found, value: r.found ? (r.value === undefined ? null : r.value) : null });
}
art('resolveParamPath', 'params-null', [null, 'action.params.a'], { found: false, value: null });
art('resolveParamPath', 'params-array', [[1], 'action.params.0'], (() => { const r = pca.resolveParamPath([1], 'action.params.0'); return { found: r.found, value: r.found ? r.value : null }; })());
for (const [n, path] of [['one', 'action.params.a'], ['eight', 'action.params.a.b.c.d.e.f.g.h'], ['nine', 'action.params.a.b.c.d.e.f.g.h.i'], ['seven', 'action.params.a.b.c.d.e.f.g'], ['prefix-only', 'action.params.'], ['no-prefix', 'params.a'],
  ['upper-prefix', 'ACTION.PARAMS.a'], ['number', 5], ['nul', null], ['proto-last', 'action.params.a.__proto__'], ['bad-first', 'action.params.a b.c'], ['bad-middle', 'action.params.a.b!.c'], ['seg-64', `action.params.${s(64)}`], ['seg-65', `action.params.${s(65)}`],
  ['empty-mid', 'action.params.a..b'], ['trailing-dot', 'action.params.a.'], ['dash', 'action.params.a-b.C_9']])
  art('isParamPath', n, [path], pca.isParamPath(path));
const setN = (n, root, path, value) => { const r = clone(root); const ok = pca.setNested(r, path, value); art('setNested', n, [root, path, value], { ok, root: JSON.parse(JSON.stringify(r)) }); };
setN('fresh', {}, 'a.b.c', 1);
setN('single', {}, 'a', 'v');
setN('sibling', { a: { b: 1 } }, 'a.c', 2);
setN('collide-leaf', { a: { b: 1 } }, 'a.b', 2);
setN('collide-top', { a: 1 }, 'a', 2);
setN('through-leaf', { a: 1 }, 'a.b', 2);
setN('through-null', { a: null }, 'a.b', 2);
setN('through-array', { a: [] }, 'a.b', 2);
setN('prefix-of-existing', { a: { b: { c: 1 } } }, 'a.b', 2);
setN('null-value', {}, 'x.y', null);

fs.writeFileSync(process.argv[2], JSON.stringify({ about: 'TS-reference oracle for KillWbTest.kt / KillWbArtifactsTest.kt (IntentWB.kt, IntentArtifacts.kt); generated by tools/pca-audit/kotlin-mutate/killWb-oracle-gen.mjs.', cases }, null, 0) + '\n');
console.log(`cases: ${cases.length}`);
