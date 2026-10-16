// Oracle for the Java 0.4.2 kill tests of OracleFacts.java / ParamProvenance.java (K042OracleProv*Test): runs the TS
// reference (oracle-facts.ts, offer-set.ts, label-receipts.ts, param-provenance.ts) on targeted inputs and writes the
// expected results, deterministic and reproducible:
//   npx tsx tools/pca-audit/java-mutate/k042-oracleprov-oracle.mjs sdks/java-pca/test-data/k042-oracleprov.json.gz
// It reuses every rule-16/17 input of the Go W-B oracle (tools/pca-audit/go-mutate/killD-oracle-gen.mjs, run to a temp
// file), recomputes the FULL reference result for each (reason text, world, single_source, labels, classes, env,
// friction), and adds the Java-specific cases below.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);
const out = process.argv[2];
if (!out) throw new Error('usage: k042-oracleprov-oracle.mjs <out.json.gz>');

const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'k042op-')), 'killD.json');
execFileSync(process.execPath, [...process.execArgv, path.join(here, '../go-mutate/killD-oracle-gen.mjs'), tmp], { stdio: ['ignore', 'ignore', 'inherit'] });
const base = JSON.parse(fs.readFileSync(tmp, 'utf8')).cases;
fs.rmSync(path.dirname(tmp), { recursive: true });

const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const FNS = ['validateFactWire', 'validateWorldPolicy', 'validateOfferPolicy', 'validateOfferSetWire', 'validateLabelsWire', 'validateFlowRules', 'validateProvenancePolicy', 'validateProvWire'];
const cases = [];
const names = new Set();
const push = (c) => {
  if (names.has(c.name)) throw new Error(`duplicate case ${c.name}`);
  names.add(c.name);
  cases.push(c);
};
const worldOut = (r) => (r.ok ? { ok: true, world: r.world, single_source: r.single_source } : { ok: false, reason: r.reason });
const provOut = (r) => ({ outcome: r.outcome, reason: r.reason ?? null, friction: r.friction ?? null, labels: r.labels, classes: r.classes, env: r.env });
const fnCase = (fnName, name, arg) => push({ kind: 'fn', fn: fnName, name: `${fnName}/${name}`, arg: clone(arg), want: pca[fnName](clone(arg)) });
const world = (name, input) => push({ kind: 'world', name: `world/${name}`, input: clone(input), expect: worldOut(pca.decideIntentWorld(clone(input))) });
const prov = (name, input) => push({ kind: 'prov', name: `prov/${name}`, input: clone(input), expect: provOut(pca.decideParamProvenance(clone(input))) });
const read = (name, input) => {
  const i = clone(input);
  push({ kind: 'read', name: `read/${name}`, input: clone(input), expect: pca.decideReadPurpose(i.fields, i.purpose, i.coverage, ...(Object.prototype.hasOwnProperty.call(i, 'on_uncovered') ? [i.on_uncovered] : [])) });
};
const active = (name, committed, policy) => push({ kind: 'active', name: `active/${name}`, committed: clone(committed), policy: clone(policy), expect: pca.intentWorldActive({ committed: clone(committed), policy: clone(policy) }) });

for (const c of base) {
  if (c.kind === 'fn' && FNS.includes(c.fn)) fnCase(c.fn, c.name.slice(c.fn.length + 1), c.arg);
  else if (c.kind === 'ratio') push({ kind: 'ratio', name: c.name, a: c.a, b: c.b, want: pca.ratioPpm(c.a, c.b) });
  else if (c.kind === 'flowRule') push({ kind: 'flowRule', name: c.name, rules: c.rules, cls: c.cls, want: pca.flowRuleFor(c.rules, c.cls) ?? null });
  else if (c.kind === 'flowAllowed') push({ kind: 'flowAllowed', name: c.name, rules: c.rules, cls: c.cls, origin: c.origin, aud: c.aud, want: pca.flowAllowed(c.rules, c.cls, c.origin, c.aud) });
  else if (c.kind === 'world') world(c.name.slice('world/'.length), c.input);
  else if (c.kind === 'prov') prov(c.name.slice('prov/'.length), c.input);
  else if (c.kind === 'read') read(c.name.slice('read/'.length), c.input);
  else if (c.kind === 'active') {
    const s = c.input.intent_session && typeof c.input.intent_session === 'object' ? c.input.intent_session : {};
    const committed = {};
    if (Object.prototype.hasOwnProperty.call(s, 'facts')) committed.facts = s.facts;
    if (Object.prototype.hasOwnProperty.call(s, 'offer_set')) committed.offer_set = s.offer_set;
    const p = c.input.policy && typeof c.input.policy === 'object' && !Array.isArray(c.input.policy) && Object.prototype.hasOwnProperty.call(c.input.policy, 'world') ? c.input.policy.world : {};
    active(c.name.slice('active/'.length), committed, p);
  }
}

// ------------------------------------------------------------------------------------------- Java-specific cases
const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const SESSION = pca.b64u(seed('wb/session'));
const O = [mk('wb/oracle-1'), mk('wb/oracle-2'), mk('wb/oracle-3')];
const SITE = mk('wb/site');
const D32 = pca.b64u(seed('wb/active'));
const pin = (i) => ({ kid: `o${i + 1}`, pk: O[i].pk });
const fact = (i, nm, value, t_obs = NOW - 1_000, subject = 'OF-2') => pca.signFact({ name: nm, subject, value, t_obs, oracle: `o${i + 1}` }, O[i].sk);
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900, pax: 2 } };
const W = (facts, policy, over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { facts: facts.map(pca.factRef) }, facts, policy, ...over });
const one = (over = {}) => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: [pin(0), pin(1), pin(2)], freshness_ms: 60_000, min_oracles: 1, max_faulty: 0, ...over });

// activity: every disjunct alone, wrong types, non-object inputs
active('k042-none', {}, {});
active('k042-c-null-p-null', null, null);
active('k042-facts-one', { facts: [D32] }, {});
active('k042-facts-empty', { facts: [] }, {});
active('k042-facts-obj', { facts: { length: 1 } }, {});
active('k042-offer-string', { offer_set: 'x' }, {});
active('k042-offer-number', { offer_set: 1 }, {});
active('k042-worlds-one', {}, { worlds: [{}] });
active('k042-worlds-empty', {}, { worlds: [] });
active('k042-rel-one', {}, { relational: [{}] });
active('k042-rel-obj', {}, { relational: { a: 1 } });
active('k042-offers-obj', {}, { offers: {} });
active('k042-offers-array', {}, { offers: [] });
active('k042-committed-array-policy-worlds', [D32], { worlds: [1] });
active('k042-committed-string-policy-string', 'x', 'y');
active('k042-policy-array-facts', { facts: [D32] }, [1]);

// world: boundaries and branches
world('k042-16-committed-facts', W([], { worlds: [one()] }, { committed: { facts: Array.from({ length: 16 }, (_, i) => pca.b64u(seed(`k042/d${i}`))) } }));
world('k042-17-committed-facts', W([], { worlds: [one()] }, { committed: { facts: Array.from({ length: 17 }, (_, i) => pca.b64u(seed(`k042/d${i}`))) } }));
world('k042-skew-0-future-1', W([fact(0, 'fare', 5, NOW + 1)], { skew_ms: 0, worlds: [one()] }));
world('k042-skew-0-now', W([fact(0, 'fare', 5, NOW)], { skew_ms: 0, worlds: [one()] }));
world('k042-skew-5-future-5', W([fact(0, 'fare', 5, NOW + 5)], { skew_ms: 5, worlds: [one()] }));
world('k042-skew-5-future-6', W([fact(0, 'fare', 5, NOW + 6)], { skew_ms: 5, worlds: [one()] }));
world('k042-default-skew-future-60000', W([fact(0, 'fare', 5, NOW + 60_000)], { worlds: [one()] }));
world('k042-default-skew-future-60001', W([fact(0, 'fare', 5, NOW + 60_001)], { worlds: [one()] }));
world('k042-fresh-exact', W([fact(0, 'fare', 5, NOW - 60_000)], { worlds: [one()] }));
world('k042-fresh-over', W([fact(0, 'fare', 5, NOW - 60_001)], { worlds: [one()] }));
world('k042-no-action', { now: NOW, aud: AUD, session: SESSION, policy: { worlds: [one()] } });
world('k042-action-null', { now: NOW, aud: AUD, session: SESSION, action: null, policy: {} });
world('k042-action-array', { now: NOW, aud: AUD, session: SESSION, action: [], policy: {} });
world('k042-no-policy', { now: NOW, aud: AUD, session: SESSION, action: ACTION });
world('k042-policy-null', { now: NOW, aud: AUD, session: SESSION, action: ACTION, policy: null });
world('k042-input-null', null);
world('k042-input-array', []);
world('k042-subject-resource', W([fact(0, 'fare', 5, NOW - 1_000, 'skyair.example/bookings')], { worlds: [one({ subject_path: 'action.resource' })] }));
world('k042-subject-resource-other', W([fact(0, 'fare', 5, NOW - 1_000, 'other')], { worlds: [one({ subject_path: 'action.resource' })] }));
world('k042-subject-resource-number', W([fact(0, 'fare', 5, NOW - 1_000, 'x')], { worlds: [one({ subject_path: 'action.resource' })] }, { action: { ...ACTION, resource: 5 } }));
world('k042-subject-verb', W([fact(0, 'fare', 5, NOW - 1_000, 'air.book')], { worlds: [one({ subject_path: 'action.verb' })] }));
world('k042-subject-verb-other', W([fact(0, 'fare', 5, NOW - 1_000, 'air.cancel')], { worlds: [one({ subject_path: 'action.verb' })] }));
world('k042-subject-verb-missing', W([fact(0, 'fare', 5, NOW - 1_000, 'air.book')], { worlds: [one({ subject_path: 'action.verb' })] }, { action: { resource: 'r', params: {} } }));
world('k042-subject-param-number', W([fact(0, 'fare', 5, NOW - 1_000, '2')], { worlds: [one({ subject_path: 'action.params.pax' })] }));
world('k042-subject-param-missing', W([fact(0, 'fare', 5, NOW - 1_000, 'x')], { worlds: [one({ subject_path: 'action.params.nope' })] }));
world('k042-subject-other-root', W([fact(0, 'fare', 5, NOW - 1_000, 'x')], { worlds: [one({ subject_path: 'action.other' })] }));
world('k042-two-worlds-single-source', W([fact(0, 'fare', 5), fact(1, 'tier', 'gold', NOW - 1_000)], { worlds: [one(), one({ name: 'tier', min_oracles: 1 })] }));
world('k042-min-2-single-source-no', W([fact(0, 'fare', 5), fact(1, 'fare', 9)], { worlds: [one({ min_oracles: 2 })] }));
world('k042-min-0-no-facts', W([], { worlds: [one({ min_oracles: 0 })] }));
world('k042-strings-agree-2', W([fact(0, 'tier', 'gold'), fact(1, 'tier', 'gold')], { worlds: [one({ name: 'tier', min_oracles: 2 })] }));
world('k042-strings-disagree-2', W([fact(0, 'tier', 'gold'), fact(1, 'tier', 'silver')], { worlds: [one({ name: 'tier', min_oracles: 2 })] }));
world('k042-mix', W([fact(0, 'tier', 'gold'), fact(1, 'tier', 7)], { worlds: [one({ name: 'tier', min_oracles: 2 })] }));
world('k042-negative-median', W([fact(0, 'fare', -7), fact(1, 'fare', -3), fact(2, 'fare', 4)], { worlds: [one({ min_oracles: 3, max_faulty: 1 })] }));
const R = (rel, params = {}, worlds = [], facts = []) => W(facts, { worlds, relational: rel }, { action: { ...ACTION, params: { ...ACTION.params, ...params } } });
world('k042-rel-sub-neg', R([{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }], { x: 1, y: 9 }));
world('k042-rel-sub-max-neg', R([{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }], { x: -4503599627370496, y: 4503599627370495 }));
world('k042-rel-sub-under', R([{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }], { x: -4503599627370496, y: 4503599627370496 }));
world('k042-rel-sub-max', R([{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }], { x: 4503599627370496, y: -4503599627370495 }));
world('k042-rel-sub-over', R([{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }], { x: 4503599627370496, y: -4503599627370496 }));
world('k042-rel-ratio-zero', R([{ name: 'd', fn: 'ratio_ppm', a: 'action.params.x', b: 'action.params.y' }], { x: 3, y: 0 }));
world('k042-rel-ratio-ok', R([{ name: 'd', fn: 'ratio_ppm', a: 'action.params.x', b: 'action.params.y' }], { x: 3, y: 7 }));
world('k042-rel-env-world', R([{ name: 'd', fn: 'sub', a: 'env.world.fare', b: 'action.params.pax' }], {}, [one()], [fact(0, 'fare', 50)]));
world('k042-rel-env-world-string', R([{ name: 'd', fn: 'sub', a: 'env.world.tier', b: 'action.params.pax' }], {}, [one({ name: 'tier' })], [fact(0, 'tier', 'gold')]));
world('k042-rel-env-chain', R([{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }, { name: 'e', fn: 'sub', a: 'env.world.d', b: 'action.params.pax' }]));
world('k042-rel-param-float', R([{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.pax' }], { x: 1.5 }));
world('k042-rel-param-string', R([{ name: 'd', fn: 'sub', a: 'action.params.pax', b: 'action.params.x' }], { x: '1' }));
world('k042-rel-param-missing', R([{ name: 'd', fn: 'sub', a: 'action.params.pax', b: 'action.params.nope' }]));
world('k042-rel-no-action-params', W([], { relational: [{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }] }, { action: { verb: 'v', resource: 'r' } }));
world('k042-rel-params-null', W([], { relational: [{ name: 'd', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }] }, { action: { verb: 'v', resource: 'r', params: null } }));
world('k042-committed-null', W([], {}, { committed: null }));
world('k042-committed-facts-null', W([], {}, { committed: { facts: null } }));
world('k042-committed-facts-obj', W([], {}, { committed: { facts: {} } }));
world('k042-facts-null', W([], {}, { facts: null }));
world('k042-facts-obj', W([], {}, { facts: {} }));
world('k042-offer_set-null', W([], {}, { offer_set: null }));
world('k042-offer_set-array', W([], {}, { offer_set: [] }));
world('k042-offer_set-obj-no-policy', W([], {}, { offer_set: {} }));
world('k042-committed-offer-bad', W([], {}, { committed: { offer_set: 'x' } }));
world('k042-committed-offer-ok-no-policy', W([], {}, { committed: { offer_set: D32 } }));
world('k042-committed-digest-bad', W([], {}, { committed: { facts: ['x'] } }));
world('k042-committed-digest-dup', W([], {}, { committed: { facts: [D32, D32] } }));
world('k042-committed-not-supplied', W([], { worlds: [one()] }, { committed: { facts: [D32] } }));
world('k042-fact-other-oracle-unpinned', W([pca.signFact({ name: 'fare', subject: 'OF-2', value: 5, t_obs: NOW - 1_000, oracle: 'zz' }, O[0].sk)], { worlds: [one()] }));
world('k042-fact-undeclared', W([fact(0, 'nope', 5)], { worlds: [one()] }));
world('k042-fact-bad-sig', W([pca.signFact({ name: 'fare', subject: 'OF-2', value: 5, t_obs: NOW - 1_000, oracle: 'o1' }, O[1].sk)], { worlds: [one()] }));
world('k042-two-from-one-oracle', W([fact(0, 'fare', 5), fact(0, 'fare', 6)], { worlds: [one({ min_oracles: 1 })] }));
world('k042-same-oracle-two-worlds', W([fact(0, 'fare', 5), fact(0, 'tier', 6)], { worlds: [one(), one({ name: 'tier' })] }));
world('k042-now-string', W([fact(0, 'fare', 5)], { worlds: [one()] }, { now: String(NOW) }));
world('k042-now-float', W([fact(0, 'fare', 5)], { worlds: [one()] }, { now: NOW + 0.5 }));
world('k042-now-absent', (() => { const x = W([fact(0, 'fare', 5)], { worlds: [one()] }); delete x.now; return x; })());

// offer sets
const OFFERS = [
  { offer_id: 'OF-1', price: 41_200, refundable: false, cabin: 'economy' },
  { offer_id: 'OF-2', price: 39_800, refundable: false, cabin: 'economy' },
  { offer_id: 'OF-3', price: 35_000, refundable: true, cabin: 'economy' },
  { offer_id: 'OF-4', price: 39_700, refundable: false, cabin: 'economy' },
];
const QUERY = { from: 'SFO', to: 'JFK' };
const offerSet = (over = {}) => pca.signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, SITE.sk);
const offerPolicy = (over = {}) => ({ name: 'excess_cents', site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: QUERY, offer: { refundable: false } }, ...over });
const OS = (os, policy = offerPolicy(), over = {}, extraPolicy = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { offer_set: pca.offerSetRef(os) }, offer_set: os, policy: { offers: policy, ...extraPolicy }, ...over });
const withOffer = (id) => ({ action: { ...ACTION, params: { ...ACTION.params, offer_id: id } } });
world('k042-os-base', OS(offerSet()));
world('k042-os-cheapest', OS(offerSet(), offerPolicy(), withOffer('OF-4')));
world('k042-os-chosen-refundable', OS(offerSet(), offerPolicy(), withOffer('OF-3')));
world('k042-os-no-filter-offer', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('k042-os-equal-price', OS(offerSet({ offers: [{ offer_id: 'OF-2', price: 5 }, { offer_id: 'OF-9', price: 5 }] })));
world('k042-os-issued-skew-exact', OS(offerSet({ issued_at: NOW + 60_000 })));
world('k042-os-issued-skew-over', OS(offerSet({ issued_at: NOW + 60_001 })));
world('k042-os-issued-skew0-exact', OS(offerSet({ issued_at: NOW }), offerPolicy(), {}, { skew_ms: 0 }));
world('k042-os-issued-skew0-over', OS(offerSet({ issued_at: NOW + 1 }), offerPolicy(), {}, { skew_ms: 0 }));
world('k042-os-age-exact', OS(offerSet({ issued_at: NOW - 600_000 })));
world('k042-os-age-over', OS(offerSet({ issued_at: NOW - 600_001 })));
world('k042-os-not-complete', OS(offerSet({ complete: false })));
world('k042-os-now-string', OS(offerSet(), offerPolicy(), { now: String(NOW) }));
world('k042-os-no-param', OS(offerSet(), offerPolicy(), { action: { ...ACTION, params: { total: 1 } } }));
world('k042-os-param-number', OS(offerSet(), offerPolicy(), withOffer(2)));
world('k042-os-param-unknown', OS(offerSet(), offerPolicy(), withOffer('OF-77')));
world('k042-os-no-action-params', OS(offerSet(), offerPolicy(), { action: { verb: 'v', resource: 'r' } }));
world('k042-os-other-aud', OS(offerSet(), offerPolicy(), { aud: 'other.example' }));
world('k042-os-other-session', OS(offerSet(), offerPolicy(), { session: D32 }));
world('k042-os-unpinned', OS(offerSet({ kid: 'zz' })));
world('k042-os-bad-sig', OS({ ...offerSet(), sig: offerSet({ issued_at: 1 }).sig }));
world('k042-os-ref-mismatch', { ...OS(offerSet()), committed: { offer_set: D32 } });
world('k042-os-not-committed', (() => { const x = OS(offerSet()); delete x.committed; return x; })());
world('k042-os-not-supplied', (() => { const x = OS(offerSet()); delete x.offer_set; return x; })());
world('k042-os-wire-bad', OS({ ...offerSet(), rank: 'x' }));
world('k042-os-coverage', OS(offerSet({ query: { from: 'SFO', to: 'JFK', nonstop: true } })));
world('k042-os-coverage-value', OS(offerSet({ query: { from: 'SFO', to: 'LAX' } })));
world('k042-os-query-subset', OS(offerSet({ query: { from: 'SFO' } })));
world('k042-os-with-world', { ...OS(offerSet(), offerPolicy(), {}, { worlds: [one()] }), committed: { offer_set: pca.offerSetRef(offerSet()), facts: [pca.factRef(fact(0, 'fare', 5))] }, facts: [fact(0, 'fare', 5)] });
world('k042-os-surrogate', { ...OS(offerSet()), committed: { offer_set: D32 }, offer_set: { ...offerSet(), query: { from: '\ud800' } } });

// prov: boundaries and branches
const PARAMS = { offer_id: 'OF-1', payment_ref: 'pm', passport: 'X1234567', note: 'hi', pax: { lead: 'px' } };
const HX = pca.hashCanonical('X1234567');
const receipt = (site, fields, over = {}) => pca.signLabels({ site, session: SESSION, response_digest: D32, fields, issued_at: NOW, kid: 'k1', ...over }, SITE.sk);
const PASS = receipt(AUD, { pp: { class: 'pii.identity', value_digest: HX }, pub: { class: 'public', value_digest: HX }, fin: { class: 'fin.card', value_digest: HX } });
const GOVR = receipt('gov.example', { pp: { class: 'pii.identity', value_digest: HX }, pub: { class: 'public', value_digest: HX }, card: { class: 'fin.card', value_digest: HX } });
const lref = (r, f) => `pca-labels:${pca.labelsRef(r)}#${f}`;
const KEYS = [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: 'gov.example', kid: 'k1', pk: SITE.pk }];
const P = (prov, policy = {}, over = {}) => ({ aud: AUD, session: SESSION, action: { params: PARAMS }, prov, committed_labels: [pca.labelsRef(PASS), pca.labelsRef(GOVR)], labels: [PASS, GOVR], policy: { params: { 'action.params.passport': 'critical', 'action.params.note': 'material' }, label_keys: KEYS, ...policy }, ...over });
prov('k042-first-party', P({ 'action.params.passport': [lref(PASS, 'pp')] }));
prov('k042-tool-site', P({ 'action.params.passport': [lref(GOVR, 'pp')] }, { flows: { 'pii.*': [AUD] } }));
prov('k042-tool-site-flow-denied', P({ 'action.params.passport': [lref(GOVR, 'pp')] }));
prov('k042-tool-site-public', P({ 'action.params.passport': [lref(GOVR, 'pub')] }));
prov('k042-tool-site-star', P({ 'action.params.passport': [lref(GOVR, 'card')] }, { flows: { '*': [AUD] } }));
prov('k042-two-classes', P({ 'action.params.passport': [lref(GOVR, 'card'), lref(GOVR, 'pp'), lref(PASS, 'pp')] }, { flows: { '*': [AUD] } }));
prov('k042-value-mismatch', P({ 'action.params.note': [lref(PASS, 'pp')] }));
prov('k042-no-field', P({ 'action.params.passport': [lref(PASS, 'zz')] }));
prov('k042-not-committed', P({ 'action.params.passport': [lref(PASS, 'pp')] }, {}, { committed_labels: [pca.labelsRef(GOVR)] }));
prov('k042-not-supplied', P({ 'action.params.passport': [lref(PASS, 'pp')] }, {}, { labels: [GOVR] }));
prov('k042-bad-key', P({ 'action.params.passport': [lref(PASS, 'pp')] }, { label_keys: [{ site: AUD, kid: 'k2', pk: SITE.pk }] }));
prov('k042-no-label-keys', P({ 'action.params.passport': [lref(PASS, 'pp')] }, { label_keys: undefined }));
prov('k042-other-session', P({ 'action.params.passport': [lref(receipt(AUD, { pp: { class: 'pii.identity', value_digest: HX } }, { session: D32 }), 'pp')] }, {}, { committed_labels: [pca.labelsRef(receipt(AUD, { pp: { class: 'pii.identity', value_digest: HX } }, { session: D32 }))], labels: [receipt(AUD, { pp: { class: 'pii.identity', value_digest: HX } }, { session: D32 })] }));
prov('k042-malformed-ref', P({ 'action.params.passport': ['pca-labels:xx#pp'] }));
prov('k042-malformed-ref-no-hash', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASS)}`] }));
prov('k042-malformed-ref-empty-field', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASS)}#`] }));
prov('k042-ref-field-with-hash', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASS)}#pp#x`] }));
prov('k042-registry-trusted', P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'trusted' } }));
prov('k042-registry-first-party', P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'first_party' } }));
prov('k042-registry-tool', P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'tool' } }));
prov('k042-registry-web', P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'web' } }));
prov('k042-registry-unknown', P({ 'action.params.passport': ['r2'] }, { registry: { r1: 'trusted' } }));
prov('k042-registry-join', P({ 'action.params.passport': ['r1', 'r2'] }, { registry: { r1: 'trusted', r2: 'first_party' } }));
prov('k042-registry-join-rev', P({ 'action.params.passport': ['r2', 'r1'] }, { registry: { r1: 'trusted', r2: 'web' } }));
for (const lvl of ['trusted', 'first_party', 'tool', 'web', 'agent']) {
  prov(`k042-cap-${lvl}-tool`, P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'tool' }, critical_max: lvl }));
  prov(`k042-cap-${lvl}-first`, P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'first_party' }, critical_max: lvl }));
}
for (const mode of ['allow', 'question', 'question_typed', 'deny']) {
  prov(`k042-material-${mode}`, P({ 'action.params.note': ['r1'] }, { registry: { r1: 'tool' }, material_tainted: mode }));
  prov(`k042-material-${mode}-first`, P({ 'action.params.note': ['r1'] }, { registry: { r1: 'first_party' }, material_tainted: mode }));
  if (mode !== 'allow') prov(`k042-critical-${mode}`, P({ 'action.params.passport': ['r1'] }, { registry: { r1: 'tool' }, critical_tainted: mode }));
}
prov('k042-both-question-tap', P({ 'action.params.note': ['r1'], 'action.params.passport': ['r1'] }, { registry: { r1: 'tool' }, material_tainted: 'question', critical_tainted: 'question' }));
prov('k042-both-mixed', P({ 'action.params.note': ['r1'], 'action.params.passport': ['r1'] }, { registry: { r1: 'tool' }, material_tainted: 'question', critical_tainted: 'question_typed' }));
prov('k042-undeclared-material-agent', P({}, {}, {}));
prov('k042-undeclared-material-missing', P({}, { params: { 'action.params.nope': 'material' } }));
prov('k042-nested-param', P({}, { params: { 'action.params.pax.lead': 'critical' } }));
prov('k042-free-param-tainted', P({ 'action.params.offer_id': ['r1'] }, { registry: { r1: 'web' } }));
prov('k042-prov-missing-param', P({ 'action.params.zz': ['r1'] }));
prov('k042-prov-null', P(null));
prov('k042-prov-absent', (() => { const x = P({}); delete x.prov; return x; })());
prov('k042-committed-17', P({}, {}, { committed_labels: Array.from({ length: 17 }, (_, i) => pca.b64u(seed(`k042/l${i}`))) }));
prov('k042-committed-16', P({}, {}, { committed_labels: Array.from({ length: 16 }, (_, i) => pca.b64u(seed(`k042/l${i}`))) }));
prov('k042-committed-dup', P({}, {}, { committed_labels: [D32, D32] }));
prov('k042-committed-bad', P({}, {}, { committed_labels: ['x'] }));
prov('k042-committed-null', P({}, {}, { committed_labels: null }));
prov('k042-committed-absent', (() => { const x = P({}); delete x.committed_labels; return x; })());
prov('k042-action-null', P({}, {}, { action: null }));
prov('k042-action-no-params', P({}, {}, { action: {} }));
prov('k042-action-params-null', P({}, {}, { action: { params: null } }));
prov('k042-labels-null', P({}, {}, { labels: null }));
prov('k042-labels-obj', P({}, {}, { labels: {} }));
prov('k042-labels-absent', (() => { const x = P({}); delete x.labels; return x; })());
prov('k042-labels-junk', P({ 'action.params.passport': [lref(PASS, 'pp')] }, {}, { labels: [1, null, { v: 1 }, PASS] }));
prov('k042-policy-null', P({}, {}, { policy: null }));
prov('k042-policy-bad-param', P({}, { params: { 'x.y': 'material' } }));
prov('k042-input-null', null);
prov('k042-input-array', []);
prov('k042-flows-exact', P({ 'action.params.passport': [lref(GOVR, 'pp')] }, { flows: { 'pii.identity': [AUD] } }));
prov('k042-flows-other-aud', P({ 'action.params.passport': [lref(GOVR, 'pp')] }, { flows: { 'pii.identity': ['x.example'] } }));
prov('k042-surrogate-value', P({ 'action.params.note': [lref(PASS, 'pp')] }, {}, { action: { params: { ...PARAMS, note: '\ud800' } } }));
prov('k042-aud-missing', (() => { const x = P({ 'action.params.passport': [lref(GOVR, 'pp')] }); delete x.aud; return x; })());

// read purpose
const F = [{ path: 'b', class: 'pii.identity' }, { path: 'a', class: 'secret', optional: true }, { path: 'c', class: 'public' }, { path: 'd', class: 'secret' }, { path: 'e', class: 'pii.contact', optional: false }];
read('k042-none', { fields: F, purpose: 'x', coverage: {} });
read('k042-star', { fields: F, purpose: 'x', coverage: { x: ['*'] } });
read('k042-prefix', { fields: F, purpose: 'x', coverage: { x: ['pii.*'] } });
read('k042-prefix-nodot', { fields: F, purpose: 'x', coverage: { x: ['pii*'] } });
read('k042-exact', { fields: F, purpose: 'x', coverage: { x: ['secret'] } });
read('k042-deny', { fields: F, purpose: 'x', coverage: { x: [] }, on_uncovered: 'deny' });
read('k042-bad-on', { fields: F, purpose: 'x', coverage: {}, on_uncovered: 'allow' });
read('k042-null-on', { fields: F, purpose: 'x', coverage: {}, on_uncovered: null });
read('k042-other-purpose', { fields: F, purpose: 'x', coverage: { y: ['*'] } });
read('k042-cov-not-list', { fields: F, purpose: 'x', coverage: { y: 'x' } });
read('k042-cov-number', { fields: F, purpose: 'x', coverage: { y: [1] } });
read('k042-field-null', { fields: [null], purpose: 'x', coverage: {} });
read('k042-field-path-number', { fields: [{ path: 1, class: 'x' }], purpose: 'x', coverage: {} });
read('k042-field-class-null', { fields: [{ path: 'a', class: null }], purpose: 'x', coverage: {} });
read('k042-field-optional-string', { fields: [{ path: 'a', class: 'x', optional: 'yes' }], purpose: 'x', coverage: {} });
read('k042-fields-obj', { fields: {}, purpose: 'x', coverage: {} });
read('k042-purpose-number', { fields: F, purpose: 1, coverage: {} });
read('k042-coverage-array', { fields: F, purpose: 'x', coverage: [] });
read('k042-all-optional', { fields: [{ path: 'z', class: 'q', optional: true }, { path: 'y', class: 'q', optional: true }], purpose: 'x', coverage: {} });
read('k042-utf8-order', { fields: [{ path: '！', class: 'q' }, { path: '😀', class: 'q' }, { path: 'a', class: 'q' }], purpose: 'x', coverage: {} });

// validators the Go corpus does not reach
fnCase('validateProvWire', 'k042-32', Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`action.params.p${i}`, ['x']])));
fnCase('validateProvWire', 'k042-33', Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`action.params.p${i}`, ['x']])));
fnCase('validateProvWire', 'k042-proto', { 'action.params.constructor': ['x'] });
fnCase('validateProvWire', 'k042-proto2', { 'action.params.prototype': ['x'] });
fnCase('validateProvWire', 'k042-refs-8', { 'action.params.a': Array.from({ length: 8 }, () => 'x') });
fnCase('validateProvWire', 'k042-refs-9', { 'action.params.a': Array.from({ length: 9 }, () => 'x') });
fnCase('validateProvWire', 'k042-refs-0', { 'action.params.a': [] });
fnCase('validateProvWire', 'k042-refs-obj', { 'action.params.a': {} });
fnCase('validateProvWire', 'k042-ref-empty', { 'action.params.a': [''] });
fnCase('validateProvWire', 'k042-ref-256', { 'action.params.a': ['x'.repeat(256)] });
fnCase('validateProvWire', 'k042-ref-257', { 'action.params.a': ['x'.repeat(257)] });
fnCase('validateProvWire', 'k042-null', null);
fnCase('validateProvWire', 'k042-array', []);

fs.writeFileSync(out, zlib.gzipSync(Buffer.from(JSON.stringify({ about: 'TS-reference oracle for the Java K042OracleProv kill tests; generated by tools/pca-audit/java-mutate/k042-oracleprov-oracle.mjs.', cases })), { level: 9 }));
console.log(`cases: ${cases.length}`);
