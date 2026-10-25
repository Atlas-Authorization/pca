// Oracle for the Go W-B kill tests (killD_test.go): runs the TS reference on targeted inputs and writes the golden.
//   cd packages/pca && ./node_modules/.bin/tsx <this> <out.json>
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const SESSION = pca.b64u(seed('wb/session'));
const OTHER_SESSION = pca.b64u(seed('wb/other-session'));
const O = [mk('wb/oracle-1'), mk('wb/oracle-2'), mk('wb/oracle-3'), mk('wb/oracle-4')];
const ROGUE = mk('wb/rogue');
const SITE = mk('wb/site');
const GOV = mk('wb/gov');
const J = [mk('wb/judge-1'), mk('wb/judge-2'), mk('wb/judge-3')];
const D32 = pca.b64u(seed('wb/active'));
const D32b = pca.b64u(seed('wb/active-b'));

const cases = [];
const names = new Set();
const push = (c) => {
  if (names.has(c.name)) throw new Error(`duplicate case ${c.name}`);
  names.add(c.name);
  cases.push(c);
};
const DEL = Symbol('del');
const setPath = (o, path, v) => {
  const r = clone(o);
  const ks = path.split('/');
  let cur = r;
  for (const k of ks.slice(0, -1)) cur = cur[k];
  const last = ks[ks.length - 1];
  if (v === DEL) delete cur[last];
  else cur[last] = v;
  return r;
};
const s = (n, ch = 'x') => ch.repeat(n);

// ---------------------------------------------------------------- validator-level cases (TS null = valid)
function fn(fnName, name, arg, extra = {}) {
  const f = {
    validateFactWire: pca.validateFactWire,
    validateWorldPolicy: pca.validateWorldPolicy,
    validateOfferPolicy: pca.validateOfferPolicy,
    validateOfferSetWire: pca.validateOfferSetWire,
    validateLabelsWire: pca.validateLabelsWire,
    validateFlowRules: pca.validateFlowRules,
    validateProvenancePolicy: pca.validateProvenancePolicy,
    validateProvWire: pca.validateProvWire,
    validateClassifierVerdictWire: pca.validateClassifierVerdictWire,
    validateClassifierPolicy: pca.validateClassifierPolicy,
  }[fnName];
  let r;
  try { r = f(clone(arg)); } catch (e) { throw new Error(`${fnName}/${name} threw ${e}`); }
  push({ kind: 'fn', fn: fnName, name: `${fnName}/${name}`, arg: clone(arg), want: r === null, ts_reason: r ?? '', ...extra });
}
function perturb(fnName, base, list) {
  fn(fnName, 'base', base);
  for (const [name, path, v] of list) fn(fnName, name, setPath(base, path, v));
}

// facts
const factBase = { v: 1, kind: 'pca-fact', name: 'fare', subject: 'OF-2', value: 5, t_obs: 7, oracle: 'o1', sig: 'AAAA' };
perturb('validateFactWire', factBase, [
  ['no-v', 'v', DEL], ['no-kind', 'kind', DEL], ['no-name', 'name', DEL], ['no-subject', 'subject', DEL], ['no-value', 'value', DEL],
  ['no-t_obs', 't_obs', DEL], ['no-oracle', 'oracle', DEL], ['no-sig', 'sig', DEL], ['extra', 'note', 'x'], ['alg-member', 'alg', 'ed25519'],
  ['v2', 'v', 2], ['v-string', 'v', '1'], ['kind-other', 'kind', 'pca-facts'],
  ['name-upper', 'name', 'Fare'], ['name-number', 'name', 7], ['name-65', 'name', s(65, 'a')], ['name-64', 'name', s(64, 'a')],
  ['subject-256', 'subject', s(256)], ['subject-257', 'subject', s(257)], ['subject-empty', 'subject', ''], ['subject-number', 'subject', 5],
  ['value-string-256', 'value', s(256)], ['value-string-257', 'value', s(257)], ['value-empty', 'value', ''], ['value-float', 'value', 1.5],
  ['value-negative', 'value', -3], ['value-bool', 'value', true], ['value-unsafe', 'value', 2 ** 53],
  ['t_obs-0', 't_obs', 0], ['t_obs-neg', 't_obs', -1], ['t_obs-float', 't_obs', 1.5], ['t_obs-string', 't_obs', '7'],
  ['oracle-64', 'oracle', s(64)], ['oracle-65', 'oracle', s(65)], ['oracle-empty', 'oracle', ''], ['sig-number', 'sig', 1],
]);
fn('validateFactWire', 'not-object', [factBase]);
fn('validateFactWire', 'null', null);

// world policy
const pin = (i) => ({ kid: `o${i + 1}`, pk: O[i].pk });
const worldBase = { name: 'fare', subject_path: 'action.params.offer_id', oracles: [pin(0), pin(1), pin(2)], freshness_ms: 60000, min_oracles: 3, max_faulty: 1 };
const wpBase = { skew_ms: 0, worlds: [worldBase], relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'env.world.fare' }], offers: { name: 'excess', site_keys: [{ kid: 'k', pk: SITE.pk }], max_age_ms: 0, offer_param: 'action.params.offer_id', filter: { query: {}, offer: {} } } };
perturb('validateWorldPolicy', wpBase, [
  ['extra', 'x', 1], ['skew-neg', 'skew_ms', -1], ['skew-float', 'skew_ms', 0.5], ['skew-string', 'skew_ms', '0'], ['skew-absent', 'skew_ms', DEL], ['skew-1', 'skew_ms', 1],
  ['worlds-null', 'worlds', null], ['worlds-obj', 'worlds', {}], ['worlds-absent', 'worlds', DEL], ['relational-absent', 'relational', DEL],
  ['world-null', 'worlds/0', null], ['world-extra', 'worlds/0/x', 1], ['world-no-name', 'worlds/0/name', DEL], ['world-bad-name', 'worlds/0/name', 'Fare'],
  ['world-no-subject', 'worlds/0/subject_path', DEL], ['world-subject-env', 'worlds/0/subject_path', 'env.x'], ['world-subject-number', 'worlds/0/subject_path', 3],
  ['world-subject-action-dot', 'worlds/0/subject_path', 'action.'],
  ['fresh-neg', 'worlds/0/freshness_ms', -1], ['fresh-0', 'worlds/0/freshness_ms', 0], ['fresh-float', 'worlds/0/freshness_ms', 0.5], ['fresh-string', 'worlds/0/freshness_ms', '1'],
  ['faulty-neg', 'worlds/0/max_faulty', -1], ['faulty-float', 'worlds/0/max_faulty', 0.5], ['faulty-string', 'worlds/0/max_faulty', '1'],
  ['min-2', 'worlds/0/min_oracles', 2], ['min-4', 'worlds/0/min_oracles', 4], ['min-float', 'worlds/0/min_oracles', 3.5], ['min-string', 'worlds/0/min_oracles', '3'],
  ['oracles-null', 'worlds/0/oracles', null], ['oracles-obj', 'worlds/0/oracles', {}],
  ['oracle-null', 'worlds/0/oracles/0', null], ['oracle-extra', 'worlds/0/oracles/0/x', 1], ['oracle-no-kid', 'worlds/0/oracles/0/kid', DEL], ['oracle-no-pk', 'worlds/0/oracles/0/pk', DEL],
  ['oracle-kid-64', 'worlds/0/oracles/0/kid', s(64)], ['oracle-kid-65', 'worlds/0/oracles/0/kid', s(65)], ['oracle-kid-empty', 'worlds/0/oracles/0/kid', ''],
  ['oracle-pk-short', 'worlds/0/oracles/0/pk', 'abc'], ['oracle-pq-null', 'worlds/0/oracles/0/pq_pk', null], ['oracle-pq-empty', 'worlds/0/oracles/0/pq_pk', ''], ['oracle-pq-ok', 'worlds/0/oracles/0/pq_pk', 'x'],
  ['oracle-dup-kid', 'worlds/0/oracles/1/kid', 'o1'],
  ['rel-null', 'relational', null], ['rel-entry-null', 'relational/0', null], ['rel-extra', 'relational/0/x', 1], ['rel-no-fn', 'relational/0/fn', DEL],
  ['rel-fn-ratio', 'relational/0/fn', 'ratio_ppm'], ['rel-fn-other', 'relational/0/fn', 'add'], ['rel-name-dup', 'relational/0/name', 'fare'], ['rel-name-bad', 'relational/0/name', '9d'],
  ['rel-a-env-undeclared', 'relational/0/a', 'env.world.zzz'], ['rel-a-env-self', 'relational/0/a', 'env.world.d'], ['rel-a-number', 'relational/0/a', 7], ['rel-a-world-prefix', 'relational/0/a', 'env.worldfare'],
  ['rel-b-env-undeclared', 'relational/0/b', 'env.world.zzz'], ['rel-b-bad', 'relational/0/b', 'action.x'], ['rel-b-param', 'relational/0/b', 'action.params.quote'],
  ['offers-null', 'offers', null], ['offers-name-dup', 'offers/name', 'fare'], ['offers-name-dup-rel', 'offers/name', 'd'], ['offers-name-bad', 'offers/name', 'X'], ['offers-bad', 'offers/max_age_ms', -1],
  ['offers-absent', 'offers', DEL],
]);
fn('validateWorldPolicy', 'worlds-16', { worlds: Array.from({ length: 16 }, (_, i) => ({ ...worldBase, name: `w${i}` })) });
fn('validateWorldPolicy', 'worlds-17', { worlds: Array.from({ length: 17 }, (_, i) => ({ ...worldBase, name: `w${i}` })) });
fn('validateWorldPolicy', 'rel-16', { relational: Array.from({ length: 16 }, (_, i) => ({ name: `r${i}`, fn: 'sub', a: 'action.params.a', b: 'action.params.b' })) });
fn('validateWorldPolicy', 'rel-17', { relational: Array.from({ length: 17 }, (_, i) => ({ name: `r${i}`, fn: 'sub', a: 'action.params.a', b: 'action.params.b' })) });
fn('validateWorldPolicy', 'world-dup-name', { worlds: [worldBase, worldBase] });
fn('validateWorldPolicy', 'rel-forward', { relational: [{ name: 'a', fn: 'sub', a: 'env.world.b', b: 'action.params.x' }, { name: 'b', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }] });
fn('validateWorldPolicy', 'rel-backward', { relational: [{ name: 'b', fn: 'sub', a: 'action.params.x', b: 'action.params.y' }, { name: 'a', fn: 'ratio_ppm', a: 'env.world.b', b: 'env.world.b' }] });
fn('validateWorldPolicy', 'faulty-0-min-1', { worlds: [{ ...worldBase, max_faulty: 0, min_oracles: 1 }] });
fn('validateWorldPolicy', 'faulty-0-min-0', { worlds: [{ ...worldBase, max_faulty: 0, min_oracles: 0 }] });
fn('validateWorldPolicy', 'faulty-2-min-5-3pins', { worlds: [{ ...worldBase, max_faulty: 2, min_oracles: 5 }] });
fn('validateWorldPolicy', 'faulty-1-min-3-2pins', { worlds: [{ ...worldBase, oracles: [pin(0), pin(1)] }] });
fn('validateWorldPolicy', 'empty', {});
fn('validateWorldPolicy', 'null', null);
fn('validateWorldPolicy', 'array', []);

// offer policy
const opBase = { name: 'excess', site_keys: [{ kid: 'k', pk: SITE.pk }, { kid: 'k2', pk: GOV.pk, pq_pk: 'pq' }], max_age_ms: 600000, offer_param: 'action.params.offer_id', filter: { query: { a: 1, b: 'x', c: true }, offer: { r: false } } };
perturb('validateOfferPolicy', opBase, [
  ['extra', 'x', 1], ['no-name', 'name', DEL], ['name-number', 'name', 1], ['name-empty', 'name', ''],
  ['keys-null', 'site_keys', null], ['keys-empty', 'site_keys', []], ['keys-obj', 'site_keys', {}],
  ['key-null', 'site_keys/0', null], ['key-extra', 'site_keys/0/x', 1], ['key-no-kid', 'site_keys/0/kid', DEL], ['key-kid-64', 'site_keys/0/kid', s(64)], ['key-kid-65', 'site_keys/0/kid', s(65)],
  ['key-kid-empty', 'site_keys/0/kid', ''], ['key-pk-bad', 'site_keys/0/pk', 'x'], ['key-pq-null', 'site_keys/0/pq_pk', null], ['key-pq-empty', 'site_keys/1/pq_pk', ''], ['key-dup', 'site_keys/1/kid', 'k'],
  ['age-neg', 'max_age_ms', -1], ['age-0', 'max_age_ms', 0], ['age-float', 'max_age_ms', 0.5], ['age-string', 'max_age_ms', '1'], ['no-age', 'max_age_ms', DEL],
  ['param-bad', 'offer_param', 'action.offer'], ['param-number', 'offer_param', 1], ['param-prefix-only', 'offer_param', 'action.params.'],
  ['filter-null', 'filter', null], ['filter-extra', 'filter/x', {}], ['filter-no-query', 'filter/query', DEL], ['filter-no-offer', 'filter/offer', DEL],
  ['filter-query-null', 'filter/query', null], ['filter-offer-array', 'filter/offer', []], ['filter-query-obj-value', 'filter/query/a', { x: 1 }], ['filter-offer-array-value', 'filter/offer/r', [1]],
  ['filter-empty', 'filter', { query: {}, offer: {} }], ['filter-null-value', 'filter/query/a', null], ['filter-offer-null-value', 'filter/offer/r', null],
]);
fn('validateOfferPolicy', 'null', null);

// offer set
const osBase = { v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: { from: 'SFO', pax: 2, ok: true }, rank: 'price_asc', complete: false, offers: [{ offer_id: 'A', price: 0, x: 1 }, { offer_id: 'B', price: 5 }], issued_at: 0, kid: 'k', sig: 'S' };
const attrs = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`a${i}`, i]));
perturb('validateOfferSetWire', osBase, [
  ['extra', 'x', 1], ['alg', 'alg', 'ed25519'], ['no-v', 'v', DEL], ['no-sig', 'sig', DEL], ['no-kid', 'kid', DEL],
  ['v2', 'v', 2], ['kind-other', 'kind', 'x'], ['site-256', 'site', s(256)], ['site-257', 'site', s(257)], ['site-empty', 'site', ''],
  ['session-bad', 'session', 'abc'], ['query-null', 'query', null], ['query-array', 'query', []], ['query-obj-value', 'query/from', { a: 1 }],
  ['query-key-64', 'query', { [s(64)]: 1 }], ['query-key-65', 'query', { [s(65)]: 1 }], ['query-key-empty', 'query', { '': 1 }],
  ['query-32', 'query', attrs(32)], ['query-33', 'query', attrs(33)],
  ['rank', 'rank', 'price_desc'], ['complete-string', 'complete', 'true'], ['complete-true', 'complete', true],
  ['offers-null', 'offers', null], ['offers-empty', 'offers', []], ['offer-null', 'offers/0', null],
  ['offer-id-128', 'offers/0/offer_id', s(128)], ['offer-id-129', 'offers/0/offer_id', s(129)], ['offer-id-empty', 'offers/0/offer_id', ''], ['offer-id-number', 'offers/0/offer_id', 1],
  ['offer-dup', 'offers/1/offer_id', 'A'], ['price-neg', 'offers/0/price', -1], ['price-float', 'offers/0/price', 0.5], ['price-string', 'offers/0/price', '0'], ['price-absent', 'offers/0/price', DEL],
  ['attr-obj', 'offers/0/x', { y: 1 }], ['attr-key-64', `offers/0/${s(64)}`, 1], ['attr-key-65', `offers/0/${s(65)}`, 1], ['attr-null', 'offers/0/x', null], ['query-null-value', 'query/from', null], ['attr-string', 'offers/0/x', 's'],
  ['offer-32-attrs', 'offers/0', { offer_id: 'A', price: 1, ...attrs(32) }], ['offer-33-attrs', 'offers/0', { offer_id: 'A', price: 1, ...attrs(33) }],
  ['issued-neg', 'issued_at', -1], ['issued-float', 'issued_at', 0.5], ['issued-1', 'issued_at', 1],
  ['kid-64', 'kid', s(64)], ['kid-65', 'kid', s(65)], ['kid-empty', 'kid', ''], ['sig-number', 'sig', 1],
]);
fn('validateOfferSetWire', 'offers-256', setPath(osBase, 'offers', Array.from({ length: 256 }, (_, i) => ({ offer_id: `o${i}`, price: i }))));
fn('validateOfferSetWire', 'offers-257', setPath(osBase, 'offers', Array.from({ length: 257 }, (_, i) => ({ offer_id: `o${i}`, price: i }))));

// label receipt
const lbBase = { v: 1, kind: 'pca-labels', site: AUD, session: SESSION, response_digest: D32, fields: { a: { class: 'pii.identity', value_digest: D32 }, b: { class: 'public', value_digest: D32b } }, issued_at: 0, kid: 'k1', sig: 'S' };
const lfields = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, { class: 'x', value_digest: D32 }]));
perturb('validateLabelsWire', lbBase, [
  ['extra', 'x', 1], ['alg', 'alg', 'ed25519'], ['no-v', 'v', DEL], ['no-fields', 'fields', DEL], ['v2', 'v', 2], ['kind-other', 'kind', 'pca-label'],
  ['site-256', 'site', s(256)], ['site-257', 'site', s(257)], ['site-empty', 'site', ''], ['session-bad', 'session', 'x'], ['resp-bad', 'response_digest', 'x'],
  ['fields-null', 'fields', null], ['fields-empty', 'fields', {}], ['fields-array', 'fields', []], ['fields-64', 'fields', lfields(64)], ['fields-65', 'fields', lfields(65)],
  ['field-key-256', 'fields', { [s(256)]: { class: 'x', value_digest: D32 } }], ['field-key-257', 'fields', { [s(257)]: { class: 'x', value_digest: D32 } }], ['field-key-empty', 'fields', { '': { class: 'x', value_digest: D32 } }],
  ['field-null', 'fields/a', null], ['field-extra', 'fields/a/x', 1], ['field-no-class', 'fields/a/class', DEL], ['field-no-digest', 'fields/a/value_digest', DEL],
  ['class-128', 'fields/a/class', s(128, 'a')], ['class-129', 'fields/a/class', s(129, 'a')], ['class-number', 'fields/a/class', 1], ['class-bad', 'fields/a/class', 'PII!'], ['class-empty', 'fields/a/class', ''],
  ['digest-bad', 'fields/a/value_digest', 'x'],
  ['issued-neg', 'issued_at', -1], ['issued-float', 'issued_at', 0.5], ['issued-1', 'issued_at', 1], ['issued-string', 'issued_at', '0'],
  ['kid-64', 'kid', s(64)], ['kid-65', 'kid', s(65)], ['kid-empty', 'kid', ''], ['sig-number', 'sig', 1],
]);

// flow rules
for (const [name, rules] of Object.entries({
  ok: { 'pii.*': ['a'], '*': ['b'], 'pii.identity': [], public: [s(256)] },
  'sink-257': { x: [s(257)] }, 'sink-empty': { x: [''] }, 'sinks-null': { x: null }, 'sinks-string': { x: 'a' },
  'pattern-bad': { 'PII!': ['a'] }, 'pattern-dotstar-bad': { 'PII.*': ['a'] }, 'pattern-star-only': { '*': ['a'] }, 'pattern-star-suffix-ok': { 'a.b.*': ['a'] },
  'pattern-dot-star-dot': { '.*': ['a'] }, 'pattern-trailing-dot': { 'pii.': ['a'] }, 'pattern-x-star': { 'x*': ['a'] }, empty: {},
})) fn('validateFlowRules', name, rules);
fn('validateFlowRules', 'null', null);
fn('validateFlowRules', 'array', []);

// provenance policy
const ppBase = { params: { 'action.params.a': 'material', 'action.params.b.c': 'critical' }, registry: { r1: 'trusted', [s(256)]: 'agent' }, label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }, { site: s(256), kid: s(64), pk: GOV.pk, pq_pk: 'p' }], critical_max: 'tool', material_tainted: 'allow', critical_tainted: 'deny', flows: { '*': ['x'] } };
perturb('validateProvenancePolicy', ppBase, [
  ['extra', 'x', 1], ['no-params', 'params', DEL], ['params-null', 'params', null], ['params-array', 'params', []], ['param-bad-path', 'params/env.x', 'material'], ['param-bad-sens', 'params/action.params.a', 'low'],
  ['registry-null', 'registry', null], ['registry-array', 'registry', []], ['registry-key-257', `registry/${s(257)}`, 'agent'], ['registry-key-empty', 'registry/', 'agent'], ['registry-bad-level', 'registry/r1', 'super'], ['registry-level-number', 'registry/r1', 1],
  ['keys-null', 'label_keys', null], ['keys-obj', 'label_keys', {}], ['key-null', 'label_keys/0', null], ['key-extra', 'label_keys/0/x', 1], ['key-no-site', 'label_keys/0/site', DEL],
  ['key-site-257', 'label_keys/0/site', s(257)], ['key-site-empty', 'label_keys/0/site', ''], ['key-kid-65', 'label_keys/0/kid', s(65)], ['key-kid-empty', 'label_keys/0/kid', ''], ['key-pk-bad', 'label_keys/0/pk', 'x'], ['key-pq-null', 'label_keys/0/pq_pk', null],
  ['cmax-bad', 'critical_max', 'none'], ['cmax-null', 'critical_max', null], ['mt-question_typed', 'material_tainted', 'question_typed'], ['mt-bad', 'material_tainted', 'x'], ['mt-null', 'material_tainted', null],
  ['ct-allow', 'critical_tainted', 'allow'], ['ct-question', 'critical_tainted', 'question'], ['ct-bad', 'critical_tainted', 'x'], ['ct-null', 'critical_tainted', null],
  ['flows-bad', 'flows', { 'X!': [] }], ['flows-null', 'flows', null],

]);

// prov wire
const pvBase = { 'action.params.a': ['r1', s(256)], 'action.params.B_9': Array.from({ length: 8 }, (_, i) => `r${i}`) };
const pv = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`action.params.p${i}`, ['x']]));
perturb('validateProvWire', pvBase, [
  ['refs-9', 'action.params.a', Array.from({ length: 9 }, (_, i) => `r${i}`)], ['refs-empty', 'action.params.a', []], ['refs-null', 'action.params.a', null], ['refs-string', 'action.params.a', 'r'],
  ['ref-257', 'action.params.a', [s(257)]], ['ref-empty', 'action.params.a', ['']], ['ref-number', 'action.params.a', [1]],
  ['key-nested', 'action.params.a.b', ['x']], ['key-dash', 'action.params.a-b', ['x']], ['key-proto', 'action.params.__proto__', ['x']], ['key-constructor', 'action.params.constructor', ['x']], ['key-prototype', 'action.params.prototype', ['x']],
  ['key-64', `action.params.${s(64)}`, ['x']], ['key-65', `action.params.${s(65)}`, ['x']], ['key-env', 'env.x', ['x']],
]);
fn('validateProvWire', 'paths-32', pv(32));
fn('validateProvWire', 'paths-33', pv(33));
fn('validateProvWire', 'array', []);
fn('validateProvWire', 'null', null);

// classifier verdict
const cvBase = { v: 1, kind: 'pca-intent-classification', classifier: 'tone', session: SESSION, content_digest: D32, label: 'x', measurement: 'm', judge: J[0].pk, sig: 'S' };
perturb('validateClassifierVerdictWire', cvBase, [
  ['extra', 'x', 1], ['alg', 'alg', 'ed25519'], ['no-v', 'v', DEL], ['no-judge', 'judge', DEL], ['v2', 'v', 2], ['kind-other', 'kind', 'x'],
  ['classifier-bad', 'classifier', 'Tone'], ['classifier-number', 'classifier', 1], ['session-bad', 'session', 'x'], ['content-bad', 'content_digest', 'x'],
  ['label-64', 'label', s(64)], ['label-65', 'label', s(65)], ['label-empty', 'label', ''], ['label-number', 'label', 1],
  ['measurement-256', 'measurement', s(256)], ['measurement-257', 'measurement', s(257)], ['measurement-empty', 'measurement', ''], ['judge-bad', 'judge', 'x'], ['sig-number', 'sig', 1],
]);

// classifier policy
const cpBase = { classifiers: [{ id: 'tone', param: 'action.params.body', labels: ['a', s(64)], keys: [J[0].pk, J[1].pk], k: 2, measurements: ['m', ''], pq_keys: { [J[0].pk]: 'pq' } }, { id: 'spam', param: 'action.params.x.y', labels: ['y'], keys: [J[2].pk], k: 1 }] };
perturb('validateClassifierPolicy', cpBase, [
  ['extra', 'x', 1], ['classifiers-obj', 'classifiers', {}], ['classifiers-empty', 'classifiers', []], ['c-null', 'classifiers/0', null], ['c-extra', 'classifiers/0/x', 1],
  ['id-bad', 'classifiers/0/id', 'Tone'], ['id-number', 'classifiers/0/id', 1], ['id-dup', 'classifiers/1/id', 'tone'], ['param-bad', 'classifiers/0/param', 'action.body'], ['param-number', 'classifiers/0/param', 1],
  ['labels-null', 'classifiers/0/labels', null], ['labels-empty', 'classifiers/0/labels', []], ['labels-32', 'classifiers/0/labels', Array.from({ length: 32 }, (_, i) => `l${i}`)],
  ['labels-33', 'classifiers/0/labels', Array.from({ length: 33 }, (_, i) => `l${i}`)], ['label-65', 'classifiers/0/labels/0', s(65)], ['label-empty', 'classifiers/0/labels/0', ''], ['label-number', 'classifiers/0/labels/0', 1],
  ['labels-dup', 'classifiers/0/labels/1', 'a'], ['keys-null', 'classifiers/0/keys', null], ['keys-empty', 'classifiers/0/keys', []], ['key-bad', 'classifiers/0/keys/0', 'x'], ['keys-dup', 'classifiers/0/keys/1', J[0].pk],
  ['k-0', 'classifiers/0/k', 0], ['k-1', 'classifiers/0/k', 1], ['k-3', 'classifiers/0/k', 3], ['k-float', 'classifiers/0/k', 1.5], ['k-string', 'classifiers/0/k', '2'], ['k-neg', 'classifiers/0/k', -1],
  ['measurements-null', 'classifiers/0/measurements', null], ['measurements-obj', 'classifiers/0/measurements', {}], ['measurement-number', 'classifiers/0/measurements/0', 1], ['measurements-empty', 'classifiers/0/measurements', []],
  ['pq-null', 'classifiers/0/pq_keys', null], ['pq-array', 'classifiers/0/pq_keys', []], ['pq-unknown-key', 'classifiers/0/pq_keys', { [J[2].pk]: 'x' }], ['pq-empty', 'classifiers/0/pq_keys', { [J[0].pk]: '' }],
  ['pq-number', 'classifiers/0/pq_keys', { [J[0].pk]: 1 }], ['pq-empty-map', 'classifiers/0/pq_keys', {}],
]);

// ---------------------------------------------------------------- ratioPpm / flowRuleFor / flowAllowed
for (const [a, b] of [[1, 1], [0, 1], [5, 0], [5, -1], [-1, 5], [0, 0], [3, 7], [9_007_199_254, 1], [9_007_199_255, 1], [9_007_199_254_740_991, 1_000_000], [9_007_199_254_740_991, 999_999], [1, 3]]) {
  const r = pca.ratioPpm(a, b);
  push({ kind: 'ratio', name: `ratio/${a}/${b}`, a, b, want_ok: r !== null, want: r ?? 0 });
}
const RULES = { 'pii.*': ['a.example'], 'pii.identity.*': ['b.example'], 'pii.identity': ['c.example'], 'fin.*': ['d.example'], 'fin.card.*': ['e.example'], '*': ['z.example'] };
const RULES2 = { 'pii.*': ['a.example'], 'pii.identity.*': ['b.example'] };
const RULES3 = { 'p.*': ['x'], 'pi.*': ['y'] };
const RULES4 = { 'pii.identity': ['c.example'], 'pii.*': ['a.example'], fin: ['x'] };
const RULES5 = { 'pii.identity': ['c.example'], fin: ['x'] };
const RULES6 = { '': ['x', 'origin.example'], 'pii.identity': ['c.example'] };
for (const [rn, rules] of Object.entries({ RULES, RULES2, RULES3, RULES4, RULES5, RULES6, EMPTY: {}, STAR: { '*': ['z.example'] } })) {
  for (const cls of ['pii.identitz', 'pii.identityx', 'fix', 'fi', 'finance', 'pii.identity', 'pii.identity.passport', 'pii.contact', 'piix', 'pii', 'fin.card.pan', 'fin.card', 'other', 'public', 'pi.x', 'p.x', 'pii.', 'x']) {
    const r = pca.flowRuleFor(rules, cls);
    push({ kind: 'flowRule', name: `flowRule/${rn}/${cls}`, rules, cls, want_ok: r !== undefined, want: r ?? '' });
    for (const aud of ['a.example', 'b.example', 'c.example', 'z.example', 'origin.example', 'y', 'x']) {
      push({ kind: 'flowAllowed', name: `flowAllowed/${rn}/${cls}/${aud}`, rules, cls, origin: 'origin.example', aud, want: pca.flowAllowed(rules, cls, 'origin.example', aud) });
    }
  }
}

// ---------------------------------------------------------------- rule 16 decisions
const worldOut = (r) => (r.ok ? { ok: true, world: r.world, single_source: r.single_source } : { ok: false });
function world(name, input) {
  const r = pca.decideIntentWorld(clone(input));
  push({ kind: 'world', name: `world/${name}`, input: clone(input), expect: worldOut(r), ts_reason: r.reason ?? '' });
}
const fact = (i, nm, value, t_obs = NOW - 1_000, subject = 'OF-2', kid = `o${i + 1}`, key = O[i]) => pca.signFact({ name: nm, subject, value, t_obs, oracle: kid }, key.sk);
const rawFact = (i, body, key = O[i]) => pca.signArtifact(pca.FACT_DOMAIN, body, key.sk);
const oracles = () => [pin(0), pin(1), pin(2)];
const fareWorld = (over = {}) => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: oracles(), freshness_ms: 60_000, min_oracles: 3, max_faulty: 1, ...over });
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900, pax: 2 } };
const W = (facts, policy, over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { facts: facts.map(pca.factRef) }, facts, policy, ...over });
const three = () => [fact(0, 'fare', 39_800), fact(1, 'fare', 39_900), fact(2, 'fare', 1)];
const one = (over = {}) => fareWorld({ min_oracles: 1, max_faulty: 0, ...over });

world('base-three', W(three(), { worlds: [fareWorld()] }));
// committed list bounds (16 / 17) with distinct facts from 16 single-source worlds
{
  const mkN = (n) => Array.from({ length: n }, (_, i) => fact(0, `w${i}`, i));
  const pol = (n) => ({ worlds: Array.from({ length: Math.min(n, 16) }, (_, i) => one({ name: `w${i}`, oracles: [pin(0)] })) });
  world('committed-16', W(mkN(16), pol(16)));
  const f17 = mkN(16);
  world('committed-17', { ...W(f17, pol(16)), committed: { facts: [...f17.map(pca.factRef), D32] } });
}
world('committed-dup', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: [pca.factRef(three()[0]), pca.factRef(three()[0])] } });
world('committed-not-digest', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: [pca.factRef(three()[0]), 'abc'] } });
world('committed-digest-number', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: [7] } });
world('committed-offer-bad', { ...W(three(), { worlds: [fareWorld()] }), committed: { facts: three().map(pca.factRef), offer_set: 'abc' } });
world('offer-set-array', { ...W(three(), { worlds: [fareWorld()] }), offer_set: [] });
world('facts-object', { ...W(three(), { worlds: [fareWorld()] }), facts: {} });
// a malformed supplied fact (unsigned extra member) whose ref is committed: unmatched
{
  const f = three();
  const bad = { ...f[0], v: 2 };
  world('committed-malformed', { ...W(f, { worlds: [fareWorld()] }), facts: [bad, f[1], f[2]], committed: { facts: [pca.factRef(bad), pca.factRef(f[1]), pca.factRef(f[2])] } });
  // properly signed but malformed facts: wire-invalid bodies signed by the pinned key
  const signedBad = (i, over) => rawFact(i, { v: 1, kind: 'pca-fact', name: 'fare', subject: 'OF-2', value: 5, t_obs: NOW - 1_000, oracle: `o${i + 1}`, ...over });
  for (const [nm, over] of Object.entries({
    v2: { v: 2 }, kind: { kind: 'x' }, 'name-upper': { name: 'Fare' }, 'subject-257': { subject: s(257) }, 'subject-empty': { subject: '' },
    'value-257': { value: s(257) }, 'value-float': { value: 1.5 }, 't_obs-neg': { t_obs: -1 }, 't_obs-float': { t_obs: 1.5 }, 'oracle-65': { oracle: s(65) }, extra: { note: 'x' },
  })) {
    const fs3 = [signedBad(0, over), fact(1, 'fare', 6), fact(2, 'fare', 7)];
    world(`signed-malformed-${nm}`, W(fs3, { worlds: [fareWorld()] }));
  }
  // boundary-valid facts (accepted)
  const okFact = (over, action = ACTION) => W([rawFact(0, { v: 1, kind: 'pca-fact', name: 'fare', subject: 'OF-2', value: 5, t_obs: NOW - 1_000, oracle: 'o1', ...over })], { worlds: [one()] }, { action });
  world('fact-subject-256', okFact({ subject: s(256) }, { ...ACTION, params: { ...ACTION.params, offer_id: s(256) } }));
  world('fact-value-256', okFact({ value: s(256) }));
  world('fact-t_obs-0', { ...okFact({ t_obs: 0 }), policy: { worlds: [one({ freshness_ms: NOW })] } });
  world('fact-oracle-64', { ...okFact({ oracle: s(64) }), policy: { worlds: [one({ oracles: [{ kid: s(64), pk: O[0].pk }] })] } });
}
world('fact-undeclared-world-first', W([fact(0, 'tier', 'gold'), ...three()], { worlds: [fareWorld()] }));
world('fact-unpinned-first', W([fact(0, 'fare', 1, NOW - 1_000, 'OF-2', 'o9'), fact(1, 'fare', 2), fact(2, 'fare', 3)], { worlds: [fareWorld()] }));
world('fact-second-world-pin', W([fact(0, 'fare', 1), fact(1, 'fare', 2), fact(2, 'fare', 3), fact(0, 'tier', 4, NOW - 1_000, 'OF-2', 'o1')], { worlds: [fareWorld(), one({ name: 'tier', oracles: [pin(1)] })] }));
world('fact-two-worlds-ok', W([fact(0, 'fare', 1), fact(1, 'fare', 2), fact(2, 'fare', 3), fact(1, 'tier', 4)], { worlds: [fareWorld(), one({ name: 'tier', oracles: [pin(1)] })] }));
world('fact-subject-resource', W([fact(0, 'fare', 1, NOW - 1_000, 'skyair.example/bookings')], { worlds: [one({ subject_path: 'action.resource' })] }));
world('fact-subject-verb', W([fact(0, 'fare', 1, NOW - 1_000, 'air.book')], { worlds: [one({ subject_path: 'action.verb' })] }));
world('fact-subject-verb-mismatch', W([fact(0, 'fare', 1, NOW - 1_000, 'OF-2')], { worlds: [one({ subject_path: 'action.verb' })] }));
world('fact-subject-param-number', W([fact(0, 'fare', 1, NOW - 1_000, '2')], { worlds: [one({ subject_path: 'action.params.pax' })] }));
world('fact-subject-param-missing', W([fact(0, 'fare', 1, NOW - 1_000, 'OF-2')], { worlds: [one({ subject_path: 'action.params.nope' })] }));
world('fact-subject-other-action', W([fact(0, 'fare', 1, NOW - 1_000, 'x')], { worlds: [one({ subject_path: 'action.other' })] }));
world('fact-subject-no-params', W([fact(0, 'fare', 1, NOW - 1_000, 'OF-2')], { worlds: [one()] }, { action: { verb: 'air.book', resource: 'r' } }));
world('fact-dup-pair-two-worlds', W([fact(0, 'fare', 1), fact(0, 'tier', 2)], { worlds: [one(), one({ name: 'tier' })] }));
// freshness boundaries per world
world('fresh-exact', W([fact(0, 'fare', 1, NOW - 60_000)], { worlds: [one()] }));
world('fresh-over', W([fact(0, 'fare', 1, NOW - 60_001)], { worlds: [one()] }));
world('future-exact', W([fact(0, 'fare', 1, NOW + 60_000)], { worlds: [one()] }));
world('future-over', W([fact(0, 'fare', 1, NOW + 60_001)], { worlds: [one()] }));
world('skew-5-exact', W([fact(0, 'fare', 1, NOW + 5)], { worlds: [one()], skew_ms: 5 }));
world('skew-5-over', W([fact(0, 'fare', 1, NOW + 6)], { worlds: [one()], skew_ms: 5 }));
world('fresh-0-now', W([fact(0, 'fare', 1, NOW)], { worlds: [one({ freshness_ms: 0 })] }));
world('fresh-0-past', W([fact(0, 'fare', 1, NOW - 1)], { worlds: [one({ freshness_ms: 0 })] }));
world('min-2-of-3-one-stale', W([fact(0, 'fare', 1, NOW - 70_000), fact(1, 'fare', 2), fact(2, 'fare', 3)], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }));
world('min-3-one-other-world', W([fact(0, 'fare', 1), fact(1, 'fare', 2), fact(2, 'tier', 3)], { worlds: [fareWorld(), one({ name: 'tier', oracles: [pin(2)] })] }));
// medians
world('median-two', W([fact(0, 'fare', 10), fact(1, 'fare', 20)], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }));
world('median-five', W([fact(0, 'fare', 50), fact(1, 'fare', 10), fact(2, 'fare', 40), fact(3, 'fare', 20, NOW - 1_000, 'OF-2', 'o4', O[3])], { worlds: [fareWorld({ min_oracles: 3, oracles: [...oracles(), pin(3)] })] }));
world('median-negative', W([fact(0, 'fare', -10), fact(1, 'fare', 5), fact(2, 'fare', -20)], { worlds: [fareWorld()] }));
world('min-0-no-facts', W([], { worlds: [one({ min_oracles: 0 })] }));
world('min-0-strings', W([fact(0, 'fare', 'a')], { worlds: [one({ min_oracles: 0 })] }));
world('strings-two-agree', W([fact(0, 'fare', 'a'), fact(1, 'fare', 'a')], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }));
world('strings-two-disagree', W([fact(0, 'fare', 'a'), fact(1, 'fare', 'b')], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }));
world('mix-string-first', W([fact(0, 'fare', 'a'), fact(1, 'fare', 2)], { worlds: [fareWorld({ min_oracles: 2, max_faulty: 0 })] }));
world('single-source-two', W([fact(0, 'fare', 1), fact(1, 'tier', 2)], { worlds: [one(), one({ name: 'tier', oracles: [pin(1)] }), fareWorld({ name: 'none', min_oracles: 0, max_faulty: 0 })] }));
// relational
const R = (rel, params = {}) => W([], { relational: rel }, { action: { ...ACTION, params: { ...ACTION.params, ...params } } });
world('rel-sub-zero', R([{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.total' }]));
world('rel-ratio-1', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.one', b: 'action.params.one' }], { one: 1 }));
world('rel-ratio-a-zero', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.zero', b: 'action.params.one' }], { zero: 0, one: 1 }));
world('rel-ratio-floor', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.one', b: 'action.params.three' }], { one: 1, three: 3 }));
world('rel-ratio-b-neg', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.one', b: 'action.params.neg' }], { one: 1, neg: -3 }));
world('rel-ratio-max', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.big', b: 'action.params.one' }], { big: 9_007_199_254, one: 1 }));
world('rel-ratio-over', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.big', b: 'action.params.one' }], { big: 9_007_199_255, one: 1 }));
world('rel-ratio-exact-max', R([{ name: 'r', fn: 'ratio_ppm', a: 'action.params.big', b: 'action.params.m' }], { big: 9_007_199_254_740_991, m: 1_000_000 }));
world('rel-sub-max', R([{ name: 'r', fn: 'sub', a: 'action.params.big', b: 'action.params.zero' }], { big: 9_007_199_254_740_991, zero: 0 }));
world('rel-sub-min', R([{ name: 'r', fn: 'sub', a: 'action.params.zero', b: 'action.params.big' }], { big: 9_007_199_254_740_991, zero: 0 }));
world('rel-sub-under', R([{ name: 'r', fn: 'sub', a: 'action.params.neg', b: 'action.params.big' }], { big: 9_007_199_254_740_991, neg: -1 }));
world('rel-operand-float', R([{ name: 'r', fn: 'sub', a: 'action.params.f', b: 'action.params.total' }], { f: 1.5 }));
world('rel-operand-a-missing', R([{ name: 'r', fn: 'sub', a: 'action.params.nope', b: 'action.params.total' }]));
world('rel-operand-nested', R([{ name: 'r', fn: 'sub', a: 'action.params.o.x', b: 'action.params.total' }], { o: { x: 5 } }));
world('rel-env-string-world', W([fact(0, 'fare', 'gold')], { worlds: [one()], relational: [{ name: 'r', fn: 'sub', a: 'env.world.fare', b: 'action.params.total' }] }));
world('rel-env-world-b', W([fact(0, 'fare', 100)], { worlds: [one()], relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'env.world.fare' }, { name: 'q', fn: 'ratio_ppm', a: 'env.world.r', b: 'env.world.fare' }] }));
world('rel-no-params', { ...R([{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }]), action: { verb: 'v', resource: 'r' } });
world('rel-params-null', { ...R([]), action: { verb: 'v', resource: 'r', params: null } });
world('rel-params-null-nopolicy', { now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r', params: null }, committed: {}, policy: {} });
// now handling
world('now-absent', (() => { const i = W(three(), { worlds: [fareWorld()] }); delete i.now; return i; })());
world('now-absent-relational', (() => { const i = R([{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }]); delete i.now; return i; })());
world('now-unsafe', { ...W(three(), { worlds: [fareWorld()] }), now: 2 ** 60 });
// offers
const OFFERS = [
  { offer_id: 'OF-1', price: 38_900, stops: 1, refundable: false },
  { offer_id: 'OF-2', price: 39_800, stops: 0, refundable: false },
  { offer_id: 'OF-3', price: 41_200, stops: 0, refundable: true },
];
const QUERY = { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 };
const offerSet = (over = {}, key = SITE) => pca.signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, key.sk);
const rawOS = (over = {}, key = SITE) => pca.signArtifact(pca.OFFER_SET_DOMAIN, { v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, key.sk);
const offerPolicy = (over = {}) => ({ name: 'excess_cents', site_keys: [{ kid: 'other', pk: GOV.pk }, { kid: 'skyair-2026', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: QUERY, offer: { refundable: false } }, ...over });
const OS = (os, policy = offerPolicy(), over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { offer_set: pca.offerSetRef(os) }, offer_set: os, policy: { offers: policy }, ...over });
const withOffer = (id) => ({ action: { ...ACTION, params: { ...ACTION.params, offer_id: id } } });
world('os-base', OS(offerSet()));
world('os-second-key', OS(offerSet({ kid: 'other' }, GOV)));
world('os-not-committed', { ...OS(offerSet()), committed: {} });
world('os-not-supplied', (() => { const i = OS(offerSet()); delete i.offer_set; return i; })());
world('os-committed-no-policy', { ...OS(offerSet()), policy: {} });
for (const [nm, over] of Object.entries({
  extra: { note: 'x' }, v2: { v: 2 }, kind: { kind: 'x' }, 'site-257': { site: s(257) }, 'session-bad': { session: 'x' }, 'query-null': { query: null },
  'query-33': { query: attrs(33) }, 'query-key-65': { query: { [s(65)]: 1 } }, 'query-obj': { query: { a: { b: 1 } } }, rank: { rank: 'x' }, 'complete-string': { complete: 'yes' },
  'offers-empty': { offers: [] }, 'offers-257': { offers: Array.from({ length: 257 }, (_, i) => ({ offer_id: `o${i}`, price: i })) }, 'offer-id-129': { offers: [{ offer_id: s(129), price: 1 }] },
  'offer-dup': { offers: [{ offer_id: 'OF-2', price: 1 }, { offer_id: 'OF-2', price: 2 }] }, 'price-neg': { offers: [{ offer_id: 'OF-2', price: -1 }] }, 'price-float': { offers: [{ offer_id: 'OF-2', price: 0.5 }] },
  'attrs-33': { offers: [{ offer_id: 'OF-2', price: 1, ...attrs(33) }] }, 'attr-key-65': { offers: [{ offer_id: 'OF-2', price: 1, [s(65)]: 1 }] }, 'attr-obj': { offers: [{ offer_id: 'OF-2', price: 1, x: [1] }] },
  'issued-neg': { issued_at: -1 }, 'issued-float': { issued_at: 0.5 }, 'kid-65': { kid: s(65) }, 'offer-null': { offers: [null] },
})) world(`os-signed-malformed-${nm}`, OS(rawOS(over)));
// boundary-valid offer sets
world('os-site-256', OS(rawOS({ site: s(256) }), offerPolicy(), { aud: s(256) }));
world('os-query-32', OS(rawOS({ query: attrs(32) }), offerPolicy({ filter: { query: attrs(32), offer: {} } })));
world('os-query-key-64', OS(rawOS({ query: { [s(64)]: 1 } }), offerPolicy({ filter: { query: { [s(64)]: 1 }, offer: {} } })));
world('os-offers-256', OS(rawOS({ offers: Array.from({ length: 256 }, (_, i) => ({ offer_id: i === 0 ? 'OF-2' : `o${i}`, price: 1000 - i })) }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-offer-id-128', OS(rawOS({ offers: [{ offer_id: s(128), price: 1 }] }), offerPolicy({ filter: { query: QUERY, offer: {} } }), withOffer(s(128))));
world('os-price-0', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 0 }, { offer_id: 'OF-1', price: 0 }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-attrs-32', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 1, ...attrs(32) }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-attr-key-64', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 1, [s(64)]: 1 }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-issued-0', OS(rawOS({ issued_at: 0 }), offerPolicy({ max_age_ms: NOW })));
world('os-kid-64', OS(rawOS({ kid: s(64) }), offerPolicy({ site_keys: [{ kid: s(64), pk: SITE.pk }] })));
world('os-complete-false', OS(rawOS({ complete: false })));
world('os-unpinned', OS(offerSet({ kid: 'nobody' })));
world('os-wrong-key', OS(offerSet({}, ROGUE)));
world('os-other-site', OS(offerSet({ site: 'evil.example' })));
world('os-other-session', OS(offerSet({ session: OTHER_SESSION })));
world('os-no-clock', { ...OS(offerSet()), now: 'x' });
world('os-future-exact', OS(offerSet({ issued_at: NOW + 60_000 })));
world('os-future-over', OS(offerSet({ issued_at: NOW + 60_001 })));
world('os-skew0-future', { ...OS(offerSet({ issued_at: NOW + 1 })), policy: { skew_ms: 0, offers: offerPolicy() } });
world('os-age-exact', OS(offerSet({ issued_at: NOW - 600_000 })));
world('os-age-over', OS(offerSet({ issued_at: NOW - 600_001 })));
world('os-age-0', OS(offerSet({ issued_at: NOW }), offerPolicy({ max_age_ms: 0 })));
world('os-age-0-over', OS(offerSet({ issued_at: NOW - 1 }), offerPolicy({ max_age_ms: 0 })));
world('os-narrowed', OS(offerSet({ query: { ...QUERY, stops: 0 } })));
world('os-narrowed-value', OS(offerSet({ query: { ...QUERY, pax: 3 } })));
world('os-param-missing', OS(offerSet(), offerPolicy(), { action: { ...ACTION, params: { total: 1 } } }));
world('os-param-number', OS(offerSet(), offerPolicy(), withOffer(7)));
world('os-param-nested', OS(offerSet(), offerPolicy({ offer_param: 'action.params.sel.id' }), { action: { ...ACTION, params: { ...ACTION.params, sel: { id: 'OF-1' } } } }));
world('os-chosen-missing', OS(offerSet(), offerPolicy(), withOffer('OF-9')));
world('os-chosen-filtered', OS(offerSet(), offerPolicy(), withOffer('OF-3')));
world('os-chosen-cheapest', OS(offerSet(), offerPolicy(), withOffer('OF-1')));
world('os-tie-min', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 5 }, { offer_id: 'OF-1', price: 5 }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-filter-missing-attr', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { meal: true } } })));
world('os-filter-multi', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { refundable: false, stops: 0 } } })));
world('os-cheaper-filtered-out', OS(offerSet(), offerPolicy({ filter: { query: QUERY, offer: { stops: 0 } } }), withOffer('OF-3')));
world('os-alg-unsupported', OS({ ...offerSet(), alg: 'no-such-suite' }));
world('os-ref-mismatch', { ...OS(offerSet()), committed: { offer_set: pca.offerSetRef(offerSet({ issued_at: NOW - 9_000 })) } });
world('os-with-facts-fail-first', { ...W([fact(0, 'fare', 1)], { worlds: [one()], offers: offerPolicy() }), committed: { facts: [pca.factRef(fact(0, 'fare', 1))] } });

// ---------------------------------------------------------------- rule 17 decisions
const provOut = (r) => (r.outcome === 'deny' ? { outcome: 'deny' } : { outcome: r.outcome, labels: r.labels, classes: r.classes, ...(r.outcome === 'question' ? { friction: r.friction } : {}) });
function prov(name, input) {
  const r = pca.decideParamProvenance(clone(input));
  push({ kind: 'prov', name: `prov/${name}`, input: clone(input), expect: provOut(r), ts_reason: r.reason ?? '' });
}
const PARAMS = { offer_id: 'OF-1', payment_ref: 'pm_ana_visa', add_ons: 'tripshield', passport: 'X1234567', note: 'hi', pax: { lead: 'px_ana' } };
const POLICY = {
  params: { 'action.params.offer_id': 'material', 'action.params.add_ons': 'material', 'action.params.payment_ref': 'critical', 'action.params.passport': 'critical' },
  registry: { 'skyair:offer_set:1': 'first_party', 'wallet:profile:ana': 'trusted', 'web:ad': 'web', 'tool:fx': 'tool', 'agent:planner': 'agent' },
  label_keys: [{ site: 'gov.example', kid: 'g1', pk: GOV.pk }, { site: AUD, kid: 'k1', pk: SITE.pk }],
};
const CLEAN = { 'action.params.offer_id': ['skyair:offer_set:1'], 'action.params.payment_ref': ['wallet:profile:ana'], 'action.params.add_ons': ['wallet:profile:ana'], 'action.params.passport': ['wallet:profile:ana'] };
const P = (provOver = {}, policyOver = {}, over = {}) => ({ aud: AUD, session: SESSION, action: { params: PARAMS }, prov: { ...CLEAN, ...provOver }, policy: { ...POLICY, ...policyOver }, ...over });
const receipt = (site, key, kid, fields, session = SESSION) => pca.signLabels({ site, session, response_digest: pca.b64u(seed('wb/response')), fields, issued_at: NOW - 5_000, kid }, key.sk);
const rawReceipt = (over, key = SITE) => pca.signArtifact(pca.LABELS_DOMAIN, { v: 1, kind: 'pca-labels', site: AUD, session: SESSION, response_digest: pca.b64u(seed('wb/response')), fields: { pp: { class: 'pii.identity', value_digest: pca.hashCanonical('X1234567') } }, issued_at: NOW - 5_000, kid: 'k1', ...over }, key.sk);
const HX = pca.hashCanonical('X1234567');
const PASSPORT = receipt(AUD, SITE, 'k1', { pp: { class: 'pii.identity', value_digest: HX } });
const GOVR = receipt('gov.example', GOV, 'g1', { passport: { class: 'pii.identity', value_digest: HX }, card: { class: 'fin.card', value_digest: HX }, pub: { class: 'public', value_digest: HX }, name: { class: 'pii.contact', value_digest: pca.hashCanonical('Ana') } });
const lref = (r, f) => `pca-labels:${pca.labelsRef(r)}#${f}`;
const withRefs = (receipts, provOver, extra = {}) => ({ committed_labels: receipts.map(pca.labelsRef), labels: receipts, ...extra, prov: { ...CLEAN, ...provOver } });

prov('clean', P());
prov('policy-null', { ...P(), policy: null });
prov('policy-bad-registry', P({}, { registry: { x: 'super' } }));
prov('prov-absent', (() => { const p = P(); delete p.prov; return p; })());
prov('prov-null', { ...P(), prov: null });
prov('params-null', { ...P(), action: { params: null } });
prov('params-absent', { ...P(), action: {}, prov: {} });
prov('prov-bad', P({ 'action.params.offer_id': [] }));
prov('prov-33', { ...P(), action: { params: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`p${i}`, i])) }, prov: pv(33), policy: { params: {} } });
prov('prov-32', { ...P(), action: { params: Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`p${i}`, i])) }, prov: pv(32), policy: { params: {} } });
prov('refs-8', P({ 'action.params.offer_id': Array.from({ length: 8 }, (_, i) => `r${i}`) }));
prov('ref-256', P({ 'action.params.offer_id': [s(256)] }));
prov('committed-16', { ...P(), committed_labels: Array.from({ length: 16 }, (_, i) => pca.b64u(seed(`wb/l${i}`))) });
prov('committed-17', { ...P(), committed_labels: Array.from({ length: 17 }, (_, i) => pca.b64u(seed(`wb/l${i}`))) });
prov('committed-dup', { ...P(), committed_labels: [D32, D32] });
prov('committed-bad', { ...P(), committed_labels: ['abc'] });
prov('committed-null', { ...P(), committed_labels: null });
prov('labels-null', { ...P(), labels: null });
prov('labels-object', { ...P(), labels: {} });
prov('prov-not-carried', P({ 'action.params.seat': ['x'] }));
prov('prov-not-carried-sorted', P({ 'action.params.zzz': ['x'], 'action.params.aaa': ['x'] }));
prov('registry-level', P({ 'action.params.offer_id': ['tool:fx'] }));
prov('registry-agent', P({ 'action.params.offer_id': ['agent:planner'] }));
prov('registry-none', P({ 'action.params.offer_id': ['nope'] }, { registry: undefined }));
prov('join-trusted-first', P({ 'action.params.offer_id': ['wallet:profile:ana', 'skyair:offer_set:1'] }));
prov('join-web-tool', P({ 'action.params.offer_id': ['web:ad', 'tool:fx'] }));
prov('join-tool-web', P({ 'action.params.offer_id': ['tool:fx', 'web:ad'] }));
prov('join-all-trusted', P({ 'action.params.offer_id': ['wallet:profile:ana', 'wallet:profile:ana'] }));
prov('free-trusted', P({ 'action.params.note': ['wallet:profile:ana'] }));
// label refs
prov('label-first-party', P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-foreign-no-flow', P({}, {}, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-public', P({}, {}, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'pub')] })));
prov('label-foreign-flow', P({}, { flows: { 'pii.*': [AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-flow-other', P({}, { flows: { 'pii.*': ['x.example'] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-specific', P({}, { flows: { 'pii.*': [AUD], 'pii.identity': ['x'] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-star', P({}, { flows: { '*': [AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-prefix-longest', P({}, { flows: { 'pii.*': ['x'], 'pii.identity.*': [AUD], 'p.*': [AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-two-classes', P({}, { flows: { '*': [AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport'), lref(GOVR, 'card'), lref(GOVR, 'passport'), lref(GOVR, 'pub')] })));
prov('label-two-classes-sorted', P({}, { flows: { '*': [AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'pub'), lref(GOVR, 'card'), lref(GOVR, 'name')] })));
prov('label-two-params', P({}, { flows: { 'fin.*': [AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')], 'action.params.payment_ref': [lref(GOVR, 'card')] })));
prov('label-mismatch-value', P({}, {}, withRefs([PASSPORT], { 'action.params.offer_id': [lref(PASSPORT, 'pp')] })));
prov('label-and-web', P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp'), 'web:ad'] })));
prov('label-ref-no-hash', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASSPORT)}`] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [PASSPORT] }));
prov('label-ref-empty-field', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASSPORT)}#`] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [PASSPORT] }));
prov('label-ref-bad-digest', P({ 'action.params.passport': ['pca-labels:abc#pp'] }));
prov('label-ref-hash-first', P({ 'action.params.passport': ['pca-labels:#pp'] }));
prov('label-ref-two-hashes', P({ 'action.params.passport': [`pca-labels:${pca.labelsRef(PASSPORT)}#pp#x`] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [PASSPORT] }));
prov('label-ref-prefix-only', P({ 'action.params.passport': ['pca-labels:'] }));
prov('label-ref-like', P({ 'action.params.passport': ['pca-label:x#y'] }));
prov('label-uncommitted', { ...P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })), committed_labels: [] });
prov('label-not-supplied', { ...P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })), labels: [] });
prov('label-unpinned', (() => { const r = receipt(AUD, SITE, 'k9', PASSPORT.fields); return P({}, {}, withRefs([r], { 'action.params.passport': [lref(r, 'pp')] })); })());
prov('label-site-mismatch', (() => { const r = receipt('gov.example', SITE, 'k1', PASSPORT.fields); return P({}, {}, withRefs([r], { 'action.params.passport': [lref(r, 'pp')] })); })());
prov('label-bad-sig', (() => { const r = receipt(AUD, ROGUE, 'k1', PASSPORT.fields); return P({}, {}, withRefs([r], { 'action.params.passport': [lref(r, 'pp')] })); })());
prov('label-other-session', (() => { const r = receipt(AUD, SITE, 'k1', PASSPORT.fields, OTHER_SESSION); return P({}, {}, withRefs([r], { 'action.params.passport': [lref(r, 'pp')] })); })());
prov('label-no-field', P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'nope')] })));
prov('label-alg-unsupported', (() => { const r = { ...PASSPORT, alg: 'no-such-suite' }; return P({}, {}, withRefs([r], { 'action.params.passport': [lref(r, 'pp')] })); })());
for (const [nm, over] of Object.entries({
  extra: { note: 'x' }, v2: { v: 2 }, kind: { kind: 'x' }, 'site-257': { site: s(257) }, 'session-bad': { session: 'x' }, 'resp-bad': { response_digest: 'x' },
  'fields-empty': { fields: {} }, 'fields-65': { fields: lfields(65) }, 'field-key-257': { fields: { [s(257)]: { class: 'x', value_digest: HX } } }, 'field-extra': { fields: { pp: { class: 'x', value_digest: HX, y: 1 } } },
  'class-129': { fields: { pp: { class: s(129, 'a'), value_digest: HX } } }, 'class-bad': { fields: { pp: { class: 'X!', value_digest: HX } } }, 'digest-bad': { fields: { pp: { class: 'x', value_digest: 'x' } } },
  'issued-neg': { issued_at: -1 }, 'issued-float': { issued_at: 0.5 }, 'kid-65': { kid: s(65) }, 'field-null': { fields: { pp: null } },
})) {
  const r = rawReceipt(over);
  prov(`label-signed-malformed-${nm}`, P({}, {}, withRefs([r], { 'action.params.passport': [lref(r, 'pp')] })));
}
{
  const ok = (nm, over, f = 'pp', pol = {}) => { const r = rawReceipt(over); prov(`label-signed-ok-${nm}`, P({}, pol, withRefs([r], { 'action.params.passport': [lref(r, f)] }))); };
  ok('fields-64', { fields: { ...lfields(63), pp: { class: 'x', value_digest: HX } } });
  ok('field-key-256', { fields: { [s(256)]: { class: 'x', value_digest: HX } } }, s(256));
  ok('class-128', { fields: { pp: { class: s(128, 'a'), value_digest: HX } } });
  ok('issued-0', { issued_at: 0 });
  ok('kid-64', { kid: s(64) }, 'pp', { label_keys: [{ site: AUD, kid: s(64), pk: SITE.pk }] });
  ok('site-256', { site: s(256) }, 'pp', { label_keys: [{ site: s(256), kid: 'k1', pk: SITE.pk }], flows: { '*': [AUD] } });
}
// first failure in ascending prov-path order (the reason names the first failing path's problem)
{
  const bad = 'pca-labels:abc#pp';
  const unc = lref(PASSPORT, 'pp');
  const nf = lref(PASSPORT, 'nope');
  prov('order-a-malformed-p-uncommitted', P({ 'action.params.add_ons': [bad], 'action.params.passport': [unc] }));
  prov('order-a-uncommitted-p-malformed', P({ 'action.params.add_ons': [unc], 'action.params.passport': [bad] }));
  prov('order-o-malformed-p-nofield', P({ 'action.params.offer_id': [bad], 'action.params.passport': [nf] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [PASSPORT] }));
  prov('order-o-nofield-p-malformed', P({ 'action.params.offer_id': [nf], 'action.params.passport': [bad] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [PASSPORT] }));
  prov('order-a-unsupplied-pa-malformed', P({ 'action.params.add_ons': [unc], 'action.params.payment_ref': [bad] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [] }));
  prov('order-a-malformed-pa-unsupplied', P({ 'action.params.add_ons': [bad], 'action.params.payment_ref': [unc] }, {}, { committed_labels: [pca.labelsRef(PASSPORT)], labels: [] }));
  prov('order-four', P({ 'action.params.add_ons': [unc], 'action.params.offer_id': [bad], 'action.params.passport': [nf], 'action.params.payment_ref': [bad] }, {}, { committed_labels: [], labels: [PASSPORT] }));
  prov('order-four-b', P({ 'action.params.add_ons': [bad], 'action.params.offer_id': [nf], 'action.params.passport': [unc], 'action.params.payment_ref': [nf] }, {}, { committed_labels: [], labels: [PASSPORT] }));
}
// overlaps / prefixes
prov('overlap-policy-params', P({}, { params: { 'action.params.pax': 'material', 'action.params.pax.lead': 'material' } }, { prov: {} }));
prov('overlap-two-policy', P({}, { params: { 'action.params.pax.lead': 'critical' } }, { prov: { 'action.params.pax': ['web:ad'] } }));
prov('prov-same-prefix-names', { ...P(), action: { params: { ...PARAMS, offer: 'x', offer_id: 'y' } }, prov: { ...CLEAN, 'action.params.offer': ['web:ad'] } });
prov('policy-param-absent', P({}, { params: { ...POLICY.params, 'action.params.seat': 'critical' } }));
prov('policy-param-nested-present', P({}, { params: { ...POLICY.params, 'action.params.pax.lead': 'critical' } }));
// critical max, modes
for (const cmax of ['trusted', 'first_party', 'tool', 'web', 'agent']) {
  for (const lvl of ['wallet:profile:ana', 'skyair:offer_set:1', 'tool:fx', 'web:ad', 'agent:planner']) {
    prov(`cmax-${cmax}-${lvl}`, P({ 'action.params.payment_ref': [lvl] }, { critical_max: cmax, critical_tainted: 'question' }));
  }
}
for (const mode of ['question', 'question_typed', 'deny']) prov(`ct-${mode}`, P({ 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: mode }));
for (const mode of ['allow', 'question', 'question_typed', 'deny']) prov(`mt-${mode}`, P({ 'action.params.add_ons': ['tool:fx'] }, { material_tainted: mode }));
prov('mt-first-party', P({ 'action.params.add_ons': ['skyair:offer_set:1'] }, { material_tainted: 'deny' }));
prov('ct-first-party', P({ 'action.params.payment_ref': ['skyair:offer_set:1'] }, { critical_tainted: 'deny' }));
prov('mix-typed-and-tap', P({ 'action.params.add_ons': ['web:ad'], 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: 'question_typed', material_tainted: 'question' }));
prov('mix-allow-and-tap', P({ 'action.params.add_ons': ['web:ad'], 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: 'question', material_tainted: 'allow' }));
prov('free-tainted', P({ 'action.params.note': ['web:ad'] }, { material_tainted: 'deny', critical_tainted: 'deny' }));
prov('deny-and-question', P({ 'action.params.add_ons': ['web:ad'], 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: 'deny', material_tainted: 'question' }));
prov('cmax-deny-before-mode', P({ 'action.params.payment_ref': ['web:ad'], 'action.params.add_ons': ['web:ad'] }, { critical_max: 'tool', material_tainted: 'deny' }));
prov('flow-deny-before-cmax', P({ 'action.params.payment_ref': ['web:ad'] }, { critical_max: 'trusted' }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));

// ---------------------------------------------------------------- rule 18 decisions
const clsOut = (r) => (r.ok ? { ok: true, classes: r.classes } : { ok: false });
function cls(name, input) {
  const r = pca.decideClassifierDimensions(clone(input));
  push({ kind: 'cls', name: `cls/${name}`, input: clone(input), expect: clsOut(r), ts_reason: r.reason ?? '' });
}
const MESSAGE = 'We are sorry for the delay.';
const TONE = { id: 'tone', param: 'action.params.body', labels: ['neutral', 'apologetic', 'hostile', 'other'], keys: J.map((j) => j.pk), k: 2, measurements: ['m-tone-1'] };
const SPAM = { id: 'spam', param: 'action.params.body', labels: ['ham', 'spam'], keys: [J[0].pk, J[1].pk], k: 1 };
const verdict = (j, label, over = {}) => pca.signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(MESSAGE), label, measurement: 'm-tone-1', ...over }, j.sk);
const rawVerdict = (j, over) => pca.signArtifact(pca.INTENT_CLASSIFIER_DOMAIN, { v: 1, kind: 'pca-intent-classification', classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(MESSAGE), label: 'apologetic', measurement: 'm-tone-1', judge: j.pk, ...over }, j.sk);
const C = (verdicts, policyOver = {}, over = {}) => ({ session: SESSION, action: { params: { body: MESSAGE } }, committed: verdicts.map(pca.classifierVerdictRef), verdicts, policy: { classifiers: [{ ...TONE, ...policyOver }] }, ...over });
const two = () => [verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic')];
cls('quorum', C(two()));
cls('quorum-3', C([...two(), verdict(J[2], 'apologetic')], { k: 3 }));
cls('quorum-3-short', C(two(), { k: 3 }));
cls('two-classifiers', { ...C([...two(), verdict(J[0], 'spam', { classifier: 'spam' })]), policy: { classifiers: [TONE, SPAM] } });
cls('two-classifiers-second-none', { ...C(two()), policy: { classifiers: [TONE, SPAM] } });
cls('committed-8', { ...C(two()), committed: [...two().map(pca.classifierVerdictRef), ...Array.from({ length: 6 }, (_, i) => pca.b64u(seed(`wb/c${i}`)))] });
cls('committed-9', { ...C(two()), committed: [...two().map(pca.classifierVerdictRef), ...Array.from({ length: 7 }, (_, i) => pca.b64u(seed(`wb/c${i}`)))] });
cls('committed-dup', { ...C(two()), committed: [pca.classifierVerdictRef(two()[0]), pca.classifierVerdictRef(two()[0])] });
cls('committed-bad', { ...C(two()), committed: ['x'] });
cls('committed-obj', { ...C(two()), committed: {} });
cls('verdicts-obj', { ...C(two()), verdicts: {} });
cls('verdicts-absent', (() => { const i = C(two()); delete i.verdicts; return i; })());
cls('action-absent', (() => { const i = C(two()); delete i.action; return i; })());
cls('params-null', { ...C(two()), action: { params: null } });
cls('params-absent', { ...C(two()), action: {} });
cls('params-null-nothing-committed', { ...C([]), action: { params: null } });
cls('policy-null', { ...C(two()), policy: null });
cls('policy-bad', C(two(), { k: 9 }));
cls('undeclared', C([...two(), verdict(J[2], 'x', { classifier: 'spam' })]));
cls('off-allowlist', C([verdict(J[0], 'apologetic'), verdict(ROGUE, 'apologetic')]));
cls('bad-sig', C([verdict(J[0], 'apologetic'), { ...verdict(J[1], 'neutral'), label: 'apologetic' }]));
cls('other-session', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic', { session: OTHER_SESSION })]));
cls('param-missing', { ...C(two()), action: { params: { other: 1 } } });
cls('other-content', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic', { content_digest: pca.classifierContentDigest('x') })]));
cls('label-outside', C([verdict(J[0], 'apologetic'), verdict(J[1], 'sarcastic')]));
cls('measurement-unpinned', C([verdict(J[0], 'apologetic'), verdict(J[1], 'apologetic', { measurement: 'm-evil' })]));
cls('measurement-none-pinned', C([verdict(J[0], 'apologetic', { measurement: 'q' }), verdict(J[1], 'apologetic', { measurement: 'r' })], { measurements: undefined }));
cls('measurement-empty-pin', C(two(), { measurements: [] }));
cls('double-vote-same', C([verdict(J[0], 'apologetic'), verdict(J[0], 'apologetic', { measurement: 'm-tone-1' }), verdict(J[1], 'apologetic')].filter((v, i, a) => i !== 1 || pca.classifierVerdictRef(v) !== pca.classifierVerdictRef(a[0]))));
cls('double-vote', C([verdict(J[0], 'apologetic'), verdict(J[0], 'neutral'), verdict(J[1], 'apologetic')]));
cls('ambiguous', C([verdict(J[0], 'apologetic'), verdict(J[1], 'neutral')], { k: 1 }));
cls('no-quorum', C([verdict(J[0], 'apologetic'), verdict(J[1], 'neutral')]));
cls('first-failure-order', C([verdict(J[0], 'sarcastic'), verdict(ROGUE, 'apologetic')]));
for (const [nm, over] of Object.entries({
  extra: { note: 'x' }, v2: { v: 2 }, kind: { kind: 'x' }, 'classifier-bad': { classifier: 'Tone' }, 'session-bad': { session: 'x' }, 'content-bad': { content_digest: 'x' },
  'label-65': { label: s(65) }, 'measurement-257': { measurement: s(257) }, 'judge-bad': { judge: 'x' }, 'label-empty': { label: '' },
})) cls(`signed-malformed-${nm}`, C([verdict(J[0], 'apologetic'), rawVerdict(J[1], over)]));
cls('signed-ok-label-64', C([rawVerdict(J[0], { label: s(64) }), rawVerdict(J[1], { label: s(64) })], { labels: [s(64)] }));
cls('signed-ok-measurement-256', C([rawVerdict(J[0], { measurement: s(256) }), rawVerdict(J[1], { measurement: s(256) })], { measurements: [s(256)] }));
cls('pq-keys-unpinned-ed', C(two(), { pq_keys: { [J[0].pk]: 'pq' } }));
cls('empty-classifiers-committed', { ...C(two()), policy: { classifiers: [] } });
cls('content-structured', (() => { const body = { b: 'x', a: [1, 2] }; const v = (j) => pca.signClassifierVerdict({ classifier: 'tone', session: SESSION, content_digest: pca.classifierContentDigest(body), label: 'neutral', measurement: 'm-tone-1' }, j.sk); return { ...C([v(J[0]), v(J[1])]), action: { params: { body } } }; })());

{
  // classified content that has no strict canonical form (nesting deeper than the canonical depth limit): fail closed
  let deep = 'x';
  for (let i = 0; i < 40; i++) deep = { d: deep };
  cls('content-too-deep', { ...C(two()), action: { params: { body: deep } } });
}
// ---------------------------------------------------------------- activity, read purpose
function active(name, input) { push({ kind: 'active', name: `active/${name}`, input: clone(input), expect: pca.intentWBActive(clone(input)) }); }
active('facts-one', { intent_session: { facts: [D32] }, policy: {} });
active('facts-string', { intent_session: { facts: 'x' }, policy: {} });
active('offer-number', { intent_session: { offer_set: 1 }, policy: {} });
active('relational-list', { intent_session: {}, policy: { world: { relational: [{}] } } });
active('relational-empty', { intent_session: {}, policy: { world: { relational: [] } } });
active('worlds-empty', { intent_session: {}, policy: { world: { worlds: [] } } });
active('offers-string', { intent_session: {}, policy: { world: { offers: 'x' } } });
active('offers-null', { intent_session: {}, policy: { world: { offers: null } } });
active('labels-empty', { intent_session: { labels: [] }, policy: {} });
active('labels-string', { intent_session: { labels: 'x' }, policy: {} });
active('prov-string', { intent_session: { prov: 'x' }, policy: {} });
active('provenance-null', { intent_session: {}, policy: { provenance: null } });
active('provenance-string', { intent_session: {}, policy: { provenance: 'x' } });
active('classes-empty', { intent_session: { classes: [] }, policy: {} });
active('classifiers-empty', { intent_session: {}, policy: { classifiers: [] } });
active('classes-string', { intent_session: { classes: 'x' }, policy: {} });
active('session-absent', { policy: { classifiers: [{}] } });
active('world-array', { intent_session: {}, policy: { world: [] } });

function read(name, input) {
  const i = clone(input);
  let r;
  try { r = pca.decideReadPurpose(i.fields, i.purpose, i.coverage, ...(i.on_uncovered !== undefined ? [i.on_uncovered] : [])); } catch (e) { throw new Error(`read ${name} threw ${e}`); }
  push({ kind: 'read', name: `read/${name}`, input: clone(input), expect: r });
}
const COVER = { booking: ['pii.identity', 'itinerary'], support: ['pii.*', 'internal'], all: ['*'], comparison: [], dotted: ['pii.identity.*'] };
const FIELDS = [
  { path: 'name', class: 'pii.identity' }, { path: 'email', class: 'pii.contact', optional: true }, { path: 'loyalty', class: 'internal', optional: true },
  { path: 'fares', class: 'public' }, { path: 'pp', class: 'pii.identity.passport' }, { path: 'x', class: 'piix' }, { path: 'y', class: 'pii' },
  { path: 'opt-cov', class: 'itinerary', optional: true }, { path: 'req-false', class: 'secret', optional: false }, { path: 'dup', class: 'secret' }, { path: 'dup', class: 'secret' },
  { path: 'dupo', class: 'secret', optional: true }, { path: 'dupo', class: 'secret', optional: true },
];
for (const p of Object.keys(COVER)) read(`p-${p}`, { fields: FIELDS, purpose: p, coverage: COVER });
read('deny-mode', { fields: FIELDS, purpose: 'booking', coverage: COVER, on_uncovered: 'deny' });
read('question-mode', { fields: FIELDS, purpose: 'booking', coverage: COVER, on_uncovered: 'question' });
read('all-covered', { fields: [{ path: 'a', class: 'pii.identity' }], purpose: 'booking', coverage: COVER, on_uncovered: 'deny' });
read('empty-fields', { fields: [], purpose: 'booking', coverage: COVER });
read('coverage-entry-number', { fields: FIELDS, purpose: 'booking', coverage: { booking: [1] } });
read('field-path-number', { fields: [{ path: 1, class: 'x' }], purpose: 'booking', coverage: COVER });
read('field-class-number', { fields: [{ path: 'a', class: 1 }], purpose: 'booking', coverage: COVER });
read('field-null', { fields: [null], purpose: 'booking', coverage: COVER });
read('on-uncovered-number', { fields: FIELDS, purpose: 'booking', coverage: COVER, on_uncovered: 1 });
read('other-purpose-malformed', { fields: FIELDS, purpose: 'booking', coverage: { ...COVER, x: 'y' } });

// ---------------------------------------------------------------- the W-B unit
function wb(name, input) {
  const r = pca.decideIntentWB(clone(input));
  push({ kind: 'wb', name: `wb/${name}`, input: clone(input), expect: { outcome: r.outcome, checks: r.checks }, ts_reason: r.reason ?? '' });
}
const IS = (o = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'air.book', resource: 'r', params: { ...PARAMS, body: MESSAGE, offer_id: 'OF-2' } }, intent_session: {}, policy: {}, ...o });
const f3 = three();
const vs = two();
wb('empty', IS());
wb('facts-pass', IS({ intent_session: { facts: f3.map(pca.factRef) }, artifacts: { facts: f3 }, policy: { world: { worlds: [fareWorld()] } } }));
wb('facts-no-artifacts', IS({ intent_session: { facts: f3.map(pca.factRef) }, policy: { world: { worlds: [fareWorld()] } } }));
wb('facts-fail', IS({ intent_session: { facts: f3.map(pca.factRef) }, artifacts: { facts: f3.slice(0, 2) }, policy: { world: { worlds: [fareWorld()] } } }));
wb('world-policy-only', IS({ policy: { world: { relational: [{ name: 'd', fn: 'sub', a: 'action.params.pax.x', b: 'action.params.pax.x' }] } } }));
wb('prov-pass', IS({ intent_session: { prov: { 'action.params.offer_id': ['wallet:profile:ana'] } }, policy: { provenance: { params: {}, registry: { 'wallet:profile:ana': 'trusted' } } } }));
wb('prov-question', IS({ intent_session: { prov: { 'action.params.offer_id': ['web:ad'] } }, policy: { provenance: { params: { 'action.params.offer_id': 'material' } } } }));
wb('prov-no-policy', IS({ intent_session: { prov: { 'action.params.offer_id': ['x'] } } }));
wb('prov-deny', IS({ intent_session: { prov: { 'action.params.nope': ['x'] } } }));
wb('prov-question-then-cls-fail', IS({ intent_session: { prov: { 'action.params.offer_id': ['web:ad'] }, classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: [vs[0]] }, policy: { provenance: { params: { 'action.params.offer_id': 'material' } }, classifiers: [TONE] } }));
wb('prov-question-then-cls-pass', IS({ intent_session: { prov: { 'action.params.offer_id': ['web:ad'] }, classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs }, policy: { provenance: { params: { 'action.params.offer_id': 'material' } }, classifiers: [TONE] } }));
wb('cls-pass', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs }, policy: { classifiers: [TONE] } }));
wb('cls-no-policy', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: vs } }));
wb('cls-policy-only', IS({ policy: { classifiers: [TONE] } }));
wb('cls-fail', IS({ intent_session: { classes: vs.map(pca.classifierVerdictRef) }, artifacts: { verdicts: [vs[0]] }, policy: { classifiers: [TONE] } }));
wb('all-pass', IS({ intent_session: { facts: f3.map(pca.factRef), prov: { 'action.params.offer_id': ['wallet:profile:ana'] }, classes: vs.map(pca.classifierVerdictRef) }, artifacts: { facts: f3, verdicts: vs }, policy: { world: { worlds: [fareWorld()] }, provenance: { params: {}, registry: { 'wallet:profile:ana': 'trusted' } }, classifiers: [TONE] } }));
wb('facts-fail-skips-rest', IS({ intent_session: { facts: f3.map(pca.factRef), prov: { 'action.params.nope': ['x'] } }, artifacts: { facts: [] }, policy: { world: { worlds: [fareWorld()] } } }));
// artifacts: null is refused upstream (intent_v2.go context check 'wb.artifacts must be an object'); decideIntentWB's nil is 'absent'
wb('ctx-artifacts-array', IS({ artifacts: [] }));
wb('ctx-artifacts-extra', IS({ artifacts: { x: [] } }));
wb('ctx-artifacts-facts-null', IS({ artifacts: { facts: null } }));
wb('ctx-artifacts-labels-obj', IS({ artifacts: { labels: {} } }));
wb('ctx-artifacts-verdicts-obj', IS({ artifacts: { verdicts: {} } }));
wb('ctx-artifacts-offer-array', IS({ artifacts: { offer_set: [] } }));
wb('ctx-artifacts-ok', IS({ artifacts: { facts: [], labels: [], verdicts: [], offer_set: {} } }));
wb('ctx-policy-null', IS({ policy: null }));
wb('ctx-policy-extra', IS({ policy: { x: 1 } }));
wb('ctx-policy-world-null', IS({ policy: { world: null } }));
wb('ctx-policy-prov-array', IS({ policy: { provenance: [] } }));
wb('ctx-policy-cls-obj', IS({ policy: { classifiers: {} } }));
wb('ctx-session-null', IS({ intent_session: null }));
wb('offer-artifact', IS({ intent_session: { offer_set: pca.offerSetRef(offerSet()) }, artifacts: { offer_set: offerSet() }, policy: { world: { offers: offerPolicy() } } }));
wb('offer-no-artifact', IS({ intent_session: { offer_set: pca.offerSetRef(offerSet()) }, artifacts: {}, policy: { world: { offers: offerPolicy() } } }));
wb('labels-active', IS({ intent_session: { labels: [pca.labelsRef(PASSPORT)], prov: { 'action.params.passport': [lref(PASSPORT, 'pp')] } }, artifacts: { labels: [PASSPORT] }, policy: { provenance: { params: {}, label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }] } } }));
wb('labels-no-artifacts', IS({ intent_session: { labels: [pca.labelsRef(PASSPORT)], prov: { 'action.params.passport': [lref(PASSPORT, 'pp')] } }, policy: { provenance: { params: {}, label_keys: [{ site: AUD, kid: 'k1', pk: SITE.pk }] } } }));

fs.writeFileSync(process.argv[2], JSON.stringify({ about: 'TS-reference oracle for killD_test.go (intent_wb.go); generated by the kill-test oracle script.', cases }, null, 0));
console.log(`cases: ${cases.length}`);
