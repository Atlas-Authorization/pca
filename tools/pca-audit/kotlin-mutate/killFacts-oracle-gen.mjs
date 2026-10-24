// Oracle for the Kotlin KillFacts*Test mutation-kill tests (OracleFacts.kt rule 16, ParamProvenance.kt rule 17 + the V14
// read cell): runs the TS reference (packages/pca/src oracle-facts.ts, offer-set.ts, param-provenance.ts,
// label-receipts.ts) on targeted inputs and writes sdks/kotlin-pca/test-data/killFacts.json.
// Reuses the Go W-B oracle (tools/pca-audit/go-mutate/killD-oracle-gen.mjs, same seeds and cases: validators, ratioPpm,
// flowRuleFor/flowAllowed, rule-16/17 decisions, read purpose), keeps the kinds the two Kotlin files implement, and adds
// Kotlin-specific boundary cases below.
//   K/tsx/run.sh tools/pca-audit/kotlin-mutate/killFacts-oracle-gen.mjs [out.json]
// Deterministic: keys are seeded, signatures are Ed25519 (deterministic).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);

const OUT = process.argv[2] ?? new URL('../../../sdks/kotlin-pca/test-data/killFacts.json', import.meta.url).pathname;

// ---- run the Go oracle into a temp file (it writes process.argv[2])
const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'killfacts-')), 'killD.json');
const argv = process.argv;
process.argv = [argv[0], argv[1], tmp];
const log = console.log;
console.log = () => {};
await import(new URL('../go-mutate/killD-oracle-gen.mjs', import.meta.url).href);
console.log = log;
process.argv = argv;
const KEEP_FN = new Set(['validateFactWire', 'validateWorldPolicy', 'validateOfferPolicy', 'validateOfferSetWire', 'validateLabelsWire', 'validateFlowRules', 'validateProvenancePolicy', 'validateProvWire']);
const cases = JSON.parse(fs.readFileSync(tmp, 'utf8')).cases.filter((c) =>
  (c.kind === 'fn' && KEEP_FN.has(c.fn)) || ['ratio', 'flowRule', 'flowAllowed', 'world', 'prov', 'read'].includes(c.kind));
fs.rmSync(path.dirname(tmp), { recursive: true, force: true });

const names = new Set(cases.map((c) => c.name));
const push = (c) => {
  if (names.has(c.name)) throw new Error(`duplicate case ${c.name}`);
  names.add(c.name);
  cases.push(c);
};
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const s = (n, ch = 'x') => ch.repeat(n);
const NOW = 1_800_000_000_000;
const AUD = 'skyair.example';
const SESSION = pca.b64u(seed('wb/session'));
const O = [mk('wb/oracle-1'), mk('wb/oracle-2'), mk('wb/oracle-3'), mk('wb/oracle-4')];
const SITE = mk('wb/site');
const GOV = mk('wb/gov');

function fn(fnName, name, arg) {
  const f = {
    validateFactWire: pca.validateFactWire, validateWorldPolicy: pca.validateWorldPolicy, validateOfferPolicy: pca.validateOfferPolicy,
    validateOfferSetWire: pca.validateOfferSetWire, validateLabelsWire: pca.validateLabelsWire, validateFlowRules: pca.validateFlowRules,
    validateProvenancePolicy: pca.validateProvenancePolicy, validateProvWire: pca.validateProvWire,
  }[fnName];
  const r = f(clone(arg));
  push({ kind: 'fn', fn: fnName, name: `${fnName}/k-${name}`, arg: clone(arg), want: r === null, ts_reason: r ?? '' });
}
const worldOut = (r) => (r.ok ? { ok: true, world: r.world, single_source: r.single_source } : { ok: false });
function world(name, input) {
  const r = pca.decideIntentWorld(clone(input));
  push({ kind: 'world', name: `world/k-${name}`, input: clone(input), expect: worldOut(r), ts_reason: r.reason ?? '' });
}
const provOut = (r) => (r.outcome === 'deny' ? { outcome: 'deny' } : { outcome: r.outcome, labels: r.labels, classes: r.classes, ...(r.outcome === 'question' ? { friction: r.friction } : {}) });
function prov(name, input) {
  const r = pca.decideParamProvenance(clone(input));
  push({ kind: 'prov', name: `prov/k-${name}`, input: clone(input), expect: provOut(r), ts_reason: r.reason ?? '' });
}
function active(name, input) {
  push({ kind: 'worldActive', name: `worldActive/${name}`, input: clone(input), expect: pca.intentWorldActive(clone(input)) });
}
function read(name, input) {
  const i = clone(input);
  const r = pca.decideReadPurpose(i.fields, i.purpose, i.coverage, ...(i.on_uncovered !== undefined ? [i.on_uncovered] : []));
  push({ kind: 'read', name: `read/k-${name}`, input: clone(input), expect: r });
}

// ---------------------------------------------------------------- extra validator cases
const pin = (i) => ({ kid: `o${i + 1}`, pk: O[i].pk });
const worldBase = { name: 'fare', subject_path: 'action.params.offer_id', oracles: [pin(0), pin(1), pin(2)], freshness_ms: 60000, min_oracles: 3, max_faulty: 1 };
fn('validateWorldPolicy', 'world-array-entry', { worlds: [[]] });
fn('validateWorldPolicy', 'rel-array-entry', { relational: [[]] });
fn('validateWorldPolicy', 'rel-name-number', { relational: [{ name: 7, fn: 'sub', a: 'action.params.a', b: 'action.params.b' }] });
fn('validateWorldPolicy', 'rel-fn-number', { relational: [{ name: 'r', fn: 1, a: 'action.params.a', b: 'action.params.b' }] });
fn('validateWorldPolicy', 'rel-a-env-ok-b-bad', { worlds: [worldBase], relational: [{ name: 'r', fn: 'sub', a: 'env.world.fare', b: 'env.world.r' }] });
fn('validateWorldPolicy', 'rel-a-env-ok-b-ok', { worlds: [worldBase], relational: [{ name: 'r', fn: 'sub', a: 'env.world.fare', b: 'env.world.fare' }] });
fn('validateWorldPolicy', 'rel-a-world-dot-only', { worlds: [worldBase], relational: [{ name: 'r', fn: 'sub', a: 'env.world.', b: 'action.params.x' }] });
fn('validateWorldPolicy', 'world-name-number', { worlds: [{ ...worldBase, name: 5 }] });
fn('validateWorldPolicy', 'world-name-null', { worlds: [{ ...worldBase, name: null }] });
fn('validateWorldPolicy', 'world-oracle-kid-number', { worlds: [{ ...worldBase, oracles: [{ kid: 1, pk: O[0].pk }, pin(1), pin(2)] }] });
fn('validateWorldPolicy', 'world-min-exact-pins', { worlds: [{ ...worldBase, min_oracles: 3, oracles: [pin(0), pin(1), pin(2)] }] });
fn('validateWorldPolicy', 'world-min-1-0pins', { worlds: [{ ...worldBase, min_oracles: 1, max_faulty: 0, oracles: [] }] });
fn('validateWorldPolicy', 'world-min-0-0pins', { worlds: [{ ...worldBase, min_oracles: 0, max_faulty: 0, oracles: [] }] });
fn('validateWorldPolicy', 'world-oracles-string', { worlds: [{ ...worldBase, oracles: 'abc' }] });
fn('validateWorldPolicy', 'world-oracle-array', { worlds: [{ ...worldBase, min_oracles: 1, max_faulty: 0, oracles: [[]] }] });
fn('validateWorldPolicy', 'world-oracle-pq-number', { worlds: [{ ...worldBase, oracles: [{ ...pin(0), pq_pk: 1 }, pin(1), pin(2)] }] });
fn('validateWorldPolicy', 'world-min-unsafe', { worlds: [{ ...worldBase, min_oracles: 2 ** 53 }] });
fn('validateWorldPolicy', 'world-faulty-unsafe', { worlds: [{ ...worldBase, max_faulty: 2 ** 53 }] });
fn('validateWorldPolicy', 'world-fresh-unsafe', { worlds: [{ ...worldBase, freshness_ms: 2 ** 53 }] });
fn('validateWorldPolicy', 'world-fresh-max', { worlds: [{ ...worldBase, freshness_ms: 2 ** 53 - 1 }] });
fn('validateWorldPolicy', 'skew-unsafe', { skew_ms: 2 ** 53 });
fn('validateWorldPolicy', 'skew-0', { skew_ms: 0 });
fn('validateWorldPolicy', 'skew-null', { skew_ms: null });
fn('validateWorldPolicy', 'offers-array', { offers: [] });
fn('validateWorldPolicy', 'offers-name-number', { offers: { name: 3, site_keys: [{ kid: 'k', pk: SITE.pk }], max_age_ms: 0, offer_param: 'action.params.o', filter: { query: {}, offer: {} } } });
fn('validateWorldPolicy', 'offers-only', { offers: { name: 'ex', site_keys: [{ kid: 'k', pk: SITE.pk }], max_age_ms: 0, offer_param: 'action.params.o', filter: { query: {}, offer: {} } } });
fn('validateWorldPolicy', 'worlds-string', { worlds: 'x' });
fn('validateWorldPolicy', 'rel-string', { relational: 'x' });
fn('validateWorldPolicy', 'rel-a-null', { relational: [{ name: 'r', fn: 'sub', a: null, b: 'action.params.b' }] });
fn('validateWorldPolicy', 'rel-a-param-prefix', { relational: [{ name: 'r', fn: 'sub', a: 'action.params.', b: 'action.params.b' }] });
const opBase = { name: 'excess', site_keys: [{ kid: 'k', pk: SITE.pk }, { kid: 'k2', pk: GOV.pk, pq_pk: 'pq' }], max_age_ms: 600000, offer_param: 'action.params.offer_id', filter: { query: { a: 1 }, offer: { r: false } } };
fn('validateOfferPolicy', 'array', []);
fn('validateOfferPolicy', 'key-array', { ...opBase, site_keys: [[]] });
fn('validateOfferPolicy', 'key-kid-number', { ...opBase, site_keys: [{ kid: 1, pk: SITE.pk }] });
fn('validateOfferPolicy', 'key-pq-number', { ...opBase, site_keys: [{ kid: 'k', pk: SITE.pk, pq_pk: 1 }] });
fn('validateOfferPolicy', 'keys-string', { ...opBase, site_keys: 'k' });
fn('validateOfferPolicy', 'filter-array', { ...opBase, filter: [] });
fn('validateOfferPolicy', 'filter-query-array', { ...opBase, filter: { query: [], offer: {} } });
fn('validateOfferPolicy', 'filter-offer-null', { ...opBase, filter: { query: {}, offer: null } });
fn('validateOfferPolicy', 'filter-offer-obj-value-2nd', { ...opBase, filter: { query: { a: 1, b: 2 }, offer: { r: 1, q: { x: 1 } } } });
fn('validateOfferPolicy', 'filter-query-obj-value-2nd', { ...opBase, filter: { query: { a: 1, b: [] }, offer: {} } });
fn('validateOfferPolicy', 'age-unsafe', { ...opBase, max_age_ms: 2 ** 53 });
fn('validateOfferPolicy', 'age-max', { ...opBase, max_age_ms: 2 ** 53 - 1 });
fn('validateOfferPolicy', 'param-exact', { ...opBase, offer_param: 'action.params.x' });
fn('validateOfferPolicy', 'param-params-no-dot', { ...opBase, offer_param: 'action.paramsx' });
const osBase = { v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: { from: 'SFO' }, rank: 'price_asc', complete: true, offers: [{ offer_id: 'A', price: 0 }], issued_at: 0, kid: 'k', sig: 'S' };
fn('validateOfferSetWire', 'array', []);
fn('validateOfferSetWire', 'null', null);
fn('validateOfferSetWire', 'v-string', { ...osBase, v: '1' });
fn('validateOfferSetWire', 'v-float', { ...osBase, v: 1.5 });
fn('validateOfferSetWire', 'site-number', { ...osBase, site: 1 });
fn('validateOfferSetWire', 'query-key-bad-2nd', { ...osBase, query: { a: 1, b: { c: 1 } } });
fn('validateOfferSetWire', 'offers-obj', { ...osBase, offers: {} });
fn('validateOfferSetWire', 'offer-array', { ...osBase, offers: [[]] });
fn('validateOfferSetWire', 'offer-second-bad', { ...osBase, offers: [{ offer_id: 'A', price: 0 }, { offer_id: 'B', price: -1 }] });
fn('validateOfferSetWire', 'offer-second-attr-bad', { ...osBase, offers: [{ offer_id: 'A', price: 0, z: 1 }, { offer_id: 'B', price: 1, y: {} }] });
fn('validateOfferSetWire', 'price-unsafe', { ...osBase, offers: [{ offer_id: 'A', price: 2 ** 53 }] });
fn('validateOfferSetWire', 'price-max', { ...osBase, offers: [{ offer_id: 'A', price: 2 ** 53 - 1 }] });
fn('validateOfferSetWire', 'issued-unsafe', { ...osBase, issued_at: 2 ** 53 });
fn('validateOfferSetWire', 'issued-string', { ...osBase, issued_at: '0' });
fn('validateOfferSetWire', 'kid-number', { ...osBase, kid: 1 });
fn('validateOfferSetWire', 'complete-number', { ...osBase, complete: 1 });
fn('validateOfferSetWire', 'rank-number', { ...osBase, rank: 1 });
fn('validateOfferSetWire', 'offer-attrs-32-plus-id-price', { ...osBase, offers: [{ offer_id: 'A', price: 0, ...Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`k${i}`, 'v'])) }] });
fn('validateOfferSetWire', 'offer-attr-bool', { ...osBase, offers: [{ offer_id: 'A', price: 0, b: true }] });
fn('validateOfferSetWire', 'offer-attr-float', { ...osBase, offers: [{ offer_id: 'A', price: 0, b: 1.5 }] });
fn('validateOfferSetWire', 'query-float', { ...osBase, query: { a: 1.5 } });
fn('validateOfferSetWire', 'query-empty', { ...osBase, query: {} });
const factBase = { v: 1, kind: 'pca-fact', name: 'fare', subject: 'OF-2', value: 5, t_obs: 7, oracle: 'o1', sig: 'AAAA' };
fn('validateFactWire', 'array', []);
fn('validateFactWire', 'v-float', { ...factBase, v: 1.5 });
fn('validateFactWire', 'kind-number', { ...factBase, kind: 1 });
fn('validateFactWire', 'value-zero', { ...factBase, value: 0 });
fn('validateFactWire', 'value-max', { ...factBase, value: 2 ** 53 - 1 });
fn('validateFactWire', 'value-min', { ...factBase, value: -(2 ** 53 - 1) });
fn('validateFactWire', 'value-null', { ...factBase, value: null });
fn('validateFactWire', 't_obs-unsafe', { ...factBase, t_obs: 2 ** 53 });
fn('validateFactWire', 't_obs-max', { ...factBase, t_obs: 2 ** 53 - 1 });
fn('validateFactWire', 'oracle-number', { ...factBase, oracle: 1 });
fn('validateFactWire', 'sig-null', { ...factBase, sig: null });
fn('validateFactWire', 'sig-empty', { ...factBase, sig: '' });
fn('validateFactWire', 'pq-members', { ...factBase, alg: 'ed25519' });
const D32 = pca.b64u(seed('wb/active'));
const lbBase = { v: 1, kind: 'pca-labels', site: AUD, session: SESSION, response_digest: D32, fields: { a: { class: 'pii.identity', value_digest: D32 } }, issued_at: 0, kid: 'k1', sig: 'S' };
fn('validateLabelsWire', 'array', []);
fn('validateLabelsWire', 'null', null);
fn('validateLabelsWire', 'v-string', { ...lbBase, v: '1' });
fn('validateLabelsWire', 'kind-number', { ...lbBase, kind: 1 });
fn('validateLabelsWire', 'site-number', { ...lbBase, site: 1 });
fn('validateLabelsWire', 'field-array', { ...lbBase, fields: { a: [] } });
fn('validateLabelsWire', 'field-second-bad', { ...lbBase, fields: { a: { class: 'x', value_digest: D32 }, b: { class: 'X', value_digest: D32 } } });
fn('validateLabelsWire', 'field-second-digest-bad', { ...lbBase, fields: { a: { class: 'x', value_digest: D32 }, b: { class: 'y', value_digest: 'q' } } });
fn('validateLabelsWire', 'class-dotted', { ...lbBase, fields: { a: { class: 'a.b.c', value_digest: D32 } } });
fn('validateLabelsWire', 'class-127', { ...lbBase, fields: { a: { class: s(127, 'a'), value_digest: D32 } } });
fn('validateLabelsWire', 'class-130', { ...lbBase, fields: { a: { class: s(130, 'a'), value_digest: D32 } } });
fn('validateLabelsWire', 'class-127-dotted-128', { ...lbBase, fields: { a: { class: `${s(63, 'a')}.${s(64, 'b')}`, value_digest: D32 } } });
fn('validateLabelsWire', 'class-129-dotted', { ...lbBase, fields: { a: { class: `${s(64, 'a')}.${s(64, 'b')}`, value_digest: D32 } } });
fn('validateLabelsWire', 'issued-unsafe', { ...lbBase, issued_at: 2 ** 53 });
fn('validateLabelsWire', 'issued-max', { ...lbBase, issued_at: 2 ** 53 - 1 });
fn('validateLabelsWire', 'kid-number', { ...lbBase, kid: 1 });
fn('validateLabelsWire', 'sig-null', { ...lbBase, sig: null });
fn('validateLabelsWire', 'digest-number', { ...lbBase, fields: { a: { class: 'x', value_digest: 1 } } });
for (const [name, rules] of Object.entries({
  'second-bad-pattern': { a: ['x'], 'B!': ['y'] }, 'second-bad-sinks': { a: ['x'], b: 'y' }, 'second-bad-sink': { a: ['x'], b: ['y', 1] },
  'sink-256': { a: [s(256)] }, 'sink-number': { a: [1] }, 'sink-null': { a: [null] }, 'empty-sinks': { a: [] }, 'dot-star-dotted': { 'a.b.*': [], 'a.b': [] },
  'star-dot-star': { '*.*': ['x'] }, 'pattern-dot-star-only': { 'a.*.*': ['x'] }, 'pattern-128': { [s(128, 'a')]: ['x'] }, 'pattern-129': { [s(129, 'a')]: ['x'] },
  'pattern-dotstar-127': { [`${s(127, 'a')}.*`]: ['x'] }, 'pattern-empty': { '': ['x'] },
})) fn('validateFlowRules', `k-${name}`, rules);
const ppBase = { params: { 'action.params.a': 'material' } };
for (const [name, p] of Object.entries({
  array: [], 'params-string': { params: 'x' }, 'params-empty': { params: {} }, 'param-second-bad': { params: { 'action.params.a': 'material', 'action.params.b': 'x' } },
  'param-number-sens': { params: { 'action.params.a': 1 } }, 'param-path-second-bad': { params: { 'action.params.a': 'critical', 'b': 'critical' } },
  'registry-ok': { ...ppBase, registry: { a: 'tool', b: 'web' } }, 'registry-second-bad': { ...ppBase, registry: { a: 'tool', b: 'nope' } }, 'registry-256': { ...ppBase, registry: { [s(256)]: 'web' } },
  'registry-string': { ...ppBase, registry: 'x' }, 'keys-empty': { ...ppBase, label_keys: [] }, 'keys-string': { ...ppBase, label_keys: 'x' },
  'key-array': { ...ppBase, label_keys: [[]] }, 'key-site-number': { ...ppBase, label_keys: [{ site: 1, kid: 'k', pk: SITE.pk }] }, 'key-kid-number': { ...ppBase, label_keys: [{ site: 's', kid: 1, pk: SITE.pk }] },
  'key-kid-64': { ...ppBase, label_keys: [{ site: 's', kid: s(64), pk: SITE.pk }] }, 'key-site-256': { ...ppBase, label_keys: [{ site: s(256), kid: 'k', pk: SITE.pk }] },
  'key-pq-number': { ...ppBase, label_keys: [{ site: 's', kid: 'k', pk: SITE.pk, pq_pk: 1 }] }, 'key-pq-ok': { ...ppBase, label_keys: [{ site: 's', kid: 'k', pk: SITE.pk, pq_pk: 'pq' }] },
  'key-second-bad': { ...ppBase, label_keys: [{ site: 's', kid: 'k', pk: SITE.pk }, { site: 's', kid: 'k' }] }, 'key-dup-ok': { ...ppBase, label_keys: [{ site: 's', kid: 'k', pk: SITE.pk }, { site: 's', kid: 'k', pk: SITE.pk }] },
  'cmax-trusted': { ...ppBase, critical_max: 'trusted' }, 'cmax-agent': { ...ppBase, critical_max: 'agent' }, 'cmax-number': { ...ppBase, critical_max: 0 },
  'mt-allow': { ...ppBase, material_tainted: 'allow' }, 'mt-question': { ...ppBase, material_tainted: 'question' }, 'mt-deny': { ...ppBase, material_tainted: 'deny' }, 'mt-number': { ...ppBase, material_tainted: 1 },
  'ct-question_typed': { ...ppBase, critical_tainted: 'question_typed' }, 'ct-deny': { ...ppBase, critical_tainted: 'deny' }, 'ct-number': { ...ppBase, critical_tainted: 1 },
  'flows-ok': { ...ppBase, flows: { 'a.*': ['x'] } }, 'flows-array': { ...ppBase, flows: [] }, 'flows-sinks-bad': { ...ppBase, flows: { a: 'x' } },
  'extra-and-bad-cmax': { ...ppBase, critical_max: 'x', y: 1 },
})) fn('validateProvenancePolicy', name, p);
for (const [name, p] of Object.entries({
  empty: {}, 'second-bad-key': { 'action.params.a': ['x'], 'action.params.b-c': ['x'] }, 'second-bad-refs': { 'action.params.a': ['x'], 'action.params.b': [] },
  'second-bad-ref': { 'action.params.a': ['x'], 'action.params.b': ['y', ''] }, 'refs-obj': { 'action.params.a': {} }, 'refs-1': { 'action.params.a': ['x'] },
  'ref-null': { 'action.params.a': [null] }, 'key-1': { 'action.params.a': ['x'] }, 'key-empty-name': { 'action.params.': ['x'] }, 'key-prefix-junk': { 'xaction.params.a': ['x'] },
  'key-suffix-junk': { 'action.params.a\n': ['x'] }, 'key-proto-like': { 'action.params.__proto__x': ['x'] }, 'key-Constructor': { 'action.params.Constructor': ['x'] },
})) fn('validateProvWire', `k-${name}`, p);

// ---------------------------------------------------------------- worldActive (intentWorldActive)
for (const [name, input] of Object.entries({
  empty: {}, 'committed-null': { committed: null, policy: {} }, 'facts-one': { committed: { facts: [D32] } }, 'facts-empty': { committed: { facts: [] } },
  'facts-string': { committed: { facts: 'x' } }, 'facts-obj': { committed: { facts: { length: 1 } } }, 'offer-string': { committed: { offer_set: '' } }, 'offer-number': { committed: { offer_set: 1 } },
  'offer-null': { committed: { offer_set: null } }, 'worlds-one': { policy: { worlds: [{}] } }, 'worlds-empty': { policy: { worlds: [] } }, 'worlds-string': { policy: { worlds: 'x' } },
  'rel-one': { policy: { relational: [1] } }, 'rel-empty': { policy: { relational: [] } }, 'rel-obj': { policy: { relational: {} } }, 'offers-obj': { policy: { offers: {} } },
  'offers-array': { policy: { offers: [] } }, 'offers-string': { policy: { offers: 'x' } }, 'policy-array': { policy: [], committed: [] }, 'policy-string': { policy: 'x', committed: 'y' },
  'committed-array-facts': { committed: [D32] },
})) active(name, input);

// ---------------------------------------------------------------- extra rule-16 decisions
const fact = (i, nm, value, t_obs = NOW - 1_000, subject = 'OF-2', kid = `o${i + 1}`, key = O[i]) => pca.signFact({ name: nm, subject, value, t_obs, oracle: kid }, key.sk);
const one = (over = {}) => ({ name: 'fare', subject_path: 'action.params.offer_id', oracles: [pin(0)], freshness_ms: 60_000, min_oracles: 1, max_faulty: 0, ...over });
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900, pax: 2 } };
const W = (facts, policy, over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { facts: facts.map(pca.factRef) }, facts, policy, ...over });
world('input-array', []);
world('input-null', null);
world('policy-null', W([], null));
world('policy-absent', (() => { const i = W([], {}); delete i.policy; return i; })());
world('action-null', W([], {}, { action: null }));
world('action-array', W([], {}, { action: [] }));
world('params-array', W([], {}, { action: { ...ACTION, params: [] } }));
world('params-string', W([], {}, { action: { ...ACTION, params: 'x' } }));
world('committed-null', W([], {}, { committed: null }));
world('committed-array', W([], {}, { committed: [] }));
world('committed-absent', (() => { const i = W([], {}); delete i.committed; return i; })());
world('committed-facts-null', W([], {}, { committed: { facts: null } }));
world('committed-facts-obj', W([], {}, { committed: { facts: {} } }));
world('facts-absent-none-committed', (() => { const i = W([], {}); delete i.facts; return i; })());
world('facts-null', W([], {}, { facts: null }));
world('offer-set-null', W([], {}, { offer_set: null }));
world('offer-set-string', W([], {}, { offer_set: 'x' }));
world('committed-offer-null', W([], {}, { committed: { facts: [], offer_set: null } }));
world('committed-offer-ok-no-policy', W([], {}, { committed: { facts: [], offer_set: D32 } }));
world('supplied-garbage-ignored', W([], { worlds: [one({ min_oracles: 0 })] }, { facts: [null, 1, 'x', { v: 1 }] }));
world('supplied-uncommitted-ignored', { ...W([fact(0, 'fare', 3)], { worlds: [one()] }), committed: { facts: [] } });
world('two-worlds-order', W([fact(0, 'b', 2), fact(1, 'a', 1)], { worlds: [one({ name: 'a', oracles: [pin(1)] }), one({ name: 'b' })] }));
world('world-min-0-value', W([], { worlds: [one({ min_oracles: 0 })] }));
world('fact-string-value-agree-3', W([fact(0, 'fare', 'q'), fact(1, 'fare', 'q'), fact(2, 'fare', 'q')], { worlds: [{ ...one(), oracles: [pin(0), pin(1), pin(2)], min_oracles: 3, max_faulty: 1 }] }));
world('fact-string-disagree-last', W([fact(0, 'fare', 'q'), fact(1, 'fare', 'q'), fact(2, 'fare', 'r')], { worlds: [{ ...one(), oracles: [pin(0), pin(1), pin(2)], min_oracles: 3, max_faulty: 1 }] }));
world('fact-mix-int-first', W([fact(0, 'fare', 1), fact(1, 'fare', 'q')], { worlds: [{ ...one(), oracles: [pin(0), pin(1)], min_oracles: 2 }] }));
world('median-three-sorted', W([fact(0, 'fare', 3), fact(1, 'fare', 1), fact(2, 'fare', 2)], { worlds: [{ ...one(), oracles: [pin(0), pin(1), pin(2)], min_oracles: 3, max_faulty: 1 }] }));
world('median-four', W([fact(0, 'fare', 40), fact(1, 'fare', 10), fact(2, 'fare', 30), fact(3, 'fare', 20, NOW - 1_000, 'OF-2', 'o4', O[3])], { worlds: [{ ...one(), oracles: [pin(0), pin(1), pin(2), pin(3)], min_oracles: 4, max_faulty: 1 }] }));
world('median-four-min-2', W([fact(0, 'fare', 40), fact(1, 'fare', 10), fact(2, 'fare', 30), fact(3, 'fare', 20, NOW - 1_000, 'OF-2', 'o4', O[3])], { worlds: [{ ...one(), oracles: [pin(0), pin(1), pin(2), pin(3)], min_oracles: 2, max_faulty: 0 }] }));
world('fresh-and-stale-min-1', W([fact(0, 'fare', 9, NOW - 70_000), fact(1, 'fare', 4)], { worlds: [{ ...one(), oracles: [pin(0), pin(1)] }] }));
world('stale-only-min-1', W([fact(0, 'fare', 9, NOW - 70_000)], { worlds: [one()] }));
world('skew-0-now', W([fact(0, 'fare', 9, NOW)], { worlds: [one()], skew_ms: 0 }));
world('skew-0-future-1', W([fact(0, 'fare', 9, NOW + 1)], { worlds: [one()], skew_ms: 0 }));
world('skew-big-fresh-0', W([fact(0, 'fare', 9, NOW + 100)], { worlds: [one({ freshness_ms: 0 })], skew_ms: 1000 }));
world('now-float', { ...W([fact(0, 'fare', 9)], { worlds: [one()] }), now: 1.5 });
world('now-string-no-worlds', { ...W([], {}), now: 'x' });
world('now-zero', { ...W([fact(0, 'fare', 9, 0)], { worlds: [one()] }), now: 0 });
world('subject-resource-number', W([fact(0, 'fare', 1, NOW - 1_000, 'r')], { worlds: [one({ subject_path: 'action.resource' })] }, { action: { ...ACTION, resource: 5 } }));
world('subject-verb-number', W([fact(0, 'fare', 1, NOW - 1_000, 'r')], { worlds: [one({ subject_path: 'action.verb' })] }, { action: { ...ACTION, verb: 5 } }));
world('subject-resource-missing', W([fact(0, 'fare', 1, NOW - 1_000, 'r')], { worlds: [one({ subject_path: 'action.resource' })] }, { action: { params: ACTION.params } }));
world('subject-nested-param', W([fact(0, 'fare', 1, NOW - 1_000, 'deep')], { worlds: [one({ subject_path: 'action.params.o.x' })] }, { action: { ...ACTION, params: { o: { x: 'deep' } } } }));
world('subject-param-obj', W([fact(0, 'fare', 1, NOW - 1_000, 'deep')], { worlds: [one({ subject_path: 'action.params.o' })] }, { action: { ...ACTION, params: { o: { x: 'deep' } } } }));
world('fact-other-oracle-same-world', W([fact(0, 'fare', 1), fact(1, 'fare', 1)], { worlds: [{ ...one(), oracles: [pin(0), pin(1)], min_oracles: 2 }] }));
world('pin-second', W([fact(1, 'fare', 1)], { worlds: [{ ...one(), oracles: [pin(0), pin(1)] }] }));
world('world-second-match', W([fact(0, 'tier', 1)], { worlds: [one(), one({ name: 'tier' })] }));
world('rel-ratio-b-zero', W([], { relational: [{ name: 'r', fn: 'ratio_ppm', a: 'action.params.total', b: 'action.params.z' }] }, { action: { ...ACTION, params: { total: 5, z: 0 } } }));
world('rel-ratio-a-neg', W([], { relational: [{ name: 'r', fn: 'ratio_ppm', a: 'action.params.n', b: 'action.params.total' }] }, { action: { ...ACTION, params: { total: 5, n: -1 } } }));
world('rel-b-missing', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.nope' }] }));
world('rel-b-string', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'action.params.s' }] }, { action: { ...ACTION, params: { total: 1, s: '2' } } }));
world('rel-sub-neg-max', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.n', b: 'action.params.z' }] }, { action: { ...ACTION, params: { n: -(2 ** 53 - 1), z: 0 } } }));
world('rel-sub-neg-over', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.n', b: 'action.params.z' }] }, { action: { ...ACTION, params: { n: -(2 ** 53 - 1), z: 1 } } }));
world('rel-sub-pos-over', W([], { relational: [{ name: 'r', fn: 'sub', a: 'action.params.n', b: 'action.params.z' }] }, { action: { ...ACTION, params: { n: 2 ** 53 - 1, z: -1 } } }));
world('rel-env-world-missing-at-runtime', W([], { worlds: [one({ min_oracles: 0 })], relational: [{ name: 'r', fn: 'sub', a: 'env.world.fare', b: 'action.params.total' }] }));
world('rel-env-world-b-int', W([fact(0, 'fare', 7)], { worlds: [one()], relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'env.world.fare' }] }));
world('rel-ratio-env-b', W([fact(0, 'fare', 3)], { worlds: [one()], relational: [{ name: 'r', fn: 'ratio_ppm', a: 'action.params.total', b: 'env.world.fare' }] }));

// offers (extra)
const OFFERS = [{ offer_id: 'OF-1', price: 38_900, stops: 1, refundable: false }, { offer_id: 'OF-2', price: 39_800, stops: 0, refundable: false }, { offer_id: 'OF-3', price: 41_200, stops: 0, refundable: true }];
const QUERY = { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 };
const rawOS = (over = {}, key = SITE) => pca.signArtifact(pca.OFFER_SET_DOMAIN, { v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: QUERY, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, key.sk);
const offerPolicy = (over = {}) => ({ name: 'excess_cents', site_keys: [{ kid: 'other', pk: GOV.pk }, { kid: 'skyair-2026', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: QUERY, offer: { refundable: false } }, ...over });
const OS = (os, policy = offerPolicy(), over = {}) => ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { offer_set: pca.offerSetRef(os) }, offer_set: os, policy: { offers: policy }, ...over });
const withOffer = (id) => ({ action: { ...ACTION, params: { ...ACTION.params, offer_id: id } } });
world('os-query-superset-ok', OS(rawOS(), offerPolicy({ filter: { query: { from: 'SFO' }, offer: {} } })));
world('os-query-missing-key', OS(rawOS({ query: { from: 'SFO' } }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-query-empty-filter-empty', OS(rawOS({ query: {} }), offerPolicy({ filter: { query: {}, offer: {} } })));
world('os-filter-value-mismatch', OS(rawOS(), offerPolicy({ filter: { query: QUERY, offer: { stops: 1 } } })));
world('os-filter-int-vs-string', OS(rawOS(), offerPolicy({ filter: { query: QUERY, offer: { stops: '0' } } })));
world('os-min-later-cheaper', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 50 }, { offer_id: 'OF-1', price: 30 }, { offer_id: 'OF-3', price: 10, x: 1 }] }), offerPolicy({ filter: { query: QUERY, offer: {} } })));
world('os-min-cheaper-filtered', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 50, x: 1 }, { offer_id: 'OF-1', price: 30, x: 2 }, { offer_id: 'OF-3', price: 10 }] }), offerPolicy({ filter: { query: QUERY, offer: { x: 1 } } })));
world('os-min-cheaper-filtered-2', OS(rawOS({ offers: [{ offer_id: 'OF-2', price: 50, x: 1 }, { offer_id: 'OF-1', price: 30, x: 1 }, { offer_id: 'OF-3', price: 10 }] }), offerPolicy({ filter: { query: QUERY, offer: { x: 1 } } })));
world('os-param-obj', OS(rawOS(), offerPolicy(), withOffer({ a: 1 })));
world('os-param-null', OS(rawOS(), offerPolicy(), withOffer(null)));
world('os-params-absent', OS(rawOS(), offerPolicy(), { action: { verb: 'v', resource: 'r' } }));
world('os-session-absent', (() => { const i = OS(rawOS()); delete i.session; return i; })());
world('os-aud-absent', (() => { const i = OS(rawOS()); delete i.aud; return i; })());
world('os-now-absent', (() => { const i = OS(rawOS()); delete i.now; return i; })());
world('os-skew-custom-ok', { ...OS(rawOS({ issued_at: NOW + 100 })), policy: { skew_ms: 100, offers: offerPolicy() } });
world('os-skew-custom-over', { ...OS(rawOS({ issued_at: NOW + 101 })), policy: { skew_ms: 100, offers: offerPolicy() } });
world('os-age-max-ok', OS(rawOS({ issued_at: 0 }), offerPolicy({ max_age_ms: NOW })));
world('os-age-max-over', OS(rawOS({ issued_at: 0 }), offerPolicy({ max_age_ms: NOW - 1 })));
world('os-first-key-only', OS(rawOS({ kid: 'other' }, GOV), offerPolicy({ site_keys: [{ kid: 'other', pk: GOV.pk }] })));
world('os-with-world-and-rel', { ...OS(rawOS()), facts: [fact(0, 'fare', 7)], committed: { facts: [pca.factRef(fact(0, 'fare', 7))], offer_set: pca.offerSetRef(rawOS()) }, policy: { worlds: [one()], relational: [{ name: 'r', fn: 'sub', a: 'action.params.total', b: 'env.world.fare' }], offers: offerPolicy() } });
world('os-world-fail-first', { ...OS(rawOS()), policy: { worlds: [one()], offers: offerPolicy() } });
world('os-offer-set-absent-uncommitted', (() => { const i = OS(rawOS()); delete i.offer_set; i.committed = {}; return i; })());

// ---------------------------------------------------------------- extra rule-17 decisions
const PARAMS = { offer_id: 'OF-1', payment_ref: 'pm_ana_visa', add_ons: 'tripshield', passport: 'X1234567', note: 'hi', pax: { lead: 'px_ana' } };
const POLICY = {
  params: { 'action.params.offer_id': 'material', 'action.params.add_ons': 'material', 'action.params.payment_ref': 'critical', 'action.params.passport': 'critical' },
  registry: { 'skyair:offer_set:1': 'first_party', 'wallet:profile:ana': 'trusted', 'web:ad': 'web', 'tool:fx': 'tool', 'agent:planner': 'agent' },
  label_keys: [{ site: 'gov.example', kid: 'g1', pk: GOV.pk }, { site: AUD, kid: 'k1', pk: SITE.pk }],
};
const CLEAN = { 'action.params.offer_id': ['skyair:offer_set:1'], 'action.params.payment_ref': ['wallet:profile:ana'], 'action.params.add_ons': ['wallet:profile:ana'], 'action.params.passport': ['wallet:profile:ana'] };
const P = (provOver = {}, policyOver = {}, over = {}) => ({ aud: AUD, session: SESSION, action: { params: PARAMS }, prov: { ...CLEAN, ...provOver }, policy: { ...POLICY, ...policyOver }, ...over });
const HX = pca.hashCanonical('X1234567');
const receipt = (site, key, kid, fields, session = SESSION) => pca.signLabels({ site, session, response_digest: pca.b64u(seed('wb/response')), fields, issued_at: NOW - 5_000, kid }, key.sk);
const PASSPORT = receipt(AUD, SITE, 'k1', { pp: { class: 'pii.identity', value_digest: HX } });
const GOVR = receipt('gov.example', GOV, 'g1', { passport: { class: 'pii.identity', value_digest: HX }, card: { class: 'fin.card', value_digest: HX }, pub: { class: 'public', value_digest: HX } });
const lref = (r, f) => `pca-labels:${pca.labelsRef(r)}#${f}`;
const withRefs = (receipts, provOver, extra = {}) => ({ committed_labels: receipts.map(pca.labelsRef), labels: receipts, ...extra, prov: { ...CLEAN, ...provOver } });
prov('input-null', null);
prov('input-array', []);
prov('policy-absent', (() => { const p = P(); delete p.policy; return p; })());
prov('policy-params-array', P({}, { params: [] }));
prov('action-null', P({}, {}, { action: null }));
prov('action-array', P({}, {}, { action: [] }));
prov('action-absent', (() => { const p = P(); delete p.action; return p; })());
prov('params-array', P({}, {}, { action: { params: [] } }));
prov('labels-absent-ok', (() => { const p = P(); delete p.labels; return p; })());
prov('labels-string', P({}, {}, { labels: 'x' }));
prov('committed-string', P({}, {}, { committed_labels: 'x' }));
prov('committed-number-entry', P({}, {}, { committed_labels: [1] }));
prov('committed-one-ok', P({}, {}, { committed_labels: [D32] }));
prov('registry-absent-label-unknown', P({ 'action.params.offer_id': ['first'] }, { registry: { first: 'first_party' } }));
prov('registry-first-party', P({ 'action.params.offer_id': ['first'] }, { registry: { first: 'first_party' } }));
prov('registry-trusted-only', P({ 'action.params.offer_id': ['t'] }, { registry: { t: 'trusted' } }));
prov('registry-web-material-allow', P({ 'action.params.offer_id': ['web:ad'] }, { material_tainted: 'allow' }));
prov('registry-tool-material-default', P({ 'action.params.offer_id': ['tool:fx'] }));
prov('registry-tool-critical-default', P({ 'action.params.payment_ref': ['tool:fx'] }));
prov('registry-agent-critical-agentmax', P({ 'action.params.payment_ref': ['agent:planner'] }, { critical_max: 'agent', critical_tainted: 'deny' }));
prov('join-agent-trusted', P({ 'action.params.offer_id': ['agent:planner', 'wallet:profile:ana'] }));
prov('join-first-trusted', P({ 'action.params.offer_id': ['skyair:offer_set:1', 'wallet:profile:ana'] }));
prov('join-unknown-trusted', P({ 'action.params.offer_id': ['unknown', 'wallet:profile:ana'] }));
prov('no-prov-sensitive-params', P({}, {}, { prov: {} }));
prov('no-prov-no-policy-params', P({}, { params: {} }, { prov: {} }));
prov('prov-nested-param', P({ 'action.params.pax': ['wallet:profile:ana'] }, { params: { 'action.params.pax.lead': 'material' } }));
prov('policy-param-nested-only', P({}, { params: { 'action.params.pax.lead': 'material' } }, { prov: {} }));
prov('label-first-party-critical-max-trusted', P({}, { critical_max: 'trusted' }, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-first-party-critical-max-first', P({}, { critical_max: 'first_party' }, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-foreign-pub-material', P({}, { material_tainted: 'deny' }, withRefs([GOVR], { 'action.params.offer_id': [lref(GOVR, 'pub')] })));
prov('label-foreign-pub-question', P({}, { flows: {} }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'pub')] })));
prov('label-foreign-flow-to-aud-tool', P({}, { flows: { 'pii.identity': [AUD] }, critical_tainted: 'question_typed' }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-flow-list-two', P({}, { flows: { 'pii.identity': ['x', AUD] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-foreign-flow-prefix-dot', P({}, { flows: { 'pii.ident.*': [AUD], 'pii.*': ['x'] } }, withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'passport')] })));
prov('label-two-receipts', P({}, { flows: { '*': [AUD] } }, withRefs([PASSPORT, GOVR], { 'action.params.passport': [lref(PASSPORT, 'pp'), lref(GOVR, 'passport')] })));
prov('label-two-receipts-second-uncommitted', P({}, { flows: { '*': [AUD] } }, { ...withRefs([PASSPORT, GOVR], { 'action.params.passport': [lref(PASSPORT, 'pp'), lref(GOVR, 'passport')] }), committed_labels: [pca.labelsRef(PASSPORT)] }));
prov('label-key-site-ok-kid-wrong', P({}, { label_keys: [{ site: AUD, kid: 'zz', pk: SITE.pk }, { site: 'zz', kid: 'k1', pk: SITE.pk }] }, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-key-second-matches', P({}, { label_keys: [{ site: AUD, kid: 'zz', pk: GOV.pk }, { site: AUD, kid: 'k1', pk: SITE.pk }] }, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-key-first-wrong-pk', P({}, { label_keys: [{ site: AUD, kid: 'k1', pk: GOV.pk }, { site: AUD, kid: 'k1', pk: SITE.pk }] }, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-no-label-keys', P({}, { label_keys: undefined }, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })));
prov('label-receipt-garbage-supplied', P({}, {}, { ...withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] }), labels: [null, 1, { v: 1 }, PASSPORT] }));
prov('label-value-obj', (() => { const r = receipt(AUD, SITE, 'k1', { o: { class: 'pii.identity', value_digest: pca.hashCanonical({ lead: 'px_ana' }) } }); return P({ 'action.params.pax': [lref(r, 'o')] }, {}, { committed_labels: [pca.labelsRef(r)], labels: [r] }); })());
prov('label-session-absent', (() => { const p = P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })); delete p.session; return p; })());
prov('label-unordered-paths', P({ 'action.params.payment_ref': ['web:ad'], 'action.params.add_ons': ['web:ad'] }, { material_tainted: 'deny', critical_tainted: 'deny' }));
prov('cmax-two-critical-order', P({ 'action.params.payment_ref': ['web:ad'], 'action.params.passport': ['agent:planner'] }, { critical_max: 'tool' }));
prov('deny-critical-order', P({ 'action.params.payment_ref': ['web:ad'], 'action.params.passport': ['agent:planner'] }, { critical_tainted: 'deny', critical_max: 'agent' }));
prov('mt-question-typed-only', P({ 'action.params.add_ons': ['tool:fx'] }, { material_tainted: 'question_typed' }));
prov('ct-question-only', P({ 'action.params.payment_ref': ['tool:fx'] }, { critical_tainted: 'question' }));
prov('mt-allow-ct-allowed-clean', P({ 'action.params.add_ons': ['tool:fx'] }, { material_tainted: 'allow', critical_tainted: 'deny' }));
prov('first-party-critical-deny', P({ 'action.params.payment_ref': ['skyair:offer_set:1'] }, { critical_tainted: 'deny', material_tainted: 'deny' }));
prov('aud-number', P({}, {}, { aud: 5 }));
prov('aud-absent-no-labels', (() => { const p = P(); delete p.aud; return p; })());
prov('aud-number-labelled', P({}, {}, { ...withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] }), aud: 5 }));
prov('aud-null-labelled', P({}, {}, { ...withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] }), aud: null }));
prov('aud-absent-labelled', (() => { const p = P({}, {}, withRefs([PASSPORT], { 'action.params.passport': [lref(PASSPORT, 'pp')] })); delete p.aud; return p; })());
prov('aud-number-public-labelled', P({}, {}, { ...withRefs([GOVR], { 'action.params.passport': [lref(GOVR, 'pub')] }), aud: 5 }));
prov('policy-extra', P({}, { extra: 1 }));

// ---------------------------------------------------------------- extra read purpose
const COVER = { booking: ['pii.identity', 'itinerary'], support: ['pii.*', 'internal'], all: ['*'], none: [] };
read('star-dot', { fields: [{ path: 'a', class: 'x' }, { path: 'b', class: 'pii' }], purpose: 'p', coverage: { p: ['pii.*'] } });
read('prefix-not-dot', { fields: [{ path: 'a', class: 'piiz' }, { path: 'b', class: 'pii.z' }], purpose: 'p', coverage: { p: ['pii.*'] } });
read('purpose-missing', { fields: [{ path: 'a', class: 'x' }, { path: 'b', class: 'public', optional: true }], purpose: 'zzz', coverage: COVER });
read('purpose-missing-public', { fields: [{ path: 'b', class: 'public' }], purpose: 'zzz', coverage: COVER, on_uncovered: 'deny' });
read('optional-only', { fields: [{ path: 'b', class: 'x', optional: true }, { path: 'a', class: 'y', optional: true }], purpose: 'none', coverage: COVER, on_uncovered: 'deny' });
read('sort-utf8', { fields: [{ path: 'é', class: 'x' }, { path: 'z', class: 'x' }, { path: 'A', class: 'x' }, { path: '\u{1F600}', class: 'x' }, { path: '�', class: 'x' }], purpose: 'none', coverage: COVER });
read('exact-class', { fields: [{ path: 'a', class: 'itinerary' }, { path: 'b', class: 'itinerary.x' }], purpose: 'booking', coverage: COVER });
read('coverage-null', { fields: [], purpose: 'booking', coverage: null });
read('coverage-array', { fields: [], purpose: 'booking', coverage: [] });
read('coverage-value-string', { fields: [], purpose: 'booking', coverage: { booking: 'x' } });
read('fields-null', { fields: null, purpose: 'booking', coverage: COVER });
read('fields-obj', { fields: {}, purpose: 'booking', coverage: COVER });
read('purpose-number', { fields: [], purpose: 1, coverage: COVER });
read('optional-string', { fields: [{ path: 'a', class: 'x', optional: 'yes' }], purpose: 'booking', coverage: COVER });
read('optional-null', { fields: [{ path: 'a', class: 'x', optional: null }], purpose: 'booking', coverage: COVER });
read('field-array', { fields: [[]], purpose: 'booking', coverage: COVER });
read('field-no-path', { fields: [{ class: 'x' }], purpose: 'booking', coverage: COVER });
read('field-no-class', { fields: [{ path: 'x' }], purpose: 'booking', coverage: COVER });
read('on-uncovered-null', { fields: [], purpose: 'booking', coverage: COVER, on_uncovered: null });
read('on-uncovered-allow', { fields: [], purpose: 'booking', coverage: COVER, on_uncovered: 'allow' });
read('second-coverage-bad', { fields: [], purpose: 'booking', coverage: { booking: ['x'], other: ['y', 2] } });
read('star-prefix-only', { fields: [{ path: 'a', class: 'pii' }, { path: 'b', class: 'pii.x' }], purpose: 'p', coverage: { p: ['.*'] } });
read('pattern-exact-and-star-mixed', { fields: [{ path: 'a', class: 'x.y' }], purpose: 'p', coverage: { p: ['x', 'x.y.*', 'z.*'] } });
read('pattern-x-dot-star-matches-x-dot', { fields: [{ path: 'a', class: 'x.' }], purpose: 'p', coverage: { p: ['x.*'] } });
read('pattern-no-star-suffix', { fields: [{ path: 'a', class: 'xy' }], purpose: 'p', coverage: { p: ['x*'] } });
read('purpose-proto', { fields: [{ path: 'a', class: 'x' }], purpose: 'constructor', coverage: COVER });

// ---------------------------------------------------------------- write
fs.writeFileSync(OUT, JSON.stringify({ about: 'TS-reference oracle for KillFacts*Test (OracleFacts.kt, ParamProvenance.kt); generated by tools/pca-audit/kotlin-mutate/killFacts-oracle-gen.mjs.', cases }, null, 0) + '\n');
console.log(`cases: ${cases.length}`);
