// Oracle for the Kotlin "Session" kill tests (KillSessionTest.kt): runs the TS reference (intent-session.ts,
// intent-session-caveat.ts) on targeted inputs and writes the golden JSON. Deterministic (byte-for-byte reproducible).
//   tsx <this> <out.json>       (out: sdks/kotlin-pca/test-data/killSession.json)
// Numbers whose LEXICAL form matters (-0, 1.0, 1e400) are carried as Raw(text, value): the TS reference sees the value
// JSON.parse would yield, the golden file carries the text.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l) => { const sk = seed(l); return { sk, pk: pca.b64u(pca.publicKeyOf(sk)) }; };
const dg = (l) => pca.b64u(seed(`ksess/${l}`));

class Raw { constructor(text, value) { this.text = text; this.value = value; } }
const NEG0 = new Raw('-0', -0);
const r = (text) => new Raw(text, JSON.parse(text === '1e400' ? '1e999' : text));
const INF = new Raw('1e400', Infinity);

const toTs = (x) => {
  if (x instanceof Raw) return x.value;
  if (Array.isArray(x)) return x.map(toTs);
  if (x && typeof x === 'object') { const o = {}; for (const [k, v] of Object.entries(x)) o[k] = toTs(v); return o; }
  return x;
};
const raws = [];
const toJsonable = (x) => {
  if (x instanceof Raw) { raws.push(x.text); return `__RAW${raws.length - 1}__`; }
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
const rep = (s, n) => s.repeat(n);

const names = new Set();
const out = { wire: [], caveat: [], grant: [], root: [] };
const add = (sec, c) => {
  const k = `${sec}/${c.name}`;
  if (names.has(k)) throw new Error(`duplicate ${k}`);
  names.add(k);
  out[sec].push(c);
};

// ---------------------------------------------------------------- the wire (validateIntentSessionWire)
const W = () => ({ session: dg('s'), root: dg('r'), seq: 0, schema: dg('sch') });
const wire = (name, arg) => add('wire', { name, arg: toJsonable(clone(arg)), ts: pca.validateIntentSessionWire(toTs(arg)) });
const wm = (name, f) => { const w = W(); f(w); wire(name, w); };
const dgs = (p, n) => Array.from({ length: n }, (_, i) => dg(`${p}${i}`));
wire('valid-min', W());
wire('not-object-string', 'x');
wire('not-object-array', []);
wire('not-object-null', null);
wm('unknown-field', (w) => { w.zz = 1; });
for (const k of ['session', 'root', 'seq', 'schema']) wm(`missing-${k}`, (w) => { delete w[k]; });
for (const k of ['session', 'root', 'schema']) {
  wm(`${k}-short`, (w) => { w[k] = 'abc'; });
  wm(`${k}-number`, (w) => { w[k] = 1; });
}
for (const [n, v] of [['neg', -1], ['max', 2147483647], ['over', 2147483648], ['string', '0'], ['frac', 0.5], ['negzero', NEG0], ['one-point-zero', r('1.0')], ['null', null], ['huge', 9007199254740992]]) wm(`seq-${n}`, (w) => { w.seq = v; });
const accE = (id, post = 1, extra = {}) => ({ id, post, ...extra });
wm('acc-ok-16', (w) => { w.acc = Array.from({ length: 16 }, (_, i) => accE(`a${i}`, i)); });
wm('acc-17', (w) => { w.acc = Array.from({ length: 17 }, (_, i) => accE(`a${i}`, i)); });
wm('acc-object', (w) => { w.acc = {}; });
wm('acc-null', (w) => { w.acc = null; });
wm('acc-empty', (w) => { w.acc = []; });
wm('acc-entry-string', (w) => { w.acc = [accE('a'), 'x']; });
wm('acc-entry-unknown', (w) => { w.acc = [accE('a', 1, { zz: 1 })]; });
wm('acc-entry-receipt-ok', (w) => { w.acc = [accE('a', 1, { receipt: dg('rc') })]; });
wm('acc-entry-receipt-bad', (w) => { w.acc = [accE('a', 0), accE('b', 1, { receipt: 'abc' })]; });
wm('acc-entry-receipt-null', (w) => { w.acc = [accE('a', 1, { receipt: null })]; });
for (const [n, id] of [['number', 1], ['empty', ''], ['dash', 'a-b'], ['64', rep('a', 64)], ['65', rep('a', 65)], ['missing', undefined]]) {
  wm(`acc-id-${n}`, (w) => { const e = accE(id); if (id === undefined) delete e.id; w.acc = [accE('z'), e]; });
}
wm('acc-dup', (w) => { w.acc = [accE('a'), accE('b'), accE('a')]; });
for (const [n, p] of [['neg', -1], ['frac', 1.5], ['string', '1'], ['negzero', NEG0], ['zero', 0], ['missing', undefined], ['safe-max', 9007199254740991], ['unsafe', 9007199254740992]]) {
  wm(`acc-post-${n}`, (w) => { const e = accE('a', p); if (p === undefined) delete e.post; w.acc = [e]; });
}
const listCases = (name, max) => {
  wm(`${name}-ok-${max}`, (w) => { w[name] = dgs(name, max); });
  wm(`${name}-${max + 1}`, (w) => { w[name] = dgs(name, max + 1); });
  wm(`${name}-empty`, (w) => { w[name] = []; });
  wm(`${name}-object`, (w) => { w[name] = {}; });
  wm(`${name}-null`, (w) => { w[name] = null; });
  wm(`${name}-entry-bad`, (w) => { w[name] = [dg('x'), 'abc']; });
  wm(`${name}-entry-number`, (w) => { w[name] = [1]; });
  wm(`${name}-dup`, (w) => { w[name] = [dg('x'), dg('y'), dg('x')]; });
  wm(`${name}-two`, (w) => { w[name] = [dg('x'), dg('y')]; });
};
listCases('facts', 16);
listCases('classes', 8);
listCases('labels', 16);
wm('offer_set-ok', (w) => { w.offer_set = dg('o'); });
wm('offer_set-bad', (w) => { w.offer_set = 'abc'; });
wm('offer_set-null', (w) => { w.offer_set = null; });
const provOf = (n, refs = ['f1']) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`action.params.p${i}`, refs]));
wm('prov-ok-32', (w) => { w.prov = provOf(32); });
wm('prov-33', (w) => { w.prov = provOf(33); });
wm('prov-empty', (w) => { w.prov = {}; });
wm('prov-array', (w) => { w.prov = []; });
wm('prov-null', (w) => { w.prov = null; });
for (const [n, k] of [['no-name', 'action.params.'], ['dash', 'action.params.a-b'], ['prefix', 'x.action.params.a'], ['suffix', 'action.params.a.b'], ['65', `action.params.${rep('a', 65)}`], ['64', `action.params.${rep('a', 64)}`], ['other', 'action.verb']]) {
  wm(`prov-key-${n}`, (w) => { w.prov = { 'action.params.ok': ['f'], [k]: ['f'] }; });
}
for (const [n, refs] of [
  ['string', 'f'], ['null', null], ['empty', []], ['8', Array.from({ length: 8 }, (_, i) => `r${i}`)], ['9', Array.from({ length: 9 }, (_, i) => `r${i}`)],
  ['entry-empty', ['a', '']], ['entry-number', ['a', 1]], ['entry-lone', ['a', '\ud800']], ['entry-lone-low', ['\udc00x']],
  ['entry-256', [rep('a', 256)]], ['entry-257', [rep('a', 257)]], ['entry-2byte-128', [rep('é', 128)]], ['entry-2byte-129', [rep('é', 129)]],
  ['entry-3byte-85', [rep('ࠀ', 85)]], ['entry-3byte-86', [rep('ࠀ', 86)]], ['entry-4byte-64', [rep('😀', 64)]], ['entry-4byte-65', [rep('😀', 65)]],
  ['entry-mixed-256', [rep('߿', 127) + 'ab']], ['entry-mixed-257', [rep('߿', 127) + 'abc']], ['entry-7f-256', [rep('\u007f', 256)]], ['entry-80-129', [rep('\u0080', 129)]],
]) wm(`prov-refs-${n}`, (w) => { w.prov = { 'action.params.a': refs }; });
wm('map_form-commit', (w) => { w.map_form = 'commit'; });
wm('map_form-plain', (w) => { w.map_form = 'plain'; });
wm('map_form-null', (w) => { w.map_form = null; });
wm('full-valid', (w) => {
  w.seq = 7; w.acc = [accE('a', 0, { receipt: dg('rc') })]; w.facts = [dg('f')]; w.offer_set = dg('o'); w.prov = provOf(2);
  w.classes = [dg('c')]; w.labels = [dg('l')]; w.map_form = 'commit';
});
// order of checks: a later bad member is reported only after earlier ones pass
wm('order-facts-then-offer', (w) => { w.facts = 'x'; w.offer_set = 'abc'; });
wm('order-offer-then-prov', (w) => { w.offer_set = 'abc'; w.prov = 'x'; });
wm('order-prov-then-classes', (w) => { w.prov = 'x'; w.classes = 'x'; });
wm('order-classes-then-labels', (w) => { w.classes = 'x'; w.labels = 'x'; });
wm('order-labels-then-map_form', (w) => { w.labels = 'x'; w.map_form = 'x'; });
wm('order-acc-then-facts', (w) => { w.acc = 'x'; w.facts = 'x'; });
wm('order-seq-then-acc', (w) => { w.seq = -1; w.acc = 'x'; });

// ---------------------------------------------------------------- the grant caveat (intentSessionCaveatError)
const C0 = () => ({ type: 'intent_session', session: dg('s'), seq: 0, root: dg('r') });
const cav = (name, arg) => add('caveat', { name, arg: toJsonable(clone(arg)), ts: pca.intentSessionCaveatError(toTs(arg)) });
const cm = (name, f) => { const c = C0(); f(c); cav(name, c); };
cav('valid-seq0', C0());
cm('valid-max', (c) => { c.seq = 2147483647; c.prev = dg('p'); });
cm('valid-seq1', (c) => { c.seq = 1; c.prev = dg('p'); });
cav('not-object', 'x');
cav('null', null);
cav('array', [C0()]);
cm('other-type', (c) => { c.type = 'envelope'; });
cm('no-type', (c) => { delete c.type; });
cm('unknown-member', (c) => { c.zz = 1; });
cm('session-short', (c) => { c.session = 'abc'; });
cm('root-short', (c) => { c.root = 'abc'; });
cm('session-missing', (c) => { delete c.session; });
cm('root-missing', (c) => { delete c.root; });
for (const [n, s] of [['neg', -1], ['over', 2147483648], ['string', '0'], ['frac', 0.5], ['negzero', NEG0], ['null', null], ['missing', undefined], ['one-point-zero', r('1.0')]]) {
  cm(`seq-${n}`, (c) => { if (s === undefined) delete c.seq; else c.seq = s; });
}
cm('seq0-with-prev', (c) => { c.prev = dg('p'); });
cm('seq0-with-prev-null', (c) => { c.prev = null; });
cm('seq1-no-prev', (c) => { c.seq = 1; });
cm('seq1-prev-short', (c) => { c.seq = 1; c.prev = 'abc'; });
cm('seq1-prev-null', (c) => { c.seq = 1; c.prev = null; });
cm('seq1-prev-number', (c) => { c.seq = 1; c.prev = 1; });
cm('seq-1.0-prev', (c) => { c.seq = r('1.0'); c.prev = dg('p'); });
cm('seq-0.0-noprev', (c) => { c.seq = r('0.0'); });

// ---------------------------------------------------------------- the grant's session caveat (grantSessionCaveat)
const gr = (name, g) => {
  const t = toTs(g);
  const f = pca.grantSessionCaveat(t);
  add('grant', { name, arg: toJsonable(clone(g)), want_index: f === undefined ? null : t.caveats.indexOf(f) });
};
const first = C0();
const second = { ...C0(), session: dg('second') };
gr('string', 'x');
gr('null', null);
gr('array', [{ caveats: [first] }]);
gr('no-caveats', {});
gr('caveats-string', { caveats: 'x' });
gr('caveats-object', { caveats: { 0: first } });
gr('caveats-empty', { caveats: [] });
gr('none-session', { caveats: [{ type: 'envelope' }, 'x', null] });
gr('first-of-two', { caveats: ['x', null, ['intent_session'], { type: 'envelope' }, first, second] });
gr('only', { caveats: [second] });
gr('malformed-still-returned', { caveats: [{ type: 'intent_session' }, first] });

// ---------------------------------------------------------------- the session root (sessionRootShapeError, verifySessionRoot)
const P = mk('ksess/principal');
const P2 = mk('ksess/principal-2');
const REV = mk('ksess/rev-auth');
const tripAcc = (id) => ({ id, agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500000, holder: { kind: 'site_local' } });
const mon = (id) => ({ id, kind: 'never', p: { verb: 'air.book' } });
const body0 = () => ({
  v: 1, kind: 'pca-intent-session', session: dg('session'), principals: [{ key: P.pk }], intent_ref: dg('ref'),
  schema: { aud: 'skyair.example', digest: dg('schema') }, layers: { task: { map_digest: dg('map0') } },
  accumulators: [tripAcc('trip_spend')], monitors: [], question_uri: 'https://principal.example/q', expires_at: 1800000003600000,
});
const signed = (b, sk = P.sk, suite) => pca.signSessionRoot(b, sk, suite);
const S0 = signed(body0());
// `pins`: the VERIFIER's PQ pins (R3-01: a PQ root verifies only under them, never its own principals entry); recorded as
// `pins` and passed by the Kotlin test as the second argument of verifyRoot.
const root = (name, S, note, pins) => {
  const ts = toTs(S);
  const shape = pca.sessionRootShapeError(ts);
  const v = pca.verifySessionRoot(ts, pins ? { pqPins: pins } : {});
  const verify = v.ok ? null : v.reason;
  // A PQ-suite root WITHOUT pq_pk: the reference's bindSuiteFields signs `pq_pk: undefined` into the body and its strict
  // canonicalizer throws; Kotlin binds no pq_pk and the pinned-suite check refuses (no PQ key). Same verdict (refused),
  // different refusal text: the golden pins Kotlin's text in `kt_verify`.
  const kt = verify === 'malformed session root: canonicalize: unsupported type undefined' ? { kt_verify: 'session root signature invalid' } : {};
  // A non-finite number (1e400 parses to Infinity): both strict canonicalizers refuse it; Kotlin keeps the lexical form
  // (normalize leaves a non-finite number as written) and refuses the exponent spelling. Kotlin's text is pinned.
  if (shape === 'malformed session root: canonicalize: non-finite number') {
    kt.kt_shape = 'malformed session root: canonicalize: exponent form is not allowed';
    kt.kt_verify = kt.kt_shape;
  }
  add('root', { name, arg: toJsonable(clone(S)), ...(pins ? { pins } : {}), shape, verify, ...kt, ...(note ? { note } : {}) });
};
const rm = (name, f, base = S0, pins) => { const S = clone(base); f(S); root(name, S, undefined, pins); };
if (pca.sessionRootShapeError(S0) !== null || !pca.verifySessionRoot(S0).ok) throw new Error('base root');
root('base', S0);
root('not-object-string', 'x');
root('not-object-null', null);
root('not-object-array', [S0]);
rm('unknown-member', (S) => { S.zz = 1; });
for (const k of ['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors', 'question_uri', 'expires_at', 'signer', 'sig']) rm(`missing-${k}`, (S) => { delete S[k]; });
rm('v-2', (S) => { S.v = 2; });
rm('v-1.0', (S) => { S.v = r('1.0'); });
rm('v-string', (S) => { S.v = '1'; });
rm('v-true', (S) => { S.v = true; });
rm('kind-other', (S) => { S.kind = 'pca-intent-other'; });
rm('session-short', (S) => { S.session = 'abc'; });
rm('intent_ref-short', (S) => { S.intent_ref = 'abc'; });
const principals = (n, first0 = { key: P.pk }) => [first0, ...Array.from({ length: n - 1 }, (_, i) => ({ key: dg(`p${i}`) }))];
rm('principals-object', (S) => { S.principals = {}; });
rm('principals-null', (S) => { S.principals = null; });
rm('principals-empty', (S) => { S.principals = []; });
rm('principals-16', (S) => { S.principals = principals(16); });
rm('principals-17', (S) => { S.principals = principals(17); });
rm('principals-2', (S) => { S.principals = principals(2); });
rm('principal-not-object', (S) => { S.principals = ['x', { key: P.pk }]; });
rm('principal-null', (S) => { S.principals = [{ key: P.pk }, null]; });
rm('principal-array', (S) => { S.principals = [[P.pk]]; });
rm('principal-unknown-member', (S) => { S.principals = [{ key: P.pk, note: 'x' }]; });
rm('principal-unknown-member-2nd', (S) => { S.principals = [{ key: P.pk }, { key: dg('o'), alg: 'ed25519', pq_pk: 'AAAA', x: 1 }]; });
rm('principal-all-members', (S) => { S.principals = [{ key: P.pk }, { key: dg('o'), alg: 'ed25519', pq_pk: 'AAAA' }]; });
rm('principal-key-short', (S) => { S.principals = [{ key: P.pk }, { key: 'abc' }]; });
rm('principal-key-missing', (S) => { S.principals = [{ key: P.pk }, { alg: 'ed25519' }]; });
rm('principal-key-number', (S) => { S.principals = [{ key: 1 }]; });
rm('principal-alg-unknown', (S) => { S.principals = [{ key: P.pk, alg: 'nope-dsa' }]; });
rm('principal-alg-number', (S) => { S.principals = [{ key: P.pk, alg: 1 }]; });
rm('principal-alg-null', (S) => { S.principals = [{ key: P.pk, alg: null }]; });
rm('principal-alg-ml-dsa-65', (S) => { S.principals = [{ key: P.pk, alg: 'ml-dsa-65' }]; });
rm('principal-pq_pk-ok', (S) => { S.principals = [{ key: P.pk, pq_pk: 'AAAA' }]; });
rm('principal-pq_pk-bad', (S) => { S.principals = [{ key: P.pk, pq_pk: 'AA=A' }]; });
rm('principal-pq_pk-null', (S) => { S.principals = [{ key: P.pk, pq_pk: null }]; });
rm('principal-pq_pk-number', (S) => { S.principals = [{ key: P.pk, pq_pk: 1 }]; });
rm('principal-pq_pk-empty', (S) => { S.principals = [{ key: P.pk, pq_pk: '' }]; });
rm('principal-dup', (S) => { S.principals = [{ key: P.pk }, { key: P.pk }]; });
rm('principal-dup-later', (S) => { S.principals = [{ key: P.pk }, { key: dg('a') }, { key: dg('a') }]; });
rm('schema-string', (S) => { S.schema = 'x'; });
rm('schema-null', (S) => { S.schema = null; });
rm('schema-extra', (S) => { S.schema.x = 1; });
rm('schema-only-aud', (S) => { delete S.schema.digest; });
rm('schema-only-digest', (S) => { delete S.schema.aud; });
rm('schema-aud-digest-swapped-keys', (S) => { S.schema = { aud: 'a', dgst: dg('x') }; });
rm('schema-aud-number', (S) => { S.schema.aud = 1; });
rm('schema-aud-empty', (S) => { S.schema.aud = ''; });
rm('schema-digest-short', (S) => { S.schema.digest = 'abc'; });
rm('layers-string', (S) => { S.layers = 'x'; });
rm('layers-null', (S) => { S.layers = null; });
rm('layers-array', (S) => { S.layers = []; });
rm('layers-unknown', (S) => { S.layers.site = { digest: dg('s') }; });
rm('layers-empty', (S) => { S.layers = {}; });
rm('task-string', (S) => { S.layers.task = 'x'; });
rm('task-null', (S) => { S.layers.task = null; });
rm('task-extra', (S) => { S.layers.task.x = 1; });
rm('task-empty', (S) => { S.layers.task = {}; });
rm('task-other-member', (S) => { S.layers.task = { digest: dg('m') }; });
rm('task-digest-short', (S) => { S.layers.task = { map_digest: 'abc' }; });
rm('org-ok', (S) => { S.layers.org = { digest: dg('org') }; });
rm('org-extra-ok', (S) => { S.layers.org = { digest: dg('org'), name: 'acme' }; });
rm('org-null', (S) => { S.layers.org = null; });
rm('org-string', (S) => { S.layers.org = 'x'; });
rm('org-empty', (S) => { S.layers.org = {}; });
rm('org-digest-short', (S) => { S.layers.org = { digest: 'abc' }; });
const std = (f) => (S) => { const d = { profile: 'travel', version: 1, digest: dg('std') }; if (f) f(d); S.layers.std = d; };
rm('std-ok', std());
rm('std-version-2', std((d) => { d.version = 2; }));
rm('std-version-1.0', std((d) => { d.version = r('1.0'); }));
rm('std-version-big', std((d) => { d.version = 9007199254740991; }));
rm('std-version-unsafe', std((d) => { d.version = 9007199254740992; }));
rm('std-profile-128', std((d) => { d.profile = rep('p', 128); }));
rm('std-profile-2byte-64', std((d) => { d.profile = rep('é', 64); }));
rm('std-profile-2byte-65', std((d) => { d.profile = rep('é', 65); }));
rm('std-null', (S) => { S.layers.std = null; });
rm('std-string', (S) => { S.layers.std = 'x'; });
rm('std-extra', std((d) => { d.x = 1; }));
rm('std-missing-digest', std((d) => { delete d.digest; }));
rm('std-missing-profile', std((d) => { delete d.profile; }));
rm('std-missing-version', std((d) => { delete d.version; }));
rm('std-profile-number', std((d) => { d.profile = 1; }));
rm('std-profile-empty', std((d) => { d.profile = ''; }));
rm('std-profile-129', std((d) => { d.profile = rep('p', 129); }));
rm('std-version-0', std((d) => { d.version = 0; }));
rm('std-version-neg', std((d) => { d.version = -1; }));
rm('std-version-negzero', std((d) => { d.version = NEG0; }));
rm('std-version-fraction', std((d) => { d.version = 1.5; }));
rm('std-version-string', std((d) => { d.version = '1'; }));
rm('std-digest-short', std((d) => { d.digest = 'abc'; }));
rm('std-and-org-ok', (S) => { std()(S); S.layers.org = { digest: dg('org') }; });
const accs = (n) => Array.from({ length: n }, (_, i) => tripAcc(`a${i}`));
const mons = (n) => Array.from({ length: n }, (_, i) => mon(`m${i}`));
rm('accumulators-object', (S) => { S.accumulators = {}; });
rm('accumulators-null', (S) => { S.accumulators = null; });
rm('accumulators-empty', (S) => { S.accumulators = []; });
rm('accumulators-16', (S) => { S.accumulators = accs(16); });
rm('accumulators-17', (S) => { S.accumulators = accs(17); });
rm('accumulators-dup', (S) => { S.accumulators = [tripAcc('a'), tripAcc('b'), tripAcc('a')]; });
rm('accumulator-bad', (S) => { S.accumulators = [tripAcc('a'), { id: 'b' }]; });
rm('accumulator-string', (S) => { S.accumulators = ['x']; });
rm('monitors-object', (S) => { S.monitors = {}; });
rm('monitors-null', (S) => { S.monitors = null; });
rm('monitors-16', (S) => { S.monitors = mons(16); });
rm('monitors-17', (S) => { S.monitors = mons(17); });
rm('monitors-dup', (S) => { S.monitors = [mon('m'), mon('n'), mon('m')]; });
rm('monitors-share-acc-id', (S) => { S.monitors = [mon('trip_spend')]; });
rm('monitor-bad', (S) => { S.monitors = [mon('a'), { id: 'm' }]; });
rm('monitor-then-question-empty', (S) => { S.monitors = mons(2); S.question_uri = ''; });
rm('accs-then-question-empty', (S) => { S.accumulators = accs(2); S.question_uri = ''; });
rm('question-number', (S) => { S.question_uri = 1; });
rm('question-null', (S) => { S.question_uri = null; });
rm('question-empty', (S) => { S.question_uri = ''; });
rm('question-2048', (S) => { S.question_uri = 'h' + rep('q', 2047); });
rm('question-2049', (S) => { S.question_uri = 'h' + rep('q', 2048); });
rm('question-2byte-1024', (S) => { S.question_uri = rep('é', 1024); });
rm('question-2byte-1025', (S) => { S.question_uri = rep('é', 1025); });
rm('question-lone-surrogate', (S) => { S.question_uri = 'h\ud800'; });
const rev = (f) => (S) => { const x = { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: REV.pk }; if (f) f(x); S.revocation = x; };
rm('revocation-ok', rev());
rm('revocation-pq_pk-ok', rev((x) => { x.pq_pk = 'AAAA'; }));
rm('revocation-null', (S) => { S.revocation = null; });
rm('revocation-string', (S) => { S.revocation = 'x'; });
rm('revocation-array', (S) => { S.revocation = []; });
rm('revocation-unknown', rev((x) => { x.x = 1; }));
rm('revocation-empty', (S) => { S.revocation = {}; });
rm('revocation-uri-number', rev((x) => { x.epoch_uri = 1; }));
rm('revocation-uri-empty', rev((x) => { x.epoch_uri = ''; }));
rm('revocation-uri-missing', rev((x) => { delete x.epoch_uri; }));
rm('revocation-age-negative', rev((x) => { x.max_age_s = -1; }));
rm('revocation-age-zero', rev((x) => { x.max_age_s = 0; }));
rm('revocation-age-frac', rev((x) => { x.max_age_s = 1.5; }));
rm('revocation-age-missing', rev((x) => { delete x.max_age_s; }));
rm('revocation-key-short', rev((x) => { x.key = 'abc'; }));
rm('revocation-key-missing', rev((x) => { delete x.key; }));
rm('revocation-key-principal', rev((x) => { x.key = P.pk; }));
rm('revocation-key-2nd-principal', (S) => { S.principals = principals(3); rev((x) => { x.key = dg('p1'); })(S); });
rm('revocation-pq_pk-bad', rev((x) => { x.pq_pk = 'AA=A'; }));
rm('revocation-pq_pk-null', rev((x) => { x.pq_pk = null; }));
rm('flows-ok', (S) => { S.flows = {}; });
rm('flows-string', (S) => { S.flows = 'x'; });
rm('flows-null', (S) => { S.flows = null; });
rm('flows-array', (S) => { S.flows = []; });
rm('flows-lone-surrogate', (S) => { S.flows = { a: '\ud800' }; });
rm('flows-infinite', (S) => { S.flows = { a: INF }; });
rm('org-extra-lone-surrogate', (S) => { S.layers.org = { digest: dg('org'), name: 'x\udc00' }; });
for (const [n, e] of [['negative', -1], ['frac', 1.5], ['string', '1'], ['null', null], ['zero', 0], ['negzero', NEG0], ['unsafe', 9007199254740992]]) rm(`expires-${n}`, (S) => { S.expires_at = e; });
rm('signer-short', (S) => { S.signer = 'abc'; });
rm('signer-number', (S) => { S.signer = 1; });
rm('signer-not-principal', (S) => { S.signer = dg('other'); });
rm('signer-rev-key', (S) => { rev()(S); S.signer = REV.pk; });
rm('alg-unknown', (S) => { S.alg = 'nope-dsa'; });
rm('alg-number', (S) => { S.alg = 1; });
rm('alg-null', (S) => { S.alg = null; });
rm('alg-ed25519', (S) => { S.alg = 'ed25519'; });
rm('alg-ed25519-pq_pk', (S) => { S.alg = 'ed25519'; S.pq_pk = 'AAAA'; });
rm('ed25519-pq_pk', (S) => { S.pq_pk = 'AAAA'; });
rm('ed25519-pq_pk-null', (S) => { S.pq_pk = null; });
rm('ed25519-pq_sig', (S) => { S.pq_sig = 'AAAA'; });
rm('ml-dsa-65-no-pq_pk', (S) => { S.alg = 'ml-dsa-65'; });
rm('ml-dsa-65-pq_pk-pq_sig', (S) => { S.alg = 'ml-dsa-65'; S.pq_pk = 'AAAA'; S.pq_sig = 'AAAA'; });
rm('sig-number', (S) => { S.sig = 1; });
rm('sig-null', (S) => { S.sig = null; });
rm('sig-lone-surrogate', (S) => { S.sig = '\ud800'; });
rm('pq_sig-lone-surrogate-ml', (S) => { S.alg = 'ml-dsa-65'; S.pq_sig = '\ud800'; });
rm('pq_pk-lone-surrogate-ml', (S) => { S.alg = 'ml-dsa-65'; S.pq_pk = '\ud800'; });
rm('sig-other', (S) => { S.sig = S0.sig.slice(0, -2) + (S0.sig.endsWith('AA') ? 'AQ' : 'AA'); });
rm('tamper-question', (S) => { S.question_uri = 'https://other.example/q'; });
rm('tamper-expires', (S) => { S.expires_at = 1800000003600001; });
rm('tamper-add-flows', (S) => { S.flows = {}; });
rm('tamper-add-revocation', rev());

// signed variants: flows and revocation in the signed body; a PQ root signed by the SECOND principal (its own pin)
const withFlows = signed({ ...body0(), flows: { r: { x: 1 } } });
root('signed-flows', withFlows);
rm('signed-flows-drop', (S) => { delete S.flows; }, withFlows);
rm('signed-flows-tamper', (S) => { S.flows = { r: { x: 2 } }; }, withFlows);
const withRev = signed({ ...body0(), revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: REV.pk } });
root('signed-revocation', withRev);
rm('signed-revocation-drop', (S) => { delete S.revocation; }, withRev);
const withBoth = signed({ ...body0(), revocation: { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: REV.pk }, flows: { f: [] } });
root('signed-both', withBoth);
const ML = pca.mlDsa65Keygen(seed('ksess/ml-dsa-65'));
const ML2 = pca.mlDsa65Keygen(seed('ksess/ml-dsa-65-other'));
const mlPk = pca.encodeMlDsaPublicKey(ML.publicKey);
const ml2Pk = pca.encodeMlDsaPublicKey(ML2.publicKey);
const pqBody = { ...body0(), principals: [{ key: P2.pk }, { key: P.pk, alg: 'ml-dsa-65', pq_pk: mlPk }] };
const pqS = signed(pqBody, P.sk, { alg: 'ml-dsa-65', mlDsa: ML });
const PINS = { [P.pk]: mlPk };
if (pca.sessionRootShapeError(pqS) !== null || !pca.verifySessionRoot(pqS, { pqPins: PINS }).ok) throw new Error('pq root');
root('pq-second-principal', pqS, undefined, PINS);
root('pq-no-verifier-pin', pqS);
root('pq-verifier-pin-other-key', pqS, undefined, { [P2.pk]: mlPk });
root('pq-verifier-pin-mismatch', pqS, undefined, { [P.pk]: ml2Pk });
root('pq-verifier-pin-not-string', pqS, undefined, { [P.pk]: 1 });
root('pq-entry-other-resigned', signed({ ...body0(), principals: [{ key: P2.pk }, { key: P.pk, alg: 'ml-dsa-65', pq_pk: ml2Pk }] }, P.sk, { alg: 'ml-dsa-65', mlDsa: ML }), undefined, PINS);
rm('pq-first-principal-has-other-pin', (S) => { S.principals = [{ key: P2.pk, pq_pk: ml2Pk }, { key: P.pk, alg: 'ml-dsa-65', pq_pk: mlPk }]; }, pqS, PINS);
root('pq-first-principal-has-other-pin-resigned', signed({ ...body0(), principals: [{ key: P2.pk, pq_pk: ml2Pk }, { key: P.pk, alg: 'ml-dsa-65', pq_pk: mlPk }] }, P.sk, { alg: 'ml-dsa-65', mlDsa: ML }), undefined, PINS);
rm('pq-signer-pin-removed', (S) => { S.principals = [{ key: P2.pk }, { key: P.pk, alg: 'ml-dsa-65' }]; }, pqS, PINS);
rm('pq-signer-pin-other', (S) => { S.principals = [{ key: P2.pk }, { key: P.pk, alg: 'ml-dsa-65', pq_pk: ml2Pk }]; }, pqS, PINS);
rm('pq-artifact-pk-other', (S) => { S.pq_pk = ml2Pk; }, pqS, PINS);
rm('pq-drop-alg', (S) => { delete S.alg; }, pqS, PINS);
rm('pq-sig-flip', (S) => { S.sig = (S.sig[0] === 'A' ? 'B' : 'A') + S.sig.slice(1); }, pqS, PINS);
rm('pq-tamper-question', (S) => { S.question_uri = 'https://other.example/q'; }, pqS, PINS);
// the same PQ root signed by the FIRST principal (its own entry declares the key; the verifier pins it)
const pqFirst = signed({ ...body0(), principals: [{ key: P.pk, pq_pk: mlPk }, { key: P2.pk }] }, P.sk, { alg: 'ml-dsa-65', mlDsa: ML });
root('pq-first-principal', pqFirst, undefined, PINS);
// ed25519 root signed by the second principal
root('ed-second-principal', signed({ ...body0(), principals: [{ key: P2.pk }, { key: P.pk }] }));
root('ed-second-signer-p2', signed({ ...body0(), principals: [{ key: P.pk }, { key: P2.pk }] }, P2.sk));

let text = JSON.stringify(out, null, 1);
text = text.replace(/"__RAW(\d+)__"/g, (_, i) => raws[Number(i)]);
fs.writeFileSync(process.argv[2], text + '\n');
console.log(`wire ${out.wire.length}, caveat ${out.caveat.length}, grant ${out.grant.length}, root ${out.root.length}`);
