// Differential oracle for the Java IntentSession / IntentRevocation 0.4.2 mutation kills
// (sdks/java-pca/test/net/atlasauth/pca/K042SessRevocTest.java).
//
// Every case is fed STRAIGHT to the reference (packages/pca/src/intent-session.ts, intent-session-caveat.ts,
// intent-revocation.ts) and the exact reason (null = ok) is recorded:
//   wire[]    validateIntentSessionWire(v)
//   caveat[]  intentSessionCaveatError(c)
//   root[]    sessionRootShapeError(s) and verifySessionRoot(s, {pqPins}).reason   (signed by the reference signer; `pq_pins`,
//             the verifier's pins as raw JSON text, when the case passes any: a PQ root verifies only under them)
//   rev[]     checkSessionRevocation(ev, {session, authority, ids, now, maxAgeMs, scope?, last?}).reason
//             with ev / last JSON and the parameters given explicitly (the Java test calls checkSessionRevocation)
//   prim[]    the primitives.intent_revocation form: the raw JSON text of the input (numbers spelled as written, e.g.
//             1e3) and the reason of checkSessionRevocation over JSON.parse(text) (scope never passed)
// Reasons of a thrown internal error ("... (fail closed): <message>") differ by language by design: only the prefix up
// to "(fail closed): " is kept and the Java test compares that prefix.
//
//   npx tsx tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts     (from the repo root; deterministic)
// writes sdks/java-pca/test-data/k042-sessrevoc-cases.json
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import * as PCA from '../../../packages/pca/src/index.ts';

// tsx may load the sources as CommonJS (no package "type"): the namespace is then on .default
const pca: any = (PCA as any).b64u ? PCA : (PCA as any).default;

const ROOT = new URL('../../../', import.meta.url).pathname;
const seed = (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const mk = (l: string) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const dg = (l: string) => pca.b64u(seed('k042sr/' + l));
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

function ser(v: any): string {
  if (v === null) return 'null';
  if (typeof v === 'number') { if (Object.is(v, -0)) return '-0'; if (!Number.isFinite(v)) throw new Error('non-finite'); return JSON.stringify(v); }
  if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => JSON.stringify(k) + ':' + ser(x)).join(',') + '}';
  throw new Error('unserializable ' + typeof v);
}
const FAIL_CLOSED = '(fail closed): ';
const cut = (r: string | null | undefined) => (r == null ? null : r.includes(FAIL_CLOSED) ? r.slice(0, r.indexOf(FAIL_CLOSED) + FAIL_CLOSED.length) : r);

const out: Record<string, any[]> = { wire: [], caveat: [], root: [], rev: [], prim: [] };
const seen = new Set<string>();
const push = (kind: string, name: string, rec: any) => {
  if (seen.has(kind + '/' + name)) throw new Error('dup ' + kind + '/' + name);
  seen.add(kind + '/' + name);
  out[kind]!.push({ name, ...rec });
};

// ---- intent_session wire ---------------------------------------------------------------------------------------
const W0 = { session: dg('s'), root: dg('r'), seq: 3, schema: dg('sc') };
const wire = (name: string, v: any) => push('wire', name, { v: ser(v), reason: pca.validateIntentSessionWire(JSON.parse(ser(v))) });
const W = (over: any) => ({ ...clone(W0), ...over });
const digests = (p: string, n: number) => Array.from({ length: n }, (_, i) => dg(p + i));
wire('ok', W0);
wire('ok-full', W({ acc: [{ id: 'a', post: 0 }, { id: 'b', post: 5, receipt: dg('rc') }], facts: digests('f', 2), offer_set: dg('os'), prov: { 'action.params.x': ['a', 'b'] }, classes: digests('c', 1), labels: digests('l', 1), map_form: 'commit' }));
wire('not-object', [1]);
wire('unknown', W({ zz: 1 }));
for (const k of ['session', 'root', 'seq', 'schema']) { const v = W({}); delete (v as any)[k]; wire('missing-' + k, v); }
for (const k of ['session', 'root', 'schema']) wire('bad-' + k, W({ [k]: 'abc' }));
wire('seq-max', W({ seq: 2147483647 }));
wire('seq-over', W({ seq: 2147483648 }));
wire('seq-neg', W({ seq: -1 }));
wire('acc-not-array', W({ acc: { id: 'a' } }));
wire('acc-16', W({ acc: Array.from({ length: 16 }, (_, i) => ({ id: 'a' + i, post: i })) }));
wire('acc-17', W({ acc: Array.from({ length: 17 }, (_, i) => ({ id: 'a' + i, post: i })) }));
wire('acc-entry-not-object', W({ acc: [{ id: 'a', post: 0 }, 'x'] }));
wire('acc-entry-array', W({ acc: [[1]] }));
wire('acc-unknown', W({ acc: [{ id: 'a', post: 0 }, { id: 'b', post: 0, zz: 1 }] }));
wire('acc-id-number', W({ acc: [{ id: 5, post: 0 }] }));
wire('acc-id-bad', W({ acc: [{ id: 'a-b', post: 0 }] }));
wire('acc-id-dup', W({ acc: [{ id: 'a', post: 0 }, { id: 'a', post: 1 }] }));
wire('acc-post-neg', W({ acc: [{ id: 'a', post: -1 }] }));
wire('acc-receipt-bad', W({ acc: [{ id: 'a', post: 0 }, { id: 'b', post: 0, receipt: 'abc' }] }));
for (const [k, max] of [['facts', 16], ['classes', 8], ['labels', 16]] as const) {
  wire(k + '-ok-max', W({ [k]: digests(k, max) }));
  wire(k + '-over', W({ [k]: digests(k, max + 1) }));
  wire(k + '-not-array', W({ [k]: dg('x') }));
  wire(k + '-entry-bad', W({ [k]: [dg('x'), 'abc'] }));
  wire(k + '-dup', W({ [k]: [dg('x'), dg('x')] }));
  wire(k + '-then-bad-map-form', W({ [k]: [dg('x')], map_form: 'plain' }));
}
wire('offer_set-bad', W({ offer_set: 'abc' }));
wire('offer_set-ok-then-bad-map-form', W({ offer_set: dg('os'), map_form: 'plain' }));
wire('prov-not-object', W({ prov: ['action.params.x'] }));
wire('prov-32', W({ prov: Object.fromEntries(Array.from({ length: 32 }, (_, i) => ['action.params.p' + i, ['r']])) }));
wire('prov-33', W({ prov: Object.fromEntries(Array.from({ length: 33 }, (_, i) => ['action.params.p' + i, ['r']])) }));
wire('prov-key-bad', W({ prov: { 'action.params.x': ['r'], 'action.x': ['r'] } }));
wire('prov-refs-not-array', W({ prov: { 'action.params.x': 'r' } }));
wire('prov-refs-empty', W({ prov: { 'action.params.x': [] } }));
wire('prov-refs-8', W({ prov: { 'action.params.x': Array.from({ length: 8 }, (_, i) => 'r' + i) } }));
wire('prov-refs-9', W({ prov: { 'action.params.x': Array.from({ length: 9 }, (_, i) => 'r' + i) } }));
wire('prov-ref-empty', W({ prov: { 'action.params.x': ['r', ''] } }));
wire('prov-ref-number', W({ prov: { 'action.params.x': ['r', 1] } }));
wire('prov-ref-lone-surrogate', W({ prov: { 'action.params.x': ['r', 'a\uD800'] } }));
wire('prov-ref-surrogate-pair', W({ prov: { 'action.params.x': ['a\uD83D\uDE00'] } }));
wire('prov-ref-256', W({ prov: { 'action.params.x': ['é'.repeat(128)] } }));
wire('prov-ref-257', W({ prov: { 'action.params.x': ['é'.repeat(128) + 'x'] } }));
wire('prov-ok-then-bad-map-form', W({ prov: { 'action.params.x': ['r'] }, map_form: 'plain' }));
wire('map_form-null', W({ map_form: null }));
wire('map_form-commit', W({ map_form: 'commit' }));

// ---- intent_session caveat ---------------------------------------------------------------------------------------
const C0 = { type: 'intent_session', session: dg('s'), seq: 0, root: dg('r') };
const C1 = { type: 'intent_session', session: dg('s'), seq: 1, root: dg('r'), prev: dg('p') };
const cav = (name: string, c: any) => push('caveat', name, { c: ser(c), reason: pca.intentSessionCaveatError(JSON.parse(ser(c))) });
cav('ok0', C0);
cav('ok1', C1);
cav('ok-max', { ...C1, seq: 2147483647 });
cav('seq-over', { ...C1, seq: 2147483648 });
cav('seq-neg', { ...C0, seq: -1 });
cav('seq-string', { ...C0, seq: '0' });
cav('not-object', ['intent_session']);
cav('string', 'intent_session');
cav('type-other', { ...C0, type: 'envelope' });
cav('type-missing', { session: dg('s'), seq: 0, root: dg('r') });
cav('unknown', { ...C0, zz: 1 });
cav('session-bad', { ...C0, session: 'abc' });
cav('root-bad', { ...C0, root: 'abc' });
cav('seq0-with-prev', { ...C0, prev: dg('p') });
cav('seq1-no-prev', { ...C0, seq: 1 });
cav('prev-bad', { ...C1, prev: 'abc' });
cav('prev-null', { ...C1, prev: null });

// ---- the session root --------------------------------------------------------------------------------------------
const principal = mk('v2/principal'), second = mk('k042sr/second'), revAuth = mk('v2/revocation-authority');
const trip = (id = 'trip_spend') => ({ id, agg: 'sum', unit: 'usd_cents', sel: { accumulates_into: 'spend.usd_cents' }, win: { kind: 'task' }, key: null, domain_max: 500_000, holder: { kind: 'site_local' } });
const mon = (id: string) => ({ id, kind: 'never', p: { verb: 'air.book' } });
const NOW = 1_800_000_000_000;
const BODY0: any = {
  v: 1, kind: 'pca-intent-session', session: dg('session'), principals: [{ key: principal.pub }], intent_ref: dg('ref'),
  schema: { aud: 'skyair.example', digest: dg('schema') }, layers: { task: { map_digest: dg('map0') } }, accumulators: [trip()], monitors: [],
  question_uri: 'https://atlas.example/q', expires_at: NOW + 86_400_000,
};
const signed = (body: any, who = principal, suite?: any) => pca.signSessionRoot(clone(body), who.sk, suite) as any;
const S0 = signed(BODY0);
function root(name: string, s: any, pins?: Record<string, string>) {
  const p = JSON.parse(ser(s));
  const v = pca.verifySessionRoot(JSON.parse(ser(s)), pins ? { pqPins: pins } : {});
  push('root', name, { s: ser(s), ...(pins ? { pq_pins: ser(pins) } : {}), shape: pca.sessionRootShapeError(p), verify: v.ok ? null : (v as any).reason });
}
// mutate a copy of the SIGNED base (stale sig) and, when the body is still well-formed, also re-signed
function variant(name: string, mut: (s: any) => void, resign = true) {
  const s = clone(S0); mut(s); root(name, s);
  if (!resign) return;
  const body = clone(BODY0); mut(body);
  for (const k of ['signer', 'alg', 'pq_pk', 'sig', 'pq_sig']) delete body[k];
  if (pca.sessionRootShapeError(body, { signed: false }) === null) {
    try { root(name + '+signed', signed(body)); } catch { /* signer not a principal etc. */ }
  }
}
root('ok', S0);
root('not-object', [S0]);
root('string', 'x');
variant('unknown-member', (s) => { s.zz = 1; }, false);
variant('v-2', (s) => { s.v = 2; });
variant('v-string', (s) => { s.v = '1'; });
variant('kind-other', (s) => { s.kind = 'pca-intent-other'; });
variant('session-bad', (s) => { s.session = 'abc'; });
variant('intent_ref-bad', (s) => { s.intent_ref = 'abc'; });
const prins = (n: number) => [{ key: principal.pub }, ...Array.from({ length: n - 1 }, (_, i) => ({ key: dg('p' + i) }))];
variant('principals-missing', (s) => { delete s.principals; });
variant('principals-object', (s) => { s.principals = { key: principal.pub }; });
variant('principals-empty', (s) => { s.principals = []; });
variant('principals-16', (s) => { s.principals = prins(16); });
variant('principals-17', (s) => { s.principals = prins(17); });
variant('principal-not-object', (s) => { s.principals = ['x', { key: principal.pub }]; });
variant('principal-unknown', (s) => { s.principals = [{ key: principal.pub, note: 'x' }]; });
variant('principal-key-bad', (s) => { s.principals = [{ key: 'abc' }, { key: principal.pub }]; });
variant('principal-key-missing', (s) => { s.principals = [{ alg: 'ed25519' }]; });
variant('principal-alg-ok', (s) => { s.principals = [{ key: principal.pub, alg: 'ed25519' }]; });
variant('principal-alg-unknown', (s) => { s.principals = [{ key: principal.pub, alg: 'nope-dsa' }]; });
variant('principal-alg-number', (s) => { s.principals = [{ key: principal.pub, alg: 1 }]; });
variant('principal-pq_pk-ok', (s) => { s.principals = [{ key: principal.pub, pq_pk: 'AAAA' }]; });
variant('principal-pq_pk-bad', (s) => { s.principals = [{ key: principal.pub, pq_pk: 'AA=A' }]; });
variant('principal-pq_pk-null', (s) => { s.principals = [{ key: principal.pub, pq_pk: null }]; });
variant('principal-dup', (s) => { s.principals = [{ key: principal.pub }, { key: principal.pub }]; });
variant('schema-string', (s) => { s.schema = 'x'; });
variant('schema-extra', (s) => { s.schema.x = 1; });
variant('schema-one-key', (s) => { s.schema = { aud: 'a' }; });
variant('schema-other-keys', (s) => { s.schema = { aud: 'a', dig: dg('x') }; });
variant('schema-aud-number', (s) => { s.schema.aud = 1; });
variant('schema-aud-empty', (s) => { s.schema.aud = ''; });
variant('schema-digest-bad', (s) => { s.schema.digest = 'abc'; });
variant('layers-string', (s) => { s.layers = 'x'; });
variant('layers-unknown', (s) => { s.layers.site = { digest: dg('s') }; });
variant('task-missing', (s) => { s.layers = { org: { digest: dg('org') } }; });
variant('task-string', (s) => { s.layers.task = 'x'; });
variant('task-extra', (s) => { s.layers.task.x = 1; });
variant('task-other', (s) => { s.layers.task = { digest: dg('m') }; });
variant('task-digest-bad', (s) => { s.layers.task = { map_digest: 'abc' }; });
variant('org-ok', (s) => { s.layers.org = { digest: dg('org') }; });
variant('org-extra-ok', (s) => { s.layers.org = { digest: dg('org'), name: 'acme' }; });
variant('org-null', (s) => { s.layers.org = null; });
variant('org-string', (s) => { s.layers.org = 'x'; });
variant('org-digest-bad', (s) => { s.layers.org = { digest: 'abc' }; });
variant('org-digest-missing', (s) => { s.layers.org = {}; });
const std = (over: any) => (s: any) => { s.layers.std = { profile: 'travel', version: 1, digest: dg('std'), ...over }; };
variant('std-ok', std({}));
variant('std-version-2', std({ version: 2 }));
variant('std-profile-128', std({ profile: 'é'.repeat(64) }));
variant('std-profile-129', std({ profile: 'é'.repeat(64) + 'x' }));
variant('std-null', (s) => { s.layers.std = null; });
variant('std-string', (s) => { s.layers.std = 'x'; });
variant('std-extra', std({ x: 1 }));
variant('std-missing-digest', (s) => { s.layers.std = { profile: 'travel', version: 1, x: dg('std') }; });
variant('std-profile-number', std({ profile: 1 }));
variant('std-profile-empty', std({ profile: '' }));
variant('std-version-0', std({ version: 0 }));
variant('std-version-neg', std({ version: -1 }));
variant('std-version-fraction', std({ version: 1.5 }));
variant('std-version-string', std({ version: '1' }));
variant('std-digest-bad', std({ digest: 'abc' }));
const accs = (n: number) => Array.from({ length: n }, (_, i) => trip('a' + i));
const mons = (n: number) => Array.from({ length: n }, (_, i) => mon('m' + i));
variant('accumulators-missing', (s) => { delete s.accumulators; });
variant('accumulators-object', (s) => { s.accumulators = {}; });
variant('accumulators-0', (s) => { s.accumulators = []; });
variant('accumulators-16', (s) => { s.accumulators = accs(16); });
variant('accumulators-17', (s) => { s.accumulators = accs(17); });
variant('accumulators-dup', (s) => { s.accumulators = [trip('a'), trip('a')]; });
variant('accumulator-bad', (s) => { s.accumulators = [trip('a'), { id: 'b' }]; });
variant('monitors-missing', (s) => { delete s.monitors; });
variant('monitors-object', (s) => { s.monitors = {}; });
variant('monitors-1', (s) => { s.monitors = mons(1); });
variant('monitors-16', (s) => { s.monitors = mons(16); });
variant('monitors-17', (s) => { s.monitors = mons(17); });
variant('monitors-dup', (s) => { s.monitors = [mon('m'), mon('m')]; });
variant('monitor-bad', (s) => { s.monitors = [mon('m'), { id: 'n' }]; });
variant('monitor-same-id-as-acc', (s) => { s.monitors = [mon('trip_spend')]; });
variant('monitor-then-question-empty', (s) => { s.monitors = mons(1); s.question_uri = ''; });
variant('question-missing', (s) => { delete s.question_uri; });
variant('question-number', (s) => { s.question_uri = 1; });
variant('question-empty', (s) => { s.question_uri = ''; });
variant('question-2048', (s) => { s.question_uri = 'é'.repeat(1024); });
variant('question-2049', (s) => { s.question_uri = 'é'.repeat(1024) + 'x'; });
const rev = (over: any) => (s: any) => { s.revocation = { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub, ...over }; };
variant('revocation-ok', rev({}));
variant('revocation-pq_pk-ok', rev({ pq_pk: 'AAAA' }));
variant('revocation-age-0', rev({ max_age_s: 0 }));
variant('revocation-string', (s) => { s.revocation = 'x'; });
variant('revocation-null', (s) => { s.revocation = null; });
variant('revocation-unknown', rev({ x: 1 }));
variant('revocation-uri-missing', (s) => { s.revocation = { max_age_s: 60, key: revAuth.pub }; });
variant('revocation-uri-number', rev({ epoch_uri: 1 }));
variant('revocation-uri-empty', rev({ epoch_uri: '' }));
variant('revocation-age-neg', rev({ max_age_s: -1 }));
variant('revocation-age-string', rev({ max_age_s: '60' }));
variant('revocation-key-bad', rev({ key: 'abc' }));
variant('revocation-key-missing', (s) => { s.revocation = { epoch_uri: 'u', max_age_s: 1 }; });
variant('revocation-key-principal', rev({ key: principal.pub }));
variant('revocation-pq_pk-bad', rev({ pq_pk: 'AA=A' }));
variant('revocation-pq_pk-number', rev({ pq_pk: 5 }));
variant('flows-ok', (s) => { s.flows = { read: { from: 'x' } }; });
variant('flows-empty', (s) => { s.flows = {}; });
variant('flows-string', (s) => { s.flows = 'x'; });
variant('flows-array', (s) => { s.flows = []; });
variant('flows-null', (s) => { s.flows = null; });
variant('expires-missing', (s) => { delete s.expires_at; });
variant('expires-neg', (s) => { s.expires_at = -1; });
variant('expires-fraction', (s) => { s.expires_at = 1.5; });
variant('expires-0', (s) => { s.expires_at = 0; });
variant('signer-missing', (s) => { delete s.signer; }, false);
variant('signer-bad', (s) => { s.signer = 'abc'; }, false);
variant('signer-not-principal', (s) => { s.signer = dg('other'); }, false);
variant('alg-ed25519', (s) => { s.alg = 'ed25519'; }, false);
variant('alg-unknown', (s) => { s.alg = 'nope-dsa'; }, false);
variant('alg-number', (s) => { s.alg = 1; }, false);
variant('ed25519-pq_pk', (s) => { s.pq_pk = 'AAAA'; }, false);
variant('ed25519-pq_sig', (s) => { s.pq_sig = 'AAAA'; }, false);
variant('ed25519-alg-pq_sig', (s) => { s.alg = 'ed25519'; s.pq_sig = 'AAAA'; }, false);
variant('ml-dsa-no-pq_pk', (s) => { s.alg = 'ml-dsa-65'; }, false);
variant('flows-lone-surrogate', (s) => { s.flows = { x: '\uD800' }; }, false);
variant('ml-dsa-pq_pk-lone-surrogate', (s) => { s.alg = 'ml-dsa-65'; s.pq_pk = '\uD800'; }, false);
variant('question-lone-surrogate', (s) => { s.question_uri = 'q\uD800'; }, false);
variant('sig-missing', (s) => { delete s.sig; }, false);
variant('sig-number', (s) => { s.sig = 1; }, false);
variant('sig-tampered', (s) => { s.sig = S0.sig.slice(0, -2) + (S0.sig.endsWith('AA') ? 'BA' : 'AA'); }, false);
variant('tampered-question', (s) => { s.question_uri = 'https://other.example/q'; }, false);
variant('tampered-flows', (s) => { s.flows = { x: 1 }; }, false);
variant('tampered-revocation', (s) => { s.revocation = { epoch_uri: 'u', max_age_s: 1, key: revAuth.pub }; }, false);
variant('tampered-expires', (s) => { s.expires_at = 1; }, false);
// flows and revocation inside the signed body: signed with them they verify, without them (stripped) they do not
{
  const b = clone(BODY0); b.flows = { read: { from: 'x' } }; b.revocation = { epoch_uri: 'u', max_age_s: 1, key: revAuth.pub };
  const s = signed(b);
  root('signed-flows-revocation', s);
  const s2 = clone(s); delete s2.flows; root('signed-flows-revocation-flows-stripped', s2);
  const s3 = clone(s); delete s3.revocation; root('signed-flows-revocation-revocation-stripped', s3);
}
// signed by the SECOND principal (ed25519), and ml-dsa-65 by the second principal: verified under the VERIFIER's pin (R3-01)
{
  const b = clone(BODY0); b.principals = [{ key: principal.pub }, { key: second.pub }];
  root('second-signer-ed25519', signed(b, second));
  const mlDsa = pca.mlDsa65Keygen(seed('k042sr/ml-dsa'));
  const pq = pca.b64u(mlDsa.publicKey);
  const other = pca.b64u(pca.mlDsa65Keygen(seed('k042sr/ml-dsa-other')).publicKey);
  const bq = clone(BODY0); bq.principals = [{ key: principal.pub }, { key: second.pub, alg: 'ml-dsa-65', pq_pk: pq }];
  const sq = signed(bq, second, { alg: 'ml-dsa-65', mlDsa });
  const PINS = { [second.pub]: pq };
  root('second-signer-ml-dsa', sq, PINS);
  root('second-signer-ml-dsa-no-verifier-pin', sq);
  root('second-signer-ml-dsa-pin-other-key', sq, { [principal.pub]: pq });
  root('second-signer-ml-dsa-pin-mismatch', sq, { [second.pub]: other });
  const bq2 = clone(BODY0); bq2.principals = [{ key: principal.pub, pq_pk: other }, { key: second.pub, alg: 'ml-dsa-65', pq_pk: pq }];
  root('second-signer-ml-dsa-first-pinned-other', signed(bq2, second, { alg: 'ml-dsa-65', mlDsa }), PINS);
  const s2 = clone(sq); s2.principals = [{ key: principal.pub }, { key: second.pub, alg: 'ml-dsa-65' }]; root('second-signer-ml-dsa-unpinned', s2, PINS);
  const bq4 = clone(BODY0); bq4.principals = [{ key: principal.pub }, { key: second.pub, alg: 'ml-dsa-65', pq_pk: other }];
  root('second-signer-ml-dsa-entry-mismatch', signed(bq4, second, { alg: 'ml-dsa-65', mlDsa }), PINS);
  const bq3 = clone(BODY0); bq3.principals = [{ key: second.pub, alg: 'ml-dsa-65', pq_pk: pq }];
  root('only-signer-ml-dsa', signed(bq3, second, { alg: 'ml-dsa-65', mlDsa }), PINS);
}

// ---- session revocation ------------------------------------------------------------------------------------------
const SESSION = dg('session');
const SCOPE = pca.sessionRevocationScope(SESSION);
const ID = pca.sessionRevocationId(SESSION);
const stranger = mk('v2/stranger');
const DEF = ['pca-intent:map:a', 'pca-intent:session:zzzz'];
const epochOf = (revoked: string[], issued: number, o: any = {}) => {
  const set = new pca.RevocationSet(revoked);
  const { signer = revAuth, scope = SCOPE, over = {}, notAfter = issued + 300_000, suite } = o;
  return { epoch: pca.signRevocationEpoch(signer.sk, { instance_id: 'ana', grant_ref: scope, epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: notAfter, ...over }, suite) as any, revoked: set.list() };
};
type RevArgs = { ev?: any; session?: any; authority?: any; ids?: any; now?: number; maxAge?: number; scope?: string; last?: any; hasLast?: boolean };
function revCase(name: string, a: RevArgs) {
  const args = { session: SESSION, authority: revAuth.pub, ids: [ID], now: NOW, maxAge: 60_000, ...a };
  const evJ = args.ev === undefined ? undefined : JSON.parse(ser(args.ev));
  const lastJ = args.last === undefined ? undefined : JSON.parse(ser(args.last));
  const r = pca.checkSessionRevocation(evJ, { session: args.session, authority: args.authority, ids: args.ids === undefined ? undefined : JSON.parse(ser(args.ids)), now: args.now, maxAgeMs: args.maxAge, ...(args.scope !== undefined ? { scope: args.scope } : {}), ...(args.last !== undefined ? { last: lastJ } : {}) } as any);
  push('rev', name, {
    ev: args.ev === undefined ? null : ser(args.ev), session: args.session, authority: ser(args.authority), ids: args.ids === undefined ? null : ser(args.ids),
    now: args.now, maxAge: args.maxAge, scope: args.scope ?? null, last: args.last === undefined ? null : ser(args.last), reason: r.ok ? null : cut((r as any).reason),
  });
}
const E = (o: any = {}) => { const { revoked = DEF, issued = NOW - 10_000, ...rest } = o; return epochOf(revoked, issued, rest); };
const withEp = (e: any, over: any) => ({ ...e, epoch: { ...e.epoch, ...over } });
revCase('ok', { ev: E() });
revCase('ok-empty-set', { ev: E({ revoked: [] }) });
revCase('ok-ids-empty', { ev: E(), ids: [] });
revCase('ok-ids-many', { ev: E(), ids: [ID, 'pca-intent:map:b', 'pca-intent:delta:x'] });
revCase('ok-at-max-age', { ev: E({ issued: NOW - 60_000 }) });
revCase('stale', { ev: E({ issued: NOW - 60_001 }) });
revCase('max-age-0-ok', { ev: E({ issued: NOW }), maxAge: 0 });
revCase('max-age-0-stale', { ev: E({ issued: NOW - 1 }), maxAge: 0 });
revCase('max-age-max-safe-ok', { ev: E({ issued: NOW - 100_000 }), maxAge: Number.MAX_SAFE_INTEGER });
revCase('max-age-neg', { ev: E(), maxAge: -1 });
revCase('max-age-fraction', { ev: E(), maxAge: 1.5 });
revCase('max-age-over-safe', { ev: E(), maxAge: Number.MAX_SAFE_INTEGER + 1 });
revCase('now-fraction', { ev: E(), now: NOW + 0.5 });
revCase('now-over-safe', { ev: E(), now: Number.MAX_SAFE_INTEGER + 1 });
revCase('now-under-safe', { ev: E(), now: -Number.MAX_SAFE_INTEGER - 1 });
revCase('now-max-safe', { ev: E(), now: Number.MAX_SAFE_INTEGER });
revCase('now-min-safe', { ev: E(), now: -Number.MAX_SAFE_INTEGER });
revCase('now-max-safe-no-ev', { now: Number.MAX_SAFE_INTEGER });
revCase('now-min-safe-no-ev', { now: -Number.MAX_SAFE_INTEGER });
revCase('max-age-max-safe-no-ev', { maxAge: Number.MAX_SAFE_INTEGER });
revCase('max-age-0-no-ev', { maxAge: 0 });
revCase('ids-not-array', { ev: E(), ids: 'x' });
revCase('authority-number', { ev: E(), authority: 5 });
revCase('authority-null', { ev: E(), authority: null });
revCase('no-ev', {});
revCase('ev-array', { ev: [E()] });
revCase('ev-string', { ev: 'x' });
revCase('ev-extra', { ev: { ...E(), proofs: {} } });
revCase('ev-empty', { ev: {} });
revCase('ev-epoch-missing', { ev: { revoked: DEF } });
revCase('epoch-string', { ev: { epoch: 'x', revoked: DEF } });
for (const k of ['instance_id', 'grant_ref', 'root', 'guardian', 'sig']) revCase('epoch-' + k + '-number', { ev: withEp(E(), { [k]: 1 }) });
for (const k of ['epoch', 'set_size', 'issued_at', 'not_after']) {
  revCase('epoch-' + k + '-neg', { ev: withEp(E(), { [k]: -1 }) });
  revCase('epoch-' + k + '-string', { ev: withEp(E(), { [k]: '1' }) });
}
revCase('epoch-guardian_epoch-ok', { ev: withEp(E(), { guardian_epoch: 3 }) });
revCase('epoch-guardian_epoch-neg', { ev: withEp(E(), { guardian_epoch: -1 }) });
revCase('epoch-guardian_epoch-string', { ev: withEp(E(), { guardian_epoch: '3' }) });
revCase('epoch-guardian_epoch-null', { ev: withEp(E(), { guardian_epoch: null }) });
revCase('epoch-alg-unknown', { ev: withEp(E(), { alg: 'nope-dsa' }) });
revCase('epoch-alg-number', { ev: withEp(E(), { alg: 1 }) });
revCase('epoch-alg-ed25519', { ev: withEp(E(), { alg: 'ed25519' }) });
revCase('epoch-pq_pk-number', { ev: withEp(E(), { pq_pk: 1 }) });
revCase('epoch-pq_sig-number', { ev: withEp(E(), { pq_sig: 1 }) });
revCase('epoch-pq_pk-null', { ev: withEp(E(), { pq_pk: null }) });
revCase('epoch-pq_sig-string', { ev: withEp(E(), { pq_sig: 'AAAA' }) });
revCase('epoch-pq_pk-string', { ev: withEp(E(), { pq_pk: 'AAAA' }) });
revCase('foreign-signer', { ev: E({ signer: stranger }) });
revCase('guardian-relabelled', { ev: withEp(E({ signer: stranger }), { guardian: revAuth.pub }) });
revCase('sig-tampered', { ev: withEp(E(), { instance_id: 'bob' }) });
revCase('other-scope', { ev: E({ scope: pca.sessionRevocationScope(dg('s2')) }) });
revCase('explicit-scope-ok', { ev: E({ scope: 'custom-scope' }), scope: 'custom-scope' });
revCase('explicit-scope-default-epoch', { ev: E(), scope: 'custom-scope' });
revCase('session-other', { ev: E(), session: dg('s2') });
revCase('not-after-eq-now', { ev: E({ issued: NOW - 10_000, notAfter: NOW }) });
revCase('not-after-before-now', { ev: E({ issued: NOW - 10_000, notAfter: NOW - 1 }) });
revCase('future-60s', { ev: E({ issued: NOW + 60_000 }), maxAge: 60_000 });
revCase('future-60001', { ev: E({ issued: NOW + 60_001 }) });
revCase('revoked', { ev: E({ revoked: [ID] }) });
revCase('revoked-second-id', { ev: E({ revoked: ['pca-intent:map:b'] }), ids: [ID, 'pca-intent:map:b'] });
revCase('id-number', { ev: E(), ids: [ID, 7] });
revCase('id-null', { ev: E(), ids: [null] });
revCase('id-list', { ev: E(), ids: [['a', 'b']] });
revCase('id-object', { ev: E(), ids: [{}] });
revCase('list-short', { ev: { ...E(), revoked: ['pca-intent:map:a'] } });
revCase('list-swapped', { ev: { ...E(), revoked: ['pca-intent:map:a', 'pca-intent:session:zzzy'] } });
revCase('list-unsorted', { ev: { ...E(), revoked: [...DEF].reverse() } });
revCase('list-dup', { ev: { ...E(), revoked: [DEF[0], DEF[0]] } });
revCase('list-not-array', { ev: { ...E(), revoked: { a: DEF[0] } } });
revCase('list-missing', { ev: { epoch: E().epoch } });
revCase('list-number-entry', { ev: { ...E(), revoked: [DEF[0], 5] } });
revCase('epoch-not-size', { ev: E({ over: { epoch: 7 } }) });
revCase('set-size-not-list', { ev: E({ over: { epoch: 3, set_size: 3 } }) });
{
  const L1 = epochOf(['pca-intent:map:a'], NOW - 30_000);
  const L2 = epochOf([ID, 'pca-intent:session:zzzz'], NOW - 30_000);
  const L0 = epochOf([], NOW - 30_000);
  revCase('append-extends', { ev: E(), last: L1 });
  revCase('append-from-empty', { ev: E(), last: L0 });
  revCase('append-same', { ev: E({ revoked: ['pca-intent:map:a'] }), last: L1 });
  revCase('append-same-2', { ev: E(), last: E({ issued: NOW - 30_000 }) });
  revCase('append-drop', { ev: E(), last: L2 });
  revCase('append-drop-grow', { ev: E({ revoked: ['pca-intent:map:a', 'pca-intent:map:b', 'pca-intent:session:zzzz'] }), last: L2 });
  revCase('append-rollback', { ev: E({ revoked: ['pca-intent:session:zzzz'] }), last: L2 });
  revCase('append-last-list-bad', { ev: E(), last: { epoch: L1.epoch, revoked: ['pca-intent:map:z'] } });
  revCase('append-last-string', { ev: E(), last: 'x' });
  revCase('append-last-null', { ev: E(), last: null });
  revCase('append-last-extra', { ev: E(), last: { ...L1, x: 1 } });
  revCase('append-last-epoch-bad', { ev: E(), last: { epoch: { ...L1.epoch, sig: 1 }, revoked: L1.revoked } });
  revCase('append-last-epoch-missing', { ev: E(), last: { revoked: L1.revoked } });
  revCase('append-last-unsigned-ok', { ev: E(), last: { epoch: { ...L1.epoch, sig: 'x' }, revoked: L1.revoked } });
  revCase('append-equal-epoch-other-root', { ev: E(), last: { epoch: { ...L2.epoch, root: E().epoch.root }, revoked: L2.revoked } });
  revCase('append-then-revoked', { ev: E({ revoked: [ID, 'pca-intent:map:a'] }), last: L1 });
}

// lone surrogates: the reference canonicalizes the epoch body and the set leaves leniently (see the Java test for its
// own, stricter, fail-closed reasons)
revCase('lone-surrogate-instance', { ev: withEp(E(), { instance_id: '\uD800' }) });
revCase('lone-surrogate-revoked', { ev: { ...E({ revoked: ['x'] }), revoked: ['\uD800'] } });

// ---- primitives.intent_revocation (raw JSON text) --------------------------------------------------------------
function prim(name: string, text: string) {
  const input = JSON.parse(text);
  let reason: string | null;
  if (input === null || typeof input !== 'object' || Array.isArray(input)) reason = 'session revocation check error (fail closed)';
  else {
    const ev: any = { ...input };
    for (const k of ['session', 'scope', 'authority', 'ids', 'now', 'max_age_ms', 'last']) delete ev[k];
    const r = pca.checkSessionRevocation(ev, { session: input.session, authority: input.authority, ids: input.ids, now: input.now, maxAgeMs: input.max_age_ms, ...('last' in input ? { last: input.last } : {}) } as any);
    reason = r.ok ? null : cut((r as any).reason);
  }
  push('prim', name, { text, reason });
}
const P = (o: any = {}, extra = '') => {
  const { e = E(), ...rest } = o;
  const base: any = { epoch: e.epoch, revoked: e.revoked, session: SESSION, authority: revAuth.pub, ids: [ID], now: NOW, max_age_ms: 60_000, ...rest };
  const t = ser(base);
  return extra ? t.slice(0, -1) + ',' + extra + '}' : t;
};
prim('ok', P());
prim('revoked', P({ e: E({ revoked: [ID] }) }));
prim('id-1e3', P({ ids: [ID] }).replace(`"ids":["${ID}"]`, '"ids":[1e3]'));
prim('id-1.50', P({ ids: [ID] }).replace(`"ids":["${ID}"]`, '"ids":[1.50]'));
prim('max-age-1e4', P().replace('"max_age_ms":60000', '"max_age_ms":6e4'));
prim('now-exp', P().replace(`"now":${NOW}`, '"now":1.8e12'));
prim('max-age-string', P({ max_age_ms: '60000' }));
prim('max-age-missing', P({ max_age_ms: undefined }));
prim('max-age-fraction', P({ max_age_ms: 1.5 }));
prim('max-age-neg', P({ max_age_ms: -1 }));
prim('max-age-minus-zero', P({ max_age_ms: -0 }));
prim('now-string', P({ now: String(NOW) }));
prim('now-missing', P({ now: undefined }));
prim('now-minus-zero-no-ev', ser({ session: SESSION, authority: revAuth.pub, ids: [ID], now: -0, max_age_ms: 60_000, epoch: E().epoch }));
prim('now-1', P({ now: 1 }));
prim('ids-string', P({ ids: 'x' }));
prim('ids-object', P({ ids: { a: 1 } }));
prim('ids-missing', P({ ids: undefined }));
prim('session-number', P({ session: 5 }));
prim('session-missing', P({ session: undefined }));
prim('authority-number', P({ authority: 5 }));
prim('scope-ignored', P({ e: E({ scope: 'custom' }), scope: 'custom' }));
prim('extra-member', P({ proofs: {} }));
prim('last-ok', P({ last: epochOf(['pca-intent:map:a'], NOW - 30_000) }));
prim('last-null', P({ last: null }));
prim('not-object', '[1,2]');
prim('string', '"x"');

writeFileSync(ROOT + 'sdks/java-pca/test-data/k042-sessrevoc-cases.json', JSON.stringify(out, null, 0) + '\n');
console.log(Object.entries(out).map(([k, v]) => `${k}=${v.length}`).join(' '));
