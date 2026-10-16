// Oracle for the Kotlin action-schema kill tests (KillGTest.kt, ActionSchema.kt): runs the TS reference
// (packages/pca/src/action-schema.ts + canonProjection of intent-v2.ts) on targeted boundary inputs and writes the golden.
//   <tsx> <this> <out.json>      (out: sdks/kotlin-pca/test-data/killG-schema.json)
// Every input is stored as JSON TEXT (so -0, 1.0, 1e400 and lone surrogates survive the trip) and fed to TS via JSON.parse.
// Deterministic: the PQ signer's hedging randomness is replaced by a fixed stream before the reference is loaded.
import fs from 'node:fs';
import { createHash } from 'node:crypto';

{
  let ctr = 0;
  globalThis.crypto.getRandomValues = (a) => {
    const u8 = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    for (let i = 0; i < u8.length; i += 32) {
      const h = createHash('sha256').update(`killG/rng/${ctr++}`).digest();
      u8.set(h.subarray(0, Math.min(32, u8.length - i)), i);
    }
    return a;
  };
}
const pca = await import(new URL('../../../packages/pca/src/index.ts', import.meta.url).href);

const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());

// ---- JSON text with raw numbers --------------------------------------------------------------------------------------
class Raw { constructor(s) { this.s = s; } }
const R = (s) => new Raw(s);
const DEL = Symbol('del');
function ser(v) {
  if (v instanceof Raw) return v.s;
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  return '{' + Object.entries(v).filter(([, x]) => x !== DEL).map(([k, x]) => JSON.stringify(k) + ':' + ser(x)).join(',') + '}';
}
const P = (t) => JSON.parse(t);
const s = (n, ch = 'a') => ch.repeat(n);
const LONE = '\ud800';

// ---- builders --------------------------------------------------------------------------------------------------------
const UNITS = { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 }, 'trip.nights': { kind: 'count' } };
const SIG = { alg: 'ed25519', kid: 'k1', value: 'AAAA' };
const base = { type: 'string', semantic: 's', sensitivity: 'free' };
const T = (type, extra = {}) => ({ ...base, type, ...extra });
function doc(over = {}) {
  return { v: 1, kind: 'pca-action-schema', site: 'https://site.example', aud: 'aud.example', version: '1', units: UNITS,
    verbs: [{ verb: 'v.do', kind: 'write', params: { 'action.params.x': T('string') } }], sig: SIG, ...over };
}
const verbDoc = (verbOver, docOver = {}) => doc({ verbs: [{ verb: 'v.do', kind: 'write', params: { 'action.params.x': T('string') }, ...verbOver }], ...docOver });
const paramDoc = (decl, path = 'action.params.x', docOver = {}) => verbDoc({ params: { [path]: decl } }, docOver);

const out = { shape: [], verify: [], value: [], conform: [], canon: [], accum: [], verbOf: [], digest: [] };
const names = new Set();
const uniq = (n) => { if (names.has(n)) throw new Error('dup case ' + n); names.add(n); return n; };

function shape(name, d) {
  const text = ser(d);
  const want = pca.actionSchemaShapeError(P(text));
  out.shape.push({ name: uniq('shape/' + name), doc: text, want });
}

// ---- paramDeclError --------------------------------------------------------------------------------------------------
const vals = (n, size = 0) => Array.from({ length: n }, (_, i) => { const x = 'v' + i; return size > x.length ? x + s(size - x.length, 'z') : x; });
const pd = [
  ['ok string', T('string')],
  ['ok integer', T('integer')], ['ok boolean', T('boolean')], ['ok date', T('date')], ['ok set', T('set', { values: ['a'] })], ['ok array', T('array')],
  ['not object str', 'x'], ['not object null', null], ['not object arr', []], ['not object num', 1],
  ['unknown member', T('string', { zz: 1 })],
  ['bad type', T('number')], ['type num', T(1)], ['no type', { semantic: 's', sensitivity: 'free' }],
  ['semantic empty', T('string', { semantic: '' })], ['semantic 128', T('string', { semantic: s(128) })], ['semantic 129', T('string', { semantic: s(129) })],
  ['semantic e64', T('string', { semantic: s(64, 'é') })], ['semantic e64a', T('string', { semantic: s(64, 'é') + 'a' })],
  ['semantic num', T('string', { semantic: 1 })], ['semantic lone', T('string', { semantic: 'a' + LONE })], ['no semantic', { type: 'string', sensitivity: 'free' }],
  ['sens material', T('string', { sensitivity: 'material' })], ['sens critical', T('string', { sensitivity: 'critical' })], ['sens high', T('string', { sensitivity: 'high' })],
  ['no sens', { type: 'string', semantic: 's' }], ['sens num', T('string', { sensitivity: 1 })],
  ['required true', T('string', { required: true })], ['required false', T('string', { required: false })], ['required str', T('string', { required: 'no' })], ['required null', T('string', { required: null })],
  ['values ok', T('string', { values: ['a', 'b'] })], ['values str', T('string', { values: 'a' })], ['values obj', T('string', { values: {} })], ['values empty', T('string', { values: [] })],
  ['values one', T('string', { values: ['a'] })],
  ['values 256', T('string', { values: vals(256) })], ['values 257', T('string', { values: vals(257) })],
  ['values entry 256B', T('string', { values: vals(1, 256) })], ['values entry 257B', T('string', { values: vals(1, 257) })],
  ['values entry num', T('string', { values: ['a', 1] })], ['values entry empty', T('string', { values: ['a', ''] })], ['values entry lone', T('string', { values: [LONE] })],
  ['values dup', T('string', { values: ['a', 'a'] })], ['values dup late', T('string', { values: ['a', 'b', 'c', 'b'] })],
  ['values on integer', T('integer', { values: ['a'] })], ['values on boolean', T('boolean', { values: ['a'] })], ['values on date', T('date', { values: ['a'] })],
  ['values on array', T('array', { values: ['a'] })], ['values on set', T('set', { values: ['a'] })], ['values null', T('string', { values: null })],
  ['set without values', T('set')],
  ['min int', T('integer', { min: 0 })], ['max int', T('integer', { max: 0 })], ['min neg', T('integer', { min: -5 })],
  ['min frac', T('integer', { min: R('1.5') })], ['max frac', T('integer', { max: R('1.5') })], ['min -0', T('integer', { min: R('-0') })], ['max -0', T('integer', { max: R('-0') })],
  ['min 2^53', T('integer', { min: R('9007199254740992') })], ['max 2^53-1', T('integer', { max: R('9007199254740991') })], ['min -(2^53-1)', T('integer', { min: R('-9007199254740991') })],
  ['min 1.0', T('integer', { min: R('1.0') })], ['min str', T('integer', { min: '1' })], ['min null', T('integer', { min: null })], ['max null', T('integer', { max: null })],
  ['min on string', T('string', { min: 0 })], ['max on string', T('string', { max: 0 })], ['min on boolean', T('boolean', { min: 0 })],
  ['min on int array', T('array', { items: 'integer', min: 0 })], ['max on int array', T('array', { items: 'integer', max: 0 })],
  ['min on str array', T('array', { items: 'string', min: 0 })], ['max on str array', T('array', { items: 'string', max: 0 })], ['min on bare array', T('array', { min: 0 })],
  ['max on set', T('set', { values: ['a'], max: 0 })],
  ['min==max', T('integer', { min: 5, max: 5 })], ['min<max', T('integer', { min: 4, max: 5 })], ['min>max', T('integer', { min: 6, max: 5 })], ['min>max by 1 neg', T('integer', { min: -4, max: -5 })],
  ['min>max int array', T('array', { items: 'integer', min: 2, max: 1 })],
  ['unit ok', T('integer', { unit: 'usd_cents' })], ['unit dotted', T('integer', { unit: 'trip.nights' })], ['unit on string', T('string', { unit: 'usd_cents' })],
  ['unit num', T('integer', { unit: 5 })], ['unit null', T('integer', { unit: null })], ['unit undeclared', T('integer', { unit: 'eur_cents' })],
  ['unit on int array', T('array', { items: 'integer', unit: 'usd_cents' })],
  ['max_len 1', T('string', { max_len: 1 })], ['max_len 0', T('string', { max_len: 0 })], ['max_len -1', T('string', { max_len: -1 })], ['max_len 2', T('string', { max_len: 2 })],
  ['max_len frac', T('string', { max_len: R('1.5') })], ['max_len str', T('string', { max_len: '1' })], ['max_len null', T('string', { max_len: null })], ['max_len on integer', T('integer', { max_len: 3 })],
  ['items int', T('array', { items: 'integer' })], ['items str', T('array', { items: 'string' })], ['items 64', T('array', { items: s(64) })], ['items 65', T('array', { items: s(65) })],
  ['items empty', T('array', { items: '' })], ['items num', T('array', { items: 5 })], ['items on string', T('string', { items: 'integer' })], ['items on set', T('set', { values: ['a'], items: 'string' })],
  ['min_items set 0', T('set', { values: ['a'], min_items: 0 })], ['max_items set 1', T('set', { values: ['a'], max_items: 1 })],
  ['min_items array', T('array', { min_items: 1 })], ['max_items array', T('array', { max_items: 1 })],
  ['min_items -1', T('array', { min_items: -1 })], ['max_items -1', T('array', { max_items: -1 })], ['min_items frac', T('array', { min_items: R('0.5') })], ['max_items -0', T('array', { max_items: R('-0') })],
  ['min_items null', T('array', { min_items: null })], ['max_items str', T('array', { max_items: '1' })],
  ['min_items on string', T('string', { min_items: 0 })], ['max_items on string', T('string', { max_items: 0 })], ['min_items on integer', T('integer', { min_items: 0 })], ['max_items on boolean', T('boolean', { max_items: 1 })],
  ['min_items==max_items', T('array', { min_items: 2, max_items: 2 })], ['min_items>max_items', T('array', { min_items: 3, max_items: 2 })], ['min_items<max_items', T('array', { min_items: 1, max_items: 2 })],
  ['min_items>max_items set', T('set', { values: ['a', 'b'], min_items: 2, max_items: 1 })],
  ['pnd true default', T('string', { principal_neutral_default: true, default: 'x' })], ['pnd false', T('string', { principal_neutral_default: false })],
  ['pnd true no default', T('string', { principal_neutral_default: true })], ['pnd str', T('string', { principal_neutral_default: 'yes', default: 'x' })], ['pnd null', T('string', { principal_neutral_default: null })],
  ['pnd false default', T('string', { principal_neutral_default: false, default: 'x' })],
  ['default ok', T('string', { default: 'x' })], ['default false', T('boolean', { default: false })], ['default 0', T('integer', { default: 0 })], ['default null', T('string', { default: null })],
  ['ai ok', T('integer', { accumulates_into: ['usd_cents'] })], ['ai on string', T('string', { accumulates_into: ['u'] })], ['ai on int array', T('array', { items: 'integer', accumulates_into: ['u'] })],
  ['ai str', T('integer', { accumulates_into: 'u' })], ['ai obj', T('integer', { accumulates_into: {} })], ['ai empty', T('integer', { accumulates_into: [] })], ['ai null', T('integer', { accumulates_into: null })],
  ['ai 8', T('integer', { accumulates_into: Array.from({ length: 8 }, (_, i) => 'u' + i) })], ['ai 9', T('integer', { accumulates_into: Array.from({ length: 9 }, (_, i) => 'u' + i) })],
  ['ai entry num', T('integer', { accumulates_into: ['u', 1] })], ['ai entry 64', T('integer', { accumulates_into: [s(64)] })], ['ai entry 65', T('integer', { accumulates_into: [s(65)] })],
  ['ai entry upper', T('integer', { accumulates_into: ['A'] })], ['ai entry dotdot', T('integer', { accumulates_into: ['a..b'] })], ['ai entry dotted', T('integer', { accumulates_into: ['a.b'] })],
  ['ai entry empty', T('integer', { accumulates_into: [''] })], ['ai entry late bad', T('integer', { accumulates_into: ['a', 'b', 'C'] })],
  ['ai dup', T('integer', { accumulates_into: ['a', 'a'] })], ['ai dup late', T('integer', { accumulates_into: ['a', 'b', 'c', 'b'] })],
  ['ibs true', T('string', { issued_by_site: true })], ['ibs false', T('string', { issued_by_site: false })], ['ibs str', T('string', { issued_by_site: 'yes' })], ['ibs null', T('string', { issued_by_site: null })],
  ['desc 1024', T('string', { description: s(1024) })], ['desc 1025', T('string', { description: s(1025) })], ['desc empty', T('string', { description: '' })], ['desc num', T('string', { description: 1 })],
  ['desc 1', T('string', { description: 'd' })],
  // first-failure order across the trailing rules
  ['order default-null vs pnd', T('string', { default: null, principal_neutral_default: 'x' })],
  ['order default-null vs ai', T('string', { default: null, accumulates_into: ['u'] })],
  ['order ai vs ibs', T('string', { accumulates_into: ['u'], issued_by_site: 'x' })],
  ['order ibs vs desc', T('string', { issued_by_site: 'x', description: '' })],
  ['order values vs set', T('set', { values: [] })],
  ['order min vs unit', T('string', { min: 0, unit: 'zz' })],
];
for (const [n, d] of pd) shape('param/' + n, paramDoc(d));
for (const [n, p] of [['bad prefix', 'params.x'], ['name 64', 'action.params.' + s(64)], ['name 65', 'action.params.' + s(65)], ['name empty', 'action.params.'],
  ['name dash', 'action.params.a-b'], ['name digits', 'action.params.A_9'], ['__proto__', 'action.params.__proto__'], ['constructor', 'action.params.constructor'],
  ['prototype', 'action.params.prototype'], ['prefix space', ' action.params.x'], ['trailing nl', 'action.params.x\n']])
  shape('path/' + n, paramDoc(T('string'), p));
shape('param/unit no units', paramDoc(T('integer', { unit: 'usd_cents' }), 'action.params.x', { units: DEL }));
shape('param/unit units empty', paramDoc(T('integer', { unit: 'usd_cents' }), 'action.params.x', { units: {} }));

// ---- verbDeclError ---------------------------------------------------------------------------------------------------
const p64 = Object.fromEntries(Array.from({ length: 64 }, (_, i) => ['action.params.p' + i, T('string')]));
const p65 = { ...p64, 'action.params.p64': T('string') };
const RB = { param: 'action.params.x', map: { a: 'reversible' } };
const vd = [
  ['ok read', { kind: 'read' }], ['kind other', { kind: 'delete' }], ['kind absent', { kind: DEL }], ['kind num', { kind: 1 }],
  ['unknown member', { zz: 1 }], ['verb 128', { verb: s(128) }], ['verb 129', { verb: s(129) }], ['verb empty', { verb: '' }], ['verb num', { verb: 1 }], ['verb absent', { verb: DEL }],
  ['params arr', { params: [] }], ['params null', { params: null }], ['params absent', { params: DEL }], ['params str', { params: 'x' }], ['params empty', { params: {} }],
  ['params 64', { params: p64 }], ['params 65', { params: p65 }],
  ['param err 2nd', { params: { 'action.params.a': T('string'), 'action.params.b': T('nope') } }],
  ['rev reversible', { reversibility: 'reversible' }], ['rev rate_limited', { reversibility: 'rate_limited' }], ['rev irreversible', { reversibility: 'irreversible' }],
  ['rev bad', { reversibility: 'maybe' }], ['rev null', { reversibility: null }], ['rev num', { reversibility: 1 }],
  ['rb ok', { reversibility_by: RB }], ['rb default ok', { reversibility_by: { ...RB, default: 'irreversible' } }], ['rb default bad', { reversibility_by: { ...RB, default: 'x' } }],
  ['rb default null', { reversibility_by: { ...RB, default: null } }],
  ['rb extra', { reversibility_by: { ...RB, zz: 1 } }], ['rb extra first', { reversibility_by: { zz: 1, ...RB } }], ['rb not obj', { reversibility_by: 'x' }], ['rb null', { reversibility_by: null }], ['rb arr', { reversibility_by: [] }],
  ['rb param num', { reversibility_by: { ...RB, param: 1 } }], ['rb param undeclared', { reversibility_by: { ...RB, param: 'action.params.y' } }], ['rb param absent', { reversibility_by: { map: RB.map } }],
  ['rb map empty', { reversibility_by: { ...RB, map: {} } }], ['rb map arr', { reversibility_by: { ...RB, map: ['reversible'] } }], ['rb map str', { reversibility_by: { ...RB, map: 'x' } }],
  ['rb map bad', { reversibility_by: { ...RB, map: { a: 'x' } } }], ['rb map 2nd bad', { reversibility_by: { ...RB, map: { a: 'reversible', b: 'x' } } }],
  ['rb map all ok', { reversibility_by: { ...RB, map: { a: 'reversible', b: 'rate_limited', c: 'irreversible' } } }], ['rb map absent', { reversibility_by: { param: RB.param } }],
  ['mcp ok', { mcp: { tool: 't' } }], ['mcp extra', { mcp: { tool: 't', x: 1 } }], ['mcp empty', { mcp: {} }], ['mcp other key', { mcp: { x: 't' } }], ['mcp str', { mcp: 't' }], ['mcp null', { mcp: null }],
  ['mcp tool 128', { mcp: { tool: s(128) } }], ['mcp tool 129', { mcp: { tool: s(129) } }], ['mcp tool num', { mcp: { tool: 1 } }], ['mcp tool empty', { mcp: { tool: '' } }], ['mcp arr', { mcp: ['tool'] }],
  ['oa ok', { openapi: { operationId: 'op' } }], ['oa extra', { openapi: { operationId: 'op', x: 1 } }], ['oa empty', { openapi: {} }], ['oa other key', { openapi: { x: 'op' } }], ['oa str', { openapi: 'op' }],
  ['oa id 128', { openapi: { operationId: s(128) } }], ['oa id 129', { openapi: { operationId: s(129) } }], ['oa id num', { openapi: { operationId: 1 } }], ['oa null', { openapi: null }],
  ['harm ok', { harm: {} }], ['harm arr', { harm: [] }], ['effects ok', { effects: { a: 1 } }], ['effects str', { effects: 'x' }], ['returns ok', { returns: {} }], ['returns null', { returns: null }],
  ['world ok', { world: [] }], ['world obj', { world: {} }], ['world null', { world: null }],
  ['desc 1024', { description: s(1024) }], ['desc 1025', { description: s(1025) }], ['desc empty', { description: '' }], ['desc num', { description: 2 }],
];
for (const [n, o] of vd) shape('verb/' + n, verbDoc(o));
for (const [n, v] of [['str', 'x'], ['null', null], ['arr', []], ['num', 1]]) shape('verb/not object ' + n, doc({ verbs: [v] }));

// ---- shape (document level) ------------------------------------------------------------------------------------------
const mkVerbs = (n) => Array.from({ length: n }, (_, i) => ({ verb: 'v' + i, kind: 'read', params: {} }));
const sd = [
  ['ok', {}], ['unknown member', { zz: 1 }], ['v 2', { v: 2 }], ['v str', { v: '1' }], ['v 1.0', { v: R('1.0') }], ['v absent', { v: DEL }], ['v 0', { v: 0 }], ['v null', { v: null }],
  ['kind bad', { kind: 'pca-schema' }], ['kind absent', { kind: DEL }],
  ['site 2048', { site: s(2048) }], ['site 2049', { site: s(2049) }], ['site empty', { site: '' }], ['site absent', { site: DEL }],
  ['aud 256', { aud: s(256) }], ['aud 257', { aud: s(257) }], ['aud num', { aud: 1 }],
  ['version 128', { version: s(128) }], ['version 129', { version: s(129) }], ['version absent', { version: DEL }],
  ['units absent', { units: DEL }], ['units empty', { units: {} }], ['units arr', { units: [] }], ['units null', { units: null }], ['units str', { units: 'x' }],
  ['unit id upper', { units: { A: { kind: 'k' } } }], ['unit id 64', { units: { [s(64)]: { kind: 'k' } } }], ['unit id 65', { units: { [s(65)]: { kind: 'k' } } }],
  ['unit id dotdot', { units: { 'a..b': { kind: 'k' } } }], ['unit id 2nd bad', { units: { a: { kind: 'k' }, 'B': { kind: 'k' } } }],
  ['unit not obj', { units: { a: 'k' } }], ['unit null', { units: { a: null } }], ['unit no kind', { units: { a: {} } }], ['unit kind 64', { units: { a: { kind: s(64) } } }],
  ['unit kind 65', { units: { a: { kind: s(65) } } }], ['unit kind num', { units: { a: { kind: 1 } } }], ['unit kind empty', { units: { a: { kind: '' } } }],
  ['unit unknown member', { units: { a: { kind: 'k', zz: 1 } } }], ['unit unknown member first', { units: { a: { zz: 1, kind: 'k' } } }],
  ['unit currency 16', { units: { a: { kind: 'k', currency: s(16) } } }], ['unit currency 17', { units: { a: { kind: 'k', currency: s(17) } } }],
  ['unit currency num', { units: { a: { kind: 'k', currency: 1 } } }], ['unit currency null', { units: { a: { kind: 'k', currency: null } } }], ['unit currency empty', { units: { a: { kind: 'k', currency: '' } } }],
  ['unit exp 0', { units: { a: { kind: 'k', exponent: 0 } } }], ['unit exp 18', { units: { a: { kind: 'k', exponent: 18 } } }], ['unit exp 19', { units: { a: { kind: 'k', exponent: 19 } } }],
  ['unit exp -1', { units: { a: { kind: 'k', exponent: -1 } } }], ['unit exp frac', { units: { a: { kind: 'k', exponent: R('1.5') } } }], ['unit exp null', { units: { a: { kind: 'k', exponent: null } } }],
  ['unit exp str', { units: { a: { kind: 'k', exponent: '2' } } }], ['unit exp -0', { units: { a: { kind: 'k', exponent: R('-0') } } }], ['unit exp 17', { units: { a: { kind: 'k', exponent: 17 } } }],
  ['state ok', { state: [] }], ['state obj', { state: {} }], ['state null', { state: null }],
  ['verbs empty', { verbs: [] }], ['verbs obj', { verbs: {} }], ['verbs absent', { verbs: DEL }], ['verbs 1', { verbs: mkVerbs(1) }], ['verbs 256', { verbs: mkVerbs(256) }], ['verbs 257', { verbs: mkVerbs(257) }],
  ['verbs dup', { verbs: [...mkVerbs(2), { verb: 'v0', kind: 'write', params: {} }] }], ['verbs dup then bad', { verbs: [...mkVerbs(1), mkVerbs(1)[0], 'x'] }],
  ['sig absent', { sig: DEL }], ['sig str', { sig: 'x' }], ['sig null', { sig: null }], ['sig arr', { sig: [] }], ['sig unknown', { sig: { ...SIG, zz: 1 } }],
  ['sig alg absent', { sig: { kid: 'k1', value: 'AAAA' } }], ['sig alg num', { sig: { ...SIG, alg: 1 } }], ['sig alg null', { sig: { ...SIG, alg: null } }], ['sig alg unknown', { sig: { ...SIG, alg: 'rsa' } }],
  ['sig alg hybrid', { sig: { ...SIG, alg: 'hybrid-ed25519-ml-dsa-65' } }],
  ['sig kid 128', { sig: { ...SIG, kid: s(128) } }], ['sig kid 129', { sig: { ...SIG, kid: s(129) } }], ['sig kid empty', { sig: { ...SIG, kid: '' } }], ['sig kid absent', { sig: { alg: 'ed25519', value: 'AAAA' } }],
  ['sig value pad', { sig: { ...SIG, value: 'AAA=' } }], ['sig value noncanon', { sig: { ...SIG, value: 'AB' } }], ['sig value num', { sig: { ...SIG, value: 1 } }], ['sig value absent', { sig: { alg: 'ed25519', kid: 'k1' } }],
  ['sig value empty', { sig: { ...SIG, value: '' } }],
  ['sig pq ok', { sig: { ...SIG, pq_value: 'AAAA' } }], ['sig pq bad', { sig: { ...SIG, pq_value: 'A' } }], ['sig pq null', { sig: { ...SIG, pq_value: null } }],
  ['canon state frac', { state: [R('1.5')] }], ['canon state big', { state: [R('9007199254740993')] }], ['canon state lone', { state: [LONE] }], ['canon state -0', { state: [R('-0')] }],
  ['canon state 1e400', { state: [R('1e400')] }],
];
for (const [n, o] of sd) shape('doc/' + n, doc(o));
for (const [n, d] of [['str', 'x'], ['null', null], ['arr', []], ['num', 1]]) out.shape.push({ name: uniq('shape/doc/not object ' + n), doc: ser(d), want: pca.actionSchemaShapeError(d) });

// ---- verifyActionSchema ----------------------------------------------------------------------------------------------
const site = seed('killG/site');
const other = seed('killG/other');
const pq = { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: pca.mlDsa65Keygen(seed('killG/pq')) };
const pqOther = pca.mlDsa65Keygen(seed('killG/pq-other'));
const unsigned = (() => { const d = doc(); delete d.sig; return d; })();
const sEd = pca.signActionSchema(unsigned, 'k1', site);
const kEd = pca.actionSchemaKeyOf('k1', site);
const sHy = pca.signActionSchema(unsigned, 'kh', site, pq);
const kHy = pca.actionSchemaKeyOf('kh', site, pq);
const sEdNoAlg = (() => { const d = structuredClone(sEd); delete d.sig.alg; return d; })();
const kEdNoAlg = (() => { const k = { ...kEd }; delete k.alg; return k; })();
const kOther = pca.actionSchemaKeyOf('k1', other);
const tampered = { ...structuredClone(sEd), version: '2' };
function verify(name, d, keys) {
  const dt = ser(d), kt = ser(keys);
  const r = pca.verifyActionSchema(P(dt), P(kt));
  out.verify.push({ name: uniq('verify/' + name), doc: dt, keys: kt, want: r.ok ? null : r.reason });
}
verify('ed ok', sEd, [kEd]);
verify('ed ok 2nd key', sEd, [{ kid: 'k0', alg: 'ed25519', pk: kOther.pk }, kEd]);
verify('ed ok non-map first', sEd, ['x', null, 1, kEd]);
verify('ed kid num first', sEd, [{ ...kOther, kid: 1 }, kEd]);
verify('ed first match wins', sEd, [kOther, kEd]);
verify('ed no alg on sig', sEdNoAlg, [kEd]);
verify('ed no alg on key', sEd, [kEdNoAlg]);
verify('ed no alg both', sEdNoAlg, [kEdNoAlg]);
verify('shape bad', { ...sEd, v: 2 }, [kEd]);
verify('keys obj', sEd, { 0: kEd });
verify('keys null', sEd, null);
verify('keys str', sEd, 'x');
verify('keys empty', sEd, []);
verify('kid mismatch', sEd, [{ ...kEd, kid: 'k2' }]);
verify('key no kid', sEd, [(() => { const k = { ...kEd }; delete k.kid; return k; })()]);
verify('pq_pk num', sEd, [{ ...kEd, pq_pk: 1 }]);
verify('pq_pk null', sEd, [{ ...kEd, pq_pk: null }]);
verify('pq_pk on ed', sEd, [{ ...kEd, pq_pk: kHy.pq_pk }]);
verify('pk bad', sEd, [{ ...kEd, pk: 'AAAA' }]);
verify('pk absent', sEd, [(() => { const k = { ...kEd }; delete k.pk; return k; })()]);
verify('pk num', sEd, [{ ...kEd, pk: 1 }]);
verify('pk 33 bytes', sEd, [{ ...kEd, pk: pca.b64u(new Uint8Array(33)) }]);
verify('pk 31 bytes', sEd, [{ ...kEd, pk: pca.b64u(new Uint8Array(31)) }]);
verify('key alg num', sEd, [{ ...kEd, alg: 1 }]);
verify('key alg null', sEd, [{ ...kEd, alg: null }]);
verify('key alg unknown', sEd, [{ ...kEd, alg: 'rsa' }]);
verify('suite mismatch ed doc hybrid key', sEd, [{ ...kHy, kid: 'k1' }]);
verify('suite mismatch hybrid doc ed key', sHy, [{ ...kEd, kid: 'kh' }]);
verify('suite mismatch ml-dsa key', sEd, [{ ...kEd, alg: 'ml-dsa-65' }]);
verify('wrong key', sEd, [kOther]);
verify('tampered', tampered, [kEd]);
verify('sig value other', { ...sEd, sig: { ...sEd.sig, value: pca.signActionSchema(unsigned, 'k1', other).sig.value } }, [kEd]);
verify('hybrid ok', sHy, [kHy]);
verify('hybrid no pq_pk', sHy, [(() => { const k = { ...kHy }; delete k.pq_pk; return k; })()]);
verify('hybrid wrong pq_pk', sHy, [{ ...kHy, pq_pk: pca.b64u(pqOther.publicKey) }]);
verify('hybrid no pq_value', { ...sHy, sig: (() => { const g = { ...sHy.sig }; delete g.pq_value; return g; })() }, [kHy]);
verify('hybrid bad pq_value', { ...sHy, sig: { ...sHy.sig, pq_value: 'AAAA' } }, [kHy]);
verify('hybrid tampered', { ...structuredClone(sHy), aud: 'other.example' }, [kHy]);
verify('hybrid ed part other', { ...sHy, sig: { ...sHy.sig, value: pca.signActionSchema(unsigned, 'k1', other).sig.value } }, [kHy]);

// ---- digest ----------------------------------------------------------------------------------------------------------
out.digest.push({ doc: ser(sEd), want: pca.actionSchemaDigest(sEd) }, { doc: ser(sHy), want: pca.actionSchemaDigest(sHy) });

// ---- paramValueViolation ---------------------------------------------------------------------------------------------
// Kotlin pins its own reason text for four refusal families whose TS text interpolates the bound; the code and family agree.
function kReason(r) {
  if (/^longer than \d+ UTF-8 bytes$/.test(r)) return 'longer than the declared max_len';
  if (/^below min -?\d+$/.test(r)) return 'below min';
  if (/^above max -?\d+$/.test(r)) return 'above max';
  if (/^array items must be strings of at most \d+ UTF-8 bytes$/.test(r)) return 'array items must be strings within max_len UTF-8 bytes';
  return r;
}
function value(name, decl, x) {
  const dt = ser(decl), xt = ser(x);
  const r = pca.paramValueViolation(P(dt), P(xt));
  out.value.push({ name: uniq('value/' + name), decl: dt, x: xt, want: r === null ? null : { code: r.code, reason: kReason(r.reason), ts_reason: r.reason } });
}
const SD = T('string');
for (const [n, x] of [['num', 1], ['null', null], ['arr', []], ['bool', true], ['obj', {}], ['lone', 'a' + LONE], ['empty', ''], ['1024', s(1024)], ['1025', s(1025)],
  ['e512', s(512, 'é')], ['e512a', s(512, 'é') + 'a'], ['astral 256', s(256, '😀')], ['astral 256a', s(256, '😀') + 'a']]) value('string/' + n, SD, x);
for (const [n, x] of [['3', 'abc'], ['4', 'abcd'], ['é é', 'éé'], ['ab é', 'abé'], ['empty', '']]) value('string max3/' + n, T('string', { max_len: 3 }), x);
value('string max1/1', T('string', { max_len: 1 }), 'a');
value('string max1/2', T('string', { max_len: 1 }), 'ab');
for (const [n, x] of [['in', 'b'], ['out', 'c'], ['first', 'a'], ['empty', '']]) value('string values/' + n, T('string', { values: ['a', 'b'] }), x);
value('string values+max/long in', T('string', { values: ['abcd'], max_len: 3 }), 'abcd');
const ID = T('integer');
for (const [n, x] of [['0', 0], ['frac', R('1.5')], ['-0', R('-0')], ['2^53', R('9007199254740992')], ['2^53-1', R('9007199254740991')], ['neg max', R('-9007199254740991')],
  ['str', '1'], ['null', null], ['bool', true], ['1.0', R('1.0')], ['1e2', R('1e2')]]) value('integer/' + n, ID, x);
const IMM = T('integer', { min: -2, max: 5 });
for (const x of [-3, -2, -1, 0, 4, 5, 6]) value('integer mm/' + x, IMM, x);
for (const x of [2, 3, 4]) value('integer min3/' + x, T('integer', { min: 3 }), x);
for (const x of [2, 3, 4]) value('integer max3/' + x, T('integer', { max: 3 }), x);
value('integer both fail/min first', T('integer', { min: 5, max: 1 }), 3);
for (const [n, x] of [['true', true], ['false', false], ['str', 'true'], ['null', null], ['num', 1]]) value('boolean/' + n, T('boolean'), x);
const DD = T('date');
const dates = ['2024-02-29', '2023-02-29', '2023-02-28', '1900-02-29', '2000-02-29', '2100-02-29', '2400-02-29', '1996-02-29', '0000-01-01', '0001-01-01', '0004-02-29',
  '2024-00-01', '2024-13-01', '2024-12-31', '2024-01-00', '2024-1-01', '2024-01-01x', ' 2024-01-01', '20240-01-01', '2024-01-1', '2024/01/01', '9999-12-31', '', 'abcd-ef-gh',
  '2024-01-01\n'];
const DIM = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
for (let m = 1; m <= 12; m++) {
  const mm = String(m).padStart(2, '0');
  for (const y of ['2023', '2024']) {
    const dim = m === 2 && y === '2024' ? 29 : DIM[m - 1];
    dates.push(`${y}-${mm}-${String(dim).padStart(2, '0')}`, `${y}-${mm}-${String(dim + 1).padStart(2, '0')}`, `${y}-${mm}-01`);
  }
}
for (const x of [...new Set(dates)]) value('date/' + JSON.stringify(x), DD, x);
for (const [n, x] of [['num', 20240101], ['null', null], ['arr', ['2024-01-01']]]) value('date/' + n, DD, x);
const SET = T('set', { values: ['a', 'b', 'c'] });
for (const [n, x] of [['empty', []], ['a', ['a']], ['abc', ['a', 'b', 'c']], ['cba', ['c', 'b', 'a']], ['dup', ['a', 'a']], ['dup late', ['a', 'b', 'a']], ['out', ['d']], ['out late', ['a', 'd']],
  ['num', [1]], ['num late', ['a', 1]], ['null member', [null]], ['str', 'a'], ['obj', {}], ['null', null], ['dup+out', ['d', 'd']], ['num+dup', ['a', 'a', 1]]]) value('set/' + n, SET, x);
const SETB = T('set', { values: ['a', 'b', 'c', 'd'], min_items: 1, max_items: 2 });
for (const [n, x] of [['0', []], ['1', ['a']], ['2', ['a', 'b']], ['3', ['a', 'b', 'c']]]) value('set bounds/' + n, SETB, x);
for (const [n, x] of [['1', ['a']], ['2', ['a', 'b']]]) value('set min2/' + n, T('set', { values: ['a', 'b', 'c'], min_items: 2 }), x);
for (const [n, x] of [['0', []], ['1', ['a']]]) value('set max0/' + n, T('set', { values: ['a', 'b'], max_items: 0 }), x);
const AR = T('array');
for (const [n, x] of [['empty', []], ['strs', ['a', 'b', 'a']], ['num item', [1]], ['num late', ['a', 1]], ['null item', [null]], ['lone item', [LONE]], ['empty str', ['']],
  ['1024', [s(1024)]], ['1025', [s(1025)]], ['obj', {}], ['str', 'a'], ['null', null], ['64', Array(64).fill('a')], ['65', Array(65).fill('a')], ['63', Array(63).fill('a')]]) value('array/' + n, AR, x);
const AS3 = T('array', { items: 'string', max_len: 3 });
for (const [n, x] of [['3', ['abc']], ['4', ['abcd']], ['é é', ['éé']], ['abé', ['abé']]]) value('array s3/' + n, AS3, x);
const AI = T('array', { items: 'integer', min: -1, max: 3 });
for (const [n, x] of [['ok', [-1, 0, 3]], ['below', [-2]], ['above', [4]], ['above late', [0, 4]], ['frac', [R('1.5')]], ['-0', [R('-0')]], ['str', ['1']], ['big', [R('9007199254740992')]],
  ['frac then above', [R('0.5'), 9]], ['above then frac', [9, R('0.5')]], ['empty', []], ['65', Array(65).fill(0)], ['64', Array(64).fill(0)]]) value('array int/' + n, AI, x);
for (const [n, x] of [['ok', [5, -5]], ['frac', [R('1.5')]]]) value('array int nominmax/' + n, T('array', { items: 'integer' }), x);
for (const [n, x] of [['min only below', [-1]], ['min only ok', [0, 100]]]) value('array int min/' + n, T('array', { items: 'integer', min: 0 }), x);
for (const [n, x] of [['max only above', [1]], ['max only ok', [0, -100]]]) value('array int max/' + n, T('array', { items: 'integer', max: 0 }), x);
const AB = T('array', { min_items: 1, max_items: 2 });
for (const [n, x] of [['0', []], ['1', ['a']], ['2', ['a', 'b']], ['3', ['a', 'b', 'c']]]) value('array bounds/' + n, AB, x);
value('array other items/num', T('array', { items: 'date' }), [1]);
value('array other items/str', T('array', { items: 'date' }), ['x']);
for (const [n, d] of [['unknown', T('number')], ['type num', T(1)], ['type absent', { semantic: 's' }], ['type null', T(null)]]) value('type/' + n, d, 'x');

// ---- conformAction ---------------------------------------------------------------------------------------------------
const CD = doc({ verbs: [
  { verb: 'v.read', kind: 'read', params: {} },
  { verb: 'air.book', kind: 'write', params: {
    'action.params.amount': T('integer', { min: 1, max: 100 }),
    'action.params.class': T('string', { values: ['eco', 'biz'] }),
    'action.params.note': T('string', { required: false, max_len: 4 }),
    'action.params.refundable': T('boolean', { required: true }),
    'action.params.addons': T('set', { values: ['bag', 'meal'], required: false }),
    'action.params.ids': T('array', { items: 'integer', required: false }),
    'action.params.\u{10000}': T('string', { required: false }),
    'action.params.￿': T('string', { required: false }),
  } },
  { verb: 'air.book', kind: 'read', params: {} },
] });
// the astral / BMP-max names are not valid paths (shape rejects them) but conformAction does not re-check shape
const OKP = { amount: 5, class: 'eco', refundable: true };
function conform(name, d, verb, params) {
  const dt = ser(d), pt = ser(params);
  const r = pca.conformAction(P(dt), verb, P(pt));
  out.conform.push({ name: uniq('conform/' + name), doc: dt, verb, params: pt,
    want: r.ok ? { ok: true } : { ok: false, code: r.code, path: r.path ?? null, reason: r.code === 'bad_type' || r.code === 'out_of_domain' ? r.reason.replace(/^('[^']*': )(.*)$/, (_, a, b) => a + kReason(b)) : r.reason } });
}
conform('ok', CD, 'air.book', OKP);
conform('ok read', CD, 'v.read', {});
conform('ok all', CD, 'air.book', { ...OKP, note: 'abcd', addons: ['meal', 'bag'], ids: [1, 2], '\u{10000}': 'x', '￿': 'y' });
conform('params arr', CD, 'air.book', []);
conform('params null', CD, 'air.book', null);
conform('params str', CD, 'air.book', 'x');
conform('unknown verb', CD, 'air.cancel', OKP);
conform('verb case', CD, 'Air.book', OKP);
conform('undeclared', CD, 'air.book', { ...OKP, zz: 1 });
conform('undeclared order', CD, 'air.book', { ...OKP, zz: 1, yy: 1 });
conform('undeclared utf8 order', CD, 'air.book', { '\u{10001}': 1, '￾': 1 });
conform('undeclared on read', CD, 'v.read', { a: 1 });
conform('missing required default', CD, 'air.book', { class: 'eco', refundable: true });
conform('missing required true', CD, 'air.book', { amount: 5, class: 'eco' });
conform('missing class', CD, 'air.book', { amount: 5, refundable: true });
conform('optional absent ok', CD, 'air.book', OKP);
conform('first failure in byte order', CD, 'air.book', { amount: 0, class: 'xxx', refundable: 'no' });
conform('class bad', CD, 'air.book', { ...OKP, class: 'first' });
conform('amount above', CD, 'air.book', { ...OKP, amount: 101 });
conform('amount below', CD, 'air.book', { ...OKP, amount: 0 });
conform('amount frac', CD, 'air.book', { ...OKP, amount: R('1.5') });
conform('note long', CD, 'air.book', { ...OKP, note: 'abcde' });
conform('refundable str', CD, 'air.book', { ...OKP, refundable: 'yes' });
conform('addons dup', CD, 'air.book', { ...OKP, addons: ['bag', 'bag'] });
conform('ids frac', CD, 'air.book', { ...OKP, ids: [R('0.5')] });
conform('astral vs bmp order', CD, 'air.book', { ...OKP, '\u{10000}': 1, '￿': 2 });
conform('missing reported before later bad', CD, 'air.book', { amount: 5, refundable: 'x' });
conform('required false null value', CD, 'air.book', { ...OKP, note: null });
conform('verbs not array', { verbs: {} }, 'air.book', {});
conform('verb entries non-object', { verbs: ['x', 1, { verb: 'a', kind: 'read', params: {} }] }, 'a', {});

// ---- schemaVerb ------------------------------------------------------------------------------------------------------
function verbOf(name, d, verb) {
  const dt = ser(d);
  const r = pca.schemaVerb(P(dt), verb);
  out.verbOf.push({ name: uniq('verbOf/' + name), doc: dt, verb, want: r === undefined ? null : ser(r) });
}
verbOf('first of dup', CD, 'air.book');
verbOf('read', CD, 'v.read');
verbOf('absent', CD, 'zz');
verbOf('verbs obj', { verbs: { verb: 'a' } }, 'a');
verbOf('verbs absent', {}, 'a');
verbOf('non-object entries', { verbs: ['a', 1, [], { verb: 'a', n: 1 }, { verb: 'a', n: 2 }] }, 'a');
verbOf('verb num', { verbs: [{ verb: 1 }, { verb: '1', n: 2 }] }, '1');

// ---- canonProjection -------------------------------------------------------------------------------------------------
const PD = doc({ verbs: [{ verb: 'p', kind: 'write', params: {
  'action.params.b': T('boolean'), 'action.params.flag': T('boolean'), 'action.params.s': T('set', { values: ['a', 'b', '\u{10000}', '￿'] }),
  'action.params.arr': T('array'), 'action.params.n': T('integer'), 'action.params.str': T('string'), 'action.params.d': T('date'), 'action.params.Z': T('array', { items: 'integer' }),
} }] });
function canon(name, d, verb, params) {
  const dt = ser(d), pt = ser(params);
  const r = pca.canonProjection(P(dt), verb, P(pt));
  out.canon.push({ name: uniq('canon/' + name), doc: dt, verb, params: pt, want: Object.entries(r) });
}
canon('all', PD, 'p', { b: true, flag: false, s: ['￿', 'b', '\u{10000}', 'a'], arr: ['z', 'a', 'z'], n: 5, str: 'x', d: '2024-01-01', Z: [3, 1, R('2')] });
canon('bool non-true', PD, 'p', { b: 1, flag: 'true' });
canon('bool null', PD, 'p', { b: null });
canon('none present', PD, 'p', {});
canon('set empty', PD, 'p', { s: [] });
canon('array empty', PD, 'p', { arr: [] });
canon('unknown verb', PD, 'q', { b: true });
canon('only Z', PD, 'p', { Z: [R('1e0'), 2] });
canon('extra undeclared', PD, 'p', { zz: true, b: false });

// ---- accumulationParams ----------------------------------------------------------------------------------------------
function accum(name, v, unit) {
  const vt = ser(v);
  out.accum.push({ name: uniq('accum/' + name), verb: vt, unit, want: pca.accumulationParams(P(vt), unit) });
}
const AV = { verb: 'a', kind: 'write', params: {
  'action.params.z': T('integer', { accumulates_into: ['usd', 'eur'] }), 'action.params.a': T('integer', { accumulates_into: ['usd'] }),
  'action.params.s': T('string', { accumulates_into: ['usd'] }), 'action.params.m': T('integer', { accumulates_into: ['eur'] }),
  'action.params.n': T('integer'), 'action.params.\u{10000}': T('integer', { accumulates_into: ['usd'] }), 'action.params.￿': T('integer', { accumulates_into: ['usd'] }),
  'action.params.ar': T('array', { items: 'integer', accumulates_into: ['usd'] }),
} };
accum('usd', AV, 'usd');
accum('eur', AV, 'eur');
accum('none', AV, 'gbp');
accum('empty params', { verb: 'a', kind: 'read', params: {} }, 'usd');

fs.writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n');
const n = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.length]));
console.error('killG oracle:', JSON.stringify(n));
