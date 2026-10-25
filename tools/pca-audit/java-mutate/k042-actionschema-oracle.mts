// Differential oracle for the Java ActionSchema 0.4.2 mutation kills (sdks/java-pca/test/net/atlasauth/pca/K042ActionSchemaTest.java).
//
// Runs the TypeScript reference (packages/pca/src/action-schema.ts + intent-v2.ts canonProjection) on targeted inputs at
// the exact boundary of every rule-14 check: the schema shape (document / units / sig), every verb-entry and parameter
// declaration rule, the closed-world conformance (order of failures, every value-domain rule), the signature check against
// the discovery key list (ed25519 and a pinned ML-DSA-65 key), accumulationParams and the env.canon projection.
// Every input is stored as RAW JSON TEXT and the reference evaluates JSON.parse(raw), so both sides see the same value
// (including -0 and lone-surrogate escapes, which JSON.stringify could not round-trip).
//
//   npx tsx tools/pca-audit/java-mutate/k042-actionschema-oracle.mts     (from the repo root)
// writes sdks/java-pca/test-data/k042-actionschema.json. Deterministic except the ML-DSA signature bytes (hedged signing).
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import * as pcaNs from '../../../packages/pca/src/index.ts';
const pca: any = (pcaNs as any).actionSchemaShapeError ? pcaNs : (pcaNs as any).default; // CJS interop under tsx

const ROOT = new URL('../../../', import.meta.url).pathname;
const seed = (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const s = (n: number, ch = 'a') => ch.repeat(n);
const names = new Set<string>();
const uniq = (n: string) => {
  if (names.has(n)) throw new Error(`duplicate case ${n}`);
  names.add(n);
  return n;
};
const raw = (x: any): string => (typeof x === 'object' && x !== null && x.__raw !== undefined ? x.__raw : JSON.stringify(x));
const R = (text: string) => ({ __raw: text });

// ---------------------------------------------------------------------------------------------------------------------
// shape: actionSchemaShapeError(doc) (signed)
const SIG = { alg: 'ed25519', kid: 'k1', value: 'AA' };
const BASE: any = {
  v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
  verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.total': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', unit: 'usd_cents' } } }],
  sig: SIG,
};
const shape: any[] = [];
const addShape = (name: string, doc: any) => {
  const r = raw(doc);
  shape.push({ name: uniq('shape/' + name), doc: r, expect: pca.actionSchemaShapeError(JSON.parse(r)) });
};
const withDoc = (f: (d: any) => void) => { const d = clone(BASE); f(d); return d; };
const verbsN = (n: number) => Array.from({ length: n }, (_, i) => ({ verb: `v${i}`, kind: 'read', params: {} }));

addShape('base', BASE);
addShape('not object string', 'x');
addShape('not object array', []);
addShape('not object null', null);
addShape('unknown member', withDoc((d) => { d.zz = 'x'; }));
addShape('unknown member first', R('{"zz":1,' + JSON.stringify(BASE).slice(1)));
addShape('v 2', withDoc((d) => { d.v = 2; }));
addShape('v 1.0', R(JSON.stringify(BASE).replace('"v":1', '"v":1.0')));
addShape('v string', withDoc((d) => { d.v = '1'; }));
addShape('v missing', withDoc((d) => { delete d.v; }));
addShape('kind wrong', withDoc((d) => { d.kind = 'pca-schema'; }));
addShape('kind missing', withDoc((d) => { delete d.kind; }));
for (const [k, max] of [['site', 2048], ['aud', 256], ['version', 128]] as const) {
  addShape(`${k} ${max}`, withDoc((d) => { d[k] = s(max); }));
  addShape(`${k} ${max + 1}`, withDoc((d) => { d[k] = s(max + 1); }));
  addShape(`${k} ${max} multibyte over`, withDoc((d) => { d[k] = s(max - 1) + 'é'; }));
  addShape(`${k} empty`, withDoc((d) => { d[k] = ''; }));
  addShape(`${k} missing`, withDoc((d) => { delete d[k]; }));
  addShape(`${k} number`, withDoc((d) => { d[k] = 7; }));
  addShape(`${k} lone surrogate`, R(JSON.stringify(withDoc((d) => { d[k] = 'LONE'; })).replace('"LONE"', '"a\\ud800"')));
}
// units
const unit = (u: any) => withDoc((d) => { d.units.usd_cents = u; });
addShape('no units, no unit refs', withDoc((d) => { delete d.units; d.verbs = verbsN(1); }));
addShape('units empty', withDoc((d) => { d.units = {}; d.verbs = verbsN(1); }));
addShape('units not object', withDoc((d) => { d.units = []; }));
addShape('units string', withDoc((d) => { d.units = 'x'; }));
addShape('units null', withDoc((d) => { d.units = null; d.verbs = verbsN(1); }));
addShape('unit id upper', withDoc((d) => { d.units.USD = { kind: 'money' }; }));
addShape('unit id dotted', withDoc((d) => { d.units['spend.usd'] = { kind: 'money' }; }));
addShape('unit id trailing dot', withDoc((d) => { d.units['spend.'] = { kind: 'money' }; }));
addShape('unit id 64', withDoc((d) => { d.units[s(64)] = { kind: 'money' }; }));
addShape('unit id 65', withDoc((d) => { d.units[s(65)] = { kind: 'money' }; }));
addShape('unit not object', unit('money'));
addShape('unit null', unit(null));
addShape('unit array', unit([]));
addShape('unit kind missing', unit({ currency: 'USD' }));
addShape('unit kind empty', unit({ kind: '' }));
addShape('unit kind 64', unit({ kind: s(64) }));
addShape('unit kind 65', unit({ kind: s(65) }));
addShape('unit unknown member', unit({ kind: 'money', zz: 1 }));
addShape('unit unknown member first', unit({ zz: 1, kind: 'money' }));
addShape('currency 16', unit({ kind: 'money', currency: s(16) }));
addShape('currency 17', unit({ kind: 'money', currency: s(17) }));
addShape('currency empty', unit({ kind: 'money', currency: '' }));
addShape('currency null', unit({ kind: 'money', currency: null }));
addShape('currency number', unit({ kind: 'money', currency: 5 }));
addShape('exponent 0', unit({ kind: 'money', exponent: 0 }));
addShape('exponent 18', unit({ kind: 'money', exponent: 18 }));
addShape('exponent 19', unit({ kind: 'money', exponent: 19 }));
addShape('exponent -1', unit({ kind: 'money', exponent: -1 }));
addShape('exponent fraction', unit({ kind: 'money', exponent: 1.5 }));
addShape('exponent null', unit({ kind: 'money', exponent: null }));
addShape('exponent string', unit({ kind: 'money', exponent: '2' }));
addShape('only kind', unit({ kind: 'money' }));
addShape('second unit bad', withDoc((d) => { d.units.zz = { kind: 'money', exponent: 99 }; }));
// state
addShape('state ok', withDoc((d) => { d.state = []; }));
addShape('state items', withDoc((d) => { d.state = [{ x: 1 }, 'y']; }));
addShape('state not array', withDoc((d) => { d.state = {}; }));
addShape('state null', withDoc((d) => { d.state = null; }));
addShape('state string', withDoc((d) => { d.state = 's'; }));
addShape('state fraction (non-strict number)', withDoc((d) => { d.state = [0.5]; }));
addShape('state -0 (non-strict number)', R(JSON.stringify(withDoc((d) => { d.state = ['NZ']; })).replace('"NZ"', '-0')));
addShape('state lone surrogate', R(JSON.stringify(withDoc((d) => { d.state = ['LONE']; })).replace('"LONE"', '"\\udc00"')));
addShape('state 1e21', R(JSON.stringify(withDoc((d) => { d.state = ['BIG']; })).replace('"BIG"', '1e21')));
// verbs
addShape('verbs missing', withDoc((d) => { delete d.verbs; }));
addShape('verbs not array', withDoc((d) => { d.verbs = {}; }));
addShape('verbs null', withDoc((d) => { d.verbs = null; }));
addShape('verbs empty', withDoc((d) => { d.verbs = []; }));
addShape('verbs 1', withDoc((d) => { d.verbs = verbsN(1); }));
addShape('verbs 2', withDoc((d) => { d.verbs = verbsN(2); }));
addShape('verbs 256', withDoc((d) => { d.verbs = verbsN(256); }));
addShape('verbs 257', withDoc((d) => { d.verbs = verbsN(257); }));
addShape('verb twice', withDoc((d) => { d.verbs = [...verbsN(2), ...verbsN(1)]; }));
addShape('verb twice adjacent', withDoc((d) => { d.verbs = [...verbsN(1), ...verbsN(1)]; }));
addShape('verb bad', withDoc((d) => { d.verbs = [{ verb: 'x' }]; }));
addShape('verb bad after good', withDoc((d) => { d.verbs = [...verbsN(1), { verb: 'x', kind: 'read' }]; }));
addShape('verb unit undeclared (no units)', withDoc((d) => { delete d.units; }));
addShape('verb unit undeclared', withDoc((d) => { d.units = { other: { kind: 'money' } }; }));
// sig
const sig = (x: any) => withDoc((d) => { d.sig = x; });
addShape('sig missing', withDoc((d) => { delete d.sig; }));
addShape('sig not object', sig('x'));
addShape('sig array', sig([]));
addShape('sig null', sig(null));
addShape('sig unknown member', sig({ ...SIG, zz: 1 }));
addShape('sig unknown member first', sig({ zz: 1, ...SIG }));
addShape('sig no alg', sig({ kid: 'k', value: 'AA' }));
addShape('sig alg unknown', sig({ ...SIG, alg: 'rsa' }));
addShape('sig alg null', sig({ ...SIG, alg: null }));
addShape('sig alg number', sig({ ...SIG, alg: 7 }));
addShape('sig alg ml-dsa-65', sig({ ...SIG, alg: 'ml-dsa-65' }));
addShape('sig kid missing', sig({ alg: 'ed25519', value: 'AA' }));
addShape('sig kid empty', sig({ ...SIG, kid: '' }));
addShape('sig kid 128', sig({ ...SIG, kid: s(128) }));
addShape('sig kid 129', sig({ ...SIG, kid: s(129) }));
addShape('sig kid number', sig({ ...SIG, kid: 1 }));
addShape('sig value bad', sig({ ...SIG, value: 'A+' }));
addShape('sig value padded', sig({ ...SIG, value: 'AA==' }));
addShape('sig value missing', sig({ alg: 'ed25519', kid: 'k' }));
addShape('sig value number', sig({ ...SIG, value: 5 }));
addShape('sig value empty', sig({ ...SIG, value: '' }));
addShape('sig pq_value ok', sig({ ...SIG, pq_value: 'AAAA' }));
addShape('sig pq_value bad', sig({ ...SIG, pq_value: 'A=' }));
addShape('sig pq_value null', sig({ ...SIG, pq_value: null }));
addShape('sig pq_value number', sig({ ...SIG, pq_value: 1 }));
addShape('sig ok, non-strict body after', withDoc((d) => { d.state = [1.5]; d.sig = { ...SIG }; }));

// ---- verb entries (verbDeclError), inside the base document
const P = { 'action.params.cabin': { type: 'string', semantic: 's', sensitivity: 'free', values: ['eco', 'biz'] } };
const V = { verb: 'a.b', kind: 'write', params: P };
const verb = (name: string, v: any, units?: any) =>
  addShape('verb/' + name, withDoc((d) => { d.verbs = [v]; if (units === null) delete d.units; else if (units !== undefined) d.units = units; }));
const paramsN = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`action.params.p${i}`, { type: 'string', semantic: 's', sensitivity: 'free' }]));
verb('base', V);
verb('read', { ...V, kind: 'read' });
verb('not object', []);
verb('null', null);
verb('string', 'a.b');
verb('unknown member', { ...V, zz: 1 });
verb('unknown member first', { zz: 1, ...V });
verb('verb empty', { ...V, verb: '' });
verb('verb missing', { kind: 'write', params: P });
verb('verb number', { ...V, verb: 5 });
verb('verb 128', { ...V, verb: s(128) });
verb('verb 129', { ...V, verb: s(129) });
verb('verb lone surrogate', { ...V, verb: 'LONE' });
shape[shape.length - 1] = (() => {
  const r = JSON.stringify(withDoc((d) => { d.verbs = [{ ...V, verb: 'LONE' }]; })).replace('"LONE"', '"\\ud800"');
  return { name: 'shape/verb/verb lone surrogate', doc: r, expect: pca.actionSchemaShapeError(JSON.parse(r)) };
})();
verb('kind bad', { ...V, kind: 'delete' });
verb('kind missing', { verb: 'a.b', params: P });
verb('kind number', { ...V, kind: 1 });
verb('params missing', { verb: 'a.b', kind: 'write' });
verb('params array', { ...V, params: [] });
verb('params null', { ...V, params: null });
verb('params empty', { ...V, params: {} });
verb('params 64', { ...V, params: paramsN(64) });
verb('params 65', { ...V, params: paramsN(65) });
verb('param bad', { ...V, params: { 'action.params.x': { type: 'string' } } });
verb('second param bad', { ...V, params: { ...P, 'action.params.x': { type: 'string', semantic: 's', sensitivity: 'loud' } } });
verb('reversibility reversible', { ...V, reversibility: 'reversible' });
verb('reversibility rate_limited', { ...V, reversibility: 'rate_limited' });
verb('reversibility irreversible', { ...V, reversibility: 'irreversible' });
verb('reversibility bad', { ...V, reversibility: 'maybe' });
verb('reversibility null', { ...V, reversibility: null });
verb('reversibility number', { ...V, reversibility: 0 });
const RB = (r: any) => ({ ...V, reversibility_by: r });
verb('rev_by ok', RB({ param: 'action.params.cabin', map: { eco: 'reversible' }, default: 'irreversible' }));
verb('rev_by no default', RB({ param: 'action.params.cabin', map: { eco: 'reversible' } }));
verb('rev_by map 2', RB({ param: 'action.params.cabin', map: { eco: 'reversible', biz: 'rate_limited' } }));
verb('rev_by not object', RB('x'));
verb('rev_by array', RB([]));
verb('rev_by null', RB(null));
verb('rev_by unknown member', RB({ param: 'action.params.cabin', map: { eco: 'reversible' }, zz: 1 }));
verb('rev_by unknown member first', RB({ zz: 1, param: 'action.params.cabin', map: { eco: 'reversible' } }));
verb('rev_by param not string', RB({ param: 1, map: { eco: 'reversible' } }));
verb('rev_by param missing', RB({ map: { eco: 'reversible' } }));
verb('rev_by param undeclared', RB({ param: 'action.params.other', map: { eco: 'reversible' } }));
verb('rev_by map not object', RB({ param: 'action.params.cabin', map: [] }));
verb('rev_by map string', RB({ param: 'action.params.cabin', map: 'x' }));
verb('rev_by map missing', RB({ param: 'action.params.cabin' }));
verb('rev_by map empty', RB({ param: 'action.params.cabin', map: {} }));
verb('rev_by map value bad', RB({ param: 'action.params.cabin', map: { eco: 'reversible', biz: 'nope' } }));
verb('rev_by map value bad first', RB({ param: 'action.params.cabin', map: { eco: 'nope', biz: 'reversible' } }));
verb('rev_by map value number', RB({ param: 'action.params.cabin', map: { eco: 1 } }));
verb('rev_by default bad', RB({ param: 'action.params.cabin', map: { eco: 'reversible' }, default: 'nope' }));
verb('rev_by default null', RB({ param: 'action.params.cabin', map: { eco: 'reversible' }, default: null }));
verb('rev_by default reversible', RB({ param: 'action.params.cabin', map: { eco: 'reversible' }, default: 'reversible' }));
verb('rev_by and bad reversibility', { ...RB({ param: 'action.params.cabin', map: { eco: 'reversible' } }), reversibility: 'x' });
for (const [k, inner] of [['mcp', 'tool'], ['openapi', 'operationId']] as const) {
  verb(`${k} ok`, { ...V, [k]: { [inner]: 't' } });
  verb(`${k} 128`, { ...V, [k]: { [inner]: s(128) } });
  verb(`${k} 129`, { ...V, [k]: { [inner]: s(129) } });
  verb(`${k} empty value`, { ...V, [k]: { [inner]: '' } });
  verb(`${k} number value`, { ...V, [k]: { [inner]: 1 } });
  verb(`${k} empty object`, { ...V, [k]: {} });
  verb(`${k} extra member`, { ...V, [k]: { [inner]: 't', x: 'y' } });
  verb(`${k} wrong member`, { ...V, [k]: { zz: 't' } });
  verb(`${k} not object`, { ...V, [k]: 't' });
  verb(`${k} array`, { ...V, [k]: ['t'] });
  verb(`${k} null`, { ...V, [k]: null });
}
for (const k of ['harm', 'effects', 'returns']) {
  verb(`${k} ok`, { ...V, [k]: { a: 1 } });
  verb(`${k} array`, { ...V, [k]: [] });
  verb(`${k} number`, { ...V, [k]: 1 });
  verb(`${k} null`, { ...V, [k]: null });
}
verb('world ok', { ...V, world: [] });
verb('world items', { ...V, world: [1, 'x'] });
verb('world object', { ...V, world: {} });
verb('world null', { ...V, world: null });
verb('description 1024', { ...V, description: s(1024) });
verb('description 1025', { ...V, description: s(1025) });
verb('description empty', { ...V, description: '' });
verb('description number', { ...V, description: 1 });
verb('description null', { ...V, description: null });

// ---- parameter declarations (paramDeclError)
const U = { usd_cents: { kind: 'money' } };
const decl = (name: string, d: any, path = 'action.params.x', units: any = U) =>
  addShape('param/' + name, withDoc((doc) => { doc.verbs = [{ verb: 'a.b', kind: 'write', params: { [path]: d } }]; if (units === null) delete doc.units; else doc.units = units; }));
const S = { type: 'string', semantic: 's', sensitivity: 'free' };
const I = { type: 'integer', semantic: 's', sensitivity: 'free' };
const A = { type: 'array', semantic: 's', sensitivity: 'free' };
const SET = { type: 'set', semantic: 's', sensitivity: 'free' };
const B = { type: 'boolean', semantic: 's', sensitivity: 'free' };
const D = { type: 'date', semantic: 's', sensitivity: 'free' };
const vals = (n: number, size = 0) => Array.from({ length: n }, (_, i) => { const x = `v${i}`; return size > x.length ? x + s(size - x.length, 'z') : x; });
const units8 = (n: number) => Array.from({ length: n }, (_, i) => `u${i}`);
decl('base string', S);
for (const t of [I, A, B, D]) decl(`base ${t.type}`, t);
decl('bad path', S, 'params.x');
decl('path name empty', S, 'action.params.');
decl('path name 64', S, 'action.params.' + s(64));
decl('path name 65', S, 'action.params.' + s(65));
decl('path nested', S, 'action.params.a.b');
decl('path dash', S, 'action.params.a-b');
decl('__proto__', S, 'action.params.__proto__');
decl('constructor', S, 'action.params.constructor');
decl('prototype', S, 'action.params.prototype');
decl('prototype2', S, 'action.params.prototype2');
decl('not object', 'x');
decl('array', []);
decl('null decl', null);
decl('unknown member', { ...S, zz: 1 });
decl('unknown member first', { zz: 1, ...S });
decl('bad type', { ...S, type: 'number' });
decl('no type', { semantic: 's', sensitivity: 'free' });
decl('type number', { ...S, type: 1 });
decl('semantic empty', { ...S, semantic: '' });
decl('semantic missing', { type: 'string', sensitivity: 'free' });
decl('semantic 128', { ...S, semantic: s(128) });
decl('semantic 129', { ...S, semantic: s(129) });
decl('semantic number', { ...S, semantic: 1 });
decl('bad sensitivity', { ...S, sensitivity: 'high' });
decl('sensitivity missing', { type: 'string', semantic: 's' });
decl('sensitivity material', { ...S, sensitivity: 'material' });
decl('sensitivity critical', { ...S, sensitivity: 'critical' });
decl('required true', { ...S, required: true });
decl('required false', { ...S, required: false });
decl('required string', { ...S, required: 'no' });
decl('required null', { ...S, required: null });
decl('values ok', { ...S, values: ['a', 'b'] });
decl('values 1', { ...S, values: ['a'] });
decl('values not array', { ...S, values: 'a' });
decl('values null', { ...S, values: null });
decl('values empty', { ...S, values: [] });
decl('values 256', { ...S, values: vals(256) });
decl('values 257', { ...S, values: vals(257) });
decl('values entry 256 bytes', { ...S, values: vals(1, 256) });
decl('values entry 257 bytes', { ...S, values: vals(1, 257) });
decl('values entry not string', { ...S, values: ['a', 1] });
decl('values entry not string first', { ...S, values: [1, 'a'] });
decl('values entry empty', { ...S, values: ['a', ''] });
decl('values dup', { ...S, values: ['a', 'a'] });
decl('values dup later', { ...S, values: ['a', 'b', 'a'] });
decl('values on integer', { ...I, values: ['a'] });
decl('values on boolean', { ...B, values: ['a'] });
decl('values on array', { ...A, values: ['a'] });
decl('values on set', { ...SET, values: ['a'] });
decl('set without values', SET);
decl('set values null', { ...SET, values: null });
for (const k of ['min', 'max']) {
  decl(`${k} on integer`, { ...I, [k]: 0 });
  decl(`${k} negative on integer`, { ...I, [k]: -5 });
  decl(`${k} fraction`, { ...I, [k]: 1.5 });
  decl(`${k} string`, { ...I, [k]: '1' });
  decl(`${k} null`, { ...I, [k]: null });
  decl(`${k} unsafe`, { ...I, [k]: 2 ** 53 });
  decl(`${k} on string`, { ...S, [k]: 0 });
  decl(`${k} on boolean`, { ...B, [k]: 0 });
  decl(`${k} on int array`, { ...A, items: 'integer', [k]: 0 });
  decl(`${k} on string array`, { ...A, items: 'string', [k]: 0 });
  decl(`${k} on array no items`, { ...A, [k]: 0 });
  decl(`${k} on set`, { ...SET, values: ['a'], [k]: 0 });
}
decl('min -0', R(JSON.stringify({ ...I, min: 'NZ' }).replace('"NZ"', '-0')));
decl('min == max', { ...I, min: 5, max: 5 });
decl('min < max', { ...I, min: 4, max: 5 });
decl('min > max', { ...I, min: 6, max: 5 });
decl('min > max by one (negative)', { ...I, min: -4, max: -5 });
decl('min > max int array', { ...A, items: 'integer', min: 6, max: 5 });
decl('min only', { ...I, min: 6 });
decl('max only', { ...I, max: -6 });
decl('unit ok', { ...I, unit: 'usd_cents' });
decl('unit on string', { ...S, unit: 'usd_cents' });
decl('unit on array', { ...A, items: 'integer', unit: 'usd_cents' });
decl('unit not string', { ...I, unit: 5 });
decl('unit null', { ...I, unit: null });
decl('unit without units', { ...I, unit: 'usd_cents' }, 'action.params.x', null);
decl('unit undeclared', { ...I, unit: 'eur_cents' });
decl('unit undeclared, a unit named unit', { ...I, unit: 'usd_cents' }, 'action.params.x', { unit: { kind: 'money' } });
decl('items integer on string with min', { ...S, items: 'integer', min: 0 });
decl('items integer on integer with max', { ...I, items: 'integer', max: 0 });
decl('unit empty units', { ...I, unit: 'usd_cents' }, 'action.params.x', {});
decl('max_len 1', { ...S, max_len: 1 });
decl('max_len 2', { ...S, max_len: 2 });
decl('max_len 0', { ...S, max_len: 0 });
decl('max_len -1', { ...S, max_len: -1 });
decl('max_len fraction', { ...S, max_len: 1.5 });
decl('max_len string', { ...S, max_len: '1' });
decl('max_len null', { ...S, max_len: null });
decl('max_len on integer', { ...I, max_len: 3 });
decl('items integer on array', { ...A, items: 'integer' });
decl('items named on array', { ...A, items: 'airport' });
decl('items 64', { ...A, items: s(64) });
decl('items 65', { ...A, items: s(65) });
decl('items empty', { ...A, items: '' });
decl('items number', { ...A, items: 1 });
decl('items null', { ...A, items: null });
decl('items on string', { ...S, items: 'integer' });
decl('items on set', { ...SET, values: ['a'], items: 'integer' });
for (const k of ['min_items', 'max_items']) {
  decl(`${k} on set`, { ...SET, values: ['a'], [k]: 0 });
  decl(`${k} on array`, { ...A, [k]: 1 });
  decl(`${k} 0 on array`, { ...A, [k]: 0 });
  decl(`${k} on string`, { ...S, [k]: 0 });
  decl(`${k} on integer`, { ...I, [k]: 0 });
  decl(`${k} negative`, { ...A, [k]: -1 });
  decl(`${k} fraction`, { ...A, [k]: 0.5 });
  decl(`${k} string`, { ...A, [k]: '1' });
  decl(`${k} null`, { ...A, [k]: null });
}
decl('min_items == max_items', { ...A, min_items: 2, max_items: 2 });
decl('min_items < max_items', { ...A, min_items: 1, max_items: 2 });
decl('min_items > max_items', { ...A, min_items: 3, max_items: 2 });
decl('min_items > max_items set', { ...SET, values: ['a'], min_items: 1, max_items: 0 });
decl('min_items only big', { ...A, min_items: 99 });
decl('default null', { ...S, default: null });
decl('default', { ...S, default: 'x' });
decl('default false', { ...B, default: false });
decl('pnd not bool', { ...S, default: 'x', principal_neutral_default: 1 });
decl('pnd null', { ...S, default: 'x', principal_neutral_default: null });
decl('pnd true no default', { ...S, principal_neutral_default: true });
decl('pnd true default', { ...S, default: 'x', principal_neutral_default: true });
decl('pnd false no default', { ...S, principal_neutral_default: false });
decl('pnd true default false', { ...B, default: false, principal_neutral_default: true });
decl('acc ok', { ...I, accumulates_into: ['spend.usd'] });
decl('acc on string', { ...S, accumulates_into: ['spend'] });
decl('acc on array', { ...A, items: 'integer', accumulates_into: ['spend'] });
decl('acc not array', { ...I, accumulates_into: 'spend' });
decl('acc null', { ...I, accumulates_into: null });
decl('acc object', { ...I, accumulates_into: {} });
decl('acc empty', { ...I, accumulates_into: [] });
decl('acc 1', { ...I, accumulates_into: units8(1) });
decl('acc 8', { ...I, accumulates_into: units8(8) });
decl('acc 9', { ...I, accumulates_into: units8(9) });
decl('acc entry not string', { ...I, accumulates_into: [1] });
decl('acc entry not string later', { ...I, accumulates_into: ['a', 1] });
decl('acc entry 64', { ...I, accumulates_into: [s(64)] });
decl('acc entry 65', { ...I, accumulates_into: [s(65)] });
decl('acc entry bad id', { ...I, accumulates_into: ['Spend'] });
decl('acc entry empty', { ...I, accumulates_into: [''] });
decl('acc entry dotted ok', { ...I, accumulates_into: ['a.b_c.d9'] });
decl('acc dup', { ...I, accumulates_into: ['a', 'a'] });
decl('acc dup later', { ...I, accumulates_into: ['a', 'b', 'a'] });
decl('issued_by_site', { ...S, issued_by_site: true });
decl('issued_by_site false', { ...S, issued_by_site: false });
decl('issued_by_site not bool', { ...S, issued_by_site: 'yes' });
decl('issued_by_site null', { ...S, issued_by_site: null });
decl('description 1024', { ...S, description: s(1024) });
decl('description 1025', { ...S, description: s(1025) });
decl('description empty', { ...S, description: '' });
decl('description null', { ...S, description: null });
decl('description number', { ...S, description: 1 });
decl('full integer', { ...I, required: false, min: 0, max: 10, unit: 'usd_cents', default: 1, principal_neutral_default: true, accumulates_into: ['usd_cents'], issued_by_site: true, description: 'd' });
decl('full set', { ...SET, values: ['a', 'b'], min_items: 0, max_items: 2, default: ['a'], description: 'd' });
decl('full array', { ...A, items: 'integer', min: 0, max: 9, min_items: 0, max_items: 3, max_len: 5 });
// second parameter of the same verb, to reach every check after a passing first one
addShape('param/second param bad', withDoc((doc) => { doc.verbs = [{ verb: 'a.b', kind: 'write', params: { 'action.params.a': S, 'action.params.b': { ...S, max_len: 0 } } }]; }));

// ---------------------------------------------------------------------------------------------------------------------
// paramValueViolation(d, x)
const pvv: any[] = [];
const addPvv = (name: string, d: any, x: any) => {
  const dr = raw(d);
  const xr = raw(x);
  pvv.push({ name: uniq('pvv/' + name), d: dr, x: xr, expect: pca.paramValueViolation(JSON.parse(dr), JSON.parse(xr)) });
};
const strs = (n: number, size: number) => Array.from({ length: n }, (_, i) => { const x = `s${i}`; return size > x.length ? x + s(size - x.length, 'z') : x; });
const ints = (n: number) => Array.from({ length: n }, (_, i) => i);
addPvv('string ok', { type: 'string' }, 'x');
addPvv('string empty ok', { type: 'string' }, '');
addPvv('string not string', { type: 'string' }, 1);
addPvv('string null', { type: 'string' }, null);
addPvv('string lone surrogate', { type: 'string' }, R('"a\\ud800"'));
addPvv('string default max 1024', { type: 'string' }, s(1024));
addPvv('string default max 1025', { type: 'string' }, s(1025));
addPvv('string max_len 3', { type: 'string', max_len: 3 }, 'abc');
addPvv('string max_len 3 over', { type: 'string', max_len: 3 }, 'abcd');
addPvv('string max_len bytes', { type: 'string', max_len: 3 }, 'aé');
addPvv('string max_len bytes over', { type: 'string', max_len: 3 }, 'aéé');
addPvv('string values in', { type: 'string', values: ['a', 'b'] }, 'b');
addPvv('string values out', { type: 'string', values: ['a', 'b'] }, 'c');
addPvv('string values too long first', { type: 'string', values: ['abcd'], max_len: 3 }, 'abcd');
addPvv('integer ok', { type: 'integer' }, 7);
addPvv('integer negative ok', { type: 'integer' }, -7);
addPvv('integer fraction', { type: 'integer' }, 7.5);
addPvv('integer -0', { type: 'integer' }, R('-0'));
addPvv('integer string', { type: 'integer' }, '7');
addPvv('integer unsafe', { type: 'integer' }, 2 ** 53);
addPvv('integer at min', { type: 'integer', min: 5, max: 9 }, 5);
addPvv('integer at max', { type: 'integer', min: 5, max: 9 }, 9);
addPvv('integer below min', { type: 'integer', min: 5, max: 9 }, 4);
addPvv('integer above max', { type: 'integer', min: 5, max: 9 }, 10);
addPvv('integer only min below', { type: 'integer', min: -3 }, -4);
addPvv('integer only min above', { type: 'integer', min: -3 }, 1000);
addPvv('integer only max above', { type: 'integer', max: -3 }, -2);
addPvv('integer only max below', { type: 'integer', max: -3 }, -1000);
addPvv('integer min 0 at 0', { type: 'integer', min: 0 }, 0);
addPvv('boolean false', { type: 'boolean' }, false);
addPvv('boolean true', { type: 'boolean' }, true);
addPvv('boolean string', { type: 'boolean' }, 'true');
addPvv('boolean number', { type: 'boolean' }, 1);
addPvv('date ok', { type: 'date' }, '2024-02-29');
addPvv('date bad', { type: 'date' }, '2023-02-29');
addPvv('date not string', { type: 'date' }, 20240229);
addPvv('date null', { type: 'date' }, null);
addPvv('date lone surrogate', { type: 'date' }, R('"\\ud800"'));
// every month: day 1, the last day and the day after, in a common, a leap, a century and a 400-year
const DIM = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
for (const y of [2023, 2024, 1900, 2000]) {
  for (let m = 1; m <= 12; m++) {
    const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
    const last = m === 2 && leap ? 29 : DIM[m - 1]!;
    const ds = (d: number) => `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    for (const d of [1, last, last + 1]) addPvv(`date ${ds(d)}`, { type: 'date' }, ds(d));
  }
}
for (const x of ['0001-01-01', '0000-01-01', '2024-00-01', '2024-13-01', '2024-01-00', '2024-1-01', '2024-01-1', '20240-1-01', '2024/01/01',
  '202a-01-01', '2024-01-01 ', '', '2024-01-:1', '9999-12-31', '2024-02-30', '2100-02-29', '2400-02-29', '2024-01-32', '2024-04-31'])
  addPvv(`date str ${JSON.stringify(x)}`, { type: 'date' }, x);
addPvv('set ok', { type: 'set', values: ['a', 'b', 'c'] }, ['c', 'a']);
addPvv('set empty ok', { type: 'set', values: ['a', 'b', 'c'] }, []);
addPvv('set all (default max = len(values))', { type: 'set', values: ['a', 'b', 'c'] }, ['a', 'b', 'c']);
addPvv('set not array', { type: 'set', values: ['a'] }, 'a');
addPvv('set object', { type: 'set', values: ['a'] }, { a: 1 });
addPvv('set member not string', { type: 'set', values: ['a'] }, ['a', 1]);
addPvv('set member not string first', { type: 'set', values: ['a'] }, [1, 'z', 'z']);
addPvv('set member null', { type: 'set', values: ['a'] }, [null]);
addPvv('set dup', { type: 'set', values: ['a', 'b'] }, ['a', 'a']);
addPvv('set dup and unknown', { type: 'set', values: ['a', 'b'] }, ['z', 'z']);
addPvv('set unknown member', { type: 'set', values: ['a', 'b'] }, ['a', 'z']);
addPvv('set unknown member first', { type: 'set', values: ['a', 'b'] }, ['z', 'a']);
addPvv('set at min_items', { type: 'set', values: ['a', 'b', 'c'], min_items: 2 }, ['a', 'b']);
addPvv('set below min_items', { type: 'set', values: ['a', 'b', 'c'], min_items: 2 }, ['a']);
addPvv('set at max_items', { type: 'set', values: ['a', 'b', 'c'], max_items: 2 }, ['a', 'b']);
addPvv('set above max_items', { type: 'set', values: ['a', 'b', 'c'], max_items: 2 }, ['a', 'b', 'c']);
addPvv('set max_items 0', { type: 'set', values: ['a'], max_items: 0 }, ['a']);
addPvv('set min_items 1 empty', { type: 'set', values: ['a'], min_items: 1 }, []);
addPvv('array strings ok', { type: 'array' }, ['x', 'y']);
addPvv('array not array', { type: 'array' }, 'x');
addPvv('array object', { type: 'array' }, {});
addPvv('array string item not string', { type: 'array' }, ['x', 1]);
addPvv('array string item null', { type: 'array' }, [null]);
addPvv('array string item at max_len', { type: 'array', max_len: 2 }, ['ab']);
addPvv('array string item over max_len', { type: 'array', max_len: 2 }, ['abc']);
addPvv('array string item over max_len bytes', { type: 'array', max_len: 2 }, ['é', 'aé']);
addPvv('array string item lone surrogate', { type: 'array' }, R('["\\ud800"]'));
addPvv('array string items empty strings', { type: 'array' }, ['', '']);
addPvv('array named items', { type: 'array', items: 'airport' }, ['SFO']);
addPvv('array named items int', { type: 'array', items: 'airport' }, [1]);
addPvv('array ints ok', { type: 'array', items: 'integer' }, [1, 2]);
addPvv('array ints string item', { type: 'array', items: 'integer' }, [1, '2']);
addPvv('array ints fraction', { type: 'array', items: 'integer' }, [1.5]);
addPvv('array ints -0', { type: 'array', items: 'integer' }, R('[-0]'));
addPvv('array ints at min', { type: 'array', items: 'integer', min: 2, max: 5 }, [2, 5]);
addPvv('array ints below min', { type: 'array', items: 'integer', min: 2, max: 5 }, [1]);
addPvv('array ints above max', { type: 'array', items: 'integer', min: 2, max: 5 }, [6]);
addPvv('array ints only min', { type: 'array', items: 'integer', min: 2 }, [1000]);
addPvv('array ints only max', { type: 'array', items: 'integer', max: 2 }, [-1000]);
addPvv('array ints only min below', { type: 'array', items: 'integer', min: 2 }, [1]);
addPvv('array ints only max above', { type: 'array', items: 'integer', max: 2 }, [3]);
addPvv('array ints below min later', { type: 'array', items: 'integer', min: 2 }, [3, 1]);
addPvv('array ints bad type after range', { type: 'array', items: 'integer', min: 2 }, [1, 'x']);
addPvv('array strings with min (ignored)', { type: 'array', min: 2, max: 5 }, ['a']);
addPvv('array empty default min_items', { type: 'array' }, []);
addPvv('array at min_items', { type: 'array', min_items: 2 }, ['a', 'b']);
addPvv('array below min_items', { type: 'array', min_items: 2 }, ['a']);
addPvv('array at max_items', { type: 'array', max_items: 2 }, ['a', 'b']);
addPvv('array above max_items', { type: 'array', max_items: 2 }, ['a', 'b', 'c']);
addPvv('array default max_items 64', { type: 'array', items: 'integer' }, ints(64));
addPvv('array default max_items 65', { type: 'array', items: 'integer' }, ints(65));
addPvv('array default max_len 1024 item', { type: 'array' }, strs(1, 1024));
addPvv('array default max_len 1025 item', { type: 'array' }, strs(1, 1025));
addPvv('array items 0 max_len 0', { type: 'array', max_len: 0 }, ['']);
addPvv('unknown type', { type: 'number' }, 1);
addPvv('type not string', { type: 1 }, 1);
addPvv('no type', {}, 1);

// ---------------------------------------------------------------------------------------------------------------------
// conformAction(doc, verb, params)
const conform: any[] = [];
const addConform = (name: string, doc: any, verb: string, params: any) => {
  const dr = raw(doc);
  const pr = raw(params);
  const r: any = pca.conformAction(JSON.parse(dr), verb, JSON.parse(pr));
  conform.push({ name: uniq('conform/' + name), doc: dr, verb, params: pr, expect: r.ok ? { ok: true } : { ok: false, code: r.code, path: r.path ?? null, reason: r.reason } });
};
const CD = {
  verbs: [
    { verb: 'x.y', kind: 'read', params: {} },
    { verb: 'a.b', kind: 'write', params: {
      'action.params.n': { type: 'integer', semantic: 's', sensitivity: 'free', min: 1, max: 9 },
      'action.params.a': { type: 'string', semantic: 's', sensitivity: 'free', values: ['x', 'y'] },
      'action.params.opt': { type: 'boolean', semantic: 's', sensitivity: 'free', required: false },
      'action.params.req': { type: 'boolean', semantic: 's', sensitivity: 'free', required: true },
      'action.params.é': { type: 'string', semantic: 's', sensitivity: 'free', required: false },
      'action.params.Z': { type: 'string', semantic: 's', sensitivity: 'free', required: false } } },
  ],
};
addConform('ok', CD, 'a.b', { n: 5, a: 'x', req: true });
addConform('ok with optional', CD, 'a.b', { n: 5, a: 'x', req: true, opt: false, Z: 'q' });
addConform('ok other verb', CD, 'x.y', {});
addConform('params array', CD, 'a.b', []);
addConform('params null', CD, 'a.b', null);
addConform('params string', CD, 'a.b', 'x');
addConform('unknown verb', CD, 'a.c', {});
addConform('unknown verb with params', CD, 'a.c', { n: 1 });
addConform('unknown verb case', CD, 'A.B', { n: 5, a: 'x', req: true });
addConform('undeclared on empty verb', CD, 'x.y', { q: 1 });
addConform('undeclared first in utf8 order', CD, 'a.b', { zz: 1, b0: 1, n: 5 });
addConform('undeclared utf8 vs utf16 order', CD, 'a.b', { '￿': 1, '\u{1F600}': 1 });
addConform('undeclared before missing', CD, 'a.b', { q: 1 });
addConform('missing (first declared in order)', CD, 'a.b', { n: 5, req: true });
addConform('missing required true', CD, 'a.b', { n: 5, a: 'x' });
addConform('missing all', CD, 'a.b', {});
addConform('bad_type', CD, 'a.b', { n: '5', a: 'x', req: true });
addConform('out_of_domain', CD, 'a.b', { n: 10, a: 'x', req: true });
addConform('out_of_domain below', CD, 'a.b', { n: 0, a: 'x', req: true });
addConform('first failure wins (a before n)', CD, 'a.b', { n: 10, a: 'z', req: true });
addConform('first failure wins (Z before a)', CD, 'a.b', { n: 5, a: 'z', req: true, Z: 1 });
addConform('optional present bad', CD, 'a.b', { n: 5, a: 'x', req: true, opt: 'no' });
addConform('utf8 last param bad', CD, 'a.b', { n: 5, a: 'x', req: true, 'é': 1 });
addConform('string too long', { verbs: [{ verb: 'v', kind: 'read', params: { 'action.params.s': { type: 'string', max_len: 2 } } }] }, 'v', { s: 'abc' });
addConform('array item long', { verbs: [{ verb: 'v', kind: 'read', params: { 'action.params.s': { type: 'array', max_len: 2 } } }] }, 'v', { s: ['abc'] });
addConform('first of duplicate verbs wins', { verbs: [{ verb: 'v', kind: 'read', params: {} }, { verb: 'v', kind: 'read', params: { 'action.params.p': { type: 'integer' } } }] }, 'v', {});
addConform('verbs not array', { verbs: { verb: 'v' } }, 'v', {});
addConform('doc string', 'x', 'v', {});
addConform('non-object verb entries skipped', { verbs: ['v', 1, { verb: 'v', kind: 'read', params: {} }] }, 'v', {});

// ---------------------------------------------------------------------------------------------------------------------
// verifyActionSchema(doc, keys)
const verify: any[] = [];
const addVerify = (name: string, doc: any, keys: any) => {
  const dr = raw(doc);
  const kr = raw(keys);
  const r: any = pca.verifyActionSchema(JSON.parse(dr), JSON.parse(kr));
  verify.push({ name: uniq('verify/' + name), doc: dr, keys: kr, expect: r.ok ? null : r.reason });
};
const SITE = seed('k042/schema-site');
const OTHER = seed('k042/schema-other');
const UNSIGNED: any = clone(BASE);
delete UNSIGNED.sig;
const signed = pca.signActionSchema(UNSIGNED, 'k1', SITE);
const key = pca.actionSchemaKeyOf('k1', SITE);
const otherKey = pca.actionSchemaKeyOf('k1', OTHER);
const k = (m: any) => { const x: any = { ...key }; for (const [a, b] of Object.entries(m)) { if (b === undefined) delete x[a]; else x[a] = b; } return [x]; };
addVerify('valid', signed, [key]);
addVerify('valid absent alg', signed, k({ alg: undefined }));
addVerify('keys not array', signed, key);
addVerify('keys null', signed, null);
addVerify('keys string', signed, 'k1');
addVerify('keys empty', signed, []);
addVerify('no key with kid', signed, k({ kid: 'k2' }));
addVerify('key kid number', signed, k({ kid: 1 }));
addVerify('non-object entries skipped', signed, ['junk', null, 1, ['k1'], { kid: 'k2', pk: otherKey.pk }, key]);
addVerify('entry without kid skipped', signed, [{ pk: otherKey.pk }, { kid: null, pk: otherKey.pk }, key]);
addVerify('first match wins (foreign first)', signed, [otherKey, key]);
addVerify('first match wins (right first)', signed, [key, otherKey]);
addVerify('pk missing', signed, k({ pk: undefined }));
addVerify('pk number', signed, k({ pk: 5 }));
addVerify('pk short', signed, k({ pk: key.pk.slice(0, 20) }));
addVerify('pk padded', signed, k({ pk: key.pk + '=' }));
addVerify('pq_pk null', signed, k({ pq_pk: null }));
addVerify('pq_pk number', signed, k({ pq_pk: 1 }));
addVerify('pq_pk string on ed25519', signed, k({ pq_pk: 'AAAA' }));
addVerify('pq_pk null and pk bad', signed, k({ pq_pk: null, pk: 5 }));
addVerify('key alg unknown', signed, k({ alg: 'rsa' }));
addVerify('key alg null', signed, k({ alg: null }));
addVerify('key alg number', signed, k({ alg: 3 }));
addVerify('key alg ml-dsa-65', signed, k({ alg: 'ml-dsa-65' }));
addVerify('key alg unknown and pk bad', signed, k({ alg: 'rsa', pk: 'x' }));
addVerify('foreign key', signed, [otherKey]);
addVerify('tampered body', { ...signed, version: '2' }, [key]);
addVerify('tampered sig', { ...signed, sig: { ...signed.sig, value: signed.sig.value.replace(/^./, (c: string) => (c === 'A' ? 'B' : 'A')) } }, [key]);
addVerify('sig alg absent (ed25519)', { ...signed, sig: { kid: 'k1', value: signed.sig.value } }, [key]);
addVerify('sig alg ml-dsa-65 vs ed25519 key', { ...signed, sig: { ...signed.sig, alg: 'ml-dsa-65' } }, [key]);
addVerify('ill-shaped', { ...signed, zz: 1 }, [key]);
addVerify('ill-shaped and keys bad', { ...signed, zz: 1 }, 'x');
addVerify('signature over the doc with sig is not the body', (() => {
  // a signature over the WHOLE document (including a placeholder sig) must not verify
  const whole: any = { ...UNSIGNED, sig: { alg: 'ed25519', kid: 'k1', value: 'AA' } };
  const msg = Buffer.concat([Buffer.from(pca.ACTION_SCHEMA_DOMAIN), Buffer.from(pca.canonicalizeStrict(whole))]);
  return { ...whole, sig: { alg: 'ed25519', kid: 'k1', value: pca.b64u(pca.sign(SITE, new Uint8Array(msg))) } };
})(), [key]);
// a pinned ML-DSA-65 key (the key entry pins pq_pk)
const ml = pca.mlDsa65Keygen(seed('k042/schema-mldsa'));
const mlSigned = pca.signActionSchema(UNSIGNED, 'kq', SITE, { alg: 'ml-dsa-65', mlDsa: ml } as any);
const mlKey: any = pca.actionSchemaKeyOf('kq', SITE, { alg: 'ml-dsa-65', mlDsa: ml } as any);
const hySigned = pca.signActionSchema(UNSIGNED, 'kh', SITE, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml } as any);
const hyKey: any = pca.actionSchemaKeyOf('kh', SITE, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml } as any);
const ml2 = pca.mlDsa65Keygen(seed('k042/schema-mldsa-2'));
const ml2Key: any = pca.actionSchemaKeyOf('kq', SITE, { alg: 'ml-dsa-65', mlDsa: ml2 } as any);
addVerify('ml-dsa-65 valid', mlSigned, [mlKey]);
addVerify('ml-dsa-65 no pq_pk', mlSigned, [{ ...mlKey, pq_pk: undefined }]);
addVerify('ml-dsa-65 wrong pq_pk', mlSigned, [ml2Key]);
addVerify('ml-dsa-65 key says ed25519', mlSigned, [{ ...mlKey, alg: 'ed25519' }]);
addVerify('hybrid valid', hySigned, [hyKey]);
addVerify('hybrid missing pq_value', { ...hySigned, sig: { alg: hySigned.sig.alg, kid: 'kh', value: hySigned.sig.value } }, [hyKey]);
addVerify('hybrid vs ml-dsa key', hySigned, [{ ...hyKey, alg: 'ml-dsa-65' }]);

// ---------------------------------------------------------------------------------------------------------------------
// accumulationParams(verb, unit) and canonProjection(doc, verb, params)
const acc: any[] = [];
const addAcc = (name: string, v: any, unit: string) => {
  const vr = raw(v);
  acc.push({ name: uniq('acc/' + name), v: vr, unit, expect: pca.accumulationParams(JSON.parse(vr), unit) });
};
addAcc('two, utf8 order', { params: { 'action.params.b': { type: 'integer', accumulates_into: ['u', 'w'] }, 'action.params.a': { type: 'integer', accumulates_into: ['u'] }, 'action.params.é': { type: 'integer', accumulates_into: ['u'] }, 'action.params.Z': { type: 'integer', accumulates_into: ['u'] } } }, 'u');
addAcc('without unit', { params: { 'action.params.a': { type: 'integer', accumulates_into: ['w'] } } }, 'u');
addAcc('non-integer skipped', { params: { 'action.params.a': { type: 'string', accumulates_into: ['u'] }, 'action.params.b': { type: 'array', accumulates_into: ['u'] } } }, 'u');
addAcc('absent accumulates_into', { params: { 'action.params.a': { type: 'integer' } } }, 'u');
addAcc('mixed', { params: { 'action.params.a': { type: 'integer' }, 'action.params.b': { type: 'integer', accumulates_into: ['u'] }, 'action.params.c': { type: 'string', accumulates_into: ['u'] } } }, 'u');
addAcc('no params', { params: {} }, 'u');

const canon: any[] = [];
const addCanon = (name: string, doc: any, verb: string, params: any) => {
  const dr = raw(doc);
  const pr = raw(params);
  let expect: any;
  try { expect = { ok: true, out: pca.canonProjection(JSON.parse(dr), verb, JSON.parse(pr)) }; } catch { expect = { ok: false }; }
  canon.push({ name: uniq('canon/' + name), doc: dr, verb, params: pr, expect });
};
const CP = { verbs: [{ verb: 'v', kind: 'write', params: {
  'action.params.b': { type: 'boolean' }, 'action.params.f': { type: 'boolean' }, 'action.params.s': { type: 'set', values: ['x', 'y', 'z', 'é', 'Z'] },
  'action.params.arr': { type: 'array' }, 'action.params.n': { type: 'integer' }, 'action.params.str': { type: 'string' }, 'action.params.absent': { type: 'boolean' } } }] };
addCanon('all kinds', CP, 'v', { b: true, f: false, s: ['z', 'é', 'x', 'Z'], arr: ['q', 'p'], n: 3, str: 'w' });
addCanon('boolean non-true is false', CP, 'v', { b: 'true', f: 1 });
addCanon('unknown verb', CP, 'nope', { b: true });
addCanon('only absent', CP, 'v', {});
addCanon('array of ints and objects', CP, 'v', { arr: [3, { b: 1, a: [2] }] });

const out = { shape, pvv, conform, verify, acc, canon };
writeFileSync(ROOT + 'sdks/java-pca/test-data/k042-actionschema.json', JSON.stringify(out) + '\n');
console.log(`wrote ${shape.length} shape, ${pvv.length} pvv, ${conform.length} conform, ${verify.length} verify, ${acc.length} acc, ${canon.length} canon cases`);
