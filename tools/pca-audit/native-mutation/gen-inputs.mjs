// Deterministic INPUT corpus for the native-verifier mutation campaign (Java/Kotlin/.NET/PHP/Ruby/Swift): structural
// field mutations of known-good PCActns (verify inputs) + prefix / deletion / substitution fuzz of JSON texts (parse
// inputs). Each native verifier pins its own observable output (verdict, diagnostic reason, rejection message,
// canonical form) over these inputs in a committed snapshot, so mutation testing also sees diagnostics, which the
// shared conformance corpus (allow + checks only) does not pin. Regenerate: node gen-inputs.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const CONF = join(here, '../../../packages/pca/conformance');
const core = JSON.parse(readFileSync(join(CONF, 'vectors.json'), 'utf8'));
const byName = new Map(core.vectors.map((v) => [v.name, v]));

const out = [];
// lone UTF-16 surrogates cannot cross the UTF-8 / JSON-lines transport into every language: such inputs are skipped
const hasLone = (t) => /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(t);
const add = (o) => { if (!hasLone(o.raw) && !(o.grant && hasLone(o.grant))) out.push(JSON.stringify(o)); };

// ---------------------------------------------------------------- parse fuzz
const D1 = byName.get('valid-raw-json-format-insensitive').pcactn_json;
const D2 = '{"a":[1,-2,0.5,-0.000001,123456789012345.5,1e5,true,false,null,"x\\u00e9\\ud83d\\ude00\\n\\t\\"\\\\\\/\\b\\f\\r"],"b":{"c":{}},"d":[],"e":"","f":-0, "g": [ 1 , 2 ] }\n';
let n = 0;
const parseId = () => `p${String(n++).padStart(5, '0')}`;
for (const [tag, d] of [['d1', D1], ['d2', D2]]) {
  for (let i = 0; i <= d.length; i++) add({ id: parseId(), kind: 'parse', raw: d.slice(0, i), note: `${tag}-prefix-${i}` });
}
const SUBS = ['"', '\\', '0', 'e', '-', ',', ':', '}', ']', ' ', 'u', 'x', '.', '\u0001'];
for (let i = 0; i < D2.length; i++) {
  add({ id: parseId(), kind: 'parse', raw: D2.slice(0, i) + D2.slice(i + 1), note: `d2-del-${i}` });
  for (const s of SUBS) if (D2[i] !== s) add({ id: parseId(), kind: 'parse', raw: D2.slice(0, i) + s + D2.slice(i + 1), note: `d2-sub-${i}` });
}
for (let i = 0; i < D1.length; i += 7) add({ id: parseId(), kind: 'parse', raw: D1.slice(0, i) + D1.slice(i + 1), note: `d1-del-${i}` });
// strings: escapes, truncated escapes, surrogates
for (const raw of ['"\\u', '"\\u0', '"\\u00', '"\\u000', '"\\u0000"', '"\\uD800"', '"\\uDC00"', '"\\uD83D\\uDE00"', '"\\uD83D\\u0041"', '"\\ud83d"', '"\\x"', '"\\', '"a', '"', '\\', '"\\u00G0"', '"\\u00g0"', '"\\u00F0"', '"\\u00f0"', '"\\u00:0"', '"\\u00/0"', '"\\u00@0"', '"\\u00`0"',
  '-', '-0', '-1', '--1', '+1', '01', '1.', '1.e1', '.5', '1e', '1e+', '1e-', '1E5', '1e5', '0.1', '0.10', '0.000001', '0.0000001', '-0.000001', '123456789012345.5', '-123456789012345.5', '1234567890123456.5', '12345678901234.5', '9007199254740991', '9007199254740992', '-9007199254740991', '-9007199254740992', '10000000000000000', '99999999999999999999', '1.0', '-0.0', '0.5e0',
  'tru', 'true', 'trux', 'fals', 'false', 'nul', 'null', 'nulll', 't', 'f', 'n', ' ', '', '\t\n\r ', '\u00a0 1', '1\u00a0', '[1,]', '[,1]', '[1 2]', '{"a":1,}', '{,}', '{"a" 1}', '{"a":}', '{1:2}', '{"a":1 "b":2}', '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '[', '{', '[[', '{"a"', '{"a":', '{"a":1', '[1', '[1,', '[1,2', ']', '}', '[]', '{}', '[ ]', '{ }', '"\u0001"', '"\t"', '"\u007f"'])
  add({ id: parseId(), kind: 'parse', raw, note: 'misc' });
const nest = (d, o, c, mid = '1') => o.repeat(d) + mid + c.repeat(d);
for (const d of [30, 31, 32, 33, 34]) {
  add({ id: parseId(), kind: 'parse', raw: nest(d, '[', ']'), note: `nest-arr-${d}` });
  add({ id: parseId(), kind: 'parse', raw: nest(d, '{"a":', '}'), note: `nest-obj-${d}` });
}
for (const len of [1048576, 1048577]) add({ id: parseId(), kind: 'parse', raw: '[' + ' '.repeat(len - 2) + ']', note: `size-${len}` });
add({ id: parseId(), kind: 'parse', raw: '"' + '\u20ac'.repeat(349524) + 'aa"', note: 'size-bytes-1048576' });
add({ id: parseId(), kind: 'parse', raw: '"' + '\u20ac'.repeat(349524) + 'aaa"', note: 'size-bytes-1048577' });

// ---------------------------------------------------------------- verify fuzz (structural mutations of good PCActns)
const BASES = ['valid-raw-json-format-insensitive', 'delegated-2-hop-chain', 'valid-with-optional-slots', 'valid-with-unsigned-threshold-container',
  'pq-leaf-hybrid-ed25519-ml-dsa-65-valid', 'pq-leaf-ml-dsa-65-valid', 'pq-nonleaf-hybrid-ed25519-ml-dsa-65-hop-valid', 'pqbind-chain3-hop2-hybrid-ed25519-ml-dsa-65-valid'];
const isPq = (bn) => bn.startsWith('pq');
const clone = (x) => JSON.parse(JSON.stringify(x));
function* paths(node, prefix = []) {
  yield prefix;
  if (node && typeof node === 'object') for (const k of Array.isArray(node) ? node.keys() : Object.keys(node)) yield* paths(node[k], [...prefix, k]);
}
const get = (root, p) => p.reduce((o, k) => o[k], root);
const A43 = 'A'.repeat(43), A86 = 'A'.repeat(86);
const ops = [
  ['del', (par, k) => { if (Array.isArray(par)) par.splice(k, 1); else delete par[k]; }],
  ['null', (par, k) => { par[k] = null; }],
  ['empty', (par, k) => { par[k] = ''; }],
  ['str', (par, k) => { par[k] = 'x'; }],
  ['b43', (par, k) => { par[k] = A43; }],
  ['b86', (par, k) => { par[k] = A86; }],
  ['one', (par, k) => { par[k] = 1; }],
  ['neg', (par, k) => { par[k] = -1; }],
  ['frac', (par, k) => { par[k] = 1.5; }],
  ['true', (par, k) => { par[k] = true; }],
  ['arr', (par, k) => { par[k] = []; }],
  ['obj', (par, k) => { par[k] = {}; }],
  ['zero', (par, k) => { par[k] = 0; }],
  ['big', (par, k) => { par[k] = 9007199254740991; }],
  ['one-dot-zero-sib', (par, k) => { if (!Array.isArray(par)) par.zz = 1; }],
];
for (const bn of BASES) {
  const v = byName.get(bn);
  if (!v) throw new Error('missing base ' + bn);
  const base = v.pcactn ?? JSON.parse(v.pcactn_json);
  const grant = JSON.stringify(v.grant);
  const ctx = v.context;
  let i = 0;
  for (const p of paths(base)) {
    if (p.length === 0) continue;
    if (isPq(bn) && p.length > 3) continue;
    const isBigStr = typeof get(base, p) === 'string' && get(base, p).length > 400; // skip mutating huge PQ blobs op-by-op: only del/null/empty/str
    for (const [on, f] of ops) {
      if (isPq(bn) && !['del', 'null', 'str', 'one', 'arr'].includes(on)) continue;
      if (isBigStr && !['del', 'null', 'empty', 'str', 'b43', 'one'].includes(on)) continue;
      const m = clone(base);
      const par = get(m, p.slice(0, -1));
      f(par, p[p.length - 1]);
      add({ id: `v-${bn}-${i++}`, kind: 'verify', raw: JSON.stringify(m), grant, now: ctx.now, aud: ctx.aud, allowed_suites: ctx.allowed_suites ?? null, note: `${bn} ${p.join('/')} ${on}` });
    }
  }
  // top-level extras
  for (const [k, val] of [['counter', 9007199254740991], ['counter', -1], ['ver', 3], ['iat', 1800000000000 + 60001], ['exp', 1], ['aud', 'x'.repeat(256)], ['aud', 'x'.repeat(257)], ['aud', '\u20ac'.repeat(86)], ['aud', '\u20ac'.repeat(85)], ['nonce', 'n'.repeat(128)], ['nonce', 'n'.repeat(129)], ['nonce', '\u20ac'.repeat(43)], ['nonce', '\u20ac'.repeat(42)], ['nonce', ''], ['caution', 0], ['caution', 1], ['caution', 1.5], ['caution', -0.5], ['caution', 0.000001], ['caution', 0.5], ['caution', 'x']]) {
    const m = clone(base); m[k] = val;
    add({ id: `v-${bn}-${i++}`, kind: 'verify', raw: JSON.stringify(m), grant, now: ctx.now, aud: ctx.aud, allowed_suites: ctx.allowed_suites ?? null, note: `${bn} top ${k}` });
  }
  // context variants
  for (const [now, aud] of [[ctx.now + 600_000, ctx.aud], [ctx.now + 600_001, ctx.aud], [ctx.now - 60_000, ctx.aud], [ctx.now - 60_001, ctx.aud], [ctx.now, 'other'], [ctx.now, '']])
    add({ id: `v-${bn}-${i++}`, kind: 'verify', raw: v.pcactn_json ?? JSON.stringify(base), grant, now, aud, allowed_suites: ctx.allowed_suites ?? null, note: `${bn} ctx ${now} ${aud}` });
  for (const allowed of [[], ['ed25519'], ['ml-dsa-65'], ['hybrid-ed25519-ml-dsa-65'], ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']])
    add({ id: `v-${bn}-${i++}`, kind: 'verify', raw: v.pcactn_json ?? JSON.stringify(base), grant, now: ctx.now, aud: ctx.aud, allowed_suites: allowed, note: `${bn} allowed ${allowed}` });
  // chain-level: grant mutations
  const g = JSON.parse(grant);
  for (const [k, f] of [['no-issuer', (x) => { delete x.issuer; }], ['issuer-num', (x) => { x.issuer = 5; }], ['id', (x) => { x.id = 'zz'; }], ['holder', (x) => { x.holder = 'zz'; }], ['empty', (x) => { for (const kk of Object.keys(x)) delete x[kk]; }]]) {
    const gg = clone(g); f(gg);
    add({ id: `v-${bn}-${i++}`, kind: 'verify', raw: v.pcactn_json ?? JSON.stringify(base), grant: JSON.stringify(gg), now: ctx.now, aud: ctx.aud, allowed_suites: ctx.allowed_suites ?? null, note: `${bn} grant ${k}` });
  }
}
const text = out.join('\n') + '\n';
writeFileSync(join(here, 'inputs.jsonl.gz'), gzipSync(Buffer.from(text), { level: 9 }));
console.log(`inputs: ${out.length} lines, ${text.length} bytes plain`);
