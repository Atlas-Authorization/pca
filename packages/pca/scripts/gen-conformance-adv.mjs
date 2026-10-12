// STAGE 3 of the conformance pipeline: generates >= 4000 ADVERSARIAL parser-differential vectors into
// conformance/vectors-adversarial.json.gz (FULL set) and splices a deterministic representative SAMPLE into the curated core
// conformance/vectors.json (idempotent: every vector this script owns is named `adv-*` and is dropped/re-added).
//
//   pnpm --filter @atlasauth/pca build \
//     && node packages/pca/scripts/gen-conformance.mjs \
//     && node packages/pca/scripts/gen-conformance-pq.mjs \
//     && node packages/pca/scripts/gen-conformance-adv.mjs
//
// Every vector is a RAW JSON text (`pcactn_json`) so each verifier runs it through its OWN strict parser, plus a
// handful of primitive vectors (json_parse / b64u / canonical). The expected verdict is produced by the TypeScript
// reference (decodePCActn + verifyPCActnCore), and where the verdict is unconditional the stated INTENT is asserted
// against the reference, so a reference bug cannot silently become a golden vector. Deterministic: fixed keys,
// RFC 8032 deterministic signatures, no clock, no randomness (mulberry32 with a fixed seed where a shuffle is needed).
//
// Families: equiv (format-only rewrites that MUST accept), dupkey, num (number-literal battery at every numeric
// slot), struct (null/missing/empty/array-vs-object at every path, validly re-signed), top (top-level / BOM /
// trailing garbage / truncation), ws (whitespace), uni (unicode / surrogates / normalisation / byte-vs-char bounds),
// b64 (base64url alphabet / padding / trailing bits / length at every byte field), alg (suite + alg confusion),
// key (key-type confusion: small-order, non-canonical, wrong-length keys), gref (grant_ref_bound variants),
// depth (nesting boundary), order (canonical key-order UTF-8 vs UTF-16).
import { createHash } from 'node:crypto';
import * as pca from '../dist/index.js';
import * as W from './ed25519-weak.mjs';
import { CORE_PATH, readCore, writeAdversarial, writeCore } from './conformance-io.mjs';

const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
const KEYMAP = { chain: 'cap_chain' };

const seed = (label) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${label}`).digest());
const mk = (label) => { const secretKey = seed(label); return { label, secretKey, publicKey: pca.publicKeyOf(secretKey) }; };
const principal = mk('principal'), agent = mk('agent'), sub = mk('subagent'), rogue = mk('rogue');
const clone = (x) => JSON.parse(JSON.stringify(x));
const te = new TextEncoder();
const mulberry32 = (a) => () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };

// ---------------------------------------------------------------- reseal helpers
function reseal(parent, toHolder, caveats, signerSecret, extra = {}) {
  const issuer = parent.holder;
  const body = { issuer, holder: toHolder, caveats, parent: pca.capHash(parent) };
  const body_digest = pca.hashCanonical(body);
  const msg = new Uint8Array([...te.encode('atlas-pca/cap/v1\0'), ...pca.unb64u(body_digest)]);
  return { id: body_digest, issuer, holder: toHolder, caveats, parent: body.parent, body_digest, sig: pca.b64u(pca.sign(signerSecret, msg)), ...extra };
}
const resign = (p, secret = agent.secretKey) => { const { sig: _s, pq_sig: _q, ...body } = p; return pca.signPCActn(body, secret); };

// ---------------------------------------------------------------- bases
const uniText = 'caf\u00e9 \u{1F600} \u2028 \uff5e <&> "q" \\ \n \u0001 \u007f';
const planNodes = [
  { id: 'n1', verb: 'read', resource: 'db/users' },
  { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: pca.paramsDigest({ qty: 3 }), reversibility_class: 'reversible' },
  { id: 'n3', verb: 'send', resource: 'mail/out' },
];
const mkRoot = (caveats) => pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: pca.b64u(principal.publicKey), holder: pca.b64u(agent.publicKey), caveats });
const rootPlain = mkRoot([{ type: 'max_spend', usd: 100 }, { type: 'resource_prefix', prefix: 'db/' }]);
const rootUni = mkRoot([{ type: 'max_spend', usd: 100 }, { type: 'note', text: uniText, '\uff5e': 1, '\u{1F600}': 2, z: 3, ratio: 0.25 }]);
const build = (grant, chain, o = {}) => pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant, chain, plan: planNodes, nodeId: 'n2', params: { qty: 3 }, counter: 7, signerSecret: agent.secretKey, ...o });
const hop1 = reseal(rootPlain, pca.b64u(sub.publicKey), [{ type: 'max_spend', usd: 100 }, { type: 'resource_prefix', prefix: 'db/' }, { type: 'verb_allow', verbs: ['write'] }], agent.secretKey);
const B1 = build(rootPlain, [rootPlain]);
const B2 = build(rootPlain, [rootPlain, hop1], { signerSecret: sub.secretKey, nodeId: 'n1', params: undefined, nonce: 'n-0001', caution: 0.5, rationaleCommitment: pca.b64u(new Uint8Array(32).fill(3)), toolBinding: pca.b64u(new Uint8Array(32).fill(4)), progressStep: { n: 1 }, prohibitionEvidence: [] });
const B3 = build(rootUni, [rootUni]);
const bases = { b1: [B1, rootPlain, 'plain 1-hop'], b2: [B2, rootPlain, '2-hop with optional signed slots'], b3: [B3, rootUni, '1-hop with unicode caveats'] };

// ---------------------------------------------------------------- serializer with raw-literal + style control
let LITS = [];
const L = (s) => { LITS.push(s); return `@@L${LITS.length - 1}@@`; };
const unL = (t) => t.replace(/"@@L(\d+)@@"/g, (_m, i) => LITS[Number(i)]);
const hex4 = (c, up) => { const h = c.toString(16).padStart(4, '0'); return up ? h.toUpperCase() : h; };
function qstr(s, style = {}) {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') o += style.escQuote ?? '\\"';
    else if (ch === '\\') o += '\\\\';
    else if (c < 0x20) o += style.escCtl === 'short' ? ({ 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r' }[c] ?? '\\u' + hex4(c, style.up)) : '\\u' + hex4(c, style.up);
    else if (style.slash && ch === '/') o += '\\/';
    else if (style.allU || (style.nonAscii && c > 0x7f) || (style.ascii && c < 0x80 && /[A-Za-z0-9]/.test(ch) && style.ascii(c))) {
      if (c > 0xffff) { const v = c - 0x10000; o += '\\u' + hex4(0xd800 + (v >> 10), style.up) + '\\u' + hex4(0xdc00 + (v & 0x3ff), style.up); } else o += '\\u' + hex4(c, style.up);
    } else o += ch;
  }
  return o + '"';
}
/** @param {*} v @param {{indent?:string, nl?:string, sep?:string, colon?:string, order?:(keys:string[],path:string)=>string[], ws?:string, ...}} st */
function ser(v, st = {}, path = '') {
  const nl = st.indent !== undefined ? '\n' : '';
  const ind = (d) => (st.indent !== undefined ? st.indent.repeat(d) : '');
  const depth = path === '' ? 0 : path.split('/').length - 1;
  const colon = st.colon ?? (st.indent !== undefined ? ': ' : ':');
  const comma = st.comma ?? ',';
  if (v === null) return 'null';
  if (typeof v === 'string') return v.startsWith('@@L') && /^@@L\d+@@$/.test(v) ? v : qstr(v, st);
  if (typeof v === 'number') return pca.canonicalize(v);
  if (typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) {
    if (!v.length) return '[]';
    return '[' + nl + v.map((x, i) => ind(depth + 1) + ser(x, st, path + '/' + i)).join(comma + nl) + nl + ind(depth) + ']';
  }
  let keys = Object.keys(v);
  if (st.order) keys = st.order(keys, path);
  if (!keys.length) return '{}';
  return '{' + nl + keys.map((k) => ind(depth + 1) + qstr(k, st) + colon + ser(v[k], st, path + '/' + k)).join(comma + nl) + nl + ind(depth) + '}';
}
const T = (v, st) => unL(ser(v, st));
const compact = (v) => T(v, {});

// ---------------------------------------------------------------- vector registry
const out = [];
const fam = {};
const names = new Set(); // (names registered in the resolve pass)
// the async reference: collect jobs and resolve in order
const jobs = [];
const emitA = (...a) => jobs.push(a);

// ================================================================= family: equiv (format-only rewrites => accept)
{
  const shuffle = (seedN) => (keys) => { const r = mulberry32(seedN); const k = [...keys]; for (let i = k.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [k[i], k[j]] = [k[j], k[i]]; } return k; };
  const styles = {
    compact: {}, indent1: { indent: ' ' }, indent2: { indent: '  ' }, indent4: { indent: '    ' }, tab: { indent: '\t' },
    reversed: { order: (k) => [...k].reverse() }, shuffleA: { order: shuffle(11) }, shuffleB: { order: shuffle(23) }, shuffleC: { order: shuffle(37) },
    sortedCodeUnit: { order: (k) => [...k].sort() },
    allU: { allU: true }, allUUpper: { allU: true, up: true }, nonAsciiU: { nonAscii: true }, nonAsciiUUpper: { nonAscii: true, up: true },
    slash: { slash: true }, shortCtl: { escCtl: 'short' }, sloppy: { colon: ' : ', comma: ' ,', indent: ' ' },
    asciiLetterU: { ascii: (c) => c % 2 === 0 }, asciiAllU: { ascii: () => true }, asciiAllUUpper: { ascii: () => true, up: true },
    crlf: { indent: '\r\n' }, mixedWs: { indent: ' \t', colon: ' \t:\r\n ', comma: '\t,\n' },
  };
  for (const [bn, [pc, g]] of Object.entries(bases)) {
    for (const [sn, st] of Object.entries(styles)) emitA('equiv', `${bn}-${sn}`, `Same signed value as the golden ${bn} PCActn, serialised differently (${sn}): format-only, MUST accept.`, T(pc, st), g, { want: 'accept' });
  }
  // allowed whitespace at the document edges
  for (const w of [' ', '\t', '\n', '\r', ' \r\n\t ']) {
    const t = compact(B1);
    emitA('equiv', `lead-${JSON.stringify(w).slice(1, -1).replace(/\W/g, '')}`, `Allowed whitespace (${JSON.stringify(w)}) before the document: accept.`, w + t, rootPlain, { want: 'accept' });
    emitA('equiv', `trail-${JSON.stringify(w).slice(1, -1).replace(/\W/g, '')}`, `Allowed whitespace (${JSON.stringify(w)}) after the document: accept.`, t + w, rootPlain, { want: 'accept' });
  }
}

// ================================================================= family: ws (forbidden whitespace / invisible characters between tokens)
{
  const BAD = { vt: '\u000b', ff: '\u000c', nbsp: '\u00a0', nel: '\u0085', ls: '\u2028', ps: '\u2029', zwsp: '\u200b', bomc: '\ufeff', ideo: '\u3000', ogham: '\u1680', emsp: '\u2003', nul: '\u0000', del: '\u007f', us: '\u001f' };
  const t = compact(B1);
  const spots = { start: (w) => w + t, end: (w) => t + w, afterColon: (w) => t.replace('"ver":', '"ver":' + w), beforeColon: (w) => t.replace('"ver":', '"ver"' + w + ':'), afterComma: (w) => t.replace(',"action"', ',' + w + '"action"'), afterOpenBrace: (w) => '{' + w + t.slice(1), inArray: (w) => t.replace('"path":[', '"path":[' + w), beforeLastBrace: (w) => t.slice(0, -1) + w + '}' };
  for (const [wn, w] of Object.entries(BAD)) for (const [sn, f] of Object.entries(spots)) emitA('ws', `${wn}-${sn}`, `Forbidden whitespace/invisible U+${w.codePointAt(0).toString(16).padStart(4, '0')} at ${sn}: outside the strict JSON profile, wire failure.`, f(w), rootPlain, { want: 'wire' });
}

// ================================================================= family: top (top-level shapes, BOM, garbage, truncation)
{
  const t = compact(B1);
  const tops = {
    empty: '', 'only-ws': ' \n', null: 'null', true: 'true', false: 'false', zero: '0', string: '"x"', array: '[]', 'array-of-obj': '[' + t + ']', 'empty-obj': '{}', 'obj-in-string': JSON.stringify(t),
    'bom': '\ufeff' + t, 'bom-bom': '\ufeff\ufeff' + t, 'bom-only': '\ufeff', 'utf16-bom-fe': '\ufffe' + t, 'replacement-prefix': '\ufffd' + t,
    'double-obj': t + t, 'double-obj-ws': t + '\n' + t, 'obj-comma-obj': t + ',' + t, 'garbage-x': t + 'x', 'garbage-brace': t + '}', 'garbage-comma': t + ',', 'garbage-nul': t + '\u0000', 'garbage-nul-mid': t.slice(0, 20) + '\u0000' + t.slice(20),
    'garbage-slash': t + '//c', 'garbage-block': t + '/*c*/', 'lead-block': '/*c*/' + t, 'lead-line': '//c\n' + t, 'garbage-semicolon': t + ';', 'garbage-lf-x': t + '\nx', 'garbage-zero': t + '0', 'garbage-null': t + 'null', 'garbage-bracket': t + ']',
    'lead-garbage': 'x' + t, 'lead-comma': ',' + t, 'lead-bracket': '[' + t, 'trailing-comma-obj': t.slice(0, -1) + ',}', 'trailing-comma-arr': t.replace('"trusted_refs":[]', '"trusted_refs":[,]'), 'leading-comma-arr': t.replace('"path":[', '"path":[,'),
    'single-quote': t.replace(/"/g, "'"), 'unquoted-keys': t.replace(/"([a-z_]+)":/g, '$1:'), 'hex-literal': t.replace('"ver":2', '"ver":0x2'), 'plus-literal': t.replace('"ver":2', '"ver":+2'), 'octal-literal': t.replace('"ver":2', '"ver":02'),
    'tabs-in-string': t.replace('rs-conformance', 'rs-\tconformance'), 'lf-in-string': t.replace('rs-conformance', 'rs-\nconformance'), 'nul-in-string': t.replace('rs-conformance', 'rs-\u0000conformance'), 'del-in-string': t.replace('rs-conformance', 'rs-\u007fconformance'),
    'unterminated-string': t.slice(0, t.indexOf('rs-conformance') + 5), 'unterminated-obj': t.slice(0, -1), 'extra-close': t + '}', 'missing-colon': t.replace('"ver":2', '"ver"2'), 'double-colon': t.replace('"ver":2', '"ver"::2'), 'missing-comma': t.replace('"ver":2,', '"ver":2'), 'double-comma': t.replace('"ver":2,', '"ver":2,,'),
    'key-not-string': t.replace('"ver":2', '2:2'), 'bare-word': t.replace('"ver":2', '"ver":two'), 'true-as-ver': t.replace('"ver":2', '"ver":true'), 'null-as-ver': t.replace('"ver":2', '"ver":null'), 'str-ver': t.replace('"ver":2', '"ver":"2"'), 'arr-ver': t.replace('"ver":2', '"ver":[2]'), 'obj-ver': t.replace('"ver":2', '"ver":{"v":2}'),
    'bad-escape-x': t.replace('rs-conformance', 'rs-\\xconformance'), 'bad-escape-v': t.replace('rs-conformance', 'rs-\\vconformance'), 'bad-escape-0': t.replace('rs-conformance', 'rs-\\0conformance'), 'bad-escape-apos': t.replace('rs-conformance', "rs-\\'conformance"), 'short-u': t.replace('rs-conformance', 'rs-\\u12conformance'), 'bad-hex-u': t.replace('rs-conformance', 'rs-\\u12G4conformance'), 'u-plus': t.replace('rs-conformance', 'rs-\\u+123conformance'), 'u-space': t.replace('rs-conformance', 'rs-\\u 123conformance'), 'backslash-eof': t.slice(0, -1) + '\\',
    'NaN-ver': t.replace('"ver":2', '"ver":NaN'), 'Infinity-ver': t.replace('"ver":2', '"ver":Infinity'), 'neginf-ver': t.replace('"ver":2', '"ver":-Infinity'), 'undefined-ver': t.replace('"ver":2', '"ver":undefined'), 'True-ver': t.replace('"ver":2', '"ver":True'), 'NULL-ver': t.replace('"ver":2', '"ver":NULL'),
  };
  delete tops['del-in-string']; // raw DEL is a legal string character
  for (const [n, x] of Object.entries(tops)) emitA('top', n, `Top-level / token-level malformed or non-profile input (${n}).`, x, rootPlain, { want: 'wire' });
  // truncation at each of 48 evenly-spaced cut points (every prefix is invalid JSON or a missing field)
  for (let k = 1; k <= 48; k++) emitA('top', `trunc-${String(k).padStart(2, '0')}`, `The golden PCActn cut at ${Math.floor((t.length * k) / 49)} of ${t.length} characters.`, t.slice(0, Math.floor((t.length * k) / 49)), rootPlain, { want: 'wire' });
}

// ================================================================= family: dupkey (duplicate keys at every object)
{
  const base = B2;
  const objPaths = [];
  const walk = (v, p) => { if (v && typeof v === 'object') { if (!Array.isArray(v)) objPaths.push(p); for (const [k, c] of Object.entries(v)) walk(c, [...p, k]); } };
  walk(base, []);
  const get = (o, p) => p.reduce((a, k) => a[k], o);
  for (const p of objPaths) {
    const o = get(base, p);
    const k0 = Object.keys(o)[0];
    if (k0 === undefined) continue;
    const label = p.join('.') || 'root';
    const rawOf = (v) => compact(v);
    const sameVal = rawOf(o[k0]);
    const diffVal = o[k0] === 'x' ? '"y"' : '"x"';
    // build text by re-serialising with the duplicate injected: do it textually on a sentinel
    const withDup = (injector) => {
      const clone2 = clone(base);
      const tgt = get(clone2, p);
      tgt['@@DUP@@'] = 0;
      let txt = T(clone2);
      return txt.replace(/"@@DUP@@":0/, injector);
    };
    const kk = JSON.stringify(k0);
    emitA('dupkey', `${label}-same`, `Duplicate key ${kk} with the SAME value in object ${label}: rejected (no last-wins / first-wins).`, withDup(`${kk}:${sameVal}`), rootPlain, { want: 'wire' });
    emitA('dupkey', `${label}-diff`, `Duplicate key ${kk} with a DIFFERENT value in object ${label}: rejected.`, withDup(`${kk}:${diffVal}`), rootPlain, { want: 'wire' });
    const esc = '"' + [...k0].map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') + '"';
    emitA('dupkey', `${label}-escaped`, `Duplicate key ${kk} spelled with \\u escapes (equal after unescaping) in ${label}: rejected.`, withDup(`${esc}:${diffVal}`), rootPlain, { want: 'wire' });
    emitA('dupkey', `${label}-escaped-upper`, `Duplicate key via UPPER-case hex \\u escapes in ${label}: rejected.`, withDup(`${esc.toUpperCase().replace(/\\U/g, '\\u')}:${sameVal}`), rootPlain, { want: 'wire' });
  }
  // special key names
  for (const k of ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty', '', ' ', 'sig ', 'Sig', 'SIG', 'ver\u0000', 'v\u0435r', '\u0073ig', 'sig\u200b']) {
    const o = clone(B1); Object.defineProperty(o, k, { value: 1, enumerable: true, configurable: true, writable: true });
    emitA('dupkey', `unknown-key-${[...k].map((c) => c.codePointAt(0).toString(16)).join('_') || 'empty'}`, `Unknown top-level key ${JSON.stringify(k)}: the top-level field set is closed (wire failure), and is never merged/ignored/looked up on a prototype.`, T(o), rootPlain, { want: 'wire' });
    const o2 = clone(B1); Object.defineProperty(o2.action, k, { value: 1, enumerable: true, configurable: true, writable: true });
    emitA('dupkey', `unknown-action-key-${[...k].map((c) => c.codePointAt(0).toString(16)).join('_') || 'empty'}`, `Unknown action key ${JSON.stringify(k)}: closed field set (wire failure).`, T(o2), rootPlain, { want: 'wire' });
  }
  // proto-pollution shaped payloads inside the free-form signed caveats / unsigned threshold container
  for (const [n, frag] of Object.entries({ proto: '{"__proto__":{"x":1}}', ctor: '{"constructor":{"prototype":{"x":1}}}', 'proto-str': '{"__proto__":"x"}', 'proto-arr': '{"__proto__":[]}' })) {
    emitA('dupkey', `threshold-${n}`, `Unsigned threshold container carrying a ${n} shaped payload: wire failure (shares required), never prototype pollution.`, T({ ...clone(B1), threshold: L(frag) }), rootPlain, { want: 'wire' });
    emitA('dupkey', `risk-inputs-${n}`, `risk_claim.inputs holding a ${n} payload: it is just an ordinary key.`, T({ ...clone(B1), risk_claim: { r: 0, inputs: L(frag) } }), rootPlain);
  }
}

// ================================================================= family: num (number literal battery at every numeric slot)
{
  const slots = {
    ver: (o, v) => { o.ver = v; }, counter: (o, v) => { o.counter = v; }, iat: (o, v) => { o.iat = v; }, exp: (o, v) => { o.exp = v; },
    'attestation.epoch': (o, v) => { o.attestation.epoch = v; }, 'freshness.epoch': (o, v) => { o.freshness.epoch = v; },
    'proof.index': (o, v) => { o.plan.inclusion_proof.index = v; }, 'proof.size': (o, v) => { o.plan.inclusion_proof.size = v; },
    'risk.r': (o, v) => { o.risk_claim.r = v; }, 'prov.taint': (o, v) => { o.provenance.taint_level = v; }, caution: (o, v) => { o.caution = v; },
    'caveat.usd': (o, v) => { o.threshold = { shares: [], x: v }; }, 'risk.inputs.n': (o, v) => { o.risk_claim.inputs = { n: v }; },
  };
  const intSlots = new Set(['ver', 'counter', 'iat', 'exp', 'attestation.epoch', 'freshness.epoch', 'proof.index', 'proof.size']);
  const lits = ['1.0', '1e0', '1E0', '1e+0', '-0', '-0.0', '0.0', '00', '01', '+1', '0x1', '1.', '.5', '0.50', '1e2', '1.5e1', '9007199254740991', '9007199254740992', '9007199254740993', '18446744073709551616', '9223372036854775808', '-9007199254740993', '1e400', '-1e400', '1e-400', '4.9e-324', '1.7976931348623157e308', '123456789012345678', '0.1234567890123456', '0.000001', '0.0000009', '1e-7', '-1', '2147483648', '4294967296', '3.14', '٣', '１', '1_0', '1,0', 'NaN', 'Infinity', '-Infinity', '0b1', '1e', '1e+', '--1', '1.2.3', '0.5e0', '100000000000000000000', '1000000000000000', '1234567890123456', '0.123456789012345', '12345678901234.5', '-0.5', '5e-1'];
  for (const [sn, set] of Object.entries(slots)) {
    for (const [li, lit] of lits.entries()) {
      const o = clone(B1); set(o, L(lit));
      const wire = intSlots.has(sn) && !/^(-1|2147483648|4294967296)$/.test(lit) ? undefined : undefined;
      emitA('num', `${sn.replace(/\./g, '-')}-${String(li).padStart(2, '0')}`, `Number literal ${lit} at ${sn} (re-signing impossible for non-canonical literals; the strict number profile decides).`, T(o), rootPlain, { want: undefined, _wire: wire });
    }
  }
}

// ================================================================= family: struct (type/shape confusion at every path, validly re-signed)
{
  const base = B2;
  const paths = [];
  const walk = (v, p) => { if (v && typeof v === 'object') for (const [k, c] of Object.entries(v)) { paths.push([...p, k]); walk(c, [...p, k]); } };
  walk(base, []);
  const get = (o, p) => p.reduce((a, k) => a[k], o);
  const setAt = (o, p, f) => { const par = get(o, p.slice(0, -1)); const k = p.at(-1); f(par, k); };
  const ops = {
    del: (par, k) => { if (Array.isArray(par)) par.splice(Number(k), 1); else delete par[k]; },
    nul: (par, k) => { par[k] = null; }, emptyObj: (par, k) => { par[k] = {}; }, emptyArr: (par, k) => { par[k] = []; }, emptyStr: (par, k) => { par[k] = ''; },
    zero: (par, k) => { par[k] = 0; }, str: (par, k) => { par[k] = 'x'; }, wrapArr: (par, k) => { par[k] = [par[k]]; }, wrapObj: (par, k) => { par[k] = { v: par[k] }; }, bool: (par, k) => { par[k] = true; },
    dupElem: (par, k) => { if (Array.isArray(par)) par.splice(Number(k), 0, clone(par[k])); else par[k + '2'] = clone(par[k]); },
    asString: (par, k) => { par[k] = typeof par[k] === 'string' ? par[k] : JSON.stringify(par[k]); },
  };
  for (const p of paths) for (const [on, op] of Object.entries(ops)) {
    const o = clone(base);
    setAt(o, p, op);
    let sig;
    try { sig = resign(o, sub.secretKey); } catch { sig = o; }
    emitA('struct', `${p.join('.')}~${on}`, `Re-signed (hence signature-valid when the wire admits it) PCActn with path ${p.join('.')} mutated by ${on}: null/missing/empty/array-vs-object/type confusion.`, T(sig), rootPlain);
  }
}

// ================================================================= family: uni (unicode, surrogates, normalisation, byte-vs-char bounds)
{
  const withAud = (aud) => resign({ ...clone(B1), aud });
  const nfc = 'caf\u00e9', nfd = 'cafe\u0301';
  const audCases = { nfc, nfd, 'nfc-vs-nfd-verifier': nfd, cyrillic: 'rs-conf\u043erm', fullwidth: 'rs\uff0dconformance', zwj: 'rs-conformance\u200d', 'bom-char': '\ufeffrs-conformance', rtl: 'rs-conformance\u202e', astral: 'rs-\u{1F600}', 'astral-esc': 'rs-\u{1F600}', 'trail-sp': 'rs-conformance ', 'upper': 'RS-CONFORMANCE', nul: 'rs\u0000x', del: 'rs\u007fx', 'a-ring-1': '\u00c5', 'a-ring-2': 'A\u030a', 'a-ring-angstrom': '\u212b', 'fi-lig': '\ufb01', 'fi-split': 'fi', 'ohm': '\u2126', 'omega': '\u03a9', 'kelvin': '\u212a', 'K': 'K', 'tr-i': '\u0131', 'dotted-i': '\u0130', 'i-dot': 'i\u0307', 'hangul-lv': '\ud55c', 'hangul-jamo': '\u1112\u1161\u11ab', 'noncharacter-fffe': '\ufffe', 'noncharacter-ffff': '\uffff', 'noncharacter-1fffe': '\u{1fffe}', 'max-cp': '\u{10ffff}', 'ls': '\u2028', 'ps': '\u2029' };
  for (const [n, aud] of Object.entries(audCases)) {
    emitA('uni', `aud-self-${n}`, `aud = ${JSON.stringify(aud)} and the verifier expects the SAME string (byte-exact): audience binding never normalises.`, T(withAud(aud)), rootPlain, { aud });
    emitA('uni', `aud-other-${n}`, `aud = ${JSON.stringify(aud)} but the verifier expects 'rs-conformance': audience fails (no normalisation / case folding).`, T(withAud(aud)), rootPlain, { want: aud === AUD ? undefined : 'reject' });
  }
  emitA('uni', 'aud-nfd-pc-nfc-verifier', 'PCActn aud is NFD, verifier expects the NFC spelling of the same text: audience fails (byte comparison).', T(withAud(nfd)), rootPlain, { aud: nfc, want: 'reject' });
  emitA('uni', 'aud-nfc-pc-nfd-verifier', 'PCActn aud is NFC, verifier expects the NFD spelling: audience fails.', T(withAud(nfc)), rootPlain, { aud: nfd, want: 'reject' });
  // byte-length bounds for aud (256 bytes) and nonce (128 bytes) with every UTF-8 width
  const mkLen = (unit, bytes, over) => unit.repeat(Math.floor(bytes / new TextEncoder().encode(unit).length) + (over ? 1 : 0));
  for (const [un, unit] of Object.entries({ a1: 'a', b2: '\u00e9', c3: '\u20ac', d4: '\u{1F600}', e1u: 'Z' })) {
    for (const over of [false, true]) {
      const au = mkLen(unit, 256, over);
      emitA('uni', `aud-bytes-${un}-${over ? 'over' : 'at'}`, `aud of ${new TextEncoder().encode(au).length} UTF-8 bytes / ${[...au].length} code points / ${au.length} UTF-16 units (limit 256 BYTES), verifier expects the same string.`, T(withAud(au)), rootPlain, { aud: au });
      const nn = mkLen(unit, 128, over);
      emitA('uni', `nonce-bytes-${un}-${over ? 'over' : 'at'}`, `nonce of ${new TextEncoder().encode(nn).length} UTF-8 bytes / ${[...nn].length} code points (limit 128 BYTES).`, T(resign({ ...clone(B1), nonce: nn })), rootPlain);
    }
  }
  for (const [n, nonce] of Object.entries({ empty: '', space: ' ', nul: '\u0000', nfd: nfd, esc: 'a"b\\c', longascii: 'x'.repeat(128), over: 'x'.repeat(129), astral: '\u{1F600}'.repeat(32), 'astral-over': '\u{1F600}'.repeat(33) })) emitA('uni', `nonce-${n}`, `nonce ${n}.`, T(resign({ ...clone(B1), nonce })), rootPlain);
  // surrogate / escape handling in an unsigned-free string slot (action.verb is signed and in the plan: use risk_claim.inputs)
  const surr = {
    'lone-high': '\\ud800', 'lone-low': '\\udc00', 'reversed-pair': '\\udc00\\ud800', 'high-high': '\\ud800\\ud800', 'high-then-u0041': '\\ud800\\u0041', 'high-then-char': '\\ud800a', 'low-then-high-pair': '\\udc00\\ud83d\\ude00', 'valid-pair': '\\ud83d\\ude00', 'valid-pair-upper': '\\uD83D\\uDE00', 'pair-split-by-text': '\\ud83dx\\ude00', 'max-pair': '\\udbff\\udfff', 'lone-high-end': 'a\\udbff', 'lone-low-end': 'a\\udfff', 'nul-esc': '\\u0000', 'ff-esc': '\\u00ff', 'fffe': '\\ufffe', 'ffff': '\\uffff', 'del-esc': '\\u007f', 'slash-esc': '\\/', 'ctl-esc-1f': '\\u001f', 'overlong-esc-not-a-thing': '\\u00c0\\u0080',
  };
  for (const [n, e] of Object.entries(surr)) emitA('uni', `esc-${n}`, `risk_claim.inputs.s = "${e}" (a raw JSON escape sequence): lone surrogates are rejected, valid pairs / BMP escapes decode.`, T({ ...clone(B1), risk_claim: { r: 0, inputs: { s: L(`"${e}"`) } } }), rootPlain, { want: /^\\ud[89ab]|^\\udc|^\\udb|^\\ud83dx|^a\\ud|^\\ud800|^\\udc00|^\\udbff\\udfff$/i.test(e) && !/^\\u[dD]8[0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}$/.test(e) && !/^\\ud83d\\ude00$|^\\udbff\\udfff$/i.test(e) && n !== 'low-then-high-pair' ? undefined : undefined });
  // raw control characters inside strings
  for (let c = 0; c < 0x20; c++) emitA('uni', `rawctl-${c.toString(16).padStart(2, '0')}`, `Raw control character U+${c.toString(16).padStart(4, '0')} inside a JSON string: wire failure.`, compact(B1).replace('rs-conformance', 'rs-conformance' + String.fromCharCode(c)), rootPlain, { want: 'wire' });
  // unicode in resource / verb / node id of the plan (all signed): equal, normalisation-sensitive
  for (const [n, s] of Object.entries({ nfc, nfd, emoji: '\u{1F600}', cjk: '\u4e2d\u6587', ls: 'a\u2028b', zwsp: 'a\u200bb', del: 'a\u007fb', quote: 'a"b', bslash: 'a\\b', slash: 'a/b', ctl: 'a\u0001b' })) {
    const nodes = [{ id: 'n1', verb: 'read', resource: 'db/' + s }, { id: 'n2', verb: 'write', resource: 'db/orders' }];
    const o = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: rootPlain, chain: [rootPlain], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: agent.secretKey });
    emitA('uni', `resource-${n}`, `Plan resource contains ${n}: Merkle leaf hashing is over canonical UTF-8 bytes; accept in every language.`, T(o), rootPlain, { plan: nodes, want: 'accept' });
  }
  // canonical key-order: UTF-8 byte order (== code point order), NOT UTF-16 code-unit order
  const orderKeys = [['\uff5e', '\u{1F600}'], ['\ue000', '\u{10000}'], ['\u{10000}', '\uffff'], ['\u0080', '\u007f'], ['\u00ff', '\u0100'], ['\ud7ff', '\ue000'], ['\u{1F600}', '\u{1F601}'], ['a', 'A'], ['a', 'aa'], ['', 'a'], ['\u0000', 'a'], ['é', 'e\u0301'], ['\u{10ffff}', '\uffff'], ['\ufffd', '\u{10000}'], ['b', '\u00e9']];
  for (const [i, [k1, k2]] of orderKeys.entries()) {
    for (const rev of [false, true]) {
      const cav = { type: 'note', [rev ? k2 : k1]: 1, [rev ? k1 : k2]: 2 };
      const g = mkRoot([cav]);
      const pc = build(g, [g]);
      emitA('uni', `keyorder-${i}${rev ? 'r' : ''}`, `Capability caveat whose keys ${JSON.stringify(k1)} and ${JSON.stringify(k2)} sort differently under UTF-16 code-unit vs UTF-8 byte order (insertion order ${rev ? 'reversed' : 'natural'}): the hop digest / id depend on bytewise code point order.`, T(pc), g, { want: 'accept' });
    }
  }
}

// ================================================================= family: b64 (base64url at every byte field)
{
  const fields = {
    sig: [(o) => o.sig, (o, v) => { o.sig = v; }, 64], grant_ref: [(o) => o.grant_ref, (o, v) => { o.grant_ref = v; }, 32], 'action.params_digest': [(o) => o.action.params_digest, (o, v) => { o.action.params_digest = v; }, 32],
    'plan.root': [(o) => o.plan.root, (o, v) => { o.plan.root = v; }, 32], 'plan.conditions_digest': [(o) => o.plan.conditions_digest, (o, v) => { o.plan.conditions_digest = v; }, 32], 'proof.hash': [(o) => o.plan.inclusion_proof.path[0].hash, (o, v) => { o.plan.inclusion_proof.path[0].hash = v; }, 32],
    'hop.id': [(o) => o.cap_chain[0].id, (o, v) => { o.cap_chain[0].id = v; }, 32], 'hop.issuer': [(o) => o.cap_chain[0].issuer, (o, v) => { o.cap_chain[0].issuer = v; }, 32], 'hop.holder': [(o) => o.cap_chain[0].holder, (o, v) => { o.cap_chain[0].holder = v; }, 32],
    'hop.body_digest': [(o) => o.cap_chain[0].body_digest, (o, v) => { o.cap_chain[0].body_digest = v; }, 32], 'hop.sig': [(o) => o.cap_chain[0].sig, (o, v) => { o.cap_chain[0].sig = v; }, 64], 'hop2.parent': [(o) => o.cap_chain[1].parent, (o, v) => { o.cap_chain[1].parent = v; }, 32],
    rationale_commitment: [(o) => o.rationale_commitment, (o, v) => { o.rationale_commitment = v; }, 32], tool_binding: [(o) => o.tool_binding, (o, v) => { o.tool_binding = v; }, 32],
  };
  const flipLast = (s) => s.slice(0, -1) + (s.at(-1) === 'A' ? 'B' : 'A');
  const stdAlpha = (s) => { const i = [...s].findIndex((c) => c === '-' || c === '_'); return i < 0 ? null : s.replace(/-/g, '+').replace(/_/g, '/'); };
  for (const [fn, [getf, setf, len]] of Object.entries(fields)) {
    const o0 = clone(B2);
    const cur = getf(o0);
    const full = Math.ceil((len * 4) / 3);
    const variants = {
      pad1: cur + '=', pad2: cur + '==', pad4: cur + '====', sp: cur + ' ', splead: ' ' + cur, tab: '\t' + cur, nl: cur + '\n', empty: '', short1: cur.slice(0, -1), short4: cur.slice(0, -4), long1: cur + 'A', long4: cur + 'AAAA', upperlast: flipLast(cur), allA: 'A'.repeat(full), allAplusEq: 'A'.repeat(full - 1) + '=', std: stdAlpha(cur), std2: cur.replace(/[-_]/, '+') === cur ? cur + '+' : cur.replace(/[-_]/, '+'), slash: cur.slice(0, -1) + '/', plus: cur.slice(0, -1) + '+', nul: cur.slice(0, 5) + '\u0000' + cur.slice(5), uni: '\u0430' + cur.slice(1), fw: '\uff21' + cur.slice(1), dot: cur.slice(0, 5) + '.' + cur.slice(6), num: 12345, nullv: null, arr: [cur], obj: { v: cur }, bool: true, nl_mid: cur.slice(0, 10) + '\n' + cur.slice(10), hash: cur.slice(0, 8) + '#' + cur.slice(9),
    };
    // non-canonical trailing bits: change the last char to another char of the same value group (different unused bits)
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = A.indexOf(cur.at(-1));
    if (len === 32) variants.trailbits = cur.slice(0, -1) + A[(last & 0x3c) | 1]; // 43 chars: low 2 bits unused
    if (len === 64) variants.trailbits = cur.slice(0, -1) + A[(last & 0x30) | 2]; // 86 chars: low 4 bits unused
    if (len === 32) variants.trailbits2 = cur.slice(0, -1) + A[(last & 0x3c) | 2];
    if (len === 32) variants.trailbits3 = cur.slice(0, -1) + A[(last & 0x3c) | 3];
    for (const [vn, v] of Object.entries(variants)) {
      if (v === null && vn === 'std') continue;
      const o = clone(B2);
      setf(o, v);
      emitA('b64', `${fn}-${vn}`, `Byte field ${fn} replaced by a ${vn} variant (strict base64url: alphabet A-Za-z0-9-_, no padding, no whitespace, zero trailing bits, fixed ${len}-byte length): wire failure.`, T(o), rootPlain, { want: JSON.stringify(v) === JSON.stringify(cur) || vn === 'upperlast' || vn === 'allA' ? undefined : 'wire' });
    }
  }
  // fields hit with an in-range but WRONG byte-length
  for (const [fn, [, setf, len]] of Object.entries(fields)) for (const bytes of [0, 1, 31, 33, 63, 65, 96, 3309]) {
    if (bytes === len) continue;
    const o = clone(B2); setf(o, pca.b64u(new Uint8Array(bytes).fill(7)));
    emitA('b64', `${fn}-len${bytes}`, `Byte field ${fn} is canonical base64url of ${bytes} bytes (needs ${len}): wire failure.`, T(o), rootPlain, { want: 'wire' });
  }
}

// ================================================================= family: alg (signature-suite / algorithm confusion)
{
  const algVals = ['none', 'None', 'NONE', 'null', '', ' ', 'ed25519 ', ' ed25519', 'ED25519', 'Ed25519', 'EdDSA', 'eddsa', 'ed25519\u0000', 'ed448', 'rsa', 'hs256', 'es256', 'ml-dsa-65', 'ml-dsa-44', 'ml-dsa-87', 'mldsa65', 'ML-DSA-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-ed25519-ml-dsa-87', 'hybrid-nested-ed25519-ml-dsa-65', 'hybrid-ed25519', 'hybrid', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f', 'slh-dsa-shake-128f', 'falcon-512', 'fn-dsa-512', 'less-1', '\u0065d25519', 'ed25519\u200b', 'ed2551\u0039', '\uff45d25519'];
  const nonStr = [0, 1, true, false, [], {}, ['ed25519'], { alg: 'ed25519' }];
  const levels = { leaf: (o, f) => f(o), hop: (o, f) => f(o.cap_chain[0]) };
  const reseal2 = (o) => { try { return resign(o); } catch { return o; } };
  for (const [ln, lv] of Object.entries(levels)) {
    for (const [i, a] of algVals.entries()) {
      for (const [mode, f] of Object.entries({ alg: (t) => { t.alg = a; }, 'alg+pq_pk': (t) => { t.alg = a; t.pq_pk = pca.b64u(new Uint8Array(1952).fill(1)); }, 'alg+pq_sig': (t) => { t.alg = a; t.pq_sig = pca.b64u(new Uint8Array(3309).fill(2)); } })) {
        const o = clone(B1); lv(o, f);
        emitA('alg', `${ln}-${mode.replace('+', '-')}-${String(i).padStart(2, '0')}`, `${ln} signature suite confusion: alg=${JSON.stringify(a)} (${mode}); ${ln === 'leaf' ? 're-signed with the Ed25519 leaf key' : 'hop sig left as-is'}. Only exact registered suite names with their exact companion fields may verify.`, T(ln === 'leaf' ? reseal2(o) : o), rootPlain);
      }
    }
    for (const [i, a] of nonStr.entries()) {
      const o = clone(B1); lv(o, (t) => { t.alg = a; });
      emitA('alg', `${ln}-alg-type-${i}`, `${ln}: alg is the non-string ${JSON.stringify(a)}: wire failure.`, T(ln === 'leaf' ? reseal2(o) : o), rootPlain, { want: 'wire' });
    }
    for (const [pn, f] of Object.entries({ 'pq_pk-only': (t) => { t.pq_pk = pca.b64u(new Uint8Array(1952).fill(1)); }, 'pq_sig-only': (t) => { t.pq_sig = pca.b64u(new Uint8Array(3309).fill(2)); }, 'pq_pk-empty': (t) => { t.pq_pk = ''; }, 'pq_sig-null': (t) => { t.pq_sig = null; }, 'pq_pk-num': (t) => { t.pq_pk = 7; }, 'alg-ed25519-explicit': (t) => { t.alg = 'ed25519'; }, 'alg-ed25519-pqpk': (t) => { t.alg = 'ed25519'; t.pq_pk = pca.b64u(new Uint8Array(1952).fill(1)); }, 'alg-ed25519-pqsig': (t) => { t.alg = 'ed25519'; t.pq_sig = pca.b64u(new Uint8Array(3309).fill(2)); }, 'sig-3309': (t) => { t.sig = pca.b64u(new Uint8Array(3309).fill(5)); }, 'sig-removed': (t) => { delete t.sig; } })) {
      const o = clone(B1); lv(o, f);
      emitA('alg', `${ln}-${pn}`, `${ln} suite-field stray/missing companion (${pn}): ed25519 with pq fields, pq fields without alg, or sig removed.`, T(ln === 'leaf' ? (pn === 'sig-removed' ? o : reseal2(o)) : o), rootPlain);
    }
  }
  // hybrid / pure PQ half-missing derived from the committed PQ leaf vectors (file read, so run after the PQ stage)
  const file = readCore();
  const pqv = file.vectors.filter((v) => /^pq-leaf-/.test(v.name) && v.expect.allow && v.pcactn);
  for (const v of pqv) {
    const mutants = {
      'drop-pq_sig': (p) => { delete p.pq_sig; }, 'drop-sig': (p) => { delete p.sig; }, 'drop-pq_pk': (p) => { delete p.pq_pk; }, 'drop-alg': (p) => { delete p.alg; },
      'alg-none': (p) => { p.alg = 'none'; }, 'alg-ed25519': (p) => { p.alg = 'ed25519'; }, 'swap-sig-pqsig': (p) => { if (p.pq_sig) { const t = p.sig; p.sig = p.pq_sig; p.pq_sig = t; } }, 'sig-eq-pqsig': (p) => { if (p.pq_sig) p.pq_sig = p.sig; },
      'empty-pq_sig': (p) => { p.pq_sig = ''; }, 'pq_sig-trunc': (p) => { if (p.pq_sig) p.pq_sig = p.pq_sig.slice(0, -4); }, 'pq_sig-pad': (p) => { if (p.pq_sig) p.pq_sig += '='; }, 'pq_pk-pad': (p) => { if (p.pq_pk) p.pq_pk += '='; }, 'pq_sig-ws': (p) => { if (p.pq_sig) p.pq_sig = ' ' + p.pq_sig; },
      'alg-upper': (p) => { p.alg = String(p.alg).toUpperCase(); }, 'alg-trailsp': (p) => { p.alg += ' '; },
    };
    for (const [mn, f] of Object.entries(mutants)) {
      const p = clone(v.pcactn); f(p);
      emitA('alg', `${v.name.replace(/^pq-leaf-/, '')}-${mn}`, `Derived from ${v.name} (valid): ${mn}. No downgrade to a weaker/other suite and no half-present hybrid may verify.`, T(p), v.grant, { plan: v.plan_nodes, now: v.context.now, aud: v.context.aud, suiteIndependent: true });
    }
  }
}

// ================================================================= family: key (key-type confusion)
{
  // encodings of special Ed25519 points / scalars
  const P = 2n ** 255n - 19n;
  const le32 = (n) => { const b = new Uint8Array(32); let x = n; for (let i = 0; i < 32; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
  const keys = {
    identity: le32(1n), 'identity-hi': (() => { const b = le32(1n); b[31] |= 0x80; return b; })(), order2: le32(P - 1n), zero: le32(0n), 'zero-sign': (() => { const b = le32(0n); b[31] |= 0x80; return b; })(),
    'y=p': le32(P), 'y=p+1': le32(P + 1n), 'y=p+2': le32(P + 2n), 'y=2^255-1': le32(2n ** 255n - 1n), 'y=p-1-hi': (() => { const b = le32(P - 1n); b[31] |= 0x80; return b; })(),
    order4a: le32(0n), 'order8-a': pca.unb64u('xMUfIPrwjVSCTAlNMAeECSBp8E56NgKGDNUGYo4lbsc'.replace(/[^A-Za-z0-9_-]/g, 'A')), allFF: new Uint8Array(32).fill(255), all80: new Uint8Array(32).fill(0x80), 'off-curve': le32(2n),
  };
  const sigs = { zero: new Uint8Array(64), 'R=identity,S=0': (() => { const s = new Uint8Array(64); s[0] = 1; return s; })(), 'R=identity,S=1': (() => { const s = new Uint8Array(64); s[0] = 1; s[32] = 1; return s; })(), allFF: new Uint8Array(64).fill(255), 'S=L': (() => { const s = new Uint8Array(64); s[0] = 1; const L_ = 7237005577332262213973186563042994240857116359379907606001950938285454250989n; s.set(le32(L_), 32); return s; })(), 'S=L+1': (() => { const s = new Uint8Array(64); s[0] = 1; const L_ = 7237005577332262213973186563042994240857116359379907606001950938285454250990n; s.set(le32(L_), 32); return s; })(), 'S=2^253': (() => { const s = new Uint8Array(64); s[0] = 1; s.set(le32(2n ** 253n), 32); return s; })() };
  for (const [kn, kb] of Object.entries(keys)) {
    for (const [sn, sb] of Object.entries(sigs)) {
      const kpub = pca.b64u(kb);
      // (a) as the LEAF holder: grant root delegates to this key; forged leaf signature
      const g = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: pca.b64u(principal.publicKey), holder: kpub, caveats: [{ type: 'note', text: 'k' }] });
      const pcL = build(g, [g]);
      pcL.sig = pca.b64u(sb);
      emitA('key', `leaf-${kn}-${sn.replace(/[^A-Za-z0-9]+/g, '_')}`, `Leaf holder is the special key encoding "${kn}" with forged leaf signature "${sn}": strict RFC 8032 (small-order/non-canonical keys and signatures) must NOT verify.`, T(pcL), g, { want: 'reject' });
      // (b) as the grant ISSUER (root signature forged): chain fails
      const hop = { ...g, issuer: kpub };
      const body = { issuer: kpub, holder: g.holder, caveats: g.caveats, parent: null };
      const bd = pca.hashCanonical(body);
      const forged = { id: bd, issuer: kpub, holder: g.holder, caveats: g.caveats, body_digest: bd, sig: pca.b64u(sb) };
      void hop;
      const pcI = build(forged, [forged]);
      emitA('key', `issuer-${kn}-${sn.replace(/[^A-Za-z0-9]+/g, '_')}`, `Root capability issued by special key "${kn}" with forged signature "${sn}": chain fails (strict verification).`, T(pcI), forged, { want: 'reject' });
    }
  }
  // key length / type confusion: holder/issuer is a canonical base64url of the wrong length (31/33/64/1952-byte pq key) -> wire failure
  for (const bytes of [0, 16, 31, 33, 48, 64, 1952]) {
    for (const where of ['holder', 'issuer']) {
      const o = clone(B1); o.cap_chain[0][where] = pca.b64u(new Uint8Array(bytes).fill(9));
      emitA('key', `wronglen-${where}-${bytes}`, `Capability ${where} is a ${bytes}-byte value (an Ed25519 key is 32 bytes; a 1952-byte ML-DSA-65 key must not be accepted as an ed25519 key): wire failure.`, T(o), rootPlain, { want: 'wire' });
    }
  }
}

// ================================================================= family: gref (grant_ref_bound variants beyond the base corpus)
{
  const rid = rootPlain.id;
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const rs = (mut, base = B1, secret = agent.secretKey) => { const o = clone(base); mut(o); return T(resign(o, secret)); };
  const gr = (ref) => rs((o) => { o.grant_ref = ref; });
  emitA('gref', 'positive-compact', 'grant_ref == root id (control).', gr(rid), rootPlain, { want: 'accept' });
  for (const i of [0, 1, 10, 20, 30, 41, 42]) {
    const c = rid[i]; const alt = A[(A.indexOf(c) + 1) % 64];
    emitA('gref', `one-char-${i}`, `grant_ref differs from the root id by one character at index ${i}: exact comparison, grant_ref_bound fails${i === 42 ? ' (or non-canonical trailing bits => wire)' : ''}.`, gr(rid.slice(0, i) + alt + rid.slice(i + 1)), rootPlain);
  }
  for (const [n, v] of Object.entries({ padded: rid + '=', spaced: rid + ' ', upper: rid.toUpperCase(), lower: rid.toLowerCase(), std: rid.replace(/-/g, '+').replace(/_/g, '/'), swapped: rid.split('').reverse().join(''), nfkc: rid.normalize('NFKC'), pre: 'A' + rid.slice(1), dup: rid + rid, half: rid.slice(0, 22), trailbits: rid.slice(0, -1) + A[(A.indexOf(rid.at(-1)) & 0x3c) | ((A.indexOf(rid.at(-1)) & 3) ^ 1)] })) emitA('gref', `variant-${n}`, `grant_ref spelled as a ${n} variant of the root id.`, gr(v), rootPlain);
  // chain root differs from the trusted grant, but grant_ref names the chain root
  const other = mkRoot([{ type: 'note', text: 'other' }]);
  emitA('gref', 'ref-names-chainroot-grant-differs', 'cap_chain[0] is another capability, grant_ref names it, trusted grant is different: grant_ref_bound passes but chain fails.', T(build(other, [other])), rootPlain, { want: 'reject' });
  emitA('gref', 'ref-names-trusted-grant-chain-differs', 'grant_ref names the trusted grant but cap_chain[0] is a different capability: grant_ref_bound fails (and chain).', rs((o) => { o.cap_chain = [other]; }), rootPlain, { want: 'reject' });
  emitA('gref', 'ref-names-hop2', 'grant_ref names hop 2 of a 2-hop chain (not the root): grant_ref_bound fails.', rs((o) => { o.grant_ref = hop1.id; }, B2, sub.secretKey), rootPlain, { want: 'reject' });
  emitA('gref', 'two-roots', 'cap_chain = [root, root] (duplicate root): chain fails; grant_ref_bound is evaluated independently.', rs((o) => { o.cap_chain = [rootPlain, rootPlain]; }), rootPlain, { want: 'reject' });
  emitA('gref', 'chain-dup-hop', 'cap_chain = [root, hop1, hop1]: chain fails.', rs((o) => { o.cap_chain = [rootPlain, hop1, hop1]; }, B2, sub.secretKey), rootPlain, { want: 'reject' });
  emitA('gref', 'chain-reordered-ref-leafid', 'cap_chain reordered [hop1, root], grant_ref = root id: grant_ref_bound fails (first hop is not the root id).', rs((o) => { o.cap_chain = [hop1, rootPlain]; }, B2, sub.secretKey), rootPlain, { want: 'reject' });
  emitA('gref', 'ref-names-hop1-chain-reordered', 'cap_chain reordered, grant_ref = new first hop id: grant_ref_bound passes, chain fails.', rs((o) => { o.cap_chain = [hop1, rootPlain]; o.grant_ref = hop1.id; }, B2, sub.secretKey), rootPlain, { want: 'reject' });
  emitA('gref', 'missing-chain-field', 'cap_chain absent: wire failure.', rs((o) => { delete o.cap_chain; }), rootPlain, { want: 'wire' });
  emitA('gref', 'chain-null', 'cap_chain null: wire failure.', rs((o) => { o.cap_chain = null; }), rootPlain, { want: 'wire' });
  emitA('gref', 'chain-object', 'cap_chain is an object (array-vs-object confusion): wire failure.', rs((o) => { o.cap_chain = { 0: rootPlain }; }), rootPlain, { want: 'wire' });
  emitA('gref', 'chain-root-as-object', 'cap_chain is the root capability itself rather than an array: wire failure.', rs((o) => { o.cap_chain = rootPlain; }), rootPlain, { want: 'wire' });
  emitA('gref', 'ref-eq-bodydigest', 'grant_ref equals the root body_digest (== id in this scheme): control, accept.', gr(rootPlain.body_digest), rootPlain, { want: 'accept' });
  emitA('gref', 'hop-id-neq-digest', 'cap_chain[0].id differs from its body_digest (re-signed): chain fails.', rs((o) => { o.cap_chain[0].id = pca.b64u(new Uint8Array(32).fill(1)); }), rootPlain, { want: 'reject' });
  // chain length boundaries around max 16 hops (valid delegations)
  {
    const ks = Array.from({ length: 20 }, (_, i) => mk('hop' + i));
    let g = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: pca.b64u(principal.publicKey), holder: pca.b64u(ks[0].publicKey), caveats: [{ type: 'note', text: 'deep' }] });
    const chain = [g];
    let cur = g;
    let cav = [{ type: 'note', text: 'deep' }];
    for (let i = 0; i < 19; i++) { cav = [...cav, { type: 'note', text: 'h' + i }]; const nx = reseal(cur, pca.b64u(ks[i + 1].publicKey), cav, ks[i].secretKey); chain.push(nx); cur = nx; }
    for (const n of [1, 2, 8, 15, 16, 17, 18, 20]) {
      const pc = build(g, chain.slice(0, n), { signerSecret: ks[n - 1].secretKey });
      emitA('gref', `chainlen-${n}`, `A valid delegation chain of ${n} hops (limit 16, checked before any signature work).`, T(pc), g, { want: n <= 16 ? 'accept' : 'reject' });
    }
  }
}

// ================================================================= family: depth (nesting around the limit of 32 containers)
{
  const nest = (d, leaf = 1) => { let v = leaf; for (let i = 0; i < d; i++) v = [v]; return v; };
  const nestO = (d) => { let v = 1; for (let i = 0; i < d; i++) v = { a: v }; return v; };
  // risk_claim.inputs is depth 3 below the root ({} root =1, risk_claim=2, inputs=3): extra containers go inside
  for (const d of [20, 25, 27, 28, 29, 30, 31, 32, 33, 34, 40, 64, 100, 200, 1000, 5000]) {
    for (const kind of ['arr', 'obj']) {
      const v = kind === 'arr' ? nest(d) : nestO(d);
      const o = { ...clone(B1), risk_claim: { r: 0, inputs: { n: L(JSON.stringify(v)) } } };
      emitA('depth', `${kind}-${d}`, `${d} extra nested ${kind === 'arr' ? 'arrays' : 'objects'} inside risk_claim.inputs (total depth ${d + 3}); the limit is 32 containers: deeper => wire failure, never a stack overflow.`, T(o), rootPlain);
    }
  }
  for (const d of [100000]) emitA('depth', `deep-raw-${d}`, `${d} unbalanced '[' characters: rejected by the depth limit long before recursion exhausts the stack.`, '['.repeat(d), rootPlain, { want: 'wire' });
  emitA('depth', 'deep-raw-obj-50000', '50000 nested {"a": openers: rejected by the depth limit.', '{"a":'.repeat(50000), rootPlain, { want: 'wire' });
  emitA('depth', 'wide-array-5000', 'A 5000-element flat array in risk_claim.inputs: accepted, linear time.', T({ ...clone(B1), risk_claim: { r: 0, inputs: { n: L('[' + '0,'.repeat(4999) + '0]') } } }), rootPlain);
  emitA('depth', 'wide-obj-3000', 'A 3000-key flat object in risk_claim.inputs: accepted, duplicate detection is not quadratic.', T({ ...clone(B1), risk_claim: { r: 0, inputs: Object.fromEntries(Array.from({ length: 3000 }, (_, i) => ['k' + i, i])) } }), rootPlain);
  emitA('depth', 'wide-obj-dup-last', 'A 3000-key flat object whose LAST key duplicates the FIRST: rejected.', T({ ...clone(B1), risk_claim: { r: 0, inputs: L('{' + Array.from({ length: 3000 }, (_, i) => `"k${i}":${i}`).join(',') + ',"k0":0}') } }), rootPlain, { want: 'wire' });
  emitA('depth', 'digits-3000', 'A 3000-digit integer literal: the number profile rejects it immediately (no bigint parse).', T({ ...clone(B1), counter: L('9'.repeat(3000)) }), rootPlain, { want: 'wire' });
  emitA('depth', 'digits-20000-frac', 'A 20000-digit fractional literal: rejected immediately.', T({ ...clone(B1), risk_claim: { r: L('0.' + '1'.repeat(20000)), inputs: {} } }), rootPlain, { want: 'wire' });
  emitA('depth', 'zeros-exp', 'A literal 0e999999999: rejected (exponents are not in the profile) without evaluating the exponent.', T({ ...clone(B1), risk_claim: { r: L('0e999999999'), inputs: {} } }), rootPlain, { want: 'wire' });
  emitA('depth', 'exp-huge', 'A literal 1e999999999999: rejected without evaluating the exponent.', T({ ...clone(B1), risk_claim: { r: L('1e999999999999'), inputs: {} } }), rootPlain, { want: 'wire' });
}

// ================================================================= family: merkle (RFC 6962 shape at every size, incl. int32/int53 boundaries)
{
  const sides = (m, n) => { if (n === 1n) return []; let k = 1n; while (k * 2n < n) k *= 2n; return m < k ? [...sides(m, k), 'R'] : [...sides(m - k, n - k), 'L']; };
  const sizes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 129];
  for (const n of sizes) {
    const nodes = Array.from({ length: n }, (_, i) => ({ id: 'n' + i, verb: i % 2 ? 'write' : 'read', resource: 'db/r' + i }));
    const idxs = [...new Set([0, 1, n >> 1, n - 2, n - 1].filter((i) => i >= 0 && i < n))];
    for (const i of idxs) {
      const pc = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: rootPlain, chain: [rootPlain], plan: nodes, nodeId: 'n' + i, counter: 1, signerSecret: agent.secretKey });
      emitA('merkle', `real-n${n}-i${i}`, `Genuine inclusion proof for leaf ${i} of a ${n}-leaf plan (RFC 6962 split): accept.`, T(pc), rootPlain, { plan: nodes, want: 'accept' });
    }
  }
  const h = (i) => pca.b64u(new Uint8Array(32).fill(i));
  const bigs = [[0n, 1n], [0n, 2n], [1n, 2n], [2n, 3n], [5n, 6n], [(1n << 31n) - 1n, 1n << 31n], [1n << 31n, (1n << 31n) + 1n], [0n, 1n << 31n], [(1n << 32n) - 1n, 1n << 32n], [1n << 32n, (1n << 32n) + 1n], [0n, (1n << 32n) + 1n], [(1n << 40n) + 3n, 1n << 41n], [(1n << 52n) + 1n, (1n << 53n) - 1n], [(1n << 53n) - 2n, (1n << 53n) - 1n], [0n, (1n << 53n) - 1n], [(1n << 53n) - 1n, (1n << 53n) - 1n], [5n, 5n], [6n, 5n], [0n, 0n], [7n, 3n]];
  for (const [m, n] of bigs) {
    const sd = n >= 1n && m < n ? sides(m, n) : ['L'];
    const mk = (path, tag, desc) => {
      const o = clone(B1);
      o.plan.inclusion_proof = { index: L(m.toString()), size: L(n.toString()), path };
      emitA('merkle', `shape-i${m}-n${n}-${tag}`.replace(/[^\w-]/g, '_'), desc, T(resign(o)), rootPlain, { want: m < n && n >= 1n ? undefined : 'reject' });
    };
    mk(sd.map((s, i) => ({ side: s, hash: h(i + 1) })), 'ok', `Proof claiming leaf ${m} of ${n} with a shape-correct path (${sd.length} steps) of arbitrary siblings: the shape passes, the root mismatches (plan_inclusion false) — never a crash, overflow or accept.`);
    if (sd.length > 0) {
      mk(sd.slice(1).map((s, i) => ({ side: s, hash: h(i + 1) })), 'short', 'Same claim, path one step short.');
      mk([...sd, 'L'].map((s, i) => ({ side: s, hash: h(i + 1) })), 'long', 'Same claim, path one step long.');
      mk(sd.map((s, i) => ({ side: i === 0 ? (s === 'L' ? 'R' : 'L') : s, hash: h(i + 1) })), 'flip0', 'Same claim, first side flipped.');
    }
  }
  for (const side of ['L', 'R', 'l', 'r', 'LEFT', '', ' L', 'L ', 'l\u0000', 'Ｌ', null, 0, true]) {
    const o = clone(B1); o.plan.inclusion_proof.path[0].side = side;
    emitA('merkle', `side-${JSON.stringify(side)}`.replace(/[^\w-]/g, '_'), `inclusion step side = ${JSON.stringify(side)}: only the exact strings L and R are wire-valid.`, T(resign(o)), rootPlain);
  }
}

// ================================================================= family: time (freshness arithmetic at every boundary)
{
  const nows = [NOW, 0, 1, 2147483647, 2147483648, 4294967295, 4294967296, 9007199254740991 - 4_000_000, 253402300799000];
  for (const now of nows) {
    for (const d of [-3_600_001, -3_600_000, -1_000, -1, 0, 1, 59_999, 60_000, 60_001, 120_000]) {
      for (const life of [-1, 0, 1, 3_599_999, 3_600_000, 3_600_001]) {
        if (now + d < 0) continue;
        const iat = now + d, exp = iat + life;
        if (exp > 9007199254740991) continue;
        if (!(Math.abs(d) === 1 || Math.abs(d) === 0 || d === 60_000 || d === 59_999 || d === 60_001 || d === -3_600_000) && now !== NOW) continue;
        const o = clone(B1); o.iat = iat; o.exp = exp;
        emitA('time', `now${now}-d${d}-l${life}`.replace(/-/g, 'm').replace('m', '-'), `now=${now}, iat=now${d >= 0 ? '+' : ''}${d}, lifetime=${life} ms (iat<=now+60000, now<=exp, 0<exp-iat<=3600000): boundary arithmetic must agree to the millisecond.`, T(resign(o)), rootPlain, { now });
      }
    }
  }
  // exp boundary relative to now
  for (const e of [-60_001, -60_000, -1, 0, 1]) for (const [life] of [[3_000_000], [1]]) {
    const exp = NOW + e, iat = exp - life;
    const o = clone(B1); o.iat = iat; o.exp = exp;
    emitA('time', `expd${e}-l${life}`.replace(/-/g, 'm'), `exp = now${e >= 0 ? '+' : ''}${e}, lifetime ${life}: expiry boundary (now <= exp accepts, now > exp rejects).`, T(resign(o)), rootPlain);
  }
  for (const [ti, lit] of ['1.5', '1e3', '-1', '0', '1800000000', '18e11', '"1800000000000"', 'true', 'null', '1799999999999.0'].entries()) { const o = clone(B1); o.iat = L(lit); emitA('time', `iat-type-${ti}`, `iat = ${lit}: type/unit confusion (seconds vs ms, string, float, non-canonical).`, T(o), rootPlain); }
}

// ================================================================= family: atten (append-only caveat rule with validly signed hops)
{
  const c1 = { type: 'max_spend', usd: 100 }, c2 = { type: 'resource_prefix', prefix: 'db/' }, c3 = { type: 'note', text: 'café', n: 0.5, flag: true, none: null, arr: [1, { k: 'v' }] }, c4 = { type: 'verb_allow', verbs: ['read', 'write'] };
  const P = [c1, c2, c3, c4];
  const g = mkRoot(P);
  const kid = (caveats, tag, desc, want) => {
    const hop = reseal(g, pca.b64u(sub.publicKey), caveats, agent.secretKey);
    const pc = build(g, [g, hop], { signerSecret: sub.secretKey, nodeId: 'n1', params: undefined });
    emitA('atten', tag, desc, T(pc), g, { want });
  };
  kid(P, 'identical', 'Child repeats the parent caveats exactly: accept (no-op attenuation).', 'accept');
  kid([...P, { type: 'note', text: 'x' }], 'append-one', 'Child appends one caveat: accept.', 'accept');
  kid([...P, ...P], 'append-copy', 'Child appends a copy of the parent list: accept (append-only).', 'accept');
  kid([...P, c1], 'append-dup-first', 'Child appends a duplicate of the first caveat: accept.', 'accept');
  kid([...P, {}].slice(0, 4), 'same-len-after-slice', 'Identical via slice: accept.', 'accept');
  for (let drop = 0; drop < 4; drop++) kid(P.filter((_, i) => i !== drop), `drop-${drop}`, `Child drops parent caveat ${drop} (validly signed): chain fails.`, 'reject');
  for (let keep = 0; keep < 4; keep++) kid(P.slice(0, keep), `prefix-only-${keep}`, `Child keeps only the first ${keep} parent caveats: chain fails.`, 'reject');
  const perms = (a) => a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((r) => [x, ...r]));
  perms([0, 1, 2, 3]).forEach((pm, i) => { if (pm.join('') !== '0123') kid(pm.map((j) => P[j]), `perm-${pm.join('')}`, `Child reorders the parent caveats (${pm.join('')}): chain fails.`, 'reject'); void i; });
  // value-level edits inside caveat 3 (kept in the same position, validly signed)
  const edits = { 'text-nfd': (c) => { c.text = 'café'; }, 'text-case': (c) => { c.text = 'CAFÉ'; }, 'n-0.51': (c) => { c.n = 0.51; }, 'n-int': (c) => { c.n = 1; }, 'n-str': (c) => { c.n = '0.5'; }, 'flag-false': (c) => { c.flag = false; }, 'flag-str': (c) => { c.flag = 'true'; }, 'flag-1': (c) => { c.flag = 1; }, 'none-missing': (c) => { delete c.none; }, 'none-false': (c) => { c.none = false; }, 'none-str': (c) => { c.none = 'null'; }, 'none-0': (c) => { c.none = 0; }, 'arr-reorder': (c) => { c.arr = [{ k: 'v' }, 1]; }, 'arr-obj-edit': (c) => { c.arr = [1, { k: 'w' }]; }, 'arr-wider': (c) => { c.arr = [1, { k: 'v' }, 2]; }, 'extra-key': (c) => { c.extra = 1; }, 'type-edit': (c) => { c.type = 'Note'; }, 'type-nfd': (c) => { c.type = 'note'; }, 'type-trail': (c) => { c.type = 'note '; }, 'empty-obj': (c) => { for (const k of Object.keys(c)) delete c[k]; c.type = 'note'; } };
  for (const [en, f] of Object.entries(edits)) { const c = clone(c3); f(c); kid([c1, c2, c, c4], `edit-${en}`, `Child edits one value inside caveat 3 (${en}) with a valid signature: byte-exact canonical equality required, chain ${en === 'type-nfd' ? 'passes only if the spelling is identical' : 'fails'}.`, en === 'type-nfd' ? undefined : 'reject'); }
  // structural junk in appended caveats
  for (const [jn, jv] of Object.entries({ null: null, num: 1, str: 'x', arr: [], 'obj-no-type': { a: 1 }, 'type-num': { type: 1 }, 'type-null': { type: null }, 'type-arr': { type: [] }, 'type-empty': { type: '' }, 'type-long': { type: 'x'.repeat(4096) } })) {
    const hop = reseal(g, pca.b64u(sub.publicKey), [...P, jv], agent.secretKey);
    const pc = build(g, [g, hop], { signerSecret: sub.secretKey, nodeId: 'n1', params: undefined });
    emitA('atten', `junk-${jn}`, `Child appends a non-conforming caveat (${jn}): each wire layer requires {type:string,...} objects.`, T(pc), g);
  }
  // 3-hop chains: middle hop forgets / reorders what the root had
  const hopA = reseal(g, pca.b64u(sub.publicKey), [...P, { type: 'note', text: 'A' }], agent.secretKey);
  for (const [tn, cv, want] of [['ok', [...P, { type: 'note', text: 'A' }, { type: 'note', text: 'B' }], 'accept'], ['forget-A', [...P, { type: 'note', text: 'B' }], 'reject'], ['forget-root', [{ type: 'note', text: 'A' }, { type: 'note', text: 'B' }], 'reject'], ['reorder', [...P, { type: 'note', text: 'B' }, { type: 'note', text: 'A' }], 'reject'], ['same', [...P, { type: 'note', text: 'A' }], 'accept']]) {
    const hop2 = reseal(hopA, pca.b64u(rogue.publicKey), cv, sub.secretKey);
    const pc = build(g, [g, hopA, hop2], { signerSecret: rogue.secretKey, nodeId: 'n1', params: undefined });
    emitA('atten', `3hop-${tn}`, `Three-hop chain, last hop ${tn}.`, T(pc), g, { want });
  }
  // many caveats
  for (const n of [0, 1, 50, 255, 500, 2000]) { const capOk = n + 1 <= 256 && 2 * n + 1 <= 1024; /* shared caps: 256 per hop, 1024 per chain */ const many = Array.from({ length: n }, (_, i) => ({ type: 'note', text: 'c' + i })); const g2 = mkRoot(many); const hop = reseal(g2, pca.b64u(sub.publicKey), [...many, { type: 'note', text: 'last' }], agent.secretKey); emitA('atten', `many-${n}`, `Root with ${n} caveats extended by one: ${capOk ? 'accept, linear time' : 'rejected by the shared caveat cap (256 per hop / 1024 per chain), before any hashing'}.`, T(build(g2, [g2, hop], { signerSecret: sub.secretKey, nodeId: 'n1', params: undefined })), g2, { want: capOk ? 'accept' : 'reject' }); }
}

// ================================================================= family: size (shared PCActn raw-size cap: 512 KiB = 524288 UTF-8 BYTES, checked before parsing)
{
  const CAP = 524288;
  const nb = (t) => te.encode(t).length;
  const c0 = compact(B1), n0 = nb(c0);
  emitA('size', 'limit-1', 'A valid PCActn padded with trailing whitespace to exactly 524287 bytes: accept (one under the artifact cap).', c0 + ' '.repeat(CAP - 1 - n0), rootPlain, { want: 'accept' });
  emitA('size', 'limit', 'A valid PCActn padded with trailing whitespace to exactly 524288 bytes: accept (AT the artifact cap).', c0 + ' '.repeat(CAP - n0), rootPlain, { want: 'accept' });
  emitA('size', 'limit+1', 'A valid PCActn padded with trailing whitespace to 524289 bytes: wire failure (one over the artifact cap), decided before parsing.', c0 + ' '.repeat(CAP + 1 - n0), rootPlain, { want: 'wire' });
  emitA('size', 'limit+1-leading-ws', 'As limit+1 but the padding precedes the document: wire failure.', ' '.repeat(CAP + 1 - n0) + c0, rootPlain, { want: 'wire' });
  emitA('size', 'ws-only-1MiB', 'A 1 MiB document of whitespace only: wire failure (size cap before parsing).', ' '.repeat(1 << 20), rootPlain, { want: 'wire' });
  // the cap counts UTF-8 BYTES, not characters / UTF-16 units: each width exactly at the cap (accept) and by character count under the cap but bytes over it (reject)
  const padDoc = (pad) => compact(resign({ ...clone(B1), risk_claim: { r: 0, inputs: { pad } } }));
  for (const [wn, ch] of [['2b', '\u00e9'], ['3b', '\u20ac'], ['4b', '\u{1F600}']]) {
    const w = nb(ch), room = CAP - nb(padDoc(''));
    const doc = padDoc(ch.repeat(Math.floor(room / w))), fill = CAP - nb(doc);
    emitA('size', `bytes-${wn}-at-cap`, `Signed document with ${wn} characters filling the cap, trailing whitespace to exactly 524288 BYTES: accept.`, doc + ' '.repeat(fill), rootPlain, { want: 'accept' });
    emitA('size', `bytes-${wn}-cap+1`, `The same document with one more whitespace byte (524289 bytes): wire failure.`, doc + ' '.repeat(fill + 1), rootPlain, { want: 'wire' });
    emitA('size', `bytes-${wn}-chars-under-bytes-over`, `${wn} characters: the character count is under 524288 but the UTF-8 byte count is over: wire failure (bytes, not characters).`, padDoc(ch.repeat(Math.floor(room / w) + 2)), rootPlain, { want: 'wire' });
  }
  // a realistic hybrid LESS-cat1 sized PCActn (~130 KB base64url pq_pk + signature-sized blobs, ~200 KB total): well under the cap, accept
  const blob = (n, k) => { const unit = pca.b64u(new Uint8Array(createHash('sha256').update('less-sized/' + k).digest())); return unit.repeat(Math.ceil(n / unit.length)).slice(0, n); };
  const lessDoc = compact(resign({ ...clone(B1), risk_claim: { r: 0, inputs: { pq_pk: blob(129979, 'pk'), pq_sig: blob(1772, 'sig'), holder_pq_pk: blob(68000, 'hpk') } } }));
  if (nb(lessDoc) < 195000 || nb(lessDoc) > 205000) throw new Error('LESS-sized vector is ' + nb(lessDoc) + ' bytes');
  emitA('size', 'less-hybrid-200KB', 'A realistic hybrid LESS-cat1 sized PCActn (~130 KB pq_pk-shaped blob + signature-sized blobs, ~200 KB): under the artifact cap, accept.', lessDoc, rootPlain, { want: 'accept' });
}

// ================================================================= family: ed (weak-key / weak-signature Ed25519 acceptance)
// The reference (keys.ts) is STRICTER than plain RFC 8032: it rejects small-order and mixed-order A and R, non-canonical S and non-canonical
// point encodings. Each vector below is crafted so that a PLAIN RFC 8032 verifier (cofactorless or cofactored) would accept the signature
// (ed25519-weak.mjs asserts it), at the three places a native verifier checks Ed25519: the PCActn leaf, a delegation hop and the root hop.
{
  const capMsg = (digest) => new Uint8Array([...te.encode('atlas-pca/cap/v1\0'), ...pca.unb64u(digest)]);
  const mkCap = (body, sig) => { const bd = pca.hashCanonical(body); return { id: bd, issuer: body.issuer, holder: body.holder, caveats: body.caveats, ...(body.parent !== undefined ? { parent: body.parent } : {}), body_digest: bd, sig: pca.b64u(sig) }; };
  const need = (name, c) => { if (!W.hasPlainAcceptance(c.plain)) throw new Error('weak vector ' + name + ' is not accepted by a plain RFC 8032 verifier'); };
  for (const spec of W.specs()) {
    const Apub = W.pubFor(spec), Ab = pca.b64u(Apub);
    // (1) PCActn LEAF: the leaf capability's holder is the weak key; the PCActn `sig` is crafted over the v2 signed message
    {
      const g = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: pca.b64u(principal.publicKey), holder: Ab, caveats: [{ type: 'note', text: 'ed' }] });
      const pcFor = (i) => build(g, [g], { counter: i + 1, signerSecret: agent.secretKey });
      const c = W.craft({ ...spec, msgFor: (i) => pca.thresholdMessage(pcFor(i)) }); need(spec.name, c);
      const pc = pcFor(c.tweak); pc.sig = pca.b64u(c.sig);
      emitA('ed', `leaf-${spec.name}`, `PCActn leaf. ${spec.desc}`, T(pc), g, { want: 'reject' });
    }
    // (2) delegation HOP: hop 1 is issued by the weak key (the root's holder)
    {
      const root = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: pca.b64u(principal.publicKey), holder: Ab, caveats: [{ type: 'note', text: 'ed' }] });
      const bodyFor = (i) => ({ issuer: Ab, holder: pca.b64u(sub.publicKey), caveats: [{ type: 'note', text: 'ed' }, { type: 'note', text: 't' + i }], parent: pca.capHash(root) });
      const c = W.craft({ ...spec, msgFor: (i) => capMsg(pca.hashCanonical(bodyFor(i))) }); need(spec.name, c);
      const hop = mkCap(bodyFor(c.tweak), c.sig);
      const pc = build(root, [root, hop], { signerSecret: sub.secretKey, nodeId: 'n1', params: undefined });
      emitA('ed', `hop-${spec.name}`, `Capability hop. ${spec.desc}`, T(pc), root, { want: 'reject' });
    }
    // (3) ROOT hop: the principal (root issuer) is the weak key, and the verifier's own trusted grant is that root
    {
      const bodyFor = (i) => ({ issuer: Ab, holder: pca.b64u(agent.publicKey), caveats: [{ type: 'note', text: 'ed' }, { type: 'note', text: 't' + i }] });
      const c = W.craft({ ...spec, msgFor: (i) => capMsg(pca.hashCanonical(bodyFor(i))) }); need(spec.name, c);
      const root = mkCap(bodyFor(c.tweak), c.sig);
      const pc = build(root, [root]);
      emitA('ed', `root-${spec.name}`, `Root hop. ${spec.desc}`, T(pc), root, { want: 'reject' });
    }
  }
  emitA('ed', 'control-honest-leaf', 'Control: an honest key and signature on the same shape still verify.', T(build(rootPlain, [rootPlain])), rootPlain, { want: 'accept' });
}

// ================================================================= resolve (async reference)
const done = [];
const PROBLEMS = [];
for (const [family, name, description, text, grant, o] of jobs) {
  const full = `adv-${family}-${name}`;
  if (names.has(full)) throw new Error('duplicate vector name ' + full);
  names.add(full);
  const { now = NOW, aud = AUD, want, plan = planNodes, suiteIndependent } = o ?? {};
  let obj, werr = null;
  try { obj = pca.decodePCActn(text); } catch (e) { werr = e; }
  let checks;
  if (werr) checks = { wire: false };
  else {
    const r = await pca.verifyPCActnCore(obj, { grant, nowEpoch: now, audience: aud });
    checks = r.checks.wire === 'fail' ? { wire: false } : Object.fromEntries([['wire', true], ...CHECKS.map((k) => [k, r.checks[KEYMAP[k] ?? k] === 'pass'])]);
  }
  const allow = Object.values(checks).every(Boolean);
  // derived-from-PQ mutants are only committed when the verdict does not depend on a real PQ verification (a terminal wire
  // failure, or a leaf that resolves to plain ed25519): runners skip suite-requiring vectors by inspecting `pcactn`, which a raw-text vector lacks.
  if (suiteIndependent && checks.wire !== false && obj && obj.alg !== undefined && obj.alg !== 'ed25519') continue;
  if (want === 'accept' && !allow) PROBLEMS.push(`${full}: intended accept, reference gave ${JSON.stringify(checks)}`);
  if (want === 'wire' && checks.wire !== false) PROBLEMS.push(`${full}: intended wire failure, reference gave ${JSON.stringify(checks)}`);
  if (want === 'reject' && allow) PROBLEMS.push(`${full}: intended reject, reference accepted`);
  fam[family] = (fam[family] ?? 0) + 1;
  done.push({ name: full, class: allow ? 'positive' : 'negative', description, grant, plan_nodes: plan, context: { now, aud }, pcactn_json: text, expect: { allow, checks } });
}
if (PROBLEMS.length) { console.error(PROBLEMS.join('\n')); throw new Error(PROBLEMS.length + ' intent mismatches (reference disagrees with stated intent)'); }
const advVectors = [...out, ...done];

// ================================================================= primitives: json_parse / b64u / canonical
const jsonParse = [];
const jp = (input, accept, extra) => { let canonical; let acc = true; try { canonical = pca.canonicalizeStrict(pca.strictParse(input)); } catch { acc = false; } if (acc !== accept && accept !== undefined) throw new Error('json_parse intent mismatch for ' + JSON.stringify(input.slice(0, 60)) + ` (ref ${acc})`); const e = { input, accept: acc }; if (acc) e.canonical = canonical; if (extra) e.note = extra; jsonParse.push(e); };
{
  // strict profile grammar sweep
  const bad = ['', ' ', '{', '}', '{"a"}', '{"a":}', '{"a":1,}', '{,}', '{"a":1 "b":2}', "{'a':1}", '{a:1}', '[1,]', '[,1]', '[1 2]', '[01]', '[+1]', '[.5]', '[5.]', '[1e5]', '[1E5]', '[1e+5]', '[1.0]', '[-0]', '[-0.0]', '[0x1]', '[Infinity]', '[NaN]', '[-]', '[--1]', '["\\x"]', '["\\u12"]', '["\\ud800"]', '["\\udc00"]', '["\\ud800\\ud800"]', '["\\udc00\\ud800"]', '["\t"]', '["\n"]', '["\u0000"]', '["\u001f"]', '[1]x', '[1][1]', '[1] [1]', '\ufeff[1]', '/*c*/[1]', '[1]//c', '[1,/*c*/2]', '{"a":1,"a":1}', '{"a":1,"\\u0061":2}', '{"\\u0061":1,"a":2}', '{"a":1,"A":2,"a":3}', '[tru]', '[nul]', '[True]', '[NULL]', '[falsey]', '\u000b[1]', '\u00a0[1]', '[1]\u00a0', '[1\u2028]', '{"a":1}\u0000', '[9007199254740992]', '[9007199254740993]', '[-9007199254740992]', '[0.1234567890123456]', '[0.0000009]', '[1e-7]', '[123456789012345678]', '[100000000000000000000]', '[1.50]', '[0.10]', '[00.5]', '[-01]', '["\\/\\x"]', '[1.]', '[1.e1]', '[1e]', '[]]', '[[]', '{"a":{"b":}}', '"\\ud800\\u0041"', '"\\u00"', '"abc', 'abc"', 'tru', 'nulll', '--', '-', '.', '0.', '-.5', '1..2', '[1,2,]', '{"":}', '{"a":1}}', '{{}}', '[{]}', '[}]'];
  for (const s of bad) jp(s, false);
  const good = ['{}', '[]', '{"a":1}', '[1,2,3]', '{"a":[{"b":null}]}', ' [ 1 , 2 ] ', '\t\r\n[1]', '"x"', '1', '-1', '0', 'true', 'false', 'null', '0.5', '-0.5', '0.000001', '0.123456789012345', '9007199254740991', '-9007199254740991', '12345678901234.5', '["\\u0041"]', '["\\u00e9"]', '["\\ud83d\\ude00"]', '["\\uD83D\\uDE00"]', '["\\/"]', '["\\b\\f\\n\\r\\t\\"\\\\"]', '["\\u0000"]', '["\\u001f"]', '["\\u007f"]', '["\\u2028\\u2029"]', '["\\ufffe\\uffff"]', '{"b":1,"a":2}', '{"\\uff5e":1,"\\ud83d\\ude00":2}', '{"\\ud83d\\ude00":1,"\\uff5e":2}', '{"\u00e9":1,"e\u0301":2}', '{"":1,"a":2}', '{"a":{"a":{"a":1}}}', '["\u00e9\u{1F600}\u0000"]'.replace('\u0000', ''), '{"a":1,"b":{"c":[1,2,{"d":null}]}}', '[1.5,2.25,0.125]', '[100000,10,1000000]', '["a\\u0000b"]', '["\\u00ff\\u0100"]', '{"A":1,"a":2}', '{"a":1,"aa":2,"a\\u0000":3}', '["\\uDBFF\\uDFFF"]', '[true,false,null]', '{"__proto__":1}', '{"constructor":{"prototype":1}}', '{"toString":1,"hasOwnProperty":2}'];
  for (const s of good) jp(s, true);
  // generated: nesting boundary, number-form sweep, key ordering
  const nestArr = (d) => '['.repeat(d) + ']'.repeat(d);
  for (const d of [1, 2, 31, 32]) jp(nestArr(d), true);
  for (const d of [33, 34, 40, 100, 1000, 100000]) jp(nestArr(d), false);
  for (const d of [31, 32, 33]) jp('{"a":'.repeat(d) + '1' + '}'.repeat(d), d <= 32);
  for (const n of [1, 2, 9, 14, 15, 16, 17, 18]) jp('0.' + '1'.repeat(n), n <= 15);
  for (const n of [1, 15, 16, 17]) jp('1' + '0'.repeat(n), n <= 15);
  for (const lit of ['1', '10', '100', '0.5', '0.25', '0.125', '0.1', '0.2', '0.3', '1.5', '2.5', '10.25', '123.456', '0.001', '0.000001', '0.0000011', '999999999999999', '99999999999999.9', '9999999999999.99', '0.999999999999999', '0.0000001', '1.10', '2.50', '3.00', '-1.5', '-0.000001', '-0.0000001']) jp(lit, undefined);
  for (const k of ['a', 'B', '\u00e9', '\uff5e', '\u{1F600}', '\ue000', '\u{10000}', '\uffff', '\u0080', '\u007f']) for (const k2 of ['a', 'B', '\u00e9', '\uff5e', '\u{1F600}', '\ue000', '\u{10000}', '\uffff', '\u0080', '\u007f']) if (k < k2 || k === k2) { if (k !== k2) jp(`{${JSON.stringify(k2)}:1,${JSON.stringify(k)}:2}`, true); }
  for (let c = 0x20; c < 0x7f; c += 3) jp(`["\\u${c.toString(16).padStart(4, '0')}"]`, true);
  for (let c = 0; c < 0x20; c++) { jp(`["${String.fromCharCode(c)}"]`, false); jp(`[${String.fromCharCode(c)}1]`, [9, 10, 13].includes(c) ? true : false); }
  for (const c of [0x0b, 0x0c, 0x85, 0xa0, 0x1680, 0x2000, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff, 0x200b]) { jp(`[${String.fromCharCode(c)}1]`, false); jp(`${String.fromCharCode(c)}[1]`, false); jp(`[1]${String.fromCharCode(c)}`, false); jp(`{"a"${String.fromCharCode(c)}:1}`, false); }
  for (let hi = 0xd800; hi <= 0xdbff; hi += 0x155) { jp(`["\\u${hi.toString(16)}"]`, false); jp(`["\\u${hi.toString(16)}\\u0041"]`, false); jp(`["\\u${hi.toString(16)}\\ud800"]`, false); jp(`["\\u${hi.toString(16)}\\udc00"]`, true); jp(`["\\u${hi.toString(16).toUpperCase()}\\uDC00"]`, true); }
  for (let lo = 0xdc00; lo <= 0xdfff; lo += 0x155) { jp(`["\\u${lo.toString(16)}"]`, false); jp(`["\\u${lo.toString(16)}\\ud800"]`, false); jp(`["a\\u${lo.toString(16)}"]`, false); }
}
const b64u = [];
{
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const ref = (s, len) => { try { const b = pca.unb64u(s); return pca.b64u(b) === s && (len === undefined || b.length === len); } catch { return false; } };
  const add = (input, len) => b64u.push({ input, valid: ref(input, len), ...(len !== undefined ? { len } : {}) });
  for (let n = 0; n <= 70; n++) { const s = pca.b64u(new Uint8Array(n).map((_, i) => (i * 37 + 11) & 255)); add(s); add(s, n); add(s + '='); add(s + 'A'); if (s.length) add(s.slice(0, -1)); add(' ' + s); }
  for (const c of A) { add('A' + c); add('AA' + c); add('AAA' + c); add('AAAAA' + c); }
  for (const bad of ['+', '/', '=', '==', 'A=', 'A==', 'AA=', 'AA==', 'AAA=', 'AAAA=', 'AAAA====', 'A\nA', 'AA AA', 'AAA\tA', '\u0430AAA', 'AAA\u0430', '\uff21AAA', 'AAAA\u0000', 'AA+/', 'AA-_', 'AA_-', '-_-_', '-_-', '_-', '-', '_', 'AAAAA', 'AAAAAAAAA', 'AAAAAAAAAAAAA', 'AB', 'AC', 'AQ', 'AR', 'AAB', 'AAC', 'AAAB', 'AAAAB']) add(bad);
}
const canonical = [];
{
  const add = (value) => { const expect = pca.canonicalizeStrict(value); canonical.push({ value, expect, hash: pca.hashCanonical(value) }); };
  for (const v of [{ a: 1 }, { b: 1, a: 2 }, { '': 1, a: 2 }, { '\uff5e': 1, '\u{1F600}': 2 }, { '\ue000': 1, '\u{10000}': 2 }, { '\uffff': 1, '\u{10000}': 2 }, { '\u0080': 1, '\u007f': 2 }, { s: '\u2028\u2029' }, { s: '\u007f' }, { s: '\u0000' }, { s: '\u001f' }, { s: '\b\f\n\r\t' }, { s: '"\\/' }, { s: '\u{1F600}' }, { s: 'caf\u00e9' }, { s: 'cafe\u0301' }, { n: [0, 1, -1, 0.5, 0.25, 100000, 999999999999999, 0.000001, 123456789012.345] }, { n: [] }, { o: {} }, { z: null, t: true, f: false }, [], [[]], [{}], { a: { b: { c: [1, { d: 2 }] } } }, { 'A': 1, 'a': 2, 'B': 3 }, { 'aa': 1, 'a': 2, 'a\u0000': 3 }, { 10: 1, 9: 2, 2: 3 }, { b: [3, 2, 1], a: [1, 2, 3] }, 'str', 5, true, null, 0.1, 1e-6, 123456.789]) add(v);
}

// ================================================================= standalone chain API vectors (R4-01): primitives.chain_pin
// The standalone `verify_chain` / `VerifyChain` entry point of every verifier (NOT the PCActn path, which already pins hop 0
// via chain[0] == grant). A vector is { name, description, chain, expected_root_issuer, pq_pins?, trusted_root?,
// allowed_suites?, expect: { ok, reason? } }. A non-ed25519 ROOT is accepted only when the verifier supplies `pq_pins[root.issuer]`
// equal to the root's `pq_pk`, or `trusted_root` is the root itself (same content hash); otherwise `reason` is the exact R3-01
// string (runners compare `ok` always, and `reason` exactly whenever it starts with "hop 0: root suite"). Reference: pca.verifyChain.
const chainPin = [];
{
  const sd = (l) => seed('chainpin/' + l);
  const victimPub = pca.b64u(principal.publicKey);
  const victimMl = pca.mlDsa65Keygen(sd('principal-mldsa65'));   // the victim's GENUINE ML-DSA key
  const atkMl = pca.mlDsa65Keygen(sd('attacker-mldsa65'));       // the attacker's own ML-DSA key
  const agentMl = pca.mlDsa65Keygen(sd('agent-mldsa65'));
  const pk = (kp) => pca.encodeMlDsaPublicKey(kp.publicKey);
  const cav = [{ type: 'max_spend', usd: 100 }];
  const hopCav = { type: 'resource_prefix', prefix: 'db/' };
  const root = (suite, { secret = principal.secretKey, issuer = victimPub, holderPq } = {}) => pca.mintRoot({ principalSecret: secret, principalPublic: issuer, holder: pca.b64u(agent.publicKey), ...(holderPq ? { holderPq } : {}), caveats: cav, ...(suite ? { suite } : {}) });
  const PURE = (kp) => ({ alg: 'ml-dsa-65', mlDsa: kp }), HYB = (kp) => ({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: kp });
  const edRoot = root(undefined);
  const edRootBound = root(undefined, { holderPq: pk(agentMl) });
  const pureGen = root(PURE(victimMl)), hybGen = root(HYB(victimMl));
  const pureGenBound = root(PURE(victimMl), { holderPq: pk(agentMl) }), hybGenBound = root(HYB(victimMl), { holderPq: pk(agentMl) });
  const pureAtk = root(PURE(atkMl), { secret: rogue.secretKey });   // names the VICTIM as issuer, signed by the attacker's own ML-DSA key
  const hybAtk = root(HYB(atkMl), { secret: rogue.secretKey });
  const edHop = (parent) => pca.delegate(parent, pca.b64u(sub.publicKey), [hopCav], agent.secretKey);
  const pqHop = (parent, kp = agentMl) => pca.delegate(parent, pca.b64u(sub.publicKey), [hopCav], agent.secretKey, PURE(kp));
  const hybHop = (parent) => pca.delegate(parent, pca.b64u(sub.publicKey), [hopCav], agent.secretKey, HYB(agentMl));
  const tamper = (c) => { const x = clone(c); const b = pca.unb64u(x.pq_sig ?? x.sig); b[7] ^= 1; if (x.pq_sig !== undefined) x.pq_sig = pca.b64u(b); else x.sig = pca.b64u(b); return x; };
  const pin = (id, k) => ({ [id]: pk(k) });
  const REASON_PIN = (alg) => `hop 0: root suite '${alg}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`;
  const add = (name, description, chain, o = {}, wantOk, wantReason) => {
    const eri = o.expected_root_issuer === undefined ? victimPub : o.expected_root_issuer;
    const policy = {};
    if (o.pq_pins !== undefined) policy.pqPins = o.pq_pins;
    if (o.trusted_root !== undefined) policy.trustedRoot = o.trusted_root;
    if (o.allowed_suites !== undefined) policy.allowedSuites = o.allowed_suites;
    const r = pca.verifyChain(chain, eri, policy);
    if (r.ok !== wantOk) throw new Error(`chain_pin ${name}: reference ok=${r.ok} (${r.reason}) != intended ${wantOk}`);
    if (wantReason !== undefined && r.reason !== wantReason) throw new Error(`chain_pin ${name}: reference reason ${JSON.stringify(r.reason)} != intended ${JSON.stringify(wantReason)}`);
    chainPin.push({
      name: 'chainpin-' + name, class: wantOk ? 'positive' : 'negative', description, chain, expected_root_issuer: eri,
      ...(o.pq_pins !== undefined ? { pq_pins: o.pq_pins } : {}), ...(o.trusted_root !== undefined ? { trusted_root: o.trusted_root } : {}),
      ...(o.allowed_suites !== undefined ? { allowed_suites: o.allowed_suites } : {}),
      expect: { ok: r.ok, ...(r.ok ? {} : { reason: r.reason }) },
    });
  };
  // -- the attack (R4-01): attacker-own-key roots naming the victim as issuer
  add('pure-pq-root-attacker-own-key-no-pin', 'R4-01: a pure ml-dsa-65 root naming the victim Ed25519 issuer, signed by the ATTACKER\'s own ML-DSA key, with no pin and no stored grant: refused (the root\'s own pq_pk proves nothing about its issuer).', [pureAtk], {}, false, REASON_PIN('ml-dsa-65'));
  add('hybrid-root-attacker-own-pq-key-no-pin', 'R4-01: a hybrid root naming the victim issuer whose PQ half is the attacker\'s own key (the Ed25519 half is not the victim\'s): refused for want of a pin before any signature is judged.', [hybAtk], {}, false, REASON_PIN('hybrid-ed25519-ml-dsa-65'));
  add('pure-pq-root-attacker-own-key-wrong-pin', 'A pin exists for the victim but is the genuine key; the root presents the attacker\'s key: the pin differs from the artifact key, refused.', [pureAtk], { pq_pins: pin(victimPub, victimMl) }, false, REASON_PIN('ml-dsa-65'));
  add('pure-pq-root-pin-for-other-issuer', 'A pin is supplied, but for a different issuer: no pin for root.issuer, refused.', [pureAtk], { pq_pins: pin(pca.b64u(agent.publicKey), atkMl) }, false, REASON_PIN('ml-dsa-65'));
  add('pure-pq-root-trusted-root-is-other-root', 'trusted_root is the victim\'s genuine root, the presented root is the attacker\'s: not the same root, refused.', [pureAtk], { trusted_root: pureGen }, false, REASON_PIN('ml-dsa-65'));
  add('pure-pq-root-attacker-key-pinned-to-victim-key', 'The victim pinned its genuine PQ key; the attacker\'s root carries the attacker\'s key: refused (a pin that differs from the artifact key is a refusal).', [pureAtk], { pq_pins: pin(victimPub, victimMl) }, false, REASON_PIN('ml-dsa-65'));
  // -- genuine roots
  add('pure-pq-root-genuine-no-pin', 'A genuine pure ml-dsa-65 root, but the verifier has neither a pin nor a stored grant: refused.', [pureGen], {}, false, REASON_PIN('ml-dsa-65'));
  add('hybrid-root-genuine-no-pin', 'A genuine hybrid root with no pin and no stored grant: refused (the Ed25519 half alone is not the whole root).', [hybGen], {}, false, REASON_PIN('hybrid-ed25519-ml-dsa-65'));
  add('pure-pq-root-pinned', 'A genuine pure ml-dsa-65 root with pq_pins[issuer] equal to its pq_pk: accepted.', [pureGen], { pq_pins: pin(victimPub, victimMl) }, true);
  add('hybrid-root-pinned', 'A genuine hybrid root with pq_pins[issuer] equal to its pq_pk: accepted.', [hybGen], { pq_pins: pin(victimPub, victimMl) }, true);
  add('pure-pq-root-trusted-root', 'The verifier\'s stored grant (trusted_root) is this very root: accepted without a pin.', [pureGen], { trusted_root: pureGen }, true);
  add('hybrid-root-trusted-root', 'trusted_root is this hybrid root: accepted without a pin.', [hybGen], { trusted_root: hybGen }, true);
  add('hybrid-root-wrong-pin', 'A genuine hybrid root, but the pin for the issuer is another key: refused.', [hybGen], { pq_pins: pin(victimPub, atkMl) }, false, REASON_PIN('hybrid-ed25519-ml-dsa-65'));
  add('pure-pq-root-pinned-bad-signature', 'The pin matches the root\'s pq_pk but the PQ signature is corrupt: the pin only authorises the key, the signature must still verify.', [tamper(pureGen)], { pq_pins: pin(victimPub, victimMl) }, false);
  add('hybrid-root-pinned-bad-pq-signature', 'The pin matches but the hybrid root\'s pq_sig is corrupt: refused.', [tamper(hybGen)], { pq_pins: pin(victimPub, victimMl) }, false);
  add('pure-pq-root-pinned-wrong-expected-issuer', 'A pinned, genuine root checked against a different expected root issuer: the issuer check refuses before any key work.', [pureGen], { pq_pins: pin(victimPub, victimMl), expected_root_issuer: pca.b64u(rogue.publicKey) }, false);
  add('ed25519-root-no-pin-needed', 'An Ed25519 root needs no pin and no stored grant: accepted (byte-identical to the pre-PQ behaviour).', [edRoot], {}, true);
  add('ed25519-root-irrelevant-pin', 'An Ed25519 root with an unrelated pin supplied: accepted; pins only matter for roots that carry a PQ key.', [edRoot], { pq_pins: pin(victimPub, atkMl) }, true);
  // -- mixed chains
  add('mixed-ed25519-root-bound-pq-hop', 'Ed25519 root committing holder_pq, then a pure ml-dsa-65 hop 1 under the committed key: accepted without any pin (hop >= 1 is bound by holder_pq).', [edRootBound, pqHop(edRootBound)], {}, true);
  add('mixed-ed25519-root-attacker-pq-hop', 'Ed25519 root committing holder_pq to the agent\'s key, hop 1 pure ml-dsa-65 under the ATTACKER\'s key: the holder_pq binding refuses it.', [edRootBound, pqHop(edRootBound, atkMl)], {}, false);
  add('mixed-pure-pq-root-pinned-ed25519-hop', 'A pinned pure-PQ root followed by an Ed25519 hop: accepted.', [pureGen, edHop(pureGen)], { pq_pins: pin(victimPub, victimMl) }, true);
  add('mixed-pure-pq-root-pinned-pq-hop', 'A pinned pure-PQ root (committing holder_pq) followed by a pure ml-dsa-65 hop under the committed key: accepted.', [pureGenBound, pqHop(pureGenBound)], { pq_pins: pin(victimPub, victimMl) }, true);
  add('mixed-hybrid-root-pinned-hybrid-hop', 'A pinned hybrid root (committing holder_pq) followed by a hybrid hop under the committed key: accepted.', [hybGenBound, hybHop(hybGenBound)], { pq_pins: pin(victimPub, victimMl) }, true);
  add('mixed-pure-pq-root-unpinned-ed25519-hop', 'A pure-PQ root with no pin followed by an Ed25519 hop: the root hop is refused, whatever follows.', [pureGen, edHop(pureGen)], {}, false, REASON_PIN('ml-dsa-65'));
  add('mixed-pure-pq-root-trusted-root-pq-hop', 'trusted_root is the (committing) pure-PQ root; hop 1 is a pure ml-dsa-65 hop under the committed key: accepted.', [pureGenBound, pqHop(pureGenBound)], { trusted_root: pureGenBound }, true);
  add('mixed-pinned-root-attacker-pq-hop', 'A pinned root followed by a hop signed under an attacker key that holder_pq does not commit to: refused at hop 1.', [pureGenBound, pqHop(pureGenBound, atkMl)], { pq_pins: pin(victimPub, victimMl) }, false);
  // -- suite policy ordering
  add('pinned-pure-pq-root-suite-policy-refuses', 'A pinned pure-PQ root under allowed_suites ["ed25519"]: the suite policy refuses it (ahead of the pin).', [pureGen], { pq_pins: pin(victimPub, victimMl), allowed_suites: ['ed25519'] }, false);
  add('pinned-pure-pq-root-suite-policy-allows', 'A pinned pure-PQ root under allowed_suites ["ed25519","ml-dsa-65"]: accepted.', [pureGen], { pq_pins: pin(victimPub, victimMl), allowed_suites: ['ed25519', 'ml-dsa-65'] }, true);
}

// ================================================================= splice
// The FULL adversarial set goes to conformance/vectors-adversarial.json.gz (flagship repo + monorepo gate only); the CURATED
// core conformance/vectors.json keeps the golden vectors plus a deterministic representative sample of every family.
const file = readCore();
file.vectors = file.vectors.filter((v) => !v.name.startsWith('adv-'));
const baseCounts = { json_parse: 54, b64u: 21, canonical: 5 }; // entries written by gen-conformance.mjs (asserted below)
if (file.primitives.json_parse.length < 54 || file.primitives.b64u.length < 21 || file.primitives.canonical.length < 5) throw new Error('base primitives missing: run gen-conformance.mjs first');

// --- deterministic representative sample -----------------------------------------------------------------------------
// Per family: first one smallest vector of every distinct outcome class (allow + the exact set of failing checks), then evenly
// strided fill (small vectors only) up to SAMPLE_PER_FAMILY. Depends only on the generated vectors, so it is reproducible.
const SAMPLE_PER_FAMILY = 6, SAMPLE_MAX_BYTES = 2200;
const failing = (v) => Object.entries(v.expect.checks).filter(([, ok]) => !ok).map(([k]) => k).sort().join('+');
const byFam = new Map();
for (const v of advVectors) { const f = v.name.split('-')[1]; if (!byFam.has(f)) byFam.set(f, []); byFam.get(f).push(v); }
const sampleNames = new Set();
for (const [famName, list] of byFam) {
  if (famName === 'size') continue; // 200-600 KB documents: full set + all-languages gate only (never in the vendored core)
  const size = new Map(list.map((v) => [v.name, JSON.stringify(v).length]));
  const small = list.filter((v) => size.get(v.name) <= SAMPLE_MAX_BYTES);
  const pool = small.length >= SAMPLE_PER_FAMILY ? small : [...list].sort((a, b) => size.get(a.name) - size.get(b.name)).slice(0, SAMPLE_PER_FAMILY);
  const picked = new Set();
  const classes = new Map();
  for (const v of pool) { const k = `${v.expect.allow}/${failing(v)}`; const cur = classes.get(k); if (!cur || size.get(v.name) < size.get(cur.name)) classes.set(k, v); }
  for (const v of [...classes.values()].sort((a, b) => size.get(a.name) - size.get(b.name) || (a.name < b.name ? -1 : 1)).slice(0, SAMPLE_PER_FAMILY)) picked.add(v.name);
  const want = Math.min(SAMPLE_PER_FAMILY, pool.length);
  for (let j = 0; picked.size < want && j < pool.length * 2; j++) picked.add(pool[Math.floor((j * pool.length) / want) % pool.length].name);
  for (const n of picked) sampleNames.add(n);
}
const sample = advVectors.filter((v) => sampleNames.has(v.name));
const every = (a, k) => a.filter((_, i) => i % k === 0);
const primSample = { json_parse: every(jsonParse, 6), b64u: every(b64u, 12), canonical: every(canonical, 2) };
file.vectors.push(...sample);
file.primitives.json_parse = [...file.primitives.json_parse.slice(0, baseCounts.json_parse), ...primSample.json_parse];
file.primitives.b64u = [...file.primitives.b64u.slice(0, baseCounts.b64u), ...primSample.b64u];
file.primitives.canonical = [...file.primitives.canonical.slice(0, baseCounts.canonical), ...primSample.canonical];
file.primitives.chain_pin = chainPin;
writeCore(file);
const advFile = {
  format: file.format, ver: file.ver,
  description: 'FULL adversarial parser-differential corpus (a superset of the adv-* sample embedded in vectors.json). Same vector schema as vectors.json; `primitives` holds ONLY the adversarial json_parse/b64u/canonical entries (the base ones live in vectors.json). Generated by packages/pca/scripts/gen-conformance-adv.mjs.',
  sample_in_core: [...sampleNames],
  vectors: advVectors,
  primitives: { json_parse: jsonParse, b64u, canonical },
};
const advPath = writeAdversarial(advFile, { plain: process.argv.includes('--plain') });
const prim = jsonParse.length + b64u.length + canonical.length;
console.log(`wrote ${advVectors.length} adversarial vectors + ${prim} adversarial primitive vectors (json_parse ${jsonParse.length}, b64u ${b64u.length}, canonical ${canonical.length}) -> ${advPath}`);
console.log(`core ${CORE_PATH} keeps ${sample.length} sampled adv vectors + ${primSample.json_parse.length + primSample.b64u.length + primSample.canonical.length} sampled primitives`);
console.log(Object.entries(fam).map(([k, v]) => `${k}=${v}`).join(' '));
console.log(`accept=${advVectors.filter((v) => v.expect.allow).length} reject=${advVectors.filter((v) => !v.expect.allow).length} wire-reject=${advVectors.filter((v) => v.expect.checks.wire === false).length}`);
