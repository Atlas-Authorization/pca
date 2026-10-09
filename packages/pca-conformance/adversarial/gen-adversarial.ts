// Deterministic ADVERSARIAL / MALFORMED corpus generator for the PCA cross-language conformance gate.
//   tsx gen-adversarial.ts [--out corpus.jsonl] [--check]
// Outputs: MANIFEST (committed, small: id/category/name/intent/ref/sha256+length of raw) and, with --corpus <file>,
// the FULL corpus (several MB: 1 MiB+ inputs) in the SAME shape tools/pca-diff-fuzz drivers consume
//   {id, kind:'verify'|'canon', raw, grant, now, aud}  plus  {category, name, intent, ref}
// where `ref` is the TypeScript reference verdict (packages/pca/src, run from source) and `intent` is what a
// security reviewer would EXPECT ('accept' | 'reject' | 'either'). If ref contradicts intent the vector is
// flagged `refDeviates:true` -- that is a FINDING about the reference, recorded rather than papered over.
// Pure function of the source tree: no clock, no randomness (a seeded mulberry32 is used only for filler bytes),
// Ed25519 is deterministic => regenerating gives a byte-identical file (`--check` asserts it).
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pca, refVerify, refCanon } from './ref';
import { safeParse } from '../../../tools/pca-diff-fuzz/gen/safejson';
const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const OUT = args.includes('--out') ? args[args.indexOf('--out') + 1]! : join(HERE, 'manifest.jsonl');
const CORPUS = args.includes('--corpus') ? args[args.indexOf('--corpus') + 1]! : null;
const CHECK = args.includes('--check');
export const NOW = 1_800_000_000_000;
export const AUD = 'rs-adv';

// ---------------------------------------------------------------- deterministic helpers
function mulberry32(a: number) {
  return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const rnd = mulberry32(0xadf0e5);
const RAW: string[] = [];
/** A sentinel string standing for an arbitrary raw JSON literal in the serialised text. */
const lit = (s: string) => { RAW.push(s); return `@@RAW#${RAW.length - 1}@@`; };
const rawText = (x: unknown): string => JSON.stringify(x).replace(/"@@RAW#(\d+)@@"/g, (_m, i) => RAW[Number(i)]!);
const P = <T,>(x: T): T => safeParse(rawText(x)) as T;
const clone = <T,>(x: T): T => structuredClone(x);
type Key = { sk: Uint8Array; pub: string };
const keyOf = (label: string): Key => { const sk = new Uint8Array(createHash('sha256').update(`pca-adversarial/${label}`).digest()); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
const K = { principal: keyOf('principal'), agent: keyOf('agent'), sub: keyOf('sub'), sub2: keyOf('sub2'), rogue: keyOf('rogue') };
const te = new TextEncoder();
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

function sealHop(parent: any | null, issuer: Key, holderPub: string, caveats: unknown[], signer: Key = issuer): any {
  const parentHash = parent ? pca.capHash(P(parent)) : null;
  const body = { issuer: issuer.pub, holder: holderPub, caveats, parent: parentHash };
  const body_digest = pca.hashCanonical(P(body));
  const msg = new Uint8Array([...te.encode('atlas-pca/cap/v1\0'), ...pca.unb64u(body_digest)]);
  const cap: any = { id: body_digest, issuer: issuer.pub, holder: holderPub, caveats, body_digest, sig: pca.b64u(pca.sign(signer.sk, msg)) };
  if (parentHash !== null) cap.parent = parentHash;
  return cap;
}
const PLAN = Array.from({ length: 4 }, (_, i) => ({ id: `n${i}`, verb: ['read', 'write', 'send', 'delete'][i]!, resource: `db/t${i}`, params_digest: pca.paramsDigest(), reversibility_class: 'reversible' }));

interface Spec { depth?: 1 | 2 | 3; caveats?: unknown[][]; node?: number; plan?: any[]; counter?: unknown; iat?: number; exp?: number; aud?: unknown; verb?: string; resource?: string; ver?: unknown; }
interface Built { pc: any; grant: any; holders: Key[]; keys: Key[]; reseal: (mut: (pc: any) => void) => any; sign: (pc: any, k?: Key) => any }
function build(s: Spec = {}): Built {
  const depth = s.depth ?? 1;
  const cavs = s.caveats ?? [[{ type: 'resource_prefix', prefix: 'db/' }], [{ type: 'verb_allow', verbs: ['read', 'write', 'send', 'delete'] }], [{ type: 'note', text: 'leaf' }]];
  const keys = [K.principal, K.agent, K.sub, K.sub2].slice(0, depth + 1);
  let acc: unknown[] = [...cavs[0]!];
  const chain: any[] = [sealHop(null, keys[0]!, keys[1]!.pub, acc)];
  for (let h = 1; h < depth; h++) { acc = [...acc, ...(cavs[h] ?? [])]; chain.push(sealHop(chain[h - 1], keys[h]!, keys[h + 1]!.pub, acc)); }
  const plan = s.plan ?? PLAN;
  const node = plan[s.node ?? 1];
  const cp = pca.commitPlan(plan);
  const iat = s.iat ?? NOW - 1000, exp = s.exp ?? iat + 600_000;
  const pc: any = {
    ver: s.ver ?? 2,
    action: { verb: s.verb ?? node.verb, resource: s.resource ?? node.resource, params_digest: pca.paramsDigest(), reversibility_class: 'reversible' },
    grant_ref: chain[0].id, cap_chain: chain,
    plan: { root: cp.root, inclusion_proof: cp.proofFor(node.id), node_id: node.id, conditions_digest: pca.conditionsDigest(node.pre, node.post) },
    attestation: { quote_digest: '', epoch: 0, model_id: 'unattested', measurement: '', operator: 'unattested' },
    provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
    freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
    counter: s.counter ?? 1, risk_claim: { r: 0, inputs: {} }, aud: s.aud ?? AUD, iat, exp,
  };
  const holder = keys[keys.length - 1]!;
  const sign = (p: any, k: Key = holder) => {
    try { const { sig: _s, threshold: _t, ...body } = P(p); p.sig = pca.b64u(pca.sign(k.sk, pca.thresholdMessage(body))); }
    catch { if (p.sig === undefined) p.sig = pca.b64u(new Uint8Array(64)); } // out-of-profile body: unsignable => leave as is
    return p;
  };
  sign(pc);
  const reseal = (mut: (pc: any) => void) => { const c = clone(pc); mut(c); return sign(c); };
  return { pc, grant: chain[0], holders: keys.slice(1), keys, reseal, sign };
}

// ---------------------------------------------------------------- collection
type Intent = 'accept' | 'reject' | 'either';
interface Pending { category: string; name: string; intent: Intent; kind: 'verify' | 'canon'; raw: string; grant: string; now: number; aud: string }
const PEND: Pending[] = [];
const grantStr = (g: any) => { try { return pca.canonicalizeStrict(P(g)); } catch { return rawText(g); } };
function V(category: string, name: string, intent: Intent, b: Built | { pc: any; grant: any }, o: { raw?: string; now?: number; aud?: string; pc?: any } = {}) {
  PEND.push({ category, name, intent, kind: 'verify', raw: o.raw ?? rawText(o.pc ?? b.pc), grant: grantStr(b.grant), now: o.now ?? NOW, aud: o.aud ?? AUD });
}
function C(category: string, name: string, intent: Intent, raw: string) { PEND.push({ category, name, intent, kind: 'canon', raw, grant: '', now: NOW, aud: AUD }); }

const base = build();
const base2 = build({ depth: 2 });
const base3 = build({ depth: 3 });
const BT = rawText(base.pc);
const G = (b: Built) => b;

// ---- 0. controls
V('control', 'valid-1hop', 'accept', base);
V('control', 'valid-2hop', 'accept', base2);
V('control', 'valid-3hop', 'accept', base3);
V('control', 'valid-trailing-newline', 'accept', base, { raw: BT + '\n' });

// ---- 1. truncated / over-long / empty inputs
V('truncation', 'empty-string', 'reject', base, { raw: '' });
V('truncation', 'whitespace-only', 'reject', base, { raw: ' \n\t ' });
V('truncation', 'open-brace-only', 'reject', base, { raw: '{' });
V('truncation', 'empty-object', 'reject', base, { raw: '{}' });
V('truncation', 'null-literal', 'reject', base, { raw: 'null' });
V('truncation', 'array-top-level', 'reject', base, { raw: '[]' });
V('truncation', 'string-top-level', 'reject', base, { raw: '"x"' });
for (const f of [1, 2, 10, 50, 100, 500, 1000]) V('truncation', `cut-at-${f}`, 'reject', base, { raw: BT.slice(0, f) });
V('truncation', 'cut-last-char', 'reject', base, { raw: BT.slice(0, -1) });
V('truncation', 'cut-mid-string', 'reject', base, { raw: BT.slice(0, BT.indexOf('"sig"') + 10) });
V('truncation', 'cut-mid-escape', 'reject', base, { raw: '{"ver":2,"aud":"a\\u00' });
V('overlong', 'padded-over-1MiB-whitespace', 'reject', base, { raw: BT + ' '.repeat(1_048_576) });
V('overlong', 'exactly-1MiB-valid-padding', 'either', base, { raw: BT + ' '.repeat(1_048_576 - BT.length) });
V('overlong', '1MiB+1-valid-padding', 'reject', base, { raw: BT + ' '.repeat(1_048_577 - BT.length) });
{ const huge = base.reseal((p) => { p.action.resource = 'db/' + 'A'.repeat(1_100_000); }); V('overlong', 'resource-1.1M-chars-resigned', 'reject', base, { pc: huge }); }
{ const big = base.reseal((p) => { p.action.resource = 'db/' + 'A'.repeat(200_000); }); V('overlong', 'resource-200k-chars-resigned', 'either', base, { pc: big }); }
V('overlong', 'aud-100k-chars', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, `"aud":"${'x'.repeat(100_000)}"`) });
V('overlong', 'counter-1000-digits', 'reject', base, { raw: BT.replace('"counter":1', `"counter":${'9'.repeat(1000)}`) });
V('overlong', 'sig-10k-chars', 'reject', base, { raw: BT.replace(/"sig":"[^"]*"\}$/, `"sig":"${'A'.repeat(10_000)}"}`) });

// ---- 2. trailing garbage
for (const [n, t] of [['x', 'x'], ['second-doc', '{}'], ['dup-doc', BT], ['nul', '\u0000'], ['comma', ','], ['close-brace', '}'], ['comment', '//c'], ['block-comment', '/*c*/'], ['zwsp', '​'], ['nbsp', ' '], ['vtab', '\u000b'], ['formfeed', '\f']] as const) V('trailing-garbage', n, n === 'nbsp' || n === 'formfeed' || n === 'vtab' || n === 'zwsp' ? 'reject' : 'reject', base, { raw: BT + t });
V('trailing-garbage', 'leading-whitespace-ok', 'accept', base, { raw: '  \r\n\t' + BT });
V('trailing-garbage', 'leading-bom', 'reject', base, { raw: '﻿' + BT });
V('trailing-garbage', 'leading-comment', 'reject', base, { raw: '/*c*/' + BT });

// ---- 3. duplicate keys / key order
const dupAt = (needle: string, ins: string) => BT.replace(needle, ins + needle);
V('dup-keys', 'dup-ver-first-2-then-3', 'reject', base, { raw: BT.replace('{"ver":2,', '{"ver":2,"ver":3,') });
V('dup-keys', 'dup-ver-3-then-2', 'reject', base, { raw: BT.replace('{"ver":2,', '{"ver":3,"ver":2,') });
V('dup-keys', 'dup-aud-other-then-real', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, `"aud":"evil","aud":"${AUD}"`) });
V('dup-keys', 'dup-aud-real-then-other', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, `"aud":"${AUD}","aud":"evil"`) });
V('dup-keys', 'dup-aud-escaped-key', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, `"aud":"${AUD}","\\u0061ud":"evil"`) });
V('dup-keys', 'dup-sig-bad-then-good', 'reject', base, { raw: BT.replace(/"sig":"([^"]*)"\}$/, `"sig":"${'A'.repeat(86)}","sig":"$1"}`) });
V('dup-keys', 'dup-sig-good-then-bad', 'reject', base, { raw: BT.replace(/"sig":"([^"]*)"\}$/, `"sig":"$1","sig":"${'A'.repeat(86)}"}`) });
V('dup-keys', 'dup-nested-action-verb', 'reject', base, { raw: BT.replace('"verb":"write"', '"verb":"read","verb":"write"') });
V('dup-keys', 'dup-nested-hop-holder', 'reject', base, { raw: BT.replace(/"holder":"([^"]*)"/, '"holder":"$1","holder":"$1"') });
V('dup-keys', 'dup-counter', 'reject', base, { raw: BT.replace('"counter":1', '"counter":1,"counter":1') });
V('dup-keys', 'dup-in-grant-like-caveat', 'reject', base, { raw: BT.replace('"type":"resource_prefix"', '"type":"resource_prefix","type":"resource_prefix"') });
{ // key-order tricks: all must be ACCEPTED (order carries no meaning) except where the order changes the canonical bytes.
  const o = JSON.parse(BT); const rev = Object.fromEntries(Object.entries(o).reverse());
  V('key-order', 'top-level-reversed', 'accept', base, { raw: JSON.stringify(rev) });
  const o2 = JSON.parse(BT); o2.action = Object.fromEntries(Object.entries(o2.action).reverse()); o2.plan = Object.fromEntries(Object.entries(o2.plan).reverse());
  V('key-order', 'nested-reversed', 'accept', base, { raw: JSON.stringify(o2) });
  const o3 = JSON.parse(BT); o3.cap_chain[0] = Object.fromEntries(Object.entries(o3.cap_chain[0]).reverse());
  V('key-order', 'hop-reversed', 'accept', base, { raw: JSON.stringify(o3) });
  const sp = JSON.stringify(JSON.parse(BT), null, 3);
  V('key-order', 'pretty-printed', 'accept', base, { raw: sp });
  V('key-order', 'unicode-escaped-keys', 'accept', base, { raw: BT.replace(/"(ver|aud|iat|exp)"/g, (_m, k: string) => `"\\u00${k.charCodeAt(0).toString(16)}${k.slice(1)}"`) });
}

// ---- 4. JSON number edge cases (in a signed field AND an unsigned position)
const NUMS: [string, Intent][] = [['-0', 'reject'], ['0', 'accept'], ['1e400', 'reject'], ['-1e400', 'reject'], ['1e2', 'reject'], ['1E2', 'reject'], ['1.0', 'reject'], ['1.5', 'reject'], ['01', 'reject'], ['00', 'reject'], ['+1', 'reject'], ['.5', 'reject'], ['5.', 'reject'], ['0x10', 'reject'], ['NaN', 'reject'], ['Infinity', 'reject'], ['-Infinity', 'reject'], ['nan', 'reject'], ['9007199254740991', 'accept'], ['9007199254740992', 'reject'], ['9007199254740993', 'reject'], ['18446744073709551616', 'reject'], ['99999999999999999999999999', 'reject'], ['-1', 'reject'], ['4294967296', 'accept'], ['1e-400', 'reject'], ['0e0', 'reject'], ['1_000', 'reject'], ['1 2', 'reject'], ['٣', 'reject'], ['１', 'reject'], ['true', 'reject'], ['null', 'reject'], ['"1"', 'reject'], ['[1]', 'reject']];
for (const [n, intent] of NUMS) {
  const nm = n.replace(/[^A-Za-z0-9.+-]/g, (ch) => 'u' + ch.codePointAt(0)!.toString(16));
  const p = clone(base.pc); p.counter = lit(n); base.sign(p);
  V('number', `counter=${nm}`, intent, base, { pc: p });
  const q = clone(base.pc); q.iat = lit(n); q.exp = lit(n); // unsigned-position stress: out-of-range freshness
  V('number', `iat-exp=${nm}`, 'reject', base, { pc: base.sign(q) });
  V('number', `ver=${nm}`, 'reject', base, { raw: BT.replace('"ver":2', `"ver":${n}`) });
}
V('number', 'taint-level-NaN-in-provenance', 'reject', base, { pc: base.reseal((p) => { p.provenance.taint_level = lit('NaN'); }) });
V('number', 'risk-r-2pow53+1', 'reject', base, { pc: base.reseal((p) => { p.risk_claim.r = lit('9007199254740993'); }) });
V('number', 'risk-r-1e400', 'reject', base, { pc: base.reseal((p) => { p.risk_claim.r = lit('1e400'); }) });
V('number', 'risk-r-0.1+0.2-form', 'reject', base, { pc: base.reseal((p) => { p.risk_claim.r = lit('0.30000000000000004'); }) });
V('number', 'caveat-n-2pow53+1', 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0].caveats[0].n = lit('9007199254740993'); }) });
for (const n of ['-0', '1e400', '9007199254740993', '1.0', 'NaN']) C('number', `canon:[${n}]`, 'reject', `[${n}]`);
for (const n of ['0', '-1', '0.5', '123456789012345', '9007199254740991']) C('number', `canon:[${n}]`, 'accept', `[${n}]`);
for (const n of ['0.000001', '0.0000001', '1234567890123456', '0.1234567890123456']) C('number', `canon:[${n}]`, 'either', `[${n}]`);

// ---- 5. Unicode in ids / audiences / verbs / resources
const NFC = 'café', NFD = 'café';
{
  const bNFC = build({ aud: NFC });
  V('unicode', 'aud-NFC-matches', 'accept', bNFC, { aud: NFC });
  V('unicode', 'aud-NFD-vs-NFC-context', 'reject', bNFC, { aud: NFD });
  const bNFD = build({ aud: NFD });
  V('unicode', 'aud-NFC-vs-NFD-context', 'reject', bNFD, { aud: NFC });
  V('unicode', 'aud-NFD-matches', 'accept', bNFD, { aud: NFD });
}
for (const [n, a] of [['cyrillic-homoglyph', 'rs-adv'.replace('a', 'а')], ['zero-width-joiner', 'rs‍-adv'], ['zero-width-space', 'rs-adv​'], ['fullwidth', 'ｒｓ－ａｄｖ'], ['trailing-space', 'rs-adv '], ['uppercase', 'RS-ADV'], ['astral', 'rs-adv\u{1F600}'], ['bidi-override', '‮rs-adv'], ['nul', 'rs-adv\u0000'], ['empty', '']] as const)
  V('unicode', `aud-${n}`, 'reject', build({ aud: a }), { aud: AUD });
for (const [n, a] of [['homoglyph-ctx', 'rs-adv'.replace('a', 'а')], ['astral-ctx', 'rs-adv\u{1F600}'], ['zwsp-ctx', 'rs-adv​']] as const)
  V('unicode', `aud-matches-${n}`, 'accept', build({ aud: a }), { aud: a });
V('unicode', 'aud-lone-high-surrogate-escape', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"x\\ud800"') });
V('unicode', 'aud-lone-low-surrogate-escape', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"x\\udc00"') });
V('unicode', 'aud-reversed-surrogate-pair', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"x\\ude00\\ud83d"') });
V('unicode', 'aud-valid-surrogate-pair-escape', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"rs-adv\\ud83d\\ude00"') });
V('unicode', 'aud-U+FFFD', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"rs-adv�"') });
V('unicode', 'aud-noncharacter-FFFF', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"rs-adv￿"') });
V('unicode', 'raw-control-0x01-in-string', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"rs-adv\u0001"') });
V('unicode', 'raw-DEL-in-string-ctx', 'accept', build({ aud: 'rs\u007fadv' }), { aud: 'rs\u007fadv' });
V('unicode', 'escaped-aud-equals-literal', 'accept', base, { raw: BT.replace(`"aud":"${AUD}"`, '"aud":"\\u0072s-adv"') });
for (const [n, s] of [['NFC', NFC], ['NFD', NFD], ['astral', '\u{1F600}'], ['zwj', 'a‍b'], ['rtl', '‮evil'], ['homoglyph', 'dб/t1'], ['combining-only', '́'], ['U+2028', 'a b']] as const) {
  const b = build({ resource: `db/${s}`, plan: PLAN.map((x, i) => (i === 1 ? { ...x, resource: `db/${s}` } : x)) });
  V('unicode', `resource-${n}-in-plan+action`, 'accept', b);
}
V('unicode', 'resource-NFC-action-vs-NFD-plan', 'reject', build({ resource: `db/${NFC}`, plan: PLAN.map((x, i) => (i === 1 ? { ...x, resource: `db/${NFD}` } : x)) }));
V('unicode', 'verb-homoglyph-action-vs-plan', 'reject', build({ verb: 'wrіte' }));
V('unicode', 'verb-case-action-vs-plan', 'reject', build({ verb: 'Write' }));
V('unicode', 'verb-trailing-nul-action-vs-plan', 'reject', build({ verb: 'write\u0000' }));
V('unicode', 'node-id-NFD-in-proof', 'reject', base, { pc: base.reseal((p) => { p.plan.node_id = 'ń' + p.plan.node_id; }) });
{ // lone surrogates / non-BMP in canon cases
  C('unicode', 'canon:lone-high-escape', 'reject', '["\\ud800"]'); C('unicode', 'canon:lone-low-escape', 'reject', '["\\udc00"]');
  C('unicode', 'canon:pair-escape', 'accept', '["\\ud83d\\ude00"]'); C('unicode', 'canon:pair-reversed', 'reject', '["\\ude00\\ud83d"]');
  C('unicode', 'canon:NFC-vs-NFD-differ', 'accept', `["${NFC}","${NFD}"]`); C('unicode', 'canon:bom-prefix', 'reject', '﻿[1]');
  C('unicode', 'canon:key-escaped-dup', 'reject', '{"a":1,"\\u0061":2}'); C('unicode', 'canon:key-order-sort-utf16', 'accept', '{"\\ud83d\\ude00":1,"\\uffff":2,"a":3}');
  C('unicode', 'canon:slash-escape', 'accept', '["\\/"]'); C('unicode', 'canon:bad-escape-\\x', 'reject', '["\\x41"]'); C('unicode', 'canon:bad-escape-\\u12', 'reject', '["\\u12"]');
  C('unicode', 'canon:U+2028-literal', 'accept', '[" "]'); C('unicode', 'canon:DEL-literal', 'accept', '["\u007f"]'); C('unicode', 'canon:raw-newline-in-string', 'reject', '["a\nb"]');
}

// ---- 6. deep nesting / huge arrays (resource exhaustion: must REJECT, never hang/crash)
const nest = (n: number, o = '[', c = ']') => o.repeat(n) + c.repeat(n);
for (const n of [31, 32, 33, 64, 128, 1000, 10_000, 100_000]) {
  C('resource-exhaustion', `canon:array-depth-${n}`, n <= 32 ? 'either' : 'reject', nest(n));
  C('resource-exhaustion', `canon:object-depth-${n}`, n <= 32 ? 'either' : 'reject', '{"a":'.repeat(n) + '1' + '}'.repeat(n));
}
for (const n of [20, 31, 32, 33, 200, 5000, 100_000]) V('resource-exhaustion', `risk-inputs-array-depth-${n}`, n > 30 ? 'reject' : 'either', base, { raw: BT.replace('"inputs":{}', `"inputs":{"x":${nest(n)}}`) });
V('resource-exhaustion', 'unbalanced-open-100k', 'reject', base, { raw: BT.replace('"inputs":{}', `"inputs":{"x":${'['.repeat(100_000)}}`) });
V('resource-exhaustion', 'unbalanced-close-100k', 'reject', base, { raw: BT + ']'.repeat(100_000) });
for (const n of [1000, 50_000, 150_000]) {
  const arr = `[${Array(n).fill('1').join(',')}]`; // <= ~300k chars
  V('resource-exhaustion', `huge-array-${n}-in-unsigned-slot`, 'either', base, { raw: BT.replace('"inputs":{}', `"inputs":{"x":${arr}}`) });
}
V('resource-exhaustion', 'huge-array-600k-elems-over-1MiB', 'reject', base, { raw: BT.replace('"inputs":{}', `"inputs":{"x":[${Array(600_000).fill('1').join(',')}]}`) });
V('resource-exhaustion', 'cap-chain-500-hops-junk', 'reject', base, { pc: base.reseal((p) => { p.cap_chain = Array(500).fill(p.cap_chain[0]); }) });
V('resource-exhaustion', 'cap-chain-5000-hops-junk', 'reject', base, { pc: base.reseal((p) => { p.cap_chain = Array(5000).fill(p.cap_chain[0]); }) });
V('resource-exhaustion', 'caveats-100k-empty-objects', 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0].caveats = Array(100_000).fill({}); }) });
V('resource-exhaustion', 'inclusion-path-100k-steps', 'reject', base, { pc: base.reseal((p) => { p.plan.inclusion_proof.path = Array(100_000).fill(p.plan.inclusion_proof.path[0]); }) });
V('resource-exhaustion', 'object-100k-keys', 'reject', base, { raw: BT.replace('"inputs":{}', `"inputs":{${Array.from({ length: 60_000 }, (_, i) => `"k${i}":1`).join(',')}}`) });
V('resource-exhaustion', 'string-escape-heavy-500k', 'reject', base, { raw: BT.replace(`"aud":"${AUD}"`, `"aud":"${'\\u0041'.repeat(90_000)}"`) });
V('resource-exhaustion', 'quadratic-dup-keys-20k', 'reject', base, { raw: BT.replace('"inputs":{}', `"inputs":{${Array.from({ length: 20_000 }, () => '"k":1').join(',')}}`) });

// ---- 7. base64 / base64url variant confusion
const sigOf = (p: any) => p.sig as string;
const sigB = pca.unb64u(sigOf(base.pc));
const std = Buffer.from(sigB).toString('base64'); // with '=' padding when needed, +/ alphabet
let sigCat = 'base64';
const mutSig = (n: string, s: string, intent: Intent = 'reject') => V(sigCat, `leaf-sig-${n}`, intent, base, { pc: Object.assign(clone(base.pc), { sig: s }) });
mutSig('canonical-control', sigOf(base.pc), 'accept');
mutSig('padded', sigOf(base.pc) + '=='); mutSig('padded-1', sigOf(base.pc) + '=');
mutSig('std-padded', std); mutSig('std-unpadded', std.replace(/=+$/, ''));
mutSig('trailing-newline', sigOf(base.pc) + '\n'); mutSig('leading-space', ' ' + sigOf(base.pc)); mutSig('inner-space', sigOf(base.pc).slice(0, 40) + ' ' + sigOf(base.pc).slice(40));
mutSig('inner-newline', sigOf(base.pc).slice(0, 40) + '\n' + sigOf(base.pc).slice(40)); mutSig('crlf-wrapped', sigOf(base.pc).slice(0, 40) + '\r\n' + sigOf(base.pc).slice(40));
mutSig('mixed-alphabet', sigOf(base.pc).replace(/[-_]/, '+').replace(/[^+]$/, 'A') + '');
mutSig('plus-slash-injected', '+/' + sigOf(base.pc).slice(2));
mutSig('empty', ''); mutSig('one-char', 'A'); mutSig('63-bytes', pca.b64u(sigB.slice(0, 63))); mutSig('65-bytes', pca.b64u(new Uint8Array([...sigB, 0]))); mutSig('32-bytes', pca.b64u(sigB.slice(0, 32)));
mutSig('len-85-chars', sigOf(base.pc).slice(0, 85)); mutSig('len-87-chars', sigOf(base.pc) + 'A');
mutSig('noncanonical-last-char', sigOf(base.pc).slice(0, 85) + (sigOf(base.pc)[85] === 'A' ? 'B' : 'A'));
mutSig('fullwidth-chars', 'Ａ' + sigOf(base.pc).slice(1)); mutSig('nul-inside', sigOf(base.pc).slice(0, 10) + '\u0000' + sigOf(base.pc).slice(11));
mutSig('number', lit('12345') as any); mutSig('null', null as any); mutSig('array', [sigOf(base.pc)] as any); mutSig('object', { v: sigOf(base.pc) } as any);
for (const f of ['issuer', 'holder', 'id', 'body_digest', 'sig']) {
  V('base64', `hop-${f}-padded`, 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0][f] += '='; }) });
  V('base64', `hop-${f}-std-alphabet`, 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0][f] = Buffer.from(pca.unb64u(p.cap_chain[0][f])).toString('base64'); }) });
  V('base64', `hop-${f}-whitespace`, 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0][f] = ' ' + p.cap_chain[0][f]; }) });
}
V('base64', 'grant_ref-padded', 'reject', base, { pc: base.reseal((p) => { p.grant_ref += '='; }) });
V('base64', 'plan-root-padded', 'reject', base, { pc: base.reseal((p) => { p.plan.root += '='; }) });
V('base64', 'plan-root-uppercased', 'reject', base, { pc: base.reseal((p) => { p.plan.root = p.plan.root.toUpperCase(); }) });
V('base64', 'proof-sibling-padded', 'reject', base, { pc: base.reseal((p) => { p.plan.inclusion_proof.path[0].hash += '='; }) });
V('base64', 'params_digest-padded', 'reject', base, { pc: base.reseal((p) => { p.action.params_digest += '='; }) });
V('base64', 'conditions_digest-std-alphabet', 'reject', base, { pc: base.reseal((p) => { p.plan.conditions_digest = Buffer.from(pca.unb64u(p.plan.conditions_digest)).toString('base64') + '='; }) });
for (const [n, s] of [['padded', 'AA=='], ['std', '+/+/'], ['ws', 'AA AA'], ['ok', 'AAAA'], ['nc-tail', 'AAB'], ['empty', ''], ['url', '-_-_']] as const) C('base64', `canon-string:${n}`, 'accept', JSON.stringify([s]));

// ---- 8. signature malleability / wrong length
const sB = (b: Uint8Array) => { let v = 0n; for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[32 + i]!); return v; };
const toLE = (v: bigint) => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
{
  sigCat = 'sig-malleability';
  const s = sB(sigB); const hi = s + L;
  const mall = new Uint8Array(sigB); if (hi < (1n << 256n)) mall.set(toLE(hi), 32);
  mutSig('S+L-malleable', pca.b64u(mall)); // high-S / non-canonical s: strict verifiers must reject
  const mall2 = new Uint8Array(sigB); mall2.set(toLE(s + 2n * L < (1n << 256n) ? s + 2n * L : s), 32); mutSig('S+2L', pca.b64u(mall2));
  const sFF = new Uint8Array(sigB); sFF.fill(0xff, 32); mutSig('S-all-ff', pca.b64u(sFF));
  const sL = new Uint8Array(sigB); sL.set(toLE(L), 32); mutSig('S-equals-L', pca.b64u(sL));
  const s0 = new Uint8Array(sigB); s0.fill(0, 32); mutSig('S-zero', pca.b64u(s0));
  const r0 = new Uint8Array(sigB); r0.fill(0, 0, 32); mutSig('R-zero', pca.b64u(r0));
  const rid = new Uint8Array(sigB); rid.fill(0, 0, 32); rid[0] = 1; mutSig('R-identity-point', pca.b64u(rid));
  const rhi = new Uint8Array(sigB); rhi[31] |= 0x80; mutSig('R-sign-bit-flipped', pca.b64u(rhi));
  const rff = new Uint8Array(sigB); rff.fill(0xff, 0, 32); mutSig('R-all-ff-noncanonical-y', pca.b64u(rff));
  mutSig('all-zero-64', pca.b64u(new Uint8Array(64))); mutSig('all-ff-64', pca.b64u(new Uint8Array(64).fill(0xff)));
  const swapped = new Uint8Array(64); swapped.set(sigB.slice(32), 0); swapped.set(sigB.slice(0, 32), 32); mutSig('R-S-swapped', pca.b64u(swapped));
  for (const bit of [0, 7, 255, 256, 511]) { const f = new Uint8Array(sigB); f[bit >> 3] ^= 1 << (bit & 7); mutSig(`bitflip-${bit}`, pca.b64u(f)); }
  // same S+L trick on a delegation hop
  const hopS = pca.unb64u(base.pc.cap_chain[0].sig); const hm = new Uint8Array(hopS); const hs = sB(hopS); if (hs + L < (1n << 256n)) hm.set(toLE(hs + L), 32);
  V('sig-malleability', 'hop-sig-S+L', 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0].sig = pca.b64u(hm); }) });
  V('sig-malleability', 'hop-sig-63-bytes', 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0].sig = pca.b64u(hopS.slice(0, 63)); }) });
  V('sig-malleability', 'hop-sig-65-bytes', 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0].sig = pca.b64u(new Uint8Array([...hopS, 0])); }) });
  V('sig-malleability', 'leaf-signed-by-rogue', 'reject', base, { pc: base.sign(clone(base.pc), K.rogue) });
  V('sig-malleability', 'leaf-signed-by-delegator-not-holder', 'reject', base2, { pc: base2.sign(clone(base2.pc), K.agent) });
  V('sig-malleability', 'hop-signed-by-holder-not-issuer', 'reject', base, { pc: base.reseal((p) => { p.cap_chain[0] = sealHop(null, K.principal, K.agent.pub, p.cap_chain[0].caveats, K.agent); }) });
}

// ---- 9. algorithm / suite downgrade + confusion
{
  const edPk = base.holders[base.holders.length - 1]!.pub;
  const setAlg = (n: string, f: (p: any) => void, intent: Intent = 'reject') => V('alg-confusion', n, intent, base, { pc: base.reseal(f) });
  for (const a of ['none', 'None', 'NONE', '', 'ed25519', 'Ed25519', 'ED25519', 'EdDSA', 'ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-65', 'rsa', 'HS256', 'ed25519 ', 'ed25519\u0000', 'hybrid-ed25519-ml-dsa-99'])
    setAlg(`alg=${JSON.stringify(a)}-only`, (p) => { p.alg = a; }, a === 'ed25519' ? 'either' : 'reject');
  setAlg('alg-null', (p) => { p.alg = null; }); setAlg('alg-number', (p) => { p.alg = 0; }); setAlg('alg-array', (p) => { p.alg = ['ed25519']; });
  setAlg('alg-none-with-sig-stripped', (p) => { p.alg = 'none'; delete p.sig; });
  setAlg('alg-none-with-empty-sig', (p) => { p.alg = 'none'; p.sig = ''; });
  setAlg('ed25519-key-presented-as-ml-dsa-65', (p) => { p.alg = 'ml-dsa-65'; p.pq_pk = edPk; });
  setAlg('ed25519-key+sig-presented-as-ml-dsa-65', (p) => { p.alg = 'ml-dsa-65'; p.pq_pk = edPk; p.pq_sig = p.sig; });
  setAlg('ed25519-key-presented-as-hybrid', (p) => { p.alg = 'hybrid-ed25519-ml-dsa-65'; p.pq_pk = edPk; p.pq_sig = p.sig; });
  setAlg('hybrid-with-pq-sig-stripped', (p) => { p.alg = 'hybrid-ed25519-ml-dsa-65'; p.pq_pk = edPk; });
  setAlg('hybrid-with-pq-pk-stripped', (p) => { p.alg = 'hybrid-ed25519-ml-dsa-65'; p.pq_sig = p.sig; });
  setAlg('ed25519-with-stray-pq_pk', (p) => { p.alg = 'ed25519'; p.pq_pk = edPk; });
  setAlg('ed25519-with-stray-pq_sig', (p) => { p.alg = 'ed25519'; p.pq_sig = p.sig; });
  setAlg('no-alg-with-stray-pq_sig', (p) => { p.pq_sig = p.sig; });
  setAlg('no-alg-with-stray-pq_pk', (p) => { p.pq_pk = edPk; });
  setAlg('pq-sig-empty-string', (p) => { p.alg = 'ml-dsa-65'; p.pq_pk = edPk; p.pq_sig = ''; });
  setAlg('pq-sig-huge-100k', (p) => { p.alg = 'ml-dsa-65'; p.pq_pk = edPk; p.pq_sig = 'A'.repeat(100_000); });
  setAlg('hop-alg-none', (p) => { p.cap_chain[0].alg = 'none'; });
  setAlg('hop-alg-ml-dsa-65-ed25519-keys', (p) => { p.cap_chain[0].alg = 'ml-dsa-65'; p.cap_chain[0].pq_pk = edPk; });
  setAlg('hop-pq_sig-stray', (p) => { p.cap_chain[0].pq_sig = p.cap_chain[0].sig; });
  setAlg('alg-case-trick-key', (p) => { p.ALG = 'none'; });
  setAlg('suite-key-instead-of-alg', (p) => { p.suite = 'none'; });
  // Real PQ vectors from the shared golden corpus, then downgraded / mismatched.
  const gold = JSON.parse(readFileSync(join(HERE, '../../pca/conformance/vectors.json'), 'utf8'));
  const gv = (n: string) => gold.vectors.find((v: any) => v.name === n);
  const hyb = gv('pq-leaf-hybrid-ed25519-ml-dsa-65-valid'), pure = gv('pq-leaf-ml-dsa-65-valid'), hyb87 = gv('pq-leaf-hybrid-ed25519-ml-dsa-87-valid');
  const gctx = (v: any) => ({ now: v.context.now, aud: v.context.aud });
  const GV = (name: string, intent: Intent, v: any, f: (p: any) => void) => { const p = clone(v.pcactn); f(p); V('suite-downgrade', name, intent, { pc: p, grant: v.grant }, { pc: p, ...gctx(v) }); };
  if (hyb && pure && hyb87) {
    GV('hybrid-pq_sig-stripped', 'reject', hyb, (p) => { delete p.pq_sig; });
    GV('hybrid-ed-sig-stripped', 'reject', hyb, (p) => { delete p.sig; });
    GV('hybrid-pq_pk-stripped', 'reject', hyb, (p) => { delete p.pq_pk; });
    GV('hybrid-alg-downgraded-to-ed25519', 'reject', hyb, (p) => { p.alg = 'ed25519'; });
    GV('hybrid-alg-removed', 'reject', hyb, (p) => { delete p.alg; });
    GV('hybrid-alg-none', 'reject', hyb, (p) => { p.alg = 'none'; });
    GV('hybrid-alg-relabelled-pure-ml-dsa-65', 'reject', hyb, (p) => { p.alg = 'ml-dsa-65'; });
    GV('hybrid-alg-relabelled-ml-dsa-87-suite', 'reject', hyb, (p) => { p.alg = 'hybrid-ed25519-ml-dsa-87'; });
    GV('hybrid-pq_sig-swapped-from-pure-vector', 'reject', hyb, (p) => { p.pq_sig = pure.pcactn.pq_sig; });
    GV('hybrid-pq_sig-swapped-from-87-vector', 'reject', hyb, (p) => { p.pq_sig = hyb87.pcactn.pq_sig; });
    GV('hybrid-ed-sig-zeroed', 'reject', hyb, (p) => { p.sig = pca.b64u(new Uint8Array(64)); });
    GV('hybrid-pq_sig-zeroed', 'reject', hyb, (p) => { p.pq_sig = pca.b64u(new Uint8Array(pca.unb64u(p.pq_sig).length)); });
    GV('hybrid-pq_sig-truncated', 'reject', hyb, (p) => { p.pq_sig = p.pq_sig.slice(0, -4); });
    GV('hybrid-pq_sig-extended', 'reject', hyb, (p) => { p.pq_sig += 'AAAA'; });
    GV('hybrid-pq_sig-bitflip', 'reject', hyb, (p) => { const b = pca.unb64u(p.pq_sig); b[10] ^= 1; p.pq_sig = pca.b64u(b); });
    GV('hybrid-pq_pk-truncated', 'reject', hyb, (p) => { p.pq_pk = p.pq_pk.slice(0, -4); });
    GV('hybrid-body-tampered-after-sign', 'reject', hyb, (p) => { p.counter += 1; });
    GV('hybrid-pq_sig-in-sig-slot', 'reject', hyb, (p) => { p.sig = p.pq_sig; });
    GV('hybrid-sig-in-pq_sig-slot', 'reject', hyb, (p) => { p.pq_sig = p.sig; });
    GV('pure-mldsa-with-stray-ed-pk-in-pq_pk-slot', 'reject', pure, (p) => { p.pq_pk = base.holders[0]!.pub; });
    GV('pure-mldsa-sig-bitflip', 'reject', pure, (p) => { const b = pca.unb64u(p.sig); b[5] ^= 1; p.sig = pca.b64u(b); });
    GV('pure-mldsa-alg-relabelled-hybrid', 'reject', pure, (p) => { p.alg = 'hybrid-ed25519-ml-dsa-65'; });
    GV('pure-mldsa-alg-none', 'reject', pure, (p) => { p.alg = 'none'; });
    GV('pure-mldsa-alg-ed25519', 'reject', pure, (p) => { p.alg = 'ed25519'; });
  }
}

// ---- 10. field injection / prototype pollution shapes
{
  const add = (n: string, f: (p: any) => void, intent: Intent = 'reject') => V('field-injection', n, intent, base, { pc: base.reseal(f) });
  const addRaw = (n: string, ins: string, intent: Intent = 'reject') => V('field-injection', n, intent, base, { raw: BT.replace(/^\{/, `{${ins},`) });
  add('unknown-top-level-field', (p) => { p.extra = 1; });
  add('unknown-top-level-null', (p) => { p.extra = null; });
  for (const k of ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty', 'valueOf', '__defineGetter__', '__lookupGetter__']) addRaw(`top-level-key-${k}`, `"${k}":{"polluted":true}`);
  addRaw('proto-with-allow-true', '"__proto__":{"allow":true}');
  addRaw('proto-null', '"__proto__":null');
  addRaw('proto-string', '"__proto__":"x"');
  addRaw('constructor-prototype-chain', '"constructor":{"prototype":{"allow":true}}');
  addRaw('dollar-ref', '"$ref":"#"'); addRaw('at-type', '"@type":"x"'); addRaw('empty-key', '"":1'); addRaw('nul-key', '"\\u0000":1'); addRaw('long-key-10k', `"${'k'.repeat(10_000)}":1`);
  add('nested-action-extra', (p) => { p.action.extra = 1; }, 'either');
  add('nested-plan-extra', (p) => { p.plan.extra = 1; }, 'either');
  add('nested-proto-in-action', (p) => { Object.defineProperty(p.action, '__proto__', { value: { polluted: 1 }, enumerable: true, writable: true, configurable: true }); }, 'either');
  V('field-injection', 'proto-in-caveat-signed', 'either', base, { pc: base.reseal((p) => { p.cap_chain[0].caveats[0] = JSON.parse('{"type":"x","__proto__":{"polluted":1}}'); }) });
  V('field-injection', 'proto-key-in-risk-inputs-signed', 'either', base, { pc: base.reseal((p) => { p.risk_claim.inputs = JSON.parse('{"__proto__":{"a":1},"constructor":2}'); }) });
  V('field-injection', 'proto-key-in-risk-inputs-raw', 'either', base, { raw: BT.replace('"inputs":{}', '"inputs":{"__proto__":{"a":1}}') });
  for (const k of ['aud', 'sig', 'cap_chain', 'plan', 'action', 'counter', 'exp', 'iat', 'ver', 'grant_ref']) {
    if (k === 'sig') { const m = clone(base.pc); delete m.sig; V('field-injection', 'missing-sig', 'reject', base, { pc: m }); const n = clone(base.pc); n.sig = null; V('field-injection', 'null-sig', 'reject', base, { pc: n }); continue; }
    add(`missing-${k}`, (p) => { delete p[k]; }); add(`null-${k}`, (p) => { p[k] = null; });
  }
  add('type-swap-aud-array', (p) => { p.aud = [AUD]; }); add('type-swap-aud-object', (p) => { p.aud = { v: AUD }; }); add('type-swap-cap_chain-object', (p) => { p.cap_chain = { 0: p.cap_chain[0] }; });
  add('type-swap-plan-array', (p) => { p.plan = [p.plan]; }); add('type-swap-counter-string', (p) => { p.counter = '1'; }); add('type-swap-ver-string', (p) => { p.ver = '2'; }); add('type-swap-ver-true', (p) => { p.ver = true; });
  add('type-swap-attestation-null', (p) => { p.attestation = null; }); add('type-swap-risk_claim-array', (p) => { p.risk_claim = []; }); add('type-swap-provenance-string', (p) => { p.provenance = 'x'; });
  add('threshold-container-valid-shape', (p) => { p.threshold = { shares: [] }; }, 'either');
  add('threshold-container-proto', (p) => { p.threshold = JSON.parse('{"__proto__":{"x":1}}'); }, 'either');
  add('threshold-container-garbage', (p) => { p.threshold = 'x'; }, 'either');
}

// ---- 11. attenuation widening (all hops validly signed => only attenuation logic can catch)
{
  const c0 = [{ type: 'resource_prefix', prefix: 'db/' }], c1 = [{ type: 'verb_allow', verbs: ['read'] }];
  const mkChain = (hop2caveats: (parent: unknown[]) => unknown[], name: string, intent: Intent) => {
    const b = build({ depth: 2 });
    const h0 = b.pc.cap_chain[0];
    const h1 = sealHop(h0, K.agent, K.sub.pub, hop2caveats(clone(h0.caveats)), K.agent);
    V('attenuation', name, intent, b, { pc: b.reseal((p) => { p.cap_chain[1] = h1; }) });
  };
  mkChain((c) => [...c, { type: 'note' }], 'append-caveat-ok', 'accept');
  mkChain((c) => c, 'identical-caveats-ok', 'either');
  mkChain((c) => [], 'empty-caveats-widen', 'reject');
  mkChain((c) => c.slice(1), 'drop-first-caveat', 'reject');
  mkChain((c) => [{ type: 'allow_all' }], 'replace-with-allow-all', 'reject');
  mkChain((c) => [{ ...(c[0] as object), prefix: '' }, ...c.slice(1)], 'edit-prefix-to-empty', 'reject');
  mkChain((c) => [{ ...(c[0] as object), prefix: '/' }, ...c.slice(1)], 'edit-prefix-to-root', 'reject');
  mkChain((c) => [{ ...(c[0] as object), extra: 1 }, ...c.slice(1)], 'add-key-to-parent-caveat', 'reject');
  mkChain((c) => [...c, ...c], 'duplicate-parent-caveats-appended', 'either');
  mkChain((c) => [...c, c[0]], 'dup-first-caveat-appended', 'either');
  mkChain((c) => [c[0]!, c[0]!], 'dup-first-only', 'accept');
  mkChain((c) => [...c].reverse(), 'reordered-single-noop', 'either');
  mkChain((c) => c.map((x: any) => ({ type: x.type })), 'strip-caveat-params', 'reject');
  mkChain((c) => [...c, null], 'append-null-caveat', 'reject');
  mkChain((c) => [...c, 'x'], 'append-string-caveat', 'reject');
  mkChain((c) => [...c, {}], 'append-typeless-caveat', 'reject');
  mkChain((c) => [...c, { type: 5 }], 'append-nonstring-type', 'reject');
  mkChain((c) => [...c, [] as unknown], 'append-array-caveat', 'reject');
  const b3 = build({ depth: 3 });
  { // skip-level widening: hop 3 forgets hop 2's caveats but keeps hop 1's
    const h2 = b3.pc.cap_chain[1];
    V('attenuation', 'three-hop-forget-middle-caveats', 'reject', b3, { pc: b3.reseal((p) => { p.cap_chain[2] = sealHop(h2, K.sub, K.sub.pub, p.cap_chain[0].caveats, K.sub); }) });
  }
  V('attenuation', 'action-outside-resource_prefix-caveat', 'either', base, { pc: build({ resource: 'other/x', plan: PLAN.map((x, i) => (i === 1 ? { ...x, resource: 'other/x' } : x)) }).pc, });
  void c0; void c1;
}

// ---- 12. plan / commitment hash mismatches
{
  const add = (n: string, f: (p: any) => void, intent: Intent = 'reject') => V('plan-commit', n, intent, base, { pc: base.reseal(f) });
  add('root-flipped', (p) => { p.plan.root = pca.paramsDigest({ x: 1 }); });
  add('root-zero-hash', (p) => { p.plan.root = pca.b64u(new Uint8Array(32)); });
  add('root-empty', (p) => { p.plan.root = ''; });
  add('node_id-other-leaf', (p) => { p.plan.node_id = 'n2'; });
  add('node_id-unknown', (p) => { p.plan.node_id = 'zzz'; });
  add('node_id-empty', (p) => { p.plan.node_id = ''; });
  add('conditions_digest-other', (p) => { p.plan.conditions_digest = pca.conditionsDigest({ a: 1 }, {}); });
  add('conditions_digest-empty-string', (p) => { p.plan.conditions_digest = ''; });
  add('action-verb-not-in-plan', (p) => { p.action.verb = 'drop'; });
  add('action-resource-not-in-plan', (p) => { p.action.resource = 'db/other'; });
  add('action-params_digest-other', (p) => { p.action.params_digest = pca.paramsDigest({ q: 1 }); });
  add('action-params_digest-empty', (p) => { p.action.params_digest = ''; });
  add('action-reversibility-changed', (p) => { p.action.reversibility_class = 'irreversible'; });
  add('grant_ref-other', (p) => { p.grant_ref = pca.paramsDigest({ g: 1 }); });
  add('grant_ref-empty', (p) => { p.grant_ref = ''; });
  add('grant_ref-leaf-id-not-root', (p) => { p.grant_ref = p.cap_chain[p.cap_chain.length - 1].id; }, 'either');
  add('inclusion-index-negative', (p) => { p.plan.inclusion_proof.index = -1; });
  add('inclusion-index-huge', (p) => { p.plan.inclusion_proof.index = 2 ** 40; });
  add('inclusion-size-zero', (p) => { p.plan.inclusion_proof.size = 0; });
  add('inclusion-size-mismatch', (p) => { p.plan.inclusion_proof.size = 5; });
  add('inclusion-path-empty', (p) => { p.plan.inclusion_proof.path = []; });
  add('inclusion-proof-null', (p) => { p.plan.inclusion_proof = null; });
  add('inclusion-proof-from-other-plan', (p) => { const o = pca.commitPlan(PLAN.slice(0, 3).map((n, i) => ({ ...n, id: `m${i}` }))); p.plan.inclusion_proof = o.proofFor('m1'); });
  V('plan-commit', 'singleton-plan-valid', 'accept', build({ plan: [PLAN[0]], node: 0 }));
  V('plan-commit', 'second-preimage-leaf-as-inner-node', 'reject', base, { pc: base.reseal((p) => { const pr = p.plan.inclusion_proof; p.plan.root = pr.path[0].hash; p.plan.inclusion_proof = { ...pr, index: 0, size: 2, path: pr.path.slice(1) }; }) });
  V('plan-commit', 'plan-of-2-odd-node-duplicate-ambiguity', 'accept', build({ plan: PLAN.slice(0, 3), node: 2 }));
}

// ---- 12b. grant_ref binding (check `grant_ref_bound`): the signed grant_ref MUST equal cap_chain[0].id exactly
{
  const G = 'grant-ref-bound';
  const rid = (b: Built): string => b.pc.cap_chain[0].id;
  const flipCase = (id: string): string => { const i = [...id].findIndex((ch, k) => k < 40 && /[A-Za-z]/.test(ch)); const ch = id[i]!; return id.slice(0, i) + (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()) + id.slice(i + 1); };
  const freshRef = pca.paramsDigest({ fresh: 'grant_ref' });
  V(G, 'positive-depth-1', 'accept', base);
  V(G, 'positive-depth-2-root-id', 'accept', base2);
  V(G, 'positive-depth-3-root-id', 'accept', base3);
  for (const [tag, b] of [['depth-1', base], ['depth-2', base2], ['depth-3', base3]] as const) {
    V(G, `mismatch-fresh-value-resigned-${tag}`, 'reject', b, { pc: b.reseal((p) => { p.grant_ref = freshRef; }) });
    V(G, `mismatch-fresh-value-not-resigned-${tag}`, 'reject', b, { pc: (() => { const c = clone(b.pc); c.grant_ref = freshRef; return c; })() });
  }
  V(G, 'fresh-namespace-1', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = pca.paramsDigest({ ns: 1 }); }) });
  V(G, 'fresh-namespace-2', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = pca.paramsDigest({ ns: 2 }); }) });
  V(G, 'equals-middle-hop-id-depth-3', 'reject', base3, { pc: base3.reseal((p) => { p.grant_ref = p.cap_chain[1].id; }) });
  V(G, 'equals-leaf-hop-id-depth-2', 'reject', base2, { pc: base2.reseal((p) => { p.grant_ref = p.cap_chain[1].id; }) });
  V(G, 'equals-leaf-hop-id-depth-3', 'reject', base3, { pc: base3.reseal((p) => { p.grant_ref = p.cap_chain[2].id; }) });
  V(G, 'equals-parent-hash-of-hop-1', 'reject', base2, { pc: base2.reseal((p) => { p.grant_ref = p.cap_chain[1].parent; }) });
  V(G, 'equals-leaf-holder-key', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = p.cap_chain[p.cap_chain.length - 1].holder; }) });
  V(G, 'equals-leaf-holder-key-depth-2', 'reject', base2, { pc: base2.reseal((p) => { p.grant_ref = p.cap_chain[1].holder; }) });
  V(G, 'equals-grant-issuer-key', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = p.cap_chain[0].issuer; }) });
  V(G, 'equals-plan-root', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = p.plan.root; }) });
  V(G, 'equals-params-digest', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = p.action.params_digest; }) });
  V(G, 'case-variant-of-root-id', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = flipCase(rid(base)); }) });
  V(G, 'case-variant-of-root-id-depth-2', 'reject', base2, { pc: base2.reseal((p) => { p.grant_ref = flipCase(rid(base2)); }) });
  V(G, 'empty-string', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = ''; }) });
  V(G, 'absent', 'reject', base, { pc: base.reseal((p) => { delete p.grant_ref; }) });
  V(G, 'null', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = null; }) });
  V(G, 'number', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = 0; }) });
  V(G, 'array-of-root-id', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = [rid(base)]; }) });
  V(G, 'object-wrapping-root-id', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = { id: rid(base) }; }) });
  V(G, 'whitespace-trailing-space', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + ' '; }) });
  V(G, 'whitespace-leading-space', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = ' ' + rid(base); }) });
  V(G, 'whitespace-trailing-newline', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + '\n'; }) });
  V(G, 'whitespace-leading-tab', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = '\t' + rid(base); }) });
  V(G, 'whitespace-only', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = ' '.repeat(43); }) });
  V(G, 'nul-appended', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + '\u0000'; }) });
  V(G, 'unicode-cyrillic-lookalike-first-char', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = 'а' + rid(base).slice(1); }) });
  V(G, 'unicode-fullwidth-first-char', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = 'Ａ' + rid(base).slice(1); }) });
  V(G, 'unicode-zero-width-space-appended', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + '​'; }) });
  V(G, 'unicode-zero-width-joiner-inserted', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base).slice(0, 20) + '‍' + rid(base).slice(20); }) });
  V(G, 'unicode-nbsp-appended', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + ' '; }) });
  V(G, 'unicode-nfd-combining-mark', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base).slice(0, 1) + '́' + rid(base).slice(1); }) });
  V(G, 'unicode-bidi-override-wrapped', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = '‮' + rid(base) + '‬'; }) });
  V(G, 'padded-with-equals', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + '='; }) });
  V(G, 'standard-base64-alphabet', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base).replace(/-/g, '+').replace(/_/g, '/') + 'A'; }) });
  V(G, 'truncated-by-one', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base).slice(0, -1); }) });
  V(G, 'doubled-root-id', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base) + rid(base); }) });
  V(G, 'very-long-4096', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = 'A'.repeat(4096); }) });
  V(G, 'very-long-65536', 'reject', base, { pc: base.reseal((p) => { p.grant_ref = rid(base).repeat(1500); }) });
  V(G, 'empty-chain-grant_ref-set', 'reject', base, { pc: base.reseal((p) => { p.cap_chain = []; }) });
  V(G, 'empty-chain-grant_ref-empty', 'reject', base, { pc: base.reseal((p) => { p.cap_chain = []; p.grant_ref = ''; }) });
  V(G, 'chain-not-array-null', 'reject', base, { pc: base.reseal((p) => { p.cap_chain = null; }) });
  V(G, 'chain-root-replaced-by-leaf-keeps-root-ref', 'reject', base2, { pc: base2.reseal((p) => { p.cap_chain = [p.cap_chain[1]]; }) });
  V(G, 'chain-hops-reordered-grant_ref-root', 'reject', base2, { pc: base2.reseal((p) => { p.cap_chain = [p.cap_chain[1], p.cap_chain[0]]; }) });
  V(G, 'chain-hops-reordered-grant_ref-follows-first', 'reject', base2, { pc: base2.reseal((p) => { p.cap_chain = [p.cap_chain[1], p.cap_chain[0]]; p.grant_ref = p.cap_chain[0].id; }) });
}

// ---- 13. epoch / expiry boundaries (context now = NOW)
{
  const T = (n: string, iat: number, exp: number, intent: Intent, now = NOW) => V('epoch', n, intent, build({ iat, exp }), { now });
  T('now==exp', NOW - 1000, NOW, 'accept'); T('now==exp+1', NOW - 1000, NOW - 1, 'reject'); T('now==exp-1', NOW - 1000, NOW + 1, 'accept');
  T('iat==now', NOW, NOW + 1000, 'accept'); T('iat==now+60000', NOW + 60_000, NOW + 70_000, 'accept'); T('iat==now+60001', NOW + 60_001, NOW + 70_000, 'reject');
  T('lifetime==3600000', NOW - 1000, NOW - 1000 + 3_600_000, 'accept'); T('lifetime==3600001', NOW - 1000, NOW - 1000 + 3_600_001, 'reject');
  T('exp==iat', NOW - 1000, NOW - 1000, 'reject', NOW - 1000); T('exp<iat', NOW, NOW - 1, 'reject'); T('iat==0', 0, 1000, 'reject'); T('exp==0', 0, 0, 'reject');
  T('iat-negative', -5, 1000, 'reject'); T('exp-2^53-1', NOW - 1000, 2 ** 53 - 1, 'reject'); T('iat-in-seconds', Math.floor(NOW / 1000) - 1, Math.floor(NOW / 1000) + 600, 'reject');
  T('exp-in-seconds', NOW - 1000, Math.floor(NOW / 1000) + 600, 'reject');
  T('now-0-ctx', NOW - 1000, NOW - 400_000, 'reject', 0); T('now-negative-ctx', NOW - 1000, NOW + 1000, 'reject', -1);
  T('now-2^53-1-ctx', NOW - 1000, NOW + 1000, 'reject', 2 ** 53 - 1);
  T('far-future-both', 4_102_444_800_000, 4_102_445_400_000, 'reject');
  const bi = build({ iat: NOW - 1000, exp: NOW + 1000 });
  V('epoch', 'iat-as-string', 'reject', bi, { pc: bi.reseal((p) => { p.iat = String(NOW - 1000); }) });
  V('epoch', 'exp-as-float-literal', 'reject', bi, { pc: bi.reseal((p) => { p.exp = lit(`${NOW + 1000}.0`); }) });
  V('epoch', 'exp-as-exponent-literal', 'reject', bi, { pc: bi.reseal((p) => { p.exp = lit('1.800000001e12'); }) });
  V('epoch', 'attestation-epoch-negative', 'either', bi, { pc: bi.reseal((p) => { p.attestation.epoch = -1; }) });
  V('epoch', 'freshness-epoch-2^53', 'reject', bi, { pc: bi.reseal((p) => { p.freshness.epoch = lit('9007199254740992'); }) });
  V('epoch', 'counter-0', 'accept', build({ counter: 0 })); V('epoch', 'counter-2^53-1', 'accept', build({ counter: 2 ** 53 - 1 }));
  V('epoch', 'counter-negative', 'reject', build({ counter: -1 }));
}

// ---- 14. empty / duplicated caveat lists
{
  const c = (n: string, caveats: unknown[][], intent: Intent, depth: 1 | 2 | 3 = 1) => V('caveat-lists', n, intent, build({ depth, caveats }));
  c('root-empty-caveats', [[]], 'accept');
  c('root-dup-caveats', [[{ type: 'note' }, { type: 'note' }]], 'accept');
  c('root-many-identical-1000', [Array(1000).fill({ type: 'note' })], 'accept');
  c('root-caveat-empty-object', [[{}]], 'reject');
  c('root-caveat-null', [[null]], 'reject');
  c('root-caveat-type-empty-string', [[{ type: '' }]], 'either');
  c('2hop-empty-then-empty', [[], []], 'accept', 2);
  c('2hop-nonempty-then-empty-extension', [[{ type: 'note' }], []], 'accept', 2);
  c('3hop-all-empty', [[], [], []], 'accept', 3);
  const b = build();
  V('caveat-lists', 'caveats-missing', 'reject', b, { pc: b.reseal((p) => { delete p.cap_chain[0].caveats; }) });
  V('caveat-lists', 'caveats-null', 'reject', b, { pc: b.reseal((p) => { p.cap_chain[0].caveats = null; }) });
  V('caveat-lists', 'caveats-object', 'reject', b, { pc: b.reseal((p) => { p.cap_chain[0].caveats = {}; }) });
  V('caveat-lists', 'caveats-string', 'reject', b, { pc: b.reseal((p) => { p.cap_chain[0].caveats = '[]'; }) });
  V('caveat-lists', 'caveats-appended-unsigned', 'reject', b, { pc: b.reseal((p) => { p.cap_chain[0].caveats.push({ type: 'x' }); }) });
  V('caveat-lists', 'caveats-emptied-unsigned', 'reject', b, { pc: b.reseal((p) => { p.cap_chain[0].caveats = []; }) });
  V('caveat-lists', 'cap_chain-empty', 'reject', b, { pc: b.reseal((p) => { p.cap_chain = []; }) });
  V('caveat-lists', 'cap_chain-duplicated-root', 'reject', b, { pc: b.reseal((p) => { p.cap_chain = [p.cap_chain[0], p.cap_chain[0]]; }) });
  V('caveat-lists', 'cap_chain-17-hops', 'reject', b, { pc: b.reseal((p) => { p.cap_chain = Array(17).fill(p.cap_chain[0]); }) });
}

// ---- 15. golden primitives from the shared corpus (strict JSON profile + canonical + base64url)
{
  const gold = JSON.parse(readFileSync(join(HERE, '../../pca/conformance/vectors.json'), 'utf8'));
  gold.primitives.json_parse.forEach((j: any, i: number) => C('golden-json', `json_parse[${i}]`, j.accept ? 'accept' : 'reject', j.input));
  for (const v of gold.vectors) {
    if (v.requires) continue;
    const raw = v.pcactn_json ?? JSON.stringify(v.pcactn);
    PEND.push({ category: 'golden', name: v.name, intent: v.expect.allow ? 'accept' : 'reject', kind: 'verify', raw, grant: JSON.stringify(v.grant), now: v.context.now, aud: v.context.aud });
  }
}

// ---------------------------------------------------------------- emit
async function main() {
  const seen = new Set<string>();
  const lines: string[] = [];
  const full: string[] = [];
  let deviates = 0;
  for (const [i, p] of PEND.entries()) {
    const id = `adv${String(i).padStart(4, '0')}`;
    const ref = p.kind === 'verify' ? await refVerify(p.raw, p.grant, p.now, p.aud) : refCanon(p.raw);
    const accepted = p.kind === 'verify' ? ref.allow === true : ref.canon !== undefined;
    const refDeviates = p.intent !== 'either' && (p.intent === 'accept') !== accepted;
    if (refDeviates) deviates++;
    const key = `${p.category}/${p.name}`;
    if (seen.has(key)) throw new Error('duplicate vector name ' + key);
    seen.add(key);
    const dev = refDeviates ? { refDeviates: true } : {};
    full.push(JSON.stringify({ id, category: p.category, name: p.name, intent: p.intent, kind: p.kind, raw: p.raw, grant: p.grant, now: p.now, aud: p.aud, ref, ...dev }));
    const sha = createHash('sha256').update(JSON.stringify([p.raw, p.grant, p.now, p.aud, p.kind])).digest('hex');
    lines.push(JSON.stringify({ id, category: p.category, name: p.name, intent: p.intent, kind: p.kind, rawLen: p.raw.length, sha256: sha, ref, ...dev }));
  }
  if (CORPUS) writeFileSync(CORPUS, full.join('\n') + '\n');
  const text = lines.join('\n') + '\n';
  if (CHECK) {
    const cur = readFileSync(OUT, 'utf8');
    if (cur !== text) { console.error(`DRIFT: ${OUT} differs from a fresh generation`); process.exit(1); }
    console.log(`ok: ${lines.length} vectors regenerate byte-identically (manifest sha256 ${createHash('sha256').update(text).digest('hex').slice(0, 16)})`);
    return;
  }
  writeFileSync(OUT, text);
  const byCat: Record<string, number> = {};
  for (const p of PEND) byCat[p.category] = (byCat[p.category] ?? 0) + 1;
  console.log(`wrote ${lines.length} vectors to ${OUT}; reference deviates from intent on ${deviates}`);
  console.log(JSON.stringify(byCat));
}
void G; void rnd;
main();
