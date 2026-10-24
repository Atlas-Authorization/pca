// Size / time DoS corpus for the PCA verifiers (deterministic). Writes JSONL {id,category:'dos',name,expect,kind,raw,grant,now,aud}.
//   node dos.mjs <out.jsonl>
// `expect` is the intended outcome ('accept' | 'reject'); the all-languages runner additionally measures wall time per vector
// per language and fails any vector that takes > 1000 ms over the language's trivial-vector baseline.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import * as pca from '../../../packages/pca/dist/index.js';
// MAX is the shared PCActn raw-size cap (512 KiB, UTF-8 bytes, checked before parsing); JSMAX is the strict-JSON profile's own 1 MiB bound.
const NOW = 1_800_000_000_000, AUD = 'rs-conformance', MAX = 524288, JSMAX = 1 << 20;
const seed = (l) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const principal = seed('principal'), agent = seed('agent'), sub = seed('subagent');
const pub = (k) => pca.b64u(pca.publicKeyOf(k));
const te = new TextEncoder();
const reseal = (parent, toHolder, caveats, signer) => {
  const body = { issuer: parent.holder, holder: toHolder, caveats, parent: pca.capHash(parent) };
  const bd = pca.hashCanonical(body);
  const msg = new Uint8Array([...te.encode('atlas-pca/cap/v1\0'), ...pca.unb64u(bd)]);
  return { id: bd, issuer: body.issuer, holder: toHolder, caveats, parent: body.parent, body_digest: bd, sig: pca.b64u(pca.sign(signer, msg)) };
};
const nodes = [{ id: 'n1', verb: 'read', resource: 'db/users' }, { id: 'n2', verb: 'write', resource: 'db/orders' }];
const root = pca.mintRoot({ principalSecret: principal, principalPublic: pub(principal), holder: pub(agent), caveats: [{ type: 'note', text: 'k' }] });
const mk = (o = {}) => pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600000, grant: root, chain: [root], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: agent, ...o });
const sign = (p) => { const { sig: _s, ...b } = p; return pca.signPCActn(b, agent); };
const out = [];
const add = (name, expect, raw, grant = root, aud = AUD) => out.push({ id: `dos-${String(out.length).padStart(3, '0')}`, category: 'dos', name, expect, kind: 'verify', raw, grant: JSON.stringify(grant), now: NOW, aud });
const bytes = (s) => te.encode(s).length;

// ---- exact size boundary, measured in UTF-8 BYTES of the input, with every character width
const baseWith = (pad) => { const p = mk(); p.risk_claim = { r: 0, inputs: { pad } }; return pca.canonicalize(sign(p)); };
for (const [wn, ch] of [['1b', 'a'], ['2b', 'é'], ['3b', '€'], ['4b', '\u{1F600}']]) {
  const w = bytes(ch);
  const empty = bytes(baseWith(''));
  const room = MAX - empty;
  const n = Math.floor(room / w);
  let raw = baseWith(ch.repeat(n));
  const filler = MAX - bytes(raw); // 0..w-1 bytes left: top up with ascii via a second key is not possible; pad the doc with trailing whitespace instead
  add(`size-${wn}-fill-then-ws-to-exactly-512KiB`, 'accept', raw + ' '.repeat(filler));
  add(`size-${wn}-exactly-512KiB-plus-1`, 'reject', raw + ' '.repeat(filler + 1));
  // many characters but too many bytes, while chars (and UTF-16 units for BMP) stay under the limit
  add(`size-${wn}-chars-under-bytes-over`, 'reject', baseWith(ch.repeat(n + 2)) + (w === 1 ? '' : ''));
}
add('size-ws-512KiB+1', 'reject', ' '.repeat(MAX + 1 - bytes(mk() && pca.canonicalize(mk()))) + pca.canonicalize(mk()));
add('size-escape-heavy-exact', 'accept', (() => { // signed value is k x "A"; the text spells each A as \\u0041 (6 bytes) and is padded to EXACTLY 512 KiB (524288) bytes
  const sz = (k) => { const p = mk(); p.risk_claim = { r: 0, inputs: { pad: 'A'.repeat(k) } }; return sign(p); };
  const k = Math.floor((MAX - bytes(pca.canonicalize(sz(0)))) / 6);
  const t = pca.canonicalize(sz(k)).replace('"' + 'A'.repeat(k) + '"', '"' + '\\u0041'.repeat(k) + '"');
  return t + ' '.repeat(MAX - bytes(t));
})());
// ---- nesting / width / literal bombs (each ~1 MiB: now rejected by the 512 KiB artifact cap before any parsing; the -400k variants below stay UNDER the cap and still reach the strict parser)
add('bomb-open-brackets-1MiB', 'reject', '['.repeat(JSMAX));
add('bomb-open-objects-1MiB', 'reject', '{"a":'.repeat(JSMAX / 5 | 0));
add('bomb-open-objects-mixed', 'reject', '[{"a":'.repeat(JSMAX / 6 | 0));
const body0 = pca.canonicalize(mk());
add('bomb-digits-counter-under-cap', 'reject', body0.replace('"counter":1', '"counter":' + '9'.repeat(MAX - 4000)));
add('bomb-digits-5000-counter', 'reject', body0.replace('"counter":1', '"counter":' + '9'.repeat(5000)));
add('bomb-frac-digits-under-cap', 'reject', body0.replace('"r":0', '"r":0.' + '1'.repeat(MAX - 4000)));
add('bomb-exponent', 'reject', body0.replace('"r":0', '"r":1e99999999999999999999'));
add('bomb-aud-under-cap', 'reject', body0.replace(`"aud":"${AUD}"`, `"aud":"${'a'.repeat(MAX - 4000)}"`));
add('bomb-aud-under-cap-matching', 'reject', body0.replace(`"aud":"${AUD}"`, `"aud":"${'a'.repeat(MAX - 4000)}"`), root, 'a'.repeat(MAX - 4000));
for (const f of ['sig', 'grant_ref']) add(`bomb-b64-${f}-under-cap`, 'reject', body0.replace(new RegExp(`"${f}":"[^"]*"`), `"${f}":"${'A'.repeat(MAX - 4000)}"`));
add('bomb-b64-nearly-valid-backtrack', 'reject', body0.replace(/"sig":"[^"]*"/, `"sig":"${'A'.repeat(200000)}="`));
add('bomb-key-under-cap', 'reject', body0.replace('"counter":1', `"${'k'.repeat(MAX - 4000)}":1`));
// the same shapes at 1 MiB: over the artifact cap, rejected before any parsing
add('bomb-digits-counter-1MiB-over-cap', 'reject', body0.replace('"counter":1', '"counter":' + '9'.repeat(JSMAX - 4000)));
add('bomb-aud-1MiB-over-cap', 'reject', body0.replace(`"aud":"${AUD}"`, `"aud":"${'a'.repeat(JSMAX - 4000)}"`));
add('bomb-key-1MiB-over-cap', 'reject', body0.replace('"counter":1', `"${'k'.repeat(JSMAX - 4000)}":1`));
add('bomb-unicode-escapes-heavy', 'reject', body0.replace(`"aud":"${AUD}"`, `"aud":"${'\\u0000'.repeat(MAX / 6 - 700 | 0)}"`));
add('bomb-lone-surrogates', 'reject', body0.replace(`"aud":"${AUD}"`, `"aud":"${'\\ud800'.repeat(MAX / 6 - 700 | 0)}"`));
add('bomb-dup-keys-20k', 'reject', body0.replace('"risk_claim":{', '"risk_claim":{' ).replace('"inputs":{}', '"inputs":{' + Array.from({ length: 20000 }, (_, i) => `"k${i}":0`).join(',') + ',"k0":1}'));
add('bomb-dup-keys-adjacent-30k', 'reject', body0.replace('"inputs":{}', '"inputs":{' + Array.from({ length: 30000 }, () => '"k":0').join(',') + '}'));
add('wide-keys-25k-distinct', 'accept', (() => { const p = mk(); p.risk_claim = { r: 0, inputs: Object.fromEntries(Array.from({ length: 25000 }, (_, i) => ['key' + i, i])) }; return pca.canonicalize(sign(p)); })());
add('wide-keys-40k-distinct-over-cap', 'reject', (() => { const p = mk(); p.risk_claim = { r: 0, inputs: Object.fromEntries(Array.from({ length: 40000 }, (_, i) => ['key' + i, i])) }; return pca.canonicalize(sign(p)); })());
add('wide-array-150k-ints', 'accept', (() => { const p = mk(); p.risk_claim = { r: 0, inputs: { a: Array.from({ length: 150000 }, (_, i) => i % 10) } }; return pca.canonicalize(sign(p)); })());
add('wide-array-300k-nested-empty', 'reject', body0.replace('"inputs":{}', '"inputs":{"a":' + '[' + '[],'.repeat(300000) + '[]]}'));
// ---- chain / proof / caveat bombs
add('chain-5000-junk-hops', 'reject', (() => { const p = mk(); p.cap_chain = Array.from({ length: 5000 }, () => root); return JSON.stringify(p); })());
add('chain-17-hops-fat-caveats', 'reject', (() => { const p = mk(); const c = { ...root, caveats: Array.from({ length: 2000 }, (_, i) => ({ type: 'n', i })) }; p.cap_chain = Array.from({ length: 17 }, () => c); return JSON.stringify(p); })());
add('proof-path-100k-steps', 'reject', (() => { const p = mk(); p.plan.inclusion_proof.path = Array.from({ length: 100000 }, () => ({ side: 'L', hash: p.plan.root })); return JSON.stringify(p); })());
add('proof-size-2^53-1-path-53', 'reject', (() => { const p = mk(); p.plan.inclusion_proof = { index: 1, size: 9007199254740991, path: Array.from({ length: 53 }, () => ({ side: 'R', hash: p.plan.root })) }; return pca.canonicalize(sign(p)); })());
for (const n of [15000]) add(`atten-${n}-caveats-prefix-compare`, 'reject', (() => { const many = Array.from({ length: n }, (_, i) => ({ type: 'note', i })); const g = pca.mintRoot({ principalSecret: principal, principalPublic: pub(principal), holder: pub(agent), caveats: many }); const hop = reseal(g, pub(sub), [...many, { type: 'note', i: -1 }], agent); const p = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600000, grant: g, chain: [g, hop], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: sub }); out.push({ _g: JSON.stringify(g) }); return pca.canonicalize(p); })());
// fix the grant of the previous vector
{ const gi = out.findIndex((x) => x._g); const g = out[gi]._g; out.splice(gi, 1); out[out.length - 1].grant = g; }
add('atten-3000-identical-caveats-quadratic', 'reject', (() => { const many = Array.from({ length: 3000 }, () => ({ type: 'same' })); const g = pca.mintRoot({ principalSecret: principal, principalPublic: pub(principal), holder: pub(agent), caveats: many }); const hop = reseal(g, pub(sub), [...many, { type: 'x' }], agent); out.push({ _g: JSON.stringify(g) }); return pca.canonicalize(pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600000, grant: g, chain: [g, hop], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: sub })); })());
{ const gi = out.findIndex((x) => x._g); const g = out[gi]._g; out.splice(gi, 1); out[out.length - 1].grant = g; }
// ---- shared artifact size cap (512 KiB = 524288 UTF-8 bytes of raw document text): limit-1 / limit / limit+1, then a realistic LESS-sized PCActn
{
  const c0 = pca.canonicalize(mk()); const n0 = bytes(c0);
  add('artifact-size-limit-1', 'accept', c0 + ' '.repeat(MAX - 1 - n0));
  add('artifact-size-limit', 'accept', c0 + ' '.repeat(MAX - n0));
  add('artifact-size-limit+1', 'reject', c0 + ' '.repeat(MAX + 1 - n0));
  // hybrid LESS-cat1 shape: ~130 KB base64url pq_pk (97484 raw bytes) + a ~1.7 KB pq_sig-like blob + a second ~68 KB key blob, in signed fields
  const b64 = (n, k) => pca.b64u(new Uint8Array(createHash('sha256').update(`less-sized/${k}`).digest()).slice(0, 32)).repeat(Math.ceil((n * 4) / 3 / 43)).slice(0, Math.ceil((n * 4) / 3));
  const p = mk(); p.risk_claim = { r: 0, inputs: { pq_pk: b64(97484, 'pk'), pq_sig: b64(1329, 'sig'), holder_pq_pk: b64(50000, 'hpk') } };
  const less = pca.canonicalize(sign(p)); const lb = bytes(less);
  if (lb < 190000 || lb > 210000) throw new Error('LESS-sized vector is ' + lb + ' bytes, expected ~200 KB');
  add('artifact-size-less-hybrid-~200KB-accept', 'accept', less);
}
// ---- shared caveat caps (256 per hop = a hop's whole cumulative list; 1024 summed over all hops): limit-1 / limit / limit+1
// Chain of hops whose cumulative caveat-list lengths are `lens` (non-decreasing; the root is hop 0, each later hop re-seals the
// parent's list plus the extra caveats). Holders alternate agent/sub, so the leaf signer is chosen from the hop count.
const capChain = (lens) => {
  const mkList = (n) => Array.from({ length: n }, (_, i) => ({ type: 'note', i }));
  let cur = pca.mintRoot({ principalSecret: principal, principalPublic: pub(principal), holder: pub(agent), caveats: mkList(lens[0]) });
  const g = cur; const chain = [cur]; let holder = agent;
  for (let k = 1; k < lens.length; k++) { const next = holder === agent ? sub : agent; cur = reseal(cur, pub(next), mkList(lens[k]), holder); chain.push(cur); holder = next; }
  return { g, chain, holder };
};
const capVec = (name, expect, lens) => { const { g, chain, holder } = capChain(lens); add(name, expect, pca.canonicalize(pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600000, grant: g, chain, plan: nodes, nodeId: 'n1', counter: 1, signerSecret: holder })), g); };
capVec('caveats-per-hop-255-limit-1', 'accept', [255]);
capVec('caveats-per-hop-256-limit', 'accept', [256]);
capVec('caveats-per-hop-257-limit+1', 'reject', [257]);
capVec('caveats-per-hop-256-leaf-of-3-hop-limit', 'accept', [100, 200, 256]);
capVec('caveats-per-hop-257-leaf-of-3-hop-limit+1', 'reject', [60, 150, 257]);
capVec('caveats-per-chain-1023-limit-1', 'accept', [204, 204, 205, 205, 205]);
capVec('caveats-per-chain-1024-limit', 'accept', [204, 205, 205, 205, 205]);
capVec('caveats-per-chain-1025-limit+1', 'reject', [205, 205, 205, 205, 205]);
capVec('caveats-per-chain-16-hops-65-each-1040', 'reject', Array.from({ length: 16 }, () => 65));
capVec('caveats-per-chain-16-hops-64-each-1024-limit', 'accept', Array.from({ length: 16 }, () => 64));
add('control-valid', 'accept', pca.canonicalize(mk()));
out.forEach((v, i) => { v.id = `dos-${String(i).padStart(3, '0')}`; });
writeFileSync(process.argv[2], out.map((v) => JSON.stringify(v)).join('\n') + '\n');
console.error(`dos: ${out.length} vectors`);
