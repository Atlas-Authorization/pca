// Oracle for the Ruby wire-sweep kill test (sdks/ruby-pca/test/kill/9j_wire_sweep.rb): the TS reference validateWireV2
// (packages/pca/src/wire.ts, from the built dist) on EVERY single-member perturbation of the conformance corpus' wire-valid
// PCActns: each path of the object (to depth 5) replaced by a set of wrongly typed / out-of-range values, and deleted.
//   node tools/pca-audit/ruby-mutate/wire-sweep-oracle.mjs sdks/ruby-pca/test-data/k042-wire-sweep.json.gz
// Output { about, cases: [[pcactnJsonText, ok]] } (ok = validateWireV2 returned null). Raw JSON text keeps -0 / big integers.
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const { validateWireV2 } = await import(path.join(root, 'packages/pca/dist/wire.js'));
const out = process.argv[2];
if (!out) throw new Error('usage: wire-sweep-oracle.mjs <out.json.gz>');
const vectors = JSON.parse(fs.readFileSync(path.join(root, 'packages/pca/conformance/vectors.json'), 'utf8')).vectors;
const valid = vectors.filter((v) => v.pcactn && typeof v.pcactn === 'object' && validateWireV2(v.pcactn) === null);
// one representative per shape (top-level keys + each hop's keys + each caveat type)
const shape = (p) => JSON.stringify([Object.keys(p).sort(), (p.cap_chain ?? []).map((h) => [Object.keys(h).sort(), (h.caveats ?? []).map((c) => c.type)]), Object.keys(p.plan ?? {}).sort(), p.alg ?? '']);
const seen = new Map();
for (const v of valid) if (!seen.has(shape(v.pcactn))) seen.set(shape(v.pcactn), v.pcactn);
const bases = [...seen.values()].slice(0, 14);
const WRONG = [null, 'x', '', 0, -1, 1.5, 9007199254740992, 1e21, true, false, [], {}, [1], { a: 1 }, 'A'.repeat(300), '-', 'AAAA', { type: 'x' }];
const paths = (o, pre = [], depth = 0, acc = []) => {
  if (depth > 5 || o === null || typeof o !== 'object') return acc;
  const keys = Array.isArray(o) ? o.slice(0, 3).map((_, i) => i) : Object.keys(o);
  for (const k of keys) { acc.push([...pre, k]); paths(o[k], [...pre, k], depth + 1, acc); }
  return acc;
};
const clone = (x) => JSON.parse(JSON.stringify(x));
const set = (root, p, v, del) => {
  const r = clone(root); let c = r;
  for (const k of p.slice(0, -1)) c = c[k];
  const last = p[p.length - 1];
  if (del) { if (Array.isArray(c)) c.splice(last, 1); else delete c[last]; } else c[last] = v;
  return r;
};
const ser = (v) => (typeof v === 'number' && Object.is(v, -0) ? '-0' : JSON.stringify(v));
const cases = []; const seenText = new Set();
const add = (p) => { const t = JSON.stringify(p); if (seenText.has(t)) return; seenText.add(t); cases.push([t, validateWireV2(p) === null]); };
for (const b of bases) {
  add(b);
  add({ ...clone(b), zz: 1 });
  for (const p of paths(b)) {
    add(set(b, p, undefined, true));
    for (const w of WRONG) add(set(b, p, w, false));
  }
}
const body = JSON.stringify({ about: 'k042 wire sweep: [pcactn json text, validateWireV2 === null]', cases });
fs.writeFileSync(out, zlib.gzipSync(Buffer.from(body), { level: 9 }));
console.error(`bases ${bases.length}, cases ${cases.length}, ok ${cases.filter((c) => c[1]).length}`);
