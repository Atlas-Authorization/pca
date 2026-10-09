import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const [,, src, out] = process.argv;
const raw = readFileSync(src, 'utf8');
const lines = raw.split('\n');
const start = lines.findIndex((l) => l.startsWith('A.1.  ristretto255-SHA512'));
const end = lines.findIndex((l) => l.startsWith('A.2.  decaf448'));
let cur = null; let mode = null; const modeInfo = {}; const vectors = [];
let field = null;
const cleaned = [];
for (let i = start; i < end; i++) {
  const l = lines[i];
  if (/^RFC 9497|^Davidson|^\f/.test(l)) continue;
  cleaned.push(l);
}
const target = () => (cur ?? modeInfo[mode]);
for (const l of cleaned) {
  let m;
  if ((m = /^A\.1\.(\d)\.\s+(OPRF|VOPRF|POPRF) Mode/.exec(l))) { mode = m[2]; modeInfo[mode] = { mode }; cur = null; field = null; continue; }
  if ((m = /^A\.1\.\d\.\d\.\s+Test Vector (\d+), Batch Size (\d+)/.exec(l))) { cur = { mode, n: Number(m[1]), batch: Number(m[2]) }; vectors.push(cur); field = null; continue; }
  if ((m = /^\s{3}(\w+) = (\S*)$/.exec(l))) { field = m[1]; target()[field] = m[2]; continue; }
  if (field && (m = /^\s{3}(\S+)$/.test(l) && l.trim())) { target()[field] += l.trim(); continue; }
}
const doc = {
  provenance: {
    source: 'RFC 9497, Appendix A.1 (ristretto255-SHA512), Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups',
    url: 'https://www.rfc-editor.org/rfc/rfc9497.txt',
    retrievedOn: '2026-10-08',
    sourceSha256: createHash('sha256').update(raw).digest('hex'),
    note: 'Extracted verbatim (hex strings re-joined across line wraps) by a script; no value hand-edited. Appendix A.2-A.6 (decaf448, P-256, P-384, P-521) are not included because this package implements only ristretto255-SHA512.',
  },
  modes: modeInfo,
  vectors,
};
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n');
console.log(vectors.length, Object.keys(modeInfo));
