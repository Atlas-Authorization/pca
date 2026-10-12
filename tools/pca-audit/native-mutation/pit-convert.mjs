#!/usr/bin/env node
// PIT mutations.xml -> (1) the compact results JSON committed under results/<crate-lang>-pit.json and (2) a survivors list for
// native-check-equivalents.mjs ([{crate,file,mutant,line,occurrence,lineno,fn}], SURVIVED + NO_COVERAGE; `line` = the trimmed
// source line, `occurrence` = which copy of that text in the file (the site key), `fn` = PIT's mutated method). Committed as
// results/<java|kotlin>-survivors.json next to the compact results.
//   node pit-convert.mjs <java-pca|kotlin-pca> <mutations.xml> <results.json> <survivors.json>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const [crate, xmlPath, outResults, outSurv] = process.argv.slice(2);
if (!outSurv) { console.error('usage: pit-convert.mjs <crate> <mutations.xml> <results.json> <survivors.json>'); process.exit(2); }
const xml = fs.readFileSync(xmlPath, 'utf8');
const tag = (blk, t) => { const m = new RegExp(`<${t}>([\\s\\S]*?)</${t}>`).exec(blk); return m ? m[1] : ''; };
const unesc = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const srcRoot = crate === 'kotlin-pca' ? 'src/main/kotlin' : 'src';
const lines = new Map();
const srcLine = (rel, n) => {
  if (!lines.has(rel)) lines.set(rel, fs.readFileSync(path.join(root, 'sdks', crate, rel), 'utf8').split('\n'));
  return (lines.get(rel)[n - 1] ?? '').trim();
};
const results = [], surv = [];
for (const m of xml.matchAll(/<mutation\b([^>]*)>([\s\S]*?)<\/mutation>/g)) {
  const st = /status='([A-Z_]+)'/.exec(m[1])?.[1] ?? /status="([A-Z_]+)"/.exec(m[1])?.[1];
  const b = m[2];
  const file = tag(b, 'sourceFile'), cls = tag(b, 'mutatedClass'), line = Number(tag(b, 'lineNumber'));
  const mut = tag(b, 'mutator').split('.').pop(), desc = unesc(tag(b, 'description')), method = unesc(tag(b, 'mutatedMethod'));
  results.push({ st, file, method, line, mut, desc });
  if (st !== 'SURVIVED' && st !== 'NO_COVERAGE') continue;
  const pkg = cls.replace(/\$.*$/, '').split('.').slice(0, -1).join('/');
  const rel = `${srcRoot}/${pkg}/${file}`;
  // Kotlin maps inlined stdlib bodies (any / all / map / firstOrNull) to line numbers past the end of the file (SMAP): key such a
  // mutant by the declaration line of its method, the only stable source text for it.
  let text = srcLine(rel, line);
  let at = line;
  if (!text) {
    const name = method.replace(/\$.*$/, '');
    const all = lines.get(rel);
    at = all.findIndex((l) => new RegExp(`\\bfun ${name}\\(`).test(l)) + 1;
    text = at ? all[at - 1].trim() : '';
  }
  const occurrence = lines.get(rel).slice(0, at).filter((l) => l.trim() === text).length;
  surv.push({ crate, file: rel, mutant: `${mut}: ${desc}`, line: text, occurrence, lineno: at, fn: method, status: st });
}
fs.writeFileSync(outResults, JSON.stringify(results));
fs.writeFileSync(outSurv, JSON.stringify(surv, null, 1));
const c = {};
for (const r of results) c[r.st] = (c[r.st] ?? 0) + 1;
console.log(crate, results.length, 'mutants', JSON.stringify(c), 'survivors(+no-coverage):', surv.length, 'distinct keys:', new Set(surv.map((s) => [s.file, s.mutant, s.line, s.occurrence].join('\0'))).size);
