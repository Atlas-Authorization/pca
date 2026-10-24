#!/usr/bin/env node
// gen-mutants.mjs --pkg-dir <dir> --src <src/x.ts> [--backlog <all.txt> --tag <pca/src/x.ts>] [--lines a-b] --out <mutants.jsonl>
// Generates the mutants Stryker would generate for ONE source file, with Stryker's own instrumenter (exact locations and
// replacement code). Optional --backlog/--tag keeps only the sites listed in a merge-log style backlog
// ("... <tag>:<line>:<col> (#n) <Mutator> '<orig>' -> '<repl>'", replacements may be truncated: matched by prefix).
import fs from 'node:fs';
import path from 'node:path';
const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i < 0 ? d : process.argv[i + 1]; };
const pkgDir = path.resolve(arg('pkg-dir', '.')); const src = arg('src'); const out = arg('out', 'mutants.jsonl');
const backlog = arg('backlog'); const tag = arg('tag'); const lines = arg('lines');
const instr = process.env.STRYKER_INSTRUMENTER ?? path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'node_modules/@stryker-mutator/instrumenter/dist/src/index.js');
if (!src) { console.error('usage: gen-mutants.mjs --pkg-dir <dir> --src <src/x.ts> [--backlog all.txt --tag pca/src/x.ts] [--lines 100-200] --out m.jsonl'); process.exit(2); }
const { Instrumenter } = await import(instr);
const content = fs.readFileSync(path.join(pkgDir, src), 'utf8');
const L = content.split('\n');
const nop = () => {};
const log = { isTraceEnabled: () => false, isDebugEnabled: () => false, isInfoEnabled: () => false, trace: nop, debug: nop, info: nop, warn: nop, error: nop, fatal: nop };
const res = await new Instrumenter(log).instrument([{ name: src, content, mutate: true }], { plugins: null, excludedMutations: [], ignorers: [], mutationRanges: [], noHeader: false });
const lineStart = [0]; for (let i = 0; i < content.length; i++) if (content[i] === '\n') lineStart.push(i + 1);
let want = null;
if (backlog) {
  want = new Map();
  for (const line of fs.readFileSync(backlog, 'utf8').split('\n')) {
    const i = line.indexOf(tag + ':'); if (i < 0) continue;
    const m = line.slice(i + tag.length + 1).match(/^(\d+):(\d+) \(#(\d+)\) (\w+) '([\s\S]*)' -> '([\s\S]*)'$/); if (!m) continue;
    const k = `${m[1]}:${m[2]}:${m[4]}`; (want.get(k) ?? want.set(k, []).get(k)).push(m[6]);
  }
}
const [lo, hi] = lines ? lines.split('-').map(Number) : [1, Infinity];
const outL = []; const seen = new Set();
for (const raw of res.mutants) {
  const m = raw.toApiMutant ? raw.toApiMutant() : raw;
  const s = m.location.start, e = m.location.end; // 0-based lines, 0-based columns
  const k = `${s.line + 1}:${s.column + 1}:${m.mutatorName}`;
  if (s.line + 1 < lo || s.line + 1 > hi) continue;
  if (want) { const w = want.get(k); if (!w || !w.some((x) => x === '<multiline>' || m.replacement.startsWith(x))) continue; seen.add(k); }
  const so = lineStart[s.line] + s.column, eo = lineStart[e.line] + e.column;
  outL.push({ id: `${k}:${outL.length}`, mutator: m.mutatorName, line: s.line + 1, col: s.column + 1, eline: e.line + 1, ecol: e.column + 1, orig: content.slice(so, eo), repl: m.replacement, lineText: L[s.line] });
}
fs.writeFileSync(out, outL.map((x) => JSON.stringify(x)).join('\n') + '\n');
console.log(`${src}: ${res.mutants.length} mutants from the instrumenter, ${outL.length} written to ${out}` + (want ? ` (${want.size} backlog sites, ${[...want.keys()].filter((k) => !seen.has(k)).length} not found)` : ''));
