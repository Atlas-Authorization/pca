#!/usr/bin/env node
// related-tests.mjs <pkg-dir> <src/x.ts> [direct|all]
// Prints the test files (relative to the package) that import <src/x.ts>: `direct` = test files importing it themselves,
// `all` (default) = every test file that reaches it through the relative-import graph. Used to pick the test lists of the
// two-phase assert-runner on CI (phase 1 = direct, phase 2 = all).
import fs from 'node:fs';
import path from 'node:path';

const [pkgDir, src, mode = 'all'] = process.argv.slice(2);
if (!pkgDir || !src) { console.error('usage: related-tests.mjs <pkg-dir> <src/x.ts> [direct|all]'); process.exit(2); }
const root = path.resolve(pkgDir);
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => {
  if (e.name === 'node_modules' || e.name === 'dist') return [];
  const p = path.join(d, e.name);
  return e.isDirectory() ? walk(p) : /\.(c|m)?tsx?$/.test(e.name) ? [p] : [];
});
const files = ['src', 'test'].filter((d) => fs.existsSync(path.join(root, d))).flatMap((d) => walk(path.join(root, d)));
const known = new Set(files);
const resolve = (from, spec) => {
  const base = path.resolve(path.dirname(from), spec.replace(/\.(c|m)?js$/, ''));
  for (const c of [base, `${base}.ts`, `${base}.tsx`, `${base}.mts`, `${base}.cts`, path.join(base, 'index.ts')]) if (known.has(c)) return c;
  return null;
};
// reverse graph: module -> the files that import it
const importers = new Map();
const RE = /(?:from\s*|import\s*\(\s*|import\s+|require\s*\(\s*|vi\.mock\s*\(\s*)['"](\.\.?\/[^'"]+)['"]/g;
for (const f of files) {
  const text = fs.readFileSync(f, 'utf8');
  for (const m of text.matchAll(RE)) {
    const t = resolve(f, m[1]);
    if (t) (importers.get(t) ?? importers.set(t, new Set()).get(t)).add(f);
  }
}
const isTest = (f) => /\.(test|spec)\.(c|m)?tsx?$/.test(f);
const target = path.join(root, src);
const out = new Set();
if (mode === 'direct') {
  for (const f of importers.get(target) ?? []) if (isTest(f)) out.add(f);
} else {
  const seen = new Set([target]);
  const q = [target];
  while (q.length) {
    for (const f of importers.get(q.pop()) ?? []) {
      if (seen.has(f)) continue;
      seen.add(f);
      if (isTest(f)) out.add(f);
      else q.push(f);
    }
  }
}
console.log([...out].map((f) => path.relative(root, f)).sort().join(' '));
