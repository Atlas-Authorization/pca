#!/usr/bin/env node
// Test-side snapshot for the targeted mutation mode (Go / Rust / Swift).
//   node snapshot.mjs make --root <workspace> --exclude-list <file: one repo-relative path per line, the mutated sources>
//        --corpus-root <flagship checkout> --out <dir> --tool-files a,b,c --cfg <string>
//   node snapshot.mjs compare <old snapshot dir> <new snapshot dir>        -> JSON {ok, reasons}; exit 0 either way
// A snapshot = every git-tracked file of the workspace that is not a mutated source / doc / ledger / workflow (sdk/), the shared
// conformance corpus (corpus/) and meta.json {tool_hash}. A carried kill stays valid only when the tests and corpus the
// baseline ran against only GREW: new files, pure line insertions, JSON that gained data. Everything else (edit, deletion,
// binary change) makes the whole baseline run unusable and the shard runs in full.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { compareSnapshots, toolHash } from './lib.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const opt = (n) => rest.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);
if (cmd === 'compare') {
  console.log(JSON.stringify(compareSnapshots(rest[0], rest[1])));
} else if (cmd === 'make') {
  const root = path.resolve(opt('root')), out = path.resolve(opt('out')), cr = opt('corpus-root');
  const excl = new Set(fs.readFileSync(opt('exclude-list'), 'utf8').split('\n').map((s) => s.trim()).filter(Boolean));
  fs.rmSync(out, { recursive: true, force: true });
  const skip = /(^|\/)(\.github|docs|\.git)\/|\.md$|(^|\/)(LICENSE|CHANGELOG)[^/]*$|equivalents[^/]*\.json$/;
  const tracked = execFileSync('git', ['-C', root, 'ls-files', '-z'], { maxBuffer: 1 << 28 }).toString().split('\0').filter(Boolean);
  let n = 0;
  for (const rel of tracked) {
    if (excl.has(rel) || skip.test(rel)) continue;
    const src = path.join(root, rel);
    if (!fs.existsSync(src) || !fs.statSync(src).isFile()) continue;
    fs.mkdirSync(path.dirname(path.join(out, 'sdk', rel)), { recursive: true });
    fs.copyFileSync(src, path.join(out, 'sdk', rel)); n++;
  }
  let c = 0;
  for (const d of ['conformance', 'packages/pca/conformance', 'packages/pca-conformance', 'tools/pca-diff-fuzz/counterexamples']) {
    const base = path.join(cr, d);
    if (!fs.existsSync(base)) continue;
    const walk = (dir) => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else if (e.isFile()) { const rel = path.relative(cr, p); fs.mkdirSync(path.dirname(path.join(out, 'corpus', rel)), { recursive: true }); fs.copyFileSync(p, path.join(out, 'corpus', rel)); c++; } } };
    walk(base);
  }
  const files = (opt('tool-files') || '').split(',').filter(Boolean);
  fs.writeFileSync(path.join(out, 'meta.json'), JSON.stringify({ tool_hash: toolHash(files, opt('cfg') || ''), sdk_files: n, corpus_files: c, sha: process.env.GITHUB_SHA || '' }));
  console.log(`snapshot: ${n} sdk file(s), ${c} corpus file(s) -> ${out}`);
} else { console.error('usage: snapshot.mjs make|compare'); process.exit(2); }
