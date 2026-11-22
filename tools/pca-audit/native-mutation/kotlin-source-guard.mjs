#!/usr/bin/env node
// Every shipped Kotlin source must have mutants in the run. Walks the whole SDK tree, so a new module or subdirectory is
// in scope by default, and fails on any shipped file no shard mutated. A file with no mutable code must be listed in
// <sdk>/mutation-file-exclusions.json ([{file, reason}]); a listed file that has mutants, or is gone, also fails.
//   node kotlin-source-guard.mjs <sdkDir> <reportsDir> <shards>     node kotlin-source-guard.mjs --self-check
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert';

const NOT_SHIPPED = new Set(['build', 'target', 'examples', 'test', 'androidTest', 'mutation', 'guard-common-test', '.git', '.gradle', 'reports']);
const walk = (d, f) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) {
  if (e.isDirectory()) { if (!NOT_SHIPPED.has(e.name)) walk(path.join(d, e.name), f); } else f(path.join(d, e.name), e.name);
} };

function check(sdk, reports, shards) {
  const errors = [], mutated = new Set();
  let lists = 0;
  walk(reports, (p, n) => { if (/^mutated-files-\d+\.json$/.test(n)) { lists++; for (const k of JSON.parse(fs.readFileSync(p, 'utf8'))) mutated.add(k); } });
  if (lists !== shards) errors.push(`mutated-file lists from ${lists}/${shards} shards`);
  const shipped = new Map();
  walk(sdk, (p, n) => {
    if (!/\.(kt|java)$/.test(n)) return;
    const pkg = /^\s*package\s+([\w.]+)/m.exec(fs.readFileSync(p, 'utf8'))?.[1] ?? '';
    shipped.set(path.relative(sdk, p), `${pkg.replaceAll('.', '/')}/${n}`);
  });
  const xp = path.join(sdk, 'mutation-file-exclusions.json');
  const excl = fs.existsSync(xp) ? JSON.parse(fs.readFileSync(xp, 'utf8')) : [];
  const listed = new Set();
  for (const e of excl) {
    listed.add(e.file);
    if (!e.reason) errors.push(`exclusion without a reason: ${e.file}`);
    if (!shipped.has(e.file)) errors.push(`exclusion names no shipped file: ${e.file}`);
    else if (mutated.has(shipped.get(e.file))) errors.push(`excluded file has mutants, drop the exclusion: ${e.file}`);
  }
  for (const [rel, key] of shipped) if (!mutated.has(key) && !listed.has(rel)) errors.push(`shipped file never mutated: ${rel}`);
  return { errors, shipped: shipped.size };
}

function selfCheck() {
  const t = fs.mkdtempSync(path.join(os.tmpdir(), 'ksg-'));
  const put = (rel, s) => { fs.mkdirSync(path.dirname(path.join(t, rel)), { recursive: true }); fs.writeFileSync(path.join(t, rel), s); };
  const sdk = path.join(t, 'sdk'), rep = path.join(t, 'rep');
  put('sdk/src/main/kotlin/a/b/Deep.kt', 'package a.b\n');
  put('sdk/src/test/kotlin/a/b/DeepTest.kt', 'package a.b\n');
  put('sdk/examples/x/Main.kt', 'package x\n');
  put('rep/shard-1/mutated-files-1.json', JSON.stringify(['a/b/Deep.kt']));
  assert.deepEqual(check(sdk, rep, 1), { errors: [], shipped: 1 });
  assert.match(check(sdk, rep, 2).errors[0], /1\/2 shards/);
  put('sdk/new-module/deep/er/New.kt', 'package a.c\n');
  assert.match(check(sdk, rep, 1).errors[0], /never mutated: new-module\/deep\/er\/New\.kt/);
  // the same file name in another package does not count as mutated
  put('sdk/new-module/deep/er/New.kt', 'package a.c\n'); put('sdk/o/Deep.kt', 'package other\n');
  assert.ok(check(sdk, rep, 1).errors.some((e) => e.includes('o/Deep.kt')));
  fs.rmSync(path.join(sdk, 'o'), { recursive: true });
  put('sdk/mutation-file-exclusions.json', JSON.stringify([{ file: 'new-module/deep/er/New.kt', reason: 'declarations only' }]));
  assert.deepEqual(check(sdk, rep, 1).errors, []);
  put('sdk/mutation-file-exclusions.json', JSON.stringify([{ file: 'new-module/deep/er/New.kt' }, { file: 'gone.kt', reason: 'r' }, { file: 'src/main/kotlin/a/b/Deep.kt', reason: 'r' }]));
  const e = check(sdk, rep, 1).errors.join('\n');
  assert.match(e, /without a reason/); assert.match(e, /no shipped file: gone/); assert.match(e, /has mutants/);
  fs.rmSync(t, { recursive: true });
  console.log('kotlin-source-guard self-check ok');
}

if (process.argv[2] === '--self-check') selfCheck();
else {
  const [sdk, reports, shards] = process.argv.slice(2);
  const { errors, shipped } = check(sdk, reports, Number(shards));
  for (const e of errors) console.error(`::error::${e}`);
  console.log(`${shipped} shipped source file(s), ${errors.length} problem(s)`);
  process.exitCode = errors.length ? 1 : 0;
}
