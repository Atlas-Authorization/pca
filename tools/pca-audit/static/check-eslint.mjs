#!/usr/bin/env node
// Run eslint-plugin-security over the PCA production sources and fail on any finding that is not triaged in triage.json.
// Usage (repo root): node tools/pca-audit/static/check-eslint.mjs [--json out.json]
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const eslint = join(root, 'node_modules/.bin/eslint');
const r = spawnSync(eslint, ['-c', join(here, 'eslint.security.config.mjs'), '-f', 'json', 'packages/pca*/src/**/*.ts'], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 28 });
if (r.error || !r.stdout) {
  console.log('SKIPPED: eslint not runnable here (' + (r.error?.message ?? r.stderr.slice(0, 120)) + ')');
  process.exit(2);
}
const triage = JSON.parse(readFileSync(join(here, 'triage.json'), 'utf8'))['eslint-security'];
const counts = new Map(); // rule\0file -> n
for (const f of JSON.parse(r.stdout)) {
  const file = relative(root, f.filePath);
  for (const m of f.messages) {
    const rule = m.ruleId ?? '(unknown-rule-comment)';
    const k = `${rule}\0${file}`;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
}
const untriaged = [];
const totalByRule = new Map();
for (const [k, n] of counts) {
  const [rule, file] = k.split('\0');
  totalByRule.set(rule, (totalByRule.get(rule) ?? 0) + n);
  const entry = triage.find((t) => t.rule === rule && (t.files === '*' || t.files.includes(file)));
  if (!entry) untriaged.push(`${rule} ${file} x${n}`);
  else if (entry.files !== '*' && n > entry.max) untriaged.push(`${rule} ${file} x${n} (triaged max ${entry.max})`);
}
for (const t of triage) if (t.files === '*' && (totalByRule.get(t.rule) ?? 0) > t.max) untriaged.push(`${t.rule} total ${totalByRule.get(t.rule)} (triaged max ${t.max})`);
console.log([...totalByRule].map(([r2, n]) => `${String(n).padStart(5)} ${r2}`).join('\n'));
if (process.argv.includes('--json')) writeFileSync(process.argv[process.argv.indexOf('--json') + 1], JSON.stringify({ totals: Object.fromEntries(totalByRule), untriaged }, null, 1));
if (untriaged.length) {
  console.log('UNTRIAGED:\n  ' + untriaged.join('\n  '));
  process.exit(1);
}
console.log('OK: every eslint-plugin-security finding is triaged (see tools/pca-audit/static/triage.json)');
