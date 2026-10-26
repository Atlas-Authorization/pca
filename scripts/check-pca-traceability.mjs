#!/usr/bin/env node
// Verifies docs/pca/security/traceability.md against the repo:
//  - every referenced test file exists
//  - every referenced test-name substring appears in that file
//  - every T-ID / G-ID defined in threat-model.md appears in traceability.md
//  - every C-ID (security-contract invariant) defined in security-contract.md appears in traceability.md
//  - every "NO AUTOMATED TEST" ID is explained in the Gaps section
// Usage: node scripts/check-pca-traceability.mjs   (exit 1 on any miss)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tracePath = path.join(root, 'docs/pca/security/traceability.md');
const threatPath = path.join(root, 'docs/pca/security/threat-model.md');
const contractPath = path.join(root, 'docs/pca/security/security-contract.md');
const errors = [];
const trace = fs.readFileSync(tracePath, 'utf8');
const threat = fs.readFileSync(threatPath, 'utf8');
const contract = fs.existsSync(contractPath) ? fs.readFileSync(contractPath, 'utf8') : '';
if (!contract) errors.push('security-contract.md is missing');

const threatIds = new Set([...threat.matchAll(/^###\s+(T-\d{3})\b/gm)].map((m) => m[1]));
const guaranteeIds = new Set([...threat.matchAll(/\*\*(G-\d+)\b/g)].map((m) => m[1]));
if (threatIds.size === 0) errors.push('no T-IDs found in threat-model.md');
if (guaranteeIds.size === 0) errors.push('no G-IDs found in threat-model.md');
const contractIds = new Set([...contract.matchAll(/^###\s+(C-\d+)\b/gm)].map((m) => m[1]));
if (contract && contractIds.size === 0) errors.push('no C-IDs found in security-contract.md');

const gapsIdx = trace.indexOf('\n## Gaps');
const gapsText = gapsIdx >= 0 ? trace.slice(gapsIdx) : '';
if (gapsIdx < 0) errors.push('traceability.md has no "## Gaps" section');

const mapped = new Map(); // id -> count of real test rows
const noTest = new Set();
const fileCache = new Map();
let rows = 0;
for (const line of trace.split('\n')) {
  const m = line.match(/^\|\s*([TGC]-\d+)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$/);
  if (!m) continue;
  const [, id, file, name] = m;
  if (file === 'NO AUTOMATED TEST') {
    noTest.add(id);
    continue;
  }
  rows++;
  const abs = path.join(root, file);
  if (!fs.existsSync(abs)) {
    errors.push(`${id}: test file does not exist: ${file}`);
    continue;
  }
  if (!fileCache.has(abs)) fileCache.set(abs, fs.readFileSync(abs, 'utf8'));
  if (!fileCache.get(abs).includes(name)) errors.push(`${id}: test name not found in ${file}: ${JSON.stringify(name)}`);
  mapped.set(id, (mapped.get(id) ?? 0) + 1);
}

for (const id of [...threatIds, ...guaranteeIds]) {
  if (!mapped.has(id) && !noTest.has(id)) errors.push(`${id}: defined in threat-model.md but absent from traceability.md`);
}
for (const id of contractIds) {
  if (!mapped.has(id) && !noTest.has(id)) errors.push(`${id}: defined in security-contract.md but absent from traceability.md`);
}
for (const id of [...mapped.keys(), ...noTest]) {
  if (!threatIds.has(id) && !guaranteeIds.has(id) && !contractIds.has(id)) errors.push(`${id}: in traceability.md but not defined in threat-model.md or security-contract.md`);
}
for (const id of noTest) {
  if (!new RegExp(`\\*\\*${id}\\b`).test(gapsText)) errors.push(`${id}: marked NO AUTOMATED TEST but not explained in Gaps`);
}

const tCount = [...threatIds].length;
console.log(`attacks: ${tCount}, guarantees: ${guaranteeIds.size}, contract invariants: ${contractIds.size}, mapped test rows: ${rows}, test files: ${fileCache.size}, no-test ids: ${noTest.size} (${[...noTest].join(', ')})`);
if (errors.length) {
  console.error(`\nFAILED with ${errors.length} problem(s):`);
  for (const e of errors) console.error(' - ' + e);
  process.exit(1);
}
console.log('OK');
