#!/usr/bin/env node
// Guards the action-kit native ports (track A7): the shared vector corpus is complete and every one of the nine native CI
// workflows (plus the Python one) carries an `actions-vectors` job/step that replays it. A deleted vector file or a dropped
// CI step fails here, so a native can never silently stop being checked against the reference.
// Usage: node scripts/check-pca-actions-natives.mjs   (exit 1 on any miss)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.join(root, 'packages/pca-conformance/vectors/actions');
const errors = [];
const KINDS = ['parse', 'digest', 'effective', 'expand', 'floor', 'conform', 'pack', 'schema_verb', 'rule22', 'rule22_schema', 'pack_verify', 'evolution_verify', 'reapproval_verify', 'pin', 'pack_proof_verify', 'tracker', 'schema_shape', 'approval_render', 'approval_digest', 'approval_challenge', 'approval_escalation'];
const MIN_TOTAL = 781;
const counts = new Map();
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
for (const f of files) {
  const c = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  if (`${c.id}.json` !== f) errors.push(`${f}: id ${c.id} does not match the file name`);
  counts.set(c.kind, (counts.get(c.kind) ?? 0) + 1);
}
if (files.length < MIN_TOTAL) errors.push(`only ${files.length} action vectors (expected at least ${MIN_TOTAL})`);
for (const k of KINDS) if ((counts.get(k) ?? 0) < 8) errors.push(`vector kind ${k} has ${counts.get(k) ?? 0} cases (need at least 8)`);
for (const k of counts.keys()) if (!KINDS.includes(k)) errors.push(`unknown vector kind ${k}`);

const LANGS = ['go', 'rust', 'python', 'ruby', 'php', 'java', 'kotlin', 'dotnet', 'swift'];
for (const l of LANGS) {
  const f = path.join(root, `scripts/pca-ci-workflows/pca-${l}/workflows/ci.yml`);
  if (!fs.existsSync(f)) { errors.push(`missing workflow: ${path.relative(root, f)}`); continue; }
  if (!/^\s*(?:-\s*name:\s*['"]?|)actions-vectors\b|^\s{2}actions-vectors:/m.test(fs.readFileSync(f, 'utf8'))) errors.push(`${l}: ci.yml has no actions-vectors job or step`);
}
for (const s of ['sync-pca-mirror.sh', 'sync-pca-python-mirror.sh', 'sync-pca-rust-mirror.sh']) {
  if (!fs.readFileSync(path.join(root, 'scripts', s), 'utf8').includes('conformance/actions')) errors.push(`${s} does not vendor conformance/actions`);
}
if (errors.length) { console.error('check-pca-actions-natives: FAIL\n  ' + errors.join('\n  ')); process.exit(1); }
console.log(`check-pca-actions-natives: OK (${files.length} vectors, ${LANGS.length} native workflows)`);
