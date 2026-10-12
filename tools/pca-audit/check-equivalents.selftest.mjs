#!/usr/bin/env node
// Self-test for the two equivalent-mutant ledger checkers (native-check-equivalents.mjs and stryker/check-equivalents.mjs)
// and their shared site keying (site-key.mjs). Plain node, no test runner, temp fixtures only:
//   node tools/pca-audit/check-equivalents.selftest.mjs
// Cases (each for both checkers):
//   1. two identical lines, only one ledgered: the other survivor is still reported (UNLISTED SURVIVOR)
//   2. stale entry: the ledgered site no longer survives (the identical line elsewhere does not keep it alive)
//   3. ambiguity: an entry whose text occurs twice in the file and has no occurrence is an error, even in the static check
//   4. both sites ledgered: OK, and still OK after unrelated lines are inserted above (line numbers are hints only)
//   5. multiplicity: the same mutant reported twice on one line needs multiplicity 2
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const NATIVE = path.join(here, 'native-check-equivalents.mjs');
const TS = path.join(here, 'stryker', 'check-equivalents.mjs');
let failed = 0, passed = 0;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pca-eq-selftest-'));
const write = (p, s) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, typeof s === 'string' ? s : JSON.stringify(s, null, 1)); };
const run = (script, args) => { const r = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' }); return { code: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') }; };
const expect = (name, r, code, ...needles) => {
  const miss = needles.filter((n) => !(n instanceof RegExp ? n.test(r.out) : r.out.includes(n)));
  if (r.code === code && miss.length === 0) { passed++; console.log(`ok   ${name}`); return; }
  failed++;
  console.log(`FAIL ${name}: exit ${r.code} (want ${code})${miss.length ? `, missing ${miss.map(String).join(' / ')}` : ''}\n${r.out.split('\n').map((l) => '     | ' + l).join('\n')}`);
};

// ---- native fixtures -------------------------------------------------------------------------------------------------
// sdks/demo-pca/src/a.go: `return false` on lines 3 and 6
const GO = ['func a(x int) bool {', '\tif x > 1 {', '\t\treturn false', '\t}', '\tif x < 0 {', '\t\treturn false', '\t}', '\treturn true', '}', ''].join('\n');
const nat = (name, { source = GO, ledger, survivors }) => {
  const root = path.join(tmp, 'native', name);
  write(path.join(root, 'sdks/demo-pca/src/a.go'), source);
  write(path.join(root, 'ledger.json'), { about: 'selftest', equivalents: ledger });
  const args = [`--root=${root}`, `--ledger=${path.join(root, 'ledger.json')}`];
  if (survivors) { write(path.join(root, 'surv.json'), survivors); args.push(path.join(root, 'surv.json')); }
  return run(NATIVE, args);
};
const E = (occurrence, extra = {}) => ({ crate: 'demo-pca', file: 'src/a.go', mutant: 'return false -> true', line: 'return false', ...(occurrence ? { occurrence } : {}), reason: 'selftest justification text', ...extra });
const S = (lineno, extra = {}) => ({ crate: 'demo-pca', file: 'src/a.go', mutant: 'return false -> true', line: 'return false', lineno, ...extra });

expect('native 1: identical line, one ledgered -> the other survivor is reported',
  nat('n1', { ledger: [E(1)], survivors: [S(3), S(6)] }), 1, 'UNLISTED SURVIVOR', /src\/a\.go:6:.*\(#2\)/);
expect('native 1b: same, survivor carries its run-time occurrence',
  nat('n1b', { ledger: [E(1)], survivors: [S(3, { occurrence: 1 }), S(6, { occurrence: 2 })] }), 1, 'UNLISTED SURVIVOR', '(#2)');
expect('native 2: stale entry (its site no longer survives; the identical line does not keep it alive)',
  nat('n2', { ledger: [E(1), E(2)], survivors: [S(3)] }), 1, 'STALE', '(#2)');
expect('native 3: ambiguous entry (text twice, no occurrence) fails the static check',
  nat('n3', { ledger: [E(undefined)] }), 1, 'AMBIGUOUS', 'occurs 2 times');
expect('native 3b: ambiguous entry also fails the full check',
  nat('n3b', { ledger: [E(undefined)], survivors: [S(3)] }), 1, 'AMBIGUOUS');
expect('native 3c: unique text needs no occurrence',
  nat('n3c', { ledger: [{ ...E(undefined), mutant: 'return true -> false', line: 'return true' }] }), 0, 'native equivalents ok');
expect('native 3d: occurrence beyond the copies in the file is stale',
  nat('n3d', { ledger: [E(3)] }), 1, 'STALE (occurrence 3');
expect('native 4: both sites ledgered -> ok',
  nat('n4', { ledger: [E(1, { lineno: 3 }), E(2, { lineno: 6 })], survivors: [S(3), S(6)] }), 0, '2 survivors all matched');
const shifted = '// header\n// more header\n' + GO;
expect('native 4b: line churn above the sites -> still ok (hints drift, keys do not)',
  nat('n4b', { source: shifted, ledger: [E(1, { lineno: 3 }), E(2, { lineno: 6 })], survivors: [S(5), S(8)] }), 0, 'drifted', '2 survivors all matched');
expect('native 4c: a survivor without occurrence or line hint on a repeated text is unplaceable',
  nat('n4c', { ledger: [E(1), E(2)], survivors: [{ ...S(3), lineno: undefined }] }), 1, 'UNPLACEABLE');
expect('native 4d: fn must agree when both sides carry it',
  nat('n4d', { ledger: [E(1, { fn: 'a' }), E(2, { fn: 'a' })], survivors: [S(3, { fn: 'a' }), S(6, { fn: 'b' })] }), 1, 'UNLISTED SURVIVOR');
expect('native 5: same mutant twice at one site needs multiplicity 2',
  nat('n5', { ledger: [E(1), E(2)], survivors: [S(3), S(3), S(6)] }), 1, 'multiplicity: 2 identical');
expect('native 5b: multiplicity 2 covers them',
  nat('n5b', { ledger: [E(1, { multiplicity: 2 }), E(2)], survivors: [S(3), S(3), S(6)] }), 0, '3 survivors all matched');

// ---- Stryker / TS fixtures -------------------------------------------------------------------------------------------
// packages/demo/src/a.ts: `if (x === undefined) return 0;` on lines 2 and 5
const TSSRC = ['export function f(x?: number, y?: number): number {', '  if (x === undefined) return 0;', '  return x;', '}', '  if (x === undefined) return 0;', ''].join('\n');
const LINE = 'if (x === undefined) return 0;';
const T = (occurrence, extra = {}) => ({ package: 'demo', file: 'src/a.ts', mutator: 'ConditionalExpression', original: 'x === undefined', replacement: 'false', line: LINE, ...(occurrence ? { occurrence } : {}), reason: 'selftest justification text', ...extra });
const M = (line, status = 'Survived') => ({ mutatorName: 'ConditionalExpression', replacement: 'false', status, location: { start: { line, column: 7 }, end: { line, column: 22 } } });
const ts = (name, { source = TSSRC, ledger, mutants }) => {
  const root = path.join(tmp, 'ts', name);
  write(path.join(root, 'packages/demo/src/a.ts'), source);
  write(path.join(root, 'ledger.json'), { about: 'selftest', equivalents: ledger });
  const args = [`--root=${root}`, `--ledger=${path.join(root, 'ledger.json')}`, '--package=demo'];
  if (mutants) { write(path.join(root, 'report.json'), { files: { 'src/a.ts': { source, mutants } } }); args.push(path.join(root, 'report.json')); }
  return run(TS, args);
};
expect('ts 1: identical line, one ledgered -> the other survivor is reported',
  ts('t1', { ledger: [T(1)], mutants: [M(2), M(5)] }), 1, 'UNLISTED SURVIVOR', 'src/a.ts:5:7 (#2)');
expect('ts 2: stale entry (site killed while the identical line survives)',
  ts('t2', { ledger: [T(1), T(2)], mutants: [M(2), M(5, 'Killed')] }), 1, 'STALE', '(#2)');
expect('ts 3: ambiguous entry fails the static check',
  ts('t3', { ledger: [T(undefined)] }), 1, 'AMBIGUOUS', 'occurs 2 times');
expect('ts 4: both sites ledgered -> ok',
  ts('t4', { ledger: [T(1, { lineno: 2 }), T(2, { lineno: 5 })], mutants: [M(2), M(5)] }), 0, '2 survivors all listed');
const tsShift = '// a\n// b\n// c\n' + TSSRC;
expect('ts 4b: line churn above the sites -> still ok',
  ts('t4b', { source: tsShift, ledger: [T(1, { lineno: 2 }), T(2, { lineno: 5 })], mutants: [M(5), M(8)] }), 0, 'drifted', '2 survivors all listed');
expect('ts 5: same mutant twice on one line needs multiplicity',
  ts('t5', { ledger: [T(1), T(2)], mutants: [M(2), M(2), M(5)] }), 1, 'multiplicity: 2 identical');

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
