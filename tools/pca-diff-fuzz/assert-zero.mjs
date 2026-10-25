#!/usr/bin/env node
// CI gate: fail unless every implementation that must run did run with ZERO divergence from the TS oracle.
//   node assert-zero.mjs <outDir> [--require go,python,ruby,php,dotnet,rust,java]
// Without --require, implementations that were skipped (toolchain unavailable) are reported but tolerated;
// with --require, a skipped/failed required implementation is itself a failure (no silent green).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
const out = args[0];
const ri = args.indexOf('--require');
const required = ri >= 0 ? args[ri + 1].split(',').filter(Boolean) : [];
if (!out) { console.error('usage: assert-zero.mjs <outDir> [--require a,b,c]'); process.exit(2); }

const r = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
const problems = [];
const ran = new Set(r.implementations);
for (const n of required) if (!ran.has(n)) problems.push(`${n}: required but did not run (${r.status[n] ?? 'no status'})`);
if (r.oracleErrors) problems.push(`oracle errors: ${r.oracleErrors}`);
for (const [n, d] of Object.entries(r.divergences)) {
  const div = d.compared - d.agree;
  if (div) problems.push(`${n}: ${div} divergent case(s) vs oracle ${JSON.stringify(d.byClass)}`);
  if (d.errorClassDiffs) problems.push(`${n}: ${d.errorClassDiffs} error-class difference(s)`);
}
if (r.crossImplementation.verifyCasesWithAnyDisagreement) problems.push(`cross-impl disagreement: ${r.crossImplementation.verifyCasesWithAnyDisagreement}`);
if (r.sdkVsSdk.verifyCasesWhereSDKsDisagree || r.sdkVsSdk.canonCasesWhereSDKsDisagree) problems.push('SDK-vs-SDK disagreement');
for (const [who, m] of Object.entries(r.metamorphic)) {
  for (const k of ['preserving', 'numrepr', 'breaking']) if (m[k]?.violated) problems.push(`${who}: ${m[k].violated} metamorphic ${k} violation(s)`);
}
for (const row of r.adversarialClasses) for (const [w, n] of Object.entries(row.acceptedByImpl)) if (n) problems.push(`${w} ACCEPTED ${n} must-reject case(s) in class "${row.label}"`);

console.log(`pca-diff-fuzz gate: ran=[${[...ran].join(',')}] corpus=${r.corpus.total}`);
const skipped = Object.entries(r.status).filter(([, s]) => s !== 'ran').map(([n, s]) => `${n} (${s})`);
if (skipped.length) console.log(`not run: ${skipped.join('; ')}`);
if (problems.length) { console.error('FAIL:\n  ' + problems.join('\n  ')); process.exit(1); }
console.log('PASS: zero divergence from the TS oracle');
